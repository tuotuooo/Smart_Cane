#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apk_runtime_dump.py — 纯 root 的 Android 进程内存脱壳器（DEX / CDEX / Hermes）。

原理
----
加固壳（SecNeo / 乐固 / 梆梆…）会在运行时把真实 DEX 解密后 **MemMap 到匿名内存**。
mmap 出来的 DEX 有自己的区域，magic 位于该区域偏移 0 或区域内某个页首附近。因此：

  1. 解析 /proc/<pid>/maps，筛出可读、非文件映射、尺寸合理的区域；
  2. 先只读每区头部（默认 64KB）做 magic 探测 —— 便宜；
  3. 命中才整区拉取，再在区内按 magic + 头部 file_size 精确裁剪；
  4. 落盘 + SHA1 去重。

不需要 Frida、不需要 apktool、不需要改包。只要 adb 是 root。

用法
----
  # 自动找包对应的进程并全量扫描
  python apk_runtime_dump.py --pkg com.example.app --out ./memdump

  # 已知 pid，只找 Hermes bundle
  python apk_runtime_dump.py --pid 12345 --magic hermes

  # 只看候选区域（不读取内容，先摸清地形）
  python apk_runtime_dump.py --pkg com.example.app --list

  # 指定区域整段 dump（magic 不在头部时用）
  python apk_runtime_dump.py --pkg com.example.app --region 0x7c37c3a00000-0x7c37d3a00000

退出码：0=成功（可能 0 命中）；2=进程不存在；3=adb 不可用。
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

PAGE = 4096

DEX_MAGICS = [b"dex\n035", b"dex\n036", b"dex\n037", b"dex\n038", b"dex\n039"]
CDEX_MAGICS = [b"cdex001\0", b"cdex002\0", b"cdex003\0"]
HERMES_MAGIC = b"\xc6\x1f\xbc\x03"

MAGIC_SETS = {
    "dex": DEX_MAGICS,
    "cdex": CDEX_MAGICS,
    "hermes": [HERMES_MAGIC],
    "all": DEX_MAGICS + CDEX_MAGICS + [HERMES_MAGIC],
}

# 这些区域一定不是我们想要的（系统库、已解压的 apk/vdex、字体、jit…）
SKIP_PATHS = re.compile(
    r"(/system/|/apex/|/vendor/|/product/|/system_ext/|/odm/|/data/app/|"
    r"/data/dalvik-cache/|/data/misc/|\.so$|\.odex$|\.oat$|\.vdex$|\.art$|\.apk$|"
    r"\.ttf$|\.ttc$|\.otf$|\.jar$|/dev/zero|/memfd:jit|icudt|/dev/fastpipe|"
    r"\[vectors\]|\[vdso\]|\[vvar\]|\[vsyscall\])", re.I)

MAPS_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+(\S+)\s+(\d+)\s*(.*)$")


# ---------------------------------------------------------------------------
# adb 定位（独立实现，避免跨 skill 依赖）
# ---------------------------------------------------------------------------
def find_adb(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    name = "adb.exe" if os.name == "nt" else "adb"
    hit = shutil.which(name)
    if hit:
        return hit
    pats = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(env)
        if root:
            pats.append(os.path.join(root, "platform-tools", name))
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        if local:
            pats.append(os.path.join(local, "Android", "Sdk", "platform-tools", name))
        for b in ("C:", "D:", "E:"):
            pats += [
                b + r"\leidian\LDPlayer*\adb.exe",
                b + r"\Program Files\Nox\bin\adb.exe",
                b + r"\Program Files\Microvirt\MEmu\adb.exe",
                b + r"\Program Files\MuMu\emulator\*\adb.exe",
                b + r"\Program Files\BlueStacks_nxt\*\adb.exe",
            ]
    else:
        home = os.path.expanduser("~")
        pats += [os.path.join(home, "Android", "Sdk", "platform-tools", name),
                 "/opt/android-sdk/platform-tools/adb",
                 "/usr/lib/android-sdk/platform-tools/adb"]
    import glob
    for p in pats:
        for m in glob.glob(p):
            if os.path.isfile(m):
                return os.path.abspath(m)
    return None


class Device:
    def __init__(self, adb, serial=None, timeout=300):
        self.adb = adb
        self.serial = serial
        self.timeout = timeout

    def _prefix(self):
        return ["-s", self.serial] if self.serial else []

    def run(self, args, binary=False):
        cmd = [self.adb] + self._prefix() + args
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=self.timeout)
            if binary:
                return p.stdout
            return (p.stdout or p.stderr).decode("utf-8", "replace")
        except Exception as e:
            return b"" if binary else "[adb error] %s" % e

    def shell(self, cmd):
        return self.run(["shell", cmd])

    def exec_out(self, cmd):
        # 必须包 sh -c，否则重定向会被当成字面参数
        return self.run(["exec-out", "sh", "-c", cmd], binary=True)


# ---------------------------------------------------------------------------
# maps 解析与内存读取
# ---------------------------------------------------------------------------
def parse_maps(dev, pid):
    txt = dev.shell("cat /proc/%s/maps" % pid)
    out = []
    for line in txt.splitlines():
        m = MAPS_RE.match(line)
        if not m:
            continue
        out.append({
            "start": int(m.group(1), 16),
            "end": int(m.group(2), 16),
            "perms": m.group(3),
            "offset": int(m.group(4), 16),
            "path": (m.group(7) or "").strip(),
        })
    return out


def read_mem(dev, pid, start, size):
    """按页对齐 seek 读 /proc/<pid>/mem。偏移 0 读会 EIO，必须页对齐。"""
    if size <= 0:
        return b""
    skip = start // PAGE
    count = (size + PAGE - 1) // PAGE
    cmd = "toybox dd if=/proc/%s/mem bs=%d skip=%d count=%d 2>/dev/null" % (
        pid, PAGE, skip, count)
    return dev.exec_out(cmd)


def candidates(regions, min_mb, max_mb):
    out = []
    for r in regions:
        if "r" not in r["perms"]:
            continue
        size = r["end"] - r["start"]
        if size < min_mb * 1024 * 1024 or size > max_mb * 1024 * 1024:
            continue
        if SKIP_PATHS.search(r["path"]):
            continue
        out.append(r)
    # 匿名区域优先，其次大的优先
    out.sort(key=lambda r: (0 if not r["path"] else 1, -(r["end"] - r["start"])))
    return out


# ---------------------------------------------------------------------------
# 从一段内存里精确切出制品
# ---------------------------------------------------------------------------
def carve(blob, magics):
    hits = []
    for mg in magics:
        off = 0
        while True:
            off = blob.find(mg, off)
            if off < 0:
                break
            if off + 0x28 <= len(blob):
                # DEX 头部 0x20 处是 file_size；Hermes 用同一偏移做长度启发
                flen = int.from_bytes(blob[off + 0x20:off + 0x24], "little")
                limit = len(blob) - off + PAGE   # 容忍尾部未映射
                if 0x70 <= flen <= 300 * 1024 * 1024 and flen <= limit:
                    kind = ("dex" if mg.startswith(b"dex")
                            else "cdex" if mg.startswith(b"cdex")
                            else "hermes")
                    hits.append((kind, blob[off:off + flen], off))
            off += 4
    # 同一起点重复命中（dex\n03x 共用前缀）去重
    seen, uniq = set(), []
    for kind, data, off in hits:
        key = (kind, off, len(data))
        if key in seen:
            continue
        seen.add(key)
        uniq.append((kind, data, off))
    return uniq


def save(outdir, kind, data):
    h = hashlib.sha1(data).hexdigest()
    path = os.path.join(outdir, "%s_%s.bin" % (kind, h[:12]))
    if os.path.exists(path):
        return path, False
    with open(path, "wb") as f:
        f.write(data)
    return path, True


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="纯 root 的 Android 进程内存脱壳（DEX/CDEX/Hermes）")
    ap.add_argument("--pkg", help="目标包名（用于 pidof 查 pid）")
    ap.add_argument("--pid", type=int, help="直接指定 pid（优先于 --pkg）")
    ap.add_argument("--out", default="./memdump", help="产物目录（默认 ./memdump）")
    ap.add_argument("--magic", choices=list(MAGIC_SETS), default="all",
                    help="要找的制品类型（默认 all）")
    ap.add_argument("--head-kb", type=int, default=64,
                    help="每区头部探测字节数（默认 64KB）")
    ap.add_argument("--min-mb", type=int, default=1, help="最小候选区域（MB，默认 1）")
    ap.add_argument("--max-mb", type=int, default=400, help="最大候选区域（MB，默认 400）")
    ap.add_argument("--region", help="强制整段 dump 指定区域，格式 0xSTART-0xEND")
    ap.add_argument("--list", action="store_true", help="只列出候选区域，不读内容")
    ap.add_argument("--adb", help="adb 路径（默认自动查找）")
    ap.add_argument("--serial", help="多设备时指定 serial")
    ap.add_argument("--json", action="store_true", help="输出 JSON 摘要")
    args = ap.parse_args()

    adb = find_adb(args.adb)
    if not adb:
        print("[!] 找不到 adb，请用 --adb 指定", file=sys.stderr)
        return 3
    dev = Device(adb, args.serial)

    pid = args.pid
    if not pid:
        if not args.pkg:
            print("[!] 需要 --pkg 或 --pid", file=sys.stderr)
            return 2
        out = dev.shell("pidof " + args.pkg).strip()
        if not out:
            print("[!] 进程未运行: %s（先启动 App）" % args.pkg, file=sys.stderr)
            return 2
        pid = int(out.split()[0])

    os.makedirs(args.out, exist_ok=True)
    regions = parse_maps(dev, pid)
    cand = candidates(regions, args.min_mb, args.max_mb)
    summary = {"adb": adb, "pid": pid, "regions_total": len(regions),
               "candidates": len(cand), "artifacts": []}

    if args.list:
        print("pid=%s  regions=%d  candidates=%d" % (pid, len(regions), len(cand)))
        for r in cand:
            print("  %012x-%012x %s %8.1f MB  %s" % (
                r["start"], r["end"], r["perms"],
                (r["end"] - r["start"]) / 1048576.0, r["path"] or "[anon]"))
        if args.json:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    magics = MAGIC_SETS[args.magic]
    targets = []

    if args.region:
        m = re.match(r"^(0x)?([0-9a-fA-F]+)-(0x)?([0-9a-fA-F]+)$", args.region)
        if not m:
            print("[!] --region 格式应为 0xSTART-0xEND", file=sys.stderr)
            return 2
        targets = [{"start": int(m.group(2), 16), "end": int(m.group(4), 16),
                    "path": "[forced]"}]
    else:
        print("[*] pid=%s candidates=%d, 头部探测中…" % (pid, len(cand)))
        for r in cand:
            size = r["end"] - r["start"]
            head = read_mem(dev, pid, r["start"], min(size, args.head_kb * 1024))
            if any(mg in head for mg in magics):
                print("  [~] magic 命中头部: %s (%.1f MB) @0x%x" % (
                    r["path"] or "[anon]", size / 1048576.0, r["start"]))
                targets.append(r)

    got = 0
    for r in targets:
        size = r["end"] - r["start"]
        blob = read_mem(dev, pid, r["start"], size)
        if not blob:
            continue
        for kind, data, off in carve(blob, magics):
            path, new = save(args.out, kind, data)
            summary["artifacts"].append({
                "kind": kind, "size": len(data), "region": "0x%x" % r["start"],
                "offset": "0x%x" % off, "path": path, "sha1": hashlib.sha1(data).hexdigest(),
            })
            if new:
                got += 1
                print("      [+] %-6s %9d B  @0x%x+0x%x -> %s" % (
                    kind, len(data), r["start"], off, os.path.basename(path)))

    print("[*] 完成: %d 个新制品 -> %s" % (got, args.out))
    if not got and args.magic == "hermes":
        print("[i] Hermes 未命中通常是引擎还没初始化（RN 页面未加载）。"
              "先让 App 进入主界面再扫。")
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

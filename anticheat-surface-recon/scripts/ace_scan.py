#!/usr/bin/env python3
"""ACE 检测面测绘：对反作弊 so 做能力面统计。

只做静态事实提取，不涉及绕过：
  - 每个库导入了哪些敏感 libc 能力（ptrace / process_vm_readv / inotify …）
  - 每个库里出现了哪些检测特征字符串，按类别归并，并给出上下文
  - 哪些库真正具备"检测能力"，哪些只是载体

用法:
    python ace_scan.py libtersafe.so libtprt.so ...
    python ace_scan.py *.so --json ace.json
"""
import sys, os, json, struct, collections, re

# 每类：关键词 -> 说明。命中要求出现在 >=4 字符的可打印串里，避免随机字节误报。
CATS = {
    "调试/注入": {
        "want": ["ptrace", "PTRACE", "TracerPid", "/proc/self/status", "dbg.",
                 "23946", "27042", "gdb", "lldb", "waitpid", "PEEKTEXT", "PEEKDATA"],
        "why": "检测是否有调试器附加或进程被挂起",
    },
    "Hook 框架": {
        "want": ["frida", "Frida", "gum-js-loop", "gmain", "linjector", "re.frida",
                 "xposed", "Xposed", "XposedBridge", "epic", "YAHFA", "SandHook",
                 "Dobby", "Substrate", "cydia", "inline hook", "PLT hook", "GOT"],
        "why": "检测主流 Hook / 注入框架的残留",
    },
    "Root": {
        "want": ["/system/bin/su", "/system/xbin/su", "/sbin/su", "magisk", "Magisk",
                 "superuser", "SuperSU", "busybox", "test-keys", "ro.debuggable",
                 "ro.secure", "daemonsu", "supolicy", "sepolicy"],
        "why": "检测 root 环境（su 路径 / Magisk / 测试签名）",
    },
    "模拟器": {
        "want": ["goldfish", "ranchu", "qemu", "QEMU", "vbox", "genymotion",
                 "Genymotion", "bluestacks", "BlueStacks", "nox", "Nox",
                 "ttVM", "andy", "microvirt", "/dev/qemu_pipe", "ro.kernel.qemu"],
        "why": "检测模拟器指纹（本机 MuMu 正落在此类）",
    },
    "内存完整性": {
        "want": ["/proc/self/maps", "/proc/self/smaps", "mprotect", "mincore",
                 "memfd", "process_vm_readv", "process_vm_writev", "/proc/self/mem",
                 "kallsyms", "dl_iterate_phdr", "linker", "maps"],
        "why": "检测代码段被改写 / 外部读内存",
    },
    "多开/分身": {
        "want": ["parallel", "Parallel", "multiopen", "multi-open", "virtualapp",
                 "VirtualApp", "duokai", "app_clone", "clone"],
        "why": "检测应用分身/多开环境",
    },
    "抓包/网络": {
        "want": ["pcap", "tcpdump", "AF_PACKET", "iptables", "http_proxy",
                 "https_proxy", "vpn", "VPN", "charles", "Charles", "fiddler",
                 "mitm", "burp", "proxy"],
        "why": "检测抓包工具 / 代理 / VPN（决定我们能不能抓）",
    },
    "时间/加速": {
        "want": ["clock_gettime", "gettimeofday", "speedhack", "time jump",
                 "CLOCK_MONOTONIC"],
        "why": "检测变速齿轮 / 时间加速",
    },
    "屏幕/录屏": {
        "want": ["screencap", "MediaProjection", "screenrecord", "VirtualDisplay"],
        "why": "检测录屏/投屏（部分反作弊据此判透视）",
    },
}

SENSITIVE_IMPORTS = ["ptrace", "process_vm_readv", "process_vm_writev", "inotify_init",
                     "inotify_add_watch", "prctl", "personality", "syscall",
                     "fopen", "popen", "kill", "getppid", "readlink", "access"]


def elf_dynsym(path):
    """取 .dynsym 里的符号名（导入 + 导出）。"""
    try:
        with open(path, "rb") as f:
            h = f.read(64)
            if h[:4] != b"\x7fELF" or h[4] != 2:
                return []
            e_shoff = struct.unpack_from("<Q", h, 40)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", h, 58)
            f.seek(e_shoff + e_shstrndx * e_shentsize)
            sh = f.read(e_shentsize)
            noff, nsize = struct.unpack_from("<QQ", sh, 24)
            f.seek(noff)
            shstr = f.read(nsize)
            secs = {}
            for i in range(e_shnum):
                f.seek(e_shoff + i * e_shentsize)
                s = f.read(e_shentsize)
                nm, typ, flags, addr, off, size, link, info, align, ent = \
                    struct.unpack_from("<IIQQQQIIQQ", s, 0)
                name = shstr[nm:shstr.index(b"\x00", nm)].decode("utf-8", "replace")
                secs[name] = (off, size, link, ent)
            if ".dynsym" not in secs or ".dynstr" not in secs:
                return []
            symoff, symsize, link, ent = secs[".dynsym"]
            stroff, strsize = secs[".dynstr"][0], secs[".dynstr"][1]
            f.seek(stroff)
            strs = f.read(strsize)
            f.seek(symoff)
            raw = f.read(symsize)
            out = []
            step = ent or 24
            for i in range(len(raw) // step):
                nm = struct.unpack_from("<I", raw, i * step)[0]
                if nm == 0 or nm >= len(strs):
                    continue
                end = strs.find(b"\x00", nm)
                if end < 0:
                    continue
                out.append(strs[nm:end].decode("utf-8", "replace"))
            return out
    except Exception:
        return []


def printable_runs(data, minlen=4):
    return re.findall(rb"[ -~]{%d,}" % minlen, data)


def scan(path):
    with open(path, "rb") as f:
        data = f.read()
    runs = [r.decode("ascii", "replace") for r in printable_runs(data)]
    joined = "\n".join(runs)
    hits = {}
    for cat, spec in CATS.items():
        found = collections.Counter()
        ctx = []
        for kw in spec["want"]:
            # 整串匹配，避免 "clone" 命中 "clone3" 之类的噪音
            n = joined.count(kw)
            if n:
                found[kw] += n
                for r in runs:
                    if kw in r and len(ctx) < 3:
                        ctx.append(r[:110])
        if found:
            hits[cat] = {"counts": dict(found), "total": sum(found.values()),
                         "why": spec["why"], "context": ctx}
    syms = elf_dynsym(path)
    imp = collections.Counter(s for s in syms if s in SENSITIVE_IMPORTS)
    return {
        "file": os.path.basename(path),
        "size": len(data),
        "dynsym": len(syms),
        "sensitive_imports": dict(imp),
        "categories": hits,
        "category_totals": {k: v["total"] for k, v in hits.items()},
    }


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 1
    out_json = None
    if "--json" in sys.argv:
        out_json = sys.argv[sys.argv.index("--json") + 1]
    results = [scan(p) for p in args if os.path.exists(p)]

    L = ["# ACE / 反作弊库 检测面测绘", ""]
    L += ["| 库 | 体积 | dynsym | " + " | ".join(CATS.keys()) + " |",
          "|---|---|---|" + "|".join(["---"] * len(CATS)) + "|"]
    for r in results:
        row = ["`%s`" % r["file"], "%.1fMB" % (r["size"] / 1048576), str(r["dynsym"])]
        for c in CATS:
            t = r["category_totals"].get(c, 0)
            row.append(str(t) if t else "-")
        L.append("| " + " | ".join(row) + " |")

    for r in results:
        if not r["categories"]:
            continue
        L += ["", "## `%s`" % r["file"], ""]
        if r["sensitive_imports"]:
            L.append("敏感导入：`%s`" % "`, `".join(
                "%s×%d" % (k, v) for k, v in r["sensitive_imports"].items()))
            L.append("")
        for cat, d in sorted(r["categories"].items(), key=lambda x: -x[1]["total"]):
            L.append("**%s**（%d 处）— %s" % (cat, d["total"], d["why"]))
            L.append("")
            L.append("命中：`%s`" % "`, `".join(
                "%s×%d" % (k, v) for k, v in
                sorted(d["counts"].items(), key=lambda x: -x[1])))
            if d["context"]:
                L.append("")
                for c in d["context"]:
                    L.append("> `%s`" % c)
            L.append("")

    print("\n".join(L))
    if out_json:
        json.dump(results, open(out_json, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print("\nJSON 已写:", out_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_and_connect.py — 自动发现并连接本机安卓模拟器，封装常见 ADB 操作。

设计目标（解决的核心痛点）：
  1. 每次都要"翻箱倒柜"找 adb 可执行文件（各模拟器自带、Android SDK、PATH）。
  2. 每次都要猜模拟器监听在哪个 ADB 端口。
  3. 手动 `adb connect` + `adb devices` 反复试错。

用法：
  # 仅发现并连接，输出 JSON（可被 WorkBuddy 解析）
  python find_and_connect.py
  python find_and_connect.py --human          # 人类可读输出
  python find_and_connect.py --info --human   # 额外采集 root/ABI/su/toybox 画像

  # 透传：将 `--` 之后的参数作为 adb 子命令，自动选首个在线设备执行
  python find_and_connect.py -- install C:/path/to/app.apk
  python find_and_connect.py -- shell getprop ro.build.version.release
  python find_and_connect.py -- logcat -d | findstr Activity
  python find_and_connect.py -- -s 127.0.0.1:5555 shell pm list packages

退出码：
  0  成功（至少发现一个可用 adb，且存在在线设备时才对透传命令返回 0）
  2  未发现任何 adb 客户端
  3  未发现任何在线设备（发现 adb 但连不上模拟器）
"""
import argparse
import glob
import json
import os
import shutil
import socket
import subprocess
import sys

# ---------------------------------------------------------------------------
# 1. 已知模拟器 ADB 端口表（带语义标签，便于报告）
# ---------------------------------------------------------------------------
PORTS = [
    (5554, "Android Studio Emulator (base)"),
    (5555, "LDPlayer(雷电) / BlueStacks / 通用"),
    (62001, "Nox(夜神) 主实例"),
    (62025, "Nox(夜神) 多开 #1"),
    (62026, "Nox(夜神) 多开 #2"),
    (7555, "MuMu 主实例"),
    (16384, "MuMu12 主实例"),
    (16416, "MuMu12 多开"),
    (21503, "逍遥 / 腾讯手游助手"),
    (58001, "海马玩 Droid4X"),
]

# ---------------------------------------------------------------------------
# 2. 候选 adb 可执行文件搜索路径（按优先级）
# ---------------------------------------------------------------------------
def adb_search_globs():
    """返回跨平台 adb 搜索 glob / 固定路径列表。"""
    globs = []

    # Android SDK（环境变量优先）
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(env)
        if root:
            globs.append(os.path.join(root, "platform-tools", "adb"))

    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        if local:
            globs.append(os.path.join(local, "Android", "Sdk", "platform-tools", "adb.exe"))
        # 常见模拟器目录（覆盖 C/D/E 盘）
        bases = ["C:", "D:", "E:"]
        patterns = [
            r"{b}\leidian\LDPlayer*\adb.exe",
            r"{b}\Program Files\Nox\bin\adb.exe",
            r"{b}\Program Files (x86)\Nox\bin\adb.exe",
            r"{b}\Program Files\Microvirt\MEmu\adb.exe",
            r"{b}\Program Files\BlueStacks_nxt\*\adb.exe",
            r"{b}\Program Files\MuMu\emulator\*\adb.exe",
            r"{b}\Program Files (x86)\MuMu\emulator\*\adb.exe",
        ]
        for b in bases:
            for p in patterns:
                globs.append(p.format(b=b))
    else:
        home = os.path.expanduser("~")
        globs.append(os.path.join(home, "Android", "Sdk", "platform-tools", "adb"))
        globs.append("/opt/android-sdk/platform-tools/adb")
        globs.append("/usr/lib/android-sdk/platform-tools/adb")
    return globs


def find_adb():
    """返回 (adb_path, candidates)。优先 PATH，其次模拟器自带。"""
    # 1) PATH 中的 adb 最高优先级（版本通常最匹配系统）
    name = "adb.exe" if os.name == "nt" else "adb"
    in_path = shutil.which(name)
    if in_path:
        return in_path, [in_path]

    found = []
    seen = set()
    for pattern in adb_search_globs():
        for match in glob.glob(pattern):
            ap = os.path.abspath(match)
            if ap not in seen and os.path.isfile(ap):
                seen.add(ap)
                found.append(ap)
    if found:
        return found[0], found
    return None, []


# ---------------------------------------------------------------------------
# 3. 端口探测
# ---------------------------------------------------------------------------
def probe_port(port, host="127.0.0.1", timeout=0.4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# 4. adb 命令封装
# ---------------------------------------------------------------------------
def run_adb(adb, args, timeout=60):
    cmd = [adb] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "adb command timed out"
    except FileNotFoundError:
        return 127, "", "adb not found"


def parse_devices(stdout):
    """解析 `adb devices -l` 输出。"""
    devices = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, status = parts[0], parts[1]
        info = " ".join(parts[2:]) if len(parts) > 2 else ""
        devices.append({"serial": serial, "status": status, "info": info})
    return devices


def connect_and_list(adb):
    """连接所有监听端口并列出设备。"""
    listening = []
    for port, label in PORTS:
        if probe_port(port):
            listening.append({"port": port, "label": label})
            run_adb(adb, ["connect", f"127.0.0.1:{port}"], timeout=15)

    rc, out, err = run_adb(adb, ["devices", "-l"], timeout=20)
    devices = parse_devices(out)
    # 选择首个在线设备作为主设备
    primary = next((d["serial"] for d in devices if d["status"] == "device"), None)
    return listening, devices, primary


# ---------------------------------------------------------------------------
# 4.5 设备画像：判断"这台机器现在能不能做需要 root 的事"
# ---------------------------------------------------------------------------
def _sh(adb, serial, cmd, timeout=20):
    rc, out, err = run_adb(adb, ["-s", serial, "shell", cmd], timeout=timeout)
    return (out or err).strip()


def collect_info(adb, serial):
    """采集运行时关键属性。root=True 表示 adb shell 当前已是 uid=0。"""
    uid_raw = _sh(adb, serial, "id")
    is_root = "uid=0" in uid_raw
    props = {}
    for key in ("ro.product.cpu.abi", "ro.build.version.sdk", "ro.build.version.release",
                "ro.build.type", "ro.build.tags", "ro.debuggable", "ro.secure",
                "service.adb.root", "ro.product.model"):
        props[key] = _sh(adb, serial, f"getprop {key}")

    # su 是否落在 PATH 上（root 检测 App 的主要探测点）
    su = _sh(adb, serial, "which su 2>/dev/null || echo NONE")
    su_paths = _sh(
        adb, serial,
        "for p in /system/bin/su /system/xbin/su /sbin/su /system/sd/xbin/su "
        "/system/bin/failsafe/su /data/local/su /data/local/bin/su; do "
        "[ -e $p ] && printf '%s ' $p; done; echo")

    # 有 toybox dd 才能读 /proc/pid/mem（toolbox 的 dd 不可用）
    toybox_dd = "dd" in _sh(adb, serial, "toybox 2>/dev/null | tr ' ' '\\n' | grep -x dd")

    # /system 可写性必须用真实写探针：动态分区下 `mount -o remount,rw /system`
    # 会报 "not in /proc/mounts"（不是 read-only 字样），靠字符串判断会误判为可写。
    _sh(adb, serial, "mount -o remount,rw /system >/dev/null 2>&1; "
                     "mount -o remount,rw / >/dev/null 2>&1")
    probe = _sh(adb, serial,
                "(touch /system/bin/.adbwrite 2>/dev/null && rm -f /system/bin/.adbwrite "
                "&& echo WRITABLE) || echo READONLY")
    system_writable = "WRITABLE" in probe

    return {
        "serial": serial,
        "adb_shell_uid": uid_raw,
        "root": is_root,
        "su_in_path": su if su and su != "NONE" else None,
        "su_paths": [p for p in su_paths.split() if p],
        "toybox_dd": toybox_dd,
        "system_writable": system_writable,
        "props": props,
    }


def print_info(info):
    print(f"设备      : {info['serial']}")
    print(f"型号/ABI  : {info['props'].get('ro.product.model')} / "
          f"{info['props'].get('ro.product.cpu.abi')}")
    print(f"Android   : {info['props'].get('ro.build.version.release')} "
          f"(SDK {info['props'].get('ro.build.version.sdk')})")
    print(f"adb shell : {info['adb_shell_uid']}")
    print(f"root      : {'YES (uid=0)' if info['root'] else 'NO'}")
    print(f"su        : {info['su_in_path'] or '未在 PATH'}"
          f"  候选路径={info['su_paths'] or '无'}")
    print(f"toybox dd : {'可用' if info['toybox_dd'] else '不可用（无法读 /proc/pid/mem）'}")
    print(f"/system   : {'可写' if info['system_writable'] else '只读(dm-verity)'}")
    print(f"debuggable: {info['props'].get('ro.debuggable')}   "
          f"tags={info['props'].get('ro.build.tags')}")


# ---------------------------------------------------------------------------
# 5. 主流程
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="自动发现并连接安卓模拟器")
    parser.add_argument("--human", action="store_true", help="人类可读输出（默认 JSON）")
    parser.add_argument("--info", action="store_true",
                        help="额外采集设备画像（ABI/SDK/root/su/toybox dd//system 可写性）")
    parser.add_argument("rest", nargs="*", help="透传参数（等价于在 `--` 之后）")
    # 支持 `--` 分隔符，避免 argparse 吞掉负号开头的 adb 参数
    args, leftover = parser.parse_known_args()
    passthrough = list(args.rest) + leftover
    # 过滤掉因 nargs='*' 误吞的 '--'
    passthrough = [a for a in passthrough if a != "--"]

    adb, candidates = find_adb()
    if not adb:
        result = {
            "adb_found": False,
            "adb": None,
            "candidates": candidates,
            "error": "未在 PATH 或常见模拟器目录中找到 adb",
        }
        print(json.dumps(result, ensure_ascii=False, indent=2) if not args.human else result["error"])
        sys.exit(2)

    listening, devices, primary = connect_and_list(adb)

    result = {
        "adb_found": True,
        "adb": adb,
        "candidates": candidates,
        "listening_ports": listening,
        "devices": devices,
        "primary_device": primary,
    }

    # 透传模式：执行 adb 子命令
    if passthrough:
        if primary and "-s" not in passthrough:
            exec_args = ["-s", primary] + passthrough
        else:
            exec_args = passthrough
        rc, out, err = run_adb(adb, exec_args, timeout=120)
        if args.human:
            sys.stdout.write(out)
            if err:
                sys.stderr.write(err)
        else:
            result["passthrough"] = {
                "args": exec_args,
                "returncode": rc,
                "stdout": out,
                "stderr": err,
            }
            print(json.dumps(result, ensure_ascii=False, indent=2))
        sys.exit(0 if rc == 0 else 1)

    if not devices:
        result["error"] = "已找到 adb，但当前没有在线设备（模拟器可能未启动）"
        print(json.dumps(result, ensure_ascii=False, indent=2) if not args.human else result["error"])
        sys.exit(3)

    info = None
    if args.info and primary:
        info = collect_info(adb, primary)
        result["device_info"] = info

    if args.human:
        print(f"adb: {adb}")
        ports = ", ".join("%s(%s)" % (p["port"], p["label"]) for p in listening) or "无"
        print(f"监听端口: {ports}")
        print("设备:")
        for d in devices:
            mark = " *" if d["serial"] == primary else ""
            print(f"  {d['serial']}  [{d['status']}]  {d['info']}{mark}")
        if info:
            print("-" * 46)
            print_info(info)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()

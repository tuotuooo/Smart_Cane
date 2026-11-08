#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
env_probe.py —— 安卓环境一致性探针（防守方视角自检）

用途：在**登录任何账号之前**，判断这台设备有几个"独立破绽"会被反作弊看到。
定位：不是绕过工具，是自检工具。它回答的问题是"我这台机器的哪些特征自相矛盾"。

核心思路：单个特征不可疑，**矛盾才可疑**。
  ro.build.type=user + release-keys  → 必然是 Enforcing，若 Permissive 就是被改过
  ro.debuggable=0                    → adbd 不应是 uid=0，若是就是后门
  自称真实机型                        → 不应有 qemu.* 属性

用法：
  python env_probe.py                          # 自动找 adb + 连 127.0.0.1:7555
  python env_probe.py --serial emulator-5554
  python env_probe.py --adb "C:/Program Files/Netease/MuMu/nx_main/adb.exe" --json base.json
  python env_probe.py --diff before.json       # 与上次基线对比（关 root 前后用这个）

退出码：0 = 无高危破绽；1 = 存在高危；2 = 连不上设备
"""

import argparse
import json
import os
import re
import subprocess
import sys

ADB_CANDIDATES = [
    r"C:/Program Files/Netease/MuMu/nx_main/adb.exe",
    r"C:/Program Files/Netease/MuMu/emulator/nemu/vmonitor/bin/adb_server.exe",
    r"C:/Program Files/Netease/MuMuPlayer-12.0/shell/sdk/platform-tools/adb.exe",
    "adb",
]

# 真实 SoC 的 ro.hardware 常见值（用于判断"是不是芯片代号"）
REAL_HARDWARE_HINT = re.compile(
    r"qcom|mt\d|exynos|samsung.*exynos|kirin|hi\d|unisoc|ums\d|rk\d|s5e|sm\d|tensor|gs\d",
    re.I,
)


def find_adb(explicit=None):
    if explicit:
        return explicit
    for p in ADB_CANDIDATES:
        if p == "adb":
            continue
        if os.path.exists(p):
            return p
    return "adb"


def run(cmd, timeout=15):
    try:
        r = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"__ERR__{e}"


def sh(adb, serial, cmd, timeout=15):
    out = run([adb, "-s", serial, "shell", cmd], timeout)
    lines = [l for l in out.replace("\r", "").split("\n")]
    lines = [l for l in lines if not l.startswith("__ERR__")]
    # 去掉 adb 自己的错误行
    lines = [l for l in lines if not l.startswith("adb:") and not l.startswith("* ")]
    return "\n".join(lines).strip()


def connect(adb, serial):
    """需要连的（含冒号）先 connect；同一条进程内做，避免 adb server 被复用丢连接。"""
    if ":" in serial:
        run([adb, "connect", serial], 10)
    out = run([adb, "devices"], 10)
    return serial in out


def probe(adb, serial):
    props = {}
    for k in [
        "ro.product.brand", "ro.product.model", "ro.product.device",
        "ro.product.manufacturer", "ro.build.type", "ro.build.tags",
        "ro.debuggable", "ro.secure", "ro.build.version.release",
        "ro.build.version.sdk", "ro.kernel.qemu", "ro.hardware",
        "ro.serialno", "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
        "ro.build.description", "ro.build.fingerprint",
        "ro.product.cpu.abi", "ro.product.cpu.abilist",
        "ro.product.cpu.abilist64", "ro.product.cpu.abilist32",
    ]:
        v = sh(adb, serial, f"getprop {k}")
        props[k] = "" if v.startswith("__ERR__") else v

    d = {"props": props}

    d["which_su"] = sh(adb, serial, "which su")
    d["su_paths"] = {}
    for p in ["/system/bin/su", "/system/xbin/su", "/sbin/su",
              "/vendor/bin/su", "/system/sd/xbin/su",
              "/system/bin/.ext/.su", "/data/local/su", "/data/local/bin/su"]:
        r = sh(adb, serial, f"ls {p} 2>/dev/null || echo ABSENT")
        d["su_paths"][p] = "" if r == "ABSENT" else r

    d["getenforce"] = sh(adb, serial, "getenforce")
    d["selinux_enforce_file"] = sh(adb, serial, "cat /sys/fs/selinux/enforce 2>/dev/null")
    d["id"] = sh(adb, serial, "id")
    d["mount_system"] = sh(adb, serial, "mount 2>/dev/null | grep -E ' /system | /vendor ' | head -4")

    d["qemu_props"] = sh(
        adb, serial,
        "getprop | grep -i -E 'goldfish|ranchu|qemu|mumu|netease|nox|bluestacks|ldplayer|genymotion' | head -20",
    )
    d["cpuinfo_hw"] = sh(adb, serial, "grep -m1 -i 'hardware' /proc/cpuinfo")
    d["init_d"] = sh(adb, serial, "ls -d /system/etc/init.d 2>/dev/null || echo ABSENT")
    d["frida_port"] = sh(adb, serial, "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -c ':69A2\\|:69A3'")
    d["frida_bin"] = sh(adb, serial, "ls /data/local/tmp/frida-server /data/local/tmp/re.frida.server 2>/dev/null || echo ABSENT")
    d["xposed"] = sh(adb, serial, "ls /system/framework/XposedBridge.jar /system/lib/libxposed_art.so 2>/dev/null || echo ABSENT")
    d["magisk"] = sh(adb, serial, "ls -d /sbin/.magisk /data/adb/magisk /data/adb/modules 2>/dev/null || echo ABSENT")

    # 11. 能力探针：模拟器/root 专属设备节点与内核面可读性
    #     这一组比属性更硬 —— 属性可以伪造，设备节点和"能读到不该读的"不能
    d["dev_nodes"] = {}
    for p in ["/dev/vga_arbiter", "/dev/ttyS2", "/dev/loop-control", "/dev/uhid"]:
        r = sh(adb, serial, f"ls -d {p} 2>/dev/null || echo ABSENT")
        d["dev_nodes"][p] = "" if r == "ABSENT" else r
    d["proc_readable"] = {}
    for p in ["/proc/config.gz", "/proc/modules", "/proc/kallsyms", "/proc/kpageflags", "/proc/iomem"]:
        head = sh(adb, serial, f"head -c 1 {p} 2>/dev/null | wc -c")
        d["proc_readable"][p] = head.strip() not in ("", "0", "__ERR__")
    # /data/adb 是 Magisk 的根目录；关闭 root 开关通常**不删**它
    r = sh(adb, serial, "ls -d /data/adb 2>/dev/null || echo ABSENT")
    d["data_adb"] = "" if r == "ABSENT" else r
    return d


def analyze(d):
    """返回 [(等级, 检查项, 证据, 说明)]，等级 high/med/low"""
    p = d["props"]
    out = []
    H, M, L = "high", "med", "low"

    build_type = p.get("ro.build.type", "")
    tags = p.get("ro.build.tags", "")
    debug = p.get("ro.debuggable", "")

    # 0. CPU ABI —— 最便宜也最硬的一条，getprop 就能读，不需要任何权限
    abi = (p.get("ro.product.cpu.abi") or "").strip()
    abilist = (p.get("ro.product.cpu.abilist") or "").strip()
    if "x86" in abi:
        out.append((H, "CPU ABI 为 x86/x86_64",
                    f"abi={abi} abilist={abilist}",
                    "真实手机 ABI 必为 arm64-v8a。ABI 与机型并列出现即为硬矛盾，"
                    "且这是 getprop 级读取，反作弊几乎必查"))
    elif "arm64" in abilist and "x86" in abilist:
        out.append((M, "abilist 混有 x86", abilist, "ARM 转译层特征（houdini/ndk-translation）"))

    # 1. SELinux —— 最容易漏且最硬的一条
    en = (d.get("getenforce") or "").strip()
    if en and en.lower() != "enforcing":
        sev = H if build_type == "user" else M
        out.append((sev, "SELinux 非 Enforcing",
                    f"getenforce={en} / /sys/fs/selinux/enforce={d.get('selinux_enforce_file','')}",
                    f"与 ro.build.type={build_type} 矛盾：正式版系统必须 Enforcing。"
                    "libturinggame 有 /sys/fs/selinux/enforce 明文检测"))

    # 2. su 文件
    hits = [k for k, v in d["su_paths"].items() if v]
    if hits:
        out.append((H, "su 二进制存在", ", ".join(hits), "直接命中 su 路径表探测"))
    if d.get("which_su"):
        out.append((H, "PATH 中有 su", d["which_su"], "same"))

    # 3. adbd 身份
    ident = d.get("id", "")
    if "uid=0" in ident:
        if debug != "1":
            out.append((H, "adbd 为 root 但 ro.debuggable=0",
                        ident, "矛盾：非 debuggable 构建不应给出 root adbd"))

    # 4. 调试/签名属性
    if debug == "1":
        out.append((H, "ro.debuggable=1", debug, "userdebug/eng 构建特征，正式版必为 0"))
    if "test-keys" in tags:
        out.append((H, "test-keys 签名", tags, "非官方构建"))

    # 5. 模拟器明文
    q = (d.get("qemu_props") or "").strip()
    if q:
        out.append((H, "模拟器属性存在", q.replace("\n", " | ")[:200],
                    "qemu.* / goldfish / 厂商名等属性在真实设备上不存在"))
    if (p.get("ro.kernel.qemu") or "").strip() == "1":
        out.append((H, "ro.kernel.qemu=1", "1", "经典模拟器标志"))

    # 6. 芯片指纹
    hw = (p.get("ro.hardware") or "").strip()
    ci = (d.get("cpuinfo_hw") or "").strip()
    if hw and not REAL_HARDWARE_HINT.search(hw):
        out.append((M, "ro.hardware 不像芯片代号", f"ro.hardware={hw}",
                    "真实设备一般为 qcom/mt6xxx/exynos/kirin 等"))
    if not ci:
        out.append((L, "/proc/cpuinfo 无 hardware 行", "", "部分模拟器缺失"))

    # 7. 分区可写
    ms = (d.get("mount_system") or "")
    if re.search(r"\brw\b", ms):
        out.append((M, "/system 或 /vendor 可写", ms.replace("\n", " | ")[:200],
                    "正式版应只读"))

    # 8. 注入框架
    for key, label in [("frida_bin", "frida-server"), ("xposed", "Xposed"),
                       ("magisk", "Magisk"), ("init_d", "init.d")]:
        v = (d.get(key) or "").strip()
        if v and v != "ABSENT":
            sev = H if key in ("frida_bin", "xposed") else M
            out.append((sev, f"{label} 残留", v.replace("\n", " | ")[:160], ""))

    # 9. frida 端口
    fp = (d.get("frida_port") or "").strip()
    if fp.isdigit() and int(fp) > 0:
        out.append((H, "frida 默认端口在监听", fp, "27042/27043"))

    # 10. 机型 × 系统版本一致性（简化版）
    model = (p.get("ro.product.model") or "").strip().upper()
    sdk = (p.get("ro.build.version.sdk") or "").strip()
    # 已知机型最高 SDK（可按需扩充）
    known_max = {"SM-A5260": "33", "SM-G9910": "34", "SM-S9180": "34"}
    if model in known_max and sdk.isdigit() and sdk > known_max[model]:
        out.append((M, "机型与系统版本不匹配",
                    f"{model} 最高 Android SDK {known_max[model]}，实际 {sdk}",
                    "硬件-系统交叉校验：反作弊侧通常有设备库，这类矛盾很容易命中"))

    # 12. 能力探针结果（比属性硬：属性可伪造，设备节点不可）
    nodes = [k for k, v in (d.get("dev_nodes") or {}).items() if v]
    if "/dev/vga_arbiter" in nodes:
        out.append((H, "/dev/vga_arbiter 存在", "QEMU VGA 仲裁设备",
                    "QEMU/KVM 虚拟化专属，真实手机没有。我们已实测：封禁会话里 App "
                    "每轮巡检都会 getattr 它"))
    tty_nodes = [n for n in nodes if n.startswith("/dev/ttyS")]
    if tty_nodes:
        out.append((M, "串口设备节点存在", ", ".join(tty_nodes),
                    "模拟器暴露 ttyS*；真机通常不给出"))
    if (d.get("data_adb") or "").strip():
        out.append((H, "/data/adb 存在（Magisk 残留）", d["data_adb"].splitlines()[0][:120],
                    "关闭 root 开关不会删除此目录。我们已实测：封禁会话里 App 直接 getattr 它"))
    readable = [k for k, v in (d.get("proc_readable") or {}).items() if v]
    if readable:
        out.append((M, "内核面可读", ", ".join(readable),
                    "shell 权限比 App 宽，此项仅作参考；决定性证据要看 avc 审计里 App 是否读取成功"))

    return out


def print_report(d, findings, prev=None):
    p = d["props"]
    print("=" * 62)
    print("设备画像")
    print("=" * 62)
    for k in ["ro.product.brand", "ro.product.model", "ro.build.type",
              "ro.build.tags", "ro.debuggable", "ro.build.version.release",
              "ro.build.version.sdk", "ro.kernel.qemu", "ro.hardware"]:
        print(f"  {k:<30} {p.get(k,'') or '(空)'}")
    print(f"  {'getenforce':<30} {d.get('getenforce') or '(空)'}")
    print(f"  {'id':<30} {(d.get('id') or '')[:60]}")

    print()
    print("=" * 62)
    print(f"破绽：{len(findings)} 项")
    print("=" * 62)
    if not findings:
        print("  ✅ 未发现自相矛盾的环境特征")
    for sev, name, ev, note in sorted(findings, key=lambda x: {"high": 0, "med": 1, "low": 2}[x[0]]):
        mark = {"high": "🔴", "med": "🟠", "low": "🟡"}[sev]
        print(f"\n  {mark} [{sev.upper()}] {name}")
        if ev:
            print(f"       证据: {ev}")
        if note:
            print(f"       说明: {note}")

    high = sum(1 for f in findings if f[0] == "high")
    med = sum(1 for f in findings if f[0] == "med")
    print()
    print("-" * 62)
    if high:
        print(f"  结论：{high} 项高危 + {med} 项中危。这种状态登录账号，被判「环境异常」的概率很高。")
        print("  注意：高危项彼此独立，去掉一个不等于全清。先看下面每一项。")
    elif med:
        print(f"  结论：{med} 项中危，无高危。相对安全，但仍有特征可选。")
    else:
        print("  结论：环境干净。")

    if prev:
        print()
        print("=" * 62)
        print("与基线对比")
        print("=" * 62)
        pf = {(s, n) for s, n, _, _ in prev.get("_findings", [])}
        cf = {(s, n) for s, n, _, _ in findings}
        for s, n in sorted(pf - cf):
            print(f"  ✅ 已消除: [{s}] {n}")
        for s, n in sorted(cf - pf):
            print(f"  ⚠️  新增  : [{s}] {n}")
        if pf == cf:
            print("  无变化")

    return 0 if high == 0 else 1


def main():
    ap = argparse.ArgumentParser(description="安卓环境一致性探针")
    ap.add_argument("--adb", help="adb 路径，默认自动查找")
    ap.add_argument("--serial", default="127.0.0.1:7555", help="设备序列号/IP:端口")
    ap.add_argument("--json", help="把原始画像写入文件（作为基线）")
    ap.add_argument("--diff", help="与基线 json 对比")
    a = ap.parse_args()

    adb = find_adb(a.adb)
    if not connect(adb, a.serial):
        print(f"[x] 连不上设备 {a.serial}（adb={adb}）")
        print("    模拟器没开？或端口不对：MuMu 常见 7555 / 16384 / 5555")
        return 2

    d = probe(adb, a.serial)
    findings = analyze(d)

    prev = None
    if a.diff and os.path.exists(a.diff):
        with open(a.diff, encoding="utf-8") as f:
            prev = json.load(f)

    if a.json:
        d["_findings"] = findings
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        print(f"[i] 基线已写入 {a.json}\n")

    return print_report(d, findings, prev)


if __name__ == "__main__":
    sys.exit(main())

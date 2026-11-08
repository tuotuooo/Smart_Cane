#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ace_gate.py —— 基于实测探测清单的登录前环境门禁

设计原则：**只判定能判的，把不能判的显式标出来，不假装有结论。**

证据分层（这是整个工具的核心，也是它可信的原因）：
  L1 DAC     文件 mode/owner —— shell 侧可精确判定，与 SELinux 无关
  L2 LSM     SELinux 标签 + 强制态 —— 标签可读；策略不可读，用 AOSP 公认预期
  L3 syscall 无路径探针（netlink 特权读取等）—— 无法在 shell 侧判定

判定规则：
  DAC 就挡住的 → 真机也挡住 → 通过（与 SELinux 无关，最硬）
  DAC 放行 + Enforcing → 看策略预期（L2，略弱）
  DAC 放行 + Permissive → 一定泄露（实测可证）

用法：
  python ace_gate.py                      # 自动连设备并出判定
  python ace_gate.py --serial 127.0.0.1:7555
  python ace_gate.py --json g1.json       # 存档，供 --diff 对比
  python ace_gate.py --diff g0.json       # 与基线对比，看哪几项修好了
  python ace_gate.py --app-pid 2137       # 额外查游戏进程的 Seccomp/域/uid
"""

import argparse
import json
import os
import re
import subprocess
import sys

# ---------------------------------------------------------------- adb

ADB_CANDIDATES = [
    os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
    r"C:\platform-tools\adb.exe",
    r"C:\Program Files\Netease\MuMu\nx_main\adb.exe",
    r"C:\Program Files\Netease\MuMuPlayer-12.0\shell\adb.exe",
    "adb",
]

SERIAL = None   # None = 自动挑设备；给值则强绑


def find_adb():
    for p in ADB_CANDIDATES:
        if os.path.sep in p or "/" in p:
            if os.path.exists(p):
                return p
        else:
            try:
                subprocess.run([p, "version"], capture_output=True, timeout=10, check=True)
                return p
            except Exception:
                pass
    sys.exit("[x] 找不到 adb，用 --adb 指定")


def sh(adb, serial, cmd, timeout=40):
    full = [adb]
    if serial:
        full += ["-s", serial]
    full += ["shell", cmd]
    try:
        r = subprocess.run(full, capture_output=True, timeout=timeout)
        out = r.stdout.decode("utf-8", "replace").replace("\r", "")
        err = r.stderr.decode("utf-8", "replace").replace("\r", "")
        return out if out.strip() else err
    except subprocess.TimeoutExpired:
        return ""


def list_devices(adb):
    try:
        out = subprocess.run([adb, "devices"], capture_output=True, timeout=15)
    except Exception:
        return []
    devs = []
    for ln in out.stdout.decode("utf-8", "replace").replace("\r", "").splitlines()[1:]:
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":
            devs.append(parts[0])
    return devs


def resolve_serial(adb, want):
    """want 为空时自动挑：优先 USB 真机（不带端口号），其次任一在线设备"""
    if want:
        return ensure_connected(adb, want)
    devs = list_devices(adb)
    if not devs:
        sys.exit("[x] 没有在线设备。真机请开 USB 调试并在手机上点\"允许\"，然后 adb devices")
    usb = [d for d in devs if ":" not in d]
    if len(usb) == 1:
        return usb[0]
    if len(devs) == 1:
        return devs[0]
    if usb:
        print("[!] 多台设备，选用 %s（其余：%s）" % (usb[0], ", ".join(devs)))
        return usb[0]
    print("[!] 多台设备，选用 %s" % devs[0])
    return devs[0]


def ensure_connected(adb, serial):
    if not serial or ":" not in serial:
        return serial
    try:
        subprocess.run([adb, "connect", serial], capture_output=True, timeout=15)
    except Exception:
        pass
    out = subprocess.run([adb, "devices"], capture_output=True, timeout=15)
    txt = out.stdout.decode("utf-8", "replace")
    if serial in txt:
        return serial
    for ln in txt.splitlines()[1:]:
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device":
            return parts[0]
    return serial


# ---------------------------------------------------------------- 结构判据
# (key, 读取命令, 通过条件, 等级, 说明)
#   等级 BLOCK = 命中即判死，不必再谈别的
#        WARN  = 高度可疑，需人判断
#        INFO  = 只记录

PROPS = [
    "ro.product.cpu.abi", "ro.product.cpu.abilist", "ro.product.cpu.abilist32",
    "ro.product.cpu.abilist64", "ro.dalvik.vm.native.bridge",
    "ro.enable.native.bridge.exec", "ro.build.type", "ro.build.tags",
    "ro.debuggable", "ro.secure", "ro.product.brand", "ro.product.model",
    "ro.product.device", "ro.product.manufacturer", "ro.hardware",
    "ro.board.platform", "ro.build.version.sdk", "ro.build.version.release",
    "ro.product.first_api_level", "ro.kernel.qemu", "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked", "ro.build.fingerprint", "ro.system.build.version.sdk",
    "ro.vendor.build.version.sdk", "ro.boot.hardware", "qemu.hw.mainkeys",
    "ro.boot.qemu", "ro.boot.selinux",
]

ARM64 = re.compile(r"^arm64")
X86 = re.compile(r"x86|i686|i386")


def collect_props(adb, s):
    cmd = ";".join('printf "%%s=%%s\\n" %s "$(getprop %s)"' % (p, p) for p in PROPS)
    out = sh(adb, s, cmd)
    props = {}
    for ln in out.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            props[k.strip()] = v.strip()
    return props


def structural(props, extra):
    """返回 [(名称, 结论 PASS/FAIL/WARN/SKIP, 实测值, 说明)]"""
    r = []

    def add(name, ok, val, note):
        r.append({"check": name, "verdict": ok, "value": val, "note": note})

    abi = props.get("ro.product.cpu.abi", "")
    alist = props.get("ro.product.cpu.abilist", "")
    if not abi:
        add("主 ABI", "SKIP", "", "读不到")
    elif ARM64.match(abi) and not X86.search(alist):
        add("主 ABI", "PASS", abi, "arm64 且 abilist 无 x86")
    else:
        add("主 ABI", "FAIL", "%s | abilist=%s" % (abi, alist),
            "★架构级矛盾：真机必 arm64。改它要 resetprop(=root)，而 root 又留下 /data/adb")

    nb = props.get("ro.dalvik.vm.native.bridge", "")
    nbe = props.get("ro.enable.native.bridge.exec", "")
    if nb and nb != "0":
        add("转译层 native bridge", "FAIL", "bridge=%s exec=%s" % (nb, nbe),
            "★比 ABI 更硬：libnb/houdini 存在即说明在跑 x86 翻译，真 ARM 机为空")
    else:
        add("转译层 native bridge", "PASS", nb or "(空)", "无转译层")

    lad = extra.get("/system/lib64/libhoudini.so", "")
    if lad and lad != "ABSENT":
        add("houdini 库文件", "FAIL", lad, "★x86 转译层实体，真 ARM 机不存在")
    else:
        add("houdini 库文件", "PASS", "ABSENT", "不存在")

    enf = extra.get("__enforce__", "")
    en = extra.get("__getenforce__", "")
    if en.strip() == "Enforcing" or enf.strip() == "1":
        add("SELinux 强制态", "PASS", "%s / enforce=%s" % (en.strip(), enf.strip()), "Enforcing")
    else:
        add("SELinux 强制态", "FAIL", "%s / enforce=%s" % (en.strip(), enf.strip()),
            "★Permissive 会把整份探测清单的答案翻成\"成功\"；setenforce 1 需要 root")

    bt, tg, dbg = props.get("ro.build.type", ""), props.get("ro.build.tags", ""), props.get("ro.debuggable", "")
    if bt == "user" and "release-keys" in tg and dbg == "0":
        add("构建自洽性", "PASS", "%s/%s/debuggable=%s" % (bt, tg, dbg), "正式版三件套一致")
    else:
        add("构建自洽性", "WARN", "%s/%s/debuggable=%s" % (bt, tg, dbg),
            "非标准正式版构建")

    d = extra.get("/data/adb", "")
    if d == "ABSENT":
        add("root 残留 /data/adb", "PASS", "ABSENT", "Magisk/root 目录不存在")
    else:
        add("root 残留 /data/adb", "FAIL", d, "★目录存在即命中 root 探测")

    v = extra.get("/dev/vga_arbiter", "")
    if v == "ABSENT":
        add("虚拟化 /dev/vga_arbiter", "PASS", "ABSENT", "QEMU VGA 仲裁设备不存在")
    else:
        add("虚拟化 /dev/vga_arbiter", "FAIL", v, "★QEMU 专有节点，ARM 真机无")

    p = extra.get("/dev/port", "")
    if p == "ABSENT":
        add("虚拟化 /dev/port", "PASS", "ABSENT", "x86 I/O 端口设备不存在")
    else:
        add("虚拟化 /dev/port", "FAIL", p, "★x86 I/O 端口，ARM 真机无")

    qhit = False
    for k in ("ro.kernel.qemu", "ro.boot.qemu", "qemu.hw.mainkeys"):
        val = props.get(k, "")
        if val and val not in ("0", "false"):
            add("QEMU 属性 %s" % k, "FAIL", val, "模拟器明文属性")
            qhit = True
    if not qhit:
        add("QEMU 属性", "PASS", "(全空)", "无 qemu 痕迹")

    # ro.boot.hardware 是量产机正常属性（如 kona=SM8250），不是 QEMU 痕迹；
    # 但它必须与 ro.hardware / 机型自洽，这里只做对照记录。
    bhw, hw2 = props.get("ro.boot.hardware", ""), props.get("ro.board.platform", "")
    if bhw or hw2:
        add("ro.boot.hardware", "INFO", "boot=%s board=%s" % (bhw, hw2),
            "量产机正常属性；需与机型档位自洽（本例 SM-A5260 应为 lito/atoll，不是 kona）")

    # ---- 三条"改不了"的物理事实（2026-11-07 从 71 项清单里挖出）----
    ci = extra.get("__cpuinfo__", "")
    if not ci:
        add("CPU 架构事实", "SKIP", "", "/proc/cpuinfo 读不到")
    elif re.search(r"^(model name|vendor_id)\s*:", ci, re.M) and re.search(r"Intel|AMD|Hygon", ci):
        add("CPU 架构事实", "FAIL", ci.splitlines()[0].strip()[:60],
            "★宿主 CPU 直通：真机 cpuinfo 只有 CPU implementer 0x41 / Hardware qcom，没有 model name")
    elif "CPU implementer" in ci or "Hardware" in ci:
        add("CPU 架构事实", "PASS", ci.splitlines()[0].strip()[:60], "ARM 真机形态")
    else:
        add("CPU 架构事实", "WARN", ci.splitlines()[0].strip()[:60], "形态不明")

    avail = extra.get("__clocksrc__", "")
    cur = extra.get("__clkcur__", "").strip()
    if not cur:
        add("时钟源 clocksource", "SKIP", "", "读不到（sysfs 被挡）")
    elif "kvm-clock" in avail or "kvm-clock" in cur:
        add("时钟源 clocksource", "FAIL", "cur=%s | avail=%s" % (cur, avail),
            '★kvm-clock 表示内核自述跑在 KVM 里；真机是 arch_sys_counter')
    elif "arch_sys_counter" in cur or "arch_timer" in avail:
        add("时钟源 clocksource", "PASS", "cur=%s" % cur, "ARM 架构计时器")
    elif cur == "tsc" or "hpet" in avail:
        add("时钟源 clocksource", "WARN", "cur=%s | avail=%s" % (cur, avail),
            "x86 时钟源，非手机架构")
    else:
        add("时钟源 clocksource", "WARN", "cur=%s | avail=%s" % (cur, avail), "非常见手机取值")

    hp = extra.get("/dev/hpet", "")
    if hp == "ABSENT":
        add("x86 定时器 /dev/hpet", "PASS", "ABSENT", "HPET 不存在")
    else:
        add("x86 定时器 /dev/hpet", "FAIL", hp,
            "★HPET 是 x86 高精度定时器，ARM 真机无此节点（且 ACE 实际探测了它）")

    # ---- 包面：审计日志完全覆盖不到的一类 ----
    emu = extra.get("__emupkg__", "")
    if emu:
        add("模拟器/root 包", "FAIL", emu.replace("\n", " ")[:70],
            "★包名即自证：nemu=网易模拟器、topjohnwu=Magisk。需挂载 /system 才能删")
    else:
        add("模拟器/root 包", "PASS", "(无)", "无模拟器/root 特征包")

    oa = extra.get("__oaidpkg__", "")
    if not oa:
        add("OAID 链路", "WARN", "(缺失)",
            "TDM 实测上报 deviceInfo not found:OAID；真机应有 com.mdid.msa")
    elif "mdid" in oa.lower():
        add("OAID 链路", "PASS", oa.replace("\n", " ")[:60], "MSA 正常")
    else:
        add("OAID 链路", "WARN", oa.replace("\n", " ")[:60], "非标准 OAID 提供方（疑似伪造器）")

    hw = props.get("ro.hardware", "")
    if hw and hw[0].isupper():
        add("ro.hardware 形态", "WARN", hw, "真机填芯片代号（qcom/mt/…），不填厂商名")
    else:
        add("ro.hardware 形态", "PASS", hw, "芯片代号形态")

    sdk = props.get("ro.build.version.sdk", "")
    ssdk = props.get("ro.system.build.version.sdk", "")
    if sdk and ssdk and sdk != ssdk:
        add("SDK 一致性", "WARN", "build=%s system=%s" % (sdk, ssdk), "分区 SDK 不一致")
    else:
        add("SDK 一致性", "PASS", sdk, "一致")

    # 可选：游戏进程自身的域 / Seccomp / CapEff
    if extra.get("__pid__"):
        add("目标进程 Seccomp", extra.get("__seccomp__", "SKIP"),
            extra.get("__seccomp_val__", ""),
            "真机 app 进程 Seccomp 应为 2（启用过滤器）；0 = 无沙箱过滤")
        add("目标进程 SELinux 域", extra.get("__domain_verdict__", "SKIP"),
            extra.get("__domain__", ""),
            "真机应为 untrusted_app")
        add("目标进程 CapEff", extra.get("__capeff__verdict__", "SKIP"),
            extra.get("__capeff__", ""), "真机 app 应为 0")
    else:
        add("目标进程 Seccomp", "SKIP", "", "进程未运行，用 --app-pid 指定")

    return r


# ---------------------------------------------------------------- 路径判据
# 真机上 untrusted_app 是否应当能读到内容（AOSP 公认预期）。
# 只列"应当读不到"的；不在表内的按可读处理（公开信息，不算泄露）。
# 区分"只 stat 成功"和"真读到内容"——前者是元数据泄露，后者才是能力泄露
CONTENT_OPS = {"open", "map", "read", "execmod"}

SHOULD_BE_DENIED = {
    "/data/adb": "root 残留，真机不存在",
    "/dev/vga_arbiter": "QEMU 专有节点",
    "/dev/port": "x86 I/O 端口",
    "/dev/vcs": "虚拟控制台，Android 无",
    "/dev/vcsu": "虚拟控制台，Android 无",
    "/dev/ttyS1": "可用串口，真 SoC 少见",
    "/dev/ttyS2": "可用串口，真 SoC 少见",
    "/dev/console": "需 root 才可读",
    "/dev/mem": "物理内存直读，必禁",
    "/proc/kallsyms": "内核符号表，泄露内核地址",
    "/proc/kmsg": "内核日志",
    "/proc/iomem": "物理内存布局，DMA 外挂前置",
    "/proc/kpageflags": "物理页标志位，内存扫描前置",
    "/proc/pagetypeinfo": "物理页分布，内存扫描前置",
    "/proc/buddyinfo": "物理页碎片，内存扫描前置",
    "/proc/config.gz": "内核编译配置",
    "/proc/modules": "内核模块表，泄露 rootkit",
    "/proc/timer_list": "泄露内核地址",
    "/proc/sysrq-trigger": "内核级操作入口",
    "/proc/bootconfig": "内核启动配置",
    "/proc/keys": "内核密钥环",
    "/proc/slabinfo": "内核对象布局",
    "/dev/ashmem": "匿名共享内存，注入常用",
    "/dev/userfaultfd": "用户态缺页接管，绕过写保护",
    "/dev/uhid": "伪造 HID 设备，注入常用",
    "/dev/cpu_dma_latency": "DMA 延迟控制",
    "/dev/socket/property_service": "属性服务 socket，需特定域",
    # 属性数据区：0444 但它就是绕过 property_service 直接 dump 全部系统属性的入口，
    # untrusted_app 不应能 open/mmap（SELinux property_data_file 拒绝）
    "/dev/__properties__/*": "属性数据区，可绕过 property_service 直读全部属性",
    "/dev/binderfs/vndbinder": "binder 节点，需特定域",
}


def classify_path(p):
    """把枚举路径归一化到策略键；返回 None 表示该类是枚举项、不逐项探测"""
    if p.startswith("/dev/tty") and "枚举" in p:
        return None
    if p.startswith("/dev/vcsu"):
        return None
    if p.startswith("/dev/__properties__/"):
        return "/dev/__properties__/*"
    return p


def dac_can_read(mode):
    """> uid 10053 视角：other 位是否可读"""
    if not mode or len(mode) < 10:
        return None
    return mode[7] in ("r", "w") or mode[7] == "x" and mode[0] in ("d",)


def probe_paths(adb, s, paths):
    """一次 shell 调用拿全部 stat + label"""
    benign = [p for p in paths if "（枚举）" not in p]
    quoted = " ".join("'%s'" % p.replace("'", "") for p in benign)
    cmd = (
        'for p in %s; do '
        'm=$(stat -c "%%A|%%U|%%G" "$p" 2>/dev/null) || m=ABSENT; '
        'l=$(ls -Zd "$p" 2>/dev/null | awk "{print \\$1}"); '
        'printf "%%s\\t%%s\\t%%s\\n" "$p" "$m" "$l"; '
        'done' % quoted
    )
    out = sh(adb, s, cmd, timeout=90)
    res = {}
    for ln in out.splitlines():
        parts = ln.split("\t")
        if len(parts) < 2:
            continue
        p, m = parts[0], parts[1]
        lab = parts[2] if len(parts) > 2 else ""
        res[p] = {"mode": m, "label": lab}
    return res


def judge_paths(adb, s, inventory, selinux_enforcing):
    paths = [i["path"] for i in inventory]
    stat = probe_paths(adb, s, paths)
    rows = []
    for item in inventory:
        p = item["path"]
        key = classify_path(p)
        if key is None:
            rows.append({
                "path": p, "key": "", "ops": ",".join(item.get("ops", [])),
                "mode": "-", "label": "", "exists": True, "dac_read": None,
                "policy": "枚举项", "level": "meta", "verdict": "SKIP",
                "why": "循环枚举项，不逐项探测（数量按设备展开，无终点）",
            })
            continue
        st = stat.get(p, {"mode": "?", "label": ""})
        mode = st["mode"]
        exists = mode != "ABSENT" and mode != "?"
        can = dac_can_read(mode) if exists else None
        policy = SHOULD_BE_DENIED.get(key) or SHOULD_BE_DENIED.get(p)

        if not exists:
            verdict, why = "PASS", "不存在"
        elif can is False:
            verdict, why = "PASS", "DAC 已挡（other 位不可读）"
        elif can is None:
            verdict, why = "SKIP", "mode 解析失败"
        else:
            if selinux_enforcing:
                if policy:
                    verdict, why = "WARN", "DAC 放行，靠 SELinux 拦：%s" % policy
                else:
                    verdict, why = "PASS", "公开信息，可读无害"
            else:
                verdict = "FAIL" if policy else "PASS"
                why = ("★Permissive 下实际可读：%s" % policy) if policy else "公开信息"

        ops = set(item.get("ops", []))
        rows.append({
            "path": p, "key": key, "ops": ",".join(item.get("ops", [])),
            "mode": mode, "label": st.get("label", ""),
            "exists": exists, "dac_read": can,
            "level": "content" if ops & CONTENT_OPS else "meta",
            "policy": policy or "", "verdict": verdict, "why": why,
        })
    return rows


# ---------------------------------------------------------------- 报告

ICON = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️ ", "SKIP": "⬜", "INFO": "ℹ️ "}


def report(struct, paths, props, src):
    L = []
    L.append("# 环境门禁报告（反作弊检测面自检）\n")
    L.append("- 设备序列：`%s`" % src)
    L.append("- 路径清单：`probe_inventory.py` 产出（%d 项实测探测）" % len(paths))
    L.append("- 模型：`%s %s` / `%s` / ABI `%s`" % (
        props.get("ro.product.brand", "?"), props.get("ro.product.model", "?"),
        props.get("ro.build.version.release", "?"), props.get("ro.product.cpu.abi", "?")))
    L.append("")

    blocks = [x for x in struct if x["verdict"] == "FAIL"]
    warns = [x for x in struct if x["verdict"] == "WARN"]
    pf = [x for x in paths if x["verdict"] == "FAIL"]
    pw = [x for x in paths if x["verdict"] == "WARN"]

    L.append("## 判定\n")
    if blocks or pf:
        L.append("### ❌ NO-GO —— 不要登录，这个环境一定会被判死\n")
        L.append("硬阻断 %d 项、路径泄露 %d 项。封禁延迟实测 **3 分 23 秒**，"
                 "环境类判定不看你在干什么，登录即成立。\n" % (len(blocks), len(pf)))
    elif warns:
        L.append("### ⚠️ 有条件 GO —— 无硬阻断，但有 %d 项靠 SELinux 兜底\n" % len(warns))
    else:
        L.append("### ✅ GO —— 结构面无阻断\n")
    L.append("")

    L.append("## 一、结构判据（L1 DAC + 属性，可直接判定）\n")
    L.append("| | 判据 | 实测 | 说明 |")
    L.append("|---|---|---|---|")
    for x in struct:
        L.append("| %s | %s | `%s` | %s |" % (
            ICON.get(x["verdict"], "?"), x["check"], x["value"], x["note"]))
    L.append("")

    L.append("## 二、路径探测（%d 项，按可达性 + 泄露层级）\n" % len(paths))
    bad = [x for x in paths if x["verdict"] in ("FAIL", "WARN")]
    groups = [
        ("内容级泄露（真读到了内容）",
         [x for x in bad if x["level"] == "content"]),
        ("元数据级泄露（只 stat/connect 成功）",
         [x for x in bad if x["level"] == "meta"]),
        ("已阻断或无害",
         [x for x in paths if x["verdict"] in ("PASS", "SKIP")]),
    ]
    for title, sel in groups:
        if not sel:
            continue
        L.append("### %s（%d）\n" % (title, len(sel)))
        L.append("| | 路径 | 操作 | mode | 结论 |")
        L.append("|---|---|---|---|---|")
        for x in sorted(sel, key=lambda y: y["path"]):
            L.append("| %s | `%s` | %s | `%s` | %s |" % (
                ICON.get(x["verdict"], "?"), x["path"], x["ops"] or "-",
                x["mode"], x["why"]))
        L.append("")

    # 统计
    n_ex = sum(1 for x in paths if x["exists"])
    n_dac = sum(1 for x in paths if x["dac_read"] is False)
    n_content = len(groups[0][1])
    n_meta = len(groups[1][1])
    L.append("## 三、数字\n")
    L.append("| 项 | 值 |")
    L.append("|---|---|")
    L.append("| 清单总项 | %d |" % len(paths))
    L.append("| 路径存在 | %d |" % n_ex)
    L.append("| **DAC 已挡**（与 SELinux 无关，真机同样挡） | **%d** |" % n_dac)
    L.append("| **内容级泄露** | **%d** |" % n_content)
    L.append("| 元数据级泄露（stat 成功） | %d |" % n_meta)
    L.append("| 循环枚举项（未逐项探测） | %d |" % sum(1 for x in paths if x["verdict"] == "SKIP"))
    L.append("")
    L.append("> **内容级**：App 真的读到了内容 —— 能力泄露，最硬。")
    L.append("> **元数据级**：只证明「本应被 SELinux 拒的访问被放行了」，没读到内容，信号弱一档。")
    L.append("> **DAC 已挡**：文件权限位就挡住了，与 SELinux 无关 —— 真机同样挡，这一批永远安全。")
    L.append("")

    L.append("## 四、无法判定（必须显式承认）\n")
    L.append("| 类型 | 为什么测不到 |")
    L.append("|---|---|")
    L.append("| 无路径探针（`nlmsg_readpriv` 等） | 不碰文件系统，shell 侧无从复现，只能靠审计日志 |")
    L.append("| SELinux 策略本体 | 编译后的 policy 需 root 才能读；本工具用的是 AOSP 公认预期，非本机实际策略 |")
    L.append("| 探针全集 | 清单只包含\"MuMu 上被拒\"的访问。真机能读到的东西可能还有别的探针，不会出现在审计里 |")
    L.append("| 服务端聚合逻辑 | 哪些项组合起来算\"环境异常\"，只在服务端，客户端看不到 |")
    L.append("")
    L.append("> 这四项决定了本工具的定位：**它能否决，不能担保。** NO-GO 一定准，GO 不代表一定安全。")
    L.append("")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adb")
    ap.add_argument("--serial", default=SERIAL, help="留空=自动挑设备（优先 USB 真机）")
    ap.add_argument("--inventory", default=None,
                    help="probe_inventory.py 产出的清单 JSON；不给则只跑结构面判据")
    ap.add_argument("--json")
    ap.add_argument("--diff")
    ap.add_argument("--out")
    ap.add_argument("--app-pid", type=int)
    a = ap.parse_args()

    adb = a.adb or find_adb()
    s = resolve_serial(adb, a.serial)
    ident = sh(adb, s, "getprop ro.product.brand; getprop ro.product.model; getprop ro.build.version.release").strip().split("\n")
    print("[*] adb = %s" % adb)
    print("[*] 设备 = %s  (%s)" % (s, " / ".join(x.strip() for x in ident if x.strip()) or "?"))
    print()

    inventory = []
    if a.inventory:
        if not os.path.exists(a.inventory):
            sys.exit("[x] 找不到清单 %s" % a.inventory)
        inventory = json.load(open(a.inventory, encoding="utf-8"))

    # 结构面需要的额外读数
    extra = {}
    for p in ("/data/adb", "/dev/vga_arbiter", "/dev/port", "/system/lib64/libhoudini.so", "/dev/hpet"):
        extra[p] = sh(adb, s, "stat -c '%%A|%%U' '%s' 2>/dev/null || echo ABSENT" % p).strip() or "ABSENT"
    extra["__cpuinfo__"] = sh(adb, s, "grep -m2 -E '^(model name|vendor_id|CPU implementer|Hardware)' /proc/cpuinfo 2>/dev/null").strip()
    extra["__emupkg__"] = sh(adb, s, "pm list packages 2>/dev/null | grep -iE 'nemu|bluestacks|ldmnq|bignox|genymotion|vphone|mumu|topjohnwu|magisk' | sed 's/package://'").strip()
    extra["__oaidpkg__"] = sh(adb, s, "pm list packages 2>/dev/null | grep -iE 'mdid.msa|oaid' | sed 's/package://'").strip()
    extra["__clocksrc__"] = sh(adb, s, "cat /sys/devices/system/clocksource/clocksource0/available_clocksource 2>/dev/null").strip()
    extra["__clkcur__"] = sh(adb, s, "cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null").strip()
    extra["__getenforce__"] = sh(adb, s, "getenforce").strip()
    extra["__enforce__"] = sh(adb, s, "cat /sys/fs/selinux/enforce 2>/dev/null").strip()
    if a.app_pid:
        st = sh(adb, s, "grep -E '^(Uid|CapEff|Seccomp):' /proc/%d/status 2>/dev/null" % a.app_pid)
        dom = sh(adb, s, "cat /proc/%d/attr/current 2>/dev/null" % a.app_pid).strip()
        extra["__pid__"] = a.app_pid
        extra["__domain__"] = dom
        extra["__domain_verdict__"] = "PASS" if "untrusted_app" in dom else "FAIL"
        sec = re.search(r"Seccomp:\s*(\d+)", st)
        extra["__seccomp_val__"] = sec.group(1) if sec else "?"
        extra["__seccomp__"] = "PASS" if sec and sec.group(1) == "2" else "FAIL"
        cap = re.search(r"CapEff:\s*([0-9a-f]+)", st)
        capv = cap.group(1) if cap else "?"
        extra["__capeff__"] = capv
        extra["__capeff__verdict__"] = "PASS" if set(capv) == {"0"} else "FAIL"

    props = collect_props(adb, s)
    struct = structural(props, extra)
    enforcing = extra.get("__getenforce__", "").strip() == "Enforcing" or extra.get("__enforce__") == "1"
    paths = judge_paths(adb, s, inventory, enforcing)

    md = report(struct, paths, props, s)
    out = a.out or "GATE_REPORT.md"
    open(out, "w", encoding="utf-8").write(md)
    print(md)

    if a.json:
        json.dump({"struct": struct, "paths": paths, "props": props},
                  open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("[+] 已存档 %s" % a.json)

    if a.diff and os.path.exists(a.diff):
        old = json.load(open(a.diff, encoding="utf-8"))
        oc = {x["check"]: x["verdict"] for x in old.get("struct", [])}
        op = {x["path"]: x["verdict"] for x in old.get("paths", [])}
        print("\n## 与 %s 的差异\n" % a.diff)
        for x in struct:
            o = oc.get(x["check"])
            if o and o != x["verdict"]:
                print("  %-22s %s → %s" % (x["check"], o, x["verdict"]))
        for x in paths:
            o = op.get(x["path"])
            if o and o != x["verdict"]:
                print("  %-40s %s → %s" % (x["path"], o, x["verdict"]))
        fixed = [x["check"] for x in struct if oc.get(x["check"]) == "FAIL" and x["verdict"] != "FAIL"]
        print("\n  修好 %d 项，仍未修 %d 项" % (
            len(fixed), sum(1 for x in struct if x["verdict"] == "FAIL")))

    hard = [x for x in struct if x["verdict"] == "FAIL"] + [x for x in paths if x["verdict"] == "FAIL"]
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())

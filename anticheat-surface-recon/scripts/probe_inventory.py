#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_inventory.py — 从 SELinux 审计日志反推反作弊的探测清单

原理：App 进程每探一个路径，若该路径在真机上应被拒绝，内核就会写一条 avc 审计。
      于是 logcat 里就成了这份探测清单的**实际执行记录**，不需要 root、不需要注入。

两种探测要分开看：
  getattr  -> 只判断"存在/权限"，属**存在性探测**（模拟器设备节点、/data/adb 这类）
  open/read-> 真的读到了内容，属**能力探针**（能读内核信息 = 环境不正常）
  后者比前者硬得多：存在性可以靠隐藏骗过，能力缺失骗不过。

用法：
  python probe_inventory.py --logcat sessions/xxx/logcat.txt
  python probe_inventory.py --logcat ... --json probe_inventory.json
  python probe_inventory.py --diff old.json new.json
"""
import argparse
import json
import os
import re
import sys
from collections import OrderedDict

APP = "com.tencent.tmgp.dfm"

# avc 行样例：
# 11-07 20:27:12.880  2137  2137 I auditd  : type=1400 audit(0.0:1130): avc:  denied  { read } for
#   comm="CrashSightThrea" name="iomem" dev="proc" ino=... scontext=... tcontext=... tclass=file
#   permissive=1 app=com.tencent.tmgp.dfm
LINE = re.compile(
    r"^(?P<ts>\d\d-\d\d \d\d:\d\d:\d\d\.\d+).*?"
    r"avc:\s+denied\s+\{\s*(?P<op>\w+)\s*\}.*?"
    r'comm="(?P<comm>[^"]*)".*?'
    r'(?:path="(?P<path>[^"]*)"|name="(?P<name>[^"]*)")'
)
PERMISSIVE = re.compile(r"permissive=(\d)")

# 分类：按路径语义归组，顺序即报告顺序
CATS = [
    ("root 残留", lambda p: p.startswith("/data/adb") or p in ("su", "/system/xbin/su")),
    ("虚拟化 / 模拟器", lambda p: p in (
        "/dev/vga_arbiter", "/dev/ttyS2") or re.search(r"/dev/ttyS\d", p)
     or p.startswith("/dev/tty") or "qemu" in p or "goldfish" in p),
    ("内核信息面", lambda p: p in (
        "/proc/kallsyms", "/proc/kpageflags", "/proc/pagetypeinfo", "/proc/modules",
        "/proc/config.gz", "/proc/iomem", "/proc/misc", "/proc/bootconfig",
        "/proc/cmdline", "/proc/sysrq-trigger", "/proc/timer_list", "/proc/kmsg",
        "/proc/keys", "/proc/locks", "/proc/swaps", "/proc/cgroups")),
    ("系统指纹", lambda p: p in (
        "/proc/buddyinfo", "/proc/slabinfo", "/proc/zoneinfo", "/proc/softirqs",
        "/proc/loadavg", "/proc/uptime", "/proc/vmstat")),
    ("设备枚举", lambda p: p.startswith("/dev/") and "/__properties__/" not in p),
    ("属性区", lambda p: "/__properties__/" in p),
    ("转译层", lambda p: "houdini" in p or "ndk_translation" in p),
]

CAP_OP = {"open", "read", "map", "execmod"}

# /dev/tty0..63、/dev/vcsu0..N 是**循环枚举**，不是固定表项。归一化，避免清单被灌水。
TTY_RE = re.compile(r"^/dev/(tty|vcsu)(\d+)$")


def norm_path(p):
    m = TTY_RE.match(p)
    if m:
        return "/dev/%s<N>（枚举）" % m.group(1), p
    return p, None


def classify(p):
    for name, fn in CATS:
        try:
            if fn(p):
                return name
        except Exception:
            pass
    return "其他"


def parse(path):
    recs = []
    nonpath = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for ln in f:
            # 必须真的带 app= 字段；只靠包名匹配会把"路径里含包名"的行也算进来
            if ("app=" + APP) not in ln or "avc:" not in ln:
                continue
            m = LINE.search(ln)
            if not m:
                # 没有 path/name 的探针（如 netlink）单独收集
                om = re.search(r"avc:\s+denied\s+\{\s*(\w+)\s*\}", ln)
                if om and "auditd" in ln:
                    ts = ln[:18]
                    nonpath.append({"ts": ts, "op": om.group(1)})
                continue
            p = m.group("path") or m.group("name") or ""
            if not p:
                continue
            # 裸名（name="iomem"）与完整路径（path="/proc/iomem"）是同一探针，去掉裸名
            if "/" not in p:
                continue
            recs.append({
                "ts": m.group("ts"),
                "op": m.group("op"),
                "comm": m.group("comm"),
                "path": p,
                "permissive": (PERMISSIVE.search(ln).group(1) if PERMISSIVE.search(ln) else "?"),
            })
    return recs, nonpath


def build(recs):
    """按路径聚合：首末时间、操作集合、线程集合"""
    items = OrderedDict()
    seen = set()          # auditd 与 init 会把同一条 avc 各打一遍，先去重
    variants = {}         # 枚举类路径的具体取值
    for r in recs:
        key = (r["ts"], r["op"], r["path"])
        if key in seen:
            continue
        seen.add(key)
        np, concrete = norm_path(r["path"])
        if concrete:
            variants.setdefault(np, set()).add(concrete)
        it = items.setdefault(np, {
            "path": np, "ops": set(), "comm": set(),
            "first": r["ts"], "last": r["ts"], "n": 0, "permissive": set(),
        })
        it["ops"].add(r["op"])
        it["comm"].add(r["comm"])
        it["permissive"].add(r["permissive"])
        it["last"] = r["ts"]
        it["n"] += 1
    out = []
    for it in items.values():
        it = dict(it)
        it["ops"] = sorted(it["ops"])
        it["comm"] = sorted(it["comm"])
        it["permissive"] = sorted(it["permissive"])
        it["cat"] = classify(it["path"])
        it["cap"] = bool(set(it["ops"]) & CAP_OP)
        if it["path"] in variants:
            it["variants"] = sorted(variants[it["path"]])
        out.append(it)
    out.sort(key=lambda x: (x["first"], x["path"]))
    return out


def report(items, src, nonpath=None):
    nonpath = nonpath or []
    cap = [i for i in items if i["cap"]]
    exists = [i for i in items if not i["cap"]]
    t_first = items[0]["first"][6:] if items else "-"
    t_last = max((i["last"] for i in items), default="-")[6:]

    L = []
    L.append("# 反作弊探测清单（实测）\n")
    L.append("> 来源：`%s` 里的 SELinux avc 审计（`app=%s`）。" % (os.path.basename(src), APP))
    L.append("> 不是字符串猜测，是**内核记录下来的实际调用**。\n")
    L.append("| 项 | 值 |")
    L.append("|---|---|")
    L.append("| 唯一路径 | **%d** |" % len(items))
    L.append("| 其中「能力探针」（真读到内容） | **%d** |" % len(cap))
    L.append("| 其中「存在性探测」（只 stat） | **%d** |" % len(exists))
    L.append("| 审计条数 | %d |" % sum(i["n"] for i in items))
    L.append("| 覆盖时段 | %s → %s |" % (t_first, t_last))
    L.append("")
    L.append("**两类探测的区别**：`getattr` 只判断\"存在/权限\"，可以靠隐藏文件骗过；")
    L.append("`open`/`read`/`map` 是真把内容读出来了——**存在性可以藏，能力缺失藏不住**。\n")
    L.append("## 〇、这份清单怎么来的\n")
    L.append("**不是搜字符串，是内核替我们记的账。** 四步：\n")
    L.append("```")
    L.append("① 设备 SELinux = Permissive")
    L.append("   → App 访问一个「策略判定应拒」的目标")
    L.append("   → 内核在 LSM 层写一条 avc denied 审计，但**放行执行**")
    L.append("② 过滤 logcat：app=<包名> 且含 'avc:  denied'")
    L.append("③ 去重 + 解析：{ 操作 } / path= / name= / 线程 / 时间")
    L.append("④ 归一化：/dev/tty3,/dev/tty8… 这类循环枚举合并为 1 项")
    L.append("```\n")
    L.append("原始记录长这样（未处理的原文）：\n")
    L.append("```")
    L.append('11-07 20:27:48.640  2137  2137 I auditd : type=1400 audit(0.0:1749):')
    L.append('  avc:  denied  { getattr } for  comm="Thread-186" path="/data/adb"')
    L.append('  scontext=u:r:untrusted_app:s0:c53,c256,c512,c768')
    L.append('  tcontext=u:object_r:adb_data_file:s0 tclass=dir permissive=1')
    L.append('  app=com.tencent.tmgp.dfm')
    L.append("```\n")
    L.append("逐字段：`{ getattr }` = 只 stat 没读；`path=` = 目标；`comm=` = 探测线程；")
    L.append("`scontext` = 谁在问（App 的 SELinux 域）；`tcontext` = 目标的标签；")
    L.append("`permissive=1` = 内核判了拒绝但没执行拒绝；`app=` = 归因到哪个包。\n")
    L.append("**为什么信这份清单**：审计是 LSM 层写的，App 侧无法伪造、无法删除（除非改内核）。")
    L.append("它记的是 syscall 事实，不是 App 的自述。\n")
    L.append("### 去重是必须的，否则数字会翻倍\n")
    L.append("同一事件被 `auditd` 和 `init` 各打一遍（实测：`/data/adb` 在 20:27:48 只有 1 条，")
    L.append("之后每次出现 2 条）。直接 `grep -c` 会算成两倍，本工具按时间+路径+操作去重。\n")
    L.append("### 三个漏项来源（为什么 64 项不是全集）\n")
    L.append("| 漏什么 | 原因 | 后果 |")
    L.append("|---|---|---|")
    L.append("| 策略**允许**的访问 | 不产生 avc 记录 | `/proc/cpuinfo`、sysfs、读系统属性（走 socket）、`pm list packages` 全都不在表里 |")
    L.append("| 别的域代劳 | 审计按 `scontext` 归因 | App 通过 binder 让系统服务代读，记的是那个服务的域，不是 `app=` |")
    L.append("| 无文件对象的探针 | 没有 `path=` | `nlmsg_readpriv` 这类 netlink 调用只能靠 `tclass` 认出来 |")
    L.append("")
    L.append("**所以 64 项是「文件面」子集。** 属性面/包面/CPU 面必须另外补——")
    L.append("`ace_gate.py` 里那 13 条硬阻断，有一半是从这个缺口手工补出来的。\n")
    L.append("### 一个反向偏差：这份清单可能比真机**更长**\n")
    L.append("permissive 不只\"记录了本应被拒的访问\"，它还**让探测继续往下走**。")
    L.append("真机上 `open(\"/proc/iomem\")` 被拒后，程序可能就此打住；")
    L.append("permissive 下它拿到了 fd，可能继续读、继续进更深的分支。\n")
    L.append("> 结论：这 64 项 = 「在这台 permissive 机器上、这个进程、被 LSM 拒绝的文件访问的去重集合」。")
    L.append("> 对「它查过什么」是**可靠的下界**，对「它总共查什么」**不是全集**。\n")

    # 能力探针单列，这是最硬的一组
    L.append("## 一、能力探针（真读到内容，%d 项）\n" % len(cap))
    L.append("| 路径 | 操作 | 首次 | 线程 |")
    L.append("|---|---|---|---|")
    for i in cap:
        L.append("| `%s` | %s | %s | %s |" % (
            i["path"], "/".join(i["ops"]), i["first"][6:], ",".join(i["comm"])[:40]))
    L.append("")

    L.append("## 二、存在性探测（只 stat，%d 项）\n" % len(exists))
    bycat = OrderedDict()
    for i in exists:
        bycat.setdefault(i["cat"], []).append(i)
    for cat in [c for c, _ in CATS] + ["其他"]:
        if cat not in bycat:
            continue
        L.append("### %s（%d）\n" % (cat, len(bycat[cat])))
        L.append("| 路径 | 首次 | 次数 |")
        L.append("|---|---|---|")
        for i in bycat[cat]:
            extra = ""
            if i.get("variants"):
                extra = "（实测枚举 %d 个：`%s`）" % (
                    len(i["variants"]), "` `".join(i["variants"][:8]))
            L.append("| `%s` %s | %s | %d |" % (i["path"], extra, i["first"][6:], i["n"]))
        L.append("")

    if nonpath:
        agg = OrderedDict()
        for r in nonpath:
            agg.setdefault(r["op"], [0, r["ts"]])
            agg[r["op"]][0] += 1
        L.append("## 三、无路径探针（netlink / 系统调用层，%d 次）\n" % len(nonpath))
        L.append("| 操作 | 次数 | 首次 | 含义 |")
        L.append("|---|---|---|---|")
        note = {
            "nlmsg_readpriv": "netlink 读路由/网卡的**特权**信息 → 枚举虚拟网卡",
            "sys_admin": "挂载/命名空间能力",
            "ptrace": "调试/注入能力",
            "setenforce": "改 SELinux 状态",
        }
        for op, (n, ts) in agg.items():
            L.append("| `%s` | %d | %s | %s |" % (op, n, ts[6:], note.get(op, "")))
        L.append("")

    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logcat", required=True)
    ap.add_argument("--json")
    ap.add_argument("--out")
    a = ap.parse_args()
    if not os.path.exists(a.logcat):
        sys.exit("[x] 找不到 %s" % a.logcat)
    recs, nonpath = parse(a.logcat)
    if not recs and not nonpath:
        sys.exit("[x] 没有解析到 avc 记录（确认日志里有 app=%s 且 SELinux 为 permissive）" % APP)
    items = build(recs)
    md = report(items, a.logcat, nonpath)
    dst = a.out or os.path.join(os.path.dirname(a.logcat) or ".", "PROBE_INVENTORY.md")
    open(dst, "w", encoding="utf-8").write(md)
    print(md)
    print("[*] 已写 %s" % dst)
    if a.json:
        json.dump(items, open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("[*] 已写 %s" % a.json)


if __name__ == "__main__":
    main()

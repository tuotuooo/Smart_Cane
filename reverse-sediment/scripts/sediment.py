#!/usr/bin/env python3
"""sediment.py — 逆向结论沉淀器：校验 -> 冲突召回 -> 归属 -> 渲染 -> 索引

设计原则：**这不是总结生成器，是结论审查器。**
  脚本不负责"想出结论"（那靠人/AI），只负责把不合格的结论挡在门外：
    · 每条结论必须有可执行的复现方法（verify），没有就不许进 skill
    · 置信度必须三选一：confirmed / suspected / refuted
    · refuted（已推翻）必须写清"当初怎么判的 + 为什么错"，否则拒收
    · 与现有 skill 里的旧结论做冲突召回，逼人二选一

为什么已推翻的结论必须保留：
  同一个错误常量会级联出整串假结论。下次换个会话、换个人，
  从同一个常量出发还会推出同一个错。**推翻记录才是防重犯的资产。**

子命令：
  template   生成 claims.json 空模板
  check      校验（卡点一：置信度与证据完整性）
  conflict   冲突召回（卡点二：跟现有 skill 里的旧结论撞不撞）
  route      归属建议（卡点三：该进哪个 skill，先合并还是新建）
  render     渲染成 markdown 片段（卡点四：成文）
  index      扫全部 skill 生成总览表（用来"汇源到一起"）
  all        check + conflict + route + render 一条龙

用法：
  python sediment.py template -o claims.json
  python sediment.py check    claims.json
  python sediment.py conflict claims.json --root ~/.workbuddy/skills
  python sediment.py render   claims.json -o out/
  python sediment.py index    --root ~/.workbuddy/skills
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

CONFIDENCE = ("confirmed", "suspected", "refuted")

# ---------------------------------------------------------------- 归属路由表
# 顺序有讲究：越具体的越靠前。先命中先返回。
ROUTES = [
    (("脱壳", "内存dump", "内存 dump", "/proc/pid/mem", "frida", "memdump", "dumpdex", "加固壳"),
     "apk-runtime-dump"),
    (("https", "抓包", "证书", "mitmproxy", "ca 证书", "tls", "sni", "h2"),
     "android-https-capture"),
    (("模拟器", "adb", "logcat", "am start", "pm install", "雷电", "emulator"),
     "android-emulator-adb"),
    (("ble", "gatt", "蓝牙", "广播", "特征值", "spp", "串口", "固件", "ota", "刷机",
      "mcu", "soc", "uart", "swd", "spi", "i2c", "表盘", "手环", "手表"),
     "ble-device-recon"),
    (("apk", "dex", "manifest", "smali", "flutter", "so 文件", "jadx", "资源", "签名", "重打包"),
     "apk-analyzer"),
    (("方法", "方法论", "决策树", "判据", "通用", "流程", "原则", "教训", "误判"),
     "apk-reverse-master"),
]


def ngrams(s: str, n: int = 3) -> set:
    s = re.sub(r"\s+", "", s or "")
    if len(s) < n:
        return {s} if s else set()
    return {s[i:i + n] for i in range(len(s) - n + 1)}


def jaccard(a: str, b: str) -> float:
    A, B = ngrams(a), ngrams(b)
    if not A or not B:
        return 0.0
    return len(A & B) / len(A | B)


# ---------------------------------------------------------------- 读取与校验
def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check(data: dict) -> tuple[list, list]:
    """返回 (errors, warnings)。errors 非空就拒绝入库。"""
    err, warn = [], []
    claims = data.get("claims") or []
    if not claims:
        err.append("claims 为空：没有结论就没有可沉淀的东西")
    if not data.get("project"):
        warn.append("缺少 project 字段（建议填项目名，方便回溯）")

    seen = set()
    for i, c in enumerate(claims, 1):
        tag = f"[{i}] {str(c.get('claim', ''))[:34]}"
        if not c.get("claim"):
            err.append(f"[{i}] claim 为空")
            continue
        if len(c["claim"]) > 220:
            warn.append(f"{tag}… 超过 220 字，建议拆成多条")

        conf = c.get("confidence")
        if conf not in CONFIDENCE:
            err.append(f"{tag}… confidence={conf!r} 不合法，只能是 {CONFIDENCE}")
            continue

        ev = [e for e in (c.get("evidence") or []) if str(e).strip()]
        if not ev:
            err.append(f"{tag}… 缺 evidence：结论必须有至少一条证据")
        if conf == "refuted" and len(ev) < 2:
            err.append(f"{tag}… 已推翻的结论至少需要两条证据："
                       f"①当初是怎么判的 ②为什么那个判断错了")

        verify = str(c.get("verify") or "").strip()
        if not verify:
            err.append(f"{tag}… 缺 verify：**没有可复现验证方法的结论不许进 skill**。"
                       f"写一条能跑的命令，或写清可观察的现象")
        elif len(verify) < 8:
            warn.append(f"{tag}… verify 太短，换个人大概率复现不出来")

        if conf == "refuted":
            if not str(c.get("why_wrong") or "").strip():
                err.append(f"{tag}… 已推翻但没写 why_wrong："
                           f"不写清为什么错，下次还会从同一个错误推出同一个结论")
            if not str(c.get("was") or "").strip():
                err.append(f"{tag}… 已推翻但没写 was：当初被当成什么了？")

        if not c.get("target"):
            warn.append(f"{tag}… 缺 target，走 route 自动推断")

        key = re.sub(r"\s+", "", c["claim"])[:60]
        if key in seen:
            warn.append(f"{tag}… 与前面的结论高度重复，考虑合并")
        seen.add(key)

    return err, warn


# ---------------------------------------------------------------- 冲突召回
def skill_corpus(root: Path) -> list:
    """把每个 skill 的 md 拆成 (skill, 文件, 行号, 文本)，跳过代码块。"""
    rows = []
    for md in sorted(root.glob("*/**/*.md")):
        skill = md.relative_to(root).parts[0]
        try:
            lines = md.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        in_code = False
        for n, line in enumerate(lines, 1):
            if line.strip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                continue
            t = line.strip().lstrip("-*|># ").strip()
            if len(t) < 12 or t.startswith("|") or set(t) <= set("-: "):
                continue
            rows.append((skill, md.name, n, t))
    return rows


def conflict(data: dict, root: Path, thr: float = 0.32, topk: int = 3) -> list:
    corpus = skill_corpus(root)
    out = []
    for c in data.get("claims") or []:
        claim = c.get("claim", "")
        scored = []
        for skill, fn, n, text in corpus:
            s = jaccard(claim, text)
            if s >= thr:
                scored.append((s, skill, fn, n, text))
        scored.sort(reverse=True)
        out.append((claim, scored[:topk]))
    return out


# ---------------------------------------------------------------- 归属
def route(text: str, existing: set) -> str:
    low = text.lower()
    best, best_hits = None, 0
    for kws, skill in ROUTES:
        hits = sum(1 for k in kws if k in low)
        if hits > best_hits and skill in existing:
            best, best_hits = skill, hits
    return best or "apk-reverse-master"


def existing_skills(root: Path) -> set:
    if not root.is_dir():
        return set()
    return {p.name for p in root.iterdir() if p.is_dir() and (p / "SKILL.md").exists()}


# ---------------------------------------------------------------- 渲染
def render(data: dict, outdir: str = None) -> dict:
    """按 target 分组渲染。返回 {target: markdown}"""
    groups = {}
    for c in data.get("claims") or []:
        groups.setdefault(c.get("target") or "未归类", []).append(c)

    docs = {}
    for target, items in groups.items():
        buf = []
        title = data.get("project", "未命名项目")
        buf.append(f"<!-- sediment: {title} @ {data.get('date', '')} -->")
        buf.append("")

        ok = [c for c in items if c.get("confidence") == "confirmed"]
        maybe = [c for c in items if c.get("confidence") == "suspected"]
        dead = [c for c in items if c.get("confidence") == "refuted"]

        for sec, items2 in (("", ok), ("待验（有一致证据但未闭合）", maybe)):
            if not items2:
                continue
            if sec:
                buf.append(f"### {sec}")
                buf.append("")
            for c in items2:
                buf.append(f"**{c['claim']}**")
                buf.append("")
                for e in c.get("evidence") or []:
                    buf.append(f"- 证据：{e}")
                buf.append(f"- 复现：`{c['verify']}`")
                if c.get("note"):
                    buf.append(f"- 备注：{c['note']}")
                buf.append("")

        if dead:
            buf.append("### 已推翻（勿再采信）")
            buf.append("")
            buf.append("> 保留这些记录的目的不是存档，是防止下次从同一个错误的起点"
                       "推出同一个结论。")
            buf.append("")
            for c in dead:
                buf.append(f"**~~{c['claim']}~~**")
                buf.append("")
                buf.append(f"- 当初被当成：{c['was']}")
                for e in c.get("evidence") or []:
                    buf.append(f"- 证据：{e}")
                buf.append(f"- 为什么错：{c['why_wrong']}")
                buf.append(f"- 怎么证伪的：`{c['verify']}`")
                buf.append("")

        docs[target] = "\n".join(buf).rstrip() + "\n"

    if outdir:
        os.makedirs(outdir, exist_ok=True)
        for target, md in docs.items():
            name = (target.replace("/", "__").replace(".md", "") + ".sediment.md")
            p = os.path.join(outdir, name)
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(md)
        print(f"[+] 已写出 {len(docs)} 个片段到 {outdir}")
        for target in docs:
            print(f"    {target}")

    return docs


# ---------------------------------------------------------------- 索引
def index(root: Path) -> str:
    buf = ["| skill | 用途 | references | scripts |", "|---|---|---|---|"]
    if not root.is_dir():
        return "\n".join(buf + [f"| （root 不存在：{root}） | | | |"])
    for d in sorted(root.iterdir()):
        sk = d / "SKILL.md"
        if not d.is_dir() or not sk.exists():
            continue
        try:
            text = sk.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        m = re.search(r"^description:\s*(.+)$", text, re.M)
        if not m:
            m = re.search(r"^>\s*(.+)$", text, re.M)
        desc = (m.group(1) if m else "").strip().strip("\"'")
        if len(desc) > 60:
            desc = desc[:58] + "…"
        nr = len(list((d / "references").glob("*.md"))) if (d / "references").is_dir() else 0
        ns = len(list((d / "scripts").glob("*.py"))) if (d / "scripts").is_dir() else 0
        buf.append(f"| `{d.name}` | {desc} | {nr} | {ns} |")
    return "\n".join(buf)


TEMPLATE = {
    "project": "",
    "date": "",
    "source": "",
    "claims": [
        {
            "claim": "一句话把结论说死（不要写'可能是'，置信度字段会表达不确定）",
            "confidence": "confirmed",
            "evidence": ["实测/日志/反汇编/抓包 —— 具体到能被人复核"],
            "verify": "python scripts/xxx.py --arg ...   # 或一条可观察步骤",
            "target": "",
            "section": "",
            "note": "",
        },
        {
            "claim": "曾经确信但后来被推翻的结论",
            "confidence": "refuted",
            "was": "当初被当成什么了",
            "evidence": ["当初是怎么判的", "后来什么证据推翻了它"],
            "why_wrong": "错误链条是什么：哪个常量/前提错了，导致后面全错",
            "verify": "怎么证伪的",
            "target": "",
            "section": "已推翻",
        },
    ],
}


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(
        description="逆向结论沉淀器：先卡质量，再成文")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("template", help="生成 claims.json 空模板")
    p.add_argument("-o", "--out", default="claims.json")

    p = sub.add_parser("check", help="校验结论质量")
    p.add_argument("claims")

    p = sub.add_parser("conflict", help="与现有 skill 做冲突召回")
    p.add_argument("claims")
    p.add_argument("--root", default=str(Path.home() / ".workbuddy" / "skills"))
    p.add_argument("--thr", type=float, default=0.32)

    p = sub.add_parser("route", help="推断归属 skill")
    p.add_argument("claims")
    p.add_argument("--root", default=str(Path.home() / ".workbuddy" / "skills"))

    p = sub.add_parser("render", help="渲染 markdown 片段")
    p.add_argument("claims")
    p.add_argument("-o", "--out", default=None)

    p = sub.add_parser("index", help="生成全部 skill 总览表")
    p.add_argument("--root", default=str(Path.home() / ".workbuddy" / "skills"))

    p = sub.add_parser("all", help="check + conflict + route + render")
    p.add_argument("claims")
    p.add_argument("--root", default=str(Path.home() / ".workbuddy" / "skills"))
    p.add_argument("-o", "--out", default=None)

    a = ap.parse_args()
    root = Path(os.path.expanduser(
        getattr(a, "root", str(Path.home() / ".workbuddy" / "skills"))))

    if a.cmd == "template":
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(TEMPLATE, f, ensure_ascii=False, indent=2)
        print(f"[+] 模板已写出 {a.out}")
        return 0

    if a.cmd == "index":
        print(index(root))
        return 0

    data = load(a.claims)

    if a.cmd in ("check", "all"):
        err, warn = check(data)
        for w in warn:
            print(f"[!] {w}")
        for e in err:
            print(f"[X] {e}")
        if err:
            print(f"\n拒绝入库：{len(err)} 个必填项缺失。补齐再跑一次。")
            if a.cmd == "check":
                return 1
        else:
            print(f"\n[+] 校验通过：{len(data.get('claims') or [])} 条结论")

    if a.cmd in ("conflict", "all"):
        print("\n=== 冲突召回（只是提示，判定由人来做）===")
        res = conflict(data, root, getattr(a, "thr", 0.32))
        hit = False
        for claim, scored in res:
            if not scored:
                continue
            hit = True
            print(f"\n? {claim}")
            for s, skill, fn, n, text in scored:
                print(f"    {s:.2f}  {skill}/{fn}:{n}  {text[:70]}")
        if hit:
            print("\n上面如果撞到了**旧结论**，必须二选一：")
            print("  · 新证据更强 -> 把旧的标成 refuted，写清 why_wrong")
            print("  · 只是补充   -> 合并成一条，别让同一知识点散在两处")
        else:
            print("与现有 skill 无高相似度旧结论，属新增。")

    if a.cmd in ("route", "all"):
        exist = existing_skills(root)
        print("\n=== 归属建议 ===")
        for c in data.get("claims") or []:
            if c.get("target"):
                continue
            t = route(c.get("claim", "") + " " + " ".join(c.get("evidence") or []), exist)
            c["target"] = t
            print(f"  -> {t}  : {c.get('claim','')[:50]}")
        if not any(not x.get("target") for x in data.get("claims") or []):
            print("  （全部已有 target，未改动）")

    if a.cmd in ("render", "all"):
        print("\n=== 渲染 ===")
        render(data, a.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())

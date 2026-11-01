#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hermes 字节码（HBC）反汇编结果的后处理索引器。

**定位**：`apk_analyze.py bundle` 只判定「是不是未加密 HBC」；真要拿到 JS 逻辑，需要
先用外部反汇编器产出文本，本脚本把那份文本加工成可查询的业务情报。

依赖关系（两步走）：
  1) 反汇编（外部，非本 skill 自带）：
       hermes-dec（https://github.com/P1sec/hermes-dec，AGPL-3.0，纯标准库）
         PYTHONPATH=<hermes-dec>/src python -m hermes_dec.disassembly.hbc_disassembler \\
             main.jsbundle > main.disasm.txt
     注意：hermes-dec 自带 hbc51~hbc99 的 opcode 表，需与样本 `version` 字段匹配。
  2) 索引（本脚本，纯标准库）：
       python hbc_index.py main.disasm.txt -o js_out/

输入：hbc_disassembler 的文本输出（`=> [Function #N "..."]` 分节 + `# String: '...'` 注解）
输出：
  strings_all.txt   被指令引用的唯一字符串（含 kind 与引用函数数）
  modules.txt       Metro 模块路径（业务结构；生产包常被剥离只剩个位数）
  endpoints.txt     URL / 域名 / API 路径
  keyfuncs.txt      按 auth/risk/network/storage/update/deeplink 分组定位到函数号
  summary.json      统计汇总

用法：
  python hbc_index.py main.disasm.txt -o js_out/

⚠️ 已踩过的坑：
  * **不要**用「裸打印扫描」代替字符串表——会把相邻字符串粘连成一条，造出
    `oauth2` / `one_login` 这类看似合理、实则 0 命中的假串。本脚本读的是反汇编器
    已按 string table 正确解码的注解，不会有此问题。
  * 定位到函数号后，直接在 `main.disasm.txt` 里 grep `[Function #N` 即可读该函数指令序列。
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict

# 函数头：  ==> [Function #123 "name" of 77066 bytes]: 1 params, frame size=19, ... @ offset 0x00108a5c
RE_FUNC = re.compile(r'^=*>\s*\[Function #(\d+)\s+"([^"]*)"\s+of\s+(\d+)\s+bytes\]:\s*(\d+)\s+params.*?frame size=(\d+).*?@ offset (0x[0-9a-fA-F]+)')
# 指令里的字符串： # String: 'xxx' (Identifier)
RE_STR = re.compile(r"#\s*String:\s*'(.*)'\s*\((String|Identifier|Predefined)\)\s*$")

# ---- 归类规则 ----
RE_URL = re.compile(r'https?://[^\s\'"<>()]+', re.I)
RE_HOST = re.compile(r'^[a-z0-9][a-z0-9.-]{2,}\.(com|cn|net|org|io|co|me|tv|xyz|top|cc|app|dev|link|site)(/|$)', re.I)
RE_MODPATH = re.compile(r'^(?:\./)?(?:node_modules/)?[\w@][\w@./-]*\.(?:js|jsx|ts|tsx|json)$')
RE_APIPATH = re.compile(r'^/(?:api|v\d|oauth|user|account|login|auth|gacha|game|card|album|char|building|wiki)/', re.I)

# 关键词分组：用来定位「哪个函数负责什么」
KEYWORD_GROUPS = {
    "auth": [
        "oauth", "token", "login", "logout", "refresh", "authorize", "grant",
        "cookie", "credential", "session", "signin", "captcha", "geetest",
        "one_login", "onelogin", "phone", "sms", "verify_code",
    ],
    "risk": [
        "root", "magisk", "frida", "xposed", "emulator", "jailbreak", "hook",
        "tamper", "signature", "integrity", "attest", "safetynet", "risk",
        "deviceid", "fingerprint", "blackbox", "secneo", "detect",
    ],
    "network": [
        "http", "request", "response", "interceptor", "axios", "fetch",
        "timeout", "retry", "header", "cookie", "dns", "httpdns", "oss",
    ],
    "storage": [
        "mmkv", "asyncstorage", "sqlite", "realm", "preferences", "cache",
        "localstorage", "keychain",
    ],
    "update": [
        "codepush", "hotupdate", "bundle", "version", "upgrade", "download",
        "appcenter", "expo-updates",
    ],
    "deeplink": [
        "skland://", "scheme", "deeplink", "universal link", "url_scheme",
        "getinitialurl", "addEventListener(\"url\")",
    ],
}


def parse(path):
    """返回 (functions, string_refs)。functions: id -> dict；string_refs: str -> set(func_id)"""
    functions = {}
    string_refs = defaultdict(set)
    kinds = {}
    cur = None
    cur_id = -1
    bad = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = RE_FUNC.match(line)
            if m:
                cur_id = int(m.group(1))
                functions[cur_id] = {
                    "name": m.group(2),
                    "bytecode_size": int(m.group(3)),
                    "params": int(m.group(4)),
                    "frame_size": int(m.group(5)),
                    "offset": m.group(6),
                    "strings": [],
                }
                cur = functions[cur_id]
                continue
            if cur is None:
                continue
            ms = RE_STR.search(line)
            if ms:
                s = ms.group(1)
                # 反转义：\' \\ \" \n \t
                s = s.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
                s = s.replace("\\n", "\n").replace("\\t", "\t")
                if len(s) > 400:
                    s = s[:400]
                cur["strings"].append(s)
                string_refs[s].add(cur_id)
                kinds[s] = ms.group(2)
            elif line.startswith("=>") and "# String" in line:
                bad += 1
    return functions, string_refs, kinds, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("disasm")
    ap.add_argument("-o", "--out", default="js_out")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    print("[*] 解析反汇编 …", file=sys.stderr)
    functions, string_refs, kinds, bad = parse(args.disasm)
    print(f"[*] 函数 {len(functions)} / 唯一字符串 {len(string_refs)} / 未解析串行 {bad}", file=sys.stderr)

    # ---- 1. 全部字符串 ----
    with open(os.path.join(args.out, "strings_all.txt"), "w", encoding="utf-8") as f:
        f.write(f"# 函数总数: {len(functions)}\n# 唯一字符串: {len(string_refs)}\n\n")
        for s, fids in sorted(string_refs.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            one = s.replace("\n", "\\n").replace("\t", "\\t")
            f.write(f"{len(fids):6d}  {kinds.get(s,'?'):10s}  {one}\n")

    # ---- 2. Metro 模块路径 ----
    mods = sorted(s for s in string_refs if RE_MODPATH.match(s))
    with open(os.path.join(args.out, "modules.txt"), "w", encoding="utf-8") as f:
        f.write(f"# Metro 模块路径 {len(mods)} 条\n\n")
        for s in mods:
            f.write(f"{len(string_refs[s]):5d}  {s}\n")

    # ---- 3. 端点 ----
    urls, hosts, apipaths = set(), set(), set()
    for s in string_refs:
        for u in RE_URL.findall(s):
            urls.add(u)
        if RE_HOST.match(s):
            hosts.add(s.split("/")[0])
        if RE_APIPATH.match(s):
            apipaths.add(s)
    with open(os.path.join(args.out, "endpoints.txt"), "w", encoding="utf-8") as f:
        f.write(f"# URL {len(urls)} / 主机 {len(hosts)} / API 路径 {len(apipaths)}\n\n")
        f.write("## URL\n")
        for u in sorted(urls):
            f.write(f"  {u}\n")
        f.write("\n## 主机\n")
        for h in sorted(hosts):
            f.write(f"  {h}\n")
        f.write("\n## API 路径\n")
        for p in sorted(apipaths):
            f.write(f"  {p}\n")

    # ---- 4. 关键词函数定位 ----
    # 对每个函数，统计它命中的关键词组
    func_hits = defaultdict(lambda: defaultdict(set))
    for s, fids in string_refs.items():
        low = s.lower()
        for grp, kws in KEYWORD_GROUPS.items():
            for kw in kws:
                if kw in low:
                    for fid in fids:
                        func_hits[fid][grp].add(kw)
    with open(os.path.join(args.out, "keyfuncs.txt"), "w", encoding="utf-8") as f:
        for grp in KEYWORD_GROUPS:
            ids = sorted([i for i, g in func_hits.items() if grp in g],
                         key=lambda i: -len(functions[i]["strings"]))
            f.write(f"\n### 分组 {grp}: {len(ids)} 个函数\n")
            for i in ids[:40]:
                fn = functions[i]
                kws = ",".join(sorted(func_hits[i][grp])[:8])
                f.write(f"\n[Function #{i} \"{fn['name']}\" size={fn['bytecode_size']} params={fn['params']} @{fn['offset']}]\n")
                f.write(f"  keywords: {kws}\n")
                seen = []
                for s in fn["strings"]:
                    t = s.strip()
                    if len(t) < 3 or t in seen:
                        continue
                    if any(k in t.lower() for k in KEYWORD_GROUPS[grp]):
                        seen.append(t)
                    if len(seen) >= 12:
                        break
                for t in seen:
                    f.write(f"    - {t[:160]}\n")

    # ---- 5. 汇总 ----
    summary = {
        "functions": len(functions),
        "unique_strings": len(string_refs),
        "module_paths": len(mods),
        "urls": len(urls),
        "hosts": len(hosts),
        "api_paths": len(apipaths),
        "keyword_functions": {g: len([i for i, h in func_hits.items() if g in h]) for g in KEYWORD_GROUPS},
        "largest_functions": [
            {"id": i, "name": functions[i]["name"], "size": functions[i]["bytecode_size"],
             "strings": len(functions[i]["strings"])}
            for i in sorted(functions, key=lambda i: -functions[i]["bytecode_size"])[:15]
        ],
    }
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

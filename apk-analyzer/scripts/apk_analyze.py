#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apk_analyze.py —— 无依赖 APK 静态分析引擎（纯标准库实现）。

子命令：
  analyze   <apk> [--json]              完整静态报告：哈希 / 结构 / Manifest / DEX 线索 / 证书 / bundle / 完整性清单
  manifest  <apk> [--json]              仅解析 AndroidManifest.xml（包名 / 权限 / 组件 / launcher）
  dex       <apk> [--json] [--keyword K] DEX 字符串 / 类 / URL / 关键词分组统计
  dexfile   <dex...> [--json] [--keyword K] 直接分析裸 .dex（运行时脱壳产物）
  strings   <apk> [--keyword K...] [--out FILE] 提取 dex + 明文 assets 的全部可打印字符串，可按关键词过滤
  bundle    <apk>                       分析 Hermes/JS bundle：双区容器结构 + 熵测绘 + 明文串（不声称可解密）

设计要点（来自实战沉淀）：
  * 不依赖 aapt / apktool / jadx，本机未装这些工具也能跑。
  * AndroidManifest AXML 解析采用手工 chunk 遍历（已修复 StringPool type=0x0001、
    以及根 chunk 0x0003 需递归进入子块两个坑）。
  * React Native + Hermes 的加密 bundle 是「双区容器」：头部高熵加密字节码 +
    后段低熵明文字符串表/内嵌 Web 资源。用 4KB 块熵测绘定位分界。
  * **不要相信 "header XOR 魔数" 得到的 4 字节值**：对任意数据都成立，是恒等式；
    实测用它 XOR 整文件熵不降反升（6.79→7.21），且该值在 DEX 中 0 命中。
    真实加密在 native 流/分组密码层，静态不可解。
  * 完整性清单 assets/meta-data/manifest.mf 采用 base64 多块拼接，尽力解码出
    AndroidManifest.xml,!stamp-cert-sha256 等条目。
  * 签名证书优先用 cryptography 解析；未安装时回退到原始 DER 指纹计算。
  * 加固样本的 classes.dex 常是「桩 + 填充」，判断依据看类数/方法数，不看文件体积。
"""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import struct
import sys
import zipfile

# ============================ 通用工具 ============================

def file_hashes(path):
    algos = {k: hashlib.new(k) for k in ("sha256", "md5", "sha1")}
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 16), b""):
            for a in algos.values():
                a.update(blk)
    return {k: v.hexdigest() for k, v in algos.items()}


# ============================ AXML 解析 ============================

def axml_strings(b):
    """解析 AXML 的 StringPool，返回字符串列表；失败返回 None。"""
    pos, n = 0, len(b)
    while pos + 8 <= n:
        ctype = struct.unpack_from("<H", b, pos)[0]
        csize = struct.unpack_from("<I", b, pos + 4)[0]
        if ctype == 0x0001:  # RES_STRING_POOL_TYPE
            header_size = struct.unpack_from("<H", b, pos + 2)[0]
            str_count = struct.unpack_from("<I", b, pos + 8)[0]
            flags = struct.unpack_from("<I", b, pos + 16)[0]
            str_start = struct.unpack_from("<I", b, pos + 20)[0]
            utf8 = bool(flags & 0x100)
            base = pos + str_start
            offs = [struct.unpack_from("<I", b, pos + header_size + i * 4)[0]
                    for i in range(str_count)]
            out = []
            for off in offs:
                p = base + off
                if utf8:
                    sz = struct.unpack_from("<H", b, p)[0]
                    if sz & 0x8000:
                        sz = ((sz & 0x7FFF) << 16) | struct.unpack_from("<H", b, p + 2)[0]
                        p += 4
                    else:
                        p += 2
                    u16len = struct.unpack_from("<H", b, p)[0]
                    p += 2
                    raw = b[p:p + sz]
                    try:
                        out.append(raw.decode("utf-8", "replace"))
                    except Exception:
                        out.append("")
                else:
                    sz = struct.unpack_from("<H", b, p)[0]
                    if sz & 0x8000:
                        sz = ((sz & 0x7FFF) << 16) | struct.unpack_from("<H", b, p + 2)[0]
                        p += 4
                    else:
                        p += 2
                    raw = b[p:p + sz * 2]
                    try:
                        out.append(raw.decode("utf-16-le", "replace"))
                    except Exception:
                        out.append("")
            return out
        if ctype == 0x0003:  # 根 chunk：仅前进一步进入子块
            pos += 8
            continue
        if csize <= 0:
            break
        pos += csize
    return None


def axml_walk(b):
    """遍历 AXML 的 StartTag/EndTag，返回 (strings, nodes)。

    nodes 元素为 (tag, attrs_dict, parent_tag_or_None)。
    数值/布尔属性以原始 uint32 值保留；字符串属性为字符串。
    """
    strings = axml_strings(b)
    if strings is None:
        return None, None
    pos, n = 0, len(b)
    nodes = []
    stack = []
    RES_VALUE_TYPE_STRING = 0x03
    while pos + 8 <= n:
        ctype = struct.unpack_from("<H", b, pos)[0]
        csize = struct.unpack_from("<I", b, pos + 4)[0]
        if ctype == 0x0102:  # StartTag
            name_idx = struct.unpack_from("<I", b, pos + 20)[0]
            attr_start = struct.unpack_from("<H", b, pos + 24)[0]
            attr_size = struct.unpack_from("<H", b, pos + 26)[0]
            attr_count = struct.unpack_from("<H", b, pos + 28)[0]
            tag = strings[name_idx] if name_idx < len(strings) else "?"
            attrs = {}
            ap = pos + 16 + attr_start
            for _ in range(attr_count):
                a_name = struct.unpack_from("<I", b, ap + 4)[0]
                a_raw = struct.unpack_from("<I", b, ap + 8)[0]
                a_dtype = struct.unpack_from("<B", b, ap + 15)[0]
                an = strings[a_name] if a_name < len(strings) else "?"
                if a_dtype == RES_VALUE_TYPE_STRING and a_raw < len(strings):
                    av = strings[a_raw]
                elif a_dtype == 0x00:  # TYPE_NULL：属性未显式声明
                    av = None
                else:
                    av = struct.unpack_from("<I", b, ap + 16)[0]
                an = an.split(":")[-1]
                attrs[an] = av
                ap += attr_size if attr_size else 20
            parent = stack[-1][0] if stack else None
            nodes.append((tag, attrs, parent))
            stack.append((tag, attrs))
        elif ctype == 0x0103:  # EndTag
            if stack:
                stack.pop()
        elif ctype == 0x0003:  # 根 chunk
            pos += 8
            continue
        if csize <= 0:
            break
        pos += csize
    return strings, nodes


# ============================ DEX 分析 ============================

def dex_analysis(data):
    printable = re.compile(rb"[\x20-\x7e]{5,}")
    strings = set()
    for m in printable.finditer(data):
        try:
            strings.add(m.group().decode("ascii"))
        except Exception:
            pass
    classes = sorted({c.decode("ascii", "ignore")
                      for c in re.findall(rb"L[\w\$/]+;", data)})
    urls = sorted({u.decode("ascii", "ignore")
                   for u in re.findall(rb"https?://[^\s\x00\"'<>)+]{4,}", data)})
    keywords = ["kms", "license", "licence", "activate", "activation", "slmgr",
                "signature", "sign", "server", "token", "aes", "rsa", "encrypt",
                "decrypt", "base64", "secret", "iv", "key", "auth", "verify",
                "http", "api", "root", "xposed", "frida", "hook", "obfus",
                "hermes", "bundle", "jsbundle", "reactnative", "dexhelper",
                "legu", "shell", "integrity", "tamper", "md5", "sha", "captcha",
                "geetest", "oauth", "grant", "session", "credential", "cert"]
    kw_hits = {}
    for kw in keywords:
        cnt = sum(1 for s in strings if kw in s.lower())
        if cnt:
            kw_hits[kw] = cnt
    interesting = [c for c in classes if re.search(
        r"(kms|licen|activ|crypto|native|http|util|sign|auth|net|server|"
        r"hermes|bundle|dexhelper|shell|security|obfus)", c, re.I)]
    return {
        "str_count": len(strings),
        "class_count": len(classes),
        "urls": urls,
        "keyword_hits": dict(sorted(kw_hits.items(), key=lambda x: -x[1])),
        "interesting_classes": interesting,
    }


def find_hosts(strings):
    hosts = set()
    for s in strings:
        for m in re.finditer(r"https?://([a-zA-Z0-9\.\-]+)", s):
            hosts.add(m.group(1))
        for m in re.finditer(
                r"\b([a-z0-9\.\-]+\.(?:com|cn|net|org|io|top|xyz|club|vip|cc|me|app)"
                r"(?:\.[a-z]{2})?)\b", s):
            h = m.group(1)
            if len(h) > 6 and h.count(".") >= 1:
                hosts.add(h)
    return sorted(hosts)


# ============================ 签名证书 ============================

def parse_cert(z):
    cert_name = None
    for name in z.namelist():
        if name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC")):
            cert_name = name
            break
    info = {"file": cert_name, "subject": None, "issuer": None,
            "serial": None, "validity": None, "sha1": None, "sha256": None}
    if not cert_name:
        info["subject"] = "(无签名文件)"
        return info
    der = z.read(cert_name)
    # 直接在 PKCS#7 容器里找 X.509 证书 DER (30 82 ...)
    def parse_certs(data):
        certs, i, ln0 = [], 0, len(data)
        while i < ln0 - 4:
            if data[i] == 0x30 and data[i + 1] == 0x82:
                ln = int.from_bytes(data[i + 2:i + 4], "big")
                end = i + 4 + ln
                if end <= ln0:
                    certs.append(data[i:end]); i = end; continue
            elif data[i] == 0x30 and data[i + 1] == 0x81:
                ln = data[i + 2]; end = i + 3 + ln
                if end <= ln0:
                    certs.append(data[i:end]); i = end; continue
            i += 1
        return certs
    certs = parse_certs(der)
    if not certs:
        certs = [der]  # 退化为整块
    cert = certs[0]
    info["sha1"] = hashlib.sha1(cert).hexdigest()
    info["sha256"] = hashlib.sha256(cert).hexdigest()
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(cert)
        info["subject"] = c.subject.rfc4514_string()
        info["issuer"] = c.issuer.rfc4514_string()
        info["serial"] = format(c.serial_number, "x")
        info["validity"] = f"{c.not_valid_before} ~ {c.not_valid_after}"
    except ImportError:
        info["subject"] = "(cryptography 未安装，仅记录指纹)"
    except Exception as e:
        info["subject"] = f"(解析失败: {e})"
    return info


# ============================ 完整性清单 manifest.mf ============================

def decode_manifest_mf(z):
    """尽力解码 assets/meta-data/manifest.mf（反重打包完整性清单）。

    App 私有格式：base64url 记录拼接，每条记录 = base64url([前缀字节][载荷])，记录间
    以 '=' 内联填充分隔；头部记录载荷为明文 'AndroidManifest.xml,!stamp-cert-sha256'
    （其中 stamp-cert-sha256 即期望的签名证书指纹）。

    因 '=' 是内联填充、前缀字节打断连续可读串，本函数采用「在 base64 原文中搜索已知
    载荷的 base64 编码」+「整串去填充后解码提取明文片段」双策略，尽力给出证据。

    返回 dict: {present, decode_ok, records, markers, header_text, note}
    """
    res = {"present": False, "decode_ok": False, "records": [],
           "markers": [], "header_text": None, "note": ""}
    target = None
    for name in z.namelist():
        if "manifest.mf" in name.lower():
            target = name
            break
    if not target:
        res["note"] = "未找到 manifest.mf"
        return res
    res["present"] = True
    raw = z.read(target).decode("ascii", "replace").strip()
    markers = []

    # 策略 1：在 base64 原文中搜索已知载荷的编码串（最稳健）
    # base64('AndroidManifest.xml,!stamp-cert-sha256') 的前缀（约 16 字符）足够唯一
    head_b64 = base64.urlsafe_b64encode(
        b"AndroidManifest.xml,!stamp-cert-sha256").decode().rstrip("=")
    if head_b64[:16] in raw:
        markers.append("AndroidManifest.xml")
        markers.append("stamp-cert-sha256(签名证书指纹)")
        # 精确解码头部记录：定位编码起点，取 52 字符解码
        idx = raw.find(head_b64[:16])
        window = raw[idx:idx + 52]
        try:
            res["header_text"] = base64.urlsafe_b64decode(
                window + "=" * ((4 - len(window) % 4) % 4)).decode("ascii", "replace")
        except Exception:
            res["header_text"] = None

    # 策略 2：整串去 '=' 后解码，提取可读文件名/片段（容错：试裁 0-3 尾字符对齐）
    clean = raw.replace("=", "")
    for trim in range(0, 4):
        trial = clean[:-trim] if trim else clean
        if len(trial) % 4 != 0:
            continue
        try:
            d = base64.urlsafe_b64decode(trial)
        except Exception:
            continue
        res["decode_ok"] = True
        recs = [r.decode("ascii", "replace") for r in re.findall(rb"[\x20-\x7e]{4,}", d)]
        # 过滤掉明显是二进制乱码的短串，保留可读文件名/路径
        kept = [r for r in recs if re.search(r"[A-Za-z0-9_./-]{4,}", r)][:40]
        if kept:
            res["records"] = kept
        if b"AndroidManifest" in d and "AndroidManifest.xml" not in markers:
            markers.append("AndroidManifest.xml")
        if b"stamp-cert" in d and "stamp-cert-sha256(签名证书指纹)" not in markers:
            markers.append("stamp-cert-sha256(签名证书指纹)")
        break

    res["markers"] = list(dict.fromkeys(markers))
    if res["markers"]:
        res["note"] = "识别到: " + ", ".join(res["markers"])
    else:
        res["note"] = "存在但未能识别标准标记(可能是私有二进制格式)"
    return res


# ============================ Hermes / JS bundle ============================

# Hermes 字节码头：BytecodeFileHeader::MAGIC = 0x1F1903C103BC1FC6
# 小端落盘后前 4 字节为 C6 1F BC 03。
# 注意：曾误写成 00 07 D0 8B —— 那是某加密样本自己的文件头（= 真魔数 XOR 假密钥），
# 用它判断会导致"魔数命中、疑似未加密"的错误结论。
HERMES_MAGIC = bytes([0xC6, 0x1F, 0xBC, 0x03])


def analyze_bundle(z, xor_key=None, out_path=None):
    """分析 assets 下的 JS/Hermes bundle。

    返回 dict: {bundle, size, header_hex, hermes_valid, version, file_length,
               file_length_match, function_count, string_count,
               identifier_count, string_storage_size, entropy_profile,
               plaintext_str_count, sample_strings, note}
    """
    candidate = None
    for name in z.namelist():
        low = name.lower()
        if low.endswith(".jsbundle") or low.endswith(".hbc") or low.endswith(".js"):
            if "rn/" in low or "bundle" in low or low.endswith(".hbc"):
                candidate = name
                break
    if not candidate:
        # 退化为首个 .jsbundle / .hbc
        for name in z.namelist():
            low = name.lower()
            if low.endswith(".jsbundle") or low.endswith(".hbc"):
                candidate = name
                break
    res = {"bundle": candidate, "size": None, "header_hex": None,
           "hermes_valid": False, "version": None, "file_length": None,
           "file_length_match": None, "function_count": None,
           "string_count": None, "identifier_count": None,
           "string_storage_size": None, "entropy_profile": [],
           "plaintext_str_count": 0, "sample_strings": []}
    if not candidate:
        res["note"] = "未找到 JS/Hermes bundle"
        return res
    data = z.read(candidate)
    n = len(data)
    res["size"] = n
    res["header_hex"] = data[:16].hex()

    # ---- 标准 Hermes 头解析 ----
    # BytecodeFileHeader: magic(8) version(4) sourceHash(20) fileLength(4) ...
    # 注意 sourceHash 是 20 字节 SHA1，所以 fileLength 在 0x20 而不是 0x10。
    if n >= 96 and struct.unpack("<Q", data[:8])[0] == 0x1F1903C103BC1FC6:
        u32 = lambda o: struct.unpack("<I", data[o:o + 4])[0]
        res["version"] = u32(8)
        res["file_length"] = u32(32)
        res["file_length_match"] = (res["file_length"] == n)
        res["function_count"] = u32(40)
        res["identifier_count"] = u32(48)
        res["string_count"] = u32(52)
        res["string_storage_size"] = u32(60)
        # magic 正确 + fileLength 自洽 => 确实是标准未加密 Hermes 字节码
        res["hermes_valid"] = bool(res["file_length_match"])

    # 明文串（即便代码段加密，字符串表与内嵌 Web 资源常明文留存）
    # 过滤：要求含 >=4 连续小写字母 —— 排除加密区随机串，保留真实 JS/RN 标识与文本
    all_strs = re.findall(rb"[\x20-\x7e]{5,}", data)
    meaningful = []
    seen = set()
    for s in all_strs:
        try:
            t = s.decode("ascii")
        except Exception:
            continue
        if not re.search(r"[a-z]{4,}", t):
            continue
        if t not in seen:
            seen.add(t)
            meaningful.append(t)
    res["plaintext_str_count"] = len(meaningful)
    res["sample_strings"] = meaningful[:30]

    # ---- 分段熵剖面（仅作结构参考，不代表"加密/明文"分界）----
    # 标准 Hermes 文件的自然形态：头部与函数头/字节码/索引表是二进制（高熵），
    # 字符串存储区（stringStorage）是大段可打印文本。熵高低起伏是正常的，
    # **不能**据此宣称"前段被加密"。
    def _ent(blk):
        c = __import__("collections").Counter(blk)
        L = len(blk) or 1
        return -sum((v / L) * math.log2(v / L) for v in c.values())
    step = 262144
    for off in range(0, n, step):
        blk = data[off:off + step]
        if not blk:
            break
        res["entropy_profile"].append({
            "offset": "0x%X" % off,
            "entropy": round(_ent(blk), 2),
            "printable": round(sum(1 for x in blk if 32 <= x < 127) / len(blk), 2),
        })

    if res["hermes_valid"]:
        res["note"] = ("标准未加密 Hermes 字节码（v%s，fileLength 与文件大小一致，"
                       "%s 个函数 / %s 个字符串）。可直接用 hbc 反汇编工具还原 JS，"
                       "无需运行时脱壳。" % (res["version"], res["function_count"],
                                        res["string_count"]))
    elif res["version"] is not None:
        res["note"] = ("magic 正确但 fileLength(%s) 与文件大小(%d) 不一致，"
                       "文件可能被截断或被二次打包。" % (res["file_length"], n))
    else:
        res["note"] = ("头部不是标准 Hermes 魔数，可能是自定义容器/加密载荷。"
                       "此时熵剖面只能提示结构，**不要**用 header XOR 魔数推导密钥——"
                       "那是恒等式假象（已实测：整文件 XOR 后熵不降反升）。"
                       "取真实字节码应走运行时 dump。")
    return res


# ============================ 结构盘点 ============================

def inventory(z):
    names = z.namelist()
    dexes = [(n, z.getinfo(n).file_size) for n in names if n.endswith(".dex")]
    so = {}
    total_so = 0
    for n in names:
        if n.endswith(".so"):
            arch = n.split("/")[1] if n.startswith("lib/") else "?"
            so.setdefault(arch, []).append((n, z.getinfo(n).file_size))
            total_so += z.getinfo(n).file_size
    assets = [(n, z.getinfo(n).file_size) for n in names if n.startswith("assets/")]
    meta = [(n, z.getinfo(n).file_size) for n in names if n.startswith("META-INF/")]
    interesting_assets = [a for a in assets if any(
        k in a[0].lower() for k in
        ["jsbundle", "bundle", ".db", ".key", ".pem", ".crt", ".pub", ".mf",
         ".sf", ".bin", ".dat", ".json", ".so", "native", ".enc", ".zip", ".hbc"])]
    return {
        "total": len(names), "dexes": dexes, "so": so, "total_so": total_so,
        "assets_count": len(assets), "interesting_assets": interesting_assets,
        "meta": meta,
        "flutter": any(re.search(r"^lib/[^/]+/libapp\.so$", n) for n in names),
    }


# ============================ 命令实现 ============================

def open_apk(path):
    if not os.path.isfile(path):
        sys.exit(f"[!] APK 不存在: {path}")
    try:
        return zipfile.ZipFile(path)
    except Exception as e:
        sys.exit(f"[!] 无法打开 APK (不是合法 zip?): {e}")


def cmd_analyze(args):
    z = open_apk(args.apk)
    report = {}
    report["file"] = os.path.basename(args.apk)
    report["hashes"] = file_hashes(args.apk)
    inv = inventory(z)
    report["inventory"] = {
        "total": inv["total"],
        "dexes": [{"name": n, "size": s} for n, s in inv["dexes"]],
        "so_archs": {a: [{"name": n, "size": s} for n, s in items]
                     for a, items in inv["so"].items()},
        "total_so": inv["total_so"],
        "assets_count": inv["assets_count"],
        "interesting_assets": [{"name": n, "size": s} for n, s in inv["interesting_assets"]],
        "meta": [n for n, _ in inv["meta"]],
        "flutter": inv["flutter"],
    }
    # Manifest
    try:
        manifest = z.read("AndroidManifest.xml")
        strings, nodes = axml_walk(manifest)
    except KeyError:
        strings, nodes = None, None
    if nodes:
        pkg = ver = vcode = min_sdk = tgt_sdk = debuggable = None
        perms, components, launcher = [], [], []
        intent_markers = []
        for tag, attrs, parent in nodes:
            if tag == "manifest":
                pkg = attrs.get("package"); ver = attrs.get("versionName")
                vcode = attrs.get("versionCode")
            elif tag == "uses-sdk":
                min_sdk = attrs.get("minSdkVersion"); tgt_sdk = attrs.get("targetSdkVersion")
            elif tag == "application":
                debuggable = attrs.get("debuggable")
            elif tag == "uses-permission":
                if attrs.get("name"):
                    perms.append(attrs["name"])
            elif tag in ("activity", "service", "receiver", "provider"):
                components.append({"type": tag, "name": attrs.get("name"),
                                   "exported": attrs.get("exported")})
            elif tag == "action" and attrs.get("name") == "android.intent.action.MAIN":
                intent_markers.append("MAIN")
            elif tag == "category" and attrs.get("name") == "android.intent.category.LAUNCHER":
                intent_markers.append("LAUNCHER")
                if "MAIN" in intent_markers and components:
                    launcher.append(components[-1]["name"])
        report["manifest"] = {
            "package": pkg, "version_name": ver, "version_code": vcode,
            "min_sdk": min_sdk, "target_sdk": tgt_sdk, "debuggable": debuggable,
            "permissions": perms, "components": components, "launchers": launcher,
        }
    else:
        report["manifest"] = {"parse": "failed", "note": "回退到原始字符串扫描"}
    # DEX
    dex_reports = []
    all_strings = set()
    for n, _ in inv["dexes"]:
        r = dex_analysis(z.read(n))
        all_strings |= {s.decode("ascii", "ignore")
                        for s in re.findall(rb"[\x20-\x7e]{5,}", z.read(n))}
        dex_reports.append({
            "dex": n, "str_count": r["str_count"], "class_count": r["class_count"],
            "urls": r["urls"], "keyword_hits": r["keyword_hits"],
            "interesting_classes": r["interesting_classes"][:60],
        })
    report["dex"] = dex_reports
    report["hosts"] = find_hosts(all_strings)
    # 证书
    report["certificate"] = parse_cert(z)
    # bundle
    report["bundle"] = analyze_bundle(z)
    # manifest.mf
    report["integrity_manifest"] = decode_manifest_mf(z)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    # 人类可读
    print("=" * 72)
    print("APK 静态分析报告:", report["file"])
    print("=" * 72)
    h = report["hashes"]
    print("\n[1] 文件哈希]\n  sha256:", h["sha256"], "\n  md5:", h["md5"], "\n  sha1:", h["sha1"])
    inv_r = report["inventory"]
    print(f"\n[2] 包结构] 总条目 {inv_r['total']} | DEX {len(inv_r['dexes'])} | 原生库架构 {list(inv_r['so_archs'])}")
    for d in inv_r["dexes"]:
        print(f"     DEX {d['name']:18s} {d['size']/1024/1024:7.2f} MB")
    print(f"     原生库总大小 {inv_r['total_so']/1024/1024:6.2f} MB")
    print(f"     assets 数 {inv_r['assets_count']} | 关键 assets:")
    for a in inv_r["interesting_assets"][:25]:
        print(f"        {a['name']:60s} {a['size']/1024:8.1f} KB")
    print("     签名文件:", inv_r["meta"])
    m = report["manifest"]
    print("\n[3] AndroidManifest 解析]")
    if "package" in m:
        print(f"     包名: {m['package']}  版本: {m['version_name']} (code={m['version_code']})")
        print(f"     SDK: min={m['min_sdk']} target={m['target_sdk']}  debuggable={m['debuggable']}")
        print(f"     权限({len(m['permissions'])}):")
        for p in m["permissions"]:
            print("        -", p)
        print(f"     组件({len(m['components'])}):")
        for c in m["components"]:
            star = " [LAUNCHER]" if c["name"] in m["launchers"] else ""
            print(f"        {c['type']:9} {c['name']}  exported={c['exported']}{star}")
    else:
        print("     (AXML 解析失败，已回退原始扫描)")
    if report["inventory"].get("flutter"):
        print("\n[!] 检测到 Flutter（libapp.so 存在）：业务代码在 Dart AOT snapshot 里，")
        print("    下面 [4] 的 DEX 线索只有启动壳与桥接，不是业务代码。")
        print("    请改用: apk_analyze.py flutter <apk>")
    print("\n[4] DEX 线索]")
    for d in report["dex"]:
        print(f"     -- {d['dex']} (串 {d['str_count']} / 类 {d['class_count']})")
        print("        关键词命中:", ", ".join(f"{k}:{v}" for k, v in d["keyword_hits"].items()) or "无")
        if d["urls"]:
            print("        URL 示例:")
            for u in d["urls"][:10]:
                print("          ", u)
        if d["interesting_classes"]:
            print("        关键类(前10):")
            for c in d["interesting_classes"][:10]:
                print("          ", c)
    print(f"\n     候选网络域名({len(report['hosts'])}):")
    for hst in report["hosts"][:30]:
        print("        ", hst)
    c = report["certificate"]
    print("\n[5] 签名证书]")
    print(f"     文件: {c['file']}")
    print(f"     Subject: {c['subject']}")
    if c.get("issuer"):
        print(f"     Issuer: {c['issuer']}  Serial: {c['serial']}")
    if c.get("validity"):
        print(f"     有效期: {c['validity']}")
    if c.get("sha1"):
        print(f"     SHA1 : {c['sha1']}")
        print(f"     SHA256: {c['sha256']}")
    b = report["bundle"]
    print("\n[6] JS/Hermes Bundle]")
    if b.get("bundle"):
        print(f"     文件: {b['bundle']}  大小 {b['size']}  头部 {b['header_hex']}")
        if b.get("version") is not None:
            print(f"     Hermes 版本: v{b['version']}  "
                  f"fileLength={b['file_length']} 匹配={b['file_length_match']}")
            print(f"     函数数: {b['function_count']}  字符串数: {b['string_count']}  "
                  f"标识符数: {b['identifier_count']}")
        print(f"     标准未加密 HBC: {b['hermes_valid']}")
        if b.get("note"):
            print(f"     备注: {b['note']}")
        print(f"     明文串数: {b['plaintext_str_count']}")
        if b["sample_strings"]:
            print("     明文串示例(前10):")
            for s in b["sample_strings"][:10]:
                print("        ", s)
    else:
        print("     (未找到 bundle)")
    mf = report["integrity_manifest"]
    print("\n[7] 完整性清单 (manifest.mf / 反重打包校验)]")
    if mf["present"]:
        print(f"     存在, base64 解码: {mf['decode_ok']}")
        print(f"     说明: {mf['note']}")
        if mf.get("header_text"):
            print(f"     头部记录: {mf['header_text']}")
        if mf["records"]:
            print("     解码可读片段:")
            for r in mf["records"][:15]:
                print("        ", r[:80])
    else:
        print("     (未找到 manifest.mf)")


def cmd_manifest(args):
    z = open_apk(args.apk)
    try:
        manifest = z.read("AndroidManifest.xml")
        strings, nodes = axml_walk(manifest)
    except KeyError:
        nodes = None
    if not nodes:
        print("[!] AndroidManifest 解析失败", file=sys.stderr)
        sys.exit(2)
    pkg = ver = vcode = min_sdk = tgt_sdk = debuggable = None
    perms, components, launcher = [], [], []
    markers = []
    for tag, attrs, parent in nodes:
        if tag == "manifest":
            pkg = attrs.get("package"); ver = attrs.get("versionName")
            vcode = attrs.get("versionCode")
        elif tag == "uses-sdk":
            min_sdk = attrs.get("minSdkVersion"); tgt_sdk = attrs.get("targetSdkVersion")
        elif tag == "application":
            debuggable = attrs.get("debuggable")
        elif tag == "uses-permission" and attrs.get("name"):
            perms.append(attrs["name"])
        elif tag in ("activity", "service", "receiver", "provider"):
            components.append({"type": tag, "name": attrs.get("name"),
                               "exported": attrs.get("exported")})
        elif tag == "action" and attrs.get("name") == "android.intent.action.MAIN":
            markers.append("MAIN")
        elif tag == "category" and attrs.get("name") == "android.intent.category.LAUNCHER":
            markers.append("LAUNCHER")
            if "MAIN" in markers and components:
                launcher.append(components[-1]["name"])
    result = {"package": pkg, "version_name": ver, "version_code": vcode,
              "min_sdk": min_sdk, "target_sdk": tgt_sdk, "debuggable": debuggable,
              "permissions": perms, "components": components, "launchers": launcher}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("包名:", pkg, " 版本:", ver, f"(code={vcode})")
        print("SDK: min=", min_sdk, "target=", tgt_sdk, " debuggable=", debuggable)
        print("权限:")
        for p in perms:
            print("  -", p)
        print("组件:")
        for c in components:
            star = " [LAUNCHER]" if c["name"] in launcher else ""
            print(f"  {c['type']:9} {c['name']}  exported={c['exported']}{star}")


def cmd_dex(args):
    z = open_apk(args.apk)
    names = [n for n in z.namelist() if n.endswith(".dex")]
    strings = set()
    for n in names:
        strings |= {s.decode("ascii", "ignore")
                    for s in re.findall(rb"[\x20-\x7e]{5,}", z.read(n))}
    r = dex_analysis(z.read(names[0]) if names else b"")
    r["hosts"] = find_hosts(strings)
    if args.keyword:
        filt = {k: v for k, v in r["keyword_hits"].items() if k in args.keyword}
        r["keyword_hits"] = filt
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"DEX 文件: {names or '无'}")
        print(f"字符串数: {r['str_count']}  类数: {r['class_count']}")
        print("关键词命中:", r["keyword_hits"] or "无")
        print("URL/域名示例:")
        for u in (r["urls"] + r["hosts"])[:25]:
            print("  ", u)


def cmd_dexfile(args):
    """直接分析裸 .dex 文件（运行时脱壳产物，无需原始 APK）。"""
    import glob as _glob
    files = []
    for p in args.paths:
        hits = sorted(_glob.glob(p))
        files.extend(hits if hits else ([p] if os.path.isfile(p) else []))
    if not files:
        print("[!] 没有匹配到 .dex 文件", file=sys.stderr)
        sys.exit(1)

    per = []
    all_strings = set()
    for p in files:
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError as e:
            per.append({"path": p, "error": str(e)})
            continue
        if not data.startswith(b"dex\n"):
            per.append({"path": p, "error": "不是 DEX（magic=%r）" % data[:8]})
            continue
        r = dex_analysis(data)
        r["path"] = p
        r["size"] = len(data)
        r["sha256"] = hashlib.sha256(data).hexdigest()
        per.append(r)
        all_strings |= {s.decode("ascii", "ignore")
                        for s in re.findall(rb"[\x20-\x7e]{5,}", data)}

    ok = [r for r in per if "error" not in r]
    agg = {
        "files": per,
        "dex_count": len(ok),
        "total_size": sum(r["size"] for r in ok),
        "total_str_count": sum(r["str_count"] for r in ok),
        "total_class_count": sum(r["class_count"] for r in ok),
        "hosts": sorted(find_hosts(all_strings)),
        "urls": sorted({u for r in ok for u in r["urls"]}),
        "keyword_hits": {},
        "interesting_classes": sorted({c for r in ok for c in r["interesting_classes"]}),
    }
    for r in ok:
        for k, v in r["keyword_hits"].items():
            agg["keyword_hits"][k] = agg["keyword_hits"].get(k, 0) + v
    agg["keyword_hits"] = dict(sorted(agg["keyword_hits"].items(), key=lambda x: -x[1]))

    matched = None
    if args.keyword:
        kws = [k.lower() for k in args.keyword]
        matched = sorted(s for s in all_strings if any(k in s.lower() for k in kws))
        agg["matched_strings"] = len(matched)

    if args.out and matched is not None:
        with open(args.out, "w", encoding="utf-8") as f:
            for s in matched:
                f.write(s + "\n")
        agg["out"] = args.out

    if args.json:
        if args.out:
            agg.pop("matched_strings", None)
        print(json.dumps(agg, ensure_ascii=False, indent=2))
        return

    print("DEX 文件数: %d  总大小: %.1f MB" % (
        agg["dex_count"], agg["total_size"] / 1048576.0))
    print("合计字符串: %d  合计类数: %d" % (
        agg["total_str_count"], agg["total_class_count"]))
    print("\n每个文件:")
    for r in agg["files"]:
        if "error" in r:
            print("  [!] %s -> %s" % (os.path.basename(r["path"]), r["error"]))
        else:
            print("  %-24s %10d B  类=%-6d 串=%-6d" % (
                os.path.basename(r["path"]), r["size"],
                r["class_count"], r["str_count"]))
    print("\n关键词命中:", agg["keyword_hits"] or "无")
    if agg["interesting_classes"]:
        print("\n可疑类(前40):")
        for c in agg["interesting_classes"][:40]:
            print("  ", c)
    if agg["hosts"]:
        print("\n域名/主机(前30):")
        for h in agg["hosts"][:30]:
            print("  ", h)
    if matched is not None:
        if args.out:
            print("\n已写出 %d 条匹配字符串 -> %s" % (len(matched), args.out))
        else:
            print("\n匹配字符串(前 %d 条):" % min(len(matched), 200))
            for s in matched[:200]:
                print("  ", s)


def cmd_strings(args):
    z = open_apk(args.apk)
    strings = set()
    for n in z.namelist():
        if n.endswith(".dex") or (n.startswith("assets/") and
                                  (n.endswith(".jsbundle") or n.endswith(".js") or n.endswith(".hbc"))):
            try:
                for m in re.finditer(rb"[\x20-\x7e]{4,}", z.read(n)):
                    try:
                        strings.add(m.group().decode("ascii"))
                    except Exception:
                        pass
            except Exception:
                pass
    if args.keyword:
        kws = [k.lower() for k in args.keyword]
        strings = {s for s in strings if any(k in s.lower() for k in kws)}
    out = sorted(strings)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for s in out:
                f.write(s + "\n")
        print(f"已写出 {len(out)} 条字符串 -> {args.out}")
    else:
        print(f"共 {len(out)} 条字符串" + (f" (按关键词 {args.keyword} 过滤)" if args.keyword else ""))
        for s in out[:200]:
            print("  ", s)


def cmd_bundle(args):
    z = open_apk(args.apk)
    res = analyze_bundle(z)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        if not res.get("bundle"):
            print("[!] 未找到 JS/Hermes bundle")
            sys.exit(2)
        print("Bundle 文件:", res["bundle"])
        print("大小:", res["size"], " 头部:", res["header_hex"])
        if res.get("version") is not None:
            print("Hermes 版本: v%s  fileLength=%s 匹配=%s" % (
                res["version"], res["file_length"], res["file_length_match"]))
            print("函数数: %s  字符串数: %s  标识符数: %s  字符串存储=%s B" % (
                res["function_count"], res["string_count"],
                res["identifier_count"], res["string_storage_size"]))
        print("标准未加密 HBC:", res["hermes_valid"])
        if res.get("entropy_profile"):
            print("分段熵剖面（仅结构参考，不代表加密分界）:")
            for e in res["entropy_profile"]:
                print("   %-10s 熵=%.2f 可打印=%.2f" % (
                    e["offset"], e["entropy"], e["printable"]))
        if res.get("note"):
            print("备注:", res["note"])
        print("明文串数:", res["plaintext_str_count"])
        print("明文串样本(前30):")
        for s in res["sample_strings"]:
            print("  ", s[:140])


# ============================ Flutter 层 ============================
# Flutter 应用的业务代码全在 lib/<abi>/libapp.so（AOT snapshot），
# DEX 只剩壳/桥接，所以 dex 子命令几乎是空的 —— 必须单独处理。

CLOUD_VENDORS = [
    ("VeryFit / IDO", ["idoocloud", "veryfitplus", "veryfit", "switchappkey", "ido_key"]),
    ("华为运动健康", ["huawei_health", "hilink"]),
    ("小米生态", ["mi_fitness", "zepp", "huami"]),
]

# 芯片厂指纹只能证明"SDK 支持这家芯片"，不能证明设备用的就是它。
# 命中多家 = 通用协议 SDK（protocol_c 一类），必须靠设备端证据二次确认。
CHIP_VENDORS = [
    ("SiFli 思澈", ["sifli", "sf32lb", "sftool"]),
    ("Nordic", ["nordic", "nrf5", "nrfutil", "nrf_dfu"]),
    ("杰理 JieLi", ["jieli", "jl_bt"]),
    ("恒玄 BES", ["bestechnic", "bes2700", "bes_"]),
    ("汇顶 Goodix", ["goodix", "gr551"]),
    ("瑞昱 Realtek", ["realtek", "rtl87"]),
    ("Ambiq", ["ambiq", "apollo3"]),
    ("Telink", ["telink", "tlsr8"]),
    ("中科蓝讯", ["bluetooth_ab53", "ab532"]),
]

OTA_HINTS = ["ota", "firmware", "dfu", "upgrade", "sftool", "bootloader", "efuse"]


def _dart_strings(buf, min_len=4, max_len=300):
    out = set()
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, buf):
        s = m.group()
        if len(s) > max_len:
            s = s[:max_len]
        try:
            out.add(s.decode("ascii"))
        except Exception:
            pass
    return out


def analyze_flutter(z, keyword=None):
    names = z.namelist()
    libapp = [n for n in names if re.search(r"^lib/[^/]+/libapp\.so$", n)]
    libflut = [n for n in names if re.search(r"^lib/[^/]+/libflutter\.so$", n)]
    res = {
        "flutter": bool(libapp),
        "libapp": [{"name": n, "size": z.getinfo(n).file_size} for n in libapp],
        "libflutter": [{"name": n, "size": z.getinfo(n).file_size} for n in libflut],
        "dart_version": None,
        "packages": {},
        "api_paths": [],
        "hosts": [],
        "white_label": [],
        "ota_hits": [],
        "note": None,
    }
    if not libapp:
        res["note"] = ("未发现 libapp.so，不是 Flutter AOT 应用。"
                       "RN 应用请用 bundle 子命令；纯原生应用用 dex 子命令。")
        return res

    target = max(libapp, key=lambda n: z.getinfo(n).file_size)
    res["engine_ok"] = bool(libflut)
    buf = z.read(target)
    ss = _dart_strings(buf)

    # Dart 版本（AOT snapshot 里会留 engine 版本串）
    for s in ss:
        m = re.match(r"^(?:Flutter|Dart VM version)?\s*(\d+\.\d+\.\d+)\s*\(stable\)", s)
        if m:
            res["dart_version"] = m.group(1)
            break

    low = {s: s.lower() for s in ss}

    # Dart 包结构：package:xxx/yyy.dart —— 反推功能模块，比读汇编高效得多
    pkgs = {}
    for s in ss:
        m = re.match(r"^package:([A-Za-z0-9_]+)/([A-Za-z0-9_/]+\.dart)$", s)
        if m:
            pkgs.setdefault(m.group(1), set()).add(m.group(2))
    res["packages"] = {k: {"files": len(v), "sample": sorted(v)[:6]}
                       for k, v in sorted(pkgs.items(), key=lambda x: -len(x[1]))}

    # 接口路径
    apis = sorted({s for s in ss if re.match(r"^/?api/", s) and len(s) < 120})
    res["api_paths"] = apis

    # 主机名
    hosts = set()
    for s in ss:
        for m in re.finditer(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,30})\.)+(?:com|cn|net|io|org|cc|top|xyz))\b", s):
            h = m.group(1)
            if not h.startswith(("schemas.", "www.w3.")):
                hosts.add(h)
    res["hosts"] = sorted(hosts)

    # 白牌 / 方案商指纹（分两类，含义不同）
    joined = " ".join(low.keys())
    for vendor, sigs in CLOUD_VENDORS:
        hit = [x for x in sigs if x in joined]
        if hit:
            res["white_label"].append({"vendor": vendor, "kind": "cloud", "evidence": hit[:4]})
    chips = []
    for vendor, sigs in CHIP_VENDORS:
        hit = [x for x in sigs if x in joined]
        if hit:
            chips.append({"vendor": vendor, "kind": "chip", "evidence": hit[:4]})
    res["white_label"].extend(chips)
    res["chip_vendor_count"] = len(chips)

    # OTA / 固件线索
    if keyword:
        kws = [k.lower() for k in keyword]
    else:
        kws = OTA_HINTS
    tz = re.compile(r"^(Africa|America|Antarctica|Arctic|Asia|Atlantic|Australia|"
                    r"Europe|Indian|Pacific|Etc|US|Canada)/")
    hits = {s for s in ss
            if _kw_hit(s, kws)
            and "rotate" not in s.lower() and "total" not in s.lower()
            and not tz.match(s)
            and not s.startswith(("<", "&"))
            and _looks_like_code(s)}
    # 无空格的（标识符/路径）排前面，含空格的（日志/文案）排后面
    res["ota_hits"] = sorted(hits, key=lambda s: (" " in s, s))[:120]

    res["note"] = ("libapp.so 里的字符串是按 Dart snapshot 布局**连续存储**的，"
                   "按可打印区间切分可能把相邻串粘成一条。关键结论（域名/接口）"
                   "请在原始字节里 count() 二次确认——这与 Hermes 的 1.5c 坑同源。")
    return res


OTA_RE = re.compile(r"OTA|Ota|(?<![A-Za-z])ota(?![A-Za-z])")


def _kw_hit(s, kws):
    """关键词命中判断。
    'ota' 必须按词/驼峰匹配——Annotation、Bogota、microtask、rotation 都含 'ota' 子串。"""
    ls = s.lower()
    for k in kws:
        if k == "ota":
            if OTA_RE.search(s):
                return True
        elif k in ls:
            return True
    return False


def _looks_like_code(s):
    """区分 '代码/标识符' 与 '自然语言文案'。
    多语言文案里大量含 ota（芬兰语 ota = 拿、葡语 nota 等），不过滤会把噪音当线索。"""
    if " " not in s:
        return True
    if ". " in s or '"' in s or "'" in s:
        return False
    if s.count(", ") > 1:
        return False
    if not re.search(r"(OTA|Ota|Firmware|DFU|Upgrade|Sifli)", s):
        return False
    return len(s) < 100


def cmd_flutter(args):
    z = open_apk(args.apk)
    res = analyze_flutter(z, args.keyword)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return
    if not res["flutter"]:
        print("[!] " + res["note"])
        sys.exit(2)
    print("=== Flutter 应用 ===")
    for a in res["libapp"]:
        print("  libapp.so: %-34s %8.1f MB" % (a["name"], a["size"] / 1e6))
    print("  引擎 libflutter.so:", "有" if res.get("engine_ok") else "无(可疑)")
    if res["dart_version"]:
        print("  Dart/Flutter 版本:", res["dart_version"])

    cloud = [w for w in res["white_label"] if w["kind"] == "cloud"]
    chips = [w for w in res["white_label"] if w["kind"] == "chip"]
    print("\n[云平台/方案]")
    if cloud:
        for w in cloud:
            print("  %-16s <- %s" % (w["vendor"], ", ".join(w["evidence"])))
        print("  → 白牌方案：一套 App 套多个品牌，同方案设备/固件/工具链大概率可复用")
    else:
        print("  未命中已知白牌云平台（可能是自研或私有云）")

    if chips:
        print("\n[芯片厂指纹] 命中 %d 家" % len(chips))
        for w in chips:
            print("  %-16s <- %s" % (w["vendor"], ", ".join(w["evidence"])))
        if len(chips) >= 3:
            print("  ! 命中 >=3 家说明这是**通用协议 SDK**（如 protocol_c），")
            print("    只能证明它支持这些芯片，不能证明设备用的是哪家。")
            print("    判定实际芯片必须靠设备端证据：GATT UUID / 固件内串 / 拆机丝印。")

    print("\n[Dart 包结构] 前 15 个（按文件数）")
    for i, (k, v) in enumerate(res["packages"].items()):
        if i >= 15:
            break
        print("  %-32s %3d 文件  例: %s" % (k, v["files"], v["sample"][0] if v["sample"] else ""))

    if res["api_paths"]:
        print("\n[接口路径] %d 条" % len(res["api_paths"]))
        for s in res["api_paths"][:40]:
            print("  ", s)
    else:
        print("\n[接口路径] 未发现 api/ 前缀（可能在宿主 DEX 或动态拼接）")

    if res["hosts"]:
        print("\n[域名] %d 个" % len(res["hosts"]))
        for h in res["hosts"][:40]:
            print("  ", h)

    if res["ota_hits"]:
        print("\n[OTA/固件线索] %d 条（前 40）" % len(res["ota_hits"]))
        for s in res["ota_hits"][:40]:
            print("  ", s[:130])

    if res.get("note"):
        print("\n[注意] " + res["note"])


# ============================ 入口 ============================

def main():
    p = argparse.ArgumentParser(description="无依赖 APK 静态分析引擎")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("analyze", help="完整静态报告")
    pa.add_argument("apk")
    pa.add_argument("--json", action="store_true")
    pa.set_defaults(func=cmd_analyze)

    pm = sub.add_parser("manifest", help="仅解析 AndroidManifest.xml")
    pm.add_argument("apk")
    pm.add_argument("--json", action="store_true")
    pm.set_defaults(func=cmd_manifest)

    pd = sub.add_parser("dex", help="DEX 字符串/类/URL/关键词")
    pd.add_argument("apk")
    pd.add_argument("--json", action="store_true")
    pd.add_argument("--keyword", action="append", help="仅统计指定关键词(可重复)")
    pd.set_defaults(func=cmd_dex)

    pdf = sub.add_parser("dexfile", help="直接分析裸 .dex（运行时脱壳产物）")
    pdf.add_argument("paths", nargs="+", help="dex 路径或 glob")
    pdf.add_argument("--json", action="store_true")
    pdf.add_argument("--keyword", action="append", help="打印/写出匹配这些关键词的字符串(可重复)")
    pdf.add_argument("--out", help="把匹配到的字符串写出到文件")
    pdf.set_defaults(func=cmd_dexfile)

    ps = sub.add_parser("strings", help="提取 dex + 明文 assets 字符串")
    ps.add_argument("apk")
    ps.add_argument("--keyword", action="append", help="过滤关键词(可重复)")
    ps.add_argument("--out", help="写出到文件(每行一条)")
    ps.set_defaults(func=cmd_strings)

    pb = sub.add_parser("bundle", help="分析 Hermes/JS bundle 容器结构(加密区/明文区)")
    pb.add_argument("apk")
    pb.add_argument("--json", action="store_true")
    pb.set_defaults(func=cmd_bundle)

    pf = sub.add_parser("flutter", help="Flutter 应用：libapp.so 字符串/Dart 包结构/接口/白牌指纹")
    pf.add_argument("apk")
    pf.add_argument("--json", action="store_true")
    pf.add_argument("--keyword", action="append",
                    help="只保留含这些关键词的字符串(可重复)，默认 OTA/固件关键词")
    pf.set_defaults(func=cmd_flutter)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

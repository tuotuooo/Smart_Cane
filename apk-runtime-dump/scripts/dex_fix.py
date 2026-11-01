#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dex_fix.py — 校验 / 规范化从内存 dump 出来的 DEX。

为什么需要
----------
加固壳把 DEX 解密后直接 MemMap 给 ART，**不会重算头部校验**：

  * `checksum`（偏移 0x08，adler32）与 `signature`（偏移 0x0C，SHA-1）都是旧值；
  * 文件内容本身是完整的，ART 对内存 DEX 不做校验，所以 App 能正常跑。

但 jadx / baksmali / apktool 会先校验头部，直接喂进去常常报
`Invalid checksum` / `Bad signature`。本脚本重算这两个字段，产出可直接反编译的副本。

**顺序很重要**：signature 覆盖 `[0x20, EOF)`，checksum 覆盖 `[0x0C, EOF)`。
必须先写 signature，再算 checksum，否则 checksum 会算错。

用法
----
  python dex_fix.py classes.dex                 # 校验 + 生成 classes_fixed.dex
  python dex_fix.py "memdump/*.bin" --out-dir fixed/
  python dex_fix.py classes.dex --validate-only # 只体检，不写文件
  python dex_fix.py classes.dex --json

退出码：0=全部结构有效；1=有文件结构异常（仍可能已产出 normalized 副本）。
"""
import argparse
import glob
import hashlib
import json
import os
import struct
import sys
import zlib

HEADER_SIZE = 0x70


def uleb128(buf, pos):
    result = shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def header(d):
    return {
        "magic": d[:8].decode("latin1"),
        "version": d[4:7].decode("latin1", "replace"),
        "checksum": struct.unpack("<I", d[8:12])[0],
        "signature": d[12:32].hex(),
        "file_size": struct.unpack("<I", d[0x20:0x24])[0],
        "header_size": struct.unpack("<I", d[0x24:0x28])[0],
        "endian_tag": "0x%08x" % struct.unpack("<I", d[0x28:0x2C])[0],
        "strings": struct.unpack("<I", d[0x38:0x3C])[0],
        "types": struct.unpack("<I", d[0x40:0x44])[0],
        "protos": struct.unpack("<I", d[0x48:0x4C])[0],
        "fields": struct.unpack("<I", d[0x50:0x54])[0],
        "methods": struct.unpack("<I", d[0x58:0x5C])[0],
        "classes": struct.unpack("<I", d[0x60:0x64])[0],
    }


def check_code_offsets(d):
    """遍历 class_def → class_data → method，检查每个 code_off 是否落在文件内。"""
    n = len(d)
    cd_size = struct.unpack("<I", d[0x60:0x64])[0]
    cd_off = struct.unpack("<I", d[0x64:0x68])[0]
    valid = invalid = 0
    if cd_off + cd_size * 32 > n:
        return valid, invalid
    for i in range(cd_size):
        base = cd_off + i * 32
        cdata_off = struct.unpack("<I", d[base + 24:base + 28])[0]
        if not cdata_off or cdata_off >= n:
            continue
        p = cdata_off
        try:
            sf, p = uleb128(d, p)
            inf, p = uleb128(d, p)
            dm, p = uleb128(d, p)
            vm, p = uleb128(d, p)
            for _ in range(sf):
                _, p = uleb128(d, p)
                _, p = uleb128(d, p)
            for _ in range(inf):
                _, p = uleb128(d, p)
                _, p = uleb128(d, p)
            for _ in range(dm + vm):
                _, p = uleb128(d, p)      # method_idx diff
                _, p = uleb128(d, p)      # access_flags
                code_off, p = uleb128(d, p)
                if code_off == 0:
                    continue
                if HEADER_SIZE < code_off < n - 8:
                    valid += 1
                else:
                    invalid += 1
        except (IndexError, struct.error):
            invalid += 1
    return valid, invalid


def normalize(d):
    """重算 signature 再重算 checksum，返回新 bytes。"""
    buf = bytearray(d)
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
    buf[8:12] = struct.pack("<I", zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


def verify(d):
    ok_sig = d[12:32] == hashlib.sha1(d[32:]).digest()
    ok_chk = struct.unpack("<I", d[8:12])[0] == (zlib.adler32(d[12:]) & 0xFFFFFFFF)
    return ok_chk, ok_sig


def process(path, out_dir, suffix, validate_only):
    with open(path, "rb") as f:
        d = f.read()
    rec = {"path": path, "size": len(d),
           "sha256": hashlib.sha256(d).hexdigest()}
    if not d.startswith(b"dex\n"):
        rec["error"] = "not a dex (magic=%r)" % d[:8]
        return rec, False

    h = header(d)
    rec["header"] = h
    rec["truncated"] = (h["file_size"] != len(d))
    chk_ok, sig_ok = verify(d)
    rec["checksum_ok"] = chk_ok
    rec["signature_ok"] = sig_ok
    valid, invalid = check_code_offsets(d)
    rec["code_off_valid"] = valid
    rec["code_off_invalid"] = invalid

    if not validate_only:
        fixed = normalize(d)
        stem = os.path.splitext(os.path.basename(path))[0]
        os.makedirs(out_dir or os.path.dirname(path) or ".", exist_ok=True)
        dst = os.path.join(out_dir or os.path.dirname(path) or ".",
                           "%s%s.dex" % (stem, suffix))
        with open(dst, "wb") as f:
            f.write(fixed)
        fchk, fsig = verify(fixed)
        rec["fixed_path"] = dst
        rec["fixed_ok"] = bool(fchk and fsig)
        rec["fixed_sha256"] = hashlib.sha256(fixed).hexdigest()

    healthy = (not rec["truncated"]) and invalid == 0
    return rec, healthy


def main():
    ap = argparse.ArgumentParser(description="校验 / 规范化内存 dump 出来的 DEX")
    ap.add_argument("paths", nargs="+", help="dex 文件路径或 glob")
    ap.add_argument("--out-dir", help="规范化副本输出目录（默认与原文件同目录）")
    ap.add_argument("--suffix", default="_fixed", help="输出文件名后缀（默认 _fixed）")
    ap.add_argument("--validate-only", action="store_true", help="只体检，不写文件")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    files = []
    for p in args.paths:
        files.extend(sorted(glob.glob(p)) or ([p] if os.path.isfile(p) else []))

    if not files:
        print("[!] 没有匹配到文件", file=sys.stderr)
        return 1

    records, all_healthy = [], True
    for p in files:
        rec, healthy = process(p, args.out_dir, args.suffix, args.validate_only)
        records.append(rec)
        all_healthy &= healthy
        if args.json:
            continue
        if "error" in rec:
            print("[!] %s: %s" % (p, rec["error"]))
            continue
        h = rec["header"]
        print("%s" % os.path.basename(p))
        print("  %8d B  v%s  classes=%-6d methods=%-6d strings=%-6d" % (
            rec["size"], h["version"], h["classes"], h["methods"], h["strings"]))
        print("  checksum_ok=%-5s signature_ok=%-5s truncated=%-5s" % (
            rec["checksum_ok"], rec["signature_ok"], rec["truncated"]))
        print("  code_off: valid=%-6d invalid=%d" % (
            rec["code_off_valid"], rec["code_off_invalid"]))
        if rec.get("fixed_path"):
            print("  -> %s  (normalized_ok=%s)" % (rec["fixed_path"], rec["fixed_ok"]))

    if args.json:
        print(json.dumps(records, ensure_ascii=False, indent=2))
    return 0 if all_healthy else 1


if __name__ == "__main__":
    sys.exit(main())

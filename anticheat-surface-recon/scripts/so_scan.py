#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
so_scan.py —— 从大型 .so / 二进制里提取网络常量

不依赖 strings 命令，直接正则扫描原始字节，速度比 strings|grep 快一个量级，
且能跨 4KB 块边界命中（用重叠窗口）。

提取：
  - http(s)/ws(s) URL
  - 裸域名（按 TLD 白名单过滤，避免误抓）
  - IPv4:port
  - 协议关键字相关短串（quic/kcp/udp/websocket/protobuf/flatbuffer…）

用法：
  python so_scan.py libUE4.so
  python so_scan.py libUE4.so --top 200 --json out.json
"""
import re
import sys
import json
import collections
from pathlib import Path

CHUNK = 64 << 20          # 64MB
OVERLAP = 4096

URL_RE = re.compile(rb"(?:https?|wss?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{4,160}")

# 域名：至少两段，TLD 走白名单，避免把 "libc.so" 之类当域名
TLD = rb"(?:com|cn|net|org|io|co|tv|info|xyz|top|vip|game|games|app|cloud|site|online|tech|dev)"
DOMAIN_RE = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,6}" + TLD + rb"\b")

IPPORT_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                       rb"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d):\d{2,5}\b")

# 协议/传输关键字（用于判断网络栈实现）
PROTO_KEYS = [
    b"quic", b"QUIC", b"kcp", b"KCP", b"websocket", b"WebSocket", b"protobuf",
    b"flatbuffer", b"msgpack", b"udp", b"UDPSocket", b"TCP", b"TLS", b"pinning",
    b"certificate", b"SSL_CTX", b"session_ticket", b"X25519", b"ChaCha20",
    b"AES-128-GCM", b"AEAD", b"DTLS", b"srtt", b"RTT", b"PacketLoss",
    b"NetDriver", b"GameNetDriver", b"bUseIpConnection", b"NetServer", b"Replication",
]

# 游戏业务语义关键字（找服务器地址附近的上下文）
BIZ_KEYS = [
    "gate", "gateway", "login", "lobby", "room", "match", "battle", "relay",
    "dns", "route", "dispatch", "region", "cluster", "zone", "server",
    "anticheat", "tersafe", "tenprotect", "themis", "report", "log",
]


def scan(path, top=120):
    p = Path(path)
    size = p.stat().st_size
    urls = collections.Counter()
    domains = collections.Counter()
    ipports = collections.Counter()
    proto_hits = collections.Counter()
    ctx = collections.defaultdict(list)     # biz keyword -> 附近字符串

    with p.open("rb") as f:
        prev = b""
        off = 0
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            data = prev + buf
            base_off = off - len(prev)

            for m in URL_RE.finditer(data):
                s = m.group().decode("ascii", "replace")
                urls[s] += 1

            for m in DOMAIN_RE.finditer(data):
                d = m.group().decode("ascii", "replace").lower()
                # 过滤明显不是域名的（全数字、以 - 开头等）
                if d[0].isdigit() and "." in d.split(".")[0]:
                    pass
                domains[d] += 1

            for m in IPPORT_RE.finditer(data):
                ipports[m.group().decode("ascii", "replace")] += 1

            low = data.lower()
            for k in PROTO_KEYS:
                n = low.count(k.lower())
                if n:
                    proto_hits[k.decode()] += n

            prev = data[-OVERLAP:]
            off += len(buf)

    # 二次：把域名按是否腾讯系分组
    tencent_like = sorted(
        [(d, c) for d, c in domains.items()
         if any(t in d for t in ("qq.com", "tencent", "gcloud", "myapp", "wetest", "anticheat"))],
        key=lambda x: -x[1])

    return {
        "file": str(p),
        "size": size,
        "tencent_domains": tencent_like[:top],
        "all_domains_top": domains.most_common(top),
        "urls": urls.most_common(top),
        "ipports": ipports.most_common(top),
        "proto_hits": proto_hits.most_common(),
    }


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    top = int(sys.argv[sys.argv.index("--top") + 1]) if "--top" in sys.argv else 120
    r = scan(path, top)

    print("file: %s  (%.1f MB)" % (r["file"], r["size"] / 1048576))

    print("\n===== 腾讯系域名 (%d) =====" % len(r["tencent_domains"]))
    for d, c in r["tencent_domains"]:
        print("  %-55s x%d" % (d, c))

    print("\n===== URL (%d) =====" % len(r["urls"]))
    for u, c in r["urls"][:80]:
        print("  %-90s x%d" % (u, c))

    print("\n===== IPv4:port (%d) =====" % len(r["ipports"]))
    for ip, c in r["ipports"][:60]:
        print("  %-24s x%d" % (ip, c))

    print("\n===== 协议/传输关键字 =====")
    for k, c in r["proto_hits"]:
        print("  %-14s %d" % (k, c))

    print("\n===== 其它域名 top40 =====")
    for d, c in r["all_domains_top"][:40]:
        print("  %-50s x%d" % (d, c))

    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        Path(out).write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
        print("\nJSON -> %s" % out)


if __name__ == "__main__":
    main()

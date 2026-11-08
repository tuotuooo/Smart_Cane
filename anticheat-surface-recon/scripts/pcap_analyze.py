#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap 网络逻辑分析器（纯标准库，无 scapy 依赖）

用途：分析 Android tcpdump -i any 抓到的 pcap，提取
  - DNS 查询域名 -> 解析结果
  - TLS ClientHello SNI（明文可见，即使后续加密）
  - HTTP Host 头（未加密的话）
  - 端点排名（IP:port，包数/字节数）
  - QUIC 检测（UDP 443 首字节 0xC0+ 特征）

用法：
  python pcap_analyze.py dfm_cold.pcap
  python pcap_analyze.py dfm_cold.pcap --json out.json
"""
import sys
import json
import struct
import collections
from pathlib import Path


# ---------------------------------------------------------------- pcap 读取
def read_pcapng(data):
    """pcapng：SHB / IDB / EPB / SPB。
    PCAPdroid、Wireshark 默认都可能导出这个格式，不能只认经典 pcap。
    返回 (ts, packet, linktype)；多接口时按 interface_id 取各自 linktype。
    """
    pos = 0
    n = len(data)
    endian = "<"
    linktypes = []      # 每个 IDB 的 linktype
    tsresol = []        # 每个 IDB 的时间戳精度（秒/单位）
    while pos + 12 <= n:
        btype = struct.unpack(endian + "I", data[pos:pos + 4])[0]
        if btype == 0x0A0D0D0A:      # SHB，字节序在此确定
            bom = data[pos + 8:pos + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            linktypes, tsresol = [], []
        blen = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
        if blen < 12 or pos + blen > n:
            break
        body = data[pos + 8:pos + blen - 4]

        if btype == 0x00000001:      # IDB
            lt = struct.unpack(endian + "H", body[0:2])[0]
            linktypes.append(lt)
            res = 1e-6
            off = 8
            while off + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[off:off + 4])
                if code == 0:
                    break
                val = body[off + 4:off + 4 + olen]
                if code == 9 and olen >= 1:      # if_tsresol
                    v = val[0]
                    res = (2.0 ** -(v & 0x7F)) if (v & 0x80) else (10.0 ** -v)
                off += 4 + ((olen + 3) // 4) * 4
            tsresol.append(res)

        elif btype == 0x00000006:    # EPB
            if len(body) < 20:
                pos += blen
                continue
            iface, tsh, tsl, caplen, _orig = struct.unpack(endian + "IIIII", body[0:20])
            pkt = body[20:20 + caplen]
            lt = linktypes[iface] if iface < len(linktypes) else None
            res = tsresol[iface] if iface < len(tsresol) else 1e-6
            if lt is not None:
                yield ((tsh << 32) | tsl) * res, pkt, lt

        elif btype == 0x00000003:    # SPB（无时间戳，用 0）
            if len(body) >= 4:
                orig = struct.unpack(endian + "I", body[0:4])[0]
                lt = linktypes[0] if linktypes else None
                if lt is not None:
                    yield 0.0, body[4:4 + orig], lt

        pos += blen


def read_pcap(path):
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise SystemExit("文件太小，不是 pcap")
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":          # pcapng
        for x in read_pcapng(data):
            yield x
        return
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        raise SystemExit("未知 pcap 魔数: %s（可能是 pcapng，请用 tcpdump -w 重抓）" % magic.hex())

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    n = len(data)
    while off + 16 <= n:
        ts_sec, ts_usec, caplen, _origlen = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + caplen > n:
            break
        yield ts_sec + ts_usec / (1e9 if nano else 1e6), data[off:off + caplen], linktype
        off += caplen


# ---------------------------------------------------------------- 链路层剥壳
def strip_l2(pkt, linktype):
    """返回 (ether_type, payload)"""
    if linktype == 1:          # Ethernet
        if len(pkt) < 14:
            return None, b""
        et = struct.unpack(">H", pkt[12:14])[0]
        return et, pkt[14:]
    if linktype == 113:        # Linux SLL (tcpdump -i any 的默认)
        if len(pkt) < 16:
            return None, b""
        et = struct.unpack(">H", pkt[14:16])[0]
        return et, pkt[16:]
    if linktype == 276:        # Linux SLL2
        if len(pkt) < 20:
            return None, b""
        et = struct.unpack(">H", pkt[0:2])[0]
        return et, pkt[20:]
    if linktype == 0:          # BSD loopback
        return struct.unpack(">I", pkt[:4])[0] & 0xFFFF, pkt[4:]
    if linktype in (12, 101):  # RAW IP（PCAPdroid 的典型输出、tcpdump -i 任意 iface 也可能）
        if not pkt:
            return None, b""
        ver = pkt[0] >> 4
        if ver == 4:
            return 0x0800, pkt
        if ver == 6:
            return 0x86DD, pkt
        return None, b""
    if linktype == 228:        # LINKTYPE_IPV4
        return 0x0800, pkt
    if linktype == 229:        # LINKTYPE_IPV6
        return 0x86DD, pkt
    return None, b""


# ---------------------------------------------------------------- IPv4
def parse_ipv4(buf):
    if len(buf) < 20:
        return None
    ver_ihl = buf[0]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl:
        return None
    proto = buf[9]
    src = "%d.%d.%d.%d" % tuple(buf[12:16])
    dst = "%d.%d.%d.%d" % tuple(buf[16:20])
    total_len = struct.unpack(">H", buf[2:4])[0]
    frag_off = struct.unpack(">H", buf[6:8])[0]
    if frag_off & 0x1FFF:
        return {"proto": proto, "src": src, "dst": dst, "l4": b"", "frag": True}
    return {"proto": proto, "src": src, "dst": dst, "l4": buf[ihl:total_len], "frag": False}


def parse_l4(info):
    l4 = info["l4"]
    if info["proto"] == 6 and len(l4) >= 20:            # TCP
        sport, dport = struct.unpack(">HH", l4[:4])
        doff = (l4[12] >> 4) * 4
        flags = l4[13]
        payload = l4[doff:] if doff >= 20 else b""
        return {"kind": "tcp", "sport": sport, "dport": dport,
                "flags": flags, "payload": payload}
    if info["proto"] == 17 and len(l4) >= 8:            # UDP
        sport, dport = struct.unpack(">HH", l4[:4])
        return {"kind": "udp", "sport": sport, "dport": dport,
                "flags": 0, "payload": l4[8:]}
    return None


# ---------------------------------------------------------------- DNS
def parse_dns_name(buf, off):
    labels, jumped, safety = [], False, 0
    while off < len(buf) and safety < 64:
        safety += 1
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                break
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                off += 2
                jumped = True
            off = ptr
            continue
        off += 1
        labels.append(buf[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(labels), off


def parse_dns(payload):
    """返回 (query_names, answers)"""
    if len(payload) < 12:
        return [], []
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", payload[:12])
    is_resp = bool(flags & 0x8000)
    off = 12
    queries = []
    for _ in range(qd):
        name, off = parse_dns_name(payload, off)
        if off + 4 > len(payload):
            break
        qtype, qclass = struct.unpack(">HH", payload[off:off + 4])
        off += 4
        queries.append((name, qtype))
    answers = []
    for _ in range(an):
        name, off = parse_dns_name(payload, off)
        if off + 10 > len(payload):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", payload[off:off + 10])
        off += 10
        rdata = payload[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append(("%d.%d.%d.%d" % tuple(rdata), name))
        elif rtype == 5:
            tgt, _ = parse_dns_name(payload, off - rdlen)
            answers.append((tgt, name))
    return (queries if not is_resp else []), (answers if is_resp else [])


# ---------------------------------------------------------------- TLS SNI
def parse_tls_sni(payload):
    """从 TCP payload 里抠 ClientHello 的 SNI"""
    if len(payload) < 6 or payload[0] != 0x16:
        return None
    if payload[1] != 0x03:
        return None
    try:
        off = 5
        if payload[off] != 0x01:          # ClientHello
            return None
        off += 4                          # handshake type(1) + length(3) -> 指向 client_version
        off += 2 + 32                     # client_version(2) + random(32)
        sid_len = payload[off]; off += 1 + sid_len
        cs_len = struct.unpack(">H", payload[off:off + 2])[0]; off += 2 + cs_len
        cm_len = payload[off]; off += 1 + cm_len
        if off + 2 > len(payload):
            return None
        ext_total = struct.unpack(">H", payload[off:off + 2])[0]; off += 2
        end = min(off + ext_total, len(payload))
        while off + 4 <= end:
            etype, elen = struct.unpack(">HH", payload[off:off + 4])
            off += 4
            if etype == 0x0000:           # server_name
                if off + 5 > len(payload):
                    return None
                # list_len(2) + type(1) + name_len(2)
                nlen = struct.unpack(">H", payload[off + 3:off + 5])[0]
                return payload[off + 5:off + 5 + nlen].decode("ascii", "replace")
            off += elen
    except Exception:
        return None
    return None


def parse_http_host(payload):
    if not payload[:5].lower() in (b"get /", b"post ", b"host "):
        if b"Host: " not in payload[:2000]:
            return None
    i = payload.find(b"Host: ")
    if i < 0:
        return None
    j = payload.find(b"\r\n", i)
    return payload[i + 6:j].decode("ascii", "replace")


# ---------------------------------------------------------------- 主流程
def guess_local_ip(path):
    """本机 IP：出现频次最高的私网地址（模拟器通常是 10.0.2.15）"""
    cnt = collections.Counter()
    for _ts, pkt, lt in read_pcap(path):
        et, payload = strip_l2(pkt, lt)
        if et != 0x0800:
            continue
        ip = parse_ipv4(payload)
        if not ip:
            continue
        for a in (ip["src"], ip["dst"]):
            if a.startswith(("10.", "192.168.", "172.")):
                cnt[a] += 1
    return cnt.most_common(1)[0][0] if cnt else None


def analyze(path):
    local_ip = guess_local_ip(path)
    linktype = None
    dns_q = collections.Counter()      # 域名 -> 查询次数
    dns_a = collections.defaultdict(set)   # 域名 -> 解析 IP 集合
    sni = collections.Counter()        # SNI -> 次数
    sni_by_ip = collections.defaultdict(set)   # IP:port -> {SNI}
    endpoint = collections.defaultdict(lambda: {"pkts": 0, "bytes": 0, "dirs": set()})
    proto_mix = collections.Counter()
    quic_hint = collections.Counter()
    http_hosts = collections.Counter()
    tls_versions = collections.Counter()

    first_ts = last_ts = None
    npkt = 0

    for ts, pkt, lt in read_pcap(path):
        linktype = lt
        npkt += 1
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        et, payload = strip_l2(pkt, lt)
        if et != 0x0800:               # 只看 IPv4
            continue
        ip = parse_ipv4(payload)
        if not ip or ip["frag"]:
            continue
        l4 = parse_l4(ip)
        if not l4:
            continue
        proto_mix[l4["kind"]] += 1

        # DNS
        if l4["kind"] == "udp" and 53 in (l4["sport"], l4["dport"]):
            q, a = parse_dns(l4["payload"])
            for name, _qt in q:
                dns_q[name] += 1
            for ipaddr, owner in a:
                dns_a[owner].add(ipaddr)
            continue

        # 方向：以本机 IP 为准
        if ip["src"] == local_ip:
            srv_ip, srv_port, direction = ip["dst"], l4["dport"], "out"
        else:
            srv_ip, srv_port, direction = ip["src"], l4["sport"], "in"
        key = (srv_ip, srv_port, l4["kind"])
        e = endpoint[key]
        e["pkts"] += 1
        e["bytes"] += len(l4["payload"])
        e["dirs"].add(direction)

        # TLS / HTTP
        if l4["kind"] == "tcp" and l4["payload"] and direction == "out":
            s = parse_tls_sni(l4["payload"])
            if s:
                sni[s] += 1
                sni_by_ip["%s:%d" % (srv_ip, srv_port)].add(s)
                tls_versions["0x%02x%02x" % (l4["payload"][9], l4["payload"][10])] += 1
            else:
                h = parse_http_host(l4["payload"])
                if h:
                    http_hosts[h] += 1

        # QUIC 特征：UDP 443 且首字节高位 0xC0
        if l4["kind"] == "udp" and 443 in (l4["sport"], l4["dport"]) and l4["payload"]:
            if l4["payload"][0] & 0xC0:
                quic_hint[srv_ip] += 1

    return {
        "file": str(path),
        "linktype": linktype,
        "local_ip": local_ip,
        "packets": npkt,
        "duration_s": round((last_ts - first_ts), 1) if first_ts else 0,
        "proto_mix": dict(proto_mix),
        "tls_versions": dict(tls_versions),
        "dns_queries": dns_q.most_common(),
        "dns_answers": {k: sorted(v) for k, v in dns_a.items()},
        "tls_sni": sni.most_common(),
        "sni_by_endpoint": {k: sorted(v) for k, v in sni_by_ip.items()},
        "http_hosts": http_hosts.most_common(),
        "quic_hosts": quic_hint.most_common(),
        "endpoints": [
            {"ip": ip, "port": p, "proto": k, "pkts": v["pkts"],
             "bytes": v["bytes"], "dirs": "".join(sorted(v["dirs"]))}
            for (ip, p, k), v in sorted(endpoint.items(), key=lambda x: -x[1]["bytes"])
        ],
    }


def as_markdown(r):
    L = []
    L.append("# 抓包分析：%s\n" % Path(r["file"]).name)
    L.append("- 包数 **%d**，时长 **%.1f s**，链路层 linktype=%s" %
             (r["packets"], r["duration_s"], r["linktype"]))
    L.append("- 协议分布：%s\n" % ", ".join("%s=%d" % (k, v) for k, v in r["proto_mix"].items()))

    L.append("\n## 1. DNS 查询（域名 → IP）\n")
    if r["dns_queries"]:
        L.append("| 域名 | 查询次数 | 解析到 |")
        L.append("|---|---|---|")
        for name, cnt in r["dns_queries"][:60]:
            ips = r["dns_answers"].get(name, [])
            L.append("| `%s` | %d | %s |" % (name, cnt, ", ".join(ips[:4]) or "—"))
    else:
        L.append("（本次窗口内无 DNS 明文查询——可能是 HTTPDNS 直连，或解析结果走缓存）")

    L.append("\n## 2. TLS SNI（HTTPS 目标域名，证书加密后仍可见）\n")
    if r["tls_sni"]:
        for s, c in r["tls_sni"]:
            L.append("- `%s` ×%d" % (s, c))
    else:
        L.append("（无 ClientHello —— 可能复用了已有连接，或全部走 IP 直连）")

    if r["http_hosts"]:
        L.append("\n## 3. 明文 HTTP Host\n")
        for h, c in r["http_hosts"]:
            L.append("- `%s` ×%d" % (h, c))

    if r["quic_hosts"]:
        L.append("\n## 4. QUIC 迹象（UDP/443）\n")
        for h, c in r["quic_hosts"]:
            L.append("- `%s` ×%d" % (h, c))

    L.append("\n## 5. 端点归属（IP ↔ SNI 关联）\n")
    L.append("| # | 目标 | 协议 | 包数 | 载荷字节 | 归属域名 |")
    L.append("|---|---|---|---|---|---|")
    unknown = []
    for i, e in enumerate(r["endpoints"][:40], 1):
        key = "%s:%d" % (e["ip"], e["port"])
        names = r["sni_by_endpoint"].get(key, [])
        owner = ", ".join("`%s`" % n for n in names) if names else "**?（无 SNI）**"
        if not names and e["port"] == 443:
            unknown.append(e)
        L.append("| %d | `%s` | %s | %d | %d | %s |" %
                 (i, key, e["proto"], e["pkts"], e["bytes"], owner))

    if unknown:
        L.append("\n### 无 SNI 的 443 端点（疑似业务服务器或连接早于抓包）\n")
        for e in unknown:
            L.append("- `%s:%d`  %d 包 / %d 字节" % (e["ip"], e["port"], e["pkts"], e["bytes"]))

    nonssl = [e for e in r["endpoints"][:40] if e["proto"] == "tcp" and e["port"] not in (443, 80)]
    if nonssl:
        L.append("\n### 非标准端口（自定义协议的重点嫌疑）\n")
        for e in nonssl:
            L.append("- `%s:%d`  %d 包 / %d 字节" % (e["ip"], e["port"], e["pkts"], e["bytes"]))
    return "\n".join(L)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    r = analyze(path)
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        Path(out).write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
        print("JSON -> %s" % out)
    md = as_markdown(r)
    mdpath = Path(path).with_suffix(".report.md")
    mdpath.write_text(md, encoding="utf-8")
    print(md)
    print("\n报告 -> %s" % mdpath)


if __name__ == "__main__":
    main()

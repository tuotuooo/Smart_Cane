#!/usr/bin/env python3
"""UDP 流分析：为"进对局后战斗面是什么协议"准备判据。

不解析游戏语义，只回答四个可测量的客观问题：
  1. 有多少条 UDP 流，客户端→服务端是哪些 5 元组
  2. 下行包间隔的分布 → 反推 tick rate（30Hz=33.3ms / 60Hz=16.7ms / 20Hz=50ms）
  3. 载荷长度分布 → 单帧快照大小、是否贴近 MTU
  4. 载荷是否加密 / 是不是 KCP / 是不是 QUIC

用法:
    python udp_flow.py capture.pcap
    python udp_flow.py capture.pcap --json out.json
"""
import sys, json, collections, math, struct, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_analyze import read_pcap, strip_l2, parse_ipv4, parse_l4


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def kcp_check(p):
    """KCP 固定头 24B: conv(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4)
    cmd: 0x81 push / 0x82 ack / 0x83 wack / 0x84 probe / 0x85 wnd / 0x86 err"""
    if len(p) < 24:
        return None
    conv = struct.unpack_from("<I", p, 0)[0]
    cmd = p[4]
    frg = p[5]
    if cmd not in (0x81, 0x82, 0x83, 0x84, 0x85, 0x86):
        return None
    if frg > 0x7f:
        return None
    if conv == 0:
        return None
    ln = struct.unpack_from("<I", p, 20)[0]
    if ln > len(p):
        return None
    return {"conv": conv, "cmd": hex(cmd), "frg": frg, "declared_len": ln}


def quic_check(p):
    if len(p) < 5:
        return False
    if not (p[0] & 0x80):
        return False
    ver = struct.unpack_from(">I", p, 1)[0]
    return ver != 0 or (p[0] & 0xC0) == 0xC0


def hist_bucket(ms):
    for lim, name in ((5, "<=5"), (10, "5-10"), (20, "10-20"), (40, "20-40"),
                      (70, "40-70"), (120, "70-120"), (250, "120-250"),
                      (600, "250-600"), (2000, "600-2000")):
        if ms <= lim:
            return name
    return ">2000"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    out_json = None
    if "--json" in sys.argv:
        out_json = sys.argv[sys.argv.index("--json") + 1]

    # 定向为键：上行和下行必须分开统计，否则 60Hz 上行会把 30Hz 下行的间隔分布盖掉
    flows = collections.defaultdict(lambda: {
        "ts": [], "sizes": [], "payload_sample": b"", "kcp": 0, "kcp_conv": set(),
        "quic": 0, "custom2255": 0, "first_bytes": collections.Counter(),
    })
    n_udp = 0
    n_pkt = 0
    first_ts_of_pair = {}          # 用于判断谁是服务端

    for ts, pkt, lt in read_pcap(path):
        n_pkt += 1
        et, payload = strip_l2(pkt, lt)
        if et != 0x0800:
            continue
        ip = parse_ipv4(payload)
        if not ip or ip["frag"]:
            continue
        l4 = parse_l4(ip)
        if not l4 or l4["kind"] != "udp":
            continue
        p = l4["payload"]
        if not p:
            continue
        n_udp += 1
        a = (ip["src"], l4["sport"])
        b = (ip["dst"], l4["dport"])
        pair = tuple(sorted([a, b]))
        first_ts_of_pair.setdefault(pair, (ts, b))   # 首包的目的端 = 服务端
        key = (a, b)
        f = flows[key]
        f["ts"].append(ts)
        f["sizes"].append(len(p))
        f["first_bytes"][p[0]] += 1
        if len(f["payload_sample"]) < 65536:
            f["payload_sample"] += p[:512]
        k = kcp_check(p)
        if k:
            f["kcp"] += 1
            f["kcp_conv"].add(k["conv"])
        if quic_check(p):
            f["quic"] += 1
        if p[:2] == b"\x22\x55":
            f["custom2255"] += 1

    rows = []
    for (a, b), f in flows.items():
        pair = tuple(sorted([a, b]))
        # 服务端判定：端口更小的那端；端口相同则取首包目的端
        _, first_dst = first_ts_of_pair.get(pair, (0, b))
        if a[1] != b[1]:
            server = a if a[1] < b[1] else b
        else:
            server = first_dst
        client = b if server == a else a
        direction = "下行" if (a == server) else "上行"
        ts = sorted(f["ts"])
        gaps = [(ts[i] - ts[i - 1]) * 1000 for i in range(1, len(ts))]
        h = collections.Counter(hist_bucket(g) for g in gaps)
        med = sorted(gaps)[len(gaps) // 2] if gaps else 0
        rows.append({
            "direction": direction,
            "client": "%s:%d" % client,
            "server": "%s:%d" % server,
            "packets": len(f["ts"]),
            "bytes": sum(f["sizes"]),
            "duration_s": round(ts[-1] - ts[0], 2) if len(ts) > 1 else 0,
            "median_gap_ms": round(med, 1),
            "implied_hz": round(1000 / med, 1) if med else None,
            "gap_hist": dict(h),
            "size_min": min(f["sizes"]), "size_max": max(f["sizes"]),
            "size_avg": round(sum(f["sizes"]) / len(f["sizes"]), 1),
            "entropy": round(entropy(f["payload_sample"]), 2),
            "kcp_hits": f["kcp"], "kcp_conv": sorted(f["kcp_conv"])[:5],
            "quic_hits": f["quic"], "frame2255": f["custom2255"],
            "top_first_byte": [[hex(x), c] for x, c in f["first_bytes"].most_common(3)],
        })
    rows.sort(key=lambda r: -r["bytes"])

    L = ["# UDP 流分析", "",
         "总包 %d，其中 UDP %d，定向流 %d 条（同一会话的上行/下行分开统计）" % (n_pkt, n_udp, len(rows)), ""]
    if not rows:
        L.append("**没有任何 UDP 流量。** 说明当前阶段全部是 TCP（登录前正常，对战面必然有 UDP）。")
    else:
        L += ["| 方向 | 客户端 | 服务端 | 包数 | 字节 | 时长s | 中位间隔ms | 反推Hz | 载荷min/max/avg | 熵 | KCP | QUIC | 2255帧 |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in rows[:30]:
            L.append("| %s | `%s` | `%s` | %d | %d | %s | %s | %s | %d/%d/%s | %s | %d | %d | %d |" % (
                r["direction"], r["client"], r["server"], r["packets"], r["bytes"], r["duration_s"],
                r["median_gap_ms"], r["implied_hz"], r["size_min"], r["size_max"],
                r["size_avg"], r["entropy"], r["kcp_hits"], r["quic_hits"], r["frame2255"]))
        L += ["", "## 判读", ""]
        kcp_rows = [r for r in rows if r["packets"] and r["kcp_hits"] > r["packets"] * 0.5]
        if kcp_rows:
            L.append("- **KCP 确认**：%d 条定向流中 >50%% 的包符合 KCP 24B 头（conv=%s）。" %
                     (len(kcp_rows), kcp_rows[0]["kcp_conv"]))
        else:
            L.append("- **未见 KCP 头**：byte[4] 不在 0x81–0x86 或 conv=0。可能是自定义 UDP 协议，"
                     "也可能是加密后失去了固定头。")
        down = [r for r in rows if r["direction"] == "下行" and r["implied_hz"]]
        if down:
            d = max(down, key=lambda r: r["bytes"])
            L.append("- **下行 tick 估计**：`%s` 中位间隔 %sms → **约 %s Hz**，单帧平均 %s 字节。" %
                     (d["server"], d["median_gap_ms"], d["implied_hz"], d["size_avg"]))
        for r in rows[:4]:
            if r["entropy"] >= 7.5:
                L.append("- `%s`（%s）熵 %.2f → 载荷高熵，**内容已加密**，只能做统计测量。" %
                         (r["server"], r["direction"], r["entropy"]))
            elif r["entropy"] <= 6.0:
                L.append("- `%s`（%s）熵 %.2f → **可能明文或半明文**，值得逐字节看。" %
                         (r["server"], r["direction"], r["entropy"]))
        L.append("")
    txt = "\n".join(L)
    print(txt)
    if out_json:
        json.dump({"packets": n_pkt, "udp": n_udp, "flows": rows},
                  open(out_json, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("JSON 已写:", out_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())

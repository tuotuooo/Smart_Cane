#!/usr/bin/env python3
"""快照结构挖掘器：从一局下行流量里找出"固定长度记录数组"的证据。

用途：在没有符号、没有文档的前提下，判断状态快照里是否存在
「头部 + N × 固定stride 的记录数组」，并给出候选字段偏移。

原理（三步，全部是统计证据，不猜语义）：
  1. 列方差剖面：对每个字节偏移算跨快照方差 → var[i]
  2. 剖面自相关：若存在 stride=s 的记录数组，则 var[i] ≈ var[i+s]
     → 在 s 的倍数上出现峰，峰位即 stride
  3. 浮点列筛选：对每个偏移按 <f 解 LE float32，跨快照统计
     - in_range  值落在合理世界坐标区间（|v| < 1e6，排除 NaN/Inf/次正规）
     - smooth    相邻快照的 |Δ| 很小（实体连续运动）
     两指标同时高的列 = 位置类字段候选

只输出统计结论，不产出任何实时数据流。用于自有环境（离线/自建服务端/纯人机）的引擎研究。

用法:
    python snapshot_miner.py pvp.pcap
    python snapshot_miner.py pvp.pcap --json out.json --max-offset 2048
"""
import sys, os, json, struct, math, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_analyze import read_pcap, strip_l2, parse_ipv4, parse_l4


def collect_flows(path, min_pkts=30):
    """返回全部定向 UDP 流（包数 >= min_pkts），按包数降序。
    不预设谁是服务端——端口大小不可靠，改成逐条探测结构强度。"""
    flows = collections.defaultdict(list)
    for ts, pkt, lt in read_pcap(path):
        et, payload = strip_l2(pkt, lt)
        if et != 0x0800:
            continue
        ip = parse_ipv4(payload)
        if not ip or ip["frag"]:
            continue
        l4 = parse_l4(ip)
        if not l4 or l4["kind"] != "udp" or not l4["payload"]:
            continue
        a = (ip["src"], l4["sport"])
        b = (ip["dst"], l4["dport"])
        flows[(a, b)].append((ts, l4["payload"]))

    out = []
    for key, items in flows.items():
        if len(items) < min_pkts:
            continue
        items.sort(key=lambda x: x[0])
        out.append((key, [p for _, p in items]))
    out.sort(key=lambda x: -len(x[1]))
    return out


def variance_profile(payloads, core):
    """每字节偏移的跨快照方差。只统计足够长的包，避免短包污染。"""
    prof = [0.0] * core
    cnt = [0] * core
    sums = [0] * core
    sqs = [0] * core
    for p in payloads:
        L = min(len(p), core)
        for i in range(L):
            v = p[i]
            sums[i] += v
            sqs[i] += v * v
            cnt[i] += 1
    for i in range(core):
        if cnt[i] < 3:
            continue
        m = sums[i] / cnt[i]
        var = sqs[i] / cnt[i] - m * m
        prof[i] = var if var > 0 else 0.0
    return prof


def stride_peaks(prof, lo=8, hi=512, top=6):
    """剖面自相关：在 stride 的倍数上剖面应相似 → 峰值即候选 stride。
    返回 (top 列表, 全量分数表)，后者用于倍数一致性校验。"""
    n = len(prof)
    mean = sum(prof) / n if n else 0
    d = [v - mean for v in prof]
    energy = sum(v * v for v in d) or 1.0
    smap = {}
    for s in range(lo, min(hi, n // 2) + 1):
        acc = 0.0
        cnt = 0
        for i in range(0, n - s):
            acc += d[i] * d[i + s]
            cnt += 1
        if cnt < s * 2:
            continue
        smap[s] = acc / energy * (cnt / (n - s))
    scores = sorted(((v, s) for s, v in smap.items()), reverse=True)
    out = []
    used = []
    for sc, s in scores:
        if any(abs(s - u) <= 2 for u in used):
            continue
        used.append(s)
        out.append((round(sc, 4), s))
        if len(out) >= top:
            break
    return out, smap


def stride_significant(smap, s, min_score=0.15, ratio=0.70):
    """固定长度记录数组的判据：s 处有峰，且 2s 处仍保留至少 70% 强度。
    随机数据的自相关在相邻小 stride 上也能出高值，但不会在 2s 上稳定复现。"""
    if smap.get(s, 0) < min_score:
        return False, "峰值 %.3f < %.2f" % (smap.get(s, 0), min_score)
    if 2 * s in smap:
        r = smap[2 * s] / smap[s]
        if r < ratio:
            return False, "2s=%d 处仅保留 %.0f%%（< %.0f%%）" % (2 * s, r * 100, ratio * 100)
        return True, "2s 处保留 %.0f%%" % (r * 100)
    return True, "2s 超出范围，无法复核"


def float_columns(payloads, max_off):
    """对每个偏移按 float32 解，统计 in_range 与 smooth。"""
    n = len(payloads)
    if n < 10:
        return []
    cols = []
    for off in range(0, max_off - 3, 4):
        vals = []
        ok = False
        for p in payloads:
            if off + 4 > len(p):
                vals.append(None)
                continue
            v = struct.unpack_from("<f", p, off)[0]
            vals.append(v)
            ok = True
        if not ok:
            continue
        good = 0
        numeric = 0
        for v in vals:
            if v is None:
                continue
            if math.isnan(v) or math.isinf(v):
                continue
            if abs(v) < 1e-30:      # 次正规/零，位置字段极少长期为 0
                continue
            numeric += 1
            if abs(v) < 1e6:
                good += 1
        if numeric < 6:
            continue
        in_range = good / max(numeric, 1)
        # 平滑度：相邻有效值的变化幅度中位数，相对量级归一
        deltas = []
        prev = None
        for v in vals:
            if v is None or math.isnan(v) or math.isinf(v) or abs(v) < 1e-30:
                prev = None
                continue
            if prev is not None:
                deltas.append(abs(v - prev) / max(abs(prev), 1.0))
            prev = v
        if not deltas:
            continue
        # 常数列排除：跨快照完全不变的不是位置字段（是 conv / ID / 标记）
        vals_ok = [v for v in vals if v is not None and not math.isnan(v) and not math.isinf(v)]
        if len(vals_ok) >= 6:
            mv = sum(vals_ok) / len(vals_ok)
            sd = (sum((v - mv) ** 2 for v in vals_ok) / len(vals_ok)) ** 0.5
            if sd < max(abs(mv) * 1e-6, 1e-9):
                cols.append({"offset": off, "const": True,
                             "in_range": round(in_range, 3), "smooth": 0.0,
                             "median_rel_delta": 0.0, "score": 0.0,
                             "sample": [round(v, 2) for v in vals if v is not None][:3]})
                continue
        deltas.sort()
        med = deltas[len(deltas) // 2]
        smooth = 1.0 / (1.0 + med * 50.0)     # 中位相对变化 0 → 1.0；0.02 → 0.5
        cols.append({
            "offset": off,
            "const": False,
            "in_range": round(in_range, 3),
            "smooth": round(smooth, 3),
            "median_rel_delta": round(med, 5),
            "score": round(in_range * smooth, 3),
            "sample": [round(v, 2) for v in vals if v is not None][:4],
        })
    cols.sort(key=lambda c: -c["score"])
    return cols


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    max_off = 2048
    out_json = None
    if "--max-offset" in sys.argv:
        max_off = int(sys.argv[sys.argv.index("--max-offset") + 1])
    if "--json" in sys.argv:
        out_json = sys.argv[sys.argv.index("--json") + 1]

    flows = collect_flows(path)
    if not flows:
        print("没有找到包数 >=30 的 UDP 流。")
        print("→ 说明这份抓包不含战斗面流量（登录前/大厅）。需要进图后的抓包。")
        return 2

    # 逐条流探测结构强度，取最强的一条
    best = None
    for key, payloads in flows:
        # 口径修正：不能直接取全体长度的 10% 分位——同一会话里常常混着几十字节的
        # 心跳/ACK，会把分位数拉到 40B 以下，导致整条流被判"太短"而跳过。
        # 先剔掉 <32B 的碎片，再取中位数作为公共核心长度。
        lens0 = sorted(len(p) for p in payloads if len(p) >= 32)
        if not lens0:
            continue
        core0 = min(max_off, lens0[len(lens0) // 2])
        if core0 < 64:
            continue
        prof0 = variance_profile(payloads, core0)
        pk0, smap0 = stride_peaks(prof0)
        # 排序用"最显著的 stride"分数，避免随机数据在小 stride 上骗到高分
        sig = [sc for sc, s in pk0 if stride_significant(smap0, s)[0]]
        top = max(sig) if sig else (pk0[0][0] * 0.5 if pk0 else 0)
        if best is None or top > best[0]:
            best = (top, key, payloads, core0, prof0, pk0, smap0)
    if best is None:
        print("所有 UDP 流的载荷都太短，无法做结构分析。")
        return 2

    _, key, payloads, core, prof, peaks, smap = best
    n = len(payloads)
    cols = float_columns(payloads[:400], min(core, max_off))
    strong = [c for c in cols if not c.get("const") and c["score"] >= 0.55]
    consts = [c for c in cols if c.get("const")]

    L = ["# 快照结构挖掘", "",
         "共 %d 条定向 UDP 流，此处展示结构最强的一条：" % len(flows), "",
         "`%s -> %s`，%d 个包，核心区 %d 字节" % (
             "%s:%d" % key[0], "%s:%d" % key[1], n, core), "",
         "## 1. 候选 stride（固定记录长度的证据）", "",
         "| 分数 | stride | 倍数复核 | 判定 |", "|---|---|---|---|"]
    for sc, s in peaks:
        ok, why = stride_significant(smap, s)
        L.append("| %s | **%d** | %s | %s |" % (sc, s, why, "✅ 显著" if ok else "✗ 不成立"))
    any_sig = any(stride_significant(smap, s)[0] for _, s in peaks)
    if not any_sig:
        L += ["", "> **没有任何 stride 通过倍数复核。** 可能原因：载荷已加密、"
              "记录变长编码、或快照是稀疏字段而非定长数组。"
              "→ 字段测绘到此为止，退回统计侧信道（tick / 带宽 / 重传）。"]

    L += ["", "## 2. 候选浮点字段（按 in_range × smooth 排序）", ""]
    if strong:
        L += ["| 偏移 | in_range | smooth | 中位相对变化 | 样本 |", "|---|---|---|---|---|"]
        for c in strong[:20]:
            L.append("| **%d** | %s | %s | %s | %s |" % (
                c["offset"], c["in_range"], c["smooth"],
                c["median_rel_delta"], c["sample"]))
    else:
        L.append("没有偏移同时满足 in_range ≥0.55 且 smooth ≥0.55。")
        live = [c for c in cols if not c.get("const")]
        if live:
            L.append("")
            L.append("最接近的 5 个：")
            for c in live[:5]:
                L.append("- 偏移 %d：in_range=%s smooth=%s" % (
                    c["offset"], c["in_range"], c["smooth"]))
    if consts:
        L += ["", "常数列（跨快照不变，可能是会话 ID / 标记，非位置字段）：%s"
              % ", ".join(str(c["offset"]) for c in consts[:12])]

    # 交叉证据：浮点字段间距是否等于 stride
    sig_peaks = [(sc, s) for sc, s in peaks if stride_significant(smap, s)[0]]
    if sig_peaks and strong:
        s = sig_peaks[0][1]
        offs = [c["offset"] for c in strong]
        pairs = sum(1 for i in range(len(offs)) for j in range(i + 1, len(offs))
                    if (offs[j] - offs[i]) % s == 0)
        total_pairs = max(len(offs) * (len(offs) - 1) // 2, 1)
        L += ["", "## 3. 交叉验证", "",
              "显著 stride = %d；强浮点列 %d 个，其中 %d/%d 对间距是该 stride 的整数倍。" %
              (s, len(offs), pairs, total_pairs)]
        if pairs >= total_pairs // 2:
            L.append("")
            L.append("**结论：存在固定 %d 字节记录数组，且内部含连续 float32 字段——"
                     "与「每实体固定大小、含位置向量」的结构一致。**" % s)
        else:
            L.append("")
            L.append("间距关系不成立，浮点列可能是全局字段而非逐实体字段。")

    txt = "\n".join(L)
    print(txt)
    if out_json:
        json.dump({"flow": ["%s:%d" % key[0], "%s:%d" % key[1]], "packets": n,
                   "core": core, "strides": peaks, "float_columns": cols[:40]},
                  open(out_json, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("\nJSON 已写:", out_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""SiFli OTA：从 btsnoop 空口日志还原固件镜像。

背景：SiFli 的 DFU 被厂商配成走自定义透传特征（不一定是 sifli_sd 服务），
所以先按"某个 handle 上几千个 WRITE_CMD"找数据面，再按帧结构重组。

帧结构（实测 V2）：
    [cateID 1B = 0x01] [片号 1B] [总长 2B LE] [数据]
    片号 01=首片(240B) 02=中片(240B) 03=尾片(74B)  → 一条消息 554B
    总长字段 = 554 + 4 = 558（是【整条消息】长度，不是本帧）

用法：
    # 先诊断，找数据面 handle
    python snoop_parse.py info hci.bin

    # 还原镜像
    python snoop_ota.py hci.bin --handle 0x200 --dir h2c -o fw.bin

    # 只看结构不落盘
    python snoop_ota.py hci.bin --handle 0x200 --dry-run
"""
import argparse
import collections
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snoop_parse import iter_att  # noqa: E402

MAGIC_CATE = 0x01
FRAG_FIRST, FRAG_MID, FRAG_LAST = 0x01, 0x02, 0x03


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="btsnoop 日志（.cfa / .curf 解压后的文件）")
    ap.add_argument("--handle", default="0x200", help="数据面 handle，如 0x200")
    ap.add_argument("--dir", default="h2c", choices=["h2c", "c2h"], help="h2c=手机→设备")
    ap.add_argument("-o", "--out", default=None, help="输出镜像路径")
    ap.add_argument("--dry-run", action="store_true", help="只统计不写文件")
    a = ap.parse_args()

    handle = int(a.handle, 0)
    dirn = 0 if a.dir == "h2c" else 1

    msgs, cur = [], bytearray()
    stats = collections.Counter()
    declared = None

    for ts, d, h, op, val, pdu in iter_att(a.file, handle=handle, dirn=dirn):
        if op not in (0x52, 0x12):      # WRITE_CMD / WRITE_REQ
            continue
        if len(val) < 4 or val[0] != MAGIC_CATE:
            stats["非 OTA 帧"] += 1
            continue
        frag = val[1]
        total = val[2] | (val[3] << 8)
        body = val[4:]
        stats[f"片号 0x{frag:02x}"] += 1

        if frag == FRAG_FIRST:
            if cur:
                msgs.append(bytes(cur))
            cur = bytearray(body)
            declared = total
        elif frag in (FRAG_MID, FRAG_LAST):
            if not cur:
                stats["孤立续片"] += 1
                continue
            cur += body
        else:
            stats["未知片号"] += 1
    if cur:
        msgs.append(bytes(cur))

    if not msgs:
        sys.exit("没有解析到 OTA 消息。先用 snoop_parse.py info 确认 handle 与方向。")

    lens = collections.Counter(len(m) for m in msgs)
    total_bytes = sum(len(m) for m in msgs)
    print(f"消息数 {len(msgs)}, 合计 {total_bytes:,} 字节", file=sys.stderr)
    print(f"消息长度分布 top3: {lens.most_common(3)}", file=sys.stderr)
    print(f"帧统计: {dict(stats)}", file=sys.stderr)
    if declared:
        print(f"首帧声明的总长: {declared}（含 4 字节帧头）", file=sys.stderr)

    blob = b"".join(msgs)
    # 结构自证
    if len(blob) >= 8:
        sp = int.from_bytes(blob[0:4], "little")
        rv = int.from_bytes(blob[4:8], "little")
        ok = 0x02000000 <= sp <= 0x03000000 and (rv & 1) == 1
        print(f"头部: SP=0x{sp:08X} reset=0x{rv:08X} "
              f"→ {'像 Cortex-M 向量表 ✓' if ok else '不像向量表（可能是密文或非镜像起点）'}",
              file=sys.stderr)

    print(f"SHA256 {hashlib.sha256(blob).hexdigest()}", file=sys.stderr)

    if a.out and not a.dry_run:
        open(a.out, "wb").write(blob)
        print(f"已写出 {a.out} ({os.path.getsize(a.out):,} B)", file=sys.stderr)


if __name__ == "__main__":
    main()

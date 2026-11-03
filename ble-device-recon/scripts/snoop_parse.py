#!/usr/bin/env python3
"""btsnoop 解析 + ATT 剥壳 + 数据面流定位/导出。

用于零 root 抓到的 HCI 日志（见 references/methodology.md 附录 A）。

用法：
  # 1. 诊断：包类型 / ATT 操作码 / 按 handle 的流量榜（先跑这个）
  python snoop_parse.py info hci.bin

  # 2. 某条通道的所有载荷，按顺序拼成一个 stream（每帧长度写入 .lens）
  python snoop_parse.py dump hci.bin --handle 0x200 --dir h2c -o stream.bin

  # 3. 按帧头筛选，打印匹配帧（用来肉眼定界）
  python snoop_parse.py frames hci.bin --handle 0x200 --grep d101 --limit 20

  # 4. 预设：本文件内置 d1 协议（d1 01 ff <u32> 02 <name>\\0 / d1 02 00 <data>），
  #    直接切出文件
  python snoop_parse.py split hci.bin --handle 0x200 --preset d1 -o outdir/

关键事实：
  * H4 包类型看 data[0]（1=CMD 2=ACL 3=SCO 4=EVT），**不是** flags 的 bit1-2。
    flags 只有 bit0 是方向（0=H2C 手机→设备，1=C2H 设备→手机）。
  * ATT 要剥三层：ACL → L2CAP(cid=4) → ATT(opcode/handle/value)。
"""
import argparse
import collections
import os
import struct
import sys

H4 = {1: 'CMD', 2: 'ACL', 3: 'SCO', 4: 'EVT', 5: 'ISO'}
ATT_OP = {
    0x01: 'ERROR_RSP', 0x02: 'MTU_REQ', 0x03: 'MTU_RSP', 0x04: 'FIND_INFO_REQ',
    0x05: 'FIND_INFO_RSP', 0x06: 'FIND_BY_TYPE_REQ', 0x08: 'READ_BY_TYPE_REQ',
    0x09: 'READ_BY_TYPE_RSP', 0x0a: 'READ_REQ', 0x0b: 'READ_RSP',
    0x0c: 'READ_BLOB_REQ', 0x0d: 'READ_BLOB_RSP', 0x10: 'READ_BY_GRP_REQ',
    0x11: 'READ_BY_GRP_RSP', 0x12: 'WRITE_REQ', 0x13: 'WRITE_RSP',
    0x16: 'PREP_WRITE_REQ', 0x17: 'PREP_WRITE_RSP', 0x18: 'EXEC_WRITE_REQ',
    0x19: 'EXEC_WRITE_RSP', 0x1b: 'NOTIFY', 0x1d: 'INDICATE', 0x1e: 'CONFIRM',
    0x52: 'WRITE_CMD',
}
# 有 value 字段的操作码
WITH_VALUE = {0x12, 0x52, 0x1b, 0x1d}


def parse(path):
    """返回 (version, datalink, [(ts_us, dir, data)])；dir: 0=H2C 1=C2H"""
    d = open(path, 'rb').read()
    if d[:8] != b'btsnoop\x00':
        sys.exit('不是 btsnoop 文件（magic 不符）。HCI 日志可能是 .cfa/.curf 变体，先解压。')
    ver, dl = struct.unpack('>II', d[8:16])
    off, recs = 16, []
    while off + 24 <= len(d):
        _orig, incl, flags, _drops = struct.unpack('>IIII', d[off:off + 16])
        ts = struct.unpack('>q', d[off + 16:off + 24])[0]
        if incl > 1 << 20 or off + 24 + incl > len(d):
            break
        recs.append((ts, flags & 1, d[off + 24:off + 24 + incl]))
        off += 24 + incl
    return ver, dl, recs


def att_of(data):
    """H4 ACL → (handle, cid, att_pdu) 或 None。"""
    if not data or data[0] != 2 or len(data) < 5:
        return None
    hdr = struct.unpack('<H', data[1:3])[0]
    handle = hdr & 0x0FFF
    dlen = struct.unpack('<H', data[3:5])[0]
    p = data[5:5 + dlen]
    if len(p) < 4:
        return None
    llen, cid = struct.unpack('<HH', p[:4])
    return handle, cid, p[4:4 + llen]


def iter_att(path, handle=None, dirn=None):
    """产出 (ts, dir, handle, opcode, value, raw_pdu)"""
    _, _, recs = parse(path)
    for ts, d, data in recs:
        if dirn is not None and d != dirn:
            continue
        r = att_of(data)
        if not r:
            continue
        h, cid, pdu = r
        if cid != 4 or not pdu:
            continue
        if handle is not None and h != handle:
            continue
        op = pdu[0]
        val = pdu[3:] if op in WITH_VALUE else b''
        yield ts, d, h, op, val, pdu


def cmd_info(a):
    path = a.file
    ver, dl, recs = parse(path)
    print('btsnoop version=%d datalink=%d records=%d' % (ver, dl, len(recs)))
    kinds = collections.Counter()
    dirs = collections.Counter()
    for ts, d, data in recs:
        kinds[H4.get(data[0], '?%d' % data[0]) if data else 'empty'] += 1
        dirs['H2C' if d == 0 else 'C2H'] += 1
    print('包类型: %s' % dict(kinds))
    print('方向  : %s' % dict(dirs))

    if kinds.get('CMD', 0) > kinds.get('ACL', 0):
        print('⚠ CMD 数量超过 ACL —— H4 类型很可能判错了（应看 data[0]）')

    ops = collections.Counter()
    per_handle = collections.Counter()
    for ts, d, h, op, val, pdu in iter_att(path):
        ops[ATT_OP.get(op, '0x%02x' % op)] += 1
        per_handle[h] += len(val)
    print('\nATT 操作码: %s' % dict(ops.most_common(10)))

    print('\n按 handle 的载荷字节数（Top 10）:')
    for h, n in per_handle.most_common(10):
        print('  handle 0x%04x  %10d B' % (h, n))

    # 每个 (handle, opcode) 的前 2 帧，用于肉眼定界
    print('\n各通道首批载荷（判断控制面/数据面）:')
    seen = collections.Counter()
    for ts, d, h, op, val, pdu in iter_att(path):
        if not val:
            continue
        k = (h, op)
        if seen[k] >= 2:
            continue
        seen[k] += 1
        print('  0x%04x %s %-10s %5dB  %s'
              % (h, 'H2C' if d == 0 else 'C2H',
                 ATT_OP.get(op, '0x%02x' % op), len(val), val[:48].hex()))


def cmd_frames(a):
    handle = int(a.handle, 0) if a.handle else None
    dirn = {'h2c': 0, 'c2h': 1, None: None}[a.dir]
    pat = bytes.fromhex(a.grep) if a.grep else None
    n = 0
    for ts, d, h, op, val, pdu in iter_att(a.file, handle, dirn):
        if pat and not val.startswith(pat):
            continue
        print('[%6d] 0x%04x %s %-10s %5dB  %s%s'
              % (n, h, 'H2C' if d == 0 else 'C2H', ATT_OP.get(op, '0x%02x' % op),
                 len(val), val[:64].hex(), ' ...' if len(val) > 64 else ''))
        n += 1
        if a.limit and n >= a.limit:
            break
    print('共 %d 帧' % n)


def cmd_dump(a):
    handle = int(a.handle, 0) if a.handle else None
    dirn = {'h2c': 0, 'c2h': 1, None: None}[a.dir]
    buf, lens = bytearray(), []
    for ts, d, h, op, val, pdu in iter_att(a.file, handle, dirn):
        if not val:
            continue
        buf += val
        lens.append(len(val))
    out = a.out or 'stream.bin'
    open(out, 'wb').write(bytes(buf))
    open(out + '.lens', 'w').write('\n'.join(map(str, lens)))
    print('导出 %s  %d B / %d 帧' % (out, len(buf), len(lens)))
    if lens:
        c = collections.Counter(lens)
        print('帧长分布 Top5: %s' % c.most_common(5))
        print('首字节 Top5: %s'
              % collections.Counter(x[4][0] for x in iter_att(a.file, handle, dirn) if x[4])
              .most_common(5))


def cmd_split(a):
    """预设 d1：d1 01 ff <size:u32 LE> 02 <name>\\0 起新文件；d1 02 00 <raw> 追加；d1 03 结束。"""
    handle = int(a.handle, 0) if a.handle else None
    dirn = {'h2c': 0, 'c2h': 1, None: None}[a.dir]
    os.makedirs(a.out, exist_ok=True)
    files, cur, idx = [], None, 0
    for ts, d, h, op, val, pdu in iter_att(a.file, handle, dirn):
        if len(val) < 3 or val[0] != 0xD1:
            continue
        key = val[1]
        if key == 0x01:
            body = val[2:]
            size = struct.unpack('<I', body[1:5])[0] if len(body) >= 5 else -1
            name = body[6:].split(b'\x00')[0].decode('utf-8', 'replace') or 'unnamed'
            cur = {'name': name, 'size': size, 'data': bytearray(), 'end': None}
            files.append(cur)
        elif key == 0x02 and cur is not None:
            cur['data'] += val[3:]
        elif key == 0x03 and cur is not None:
            cur['end'] = val[2:].hex()
            cur = None
    for x in files:
        safe = x['name'].replace('/', '_').replace('\\', '_')
        p = os.path.join(a.out, 'xfer_%d_%s.bin' % (idx, safe))
        open(p, 'wb').write(bytes(x['data']))
        got = len(x['data'])
        flag = '✓' if got == x['size'] else '✗ 差 %d' % (got - x['size'])
        print('[%d] %-28s 声明 %9d 实收 %9d %s  结束帧 %s'
              % (idx, x['name'], x['size'], got, flag, x['end']))
        idx += 1
    if not files:
        print('未匹配到 d1 01 帧。用 `frames --grep <hex>` 先确认帧头。')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('info', help='诊断：包类型/ATT 分布/流量榜')
    p.add_argument('file')
    p.set_defaults(func=cmd_info)

    for name, fn, helptext in [
        ('frames', cmd_frames, '列出匹配帧（定界用）'),
        ('dump', cmd_dump, '导出某 handle 的载荷流'),
        ('split', cmd_split, '按 d1 协议切分文件'),
    ]:
        p = sub.add_parser(name, help=helptext)
        p.add_argument('file')
        p.add_argument('--handle', default=None, help='如 0x0200')
        p.add_argument('--dir', choices=['h2c', 'c2h'], default=None,
                       help='h2c=手机→设备, c2h=设备→手机')
        if name == 'frames':
            p.add_argument('--grep', default=None, help='载荷前缀 hex，如 d101')
            p.add_argument('--limit', type=int, default=20)
        if name == 'dump':
            p.add_argument('-o', '--out', default=None)
        if name == 'split':
            p.add_argument('--preset', default='d1')
            p.add_argument('-o', '--out', default='outdir')
        p.set_defaults(func=fn)

    a = ap.parse_args()
    a.func(a)


if __name__ == '__main__':
    main()

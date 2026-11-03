#!/usr/bin/env python3
"""从 .watch 容器里取出全部条目，并打印 ezip 头部特征。"""
import os
import struct
import sys
import collections

path = sys.argv[1] if len(sys.argv) > 1 else 'xfer_1_wf_w202.watch.bin'
outdir = sys.argv[2] if len(sys.argv) > 2 else 'dial_out'
d = open(path, 'rb').read()

magic, hsz, ver, nfile, f0a, f0e, name_len = struct.unpack('<IHHHIHI', d[:0x14])
names_raw = d[0x20:0x20 + name_len]
names = [x.decode('utf-8', 'replace') for x in names_raw.split(b'\x00') if x]

idx_off = 0x20 + name_len
entries = []
for i in range(nfile):
    p = idx_off + i * 16
    name_off, size, unk, data_off = struct.unpack('<IIII', d[p:p + 16])
    real = data_off - 32
    if name_off >= len(names_raw):
        continue
    nm = names_raw[name_off:].split(b'\x00')[0].decode('utf-8', 'replace')
    entries.append((nm, size, unk, real))

print('nfile=%d 解析出 %d 条' % (nfile, len(entries)))
print('数据区起点 = 0x%X (%d)，首条 real_off=%d' % (idx_off + nfile * 16, idx_off + nfile * 16, entries[0][3]))

# 连续性验证
prev_end = 0
bad = []
for nm, size, unk, off in entries:
    if off != prev_end:
        bad.append((nm, prev_end, off))
    prev_end = off + size
print('连续性: %d 处断点，尾部结束于 %d（文件 %d）' % (len(bad), prev_end, len(d)))
for x in bad[:5]:
    print('   断点', x)

DATA = idx_off + nfile * 16          # 数据区绝对起点；索引里的 offset 是相对值
os.makedirs(outdir, exist_ok=True)
stats = collections.Counter()
for nm, size, unk, off in entries:
    rel = nm.split('/watchface/')[-1]
    dst = os.path.join(outdir, rel.replace('/', '_'))
    open(dst, 'wb').write(d[DATA + off:DATA + off + size])
    stats[rel.split('/')[0]] += 1

print('\n按目录分组:', dict(stats))

print('\n=== ezip 头部（前 32 字节） ===')
ez = [e for e in entries if 'ezip' in e[0]]
print('ezip 条目 %d 个' % len(ez))
print('%-52s %8s %s' % ('name', 'size', 'head'))
for nm, size, unk, off in ez[:14]:
    b = d[DATA + off:DATA + off + 32]
    print('%-52s %8d %s' % (nm.split('/')[-1][:50], size, b[:24].hex(' ')))

print('\n=== 首字节分布 ===')
print(collections.Counter(d[DATA + off] for nm, size, unk, off in ez).most_common())
print('=== 第 4..8 字节（疑似格式标识） ===')
print(collections.Counter(d[DATA + off + 1:DATA + off + 4].hex() for nm, size, unk, off in ez).most_common(10))
print('=== 字节 12..16 ===')
print(collections.Counter(d[DATA + off + 12:DATA + off + 16].hex() for nm, size, unk, off in ez).most_common(10))
print('=== 字节 16..20（疑似宽高） ===')
c = collections.Counter(d[DATA + off + 16:DATA + off + 20].hex() for nm, size, unk, off in ez)
for k, v in c.most_common(10):
    w = struct.unpack('<H', bytes.fromhex(k)[:2])[0]
    h = struct.unpack('<H', bytes.fromhex(k)[2:])[0]
    print('  %s  %d×%d   ×%d' % (k, w, h, v))

#!/usr/bin/env python3
"""重打包 SiFli .watch 表盘容器：替换条目 → 重算索引偏移 → 输出。

用法：
  python watch_pack.py src.watch out.watch \
      --replace /dynamic_app/watchface/wf_w202/ezip/wf_w202_picture_dialBg_0.bin=bg_new.bin

容器布局（实测，version 13）：
  head_t(32B) | 名字表(name_len) | file_head_t[nfile](16B) | 数据区
  file_head_t = { name_off:u32, size:u32, unknown:u32, data_off:u32 }
  data_off 是相对数据区起点的偏移 **+32**
  数据区紧接索引表，无任何对齐填充
"""
import argparse
import os
import struct
import sys


def load(path):
    d = open(path, 'rb').read()
    magic, hsz, ver, nfile, f0a, f0e, name_len = struct.unpack('<IHHHIHI', d[:0x14])
    if magic != 0xA1B2C8D9:
        sys.exit('magic 不是 0xA1B2C8D9: 0x%08X' % magic)
    names_raw = d[0x20:0x20 + name_len]
    idx_off = 0x20 + name_len
    data_off = idx_off + nfile * 16
    entries = []
    for i in range(nfile):
        p = idx_off + i * 16
        name_off, size, unk, off = struct.unpack('<IIII', d[p:p + 16])
        if name_off >= len(names_raw):
            sys.exit('索引 %d 的 name_off 越界' % i)
        nm = names_raw[name_off:].split(b'\x00')[0].decode('utf-8', 'replace')
        entries.append(dict(name=nm, size=size, unk=unk, off=off - 32, i=i))
    # 用"名字出现顺序"还原 name_off（重打包时不变）
    return dict(raw=d, hdr=d[:0x20], names_raw=names_raw, name_len=name_len,
                nfile=nfile, ver=ver, idx_off=idx_off, data_off=data_off, entries=entries)


def rebuild(c, replacements):
    hdr, names_raw, nfile = c['hdr'], c['names_raw'], c['nfile']
    entries = sorted(c['entries'], key=lambda e: e['off'])

    # 按数据区原顺序重排，替换命中的条目
    blobs = []
    for e in entries:
        src = c['raw'][c['data_off'] + e['off']:c['data_off'] + e['off'] + e['size']]
        new = replacements.get(e['name'])
        if new is not None:
            if len(new) != e['size']:
                # ezip 文件头 [4:8] 是它自己的长度，必须同步
                print('  替换 %s: %d -> %d B' % (e['name'].split('/')[-1], e['size'], len(new)))
            src = new
        blobs.append((e, src))

    # 重算偏移：索引里 data_off 是"相对数据区起点 + 32"
    new_names = bytearray(names_raw)
    idx = bytearray()
    body = bytearray()
    cur = 0
    for e, b in blobs:
        p = c['idx_off'] + e['i'] * 16
        name_off = struct.unpack('<I', c['raw'][p:p + 4])[0]
        idx += struct.pack('<IIII', name_off, len(b), e['unk'], cur + 32)
        body += b
        cur += len(b)

    # 容器头没有"总长度"字段（offset 8 是 file_count），只拼三段
    out = bytearray(hdr) + bytes(new_names) + bytes(idx) + bytes(body)
    return bytes(out), cur


def verify(path, expect_nfile):
    d = open(path, 'rb').read()
    magic, hsz, ver, nfile, f0a, f0e, name_len = struct.unpack('<IHHHIHI', d[:0x14])
    idx_off = 0x20 + name_len
    data_off = idx_off + nfile * 16
    bad = 0
    prev = 0
    for i in range(nfile):
        p = idx_off + i * 16
        name_off, size, unk, off = struct.unpack('<IIII', d[p:p + 16])
        if off - 32 != prev:
            bad += 1
        prev = off - 32 + size
    ok = (nfile == expect_nfile and bad == 0 and data_off + prev == len(d))
    print('校验: nfile=%d 断点=%d 数据区结束=%d 文件=%d -> %s'
          % (nfile, bad, data_off + prev, len(d), 'OK' if ok else 'FAIL'))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('src')
    ap.add_argument('dst')
    ap.add_argument('--replace', action='append', default=[],
                    help='容器内路径=本地文件，可多次')
    a = ap.parse_args()

    c = load(a.src)
    print('%s: nfile=%d name_len=%d ver=%d 数据区@%d'
          % (a.src, c['nfile'], c['name_len'], c['ver'], c['data_off']))

    repl = {}
    for spec in a.replace:
        key, _, val = spec.partition('=')
        hit = [e for e in c['entries'] if e['name'] == key]
        if not hit:
            sys.exit('容器里没有这个路径: %s' % key)
        repl[key] = open(val, 'rb').read()
        print('  命中: %s' % key)

    out, total = rebuild(c, repl)
    open(a.dst, 'wb').write(out)
    print('输出 %s  %d B（原 %d B，差 %+d）'
          % (a.dst, len(out), len(c['raw']), len(out) - len(c['raw'])))
    verify(a.dst, c['nfile'])


if __name__ == '__main__':
    main()

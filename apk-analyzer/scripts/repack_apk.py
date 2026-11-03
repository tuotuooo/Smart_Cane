#!/usr/bin/env python3
"""把替换过的条目（默认 AndroidManifest.xml）塞回 APK，并剔除旧签名。

用法：
  python repack_apk.py in.apk out.apk --manifest patched_manifest.xml
  python repack_apk.py in.apk out.apk --replace res/raw/x.bin=./x.bin --replace ...

设计要点：
  * 保留每个条目的 compress_type —— STORED 的（通常是 resources.arsc、部分 .so）
    改成 DEFLATED 会让某些 ROM / 校验逻辑行为变化。
  * 剔除 META-INF 下的 .SF/.RSA/.DSA/.MF/.EC —— 旧签名留着必然验签失败。
  * 用 ZIP64，303MB 的包不开启会直接抛 LargeZipFile。
"""
import os
import sys
import zipfile

SKIP_SIG = ('.SF', '.RSA', '.DSA', '.MF', '.EC')


def repack(src, dst, replacements):
    if os.path.exists(dst):
        os.remove(dst)
    zin = zipfile.ZipFile(src, 'r')
    zout = zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED, allowZip64=True)
    replaced, kept, dropped = 0, 0, 0
    seen = set()

    for info in zin.infolist():
        n = info.filename
        if n.startswith('META-INF/') and n.upper().endswith(SKIP_SIG):
            dropped += 1
            continue
        if n in replacements:
            data = open(replacements[n], 'rb').read()
            seen.add(n)
        else:
            with zin.open(info) as f:
                data = f.read()

        zi = zipfile.ZipInfo(n, date_time=info.date_time)
        zi.external_attr = info.external_attr
        zi.compress_type = info.compress_type
        if n in replacements:
            replaced += 1
        else:
            kept += 1
        zout.writestr(zi, data)

    missing = set(replacements) - seen
    zout.close()
    zin.close()

    print('replaced=%d kept=%d dropped_sig=%d' % (replaced, kept, dropped))
    print('size %.1f MB -> %.1f MB'
          % (os.path.getsize(src) / 1048576, os.path.getsize(dst) / 1048576))
    if missing:
        print('⚠ 这些替换目标在 APK 里不存在: %s' % ', '.join(sorted(missing)))
        return 1
    return 0


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    repl = {'AndroidManifest.xml': 'patched_manifest.xml'}
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == '--manifest':
            repl['AndroidManifest.xml'] = sys.argv[i + 1]; i += 2
        elif sys.argv[i] == '--replace':
            k, _, v = sys.argv[i + 1].partition('='); repl[k] = v; i += 2
        elif sys.argv[i] == '--no-manifest':
            repl.pop('AndroidManifest.xml', None); i += 1
        else:
            i += 1
    sys.exit(repack(src, dst, repl))


if __name__ == '__main__':
    main()

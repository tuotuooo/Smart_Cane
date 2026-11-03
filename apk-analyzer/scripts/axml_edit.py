#!/usr/bin/env python3
"""AXML (Android binary XML) 读写器 —— 修改 AndroidManifest.xml。

核心事实（实测结论，勿推翻）：
  * 改已有属性的值       → 生效
  * 插入全新的属性记录   → **不生效**，哪怕 20 字节逐字节与已有属性一致
  * 扩 ResourceMap       → 无任何影响，不要动

所以想让一个 Activity 变成 exported，只能"牺牲"它已有的某个无用属性
（screenOrientation / configChanges 之类），把它重定向成 exported。

用法：
  python axml_edit.py dump  AndroidManifest.xml
  python axml_edit.py bool  in.xml out.xml --tag application --attr allowBackup --value false
  python axml_edit.py exported in.xml out.xml --tag com.x.WallpaperGridActivity [--sacrifice screenOrientation]
  python axml_edit.py verify out.xml

纯标准库。
"""
import struct
import sys

TYPE_STRING_POOL = 0x0001
TYPE_XML = 0x0003
TYPE_RESOURCE_MAP = 0x0180
TYPE_START_NS = 0x0100
TYPE_END_NS = 0x0101
TYPE_START_TAG = 0x0102
TYPE_END_TAG = 0x0103
TYPE_CDATA = 0x0104

ATTR_SIZE = 20
NO_ENTRY = 0xFFFFFFFF
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = 'http://schemas.android.com/apk/res/android'

# 可安全牺牲的属性，按优先级排列（丢了影响最小）
SACRIFICE_ORDER = ['screenOrientation', 'configChanges', 'launchMode', 'resizeableActivity']


def _align4(n):
    return (n + 3) & ~3


class AXml:
    def __init__(self, data):
        self.raw = bytearray(data)
        self.file_type, self.file_hdr, self.file_size = struct.unpack('<HHI', bytes(self.raw[:8]))
        assert self.file_type == TYPE_XML, 'not axml (type=0x%04x)' % self.file_type
        self._parse_string_pool()
        self._parse_resource_map()
        self._parse_nodes()

    # ---------- 字符串池 ----------
    def _parse_string_pool(self):
        d = self.raw
        off = self.file_hdr
        self.sp_off = off
        t, hdr, size = struct.unpack('<HHI', bytes(d[off:off + 8]))
        assert t == TYPE_STRING_POOL, 'no string pool at 0x%x' % off
        self.sp_hdr, self.sp_size = hdr, size
        (self.str_count, self.style_count, self.sp_flags,
         self.str_start, self.style_start) = struct.unpack('<IIIII', bytes(d[off + 8:off + 28]))
        self.utf8 = bool(self.sp_flags & 0x100)
        self.str_offsets = [struct.unpack('<I', bytes(d[off + hdr + i * 4:off + hdr + i * 4 + 4]))[0]
                            for i in range(self.str_count)]
        base = off + self.str_start
        self.strings = [self._read_string(base + o) for o in self.str_offsets]

    def _read_string(self, q):
        d = self.raw
        if self.utf8:
            n = d[q]; q += 1
            if n & 0x80:
                q += 1
            n2 = d[q]; q += 1
            if n2 & 0x80:
                n2 = ((n2 & 0x7f) << 8) | d[q]; q += 1
            return bytes(d[q:q + n2]).decode('utf-8', 'replace')
        n = struct.unpack('<H', bytes(d[q:q + 2]))[0]; q += 2
        if n & 0x8000:
            n = ((n & 0x7fff) << 16) | struct.unpack('<H', bytes(d[q:q + 2]))[0]; q += 2
        return bytes(d[q:q + n * 2]).decode('utf-16-le', 'replace')

    def find_string(self, s):
        try:
            return self.strings.index(s)
        except ValueError:
            return -1

    # ---------- 资源映射 ----------
    def _parse_resource_map(self):
        d = self.raw
        off = self.sp_off + self.sp_size
        t, hdr, size = struct.unpack('<HHI', bytes(d[off:off + 8]))
        if t == TYPE_RESOURCE_MAP:
            self.rm_off, self.rm_size = off, size
            self.res_ids = list(struct.unpack('<%dI' % ((size - 8) // 4), bytes(d[off + 8:off + size])))
        else:
            self.rm_off, self.rm_size, self.res_ids = None, 0, []
        self.nodes_off = (off + size) if self.rm_off else off

    # ---------- 节点 ----------
    def _parse_nodes(self):
        d = self.raw
        off = self.nodes_off
        self.node_spans = []   # [offset, type, size, name_idx, attr_count]
        while off + 8 <= len(d):
            t, hdr, size = struct.unpack('<HHI', bytes(d[off:off + 8]))
            if size < 8:
                break
            name_idx = attr_count = None
            if t == TYPE_START_TAG:
                name_idx = struct.unpack('<I', bytes(d[off + 20:off + 24]))[0]
                attr_count = struct.unpack('<H', bytes(d[off + 28:off + 30]))[0]
            self.node_spans.append([off, t, size, name_idx, attr_count])
            off += size

    def tag_name(self, span):
        return self.strings[span[3]] if span[3] is not None else None

    def attr_list(self, span):
        """[(ns, name_idx, raw_idx, dtype, data, byte_offset)]"""
        off, t, size, name_idx, cnt = span
        base = off + 16 + 20
        out = []
        for i in range(cnt):
            p = base + i * ATTR_SIZE
            ns, nm, raw = struct.unpack('<III', bytes(self.raw[p:p + 12]))
            _vsize, _res0, dtype = struct.unpack('<HBB', bytes(self.raw[p + 12:p + 16]))
            data = struct.unpack('<I', bytes(self.raw[p + 16:p + 20]))[0]
            out.append((ns, nm, raw, dtype, data, p))
        return out

    def attr_name(self, a):
        nm = a[1]
        return self.strings[nm] if nm < len(self.strings) else '?%d' % nm

    def get_attr(self, span, name):
        for a in self.attr_list(span):
            if self.attr_name(a) == name:
                return a
        return None

    def find_tag(self, name):
        """定位一个 START_TAG。支持两种写法：
          1) 元素名，如 application / activity（精确匹配优先，其次后缀）
          2) 组件名，如 com.x.WallpaperImageGridActivity（匹配 android:name 属性值）
        注意：<activity> 这种元素名会命中第一个，定位具体组件必须传组件名。
        """
        # ① 元素名精确
        for i, span in enumerate(self.node_spans):
            if span[1] == TYPE_START_TAG and self.tag_name(span) == name:
                return i
        # ② android:name 属性值（精确 or 后缀）
        best = -1
        for i, span in enumerate(self.node_spans):
            if span[1] != TYPE_START_TAG:
                continue
            a = self.get_attr(span, 'name')
            if not a or a[3] != TYPE_STRING or a[4] >= len(self.strings):
                continue
            v = self.strings[a[4]]
            if v == name:
                return i
            if v.endswith(name) and best < 0:
                best = i
        if best >= 0:
            return best
        # ③ 元素名后缀（如 activity-alias）
        for i, span in enumerate(self.node_spans):
            if span[1] != TYPE_START_TAG:
                continue
            tn = self.tag_name(span)
            if tn and tn.endswith(name):
                return i
        return -1

    # ---------- 修改（只支持原地改值） ----------
    def set_bool(self, span_index, name, value):
        span = self.node_spans[span_index]
        a = self.get_attr(span, name)
        if a is None:
            raise KeyError('属性 %s 不存在于 <%s>；插入新属性无效，请改用 exported 牺牲法'
                           % (name, self.tag_name(span)))
        p = a[5]
        struct.pack_into('<HBB', self.raw, p + 12, 8, 0, TYPE_INT_BOOLEAN)
        struct.pack_into('<I', self.raw, p + 16, NO_ENTRY if value else 0)
        return True

    def retarget(self, span_index, from_name, to_name, bool_value=True):
        """把已有属性 from_name 改造成 to_name（布尔）。这是让组件导出的唯一可行做法。"""
        span = self.node_spans[span_index]
        a = self.get_attr(span, from_name)
        if a is None:
            raise KeyError('<%s> 上没有属性 %s' % (self.tag_name(span), from_name))
        to_idx = self.find_string(to_name)
        if to_idx < 0:
            raise KeyError('字符串池里没有 "%s" —— 无法重定向（插字符串同样无效）。'
                           '换一个 manifest 里已出现过 exported 的组件操作。' % to_name)
        p = a[5]
        struct.pack_into('<I', self.raw, p + 4, to_idx)          # name
        struct.pack_into('<I', self.raw, p + 8, NO_ENTRY)        # rawValue
        struct.pack_into('<HBB', self.raw, p + 12, 8, 0, TYPE_INT_BOOLEAN)
        struct.pack_into('<I', self.raw, p + 16, NO_ENTRY if bool_value else 0)
        return True

    def to_bytes(self):
        return bytes(self.raw)


# ---------------- CLI ----------------
def cmd_dump(path):
    ax = AXml(open(path, 'rb').read())
    print('file_size=%d  strings=%d  resmap=%d  utf8=%s  nodes=%d'
          % (ax.file_size, ax.str_count, len(ax.res_ids), ax.utf8, len(ax.node_spans)))
    for i, span in enumerate(ax.node_spans):
        if span[1] != TYPE_START_TAG:
            continue
        print('\n[%d] <%s>  attrs=%d' % (i, ax.tag_name(span), span[4]))
        for a in ax.attr_list(span):
            ns, nm, raw, dtype, data, p = a
            v = data
            if dtype == TYPE_STRING and data < len(ax.strings):
                v = repr(ax.strings[data])
            elif dtype == TYPE_INT_BOOLEAN:
                v = 'true' if data else 'false'
            print('    %-22s type=0x%02x  data=0x%08x  %s  @0x%x'
                  % (ax.attr_name(a), dtype, data, v, p))


def cmd_bool(argv):
    src, dst, tag, attr, val = argv[0], argv[1], None, None, True
    i = 2
    while i < len(argv):
        if argv[i] == '--tag':
            tag = argv[i + 1]; i += 2
        elif argv[i] == '--attr':
            attr = argv[i + 1]; i += 2
        elif argv[i] == '--value':
            val = argv[i + 1].lower() in ('true', '1', 'yes'); i += 2
        else:
            i += 1
    ax = AXml(open(src, 'rb').read())
    idx = ax.find_tag(tag)
    if idx < 0:
        sys.exit('找不到 tag: %s' % tag)
    ax.set_bool(idx, attr, val)
    open(dst, 'wb').write(ax.to_bytes())
    print('<%s> %s = %s  -> %s' % (ax.tag_name(ax.node_spans[idx]), attr, val, dst))


def cmd_exported(argv):
    src, dst, tag, sacrifice = argv[0], argv[1], None, None
    i = 2
    while i < len(argv):
        if argv[i] == '--tag':
            tag = argv[i + 1]; i += 2
        elif argv[i] == '--sacrifice':
            sacrifice = argv[i + 1]; i += 2
        else:
            i += 1
    ax = AXml(open(src, 'rb').read())
    idx = ax.find_tag(tag)
    if idx < 0:
        sys.exit('找不到 tag: %s' % tag)
    span = ax.node_spans[idx]
    if ax.get_attr(span, 'exported') is not None:
        ax.set_bool(idx, 'exported', True)
        print('已有 exported 属性，直接改值')
    else:
        order = ([sacrifice] if sacrifice else []) + SACRIFICE_ORDER
        for name in order:
            if ax.get_attr(span, name) is not None:
                ax.retarget(idx, name, 'exported', True)
                print('牺牲 %s -> exported（<%s>）' % (name, ax.tag_name(span)))
                break
        else:
            sys.exit('该元素没有可牺牲的属性，且无法插入新属性。可选清单：%s' % SACRIFICE_ORDER)
    open(dst, 'wb').write(ax.to_bytes())
    print('输出 %s（大小 %d，与原文件相同=%s）'
          % (dst, len(ax.to_bytes()), len(ax.to_bytes()) == len(open(src, 'rb').read())))


def cmd_verify(path):
    ax = AXml(open(path, 'rb').read())
    print('OK: 解析通过，%d 个 START_TAG，file_size=%d，实际=%d'
          % (sum(1 for s in ax.node_spans if s[1] == TYPE_START_TAG),
             ax.file_size, len(ax.raw)))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd, argv = sys.argv[1], sys.argv[2:]
    if cmd == 'dump':
        cmd_dump(argv[0])
    elif cmd == 'bool':
        cmd_bool(argv)
    elif cmd == 'exported':
        cmd_exported(argv)
    elif cmd == 'verify':
        cmd_verify(argv[0])
    else:
        sys.exit('未知命令 %s' % cmd)


if __name__ == '__main__':
    main()

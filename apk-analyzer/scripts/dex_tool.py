#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dex_tool.py - 轻量 DEX 解析器 + 反汇编器（纯 Python，无需 JRE/jadx）

用途：在内存 dump 出的 DEX 上做「字符串 -> 引用它的方法 -> 该方法字节码」的定点追踪。

CLI:
  python dex_tool.py str <dex> <子串>              # 列出引用该字符串的所有方法
  python dex_tool.py method <dex> <类名包含> <方法名包含>   # 反汇编匹配的方法
  python dex_tool.py xref <dex> <方法名包含>        # 列出调用该方法的位置
"""
import sys, struct

NO_INDEX = 0xFFFFFFFF

# ---------- opcode 长度表（单位数，含 opcode 本身） ----------
OPLEN = [1] * 256
_ONE = {
    0x02: 2, 0x03: 3, 0x05: 2, 0x06: 3, 0x08: 2, 0x09: 3,
    0x13: 2, 0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5, 0x19: 2,
    0x1A: 2, 0x1B: 3, 0x1C: 2, 0x1F: 2, 0x20: 2, 0x22: 2, 0x23: 2,
    0x24: 3, 0x25: 3, 0x26: 3, 0x29: 2, 0x2A: 3, 0x2B: 3, 0x2C: 3,
    0xFA: 4, 0xFB: 4, 0xFC: 3, 0xFD: 3, 0xFE: 2, 0xFF: 2,
}
OPLEN = [1] * 256
for _k, _v in _ONE.items():
    OPLEN[_k] = _v
for _a, _b, _v in [(0x2D, 0x31, 2), (0x32, 0x3D, 2), (0x44, 0x51, 2),
                   (0x52, 0x5F, 2), (0x60, 0x6D, 2), (0x6E, 0x72, 3),
                   (0x74, 0x78, 3), (0x90, 0xAF, 2), (0xD0, 0xD7, 2),
                   (0xD8, 0xE2, 2)]:
    for _i in range(_a, _b + 1):
        OPLEN[_i] = _v

# ---------- opcode 名称（只列关心的，其余输出 #xx） ----------
OPNAME = {
    0x00: "nop", 0x01: "move", 0x02: "move/from16", 0x03: "move/16",
    0x04: "move-wide", 0x05: "move-wide/from16", 0x06: "move-wide/16",
    0x07: "move-object", 0x08: "move-object/from16", 0x09: "move-object/16",
    0x0A: "move-result", 0x0B: "move-result-wide", 0x0C: "move-result-object",
    0x0D: "move-exception", 0x0E: "return-void", 0x0F: "return",
    0x10: "return-wide", 0x11: "return-object",
    0x12: "const/4", 0x13: "const/16", 0x14: "const", 0x15: "const/high16",
    0x16: "const-wide/16", 0x17: "const-wide/32", 0x18: "const-wide",
    0x19: "const-wide/high16", 0x1A: "const-string", 0x1B: "const-string/jumbo",
    0x1C: "const-class", 0x1D: "monitor-enter", 0x1E: "monitor-exit",
    0x1F: "check-cast", 0x20: "instance-of", 0x21: "array-length",
    0x22: "new-instance", 0x23: "new-array", 0x24: "filled-new-array",
    0x25: "filled-new-array/range", 0x26: "fill-array-data", 0x27: "throw",
    0x28: "goto", 0x29: "goto/16", 0x2A: "goto/32",
    0x2B: "packed-switch", 0x2C: "sparse-switch",
    0x2D: "cmpl-float", 0x2E: "cmpg-float", 0x2F: "cmpl-double",
    0x30: "cmpg-double", 0x31: "cmp-long",
    0x32: "if-eq", 0x33: "if-ne", 0x34: "if-lt", 0x35: "if-ge",
    0x36: "if-gt", 0x37: "if-le", 0x38: "if-eqz", 0x39: "if-nez",
    0x3A: "if-ltz", 0x3B: "if-gez", 0x3C: "if-gtz", 0x3D: "if-lez",
    0xFA: "invoke-polymorphic", 0xFB: "invoke-polymorphic/range",
    0xFC: "invoke-custom", 0xFD: "invoke-custom/range",
    0xFE: "const-method-handle", 0xFF: "const-method-type",
}
for _i, _n in enumerate(["aget", "aget-wide", "aget-object", "aget-boolean",
                         "aget-byte", "aget-char", "aget-short", "aput",
                         "aput-wide", "aput-object", "aput-boolean", "aput-byte",
                         "aput-char", "aput-short"]):
    OPNAME[0x44 + _i] = _n
for _i, _n in enumerate(["iget", "iget-wide", "iget-object", "iget-boolean",
                         "iget-byte", "iget-char", "iget-short", "iput",
                         "iput-wide", "iput-object", "iput-boolean", "iput-byte",
                         "iput-char", "iput-short"]):
    OPNAME[0x52 + _i] = _n
for _i, _n in enumerate(["sget", "sget-wide", "sget-object", "sget-boolean",
                         "sget-byte", "sget-char", "sget-short", "sput",
                         "sput-wide", "sput-object", "sput-boolean", "sput-byte",
                         "sput-char", "sput-short"]):
    OPNAME[0x60 + _i] = _n
for _i, _n in enumerate(["invoke-virtual", "invoke-super", "invoke-direct",
                         "invoke-static", "invoke-interface"]):
    OPNAME[0x6E + _i] = _n
    OPNAME[0x74 + _i] = _n + "/range"
for _i, _n in enumerate(["neg-int", "not-int", "neg-long", "not-long",
                         "neg-float", "neg-double", "int-to-long", "int-to-float",
                         "int-to-double", "long-to-int", "long-to-float",
                         "long-to-double", "float-to-int", "float-to-long",
                         "float-to-double", "double-to-int", "double-to-long",
                         "double-to-float", "int-to-byte", "int-to-char",
                         "int-to-short"]):
    OPNAME[0x7B + _i] = _n


def _s32(v):
    return v - 0x100000000 if v & 0x80000000 else v


def _s16(v):
    return v - 0x10000 if v & 0x8000 else v


class Dex:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.b = f.read()
        b = self.b
        if b[:4] != b"dex\n":
            raise ValueError("not a dex: magic=%r" % b[:8])
        (self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = struct.unpack_from("<12I", b, 0x38)
        self._strings = None
        self._classes = None

    # ---------- 基础表 ----------
    def strings(self):
        if self._strings is not None:
            return self._strings
        b = self.b
        out = []
        for i in range(self.string_ids_size):
            off = struct.unpack_from("<I", b, self.string_ids_off + i * 4)[0]
            p = off
            # uleb128 utf16_size
            while b[p] & 0x80:
                p += 1
            p += 1
            e = b.index(0, p)
            out.append(b[p:e].decode("utf-8", "replace").replace("\xc0\x80", ""))
        self._strings = out
        return out

    def str_at(self, idx):
        if idx >= self.string_ids_size:
            return "<bad str %d>" % idx
        return self.strings()[idx]

    def type_at(self, idx):
        si = struct.unpack_from("<I", self.b, self.type_ids_off + idx * 4)[0]
        return self.str_at(si)

    def find_string(self, needle):
        return [i for i, s in enumerate(self.strings()) if needle in s]

    def proto_at(self, idx):
        b = self.b
        shorty, ret, params_off = struct.unpack_from("<3I", b, self.proto_ids_off + idx * 12)
        args = []
        if params_off:
            n = struct.unpack_from("<I", b, params_off)[0]
            for i in range(n):
                args.append(self.type_at(struct.unpack_from("<H", b, params_off + 4 + i * 2)[0]))
        return self.type_at(ret), args

    def method_at(self, idx):
        if idx >= self.method_ids_size:
            return ("<bad>", "<bad>", ("V", []))
        cls_idx, proto_idx, name_idx = struct.unpack_from(
            "<HHI", self.b, self.method_ids_off + idx * 8)
        ret, args = self.proto_at(proto_idx)
        return self.type_at(cls_idx), self.str_at(name_idx), (ret, args)

    def field_at(self, idx):
        if idx >= self.field_ids_size:
            return ("<bad>", "<bad>", "<bad>")
        cls_idx, type_idx, name_idx = struct.unpack_from(
            "<HHI", self.b, self.field_ids_off + idx * 8)
        return self.type_at(cls_idx), self.str_at(name_idx), self.type_at(type_idx)

    # ---------- class_data ----------
    @staticmethod
    def _uleb(b, p):
        r = 0
        s = 0
        while True:
            x = b[p]
            p += 1
            r |= (x & 0x7F) << s
            if not x & 0x80:
                return r, p
            s += 7

    def classes(self):
        """[(class_desc, [(method_idx, access, code_off, is_direct)])]"""
        if self._classes is not None:
            return self._classes
        b = self.b
        out = []
        for i in range(self.class_defs_size):
            base = self.class_defs_off + i * 32
            class_idx = struct.unpack_from("<I", b, base)[0]
            class_data_off = struct.unpack_from("<I", b, base + 24)[0]
            desc = self.type_at(class_idx)
            methods = []
            if class_data_off:
                p = class_data_off
                sf, p = self._uleb(b, p)
                inf, p = self._uleb(b, p)
                dm, p = self._uleb(b, p)
                vm, p = self._uleb(b, p)
                for _ in range(sf + inf):
                    _, p = self._uleb(b, p)
                    _, p = self._uleb(b, p)
                for count, is_direct in ((dm, True), (vm, False)):
                    midx = 0
                    for _ in range(count):
                        diff, p = self._uleb(b, p)
                        acc, p = self._uleb(b, p)
                        code_off, p = self._uleb(b, p)
                        midx += diff
                        methods.append((midx, acc, code_off, is_direct))
            out.append((desc, methods))
        self._classes = out
        return out

    def code_insns(self, code_off):
        b = self.b
        if not code_off:
            return []
        n = struct.unpack_from("<I", b, code_off + 12)[0]
        start = code_off + 16
        return list(struct.unpack_from("<%dH" % n, b, start))

    # ---------- 反汇编 ----------
    def disasm(self, code_off):
        ins = self.code_insns(code_off)
        out = []
        i = 0
        n = len(ins)
        while i < n:
            u = ins[i]
            op = u & 0xFF
            hi = (u >> 8) & 0xFF
            ln = OPLEN[op]
            name = OPNAME.get(op, "#%02x" % op)
            args = []
            try:
                if op in (0x1A, 0x1C, 0x1F, 0x22, 0x60, 0x61, 0x62, 0x63, 0x64,
                          0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
                          0xFE, 0xFF):
                    idx = ins[i + 1]
                    if op == 0x1A:
                        args = ["v%d" % hi, '"%s"' % self.str_at(idx)]
                    elif op in (0x1C, 0x1F, 0x22):
                        args = ["v%d" % hi, self.type_at(idx)]
                    elif 0x60 <= op <= 0x6D:
                        c, fn, ft = self.field_at(idx)
                        args = ["v%d" % hi, "%s->%s:%s" % (c, fn, ft)]
                    else:
                        args = ["v%d" % hi, "#%d" % idx]
                elif op == 0x1B:
                    idx = struct.unpack_from("<I", ins, i * 2 + 4)[0]
                    args = ["v%d" % hi, '"%s"' % self.str_at(idx)]
                elif 0x6E <= op <= 0x72 or op == 0x24:
                    idx = ins[i + 1]
                    c, mn, (ret, prm) = self.method_at(idx)
                    regs = (ins[i + 2] & 0xF, (ins[i + 2] >> 4) & 0xF,
                            (ins[i + 2] >> 8) & 0xF, (ins[i + 2] >> 12) & 0xF)
                    if 0x6E <= op <= 0x72:
                        # 该样本中 invoke 的 8 位 AA(argc) 被左移 4 位（实证 264789/264818 吻合）
                        argc = hi >> 4
                        args = ["{v%s}" % ",v".join(str(r) for r in regs[:argc]),
                                "%s->%s(%s)%s" % (c, mn, ",".join(prm), ret)]
                    else:
                        args = ["{v%s}" % ",v".join(str(r) for r in regs), self.type_at(idx)]
                elif 0x74 <= op <= 0x78 or op == 0x25:
                    idx = ins[i + 1]
                    c, mn, (ret, prm) = self.method_at(idx)
                    first = ins[i + 2]
                    if 0x74 <= op <= 0x78:
                        args = ["{v%d..v%d}" % (first, first + hi - 1),
                                "%s->%s(%s)%s" % (c, mn, ",".join(prm), ret)]
                    else:
                        args = ["{v%d..}" % first, self.type_at(idx)]
                elif 0x52 <= op <= 0x5F:
                    a = (u >> 8) & 0xF
                    bb = (u >> 12) & 0xF
                    c, fn, ft = self.field_at(ins[i + 1])
                    args = ["v%d" % a, "v%d" % bb, "%s->%s:%s" % (c, fn, ft)]
                elif 0x90 <= op <= 0xAF or 0x2D <= op <= 0x31:
                    args = ["v%d" % ((u >> 8) & 0xFF), "v%d" % ((u >> 12) & 0xF),
                            "v%d" % ((u >> 8) & 0xF)]
                elif 0x32 <= op <= 0x3D:
                    a = (u >> 8) & 0xF
                    bb = (u >> 12) & 0xF
                    off = _s16(ins[i + 1])
                    if 0x32 <= op <= 0x37:
                        args = ["v%d" % a, "v%d" % bb, "@%+d" % off]
                    else:
                        args = ["v%d" % a, "@%+d" % off]
                elif 0x12 <= op <= 0x19 or 0xD0 <= op <= 0xE2:
                    a = (u >> 8) & 0xFF if op not in (0x12, 0xD8) else (u >> 8) & 0xF
                    if op in (0x14, 0x17):
                        imm = _s32(struct.unpack_from("<I", ins, i * 2 + 4)[0])
                    elif op == 0x18:
                        lo = struct.unpack_from("<I", ins, i * 2 + 4)[0]
                        hiw = struct.unpack_from("<I", ins, i * 2 + 8)[0]
                        imm = (hiw << 32) | lo
                    elif op == 0x13 or op == 0x15 or op == 0x16 or op == 0x19:
                        imm = _s16(ins[i + 1]) if op != 0x15 and op != 0x19 else _s16(ins[i + 1])
                    elif op == 0xD8:
                        imm = (u >> 8) & 0xFF
                        imm = imm - 256 if imm & 0x80 else imm
                    else:
                        imm = _s16(ins[i + 1])
                    if op == 0x12:
                        args = ["v%d" % ((u >> 8) & 0xF), "#%d" % ((u >> 12) & 0xF)]
                    elif op == 0xD8:
                        args = ["v%d" % ((u >> 8) & 0xF), "v%d" % ((u >> 12) & 0xF), "#%d" % imm]
                    elif 0xD0 <= op <= 0xD7:
                        args = ["v%d" % ((u >> 8) & 0xF), "v%d" % ((u >> 12) & 0xF), "#%d" % imm]
                    else:
                        args = ["v%d" % a, "#%d" % imm]
                elif op in (0x01, 0x04, 0x07):
                    args = ["v%d" % ((u >> 8) & 0xF), "v%d" % ((u >> 12) & 0xF)]
                elif op in (0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x21, 0x27):
                    args = ["v%d" % hi]
                elif op in (0x28, 0x2B, 0x2C):
                    args = ["@%+d" % (_s16(ins[i + 1]) if op != 0x28 else (hi - 256 if hi & 0x80 else hi))]
                elif op == 0x29:
                    args = ["@%+d" % _s16(ins[i + 1])]
                elif op == 0x2A:
                    args = ["@%+d" % _s32(struct.unpack_from("<I", ins, i * 2 + 4)[0])]
                elif op == 0x20 or op == 0x23:
                    args = ["v%d" % ((u >> 8) & 0xF), "v%d" % ((u >> 12) & 0xF),
                            self.type_at(ins[i + 1])]
                elif op in (0x02, 0x05, 0x08):
                    args = ["v%d" % hi, "v%d" % ins[i + 1]]
                elif op in (0x03, 0x06, 0x09):
                    args = ["v%d" % hi, "v%d" % struct.unpack_from("<H", ins, i * 2 + 2)[0]]
            except Exception as e:
                args = ["<err %s>" % e]
            out.append((i, "%s %s" % (name, ", ".join(args)) if args else name))
            i += ln if ln else 1
        return out

    def method_sig(self, midx):
        c, mn, (ret, prm) = self.method_at(midx)
        return "%s->%s(%s)%s" % (c, mn, ",".join(prm), ret)

    # ---------- 检索 ----------
    def refs_to_string(self, str_idx):
        """[(class, method_sig, code_off, instr_pos)]"""
        hits = []
        for desc, methods in self.classes():
            for midx, acc, code_off, _isd in methods:
                if not code_off:
                    continue
                ins = self.code_insns(code_off)
                for i in range(len(ins) - 1):
                    u = ins[i]
                    if (u & 0xFF) == 0x1A and ins[i + 1] == str_idx:
                        hits.append((desc, self.method_sig(midx), code_off, i))
                    elif (u & 0xFF) == 0x1B:
                        if i + 2 < len(ins):
                            j = ins[i + 1] | (ins[i + 2] << 16)
                            if j == str_idx:
                                hits.append((desc, self.method_sig(midx), code_off, i))
        return hits


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 1
    cmd, path, a = sys.argv[1], sys.argv[2], sys.argv[3]
    d = Dex(path)
    if cmd == "str":
        idxs = d.find_string(a)
        print("字符串命中 %d 条 string_id" % len(idxs))
        for si in idxs[:20]:
            print("  [%d] %r" % (si, d.str_at(si)))
        seen = set()
        for si in idxs:
            for desc, sig, co, ip in d.refs_to_string(si):
                k = (desc, sig)
                if k in seen:
                    continue
                seen.add(k)
                print("\n=== %s  (insn@%d) ===" % (sig, ip))
    elif cmd == "method":
        cls_kw, meth_kw = a, (sys.argv[4] if len(sys.argv) > 4 else "")
        for desc, methods in d.classes():
            if cls_kw not in desc:
                continue
            for midx, acc, code_off, _ in methods:
                sig = d.method_sig(midx)
                if meth_kw and meth_kw not in sig:
                    continue
                print("\n=== %s  (code_off=0x%x, access=0x%x) ===" % (sig, code_off, acc))
                for pos, line in d.disasm(code_off):
                    print("  %04x: %s" % (pos, line))
    elif cmd == "xref":
        d.classes()
        targets = []
        for desc, methods in d.classes():
            for midx, acc, code_off, _ in methods:
                sig = d.method_sig(midx)
                if a in sig:
                    targets.append((midx, sig))
        tset = {m for m, _ in targets}
        print("目标方法 %d 个" % len(targets))
        for m, s in targets[:10]:
            print("  [%d] %s" % (m, s))
        for desc, methods in d.classes():
            for midx, acc, code_off, _ in methods:
                if not code_off:
                    continue
                ins = d.code_insns(code_off)
                for i in range(len(ins) - 1):
                    op = ins[i] & 0xFF
                    if 0x6E <= op <= 0x72 or 0x74 <= op <= 0x78:
                        if ins[i + 1] in tset:
                            print("  %s  ->  %s" % (d.method_sig(midx), d.method_sig(ins[i + 1])))
                            break
    return 0


if __name__ == "__main__":
    sys.exit(main())

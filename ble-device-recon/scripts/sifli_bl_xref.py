#!/usr/bin/env python3
"""扫固件镜像找 BL / B.W 到指定地址的调用点（纯编码解码，不依赖反汇编器）。

为什么需要它：sifli_xref.py 找的是「数据引用」（谁把某个地址当字符串/常量表指针用），
但「谁调用了这个函数」属于**代码流引用**，编译器直接编码进 BL 指令，
不会经过字面量池，所以 sifli_xref.py 对它 0 命中。

线性反汇编扫全镜像当然也能找，但有两个问题：
  1. 慢（3MB 镜像几十秒），且必须处理好 thumb/data 混杂；
  2. capstone 遇到不认识的编码会停或错位，漏掉后续指令。
本脚本只做一件事：按 2 字节步进解 Thumb-2 BL/B.W 的 32 位编码，
逐位还原目标地址与目标比对。3MB 镜像 1 秒内扫完，零漏报。

Thumb-2 T4（BL / B.W 同编码，仅 bit12 区分，对找调用点无影响）：
    h1 = 11110 S imm10
    h2 = 1 1 J1 1 J2 imm11      (BL)
    h2 = 1 0 J1 0 J2 imm11      (B.W)
    I1 = NOT(J1 XOR S) ; I2 = NOT(J2 XOR S)
    imm = S:I1:I2:imm10:imm11:0
    target = PC + SignExtend(imm, 25)     其中 PC = 指令地址 + 4

用法:
    python sifli_bl_xref.py --image fw.bin 0x12182998
    python sifli_bl_xref.py --image fw.bin --base 0x12070000 0x120A9834 0x120B0178
    python sifli_bl_xref.py --image fw.bin --base 0x12070000 --all-bl   # 统计所有调用点
"""
import argparse
import struct
import sys

DEFAULT_BASE = 0x12070000


def sx(v, bits):
    """符号扩展（无符号 v 按 bits 宽取补码）。"""
    if v & (1 << (bits - 1)):
        v -= 1 << bits
    return v


def is_blw(h1, h2):
    """h1 高 5 位 = 11110，且 h2 高 2 位 = 11 且 bit12 = x（BL:1 / B.W:0）。

    简化判定：h1 & 0xF800 == 0xF000 且 h2 & 0xD000 == 0xD000（BL）
           或 h2 & 0xD000 == 0x9000（B.W）。
    """
    if (h1 & 0xF800) != 0xF000:
        return False
    hi = h2 & 0xD000
    return hi == 0xD000 or hi == 0x9000


def bl_target(addr, h1, h2):
    s = (h1 >> 10) & 1
    j1 = (h2 >> 13) & 1
    j2 = (h2 >> 11) & 1
    i1 = 1 - (j1 ^ s)
    i2 = 1 - (j2 ^ s)
    imm10 = h1 & 0x3FF
    imm11 = h2 & 0x7FF
    imm = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
    return (addr + 4 + sx(imm, 25)) & 0xFFFFFFFF


def scan(data, base, targets=None):
    """返回 {target: [site,...]} 或 {None: [(site,target),...]}（全量模式）。"""
    want = set(targets or [])
    res = {t: [] for t in want}
    everything = [] if targets is None else None
    for off in range(0, len(data) - 4, 2):
        h1, h2 = struct.unpack_from("<HH", data, off)
        if not is_blw(h1, h2):
            continue
        site = off + base
        tgt = bl_target(site, h1, h2)
        if everything is not None:
            everything.append((site, tgt))
        elif tgt in res:
            res[tgt].append(site)
    return res if targets else everything


def main():
    ap = argparse.ArgumentParser(description="扫 BL/B.W 调用点（Thumb-2 T4）")
    ap.add_argument("targets", nargs="*", type=lambda x: int(x, 0),
                    help="目标 flash 地址，可多个")
    ap.add_argument("--image", required=True, help="镜像文件")
    ap.add_argument("--base", type=lambda x: int(x, 0), default=DEFAULT_BASE,
                    help=f"加载基址（默认 0x{DEFAULT_BASE:08X}）")
    ap.add_argument("--all-bl", action="store_true", help="统计镜像内所有调用点（不筛目标）")
    ap.add_argument("--limit", type=int, default=40, help="每个目标最多打印多少处（默认 40）")
    a = ap.parse_args()

    if not a.all_bl and not a.targets:
        ap.error("要么给目标地址，要么加 --all-bl")

    data = open(a.image, "rb").read()
    print(f"镜像 {a.image}  {len(data):,} B  基址 0x{a.base:08X}")

    if a.all_bl:
        every = scan(data, a.base, None)
        print(f"全镜像 BL/B.W 调用点 {len(every):,} 处")
        rng = [t for _, t in every if a.base <= t < a.base + len(data)]
        print(f"  其中落在镜像区间内: {len(rng):,} 处")
        from collections import Counter
        c = Counter(t & ~1 for t in rng)
        print("  被调最多的 10 个地址（已归并 thumb 位）:")
        for t, n in c.most_common(10):
            print(f"    0x{t:08X}  ← {n} 处")
        return

    res = scan(data, a.base, a.targets)
    for t in a.targets:
        sites = res[t]
        print(f"\n### 0x{t:08X}  调用点 {len(sites)} 处")
        for s in sites[:a.limit]:
            print(f"    BL @0x{s:08X}  (文件偏移 0x{s - a.base:X})")
        if len(sites) > a.limit:
            print(f"    ... 其余 {len(sites) - a.limit} 处省略")
        if not sites:
            print("    （无。常见原因：目标是被 tail-call / 通过函数指针调用 /"
                  " 地址打错一位 thumb 位）")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)

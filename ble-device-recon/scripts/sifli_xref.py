"""在固件镜像里找指向指定地址的代码引用（Thumb）。

两种编码都能扫：
  LDR  Rt,[PC,#imm8*4]   h & 0xF800 == 0x4800   -> align4(PC)+imm8*4
  ADR  Rd,label          h & 0xF800 == 0xA000   -> align4(PC)+imm8*4

用法：
  python xref_lit.py 0x121C88EC              # 直接给目标地址
  python xref_lit.py --off 0x1588EC          # 给文件偏移
"""
import argparse
import struct
import sys

BASE = 0x12070000
IMG = "ota_capture/fw_image_full.bin"


def align4(x):
    return (x + 3) & ~3


def find_pools(data, targets):
    """找出所有存放目标地址的 32 位字面量槽（4 字节对齐）。"""
    pools = {t: [] for t in targets}
    n = len(data)
    for a in range(0, n - 4, 4):
        v = struct.unpack_from("<I", data, a)[0]
        if v in pools:
            pools[v].append(a)
    return pools


def scan(data, targets, pool_offsets=None):
    """返回 {target: [(file_off_of_instr, kind, imm)]}

    pool_offsets 不为空时，额外把"LDR 指向池槽"的引用算进来。
    """
    res = {t: [] for t in targets}
    by_off = {o: t for t, offs in (pool_offsets or {}).items() for o in offs}
    n = len(data)
    for a in range(0, n - 4, 2):
        h = struct.unpack_from("<H", data, a)[0]
        top = h & 0xF800
        if top != 0x4800 and top != 0xA000:
            continue
        pc = BASE + a
        imm = (h & 0xFF) * 4
        tgt = align4(pc + 4) + imm
        tgt_off = tgt - BASE
        if tgt in res:
            res[tgt].append((a, "LDR" if top == 0x4800 else "ADR", h & 0xFF))
        elif tgt_off in by_off:
            res[by_off[tgt_off]].append((a, "LDR*pool", h & 0xFF))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="*", help="目标地址，如 0x121C88EC")
    ap.add_argument("--off", action="append", default=[], help="文件偏移，如 0x1588EC")
    ap.add_argument("--image", default=IMG)
    ap.add_argument("--base", default="0x12070000", help="镜像加载基址")
    a = ap.parse_args()

    global BASE
    BASE = int(a.base, 0)
    ts = []
    for s in a.targets:
        ts.append(int(s, 16))
    for s in a.off:
        ts.append(BASE + int(s, 16))
    if not ts:
        ap.error("至少给一个地址或 --off")

    data = open(a.image, "rb").read()
    print(f"[i] 镜像 {a.image}  {len(data):,} 字节  基址 0x{BASE:08X}")

    pools = find_pools(data, set(ts))
    res = scan(data, set(ts), pools)

    for t in ts:
        hits = res.get(t, [])
        pool_offs = pools.get(t, [])
        print(f"\n=== 目标 0x{t:08X}（偏移 0x{t-BASE:06X}） ===")
        print(f"    字面量池槽 {len(pool_offs)} 个: {['0x%06X' % o for o in pool_offs[:8]]}")
        print(f"    代码引用 {len(hits)} 处")
        for off, kind, imm in hits:
            print(f"  指令 @0x{BASE+off:08X} (偏移 0x{off:06X})  {kind} imm={imm}")
            print(f"      上下文: {data[max(0,off-12):off+12].hex(' ')}")


if __name__ == "__main__":
    main()

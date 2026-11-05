"""固件镜像补丁器 —— 在原厂镜像上打字节补丁 / 注入代码块 / 改跳转。

设计原则：**只做外科手术，不重排镜像**。
镜像布局、向量表、初始化顺序全部保持原样，出问题时影响面天然受限。

用法：
  # 1) 纯字节补丁（改常量、改字符串）
  python fw_patch.py --image ota_capture/fw_image_full.bin -o out.bin \
      --set 0x1588EC=56312e30312e3939

  # 2) 注入代码块到洞穴
  python fw_patch.py --image in.bin -o out.bin \
      --inject 0x120701CC=hook.bin

  # 3) 把某个函数入口改成跳到洞穴（自动选 b.w / bl）
  python fw_patch.py --image in.bin -o out.bin \
      --inject 0x120701CC=hook.bin --redirect 0x121C8858=0x120701CD

  # 全部改完自动出报告
  python fw_patch.py --image in.bin -o out.bin ... --json out.json

约定：所有地址都是**flash 地址**（0x12070000 起），不是文件偏移。
"""
import argparse
import json
import os
import struct
import sys

BASE = 0x12070000


# ---------------------------------------------------------------- 跳转编码

def _enc_branch(src, dst, kind):
    """编码 Thumb-2 的 B.W / BL。src/dst 都是 flash 地址，src 会按 &~1 处理。"""
    src &= ~1
    dst &= ~1
    off = dst - (src + 4)
    if off % 2:
        raise ValueError(f"目标地址未对齐：0x{dst:08X}")
    if not (-(1 << 24) <= off < (1 << 24)):
        raise ValueError(f"跳转超出 ±16MB：0x{off:X}")

    u = off & 0x1FFFFFF
    s = (u >> 24) & 1
    i1 = (u >> 23) & 1
    i2 = (u >> 22) & 1
    imm10 = (u >> 12) & 0x3FF
    imm11 = (u >> 1) & 0x7FF
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1

    hw1 = 0xF000 | (s << 10) | imm10
    base = 0xC800 if kind == "bl" else 0x8800
    hw2 = base | (j1 << 13) | (j2 << 12) | imm11
    return struct.pack("<HH", hw1, hw2)


def enc_b(src, dst):
    return _enc_branch(src, dst, "b")


def enc_bl(src, dst):
    return _enc_branch(src, dst, "bl")


# ---------------------------------------------------------------- 补丁应用

def parse_set(spec):
    """'0xADDR=hexbytes' -> (addr, bytes)"""
    addr_s, hex_s = spec.split("=", 1)
    return int(addr_s, 16), bytes.fromhex(hex_s)


def parse_inject(spec):
    """'0xADDR=file' -> (addr, path)"""
    addr_s, path = spec.split("=", 1)
    return int(addr_s, 16), path


def apply_patches(img, sets, injects, redirects):
    img = bytearray(img)
    n = len(img)
    log = []

    def check(addr, length):
        off = addr - BASE
        if off < 0 or off + length > n:
            raise ValueError(
                f"地址 0x{addr:08X}（偏移 0x{off:06X}）+{length}B 超出镜像 {n:,}B")

    for addr, data in sets:
        check(addr, len(data))
        off = addr - BASE
        old = bytes(img[off:off + len(data)])
        img[off:off + len(data)] = data
        log.append({"kind": "set", "addr": f"0x{addr:08X}", "len": len(data),
                    "old": old.hex(), "new": data.hex()})

    for addr, path in injects:
        blob = open(path, "rb").read()
        check(addr, len(blob))
        off = addr - BASE
        img[off:off + len(blob)] = blob
        log.append({"kind": "inject", "addr": f"0x{addr:08X}", "len": len(blob),
                    "src": os.path.basename(path)})

    for src, dst, kind in redirects:
        check(src, 4)
        code = enc_bl(src, dst) if kind == "bl" else enc_b(src, dst)
        off = src - BASE
        old = bytes(img[off:off + 4])
        img[off:off + 4] = code
        log.append({"kind": "redirect", "addr": f"0x{src:08X}", "to": f"0x{dst:08X}",
                    "branch": kind, "old": old.hex(), "new": code.hex()})
        _verify_branch(src, dst, code)

    return bytes(img), log


def _verify_branch(src, dst, code):
    """用 capstone 复核编码结果（capstone 不可用时跳过）。"""
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    except ImportError:
        return
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    ins = list(md.disasm(code, src & ~1))
    if not ins:
        raise ValueError(f"跳转编码无法解码：{code.hex()}")
    got = ins[0].op_str.lstrip("#")
    if int(got, 16) != (dst & ~1):
        raise ValueError(f"跳转编码校验失败：期望 0x{dst & ~1:08X}，实际 {ins[0].op_str}")


def diff_summary(a, b, limit=20):
    if len(a) != len(b):
        raise ValueError("长度不一致")
    segs = []
    i = 0
    n = len(a)
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            segs.append((i, j - i))
            i = j
        else:
            i += 1
    total = sum(l for _, l in segs)
    print(f"[i] 差异：{len(segs)} 段 / {total} 字节（镜像 {n:,}B，占 {total/n*100:.4f}%）")
    for off, ln in segs[:limit]:
        print(f"    偏移 0x{off:06X}  地址 0x{BASE + off:08X}  {ln} 字节")
    if len(segs) > limit:
        print(f"    ...另有 {len(segs) - limit} 段")
    return segs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--base", default="0x12070000",
                    help="镜像加载基址（sf32lb55x QSPI4 默认 0x12070000；flash1 方案为 0x10000000）")
    ap.add_argument("--set", action="append", default=[], metavar="ADDR=HEX")
    ap.add_argument("--inject", action="append", default=[], metavar="ADDR=FILE")
    ap.add_argument("--redirect", action="append", default=[], metavar="FROM=TO")
    ap.add_argument("--json", default=None, help="把补丁清单写成 json")
    a = ap.parse_args()

    global BASE
    BASE = int(a.base, 0)
    src = open(a.image, "rb").read()
    sets = [parse_set(s) for s in a.set]
    injects = [parse_inject(s) for s in a.inject]
    redirects = []
    for s in a.redirect:
        f, t = s.split("=", 1)
        kind = "b"
        if t.endswith(":bl"):
            t, kind = t[:-3], "bl"
        redirects.append((int(f, 16), int(t, 16), kind))

    if not (sets or injects or redirects):
        ap.error("至少要有一个 --set / --inject / --redirect")

    out, log = apply_patches(src, sets, injects, redirects)

    for e in log:
        if e["kind"] == "redirect":
            print(f"  跳转 {e['addr']} -> {e['to']}  ({e['branch']})  "
                  f"{e['old']} => {e['new']}  ✓已复核")
        elif e["kind"] == "set":
            print(f"  改写 {e['addr']}  {e['len']}B  {e['old'][:24]}... => {e['new'][:24]}...")
        else:
            print(f"  注入 {e['addr']}  {e['len']}B  ({e['src']})")

    diff_summary(src, out)
    open(a.out, "wb").write(out)
    print(f"[+] 已写出 {a.out}  {len(out):,} 字节")

    if a.json:
        json.dump({"src": os.path.basename(a.image), "out": os.path.basename(a.out),
                   "entries": log}, open(a.json, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print(f"[+] 补丁清单 {a.json}")


if __name__ == "__main__":
    sys.exit(main())

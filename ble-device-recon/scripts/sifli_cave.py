"""在固件镜像里找代码洞穴（可安全注入的黑区）。

判据：连续 N 字节全为 0xFF 或全为 0x00（链接器填充 / 未用对齐区）。
只统计位于镜像内部的，排除末尾空洞。

用法：
  python cave_find.py                 # 列出 >=64B 的洞
  python cave_find.py --min 32 --top 20 --image ota_capture/fw_image_full.bin
"""
import argparse
import re

DEFAULT_IMG = "ota_capture/fw_image_full.bin"


def runs(data, fill, min_len):
    """返回 [(offset, length)]，连续的 fill 字节段。"""
    out = []
    pat = re.compile(bytes([fill]) + b"+")
    for m in pat.finditer(data):
        if m.end() - m.start() >= min_len:
            out.append((m.start(), m.end() - m.start()))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default=DEFAULT_IMG)
    ap.add_argument("--min", type=int, default=64)
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--base", default="0x12070000", help="镜像加载基址")
    a = ap.parse_args()

    base = int(a.base, 0)
    data = open(a.image, "rb").read()
    print(f"[i] {a.image}  {len(data):,} 字节  基址 0x{base:08X}")

    for fill, name in ((0xFF, "0xFF 擦除"), (0x00, "0x00 对齐")):
        rs = runs(data, fill, a.min)
        total = sum(l for _, l in rs)
        print(f"\n=== {name}  段数 {len(rs)}  合计 {total:,} 字节 ===")
        for off, ln in sorted(rs, key=lambda x: -x[1])[: a.top]:
            # 排除长尾：如果这一段延伸到文件末尾，标注出来
            tail = "（到文件尾）" if off + ln >= len(data) - 16 else ""
            print(f"  0x{off:06X}  {ln:6d}B  (地址 0x{base + off:08X}){tail}")


if __name__ == "__main__":
    main()

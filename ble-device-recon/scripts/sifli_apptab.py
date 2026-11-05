#!/usr/bin/env python3
"""sifli_apptab.py —— 读写 SiFli 固件里的「应用表」（菜单里的应用清单）。

应用表结构（SF32LB55x 手表方案实测，**每项 0x1C 字节**）：

    偏移   类型          含义
    +0x00  u32           资源 id（图标/名称的 key，改动会查不到资源）
    +0x04  u32           图标指针；**为 0 时该应用在菜单里不可见**
    +0x08  char[16]      内部名字（仅用于匹配/调试，**不是菜单上显示的文字**）
    +0x18  u32           注册函数指针（thumb 位 = +1），开机时框架逐项调用

菜单上显示的文字来自 i18n 表（见 sifli_i18n.py），不是这里的 name 字段。

用法：
    # 列出全部应用
    python sifli_apptab.py --image fw.bin --dump

    # 把某个隐藏槽（icon=0）改造成自己的应用
    python sifli_apptab.py --image fw.bin -o out.bin \\
        --entry Dice --icon 0x129FDCD8 --reg 0x12070341

    # 把某项藏起来（菜单里看不见）
    python sifli_apptab.py --image fw.bin -o out.bin --entry Dice --hide

    # 只改名字（不影响显示，仅便于自己在反汇编里认）
    python sifli_apptab.py --image fw.bin -o out.bin --entry Dice --name HELLO

约定：所有地址都是 flash 地址，不是文件偏移。
"""
import argparse
import json
import struct
import sys

BASE = 0x12070000
TABLE = 0x123246FC          # 表起点
ENTRY_SIZE = 0x1C
ENTRY_COUNT = 35


class Image:
    def __init__(self, data, base=BASE):
        self.d = bytearray(data)
        self.base = base

    def off(self, addr, n=0):
        o = addr - self.base
        if o < 0 or o + n > len(self.d):
            raise ValueError("地址 0x%08X +%dB 超出镜像 %dB" % (addr, n, len(self.d)))
        return o

    def rd(self, addr, n):
        o = self.off(addr, n)
        return bytes(self.d[o:o + n])

    def u32(self, addr):
        return struct.unpack("<I", self.rd(addr, 4))[0]

    def wr(self, addr, data):
        o = self.off(addr, len(data))
        self.d[o:o + len(data)] = data

    def wr_u32(self, addr, v):
        self.wr(addr, struct.pack("<I", v & 0xFFFFFFFF))

    def cstr(self, addr, maxlen=64):
        o = self.off(addr, 0)
        b = bytes(self.d[o:o + maxlen]).split(b"\0")[0]
        return b.decode("utf-8", "replace")


def read_table(img, table=TABLE, count=ENTRY_COUNT):
    out = []
    for i in range(count):
        e = table + i * ENTRY_SIZE
        out.append({
            "idx": i,
            "addr": "0x%08X" % e,
            "res_id": img.u32(e),
            "icon": img.u32(e + 4),
            "name": img.cstr(e + 8, 16),
            "reg": img.u32(e + 0x18),
            "visible": img.u32(e + 4) != 0,
        })
    return out


def cmd_dump(img, as_json, table, count):
    rows = read_table(img, table, count)
    if as_json:
        json.dump(rows, open(as_json, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print("[i] 应用表 -> %s（%d 项）" % (as_json, len(rows)))
        return
    print("应用表 @0x%08X  %d 项 x 0x%02X" % (table, count, ENTRY_SIZE))
    print("%-3s %-10s %-10s %-10s %-6s %s" %
          ("idx", "addr", "res_id", "icon", "菜单", "name / reg"))
    for r in rows:
        print("%-3d %-10s %08X   %08X   %-6s %-16s %08X" % (
            r["idx"], r["addr"], r["res_id"], r["icon"],
            "可见" if r["visible"] else "-", r["name"], r["reg"]))
    vis = sum(1 for r in rows if r["visible"])
    print("可见 %d / %d，隐藏槽（可改造）：" % (vis, len(rows)))
    for r in rows:
        if not r["visible"]:
            print("   %s  %-16s reg=%08X" % (r["addr"], r["name"], r["reg"]))


def find_entry(img, name, table, count):
    for r in read_table(img, table, count):
        if r["name"].lower() == name.lower():
            return r
    raise SystemExit("找不到名为 %r 的应用项。先 --dump 看一下。" % name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("-o", "--out")
    ap.add_argument("--table", default="0x%08X" % TABLE)
    ap.add_argument("--count", type=int, default=ENTRY_COUNT)
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--json", default=None)
    ap.add_argument("--entry", default=None, help="要改的应用名（--dump 里 name 列）")
    ap.add_argument("--name", default=None, help="改 name[16]（不影响菜单显示）")
    ap.add_argument("--icon", default=None, help="改图标指针，0 = 菜单隐藏")
    ap.add_argument("--reg", default=None, help="改注册函数指针（thumb 位必须 +1）")
    ap.add_argument("--hide", action="store_true", help="等价于 --icon 0")
    a = ap.parse_args()

    table = int(a.table, 16)
    img = Image(open(a.image, "rb").read())

    if a.dump or not a.out:
        cmd_dump(img, a.json, table, a.count)
        if not a.out:
            return 0

    r = find_entry(img, a.entry, table, a.count) if a.entry else None
    if r is None:
        ap.error("给了 -o 就必须同时给 --entry")

    e = int(r["addr"], 16)
    changed = []

    if a.name is not None:
        raw = a.name.encode("utf-8")
        if len(raw) > 15:
            raise SystemExit("name 最多 15 字节（字段 16 字节含结尾 0）")
        img.wr(e + 8, raw + b"\0" * (16 - len(raw)))
        changed.append("name = %r" % a.name)

    icon = 0 if a.hide else (int(a.icon, 16) if a.icon else None)
    if icon is not None:
        img.wr_u32(e + 4, icon)
        changed.append("icon = 0x%08X%s" % (icon, "（菜单隐藏）" if icon == 0 else "（菜单可见）"))

    if a.reg is not None:
        v = int(a.reg, 16)
        if not (v & 1):
            print("[!] 0x%08X 没有 thumb 位（最低位为 0）——BLX 会按 ARM 态跳转，多半 HardFault" % v)
        img.wr_u32(e + 0x18, v)
        changed.append("reg = 0x%08X" % v)

    if not changed:
        ap.error("没有要改的字段（--name / --icon / --reg / --hide）")

    print("[i] 改 %s @0x%08X  %s" % (r["name"], e, "；".join(changed)))
    # 回读复核
    print("    旧 reg=%08X icon=%08X name=%r" % (r["reg"], r["icon"], r["name"]))
    print("    新 reg=%08X icon=%08X name=%r" % (
        img.u32(e + 0x18), img.u32(e + 4), img.cstr(e + 8, 16)))

    open(a.out, "wb").write(img.d)
    print("[+] 已写出 %s  %d 字节" % (a.out, len(img.d)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

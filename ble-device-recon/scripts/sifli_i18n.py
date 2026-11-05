#!/usr/bin/env python3
"""sifli_i18n.py —— 读写 SiFli 固件的 i18n 字符串表（菜单/界面文字的真正来源）。

**菜单上显示的文字不来自应用表的 name 字段，来自 i18n 表。**
i18n 表就是一串 u32 指针，`表中第 N 项 -> 某条字符串`；界面按固定下标记取，
例如菜单标签取 idx 69。

同一份固件里**每种语言各有一张表**（中文表、英文表……），
指向各自语言资源块里的字符串。改中文表，切回英文就看不到修改 —— 这是最容易白刷一次的地方。

实测（SF32LB551 手表，3,105,248 B 镜像）：
    中文表 base 0x122932E8，963 项连续有效，idx0 = "简体中文"（语言显示名）
    中文表 idx69 -> 0x122C49A6 "摇骰子"（菜单里的 Dice 项）
    英文表 base 0x122A82CC，idx69 -> 0x122ED747 "Dice"

用法：
    # 找出候选 i18n 表（按"连续有效指针"长度排序）
    python sifli_i18n.py --image fw.bin --tables

    # 看某张表的一段
    python sifli_i18n.py --image fw.bin --dump 0x122932E8 --range 60:80

    # 某条文字被哪些槽引用（= 哪些语言的表用到了它）
    python sifli_i18n.py --image fw.bin --find-str "摇骰子"

    # 把某个槽改成指向别处（典型：指向代码洞里的自造字符串）
    python sifli_i18n.py --image fw.bin -o out.bin --set-addr 0x122933FC=0x12070400

    # 往代码洞里写字符串
    python sifli_i18n.py --image fw.bin -o out.bin --put-str 0x12070400=HELLO

约定：所有地址都是 flash 地址，不是文件偏移。
"""
import argparse
import struct
import sys

BASE = 0x12070000
MIN_RUN = 32


class Image:
    def __init__(self, data, base=BASE):
        self.d = bytearray(data)
        self.base = base
        self.end = base + len(self.d)

    def off(self, addr, n=0):
        o = addr - self.base
        if o < 0 or o + n > len(self.d):
            raise ValueError("地址 0x%08X +%dB 超出镜像 %dB" % (addr, n, len(self.d)))
        return o

    def u32(self, addr):
        o = self.off(addr, 4)
        return struct.unpack("<I", bytes(self.d[o:o + 4]))[0]

    def wr(self, addr, data):
        o = self.off(addr, len(data))
        self.d[o:o + len(data)] = data

    def cstr(self, addr, maxlen=60):
        try:
            o = self.off(addr, 0)
        except ValueError:
            return "??"
        b = bytes(self.d[o:o + maxlen]).split(b"\0")[0]
        return b.decode("utf-8", "replace")

    def in_image(self, v):
        return self.base <= v < self.end


def find_tables(img, min_run=MIN_RUN):
    """连续「指向镜像内的指针」最长串，就是 i18n 表（代码里的字面量池不会这么长）。"""
    n = len(img.d) // 4
    runs = []
    i = 0
    while i < n:
        if img.in_image(struct.unpack_from("<I", img.d, i * 4)[0]):
            j = i
            while j < n and img.in_image(struct.unpack_from("<I", img.d, j * 4)[0]):
                j += 1
            if j - i >= min_run:
                runs.append((img.base + i * 4, j - i))
            i = j
        else:
            i += 1
    runs.sort(key=lambda t: -t[1])
    return runs


def cmd_tables(img):
    runs = find_tables(img)
    print("候选 i18n 表（连续有效指针 >= %d 项）：" % MIN_RUN)
    for base, cnt in runs:
        print("  0x%08X  %4d 项  idx0=%r" % (base, cnt, img.cstr(img.u32(base))))
    print("\n提示：另一种语言的那张表可能是稀疏的（大量 0），不会被这段扫描列出。")
    print("      用 --find-str 定位某条文字的所有引用槽，再回头看它落在哪段连续指针里。")


def cmd_langs(img, master, count=13):
    """语言主表：{u32 lang_id; char *显示名} 每项 8 字节。

    实测固件里有两份，同一组 13 种语言、不同命名风格：
        0x122AD608  英文命名（English（UK）/ Polish / Khmer…）
        0x122AD670  本地命名（Polski / Nederlands / ភាសាខ្មែរ…）
    每项指向的字符串，同时也是对应语言 i18n 表的 idx0 —— 这就是"名字 → 表"的钩子。
    """
    tables = dict(find_tables(img))
    print("语言主表 @0x%08X（%d 项）" % (master, count))
    print("%-4s %-10s %-10s %-22s %s" % ("idx", "lang_id", "显示名", "字符串地址", "对应 i18n 表"))
    for i in range(count):
        a = master + i * 8
        try:
            lid = img.u32(a)
            p = img.u32(a + 4)
        except ValueError:
            break
        if not img.in_image(p):
            break
        owner = ""
        for tb, cnt in sorted(tables.items(), key=lambda kv: -kv[1]):
            if img.u32(tb) == p and cnt >= 32:
                owner = "0x%08X（%d 项）" % (tb, cnt)
                break
        print("%-4d %-10d %-10s 0x%08X  %s" %
              (i, lid, img.cstr(p, 24), p, owner or "?"))


def cmd_dump(img, base, rng):
    a, b = rng
    print("表 @0x%08X  idx %d..%d" % (base, a, b - 1))
    for i in range(a, b):
        slot = base + i * 4
        try:
            p = img.u32(slot)
        except ValueError:
            break
        txt = img.cstr(p) if img.in_image(p) else "??"
        print("  idx %-4d @0x%08X -> 0x%08X  %r" % (i, slot, p, txt))


def cmd_find_str(img, text):
    raw = text.encode("utf-8")
    pat = raw + b"\0"
    hits = []
    start = 0
    while True:
        k = bytes(img.d).find(pat, start)
        if k < 0:
            break
        hits.append(img.base + k)
        start = k + 1
    if not hits:
        raise SystemExit("镜像里找不到字符串 %r" % text)
    print("字符串 %r 出现在 %d 处：" % (text, len(hits)))
    tables = find_tables(img)
    for a in hits:
        print("  0x%08X" % a)
        pat4 = struct.pack("<I", a)
        idx = 0
        slots = []
        while True:
            k = bytes(img.d).find(pat4, idx)
            if k < 0:
                break
            if k % 4 == 0:
                slots.append(img.base + k)
            idx = k + 1
        for s in slots:
            where = ""
            for tb, cnt in tables:
                if tb <= s < tb + cnt * 4:
                    where = "  在表 0x%08X 的 idx %d" % (tb, (s - tb) // 4)
                    break
            print("    引用槽 0x%08X%s" % (s, where))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("-o", "--out")
    ap.add_argument("--tables", action="store_true")
    ap.add_argument("--langs", default=None,
                    help="语言主表基址（实测 0x122AD608 / 0x122AD670）")
    ap.add_argument("--dump", default=None, help="表基址")
    ap.add_argument("--range", default="0:40", help="A:B，默认 0:40")
    ap.add_argument("--find-str", default=None)
    ap.add_argument("--set-addr", action="append", default=[], metavar="ADDR=TARGET")
    ap.add_argument("--put-str", action="append", default=[], metavar="ADDR=TEXT")
    a = ap.parse_args()

    img = Image(open(a.image, "rb").read())

    if a.tables:
        cmd_tables(img)
    if a.langs:
        cmd_langs(img, int(a.langs, 16))
    if a.dump:
        x, y = a.range.split(":")
        cmd_dump(img, int(a.dump, 16), (int(x), int(y)))
    if a.find_str:
        cmd_find_str(img, a.find_str)

    if a.set_addr or a.put_str:
        if not a.out:
            ap.error("要改内容必须给 -o")
        for spec in a.set_addr:
            s, t = spec.split("=", 1)
            slot, target = int(s, 16), int(t, 16)
            old = img.u32(slot)
            img.wr(slot, struct.pack("<I", target))
            print("  改写 0x%08X  %08X(%r) => %08X" %
                  (slot, old, img.cstr(old) if img.in_image(old) else "??", target))
        for spec in a.put_str:
            s, text = spec.split("=", 1)
            addr = int(s, 16)
            raw = text.encode("utf-8") + b"\0"
            old = bytes(img.d[img.off(addr, len(raw)):img.off(addr, len(raw)) + len(raw)])
            img.wr(addr, raw)
            print("  写串 0x%08X  %d B  %r => %r" % (addr, len(raw), old, raw))
        open(a.out, "wb").write(img.d)
        print("[+] 已写出 %s  %d 字节" % (a.out, len(img.d)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

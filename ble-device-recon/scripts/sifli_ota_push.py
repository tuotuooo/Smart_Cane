#!/usr/bin/env python3
"""SiFli DFU 推流器 —— 在 OTA manager 模式（设备名通常变成 GTX20）下推固件数据块。

## 为什么按 UUID 解析通道，而不是写死句柄号

user bin（应用态）和 bootloader（OTA manager 态）是**两套完全不同的 GATT 表**：

    user bin（11 个特征值）                      OTA manager（只剩 2 个）
    ─────────────────────────────────────       ─────────────────────────────
    SVC 00000af0-...                            SVC 00000000-0000-0000-6473-5f696c666973
      CH 0x000F 0af6  写控制帧（33 帧）           CH 0x000F ...-0100-...  控制（ctrl_packet）
      CH 0x0011 0af7  notify 应答                 CH 0x0011 ...-0200-...  数据面 + 命令 + 应答
      CH 0x0014 0af1  图像数据
      CH 0x0016 0af2  notify
    SVC ...6473-5f696c666973（sifli DFU）
      CH 0x001A ...-0100-...
      CH 0x001C ...-0200-...

**0af0 那四个特征值在 OTA 模式下整组消失**，所以"进 OTA 后找不到 0x0014 / 0x001C"
不是 GATT 发现被截断，而是它们在该模式下不存在。按 UUID 后缀
`-0100-6473-5f696c666973` / `-0200-6473-5f696c666973` 解析才是稳的。

## 数据面和控制命令共用同一根管道（实测抓包结论）

    CTRL_REQ / START / 每个数据分片 / IMG_END   → 全部写 -0200-
    设备的所有应答                               → 从 -0200- notify 回来

## 用法

    # 设备已进入 OTA manager 后推流
    python sifli_ota_push.py --mac AA:BB:CC:DD:EE:FF --blocks pkg.blocks

    # 只验证 CTRL_REQ / START 握手，不推数据（低风险探测）
    python sifli_ota_push.py --mac ... --blocks pkg.blocks --probe

    # 需要时先重发一遍 ctrl_packet
    python sifli_ota_push.py --mac ... --blocks pkg.blocks --send-ctrl pkg.ctrl

依赖：pip install bleak
"""
import argparse
import asyncio
import struct
import sys
import time

# ---- 协议常量（来自真机抓包，逐字节核对过）----
CTRL_REQ = bytes.fromhex("010005002200010000")
START = bytes.fromhex("01000e0006000a00c4b63200b11700000000")
IMG_END1 = bytes.fromhex("01000600080002000000")
IMG_END2 = bytes.fromhex("010005000c00010000")
START_ACK_HDR = bytes.fromhex("010008000700")   # 设备回 START 成功的应答前缀

SUF_CTRL = "-0100-6473-5f696c666973"
SUF_DATA = "-0200-6473-5f696c666973"
UUID_NAME = "00002a00-"


# ------------------------------------------------------------------ 传输层
def fragment(body, mtu=247):
    """把一条消息切成 ATT 分片：[cateID=1][片号][首片带总长LE16][数据]。

    片号 0x01 首片 / 0x02 中片 / 0x03 尾片。240+242 的容量来自 mtu=247。
    实测：554B 消息 → 3 片（240 / 240 / 74），与官方 App 的 18195 帧吻合。
    """
    room = max(mtu - 3, 20)
    c1 = min(room - 4, 240)
    c2 = min(room - 2, 242)
    total = len(body)
    parts = [bytes([1, 1]) + struct.pack("<H", total) + body[:c1]]
    pos = c1
    while pos < total:
        seg = body[pos:pos + c2]
        pos += len(seg)
        parts.append(bytes([1, 3 if pos >= total else 2]) + seg)
    return parts


def load_blocks(path):
    """读 .blocks（每块前置 u16 长度）。"""
    raw = open(path, "rb").read()
    out, p = [], 0
    while p + 2 <= len(raw):
        n = struct.unpack("<H", raw[p:p + 2])[0]
        p += 2
        out.append(raw[p:p + n])
        p += n
    if p != len(raw):
        raise ValueError(f"blocks 文件尾部多余 {len(raw) - p} 字节")
    return out


async def pace_to(t0, i, rate):
    """令牌桶节流：第 i 块应在 t0 + i/rate 之后才发。"""
    if rate <= 0:
        return
    ahead = (t0 + i / rate) - time.perf_counter()
    if ahead > 0:
        await asyncio.sleep(ahead)


async def connect(mac, minutes=3.0, timeout=15.0):
    """按地址直连（不扫广播），失败则守候重试。"""
    from bleak import BleakClient
    from bleak.backends.device import BLEDevice

    deadline = time.time() + minutes * 60
    n = 0
    while True:
        n += 1
        client = BleakClient(BLEDevice(mac, "SiFli", None), timeout=timeout)
        try:
            await client.connect()
            return client
        except Exception as e:
            print(f"  [{n}] 连不上: {type(e).__name__}: {e}", flush=True)
            try:
                await client.disconnect()
            except Exception:
                pass
            if time.time() >= deadline:
                raise
            await asyncio.sleep(2.0)


def resolve(client):
    """按 UUID 后缀解析 (ctrl, data, name)；找不到再退化到句柄号。"""
    ctrl = data = name = None
    for s in client.services:
        for c in s.characteristics:
            u = str(c.uuid).lower()
            if SUF_CTRL in u:
                ctrl = c
            elif SUF_DATA in u:
                data = c
            elif u.startswith(UUID_NAME):
                name = name or c
    if data is None:      # 退化：user bin 里的 0x001C
        for s in client.services:
            for c in s.characteristics:
                if c.handle == 0x001C:
                    data = c
    return ctrl, data, name


async def read_name(client, name_char):
    if name_char is None:
        return "?"
    try:
        return (await client.read_gatt_char(name_char)).decode("utf-8", "replace")
    except Exception:
        return "?"


# ------------------------------------------------------------------ 主流程
async def main(a):
    blocks = load_blocks(a.blocks)
    frags = [fragment(b, a.mtu) for b in blocks]
    print(f"[i] 数据块 {len(blocks)}  分片 {sum(len(f) for f in frags)}  MTU 假设 {a.mtu}", flush=True)

    client = await connect(a.mac, a.wait, a.timeout)
    log = []
    try:
        ctrl, data, namec = resolve(client)
        nm = await read_name(client, namec)
        print(f"[i] 设备名={nm!r}  ctrl=0x{ctrl.handle:04X}  data=0x{data.handle:04X}"
              f"  句柄总数={sum(len(s.characteristics) for s in client.services)}", flush=True)
        if a.require_ota and nm != "GTX20":
            print("[!] 不在 OTA manager 模式（设备名不是 GTX20），中止。"
                  "先走握手流程让设备进 OTA。", flush=True)
            return 2

        def on_note(_c, d):
            b = bytes(d)
            log.append(b)
            print(f"    <- notify {b.hex()[:80]}", flush=True)

        for c in (data, ctrl):
            if c is not None:
                try:
                    await client.start_notify(c, on_note)
                except Exception as e:
                    print(f"[!] 订阅 0x{c.handle:04X} 失败 {type(e).__name__}", flush=True)
        await asyncio.sleep(0.3)

        if a.send_ctrl:
            blob = open(a.send_ctrl, "rb").read()
            print(f"[i] 重发 ctrl_packet {len(blob)}B -> 0x{ctrl.handle:04X}", flush=True)
            for fr in fragment(blob, a.mtu):
                await client.write_gatt_char(ctrl, fr, response=False)
            await asyncio.sleep(0.5)

        # CTRL_REQ 后紧跟 START；设备确认 START 才允许推数据
        await client.write_gatt_char(data, CTRL_REQ, response=False)
        await asyncio.sleep(0.3)
        await client.write_gatt_char(data, START, response=False)
        ok = False
        for _ in range(int(a.start_wait * 5)):
            await asyncio.sleep(0.2)
            if any(b[:6] == START_ACK_HDR for b in log):
                ok = True
                break
        if not ok:
            print(f"[!] START 无应答（{a.start_wait}s）。已收到 {len(log)} 条通知：", flush=True)
            for b in log[:12]:
                print(f"      {b.hex()}", flush=True)
            return 3
        # 注意：应答是 12 字节，务必用 b[:6] 比 6 字节前缀；
        # 曾写成 b[:5] 比 6 字节常量 → 恒假 → 明明收到却判"无应答"。
        print("[+] START 成功应答已收到", flush=True)

        if a.probe:
            print("[i] --probe：只验证 CTRL_REQ/START，不推数据", flush=True)
            for k in range(6):
                await asyncio.sleep(1)
                print(f"  +{k + 1}s 在线={client.is_connected} 通知={len(log)}", flush=True)
            return 0

        log.clear()
        t0 = time.perf_counter()
        for i, fl in enumerate(frags):
            for fr in fl:
                await client.write_gatt_char(data, fr, response=False)
            await pace_to(t0, i + 1, a.rate)
            if (i + 1) % 1000 == 0:
                el = time.perf_counter() - t0
                print(f"    块 {i + 1:5d}/{len(frags)}  {el:5.1f}s  {(i + 1) / max(el, .01):5.0f} 块/秒",
                      flush=True)
        print(f"[+] 推流完成 {len(frags)} 块 / {time.perf_counter() - t0:.1f}s", flush=True)

        n0 = len(log)
        await client.write_gatt_char(data, IMG_END1, response=False)
        await asyncio.sleep(0.3)
        await client.write_gatt_char(data, IMG_END2, response=False)
        print("[i] 已发提交帧，观察设备反应（应收到 cmd=0x000B / cmd=0x000D 且 result=0）", flush=True)
        for k in range(a.observe):
            await asyncio.sleep(1)
            new = log[n0:]
            print(f"  +{k + 1:2d}s  在线={client.is_connected}  新通知={len(new)}"
                  + (f"  末条={new[-1].hex()[:60]}" if new else ""), flush=True)
            if not client.is_connected:
                print("  [+] 设备断开（进入安装/重启），约 1~10s 后应以原设备名回来", flush=True)
                break
        return 0
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="SiFli DFU 数据面推流（OTA manager 模式）")
    p.add_argument("--mac", required=True, help="设备 MAC，如 AA:BB:CC:DD:EE:FF")
    p.add_argument("--blocks", required=True, help="包里的 .blocks 文件")
    p.add_argument("--rate", type=float, default=100, help="块/秒（实测 100~300 稳定）")
    p.add_argument("--observe", type=int, default=30, help="提交后观察多少秒")
    p.add_argument("--wait", type=float, default=4, help="连接重试窗口（分钟）")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--start-wait", type=float, default=10.0)
    p.add_argument("--mtu", type=int, default=247, help="分片容量假设，默认 247（实测值）")
    p.add_argument("--send-ctrl", default=None, help="推流前先重发 ctrl_packet")
    p.add_argument("--probe", action="store_true", help="只验握手，不推数据")
    p.add_argument("--no-require-ota", dest="require_ota", action="store_false", default=True)
    a, _u = p.parse_known_args()
    sys.exit(asyncio.run(main(a)) or 0)

#!/usr/bin/env python3
"""sifli_ota_flash.py — 一条命令刷完：用户模式 -> DFU -> 推流

为什么拆成两个进程：
  同一进程内断开再连接，GATT 表会拿不全，写 START 后**收到 0 条通知**，
  看起来像设备不响应，实际是本地连接状态脏了。
  所以父进程只负责把设备送进 DFU，推流交给一个干净的子进程。

时序（真机实测确认，缺任一步就走不通）：
  1. 连用户模式，发 26 帧握手（33 帧格式，内容见 HANDSHAKE）
  2. 把 ctrl_packet 切片写到 -0200-  -> 收到以 010010002100 开头的应答
  3. 写 0x22 DFU_IMAGE_INIT_COMPLETED -> 设备 0.4s 内主动断开   <<< 缺这步永远进不去
  4. 约 2~5s 后以 GTX20 回来（7 个特征）。**不广播**，只能按 MAC 直连
  5. 子进程：CTRL_REQ(0x22) + START(0x06) -> N 块 -> IMG_END -> 等待重启

用法：
  python sifli_ota_flash.py --mac AA:BB:CC:DD:EE:FF \
      --ctrl pkg/ctrl_packet.bin --blocks pkg/blocks.bin

  # 设备已经在 GTX20 里了（跳过第 1~3 步）
  python sifli_ota_flash.py --mac ... --blocks ... --skip-enter

前置：
  pip install bleak
  包必须用 sifli_fw_pack.py 生成；fw_ver 用跟上次成功一致的值（本例 1001001），
  调大一位就可能被设备静默拒绝。
"""
import argparse
import asyncio
import os
import subprocess
import sys
import time

try:
    from bleak import BleakClient
except ImportError:
    sys.exit("需要 bleak：pip install bleak")

HERE = os.path.dirname(os.path.abspath(__file__))
PUSHER = os.path.join(HERE, "sifli_ota_push.py")

# ---------------------------------------------------------------- 通道句柄
# ⚠️ 下面三个是**这台设备、这个固件版本**在用户模式（11 特征）下实测可用的句柄。
#    换设备/换固件前必须自己核一遍：
#        python recon.py map <MAC> --save gatt.json
#    两套 GATT 表的句柄完全不同（用户模式 / GTX20 模式），写死句柄的脚本
#    能"连上"但 start 帧永远无应答 —— 这是历史踩过的坑。
H_CMD = 0x000F     # 写 33 帧握手
H_RSP = 0x0011     # 收应答 notify
H_CTRL = 0x001C    # 写 ctrl_packet 分片（-0200-）

ACCEPT_HDR = bytes.fromhex("010010002100")     # ctrl_packet 被接受
CTRL_REQ = bytes.fromhex("010005002200010000")  # 0x22 DFU_IMAGE_INIT_COMPLETED

# 26 帧握手（33 帧格式）：设备进入可收 ctrl_packet 的状态。
# 内容来自一次成功的真机流量，逐帧校验和已验证。不要手改。
HANDSHAKE_HEX = """
33daaddaad010b001a0002005ff9
33daaddaad010b0015000300801e
33daaddaad0110005200040000010000000118
33daaddaad016f00050005000100000000020000000008220000000e0000000010000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005374
33daaddaad0110000400060000010100007d19
33daaddaad0110000400070001010100004d0b
33daaddaad01100004000800000201000029b0
33daaddaad01100004000900010201000019a2
33daaddaad01100004000a0000060000000b2d
33daaddaad01100004000b0001060000003b3f
33daaddaad01100004000c0000070000009afa
33daaddaad01100004000d000107000000aae8
33daaddaad01100004000e0000080122002319
33daaddaad01100004000f000108010000976b
33daaddaad01100004001000000d00000021f7
33daaddaad01100004001100010d00000011e5
33daaddaad01100004001200000e0100002e3b
33daaddaad01100004001300010e0100001e29
33daaddaad011000040014000010010000f623
33daaddaad011000040015000110010000c631
33daaddaad0110000400160000030100006ec3
33daaddaad0110000400170001030100005ed1
33daaddaad010b001500180009c1
33daaddaad010c000f00190000edac
33daaddaad010b0015001a006ba7
33daaddaad010b0031001b00e569
"""


def handshake():
    out = []
    for line in HANDSHAKE_HEX.strip().splitlines():
        line = line.strip()
        if line:
            out.append(bytes.fromhex(line))
    return out


def fragment(body, mtu=247):
    """把 ctrl_packet 切成 ATT 载荷：首片头 4B、续片头 2B，容量随 MTU 自适应。"""
    room = max(mtu - 3, 20)
    c1 = min(room - 4, 240)
    c2 = min(room - 2, 242)
    parts = [bytes([1, 1]) + len(body).to_bytes(2, "little") + body[:c1]]
    pos = c1
    while pos < len(body):
        seg = body[pos:pos + c2]
        pos += len(seg)
        parts.append(bytes([1, 3 if pos >= len(body) else 2]) + seg)
    return parts


# ---------------------------------------------------------------- 进 DFU
async def enter_dfu(mac, ctrl_blob, mtu=247):
    c = BleakClient(mac, timeout=15.0)
    await c.connect()
    ch = {x.handle: x for s in c.services for x in s.characteristics}
    total = sum(len(s.characteristics) for s in c.services)
    print(f"[+] 已连接  特征 {total}", flush=True)
    if total < 11:
        print("[!] 特征数 < 11，不在用户模式。若设备已在 GTX20 里，直接用 --skip-enter")
        await c.disconnect()
        return False

    log = []

    def cb(_x, d):
        log.append(bytes(d))

    await c.start_notify(ch[H_RSP], cb)
    await asyncio.sleep(0.3)

    hs = handshake()
    for f in hs:
        try:
            await c.write_gatt_char(ch[H_CMD], f, response=True)
            await asyncio.sleep(0.02)
        except Exception:
            pass
    await asyncio.sleep(0.2)
    print(f"[i] 握手 {len(hs)} 帧", flush=True)

    log.clear()
    t0 = time.perf_counter()
    for fr in fragment(ctrl_blob, mtu):
        await c.write_gatt_char(ch[H_CTRL], fr, response=False)

    ok = False
    while time.perf_counter() - t0 < 6.0:
        if any(b[:6] == ACCEPT_HDR for b in log):
            ok = True
            break
        await asyncio.sleep(0.05)
    print(f"[i] ctrl 应答 {'已接受' if ok else '无'} @{time.perf_counter()-t0:.2f}s", flush=True)
    if not ok:
        print("[X] ctrl 被拒 —— 九成是 fw_ver 太大，用跟上次成功一致的值重打包")
        await c.disconnect()
        return False

    await c.write_gatt_char(ch[H_CTRL], CTRL_REQ, response=False)
    print(f"[i] >>> 0x22 INIT_COMPLETED @{time.perf_counter()-t0:.2f}s（设备应立刻断开）", flush=True)

    t1 = time.perf_counter()
    while c.is_connected and time.perf_counter() - t1 < 12.0:
        await asyncio.sleep(0.05)
    print(f"[i] {'已断开 OK' if not c.is_connected else '未断开'} @{time.perf_counter()-t1:.1f}s", flush=True)
    try:
        await c.disconnect()
    except Exception:
        pass
    return True


# ---------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser(description="SiFli 手表一键刷机（用户模式 -> DFU -> 推流）")
    ap.add_argument("--mac", required=True, help="设备 MAC，GTX20 不广播，必须按地址直连")
    ap.add_argument("--ctrl", help="ctrl_packet 文件；--skip-enter 时不需要")
    ap.add_argument("--blocks", required=True, help="blocks 文件")
    ap.add_argument("--rate", type=float, default=300, help="块/秒，实测 100~300 稳定")
    ap.add_argument("--observe", type=int, default=20, help="推完观察多少秒等重启")
    ap.add_argument("--mtu", type=int, default=247)
    ap.add_argument("--skip-enter", action="store_true", help="设备已在 GTX20 里，直接推")
    a = ap.parse_args()

    if not a.skip_enter:
        if not a.ctrl:
            sys.exit("--ctrl 必填（除非 --skip-enter）")
        if not os.path.isfile(a.ctrl):
            sys.exit(f"找不到 {a.ctrl}")
        ok = asyncio.run(enter_dfu(a.mac, open(a.ctrl, "rb").read(), a.mtu))
        if not ok:
            print("RESULT: ENTER_FAIL")
            return 2
        # 进 DFU 后设备要 2~5s 才回来，且不广播，只能按 MAC 直连。
        # 这里不要插入任何探测连接 —— 会耗掉窗口且弄脏 GATT。
        time.sleep(3.0)

    cmd = [sys.executable, PUSHER,
           "--mac", a.mac,
           "--blocks", os.path.abspath(a.blocks),
           "--rate", str(a.rate),
           "--observe", str(a.observe),
           "--wait", "8", "--timeout", "15",
           "--mtu", str(a.mtu),
           "--no-require-ota"]
    print("[i] 移交推流进程（新连接，避免 GATT 脏状态）", flush=True)
    r = subprocess.run(cmd, cwd=HERE)
    print(f"RESULT: {'DONE' if r.returncode == 0 else 'PUSH_FAIL'}", flush=True)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())

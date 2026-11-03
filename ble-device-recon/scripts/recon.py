#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""蓝牙设备发现与协议测绘（BLE / SPP）。

设计原则：**先只看不动**。
  scan  → 不改任何状态，只听广播
  map   → 只读 GATT，不写
  probe → 才开始发字节，且默认只发无害探针
  spp   → 串口侧同样先被动监听再试探

子命令：
  info                     环境自检（适配器/依赖/平台陷阱）
  scan [--secs N]          广播扫描 + 厂商 ID + 方案指纹
  map  <ADDR>               GATT 全枚举（DIS 优先，读所有可读特征）
  probe <ADDR> --send ...   订阅 notify + 发探测帧 + 记录时序
  spp  --port COM5         串口被动监听 + AT/二进制探针
"""
import argparse
import asyncio
import json
import re
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ============================ 常量表 ============================

SIG_SERVICES = {
    0x1800: "Generic Access", 0x1801: "Generic Attribute",
    0x1802: "Immediate Alert", 0x1803: "Link Loss",
    0x1804: "Tx Power", 0x1805: "Current Time",
    0x180A: "Device Information", 0x180D: "Heart Rate",
    0x180F: "Battery Service", 0x1810: "Blood Pressure",
    0x1812: "HID over GATT", 0x1816: "Cycling Speed and Cadence",
    0x181A: "Environmental Sensing", 0x181C: "User Data",
    0x181E: "Bond Management", 0x1826: "Fitness Machine",
    0x1827: "Mesh Provisioning", 0x1828: "Mesh Proxy",
    0x1848: "Volume Control",
}

SIG_CHARS = {
    0x2A00: "Device Name", 0x2A01: "Appearance",
    0x2A04: "Preferred Conn Params", 0x2A05: "Service Changed",
    0x2A19: "Battery Level", 0x2A23: "System ID",
    0x2A24: "Model Number", 0x2A25: "Serial Number",
    0x2A26: "Firmware Revision", 0x2A27: "Hardware Revision",
    0x2A28: "Software Revision", 0x2A29: "Manufacturer Name",
    0x2A2A: "IEEE Regulatory Cert", 0x2A37: "Heart Rate Measurement",
    0x2A38: "Body Sensor Location", 0x2A39: "Heart Rate Control Point",
    0x2A4A: "HID Information", 0x2A4B: "Report Map",
    0x2A50: "PnP ID", 0x2A6E: "Temperature",
    0x2A9D: "Weight Measurement",
}

COMPANY_IDS = {
    0x0006: "Microsoft", 0x004C: "Apple", 0x0059: "Nordic Semiconductor",
    0x0075: "Samsung", 0x0087: "Garmin", 0x00E0: "Google",
    0x0157: "Anhui Huami (Amazfit)", 0x01DA: "Logitech", 0x027D: "Huawei",
    0x038F: "Xiaomi", 0x0499: "Ruuvi", 0x02E5: "Telink",
    0x05D6: "Realtek", 0x0A12: "CSR", 0x0D53: "Broadcom",
    0x0822: "Xiaomi", 0x045E: "Microsoft", 0x0387: "Huanju",
    0x00D2: "Dialog Semiconductor", 0x02E1: "Bose",
    # 以下是观察值，不是 SIG 官方表的中文译名，用前请交叉验证
    0x1FC5: "SiFli 思澈（实测悦心S1）",
}

# 已知私有服务特征（经验值，命中不代表确定用途）
PRIVATE = {
    0xFF00: "厂商私有 F0", 0xFF01: "私有 01", 0xFF02: "私有 02",
    0xFF03: "私有 03", 0xFFE0: "常用串口透传服务", 0xFFE1: "串口透传数据",
    0xFEE0: "私有透传", 0xFEE1: "私有透传数据",
    0x0A00: "Telink 私有 A00", 0x0A01: "Telink 私有 A01",
    0x0A02: "Telink OTA", 0x0A03: "Telink OTA 数据", 0x0AF0: "Telink/私有 AF0",
    0xAE00: "私有 AE00", 0xAE01: "私有 AE01",
}

BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"

# 方案商指纹：128 位 UUID 里塞 ASCII 是小厂常见做法（尾段小端 = 品牌名）
VENDOR_HINTS = [
    (b"sifli", "SiFli 思澈"), (b"nordic", "Nordic"),
    (b"telink", "Telink"), (b"jieli", "杰理"),
    (b"goodix", "汇顶"), (b"realtek", "瑞昱"),
    (b"bestechnic", "恒玄"), (b"zh-jieli", "杰理"),
]


# ============================ 工具函数 ============================

def norm_addr(a):
    """2FA2CDE2B5F1 / 2F-A2-CD-E2-B5-F1 → 2F:A2:CD:E2:B5:F1"""
    a = a.strip().replace("-", "").replace(":", "").upper()
    if len(a) != 12 or not re.fullmatch(r"[0-9A-F]{12}", a):
        return a
    return ":".join(a[i:i + 2] for i in range(0, 12, 2))


def short_uuid(u):
    """16 位短 UUID 在 128 位串的第 5-8 个字符，不是前 4 个。"""
    s = str(u).lower()
    if s.endswith(BASE_UUID_SUFFIX):
        try:
            return int(s[4:8], 16)
        except ValueError:
            return None
    return None


def name_of(u, table=None):
    v = short_uuid(u)
    if v is None:
        return str(u)
    nm = (table or {}).get(v) or SIG_SERVICES.get(v) or SIG_CHARS.get(v) \
         or PRIVATE.get(v)
    return "0x%04X  (%s)" % (v, nm) if nm else "0x%04X  (厂商自定义)" % v


def decode(b):
    """同时给出 ascii 和 hex —— 只给一种会漏信息。"""
    if b is None:
        return ""
    raw = bytes(b)
    if not raw:
        return "(空)"
    try:
        s = raw.decode("utf-8")
        if s.isprintable() and s.strip():
            return "ascii=%r  hex=%s" % (s, raw.hex(" "))
    except Exception:
        pass
    return "hex=%s" % raw.hex(" ")


def vendor_fingerprint(blob):
    """从任意字节里找方案商指纹（含小端反转）。"""
    low = blob.lower()
    hits = []
    for sig, name in VENDOR_HINTS:
        if sig in low or sig[::-1] in low:
            hits.append(name)
    return hits


def parse_payload(spec):
    """'hex:AA BB' / 'ascii:help\\r\\n' / 'str:\\r\\n'"""
    if ":" not in spec:
        return spec.encode("utf-8")
    kind, _, body = spec.partition(":")
    if kind == "hex":
        return bytes.fromhex(body.replace(" ", "").replace(",", ""))
    if kind in ("ascii", "str"):
        return body.encode("utf-8").decode("unicode_escape").encode("latin-1")
    return spec.encode("utf-8")


def need(mod, hint):
    try:
        return __import__(mod)
    except ImportError:
        sys.exit("[!] 缺少依赖 %s。安装：%s" % (mod, hint))


# ============================ info ============================

def cmd_info(args):
    import platform
    print("=== 环境自检 ===")
    print("  Python :", sys.version.split()[0])
    print("  平台   :", platform.system(), platform.release(), platform.machine())

    ok_bleak = ok_serial = False
    try:
        import bleak
        ok_bleak = True
        print("  bleak  :", getattr(bleak, "__version__", "已安装"))
    except ImportError:
        print("  bleak  : 缺失  →  pip install bleak")
    try:
        import serial
        ok_serial = True
        print("  pyserial:", getattr(serial, "__version__", "已安装"))
    except ImportError:
        print("  pyserial: 缺失  →  pip install pyserial")

    print("\n=== 平台提示 ===")
    if platform.system() == "Windows":
        print("  · Windows 的 BLE 走 WinRT，需要系统蓝牙已开启且未被独占")
        print("  · SPP 必须用**配对后生成的 COM 口**，不能 socket 直连")
        print("  · Windows 有 GATT 缓存：设备改服务后会读到旧值，需在")
        print("    「设置 → 蓝牙 → 删除设备」后重新配对")
        if ok_serial:
            try:
                from serial.tools import list_ports
                ports = list(list_ports.comports())
                print("  · 当前串口: %s" % (", ".join(p.device for p in ports) or "无"))
            except Exception:
                pass
    elif platform.system() == "Linux":
        print("  · 需要 bluez 权限：sudo setcap cap_net_raw+eip $(readlink -f $(which python3))")
        print("  · 或把用户加入 bluetooth 组")
    else:
        print("  · macOS 需在「系统设置 → 隐私与安全性 → 蓝牙」授权终端")

    print("\n=== 一条必须记住的 ===")
    print("  **安卓模拟器的蓝牙是虚拟 HCI（rootcanal），永远搜不到物理设备。**")
    print("  想在模拟器里连真表是不可能的，必须用 PC 的蓝牙适配器直连。")
    if ok_bleak:
        print("\n下一步： recon.py scan --secs 12")
    return 0


# ============================ scan ============================

async def do_scan(args):
    from bleak import BleakScanner
    print("扫描 BLE %.1f 秒..." % args.secs)
    found = await BleakScanner.discover(timeout=args.secs, return_adv=True)
    items = sorted(found.items(), key=lambda kv: -(kv[1][1].rssi or -999))
    if args.filter:
        kw = args.filter.lower()
        items = [kv for kv in items
                 if kw in (kv[0] or "").lower() or kw in (kv[1][0].name or "").lower()]
    print("发现 %d 个设备%s\n" % (len(items), "（已过滤）" if args.filter else ""))

    for addr, (dev, adv) in items:
        print("=" * 64)
        print("%-20s  %s   rssi=%s" % (addr, dev.name or "(无名)", adv.rssi))
        if adv.local_name and adv.local_name != dev.name:
            print("  local_name    : %s" % adv.local_name)
        if adv.manufacturer_data:
            for cid, data in adv.manufacturer_data.items():
                print("  mfg 0x%04X %-26s %s"
                      % (cid, COMPANY_IDS.get(cid, "?"), data.hex(" ")))
                # 广播里前 6 字节常常是设备自身 MAC 的反序 —— 命中说明厂商自定义格式
                mac_be = bytes.fromhex(addr.replace(":", ""))
                if len(data) >= 6 and (bytes(data[:6])[::-1] == mac_be
                                       or bytes(data[:6]) == mac_be):
                    tail = data[6:].hex(" ")
                    print("      └ 前 6B = 自身 MAC(%s)  其后 %d B: %s"
                          % ("小端" if bytes(data[:6])[::-1] == mac_be else "大端",
                             len(data) - 6, tail or "(无)"))
                fp = vendor_fingerprint(data)
                if fp:
                    print("      └ 指纹命中: %s" % ", ".join(fp))
        if adv.service_data:
            for u, data in adv.service_data.items():
                print("  service_data %s : %s" % (u, data.hex(" ")))
        if adv.service_uuids:
            print("  service_uuids:")
            for u in adv.service_uuids:
                tag = name_of(u)
                fp = vendor_fingerprint(str(u).encode())
                print("     %s%s" % (tag, ("   ▸ " + ", ".join(fp)) if fp else ""))
        if adv.tx_power is not None:
            print("  tx_power      : %s" % adv.tx_power)
    return 0


# ============================ map ============================

async def do_map(args):
    from bleak import BleakClient
    addr = norm_addr(args.addr)
    print("连接 %s ..." % addr)
    try:
        async with BleakClient(addr, timeout=args.timeout) as cli:
            print("[ok] 已连接\n")
            try:
                svcs = list(cli.services)
            except TypeError:
                svcs = list(getattr(cli.services, "services", []) or [])
            print("共 %d 个服务\n" % len(svcs))

            result = {"addr": addr, "services": []}
            dis_keys = {0x2A24, 0x2A25, 0x2A26, 0x2A27, 0x2A28, 0x2A29, 0x2A50, 0x2A23}

            print("=" * 72)
            print("【Device Information Service】—— 能读出厂商/型号/固件就是硬证据")
            dis_found = False
            for svc in svcs:
                for ch in svc.characteristics:
                    v = short_uuid(ch.uuid)
                    if v in dis_keys:
                        dis_found = True
                        try:
                            val = await cli.read_gatt_char(ch)
                            print("  %-30s %s" % (name_of(ch.uuid), decode(val)))
                        except Exception as e:
                            print("  %-30s 读失败: %s" % (name_of(ch.uuid), type(e).__name__))
            if not dis_found:
                print("  (未实现 DIS —— 廉价方案常见，无厂商自报信息)")

            print("\n" + "=" * 72)
            print("【全部服务 / 特征】")
            for svc in svcs:
                fp = vendor_fingerprint(str(svc.uuid).encode())
                print("\n[Service] %s%s"
                      % (name_of(svc.uuid), ("   ▸ " + ", ".join(fp)) if fp else ""))
                srec = {"uuid": str(svc.uuid), "name": name_of(svc.uuid),
                        "vendor_hint": fp, "chars": []}
                for ch in svc.characteristics:
                    props = ",".join(ch.properties)
                    print("   [Char] %s" % name_of(ch.uuid))
                    print("          props = %s" % props)
                    crec = {"uuid": str(ch.uuid), "props": props}
                    if args.read and "read" in ch.properties:
                        try:
                            val = await cli.read_gatt_char(ch)
                            print("          value : %s" % decode(val))
                            crec["value_hex"] = bytes(val).hex()
                        except Exception as e:
                            print("          value : <读失败 %s>" % type(e).__name__)
                    for d in ch.descriptors:
                        print("          [Desc] %s" % d.uuid)
                        crec.setdefault("descriptors", []).append(str(d.uuid))
                    srec["chars"].append(crec)
                result["services"].append(srec)

            if args.save:
                with open(args.save, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
                print("\n[ok] GATT 地图已写出 -> %s" % args.save)
            print("\n提示：把这份地图和 App 侧的 UUID 对照，能确认哪些是业务通道。")
            print("      写入特征（props 含 write）就是**控制面**入口。")
    except Exception as e:
        print("[!] 连接失败: %s: %s" % (type(e).__name__, e))
        print("    常见原因：")
        print("      1) 设备已被手机 App 占用 → 先在手机上断开/关 App")
        print("      2) 需要先配对 → 系统设置里配对后重试")
        print("      3) Windows GATT 缓存过期 → 删除设备重新配对")
        return 1
    return 0


# ============================ probe ============================

async def do_probe(args):
    from bleak import BleakClient
    addr = norm_addr(args.addr)
    received = []
    t0 = time.time()

    def make_cb(tag):
        def cb(sender, data):
            b = bytes(data)
            dt = time.time() - t0
            printable = "".join(chr(x) if 32 <= x < 127 else "." for x in b)
            print("  [+%6.3fs] NOTIFY %-14s %-3dB hex=%s |%s|"
                  % (dt, tag, len(b), b.hex(" "), printable))
            received.append({"t": round(dt, 3), "tag": tag, "hex": b.hex()})
        return cb

    print("连接 %s ..." % addr)
    async with BleakClient(addr, timeout=args.timeout) as cli:
        print("[ok] 已连接")

        # 自动订阅所有 notify/indicate 特征（除非显式指定）
        targets = []
        if args.notify:
            for spec in args.notify:
                targets.append((spec, spec[:8]))
        else:
            try:
                svcs = list(cli.services)
            except TypeError:
                svcs = list(getattr(cli.services, "services", []) or [])
            for svc in svcs:
                for ch in svc.characteristics:
                    if "notify" in ch.properties or "indicate" in ch.properties:
                        targets.append((str(ch.uuid), name_of(ch.uuid)[:22]))

        for uuid, tag in targets:
            try:
                await cli.start_notify(uuid, make_cb(tag))
                print("[ok] 订阅 notify: %s" % tag)
            except Exception as e:
                print("[!] 订阅 %s 失败: %s" % (tag, type(e).__name__))

        print("\n--- 被动监听 %.1f 秒（不发任何字节）---" % args.listen)
        await asyncio.sleep(args.listen)
        if not received:
            print("  (无主动推送)")

        if args.send:
            print("\n--- 主动探测 ---")
            write_uuid = args.write
            if not write_uuid:
                try:
                    svcs = list(cli.services)
                except TypeError:
                    svcs = list(getattr(cli.services, "services", []) or [])
                for svc in svcs:
                    for ch in svc.characteristics:
                        if "write" in ch.properties or "write-without-response" in ch.properties:
                            write_uuid = str(ch.uuid)
                            break
                    if write_uuid:
                        break
                if write_uuid:
                    print("  (未指定 --write，自动选第一个可写特征: %s)"
                          % name_of(write_uuid))
            if not write_uuid:
                print("  [!] 没找到可写特征，跳过主动探测")
            else:
                for spec in args.send:
                    payload = parse_payload(spec)
                    before = len(received)
                    try:
                        await cli.write_gatt_char(write_uuid, payload,
                                                  response=args.with_response)
                        print("  -> %-30s %s" % (spec, payload.hex(" ")))
                    except Exception as e:
                        print("  -> %-30s 发送失败: %s" % (spec, type(e).__name__))
                        continue
                    await asyncio.sleep(args.wait)
                    if len(received) == before:
                        print("     （无响应）")
                print("\n--- 收尾监听 %.1f 秒 ---" % args.tail)
                await asyncio.sleep(args.tail)

        for uuid, _ in targets:
            try:
                await cli.stop_notify(uuid)
            except Exception:
                pass

    print("\n共收到 %d 条通知" % len(received))
    if received and args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(received, f, ensure_ascii=False, indent=2)
        print("[ok] 时序已写出 -> %s" % args.save)
    if not received:
        print("\n判读：")
        print("  · BLE 上发数据命令**本来就多半没响应** —— 数据面通常在 SPP/串口。")
        print("  · 先确认这条通道是不是控制面（JSON/短命令）。")
        print("  · 想找数据面：配对后看系统是否新增 COM 口，用 spp 子命令试。")
    return 0


# ============================ spp ============================

def cmd_spp(args):
    serial = need("serial", "pip install pyserial")
    port, baud = args.port, args.baud
    try:
        s = serial.Serial()
        s.port = port
        s.baudrate = baud
        s.timeout = args.timeout
        s.write_timeout = 1.0
        s.open()
    except Exception as e:
        print("[!] 打开 %s 失败: %s" % (port, e))
        print("    可能原因：")
        print("      1) 端口被别的程序占用（串口助手/IDE）")
        print("      2) 手表未建立 SPP 链路 → 先在系统里配对并连接")
        print("      3) 选错 COM 口 → 用 info 子命令列一遍")
        return 1

    print("[ok] 已打开 %s @ %d\n" % (s.name, baud))

    def show(tag, data):
        if not data:
            return
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        print("  %s [%d B] |%s|" % (tag, len(data), printable))
        print("           hex=%s" % data.hex(" "))

    print("--- 1. 被动监听 %.1f 秒（不动）---" % args.listen)
    time.sleep(args.listen)
    if s.in_waiting:
        show("PASSIVE", s.read(s.in_waiting))
    else:
        print("  (无主动数据)")

    if args.at:
        print("\n--- 2. AT 命令试探（HFP/模组型设备常有 AT 口）---")
        for c in [b"AT\r\n", b"ATI\r\n", b"AT+CGMI\r\n", b"AT+CGMM\r\n",
                  b"AT+CGMR\r\n", b"AT+VERSION\r\n", b"AT+NAME\r\n", b"AT+GMR\r\n"]:
            s.reset_input_buffer()
            try:
                s.write(c)
            except Exception as e:
                print("  写失败: %s" % e)
                break
            time.sleep(args.wait)
            data = s.read(s.in_waiting) if s.in_waiting else b""
            label = c.strip().decode()
            if data:
                print("  %-14s -> 有响应" % label)
                show("RESP", data)
            else:
                print("  %-14s -> 无响应" % label)

    if args.probe:
        print("\n--- 3. 二进制探针 ---")
        for name, p in [("0x00*8", b"\x00" * 8), ("0xFF*8", b"\xff" * 8),
                        ("0x55*8", b"\x55" * 8), ("0xAA*8", b"\xaa" * 8)]:
            s.reset_input_buffer()
            s.write(p)
            time.sleep(args.wait)
            data = s.read(s.in_waiting) if s.in_waiting else b""
            print("  %-8s -> %s" % (name, "有响应" if data else "无响应"))
            show("RESP", data)

    s.close()
    print("\n[done]")
    return 0


# ============================ 入口 ============================

def main():
    p = argparse.ArgumentParser(
        description="蓝牙设备发现与协议测绘（BLE/SPP）。原则：先只看不动。")
    sub = p.add_subparsers(dest="cmd", required=True)

    s0 = sub.add_parser("info", help="环境自检（依赖/适配器/平台陷阱）")
    s0.set_defaults(func=cmd_info)

    s1 = sub.add_parser("scan", help="BLE 广播扫描（厂商 ID + 方案指纹）")
    s1.add_argument("--secs", type=float, default=12.0)
    s1.add_argument("--filter", help="只显示地址或名字含该串的设备")
    s1.add_argument("--json", action="store_true")
    s1.set_defaults(func=lambda a: asyncio.run(do_scan(a)))

    s2 = sub.add_parser("map", help="GATT 全枚举（DIS 优先）")
    s2.add_argument("addr", help="MAC，2FA2CDE2B5F1 或 2F:A2:CD:E2:B5:F1")
    s2.add_argument("--read", action="store_true", default=True,
                    help="读取所有可读特征（默认开）")
    s2.add_argument("--no-read", dest="read", action="store_false")
    s2.add_argument("--timeout", type=float, default=20.0)
    s2.add_argument("--save", help="GATT 地图写成 JSON")
    s2.set_defaults(func=lambda a: asyncio.run(do_map(a)))

    s3 = sub.add_parser("probe", help="订阅 notify + 发探测帧 + 记录时序")
    s3.add_argument("addr")
    s3.add_argument("--write", help="写入特征的 UUID（默认自动选第一个可写）")
    s3.add_argument("--notify", action="append", help="指定订阅的 UUID（可重复）")
    s3.add_argument("--send", action="append",
                    help="探测帧，如 'hex:AA BB' / 'ascii:help\\r\\n'（可重复）")
    s3.add_argument("--listen", type=float, default=8.0, help="被动监听秒数")
    s3.add_argument("--wait", type=float, default=1.2, help="每条命令后等待")
    s3.add_argument("--tail", type=float, default=3.0, help="收尾监听秒数")
    s3.add_argument("--with-response", action="store_true")
    s3.add_argument("--timeout", type=float, default=20.0)
    s3.add_argument("--save", help="时序记录写成 JSON")
    s3.set_defaults(func=lambda a: asyncio.run(do_probe(a)))

    s4 = sub.add_parser("spp", help="串口/SPP 探测（被动 + AT + 二进制）")
    s4.add_argument("--port", required=True, help="COM5 / /dev/rfcomm0")
    s4.add_argument("--baud", type=int, default=115200)
    s4.add_argument("--listen", type=float, default=2.0)
    s4.add_argument("--wait", type=float, default=0.7)
    s4.add_argument("--timeout", type=float, default=0.8)
    s4.add_argument("--at", action="store_true", help="发 AT 命令集")
    s4.add_argument("--probe", action="store_true", help="发二进制探针")
    s4.set_defaults(func=cmd_spp)

    args = p.parse_args()
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        print("\n(中断)")
        return 130


if __name__ == "__main__":
    sys.exit(main())

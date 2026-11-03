# 方法论：从"只知 MAC"到"能发对命令"

三个入口，按你手上有的线索选。

---

## 入口 A：手上有配套 App（最快，最有信息量）

```
APK 静态挖 UUID/命令  →  设备侧验证  →  帧格式推定  →  复现
```

### A1. 从 App 里挖出 UUID 与命令

Flutter App 用 `apk-analyzer flutter`；原生 App 用 `dex` + `strings`。

```bash
python <analyzer>/scripts/apk_analyze.py flutter app.apk
python <analyzer>/scripts/apk_analyze.py strings app.apk --keyword uuid --out u.txt
```

重点找三类：

| 类型 | 长什么样 | 价值 |
|------|---------|------|
| 完整 128 位 UUID | `00000af0-0000-1000-8000-00805f9b34fb` | 直接可用 |
| 只写短码 | `0x0AF0` / `AF0` | 补全成 128 位再用 |
| 服务名常量 | `SERVICE_UUID_AF0` | 配合用途 |

**如果 App 里带了协议库的 DWARF**（`libprotocol_c.so` 这类），别读汇编，先读结构体：

```bash
python dwarf_dump.py libprotocol_c.so structs | grep -i -A8 "head"
python dwarf_func.py libprotocol_c.so --name protocol_receive_data
```

帧头和魔数往往就在 `protocol_receive_data` 的 switch 里，比抓包猜快得多。

### A2. 在真设备上验证

```bash
recon.py map <MAC> --save gatt.json
```

对照 App 里的 UUID 列表：
- **都能对上** → 说明协议就是这套，直接进 A3；
- **App 里有、设备上没枚举出来** → 要么是 SPP 通道（GATT 里当然没有），
  要么需要先鉴权/配对后才暴露服务。

### A3. 帧格式推定（不抓包也能推）

按信息量从高到低：

1. **改变一个状态，观察哪些字节变。** 改时间、切表盘、抬腕——广播包和 notify 里
   变化的字节就是对应字段。这是最有效的单一步骤。
2. **找长度字段。** 帧头附近出现"等于剩余长度"的字节，多半就是。
3. **找校验字段。** 最后 1~2 字节改一个输入就变，且不符合规律 → 试 CRC16/累加和。
4. **找魔数/命令码。** 固定位置、固定值的字节 → 命令分发靠它。

### A4. 复现

```bash
recon.py probe <MAC> --write <UUID> --send 'hex:11 02 ...' --save seq.json
```

`seq.json` 带时间戳，成功和失败都能对比。

---

## 入口 B：只有 MAC，没有 App（纯黑盒）

```
scan → map → 认私有服务 → 试探帧 → 观察变化
```

1. `scan`：看名字、厂商 ID、广播里有没有自身 MAC。名字常带型号。
2. `map`：重点看**没有名字的私有服务**（`0xAF0`、`0xFFE0`、`0xAE00`）。
   - 有 `write` 特征 → 控制面候选；
   - 有 `notify` 特征 → 上行数据候选。
3. **先被动听 8 秒。** 很多设备连接后会主动推状态帧，白捡一份样本。
4. 再发最小探针：`\r\n`、`help`、`version`、单字节 `0x00`。
   有 ASCII 回显说明是命令行口（RT-Thread `finsh`、AT 模组），这条路最好走。
5. 全无响应 → **别急着判"数据面在 SPP"**。先抓一次官方 App 的空口日志（附录 A），
   看它有没有在同一个特征值上传大流量。有 → 是你帧格式不对，不是通道不对；
   没有 → 才是 SPP 或另一条加密通道。

**黑盒的止损点**：如果 3 轮探针（约 20 条命令）都没有任何响应，
且配对后也没有 COM 口，那基本是加密通道，离线推不动。别硬耗。

---

## 入口 C：有厂商 PC 工具或串口日志

最省事，直接抓工具与设备之间的串口流量（工具一般也是走 COM 口）。
抓到了就有完整命令集，反推帧格式即可。

---

## 一些通用规律

### UUID 尾段的 ASCII 把戏

小厂喜欢把品牌名塞进 128 位 UUID 的尾部，按小端存：

```
00000000-0000-0000-6473-5f696c666973
                  └─ 小端解: 73 69 66 6c 69 5f 73 64 = "sifli_sd"
```

**看到非标准尾段，先按 ASCII 小端解一遍。** 解得出来就等于拿到了厂商名。

### 私有服务编号的常见规律

| 段 | 常见用途 |
|----|---------|
| `0x0A00`–`0x0A0F` | Telink 生态（OTA 常是 `0x0A02`） |
| `0x0AF0`–`0x0AFF` | 通用透传（很多方案商抄同一套） |
| `0xFFE0`–`0xFFE5` | 经典串口透传（HC-05/06 时代遗留） |
| `0xAE00`–`0xAE0F` | 部分手环方案 |

### 写特征与通知特征的配对

几乎总是成对出现：`0xAF1` 写、`0xAF2` 通知；`0xAF6` 写、`0xAF7` 通知。
**写完之后等 1 秒再判断"无响应"**——设备处理需要时间，立刻判会误判。

### 判断"是不是控制面"

控制面一般有这些特征之一：
- 载荷是 JSON 或可读 ASCII；
- 长度短（< 100B）；
- 一问一答（发一条回一条）。

数据面特征：
- 二进制、有帧头帧尾、有长度/校验字段；
- 设备主动连续推送；
- 分包传输（每包接近 MTU 上限）。

---

## 一条纪律

**先只看不动。**

`scan` 和 `map` 不改变任何设备状态。`probe` 才发字节。
如果在 `map` 阶段就发现设备行为异常（不断重连、电量骤降），
先停下来查是不是被 PC 和手机同时占用，而不是继续发命令。

设备进了异常状态之后，你会分不清"协议猜错了"和"我把设备搞坏了"——
这个混淆会浪费掉后面所有时间。

---

## 附录 A：零 root 抓 BLE 空口数据（HCI snoop）

当设备已经和手机 App 配对工作时，**不需要 PC 上的蓝牙适配器**——
让手机自己记录 HCI 层，事后取日志即可。这是拿到"设备与官方 App 真实协议"
最省事的路子，前提是有 adb。

### A.1 开启（必须走 UI，改不动属性）

```bash
# 这条路无效：Android 12+ 读的是系统属性，SELinux 禁止 adb 写
#   settings put secure bluetooth_hci_log 1
#   setprop persist.bluetooth.btsnooplogmode full   ← 会 Failed to set property
```

正确做法：

```bash
adb shell am start -a android.settings.APPLICATION_DEVELOPMENT_SETTINGS
# 找到「打开蓝牙数据包日志」→ 点进去有三个选项：
#   已停用 / 已启用"已过滤" / 已启用
# 必须选「已启用」(full)，"已过滤"只留包头，看不到载荷
adb shell svc bluetooth disable && sleep 4 && adb shell svc bluetooth enable
```

验证：

```bash
adb shell dumpsys bluetooth_manager | grep mSnoopLogSettingAtEnable
# 必须是 full。若显示 empty，说明设置没生效，重启蓝牙栈再来
```

### A.2 取日志

```bash
adb bugreport ./bugreport.zip
# 解压后找：FS/data/misc/bluetooth/logs/BT_HCI_<日期>_<时间>.cfa.curf
```

**坑**：`dumpsys bluetooth_manager` 里的 `BTSNOOP_LOG_SUMMARY` **只有前 7KB**
（声明 196700 bytes in，实际只输出 9740 个 base64 字符），不能当完整日志用。
`/data/misc/bluetooth/logs/` 直接 `ls` 是 Permission denied，只能走 bugreport。

### A.3 解析（两个致命细节）

文件是标准 btsnoop：`btsnoop\0` + version(4) + datalink(4)，
之后每记录 24 字节头（orig_len, incl_len, flags, drops, timestamp:8）+ 数据。

**细节 1：H4 包类型看 `data[0]`，不是 flags。**
flags 只有 bit0 是方向（0=H2C 1=C2H）。按 `(flags>>1)&3` 判类型会得到
"465KB 的 CMD、零个 ACL"这种荒谬分布。

| data[0] | 类型 |
|---|---|
| 1 | HCI Command |
| 2 | ACL（真正承载 ATT/L2CAP 数据） |
| 3 | SCO |
| 4 | HCI Event |

**细节 2：ACL 里要剥三层才到 ATT。**

```
H4 ACL: [0]=2 | [1:3] handle+flags(LE) | [3:5] dlen(LE) | [5:5+dlen] L2CAP
L2CAP : [0:2] llen(LE) | [2:4] cid(LE)（4=ATT） | [4:4+llen] ATT PDU
ATT   : [0] opcode | [1:3] handle(LE) | [3:] value   (WRITE_REQ 0x12)
        [0] opcode | [1:3] handle(LE) | [3:] value   (WRITE_CMD 0x52)
```

### A.4 判断"这是控制面还是数据面"

- 大量 **Write Command (0x52)** + 单包接近 252/494 字节 → 大文件传输
- **Write Request (0x12)** 有来有回、载荷 5~20 字节 → 命令/配置
- **Notify (0x1b)** 单包 20~255 字节、设备周期性发 → 传感器上报

同一个 handle 上混着三种，说明这是"透传特征值"，
真实语义要靠载荷自带的帧头（cmd/key）区分，不是靠 ATT 层。

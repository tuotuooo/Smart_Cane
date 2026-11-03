---
name: ble-device-recon
description: 蓝牙设备发现与协议测绘技能。当一个物理设备（智能手表/手环/耳机/车机/智能家居）需要通过蓝牙摸清能力、复现协议、判断控制面与数据面时使用。覆盖 BLE 广播扫描与厂商指纹、GATT 服务/特征全枚举、notify 订阅与探测帧收发、SPP/RFCOMM 串口探测，以及**零 root 抓 HCI 空口日志还原私有传输协议与容器格式**（设备已与手机绑定、PC 没有蓝牙适配器时走这条）。触发词包括：蓝牙、BLE、GATT、SPP、RFCOMM、扫描蓝牙设备、看看这个手表/手环能干什么、设备协议、逆向设备、特征值 UUID、写特征、串口透传、COM 口、配对、广播包、厂商 ID、连不上设备、搜索不到设备、抓蓝牙包、HCI 日志、btsnoop、蓝牙数据包日志、表盘格式、固件传输协议、文件传到了设备上、还原设备收到的文件。注意：本技能作用对象是**物理设备**，不是 APK；分析 APK 请用 apk-analyzer。
agent_created: true
---

# BLE Device Recon（设备发现与协议测绘）

## Overview

现有工具链的对象都是 **APK**（`apk-analyzer` 静态、`apk-runtime-dump` 脱壳）。
但很多时候真正的目标是一个**物理设备**：你手上有个手表，想知道它说什么话、能控制什么、
数据从哪条通道出来。

这个技能补的是**无线面**：

| 面 | 技能 | 抓什么 |
|----|------|--------|
| 网络面 | `android-https-capture` | App ↔ 服务器 |
| **无线面** | **本技能** | **App（或 PC）↔ 硬件** |
| 静态 | `apk-analyzer` | APK 里有什么 |

两条独立的取证路线，按处境选：

| 路线 | 前提 | 拿到什么 | 成本 |
|------|------|---------|------|
| **主动探测**（`recon.py`） | PC 有蓝牙适配器，设备可连 | 能力地图、能否被自己控制 | 低，但只能试 |
| **空口抓包**（`snoop_parse.py`） | 有 adb，设备已和手机 App 绑定 | **厂商自己的完整正确流量**，私有协议 + 文件格式 | 低，且不需要 root |

**贯穿全技能的一条原则：先只看不动。**
`scan` 和 `map` 完全不改变设备状态；`probe` 才发字节，且默认只发无害探针。
反向顺序（上来就乱发命令）会把设备搞进异常状态，然后你分不清是"协议不对"还是"被我搞坏了"。

## When to Use

- 拿到一个设备，只知道 MAC，想摸清它有哪些服务、哪些可读可写。
- 从 App 里挖到了 UUID，要在**真设备**上验证这些 UUID 是干什么的。
- 在 BLE 上发了命令没反应，想知道是不是发错通道了。
- 想判断设备用的是哪家芯片方案（广播厂商 ID、服务 UUID 里的 ASCII 尾段）。
- 关心"能不能自己写个程序控制这个设备"，而不是"能不能刷固件"。
  （刷固件的可行性判定在 `apk-reverse-master` 剧本 F。）

## Quick Start

```bash
# 0. 环境自检 —— 先跑这个，能省掉一半的"连不上"
python <skill>/scripts/recon.py info

# 1. 扫描（只读）。--filter 按地址/名字过滤，找目标设备
python <skill>/scripts/recon.py scan --secs 12
python <skill>/scripts/recon.py scan --secs 12 --filter "2F:A2"

# 2. GATT 全枚举（只读）。DIS 优先，能读厂商/型号/固件就是硬证据
python <skill>/scripts/recon.py map 2F:A2:CD:E2:B5:F1 --save gatt.json

# 3. 通道探测：先被动订阅，再发探测帧
python <skill>/scripts/recon.py probe 2F:A2:CD:E2:B5:F1 --listen 8
python <skill>/scripts/recon.py probe 2F:A2:CD:E2:B5:F1 \
       --write 00000af1-0000-1000-8000-00805f9b34fb \
       --send 'ascii:help\r\n' --save seq.json

# 4. 串口/SPP 探测（Windows 上必须先配对，用系统生成的 COM 口）
python <skill>/scripts/recon.py spp --port COM5 --at --probe
```

### 另一条路线：零 root 抓空口日志（设备已与手机绑定）

```bash
# 0. 先在手机开发者选项里把「蓝牙数据包日志」设为「已启用」(full)，重启蓝牙
#    UI 路径不可绕过：settings put / setprop 都会被 SELinux 拒
adb shell dumpsys bluetooth_manager | grep mSnoopLogSettingAtEnable   # 应为 full

# 1. 在 App 里正常操作一次（装表盘 / 传文件 / 配网），然后取日志
adb bugreport ./bugreport.zip
#    解压取 FS/data/misc/bluetooth/logs/BT_HCI_*.cfa.curf

# 2. 诊断：包类型 / ATT 分布 / 按 handle 的流量榜
python <skill>/scripts/snoop_parse.py info hci.bin

# 3. 定界：看该通道的帧头长什么样
python <skill>/scripts/snoop_parse.py frames hci.bin --handle 0x200 --dir h2c --grep d101

# 4. 还原：内置 d1 预设直接切出设备收到的文件
python <skill>/scripts/snoop_parse.py split hci.bin --handle 0x200 --dir h2c -o outdir/
```

## 判据：怎么从输出里读出结论

### 4.1 芯片/方案指纹

三个地方都可能暴露方案商，可靠性递增：

| 位置 | 例子 | 可靠性 |
|------|------|--------|
| 广播 `manufacturer data` 的厂商 ID | `mfg 0x1FC5` | 中（该 ID 对应厂商，但设备可能用别家模块） |
| 服务的 128 位 UUID 尾段 ASCII | `...-6473-5f696c666973` → `sifli_sd` | **高**（厂商自己塞进去的） |
| GATT 读出的 DIS 字符串 | `Manufacturer Name String = ...` | **最高**（设备自报） |

`0xAF0`、`0xFFE0`、`0x0A00` 这类私有服务是常见透传/OTA 通道，但**只是经验值**。

### 4.2 控制面 vs 数据面

**这是最容易误判的一点。**

| 通道 | 典型特征 | 常见内容 |
|------|---------|---------|
| BLE GATT | 短包、有 notify/write | JSON 命令、状态查询、配网 |
| SPP / RFCOMM | 流式、无包边界、Windows 上映射成 COM 口 | 二进制帧、文件传输、固件 |

**但不要用"通道类型"反推"面的归属"。** 实测过一台手表：SPP 存在，但表盘文件
完全走 BLE 透传特征值（1816 个无响应 Write Command）——因为厂商把 BLE 当串口用。

正确判据是**流量形态**（见 4.4）：

| 形态 | 结论 |
|------|------|
| 上千个 `WRITE_CMD`、每包接近 MTU | 文件传输，不管它在 BLE 还是 SPP |
| 一问一答、载荷 5~20B | 命令通道 |
| 周期性固定长度 `NOTIFY` | 状态上报 |

**在 BLE 上发数据命令没有响应，有两种解释，别只信第一种**：
① 数据面在 SPP；② 数据面就在这，但你发的帧格式不对（缺帧头/校验）。
区分方法：先被动 `--listen 8` 看有没有大流量自发过来，再抓一次官方 App 的空口日志（附录 A）。

### 4.3 广播包里的自身 MAC

很多厂商把设备 MAC 放在 manufacturer data 前 6 字节（大端或小端）。
`scan` 会自动比对并标注 `前 6B = 自身 MAC(大端/小端)`。
**命中说明这是厂商自定义格式**，后面那几个字节通常是状态位，可以改状态观察变化反推含义。

### 4.4 数据面确实是 BLE 透传时，怎么拆

如果 `info` 显示某个 handle 上有上千个 `WRITE_CMD`、每包接近 MTU，那数据面就在 BLE 上，
只是被当成"串口"在用。拆法：

1. **看首字节频率**：命令字节低频、数据字节均匀。低频值就是帧头候选。
   （悦心S1 的 1816 个数据帧里 `0xd1` 占绝对多数。）
2. **看小帧的形态**：`d1 05 0a`（3B）、`d1 03 xx xx 00 00`（6B）这类短帧就是控制帧，
   它们直接把协议结构写在你脸上。
3. **试校验和先试"字节累加和 & 0xFFFF"**，再试 CRC16 四种变体。嵌入式方案里累加和
   的出现频率远高于直觉。
4. **容器靠"偏移连续"自证**：`off[i] + size[i] == off[i+1]` 全成立才算解对。

完整方法论（含"表盘不是图片是程序"的判别、按 MTU 照抄复现参数、未解字段怎么标注）
见 `references/datapath_reverse.md`。

## 典型工作流

```
只知 MAC
  │
  ├─ recon info            ← 依赖/适配器/平台陷阱，别跳过
  ├─ recon scan            ← 广播：名字、厂商 ID、服务 UUID、自身 MAC
  │     命中方案指纹 → 可去 apk-analyzer flutter 找配套 App 交叉验证
  │
  ├─ recon map <MAC>       ← GATT 全图：哪些可读、哪些可写、哪些能 notify
  │     └─ 拿到 gatt.json，这就是设备能力地图
  │
  ├─ recon probe <MAC>     ← 先被动听 8 秒，看设备会不会自己推数据
  │     再对可写特征发最小探针（\r\n / help / version / 单字节）
  │     有响应 → 控制面找到了，开始试帧格式
  │     无响应 → 大概率数据面在 SPP，转下一步
  │
  └─ recon spp --port COMx ← 配对后看新增 COM 口，被动听 + AT + 二进制探针
```

**验收标准**：
- `map` 能列出全部服务且可读特征都读出了值（读失败的会单独标注，不算失败）；
- `probe` 至少有一条通道产生响应，或确认全部无响应并给出"数据面在 SPP"的判断；
- `spp` 能收到设备主动数据，或确认端口连通（能写出去）。

## Reference

- `references/methodology.md`：从 App 侧挖 UUID → 设备侧验证 → 帧格式推定的完整方法，
  以及"只有 MAC 没有 App"时的纯黑盒路径。**附录 A** 是零 root 抓 HCI 空口日志的
  开启/取日志/解析两坑（H4 类型看 `data[0]`、ATT 要剥 L2CAP）。
- `references/datapath_reverse.md`：拿到空口日志之后——定位流、定界帧头、用校验和自证、
  拆私有容器、判"资源还是程序"、照抄参数复现。含"8KB 对齐是错的"这类反例。
- `references/pitfalls.md`：蓝牙专有坑库（模拟器虚拟蓝牙、BLE/SPP 混淆、bleak API 变更、
  Windows COM 口与 GATT 缓存、UUID 字节序等）。

## Notes

- 依赖：`pip install bleak pyserial`。`info` 会检查并给出安装命令。
- **安卓模拟器的蓝牙是虚拟 HCI（rootcanal），永远搜不到物理设备。**
  想在模拟器里连真表是不可能的——必须用 PC 的蓝牙适配器。这条踩过，代价是半天。
- 本技能只做**发现与测绘**，不做：
  - APK 分析 → `apk-analyzer`
  - 固件能不能刷 → `apk-reverse-master` 剧本 F
  - HTTPS 抓包 → `android-https-capture`
- **空口抓包的结论边界**：你还原的是"App 发了什么"，**不等于"设备接受别人发同样的东西"**。
  设备可能校验来源/会话密钥/版本号。要说"我能自己推表盘上去"，必须真的发一次。
- **HCI full 模式会持续写盘**（每小时几十 MB），抓完记得回开发者选项关掉，
  否则耗电且日志滚掉关键片段。
- 抓到的日志里含设备 MAC、配对信息、可能的用户数据。落盘/上传前想清楚。
- 探测帧只用**只读/无害**命令。RT-Thread `finsh` 这类调试口上，`help`/`version` 安全，
  `erase`/`reset` 会清配置甚至变砖——发之前先想清楚这条命令最坏会做什么。

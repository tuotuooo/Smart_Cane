---
name: ble-device-recon
description: 蓝牙设备发现与协议测绘技能。当一个物理设备（智能手表/手环/耳机/车机/智能家居）需要通过蓝牙摸清能力、复现协议、判断控制面与数据面时使用。覆盖 BLE 广播扫描与厂商指纹、GATT 服务/特征全枚举、notify 订阅与探测帧收发、SPP/RFCOMM 串口探测、**零 root 抓 HCI 空口日志还原私有传输协议与容器格式**（设备已与手机绑定、PC 没有蓝牙适配器时走这条），以及**厂商 OTA/DFU 通道识别与刷机可行性分层**（含 SiFli `sifli_sd` 全协议、包格式、验签错误码、只做 Init 的低风险探测）。触发词包括：蓝牙、BLE、GATT、SPP、RFCOMM、扫描蓝牙设备、看看这个手表/手环能干什么、设备协议、逆向设备、特征值 UUID、写特征、串口透传、COM 口、配对、广播包、厂商 ID、连不上设备、搜索不到设备、抓蓝牙包、HCI 日志、btsnoop、蓝牙数据包日志、表盘格式、固件传输协议、文件传到了设备上、还原设备收到的文件、固件升级、OTA、DFU、刷固件、能不能刷自制固件、sifli_sd、升级包、改固件镜像、注入代码、代码洞、链接基址、固件分区表、救砖、变砖、JTAG、SWD、sftool、改固件语言、把界面改成中文、固件本地化、改默认语言、改默认设置、改版本号显示、固件里的字符串改了没反应、给手表加自己的应用、改菜单文字、菜单标签、应用表、i18n 表、LVGL 注入、往固件里塞自己的代码。注意：本技能作用对象是**物理设备**，不是 APK；分析 APK 请用 apk-analyzer。
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

三条独立的取证路线，按处境选：

| 路线 | 前提 | 拿到什么 | 成本 |
|------|------|---------|------|
| **主动探测**（`recon.py`） | PC 有蓝牙适配器，设备可连 | 能力地图、能否被自己控制 | 低，但只能试 |
| **空口抓包**（`snoop_parse.py`） | 有 adb，设备已和手机 App 绑定 | **厂商自己的完整正确流量**，私有协议 + 文件格式 | 低，且不需要 root |
| **厂商文档**（`vendor_hunting`） | 能识别出方案商 | 官方 SDK / 打包工具 / 默认密钥 | **最低，且收益最大** |

> 第三条路线常被跳过：逆私有压缩算法和 RSA 签名是做不到的，
> 但厂商的 SDK 与工具源码通常是公开的。**先花 20 分钟搜，再决定要不要逆。**
> 检索方法在 `apk-reverse-master/references/vendor_hunting.md`。

**贯穿全技能的一条原则：先只看不动。**
`scan` 和 `map` 完全不改变设备状态；`probe` 才发字节，且默认只发无害探针。
反向顺序（上来就乱发命令）会把设备搞进异常状态，然后你分不清是"协议不对"还是"被我搞坏了"。

## When to Use

- 拿到一个设备，只知道 MAC，想摸清它有哪些服务、哪些可读可写。
- 从 App 里挖到了 UUID，要在**真设备**上验证这些 UUID 是干什么的。
- 在 BLE 上发了命令没反应，想知道是不是发错通道了。
- 想判断设备用的是哪家芯片方案（广播厂商 ID、服务 UUID 里的 ASCII 尾段）。
- 关心"能不能自己写个程序控制这个设备"，而不是"能不能刷固件"。
- 想知道设备有没有**固件升级通道**、升级包长什么样、验签卡在哪一层。
  （App 侧取证与可行性分层见 `apk-reverse-master` 剧本 F；拿到 UUID 回设备验证用本技能）

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

# 5. 若是固件 OTA：按片号重组出完整镜像（自动校验向量表）
python <skill>/scripts/snoop_ota.py hci.bin --handle 0x200 --dir h2c -o fw.bin
#    前面打印的"片号 0x01/02/03"计数与"消息长度分布"就是协议结构本身
```

### 第三条路线：先找厂商一手资料（最省时间）

```
① 从 APK / 设备拿到厂商锚点（so 名、包名前缀、UUID 尾段 ASCII、DWARF 源码路径）
② 按 docs.<vendor>.com → 官方包仓 → 开源 SDK 仓库 → BBS PDF 的顺序搜
③ 三条交叉验证：常量相同 / 结构相同 / 命名相同
```

检索阶梯、镜像加速（`gh-proxy.com`）、AAR 拆解、字节码取常量、坑库，全部在
`apk-reverse-master/references/vendor_hunting.md`。**遇到私有格式或带签名的升级包，
先读那份，别直接开逆。**

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

### 4.5 有没有 OTA 通道：看服务 UUID，不看 App

`map` 输出里如果出现**第二组私有服务**（不是日常用的那个），先按尾段 ASCII 解一下：

```bash
# UUID 尾段 8+12 位十六进制 → 小端 ASCII
# 00000000-0000-0000-6473-5F696C666973  ->  b'sifli_sd'
```

| 观察到 | 结论 |
|--------|------|
| 尾段解出 `sifli_sd` | **SiFli 芯片原生 OTA 通道**，协议见 `references/sifli_ota.md` |
| 有 `...-0100-` / `...-0200-` 成对特征，一个配置一个数据 | 典型的芯片厂串口透传服务（不止 SiFli 用这个套路） |
| 日常通道的特征数上千包 + 另有独立服务只在上电初期广播 | 后者大概率就是 DFU |

**判"能不能刷自制固件"要分三层，别一步下结论**：App 层（搬运工）→ 传输层（能重放）
→ **设备端验签（唯一真卡点）**。设备端强度只能靠固件/官方错误码回答，
不能靠芯片手册推测。efuse 安全启动保护的是**上电启动链**，与 OTA 验签是两套机制。

### 4.6 拿到固件镜像之后：能在哪儿改

顺序固定，跳过任何一步都会得到错的地址：

```bash
# ① 先定加载基址（不确认基址，后面所有地址都是猜的）
#    向量表 [SP, Reset] 自洽 + 复位桩字节特征（39 48 / blx / bx / fe e7）

# ② 找可注入的洞
python scripts/sifli_cave.py --image fw.bin --min 512

# ③ 找"谁引用了这个字符串/常量"（必须扫字面量池，只扫直接 ADR 会全漏）
python scripts/sifli_xref.py --image fw.bin --off 0x1588EC

# ③' 找"谁调用了这个函数"（代码流引用，不经过字面量池，要用编码解码扫）
python scripts/sifli_bl_xref.py --image fw.bin --base 0x12070000 0x12182998

# ④ 打补丁 / 注入 / 改跳转（写入后用 capstone 复核，编错直接抛异常）
python scripts/sifli_fw_patch.py --image fw.bin -o out.bin \
    --inject 0x120701CC=hook.bin --redirect 0x121C8858=0x120701CD

# ⑤ 重新签名打包
python scripts/sifli_fw_pack.py --keys <sifli02> --image out.bin --fw-ver 1001099 -o pkg
```

**想加自己的 GUI 应用**（菜单里多一项、点进去画自己的界面）：

```bash
python scripts/sifli_apptab.py --image fw.bin --dump        # 35 项应用表，icon=0 的是隐藏槽
python scripts/sifli_i18n.py   --image fw.bin --tables      # 每种语言一张 i18n 表
python scripts/sifli_i18n.py   --image fw.bin --find-str "摇骰子"  # 菜单标签的真正来源
```

编译模板在 `kit/`（`inject_app.c` + `build_app.sh`）。**菜单文字来自 i18n 表、
不来自应用表的 name 字段**，每种语言一张表，只改中文那张切英文就变回原文。

**想改行为（振动、背光、按键响应）**：

先读 `references/sifli_motor_hook.md`。要点：

- **先判双核**：BLE 协议栈在 LCPU，UI/马达在 HCPU。改 HCPU 镜像**不会**改变 BLE 行为。
  判据是被分发的东西的 ID 空间（`0x9xxx` = 跨核 IPC，不是应用协议）。
- **别在消息分发器里调带队列的 API**：`app_motor_control(mode)` 安全；
  `vib_start(mode,cycles)` 内部 `rt_mq_send`，会死锁。
- **汇编注入必须过 `ld -T`**，否则 BL 相对偏移全错、开机即死。见 `kit/motor_hook.ld`。

```bash
B=".../Arm GNU Toolchain .../bin"
"$B/arm-none-eabi-as"  -mcpu=cortex-m33 -mthumb kit/motor_hook.s -o hook.o
"$B/arm-none-eabi-ld"  -T kit/motor_hook.ld hook.o -o hook.elf
"$B/arm-none-eabi-objcopy" -O binary -j .text hook.elf hook.bin   # 40 B
```

三条硬规矩：

1. **判地址用两种独立方法交叉验证**。曾经用"反汇编覆盖率"去否掉正确答案——
   thumb 指令太密，任何对齐位置都能解出一堆指令，覆盖率没有区分度。
2. **动手之前先确认救砖通道**（SWD > UART4+BOOT_MODE）。SiFli 的 secboot
   **没有启动失败计数、没有版本回退**：写进一个不启动的镜像，软件层完全无自救。
3. **刷完没效果时，先怀疑"这行代码跑不到"，而不是"字节写错了"**。
   实测连续四次刷机零变化的案例里，补丁字节**一次都没错过**，
   全是语义错：改的函数不负责显示、改的分支被下层兜底短路、
   改的常量只在读 NVS 失败时生效。**每次刷机前问的是"这段代码真的会执行吗"。**
4. **先备份、先验最小改动、先看电量。** 顺序是：备份原厂镜像 → 刷一次原厂验证链路通
   → 只改一个字符串常量确认"改了/刷了/生效了" → 再上真补丁。
   电量 `<50%` 时不要刷：DFU 界面屏幕常亮，中途掉电会留下"已擦未写"的空白分区。
   **进 DFU 后一口气推完，中间不重连、不探测、不打印多余日志。**

> 一次刷到不开机的完整复盘（DFU 0% 的三个客户端坑 + 为什么可能真擦空 +
> 救砖路径）见 `references/sifli_motor_hook.md` §七、§八。

> 找显示值 / 配置项（改语言、改版本号、改默认设置）有专门的判定流程，
> 见 `references/sifli_firmware_surgery.md` §八 —— 含五个具体坑和六轮刷机对照表。
> 加自己的 GUI 应用（应用表 / i18n 表 / LVGL 地址 / 代码洞）见 §十一。

细节见 `references/sifli_firmware_surgery.md`。

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
  │     └─ 发现有第二组私有服务（...-0100-/...-0200- 成对）→ 按 4.5 辨 OTA 通道
  │           └─ 是 OTA → references/sifli_ota.md（或按同构推其他芯片）
  │                 ⚠ 先只做 Init 探测，无原厂固件备份前不要传 image
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
- `references/sifli_watchface.md`：**SiFli 方案专用**。eZip 图片格式（官方位域 + 厂商扩展块表）、
  官方双向转换工具的命令与坑、`.watch` 容器重打包（原样重打包可逐字节一致）、
  改造流程与未验证项。遇到 SF32LB 手表/开发板的表盘、开机图、动态应用资源，先读这份。
- `references/sifli_ota.md`：**SiFli OTA 专用**（含 2026-11-04 真机抓包 + 2026-11-05 整链路打通）。`sifli_sd` 服务与特征、
  传输帧（`01 | 片号 | 总长LE16`，240+240+74=554）、**实际走 V2 而非 V3**、设备主导的拉取式状态机、
  `ctrl_packet` 三段布局（V3，未在实测中出现）、分块镜像格式、密钥体系、
  **验签错误码 9 是判公钥的钥匙**、风险分层与只做 Init 的最小实验、官方 imgtool/ble_serial 用法。
  **§十一** 是完整的 12 步刷写时序（含两个致命坑：ACL 连接句柄被当成 ATT 句柄、
  GTX20 是另一套 GATT），以及"自己打包镜像成功刷入并跑起来"的实测结果。
- `references/sifli_firmware_surgery.md`：**拿到固件镜像之后怎么动刀**。加载基址怎么判（向量表自洽 +
  复位桩字节，附两条错误方法）、ftab / `sec_config` 布局、OTA 可写的 img_id 风险表、
  救砖通道优先级（SWD > UART4+BOOT_MODE > 无）、代码洞查找与代码注入、`fw_patch` 的复核机制、
  自编代码块的最小链接脚本。
  **§八 是"定位显示值/配置项"的完整方法论**：三种引用的区别（数据/代码/初始化赋值）、
  五个具体坑（链式兜底、NVS 不被清空、显示值≠逻辑值、多语言按块切、无反馈时要先塞探针）、
  判定流程与六轮刷机对照表。改语言、改版本号、改默认设置前必读。
  **动任何非原厂镜像前必读本文件。**
- `references/sifli_motor_hook.md`：**改设备行为（振动/提醒）专用**。双核架构判据
  （LCPU 跑 BLE、HCPU 跑 UI 与马达 —— 改错核等于白干）、马达 API 安全/危险分级
  （`app_motor_control` vs 会死锁的 `vib_start`）、IPC 消息分发表完整布局、
  汇编注入的链接脚本与偏移陷阱、`BLE→振动` 现成的 `0x9009` 通路、`vib_start` 不振的
  三个待验假设。**§七、§八 是一次刷到不开机的事故复盘 + 救砖路径。**
- `references/pitfalls.md`：蓝牙专有坑库（模拟器虚拟蓝牙、BLE/SPP 混淆、bleak API 变更、
  Windows COM 口与 GATT 缓存、UUID 字节序等；§七 是固件注入与双核的七个坑）。

## Notes

- 依赖：`pip install bleak pyserial`。`info` 会检查并给出安装命令。
- **安卓模拟器的蓝牙是虚拟 HCI（rootcanal），永远搜不到物理设备。**
  想在模拟器里连真表是不可能的——必须用 PC 的蓝牙适配器。这条踩过，代价是半天。
- 本技能只做**发现与测绘**，不做：
  - APK 分析 → `apk-analyzer`
  - 固件"能不能刷"的最终判定 → 本技能只到"通道存在 + 验签在哪一层"，
    真正下结论要 `apk-reverse-master` 剧本 F + `references/sifli_ota.md`
  - HTTPS 抓包 → `android-https-capture`
- **厂商一手资料优先于逆向**：私有压缩格式和 RSA 签名逆不出来，
  但官方 SDK / 打包器 / 默认密钥常常是公开的（见 `vendor_hunting.md`）。
- **刷机风险**：验签发生在写 flash 之前，所以"只 Init 不传 image"是低风险探测；
  但 OTA_MANAGER 自身和 ftab/bootloader 一旦刷坏，设备没有恢复通道。
  没有原厂固件备份时不要进入镜像传输阶段。
- **空口抓包的结论边界**：你还原的是"App 发了什么"，**不等于"设备接受别人发同样的东西"**。
  设备可能校验来源/会话密钥/版本号。要说"我能自己推表盘上去"，必须真的发一次。
- **HCI full 模式会持续写盘**（每小时几十 MB），抓完记得回开发者选项关掉，
  否则耗电且日志滚掉关键片段。
- 抓到的日志里含设备 MAC、配对信息、可能的用户数据。落盘/上传前想清楚。
- 探测帧只用**只读/无害**命令。RT-Thread `finsh` 这类调试口上，`help`/`version` 安全，
  `erase`/`reset` 会清配置甚至变砖——发之前先想清楚这条命令最坏会做什么。

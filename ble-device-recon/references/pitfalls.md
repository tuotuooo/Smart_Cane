# 蓝牙坑库

格式统一为 **现象 → 原因 → 正确做法**。
带 `[案例]` 的是真实踩过的。

---

## 一、连接与环境

### 1.1 在安卓模拟器里搜不到蓝牙设备

**现象**：雷电/MuMu/夜神里装 App，让 App 连手表，死活搜不到；或者模拟器"蓝牙"能开但永远 0 设备。

**原因**：**模拟器的蓝牙是虚拟 HCI（rootcanal）**，它只连接模拟器内部，物理上不接宿主机的蓝牙适配器。
不是权限问题，不是驱动问题，也不是设备问题——是架构上就不通。

**正确做法**：
- 想在 PC 上连真设备，用 **PC 的蓝牙适配器 + Python（bleak/pyserial）直连**，不要在模拟器里绕；
- 模拟器只用来做**App 侧**的事（抓包、看 UI、读配置），不碰蓝牙硬件；
- 确认方法：`adb shell dumpsys bluetooth_manager` 里 adapter 状态与真实设备行为对不上。

`[案例]` 悦心S1：先按"让雷电连手表"试了半天，根因是虚拟 HCI。换 PC 直连后 10 秒扫到设备。

---

### 1.2 设备能被手机 App 连，但 PC 连不上

**现象**：`BleakClient` 超时，报 `Device not found` 或连接后立刻断开。

**原因**（按概率排序）：
1. **设备被手机 App 占用** —— BLE 多数外设只允许一个连接；
2. 已被配对过但密钥失效，PC 侧有旧的绑定信息；
3. 设备处于休眠/广播间隙太长，扫描窗口没覆盖到。

**正确做法**：
1. 手机关 App、关蓝牙，或把手表放远；
2. Windows：`设置 → 蓝牙 → 删除该设备` 再重新配对；
3. 扫描时间给足（≥10 秒），必要时先 `scan` 拿到地址再 `map`。

---

### 1.3 Windows 上 SPP 连不上

**现象**：知道设备支持串口，但找不到端口，或者 `serial.Serial("COM5")` 打不开。

**原因**：**Windows 上 SPP 不能 socket 直连，必须先经过系统配对，由系统创建 COM 口。**

**正确做法**：
1. `设置 → 蓝牙和其他设备 → 添加设备`，配对目标设备；
2. 配对后回到「设备和打印机」，右键设备 →「属性 → 服务」，勾选串口服务；
3. 系统会新建一个 COM 口，用 `recon.py info` 或设备管理器确认是哪个；
4. 用那个 COM 口，不要猜。

`[案例]` 悦心S1：`COM5` 就是配对后系统生成的，直接打开即可读写。

---

### 1.4 Windows 读到的 GATT 服务是旧的

**现象**：设备固件明明加了新服务，PC 上枚举出来还是老样子。

**原因**：Windows 有 **GATT 缓存**，按设备地址缓存服务表，服务变更后不自动失效。

**正确做法**：删除设备 → 重新配对。命令行不解决这个问题，只能清配对。

---

### 1.5 Linux 上权限不足

**现象**：`bleak` 报 `org.bluez.Error.NotPermitted` / `AccessDenied`。

**正确做法**：
```bash
sudo setcap cap_net_raw+eip $(readlink -f $(which python3))
# 或把用户加进 bluetooth 组后重新登录
sudo usermod -aG bluetooth $USER
```

---

## 二、API 与数据

### 2.1 `len(cli.services)` 报 TypeError

**现象**：`TypeError: object of type 'BleakGATTServiceCollection' has no len()`

**原因**：bleak 3.x 的 `services` 不是 list，是自定义容器。

**正确做法**：
```python
svcs = list(cli.services)            # 3.x 支持直接迭代
# 兜底
svcs = list(getattr(cli.services, "services", []) or [])
```

### 2.2 16 位 UUID 取错位置

**现象**：从 `00000af0-0000-1000-8000-00805f9b34fb` 里取前 4 位得 `0000`，全变成 `0x0000`。

**原因**：标准 16 位短 UUID 落在**第 5–8 个字符**（0-based: `[4:8]`），不是开头。

**正确做法**：
```python
if s.endswith("-0000-1000-8000-00805f9b34fb"):
    short = int(s[4:8], 16)      # 0x0AF0
```

### 2.3 写了特征但设备"无响应"

**现象**：`write_gatt_char` 返回成功，但没收到任何 notify，于是判断"这通道不对"。

**原因**（三种，按概率）：
1. **帧格式不对** —— 通道是对的，但设备只吃它自己的帧头/校验。最容易被误判成"通道不对"；
2. 等待时间太短，设备还没来得及处理（<300ms 就判无响应）；
3. 写对了但**没订阅 notify**，或订阅的是另一个特征。

**正确做法**：
1. 先 `--listen 8` 纯被动听，确认设备连接后会不会主动推数据；
2. 每条命令后等 1 秒以上再判；
3. 确认写的特征和订阅的特征是**配对的那一对**（如 AF1 写 / AF2 通知，不是 AF1/AF1）；
4. 都不行 → **抓一次官方 App 的空口日志**（见第五节），看它到底往哪个特征值写了什么。
   **这是唯一能一次性终结"通道不对还是格式不对"这个争论的办法。**

`[案例]` 悦心S1：BLE 上发 `help`/`version` 全部无响应，早期误判"数据面在 SPP"。
后来抓 HCI 日志发现——**表盘文件就是走 BLE 的 handle 0x0200 传的**（1816 个
Write Command），只是载荷是 `d1 01/02/03` 私有帧，不是文本命令。
**"没响应"既可能是通道不对，也可能是帧不对；先抓包再下结论。**

### 2.4 设备主动推的数据读成乱码

**现象**：notify 收到的字节按 UTF-8 解码全是 `\ufffd`。

**原因**：那是二进制帧，不是文本。

**正确做法**：**永远同时打 ascii 和 hex**。只打 ascii 会丢掉整个数据面。
`recon.py` 的 `decode()` 就是这么做的。

---

## 三、判读

### 3.1 广播里的厂商 ID 就代表芯片

**现象**：`mfg 0x1FC5` → 断言"芯片是 SiFli"。

**原因**：厂商 ID 是**蓝牙模块/整机厂商**申请的，不等于主控芯片。
代工厂可以用同一颗芯片、不同 ID，也可以同一 ID、不同芯片。

**正确做法**：厂商 ID 只作线索。芯片要靠**多重证据**：
- 服务 UUID 尾段 ASCII（厂商自己塞的，最可信）；
- GATT 读出 DIS 的 Manufacturer/Model 字符串；
- 配套 App 内有该芯片的专用源码路径（如 `sifli_dial/app_custom_dial_make.c`）；
- 拆机看丝印。

### 3.2 私有服务编号能直接看出用途

**现象**：看到 `0x0AF0` 就认定是"Telink 透传"。

**原因**：这些编号是**社区经验值**，不同厂商会重叠。`0x0AF0` 在多家方案里都出现，
但内容格式各不相同。

**正确做法**：编号只用来**排序试探优先级**，实际用途必须靠发探针验证。

### 3.3 把"能连上"当成"能控制"

**现象**：`map` 成功列出服务，就认为已经打通了。

**正确做法**：能连上只是拿到了**能力地图**。真正的"打通"要满足：
有可写特征 + 发出命令 + 收到可解释的响应（或观察到设备行为改变）。

---

## 四、操作纪律

### 4.1 上来就发一堆命令

**现象**：设备不断重连、电量骤降、甚至需要重启才能恢复。

**原因**：不少设备把未知命令当异常处理，连发会触发保护或状态机死锁。

**正确做法**：
1. `scan` / `map` 阶段**一个字节都不发**；
2. 探测阶段一次一条，每条之间等 1 秒以上；
3. 只用只读命令（`help` / `version` / 状态查询）；
4. **绝对不要**碰 `erase` / `reset` / `format` / `dfu` 这类命令——
   在 RT-Thread `finsh` 这类调试口上，一条 `erase` 就能清掉配置甚至变砖。

### 4.2 设备状态被自己搞乱后再去猜协议

**现象**：发了一堆命令之后设备行为变得莫名其妙，然后开始怀疑协议解析错了。

**正确做法**：发现设备行为异常，**先复位设备**（关机重开 / 拔电），恢复到已知状态，
再重新按"先只看不动"的顺序来。不要在污染状态下继续推。

---

## 五、空口抓包（HCI snoop）

### 5.1 想用 `settings put` / `setprop` 开日志 —— 全部被拦

**现象**：

```bash
adb shell settings put secure bluetooth_hci_log 1          # 执行成功但无效
adb shell setprop persist.bluetooth.btsnooplogmode full    # Failed to set property
```

**原因**：Android 12+ 的 snoop 模式读的是系统属性，该属性由 SELinux 保护，
adb shell（uid 2000）没有权限写。`settings put` 写的是另一套没人读的键。

**正确做法**：走开发者选项 UI，选「已启用」（**full**，不是"已过滤"），
然后 `svc bluetooth disable/enable`。验证 `dumpsys bluetooth_manager |
grep mSnoopLogSettingAtEnable` 必须是 `full`。详见 `methodology.md` 附录 A。

### 5.2 用 `dumpsys` 里的 BTSNOOP_LOG_SUMMARY 当完整日志

**现象**：summary 声称 `196700 bytes in`，但 base64 解出来只有 7KB，正好缺了关键片段。

**原因**：`dumpsys` 的输出有长度上限，二进制被截断（且截断位置在记录中间）。

**正确做法**：走 `adb bugreport`，从 `FS/data/misc/bluetooth/logs/BT_HCI_*.cfa.curf`
取原文件。`/data/misc/bluetooth/logs/` 直接 `ls` 是 Permission denied，只有 bugreport 能取。

### 5.3 解析出来"几百 KB 的 CMD、零个 ACL"

**现象**：统计结果荒谬，明显不对，但解析器不报错。

**原因**：H4 包类型被当成 `(flags >> 1) & 3` 去判。**flags 只有 bit0 是方向**
（0=手机→设备，1=设备→手机），类型在 `data[0]`。

**正确做法**：`data[0]` → 1=CMD 2=ACL 3=SCO 4=EVT。
`snoop_parse.py info` 会在 CMD 数量超过 ACL 时直接告警。

### 5.4 只会剥到 L2CAP 就去读 ATT

**现象**：handle 和 opcode 全是乱的。

**原因**：ACL 里套了三层，少剥一层就全错。

```
ACL   : [0]=2 | [1:3]=handle+flags | [3:5]=dlen | [5:]=L2CAP
L2CAP : [0:2]=llen | [2:4]=cid（**4=ATT**） | [4:]=ATT PDU
ATT   : [0]=opcode | [1:3]=handle | [3:]=value
```

### 5.5 抓到的日志里没有目标操作

**原因**（按概率）：① 日志模式是"已过滤"，只留包头；② 抓完没重新取 bugreport，
读的是旧文件；③ 日志滚动覆盖（full 模式每小时几十 MB）。

**正确做法**：抓之前先 `svc bluetooth disable/enable` 清空；
操作完**立刻**取 bugreport；记下 `BT_HCI_*.cfa.curf` 的时间戳与操作时间对得上。
抓完把日志模式关回「已停用」——不然耗电且会覆盖。

---

## 六、与其他技能的边界

| 想做的事 | 该用哪个 |
|---------|---------|
| 从 APK 里找 UUID / 命令 / 协议结构 | `apk-analyzer`（Flutter 用 `flutter` 子命令） |
| 判断固件能不能刷 | `apk-reverse-master` 剧本 F |
| 抓 App 与服务器的 HTTPS | `android-https-capture` |
| 设备发现与协议测绘 | **本技能** |

**别在本技能里做 APK 分析。** 对象不同，方法完全不同——把两者混在一起，
最后两份结论都会失真。

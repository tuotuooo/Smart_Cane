# SiFli OTA（`sifli_sd` 通道）：协议全解与刷机可行性分层

> 对象：SiFli SF32LB 系列（SF32LB52x / 55x / 58x）。
> 前置：`methodology.md`（GATT 枚举）、`sifli_watchface.md`（同一台设备的应用层协议）。
> 一手资料来源与检索路径见 `apk-reverse-master/references/vendor_hunting.md`。

---

## 一、先分清两条完全独立的通道

同一台设备上跑着**两套互不相关的协议**，混用是最常见的失败原因：

| 通道 | 服务 UUID | 归属 | 跑什么 |
|------|-----------|------|--------|
| **应用层** | `0000af00-...`（写 `0x00f` / notify `0x011`） | 方案商 App（iDO / VeryFit 等） | 表盘、闹钟、设置、`33 da ad da ad` 管理帧 |
| **芯片原生** | `00000000-0000-0000-6473-5F696C666973` | **SiFli 芯片固件** | **OTA / DFU** |

UUID 尾段 `6473 5F696C666973` 按小端 ASCII 解 = **`sifli_sd`**。
这是判断"设备是 SiFli 方案"的**硬证据**（比广播厂商 ID 可靠）。

```
TARGET_SERVICE_UUID         = 00000000-0000-0000-6473-5F696C666973
CHARACTERISTIC_UUID_CFG     = 00000000-0000-0100-6473-5f696c666973   # 配置/协商
CHARACTERISTIC_UUID_DATA    = 00000000-0000-0200-6473-5f696c666973   # 数据 + notify
```

> 写数据走 `...-0200-`，且属性是 **write-without-response + notify**（同一特征双向）。
> `...-0100-` 是配置通道。两者都要先订阅 notify 再写。

---

## 二、传输帧

### 2.1 字段定义（来自 App 字节码 `SFSerialTransportPack.marshal()`）

```
[cateID : 1B] [flag : 1B] [serialDataLength : 2B] [payload...]
                            ↑ 长度字段的存在条件见 2.3（待定）
payload = SFOtaRequestPacket:
[cmdType : 2B] [length : 2B] [data...]
```

### 2.2 官方实现里硬编码的三条串（照抄即可）

`tools/ble_serial.py`（官方 Python 客户端）里只出现这三条，做了原样回放：

```
协商 packet_size :  01 00 03 00 00 01 02
协商 packet_size :  01 00 03 00 02 80 00
请求传入 ctrl 包 :  01 00 05 00 06 FF 01 00 00
```

### 2.3 ⚠️ 待定：长度字段与 payload 起点不自洽（不要硬推）

按 2.1 的定义（`flag ∈ {0,1}` 时带 2B 长度）解读第一条：

```
01 | 00 | 03 00 (len=3) | 00 01 02        ← 只剩 3 字节 payload，与 cmdType(2)+length(2) 冲突
```

而**设备下行**包的解析实测是 `cateid=data[0]; is_frag=data[1]; msg=data[2]` ——
即 payload 从第 3 字节开始，**没有长度字段**。

两种可能：① 长度字段只在某方向/某 flag 位下存在；② `flag` 是位域不是枚举。
**在没有更多样本前不要臆造通用解析器**，按下列优先级处理：

1. **首选**：原样回放官方三条握手串（已验证可用）；
2. 需要新命令时，从 App 字节码抓 `marshal()` 的入参，按样本构造；
3. 所有新帧先只写 CFG 特征试，观察 notify 有无响应，别直接进 OTA 流程。

### 2.4 下行通知的已知语义

`notify` 数据 `data[2]` 是 msg 类型（`cateID == 0x01` 时）：

| msg | 内容 | 用途 |
|-----|------|------|
| `0x01` | `img_id, img_state, img_curr_ver[20]` | 查询镜像信息（拿设备当前版本） |
| `0x03` | `status, len` | **设备请求下一个包**，`status==0` 才继续 |
| `0x07` | `status` | 允许开始发数据 |
| `0x09` | `status` | 结束 / 安装结果 |

> 这套是**设备主导的拉取式**传输：App 不发就等着，设备说"给我第 N 包"才发。
> 与表盘那个"推流 + 背压"模型完全不同，别套用。

---

## 三、一次 OTA 的状态机

```
① 连接 → 订阅 DATA 的 notify
② 写 CFG/DATA 协商包大小      （01 00 03 00 00 01 02 / ...80 00）
③ Init：把 ctrl_packet.bin 送进去   （01 00 05 00 06 FF 01 00 00 → 后跟内容）
④ 设备验签 + 解析镜像清单
      ├─ 失败 → msg 0x09 + 错误码（见 §五），流程终止、设备不写 flash
      └─ 成功 → msg 0x03/0x07 请求数据
⑤ 按设备请求逐包送 enc_<img>.bin
⑥ 全部送完 → 设备校验每个镜像 → 重启进 OTA manager → 安装 → 跳新固件
```

**关键安全性质**：**验签发生在 ③~④，早于任何 flash 写入。**
所以"只做 Init 不送 image"是**极低风险**的探测动作 —— 这是本技能里唯一推荐
在无备份情况下做的实验。

---

## 四、包格式（`tools/secureboot/imgtoolv37.py::dfu_generation`）

### 4.1 产物

```
ctrl_packet.bin     控制包（镜像清单 + 签名）
enc_<name>.bin      加密镜像（flag & 1）
com_<name>.bin      仅压缩
out_<name>.bin      不加密不压缩
```

### 4.2 `ctrl_packet.bin`（三段）

```
[0   : 32 ]  SHA256(control_packet)          明文摘要
[32  : -256] AES-CTR(control_packet)         用 s01.bin 加密
[-256: end ] RSA-2048/PKCS1v15 签名          对上面 32B 摘要签名
```

App 端 `CtrlFileValidator` 的 `encLen = len - 32 - 256` 与此吻合。
实测 313B 明文 → **601B** 文件。

### 4.3 `control_packet` 明文

```
dfu_id(1) hw_ver(4 Le) sdk_ver(4 Le) fw_ver(4 Le)
session_key(32)
img_header_len(2 Le)
img_header:
    bksize(2) img_count(1)
    × img_count: image_sig(256) image_len(4) img_flag(2) img_id(1)
```

> **`img_count` 在偏移 49，不在 13**（易错：前面的 session_key 有 32 字节）。

### 4.4 `enc_*.bin`（无文件头）

```
原镜像 → 补 0 到 16B 对齐 → 按 bksize(默认 512) 切块
每块:  SHA256(原块) 32B | 块偏移 Le32 4B | AES-CTR(原块) bksize B
```

自证：`ceil(65536/512) = 128` 块 × `(512+36) = 70144 B`，与产物逐字节一致。
签名对象：加密镜像签**密文流**的 SHA256，未加密镜像签**明文**的 SHA256。

### 4.5 加密参数

```python
key   = open("s01.bin","rb").read()                  # 32B → AES-256
ctr   = Counter.new(32, prefix=open("sig_hash.bin","rb").read(8) + b'\x00'*4,
                    initial_value=0)
AES.new(key, AES.MODE_CTR, counter=ctr)
```

---

## 五、密钥体系（决定"能不能刷自编固件"）

密钥不在 App 里，在**官方开源仓库**：
`OpenSiFli/SiFli-SDK` → `tools/secureboot/sifli02/`

| 文件 | 大小 | 用途 |
|------|------|------|
| `s01.bin` | 32 B | 升级包 AES-256 密钥 |
| `sig_hash.bin` | 32 B | 前 8B 作 CTR 前缀 |
| `sig_pri.pem` | 1674 B | RSA-2048 **签名私钥**（PKCS#1） |
| `sig_pub.pem` / `.der` | 450 / 294 B | 对应公钥 |
| `uid.bin` | 16 B | 芯片 UID 模板 |

**厂商是否换了这套？** 用 `vendor_hunting.md` §四 的三条判据核对：
App 内嵌 AES key 与 `s01.bin` **逐字节相同**、IV 前 8B 与 `sig_hash.bin` 相同、
长度公式相同 → **未替换，用的是 SDK 默认套件**。

由此推论（**推论，不是结论**）：设备端烧的公钥**极可能**也是默认 `sig_pub`。
这一条必须实测才能升级为结论，最小实验见 §七。

---

## 六、错误码（设备端）

| code | 宏 | 含义 |
|------|-----|------|
| 6 | `SDK_VER_ERROR` | 包的 sdk_ver 填错 |
| 7 | `FW_VER_ERROR` | 包的 fw_ver 填错 |
| 8 | `FW_INVALID` | 安装失败 / 单镜像校验失败 |
| **9** | **`CTRL_PACKET_INVALID`** | **ctrl 包签名验证失败** ← 判公钥的钥匙 |
| 10 | `DOWNLOAD_ONGOING` | 上次 DFU 未结束，需 force |
| 15 | `PACKET_VERIFY_ERROR` | 数据包校验错 |
| 19 | `IMAGE_VERIFY_FAIL` | 镜像校验失败（会重试） |

App 侧另有 `520 CTRL_DECRYPT_FAIL` / `480 IMAGE_SIZE` / `490 ID_MISMATCH` / `500 ID_REPEAT`
—— 都是**结构校验**，说明 **App 不验签，签名只在设备端**。

> 这就是"App 里搜不到验签代码"的原因，不是漏了。

---

## 七、风险分层与最小实验

| 操作 | 风险 | 依据 |
|------|------|------|
| 只发 Init（ctrl 包），不送 image | **极低** | 验签早于写 flash；失败即返回错误码 |
| OTA 刷 HCPU 代码（未开 overwrite） | 中 | 先写升级区，原区不动；失败可回原固件 |
| OTA 刷 OTA_MANAGER 自身 | **高** | 刷坏 = 失去恢复通道 |
| 刷 ftab / bootloader | 极高 | 直接变砖 |

**推荐的最小实验**（一次性回答"公钥是否默认"）：

```
用默认 sig_pri 生成一个 ctrl_packet.bin（任意 64KB 假镜像）
→ 只做 Init
→ 返回 9   = 公钥不是默认的，此路封死
→ 返回 0   = 公钥是默认的，整条复刻路线成立
→ 其他码    = 先解决版本号（6/7）再看
```

**做这一步之前**：确认有办法恢复。没有原厂固件备份时，**不要**进入 image 传输阶段。
获取备份的三条路（成本递增）：① App 点一次官方升级 + HCI 抓包（零 root，推荐）；
② root 读 App 数据库里的 `otaFileUrl` 下载；③ 官方固件包从论坛/BBS 找。

---

## 八、官方工具速查

```bash
# ① 生成 OTA 包 —— 必须在 sifli02/ 目录下跑（工具依赖 CWD）
cd tools/secureboot/sifli02
python ../imgtoolv37.py gen_dfu \
    --img_para main 16 0 \        # name flag img_id（可多组）
    --key=s01 --sigkey=sig \
    --dfu_id=1 --hw_ver=51 --sdk_ver=7001 --fw_ver=1001001 --com_type=0

# ② 走 BLE 推包 —— 官方 Python 客户端，需 bleak
python ble_serial.py            # 只连 SIFLI-BLE-DEV 名字，实际设备要改过滤
```

参数含义（手册与源码一致）：

| 参数 | 值域 |
|------|------|
| `flag` | `1`=加密存储，`16`=压缩（压缩需 eZIP 引擎，PC 侧工具链不全 → 先用 0） |
| `img_id` | `0`=HCPU 代码 `1`=LCPU `3`=资源 `4`=字体 `6`=OTA_MANAGER `7`=TINY_FONT |
| `dfu_id` | `0`=纯代码 `1`=代码+资源 `2`=OTA manager |
| `hw_ver` | 固定 51（未启用） |
| `sdk_ver` / `fw_ver` | **必须与设备当前值对齐**，否则 6/7 |

> `ble_serial.py` 依赖老版 bleak（`from bleak import discover` / `get_services`），
> 新版 API 已删。要么锁旧版，要么按 `ble-device-recon` 的 recon.py 重写连接部分。

---

## 九、未确认项（写报告必须带上）

| 项 | 状态 |
|----|------|
| 设备端公钥是否默认 `sig_pub` | ❓ 需 §七 最小实验，或逆固件静态确认 |
| efuse 安全启动是否已烧 | ❓ 影响"刷进去能否启动"，与"能否过 OTA 验签"是**两件事** |
| 设备当前 sdk_ver / fw_ver 实际值 | ❓ 可从 msg `0x01` 读，或从 `0x15` 能力位图推 |
| 自编固件的 flash 布局是否匹配 | ❓ 需原厂 ftab 对照 |
| §二 长度字段的确切规则 | ✅ 已由 §十 实测澄清（`01 | 片号 | 总长LE16`） |

> ⚠️ 早期结论"efuse 安全启动 ⇒ 刷固件封死"**已作废**：
> efuse 保护的是**上电启动链**，OTA 包验签是**另一套机制**。两者独立，不能互推。

---

## 十、实测抓包结果（2026-11-04，官方 1.01.03 → 1.01.06）

> 这一节是**真机实测**，优先级高于本文前面的文档推断。

### 10.1 关键修正：实际走 DFU **V2**，不是 V3

logcat 实录（tag `sifli-DFU`）：

```
D/sifli-DFU  onCreate()
I/sifli-DFU  startActionDFUNorExt
I/sifli-DFU  start with 1.1.34
D/sifli-DFU  handleActionDFUNorV2      ← V2
I/sifli-DFU  connecting to <MAC>
D/sifli-DFU  onConnectionStateChange status 0, new state 2
I/sifli-DFU  update link / update parameter
I/sifli-DFU  Refreshing result: true
```

→ **§四 的 `ctrl_packet` 三段式是 V3 格式**。厂商实际用 V2，控制信息走
`33 DA AD DA AD` 管理帧的 CMD 子命令，**没有 601 字节的 ctrl 包**。
做可行性判断时以本节为准。

### 10.2 数据面落在哪：~~应用层特征~~ → **就是 `sifli_sd` 的 `-0200-`**

> ⚠️ **本节原结论已作废（2026-11-05 修正）**，保留原文只为记录误判过程。
>
> 原文说「实测数据面：`handle 0x0200`（就是日常表盘/闹钟那个特征）」，**这个数字是解析器的 bug**：
> `snoop_parse.iter_att()` 返回的第 3 个字段是 **ACL 连接句柄 + PB 标志位**
> （`0x0200` / `0x0202` = 同一连接的 PB=0 / PB=1 两种分片标志），**不是 ATT 句柄**。
> 真实 ATT 句柄必须从 PDU 里取：`op ∈ {0x12,0x52,0x1b,0x1d}` → `unpack('<H', pdu[1:3])`。
> 修正后重新统计，官方 OTA 全程只用两个 ATT 句柄，且它们就是 `sifli_sd` 服务下的
> `-0100-`（控制）与 `-0200-`（数据面 + 命令 + 应答）。
>
> 所以「OTA 不一定在 `sifli_sd` 上」这句话本身没错（要按流量形态判），
> 但**这台设备的答案是在 `sifli_sd` 上**。完整可复现流程见 §十一。

保留的可复用判据：

| 形态 | 结论 |
|---|---|
| 十几分钟窗口内某特征上数千个 `WRITE_CMD`，每帧接近 MTU | 固件传输，不管它在哪个 UUID 上 |
| 一问一答、5~20B | 命令通道 |
| 周期性定长 notify | 状态上报 |

**但抓包里的 handle 数字不能直接搬进 bleak**：不同连接（手机 / PC、有无额外属性）
编号会整体漂移。一切以 **UUID 后缀**为准（`-0100-6473-5f696c666973` / `-0200-…`）。

### 10.3 帧格式（已闭合）

```
[cateID : 1B = 0x01] [片号 : 1B] [总长 : 2B LE] [数据]
```

| 片号 | 含义 | 数据 | 帧长 |
|------|------|------|------|
| `01` | 首片（携带总长） | 240 B | 244 B |
| `02` | 中片 | 240 B | 244 B |
| `03` | 尾片 | 74 B | 78 B |

**一条消息 = 240+240+74 = 554 B**，`总长` 字段写 `558`（= 554 + 4 帧头）。

自证：`0x022E = 558`，且 `554 + 4 = 558` ✓；
6066 条 × 554 = 3,360,416，与 h2c 总量减帧头开销完全吻合 ✓。

> 这也解释了 §2.3 的"长度字段不自洽"：**它写的是整条消息的长度，不是本帧的**。

### 10.4 还原出的镜像

| 项 | 值 |
|---|---|
| 大小 | 3,360,416 B |
| 版本串 | `V1.01.06` ×4 |
| 芯片串 | `SF32LB551` |
| 文件头 | Cortex-M 向量表（`SP=0x02590020`，reset `0xC01219C5` 奇数=Thumb） |
| 熵 / 零占比 | 7.12 / 8.2% → **明文**（密文应 ≈7.99） |

**固件里直接含 DFU 接收端**（不必另找 OTA manager 镜像）：

```
Ctrl packet parser failed!        ← 对应错误码 9
dfu_packet_download fail!
DFU_FLASH_MSG_TYPE_VERIFY
ble_dfu_flash_write: try to recv a mail
dfu_reg.set_dfu_reg.reboot
check_patch_install HCPU
```

**公钥不在应用镜像里**：全量搜索 `sig_pub.der` 原文、DER 头 `30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01`、
256 字节模数 → **0 命中**。公钥应在 **OTA manager 镜像或 efuse**。

### 10.5 抓包操作要点

```bash
# 1. 开发者选项 UI 开 full（settings put 无效）
adb shell dumpsys bluetooth_manager | grep mSnoopLogSettingAtEnable   # 应为 full

# 2. 升级完成后【立刻】抓 —— 环形日志会被后续流量覆盖
adb bugreport bug.zip
#    zip 内：FS/data/misc/bluetooth/logs/BT_HCI_*.cfa.curf

# 3. 定位 + 导出
python snoop_parse.py info hci.bin
python snoop_parse.py dump hci.bin --handle 0x200 --dir h2c -o stream.bin

# 4. 按 .lens 切帧 → 按 01/02/03 片号重组 → 拼成镜像
```

⚠️ **别用 `dumpsys bluetooth_manager` 的 `BTSNOOP_LOG_SUMMARY` 判断日志量**：
实测它恒显示 ~262 KB，而真实文件 7.1 MB。必须走 bugreport 取。

⚠️ **合成触摸事件可能点不动 Flutter 的某些行**（`input tap` 对"设备升级"无效，
而其他行正常）。这类入口让用户手动点，别在 UI 自动化上耗时间。

---

## 十一、整链路打通：从握手到装完（2026-11-05 实测）

> 这一节是**用自己写的客户端把固件真的刷进设备并跑起来**的完整记录，
> 优先级高于前面所有"可行性判断"。脚本见 `scripts/sifli_ota_push.py` +
> `scripts/sifli_fw_pack.py`，镜像侧手术见 `sifli_firmware_surgery.md`。

### 11.1 最大的坑：把 ACL 连接句柄当成 ATT 句柄

盘点本项目最耗时的一段，根因只有一个：

```python
# snoop_parse.iter_att() 返回的 h 字段
h = 0x0200   # ← 这是 ACL 连接句柄(0x0200) | PB 标志(0) ，不是 ATT 句柄
```

于是"数据走 0x0200"被理解成"数据走某个句柄号为 0x0200 的特征"，进而写死了一堆
错误句柄号去发数据，每次都被设备静默忽略，然后被误判成"设备拒绝了这个包"。

**正确解法：按 UUID 后缀解析通道，永远不写死句柄号。**

```python
SUF_CTRL = "-0100-6473-5f696c666973"
SUF_DATA = "-0200-6473-5f696c666973"
```

### 11.2 两套 GATT 表（这是第二个坑）

进 OTA manager 后设备改名 `GTX20`，**GATT 表整个换掉**：

```
user bin（11 个特征值）                        GTX20 / OTA manager（只剩 2 个）
─────────────────────────────────────         ─────────────────────────────────────
SVC 00000af0-...                              SVC 00000000-0000-0000-6473-5f696c666973
  CH 0x000F 0af6   写控制帧（33 帧）            CH 0x000F ...-0100-...  控制（ctrl_packet）
  CH 0x0011 0af7   notify 应答                  CH 0x0011 ...-0200-...  数据面+命令+应答
  CH 0x0014 0af1   图像数据
  CH 0x0016 0af2   notify
SVC ...6473-5f696c666973（sifli DFU）
  CH 0x001A ...-0100-...
  CH 0x001C ...-0200-...
```

所以"进 OTA 后只有 7 个句柄、找不到 0x0014 / 0x001C"**不是 GATT 发现被截断**，
而是那两个特征值在该模式下不存在。反复重连去"凑齐句柄"是纯浪费。

### 11.3 完整时序（12 步，逐帧核对过）

```
[user bin，11 个特征值]
 1. 26 帧 33 管理帧握手              → 0af6 / -0100-（Write Request）
      cmd: 0x001A 0x0015 0x0052 0x0005 0x0004×18 0x000F 0x0015 0x0031
 2. 设备发 cmd=0x0031（读表盘 wf_w202，分 2 帧，含 33 00 00 续片）
      → 主机必须回【空 payload 的 0x0031】ACK，否则设备卡住不发就绪信号
 3. 主机发 ctrl_packet 605B（3 片）   → -0200-
 4. 设备经 notify 发 `07 40 19 00 00 …`（就绪信号）
 5. 主机用 Write Request 回写 `07 40 19 …` → 0af6 / -0100-
 6. 主机发 CTRL_REQ `01 00 05 00 22 00 01 00 00` → -0200-
 7. 设备 ~4s 后断开，BLE 名变 GTX20

[GTX20，2 个特征值]
 8. CTRL_REQ → -0200-，设备回 `01 00 08 00 07 00 04 00 00 00 01 00`（START 成功）
      ⚠️ 判应答要用 b[:6] 比 6 字节前缀。曾写成 b[:5] 比 6 字节常量 → 恒假 →
        明明收到了却判"无应答"，白折腾两轮。
 9. 6065 块 × 3 分片 = 18195 写 → -0200-（Write Without Response，300 块/秒，60.7s）
10. IMG_END1 `01 00 06 00 08 00 02 00 00 00` → 应答 cmd=0x000B result=0
11. IMG_END2 `01 00 05 00 0c 00 01 00 00`    → 应答 cmd=0x000D result=0
12. ~8~12s 后设备断开 → 安装 → 1.5s 后以原设备名回来，11 个特征值完整
```

关键点：**数据面和控制命令共用同一根 `-0200-` 管道**，不是分开的两根。
把 START / 数据发去 `0af1`、把 CTRL_REQ 发去另一个通道，全部落空。

### 11.4 第 2 步为什么容易漏

设备先要"读表盘"，主机不回 ACK 就不继续。表现为：ctrl_packet 明明被接受
（`result_code=0`），但设备再也不发 `07 40 19`，流程死等。

**这是"看起来像被拒绝、其实只是没握手"的典型**。判断方法：看 ctrl 应答里
`result_code` 是否为 0；为 0 就不能说"包被拒了"。

### 11.5 另一个坑：fwinfo 残留锁定

"进过 OTA 但没把数据推完"会在设备侧留下未结束的 DFU 状态，之后 init 被**静默拒绝**
（应答仍是 `result_code=0`），直到设备重启或超时复位。

错误码表里对应 `10 = OTA_ONGOING`，但实际连这个码都不一定给。
处理办法：重新走一遍完整握手（第 1~7 步），多数情况能自愈；不行就长按重启手表。

### 11.6 实测结果

| 包 | 内容 | 结果 |
|---|---|---|
| 官方原样镜像 | 3,105,248 B | ✅ 18195 写 / 60.7s，`0x000B`+`0x000D` 均 result=0，8s 后断开，1.8s 后正常回来 |
| 改版镜像 | 4 处 `V1.01.06` → `V1.01.99` | ✅ 同上，**全程无拒绝、无回滚**；屏幕显示 V1.01.99 |

推论（已由屏幕显示确认）：**没有整包 RSA 验签**，或验签范围不含被改的 rodata 段。
也就是说 `ctrl_packet` 里那个 256B 签名字段和每块 SHA256 是对的，
**镜像内容本身可以任意改**。

⚠️ 反过来说：**没有安全网了**。设备不做内容完整性校验，改错照样写进去。
OTA manager（`img_id=6`）和 ftab/bootloader 一旦刷坏，BLE 恢复通道就没了。

### 11.7 推流参数

| 参数 | 实测值 |
|---|---|
| 块大小 | 512 B 明文 → 548 B 载荷（+32 SHA256 +4 偏移 +10 头 = 558 B 消息） |
| 分片 | 240 / 240 / 74（MTU 247，每片带头 4B） |
| 速率 | 300 块/秒（≈900 写/秒）稳定无流控；官方 App 是 333 写/秒同量级 |
| 单次耗时 | 3MB 镜像 ≈ 61 秒 |

### 11.8 用到的脚本

```bash
# 1. 打包（签名 + 加密 + 分块）
python sifli_fw_pack.py --keys <sifli02> --image fw_patched.bin --fw-ver 1001099 -o pkg

# 2. 设备已进 GTX20 后推流
python sifli_ota_push.py --mac AA:BB:CC:DD:EE:FF --blocks pkg.blocks --rate 100

# 3. 只想确认握手通不通（不写数据）
python sifli_ota_push.py --mac ... --blocks pkg.blocks --probe
```

### 11.9 客户端实现的五个坑（2026-11-05，连刷 6 轮全失败才定位）

这一段全是**脚本侧**的错，设备端一次问题都没有。现象高度误导：每次都说"句柄不全"，
看起来像 GATT 发现被截断，于是反复重连、加长等待 —— 全部无效。

**坑一：用合成设备对象连接，拿到的 GATT 是被截断的**

```python
BleakClient(BLEDevice(mac, "GTX20", None))   # ❌ 只有 2 服务 / 5 特征（句柄 2..0x0B）
BleakClient(mac)                             # ✅ 4 服务 / 11 特征（完整）
```

`details=None` 的合成设备在 Windows 上能连上，但**不做完整服务发现**。
本机实测：同一台设备同一时刻，前者 5 个特征，后者 11 个。

**坑二：进 OTA 后按"句柄齐全"判断模式，把成功判成失败**

DFU 模式的 GATT 天生只有 7 个特征（见 §11.2），永远凑不齐 `0x14/0x16/0x1C`。
而判定代码写的是「先查句柄齐不齐，再看名字」：

```python
if all(h in ch for h in (H_CMD, H_CTRL, H_DATA)):  break
...
if nm == "GTX20": return True        # ← 永远走不到，前面已 else 放弃
```

结果：设备已经进了 OTA，脚本报"始终拿不到完整 GATT"然后等 120s。
**名字判断必须放在句柄判断之前。**

**坑三：用"连上去读名字"探测 OTA 窗口，把窗口本身耗掉**

设备重启进 DFU 后窗口只有几秒。一次完整 GATT 发现的连接要 4~6 秒，
探一次窗口就没了 —— 于是出现"探测到 GTX20，推流脚本再连却说不在 OTA 模式"。
**探测要用广播扫描**（`BleakScanner` 读 `adv.local_name`），不建连接、不触发服务发现。

**坑四：用广播名当唯一判据，被 Windows 的名字缓存误杀**

设备刚重启进 DFU 时，读 `0x2A00` 常返回**上一次的名字**（`悦心S1`）。
于是通道都在、名字不对 → 脚本自己中止。判据应该是**通道/句柄是否齐全**，
名字只当提示。反之普通模式里根本不存在 `-0100-/-0200-`，所以"通道齐全"本身就是充分证据。

**坑五：用写死句柄的推流脚本推 DFU 模式**

两套 GATT 的句柄完全不同（§11.2），DFU 模式里 `-0100-` 在 `0x000F`、`-0200-` 在 `0x0011`。
写死 `0x14/0x16/0x1C` 的脚本能"连上"但 start 帧永远无应答。

```
现象：GATT 完整（11 句柄）→ 设备名 '悦心S1' → 写 START → 无应答
真因：连的是普通模式的表，写到了 0af1/0af2 上
```

**推流脚本必须按 UUID 后缀解析通道，不能写死句柄号。**

### 11.10 一次成功的日志长什么样

```
[i] ctrl 已接受
  <<< 0740 19 @13.8s
  >>> 回写 0740 19 -> 0x000F
  >>> CTRL_REQ
[i] 已断开 @17.1s
  + 2.9s None              ← 扫描，设备重启中
  + 5.7s 'GTX20'           ← 广播名变了，窗口打开
[+] 已进入 OTA manager，开始推流
[+] 已连接（第 1 次尝试）  MTU=527  特征 7 个
[i] 设备名='GTX20'  ctrl=0x000F  data=0x0011      ← 7 个特征才是对的
    <- notify 010008000700040000000100            ← START OK
    块  6000/6065   60.0s    300 块/秒
[+] 推流完成 6065 块 / 60.7s
  +10s  在线=False  → 设备断开（进入安装/重启）
```

对照点：**"特征 7 个 + ctrl=0x000F + data=0x0011"是正常**，
"特征 11 个 + 名字 悦心S1"才是走错了模式。

---

## 十二、把上面全做对之后，仍然卡在 0%（2026-11-07）

上一节那套流程在 11-05 是通的。11-07 复现时却**稳定卡在 0%**：
进了 GTX20、连上了、START 发出去了、**一条通知都没回来**，19.5s 后超时掉回用户模式。

### 12.1 缺 `0x22 DFU_IMAGE_INIT_COMPLETED`

```
写 ctrl_packet(0x20) -> 收到 0x21 INIT_RESPONSE（"已接受"）
                        ↓
                     写 0x22 -> 设备 0.4s 内**主动断开**
                        ↓
                     2~5s 后以 GTX20 回来
```

少了 `0x22` 这一步，设备会**干等到约 19.5s 超时**然后退回 user bin。
现象是"ctrl 已接受，但怎么等都等不到 GTX20"，或者"连上了 GTX20 却是过期的缓存"。

```
CTRL_REQ = 0100 0500 2200 0100 00     # 0x22 INIT_COMPLETED，写到 -0200-
```

补上之后：**0.4s 断开、2s 变 GTX20，稳定复现**。

### 12.2 同进程二次连接 —— START 收到 0 条通知

父进程刚断开 GATT，紧接着在同一事件循环里再连、再订阅、再写 START
→ 通知通道是哑的。**看起来像设备不响应，其实是本地连接状态脏了。**

正确做法：**父进程只负责把设备送进 DFU，推流交给独立子进程**
（`subprocess.run([sys.executable, "sifli_ota_push.py", ...])`）。

`scripts/sifli_ota_flash.py` 已经按这个拆分实现。

### 12.3 GTX20 不广播 + Windows 地址缓存过期 = 彻底连不上

DFU 模式**不发广播**。按 MAC 直连靠的是 Windows 的地址缓存，
缓存过期就 `BleakDeviceNotFoundError`，怎么重试都没用。

**这是"卡 0%"最阴的一个原因**：上一轮还在、这一轮就没了，且没有任何报错线索。

纪律：**进 DFU 之后不要插入任何需要重连或探测的步骤**，一口气推完。

### 12.4 `fw_ver` 大一位就被静默拒

`1001002` → `ctrl` 应答直接是拒绝；用 `1001001`（与历史成功包一致）→ 顺利进 DFU。
设备端是 `>` 还是 `>=` 没确认，**保守策略：永远用跟上次成功一致的值**。

### 12.5 修正后的完整时序

```
[0] 确认电量 ≥50%（DFU 界面屏幕常亮，很耗电）
[1] 连用户模式（11 特征）
[2] 发 26 帧握手
[3] 写 ctrl_packet 分片 -> 等 ACK 头 010010002100
[4] 写 0x22 INIT_COMPLETED
[5] 等主动断开（0.4s）
[6] sleep 3s
[7] 子进程按 MAC 直连 GTX20（7 特征）-> CTRL_REQ(0x22) -> START(0x06) -> 等 START_ACK
[8] 推 N 块（300 块/秒）
[9] IMG_END1 / IMG_END2 -> 等断开 -> 设备重启装镜像
```

一条命令：

```bash
python scripts/sifli_ota_flash.py --mac AA:BB:CC:DD:EE:FF \
    --ctrl pkg/ctrl_packet.bin --blocks pkg/blocks.bin
```

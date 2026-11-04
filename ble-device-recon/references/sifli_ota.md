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

### 10.2 同样跑在应用层特征上，不是独立的 `sifli_sd` 服务

实测数据面：`handle 0x0200`（就是日常表盘/闹钟那个特征），18,454 帧 / 3,435,181 字节。
`sifli_sd` 服务在这次升级里**没有任何流量**。

→ 结论：**SiFli 的 `SFSerialTransport` 被配置成走厂商自定义透传特征**。
所以「OTA 一定在 `sifli_sd` 上」是错的，要按**流量形态**找：
一次升级 = 十几分钟窗口内某 handle 上数千个 `WRITE_CMD`，每帧接近 MTU。

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

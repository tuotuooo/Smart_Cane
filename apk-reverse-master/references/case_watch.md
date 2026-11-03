# 案例：华硕悦心S1 智能手表（Flutter + 白牌 + OTA）

一个"厂商封闭设备能不能刷固件"的完整复盘。**价值不在于结论，而在于两次判断修正的过程。**

---

## 0. 一句话结论

设备芯片确证 **SiFli SF32LB**；配套 App 实为 **VeryFit(IDO) 白牌方案**（ASUS 贴牌）；
**存在完整 OTA 通道**（服务器下发 zip → SPP 分片 → 手表端 DFU 刷写）；
**设备端验签强度未验证**——需要官方固件包才能判定能否刷自制固件。

---

## 1. 我一开始错在哪

首轮判断："芯片是 SiFli → 该方案有 efuse 安全启动 + RSA 签名 → 自编译固件刷不进去 →
这条路不通，建议换 PineTime。"

**错在把两条路径当成了一条**：

```
上电启动：  bootloader ──[efuse rootkey 验 app 镜像]──> 运行
固件升级：  App ──SPP──> 固件内 dfu 模块 ──[???]──> 写 flash
```

efuse 只管第一条。第二条的校验是**固件里自己实现的**，可能复用同一套公钥，
也可能只是 CRC。**从芯片手册推不出第二条的实现。**

> 教训：看到"支持 Secure Boot"就下"刷不了"的结论，等于没查就答。

---

## 2. 芯片是怎么确证的（双重证据）

| 来源 | 证据 | 强度 |
|------|------|------|
| App 里搜 `sifli` | 命中，但同时命中 nordic/realtek/ambiq/telink 共 5 家 | **不可用**（通用 SDK） |
| 设备 GATT 服务 UUID | `00000000-0000-0000-6473-5f696c666973`，尾 8 字节小端 = `sifli_sd` | **硬证据** |
| App 内源码路径 | `libprotocol_c.so` 含 `watch_dial/sifli_dial/app_custom_dial_make.c`、`mkSifliDialFile` | 佐证 |

判定规则：**App 侧指纹只能证明"SDK 支持"，芯片必须靠设备端证据。**

---

## 3. App 技术栈与白牌识别

- 153MB，**Flutter**（`libapp.so` 44MB，DEX 只剩几百类）→ 必须走 `flutter` 子命令，
  `dex` 子命令挖不到业务代码。
- `assets` 里 `pages_server.json` 全是 `*.idoocloud.com` / `veryfitplus.com`；
  Dart 侧有 `switchAppKey` / `showSwitchAppKeyDialog` / `idoKey2069` → **白牌方案**。
- Dart 包结构直接给出模块地图：`app_common`(510) / `app_device`(165) /
  `app_sport`(143) / `device_dial`(58) / `protocol_lib`(55)。
- 接口 125 条，其中 `api/ota/*` 一整组 → 固件升级入口。

**白牌的意义**：同方案设备成千上万，固件格式、协议栈、PC 工具通用，
后面所有工作都不用从零开始。

---

## 4. OTA 体系取证（四条证据齐全才算打通）

```bash
# ① 服务端接口
api/ota/dfu/checkUpdate        # 查固件
api/ota/update/dfu/add         # 上报结果
api/ota/extensionFirmware/check
api/ota/font/check  api/ota/hid/check  api/ota/compMiniVersion/checkUpdate

# ② 传输函数
sendZipToFirmware              # zip 经 SPP 分片下发
make_zip_file / mkSifliDialFile

# ③ 状态机与回调
otaWorkMode / otaDirectStart / otaMode / startDfuModelAndListenReconnect
SifliOtaFinished / IDOBluetoothDfuConfig / checkUpdateForOTA

# ④ 模块路径
package:device_ota/{service/ota_service,utils/ota_workflow,
                    utils/ota_sdk_helper,utils/ota_check}.dart
```

**卡点**：`api/ota/dfu/checkUpdate` 裸请求返回 `{"status":200321,"message":"appKey不存在"}`。
appKey 在请求头里，必须从运行时抓包取。**这是取证问题，不是技术封锁。**

---

## 5. 表盘是同一条通道的"低风险探针"

`mkSifliDialFile(const char *file_path)` @ `0x109028`，配合 `sifliEBinFromPng`（PNG→E-Bin）、
`getSifliDialSize`、`protocol_func_support_sifli_dial_size`。

容器格式（**以实测还原的云端表盘为准，见 §9**）：

```c
head_t (32B) { u32 magic=0xA1B2C8D9; u16 header_size=32; u16 version=13;
               u16 file_count; u32 unknown_0A; u16 unknown_0E;
               u32 name_size; u8 reserve[12]; }
file_head_t (16B) { u32 name_offset; u32 size; u32 unknown;
                    u32 offset; }        // offset 需 -32 才是真实数据偏移
+ 名字表 + 索引表 + 数据区
```

⚠ **早期版本写的"8KB 对齐"是错的**（来源是 DWARF 里的本地工具 `mkSifliDialFile`）。
云端下发的表盘是**紧凑排列、零填充**：`32 + 8335 + 1936 + 423532 = 433835`，
与文件大小精确相等。**同一个格式，本地工具与云端打包器用两套布局——
不要把工具的行为当成格式的规范。**

**关键判断**：表盘不需要固件签名（设备只解析格式），所以它是**验证 SPP 链路成本最低的
探针**——成功说明分包/握手全通，失败最多表盘不显示，不影响设备。

---

## 6. 协议层（供后续复用）

- **BLE = 控制面**（JSON，service `0x0af0`，mfg `0x1FC5`）
- **SPP/RFCOMM = 数据面**（二进制帧）

⚠ **上面这条"按通道类型分面"的说法被实测修正了**：表盘文件实际是**走 BLE GATT**
传的（handle `0x0200` 透传特征值，1816 个无响应 Write Command，见 §9）。
所以正确判据不是"BLE 还是 SPP"，而是**流量形态**：

| 形态 | 结论 |
|------|------|
| 上千个 Write Command、每包接近 MTU | 文件传输，不管它在 BLE 还是 SPP |
| 一问一答、载荷 5~20B | 命令通道 |
| 周期性固定长度 Notify | 状态上报 |

在 BLE 上发数据命令无响应仍然是**正常现象**——但原因不是"数据面在 SPP"，
而是**你发的帧格式不对**（数据面有自己的 3 字节头，不是 JSON）。

- 帧头 6B：`{cmd, key, cmd1..cmd4}`；`protocol_receive_data` @ `0x114128` 的魔数白名单：
  `0x11`+`0x02` / `0x21`+`0x10` / `0xBB` / `0xD1`+`0x02`
- 校验：CRC16 + AES + MD5
- `libprotocol_c.so` 带 **17.4MB DWARF**：`.symtab` 给 6275 个 FUNC，`.debug_info` 给
  结构体/参数/局部变量。**有 DWARF 就不要先反汇编**——读 DWARF 的效率高一个数量级。

---

## 7. 五条可复用的教训

1. **efuse ≠ OTA**。判"能不能刷"必须先找 OTA 通道，再判设备端验签。
2. **Flutter 看 `libapp.so`**，不要看 DEX 类数。
3. **白牌先识别**。`idoocloud`/`veryfit`/`switchAppKey` 一出现，就按通用方案分析。
4. **芯片要双重证据**。App 指纹不可信，靠 UUID/固件串/丝印。
5. **先做表盘探针，再动固件**。顺序反了会把"链路不通"误判成"验签拦了"。
6. **能连上才有的入口，别指望改 db**。固件更新入口依赖实时 `deviceInfo`，
   数据库伪绑只能骗过设备列表。

---

## 8. OTA 通道事实（实测确认）

**接口**：`POST https://cn-device.idoocloud.com/api/ota/dfu/checkUpdate`

| 项 | 结论 |
|----|------|
| `appKey` | 放 **HTTP header**，不放 body；真值 `198956880cae47baac9ed1601a47cd2a`（运行时组装，不在 `app_key_list.json` 的 25 条白名单内） |
| `otaVersion` | 必须**无 `V` 前缀**的点分格式（`1.01.03` ok，`V1.01.03` → `10501 必须是合法的版本号`） |
| 鉴权 | 早期用 curl 手工请求时：无 token 返回 `200 / result:null`；错误 Bearer → `201010 验证Token服务器不能识别`。**但这条被实测推翻了**：App 在**未登录（游客态）且已连设备**时，OTA 提示照常弹出 → `checkUpdate` 不依赖账号登录态（App 内部可能带游客 token，或接口对游客开放）。**不要用 curl 的结论去推断 App 的行为。** |
| 响应落库 | 写入 `SportIconBean`（`version / remark / appFileUrl / otaFileUrl`），读需 root |

**入口前置条件**：`device_ota/utils/ota_workflow.dart` 的 `_checkDeviceState`，
断言 `OTA: deviceInfo == null || otaVersion.isEmpty`；`deviceInfo` 来自
`protocol_lib/src/device_info/` 的**实连读取**。→ **未连蓝牙不显示固件更新入口**（已实测）。

**Dart 侧 OTA 全模块清单**（`libapp.so` 字符串表可直读，版本 1.0.0 / 1.1.0 均含）：

```
device_ota/controller/ota_main/{network,logic,state}.dart   ← checkUpdate 请求与状态机
device_ota/utils/{ota_workflow,ota_manager,ota_file_manager,ota_check}.dart
device_ota/constants/ota_constants.dart
device_ota/models/ota_update_obj.dart
device_ota/utils/{agps_manager,epo_manager}.dart            ← AGPS/EPO 与固件共用通道
app_common/database/src/{bean/device_ota_info,dao/device_ota_info_dao}.dart
app_common/enum/firmware_platform.dart                      ← 多平台固件（SiFli 是其中之一）
app_abi/device_ota/src/service/device_ota_service.dart      ← 原生 ABI 桥
flutter_bluetooth/channel/firmware_data_channel.dart        ← 固件数据通道（getFileChecksum）
flutter_bluetooth/model/{ido_bluetooth_dfu_config,ido_bluetooth_dfu_state}.dart
```

**下发路径**：固件由 App 下载后经**蓝牙 DFU 通道**传给手表（原生侧
`IDOProtocolAPIExtRegisterCallback|_registerDataTranProgressCallbackReg`），
**不是网络直传设备**。→ 抓蓝牙即可拿到固件本体 + 分包/校验/握手全流程，
`adb bugreport` 可取回 btsnoop，**零 root**。

---

## 9. 后续复盘：改包导出 + 空口还原表盘协议

**这一段推翻了本文件早期的三个结论**，以本节为准。

### 9.1 改包：把未导出的原生 Activity 叫起来

目标：`com.example.video.dial.video_dial.WallpaperImageGridActivity`（相册网格）。
`am start -n` 直接报 `not exported from uid 10190`。

**试错过程**：

| 尝试 | 结果 |
|------|------|
| 插入 `exported` 属性（重建 string pool + 扩 resource map） | 装上无效，仍 `exported=false` |
| 同上，最小改动版（复用已有字符串索引） | 无效 |
| 插入的 20 字节与 MainActivity 的 `exported` 逐字节一致 | 无效 |
| 对照：改已有 `allowBackup` 的值 | ✅ 生效 |
| **牺牲 `screenOrientation`**，改造成 `exported` | ✅ 生效，`mResumedActivity` 变成该页 |
| 顺手把另外两个 Activity 的 `theme` 改成 `exported` | ❌ 装包失败 `does not specify android:name` |

**结论**：AXML **只能改值，不能插属性**。这不是格式问题，是解析器不读追加项。
配方见 `pitfalls.md` §9.1。

**改包代价实测**：卸载重装后登录态清空、需重新绑定手表；
手表端不用重置，重新绑定即可。

### 9.2 空口还原：表盘的真实传输协议

方法：零 root 抓 HCI（`ble-device-recon` 附录 A），在 App 里正常装一次表盘，
`adb bugreport` 取 `FS/data/misc/bluetooth/logs/BT_HCI_*.cfa.curf`。

**链路**：ATT handle `0x0200`，MTU 517，**Write Command（0x52）无响应**，单包 ≤252B。

**应用层帧**：

```
d1 05 0a                                    会话开始
d1 01 ff <size:u32 LE> 02 <name>\0          文件名 + 大小
d1 02 00 <raw>                              数据块（纯流式追加，无序号无偏移）
d1 03 <sum16 LE> <unknown:u16 LE>           结束 + 校验
```

**校验是字节累加和 & 0xFFFF**，不是 CRC16/CRC32：

| 文件 | 声明 | 实收 | sum16 | 验证 |
|------|------|------|-------|------|
| `contacts.ml` | 361 | 361 | `0x82F3` | ✓ |
| `wf_w202.watch` | 433,835 | 433,835 | `0x02AE` | ✓ |

CRC16 七种常见变体全部不匹配。`d1 03` 后 2 字节**仍未解**（contacts=0、表盘=0x0365），
已排除"长度/块数/CRC"，标未解，不要当已知。

### 9.3 容器：无对齐填充

`head_t`(32B) + 名表(8335B, 121 条) + 索引(1936B = 121×16) + 数据区(423532B)
= **433,835**，与文件大小精确相等 → **零填充**。索引 `offset` 严格连续，可据此自证解析正确
（`off[i] + size[i] == off[i+1]`）。

内含：`wf_w202.so`（17,572B，**ARM32 ELF / ET_DYN**）、`wf_w202_res.so`、
`wf_w202_tn.bin`（缩略图）、117 个 `ezip/*.bin`、以及 72B 的 `wf_w202.dsc` 清单。

`wf_w202.so` 导入符号：`lv_img_set_src` / `lv_obj_align` / `lv_task_del` /
`dlmodule_get_user_data` / `service_get_current_time`。

→ **表盘不是图片拼装，是 LVGL 动态模块（dlmodule），跑在 SiFli RTOS 上。**

### 9.4 对"宠物表盘"的结论

| 路径 | 可行性 | 成本 |
|------|--------|------|
| 换图（解 ezip 编码 → 替图 → 重打包 → 按 §9.2 推送） | 高，风险低 | 低，但宠物是**静态**的 |
| 自写 LVGL 模块（状态机驱动多套表情） | 需要 SiFli SF32LB SDK + 交叉编译 + .so 验签未知 | 高 |

**ezip 像素编码仍未解**（头 `01 18 46 38` + `01 86 01 c2` = 390×450 已识别，
压缩算法未确认）。`wf_w202.so` 是否验签**未验证**。

### 9.5 这一段的三条通用教训

1. **"能不能调起来"和"有没有入口"是两件事**。`not exported` 只是权限问题。
2. **不要按通道类型判断控制面/数据面**，要按流量形态判断。表盘走的是 BLE，不是 SPP。
3. **同一个格式可能有多个打包器**。DWARF 里的本地工具行为 ≠ 云端下发格式。

### 9.6 资源格式闭环：eZip + 容器重打包

**表盘不是图片拼装，但"是程序"不等于"不能换图"。**

`.so` 只负责布局与数据绑定，所有图片走
`lv_img_set_src("A:/dynamic_app/watchface/wf_w202/ezip/xxx.bin")`。
`.so` 里没有任何解压/解密导入符号（只有 lvgl + dlmodule + rt_malloc），
说明 **ezip 由宿主固件的硬件解码器处理**。

**ezip 是什么**：SiFli 芯片的 eZip 硬件解压格式，思澈私有算法。
试过 zlib(deflate) / LZ4 全部不匹配 —— **不要试图逆向算法**，
官方 SDK 已经给了双向工具 `tools/png2ezip/ezip.exe`：

```bash
ezip -convert x.bin -spt 1 -dpt 0 -outdir out      # ezip → PNG
ezip -convert x.png -binfile 2 -rgb565 -chip sf52x # PNG → ezip
```

**格式**（官方 4 字节头 + 厂商扩展）：

```
[0:4]  {h:11, w:11, rsv:5, fmt:5} 小端，fmt 1=无alpha 2=带alpha
[4:8]  u32 BE 压缩长度
[12:16] u16 BE 宽, u16 BE 高
[20:22] u16 BE = 32   每块行数
[22:24] u16 BE = N    块数   ← (h+31)//32 完全对应
[24:]  N × u32 BE 块偏移（递增）
```

**结果**：
- 背景图解出来是「数字圣诞」表盘（绿格纹 + 橙卡片 + 圣诞饼干 + 手写字）
- 用工具重新编码的 ezip 与原文件**首 24 字节结构完全同构**
- 容器原样重打包 **逐字节一致**（433,835 B，`cmp` 通过）
- 替换背景后 376,418 B，断点 0，解回内容正确

**限制**：2.6.4 这个 build 会 strip alpha（`-rgb565a` 与 `-rgb565` 输出相同），
所以带透明的图标类换不了，背景类可以。

**未验证**：设备是否接受官方工具生成的 ezip（需一次真机推送）。

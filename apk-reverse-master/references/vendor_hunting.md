# 厂商一手资料检索（Vendor Doc Hunting）

> **适用**：逆向遇到"厂商私有格式 / 私有 OTA / 私有密钥体系"时。
> **一句话原则**：**先花 20 分钟找方案商的一手资料，再决定要不要逆。**
> 逆 eZip 压缩算法是不可能完成的任务（硬件解码器）；找官方 `ezip.exe` 是 5 分钟。
> 逆 SiFli OTA 的 RSA 签名是数学上不可能；找 `sig_pri.pem` 是 20 分钟。
>
> 本文记录的就是那 20 分钟**具体怎么找**。对象是公开可下载的厂商 SDK / 文档，
> 不涉及任何未授权访问。

---

## 零、先判"该不该搜"（省掉一半无用功）

| 信号 | 该搜 | 为什么 |
|------|------|--------|
| 私有压缩/图像格式（ezip、zlib 变体、自定义 RLE） | ✅ **必搜** | 通常是硬件解码器，没有软件实现，逆不出来 |
| OTA/DFU 包有 RSA/ECDSA 签名段 | ✅ **必搜** | 私钥不可能逆出来；只能找厂商是否泄漏了默认密钥 |
| 帧格式带 CRC 但四种标准变体都不中 | ✅ 搜 | 厂商可能自定义多项式；但先按 §四 的差分法试一次 |
| 加密包有固定长度尾块（128/256/294B） | ✅ 搜 | 那是签名段，找官方验签代码比爆破快 |
| 容器是简单长度+偏移（`.watch`、zip 变体） | ⚠️ 可搜可不搜 | 结构自证就能解，搜只是省时间 |
| 明文 protobuf / JSON / TLV | ❌ 不搜 | 直接读 |

**判据**：如果需要的知识是"**算法**"，就搜（算法在别人脑子里）；
如果只是"**布局**"，自己解（布局在文件里）。

---

## 一、从 APK 里挖检索关键词（四个锚点）

搜之前必须有正确的关键词。四个锚点，可靠性递增：

```bash
# ① 原生库名 —— 最常暴露方案商
unzip -l app.apk | grep -E 'lib/[^/]+/lib.*\.so'

# ② 包名前缀 —— SDK 的 Java 包名往往就是厂商域名倒写
python apk_analyze.py dex app.apk --keyword 'com\.(sifli|nordic|realtek|ambiq|telink|goodix)'

# ③ GATT UUID 尾段 ASCII —— 设备侧指纹，最能确证
python -c "
import re,sys
for m in set(re.findall(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-([0-9a-f]{4})-([0-9a-f]{12})', open(sys.argv[1],'rb').read().lower())):
    tail=m[0]+m[1]
    try:
        print(m, '->', bytes.fromhex(tail.decode())[::-1])
    except Exception: pass
" libflutter.so
# 实例：6473 5f696c666973 -> b'sifli_sd'
```

```bash
# ④ .so 里的源码路径（有 DWARF 时最准，直接给出厂商工程目录结构）
strings -a libprotocol_c.so | grep -E '\.(c|h)$' | sort -u | head
# 实例：watch_dial/sifli_dial/app_custom_dial_make.c  ->  SiFli 官方表盘工具链
```

**锚点组合出检索词**：厂商名 + 功能名 + 文件类型。

```
sifli  + dfu   + python
sifli  + ota   + sdk
sifli  + ezip  + tool
```

> 别用泛词（"OTA SDK"、"表盘格式"）—— 会被通用方案（VeryFit/IDO、Zepp）的
> 海量结果淹没。**关键词里必须有厂商名**。

---

## 二、五级检索阶梯（按命中率排，逐级下降）

### L1 官方文档站（命中率最高，先来这里）

厂商文档站通常就是 `docs.<vendor>.com` / `wiki.<vendor>.com` / `<vendor>.com/docs`。

**要在这类站点找的不是 API 说明，而是三样东西**：

| 目标 | 为什么关键 |
|------|-----------|
| **包仓凭据 / 仓库地址** | 厂商常把 maven/pypi 的**用户名密码直接写在接入文档页面里**（非公开仓库但凭据公开） |
| **错误码全表** | 直接给出设备端校验分层（签名错 / 版本错 / 镜像错），省掉大量试错 |
| **协议版本矩阵** | 告诉你 AAR 版本与固件版本的对应关系 |

实例（SiFli，`docs.sifli.com`）：OTA V3 Android SDK 接入页 → 页面里给了
maven 仓库地址 + 用户名/密码 + 三段坐标 → 直接能下官方 AAR。

> **这一条最容易被跳过**：很多人看到"需要账号"就放弃，其实账号就印在页面上。

### L2 官方包仓（拿编译好的 SDK 二进制）

```bash
# maven（Java/Android SDK）
#   URL/凭据从 L1 页面抄，注意 -u user:pass
curl -u '<user>:<pass>' -O 'https://<maven-host>/<group-path>/<artifact>/<ver>/<artifact>-<ver>.aar'

# pypi / npm / nuget 同理，厂商自建源也常见
pip download <vendor>-tools -i https://<vendor>-pypi/simple --trusted-host ...
```

**拿到 AAR 之后必须做的事**（否则等于没下）：

```bash
unzip -o sdk.aar -d sdk_x/          # .aar 就是 zip
ls sdk_x/                            # classes.jar / AndroidManifest.xml / jni/ / R.txt
unzip -o sdk_x/classes.jar -d sdk_cls/
# 然后按 apk-analyzer 的 dex/jar 手法读常量（见 §五 的字节码还原）
```

### L3 开源 SDK 仓库（拿源码 + 默认密钥 + 工具链）—— 价值最高

芯片/方案商常把参考实现开源（Apache-2.0 / MIT），而**默认密钥、工具源码、
示例工程全在里面**。这是"复刻"最关键的一级。

```
GitHub:  <VendorOrg>/<Vendor>-SDK          → tools/ 下就是工具源码
Gitee:   镜像（国内更稳）
```

**必查目录**：

| 路径 | 里面有什么 |
|------|-----------|
| `tools/secureboot/` | 签名/加密/打包工具的**源码**，以及 `<chip>/` 下的默认密钥目录 |
| `tools/<fmt>2<fmt>/` | 格式转换器（ezip.exe / png2xxx），解决私有图片格式 |
| `middleware/dfu/` | 设备端 DFU 实现 → 直接读到验签逻辑与错误码定义 |
| `mcu/tools/` | 烧录器、ftab 表、flash 布局 |
| `example/` | 官方 OTA 工程（比对 flash 布局的唯一样本） |

**判据**：`tools/` 里有 `.py` 源码 = 打包格式完全透明（不用逆）；
只有 `.exe` = 只能当黑盒工具用，但参数可以从手册抄。

### L4 官方论坛 / BBS 的 PDF 与附件

`bbs.<vendor>.com` 常有"XX 使用说明.pdf"这类文档，比文档站更贴近实际参数
（imgtool 的完整命令行、flash 布局图、efuse 说明）。

- 文档站讲"接口"，BBS 讲"**怎么跑通**"。
- PDF 里的参数表**优先于**源码里的默认值（源码默认值可能是旧版）。

### L5 二手资料（只用来找线索，不采信参数）

CSDN / 博客 /  StackOverflow：可能帮你定位到 L1~L4 的入口，
但**其中的版本号、flag 值、UUID 一律要回一手核对**。
踩过：博客里的 `--sdk_ver=7010` 与设备实际值不符，直接导致 `SDK_VER_ERROR(6)`。

---

## 三、网络可达性（国内环境的实际卡点）

| 目标 | 症状 | 解 |
|------|------|-----|
| `raw.githubusercontent.com` / `github.com` clone | 超时 / `Recv failure: Connection reset` | 前缀 `https://gh-proxy.com/`，如 `https://gh-proxy.com/https://raw.githubusercontent.com/org/repo/main/x.py` |
| GitHub Release 附件 | 同上 | 同上；或 `https://ghproxy.net/` |
| 厂商文档站 | 正常 | — |
| 厂商 maven | 需要凭据 | 从 L1 页面抄；`curl -u` |

**验证下载完整性**（别拿半截文件当结论）：

```bash
# JSON/HTML 里出现 "404: Not Found" 就说明镜像没命中，不是"文件内容就是这样"
head -c 200 out.py; echo
# 二进制要有正确 magic：aar=zip(PK\x03\x04)、pem=-----BEGIN、bin=厂商魔数
```

---

## 四、交叉验证：怎么确认"我拿到的是同一套"

**这一步不能省。** 找到密钥 ≠ 用的是这套密钥。

本次（悦心S1）的决定性证据链：

| 对照项 | App 侧（逆向得到） | 官方 SDK 侧（下载得到） | 结论 |
|--------|------------------|----------------------|------|
| AES-256 key | `e692dfb5…59172b`（从 `CtrlFileValidator.aesDecrypt()` 字节码还原） | `s01.bin` 内容 | **逐字节相同** |
| AES-CTR IV 前缀 | `56ce4ec4c9dcf411`（8B 硬编码） | `sig_hash.bin` 前 8B | **相同** |
| 包长度公式 | `encLen = len - 32 - 256` | `32 + AES(ctrl) + 256(RSA)` | 吻合 |
| 错误码 | App 侧 `V3_CTRL_DECRYPT_FAIL(520)` | 固件侧 `9 = CTRL_PACKET_INVALID` | 分层一致 |

**判据模板**（任何厂商都套这三条）：

1. **常量相同**：App 里硬编码的 key/IV/magic 与官方默认文件逐字节比对；
2. **结构相同**：App 的打包/校验代码长度计算与官方工具源码一致；
3. **命名相同**：类名/函数名/错误码能一一映射。

三条全中 → 厂商**没换密钥、没改格式**，可复用官方工具链。
只中 1~2 条 → 厂商改了一部分，必须逐个字段核对，不能整套照搬。

> 反过来也成立：如果厂商换了密钥，App 里就必然有**自己的**那份 key
> （否则 App 解不了包）。所以"App 内嵌 key == 官方 key"是极强的信号。

---

## 五、从字节码里抠常量（没有源码时的最后手段）

AAR 里的 `classes.jar` 是 Java 字节码，`javap -c` 就能读出 `ldc` 的常量。

```bash
# 单个类反汇编
javap -p -c -classpath sdk_cls com/vendor/dfu/CtrlFileValidator.class | grep -A2 ldc

# 批量找"像密钥的常量"（32B hex、16B hex、base64）
cd sdk_cls && grep -rl "e692dfb5" . 2>/dev/null
```

有的 SDK 用 `new byte[]{...}` 逐字节塞常量，`javap` 会输出一长串 `bipush/sipush`，
这时用脚本按 `bipush` 序列拼回（本次 `extract_key.py` 就是这个用途）。

**注意**：DEX 里常量是 MUTF-8 字符串，`strings` 能直接命中 32 字节 hex key，
所以"先 `strings | grep -E '^[0-9a-f]{64}$'`"往往就够了。

---

## 六、坑库（都是实际踩过的）

| 坑 | 现象 | 正解 |
|----|------|------|
| GitHub 直连 | `Connection reset` | `gh-proxy.com` 前缀 |
| `.aar` 当 jar 用 | 解压后没有 class | `.aar` 是 zip，里面还有一层 `classes.jar` |
| 文档站有登录墙就放弃 | 以为要商务账号 | 接入文档页常直接印着仓库用户名密码 |
| 用厂商工具的默认参数 | 生成包设备拒收 | `sdk_ver` / `fw_ver` 必须与**设备当前值**对齐，手册示例值只是示例 |
| 厂商工具在任意目录跑 | 静默失败、退出码 0 | 很多工具硬编码 CWD 依赖（`imgtool` 要求 bin 与 `sifli02/` 同目录，`ezip.exe` 不创建输出子目录）。**先 `cd` 到工具期望的目录** |
| 信二手博客的 UUID | 连不上/无响应 | UUID 从 App 字节码或设备 GATT 枚举取，不从博客取 |
| 只下 SDK 不下 tools | 有库但不会打包 | `tools/` 才是打包器所在；SDK 只是客户端 |
| 把 PDF 里的"秘密"水印当障碍 | 不敢引用 | 公开 BBS 可下载的文档即可引用，注明来源与版本 |

---

## 七、产出物落盘规范

搜完必须落盘，否则下次重来：

```
<project>/vendor_docs/
  README.md               # 来源清单：URL / 抓取日期 / 版本 / 用来证明什么
  sdk/                    # AAR / jar / pypi 包
  tools/                  # 官方工具（imgtool / ezip / ble_serial）
  keys/                   # ⚠️ 默认密钥，仅本地留存，不要提交到公开仓库
  manual/                 # PDF 及其提取文本
```

`README.md` 里每条都要能回答：**"这个文件支撑了报告里的哪一句结论？"**
答不上来的文件就是没用的文件。

> ⚠️ 默认密钥、私钥、厂商未公开的调试工具**不要**进公开仓库
> （`.gitignore` 掉 `keys/`、`*.pem`、`*.bin`）。本仓库的做法是：
> 文档写"密钥在 `tools/secureboot/<chip>/` 下，文件名 `s01.bin` / `sig_pri.pem`"，
> 让读者自己去官方仓库取，而不是把密钥复制一份传播。

---

## 八、一个完整实例（SiFli OTA，20 分钟）

```
① APK 里发现 libprotocol_c.so 带 DWARF
   → strings 出 watch_dial/sifli_dial/app_custom_dial_make.c  → 厂商 = SiFli

② 设备 GATT 枚举到 00000000-0000-0000-6473-5f696c666973
   → 尾段小端 = "sifli_sd"  → 确证（不是"疑似"）

③ 搜 "sifli ota sdk"  → docs.sifli.com OTA V3 Android SDK 接入页
   → 拿到 maven 地址 + 凭据 + 错误码全表

④ 拉 AAR（sifliotasdk-2.2.8 / siflicore-1.2.16）
   → classes.jar → 反出 sifli_sd 的 UUID、SFSerialTransportPack 帧格式、
     CtrlFileValidator（含 AES key 与 encLen 公式）

⑤ 搜 "SiFli-SDK github" → OpenSiFli/SiFli-SDK（gh-proxy 拉）
   → tools/secureboot/imgtoolv37.py（打包器全源码）
   → tools/secureboot/sifli02/{s01.bin, sig_hash.bin, sig_pri.pem, sig_pub.pem}

⑥ bbs.sifli.com 的《SiFli OTA 使用说明》PDF
   → imgtool 完整命令行、flash 布局、efuse 说明

⑦ 交叉验证：App 内嵌 key == s01.bin（逐字节）
   → 厂商未换密钥 → 官方工具链可直接用
```

**总耗时约 20 分钟，替代了"逆 RSA 签名 + 逆私有压缩"这两件做不到的事。**

设备侧协议细节见 `ble-device-recon/references/sifli_ota.md`。

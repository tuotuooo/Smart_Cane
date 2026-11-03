# 端到端剧本

六条常见链路，每条给出**完整命令序列**与**每步验收**。照抄改包名即可。

约定：
- `<A>` = `apk-analyzer` 技能目录
- `<E>` = `android-emulator-adb` 技能目录
- `<R>` = `apk-runtime-dump` 技能目录
- 工作目录 `./analysis/`

---

## 剧本 A：普通未加固 APK，快速摸清

**适用**：用户只是想知道"这是什么应用、要什么权限、连哪些服务器"。
**耗时**：1~2 分钟。**不需要 root**。

```bash
mkdir -p analysis

# 1. 完整静态报告
python <A>/scripts/apk_analyze.py analyze sample.apk --json > analysis/static.json

# 2. 看关键线索（授权/端点/加密）
python <A>/scripts/apk_analyze.py dex sample.apk --keyword http
python <A>/scripts/apk_analyze.py dex sample.apk --keyword license
python <A>/scripts/apk_analyze.py strings sample.apk --keyword token --out analysis/strings.txt
```

**验收**：
- 报告里 `[4] DEX 线索` 的类数/方法数与包体积**匹配**（不是桩）
- 有包名、版本、签名指纹
- 至少列出 3 个业务域名

**输出**：直接写报告第 0~3 节即可，不需要第 4 节。

---

## 剧本 B：加固 APK，要拿真实代码

**适用**：剧本 A 第 1 步发现加固特征。
**耗时**：5~20 分钟。**需要 root。**

```bash
# 0. 静态确认加固（记下判据，后面要写进报告）
python <A>/scripts/apk_analyze.py analyze sample.apk | sed -n '/DEX 线索/,/^\[5\]/p'

# 1. 设备画像：这一步不过就别往下走
python <E>/scripts/find_and_connect.py --info --human
#    要看到 root: YES (uid=0)  和  toybox dd: 可用

# 2. 安装并启动（-g 避免权限弹窗打断）
python <E>/scripts/find_and_connect.py -- install -g sample.apk
python <E>/scripts/find_and_connect.py -- shell am start -n com.pkg/.SplashActivity

# 3.（可选）确认进程活着，并记录 maps 里有没有壳的 so
python <E>/scripts/find_and_connect.py -- shell "pidof com.pkg; grep -o 'libDexHelper[^ ]*' /proc/\$(pidof com.pkg)/maps | head -1"

# 4. 看地形（秒出，先确认候选区域合理）
python <R>/scripts/apk_runtime_dump.py --pkg com.pkg --list

# 5. 脱壳
python <R>/scripts/apk_runtime_dump.py --pkg com.pkg --out analysis/memdump

# 6. 规范化 + 体检
python <R>/scripts/dex_fix.py "analysis/memdump/dex_*.bin" --out-dir analysis/memdump/fixed
```

**验收**（三个都要满足）：
1. 命中 DEX 数量 ≥ 1，且总大小与业务规模相符；
2. `dex_fix.py` 每个文件 `truncated=False`；
3. `code_off: invalid = 0`。

**拿不到时的分支**：

| 情况 | 分支 |
|------|------|
| 0 命中 | 让 App 进入主界面再扫；或 `--min-mb 0 --max-mb 800` 放宽 |
| 只命中 1 个 | 多走几个界面重复扫（惰性解密） |
| invalid > 0 | `--region 0xSTART-0xEND` 整段重 dump |
| 读内存全空 | 回剧本 E |

**输出**：报告第 4 节（脱壳成果 + 产物表）。

---

## 剧本 C：React Native + Hermes 应用

**适用**：assets 里有 `index.android.bundle`，或 maps 里有 `libhermes.so`。

```bash
# 1. 静态看容器结构（不脱壳也能拿到大量业务字符串）
python <A>/scripts/apk_analyze.py bundle sample.apk
python <A>/scripts/apk_analyze.py bundle sample.apk --json > analysis/bundle.json

# 2. 提取明文字符串表
python <A>/scripts/apk_analyze.py strings sample.apk --keyword http --out analysis/bundle_strings.txt
```

若需要**真正的 JS 字节码/方法逻辑**，先看 `bundle` 的判定：

```bash
# 2. 看是否标准未加密 HBC
python <A>/scripts/apk_analyze.py bundle sample.apk --json | \
  python -c "import sys,json;d=json.load(sys.stdin);print('标准HBC:',d['hermes_valid'],'| fileLength匹配:',d['file_length_match'])"
```

- `hermes_valid: true` → **直接反汇编，不用脱壳**：
  `hbcdump -d assets/rn/main.jsbundle out.asm` 或 `hermes-dec`
- `false` → 才是自定义容器/加密，继续下面步骤

```bash
# 3. 让 RN 页面加载（登录后 / 进首页），确认引擎已初始化
python <E>/scripts/find_and_connect.py -- shell "grep -c hermes /proc/\$(pidof com.pkg)/maps"
#    输出 > 0 才能进行下一步；0 就是还没加载

# 4. 定向扫 Hermes
python <R>/scripts/apk_runtime_dump.py --pkg com.pkg --magic hermes --out analysis/hermes
```

**验收**：产物以 `c6 1f bc 03` 开头，大小与 assets 里 bundle 量级相当。

**警示**：不要用"header XOR 魔数"的方式声称能解密（见 pitfalls 1.4）。

---

## 剧本 D：定位授权 / License 校验逻辑

**适用**：KMS 激活器、License 类样本，目标是找"校验在哪、请求发到哪、结果怎么存"。

```bash
# 1. 静态圈定候选（先不脱壳）
python <A>/scripts/apk_analyze.py strings sample.apk \
  --keyword license --keyword activat --keyword sign --out analysis/lic.txt
python <A>/scripts/apk_analyze.py dex sample.apk --keyword auth

# 2. 若已加固 → 先走剧本 B 拿真 DEX，再对 fixed DEX 做同样的关键词挖掘

# 3. 动态验证：清日志 → 触发流程 → 抓线索
python <E>/scripts/find_and_connect.py -- logcat -c
#   （手动在模拟器里点"激活"，或 am start 拉起目标 Activity）
python <E>/scripts/find_and_connect.py -- logcat -d > analysis/log.txt
grep -iE "license|activat|token|sign|http|post" analysis/log.txt

# 4. 数据落地：看授权状态存在哪
python <E>/scripts/find_and_connect.py -- pull /data/data/com.pkg/shared_prefs analysis/prefs
python <E>/scripts/find_and_connect.py -- pull /data/data/com.pkg/databases analysis/db
```

**验收**：
- 能指出**校验入口类/方法**（脱壳后可读伪码）
- 能给出**授权服务器域名与路径**
- 能指出**校验结果落盘位置**（SP 键名 / db 表名 / 文件）

**注意**：只做**分析**。不提供绕过实现。

---

## 剧本 E：App 打不开 / 一启动就闪退

**排查顺序**（从最便宜的开始）：

```bash
# 1. 是不是装都装不上（签名冲突 / minSdk）
python <E>/scripts/find_and_connect.py -- install -r sample.apk

# 2. 装机成功但起不来 → 看真实异常
python <E>/scripts/find_and_connect.py -- logcat -c
python <E>/scripts/find_and_connect.py -- shell am start -n com.pkg/.MainActivity
python <E>/scripts/find_and_connect.py -- logcat -d | grep -iE "fatal|exception|died|ANR" | head -30

# 3. 进程存活多久（本机循环，比 PC 轮询准）
python <E>/scripts/find_and_connect.py -- shell \
  'am start -n com.pkg/.MainActivity >/dev/null 2>&1; for i in $(seq 1 40); do p=$(pidof com.pkg); echo "$i ${p:-DEAD}"; sleep 0.2; done'

# 4. 怀疑 root/emulator 检测
python <E>/scripts/find_and_connect.py -- logcat -d | grep -iE "root|emulator|magisk|tamper|signature"

# 5. 怀疑反重打包（改过包 / 重签过）
python <A>/scripts/apk_analyze.py analyze sample.apk | grep -A3 "完整性"
```

**判断表**：

| 表现 | 结论 |
|------|------|
| 立刻 DEAD，logcat 有 `FATAL` + Java 异常 | 代码崩溃，读栈 |
| 立刻 DEAD，无异常 | native abort / `exit()` → 检测触发 |
| 存活 1~3 秒后 DEAD | 定时检测（root/emulator） |
| 停在启动页不前进 | 网络/校验失败，不是崩溃 |
| 进到登录页就 DEAD | 反 root 在登录时触发 → 抢窗口 dump（剧本 B 第 5 步前置） |

---

## 剧本 F：IoT 硬件配套 App —— 判固件能不能刷

**适用**：手表 / 手环 / 耳机 / 车机 / 智能家居的配套 App。用户真正想要的是
"这设备的固件我能不能换成自己的"。

**必须先纠正一个前提**：这类问题**不是**"找漏洞"，而是"**找到 OTA 通道，再判断卡在哪一层**"。
绝大多数人（包括我）第一次会直接用芯片手册下结论——错在混淆了两条完全不同的路径。

```bash
# ── 第 0 步：先检索厂商一手资料（最省时间，别跳过）──────────────
#   逆私有压缩格式 = 不可能（硬件解码器）
#   逆 RSA 签名      = 不可能（私钥）
#   但官方 SDK / 打包器 / 默认密钥 常常是公开的
#   完整方法见 references/vendor_hunting.md
#
#   ① 从 APK 拿厂商锚点：so 名 / 包名前缀 / UUID 尾段 ASCII / DWARF 源码路径
grep -a -o -E '[a-z0-9_]{4,}/[a-z0-9_/]+\.c' lib*_c.so | sort -u | head
#   ② 搜 "<vendor> ota sdk" → docs.<vendor>.com（顺手抄包仓凭据 + 错误码表）
#   ③ 搜 "<vendor>-SDK github" → tools/secureboot/（打包器源码 + 默认密钥）
#   ④ BBS 上的《XX 使用说明》PDF（imgtool 完整参数、flash 布局）
#
#   这三处一手来源的价值 > 后面所有逆向步骤之和。

# ── 第 1 步：一秒判技术栈 + 白牌 + 芯片 + OTA 入口 ─────────────
python <A>/scripts/apk_analyze.py flutter device_app.apk

# 不是 Flutter 就走这两条
python <A>/scripts/apk_analyze.py dex    device_app.apk --keyword ota
python <A>/scripts/apk_analyze.py strings device_app.apk --keyword firmware --out fw.txt
```

**看什么**：
- `[云平台/方案]` → 白牌？（`idoocloud` / `veryfitplus` / `switchappkey`）
- `[芯片厂指纹]` → 命中多家就是通用 SDK，**不能**据此定芯片
- `[Dart 包结构]` → 有 `device_ota` / `protocol_lib` / `device_dial` 就定位到了
- `[接口路径]` → `api/ota/*` 是升级入口
- `[OTA/固件线索]` → `sendZipToFirmware` / `IDOBluetoothDfuConfig` / `otaWorkMode`

```bash
# ── 第 2 步：捞出完整 OTA 证据链（四条都要有，缺一条就是没打通）──
grep -a -o -E '(api/ota/[a-zA-Z/]+)' libapp.so | sort -u      # ① 服务端接口
grep -a -o -E '[A-Za-z]*[Ss]endZip[A-Za-z]*' libapp.so        # ② 传输函数
grep -a -o -E '[A-Za-z]*(Dfu|OTA|Ota)[A-Za-z]*' libapp.so     # ③ 状态机/回调
grep -a -o -E 'package:device_ota/[a-z_/]+\.dart' libapp.so   # ④ 模块路径
```

**四条齐了 = OTA 通道确实存在**。这时才可以谈"能不能换成自己的固件"。

```bash
# ── 第 3 步：拿固件包 ────────────────────────────────────────
curl -s -X POST "https://<device-host>/api/ota/dfu/checkUpdate" \
     -H 'Content-Type: application/json' -H 'appKey: <从抓包拿>' -d '{}'
```

多数返回 `{"status":...,"message":"appKey不存在"}`。appKey 在请求头里，
**只能从运行时抓**（`android-https-capture`）。拿到后 `otaFileUrl` 就是固件包地址。

```bash
# ── 第 4 步：判验签（只有这一步能下结论，且必须靠固件本体）──────
#   固件包拿到手后看三件事：
#   ① 加了密吗（熵、magic、是否有 header 段）
#   ② 有没有签名段（RSA 公钥、证书链、固定长度尾块）
#   ③ dfu 模块怎么校验（IDA/Ghidra 定位校验函数，看是比较 CRC 还是 verify）
#
#   ⚠ 先走 vendor_hunting：如果厂商用的是公开 SDK + 默认密钥，
#     这一步直接退化成"读官方 tools/secureboot/ 的源码"，不用逆。
#     已打通的实例（SiFli）：ble-device-recon/references/sifli_ota.md
```

**判定表**：

| 观察到 | 结论 |
|--------|------|
| 无 `api/ota/*` 且无 `sendZip*` | 无 OTA 通道，只能拆机（UART/SWD + bootloader） |
| 有通道、包能下、固件内是 `verify_rsa()` | 自制固件刷不进，通道只能用来降级/重放 |
| 有通道、包能下、固件内只有 CRC/长度校验 | 可刷自制固件，但坏包会变砖 |
| 有通道、包拿不到（需登录/设备 SN） | 卡在取证，不是卡在技术 |
| **厂商用公开 SDK + 默认密钥（交叉验证通过）** | **可复用官方工具链生成合法包；设备端是否接受仍须实测**（错误码 9 = 签名被拒） |

**结论必须这么写**（不许写死能/不能）：

> OTA 通道存在（证据：`api/ota/dfu/checkUpdate` + `sendZipToFirmware` + `device_ota` 模块）。
> 设备端验签强度**未验证**——需取得官方固件包后分析 dfu 模块。
> 在此之前，"能刷/不能刷"都属于推测。

**三个高频坑**（详见 pitfalls §8）：

1. **efuse ≠ OTA**：efuse rootkey 保护 bootloader 验 app 镜像；OTA 走固件内 dfu 模块。
   两者可能复用同一套公钥，也可能完全无关——**只有固件能回答**。
2. **芯片厂指纹命中多家**：通用协议 SDK 支持 SiFli/Nordic/Realtek/Ambiq/Telink 是常态。
   定芯片必须靠设备端（GATT UUID 尾段 / 固件内串 / 拆机丝印）。
3. **表盘和固件走同一条 zip 通道**：所以"先做个表盘试试"是验证链路成本最低的方式，
   失败了也不影响设备。优先做这个，别一上来就动固件。

---

## 通用收尾

```bash
# 汇总结论
python <A>/scripts/apk_analyze.py analyze sample.apk --json > analysis/static.json
python <R>/scripts/dex_fix.py "analysis/memdump/dex_*.bin" --json > analysis/dex_report.json
```

报告照 `SKILL.md` 第六节的七节结构写，**第 6 节"边界与未解项"不能省**。

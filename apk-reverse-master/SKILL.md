---
name: apk-reverse-master
description: APK 逆向的总调度与方法论技能。当用户给一个 APK 说"分析一下/逆向它/看看它怎么实现的/破解思路/它是不是加固了/拿不到源码怎么办"，或任务涉及多步逆向（静态初筛→加固判定→脱壳→解析→动态验证）时使用。它本身不实现具体操作，而是决定该用哪个子技能、按什么顺序、每步的验收标准是什么，并汇集了整套踩坑记录与判定阈值。触发词包括：分析 apk、逆向 apk、apk 逆向、破解分析、脱壳、加固判定、拿不到真实代码、逆向思路、apk 安全评估、这个包怎么回事。
agent_created: true
---

# APK Reverse Master（编排与方法论）

## Overview

这是一个**元技能**：不重复实现任何子能力，只负责三件事——

1. **选路**：拿到样本后判断走哪条链（静态够用？必须脱壳？要不要动态验证？）
2. **编排**：按顺序调用子技能，规定每一步的输入、输出与**验收标准**
3. **兜底**：识别"看起来成功了其实错了"的假结论（本目录 `references/pitfalls.md`）

具体干活的是这三个子技能：

| 子技能 | 角色 | 核心产出 |
|--------|------|---------|
| `apk-analyzer` | 静态初筛 + **改包** | 身份/签名/加固判定/manifest/DEX 线索/bundle 结构；AXML 改属性、重打包、v2/v3 重签 |
| `android-emulator-adb` | 连接层 | 可用设备 + `--info` 设备画像（root/ABI/toybox） |
| `apk-runtime-dump` | 运行时脱壳 | 真实 DEX / Hermes 字节码 + 可反编译副本 |

---

## 一、决策树：先判，再动

```
拿到 APK
  │
  ├─[1] apk-analyzer analyze ──────────────── 必做，10 秒
  │     产出：哈希 / 包名 / 签名 / 加固线索 / DEX 规模 / bundle / manifest.mf
  │
  ├─[1b] 若含 RN bundle：apk-analyzer bundle ─ 判是否标准未加密 HBC
  │     是 → 直接 hbcdump/hermes-dec 反汇编，**不用脱壳**
  │     否 → 才在 [4] 里加 --magic hermes 定向 dump
  │
  ├─[1c] 若含 lib/<abi>/libapp.so（Flutter）───────── 必做，1 秒
  │     → apk-analyzer flutter
  │     业务代码在 AOT snapshot 里且是明文，**不用脱壳**
  │     顺带判：云平台/方案（白牌？）+ 芯片厂指纹 + OTA 入口，见 2.5
  │
  ├─[1d] 若是硬件配套 App（手表/手环/耳机/车机）
  │     → 直接跳 playbook 剧本 F：固件 OTA 与"可刷性"分层判定
  │     目标不是找漏洞，而是**先判 OTA 通道存不存在、卡点在哪一层**
  │     ⚠ 到了"去真设备上验证 UUID / 发帧"这一步，对象已不是 APK，
  │        换 `ble-device-recon` 技能（设备发现与协议测绘），别在本技能里做
  │
  ├─[2] 判"是否加固" ──────────────────────── 见第二节判据
  │     │
  │     ├─ 否 ──→ [3a] 直接读 DEX 线索（字符串/类/URL），跳到 [5]
  │     │
  │     └─ 是 ──→ [3b] 需要真代码吗？
  │              ├─ 只要网络端点/配置/文案 → 静态 strings 往往够，跳到 [5]
  │              └─ 要看实现逻辑 → [4] 运行时脱壳
  │
  ├─[4] 运行时脱壳 ───────────────────────── 需 root
  │     4.1 emulator-adb --info          确认 root + toybox dd
  │     4.2 启动 App，稳定停住
  │     4.3 apk-runtime-dump --list      看地形
  │     4.4 apk-runtime-dump --pkg       落盘
  │     4.5 dex_fix 规范化               验收：code_off invalid=0
  │
  ├─[5] 动态验证（可选，但结论更硬）
        ├─ 5a logcat / 截屏 / UI dump  —— 确认静态推断的行为真的发生
        └─ 5b 要看真实接口 → android-https-capture ── 需 root 或改包
              5b.1 cap.py info          判该走哪条证书路（这是难点，不是抓包本身）
              5b.2 cap.py install       注入系统 CA（targetSdk≥24 必需）
              5b.3 cap.py proxy on      ⚠ 必须先启动 App 到目标页面，再开代理
              5b.4 cap.py run --daemon  抓
              5b.5 cap.py dump --grep --detail
              验收：0 TLS 错误 = 无 Pinning；部分失败 = 那些域名有 Pinning

  └─[6] 入口不可达 → 改包（最后手段，代价见 2.7）
        触发：目标 Activity 存在但 am start 报 not exported / allowBackup 关着
        6.1 先过三关：有无 manifest.mf 反篡改 / 有无签名比对 / 能否接受卸载重装
        6.2 apk-analyzer 的 axml_edit.py exported（牺牲法，不是插入属性）
        6.3 repack_apk.py + 重签 v2/v3
        6.4 adb uninstall → install → dumpsys package 验 exported
        验收：dumpsys activity activities 里 mResumedActivity 变成目标页
        ⚠ 组件在但产品流程从不调用（依赖被 R8 裁掉）→ 改包也没用，别浪费
```

**关键原则**：不要一上来就脱壳。先用静态把"值不值得脱"判断清楚——
如果只需要域名、开关、文案，`strings` 就够了，脱壳是几十分钟的事。
同理，**改包是最后手段**：它会让 App 数据全清、绑定丢失、官方升级断裂。
有抓包/脱壳能拿到同样信息时，不要改包。

---

## 二、判据（有明确阈值，别凭感觉）

### 2.1 是否加固

满足任意 2 条即可判定加固：

| 判据 | 阈值 |
|------|------|
| 存在壳 native 库 | `libDexHelper` / `libshella` / `libjiagu` / `libsecexe` / `libexec` / `libmobisec` |
| 桩 DEX 特征 | `classes.dex` 类数 < 500 且方法数 < 1000，但文件 > 10MB |
| 壳类名前缀 | `com.secneo.apkwrapper` / `com.tencent.StubShell` / `com.stub.StubApp` |
| DEX 尾部异常 | 大量重复字节填充（把文件撑大） |
| Application 类 | manifest 里的 `android:name` 指向壳类而非业务类 |

**反例警示**：一个 40MB 的 `classes.dex` 不等于"代码很多"，很可能是桩 + 填充。
必须同时看**类数/方法数**。真实业务 40MB 应该有上万类。

### 2.2 是否重签/修改版

| 判据 | 结论 |
|------|------|
| `Subject: CN=Android Debug, O=Android, C=US` | 重签版（官包不会用 debug 证书） |
| SHA1 指纹 = `949bab53...`（Android 默认 debug key） | 同上 |
| 签名 v1 存在但 v2/v3 缺失，且与官方指纹不符 | 重打包 |

### 2.3 是否 React Native + Hermes

| 判据 | 说明 |
|------|------|
| assets 里有 `index.android.bundle` / `rn/*.jsbundle` | RN |
| bundle magic = `0x1F1903C103BC1FC6`（8 字节） | Hermes 字节码 |
| `fileLength`（偏移 0x20）== 文件大小 | **标准未加密**，直接反汇编，不用脱壳 |
| `fileLength` 不符 / magic 不对 | 截断或自定义容器 → 才需要运行时 dump |
| 存在 `libhermes.so` / `libreactnativejni.so` | 运行时引擎（登录后才会加载） |

**注意**：bundle 前段熵高、后段可打印是**标准 HBC 的正常布局**，
不是"代码段加密"的证据。判加密只认 magic + fileLength。

### 2.4 是否有反重打包校验

`assets/meta-data/manifest.mf` 存在且头部含 `AndroidManifest.xml,!stamp-cert-sha256`
→ App 把**逐文件 SHA1 + 期望证书指纹**写死，运行时比对。
这类样本"改一个字节就跑不起来"，脱壳比改包划算。

### 2.5 是不是 Flutter / 是不是白牌方案

| 判据 | 结论 |
|------|------|
| `lib/<abi>/libapp.so` 存在（几十 MB）且 DEX 只有几百类 | **Flutter AOT**，业务代码全在 so 里 |
| 命中 `idoocloud` / `veryfitplus` / `switchappkey` | **白牌方案**（一套 App 套多品牌） |
| 命中 ≥3 个芯片厂（sifli/nordic/realtek/ambiq/telink…） | 通用协议 SDK，**不能**据此判芯片 |
| 命中 `device_ota` / `ota_workflow` / `sendZipToFirmware` | 该 App 有固件升级能力，见 2.6 |

**为什么重要**：白牌方案意味着背后的厂商（VeryFit/IDO、Zepp、华为运动健康等）有
成千上万同方案设备，固件格式、工具链、协议栈都是通用的。按"某品牌自研"去分析会
把可复用的东西全部重新发明一遍；按"通用方案"分析则能直接沿用别人的结论。

**芯片判定必须是双重证据**：App 里命中某芯片厂只说明 SDK 支持它。
真正定芯片要靠设备端——GATT 服务 UUID 尾段、固件内厂商串、拆机丝印。
（实例：UUID 尾段 `6473_5f696c666973` 小端解出 `sifli_sd`，才算确证 SiFli。）

### 2.6 IoT 设备"能不能刷自制固件"——分三层判，别一步下结论

这是最容易出错的地方。**"芯片有安全启动"不等于"没有升级通道"，两者是不同的事。**

| 层 | 有什么 | 能不能改 |
|----|--------|---------|
| App 层（Dart/Java） | OTA UI、下载、打包、重试逻辑 | 能改，但**改了没用**——它只是搬运工 |
| 传输层（SPP/BLE） | zip 分片、帧校验、断点续传 | 能改，能重放，但**过不了下一层** |
| **设备端 DFU** | **验签 → 刷写** | **唯一的真卡点** |

所以正确顺序是：

1. **先证通道存在**：有没有 `api/ota/*` 接口、`sendZipToFirmware` 这类传输函数。
   没有 → 只能拆机。
2. **再证包能拿到**：`otaFileUrl` 从服务器下发，通常要 appKey + 登录态 + 设备型号。
3. **最后才判验签**：这一步**必须靠固件本体**，不能靠芯片手册推测。
   - efuse rootkey 保护的是 **bootloader 验 app 镜像**；
   - OTA 走的是**固件内 dfu 模块**，可能复用同一套 RSA 公钥，也可能是简单 CRC；
   - 二者是否同一套 —— 只有解出固件才知道。

**结论写法**（不许写死"能/不能"）：

> OTA 通道存在（证据：…）。设备端验签强度**未验证**，需取得官方固件包分析 dfu 模块。
> 在拿到固件前，任何"能刷/不能刷"的判断都是推测。

### 2.7 要不要改包——先算代价，再动手

改包解决的是**"入口不可达"**，解决不了**"逻辑不在这"**。

| 想要的 | 改包有用吗 | 该用什么 |
|--------|-----------|---------|
| 启动一个 `exported=false` 的 Activity | ✅ | `axml_edit.py exported` + 重签 |
| 打开被关掉的 `allowBackup` 取数据 | ✅ | `axml_edit.py bool` |
| 某个按钮背后的网络请求 | ❌ | `android-https-capture` |
| 蓝牙到底发了什么字节 | ❌ | `ble-device-recon` 附录 A（HCI） |
| 被加固的真实代码 | ❌ | `apk-runtime-dump` |
| 组件在 manifest 里但产品从不调用 | ❌ | 放弃这条路（依赖被 R8 裁掉，叫起来也跑不完） |

**三关前置检查**，一关不过就别改：

| 关 | 检查 | 不过怎么办 |
|----|------|-----------|
| 反重打包 | `assets/meta-data/manifest.mf`、`libDexHelper`、自写 APK 哈希校验 | 转脱壳 |
| 签名校验 | DEX 里 `getPackageInfo`+`GET_SIGNATURES`、`MessageDigest` 比对 | 转脱壳 / hook |
| 代价 | 能否接受卸载重装（数据/登录/蓝牙绑定全丢、官方升级断裂） | 先找不改包的路 |

**判据口诀**（AXML 的硬事实，别试图推翻）：

> **改已有属性的值 → 生效；插入新属性 → 不生效（哪怕字节完全一致）；扩 ResourceMap → 无用。**

所以让组件导出只能"牺牲"它已有的一个无用属性（`screenOrientation` 首选）。
细节与配方在 `apk-analyzer/references/axml_patch.md`，翻车记录在 pitfalls §9。

---

## 三、交接契约（子技能之间传什么）

编排时按这个格式传递上下文，避免每次重新摸底：

```yaml
target:
  apk: <绝对路径>
  sha256: <哈希>
  package: <包名>
  signed_with: debug | official | unknown
hardening:
  packed: true | false
  shell: secneo | legu | bangcle | 360 | ijiami | none
  evidence: [<判据1>, <判据2>]
environment:
  adb: <路径>
  serial: <serial>
  root: true | false
  toybox_dd: true | false
artifacts:
  dex: [<路径>...]           # 真实 DEX（脱壳后）
  hermes: <路径> | null
  strings_dump: <路径>
next: static_analysis | runtime_dump | dynamic_verify | report
```

产出统一落在一个工作目录（建议 `<样本名>_analysis/`），报告与产物分开：

```
<sample>_analysis/
  report.md            # 最终报告
  static/              # apk-analyzer 输出（json/txt）
  memdump/             # 脱壳原始产物
  memdump/fixed/       # 规范化 DEX（给 jadx）
  logs/                # logcat / 动态证据
```

---

## 四、每步的验收标准（做完不等于做对）

| 步骤 | 验收标准 | 不达标怎么办 |
|------|---------|------------|
| 静态 analyze | 有包名、有签名指纹、有 DEX 类数 | manifest 解析失败 → 看 references/axml 解析坑 |
| 加固判定 | 至少 2 条独立判据一致 | 只有 1 条 → 补 logcat 看 `apkwrapper`/`jiagu` |
| 设备画像 | `root=true` 且 `toybox_dd=true` | 开 root 重启实例；无 root 则转 frida-gadget 路线 |
| 脱壳 | 命中 ≥1 个 DEX，且大小与业务规模相符 | 0 命中 → 检查时机/区域过滤，见 runtime-dump 排查表 |
| DEX 规范化 | `code_off invalid = 0` 且 `file_size == len` | invalid 多 → 区域被截断，用 `--region` 整段重 dump |
| 动态验证 | 静态推断的关键行为在 logcat/截屏里有对应证据 | 无证据 → 结论降级为"静态推断，未验证" |

**最重要的验收点**：`code_off invalid = 0`。这是"dump 到的 DEX 是完整的"唯一硬证据，
比"文件能打开"强得多。

---

## 五、反模式（这些做法会浪费大量时间）

| 反模式 | 为什么错 | 正确做法 |
|--------|---------|---------|
| 看到 40MB `classes.dex` 就说"代码很大" | 那是桩 + 填充 | 先数类/方法 |
| 用 4 字节 XOR "还原"Hermes 魔数并宣布能解密 | 恒等式假象；多半是魔数常量本身写错了 | 先按 8 字节校验 magic，再看 fileLength |
| 看到熵"前高后低"就说代码段被加密 | 标准 HBC 的正常布局 | 只认 magic + fileLength 自洽 |
| 在偏移 0x10 读 Hermes 的 fileLength | `sourceHash` 是 20 字节 SHA1，字段后移 | fileLength 在 `0x20` |
| 无 root 时死磕 `/proc/pid/mem` | 必然 Permission denied | 先 `--info` 确认 root，或走 frida-gadget |
| 用 `dd` 而不是 `toybox dd` | 命令不存在，静默返回空 | 设备上先 `which dd` |
| 从偏移 0 读 `/proc/pid/mem` | EIO | 按页对齐 seek |
| 用 `adb shell` 读二进制 | stderr 污染数据 | `adb exec-out sh -c ... 2>/dev/null` |
| 把内存 DEX 的 checksum 不匹配当成"dump 坏了" | 壳不重算头部，这是正常的 | 看 `code_off` 而非 checksum |
| 先算 checksum 再写 signature | 顺序反了，checksum 永远错 | 先 signature 后 checksum |
| 改成"能装上"的包再分析 | 反重打包校验会直接杀进程 | 不改包，直接脱壳 |
| 只 dump 一次就下结论 | 惰性解密的壳会缺 DEX | 多走几个界面再扫 |
| 用"芯片有 efuse 安全启动"直接判"固件刷不了" | 混淆了两条路径：efuse 保护的是 bootloader 验镜像，OTA 走固件内 dfu | 先按 2.6 查 OTA 通道，再判设备端 |
| 把 Flutter 的 DEX 类数当代码量 | Flutter 的 DEX 只有启动壳与桥接，业务全在 libapp.so | 看 `libapp.so`，走 `flutter` 子命令 |
| 在白牌方案上按"该品牌自研"分析 | 同方案设备成千上万，结论/工具链本可直接复用 | 先按 2.5 判白牌指纹 |
| 见到 `ota` 子串就当 OTA 线索 | `Annotation` / `Bogota` / `microtask` / `rotation` 全含 `ota` | 按词边界或驼峰匹配 |
| 凭 App 里命中某芯片厂就断定设备芯片 | 通用协议 SDK 同时支持多家芯片 | 靠设备端证据（UUID/固件串/丝印）二次确证 |
| 想靠"插入 AXML 属性"让组件导出 | 解析器只认 `attrExt` 里原有的记录，追加的一律忽略 | 用牺牲法（§2.7），改已有属性 |
| 把元素的 `theme` 改掉腾位置 | 若它是唯一属性，装包报 `does not specify android:name` | 只挑 `screenOrientation` 这类冗余属性，name 永不动 |
| `am start` 报 not exported 就判"功能不存在" | 那是权限问题，不是能力问题 | 改包导出，再用 `mResumedActivity` 验收 |
| 改包当成第一手段 | 签名变 → 数据/登录/绑定全丢，官方升级断裂 | 先找抓包/脱壳的路，改包最后用 |

---

## 六、报告结构（可直接套用）

```markdown
# <应用名> 逆向分析报告

## 0. 一句话结论
<它是什么 + 保护强度 + 能拿到什么>

## 1. 身份与真实性
包名 / 版本 / 哈希 / 签名指纹 / 是否重签

## 2. 保护体系
加固方案（含判据） / 反重打包 / 反调试 / bundle 加密

## 3. 静态情报
权限与组件 / 网络端点 / 第三方 SDK / 可疑字符串

## 4. 运行时脱壳（若适用）
设备画像 / 命中区域 / 产物清单（大小/类数/方法数/sha256）/ 验收结果

## 5. 关键逻辑定位
授权校验 / 检测点 / 加密入口（类名 + 方法名 + 证据）

## 6. 边界与未解项
明确写清"没拿到什么、为什么、需要什么条件"

## 7. 产物清单
```

第 6 节不能省。**把"不知道"写清楚比编一个结论有价值**。

---

## 七、参考

- `references/pitfalls.md`：完整坑库（按层分类：静态 / 连接 / 内存 / DEX / Hermes / 流量 / IoT固件 / **改包重签** / 报告）。
- `references/playbook.md`：6 条端到端剧本（普通包 / 加固包 / RN 包 / 授权定位 / 闪退排查 / **IoT 配套 App 判固件可刷性**）。
- `references/case_skland.md`：森空岛完整案例复盘（SecNeo + RN + 默认 debug 证书 + 2552 条哈希 + 登录接口抓包）。
- `references/case_watch.md`：悦心S1 智能手表复盘（Flutter + 白牌方案识别 + OTA 通道取证 + 芯片双重确证 + 改包导出未导出 Activity + 空口还原表盘协议）。
- 抓包细节（证书方案 / 坑库 / 手工兜底命令）在 `android-https-capture` 技能里，本层只做调度。
- **设备侧**（BLE 扫描 / GATT 枚举 / SPP 探测 / 帧收发）在 `ble-device-recon` 技能里。
  本技能管"从 APK 里读出协议"，那边管"到真设备上验证协议"——对象不同，别混用。

## Notes

- 本技能**不执行**具体命令，只做判断与调度；实际命令都在子技能里。
- 遇到新坑先记进 `references/pitfalls.md`，再更新判据阈值——这份文档是活的知识库。
- 无法取得结论时，宁可明确标注"环境阻断"并给出所需条件，也不要给出听起来合理的猜测。

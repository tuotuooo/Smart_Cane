---
name: apk-analyzer
description: 当用户需要分析或修改 Android APK 文件时使用——静态逆向、提取包信息、识别加固/加壳、解析 AndroidManifest、挖掘 DEX 中的授权/加密/网络线索、解析 Hermes JS bundle 的标准头部（版本/函数数/字符串数/是否真加密）并提取明文串、分析 Flutter AOT 应用（libapp.so 字符串 / Dart 包结构 / 接口路径 / 白牌方案与芯片厂指纹 / OTA 线索）、定位反重打包完整性校验、直接分析运行时脱壳产出的裸 .dex，以及**改包重签**（改 AndroidManifest 属性、让未导出的 Activity 可被 am start 调起、改 allowBackup、重打包 + v2/v3 签名）。触发词包括：分析 apk、逆向 apk、查这个安装包、apk 里有什么、提取 manifest、看看这个 app 的权限/组件/签名、bundle 是什么、hermes、flutter、dart、libapp.so、加固识别、授权校验分析、智能硬件配套 App、白牌方案、分析 dump 出来的 dex、改包、重打包、重新签名、改 manifest、未导出 Activity、exported、am start 被拒。本 skill 纯标准库实现，无需 aapt / apktool / jadx 等外部工具（签名需要 JDK + apksig.jar）。
agent_created: true
---

# APK Analyzer（无依赖静态分析）

## Overview

本 skill 提供一套**纯 Python 标准库**实现的 APK 静态分析能力，目标是本机没有
`aapt` / `apktool` / `jadx` 时也能对 APK 做扎实的逆向初筛。覆盖：文件哈希、包结构
盘点、AndroidManifest 解析、DEX 字符串/类/URL/关键词挖掘、签名证书提取、Hermes JS
bundle 的**标准头部解析**（版本 / 函数数 / 字符串数 / `fileLength` 自洽性 → 判断是否
真的加密）与明文串提取、反重打包完整性清单（manifest.mf）解码，以及**裸 .dex 直接
分析**（接运行时脱壳产物）。

它和 `apk-runtime-dump` 形成闭环：本 skill 做**静态初筛与判定**，后者在加固样本上把
真实 DEX 从内存取出来，再交回本 skill 的 `dexfile` 子命令继续挖。

除"读"之外，本 skill 还提供**"写"**的能力：改 `AndroidManifest.xml` 的二进制属性、
重打包、v2/v3 重签。它的用途很明确——**让不可达的入口变得可达**
（未导出的 Activity、被关掉的 allowBackup）。要不要走这条路、会不会被反篡改打死，
决策在 `apk-reverse-master`；这里只负责把字节改对。

## When to Use

- 用户丢来一个 `.apk`，要快速知道它是谁、做什么、是否加固/破解版。
- 需要解析 AndroidManifest（包名、权限、四大组件、LAUNCHER 入口）。
- 要在 DEX 中找授权/激活/加密/网络端点等线索（KMS 激活器、License 类样本尤其适用）。
- 样本是 React Native + Hermes，JS bundle 被加密，要分析其容器结构并提取明文串。
- 要识别加固/加壳（SecNeo、腾讯乐固 legu、梆梆、360 等）与自建反重打包校验。

## Quick Start

核心脚本 `scripts/apk_analyze.py`，子命令如下（`<apk>` 为 apk 路径）：

```bash
# 完整静态报告（人类可读；加 --json 输出结构化 JSON 供程序解析）
python <skill>/scripts/apk_analyze.py analyze <apk> [--json]

# 仅解析 AndroidManifest.xml（包名/权限/组件/launcher 入口）
python <skill>/scripts/apk_analyze.py manifest <apk> [--json]

# DEX 字符串/类/URL/关键词分组统计（--keyword 仅看指定词）
python <skill>/scripts/apk_analyze.py dex <apk> [--json] [--keyword hermes] [--keyword kms]

# 提取 dex + 明文 assets 的全部可打印字符串，可按关键词过滤并写出文件
python <skill>/scripts/apk_analyze.py strings <apk> [--keyword license] [--keyword kms] [--out strings.txt]

# 解析 Hermes bundle 标准头部：版本/函数数/字符串数/fileLength 自洽 → 判断是否真加密
python <skill>/scripts/apk_analyze.py bundle <apk> [--json]

# 【Flutter】libapp.so 字符串 + Dart 包结构 + 接口路径 + 白牌方案/芯片厂指纹 + OTA 线索
python <skill>/scripts/apk_analyze.py flutter <apk> [--json] [--keyword ota]

# 直接分析裸 .dex（运行时脱壳产物，无需原始 APK）
python <skill>/scripts/apk_analyze.py dexfile "memdump/dex_*.bin" [--keyword license] [--out hit.txt] [--json]

# 【JS 层】把 hermes-dec 的反汇编文本索引成业务情报（字符串→函数、域名、API、关键词分组）
python <skill>/scripts/hbc_index.py main.disasm.txt -o js_out/

# 【DEX 定点追踪】字符串 → 引用它的方法 → 反汇编；纯标准库，不需要 JRE/jadx
python <skill>/scripts/dex_tool.py str    <dex> "Game signature"   # 谁引用了这个字符串
python <skill>/scripts/dex_tool.py method <dex> "Lo0/w;" i         # 反汇编匹配的方法
python <skill>/scripts/dex_tool.py xref   <dex> "checkDeviceRoot"  # 谁调用了这个方法
```

### 改包重签（另一组命令，改的是 APK 本体）

```bash
# 看 manifest 结构：节点 span 索引 + 每个属性的类型/值/字节偏移
python <skill>/scripts/axml_edit.py dump AndroidManifest.xml

# 改一个已存在的布尔属性（如 allowBackup）
python <skill>/scripts/axml_edit.py bool in.xml out.xml --tag application --attr allowBackup --value false

# 让未导出的 Activity 可被 am start 调起（牺牲一个无用属性，见 references/axml_patch.md）
python <skill>/scripts/axml_edit.py exported in.xml out.xml --tag WallpaperImageGridActivity

# 塞回 APK（保留 STORED 条目、剔除旧签名）
python <skill>/scripts/repack_apk.py app.apk out.apk --manifest out.xml

# 重签（v1+v2+v3；apksig.jar 取自 Android SDK build-tools/lib 或 maven）
javac -cp apksig.jar -d . <skill>/scripts/Sign.java
java  -cp apksig.jar:. Sign out.apk out_signed.apk debug.keystore debug android
```

> `dex_tool.py` 用于回答"这个字符串/方法到底是谁在用"——判 root 检测、反调试、硬编码密钥
> 归属时**必须**做这一步，否则会把第三方 SDK 的行为错算成业务代码（坑见
> `apk-reverse-master/references/pitfalls.md` §3.5 / §4.5）。
> 它已内置本样本的 `invoke AA >> 4` 修正；换样本若出现 argc=16/32 这类异常，先按 §4.5 复核再改。

退出码：0=成功；非 0=APK 不存在或 Manifest 解析失败（写入 stderr）。

## 典型工作流

1. **身份与真实性**：先 `analyze`，看 `[1] 哈希` / `[3] Manifest 包名版本` / `[5] 签名证书`。
   - 若 `Subject` 是 `CN=Android Debug, O=Android, C=US` 且 SHA1 固定为
     `949bab53…` / SHA256 `111052ab…`，说明是**重签/修改/破解版**（官包不会用默认 debug 证书）。
2. **加固/加壳识别**：看 `[4] DEX 线索` 里的 `legu / DexHelper / shell / jiagu` 关键词，
   以及原生库是否含 `libDexHelper`、`libshell`、`libmsaoaid` 等；动态 logcat 抓
   `apkwrapper` / `secneo` 基本可坐实商用加固（如 SecNeo）。详见 references。
3. **授权/激活线索**：`dex` 与 `strings` 子命令按 `license / kms / activate / token /
   sign / auth / oauth / grant` 等关键词过滤，结合 `[4]` 列出的候选网络域名锁定
   授权服务器与校验逻辑。
4. **Hermes bundle 判定**：`[6]` 现在直接解析**标准 Hermes 头**（`sourceHash` 是 20 字节
   SHA1，所以 `fileLength` 在 0x20 处）。看两个字段：
   - `标准未加密 HBC: True` + `fileLength 匹配=True` → **这是普通未加密字节码**，
     可以直接用 hbc 反汇编工具还原 JS，**不需要**脱壳、也不需要"解密"。
   - `标准未加密 HBC: False` → 头部不是标准魔数，可能是自定义容器。此时熵剖面只作结构参考；
     **绝对不要**用 `header XOR 魔数` 推导密钥（那是恒等式假象，已实测 entropy 不降反升）。
     取真实字节码应走运行时 dump（`apk-runtime-dump`）。
   - 无论哪种情况，`plaintext_str_count` 的明文串（域名、RN 组件名、错误文案）都能直接用。
5. **反重打包校验**：`[7]` 完整性清单若识别到 `AndroidManifest.xml,!stamp-cert-sha256`，
   说明 App 把期望的签名证书指纹与逐文件哈希写死在 `assets/meta-data/manifest.mf`，
   运行时比对防篡改——这正是 License/防破解绑定的典型实现。
6. **衔接动态分析**：把同一 apk 交给 `android-emulator-adb` skill 安装到模拟器，抓取
   logcat 验证静态发现的授权/加密/壳行为是否真的触发。
7. **脱壳产物回炉**：运行时 dump 出的裸 DEX 用 `dexfile` 子命令直接分析，无需原始 APK：
   `python <skill>/scripts/apk_analyze.py dexfile "memdump/dex_*.bin" --keyword license`
8. **JS 层深挖（确认未加密后）**：两步走，反汇编用外部工具，索引用本 skill。
   ```bash
   # ① 反汇编（hermes-dec，AGPL-3.0，纯标准库；自带 hbc51~hbc99 opcode 表）
   PYTHONPATH=<hermes-dec>/src python -m hermes_dec.disassembly.hbc_disassembler \
       main.jsbundle > main.disasm.txt
   # ② 索引成业务情报
   python <skill>/scripts/hbc_index.py main.disasm.txt -o js_out/
   ```
   产出 `endpoints.txt`（域名/API）、`keyfuncs.txt`（按 auth/risk/network/storage/update/deeplink
   分组定位到**具体函数号**）、`strings_all.txt`、`summary.json`。拿到函数号后直接
   `grep "\[Function #N"` 读该函数指令序列。
   - 想找"环境配置/接口基址"，优先看引用了多个域名、且带 `ENV / prod / dev / staging` 字样的函数。
   - 想找"是否有反 root 检测"，在 JS 里搜 `frida/magisk/xposed/tamper/safetynet`；若只命中
     `isRoot`，注意那多半是 **mobx-state-tree 的节点 API**（`protect()` 会报
     "can only be invoked on root nodes"），与设备 root 无关。

9. **Flutter 应用**：`analyze` 的 `[4]` 里如果 DEX 类数少得离谱（几百类）而包体积几十上百 MB，
   且存在 `lib/*/libapp.so`，那就是 Flutter。此时 **`dex` 子命令几乎挖不到业务代码**，
   必须走 `flutter` 子命令——业务字符串全在 AOT snapshot 里，而且是明文的：
   ```bash
   python <skill>/scripts/apk_analyze.py flutter app.apk
   ```
   关注四块输出：
   - **`[云平台/方案]`** 命中 `idoocloud` / `veryfitplus` / `switchappkey` 之类 →
     **白牌方案**（一套 App 套多个品牌）。同方案设备、固件、工具链大概率可复用，
     后续策略要按"通用方案"而非"该品牌自研"来做。
   - **`[芯片厂指纹]`** 命中多家（≥3）时**不要**挑一个写进报告——那是通用协议 SDK
     （`protocol_c` 一类）支持多平台的证据，不是设备芯片。实际芯片必须靠设备端证据
     （GATT UUID 里的厂商标识、固件内串、拆机丝印）二次确证。
   - **`[Dart 包结构]`** 用 `package:xxx/yyy.dart` 反推功能模块，比读汇编快一个数量级。
     看到 `device_ota` / `device_dial` / `protocol_lib` 就直接定位到 OTA、表盘、协议层。
   - **`[接口路径]` / `[OTA/固件线索]`** 给出服务端 API 全貌与固件升级入口。

10. **改包（让不可达入口变可达）**：典型场景是"manifest 里这个 Activity 明明存在，
    但 `am start` 报 `not exported from uid`"。
    ```bash
    python <skill>/scripts/axml_edit.py dump AndroidManifest.xml      # 找 span 索引
    python <skill>/scripts/axml_edit.py exported in.xml out.xml --tag <类名结尾>
    python <skill>/scripts/repack_apk.py app.apk out.apk --manifest out.xml
    # 重签后 adb install -r -d
    ```
    **三条硬约束**（踩过一整轮才确认，详见 `references/axml_patch.md`）：
    - **改已有属性的值 → 生效；插入全新属性 → 不生效**，字节级与已有属性一致也没用。
      所以 `exported` 只能靠"牺牲"该元素上一个无用属性（`screenOrientation` 首选）实现。
    - **ResourceMap 不能扩**（原文件 54 项，扩到与字符串池等长无任何行为变化）。
    - **元素的 `android:name` 不能动**，否则装包报 `does not specify android:name`。
    验收：`dumpsys activity activities` 里 `mResumedActivity` 变成目标 Activity。

## Reference

- 加固识别、Hermes 头部字段布局、manifest.mf 私有格式、证书指纹对照、无依赖分析方法论：
  见 `references/apk_static_analysis.md`。脚本自动覆盖多数场景；需人工排查时加载。
- **AXML 改包与重签**：`references/axml_patch.md`。含改包的三关前置检查、属性记录布局、
  "改值生效/插入无效"的对照实验、牺牲法配方、签名方案选择、副作用清单与坑表。
  先读它再动 `axml_edit.py`。

## Notes

- **无外部依赖**：仅用 Python 标准库，本机只需有 Python 3.8+。
- 证书解析优先用 `cryptography` 库（可给出 Subject/Issuer/有效期）；未安装时回退到
  仅输出 SHA1/SHA256 指纹，不影响结论。
- **关于 Hermes**：判断"是否加密"的唯一可靠依据是**标准魔数 + fileLength 自洽**，
  不是熵、不是 header XOR。历史上这里栽过三次跟头（错误的魔数常量 → 虚构的 XOR 密钥 →
  虚构的"双区加密容器"），脚本已改为按标准头部字段判定。
- `bundle` 只做**结构判定**。真正的反汇编需外部 `hermes-dec` / `hbcdump`；反汇编后的
  **索引与业务归类由本 skill 的 `hbc_index.py` 完成**（纯标准库）。
- **不要用裸打印扫描取 Hermes 字符串**：HBC 的 string storage 是连续拼接的，按可打印区间
  切分会把相邻串粘成一条，造出 `oauth2` / `one_login` / `geetest` 这类**看似合理但 0 命中**的
  假串（已实测证伪）。要拿准确字符串，走字符串表（`hermes-dec` 反汇编注解 / `hbc_index.py`）。
- **Flutter 字符串也有粘合坑**：`libapp.so` 里的串同样是按 snapshot 布局连续存储的，
  按可打印区间切分可能把相邻串粘成一条（与 Hermes 那个坑同源）。脚本已按
  "词边界 + 结构特征"过滤常见噪音，但**关键结论（域名 / 接口名）仍要在原始字节里
  `count()` 确认**。另外 `ota` 必须按词匹配——`Annotation`、`Bogota`、`microtask`、
  `rotation` 全都含 `ota` 子串，字面包含会造出一堆假线索。
- **Flutter 的 DEX 是幌子**：Flutter 应用照样有 `classes.dex`，但里面只有启动壳和
  MethodChannel 桥接。用 DEX 类数判断"代码量"在 Flutter 上完全失效。
- 本 skill 只做**静态**分析。HTTPS 抓包、内存脱壳、jadx 反编译等需配合其他工具。
- **改包是有代价的**：签名变了 → 必须卸载重装 → App 数据/登录态/蓝牙绑定全丢，
  且之后装不上官方增量更新。动手前先确认"有没有不改包也能拿到同样信息的办法"。
  判定能不能改（反重打包、签名校验）在 `apk-reverse-master` §2.4 与 pitfalls §9。
- **`exported` 不是加上就一定跑得起来**：`am start` 不报 `SecurityException` 只证明导出生效，
  页面内部可能立刻崩或自杀。唯一硬证据是 `mResumedActivity`。

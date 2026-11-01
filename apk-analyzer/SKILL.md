---
name: apk-analyzer
description: 当用户需要分析 Android APK 文件时使用——静态逆向、提取包信息、识别加固/加壳、解析 AndroidManifest、挖掘 DEX 中的授权/加密/网络线索、解析 Hermes JS bundle 的标准头部（版本/函数数/字符串数/是否真加密）并提取明文串、定位反重打包完整性校验、以及直接分析运行时脱壳产出的裸 .dex。触发词包括：分析 apk、逆向 apk、查这个安装包、apk 里有什么、提取 manifest、看看这个 app 的权限/组件/签名、bundle 是什么、hermes、加固识别、授权校验分析、分析 dump 出来的 dex。本 skill 纯标准库实现，无需 aapt / apktool / jadx 等外部工具。
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

# 直接分析裸 .dex（运行时脱壳产物，无需原始 APK）
python <skill>/scripts/apk_analyze.py dexfile "memdump/dex_*.bin" [--keyword license] [--out hit.txt] [--json]
```

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

## Reference

- 加固识别、Hermes 头部字段布局、manifest.mf 私有格式、证书指纹对照、无依赖分析方法论：
  见 `references/apk_static_analysis.md`。脚本自动覆盖多数场景；需人工排查时加载。

## Notes

- **无外部依赖**：仅用 Python 标准库，本机只需有 Python 3.8+。
- 证书解析优先用 `cryptography` 库（可给出 Subject/Issuer/有效期）；未安装时回退到
  仅输出 SHA1/SHA256 指纹，不影响结论。
- **关于 Hermes**：判断"是否加密"的唯一可靠依据是**标准魔数 + fileLength 自洽**，
  不是熵、不是 header XOR。历史上这里栽过三次跟头（错误的魔数常量 → 虚构的 XOR 密钥 →
  虚构的"双区加密容器"），脚本已改为按标准头部字段判定。
- `bundle` 只做结构判定与明文串提取。要真正反汇编 Hermes 字节码，需外部的
  `hbcdump` / `hermes-dec`（本 skill 不实现）。
- 本 skill 只做**静态**分析。HTTPS 抓包、内存脱壳、jadx 反编译等需配合其他工具。

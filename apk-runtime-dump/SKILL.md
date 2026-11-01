---
name: apk-runtime-dump
description: 当 APK 被加固/加壳（SecNeo 盛安德、腾讯乐固、梆梆、360、爱加密等）导致静态拿不到真实代码时，用纯 root 从运行中的进程内存里把解密后的 DEX / CDEX / Hermes JS bundle 抠出来，并修复头部校验使其可被 jadx/baksmali 直接反编译。触发词包括：脱壳、dump dex、内存 dump、加固怎么破、真实 dex、拿不到源码、SecNeo、apkwrapper、dexhelper、Hermes 提取、/proc/pid/mem、从内存里挖代码。不需要 Frida、不需要 apktool、不需要改包，只要设备有 root。
agent_created: true
---

# APK Runtime Dump（root 内存脱壳）

## Overview

商用加固把真实 DEX 加密存在 APK 里，运行时才解密并 `mmap` 进匿名内存。所以
**静态分析永远拿不到真代码，但它们一定在内存里明文躺着**。

本 skill 用最轻的方式把它取出来：`adb root` + 读 `/proc/<pid>/mem`。
不注入、不重打包、不依赖 Frida——加固壳的自身完整性校验完全感知不到。

四件套定位：`apk-analyzer`（静态初筛）→ `android-emulator-adb`（连接/启动）→
**本 skill**（把真代码取出来）→ `apk-reverse-master`（编排与方法论）。

## When to Use

- `apk-analyzer` 报告显示已加固（`libDexHelper` / `libshell` / `apkwrapper` / 巨大桩 DEX），
  但你需要看真实业务代码。
- 反编译 APK 出来的 `classes.dex` 只有几百个类、几十个方法，明显是壳的桩。
- React Native 应用要取 Hermes 字节码（`libhermes.so` 已加载）。
- 需要在运行时抓某个解密后的中间产物（不只是 DEX）。

## 前置条件（先自查，不然一定失败）

```bash
# 一条命令确认：root / toybox dd / 包已安装 / ABI
python <android-emulator-adb>/scripts/find_and_connect.py --info --human
```

三个硬条件，缺一不可：

| 条件 | 检查 | 不满足的后果 |
|------|------|------------|
| `adb shell id` 是 `uid=0` | `--info` 的 `root` 字段 | 读 `/proc/pid/mem` 直接 Permission denied |
| `toybox dd` 存在 | `--info` 的 `toybox_dd` 字段 | 无法按偏移读内存 |
| 目标进程在跑 | `adb shell pidof <pkg>` | 没有内存可读 |

> 雷电：设置里勾 root 后**必须重启实例**。

## Quick Start

```bash
# 0. 启动 App（加固样本可能需要停在某个界面，见下文"时机"）
python <android-emulator-adb>/scripts/find_and_connect.py -- shell am start -n com.pkg/.SplashActivity

# 1. 先看地形：候选区域 + 尺寸（不读内存，秒出）
python <skill>/scripts/apk_runtime_dump.py --pkg com.pkg --list

# 2. 扫描并抠出制品（默认找 dex/cdex/hermes）
python <skill>/scripts/apk_runtime_dump.py --pkg com.pkg --out ./memdump

# 3. 修复 DEX 头部校验，产出可反编译副本
python <skill>/scripts/dex_fix.py "./memdump/dex_*.bin" --out-dir ./memdump/fixed
```

常见变体：

```bash
# 只要 Hermes（RN 应用）
python .../apk_runtime_dump.py --pid 1234 --magic hermes

# 已知某区域有货、但 magic 不在头部 → 强制整段 dump
python .../apk_runtime_dump.py --pkg com.pkg --region 0x7c37c3a00000-0x7c37c9e00000

# 只要 JSON 摘要（含每个制品的区域/偏移/sha1）
python .../apk_runtime_dump.py --pkg com.pkg --json
```

退出码：`0`=执行成功（0 命中也算）；`2`=进程不存在/参数缺失；`3`=找不到 adb。

## 它是怎么工作的

```
/proc/<pid>/maps
      │  筛：可读 + 非文件映射 + 1MB~400MB
      ▼
  候选区域（典型几十~几百个，其中 95% 是分配器空转）
      │  每区只读头部 64KB，找 magic
      ▼
  命中区 → 整段读出 → 区内按 magic + 头部 file_size 精确裁剪
      ▼
  dex_<sha1>.bin / hermes_<sha1>.bin
```

三个 magic：

| 类型 | magic | 说明 |
|------|-------|------|
| DEX | `dex\n035`~`039` | 标准可执行 DEX，最常见 |
| CDEX | `cdex001\0` | 紧凑型 DEX（Android 9+，部分 ROM） |
| Hermes | `c6 1f bc 03` | RN 字节码 bundle |

DEX 有效性的判据不是"找到 magic"，而是**头部 `0x20` 处的 `file_size` 自洽**
（0x70 ≤ size ≤ 300MB 且不超出区域），脚本已按此过滤误命中。

## 读结果

- 一个 APK 通常有 **多个 DEX**（multidex），全部都会命中，都要留。
- `memdump/dex_*.bin` 是**原始 dump**：内容完整但头部 checksum/signature 是旧值。
- 跑 `dex_fix.py` 得到的 `*_fixed.dex` 才是给 jadx/baksmali 的输入。
- `dex_fix.py` 同时报 `code_off: valid/invalid`——**invalid=0 是"这个 DEX 结构完整"的硬证据**；
  若有大量 invalid，说明区域被截断或 dump 时机太早。

## 时机：什么时候 dump 最有效

加固壳的解密时机各不相同，**dump 早了只有壳、dump 晚了可能被杀**：

1. **优先在 App 稳定停住的界面 dump**（启动页/登录页）。此时壳早已解完 DEX，
   且业务逻辑还没触发反调试。
2. **如果 App 检测 root 会闪退**：不要等它自己崩。启动后立刻 `pidof` 拿 pid，
   脚本一命中就落盘；也可以先 `adb shell am force-stop` 再重启，赶在检测定时器之前。
3. **Hermes bundle 先别急着 dump**。先用 `apk-analyzer bundle` 看 assets 里那份是不是
   标准未加密 HBC（magic `c61fbc03c103191f` + `fileLength` 与文件大小一致）。
   - 是 → **静态就能反汇编，不需要脱壳**；
   - 否（自定义容器/加密）→ 等 RN 页面加载后 dump。判据：
     `adb shell "grep -c hermes /proc/$(pidof com.pkg)/maps"`，为 0 就是引擎还没初始化。
4. 有些壳**惰性解密**（用到哪个类解哪个）。只 dump 一次可能缺 DEX，多走几个界面再扫。

## 已知边界

- **只对 root 有效**。无 root 时这条路完全不通，只能 frida-gadget 重打包（需要 apktool）。
- **拿不到方法体的语义**：dump 出的是 DEX，能反编译成 Java 伪码；但被 native 化的核心
  逻辑（SecNeo 的 `libDexHelper` 内部）仍在 `.so` 里，需要另外的 IDA/Ghidra 流程。
- **反调试/反 dump 强的壳**（如某些梆梆版本）会 `mprotect` 掉或延迟解密，可能扫不到。
  此时换 Frida 在 `InMemoryDexClassLoader` / `DexFile.loadDex` 处 hook 更可靠。
- **不能用于绕过授权**：本 skill 只做代码提取。

## Reference

- `references/runtime_unpack.md`：`/proc/pid/mem` 读取的 EIO/页对齐原理、toybox 与 toolbox
  的区别、DEX 头部校验为何失配、Hermes 头部字段布局与"先判要不要 dump"、各类壳的行为特征、失败排查表。

## Notes

- 全程只读，不修改设备与目标进程；产物落在本地目录。
- 一个区域可能同时含多个 DEX（连续 mmap），脚本会全部切出并按 SHA1 去重。
- 读内存是最慢的一步（百 MB 级），先 `--list` 再定向 `--region` 能省很多时间。

---
name: android-emulator-adb
description: 当用户需要连接安卓模拟器、在运行中的模拟器上安装/分析 APK、抓取 logcat 运行时日志、提取应用数据（数据库/SharedPreferences）、截取屏幕或对模拟器执行 ADB UI 自动化时使用。触发词包括：连接模拟器、连接安卓、连上雷电、安装 apk 到模拟器、抓日志、动态分析、adb、模拟器截图、提取应用数据、检查手机/模拟器有没有 root。本 skill 自动定位 adb 客户端（优先模拟器自带）、探测并连接常见模拟器（雷电/夜神/MuMu/BlueStacks/Android Studio），并能一键给出设备画像（ABI/SDK/root/su/toybox dd//system 可写性）。它是「APK 逆向四件套」的连接层。
agent_created: true
---

# Android Emulator ADB Bridge（连接层）

## Overview

本 skill 是 **APK 逆向四件套**中的**连接层**，只负责一件事：把「找到 adb → 连上模拟器 →
在设备上执行命令」这条最容易反复踩坑的链路固化下来。

- 自动定位 adb 可执行文件（PATH、Android SDK、各模拟器自带目录）
- 探测常见模拟器 ADB 端口并连接（雷电/夜神/MuMu/BlueStacks/Android Studio）
- 把任意 adb 子命令**透传**到主设备，自动补 `-s <serial>`
- `--info` 一键画像：**这台机器现在到底能不能做需要 root 的事**

配套技能：
`apk-analyzer`（静态）→ **本 skill**（连接/动态）→ `apk-runtime-dump`（root 脱壳）→
`apk-reverse-master`（编排与方法论）。

## When to Use

- 用户要求「连接安卓模拟器 / 连上雷电 / 连上我的模拟器 / 连上安卓」。
- 需要确认设备状态：有没有 root、ABI 是什么、`su` 在哪、能不能读 `/proc`。
- 需要在模拟器上安装、卸载、清数据、运行 APK。
- 需要抓 logcat、截屏、`/data/data` 取数、点击/输入/滑动。
- 任何 adb / 模拟器调试任务。

## Quick Start

```bash
# 发现 + 连接（JSON，供程序解析）
python <skill>/scripts/find_and_connect.py

# 人类可读
python <skill>/scripts/find_and_connect.py --human

# 设备画像：root / ABI / SDK / su 路径 / toybox dd / /system 可写性
python <skill>/scripts/find_and_connect.py --info --human
```

退出码：`0`=成功；`2`=未找到任何 adb 客户端；`3`=找到 adb 但无在线设备（模拟器没启动）。

## 设备画像怎么读

`--info` 输出的关键字段，直接决定后续能不能脱壳：

| 字段 | 含义 | 影响 |
|------|------|------|
| `root: YES (uid=0)` | adb shell 已是 root（`context=u:r:su:s0`） | 可读 `/proc/<pid>/mem` → 能内存脱壳 |
| `su` | `su` 是否在 PATH，以及候选路径 | App 的 root 检测主要就查这些路径 |
| `toybox dd: 可用` | 有 toybox 的 `dd` | **没有它就无法读 `/proc/pid/mem`**（toolbox 的 dd 不可用） |
| `/system: 只读(dm-verity)` | 真实写探针结果 | 只读则**不能**改名/删除 `su`，root 隐藏只能走 hook |
| `ro.debuggable` / `tags` | 构建属性 | `1` / `test-keys` 是 App 的常见检测点 |

**注意**：`/system` 可写性必须用真实写探针。动态分区设备上
`mount -o remount,rw /system` 会返回 `mount: '/system' not in /proc/mounts`——
这句话里**没有** "read-only" 字样，靠字符串匹配会误判成"可写"。脚本已改用
`touch /system/bin/.adbwrite` 探针。

## Common Tasks

所有任务用透传，不要手拼 adb 路径——脚本会自动补 `-s <primary>`。

```bash
# 装包并预授全部权限（逆向样本必用 -g，避免权限弹窗打断）
python find_and_connect.py -- install -g C:/path/app.apk

# 重置到全新状态
python find_and_connect.py -- shell pm clear com.pkg

# 抓日志（先清再抓，过滤关键词）
python find_and_connect.py -- logcat -c
python find_and_connect.py -- logcat -d

# 截屏并拉回
python find_and_connect.py -- shell screencap -p /sdcard/s.png
python find_and_connect.py -- pull /sdcard/s.png .

# 交互
python find_and_connect.py -- shell input tap 500 500
python find_and_connect.py -- shell input text "hello"

# 解析 launcher 入口（找启动 Activity 的正确方式）
python find_and_connect.py -- shell cmd package resolve-activity --brief com.pkg

# 启动并观察存活（判断是否闪退）
python find_and_connect.py -- shell am start -n com.pkg/.SplashActivity

# 指定设备时自己带 -s，脚本不会重复添加
python find_and_connect.py -- -s 127.0.0.1:5555 shell pm list packages
```

## 雷电（LDPlayer）专项

雷电是最常用也最容易踩坑的模拟器，要点：

1. **用雷电自带的 adb**：`C:\leidian\LDPlayer14\adb.exe`。系统 SDK 的 adb 版本不匹配时
   设备会显示 `offline`。
2. **端口**：主实例 `127.0.0.1:5555`；有时同时存在 `emulator-5554`，两条通道指向同一实例。
3. **开 root 要重启实例**：设置里勾选 root 后必须重启模拟器，`adb root` 才会生效。
   重连后 `adb shell id` 应显示 `uid=0(root) ... context=u:r:su:s0`。
4. **`adb root` 报 "adbd cannot run as root in production builds"** = 没开 root（不是 adb 问题）。
5. **`/system` 只读**：雷电是动态分区 + dm-verity，`/system/bin/su` 改不了名。
   想对 App 隐藏 root，只能做 Java/native hook，不能靠删文件。
6. **不要用 `su -c`**：`adb root` 之后 shell 本身就是 root，`su` 反而可能不存在或行为异常。

## Reference

- `references/emulator_ports.md`：端口/路径权威对照、adb 版本不匹配（offline）处理、
  root 与只读分区处理、命令速查、动态分析标准工作流。自动发现失败时先看这里。

## Notes

- 优先用模拟器自带 adb（版本最匹配），避免设备 `offline`。
- 同时存在多个在线设备时，`primary_device` 取第一个 `device` 状态的；需要精确控制就自带 `-s`。
- 本 skill 只管连接与设备操作。HTTPS 抓包需 mitmproxy/Charles；内存脱壳见
  `apk-runtime-dump`；静态分析见 `apk-analyzer`。

---
name: android-https-capture
description: 当用户要在 Android 真机/模拟器上抓 HTTPS 请求、分析 App 登录接口、查看请求报文、配置 mitmproxy/Charles 抓包、安装系统级 CA 证书、排查 TLS 解密失败或 SSL Pinning 时使用。触发词包括：抓包、抓请求、拦截请求、看登录接口、分析接口、HTTPS 抓包、抓流量、装证书、系统证书、mitmproxy、Charles、Fiddler、SSL Pinning、证书固定、解密 HTTPS。本 skill 会先探测设备（SDK/root/Magisk/APEX/写探针）判定该走哪条证书路，再一键完成 CA 生成、系统证书注入、adb reverse 代理、mitmdump 抓包和 flows 解析导出。Android 14 无 Magisk 的 APEX bind mount 方案已实测可用。
agent_created: true
---

# Android HTTPS Capture（抓包层）

## Overview

把「Android 抓 HTTPS」这条链路固化下来。它的难点从来不是 mitmproxy 本身，
而是**证书怎么装进系统信任区**——`targetSdk >= 24` 的 App 默认不信任用户证书，
而 Android 10+ 又是动态分区，`/system` 根本 remount 不了。

本 skill 的核心是**先探测再决策**：

```
设备画像(SDK/root/Magisk/APEX/写探针) → 选证书方案 → 注入 → adb reverse → 抓 → 解析
```

配套技能：`android-emulator-adb`（连接层）、`apk-analyzer`（静态层，
抓包前先用它看 `targetSdk` 和 `networkSecurityConfig`）。

## When to Use

- 用户说「抓包 / 抓一下请求 / 看看它登录接口长什么样 / 分析这个接口」。
- 需要看 App 的请求报文、请求头、签名参数、加密字段。
- 已装 mitmproxy/Charles 但 App 报网络错误、抓不到 HTTPS。
- 需要在 Android 14/15 这种无 Magisk 的 root 设备上装系统证书。

## 核心决策表（先看这张表，别上来就装）

| 条件 | 方案 | 说明 |
|------|------|------|
| `targetSdk < 24` | **用户证书** | 装到用户证书区即可，`cert.cer` 直接 install |
| `sdk < 24` | **用户证书** | 系统默认信任用户 CA |
| root + **Magisk** | **Magisk 模块** | 最持久，重启不丢；见 `references/cert_paths.md#magisk` |
| root + 无 Magisk + 有 APEX | **APEX bind mount** | Android 10+ 动态分区设备**实测唯一可行**的路 |
| root + `/system` 可写 | **落盘** `/system/etc/security/cacerts` | 老设备（≤ Android 9）常见 |
| 无 root | **改包** | `apk-mitm` / 加 `network_security_config` 重签 / frida 绕 pinning |

`cap.py info` 会自动跑完这段判定并直接告诉你结论。

## 快速开始

```bash
S=~/.workbuddy/skills/android-https-capture/scripts/cap.py

# 1) 先看设备，确认走哪条路（不需要 root 也能跑）
python $S info --pkg com.example.app

# 2) 生成 CA（首次会拉起 mitmdump 生成，之后复用）
python $S ca

# 3) 注入系统证书区（自动按方案分发；幂等，可重复跑）
python $S install --pkg com.example.app

# 4) ***先把 App 启动到目标页面***，再开代理（顺序不能反，见坑 1）
python $S proxy on

# 5) 抓包（daemon 模式，日志和 pid 落到 confdir）
python $S run --daemon

# 6) 在设备上操作 App，触发你要的请求
#    然后解析 —— 总览 / 按内容过滤 / 完整报文 / 导出 markdown
python $S dump flows.mitm
python $S dump flows.mitm --grep login --detail
python $S dump flows.mitm --host api.example.com --md capture.md

# 7) 收工
python $S proxy off
python $S uninstall          # 撤掉证书，系统恢复原状
python $S stop               # 停 mitmdump
```

全局参数放在子命令**前面**：`cap.py --confdir /path --serial xxx info`。

## 脚本速查

`scripts/cap.py`：

| 子命令 | 作用 | 关键输出 |
|--------|------|----------|
| `info` | 设备画像 + 判定方案 | 设备/SDK/root/Magisk/APEX/targetSdk + 结论 |
| `ca` | 生成或复用 mitmproxy CA | `subject_hash_old` 文件名（如 `c8750f0d.0`） |
| `install` | 注入系统证书区 | `BEFORE=n AFTER=n+1` |
| `uninstall` | 卸载 + 清理 | 恢复原始证书数 |
| `proxy on\|off\|status` | adb reverse + `http_proxy` | 当前 reverse 表与全局代理 |
| `run [--daemon]` | 启动 mitmdump | `flows.mitm` + pid 文件 |
| `stop` | 停 daemon | — |
| `dump` | 解析 flows | 总览 / `--detail` 报文 / `--grep` 过滤 / `--md` 导出 |

依赖：`mitmproxy`（含 `cryptography`）、`adb`。
装 mitmproxy 用**阿里云源**——清华源里没有这个包：

```bash
python -m pip install mitmproxy -i https://mirrors.aliyun.com/pypi/simple/
```

## 关键坑（按踩到的频率排序，全部实测）

### 1. 带代理冷启动 → 界面黑屏，极易误判成「App 反代理」

挂着代理启动 App，`LoginActivity` 窗口在、进程活着，但：

- `mCurrentFocus=null`
- `uiautomator dump` 报 `null root node`
- `screencap` 出来 12KB 纯黑

而同一时刻**桌面截图正常（855KB）**，排查后也确认不是 `FLAG_SECURE`（全工程 0 命中）、
进程也没崩。**先启动 App 到目标页面，再 `proxy on`，一切正常。**

按「先开代理再启动」去试，几乎必然误判成 App 检测代理并阻断。

### 2. bind mount 前必须先复制原证书，否则系统证书全被遮

```bash
mount --bind /data/local/tmp/cacerts /apex/com.android.conscrypt/cacerts
```

如果 `/data/local/tmp/cacerts` 是空目录，这行会把**原有 134 个系统证书全部遮住**，
整个系统的 HTTPS 立刻挂掉，而且现象是「所有 App 网络异常」，很难联想到是自己干的。

正确顺序：`umount`（若有旧挂载）→ `cp -f $SRC/* $STAGE/` → 放新证书 → `bind`。
`cap.py install` 已按此顺序实现，**幂等，重复跑稳定在 n→n+1**。

### 3. SELinux 不打标签，conscrypt 读不到证书

```bash
chcon u:object_r:system_security_cacerts_file:s0 /data/local/tmp/mitm_cacerts/*
```

漏了这步 `mount` 会成功、`ls` 也能看到，但 TLS 握手照样失败——没有任何报错提示，
是本流程里最安静的一个失败点。

### 4. `subject_hash_old` 不是 `subject_hash`

Android 用的是 **`subject_hash_old`**：`MD5(DER(subject))` 取前 4 字节，
**按小端**拼成十六进制。用 OpenSSL 的 `-subject_hash` 会得到另一个名字，放进去不生效。

`cap.py ca` 直接算好，别手搓。

### 5. `/system` 可写性不能用 `mount` 输出判断

动态分区设备上 `mount -o remount,rw /system` 的报错是
`'/system' not in /proc/mounts` —— **不含 "read-only" 字样**。
用字符串匹配 "read-only" 判断会得出「可写」的错误结论。

必须用**写探针**：`touch` 一个文件看返回码。`cap.py info` 就是这么做的。

### 6. Git Bash 会把设备路径改写掉

```bash
adb shell "mkdir /data/local/tmp/x"     # 可能变成 C:/Program Files/Git/data/local/tmp/x
```

`cap.py` 全部用 `subprocess` 列表形式调 adb，不经过 MSYS，天然没有这个问题。
如果手敲命令，先 `export MSYS_NO_PATHCONV=1`。

### 7. 区分「证书没装上」和「有 SSL Pinning」

装上证书后还是抓不到，看 `dump` 输出的失败明细：

- 报 `Client TLS handshake failed` / `certificate verify failed` → **有 Pinning**，
  系统证书这条路走不通，要 frida 绕（`frida -U -f pkg -l unpinning.js`）。
- 报 `connection reset` / 完全没流量 → 代理没生效，查 `proxy status`。
- 全部 200 且能读到明文 → 没 Pinning，通了。

## 与其他技能的衔接

```
android-emulator-adb  →  连上设备
        ↓
apk-analyzer          →  看 targetSdk / networkSecurityConfig / 是否有 Pinning 配置
        ↓
本 skill              →  抓包看真实报文
        ↓
apk-reverse-master    →  把接口发现回流到逆向报告
```

## 边界

- 只做**流量观察**，不改包、不重放攻击、不绕鉴权。
- 仅在自有应用或有明确授权的测试目标上使用；抓到的凭据/令牌属敏感数据，
  落盘前想清楚要不要留。
- APEX bind mount 是**临时**的，重启或 APEX 更新后自动失效（这反而是好事），
  需要时重跑 `install`。

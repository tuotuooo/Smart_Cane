# 安卓模拟器 ADB 路径与端口对照表 + APK 动态分析工作流

本参考用于 `find_and_connect.py` 未能自动命中、或需要手动处理时的兜底。大多数情况下
脚本已自动覆盖；此处为人工排查与高级用法提供权威对照。

## 一、主流模拟器 ADB 端口

| 模拟器 | 默认 ADB 端口 | 多开端口规律 | 自带 adb 常见位置 |
|--------|--------------|-------------|------------------|
| Android Studio 原生 | 5554 (emulator-5554) | 每实例 +2（5556, 5558…） | `$ANDROID_HOME/platform-tools/adb` |
| 雷电 LDPlayer | 5555 | 5557 / 5565 / 5575… | `C:\leidian\LDPlayer14\adb.exe`（版本号随安装） |
| 夜神 Nox | 62001 | 62025 / 62026 / 62027… | `C:\Program Files\Nox\bin\adb.exe` |
| MuMu (旧) | 7555 | — | `C:\Program Files\MuMu\emulator\*\adb.exe` |
| MuMu12 | 16384 | 16416 / 16448… | `C:\Program Files\MuMu\emulator\*\adb.exe` |
| 逍遥 / 腾讯手游助手 | 21503 | — | 随安装目录 |
| BlueStacks 5 | 5555 (经 `bluestacks.conf` 配置) | 自定义 | `C:\Program Files\BlueStacks_nxt\*\adb.exe` |
| 海马玩 Droid4X | 58001 | — | 随安装目录 |

> 端口探测用 TCP connect 127.0.0.1 即可，无需依赖特定 adb 版本。

## 二、adb 版本不匹配（offline）的处理

不同 adb 客户端版本与服务端（模拟器内 adb daemon）版本不一致时，设备会显示为
`offline`。处理顺序：

1. 优先使用**模拟器自带的 adb**（版本最匹配），而非系统 SDK 的 adb。
2. 强制重启 daemon：`adb kill-server && adb start-server`，再 `adb connect`。
3. 仍 offline 时，在模拟器设置中关闭"USB 调试（安全设置）"再重开，或重启模拟器。

## 二·五、root 环境：开启、验证与只读分区

需要读 `/proc/<pid>/mem`、`/data/data` 等操作时必须先过这一关。**先画像再动手**：
`python find_and_connect.py --info --human`。

### 1. 开启 root 后怎么验证

```bash
adb shell id
# 期望：uid=0(root) gid=0(root) ... context=u:r:su:s0
```

- 出现 `uid=0(root)` 且 `context=u:r:su:s0` 才算真 root。
- 只有 `context=u:r:shell:s0` / `uid=2000(shell)` = 没开成功。
- 雷电：设置里勾选 root 后**必须重启实例**；`adb root` 报
  `adbd cannot run as root in production builds` 就是没开 root。

### 2. 不要依赖 `su`

`adb root` 之后 shell 本身就是 root。此时 `su` 可能不存在、可能弹授权、
也可能被 App 的检测当做 root 证据。**直接用 shell，不要包 `su -c`**。

### 3. `/system` 通常是只读的（别在这浪费时间去删 su）

雷电/多数现代模拟器是动态分区 + dm-verity：

```bash
$ adb shell mount -o remount,rw /system
mount: '/system' not in /proc/mounts      # ← 注意：这句里没有 "read-only"
$ adb shell touch /system/bin/x
touch: '/system/bin/x': Read-only file system   # ← 这才是真相
```

两个坑：

1. `mount` 的报错文案不含 "read-only"，**用字符串匹配判断会误判成"可写"**。
   判断可写性必须做真实写探针（`touch` + `rm`）。
2. 既然改不了 `/system`，**就不能靠重命名/删除 `su` 来对 App 隐藏 root**。
   隐藏 root 只剩 hook 路线（Java 层 hook 文件存在性判断，或 native 层拦截
   `access`/`stat`/`open`）。

### 4. 设备侧工具缺失

- `dd` 可能不存在：`which dd` 返回空时用 `toybox dd`。
- `base64` / `od` 同样优先走 `toybox <cmd>`。
- `adb exec-out "<带重定向的复合命令>"` 不会经过 shell，重定向会被当成字面参数；
  必须 `adb exec-out sh -c "cmd 2>/dev/null"`。

## 三、常用 ADB 命令速查（侧重 APK 逆向）

```bash
# 安装 / 卸载
adb install -r app.apk            # 覆盖安装
adb install -g app.apk            # 安装并自动授予所有权限（Android 6+）
adb uninstall com.pkg.name        # 卸载
adb shell pm clear com.pkg.name   # 清空数据（回到全新状态）

# 应用侦查
adb shell pm list packages -3            # 三方应用
adb shell pm list packages -f com.pkg    # 含 apk 路径
adb shell pm dump com.pkg | head -50     # 包详情（权限/组件）
adb shell dumpsys package com.pkg        # 更详细

# 运行与交互
adb shell am start -n com.pkg/.MainActivity
adb shell input tap 500 500              # 点击
adb shell input text "hello"             # 输入
adb shell input swipe 300 800 300 200    # 滑动
adb shell screencap -p /sdcard/s.png && adb pull /sdcard/s.png .

# 日志
adb logcat -c                           # 清屏
adb logcat | grep -i "license\|kms\|激活"   # 实时过滤
adb logcat -d > log.txt                 # 导出当前缓冲区

# 数据提取（需 root；雷电可在设置中开启，开完要重启实例）
adb shell "cp /data/data/com.pkg/databases/app.db /sdcard/"   # adb root 后不需要 su
adb pull /sdcard/app.db .
adb shell run-as com.pkg cat /data/data/com.pkg/shared_prefs/*.xml   # 免 root 读自身（仅 debuggable）
```

## 四、APK 动态分析标准工作流

针对"激活器 / 授权校验"类样本（如 KMS 激活器逆向），推荐顺序：

1. **准备干净环境**：`adb uninstall` 旧包 → `pm clear` 或重置模拟器快照。
2. **安装并授权**：`adb install -g sample.apk`，避免权限弹窗打断流程。
3. **基线日志**：启动前 `adb logcat -c`，启动样本，捕获启动期日志。
4. **触发激活流程**：用 `input tap/text/swipe` 模拟操作，或 `am start` 直接拉起目标 Activity。
5. **实时过滤线索**：`logcat | grep -iE "license|kms|activate|http|post|sign|key"`，
   定位授权服务器地址、校验逻辑、密钥来源。
6. **数据落地**：提取 `/data/data/<pkg>/` 下的 db / sp / 缓存 / native 库，
   与静态分析（反编译）结果交叉比对。
7. **抓包配合**：若样本走 HTTPS，配合模拟器内代理（如 frida + objection，或 Charles
   证书注入）解密流量，本 skill 聚焦 ADB 侧，抓包工具另接。

## 五、与静态分析的衔接

- ADB 侧发现的 `native 库列表` / `Assets` 路径，回头对应 Apktool / jadx 反编译产物。
- `logcat` 中出现的类名 / 方法名，直接作为 jadx 搜索关键词。
- 运行时写入的 SharedPreferences 键值，是逆向授权状态机的关键证据。

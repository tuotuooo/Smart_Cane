# 证书路径详解（各方案完整命令）

> `cap.py install` 会自动选路。本文是它的**依据与手工兜底**——
> 脚本跑不动时照这里手敲。

## 前置：生成 CA 并算出正确的文件名

mitmproxy 首次运行会在 `confdir` 生成 CA：

```bash
mitmdump --set confdir=./mitm -p 0    # 起来就杀掉，只为生成证书
ls ./mitm/
# mitmproxy-ca.pem  mitmproxy-ca-cert.pem  mitmproxy-ca-cert.cer  ...
```

Android 要的文件名是 **`subject_hash_old`**：

```python
from cryptography import x509
import hashlib
c = x509.load_pem_x509_certificate(open('mitmproxy-ca-cert.pem','rb').read())
d = hashlib.md5(c.subject.public_bytes()).digest()
name = ''.join('%02x' % b for b in reversed(d[:4]))   # 注意 reversed
open(name + '.0','wb').write(...)
```

| 名字 | 算法 | Android 是否认 |
|------|------|----------------|
| `subject_hash` | SHA1(DER) 前 4 字节**大端** | ✗ 不认 |
| `subject_hash_old` | MD5(DER) 前 4 字节**小端** | ✓ 认 |

后缀必须是 `.0`（PEM 格式）。`.cer`/`.pem` 改名不行，内容必须是 PEM。

---

## 方案 A：用户证书（targetSdk < 24 或 sdk < 24）

最简单，不需要 root。

```bash
# 推到设备，然后在 设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书 里选它
adb push mitmproxy-ca-cert.cer /sdcard/Download/
```

或用命令行拉起安装器：

```bash
adb shell am start -a android.settings.SECURITY_SETTINGS
```

**判断是否够用**：`dumpsys package <pkg> | grep targetSdk`。
`targetSdk >= 24` 时 App 的默认信任锚**不含用户 CA**，装了也白装——
必须走方案 B/C/D。

---

## 方案 B：APEX bind mount（Android 10+，root，无 Magisk）

**这是 Android 14 实测唯一可行的路**，也是本 skill 的主路径。

Android 10 起系统证书搬到了 APEX：`/apex/com.android.conscrypt/cacerts`。
`/system` 是动态分区只读，remount 直接拒绝，所以只能 bind mount。

```bash
STAGE=/data/local/tmp/mitm_cacerts
SRC=/apex/com.android.conscrypt/cacerts

# 1) 先解掉可能存在的旧挂载（关键：否则下面 cp 会复制到自己的影子副本）
su -c "umount $SRC 2>/dev/null || true"

# 2) 把系统原有证书完整复制出来
su -c "rm -rf $STAGE && mkdir -p $STAGE && cp -f $SRC/* $STAGE/"
su -c "ls $STAGE | wc -l"        # 应该是 134 左右，不是 0！

# 3) 放入自己的 CA（先用 cap.py ca 拿到 hash 名）
adb push c8750f0d.0 /data/local/tmp/mitm_ca.0
su -c "cp -f /data/local/tmp/mitm_ca.0 $STAGE/c8750f0d.0"

# 4) 权限 + SELinux 标签（漏了 chcon 会静默失败）
su -c "chown root:root $STAGE/*; chmod 644 $STAGE/*"
su -c "chcon u:object_r:system_security_cacerts_file:s0 $STAGE/*"

# 5) 挂上去
su -c "mount --bind $STAGE $SRC"
su -c "ls $SRC | wc -l"          # 应该是原数 +1
```

**卸载**（重启也会自动恢复）：

```bash
su -c "umount /apex/com.android.conscrypt/cacerts"
su -c "rm -rf /data/local/tmp/mitm_cacerts"
```

### 为什么不能直接 `mount --bind` 一个只放了新证书的目录

因为 bind mount 是**整体覆盖**：挂上去之后你看到的就是被挂目录的内容，
原来的 134 个系统证书全部不可见。系统里所有依赖预置 CA 的 HTTPS 连接会立刻失败
（系统更新、推送、Play 服务、其他 App 全受影响），现象是"整个手机网络出问题"，
极难归因到自己刚做的这步操作。

所以必须 `cp` 原件 → 加新文件 → 再挂。

### 特殊情况：`/apex` 下有多个版本目录

部分设备是 `/apex/com.android.conscrypt@<version>/cacerts`。
`cap.py info` 会 glob 出真实路径，手工时先 `ls -d /apex/com.android.conscrypt*`。

---

## 方案 C：落盘 `/system/etc/security/cacerts`（Android ≤ 9，或 /system 可写）

```bash
su -c "mount -o rw,remount /system || mount -o rw,remount /"
su -c "cp c8750f0d.0 /system/etc/security/cacerts/"
su -c "chmod 644 /system/etc/security/cacerts/c8750f0d.0"
su -c "chcon u:object_r:system_security_cacerts_file:s0 /system/etc/security/cacerts/c8750f0d.0"
```

**可写性判断必须用写探针**：

```bash
su -c "touch /system/etc/security/cacerts/.zz 2>/dev/null && rm -f /system/etc/security/cacerts/.zz && echo WRITABLE || echo READONLY"
```

不要用 `mount | grep /system` 的字符串判断——动态分区上 remount 失败信息是
`'/system' not in /proc/mounts`，**不含 "read-only"**，匹配会误判为可写。

---

## 方案 D：Magisk 模块（root + Magisk，最持久）

> 本方案**未在本次实测环境验证**（该设备无 Magisk），按 Magisk 通用机制整理。

思路：把 CA 放进一个模块的 `system/etc/security/cacerts/`，让 Magisk 开机时 overlay 上去。

```
/data/adb/modules/mitm-ca/
├── module.prop
└── system/etc/security/cacerts/c8750f0d.0
```

`module.prop`：

```
id=mitm-ca
name=mitmproxy CA
version=1.0
versionCode=1
author=local
description=Inject mitmproxy CA into system trust store
```

也可以直接用现成模块（`MagiskTrustUserCerts` / `AlwaysTrustUserCerts`），
效果是把**用户证书区**的内容自动复制进系统区——好处是以后换证书只要
在设置里装用户证书即可，不用每次 bind mount。

改完 `reboot`，或对支持 live 的模块执行 `magisk --path` 相关操作。

---

## 方案 E：无 root（改包 / hook）

三条路，按侵入性排序：

### E1. apk-mitm（最省事）

```bash
npx apk-mitm app.apk          # 自动 patch network_security_config 并重签
adb install -r app-patched.apk
```

会自动做两件事：加 `<certificates src="user"/>` 信任锚、去掉常见 Pinning 配置。
缺点：重签会破坏原签名，**依赖签名校验的 App 会拒跑**（此时看 `apk-analyzer`
能不能定位到校验点）。

### E2. 手工改 network security config

如果 App 已有 `network_security_config.xml`，在其 `trust-anchors` 里加：

```xml
<certificates src="user" />
```

回编译 + 重签。注意 manifest 里的 `android:networkSecurityConfig` 必须指向它。

### E3. frida 绕 Pinning

不改包，运行时 hook 掉证书校验：

```bash
frida -U -f com.example.app -l unpinning.js --no-pause
```

适用于有 Pinning、且不能改包（有签名校验/加固）的场景。
配合方案 A/B 的系统证书一起用。

**注意**：加固 App 的 Pinning 往往在 native 层（`libDexHelper` 这类壳里），
Java 层 hook 无效，需要 hook `SSL_CTX_set_verify` / `X509_verify_cert` 等 native 符号。
先用 `grep -a` 在 .so 里找 `SSL_CTX` / `verify` 定位再决定。

---

## 代理接入方式

### 推荐：`adb reverse`（避开主机防火墙）

```bash
adb reverse tcp:8080 tcp:8080
adb shell su -c "settings put global http_proxy 127.0.0.1:8080"
```

设备侧连 `127.0.0.1:8080`，由 adb 转发到主机，**不需要设备能访问主机 IP**，
也不用开防火墙端口。USB 连接和 `adb connect` 的模拟器都适用。

### 备选：局域网 IP

```bash
adb shell su -c "settings put global http_proxy 192.168.1.100:8080"
```

需要同网段、且主机防火墙放行 8080。设备是模拟器时主机 IP 常是 `10.0.2.2`（AOSP）
或 `192.168.xx.1`（桥接）。

mitmdump 侧要加 `--set block_global=false`，否则会拒绝来自非本机的连接
（报 `Client connection refused because the proxy is not configured to allow
remote connections`）。

### 清理

```bash
adb shell su -c "settings put global http_proxy :0"
adb reverse --remove tcp:8080
```

`settings put global http_proxy :0` 里的 `:0` 是**清空**的意思，不是设成 0 端口。

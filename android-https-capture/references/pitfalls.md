# 抓包坑库

> 每条都是实测踩过的，按「现象 → 根因 → 处理」写。
> 排查顺序：先看现象在不在下面的表里，不要凭直觉改配置。

## 速查表

| 现象 | 大概率原因 | 跳到 |
|------|-----------|------|
| 抓不到任何 HTTPS，App 正常用 | 证书没进系统区 / targetSdk≥24 只装了用户证书 | §2 §3 |
| 装完证书 App 全部网络异常 | bind mount 把系统证书遮了 | §2 |
| mount 成功、ls 能看到、TLS 照样失败 | 漏了 `chcon` | §3 |
| 证书放进去了但名字不对不生效 | 用了 `subject_hash` 不是 `_old` | §4 |
| 报 `not in /proc/mounts`，判断成可写 | 用字符串匹配判断可写性 | §5 |
| 挂着代理启动 App，界面全黑 | 冷启动时机问题，不是反代理 | §1 |
| `adb shell mkdir /data/...` 建到 C 盘 | Git Bash 路径转换 | §6 |
| `pip install mitmproxy` 找不到包 | 清华源没有这个包 | §7 |
| mitmdump 拒绝连接 | 缺 `block_global=false` | §8 |
| flows 读到一半抛异常 | 文件还在写 | §9 |
| 只能抓到 HTTP，HTTPS 全是 CONNECT | 证书完全没生效 | §2 §3 |
| 部分域名能解、部分握手失败 | 那些域名有 Pinning | §10 |

---

## §1. 带代理冷启动 → 界面黑屏（最容易误判的一条）

**现象**

挂着系统代理启动 App 后：

- 窗口存在（`dumpsys window` 能看到 `LoginActivity`）
- 进程活着（`pidof` 有值）
- 但 `mCurrentFocus=null`
- `uiautomator dump` 报 `ERROR: could not get idle state` 或 `null root node`
- `screencap` 出 12KB 左右的纯黑 PNG

**排除过程（重要，别跳）**

| 检查 | 结果 | 排除了什么 |
|------|------|-----------|
| 按 HOME 再截图 | 855KB 正常 | 设备截图能力没问题 |
| `dumpsys window \| grep FLAG_SECURE` | 0 命中 | 不是防截屏 |
| `pidof` + `logcat` | 进程在、无 FATAL | 不是崩溃 |
| 关掉代理重启 | 界面完全正常 | 是代理引起的 |

**根因**

代理生效时 App 的启动链路请求失败/阻塞，UI 线程卡在等首屏数据的状态，
窗口画不出来。不是 App 主动检测代理。**没有任何证据表明这是反抓包机制**——
别在这种现象上写"该 App 有代理检测"的结论。

**处理**

顺序反过来：**先把 App 启动到目标页面，再开代理**。

```bash
cap.py proxy off          # 确保没代理
adb shell am start -n pkg/.SplashActivity
# 等界面出来（能截图/能 uiautomator 就说明好了）
cap.py proxy on           # 这时候开，一切正常
```

热启动不受影响：只要进程已经在跑、界面已经画出来，再切代理是安全的。

---

## §2. bind mount 之前没复制原证书 → 系统证书被遮光

**现象**

`mount --bind` 之后，整个系统的 HTTPS 都开始出问题：推送收不到、系统更新失败、
其他 App 报网络异常。而你的抓包看板可能一切正常。

**根因**

bind mount 是**整体覆盖**。挂一个只放了 1 个新证书的空目录上去，
原来 134 个系统证书就全部不可见了。

**处理**

顺序必须是 `umount（若有）→ cp 原件 → 加新文件 → bind`：

```bash
su -c "umount $SRC 2>/dev/null || true"     # 先恢复真实内容
su -c "rm -rf $STAGE && mkdir -p $STAGE"
su -c "cp -f $SRC/* $STAGE/"                # 关键
su -c "ls $STAGE | wc -l"                   # 必须 ≈134，不是 0
su -c "cp -f /data/local/tmp/mitm_ca.0 $STAGE/<hash>.0"
su -c "mount --bind $STAGE $SRC"
```

如果已经搞坏了：`su -c "umount /apex/com.android.conscrypt/cacerts"` 立刻恢复。

`cap.py install` 已内置此顺序，并且**幂等**（重复跑稳定 n→n+1，不会累积也不会丢）。

---

## §3. 漏 chcon → mount 成功但 TLS 照样失败

**现象**

- `mount` 返回成功
- `ls $SRC` 能看到自己的证书文件
- 但抓包依然只有 CONNECT，没有任何解密后的请求
- **没有任何错误日志**

**根因**

SELinux 下 conscrypt 进程读不到没打标签的文件。文件在、权限也对、就是读不到，
失败是静默的。

**处理**

```bash
su -c "chcon u:object_r:system_security_cacerts_file:s0 $STAGE/*"
```

同时也别忘了 `chmod 644` 和 `chown root:root`。

**验证**：`su -c "ls -Z $SRC | head"`，标签应该是
`u:object_r:system_security_cacerts_file:s0`。

---

## §4. `subject_hash_old` vs `subject_hash`

**现象**

证书放进 `/system/etc/security/cacerts/` 了，文件名也是一串 8 位十六进制，
但完全不生效。

**根因**

Android 用的是 **`subject_hash_old`**：

```
MD5(DER(subject))[:4]  →  按小端拼十六进制
```

而 OpenSSL 的 `openssl x509 -subject_hash` 给的是 SHA1 版本（大端），
两个值完全不同。查教程时经常被混用。

```bash
openssl x509 -in ca.pem -subject_hash_old -noout   # 正确
openssl x509 -in ca.pem -subject_hash -noout       # 错误（Android 不认）
```

**处理**

用 `cap.py ca`，它直接算 `_old`。手算：

```python
d = hashlib.md5(cert.subject.public_bytes()).digest()
name = ''.join('%02x' % b for b in reversed(d[:4]))   # reversed 不能少
```

文件名后缀必须是 `.0`，内容必须是 **PEM**（不是 DER、不是 `.cer` 改名）。

---

## §5. 用 `mount` 输出判断 `/system` 可写 → 误判为可写

**现象**

`mount -o remount,rw /system` 返回一行 `'/system' not in /proc/mounts`，
脚本里 `grep -i "read-only"` 没匹配上 → 判定"可写" → 后续 `cp` 全线失败。

**根因**

动态分区设备上 `/system` 根本不是独立挂载点（挂在 `/` 下的 overlay/erofs），
所以报的是"不在挂载表里"，字面上跟"只读"没关系。**字符串匹配必然误判。**

**处理**

只用**写探针**：

```bash
su -c "touch /system/etc/security/cacerts/.zz 2>/dev/null && rm -f \
       /system/etc/security/cacerts/.zz && echo WRITABLE || echo READONLY"
```

这也是 `android-emulator-adb` 的 `--info` 采用的做法。任何"能不能写"的判断
都该落到真实写操作上，不要靠解析 mount 输出。

---

## §6. Git Bash 把设备路径改写成本机路径

**现象**

```bash
adb shell "mkdir -p /data/local/tmp/x"
adb shell "ls /data/local/tmp"
# ls: /data/local/tmp: No such file
adb shell "ls C:/Program Files/Git/data/local/tmp"    # 反而有
```

**根因**

MSYS/MinGW 在把参数传给 Windows 原生 exe 前，会把看起来像 Unix 绝对路径的
字符串按自己规则转换（`/x` → `C:/Program Files/Git/x` 或 `C:/x`）。

**处理**

```bash
export MSYS_NO_PATHCONV=1
```

或者干脆用 `cap.py`——它用 `subprocess` 列表形式直接调 `adb.exe`，
不经过 shell，**天然免疫**。这是把命令写进脚本而不是手敲的另一个理由。

---

## §7. `pip install mitmproxy` 在清华源找不到

**现象**

```
ERROR: Could not find a version that satisfies the requirement mitmproxy
```

**根因**

清华 PyPI 镜像没有收录 mitmproxy（同步策略所致，不是版本问题）。

**处理**

用阿里云源：

```bash
python -m pip install mitmproxy -i https://mirrors.aliyun.com/pypi/simple/
```

装完验证**必须真的 import** 而不是看 `pip` 的退出码——
`pip install ... | tail` 的退出码是 `tail` 的，永远是 0：

```bash
python -c "import mitmproxy; print(mitmproxy.__version__)"
```

---

## §8. mitmdump 拒绝设备连接

**现象**

```
Client connection from 192.168.x.x refused because the proxy is not
configured to allow remote connections
```

**根因**

mitmproxy 默认只接受本机连接。

**处理**

加 `--set block_global=false`。

或者用 `adb reverse` 从根上避开——设备侧连 `127.0.0.1`，adbd 转发到主机，
在 mitmproxy 看来就是本机连接，不用改配置也不用动防火墙。**推荐后者。**

---

## §9. 读 `flows.mitm` 中途抛异常

**现象**

```python
for fl in io.FlowReader(f).stream():
    ...
# 抛 EOFError / TypeError / zlib.error
```

**根因**

`mitmdump -w` 是流式追加写。抓包进程还活着的时候，文件末尾是半条记录。

**处理**

包一层 try/except，读到哪算哪——已写完的 flow 都是完整的：

```python
flows = []
try:
    for fl in io.FlowReader(f).stream():
        flows.append(fl)
except Exception:
    pass          # 末尾半条丢弃即可
```

`cap.py dump` 已经这么处理了。

要完整快照就先 `cap.py stop` 再读，或者用 `mitmdump -w` 之外的方式
（`--set save_stream_file`）。

---

## §10. 只能解密部分域名

**现象**

`dump` 输出里，多数请求 200 且明文可见，但少数几个报：

```
Client TLS handshake failed
certificate verify failed
```

**根因**

这些域名单独做了 **SSL Pinning / 证书固定**。系统证书对它无效。

**处理**

判断：`cap.py dump flows.mitm` 的失败明细里，如果是
`Client TLS handshake failed` 且**集中在特定域名**，就是 Pinning。

绕法见 `cert_paths.md#e3-frida-绕-pinning`：

```bash
frida -U -f pkg -l unpinning.js --no-pause
```

加固 App 的 Pinning 常在 native 层，Java hook 无效，需要
`SSL_CTX_set_verify` / `X509_verify_cert` 级别的 hook。

**重要**：先确认是不是证书没装好。证书问题的特征是**所有** HTTPS 都失败；
Pinning 的特征是**部分**成功、部分失败。

---

## §11. 用 flows 数量判断"抓没抓到登录"要小心

**现象**

用户说"我点了登录"，但 flows 里没看到登录请求，于是判定"请求没发出"。

**实际可能**

- 请求走了 QUIC/HTTP3（UDP 443），代理只处理 TCP → 完全看不到
- App 用了自建长连接/私有协议
- 点击没真正触发（控件坐标偏了、按钮没激活）
- 请求确实失败在客户端（连不上、被风控拦在前置）

**处理**

按这个顺序排除：

```bash
# 1) 界面上到底发生了什么？先截图/dump UI 确认点击生效
adb shell uiautomator dump /sdcard/u.xml && adb pull /sdcard/u.xml

# 2) 是不是走了 UDP？
adb shell "su -c 'netstat -unp | head'"

# 3) 设备侧有没有连 8080？
adb shell "su -c 'netstat -tnp | grep 8080'"

# 4) 才有资格判断"请求没发出去"
```

控件坐标要从 `uiautomator dump` 的 `bounds` 里算中心点，
不要凭截图目测——尤其是黑屏时根本没法目测。

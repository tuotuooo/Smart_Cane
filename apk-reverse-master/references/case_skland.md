# 案例复盘：森空岛（Skland）

一个把四件套全部走通的完整样本。数值均为实测。

---

## 0. 样本

| 项 | 值 |
|----|-----|
| 文件 | `df8e24d00c2f367b8c8f3856888388c1.apk` |
| 大小 | 54,944,507 B（52.4 MB） |
| 包名 | `com.hypergryph.skland` |
| 签名 | `CN=Android Debug, O=Android, C=US`（**重签版**） |
| SHA1 | `949bab53…` / SHA256 `111052ab…`（Android 默认 debug key） |
| 技术栈 | 原生 Android + React Native（Hermes） |
| 加固 | SecNeo（盛安德） |

**第一课**：官包不会用默认 debug 证书。看到这个 Subject 就能直接判定"这是被改过/重签的版本"，
这是整条分析链的起点。

---

## 1. 走了两次弯路

### 弯路一：把桩 DEX 当成"巨大明文 DEX"

`classes.dex` 有 42MB+，第一轮统计出"25,748 个类"，于是写进报告说"静态已拿到全部代码"。

**实际情况**：

```
classes.dex (APK 内)
  字符串数  276
  类型数     81
  方法数    168
  其余      ~42MB 重复字节填充
```

判断依据不是体积，而是**类数/方法数/字符串数**。81 个类型不可能撑起一个社交类应用。

### 弯路二：三层连锁的 Hermes 误判

**第一层**：技能里的 `HERMES_MAGIC` 常量被写成了 `00 07 D0 8B`。
那不是 Hermes 魔数，而是**这个样本自己的加密文件头**（恰好 = 真魔数 XOR 假密钥）。
于是真文件（头 `C6 1F BC 03`）被判成"魔数不匹配 → 已加密"。

**第二层**：`header XOR 那个错常量` 得到 `0xC6186C88`，看着像密钥，
于是写进报告说"可 XOR 解密"。

**证伪**：

| 检验 | 结果 |
|------|------|
| 整文件 XOR 后熵 | 6.79 → **7.21**（升高，说明把好数据搅乱了） |
| DEX 中搜 `c6186c88` | **0 命中** |

**第三层**：熵测绘看到"前段高熵、后段可打印"，于是宣称"双区加密容器，0x0-0x69000 是加密区"。

**真相**：按标准头解析，`magic=0x1F1903C103BC1FC6`、`fileLength=3539736` 与文件大小
完全一致、18204 个函数——**它从头到尾就没加密**。所谓"加密区"只是 HBC 的
函数头/字节码/索引表（天然高熵），"明文区"就是 `stringStorage`。

**教训**：
1. 常量级的错误会级联出整串假结论，**先验证魔数常量本身**；
2. `header XOR magic` 对任意 4 字节都成立，是恒等式，不能当发现；
3. 熵剖面不是加密证据，判加密只认 `magic + fileLength`。

---

## 2. 静态真正拿到的

### 2.1 加固画像

```
libDexHelper-x86.so        ← SecNeo 的 native 脱壳器
com.secneo.apkwrapper.H    ← logcat 里出现，实锤
classes.dex                ← 桩
```

### 2.2 manifest.mf：2552 条文件哈希

`assets/meta-data/manifest.mf` 解码后：

```
PREFIX   : 8f7f0a8b08
HEADER   : AndroidManifest.xml,!stamp-cert-sha256
TOTAL    : 2552 条 SHA1
             = 5 条独立记录 + 2547 条（50940 B / 20 B）
SPECIAL  : AndroidManifest.xml 的 SHA1 不在列表内（单独条目）
CERT FP  : 不在文件里（硬编码在加密后的真代码/native 层）
```

含义：App 在运行时逐个校验 2552 个文件的哈希 + 比对签名证书指纹。
**改一个字节就起不来**——所以正确的路是脱壳，不是改包。

### 2.3 Hermes bundle：其实没加密

`assets/rn/main.jsbundle` 3,539,736 字节，按标准 Hermes 头解析：

```
magic            = 0x1F1903C103BC1FC6     ← 标准魔数
version          = 90
fileLength       = 3539736  == 文件大小   ← 自洽
functionCount    = 18204
stringCount      = 23045
identifierCount  = 11266
stringStorageSize= 463042
```

结论：**这是一份普通的、未加密的 Hermes 字节码。** JS 层完全静态可达，
用 `hbcdump` / `hermes-dec` 即可反汇编。之前"加密 + XOR 密钥 + 双区容器"的三层说法
全部作废（见第 1 节弯路二与 §7 的连锁复盘）。

### 2.4 实际反汇编结果（走通了整条 JS 链）

用 `hermes-dec`（自带 hbc90 opcode 表，与版本精确匹配）：

| 项 | 结果 |
|---|---|
| 反汇编覆盖 | **18,204 / 18,204 函数，零错误** |
| 产物 | `main.disasm.txt` 49.7 MB / 763,114 行；`main.decomp.js` 8.7 MB |
| 耗时 | 各约 1 分钟内 |
| 字符串 | 表内 23,045 条；被指令引用 14,824 条 |

**直接产出的业务情报**（`hbc_index.py` 索引后）：

1. **环境配置中心（一个函数搞定）**：内联 `prod|live|pre|dev|testin|staging` 六套环境，
   并把环境名拼进域名 → 生产包里同时带着 `chart-skland-testin` / `*-staging` / `*-dev`
   等预发布地址，另有 2 个 **http 明文**基址（`http://chimera.hypergryph.net`、
   `http://sfmaple-skland.hypergryph.net`）。
2. **调试页随包分发**：`skland://rn?moduleName=TestPage` 直达一个原生桥调试界面
   （发事件 / 加监听 / 打开操作面板 / 跳转 edit），这是最省事的突破口。
3. **JS 侧没有 root 检测**：全表搜 `frida/magisk/xposed/tamper` 无命中；唯一的 `isRoot`
   是 **mobx-state-tree 的节点 API**（`protect()` 报 "can only be invoked on root nodes"），
   与设备 root 无关。
4. **热更新是自研的**：`/api/v1/rn/version/check`，**不是 CodePush**（全表无 CodePush 串）。

**关键教训**：真拿到 JS 层后，很多"看起来像安全机制"的东西只是框架 API 重名。
`isRoot` 是 mobx-state-tree、`Root` 是 React Fiber、`scope` 是 Sentry —— 报结论前先看**谁在用**。

### 2.5 字符串提取的两条硬规矩（本轮代价）

| 错误做法 | 后果 |
|---|---|
| 裸打印扫描 stringStorage | 相邻串粘连，造出 `oauth2`/`one_login`/`geetest` 等**假的业务串**（原始字节 0 命中） |
| `glob("classes[0-9].dex")` | **漏掉 `classes.dex`**，一度误判"某端点不存在" |

两条都已写进 `pitfalls.md` 的 1.5c / 1.5d。

---

## 3. 动态：root 没让它闪退 —— 而第三轮复核发现"闪退机制"根本不存在

用户提醒"这 App 检测到 root 会闪退"。实测：

```
am start → 进程稳定停在 LoginActivity（pid 2134 + 子进程 2160），未闪退
```

第二轮的解释是"重签版把检测触发点后置或已 patch"。**这个解释是错的**——它假设了
检测存在，但从未验证过检测代码属于谁。

第三轮用 `dex_tool.py` 把每条 root 检测字符串反查到所属方法，结果全部落空：

| 字符串 | 真实归属 |
|---|---|
| `getRootState`、`C_ROOT_STATE`、`magisk`、`com.topjohnwu.magisk` | `cn.jiguang`（极光推送，内嵌 RootBeer） |
| `test-keys`、`goldfish`、`com.koushikdutta.superuser` | `io.sentry`（崩溃上报的设备上下文） |
| `frida` | `com.geetest.sdk`（极验验证码风控） |
| 11 条 su 路径 | `libdivider2.so`（游戏加速器 `NativeUtils.checkDeviceRoot`） |

`com.hypergryph.*` 全量筛 `root|secur|anti|detect|protect|guard|tamper|integrity|cheat|risk`，
命中的只有 `CheckinIcon`（签到）、`QRCodeCheckRequest`（扫码轮询）、`OneClickProtection`
（隐私开关）、`SklAccountBanTipsDialog`（封号提示）—— **没有一个安全类**。

加速器那段甚至能直接读出行为：检测到 root 就 `resp.i = false` 并打日志
`"device root，close process boost"`，**只关加速，不杀进程**。
壳 `libDexHelper.so` 有 `libc_ptrace`（反调试），但没有任何 root 相关字符串。

**所以：代码层面不存在"root 就杀进程"的路径。** 不闪退是正常行为，不需要用"被 patch"解释。

**顺带纠正 `Game signature`**：它不是 App 自校验，而是加速器判断"用户装的游戏是不是官方包"
（`服务端白名单.containsAll(本地各包签名MD5)`），结果只影响 boost 开关。

**这反而是最好的 dump 时机**：DEX 已解密，业务逻辑未触发，检测未生效。

---

## 4. 脱壳过程

### 4.1 环境

```bash
adb shell id
# uid=0(root) gid=0(root) ... context=u:r:su:s0   ← 真 root
adb shell toybox | grep -x dd
# dd                                              ← 有
```

`/system` 只读：

```
$ mount -o remount,rw /system
mount: '/system' not in /proc/mounts       ← 注意：没有 "read-only" 字样
$ touch /system/bin/x
touch: '/system/bin/x': Read-only file system   ← 这才是真相
```

所以"改名 `su` 隐藏 root"这条路直接封死。

### 4.2 读内存的两个卡点

```bash
# 卡点1：dd 不存在
$ adb shell "dd if=/proc/2134/mem ..."
dd: not found

# 卡点2：从偏移 0 读是 EIO
$ adb shell "head -c 16 /proc/2134/mem"
（空）

# 正解
adb exec-out sh -c "toybox dd if=/proc/2134/mem bs=4096 skip=$((0x7c37c3a00000/4096)) count=N 2>/dev/null"
```

### 4.3 命中

maps 3323 条 → 候选 168 个 → 头部探测命中 1 个大区：

```
0x7c37c3a00000  100.0 MB  [anon] rw-p
```

区内切出 5 个 DEX（脚本 24 秒跑完）：

| 文件 | 大小 | 类数 | 方法数 |
|------|------|------|--------|
| classes.dex | 28,726,879 | 11,616 | 64,960 |
| classes2.dex | 23,828,212 | 9,550 | 64,914 |
| classes3.dex | 16,551,215 | 6,537 | 50,771 |
| classes4.dex | 1,055,703 | 216 | 3,366 |
| classes5.dex | 292,551 | 127 | 1,244 |

合计约 71 MB、**10,848 个唯一类**，其中 1001 个 `com.hypergryph.*` 业务类
（`MainApplication` / `SchemeActivity` / `account/*` / `album/*` …）。

### 4.4 头部校验

```
checksum_ok=False  signature_ok=False  truncated=False
code_off: valid=52,752  invalid=0
```

前两个 False 是**正常**的（壳不重算头部）；`invalid=0` 才是"完整"的证据。
`dex_fix.py` 重算后（先 signature 后 checksum）产出 `*_fixed.dex`，可直接喂 jadx。

---

## 5. 没拿到的

| 目标 | 状态 | 原因 | 需要什么 |
|------|------|------|---------|
| Hermes 字节码 | ✓ **静态已得** | 实测是标准未加密 HBC v90（18204 函数 / 23045 字符串） | 用 `hbcdump` / `hermes-dec` 反汇编即可，**不用登录** |
| 证书期望指纹 | ✗ | 不在 manifest.mf，硬编码在 native/加密代码 | IDA 分析 `libDexHelper` |
| SecNeo 解密算法 | ✗ | 在 native 层 | IDA / Frida hook |
| 加速器选路协议 | 部分 | `Lo0/w;->i` 已反汇编，字段含义已解；服务端协议格式未取 | 抓包 |
| App 自身的完整性校验 | 部分 | `manifest.mf` 已解出 2552 条哈希，比对逻辑未定位 | 继续 `dex_tool.py` 追引用 |

**关键认知（第三轮修正）**：DEX 里确实能 `grep` 到 `su` 多路径、`magisk`、`superuser`、
`frida`、`xposed`、`ro.debuggable`、`test-keys`、`EmulatorDetector`、`goldfish`、
`getRootState`、`Game signature`——但**这些没有一条属于业务代码**，全部来自极光推送、
Sentry、极验、游戏加速器四个第三方 SDK。

所以正确表述不是"代码存在但没触发"，而是：

> **`com.hypergryph.*` 中不存在 root 检测。这个 App 不会因为设备 root 而退出。**

"字符串存在"、"代码存在"、"业务代码存在"、"当前会触发"是四个不同层次的判断，
**每上升一层都必须重新取证**。只做第一层就下第四层的结论，是本案例最大的教训。

---

## 6. 这个案例沉淀出的规则

1. **判加固看类数不看体积。**
2. **先验常量再推理**——魔数写错会让后面所有结论级联出错。
3. **`header XOR magic` 永远是假象**；判 Hermes 加不加密只认 `magic + fileLength`。
4. **熵剖面不是加密证据**，标准 HBC 本来就前高后低。
5. **开 root 不等于必闪退**——先实测存活时间，再决定要不要抢窗口。
6. **`/system` 只读的报错文案不含 read-only**，判断要用写探针。
7. **`dd` → `toybox dd`；`exec-out` → `sh -c`。**
8. **内存 DEX 的 checksum 不匹配是正常的**，完整性看 `code_off`。
9. **先 signature 后 checksum**，顺序反了永远算不对。
10. **RN 引擎登录后才加载，但 bundle 可能本来就没加密**——先静态判，再决定要不要 dump。
11. **报告必须有"没拿到什么"一节**，否则不可信。
12. **`grep` 到 `su`/`magisk`/`frida` ≠ 这个 App 会反 root。** 必须用 `dex_tool.py str`
    反查到所属类，确认是业务代码还是第三方 SDK。本案例四条线索全落空。
13. **反编译出现非法操作数（argc=16/32）时，先证指令边界、再证字段变换**，
    别急着改整张表——本案例只有 `invoke` 的 `AA` 被移位，其它指令正常。

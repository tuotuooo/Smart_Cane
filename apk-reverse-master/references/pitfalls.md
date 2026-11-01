# APK 逆向坑库

按层分类。每条的格式统一为 **现象 → 原因 → 正确做法**。
带 `[案例]` 的是真实踩过的（森空岛 / KMS 激活器等样本）。

---

## 一、静态分析层

### 1.1 "这个 DEX 有 40MB，代码量惊人"

**现象**：`classes.dex` 四十多 MB，但反编译出来只有几百个类、几十个方法，全是
`com.secneo.apkwrapper.*`。

**原因**：加固壳的**桩 DEX + 填充**。壳把桩 DEX 撑到几十 MB，用重复字节填满，
目的是干扰逆向者判断代码规模，也顺便占位。

**正确做法**：只看三个数——类数、方法数、字符串数。真实 40MB 业务代码应有上万类；
桩 DEX 是 81 类 / 168 方法 / 276 字符串这个量级。

`[案例]` 森空岛：首轮误判成"25748 类明文 DEX"，实际 classes.dex 只有 81 个类型。

---

### 1.2 AndroidManifest.xml 解析不出来

**现象**：用 `xml.etree` 读 manifest 直接抛异常，或者读出乱码。

**原因**：APK 里是 **AXML 二进制格式**，不是文本 XML。结构是 chunk 树：

```
0x00080003  RES_XML_TYPE（根 chunk）
  ├─ 0x0001  StringPool     ← 所有字符串（UTF-8/UTF-16，带长度前缀）
  ├─ 0x0180  ResourceMap     ← 属性名→资源 ID 映射（决定"哪个属性是哪个"）
  └─ 0x0102  StartElement / 0x0103 EndElement …
```

**正确做法**：
1. 先解析 `StringPool`（type=0x0001），偏移 8 开始读 `string_count` / `flags` / 三个 offset；
2. 每个 element 的**属性名是资源 ID**（如 `0x0101021b` = `versionName`），
   必须靠 `ResourceMap` 映射回名字，不能按字符串顺序猜；
3. 根 chunk 要递归（`header_size` 之后才是子 chunk）。

`[案例]` KMS 样本：第一版解析器把 `stringPool` 当成元素名，输出全是乱码。

---

### 1.3 manifest.mf 是个"未知二进制文件"

**现象**：`assets/meta-data/manifest.mf` 打开是乱码，看起来像 base64 但解不开。

**原因**：这是**重打包校验清单**的私有格式，结构为：

```
[5 字节前缀 8f7f0a8b08]
[header: 双层 base64 → "AndroidManifest.xml,!stamp-cert-sha256"]
[5 条独立 SHA1 记录]
[一个 ~68K 字符的 base64 大块 → 5 万+ 字节 = 2547 × 20 字节 SHA1]
```

总计 2552 条文件哈希。**期望的证书指纹不在文件里**（硬编码在加密后的真代码/native 层）。

**正确做法**：
- 用 `raw.split('=')` 做确定性分段，不要用正则匹配 base64（`-`/`_` 与 `+`/`/` 混用会断片）；
- base64 字符集要包含 `+` `/`，注意 `[A-Za-z0-9_-]` 里 `-` 会被当范围；
- 头部 base64 从 `QW5k`（"And"）这个标记定位起点；
- 验证解码正确性的方法：`AndroidManifest.xml` 的 SHA1 **不在**这 2552 条里（它是特殊条目）。

`[案例]` 森空岛：连续三次解码失败（`=` 当分隔符 / 正则字符类 `-` 当范围 / 字符集缺 `+` `/`）。

---

### 1.4 Hermes bundle「4 字节 XOR 密钥」

**现象**：bundle 头部不是你以为的 Hermes 魔数，而 `header XOR 魔数` 得到一个漂亮的
4 字节值，比如 `0xC6186C88`。于是断言"这就是 XOR 密钥"。

**原因（根因在更前面）**：多半是**魔数常量本身写错了**。Hermes 魔数是 8 字节
`0x1F1903C103BC1FC6`（落盘 `C6 1F BC 03 C1 03 19 1F`）。
如果误把某个样本自己的加密头（如 `00 07 D0 8B`）当成魔数常量，真文件就会被判成"不匹配"，
接着 `header XOR` 又会"凑出"那个错常量，看起来像发现了密钥——**实际上是循环论证**。

**验证方法（两步，必做）**：
1. 用该密钥 XOR 整个文件，重算熵——**熵不降反升**（如 6.79 → 7.21）就说明它不是密钥；
2. 在 DEX 里搜该 4 字节序列，**0 命中**就说明它不是从代码里取的密钥。

**正确做法**：先确认魔数常量对不对（8 字节比对），再看 `fileLength` 是否等于文件大小。
两者都对，说明**根本没加密**，直接反汇编；都不对，才考虑运行时 dump。

`[案例]` 森空岛：这条假结论写进过报告和技能文档，还连带派生出 1.5 的"双区容器"。

---

### 1.5 熵剖面"证明"了代码段被加密

**现象**：bundle 前段熵 6~7、可打印率低，后段熵低、可打印率高，于是判断
"前段加密、后段明文，双区容器"。

**原因**：**标准 Hermes 文件本来就是这种形态**。头部 + 函数头 + 字节码 + 各类索引表是
二进制（熵高），`stringStorage` 是大段可打印文本（熵低）。这是正常布局，不是加密证据。

**正确做法**：加密与否只认两条——magic 是否等于 `0x1F1903C103BC1FC6`、
`fileLength`（偏移 `0x20`）是否等于文件大小。熵剖面只用来**定位字符串存储的大致区间**。

`[案例]` 森空岛：实测 `magic=0x1F1903C103BC1FC6`、`fileLength=3539736` 与文件大小完全一致、
18204 个函数 / 23045 个字符串 —— 它是完完全全的普通未加密 HBC，"0x0-0x69000 加密区"
是虚构的。JS 层本来就可以静态反汇编。

---

### 1.5b Hermes 头 `fileLength` 读错位置

**现象**：在偏移 `0x10` 读长度，得到 4023575268 这种荒谬大数，于是判断"文件损坏/被加密"。

**原因**：`BytecodeFileHeader` 里 `sourceHash` 是 **20 字节 SHA1**，不是 4 字节。
所以后续字段整体后移：`fileLength` 在 **`0x20`**，`functionCount` 在 `0x28`，
`stringCount` 在 `0x34`，`stringStorageSize` 在 `0x3C`。

---

### 1.6 没有 cryptography 就放弃读证书

**现象**：`import cryptography` 失败，于是只报"无法解析证书"。

**正确做法**：签名证书本身在 `META-INF/*.RSA`（PKCS#7），但**指纹不需要解析**：
直接对 `META-INF/*.RSA` 里的证书 DER 做 SHA1/SHA256，或者更简单——
对 APK 做 `apksigner verify --print-certs`（如有）。无工具时至少给出
证书文件的 SHA1/SHA256，足以做"是否同一签名"的比对。

对照表（值得背下来）：

| Subject | 含义 |
|---------|------|
| `CN=Android Debug, O=Android, C=US` | Android 默认 debug key，**重签版** |
| 真实公司名 | 官方签名 |

---

## 二、环境与连接层

### 2.1 `adb` 命令不存在 / 版本不匹配

**现象**：`adb: command not found`，或设备显示 `offline`。

**正确做法**：
- **优先用模拟器自带的 adb**（版本与服务端最匹配）：雷电 `C:\leidian\LDPlayer14\adb.exe`；
- 系统 PATH 里的 SDK adb 版本高/低于模拟器时，设备会 `offline`；
- `adb kill-server && adb start-server` 再 `connect`。

---

### 2.2 `adb root` 报 "cannot run as root in production builds"

**现象**：`adbd cannot run as root in production builds`。

**原因**：模拟器的 root 开关**没开**，与 adb 版本无关。

**正确做法**：模拟器设置里勾选 root →**必须重启实例**（不重启不生效）→
`adb shell id` 应显示 `uid=0(root) ... context=u:r:su:s0`。

`[案例]` 雷电 14：开 root 前 `uid=2000(shell)`，开+重启后 `uid=0(root)`。

---

### 2.3 想靠改名 `su` 来隐藏 root — 做不到

**现象**：`mv /system/bin/su /system/bin/su.bak` 报 `Read-only file system`。

**原因**：现代模拟器是**动态分区 + dm-verity**，`/system` 只读。

**另一个陷阱**：`mount -o remount,rw /system` 的报错是
`mount: '/system' not in /proc/mounts`——**这句里没有 "read-only" 字样**。
用字符串匹配 "read-only" 判断可写性，会得出"可写"的错误结论。

**正确做法**：用**真实写探针**判断：

```bash
(touch /system/bin/.w 2>/dev/null && rm -f /system/bin/.w && echo WRITABLE) || echo READONLY
```

要隐藏 root 只能 hook（Java 层拦文件存在性判断，或 native 层拦 `access`/`stat`/`open`）。

`[案例]` 森空岛：第一版 `--info` 因此误报 `/system 可写`，第二版改探针后修正。

---

### 2.4 用 `su -c` 包所有命令

**现象**：`su: not found`，或者弹授权框卡住。

**原因**：`adb root` 之后 shell **本身就是 root**，不需要 `su`；而且 `su` 可能不存在。

**正确做法**：`adb root` 后直接 `adb shell "<cmd>"`。`su` 只在对 root 隐藏要求低的
场景（普通真机 + Magisk）才用。

---

### 2.5 设备上没有 `dd` / `base64`

**现象**：`dd: not found`，或者 `dd` 存在但行为异常。

**原因**：Android shell 工具来自 **toybox**，`dd` 不在默认命令集里；老设备是 toolbox，
更没有。

**正确做法**：显式写 `toybox dd`；同样 `toybox base64`、`toybox od`。
先 `adb shell toybox | tr ' ' '\n' | grep -x dd` 确认。

---

### 2.6 `pidof` 返回多个 pid

**现象**：`pidof com.pkg` 输出 `2134 2160`。

**原因**：多进程应用（主进程 + `:push` / `:service` 等子进程）。

**正确做法**：取**第一个**（主进程）做内存 dump；若要覆盖全部进程，
对每个 pid 各扫一遍（子进程里也可能有 DEX，但通常是同一个）。

---

## 三、内存脱壳层

### 3.1 读 `/proc/pid/mem` 全是空

按概率排序的四个原因：

| 原因 | 判据 | 修法 |
|------|------|------|
| 没 root | `id` 不是 `uid=0` | 开 root + 重启实例 |
| 从偏移 0 读 | `head -c 16 /proc/PID/mem` 为空 | 按页对齐 seek |
| 用了 `dd` 不是 `toybox dd` | `which dd` 为空 | 改 `toybox dd` |
| stderr 污染了 stdout | 输出长度忽大忽小 | `exec-out sh -c "... 2>/dev/null"` |

**原理**：`/proc/pid/mem` 按映射表做访问控制，地址 0 没有映射 → `EIO`。
必须 seek 到已映射地址，且 `bs=4096` 页对齐，`skip = start // 4096`。

---

### 3.2 `adb exec-out` 里用重定向无效

**现象**：`adb exec-out "toybox dd ... 2>/dev/null"` 返回空或报参数错误。

**原因**：`exec-out` 不做 shell 解析，`2>/dev/null` 被当成 dd 的字面参数。

**正确做法**：`adb exec-out sh -c "toybox dd ... 2>/dev/null"`。

---

### 3.3 候选区域筛得太干净，反而 0 命中

**现象**：只保留"纯匿名 `rw-p`"，结果什么都没找到。

**原因**：壳的解密区常是 **`rwxp`**（可执行）或带 `[anon:...]` 标签，
按"必须 `rw-p`"筛会漏掉。

**正确做法**：只要求 **含 `r`**，权限组合不限；先 `--list` 看地形再收紧。

---

### 3.4 dump 到了但只有 1 个 DEX

**原因**：
1. 应用本来就单 dex；
2. 壳**惰性解密**（用到才解），只 dump 一次拿不全；
3. dump 时机太早，后面几个 DEX 还没加载。

**正确做法**：让 App 多走几个界面（登录、进主页、开二级页）后重复扫描，
产物按 SHA1 自动去重，多扫几次不亏。

---

### 3.5 App 一启动就闪退（反 root）

**现象**：`am start` 后进程立刻消失。

**原因**：加固包里的 root/emulator 检测。检测点常在**登录、授权、支付**等业务节点，
启动阶段未必触发——所以"启动就崩"和"用一会儿才崩"要区别对待。

**正确做法**（按成本排序）：
1. **抢窗口**：`am start` 与 `pidof` 在同一行内连跑，拿到 pid 立刻 dump；
2. **先停再启**：`am force-stop` → `am start` → 立即扫，赶在检测定时器前；
3. **hook 检测点**：Frida 拦 `java.io.File.exists` / `Runtime.exec` / `System.getProperty`。

`[案例]` 森空岛：开 root 后**并没有**在启动阶段闪退，稳定停在 LoginActivity，
所以 dump 顺利完成。检测代码（`su` 路径、`magisk`、`frida`、`ro.debuggable`、
`Game signature`）确实存在，但触发点后置/被 patch。

---

### 3.6 一次读取几百 MB，慢到怀疑人生

**原因**：`dd` 按页读，跨 adb 通道传二进制，百 MB 级要几十秒到几分钟。

**正确做法**：先 `--list` 看地形，只对命中的区域整段读；头部探测 64KB 足够
（mmap 出来的 DEX 起点就在区域开头附近）。

---

## 四、DEX 层

### 4.1 dump 出来的 DEX 被 jadx 拒绝

**现象**：`Invalid checksum` / `Bad signature`。

**原因**：壳把 DEX 直接交给 ART，**从不重算头部**。ART 对内存 DEX 不校验，
所以 App 正常跑；jadx 校验，所以拒绝。

**正确做法**：重算。**顺序必须是对的先 signature、后 checksum**：

```python
buf[12:32] = sha1(buf[32:])                 # signature 覆盖 [0x20, EOF)
buf[8:12]  = adler32(buf[12:])              # checksum 覆盖 [0x0C, EOF)，含刚写的 signature
```

写反了 checksum 永远不对（因为 signature 会在之后被改写）。

---

### 4.2 怎么判断 DEX 是完整的

**别用 checksum**（内存 DEX 天然不匹配）。用两条：

1. `file_size`（偏移 0x20）== 实际长度；
2. 遍历 `class_def → class_data_item → method`，每个 `code_off` 都在 `(0x70, len-8)`；
   `code_off == 0` 表示抽象/无方法体，合法。

`invalid == 0` 就是"结构没坏"的硬证据。`dex_fix.py` 会打这两个数。

`[案例]` 森空岛：5 个 DEX 全部 `valid=52752+ / invalid=0`，内容完整。

---

### 4.3 按 magic 找 DEX 找到一堆假的

**原因**：字符串表里就可能有 `dex\n035` 这个字面量；随机数据里 4 字节命中也常见。

**正确做法**：magic 命中后必须校验 `0x20` 处的 `file_size` 自洽
（`0x70 ≤ size ≤ 300MB` 且不超出区域），否则丢弃。

---

### 4.4 裁 DEX 裁多了

**现象**：切出来的 DEX 末尾带着另一段数据，或者 jadx 报 map 越界。

**原因**：一个区域内常常**连续 mmap 了多个 DEX**，切到区域末尾就会吞掉后面。

**正确做法**：严格按 `file_size` 切；同一区域内的多个 magic 各自切一份。

---

## 五、Hermes / RN 层

### 5.1 一直扫不到 Hermes bundle

**原因**：RN 引擎**还没初始化**。`libhermes.so` / `libreactnativejni.so` 没加载，
bundle 自然不在内存里。

**判据**：`adb shell "grep -c hermes /proc/$(pidof com.pkg)/maps"` → `0` 就是没加载。

**正确做法**：先让 App 进入真正的 RN 页面（登录后 / 首页），再扫。

`[案例]` 森空岛：停在 LoginActivity 时 maps 里 hermes 相关 0 命中，只有 DEX 可拿。

---

### 5.2 Hermes 的"文件长度"字段不可全信

**现象**：按 `0x20` 处的长度裁剪，切出来的东西头部对但尾部垃圾。

**原因**：Hermes 头部布局与 DEX 不同，`0x20` 处的值只是**启发式长度**。

**正确做法**：先按启发式切，然后用字节码格式自校验（版本字段、段表偏移都在文件内），
不行就退化成"切到区域末尾"再人工裁。

---

## 六、工具链安装层

### 6.1 `pip install frida` 装不上

**现象**：国内镜像（清华/USTC）报 403 或 `No matching distribution`。

**原因**：`frida` 的 wheel 不在部分镜像的同步范围；USTC 会 302 到清华，清华 403。

**正确做法**：显式指定官方源 `--index-url https://pypi.org/simple`，
或先 `pip index versions frida` 确认目标源到底有没有。

**隐藏坑**：`pip install ... | tail` 的退出码是 `tail` 的，**永远是 0**。
"exit code 0 但 import 失败"就是这样来的。判断成功要看 `import frida` 是否真的能用。

---

### 6.2 `frida-server` 下载 502 / 中断

**原因**：`frida-server` 只在 GitHub Releases 分发，国内直连常 502 或断流。

**正确做法**：走代理前缀（`https://ghproxy.net/https://github.com/...`），
并用 `curl -C -` 续传。校验：文件大小应与 release 页一致。

**必须匹配**：`frida`（Python 包）与 `frida-server`（设备端）**版本号完全一致**，
否则 `frida-ps -U` 报协议不匹配。

---

## 七、结论与报告层

### 7.1 把"没读到"当成"不存在"

**现象**：报告写"该应用没有 root 检测"，实际是虚拟机没跑起来、根本没验证。

**正确做法**：区分三种状态并如实标注：

| 状态 | 表述 |
|------|------|
| 验证存在 | "存在，证据：<具体字符串/类名/logcat 行>" |
| 验证不存在 | "在 <范围> 内未发现" |
| 未验证 | "环境阻断（无 root / 无网络），未验证" |

第三类不能省略，也不能改写成第一类的否定形式。

---

### 7.2 用一个判据下结论

**现象**：只看"存在 libDexHelper"就断言是 SecNeo 加固，结果误判。

**正确做法**：至少 **2 条独立判据**一致（库名 + 类名前缀 + 桩 DEX 规模 + logcat 关键字），
并在报告里把判据逐条列出。

---

### 7.3 报告只写结论不写边界

**正确做法**：报告必须有一节"边界与未解项"，写清：
- 没拿到什么（如"证书期望指纹不在文件内"）
- 为什么（如"硬编码在加密 native 层"）
- 需要什么条件才能拿到（如"root + IDA 分析 libDexHelper"）

这一节是报告可信度的来源。**没有边界的报告等于没有结论。**

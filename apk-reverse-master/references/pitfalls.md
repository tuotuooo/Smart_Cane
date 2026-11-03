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

### 1.5c 裸打印扫描取 Hermes 字符串 → 造出假串

**现象**：把 `stringStorage` 区当连续可打印字节扫，得到 `oauth2`、`one_login`、`geetest`、
`AUTH_INVALID_CODE` 之类的"业务串"，看着很真，写进报告。

**原因**：HBC 的字符串存储是**连续拼接**的（无分隔符，靠 string table 的 offset 定位）。
按可打印区间切分必然**把相邻的两三个串粘成一条**，于是跨边界拼出并不存在的词。

**验证方法（必做）**：

```python
d = open("main.jsbundle","rb").read()
for k in [b"oauth2", b"one_login", b"geetest"]:
    print(k, d.count(k))     # 全 0 → 之前的"发现"是假的
```

`[案例]` 森空岛：`oauth2` / `one_login` / `geetest` 在 bundle 原始字节里 **0 命中**；
`one_login` 的真实来源是 Java 层极验 SDK 的资源名 `gt_one_login_btn_*`。
后续改用字符串表重提，得到 23,045 条准确结果。

**正确做法**：用 `hermes-dec` 反汇编（它按 string table 解码），再 `hbc_index.py` 索引。

---

### 1.5d shell glob `classes[0-9].dex` 漏掉 `classes.dex`

**现象**：写脚本扫全部 DEX 找某个串，结果报"0 命中"，据此宣布该串不存在。

**原因**：`classes[0-9].dex` 匹配 `classes2.dex`…`classes9.dex`，**不匹配没有数字的
`classes.dex`**——而主 DEX 恰恰就是它。

**正确做法**：显式列名，或用 `classes*.dex`：

```python
files = [f"classes.dex"] + [f"classes{i}.dex" for i in range(2, 6)]   # 显式
# 或
glob.glob("**/classes*.dex", recursive=True)
```

`[案例]` 森空岛：本轮一度因此误判"`one_login` 端点不存在"，差点写成第四条错误结论。

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

### 2.7 并发跑 adb 命令，连接突然断掉

**现象**：两条命令（比如"连接模拟器"和"截图"）同时发出去，第二条报
`device offline` / `adb server version doesn't match`，甚至整个 adb server 被重启。

**原因**：adb 是**单 server 多客户端**。两条命令同时触发"重启 server"
（版本不一致 / 端口冲突时）会互相把对方的连接踢掉。

**正确做法**：连接类命令与操作类命令**合并进同一条 shell 调用**（`&&` 串联），
不要在同一时刻并行发多条 adb。批量操作前先 `adb devices` 确认在线，
再一次性下发。真需要并行时，用同一个 server、不同 `-s <serial>`，且不要带
`kill-server` / `start-server`。

---

### 2.8 Git Bash 把设备端路径改写成 Windows 路径

**现象**：`adb shell uiautomator dump /sdcard/ui.xml` 报
`UI hierchary dumped to: C:/Program Files/Git/sdcard/ui.xml`，设备上找不到文件。

**原因**：MSYS2/Git Bash 的路径自动转换把 `/sdcard/...` 当成本机绝对路径。

**正确做法**：

```bash
export MSYS_NO_PATHCONV=1        # 整个会话关闭转换
# 或临时：MSYS_NO_PATHCONV=1 adb shell ...
# 或绕开：adb exec-out uiautomator dump /dev/tty > ui.xml
```

同理影响 `adb shell "echo x > /data/local/tmp/f"` 这类带重定向的命令。

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

`[案例]` 森空岛：开 root 后**并没有**在启动阶段闪退，稳定停在 LoginActivity，dump 顺利完成。

⚠️ **这个案例最初被写成了"检测存在但触发点后置/被 patch"——那是错的。** 后续用
`dex_tool.py` 对每条 root 检测字符串做 `const-string → 所属方法` 反向定位，发现它们
**没有一条来自业务代码**：`getRootState`/`magisk` 来自极光推送（`cn.jiguang`，内嵌 RootBeer），
`test-keys`/`superuser`/`goldfish` 来自 Sentry，`frida` 来自极验（`com.geetest`），
su 路径来自游戏加速器 `libdivider2.so`（检测到 root 只关 boost，不杀进程）。
`com.hypergryph.*` 下**根本没有任何 root 检测类**。

**教训（比技巧更重要）**：`grep` 到 `su`/`magisk`/`frida` 不等于"这个 App 会反 root"。
第三方 SDK 会往你的样本里塞进大量这类字符串。**在下"它会检测"的结论前，必须把字符串
反查到所属类和调用方**，确认是业务代码还是 SDK。否则整条推演都建在别人的代码上。

对应做法：`python dex_tool.py str <dex> "magisk"` → 直接给出引用它的完整方法签名。

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

### 4.5 反汇编出来 `invoke {v3,v0,v0,v0}`、argc 是 16/32/48

**现象**：自己写的 DEX 解码器跑出来的 `invoke-*` 参数个数离谱，寄存器列表尾部一堆 `v0`，
但方法签名、字符串、跳转目标都能正常解析。

**原因**：`invoke` 的 8 位 `AA`（argument word count，只用到 0–5）被**左移了 4 位**：

```
AA_实际 = AA_存储 >> 4
```

这是针对反编译器的编码混淆——高 4 位本来就空闲，左移不丢信息、可逆，但标准解码器会把
`0x20` 当成 argc=32。

**怎么确认是它、而不是自己算错边界**（两步，缺一不可）：

1. **先证边界对**：按 `OPLEN` 表走完整段，必须**恰好**在最后一个 unit 收尾（如 41/41 对上
   `return-void`）。边界错了不会有这种巧合。
2. **再证字段变换**：用 `FEDC`（寄存器列表）做交叉校验——按 `AA>>4` 取 argc 后，
   `regs[argc:]` 应全为 0。森空岛实测 **264,789 / 264,818 = 99.99%** 吻合，而直接取 `AA`
   只有 19 条吻合。

**别过度推广**：只改 `invoke`。同一份 DEX 里 `const-string`(0x1a)、`if-*`(0x38)、
`return`(0x0f) 的低 nibble 分布完全正常（覆盖 0–15），说明它们**没有**被处理。
先统计再动手，别整表套用。

**现成工具**：`apk-analyzer/scripts/dex_tool.py` 已内置该修正，纯标准库、不需要 JRE/jadx：

```
python dex_tool.py str    <dex> "Game signature"     # 字符串 → 引用它的方法
python dex_tool.py method <dex> "Lo0/w;" i           # 反汇编某个方法
python dex_tool.py xref   <dex> "checkDeviceRoot"    # 谁调用了它
```

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

---

## 八、IoT / 固件层

### 8.1 用"芯片有安全启动"直接判"固件刷不了"

**现象**：查到芯片型号（SiFli / Nordic / BES…），看到厂商文档写"支持 Secure Boot、
efuse rootkey、RSA 签名"，于是断言"自编译固件刷不进去"，写进报告收工。

**原因**：**把两条不同的路径当成了一条**。

```
路径 A  上电启动：  bootloader ──[efuse rootkey 验 app 镜像]──> 运行
路径 B  固件升级：  App ──SPP/BLE──> 固件内 dfu 模块 ──[??? 验签]──> 写 flash
```

efuse 保护的是**路径 A**。路径 B 的校验实现**在固件里自己写**——它可能复用同一套
RSA 公钥（那就真封死），也可能只是 CRC + 魔数（低端方案很常见，那就完全开放）。
**从芯片手册推不出路径 B 的实现。**

**正确做法**：
1. 先证路径 B 存在（有没有 OTA 接口、传输函数、OTA 状态机）；
2. 再证包能拿到（`otaFileUrl`）；
3. 最后**解固件本体**看 dfu 校验函数。到这一步才有资格说"能/不能"。

`[案例]` 悦心S1：首轮据 SiFli 通用方案判"efuse 封死、刷机不现实"，第二轮在 App 里
发现完整的 `device_ota` 模块 + `api/ota/dfu/checkUpdate` + `sendZipToFirmware`，
结论必须降级为"通道存在，验签强度待固件验证"。

---

### 8.2 把 Flutter 的 DEX 类数当代码量

**现象**：153MB 的 APK，`classes.dex` 只有几百个类，判断"这 App 没什么东西/被加固了"。

**原因**：Flutter 应用的业务代码编译进 `lib/<abi>/libapp.so`（Dart AOT snapshot），
DEX 里只剩启动壳和 MethodChannel 桥接。用 DEX 类数衡量代码量在 Flutter 上**完全失效**。

**正确做法**：`analyze` 里看到 `libapp.so` 就直接走 `flutter` 子命令。
Dart 字符串是**明文**存在 snapshot 里的，`package:xxx/yyy.dart` 还能直接反推模块结构，
比读汇编快一个数量级。

`[案例]` 悦心S1：44MB 的 `libapp.so` 里直接读出 `device_ota` / `device_dial` /
`protocol_lib` 三大模块和 125 条接口路径，全程没碰反汇编。

---

### 8.3 把白牌方案当"该品牌自研"分析

**现象**：接的是 A 品牌手表，于是按"A 公司自研协议"去啃，每个字段都从零猜。

**原因**：大量消费级硬件是**白牌方案**——同一套 App 换皮肤卖给几十个品牌。
判据：命中 `idoocloud` / `veryfitplus` / `switchAppKey`（VeryFit/IDO）、
`zepp` / `huami`（小米生态）、`huawei_health` / `hilink` 等。

**为什么重要**：白牌意味着固件格式、协议栈、工具链**全网通用**。按"通用方案"找，
别人的研究、同方案的固件包、厂商的 PC 工具都能直接复用；按"自研"找，等于把
已经有人做完的事重做一遍。

`[案例]` 悦心S1：App 里全是 `*.idoocloud.com`，还有 `switchAppKey` 切换界面 →
实为 VeryFit(IDO) 白牌，ASUS 只是贴牌方。

---

### 8.4 凭 App 里命中某芯片厂就断定设备芯片

**现象**：`libapp.so` 里搜到 `sifli`，于是判"芯片是 SiFli"，写进结论。

**原因**：配对 App 通常内置**通用协议 SDK**（`protocol_c` 一类），一个库同时支持
SiFli / Nordic / Realtek / Ambiq / Telink 多家。命中某家只证明"SDK 支持它"。

**正确做法**：**双重证据**才定芯片。
1. 设备端证据：GATT 服务 UUID 尾段、广播 manufacturer data、固件内厂商串、拆机丝印；
2. App 端佐证：SDK 里该芯片的专用代码路径（有专属 `xxx_dial_make.c` 这类源文件名更好）。

`[案例]` 悦心S1 的判定链：App 里 `[芯片厂指纹] 命中 5 家`（不可用）→
设备 GATT UUID `00000000-0000-0000-6473-5f696c666973` 小端解出 `sifli_sd`（硬证据）→
`libprotocol_c.so` 内有 `watch_dial/sifli_dial/app_custom_dial_make.c` 源码路径（佐证）
→ 才敢下"确证 SiFli"。

---

### 8.5 `ota` 子串误命中，造出一堆假线索

**现象**：按 `ota` 过滤字符串，得到 `Annotation`、`Bogota`、`microtask`、`rotation`、
`AnnotatedRegion` 等一堆结果，还以为发现了 OTA 逻辑。

**原因**：`ota` 是极常见的子串。`Annotation`（n-**ota**-tion）、`Bogota`（Bog-**ota**）、
`microtask`（micr-**ota**-sk）、`rotation`（r-**ota**-tion）全都中招。

**正确做法**：按**词边界或驼峰**匹配：

```python
OTA_RE = re.compile(r"OTA|Ota|(?<![A-Za-z])ota(?![A-Za-z])")
```

这样 `isOtaIng`、`SifliOtaFinished`、`otaFaceName` 命中，而上面那四个不命中。
另外多语言文案里 `ota` 也是常用词（芬兰语 "ota" = 拿），含空格的长句要单独过滤。

---

### 8.6 把表盘/资源包当成固件

**现象**：看到 `.zip` + 版本号 + 通过 OTA 接口下发，就认定这是固件包，结果解出来
一堆 PNG。

**原因**：表盘、字库、语言包、AGPS 数据往往和固件**共用同一条传输通道**和同一批接口
（`sendZipToFirmware` 就是既发表盘也发固件的通用函数）。区别在内容格式，不在传输。

**这反而是好事**：表盘包**不需要固件签名**（设备只解析格式），所以它是**验证链路
成本最低的探针**——成功了说明 SPP 传输、分包、握手全通；失败了最多表盘不显示。

**正确做法**：先做表盘验证链路，再谈固件。顺序反了会把"链路不通"误判成"验签拦了"。

---

### 8.7 改数据库伪绑设备，但 UI 入口不出现（依赖"实连"的入口）

**现象**：往 `DeviceCurrent` 表插入完整行（`isConnect=1`、`otaVersion='1.01.03'`、
`fwVersion*` 齐备），App 首页**设备卡片正常出现**，但点进去**没有"固件更新"入口**。
于是怀疑字段名写错、字段值不对，反复调 db —— 全是白工。

**实测结论（悦心S1 / AsusExercise）**：**没有真实蓝牙连接就不会出现固件更新入口**，
这是设计行为，不是注入姿势问题。

**代码依据**（Dart AOT 字符串表可直接读到，无需反汇编）：

```
package:device_ota/utils/ota_workflow.dart     ← 升级工作流，内含 _checkDeviceState@2184515255
package:device_ota/utils/ota_check.dart
package:device_ota/controller/ota_main/network.dart   ← checkUpdate 请求
断言文案：OTA: deviceInfo == null || otaVersion.isEmpty
```

即入口的前置条件是 **`deviceInfo != null` 且 `otaVersion` 非空**，而 `deviceInfo` 来自
`protocol_lib/src/device_info/` —— 连接建立后从设备**实时读取**的运行时对象，
**不读 `DeviceCurrent` 表**。db 只用于首页列表渲染，两套数据源。

**判据（通用）**：判断某个 UI 入口读 db 还是读实时态，看 Flutter 包的 `package:` 路径：

| 证据 | 含义 |
|------|------|
| 页面 controller 直接调 `xxx_dao.dart` | db 可信，注入有效 |
| 存在 `_checkXxxState` / `_checkUpdatePreconditions` 且牵扯 `deviceInfo` | **实时态**，db 注入无效 |
| 文案里带 `deviceInfo == null` 这类断言 | 同上，断言就是前置条件说明书 |

**正确做法**：
1. 别在 db 字段上纠缠。调一轮不生效就判定为"依赖实连"，立刻换路线。
2. 依赖实连的入口只有两条路：**真机实连**（最省事），或**伪造一个完整 GATT/SPP 外设**
   （成本极高，一般不值）。
3. 想要的是**固件本体或协议**而非 UI 时，绕开入口：固件由 App 下载后经
   `flutter_bluetooth/channel/firmware_data_channel.dart`（对应原生
   `IDOProtocolAPIExtRegisterCallback|_registerDataTranProgressCallbackReg`）走蓝牙下发，
   因此 **HCI snoop log 能同时拿到固件字节流与完整传输协议**，且 `adb bugreport`
   可取回、**不需要 root**。这比攻破 UI 前置条件划算得多。

**附带的落库线索**：`checkUpdate` 的响应会写入 `SportIconBean` 表
（`deviceModelId / deviceId / version / remark / appFileUrl / otaFileUrl`），
即真机只需 checkUpdate 一次，`otaFileUrl`（固件直链）就已落盘，但该 db 在
`/data/data/<pkg>/databases/`，读取需 root。

---

## 九、改包与重签层

> 这一层的共同特征：**改完能装上、能启动、但行为不对**，而且日志里没有任何线索。
> 操作配方在 `apk-analyzer/references/axml_patch.md`，这里只记"哪儿会翻车"。

### 9.1 给 AXML 插入新属性，装上了但完全没效果

**现象**：想给一个 `exported=false` 的 Activity 加 `android:exported="true"`。
插入了属性记录、更新了 `attributeCount` 和 chunk size、重建了字符串池、
把 ResourceMap 扩到与字符串池等长 —— 装包正常，`dumpsys package` 里仍然是 `exported=false`。
`am start` 继续报 `not exported from uid`。

**做了什么对照实验**：

| 实验 | 结果 |
|------|------|
| 改已有 `allowBackup` 的 data（真→假） | ✅ `ALLOW_BACKUP` 标志确实消失 |
| 插入 `exported`（完整重建池 + 扩 map） | ❌ 无效 |
| 插入 `exported`（最小改动，复用已有索引） | ❌ 无效 |
| 插入的 20 字节与 MainActivity 的 `exported` **逐字节一致** | ❌ 无效 |

**结论**：**Android 只认原本就在 `attrExt` 里的属性记录，追加的一律忽略。**
这不是格式写错 —— 是解析路径根本不读追加项。所以"把字节拼对"这条路是死的。

**正确做法（牺牲法）**：找该元素上一个**存在但无用**的属性，把它改造成 `exported`：
改 `name` 索引 + `rawValue=0xFFFFFFFF` + `type=0x12` + `data=0xFFFFFFFF`。
首选牺牲 `screenOrientation`（丢了只是这页能旋转），其次 `configChanges`、`launchMode`。
`theme` 绝对不能动（见 9.2）。

**判别口诀**：**改值生效，插入无效，扩 map 无用。**

---

### 9.2 把元素唯一属性改掉 → `does not specify android:name`

**现象**：

```
INSTALL_PARSE_FAILED_MANIFEST_MALFORMED: <activity> does not specify android:name
```

**原因**：批量处理时"每个 Activity 都挑第一个属性改造成 exported"，
而某些 Activity 只有 `android:theme` 一个属性，被改掉后连 `name` 都没了。

**正确做法**：
1. 改之前先 dump 该元素的属性清单，确认它有**至少两个**属性；
2. **`android:name` 永远不动**；
3. 宁可跳过这个组件，也不要为了覆盖率把它改坏。

---

### 9.3 把 ResourceMap 扩到与字符串池等长

**现象**：原始 manifest 的 resource map 只有 54 项，字符串池有几百条，怀疑"不全"，
于是补齐到等长。装机无报错，**行为零变化**。

**原因**：resource map 只是给 `attrExt` 里已有的属性记录查资源 ID 用的，
不是"字符串 → 资源 ID"的全量映射。它对新增属性没有任何帮助。

**正确做法**：**不要动它。** 扩它没有收益，只会让文件结构更难解释、
更容易在后续对比中引入噪声。

---

### 9.4 `am start` 被拒，误判成"没有入口"

**现象**：从 DEX/Flutter 包里挖到一个关键 Activity（比如相册网格、视频编辑页），
`am start -n pkg/.XxxActivity` 报：

```
java.lang.SecurityException: Permission Denial: starting Intent { ... }
from null (pid=..., uid=2000) not exported from uid 10190
```

于是判断"这个功能调不起来，放弃"。

**这是判据错误**：报错说的是**你没权限调它**，不是**它不能跑**。
App 自己用显式 Intent 启动它毫无问题。

**正确做法**：先分清三件事：

| 情况 | 判据 | 出路 |
|------|------|------|
| 组件存在、只是没导出 | manifest 里有，`exported=false` | 改包（9.1 牺牲法） |
| 组件存在、但产品流程里从不调用 | DEX 里引用它的地方为 0 / 依赖的类被 R8 裁掉 | **改包也没用**，这条路是死胡同 |
| 组件不存在 | manifest 里搜不到 | 换思路 |

第二种的典型特征：类还在 manifest 里，但 `ClassNotFoundException` 在启动瞬间抛出，
因为 R8 把它的依赖（第三方库类）裁掉了 —— 说明**产品层从来没走过这条路径**。
这时改包能把它"叫起来"，但它跑不完。

---

### 9.5 指望深链 / adb 广播 / `route` 参数直达内部页面

**现象**：想让 App 直接打开某个内部页面，试了 `am start -a VIEW -d "appscheme://..."`、
`am broadcast`、甚至猜 `--es route xxx`，全部无反应或落到首页。

**原因**：路由不是这么实现的。实测在 Flutter 包里搜 `uni_links` / `app_links` /
`getInitialLink` / `getInitialRoute` —— **0 命中**，说明根本没有外部深链接收入口。

**正确做法**：**先证明入口存在，再想怎么进**。

```bash
# 1. manifest 里有没有 scheme / 有没有 receiver 接外部广播
python <skill>/scripts/apk_analyze.py manifest app.apk
# 2. Flutter 包里有没有深链库（0 命中就别试了）
python <skill>/scripts/apk_analyze.py flutter app.apk --keyword link
```

两条都空 → 只剩改包一条路，且改完要接受 9.6 的代价。

---

### 9.6 重签后直接 `adb install`，以及它的真实代价

**现象**：`INSTALL_FAILED_UPDATE_INCOMPATIBLE`（签名冲突），或装上了但 App 数据全空、
设备要重新绑定、登录态丢失、官方增量更新从此装不上。

**原因**：签名变了就是"另一个 App"。同包名只能覆盖安装同签名的包。

**正确做法与代价清单**（动手前先接受）：

| 代价 | 说明 |
|------|------|
| 必须先 `adb uninstall` | App 数据、登录态、本地配置全清 |
| 蓝牙绑定丢失 | 设备侧不用重置，但 App 里要重新配对 |
| 官方升级通道断掉 | 之后想升级只能卸载再装官方包 |
| 部分 SDK 拒服 | 极验/支付/推送在签名不符时可能静默降级 |
| 反篡改可能杀进程 | 有 `manifest.mf` 逐文件哈希的样本，改一个字节就跑不起来 |

**所以先问一句**："有没有不改包就能拿到同样信息的办法？"
通常都有 —— 抓 HCI（`ble-device-recon` 附录 A）、抓 HTTPS（`android-https-capture`）、
脱壳（`apk-runtime-dump`）。**改包应该是最后手段，不是第一手段。**

---

### 9.7 改包成功后的"观察陷阱"

改包只是让页面能起来，**看不到内容还有别的原因**，别急着怀疑改坏了：

| 现象 | 真因 | 处理 |
|------|------|------|
| 相册/文件页一片空白 | App **没申请**媒体权限（manifest 里就没有），不是改包导致 | `adb shell pm grant <pkg> android.permission.READ_MEDIA_IMAGES` 等，再重启 App |
| 点某张图立刻崩 | 依赖类被 R8 裁掉（`ClassNotFoundException: xxx.PhotoView`） | 该路径产品层从未使用，放弃 |
| 按估算坐标点击总是点空 | 屏幕分辨率/导航栏高度没算对 | 截图 → 裁剪放大 → 用像素定位，别用比例猜 |
| 页面起来了但立刻返回 | 内部有前置校验（登录/绑定/设备在线） | 这是业务前置条件，不是改包问题 |

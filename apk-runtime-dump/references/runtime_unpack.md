# 运行时脱壳：原理、坑与排查

本文件是 `apk-runtime-dump` 的深度参考。脚本都跑不通、或结果异常时读这里。

---

## 一、为什么静态一定拿不到

商用加固（SecNeo 盛安德、腾讯乐固、梆梆、360、爱加密）的共同模型：

```
APK 内                    运行时
─────────────────────────────────────────────
classes.dex  ← 壳的桩     Application.attachBaseContext()
                          → 加载 libDexHelper.so / libshella.so
加密载荷（slack space）   → native 解密
lib*.so（壳的 native）    → InMemoryDexClassLoader 加载
assets/*（加密 bundle）   → ART 执行
```

判断是不是桩 DEX 的几个硬指标（`apk-analyzer` 会给）：

| 指标 | 正常 APK | 加固桩 |
|------|---------|--------|
| DEX 类数 | 与业务规模匹配 | 只有几十~几百 |
| DEX 方法数 | 数千以上 | 一两百 |
| 字符串数 | 数千 | 两三百 |
| 文件尾部 | 正常结束 | 大量重复填充（把文件撑到几十 MB） |
| 类名 | 业务包名 | `Lcom/secneo/apkwrapper/*`、`Lcom/stub/*` |

**注意**：桩 DEX 常被撑到 40MB+，看着像"巨大明文 DEX"，其实是填充。
别把它当成真实代码去分析。

真实 DEX 一定在内存里明文存在——否则 ART 没法执行。这就是本 skill 的立足点。

---

## 二、读 `/proc/<pid>/mem` 的四个坑

### 坑 1：从偏移 0 读一定失败

```bash
$ adb shell "head -c 16 /proc/1234/mem"
# 读出来是空的 / 报 EIO
```

`/proc/pid/mem` 是**按映射表做访问控制**的伪文件。地址 0 没有映射，读它返回 `EIO`。
必须 **seek 到某个已映射的地址**再读。所以不能用 `cat`，必须用支持 `skip` 的 `dd`。

### 坑 2：必须页对齐 seek

```bash
# 目标地址 0x7c37c3a00000
skip = 0x7c37c3a00000 / 4096
dd if=/proc/$PID/mem bs=4096 skip=$skip count=$pages
```

- `bs` 固定在 4096（页大小），`skip` 用 `start // PAGE` 算页号。
- 不用页对齐 seek 会读到 `EINVAL`。
- 想读 N 字节：`count = ceil(N / 4096)`，尾部多读的字节自己裁掉。

### 坑 3：设备上可能没有 `dd`

```bash
$ adb shell which dd
# 空  ← toolbox 里没有 dd
$ adb shell toybox dd --help
# 有
```

Android 的 shell 工具来自 **toybox**（或老版本 toolbox）。
`dd` 不在 toolbox 的默认命令集里，PATH 上找不到。
**必须显式写 `toybox dd`**。

同理，`base64` / `od` / `hexdump` 找不到时也先试 `toybox <cmd>`。

### 坑 4：`adb exec-out` 不会经过 shell

```bash
# 错：重定向被当成 dd 的字面参数
adb exec-out "dd if=/proc/1234/mem ... 2>/dev/null"

# 对：包一层 sh -c
adb exec-out sh -c "toybox dd if=/proc/1234/mem bs=4096 skip=... count=... 2>/dev/null"
```

另外 `adb shell "cmd"` 会把 `stderr` 混进 `stdout`（PTY 模式），二进制数据会被污染。
**读二进制一律用 `adb exec-out` + `sh -c` + `2>/dev/null`。**

```python
# 正确写法
dev.run(["exec-out", "sh", "-c",
         "toybox dd if=/proc/%s/mem bs=4096 skip=%d count=%d 2>/dev/null"
         % (pid, start // 4096, pages)], binary=True)
```

---

## 三、maps 里哪些区域值得看

```
地址范围                  perms  offset  path
7c37c3a00000-7c37c9e00000 rw-p  00000000        ← 匿名，最可疑
40006014b000-4000691de000 rwxp  00000000        ← 壳的可执行区（DEX 常在此）
7c3700000000-7c3700400000 r-xp  00000000 /system/framework/boot.art  ← 跳过
```

筛选规则：

1. **必须含 `r`**。写执行的 `rwxp` 区照样要读（壳的解密区常是 `rwxp`）。
2. **优先匿名区**（path 为空）。文件映射的 `.art` / `.vdex` / `.odex` 是原始未加密产物，没意义。
3. **尺寸过滤**：跳过 < 1MB（装不下一个 DEX）和 > 400MB（通常是保留地址空间，读它纯浪费时间）。
4. 跳过这些 path：`/system/` `/apex/` `/vendor/` `/data/app/` `/data/dalvik-cache/`
   以及 `.so` `.odex` `.oat` `.vdex` `.art` `.apk` `.ttf` `.jar` `[vdso]` 等。

典型现象：一个 3000+ 条 maps 的进程，筛完只剩 100~200 个候选，
其中真正有货的通常 **5~15 个**。

---

## 四、DEX 头：靠结构而不是靠 magic

DEX 头部关键偏移（小端）：

| 偏移 | 长度 | 字段 | 用途 |
|------|------|------|------|
| 0x00 | 8 | magic | `dex\n035\0` |
| 0x08 | 4 | checksum | adler32，覆盖 `[0x0C, EOF)` |
| 0x0C | 20 | signature | SHA-1，覆盖 `[0x20, EOF)` |
| 0x20 | 4 | **file_size** | **裁剪长度就靠它** |
| 0x24 | 4 | header_size | 固定 0x70 |
| 0x28 | 4 | endian_tag | 0x12345678（小端） |
| 0x38 | 4 | string_ids_size | 字符串数 |
| 0x40 | 4 | type_ids_size | 类型数 |
| 0x58 | 4 | method_ids_size | 方法数 |
| 0x60 | 4 | class_defs_size | 类数 |
| 0x64 | 4 | class_defs_off | 类定义表偏移 |

**有效性判据**：`0x70 ≤ file_size ≤ 300MB` 且 `file_size` 不超出所在区域。
只用 `blob.find(b"dex\n035")` 会在随机数据里命中大量假阳性——
字符串表里就可能有 "dex\n035" 这个字面量。

裁的时候按 `file_size` 精确切，不要贪心切到区域末尾：
一个区域常常连续 mmap 了多个 DEX，切长了会把后面的 DEX 一起吞进来（还能用，但不干净）。

**CDEX**（`cdex001\0`）：Android 9+ 的紧凑格式，同样是 `0x20` 处放 `file_size`，
但内部结构（数据表、共享数据区）和标准 DEX 不同。能 dump 出来，反编译要新版工具。

---

## 五、为什么 dump 出来的 DEX 会被 jadx 拒绝

加固壳把 DEX 解密后直接交给 ART，**从不重算头部**：

```
checksum_ok = False
signature_ok = False
code_off: valid=52752 invalid=0     ← 但结构是完整的
```

ART 对内存中的 DEX 不做校验，所以 App 跑得好好的；jadx / baksmali / apktool
会先校验，于是报 `Invalid checksum` 或 `Bad signature`。

### 规范化顺序（写反了就永远算不对）

```
1. signature = SHA1(d[0x20:])        ← 覆盖到自己之前，不含 signature 自身
2. checksum  = adler32(d[0x0C:])     ← 覆盖范围包含刚写好的 signature
```

如果先算 checksum 再写 signature，signature 一变 checksum 立刻失效。
正确写法：

```python
buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
buf[8:12]  = struct.pack("<I", zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
```

### 判断"DEX 是否完整"的硬指标

不是 checksum（内存 DEX 天然不匹配），而是：

1. `file_size == len(file)`（不相等 = 被截断）；
2. 遍历 `class_def` → `class_data_item` → 每个 method 的 `code_off`，
   **全部落在 `(0x70, len-8)` 区间内**（`code_off == 0` 表示无方法体，合法）。

`invalid` 计数为 0 就说明结构没坏，可以放心反编译。
`dex_fix.py` 会把这两个数字打出来。

---

## 六、Hermes bundle

| 项 | 值 |
|----|-----|
| magic（8 字节） | `C6 1F BC 03 C1 03 19 1F` = `0x1F1903C103BC1FC6` |
| 长度字段 | `0x20` 处 `fileLength`（**不是 0x10**，因为 `sourceHash` 是 20 字节 SHA1） |
| 何时出现 | `libhermes.so` / `libreactnativejni.so` 已加载后 |
| 常见位置 | 匿名 `rw-p` 区，或 `assets/*.jsbundle` 的 mmap |

### 先判"要不要 dump"

**大部分 RN 应用的 bundle 根本没加密**，就是标准 HBC，静态直接可反汇编。
判定（`apk-analyzer bundle` 会自动做）：

```
magic == 0x1F1903C103BC1FC6  且  fileLength == 文件大小
   → 标准未加密 HBC，别 dump，直接用 hbcdump / hermes-dec
```

只有 magic 不对、或 `fileLength` 与大小不符（被截断/自定义容器）时，才需要运行时 dump。

### 熵剖面不是加密证据

标准 Hermes 文件天然"高低熵混合"：头部 + 函数头 + 字节码 + 索引表是二进制（熵 5~7），
`stringStorage` 是大段可打印文本（熵低、可打印率接近 1）。看到"前段高熵、后段可打印"
属于**正常布局**，不能据此说"代码段加密"。

### 三次误判的连锁（务必别重演）

```
① 把某个样本自己的加密头 00 07 D0 8B 当成 HERMES_MAGIC 常量
      → 真文件（头 C6 1F BC 03）被判为"魔数不匹配"
② 用 header XOR 错误常量得到 4 字节值 → 宣称"发现 XOR 密钥"
      → 但整文件 XOR 后熵 6.79→7.21（升高），DEX 中搜该值 0 命中
③ 熵测绘看到前后差异 → 宣称"双区加密容器"
      → 真相只是标准 HBC 的自然布局
```

`header XOR magic` 对任意 4 字节都成立，是恒等式，**永远不能**当作"发现密钥"。
判断 Hermes 是否加密，只认 **magic + fileLength 自洽**。

---

## 七、失败排查表

| 现象 | 原因 | 处理 |
|------|------|------|
| 读内存全是空 | 没 root | `adb root` 后重开 shell；雷电要在设置里开 root 并重启 |
| 读内存全是空 | 从偏移 0 读 | 按页对齐 seek |
| 读内存全是空 | 用了 `dd` 而非 `toybox dd` | 改成 `toybox dd` |
| 二进制数据被污染 | `stderr` 混入 stdout | `exec-out sh -c "... 2>/dev/null"` |
| 找不到候选区域 | 过滤太严 | 调 `--min-mb 0`、`--max-mb 800` |
| 候选很多但 0 命中 | dump 太早，壳还没解 | 让 App 多停一会儿 / 进入主界面 |
| 只有 1 个 DEX | 应用是单 dex，或壳惰性解密 | 多走几个界面再扫 |
| DEX 结构 invalid 很多 | 区域被截断 | 用 `--region` 整段 dump |
| Hermes 一直 0 命中 | RN 引擎未初始化 | 先进 RN 页面；确认 maps 里有 `libhermes.so` |
| Hermes 一直 0 命中 | assets 里的 bundle 本来就没加密 | 先跑 `apk-analyzer bundle`，标准 HBC 直接反汇编即可，不用 dump |
| App 一启动就闪退 | root 检测 | 抢在崩溃前 dump；或 `am force-stop` 后立刻重启抢窗口 |
| `pidof` 为空 | 进程没起 / 包名错 | `pm list packages \| grep 关键词` 核对 |

---

## 八、各类壳的行为速查

| 壳 | 识别特征 | 解密时机 | 备注 |
|----|---------|---------|------|
| SecNeo（盛安德） | `libDexHelper-x86.so`、`com.secneo.apkwrapper.H`、logcat 有 `apkwrapper` | `attachBaseContext` 早期 | 桩 DEX 撑到几十 MB；解密区常是 `rwxp` 匿名段 |
| 腾讯乐固 | `libshella.so`、`libshellx.so`、`jiagu` 字符串 | 早期 + 部分惰性 | 部分版本 mprotect 掉已解区 |
| 梆梆 | `libsecexe.so`、`libsecmain.so` | 早期，强反调试 | 会有 ptrace 自保护 |
| 360 加固 | `libjiagu.so`、`libjiagu_art.so` | 早期 | 新版有 VMP |
| 爱加密 | `libexec.so`、`libexecmain.so` | 早期 | — |

**通用结论**：只要 App 能正常跑，真实 DEX 就一定在某段可读内存里。
找不到通常是"筛错了区域"或"时机不对"，不是"读不出来"。

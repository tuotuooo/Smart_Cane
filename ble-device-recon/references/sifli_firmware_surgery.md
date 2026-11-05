# SiFli 固件外科手术：定位基址、分区表、注入代码、救砖

> 对象：**已经拿到 SiFli 设备固件镜像**（通过 `snoop_ota.py` 从空口日志重组，或从官方包下载）。
> 上游：`sifli_ota.md`（怎么拿到镜像、怎么推回设备）。
> 本文件回答："这坨二进制是什么布局，我能在哪里改，改坏了怎么救。"

---

## 一、先算加载基址（不确认基址，后面所有地址都是猜的）

镜像里到处是「指向自身的绝对地址」——字符串指针、函数指针、常量表地址。
把镜像放到正确基址上，这些值才会指向镜像内部；放错了就指向太空。

### 1.1 判据一：向量表自洽（快，但只能证伪）

前 8 字节是 Cortex-M 的 `{SP, ResetVector}`。做法：

```python
sp, pc = struct.unpack('<II', data[0:8])
# SP 应落在 RAM 区（sf32lb55x: 0x20000000 起）
# PC 应是 thumb（最低位 = 1），且 base <= pc < base + len(data)
off = (pc & ~1) - base        # 得到复位桩的文件偏移
```

### 1.2 判据二：复位桩字节特征（决定性）

`off` 处应该是 **CMSIS 标准复位桩**，逐字节可认：

```
39 48          ldr  r0, [pc, #0xe4]     ; 取 .data 载入函数的地址
80 f3 0a 88    msr  ...                 ; ← capstone 解不了这条编码
39 48          ldr  r0, [pc, #0xe4]
80 47          blx  r0                  ; 跳 .data 载入
39 48 / 00 47  ldr r0,[pc,#..]; bx r0   ; 跳清零 .bss
fe e7 fe e7 …  for(;;)                  ; 死循环
```

判对了会看到 `39 48` / `blx` / `bx` / `fe e7` 这几组，且 `SP` 落在 RAM。

### 1.3 ⚠️ 两条走错的路（都试过，别再走）

| 方法 | 为什么错 |
|---|---|
| 「flash 指针指向可打印字符串」统计投票 | 能给出排名（实测 22347 vs 次优 20463），但**区分度不足以下结论**，且会被常量和表结构带偏 |
| 「从复位向量线性反汇编的覆盖率」 | **thumb 指令密度太高**，几乎任何对齐位置都能解出一堆指令，覆盖率没有区分度；而且 capstone 解不了 `msr` 特殊编码，会在正确位置"解出 1 条就停"，被误判为失败 |

### 1.4 实测值（SF32LB551 手表方案）

| 项 | 值 |
|---|---|
| 加载基址 | **0x12070000**（QSPI4 / flash 映射区） |
| 镜像长度 | 3,105,248 (0x2F61E0) |
| 覆盖范围 | 0x12070000 .. 0x123661E0 |
| 推测分区大小 | 0x300000（3MB），余量 40,480 B |
| SP / Reset | 0x20066458 / 0x120735FD → 复位桩在偏移 0x35FC |

> 官方参考板（`ec-lb551xxx`）默认把 HCPU 放在 **flash1 `0x10000000`**，代码在 `0x10020000`。
> **同一颗芯片可以有完全不同的映射**，必须按实测值，不能抄板级默认。

---

## 二、分区表与 sec_config

### 2.1 结构（`middleware/dfu/dfu.h`，magic `0x53454346` = "FCES"）

```
+0x0000  u32 magic = 0x53454346
+0x0004  struct flash_table ftab[16]     {base, size, xip_base, flags}  16B/项
+0x0104  u8 sig_pub_key[]                启动验签公钥（DER，294B）
+0x1000  struct image_header_enc imgs[14] {length, blksize, flags, key[32], sig[256], ver[20]} 512B/项
+0x2C00  u32 image_idx[4][4]             各核当前激活槽
```

- `imgs[HCPU].length` = bootloader **期望的镜像长度**（这也解释了一个现象：
  只改版本号、长度对不上的包会被静默拒绝）
- `ftab[flashid].base` = 存储地址，`.xip_base` = 执行地址

### 2.2 ftab 索引（官方 bootloader 文档）

| idx | 名称 | idx | 名称 |
|---|---|---|---|
| 0 | Flash 分区表 | 8 | **HCPU image Pong** |
| 1 | 校准表 | 9 | RAM boot patch |
| 2 | LCPU image Ping | 10 | HCPU 扩展 1 |
| 3 | BCPU image Ping | 11 | HCPU 扩展 2 |
| 4 | **HCPU image Ping** | 12 | LCPU 扩展 1 |
| 5 | Flash boot patch | 13 | LCPU 扩展 2 |
| 6 | LCPU image Pong | 14/15 | 保留 |
| 7 | BCPU image Pong | | |

**HCPU 有 Ping/Pong 双槽**（`imgs[2]` / `imgs[6]`）。但官方参考板两槽填的是**同一个地址**
（等于没启用）。本机是否真开双槽，**只能读回 flash 才知道**——这直接决定"刷坏能不能回滚"。

### 2.3 启动链（`middleware/boot/secboot.c`）

```c
img_hdr = &(g_sec_config->imgs[DFU_FLASH_IMG_IDX(flashid)]);
src  = g_sec_config->ftab[flashid].base;
dest = g_sec_config->ftab[flashid].xip_base;
run_img(dest);          // LDR SP,[dest]; LDR PC,[dest+4]
```

两个要点：

1. 有编译开关 `SECBOOT_USING_APP_IMG_SIG_VERIFIY`（启动时校验镜像签名）。
   **实测改 8 字节常量后设备照常启动且版本号变了** → 这台没开。
2. **没有启动失败计数 / 回退上一版本逻辑**。写进一个不启动的镜像，
   软件层完全无自救。

---

## 三、OTA 能写哪些分区

| `img_id` | 目标 | 风险 | 备注 |
|---|---|---|---|
| 0 | HCPU 代码 | 低 | 就是日常改的这个 |
| 1 | LCPU（RAM 代码） | 中 | BLE 栈在这一核，刷坏 = 连不上 |
| 3 | 资源（图片/字库外的资源） | 低 | 花屏可重刷 |
| 4 | 字库 | 低 | |
| **6** | **OTA manager 自身** | **高** | 刷坏 = BLE 恢复通道消失 |
| 7 | TINY 字库 | 低 | |

`flag`：`1` = 加密存储，`16` = 压缩（压缩要 eZIP 引擎，PC 侧工具链不全，先用 0）。

---

## 四、密钥链：能不能签出设备认的包

密钥不在 App 里，在 **`OpenSiFli/SiFli-SDK` → `tools/secureboot/sifli02/`**：

| 文件 | 用途 |
|---|---|
| `s01.bin` (32B) | 包内 AES-256 密钥 |
| `sig_hash.bin` (32B) | 前 8B 作 AES-CTR 的 IV 前缀 |
| `sig_pri.pem` | RSA-2048 **签名私钥** |
| `sig_pub.pem/.der` | 对应公钥 |

官方手册原话：**"如果没有烧写加密的 efuse，请直接使用 sifli02 目录下的 bin 进行加密"**。

**验证方式（最硬）**：用这套密钥重生成官方 ctrl_packet，和真机抓到的包**逐字节比对**。
`scripts/sifli_fw_pack.py --check` 就是干这个的——一致即证明密钥链完全匹配，
比任何"看起来对"的推理都可靠。

---

## 五、救砖通道（动非原厂镜像之前必须先落实）

### 5.1 优先级：SWD > UART4 > BOOT_MODE

| 通道 | 前提 | 能力 |
|---|---|---|
| **SWD（SWDIO/SWCLK/GND/3V3）** | PCB 上有焊盘 | **整片读写 flash，不依赖 bootloader**。最彻底 |
| **UART4 + BOOT_MODE 拉高** | 有测试点 / 排针 | ROM 下载模式，可整片烧（`sftool`） |
| BOOT_MODE 不可达 | — | 只能靠"刷不坏"来保证安全 |

官方文档明确：

> bootloader 使用芯片的 **UART4** 作为下载串口；bootmode 跳线接 1 进入下载模式，
> 接 0 正常启动；**正常启动如果发现 flash 上没有有效的用户 image，会自动进入下载模式**。
> Mode 管脚在量产板上必须留测试点。

### 5.2 `sftool`（官方 Rust 版，带 `read_flash`）

```bash
# 整片读回（第一件事：备份）
sftool -c SF32LB55 -m nor -p COM3 read_flash 0x12000000 0x400000 flash_full.bin

# 回写
sftool -c SF32LB55 -m nor -p COM3 write_flash 0x12000000 flash_full.bin
```

子命令：`config / write_flash / read_flash / erase_flash / erase_region / stub`。
默认波特率 1000000，超时或校验失败加 `--compat true`。

> efuse 没烧 → ROM 下载用的也是**默认密钥**，也就是 §四 那套。

---

## 六、注入工具箱（不改布局，只做定点手术）

五个脚本，都在 `scripts/`：

| 脚本 | 作用 |
|---|---|
| `sifli_cave.py` | 找代码洞（连续 0x00 / 0xFF 填充），给出可注入地址 |
| `sifli_xref.py` | 找**谁引用了某个地址**（字符串、常量表、函数指针）→ 数据引用 |
| `sifli_bl_xref.py` | 找**谁调用了某个函数**（扫 BL/B.W 编码）→ 代码引用 |
| `sifli_fw_patch.py` | 字节补丁 / 注入代码块 / 改跳转，写入后用 capstone 复核 |
| `sifli_fw_pack.py` | 把改过的镜像打成 OTA 包（签名 + 加密） |
| `sifli_apptab.py` | 应用表（菜单应用清单）dump / 占隐藏槽 / 改图标与注册函数 |
| `sifli_i18n.py` | i18n 表：列语言表、查某条文字被谁引用、改指针、往洞里写串 |

### 6.1 找洞

```bash
python sifli_cave.py --image fw.bin --min 512
```

实测这份镜像只有 3 个洞：

```
0x0001CC   1524B   地址 0x120701CC   ← 向量表里未使用的 IRQ 槽（硬件永不取指，最干净）
0x2F5E29    951B   地址 0x12365E29   （到文件尾）
0x2E37C6    530B   地址 0x123537C6
```

### 6.2 找引用（必须支持字面量池）

只扫 `ADR` / `LDR [PC,#imm]` 直接指向目标会**几乎全部漏掉**——编译器把地址放进
4 字节字面量池，代码 `LDR` 的是**池槽**，不是目标。

正确做法两步：① 扫出所有存有目标地址的 4 字节对齐槽；② 再找 `LDR rX,[pc,#imm]`
指向那些槽。实测同一条字符串：只做直接匹配 **0 命中**，加池扫描 **1 命中**。

```bash
python sifli_xref.py --image fw.bin 0x121C88EC      # 给 flash 地址
python sifli_xref.py --image fw.bin --off 0x1588EC  # 或给文件偏移
```

**但 `sifli_xref.py` 找不到"谁调用了这个函数"** —— 函数调用是直接编码进
`BL` 指令的，不经过字面量池。找调用点用 `sifli_bl_xref.py`：

```bash
python sifli_bl_xref.py --image fw.bin --base 0x12070000 0x12182998
python sifli_bl_xref.py --image fw.bin --base 0x12070000 --all-bl   # 全量统计
```

实测对比（同一份 3MB 镜像）：线性反汇编找到 3 处调用点，
编码解码扫出 **5 处** —— 漏的两处是 `B.W` 尾调用。

### 6.3 打补丁 / 注入 / 改跳转

**所有地址都是 flash 地址**（基址见 §一），不是文件偏移：

```bash
# 改字符串（版本号，等长替换最安全）
python sifli_fw_patch.py --image fw.bin -o out.bin --set 0x121C88EC=56312e30312e3939

# 强制默认语言（消掉 it eq 的条件兜底，详见 §8.2）
python sifli_fw_patch.py --image fw.bin -o out.bin \
    --set 0x121762CA=00bf --set 0x121762D0=28462c12 --set 0x120AFE50=28462c12

# 注入编译好的代码块
python sifli_fw_patch.py --image fw.bin -o out.bin \
    --inject 0x120701CC=hook.bin --redirect 0x121C8858=0x120701CD

# 得到 pkg.ctrl / pkg.blocks 后推流（见 sifli_ota.md §十一）
python sifli_fw_pack.py --keys <sifli02目录> --image out.bin --fw-ver 1001099 -o pkg
```

`sifli_fw_patch.py` 内部用 capstone 反解**复核**每条跳转的目标地址，
不一致直接抛异常——**不会写出坏镜像**。实测编码：

```
0x121C8858 -> 0x120701CC   a7f6b8bc   b.w  ✓
0x120BAE12 -> 0x120701CC   b5f7dbf9   bl   ✓
```

跳转距离 = `b.w` ±16MB / `bl` ±16MB，注入点离调用点通常在几 MB 内，够用。

### 6.4 编译自己的代码块

最小骨架（链接基址按 §一 改）：

```ld
MEMORY {
  FLASH (rx) : ORIGIN = 0x12070000, LENGTH = 3M
  RAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 480K
}
```

编译成裸二进制再 `--inject` 进去即可：

```bash
arm-none-eabi-gcc -mcpu=cortex-m33 -mthumb -mfloat-abi=hard -mfpu=fpv5-sp-d16 \
  -Os -ffunction-sections -fdata-sections -nostdlib -T link.ld -Wl,--gc-sections \
  -Wl,-e,0x120701CD hook.c -o hook.elf
arm-none-eabi-objcopy -O binary --only-section=.text hook.elf hook.bin
```

> 坑：`ASSERT()` 放在输出段内部会报 `ld: syntax error`，必须放顶层。
> `kit/` 里那份 616 字节的最小镜像验证过：`SP=0x20078000`、`Reset=0x120701C5`。

---

## 七、风险矩阵（按"能不能自己救回来"排）

| 改动 | 失败表现 | 可恢复性 |
|---|---|---|
| 改字符串 / 常量（版本号、默认语言） | 某处显示异常 | ✅ 重刷即可 |
| 注入代码 + 改跳转（目标函数非关键路径） | 某功能异常或崩 | ✅ GTX20 仍在，可重刷 |
| 改 HCPU 主流程 / 启动初始化 | 无画面、无 BLE | ❓ 取决于双槽 / bootloader 判定 |
| 刷 img_id 6（OTA manager） | 无 BLE 恢复通道 | ❌ 只剩 SWD/UART |
| 刷 ftab / bootloader | 不开机 | ❌ 只剩 SWD |

**结论**：在没有 SWD 或 UART4 的前提下，只做前两行。
第 2 行的安全前提是"注入点不在启动路径上，且跳转目标是可放弃的函数"。

---

## 八、定位"显示值 / 配置项"：四次失败换来的方法论

这一节是整份文档里最贵的部分。目标很小——把界面语言改成中文、把版本号改掉——
但连续四次刷机全部**毫无变化**。每一次失败都不是"补丁没写进去"（每次都逐字节校验过），
而是**改错了地址**。下面这套流程是踩完之后总结的，按顺序做能省掉大部分刷机。

### 8.1 先分清三种"引用"，工具完全不同

| 关系 | 编码方式 | 该用什么找 | 用错的后果 |
|---|---|---|---|
| **数据引用**：谁用了这个字符串/常量表 | 4 字节字面量池 + `LDR rX,[pc,#imm]` | `sifli_xref.py` | 只扫 `ADR` 会 0 命中 |
| **代码调用**：谁调用了这个函数 | 直接编码进 `BL` / `B.W` | `sifli_bl_xref.py` | 用 xref 会 0 命中 |
| **初始化赋值**：这个默认值在哪被写入 | 寄存器立即数 / 池槽 | 反汇编函数体，读池 | —— |

```bash
# 数据引用（字符串、常量表指针）
python sifli_xref.py --image fw.bin 0x122CAE34
# 代码调用（函数被谁调）
python sifli_bl_xref.py --image fw.bin --base 0x12070000 0x12182998
```

> 本轮实测：`app_set_locale_lang` 用 `sifli_bl_xref.py` 扫到 **5 处**调用点
> （`0x120A9BEA` / `0x120AFE4A` / `0x120B0096` / `0x120FC996` / `0x12103AB8`）。
> 线性反汇编只找到 3 处——因为另外 2 处是 `B.W` 尾调用，且反汇编中途被数据打断。

### 8.2 坑一：链式兜底 —— 改了默认值，但那行代码永不执行

这是最浪费时间的一个坑，连踩两次。典型形态：

```asm
get_current_language():                 ; 0x121762BC
    bl   read_nvs                       ; 读 NVS，NULL = 没设置
    ldr  r1, [pc, #8]                   ; ← 池槽 0x121762D0 = "English（UK）"
    it   eq
    moveq r0, r1                        ; NULL 时兜底成英文
    pop  {r7, pc}                       ; ★ 永远返回非 NULL
```

```asm
app_language_init():                    ; 0x120AFE14
    bl   get_current_language
    cbnz r0, skip                       ; ★ 每次都跳，下面全是死代码
    ldr  r4, [pc, #0x2c]                ; ← 池槽 0x120AFE50 = "English（UK）"
    ...  b.w app_set_locale_lang
```

上层写了「取不到就用默认值」，下层却**自己已经把空值兜底**了。
于是上层那个默认值槽是**死代码**，所以改 `0x120AFE50` 完全没有效果。

**判据**：看到一个 `if (err) use_default` 分支时，先确认那个「取配置」函数
**真的会返回错误**。方法：反汇编它，看有没有 `it eq / moveq` 或
`cbz / orr / bic` 之类的兜底指令。有 → 直接改兜底常量，别碰上层。

**修法（两种，按侵入性排序）**：

| 方式 | 做法 | 代价 |
|---|---|---|
| 改兜底常量（不足） | 把 `0x121762D0` 指向新值 | ❌ 只在读失败时生效，NVS 有值时无效 |
| **消除条件（有效）** | `it eq` → `nop`（`08 BF` → `00 BF`），让 `08 46` 变无条件 `mov r0,r1` | ✅ 绕过 NVS，每次都强制 |

```
0x121762CA:  08 BF  it eq      →  00 BF  nop
0x121762CE:  08 46  moveq r0,r1 →  08 46  mov r0,r1   （编码不变，语义变）
```

> 编码细节：Thumb `IT` 指令本身只占 2 字节，把 `0xBF08`（`it eq`）改成 `0xBF00`
> （`nop`）后，紧跟的 `movs r0, r1`（`0x4608`）就变成无条件执行。
> 必须用 capstone 复核改后的语义，别只看字节数。

### 8.3 坑二：NVS 不会被 DFU 清空

我一度以为"刷机会清 NVS，所以必然走到默认值分支"。**这是错的。**
DFU 只写镜像分区，设置分区（NVS）保留。所以：

- 语言、用户配置这类存 NVS 的值，**刷多少次都还是旧值**；
- 「刷完回出厂英文」不是 NVS 被清，而是**这台设备出厂时 NVS 里就没写过**；
- 判断方法：找一个「只在首次开机执行」的路径（如首次配网向导），看刷机后是否重现。

### 8.4 坑三：显示值 ≠ 逻辑值

版本号就是典型。`one_level_version_get()`（`0x121C8858`）返回的版本号
**只用于日志和上报**，界面显示直接打印字符串常量。证据：

- 把该函数 hook 成返回 `9/99/99`（注入块 + `b.w`，反汇编复核无误）→ **屏幕毫无变化**；
- 而把 4 处 ASCII `"V1.01.06"` 改成 `"V9.99.99"` → **屏幕直接变**；
- v99 实验（只改 `06`→`99`）的差异也只有这 4 处：
  `0x120E2C24` / `0x121C88EC` / `0x1221F994` / `0x122F5E35`。

**判据**：字符串后面紧跟什么，决定了它属于哪个子系统。

```
0x121C88EC:  "V1.01.06"
0x121C88F2:  "one_level_version_get"     ← __func__ 紧邻
0x122F5E3B:  "\x1b[0;35m%s(%d):app_gse"  ← ANSI 彩色日志格式
```

同一组字符串旁边是 `__func__` 和 ANSI 转义码 → 整块属于日志区。
日志区的字符串改函数返回值当然不影响 UI。

**通用规律**：

| 想改的东西 | 该改什么 | 不该改什么 |
|---|---|---|
| 屏幕显示的版本号 | 字符串常量（可能有多个副本，全改） | 取版本的函数 |
| 上报/日志里的版本号 | 同上（同一批副本） | —— |
| OTA 版本判定 | 包 control 里的 `fw_ver`（u32），与字符串无关 | 镜像里的任何字符串 |

> 字符串副本数要用 `grep -c` 类精确匹配数一遍。这份镜像 4 个副本，
> 少改一个就可能出现"设置页变了、关于页没变"的诡异现象。

### 8.5 坑四：多语言 = 资源块 + 显示名切块

固件里的多语言不是「一张 key → N 语言的表」，而是**按语言切块**：

```
0x122C4600 …  中文块（"平均" "总长度" "卡路里" "心率" "无目标" "十一月" …）
0x122C9B73 …  英文块（"Language" "Settings" "About" …）
0x122CAE34    块尾："English（UK）"   ← 语言的显示名
0x122C4628    中文块的显示名："简体中文"
```

`app_set_locale_lang(char *display_name)` 拿到的就是**显示名字符串**，
内部用 `strncmp` 遍历语言表匹配，然后切换资源块指针。

语言表在 `0x122AD608`，每项 **8 字节 `{语言ID, 显示名指针}`**：

| 下标 | ID | 显示名 |
|---|---|---|
| 0 | 1 | 简体中文 |
| **1** | **2** | **English（UK）← 出厂默认** |
| 2 | 4 | Deutsch |
| 3 | 6 | Español |
| 4 | 3 | Français |
| 5 | 5 | Italiano |
| 6 | 7 | 日本語 |
| 7 | 15 | Русский |
| 8 | 23 | Portuguese |
| 9 | 8 | Polish |
| 10 | 12 | Dutch |
| 11 | 39 | Khmer |
| 12 | 31 | العربية |

> ⚠️ **这张表不能靠猜**。我早期从一段字体测试样本里推出「1=en_us / 2=en_GB / 3=zh_cn」，
> 全是错的——真实 ID 里 3 是法语，中文是 1。**语言 ID 必须从菜单表里读出来。**

### 8.6 坑五：没有可见反馈时，先塞探针

连续几轮"改了没反应"，最大的问题是**不知道是地址错了还是界面没读这块文案**。
解决办法：在做真实修改的同一版里，塞一个**必然显示**的标记。

```bash
# "Steps" (0x122CAA24) → "ZZZZZ"，等长替换不破坏布局
python sifli_fw_patch.py --image fw.bin -o probe.bin --set 0x122CAA24=5a5a5a5a5a
```

结果判读：

| 现象 | 结论 |
|---|---|
| 标记出现 + 目标也改了 | ✅ 路径正确 |
| **标记出现**，但目标没变 | UI 确实读这块，但**切换开关在别处** |
| **标记没出现** | 这块字符串根本不是当前 UI 在用的，换块重找 |

这一步能把"猜"变成"测"。本轮就是靠这个探针确认了「英文块确实是 UI 源」。

### 8.7 完整判定流程（照做）

```
1. 先定"值存在哪"
   ├─ 字符串能 grep 到？ → 数副本数，逐个确认谁引用（sifli_xref.py）
   └─ 只存在结构体/枚举里？ → 找菜单表、配置表，读表而不是猜 ID

2. 找"谁写这个值"
   ├─ 有初始化函数？ → 反汇编，看默认值槽（ldr [pc,#imm] 后的池内容）
   └─ 有 setter？ → sifli_bl_xref.py 扫调用点，看每一处上下文

3. 检查"这行代码会不会执行"
   ★ 有 if(err) / cbnz / it eq 的兜底链？ → 先确认 err 真的会发生
   ★ 配置存在 NVS / flash 里？ → 刷机不会清，必须消除条件或改 NVS

4. 判断"改的是显示还是逻辑"
   字符串旁边有 __func__ / ANSI 日志格式 → 日志区，改它不影响 UI
   想改 UI 显示 → 必须改 UI 真正取用的那个副本

5. 一次刷机验证多个假设
   真实修改 + 可见探针 同包刷入，用探针结果区分失败原因

6. 每次刷机前先核对"包里的字节对不对"
   从 .blocks 还原镜像，比对 sha256 与 .json 记录，再反汇编看关键地址
   —— 这一步能排除 90% 的"是不是没刷进去"
```

### 8.8 六轮刷机的对照表（值得反复看）

| # | 改动 | 结果 | 错在哪 |
|---|---|---|---|
| 1 | hook 版本函数：`0x121C8858` → 注入块返回 9/99/99 | ❌ 无变化 | 该函数只服务日志，UI 直接打印字符串 |
| 2 | 改"语言 ID"：`0x120BAE00` `02 22`→`03 22` | ❌ 无变化 | 那是**日志参数**；且 3 = 法语不是中文 |
| 3 | 改"默认语言槽"：`0x120AFE50` → "简体中文" | ❌ 无变化 | 该分支是死代码（被下层兜底短路） |
| 4 | 改"兜底常量"：`0x121762D0` → "简体中文" | ❌ 无变化 | `it eq` 只在 NVS 读失败时生效，NVS 里有值 |
| 5 | **消 `it eq`（`0x121762CA` → `nop`）+ 探针** | ✅ **界面变中文** | —— |
| 6 | **改 4 处版本串** → `"V9.99.99"` | ✅ **屏幕显示 V9.99.99** | —— |

> 每轮都是完整刷机（6065 分片 / 约 61 s），包都经过"从 `.blocks` 还原镜像 →
> 校验 sha256 → 反汇编看关键地址"三步核对。**所以这四次失败不可能是传输问题。**

**六轮里前四轮全是"地址对了、语义错了"**。补丁字节从来没错过，
错的是对代码执行路径的判断。所以每次刷机前应该问的不是
"字节写对了吗"，而是"这行代码真的会跑到吗"。

---

## 九、实测记录（2026-11，SF32LB551 手表）

| 实验 | 结果 |
|---|---|
| 只改 4 处 `V1.01.06` → `V1.01.99` | ✅ 设备正常启动，**屏幕显示 V1.01.99** |
| 官方原样镜像 | ✅ 18195 分片推完，`cmd=0x000B/0x000D` 均返回 0，正常重启 |
| 616 字节最小固件（自写向量表 + 空 main） | ✅ 编译 / 打包 / 刷入全通 |
| hook `one_level_version_get` | ✅ 刷入正常，但 ❌ 屏幕无变化（见 §8.4） |
| 消 `it eq` + 语言强制 | ✅ **界面变中文** |
| 中文 + `V9.99.99` 同包 | ✅ **两者同时生效** |
| 换掉 Calculator 的 handler（洞内 84B） | ✅ 计算器页面叠加出 HELLO |
| 应用表占隐藏槽 + 自定义标签 + 自定义界面 | ✅ 菜单出现 HELLO，点进去显示 HELLO |
| 结论 | **无整包 RSA 验签**（或验签范围不含被改的 rodata）；内容可任意改 |
| 每次刷写耗时 | 6065~18195 分片，60.7 s，约 300 块/秒 |

---

## 十一、给固件加自己的 GUI 应用

目标：**在手表菜单里多出一个自己写的应用，点进去画自己的界面。**
这一节把全链路的地址、结构、顺序、坑全部列出来，按顺序做一次就能复现。

整条链路只动了 12 个字节：

```
代码洞写入 100B 机器码          0x12070300
应用表隐藏槽改 3 个字段         0x12324A48 / 0x12324A5C(+name)
i18n 表 idx69 指针改指新字符串   0x122933FC
代码洞里写菜单文字             0x12070400  "HELLO"
```

### 11.1 应用表：菜单里的应用清单

地址 `0x123246FC`，**35 项 × 0x1C 字节**，表尾紧接 RT-Thread Finsh 命令表，
所以**只能在原有项上改字段，不能追加**（追加会踩到 Finsh 的命令名指针）。

```
偏移    类型        含义
+0x00   u32        资源 id（图标/名称的 key）
+0x04   u32        图标指针；**为 0 = 菜单里不可见**
+0x08   char[16]   内部名字（**只用于匹配，不是菜单显示的文字**）
+0x18   u32        注册函数指针（thumb 位 = +1）
```

实测（原厂 1.01.06，35 项里 10 项 `icon=0`）：

```
idx 0  0x123246FC  Activity        icon=129FDC90  reg=120B0515
idx 4  0x1232476C  Calculator      icon=129FDCD8  reg=120B0585   ← 图标可借用
idx 6  0x123247A4  Countdown       icon=00000000                   ← 隐藏槽
idx 14 0x12324884  Setting         icon=129FDD98  reg=120B07E5
idx 30 0x12324A44  Dice            icon=00000000  reg=120B0BB1   ← 本次占用
idx 31 0x12324A60  Plane           icon=00000000
idx 34 0x12324AB4  Power_manager   icon=00000000
```

用 `sifli_apptab.py --dump` 一次列出全部 35 项并标出哪些是隐藏槽：

```bash
python sifli_apptab.py --image fw.bin --dump
python sifli_apptab.py --image fw.bin -o out.bin \
    --entry Dice --icon 0x129FDCD8 --reg 0x12070341     # 占槽 + 指向自己的注册函数
```

> ⚠️ **表项偏移算错一位会静默写坏邻居**。踩过：把 `0x12324AB8` 当成 Dice 的 icon，
> 实际是 `Power_manager[34].icon`（`0x12324AB4+4`）。当时靠 `--dump` 回显旧值
> `Power_manage...` 才发现。**改之前一定先 dump 一遍，把旧值抄下来。**

### 11.2 i18n 表：菜单文字的真正来源

菜单上那行字**不来自应用表的 `name` 字段**，来自 i18n 表：一串 u32 指针，
界面按固定下标记取。菜单标签取 **idx 69**。

**每种语言各有一张表，各自指向自己语言资源块里的字符串。**
中文固件里 idx69 = `0x122C49A6 "摇骰子"`；英文表里 idx69 = `0x122ED747 "Dice"`。
所以**只改中文表，切回英文就看不到修改** —— 这是最容易白刷一次的地方。

```
中文表  0x122932E8   963 项   idx0 -> 0x122C4628 "简体中文"
         idx69 @0x122933FC -> 0x122C49A6 "摇骰子"
英文表  0x122A82CC    稀疏（大量 0，所以"连续指针"扫描扫不到它）
         idx69 @0x122A83E0 -> 0x122ED747 "Dice"
西语表  0x12297AC4   378 项    idx0 -> "Español"
日语表  0x122AA620   378 项    idx0 -> "日本語"
德语表  0x1229586C   371 项    idx0 -> "Laufkurse"
高棉表  0x122AC40C   570 项    idx0 -> "ភាសាខ្មែរ"
```

`idx0` 是该语言的**显示名**，这一点是"名字 → 表"的钩子。语言主表就在旁边：

```
0x122AD608  13 项 × 8B  {u32 lang_id; char *显示名}   英文命名风格
0x122AD670  13 项 × 8B  同上                          本地语言命名风格
```

| lang_id | 语言 | lang_id | 语言 |
|---|---|---|---|
| 1 | 简体中文 | 15 | Русский |
| 2 | English（UK） | 23 | Portuguese |
| 3 | Français | 8 | Polski |
| 4 | Deutsch | 12 | Nederlands |
| 5 | Italiano | 31 | العربية |
| 6 | Español | 39 | ភាសាខ្មែរ |
| 7 | 日本語 | | |

**ID 不是按顺序排的**：3 是法语，不是第三种语言；39 才是高棉语。
早期"ID 3 = 中文"的推断就是从这里错的。判断语言必须读名字，不要猜 ID。

```bash
python sifli_i18n.py --image fw.bin --tables            # 找出所有语言表
python sifli_i18n.py --image fw.bin --langs 0x122AD608  # 语言 ID → 显示名 → 对应表
python sifli_i18n.py --image fw.bin --find-str "摇骰子"  # 这条文字被哪些槽引用
python sifli_i18n.py --image fw.bin -o out.bin --put-str 0x12070400=HELLO \
    --set-addr 0x122933FC=0x12070400
```

`--find-str` 是关键：它直接告诉你"这条文字在几张表里被引用"。
想让标签在所有语言下都变，就把列出来的每个槽都改掉。

### 11.3 注册 API 与 handler 协议

```
0x1215A118   gui_app_regist_msg_handler_ext(const char *name, void *handler, int flag)
             Thumb 指针 = 0x1215A119
             内部 memcmp 16 字节名字；未命中则新建 0x90 字节注册项

handler 原型  int handler(int msg, void *a, void *b, void *c)
             msg == 0  建立界面
             msg == 3  销毁界面
```

开机时框架遍历应用表、逐项调用 `+0x18` 的注册函数；点图标时框架按名字找到
handler 并投递 `msg=0`。

最小可用应用（`kit/inject_app.c`，编译出来 100 字节）：

```c
void hello_regist(void) { APP_REGIST("Hello", hello_handler, 0); }

static int hello_handler(int msg, int a, int b, int c)
{
    if (msg == 0) {                       /* 建界面 */
        void *scr = GET_SCR_ACT(0);
        void *lbl = LABEL_CREATE(scr, 0);
        LABEL_SET_TXT(lbl, "HELLO");
        OBJ_SET_POS(lbl, 55, 100);
    }
    return 0;                             /* 销毁路径什么都不做，框架自己 clean */
}
```

**注册函数必须排在编译单元的最后一个之前**（`ENTRY` 指向它，链接脚本把它放在块首），
因为应用表里记的是它的绝对地址 `0x12070341`。

### 11.4 已验证的 LVGL 地址

符号表里有 1440 项 `{name_ptr, func_addr}`，但 **ICF 合并导致 name/func 配对不可靠**
（表说 `lv_label_create = 0x121AC008`，实测那个是 `lv_label_set_text`）。
下面这些全部是**按调用上下文反汇编语义核对过**的：

| 地址 | 函数 | 判定依据 |
|---|---|---|
| `0x121A9730` | `lv_disp_get_scr_act(disp)` | `cbnz r0` → `bl lv_disp_get_default` → `ldr r0,[r0,#0x64]`，即 `disp->act_scr` |
| `0x121AA9A4` | `lv_label_create(parent)` | 调用点紧接着把返回值传给 `set_text` |
| `0x121AC008` | `lv_label_set_text(obj, txt)` | `mov r5,r0`(obj) / `mov sl,r1`(text) |
| `0x1219EB14` | `lv_obj_set_pos(obj, x, y)` | `mov r4,r1` / `mov r5,r0`，双参数都是整数 |
| `0x122199D4` | 计算器 handler | 只出现在 Calculator 注册函数的池槽里 |
| `0x120B0584` | 计算器注册函数 | 4 条有效指令：`ldr r1,[pc,#0x18]` / `adr r0,"Calculator"` / `bl regist` |

想扩展控件时，**照上面这套"看调用上下文"的办法逐个确认**，不要信符号表的 name。

### 11.5 替换已有 app 的 handler（更省字节的路线）

如果只是想在某个已有页面上叠内容，不必新增应用，改一个池槽就够了：

```
0x120B0584  Calculator 注册函数：
    push {r7,lr}
    ldr  r1,[pc,#0x18]     ; 槽 0x120B05A0 = 0x122199D5（原 handler，带 thumb 位）
    adr  r0,"Calculator"
    movs r2,#0
    bl   0x1215A118
```

把 `0x120B05A0` 的 4 字节换成 `my_handler|1`，**原 handler 地址先存进自己的常量**，
新 handler 开头 `blx` 回去跑原逻辑，再叠自己的绘制。计算器界面照常出现，
上面多一行 HELLO。这条路只需改 4 字节 + 注入代码块，不碰应用表和 i18n 表。

### 11.6 完整操作序列

```bash
# 0) 备份当前镜像，确认洞和表
python sifli_cave.py    --image fw.bin --min 256
python sifli_apptab.py  --image fw.bin --dump

# 1) 编译注入块（链接基址必须等于注入地址）
cd kit && ./build_app.sh inject_app.c hello_regist && cd ..
#    build/inject_app.bin = 100 B，脚本自动查代码里的 flash 常量 thumb 位

# 2) 注入 + 占应用表隐藏槽
python sifli_fw_patch.py --image fw.bin -o s1.bin \
    --inject 0x12070300=kit/build/inject_app.bin
python sifli_apptab.py   --image s1.bin -o s2.bin \
    --entry Dice --icon 0x129FDCD8 --reg 0x12070341

# 3) 写菜单文字 + 改 i18n 指针
python sifli_i18n.py --image s2.bin -o s3.bin \
    --put-str 0x12070400=HELLO --set-addr 0x122933FC=0x12070400

# 4) 打包 + 推流（见 sifli_ota.md §十一）
python sifli_fw_pack.py --keys <sifli02目录> --image s3.bin --fw-ver 1001099 -o pkg
python sifli_ota_push.py --blocks pkg.blocks --ctrl pkg.ctrl
```

耗时：6065 块 / 60.7 秒，设备约 15 秒后恢复广播。

### 11.7 坑清单（都踩过）

| 坑 | 现象 | 根因 / 判据 |
|---|---|---|
| 改 `name[16]` 想改菜单文字 | 字节全对，菜单文字不变 | 菜单读 i18n 表 idx，不读 name 字段 |
| 只改中文表 | 中文下生效，切英文变回原文 | 每种语言一张表 |
| 函数指针缺 thumb 位 | 点图标就 HardFault / 重启 | `blx` 按 ARM 态跳转；常量必须是奇数 |
| `--set` 字节序写反 | 刷完开不了机 | `0x12070341` → `41030712`，写成 `41037012` = `0x12700341`（镜像外） |
| 表项偏移算错一位 | 改坏了邻居字段 | Dice 的 icon 是 `0x12324A48`，不是 `0x12324AB8`（那是 Power_manager） |
| 往应用表后面追加项 | 开机异常 | 表尾紧接 Finsh 命令表 |
| 误判 i18n 索引 | 改了没反应 | 先 `--find-str` 确认槽地址，别凭下标猜 |

### 11.8 实测（SF32LB551 手表，2026-11）

| 目标 | 改动 | 结果 |
|---|---|---|
| 自编译代码能否被执行 | 洞内 84B + 换 Calculator 池槽 4B | ✅ 计算器页面上出现 HELLO |
| 能否新增应用 | 洞内 100B + 应用表 3 字段 + 写串 | ✅ 菜单多出 HELLO 项 |
| 菜单文字能否自定义 | i18n idx69 指针 + 洞内写串 5B | ✅ 菜单显示 HELLO |
| 点进去能否画界面 | handler 里 create_label + set_text | ✅ 页面居中显示 HELLO |
| 洞容量 | `0x120701CC` 起 1524B | 用掉 ~310B，余 ~1.2KB |

> 洞的余量直接决定能做多大的应用。一个完整计算器（12 个按钮 + 表达式求值）
> 大约要 500~1500 字节，**偏紧**。真要写大应用得先找新的洞，
> 或者把 UI 声明压成表驱动（数据在 rodata，代码只有几十字节的循环）。

---

## 十二、未确认项

| 项 | 状态 |
|---|---|
| 本机 ftab 实际内容（分区 base/size、双槽是否启用） | ❓ 需 `sftool read_flash` 或 SWD 读回 |
| 镜像内偏移与分区的精确对应（是否含 bootloader） | ❓ 镜像开头就是 HCPU 向量表，但 3MB 未必只有一个分区 |
| NVS 里语言键的具体位置 | ❓ 有线索：`0x120B018C` 用 `nvs_get(key=0x48)`，值为 `obj[3]` |
| 设置界面是否自带语言选择页 | ❓ 语言表存在且取用代码完整，推测 UI 里有，未逐页确认 |
| 中文字库完整性 | ❓ 中文块文案齐全，但字库是否含全部字形需实际翻页验证 |
| 默认语言常量的位置 | ❓ 已定位 `default language: %d(%s)` 日志点，尚未追到写入值 |
| 屏幕 / 触摸 / PMIC / pinmux 参数 | ❓ 自编固件 bring-up 需要，只能从现有镜像反推 |
| 改中文 i18n 表后切英文会不会变回原文 | ❓ 结构上英文表独立（`0x122A82CC` idx69=`Dice`），未实测切换 |
| 按键/触摸事件回调（`lv_obj_add_event_cb`）地址 | ❓ 做交互式应用必须，尚未定位 |
| 应用表 `res_id` 与图标资源的对应规则（能否画自定义图标） | ❓ 现在只能借用已有图标 |
| 除 `0x120701CC` 外是否有更大的代码洞 | ❓ 只按 0x00/0xFF 填充扫过，未扫"可达但无用"的函数体 |

> ⚠️ 一条通用教训：**先验常量，再推理**。
> 本项目早期因为一个魔数写错，级联出"找到 XOR 密钥 → 发现双区加密容器"两串假结论。
> 判基址、判魔数、判长度这类"唯一确定值"，必须用两种独立方法交叉验证。

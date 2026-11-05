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

四个脚本，都在 `scripts/`：

| 脚本 | 作用 |
|---|---|
| `sifli_cave.py` | 找代码洞（连续 0x00 / 0xFF 填充），给出可注入地址 |
| `sifli_xref.py` | 找**谁引用了某个地址**（字符串、常量表、函数指针） |
| `sifli_fw_patch.py` | 字节补丁 / 注入代码块 / 改跳转，写入后用 capstone 复核 |
| `sifli_fw_pack.py` | 把改过的镜像打成 OTA 包（签名 + 加密） |

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

### 6.3 打补丁 / 注入 / 改跳转

**所有地址都是 flash 地址**（基址见 §一），不是文件偏移：

```bash
# 改字节（这些是 V1.01.06 → V1.01.99）
python sifli_fw_patch.py --image fw.bin -o out.bin --set 0x121C88EC=56312e30312e3939

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

## 八、实测记录（2026-11，SF32LB551 手表）

| 实验 | 结果 |
|---|---|
| 只改 4 处 `V1.01.06` → `V1.01.99` 后刷入 | ✅ 设备正常启动，**屏幕显示 V1.01.99** |
| 官方原样镜像刷入 | ✅ 完整推完 18195 分片，`cmd=0x000B/0x000D` 均返回 0，正常重启 |
| 结论 | **没有整包 RSA 验签**（或验签范围不含被改的 rodata 段）；改内容能生效 |
| 副作用 | DFU 会清 NVS/设置分区 → 语言回出厂英文，每次刷都会 |

---

## 九、未确认项

| 项 | 状态 |
|---|---|
| 本机 ftab 实际内容（分区 base/size、期望长度、双槽是否启用） | ❓ 需 `sftool read_flash` 或 SWD 读回 |
| 镜像内偏移与分区的精确对应（镜像是否含 bootloader） | ❓ 镜像开头就是 HCPU 向量表，但 3MB 未必只有一个分区 |
| 版本号"显示"走的链路 | ❓ 4 处拷贝中只有 1 处有代码引用（`one_level_version_get`，解析用途）；显示走别处 |
| 默认语言常量的位置 | ❓ 已定位 `default language: %d(%s)` 日志点，尚未追到写入值 |
| 屏幕 / 触摸 / PMIC / pinmux 参数 | ❓ 自编固件 bring-up 需要，只能从现有镜像反推 |

> ⚠️ 一条通用教训：**先验常量，再推理**。
> 本项目早期因为一个魔数写错，级联出"找到 XOR 密钥 → 发现双区加密容器"两串假结论。
> 判基址、判魔数、判长度这类"唯一确定值"，必须用两种独立方法交叉验证。

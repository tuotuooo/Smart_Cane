# SiFli 表盘资源闭环：eZip 格式 + `.watch` 容器重打包

> 对象：**物理设备**（SiFli SF32LB 方案的智能手表 / 开发板）。
> 前置：`methodology.md` 附录 A（抓包）、`datapath_reverse.md`（还原出文件）。
> 这里解决最后一公里：**还原出来的东西怎么改成自己的，再推回去。**

---

## 一、先记住这三个事实

1. **表盘不是图片拼装，是 LVGL 动态模块**。`.so` 只做布局，图片走 `lv_img_set_src("A:.../ezip/xxx.bin")`。
   改布局要 SDK，**换图不用**。
2. **ezip 是 SiFli 私有压缩格式，有官方双向工具**。不要试图逆向算法 —— 那是硬件解码器
   （eZip 引擎）的私有算法，没有软件实现。
3. **容器重打包可以做到逐字节一致**。做不到就说明索引算错了，回去查。

---

## 二、eZip 文件格式

### 2.1 官方定义（4 字节头，小端）

| 位域 | 含义 |
|------|------|
| `[31:21]` | 图片高度 |
| `[20:10]` | 图片宽度 |
| `[9:5]` | 保留 |
| `[4:0]` | 格式：1=不带 Alpha 的 eZIP，2=带 Alpha 的 eZIP，4=不带 Alpha 的 PIXEL，5=带 Alpha 的 PIXEL |

```python
v = struct.unpack('<I', b[:4])[0]
fmt, w, h = v & 0x1F, (v >> 10) & 0x7FF, (v >> 21) & 0x7FF
```

### 2.2 厂商在头后面又加了两段（实测）

```
[0:4]   eZip 头（上面的位域）
[4:8]   u32 BE   —— 压缩数据长度（≈ 文件长度 - 8，个别差 1 字节 padding）
[8:12]  4 字节   —— 固定参数：48 10 20 00（无 alpha） / 4c 18 20 00（有 alpha）
[12:16] u16 BE w, u16 BE h    —— 宽高（与头重复，便于快速读取）
[16:20] 0
[20:22] u16 BE = 0x0020       —— 每块行数（32）
[22:24] u16 BE = 块数 N
[24:24+4N]   N × u32 BE 块偏移（相对文件起点，严格递增）
[后续]       压缩数据流
```

**自证方法**：`[24]` 起的偏移必须严格递增、末项 ≤ 文件长度，
且 `(h + 31) // 32 == N`。三条同时成立才算解对。

实例（390×450 全屏背景）：

```
01 18 46 38 | 00 01 37 b8 | 48 10 20 00 | 01 86 01 c2 | 00 00 00 00 | 00 20 00 0f
                                                                        ↑32  ↑15 块
块偏移：188, 4352, 6116, 7544, 9352, 18152, 27792, 35036, 38236, 41160, 44152,
        51036, 62364, 71864, 79412      → 450/32 = 14.06 → 15 块 ✓
```

---

## 三、双向转换（官方工具）

工具来自 SiFli 官方 SDK：`OpenSiFli/SiFli-SDK` → `tools/png2ezip/`
（`ezip.exe` / `ezip_linux` / `ezip_mac`，约 230~430KB）。

### 3.1 ezip → PNG

```bash
ezip -convert xxx.bin -spt 1 -dpt 0 -outdir out
# 输出 out/xxx.png；会打印读到的 w/h/cf，cf 就是格式位
```

**注意**：工具会保留输入路径里的子目录（`-convert out/a.bin` → `outdir/out/a.png`），
而它不创建中间目录，写失败时只打一行 `fopen failed`，退出码仍是 0。**输入放在当前目录最稳。**

### 3.2 PNG → ezip

```bash
ezip -convert xxx.png -binfile 2 -rgb565 -chip sf52x -outdir out
#   -binfile 2 = ezip；-binfile 1 = 未压缩像素
#   -chip     = sf52x（SF32LB52x）/ sf55x / sf58x / sf57x，默认 sf55x
```

首 24 字节与厂商文件**完全同构**（同一套 8 字节头 + 参数 + 15 项块表），
说明工具链就是厂商用的那一条。

### 3.3 已知限制（实测 2.6.4_20260414）

| 限制 | 现象 | 影响 |
|------|------|------|
| **丢 Alpha** | 输入 RGBA PNG，输出 `fmt=1`；往返后 alpha 全丢 | **只能换无 alpha 的图**（背景、纯色块）；图标类不行 |
| `-rgb565a` 无效 | 输出与 `-rgb565` 逐字节相同 | 同上 |
| 块表语义部分未知 | `[20:22]=0x20` 推测为每块行数；`[8:12]` 未解 | 不影响替换，因为整文件替换 |

> 要带 alpha 的图：找更早版本的 `ezip.exe`（表盘工具链可能内置另一个 build），
> 或从厂商的 GUI Builder 里取。**未验证**，别当已知。

---

## 四、`.watch` 容器重打包

```
head_t(32B) | 名字表(name_len) | file_head_t[nfile](16B) | 数据区
file_head_t = { name_off:u32, size:u32, unknown:u32, data_off:u32 }
data_off 是"相对数据区起点的偏移 + 32"
数据区紧接索引表，无任何对齐填充
```

重打包只做三件事：

1. 替换目标条目内容
2. 按原顺序重排数据区，**重算每条 `size` 与 `data_off`**
3. 拼回 `head_t + 名字表 + 索引 + 数据`

```bash
python <skill>/scripts/watch_pack.py in.watch out.watch \
    --replace "/dynamic_app/watchface/wf_w202/ezip/wf_w202_picture_dialBg_0.bin=bg_new.bin"
# Windows/Git Bash 下必须加 MSYS_NO_PATHCONV=1，否则 /dynamic_app/... 会被改写成 C:/...
```

**验收（必须做，一次就够）**：

```bash
# ① 原样重打包必须逐字节相同 —— 这是"索引算对了"的唯一硬证据
python watch_pack.py in.watch /tmp/rt.watch && cmp in.watch /tmp/rt.watch

# ② 替换后容器自洽：断点 0，数据区结束 == 文件长度
#    脚本自带 verify，会打印 "断点=0 ... -> OK"
```

实测结果：**433,835 B 原样重打包后 `cmp` 完全一致**。
替换背景后 439,256 B，断点 0，提取出的背景可被 `ezip` 正常解回，
像素与源图差异 最大 9 / 平均 2.59 / 中位 0 —— 纯 RGB565 量化，视觉无损。

---

## 五、完整改造流程

```
① ezip → PNG        ezip -convert xxx.bin -spt 1 -dpt 0
② 改图              保持宽高完全一致（容器/布局按原尺寸摆放）
                   无 alpha 的图直接改；有 alpha 的图当前工具做不到
③ PNG → ezip        ezip -convert xxx.png -binfile 2 -rgb565 -chip sf52x
④ 替换进容器        watch_pack.py --replace <容器内路径>=<新 ezip>
⑤ 自证              cmp 原样重打包；verify 断点 0
⑥ 推送              协议见 datapath_reverse.md 的 d1 01/02/03 三帧
```

**尺寸必须一致**：LVGL 按图片自身宽高摆放，但 `.so` 里的坐标是写死的。
换一张 200×200 的图去替 390×450 的背景，会变成左上角一小块。

---

## 六、边界（写报告时必须标）

- ✅ 已证：格式可解、可生成、容器可无损重打包、背景可替换
- ❓ **未证**：设备是否接受"非官方工具生成的 ezip"。可能有版本号、校验或额外字段检查
- ❓ **未证**：`.watch` 是否有整体签名/校验。容器里没看到签名字段，但设备端可能按 `.dsc` 校验
- ❓ **未证**：带 alpha 的图怎么生成（当前工具 build 丢 alpha）
- ❌ **做不到**：改表盘逻辑（指针行为、数据绑定、动画）—— 那是 `.so`，要 SiFli SDK 交叉编译

**结论写法**：

> 表盘资源可无损还原并重打包（原样重打包逐字节一致）。背景图可替换为任意同尺寸图像。
> 能否被设备接受**尚未验证**，需要一次真机推送；`.so` 逻辑未改动。

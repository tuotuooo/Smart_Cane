# APK 逆向七件套（Skill Matrix）

一套按「层次」拆开的 Android 逆向技能包。每一层都能单独使用，组合起来覆盖从连设备到出报告的完整链路。

设计原则：**能拆开复用**。只想连模拟器就只加载连接层，只想看静态信息就只加载静态层，上下文不浪费。

**分层依据是「对象边界」，不是功能分类**：
APK 文件 / 进程内存 / 网络流量 / 物理设备 / 结论，五类对象方法完全不同，混用会让两份结论都失真。

---

## 技能矩阵

| 层 | 技能 | 对象 | 单独能做什么 | 硬前置 |
|----|------|------|-------------|--------|
| 编排 | [`apk-reverse-master`](apk-reverse-master/) | — | 判断该走哪条路、验收标准、坑库、剧本 | 无 |
| 连接 | [`android-emulator-adb`](android-emulator-adb/) | 设备 | 自动找 adb、连端口、设备画像（root/ABI/su/toybox） | 模拟器运行中 |
| 静态 | [`apk-analyzer`](apk-analyzer/) | **APK 文件** | 身份·签名·加固判定·Manifest·DEX 线索·Hermes·Flutter / **改包重签** | Python 3.8+（签名需 JDK） |
| 脱壳 | [`apk-runtime-dump`](apk-runtime-dump/) | **进程内存** | root 内存 dump（DEX/CDEX/Hermes）+ DEX 规范化 | root + toybox dd |
| 流量 | [`android-https-capture`](android-https-capture/) | **网络** | 系统 CA 注入 + mitmproxy 抓 HTTPS + flows 解析 | root（或改包） |
| 无线 | [`ble-device-recon`](ble-device-recon/) | **物理设备** + **固件镜像** | BLE 扫描/GATT 枚举/SPP 探测 / **零 root 抓 HCI 还原私有协议** / **OTA 通道识别 + 整链路刷写** / **镜像手术（定位基址·注入代码·加 GUI 应用·交互式界面·重签打包）** / **双核定位 + 行为注入（振动）** | 蓝牙适配器 或 adb |
| 沉淀 | [`reverse-sediment`](reverse-sediment/) | **结论** | 结论质量审查（置信度分级·可复现校验·冲突召回·推翻记录）+ 归属路由 + 成文 + 全量技能索引 | 无 |

依赖方向是单向的：编排层调用其余五个功能层，五个功能层之间互不依赖；沉淀层横向收口，把任意层的产出固化成资产。

```
apk-reverse-master  ──┬──> android-emulator-adb   (连设备 / 装包 / 抓日志)
                      ├──> apk-analyzer           (静态初筛 + 改包，无需设备)
                      ├──> apk-runtime-dump       (运行时脱壳，需 root)
                      │         └──> apk-analyzer dexfile   (dump 产物回到静态链)
                      ├──> android-https-capture  (App ↔ 服务器)
                      └──> ble-device-recon       (App ↔ 硬件)
                                  │
        任一层产出的判据/坑/工具 ──┴──> reverse-sediment  (审查 → 去重 → 归位 → 成文)
```

**两条最容易混的边界**：
- 从 APK 里读出协议 → `apk-analyzer`；到真设备上验证协议 → `ble-device-recon`。
- 改包（`apk-analyzer`）是**最后手段**：签名变 → 数据/登录/绑定全丢、官方升级断裂。
  有抓包/脱壳能拿到同样信息时，不要改包。

**第三条路线：厂商一手资料（最省时间，也最容易被跳过）**

私有压缩格式和 RSA 签名是**逆不出来**的（硬件解码器 / 私钥），但厂商的 SDK、
打包工具、默认密钥通常公开。检索方法沉淀在
[`apk-reverse-master/references/vendor_hunting.md`](apk-reverse-master/references/vendor_hunting.md)：

```
APK 里挖厂商锚点（so 名 / 包前缀 / UUID 尾段 ASCII / DWARF 源码路径）
  → docs.<vendor>.com（顺手抄包仓凭据 + 错误码表）
  → 官方包仓（maven/pypi，下 AAR 拆 classes.jar 取常量）
  → 开源 SDK 仓库（tools/secureboot = 打包器源码 + 默认密钥，需 gh-proxy）
  → BBS 的 PDF（imgtool 完整参数、flash 布局）
  → 三条交叉验证：常量相同 / 结构相同 / 命名相同
```

实测：靠这 20 分钟替代了"逆 RSA 签名 + 逆私有压缩"两件做不到的事。

---

## 依赖

除**抓包层需要 `mitmproxy`**（`pip install mitmproxy -i https://mirrors.aliyun.com/pypi/simple/`，
清华源没有这个包）、**无线层需要 `bleak pyserial`**、**改包重签需要 JDK + `apksig.jar`**
（Android SDK build-tools 自带，或 maven `com.android.tools.build:apksig`）外，
其余脚本都只用 **Python 标准库**，本机不需要 `aapt` / `apktool` / `jadx` / `frida`。

静态层拿不到反编译级源码，但足以完成加固判定、脱壳、字符串/类/端点情报提取；
要看方法体级别的实现，用 `apk-analyzer` 里的 `dex_tool.py`（纯标准库反汇编器），
或起 jadx。

---

## 快速开始

```bash
# 1. 连接模拟器，顺便拿到设备画像
python android-emulator-adb/scripts/find_and_connect.py --info --human

# 2. 静态初筛（10 秒出结论：是否加固、什么框架、有无完整性校验）
python apk-analyzer/scripts/apk_analyze.py analyze sample.apk

# 3. 若判定为加固包，走运行时脱壳
python apk-runtime-dump/scripts/apk_runtime_dump.py --pkg com.example.app --out out/
python apk-runtime-dump/scripts/dex_fix.py out/dex_0.bin      # 规范化后可喂 jadx

# 4. dump 出来的裸 DEX 直接回静态链分析
python apk-analyzer/scripts/apk_analyze.py dexfile out/dex_0_fixed.dex --keyword license

# 5. 确认是未加密 Hermes 后，反汇编 + 索引 JS 层（拿到域名 / API / 关键函数）
hermes-dec ... > main.disasm.txt          # 见 apk-analyzer/SKILL.md 第 8 步
python apk-analyzer/scripts/hbc_index.py main.disasm.txt -o js_out/

# 6. 抓真实流量（先判该走哪条证书路，再注入）
python android-https-capture/scripts/cap.py info --pkg com.example.app
python android-https-capture/scripts/cap.py install --pkg com.example.app
python android-https-capture/scripts/cap.py proxy on     # 先把 App 起到目标页面！
python android-https-capture/scripts/cap.py run --daemon
python android-https-capture/scripts/cap.py dump flows.mitm --grep login --detail
python android-https-capture/scripts/cap.py proxy off
python android-https-capture/scripts/cap.py uninstall

# 7. 设备侧（对象是物理设备，不是 APK）
python ble-device-recon/scripts/recon.py scan --secs 12          # 广播 + 厂商指纹
python ble-device-recon/scripts/recon.py map  <MAC> --save gatt.json
python ble-device-recon/scripts/recon.py probe <MAC> --listen 8  # 先只被动听

# 7b. 设备已和手机绑定、PC 没有蓝牙适配器 → 零 root 抓空口日志
#     （手机开发者选项把「蓝牙数据包日志」设为 full，操作一次后取 bugreport）
python ble-device-recon/scripts/snoop_parse.py info hci.bin
python ble-device-recon/scripts/snoop_parse.py split hci.bin --handle 0x200 --dir h2c -o out/

# 7c. 固件：重组成镜像 → 定基址 → 改 → 重签 → 刷回去
python ble-device-recon/scripts/snoop_ota.py hci.bin --handle 0x200 --dir h2c -o fw.bin
python ble-device-recon/scripts/sifli_cave.py --image fw.bin --min 512
python ble-device-recon/scripts/sifli_xref.py --image fw.bin --off 0x1588EC
python ble-device-recon/scripts/sifli_fw_patch.py --image fw.bin -o out.bin \
    --inject 0x120701CC=hook.bin --redirect 0x121C8858=0x120701CD
python ble-device-recon/scripts/sifli_fw_pack.py --keys <sifli02> --image out.bin --fw-ver 1001099 -o pkg
python ble-device-recon/scripts/sifli_ota_push.py --mac AA:BB:CC:DD:EE:FF --blocks pkg.blocks

# 7d. 改显示值 / 配置项（默认语言、版本号）—— 判"改哪里"比"怎么改"难得多
python ble-device-recon/scripts/sifli_bl_xref.py --image fw.bin --base 0x12070000 0x12182998
python ble-device-recon/scripts/sifli_fw_patch.py --image fw.bin -o out.bin \
    --set 0x121762CA=00bf --set 0x121762D0=28462c12   # it eq→nop + 兜底改"简体中文"
# 方法（三种引用的区别、五个坑、六轮刷机对照表）见
# ble-device-recon/references/sifli_firmware_surgery.md §八

# 7e. 给固件加自己的 GUI 应用（菜单多一项、点进去画自己的界面）
python ble-device-recon/scripts/sifli_apptab.py --image fw.bin --dump      # 35 项，icon=0 可占
python ble-device-recon/scripts/sifli_i18n.py   --image fw.bin --tables    # 每种语言一张 i18n 表
python ble-device-recon/kit/build_app.sh        # 编 100B 机器码，塞进代码洞
python ble-device-recon/scripts/sifli_apptab.py --image s1.bin -o s2.bin \
    --entry Dice --icon 0x129FDCD8 --reg 0x12070341
python ble-device-recon/scripts/sifli_i18n.py --image s2.bin -o s3.bin \
    --put-str 0x12070400=HELLO --set-addr 0x122933FC=0x12070400
# 机制与坑见 sifli_firmware_surgery.md §十一（应用表 / i18n 表 / LVGL 地址 / 代码洞）

# 7f. 改设备行为（振动/提醒）—— 先判双核，再选安全的 API
#     BLE 协议栈在 LCPU，UI/马达在 HCPU。改 HCPU 镜像不会改变 BLE 行为。
#     判据：被分发的东西是 0x9xxx 段 = 跨核 IPC，不是应用协议。
#     马达两套入口：app_motor_control(mode) 安全；vib_start() 走 rt_mq_send 会死锁。
B=".../Arm GNU Toolchain .../bin"
"$B/arm-none-eabi-as"      -mcpu=cortex-m33 -mthumb ble-device-recon/kit/motor_hook.s -o hook.o
"$B/arm-none-eabi-ld"      -T ble-device-recon/kit/motor_hook.ld hook.o -o hook.elf   # ← 不能省
"$B/arm-none-eabi-objcopy" -O binary -j .text hook.elf hook.bin                      # 40 B
# 再注入 + 重签（fw_ver 必须与上次成功一致，调大一位会被静默拒）
# 链路与事故复盘见 ble-device-recon/references/sifli_motor_hook.md

# 7g. 一条命令刷完（用户模式 → DFU → 推流，父进程进 DFU / 子进程推）
python ble-device-recon/scripts/sifli_ota_flash.py --mac AA:BB:CC:DD:EE:FF \
    --ctrl pkg/ctrl_packet.bin --blocks pkg/blocks.bin
# 三个把刷机拖死一整天的坑（缺 0x22 / 同进程二次连接 / GTX20 不广播）
# 见 sifli_ota.md §十二

# 8. 入口不可达（未导出的 Activity）→ 改包，最后手段
python apk-analyzer/scripts/axml_edit.py exported in.xml out.xml --tag XxxActivity
python apk-analyzer/scripts/repack_apk.py app.apk patched.apk --manifest out.xml
# 再用 apksig 重签 v2/v3（android-https-capture 的 cap.py info 也能判该不该改包）

# 9. 收工：把这次的判据/坑/工具沉淀成技能资产（先审质量，再成文）
S=~/.workbuddy/skills/reverse-sediment/scripts/sediment.py
python $S template -o claims.json              # 空模板，含一条 refuted 示例
python $S all      claims.json -o out/         # 校验 + 冲突召回 + 归属 + 渲染
python $S index                                # 全量技能总览，决定"并进哪个"还是"该新建"
# 规则见 reverse-sediment/references/writing_rules.md（结论句三坏形态 / 证据分级 / 坑的公式）
```

---

## 安装到 WorkBuddy

```bash
cp -r android-emulator-adb apk-analyzer apk-runtime-dump apk-reverse-master \
      android-https-capture ble-device-recon reverse-sediment ~/.workbuddy/skills/
```

每个目录都是完整的 skill（`SKILL.md` + `references/` + `scripts/`），可独立安装、独立加载。

---

## 沉淀层：把经验固化成资产，而不是记流水账

`reverse-sediment` 是这个仓库里唯一的**元技能**——它不分析任何对象，只审查结论。

起因很直接：这套技能在实战中产出了**三层连环误判**（见下一节），而三次误判**没有一次是因为"没记录"**，都是"记了但没验"。所以它把"验证"做成了不可绕过的卡点。

四个卡点，脚本会拦：

| 卡点 | 拦什么 | 为什么 |
|---|---|---|
| 置信度 | 必须 `confirmed`/`suspected`/`refuted` 三选一 | 模糊表述会被下游当成确定事实引用 |
| 可复现 | 每条必须有能跑的命令或明确观察步骤 | **没有验证方法的结论 = 传闻** |
| 冲突 | 与现有 skill 的旧结论撞车必须二选一 | 同一知识点散两处、互相矛盾，比没有更糟 |
| 推翻记录 | `refuted` 必须写全"当初当成什么 + 为什么错" | 从同一个错误常量出发，下次一定推出同一个错 |

```bash
S=~/.workbuddy/skills/reverse-sediment/scripts/sediment.py

python $S template -o claims.json      # 空模板
python $S all      claims.json -o out/ # 校验 + 冲突召回 + 归属 + 渲染
python $S index                        # 全部技能总览表（决定"并进哪个"还是"该新建"）
```

实测效果：故意塞进去的不合格结论被逐条拦下（缺 `verify`、`confidence` 写成"maybe"、
已推翻却没写 `why_wrong`），冲突召回对刚写进文档的结论给出 0.46/0.36/0.34 三处命中，
不相关内容零误报。

**它对本仓库最大的价值在"归属路由"**：新结论先问"现有 skill 覆盖了吗"，
有就合并进对应章节，没有才新建。避免技能数量膨胀、知识点四散。

---

## 一条重要的经验教训

这套技能在实战中产出了**三层连环误判**，值得单独记录——因为每一层都是"看起来很合理的推理"：

```
错误的 Hermes 魔数常量（00 07 D0 8B ← 其实是样本文件头）
   └─> 推出"4 字节 XOR 密钥 0xC6186C88"（数学恒等式，不是发现）
        └─> 再推出"双区加密容器 0x0–0x69000"（熵剖面正常布局被误读）
```

真相是：那份 bundle 是**完全未加密的标准 Hermes 文件**（`fileLength == 文件大小`，18,204 个函数）。

**因此立了三条硬规矩**，写在 `apk-reverse-master/references/pitfalls.md`：

1. 任何"我发现密钥了"的结论，必须过**熵要降 + 密钥能在代码里找到出处**两道检验；
2. `header XOR magic` 对任意数据恒成立，**永远是假象**；
3. 判断加固看**类数/方法数**，不看文件体积。

这三次误判也是 [`reverse-sediment`](reverse-sediment/) 存在的原因：
它不是"总结生成器"，而是把这套流程里最容易被跳过的那一步——**验证**——做成了不可绕过的卡点。
删掉错误结论等于把"这条路走不通"的知识也删了，所以它强制保留推翻记录。

---

## 第二条教训：AXML「改值生效，插入无效」

想让一个 `exported=false` 的 Activity 能被 `am start` 调起，直觉做法是给它加一个属性。
这件事做了对照实验：

| 操作 | 结果 |
|------|------|
| 改已有 `allowBackup` 的值 | ✅ 生效 |
| 插入 `exported`（重建字符串池 + 扩 ResourceMap） | ❌ 无效 |
| 插入 `exported`（最小改动，复用已有索引） | ❌ 无效 |
| 插入的 20 字节与已有 `exported` **逐字节一致** | ❌ 无效 |
| **牺牲 `screenOrientation`**，改造成 `exported` | ✅ 生效 |

**这证明不是"字节没拼对"，而是解析器根本不读追加的属性记录。**

> 改已有属性的值 → 生效；插入新属性 → 不生效；扩 ResourceMap → 无用。

所以让组件导出只能"牺牲"它已有的一个无用属性。配方在
`apk-analyzer/references/axml_patch.md`，翻车记录在 `apk-reverse-master/references/pitfalls.md` §9。

**通用教训**：当一个"理论上应该成立"的操作实测无效时，不要反复调参数——
去做**对照实验**，用"另一个能生效的操作"证明你的工具链本身没问题。

---

## 第三条教训：解析器给的"句柄"不一定是 ATT 句柄

刷固件这条线卡了整整两天，最后一查根因荒谬得可笑：**抓包解析器返回的 `handle`
字段是「ACL 连接句柄 | PB 标志位」，不是 ATT 句柄。**

```
看到 0x0200 / 0x0202  →  以为是两个句柄号
实际是同一个连接（ACL handle 0x0200）的 PB=0 / PB=1 两种分片标志
```

于是"数据走 0x0200"被我理解成"往句柄 0x0200 的特征写"，写死了一串**根本不存在的句柄号**。
设备收到就静默丢弃，日志看起来就是"包被拒绝了"。

雪上加霜的是，进 OTA 模式后设备**整套 GATT 换掉**（`0af0` 服务整组消失），
于是"只有 7 个句柄、缺 0x0014/0x001C"又被误判成"GATT 发现被截断"，反复重连去凑齐句柄。

**修好之后**：改按 UUID 后缀解析通道，第一次试就通了——
3MB 镜像 / 18195 分片 / 61 秒推完，两个提交应答都返回 0，设备重启后**固件真的换了版本**。

三条可复用的规矩：

1. **别信字段名，验字段语义**。拿原始字节反解一次（`op ∈ {0x12,0x52,0x1b}` → `unpack('<H', pdu[1:3])`），
   比读十遍解析器的参数名有用。
2. **"设备不响应"先怀疑自己发错地方**，别急着归因到"设备校验了内容"。
   区分方法：看控制应答的 `result_code`——是 0 就说明包被接受了，问题在后面。
3. **数字型常量要用两种独立方法交叉验证**。同一个项目里，"用反汇编覆盖率否掉正确基址"
   和"魔数写错导致假密钥"是同一类错误：**单点推理会把一个错误放大成一串结论**。

---

## 第四条教训：改固件没效果，先怀疑"这行代码跑不到"

把一块手表的界面改成中文、版本号改成 `V9.99.99`，**连续四次刷机零变化**。

每一轮我都把包里的字节验到了底：从 `.blocks` 还原镜像、比 sha256 与元数据一致、
再反汇编看关键地址的指令——**补丁从来没错过**。错的全是语义：

| 轮次 | 改了什么 | 为什么无效 |
|---|---|---|
| 1 | hook `one_level_version_get` 返回 9/99/99 | 该函数只服务日志，UI 直接打印字符串常量 |
| 2 | 改"语言 ID" `02`→`03` | 那是日志参数；且真实语言表里 3 = 法语 |
| 3 | 改"默认语言槽" `0x120AFE50` | 该分支是死代码，被下层兜底短路了 |
| 4 | 改"兜底常量" `0x121762D0` | `it eq` 只在 NVS 读失败时生效，NVS 里一直有值 |
| 5 | **消掉 `it eq`（`08 BF`→`00 BF`）** | ✅ **界面变中文** |

第 3、4 轮是本项目最典型的坑——**链式兜底**：

```asm
get_current_language():
    bl   read_nvs
    ldr  r1, [pc,#8]
    it   eq
    moveq r0, r1        ; ← 自己就把空值兜底成英文，永远不返回 NULL
    pop  {r7, pc}

app_language_init():
    bl   get_current_language
    cbnz r0, skip       ; ← 每次都跳，下面的"默认值"是死代码
    ldr  r4, [pc,#0x2c]
```

上层写「取不到就用默认值」，下层却已经兜底了。改默认值当然毫无反应。

第 1 轮则是**显示值 ≠ 逻辑值**。判断依据就在字符串布局里：

```
"V1.01.06"                    ← 想改的是这个
"one_level_version_get"       ← 紧跟 __func__ 符号名
"\x1b[0;35m%s(%d):app_gse"    ← 紧跟 ANSI 彩色日志格式
```

一组字符串旁边是 `__func__` 和 ANSI 转义码 → 整块属于日志区，
改取版本的函数当然不影响屏幕。而直接把 4 处 `"V1.01.06"` 换成 `"V9.99.99"`，
屏幕立刻就变了（版本号是**字符串常量、有 4 个副本**，少改一个会出现"某页变了某页没变"）。

四条可复用的规矩：

1. **刷完没效果，先问"这段代码真的会执行吗"，不是"字节写对了吗"。**
   看到 `if (err) use_default` 的分支，先去确认那个"取配置"函数**真的会返回错误**。
2. **NVS / 设置分区不会被刷机清空**。所以"读配置失败"这个前提很可能不成立。
   要么消除条件（`it`→`nop`），要么去改 NVS 本身。
3. **没有可见反馈时，先在目标文案旁边塞一个显眼的探针**（`"Steps"`→`"ZZZZZ"`），
   一次刷机就能区分"UI 不读这块"和"读了但开关在别处"。这一步能把猜变成测。
4. **数字表不要靠猜**。语言 ID 表我从一段字体测试样本倒推，推出"3=中文"，
   实际 3 是法语——真实的中文 ID 是 1。**表要读出来，不要反推出来。**

---

## 第五条教训："改文字"有四种数据源，改错一种，字节全对现象全错

需求听起来只有一句话：**把菜单里的"摇骰子"改成"HELLO"**。

第一版我改了应用表里的 `name[16]` 字段——`"Dice"` → `"Hello"`，字节逐位核对无误，
刷回去菜单还是"摇骰子"。因为菜单上的文字**根本不读这个字段**：

| 数据源 | 改它会不会改显示 | 特征 |
|---|---|---|
| 硬编码字符串常量 | ✅ 直接生效 | 字符串独立成串，附近没有表结构 |
| **i18n 表（下标 → 指针）** | ✅ 改指针生效 | 一串密集 u32，全部指向文本块 |
| 结构体 `name` 字段 | ❌ 只用于内部匹配 | 定长 16 字节，紧邻函数指针 |
| 日志 / 上报串 | ❌ 不影响 UI | 旁边有 `__func__` 与 ANSI 转义码 |

真实链路是三段：**应用表给出下标 → i18n 表把下标翻成指针 → 指针指向文字**。
而且 i18n 表**每种语言一张**，只改中文那张，切回英文就变回原文。

最终改动只有 5 个字节（改指针 + 洞里写 `"HELLO"`），一次刷机就成功了。
**难的不是写字节，是判断这段文字从哪儿读。**

这类错误任何字节级校验都查不出来——补丁是对的，模型是错的。
所以现在的顺序固定成：**先 `--dump` 把结构打出来 → 再判断属于哪一类 → 最后才动字节**，
脚本 `sifli_apptab.py` / `sifli_i18n.py` 就是为这一步写的。

---

## 第六条教训：先找"同类的官方实现"反汇编，再动手写

目标：在手表里做一个能点的计算器。前面已经能在页面中间画出 `HELLO` 了，
看起来只差一步——加按钮、加回调、存个运算状态。

结果这一步卡了八轮刷机，每轮 60 秒推流 + 手动点屏幕，现象从"一片空白"到
"卡住后自动重启"，每次都换一个猜测。

真正的突破不是再猜一次，而是**承认猜错方向了**：

**1. 先把范围夹死，而不是换一个变量再试一次**

一版只改一个地方、崩了再换下一个，等于把 N 个可能排成队列逐个试。
改成**一次刷机测四档梯度**，每档只比上一档多一个动作：

| 档位 | 多做的一件事 | 结果 |
|---|---|---|
| A | 容器 + 一个 label | ✅ 正常 |
| B | + 一个按钮（`set_pos` 摆位） | ✅ 正常 |
| C | + 同一个按钮改用 `align` 摆位 | ✅ 正常 |
| D | 16 个按钮 + 写 `user_data` + 注册回调 | ❌ 卡住重启 |

A/B/C 全过，`lv_obj_align` 的嫌疑当场排除，问题锁定在 D 独有的动作上。

**2. 然后去反汇编 `obj_create`**

它初始化对象时会逐个字段赋值，数一遍就知道每个偏移是什么：

```asm
121a764a: strd r7, r1, [r6, #24]   ; obj->event_cb = NULL, obj->signal_cb = 默认函数
121a7652: str  r0, [r6, #32]       ; obj->design_cb = 默认函数
```

一句话定死：`+0x18` 是 `event_cb`，`+0x1C` 是 `signal_cb` 且**默认指向真函数**。
我把显示区指针写进了 `+0x1C`，于是每次重绘 LVGL 都拿它当代码调用 ——
CPU 把 label 数据当指令执行，HardFault，看门狗重启。

"先冻住几秒再重启"这个形态也在这一刻得到解释：崩在**重绘**阶段，不是创建阶段。
之前设计的"逐级留痕"探针全部无效，也是同一个原因——LVGL 绘制是异步的，
崩在首次重绘之前，屏幕上什么都不会留下。

**3. 顺带发现官方的计算器本来就在固件里**

应用表 slot 4 就是 `Calculator`，它的 handler 在 `0x122199D4`。反汇编它，
所有参数都不用猜：按键 88×58、列距 94、行距 66、起点 (10,81)、
先垫一层容器再 `set_size` 到屏幕大小、事件码是 7。

**这条教训的价值不在"找到了偏移"，而在方法**：

> 固件里如果有同类功能，它就是这个硬件上**唯一权威的参考实现**。
> 反汇编它花 20 分钟，试错可能花 8 次刷机、40 分钟，还要你陪着点屏幕。

配套的两条纪律：

- **一次刷机只测一个维度、但可以测多个档位**。梯度探针把"猜"变成"夹"。
- **写注入代码前先 `nm` 扫一遍符号表**。第一版用 `long long` 做运算，
  链接进来 800 多字节的 `__aeabi_ldivmod`，直接撑爆 1.3KB 的代码洞；
  改成 `int` 后编译器出硬件 `sdiv`，总量从 2300 降到 1140 字节。

最终方案反而更简单：**不往对象里存任何东西**，把运算状态放进显示区文本本身
（按 `=` 时解析 `"12+3"` 就地求值）。没有可写字段，就没有能写坏的地方。

---

## 免责声明

本仓库为**方法论与工具**集合，用于安全研究、恶意样本分析、自有应用调试与授权范围内的渗透测试。

请勿用于未授权的商业软件破解。使用者需自行承担合规责任。

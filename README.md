# APK 逆向六件套（Skill Matrix）

一套按「层次」拆开的 Android 逆向技能包。每一层都能单独使用，组合起来覆盖从连设备到出报告的完整链路。

设计原则：**能拆开复用**。只想连模拟器就只加载连接层，只想看静态信息就只加载静态层，上下文不浪费。

**分层依据是「对象边界」，不是功能分类**：
APK 文件 / 进程内存 / 网络流量 / 物理设备，四类对象方法完全不同，混用会让两份结论都失真。

---

## 技能矩阵

| 层 | 技能 | 对象 | 单独能做什么 | 硬前置 |
|----|------|------|-------------|--------|
| 编排 | [`apk-reverse-master`](apk-reverse-master/) | — | 判断该走哪条路、验收标准、坑库、剧本 | 无 |
| 连接 | [`android-emulator-adb`](android-emulator-adb/) | 设备 | 自动找 adb、连端口、设备画像（root/ABI/su/toybox） | 模拟器运行中 |
| 静态 | [`apk-analyzer`](apk-analyzer/) | **APK 文件** | 身份·签名·加固判定·Manifest·DEX 线索·Hermes·Flutter / **改包重签** | Python 3.8+（签名需 JDK） |
| 脱壳 | [`apk-runtime-dump`](apk-runtime-dump/) | **进程内存** | root 内存 dump（DEX/CDEX/Hermes）+ DEX 规范化 | root + toybox dd |
| 流量 | [`android-https-capture`](android-https-capture/) | **网络** | 系统 CA 注入 + mitmproxy 抓 HTTPS + flows 解析 | root（或改包） |
| 无线 | [`ble-device-recon`](ble-device-recon/) | **物理设备** | BLE 扫描/GATT 枚举/SPP 探测 / **零 root 抓 HCI 还原私有协议** | 蓝牙适配器 或 adb |

依赖方向是单向的：编排层调用其余五层，五层之间互不依赖。

```
apk-reverse-master  ──┬──> android-emulator-adb   (连设备 / 装包 / 抓日志)
                      ├──> apk-analyzer           (静态初筛 + 改包，无需设备)
                      ├──> apk-runtime-dump       (运行时脱壳，需 root)
                      │         └──> apk-analyzer dexfile   (dump 产物回到静态链)
                      ├──> android-https-capture  (App ↔ 服务器)
                      └──> ble-device-recon       (App ↔ 硬件)
```

**两条最容易混的边界**：
- 从 APK 里读出协议 → `apk-analyzer`；到真设备上验证协议 → `ble-device-recon`。
- 改包（`apk-analyzer`）是**最后手段**：签名变 → 数据/登录/绑定全丢、官方升级断裂。
  有抓包/脱壳能拿到同样信息时，不要改包。

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

# 8. 入口不可达（未导出的 Activity）→ 改包，最后手段
python apk-analyzer/scripts/axml_edit.py exported in.xml out.xml --tag XxxActivity
python apk-analyzer/scripts/repack_apk.py app.apk patched.apk --manifest out.xml
# 再用 apksig 重签 v2/v3（android-https-capture 的 cap.py info 也能判该不该改包）
```

---

## 安装到 WorkBuddy

```bash
cp -r android-emulator-adb apk-analyzer apk-runtime-dump apk-reverse-master \
      android-https-capture ble-device-recon ~/.workbuddy/skills/
```

每个目录都是完整的 skill（`SKILL.md` + `references/` + `scripts/`），可独立安装、独立加载。

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

## 免责声明

本仓库为**方法论与工具**集合，用于安全研究、恶意样本分析、自有应用调试与授权范围内的渗透测试。

请勿用于未授权的商业软件破解。使用者需自行承担合规责任。

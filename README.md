# APK 逆向四件套（Skill Matrix）

一套按「层次」拆开的 Android APK 逆向技能包。每一层都能单独使用，组合起来覆盖从连设备到出报告的完整链路。

设计原则：**能拆开复用**。只想连模拟器就只加载连接层，只想看静态信息就只加载静态层，上下文不浪费。

---

## 技能矩阵

| 层 | 技能 | 单独能做什么 | 硬前置 |
|----|------|-------------|--------|
| 编排 | [`apk-reverse-master`](apk-reverse-master/) | 判断该走哪条路、验收标准、坑库、剧本 | 无 |
| 连接 | [`android-emulator-adb`](android-emulator-adb/) | 自动找 adb、连端口、设备画像（root/ABI/su/toybox） | 模拟器运行中 |
| 静态 | [`apk-analyzer`](apk-analyzer/) | 身份·签名·加固判定·Manifest·DEX 线索·Hermes 判定 | 只需 Python 3.8+ |
| 脱壳 | [`apk-runtime-dump`](apk-runtime-dump/) | root 内存 dump（DEX/CDEX/Hermes）+ DEX 规范化 | root + toybox dd |

依赖方向是单向的：编排层调用其余三层，三层之间互不依赖。

```
apk-reverse-master  ──┬──> android-emulator-adb   (连设备 / 装包 / 抓日志)
                      ├──> apk-analyzer           (静态初筛，无需设备)
                      └──> apk-runtime-dump       (运行时脱壳，需 root)
                                 └──> apk-analyzer dexfile   (dump 产物回到静态链)
```

---

## 全部零外部依赖

四个脚本都只用 **Python 标准库**，本机不需要 `aapt` / `apktool` / `jadx` / `frida`。

这既是优点也是边界：拿不到反编译级源码，但足以完成加固判定、脱壳、字符串/类/端点情报提取。

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
```

---

## 安装到 WorkBuddy

```bash
cp -r android-emulator-adb apk-analyzer apk-runtime-dump apk-reverse-master ~/.workbuddy/skills/
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

## 免责声明

本仓库为**方法论与工具**集合，用于安全研究、恶意样本分析、自有应用调试与授权范围内的渗透测试。

请勿用于未授权的商业软件破解。使用者需自行承担合规责任。

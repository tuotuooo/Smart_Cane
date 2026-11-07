# 归属路由：新结论该进哪个 skill

> 默认策略是**优先合并，不新建**。技能数量膨胀比知识点缺失更难治——
> 一个知识点散在两个 skill 里，下次谁都不知道该信哪份。

---

## 一、按对象路由

| 结论说的是什么 | 归属 | 落在哪个章节 |
|---|---|---|
| APK 包结构、manifest、资源、签名、重打包 | `apk-analyzer` | `references/` 对应主题 |
| 加固/壳识别、内存 dump、DEX 修复、反混淆 | `apk-runtime-dump` | `SKILL.md` + `references/` |
| HTTPS 证书、mitmproxy、流量解析、接口还原 | `android-https-capture` | `references/` |
| 模拟器连接、adb、logcat、设备画像 | `android-emulator-adb` | `SKILL.md` |
| BLE/GATT/SPP、广播指纹、设备协议、固件、OTA、刷机 | `ble-device-recon` | 按 `references/` 分文件 |
| 跨对象的方法论、决策树、通用判据、误判复盘 | `apk-reverse-master` | `references/methodology.md` / `pitfalls.md` |

脚本自动推断用的关键词表在 `scripts/sediment.py` 的 `ROUTES`，顺序是"越具体越靠前"：
脱壳相关先命中 `apk-runtime-dump`，不会被泛泛的 "apk" 抢走。

---

## 二、三条边界判断（实战里最容易判错的）

### 边界 1：方法 vs 对象

同一个知识点可能同时像"方法论"又像"对象专有"。

```
"改固件没效果时先怀疑'这行代码跑不到'"
```

- 表面看是固件问题 → 该进 `ble-device-recon`
- 但它是**通用调试原则**，对 APK 打补丁、对 hook 注入都成立 → 该进 `apk-reverse-master`

**判据**：把专有名词换掉，结论还成立吗？
换成"改代码没效果时先怀疑这段真的执行了吗"依然成立 → 进 master，
然后在对象 skill 里放一个**指向 master 的链接**加一个具体案例。

### 边界 2：工具的归属

脚本放哪个 skill？

**判据：脚本的输入是哪种对象。**

- 输入是 APK/dex → `apk-analyzer/scripts/`
- 输入是固件镜像 → `ble-device-recon/scripts/`
- 输入是 HCI 日志 → `ble-device-recon/scripts/`（虽然格式跟蓝牙有关，但对象是空口流量）
- 无输入、纯编排 → 放使用它的那个 skill

### 边界 3：要不要新建 skill

新建前必须过三问：

1. **现有 skill 真的都不覆盖吗？** 先去 `index` 看全量清单，再 grep 关键词。
2. **它的对象是新的类别吗？** 六件套里对象分别是 APK、进程、流量、设备、镜像、方法。
   新 skill 应该对应**第六种对象**，不是"某个项目的专有细节"。
3. **能独立触发吗？** 如果它只会在某个现有 skill 跑完之后顺手用一下，那它是那个 skill 的一节，不是新技能。

三个都过才新建。否则合并。

---

## 三、合并时的插入位置

| 结论性质 | 插入位置 |
|---|---|
| 新判据 | 对象文档的"判据"章节；没有就新建一节 |
| 新坑 | `pitfalls.md` 对应分类下（坑库已按"连接/API/判读/操作纪律"分类） |
| 补正旧结论 | **原位置改**，并按 `refuted` 三件套保留推翻过程 |
| 新的可执行方法 | 新增脚本 + `SKILL.md` 命令速查加一行 + `README.md` 加一行 |
| 新的完整子系统（如某个芯片的 OTA 协议） | 新建 `references/<子系统>.md`，在 `SKILL.md` 索引里加一行 |

**不要**新建 `xxx.sediment.md` 扔在 skill 根目录。片段必须被插进已有结构，
否则等于把整理工作推给了下一个人。

---

## 四、跨仓库场景

如果结论来自**另一个仓库/另一个项目**，目标是汇总到当前仓库：

1. 先用 `sediment.py index` 看当前仓库有哪些 skill、各自多少文档
2. 按上面路由表判断归属
3. 如果目标是完全不同的技术栈（比如从 Android 逆向转到 Web 逆向），**不要硬塞**——
   那种情况才值得新建 skill，并在 README 里更新依赖图

---

## 五、每次沉淀后必做

```bash
# 1. 更新目标 skill 的 SKILL.md 文档索引
# 2. 如果有 README，更新能力矩阵那一行
# 3. 确认 references 数量变化后，index 表能反映出来
python scripts/sediment.py index
```

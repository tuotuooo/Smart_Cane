# AXML 改包与重签（AndroidManifest 二进制修改）

> 适用：想 `am start` 一个 `exported=false` 的 Activity、想验证某个组件是不是"没入口"
> 而不是"不能跑"、想改 `allowBackup` / `debuggable` 做动态调试。
>
> **本文件只讲"怎么改"。要不要改、改了会不会被反篡改打死，判据在
> `apk-reverse-master` 的 §2.4 与 pitfalls §9。** 两者的边界很清楚：
> 这里管字节，那边管决策。

---

## 一、先决条件：这个包能不能改

按顺序过三关，有一关不过就别浪费时间去改包：

| 关 | 检查 | 不过怎么办 |
|----|------|-----------|
| 1. 有没有反重打包 | `assets/meta-data/manifest.mf`、`libDexHelper`、自写 APK 校验 | 走 `apk-runtime-dump` 脱壳，别改包 |
| 2. 有没有签名校验回调 | DEX 里搜 `getPackageInfo` + `GET_SIGNATURES`、`MessageDigest` | 同上；或 hook 掉校验（需 frida/root） |
| 3. 重签后能不能装 | 同包名同版本必须卸旧装新，数据会丢 | 先 `adb pull` 出 `/data/data/<pkg>` 或确认无所谓 |

**悦心S1 的实测结论**：`manifest.mf` 不存在、DEX 无签名比对、重签后正常安装正常跑。
所以"改包"这条路在这个样本上是通的——但这是**验证出来的**，不是默认成立的。

---

## 二、AXML 结构速查

```
[0x00] ResChunk_header  type=0x0003(XML) headerSize=8 size=<全文件>
[0x08] StringPool       type=0x0001   ← 所有字符串，索引即"字符串 ID"
[....] ResourceMap      type=0x0180   ← 可选。把"字符串索引"映射到 "attr 资源 ID"
[....] StartNamespace   type=0x0100
[....] StartElement     type=0x0102   ← 真正承载属性
[....] EndElement       type=0x0103
```

`StartElement` 头 16 字节后接 `attrExt`（20 字节）：

```
offset 0x10  ns(4)  name(4)  attributeStart(2)  attributeSize(2)=0x14  attributeCount(2)  idIndex(2) classIndex(2) styleIndex(2)
offset 0x24  属性数组，每条 20 字节：
             ns(4) | name(4) | rawValue(4) | size(2)=8 | res0(1)=0 | dataType(1) | data(4)
```

`dataType`：`0x03`=字符串（data 是字符串索引）、`0x10`=十进制整数、`0x12`=布尔
（data = `0xFFFFFFFF` 真 / `0` 假）。

**关键点：`name` 字段是字符串池索引，不是资源 ID。** 所以"新增一个属性"意味着
同时要有一个字符串池条目 + 一个 resource map 槽位。

---

## 三、铁律：改值生效，插入新属性不生效

这是本文件最重要的一条，踩过整整一轮才确认。

做了对照实验：

| 实验 | 操作 | 结果 |
|------|------|------|
| 对照组 | 改已有 `allowBackup` 的 data（`0xFFFFFFFF`→`0`） | ✅ 生效，解析出的 `ALLOW_BACKUP` 标志确实消失 |
| 实验组 A | 给 Grid Activity **新增** `exported=true` 属性（完整重建 string pool + 扩 resource map） | ❌ 无效，仍 `exported=false` |
| 实验组 B | 同上，但用最小改动（不重建池，复用已有字符串索引） | ❌ 无效 |
| 实验组 C | 插入的 20 字节与 MainActivity 的 `exported` 属性**逐字节一致** | ❌ 无效 |

结论：**Android 解析器对"新增的属性记录"一律忽略，只认原本就在 `attrExt` 里的条目。**
字节级完全一致也不认——所以不是格式写错，是解析路径不读追加项。

`axml_edit.py` 里 `insert_attr()` / `insert_exported()` 保留着，仅作对照实验用，
**不要拿它去实现功能**。

### 那怎么把一个 Activity 变 exported？

**牺牲法**：找一个该组件上**存在但无用**的属性，把它改造成 `exported`。

属性记录里改四个字段即可（其余原样）：

```
name  → "exported" 的字符串索引
raw   → 0xFFFFFFFF        （布尔真值的 rawValue）
type  → 0x12              （TYPE_INT_BOOLEAN）
data  → 0xFFFFFFFF
```

**怎么挑牺牲品**（按安全性排序）：

| 属性 | 丢掉的影响 | 适用性 |
|------|-----------|--------|
| `screenOrientation` | 该页可旋转，可能布局错乱 | 首选，绝大多数页面无所谓 |
| `configChanges` | 旋转/字体变化会重建 Activity | 次选，可能引发状态丢失 |
| `launchMode` | 启动语义变化，可能多实例 | 慎用 |
| `theme` | **千万别动**，且如果它是唯一属性，删了会 `does not specify android:name` | 禁区 |
| `label` / `icon` | 桌面显示异常 | 一般用不上 |

⚠️ **只改属性，不动 name。** 曾把 `WallpaperVideoEditActivity` 上唯一的 `theme`
改成 `exported`，装包直接报：

```
INSTALL_PARSE_FAILED_MANIFEST_MALFORMED: <activity> does not specify android:name
```

一个元素至少要保留 `android:name`。

### ResourceMap 不能扩

原始 manifest 的 resource map 只有 **54 项**，而字符串池有几百条——说明它本来就只覆盖
"被当作属性名用"的那部分字符串，不是一一对应。

试过把它扩到 292 项（与字符串池等长），装机无报错但**行为完全不变**。
原因同上：解析器用的是 `attrExt` 里已存在的记录，map 只是给这些记录查资源 ID 的。

**结论：不要动 resource map。扩它没有收益，只会让文件结构更难解释。**

---

## 四、操作流程

```bash
# 1. 取出 manifest（用本 skill 的 apk_analyze.py，或直接解 zip）
python <skill>/scripts/apk_analyze.py manifest app.apk

# 2. 改（脚本自带 CLI）
python <skill>/scripts/axml_edit.py dump  AndroidManifest.xml          # 看结构 + 属性 + span 索引
python <skill>/scripts/axml_edit.py exported AndroidManifest.xml out.xml \
        --tag WallpaperImageGridActivity          # 牺牲法让组件可导出
python <skill>/scripts/axml_edit.py bool  AndroidManifest.xml out.xml \
        --tag application --attr allowBackup --value false

# 3. 塞回 APK（保留 STORED 条目、剔除旧签名）
python <skill>/scripts/repack_apk.py app.apk out.apk --manifest out.xml

# 4. 重签（必须 v2 或 v3，Android 11+ 只认 v2+）
#    需要 apksig.jar：Android SDK build-tools 里 lib/apksig.jar，或 maven com.android.tools.build:apksig
javac -cp apksig.jar -d . Sign.java
java  -cp apksig.jar:. Sign out.apk out_signed.apk debug.keystore debug android
#                                                   ↑in      ↑out          ↑keystore   ↑alias ↑pass

# 5. 装 + 验
adb install -r -d out_signed.apk
adb shell dumpsys package <pkg> | grep -A2 "WallpaperImageGrid"
adb shell am start -n <pkg>/<全类名>
adb shell dumpsys activity activities | grep mResumedActivity
```

> ⚠ `--tag` 收两种东西：**组件全名**（匹配 `android:name` 属性值，推荐）
> 或**元素名**（`application` / `activity`）。传 `activity` 只会命中第一个 `<activity>`，
> 所以定位具体页面必须传组件名（如 `WallpaperImageGridActivity`，支持后缀匹配）。

**验收标准（唯一硬证据）**：
`dumpsys activity activities` 里 `mResumedActivity` 变成目标 Activity。
`am start` 不报 `SecurityException` 只说明 export 生效，不说明页面能跑起来
（可能内部崩、可能立刻 finish）。

---

## 五、签名：为什么必须 v2/v3

| 方案 | 覆盖范围 | 够不够 |
|------|---------|--------|
| v1 (JAR) | zip 条目 | 不够。Android 11+ 且 targetSdk≥30 时可能被拒 |
| v2 | 整个 zip（含中央目录） | 够，最通用 |
| v3 | 加密钥轮换信息 | 够，与 v2 并存更稳 |

用 `apksigner` 最省事；没有的话用 `Sign.java`（apksig 库的薄封装）：

```java
ApkSigner.SignerConfig cfg = new ApkSigner.SignerConfig(
    1, keyName, privateKey, certs);
new ApkSigner.Builder(ImmutableList.of(cfg))
    .setInputApk(in).setOutputApk(out)
    .setV1SigningEnabled(true).setV2SigningEnabled(true).setV3SigningEnabled(true)
    .build().sign();
```

debug keystore 生成：

```bash
keytool -genkeypair -v -keystore debug.keystore -storetype PKCS12 \
  -alias debug -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass android -keypass android -dname "CN=Android Debug,O=Android,C=US"
```

**签名后校验**：`apksigner verify --print-certs out_signed.apk`，
或者看 `apk_analyze.py analyze` 的 `[5] 签名证书` 是否变成你自己的。

---

## 六、改包的副作用清单（改之前先接受）

1. **版本号没变、签名变了** → 必须先 `adb uninstall`，App 数据全清。
   想保数据：`adb backup` 或先 root 拷 `/data/data/<pkg>`。
2. **登录态丢失** → 要重新登录，某些 App 首次登录触发风控。
3. **绑定关系丢失** → 蓝牙设备需要重新配对绑定（悦心S1 实测：重装后需重新绑定，
   但设备端不用重置）。
4. **增量更新失效** → 后续官方升级装不上，只能再卸再装。
5. **某些 SDK 会检测签名** → 极验、部分支付/推送 SDK 在签名不符时静默降级或拒服。

---

## 七、坑

| 现象 | 原因 | 处理 |
|------|------|------|
| 装包报 `does not specify android:name` | 把元素唯一属性改掉了 | 保留 `android:name`，换别的属性牺牲 |
| 插入属性后完全没效果 | 见第三节，插入无效 | 用牺牲法 |
| `am start` 报 `not exported from uid` | 改的那条没生效 / 改错 Activity | `dumpsys package` 确认 `exported=true` 再试 |
| 装上了但 App 打不开 / 闪退 | 有签名校验或反篡改 | 放弃改包，转脱壳或 hook |
| 重签后 `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | 签名冲突 | `adb uninstall` 后重装 |
| APK > 300MB 打包很慢 | zip 重压缩 | `repack_apk.py` 保留原 `compress_type`，STORED 条目不动 |

---

## 八、这条路的边界

改包能解决的是**"入口不可达"**，解决不了**"逻辑不在这"**。

- ✅ 未导出 Activity 起不来 → 改包（本文）
- ✅ `allowBackup` 关着取不到数据 → 改包
- ❌ 想知道某个按钮背后的网络请求 → 改包没用，去抓包（`android-https-capture`）
- ❌ 想知道蓝牙发的是什么 → 改包没用，去抓 HCI（`ble-device-recon` 附录 A）
- ❌ 代码被加固 → 改包无用，去脱壳（`apk-runtime-dump`）

**改包的成本不在技术上，在副作用上**（数据清空、绑定丢失、后续无法升级）。
所以先问一句"有没有不改包就能拿到同样信息的办法"，通常都有。

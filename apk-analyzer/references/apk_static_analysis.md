# APK 静态分析 · 方法论与实战要点

本参考沉淀 `apk_analyze.py` 背后的分析思路、已验证的加固/加密方案，以及排查技巧。
脚本已自动化大部分内容；遇到异常或需要进一步深挖时，按本文人工推进。

## 一、无依赖分析思路（为什么不用 aapt/jadx）

APK 本质是一个 ZIP。纯标准库即可读取内部条目，关键挑战只有一个：**AndroidManifest.xml
是 AXML 二进制格式**（不是文本 XML）。手写解析器要避开两个坑（已在脚本中修复）：

1. **StringPool 块类型是 `0x0001`**（RES_STRING_POOL_TYPE），不是 `0x001C`（那是
   ResourceMap 等）。类型写错会整段漏解析。
2. **根 chunk `0x0003` 不能直接跳过整文件大小**，必须把 `pos += 8` 进入子块继续遍历，
   否则所有 StartTag 都找不到（表现为「Manifest 解析失败 / 无节点」）。

解析出来的属性里，`exported` 等若显示为 `None` 是正常（属性未显式声明，AXML 中
type=0x00 null）；显示为具体数字才是真值。

## 二、加固 / 加壳识别对照

| 特征 | 含义 |
|------|------|
| `libDexHelper.so` / `libDexHelper-x86.so` | 腾讯**乐固 legu** 或同类抽取型壳 |
| `libshell*.so` / `libmsaoaid.so` | 梆梆 / 360 加固 |
| `com.secneo.apkwrapper.H` 出现在 logcat | **SecNeo（盛安德）商用加固**——真正的 DEX 与 Hermes bundle 由壳运行时解出 |
| 签名证书 Subject = `CN=Android Debug, O=Android, C=US`，SHA1 `949bab53…`，SHA256 `111052ab…` | **Android 默认 debug 证书** → 重签/破解/修改版铁证 |
| DEX 含 `getPackageSignatureV3` / `verifyMDMSignatureV1/V2` / `Game signature verification passed` | App 自带签名/完整性校验逻辑 |
| `META-INF/services/` 下大量混淆文件（`J8.c`/`ht.c` 等） | 经混淆的 service 描述文件 |

> 实战案例：森空岛 v2.3.0 样本同时命中 SecNeo 壳 + 默认 debug 证书 + `libDexHelper` +
> `stamp-cert-sha256` 完整性校验，是「修改/重签/破解版 + 商用加固」的典型组合。

## 三、React Native + Hermes：先判"是不是真加密"

**Hermes 魔数是 8 字节：`0x1F1903C103BC1FC6`**，小端落盘为
`C6 1F BC 03 C1 03 19 1F`。只看前 4 字节 `C6 1F BC 03` 也能识别，但校验时用 8 字节更稳。

### 3.1 头部字段布局（关键：sourceHash 是 20 字节）

```
偏移   长度  字段
0x00    8   magic            0x1F1903C103BC1FC6
0x08    4   version          常见 84/86/89/90/91/95/96
0x0C   20   sourceHash       SHA1（20 字节！）
0x20    4   fileLength       ← 与文件实际大小比较
0x24    4   globalCodeIndex
0x28    4   functionCount
0x2C    4   stringKindCount
0x30    4   identifierCount
0x34    4   stringCount
0x38    4   overflowStringCount
0x3C    4   stringStorageSize
...
0x58    4   debugInfoOffset
```

**经典坑**：以为 `fileLength` 在 `0x10`。因为 `sourceHash` 是 20 字节 SHA1 而非 4 字节，
在 `0x10` 读到的是 sourceHash 的中段，会得到一个荒谬的大数（如 4023575268）。
`fileLength` 实际在 **`0x20`**。

### 3.2 加密与否的唯一判据

| 条件 | 结论 |
|------|------|
| magic == `0x1F1903C103BC1FC6` 且 `fileLength == 文件大小` | **标准未加密 Hermes**，可直接反汇编 |
| magic 对但 `fileLength` 不符 | 文件被截断或二次打包 |
| magic 不对 | 自定义容器 / 加密载荷 |

实测森空岛 `assets/rn/main.jsbundle`：

```
magic            = 0x1F1903C103BC1FC6
version          = 90
fileLength       = 3539736  (文件大小 3539736，完全一致)
functionCount    = 18204
stringCount      = 23045
identifierCount  = 11266
stringStorageSize= 463042
```

→ **这是普通的、未加密的 Hermes 字节码**。JS 层完全静态可达，用 `hbcdump` /
`hermes-dec` 就能反汇编，不需要脱壳。

### 3.3 熵剖面 ≠ 加密证据

标准 Hermes 文件本身就是"高低熵混合"：头部 + 函数头 + 字节码 + 索引表是二进制（熵高），
`stringStorage` 是大段可打印文本（熵低、可打印率高）。所以看到"前段高熵、后段可打印"
是**正常结构**，不能据此宣称"代码段被加密"。

熵剖面只用来定位"字符串存储大概在哪个区间"，不是加密判据。

### 3.4 三次误判链（务必别重演）

这个样本上连续栽了三次，每一次都由上一次派生：

```
① 把样本自己的加密头 00 07 D0 8B 误当成 HERMES_MAGIC 常量
      ↓ 于是真文件（头是 C6 1F BC 03）被判为"魔数不匹配"
② 用 header XOR 那个错误常量，得到 4 字节值 → 宣称"发现 XOR 密钥 0xC6186C88"
      ↓ 但整文件 XOR 后熵 6.79→7.21（升高），DEX 中搜该值 0 命中
③ 熵测绘看到"前段高熵后段可打印" → 宣称"双区加密容器，0x0-0x69000 是加密区"
      ↓ 而真相是：这就是标准 HBC 的自然布局
```

**教训**：`header XOR magic` 对任意数据都成立，是恒等式，永远不能作为"发现密钥"的证据。
判断 Hermes 是否加密，只认 **magic + fileLength 自洽**。

### 3.5 实用结论

- 标准 HBC：直接用 `hbcdump -d` / `hermes-dec` 反汇编，能拿到 JS 源码。
- 非标准容器：静态无解，走运行时 dump（`apk-runtime-dump`）。
- 无论哪种，**明文字符串总能抽**：`strings` / `bundle` 子命令给出的域名、组件名、
  深链（`skland://`）、错误文案，往往足够定位业务与接口。

## 四、反重打包完整性清单（manifest.mf）

路径通常为 `assets/meta-data/manifest.mf`，是 App **自建**的防篡改清单（非 Android 原生）。

- 格式：base64url 记录拼接，每条记录 = `base64url([前缀字节][载荷])`，记录之间以 `=`
  **内联填充分隔**（不要把 `=` 当记录分隔符去切分，会破坏对齐）。
- 头部记录载荷为明文：`AndroidManifest.xml,!stamp-cert-sha256`
  （`!` 分隔出 `stamp-cert-sha256` —— 期望的**签名证书 SHA256 指纹**）。
- 其余记录多为逐文件 SHA1 哈希（每条解码出 20 字节二进制，不会是可读串）。
- 脚本采用双策略：① 在 base64 原文中搜已知载荷的编码串（最稳健）定位头部；② 整串去
  `=` 后解码提取可读文件名/片段。若识别到 `stamp-cert-sha256`，即可判定该 App 做了
  **证书指纹绑定 + 逐文件哈希校验**——这正是 License/防破解授权的同源技术。

## 五、签名证书指纹对照

用 `unzip -p app.apk META-INF/*.RSA | openssl pkcs7 -inform DER -print_certs` 或脚本
的 `[5]` 段查看。重点看 Subject 与 SHA1/SHA256：

- 官方发布包：Subject 含厂商名（如 Hypergryph / 小米 / 腾讯），有效期通常 20–30 年。
- 默认 debug 证书：`CN=Android Debug, O=Android, C=US`，SHA1 `949bab53c65060108c870b514f9521887abe5f08`，
  SHA256 `111052ab0f1396aacf0f691dabb6d759d9adb3d5ad131e5c3ddc76502e8c20ba` → 修改版铁证。
- 证书指纹应与 `manifest.mf` 里的 `stamp-cert-sha256` 对照：一致说明未被重打包篡改；
  不一致说明样本相对官方包已被改签名。

## 六、进一步深挖路线图（超出本 skill 静态范围）

1. **真 DEX**：优先用 `apk-runtime-dump` 的纯 root 方案（`/proc/<pid>/mem`），
   不需要 Frida/apktool，加固壳感知不到。无 root 时再考虑 Frida hook
   `InMemoryDexClassLoader` / `DexFile.loadDex`。
2. **Hermes 字节码**：先用本 skill 的 `bundle` 判是否标准 HBC；是则直接
   `hbcdump -d` / `hermes-dec` 反汇编，**不需要脱壳**。只有非标准容器才走运行时 dump。
3. **完整解码 manifest.mf**：定位 App 私有解析器（变长/varint 二进制格式），完整还原
   逐文件哈希与证书指纹，与官方包逐字节对比。
4. **HTTPS 抓包**：样本走 HTTPS 时，用 frida + objection 或 Charles 证书注入解密流量，
   锁定授权/激活接口的请求体与签名算法。
5. **动态衔接**：把 apk 交给 `android-emulator-adb` skill 装进模拟器，抓 logcat 验证
   静态发现的加固/加密/校验行为是否真实触发（如是否弹「已篡改」或静默退出）。

## 七、常见报错与处理

- `analyze` 报 `Manifest 解析失败`：绝大多数是 AXML 解析异常，脚本已回退到原始字符串
  扫描；若仍无收获取，可换 `apktool d` 反编译后再读 `AndroidManifest.xml`。
- `签名证书` 只显示指纹无 Subject：`cryptography` 库未安装，pip 安装后即可解析。
- bundle 子命令 `明文串数` 偏少：说明该样本字符串表也被加密，需走第六节的脱壳路线。
- `manifest.mf` 显示「未能识别标准标记」：可能样本用了不同的私有格式，需人工按第四节
  思路解析其私有解析器。

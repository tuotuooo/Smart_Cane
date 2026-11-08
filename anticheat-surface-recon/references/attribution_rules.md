# 归属判定：别用名字猜职责

> 这一篇是本项目**代价最大的一课**。7 个 native 库，第一次判定错了 4 个——
> 而且错法完全一致：**看到名字像，就编了个职责，没做归属验证。**
>
> 起因是一句话：*"没有实际验证过的，都不能作为结论和依据。"* 复核之后，
> 一份已经写进报告的「七库分工」整章作废。

---

## 一、四条硬判据

只有这四类证据算「已证」。它们都由**工具链机械生成**，人想改就得改上游，改不动：

| 判据 | 形态 | 为什么不会撒谎 |
|---|---|---|
| **JNI 命名空间** | `Java_com_taptap_sdk_themis_lite_ThemisLite_*` | JNI 函数名由 Java 包路径机械拼接，改名要同步改 Java 侧 `native` 声明 |
| **CI 构建路径** | `/runner/work/tapsdk-monorepo/...`、`/bkdevops/tpmobile/...` | 编译机绝对路径在编译时烤进二进制，与运行时无关 |
| **Itanium C++ mangled** | `_ZN3MNN7Express...` | 由编译器按 namespace/class 生成，无法随意命名 |
| **自有包名引用** | `com.tencent.tmgp.dfm`（游戏自己的包名） | 只可能出现在自家代码里 |

判定顺序：**先扫 JNI 前缀**（5 秒，`grep -a -o 'Java_[A-Za-z0-9_]*'` 取第一个），
再扫 CI 路径，最后才看 mangled 符号。JNI 前缀一击必中时，后面都不用做。

### 明确不算证据的四类

| 不算 | 反例 |
|---|---|
| 文件名 | `libturinggame.so` 叫 "turing"，但它确实是腾讯图灵盾；`libthemis.so` 叫 "themis"（希腊神话「法律」），它是 TapTap 的 |
| 字符串语义 | 带 `crypto` 字样 = 加密库？带 `root` = 反 root？见 §三 |
| 符号数量 | "656 个 crypto 符号" 听起来像加密核心，实际是 boost::asio 的 TLS 实现被一起链进来 |
| 体积 | 大 = 重要？`libUE4.so` 561 MB 是游戏引擎，跟反作弊无关 |

---

## 二、案例：7 个库，错了 4 个

| 库 | 第一版判定 | 真实归属 | 一击必中的证据 |
|---|---|---|---|
| `libtersafe.so` | TenSafe 主反外挂 SDK ✅ | **ACE 核心**（内存操作/扫描） | 构建路径 `/bkdevops/tpmobile/.../VM/Memory/BopMemoryOperation.cpp`，`tpmobile`=TenProtect Mobile、`bkdevops`=腾讯蓝鲸 CI |
| `libtprt.so` | 内联 Hook 引擎 ✅ | **ACE Runtime**（hook 检测） | `g_tprt_ori_array` / `g_tprt_pfn_array` + `TssSDKIoctl` + 引用 `com.tencent.tmgp.dfm` |
| `libturinggame.so` | root/调试进程检测器 ✅ | **腾讯图灵盾**（设备风控） | `com/tencent/turingfd/sdk/game/TNative`、`turingRiskDetect` |
| `libRoosterNN.so` | 硬件画像库 ❌ | **阿里巴巴 MNN 推理引擎** | `_ZN3MNN7Express...`、`QuantizedMatMul` |
| `libtapsdkcore.so` | ACE 加密+完整性核心 ❌ | **TapTap SDK openlog** | `Java_com_taptap_sdk_openlog_internal_...`、`/runner/work/tapsdk-monorepo/.../Openlog/src/jni.cpp` |
| `libthemis.so` | 环境检测库 ❌ | **TapTap SDK themis** | `Java_com_taptap_sdk_themis_lite_...`、`Lcom/taptap/sdk/themis/lite/ThemisServiceConnection;` |
| `libmagt_sdk.so` | Rust 反作弊组件 ❌ | **联发科 MAGT 性能调度** | `Java_com_mediatek_magt_sdkbridge_..._nativeInitRust` |

**四个错的共同点：全部依赖「名字的语义联想」，没有一条依赖「产物里的机械证据」。**

而且这个错误类型在本项目里重复了不止一次：

```
getRootState / C_ROOT_STATE / magisk  →  cn.jiguang（极光推送，内嵌 RootBeer）
test-keys / goldfish / superuser      →  io.sentry（崩溃上报）
frida                                 →  com.geetest（极验风控）
su 多路径                             →  libdivider2.so（游戏加速器，检测到 root 只关 boost）
Game signature                        →  加速器的"游戏包签名白名单"，不是 App 自校验
kworker/0:1 匹配 "kworker" 正则       →  内核线程，不是 KernelSU
```

结论：**代码层面根本不存在「检测到 root 就杀进程」的路径**——之前那串"实证"全是别人的字符串。

---

## 三、五类假阳性（计数型扫描必踩）

只看命中数会得出灾难性结论。实测：

| 报出 | 真实来源 | 判定 |
|---|---|---|
| `clone` ×17（→"多开/分身检测"） | `boost::exception_detail::clone_base` | ❌ C++ 库 |
| `clone` ×4 | `MNN::Session::cloneExecution` | ❌ 推理引擎 |
| `proxy` ×6 + `mitm` ×1（→"抓包/代理检测"） | `ac-proxying` / `proxyPolicy` / `id-smime-aa-ets-commitmentType` | ❌ X.509 扩展名 |
| `GOT` ×1（→"Hook 框架"） | `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` | ❌ TLS 套件名 |
| `parallel` ×1 | `parallelizationParameter` | ❌ BoringSSL 配置项 |
| `gettimeofday` → "时间/加速检测" | 就是个普通 libc 调用，任何计时逻辑都有 | ❌ 噪音，`ace_scan.py` 的已知弱点 |

第一版据此报了 **"TAP SDK 有 18 处多开检测 + 7 处抓包检测"**。清理后是 **0**——
那个库只是被链进来的依赖，一个检测逻辑都没有。

**规矩：每一个命中都要看上下文，不能只数个数。** `ace_scan.py` 输出时会把命中位置前后
各若干字节一起打出来，就是为这一步。

---

## 四、操作流程

```bash
# ① 一击必中：JNI 前缀（5 秒）
grep -a -o 'Java_[A-Za-z0-9_]\{4,\}' target.so | sed 's/_/\//g' | cut -d/ -f2-4 | sort | uniq -c | sort -rn

# ② CI 路径（编译机绝对路径）
grep -a -o '/\(runner\|home\|bkdevops\|build\)[A-Za-z0-9._/-]\{6,80\}' target.so | sort -u | head

# ③ C++ mangled 命名空间
grep -a -o '_ZN[0-9]\{1,2\}[A-Za-z][A-Za-z0-9_]\{2,20\}' target.so | sort | uniq -c | sort -rn | head

# ④ 全库能力面 + 特征串（带上下文）
python <skill>/scripts/ace_scan.py *.so --json ace.json
```

DEX 侧同一套逻辑：

```bash
# 字符串 → 引用它的方法 → 反汇编（纯标准库，不需要 JRE）
python apk-analyzer/scripts/dex_tool.py str  classes.dex "Game signature"
python apk-analyzer/scripts/dex_tool.py xref classes.dex "checkDeviceRoot"
```

**判"这个字符串属于谁"的唯一可靠方法，是找到引用它的那个方法，看那个方法在哪个包里。**
跳过这一步，"Java 层有很多 root 检测"这种错觉就会出现——实测那两个 dex（12.3 MB + 5.3 MB）里
真正的反作弊 Java 入口只有 `com/tencent/tp/TssSdk` 一个薄壳，检测逻辑全在 native。

---

## 五、两个"看起来像加密其实不是"

这两个坑都发生过，且都差点被当成结论：

| 误判 | 真相 | 怎么发现的 |
|---|---|---|
| `libthemis.so` 字符串"近乎全加密" | **整串倒序存储**，串密度 2215 串/MB，是 7 个库里最高的 | 按体积归一化后密度正常；`noitpecxe`→`exception`、`diordna`→`android` |
| 熵剖面"前高后低"= 加密容器 | Hermes HBC 的正常布局：头+字节码高熵、stringStorage 可打印 | 标准魔数 + `fileLength == 文件大小` 双重自洽 |

**判加密只认结构性自洽（魔数 + 长度字段），不认熵、不认"看起来乱"。**
`header XOR magic` 对任意数据恒成立，永远是假象——这个错误本项目也犯过，
推出了一个不存在的"4 字节 XOR 密钥 `0xC6186C88`"。

> 反序存储的**完整变换算法没有解出来，明确标【未知】**。
> 猜混淆算法是最容易翻车的一步（同一个坑：假 XOR 密钥）。
> 能读到倒序形态、能确认它没加密，已经够用了——不要再往下猜。

---

## 六、结论标注纪律

每条结论都要带标注，缺一个就会被下游当成确定事实引用：

| 标注 | 含义 |
|---|---|
| **【已证】** | 有上述四类硬证据之一 |
| **【推断】** | 由已证事实向外推一步，未直接观测 |
| **【未知】** | 明确不知道。**写"未知"，不要写"可能""疑似"然后跳过** |

配套的"未验证清单"要单独列出来（本项目的例子：MNN 跑什么模型、libthemis 其余混淆变换、
各库实际加载顺序）。**列出未验证项比补齐它们更重要**——它防止下一个人从同一个错误起点重新推理。

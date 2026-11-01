# 端到端剧本

五条常见链路，每条给出**完整命令序列**与**每步验收**。照抄改包名即可。

约定：
- `<A>` = `apk-analyzer` 技能目录
- `<E>` = `android-emulator-adb` 技能目录
- `<R>` = `apk-runtime-dump` 技能目录
- 工作目录 `./analysis/`

---

## 剧本 A：普通未加固 APK，快速摸清

**适用**：用户只是想知道"这是什么应用、要什么权限、连哪些服务器"。
**耗时**：1~2 分钟。**不需要 root**。

```bash
mkdir -p analysis

# 1. 完整静态报告
python <A>/scripts/apk_analyze.py analyze sample.apk --json > analysis/static.json

# 2. 看关键线索（授权/端点/加密）
python <A>/scripts/apk_analyze.py dex sample.apk --keyword http
python <A>/scripts/apk_analyze.py dex sample.apk --keyword license
python <A>/scripts/apk_analyze.py strings sample.apk --keyword token --out analysis/strings.txt
```

**验收**：
- 报告里 `[4] DEX 线索` 的类数/方法数与包体积**匹配**（不是桩）
- 有包名、版本、签名指纹
- 至少列出 3 个业务域名

**输出**：直接写报告第 0~3 节即可，不需要第 4 节。

---

## 剧本 B：加固 APK，要拿真实代码

**适用**：剧本 A 第 1 步发现加固特征。
**耗时**：5~20 分钟。**需要 root。**

```bash
# 0. 静态确认加固（记下判据，后面要写进报告）
python <A>/scripts/apk_analyze.py analyze sample.apk | sed -n '/DEX 线索/,/^\[5\]/p'

# 1. 设备画像：这一步不过就别往下走
python <E>/scripts/find_and_connect.py --info --human
#    要看到 root: YES (uid=0)  和  toybox dd: 可用

# 2. 安装并启动（-g 避免权限弹窗打断）
python <E>/scripts/find_and_connect.py -- install -g sample.apk
python <E>/scripts/find_and_connect.py -- shell am start -n com.pkg/.SplashActivity

# 3.（可选）确认进程活着，并记录 maps 里有没有壳的 so
python <E>/scripts/find_and_connect.py -- shell "pidof com.pkg; grep -o 'libDexHelper[^ ]*' /proc/\$(pidof com.pkg)/maps | head -1"

# 4. 看地形（秒出，先确认候选区域合理）
python <R>/scripts/apk_runtime_dump.py --pkg com.pkg --list

# 5. 脱壳
python <R>/scripts/apk_runtime_dump.py --pkg com.pkg --out analysis/memdump

# 6. 规范化 + 体检
python <R>/scripts/dex_fix.py "analysis/memdump/dex_*.bin" --out-dir analysis/memdump/fixed
```

**验收**（三个都要满足）：
1. 命中 DEX 数量 ≥ 1，且总大小与业务规模相符；
2. `dex_fix.py` 每个文件 `truncated=False`；
3. `code_off: invalid = 0`。

**拿不到时的分支**：

| 情况 | 分支 |
|------|------|
| 0 命中 | 让 App 进入主界面再扫；或 `--min-mb 0 --max-mb 800` 放宽 |
| 只命中 1 个 | 多走几个界面重复扫（惰性解密） |
| invalid > 0 | `--region 0xSTART-0xEND` 整段重 dump |
| 读内存全空 | 回剧本 E |

**输出**：报告第 4 节（脱壳成果 + 产物表）。

---

## 剧本 C：React Native + Hermes 应用

**适用**：assets 里有 `index.android.bundle`，或 maps 里有 `libhermes.so`。

```bash
# 1. 静态看容器结构（不脱壳也能拿到大量业务字符串）
python <A>/scripts/apk_analyze.py bundle sample.apk
python <A>/scripts/apk_analyze.py bundle sample.apk --json > analysis/bundle.json

# 2. 提取明文字符串表
python <A>/scripts/apk_analyze.py strings sample.apk --keyword http --out analysis/bundle_strings.txt
```

若需要**真正的 JS 字节码/方法逻辑**，先看 `bundle` 的判定：

```bash
# 2. 看是否标准未加密 HBC
python <A>/scripts/apk_analyze.py bundle sample.apk --json | \
  python -c "import sys,json;d=json.load(sys.stdin);print('标准HBC:',d['hermes_valid'],'| fileLength匹配:',d['file_length_match'])"
```

- `hermes_valid: true` → **直接反汇编，不用脱壳**：
  `hbcdump -d assets/rn/main.jsbundle out.asm` 或 `hermes-dec`
- `false` → 才是自定义容器/加密，继续下面步骤

```bash
# 3. 让 RN 页面加载（登录后 / 进首页），确认引擎已初始化
python <E>/scripts/find_and_connect.py -- shell "grep -c hermes /proc/\$(pidof com.pkg)/maps"
#    输出 > 0 才能进行下一步；0 就是还没加载

# 4. 定向扫 Hermes
python <R>/scripts/apk_runtime_dump.py --pkg com.pkg --magic hermes --out analysis/hermes
```

**验收**：产物以 `c6 1f bc 03` 开头，大小与 assets 里 bundle 量级相当。

**警示**：不要用"header XOR 魔数"的方式声称能解密（见 pitfalls 1.4）。

---

## 剧本 D：定位授权 / License 校验逻辑

**适用**：KMS 激活器、License 类样本，目标是找"校验在哪、请求发到哪、结果怎么存"。

```bash
# 1. 静态圈定候选（先不脱壳）
python <A>/scripts/apk_analyze.py strings sample.apk \
  --keyword license --keyword activat --keyword sign --out analysis/lic.txt
python <A>/scripts/apk_analyze.py dex sample.apk --keyword auth

# 2. 若已加固 → 先走剧本 B 拿真 DEX，再对 fixed DEX 做同样的关键词挖掘

# 3. 动态验证：清日志 → 触发流程 → 抓线索
python <E>/scripts/find_and_connect.py -- logcat -c
#   （手动在模拟器里点"激活"，或 am start 拉起目标 Activity）
python <E>/scripts/find_and_connect.py -- logcat -d > analysis/log.txt
grep -iE "license|activat|token|sign|http|post" analysis/log.txt

# 4. 数据落地：看授权状态存在哪
python <E>/scripts/find_and_connect.py -- pull /data/data/com.pkg/shared_prefs analysis/prefs
python <E>/scripts/find_and_connect.py -- pull /data/data/com.pkg/databases analysis/db
```

**验收**：
- 能指出**校验入口类/方法**（脱壳后可读伪码）
- 能给出**授权服务器域名与路径**
- 能指出**校验结果落盘位置**（SP 键名 / db 表名 / 文件）

**注意**：只做**分析**。不提供绕过实现。

---

## 剧本 E：App 打不开 / 一启动就闪退

**排查顺序**（从最便宜的开始）：

```bash
# 1. 是不是装都装不上（签名冲突 / minSdk）
python <E>/scripts/find_and_connect.py -- install -r sample.apk

# 2. 装机成功但起不来 → 看真实异常
python <E>/scripts/find_and_connect.py -- logcat -c
python <E>/scripts/find_and_connect.py -- shell am start -n com.pkg/.MainActivity
python <E>/scripts/find_and_connect.py -- logcat -d | grep -iE "fatal|exception|died|ANR" | head -30

# 3. 进程存活多久（本机循环，比 PC 轮询准）
python <E>/scripts/find_and_connect.py -- shell \
  'am start -n com.pkg/.MainActivity >/dev/null 2>&1; for i in $(seq 1 40); do p=$(pidof com.pkg); echo "$i ${p:-DEAD}"; sleep 0.2; done'

# 4. 怀疑 root/emulator 检测
python <E>/scripts/find_and_connect.py -- logcat -d | grep -iE "root|emulator|magisk|tamper|signature"

# 5. 怀疑反重打包（改过包 / 重签过）
python <A>/scripts/apk_analyze.py analyze sample.apk | grep -A3 "完整性"
```

**判断表**：

| 表现 | 结论 |
|------|------|
| 立刻 DEAD，logcat 有 `FATAL` + Java 异常 | 代码崩溃，读栈 |
| 立刻 DEAD，无异常 | native abort / `exit()` → 检测触发 |
| 存活 1~3 秒后 DEAD | 定时检测（root/emulator） |
| 停在启动页不前进 | 网络/校验失败，不是崩溃 |
| 进到登录页就 DEAD | 反 root 在登录时触发 → 抢窗口 dump（剧本 B 第 5 步前置） |

---

## 通用收尾

```bash
# 汇总结论
python <A>/scripts/apk_analyze.py analyze sample.apk --json > analysis/static.json
python <R>/scripts/dex_fix.py "analysis/memdump/dex_*.bin" --json > analysis/dex_report.json
```

报告照 `SKILL.md` 第六节的七节结构写，**第 6 节"边界与未解项"不能省**。

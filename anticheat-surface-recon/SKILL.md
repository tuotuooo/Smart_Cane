---
name: anticheat-surface-recon
description: 当需要测绘一个 Android 反作弊 SDK 的检测面时使用——从内核 SELinux avc 审计**被动还原** App 实际探测了哪些路径（存在性 / 能力 / 无文件对象三类）、把 native 库的敏感能力导入与检测特征串归并成"哪个库真的具备检测能力"、判定库与字符串的真实归属（避免把第三方 SDK 错算成反作弊）、pcap/pcapng 解析与 UDP 流结构挖掘（tick rate / 固定 stride 记录数组 / 浮点列筛选）、以及**设备结构面一致性门禁**（ABI / 转译层 / SELinux / Seccomp / 模拟器属性 / 包面，13 类硬阻断）。触发词：反作弊、检测面、ACE、TenSafe、tprt、turinggame、被检测、SELinux avc、audit、谁在探测我、这个字符串是谁的、库归属、假阳性清理、pcap 解析、pcapng、tick rate、UDP 流、结构挖掘、环境门禁、环境一致性、模拟器破绽。本 skill 只做**被动观测与静态事实提取**，不实现任何 hook / 隐藏 / 伪造 / 规避。
agent_created: true
---

# 反作弊检测面测绘（被动观测视角）

## Overview

测一个反作弊栈"在看什么"，有两条路：**静态搜字符串**，和**看它实际做了什么**。
这个 skill 的核心结论是：**在探测路径这一项上，静态完全失效，运行时内核审计是唯一可行路线。**

实测样本（`com.tencent.tmgp.dfm`，ACE/TenSafe 栈）里，8 个 native 库搜 `/proc|/dev|/sys` 路径串的结果是：
`libtersafe.so` 只有 1 条（`/dev/random`），`libtprt.so` / `libUE4.so` 是 0 条。
而同一批库里 `ms_open_file`、`tss_sdk_send_data_to_svr` 这些**接口名是明文的**。

> 一句话：**它对"接口名"不加密，对"探测路径表"加密或干脆云控下发。**
> 所以你逆不出清单，但只要它的 SELinux 环境是 permissive，内核就会替你把清单打印出来。

这不是绕过检测，是把**它自己的检测动作**变成观测对象。

## 边界：这个 skill 不做什么

写在最前面，因为这几条都是实测撞过的墙，不是立场问题：

| 不做 | 为什么（技术原因，不是道德原因） |
|---|---|
| 不实现 hook / 隐藏 / 伪造 | 环境检测的主战场已经从"你装了什么"变成"你还能做什么"。`/proc/iomem` 读成功这件事，只能靠 hook `open()` 让它失败，而 hook 本身会被 `ms_hook_opcode` 的**字节比对**抓住 —— 闭环 |
| 不提供规避路径 | 三条物理事实改不了：主 ABI、native bridge / houdini、进程 `Seccomp`。改了就不能执行 |
| 不做"隐藏 root"评估 | 8 层检测 × 隐藏能力矩阵是死结，见 `apk-reverse-master` 的同类结论 |

本 skill 的产出是**清单、归属、基线**三样东西，用途是回答"我的观测行为会不会进视野"和"这条结论到底属于哪个库"。

## When to Use

- 要判断"抓包 / 装 App / 只读日志"这些**被动动作**会不会被反作弊看到。
- 手上只有一个 `logcat.txt`，想知道 App 到底探测了哪些路径（不需要 root、不需要注入）。
- 拿到一堆 `.so`，要区分"谁真的在检测"和"谁只是被链进来的依赖"。
- 发现一个可疑字符串（`test-keys` / `magisk` / `frida`），要确认它属于谁。
- 有一份 pcap，要回答"战斗面是什么协议 / tick rate 多少 / 有没有固定 stride 的记录数组"。
- 要选一台设备做观测，需要先确认它自身没有一堆破绽（否则测的是"设备被发现"而不是"观测被发现"）。

## Quick Start

```bash
S=<skill>/scripts

# ① 被动采集：整套探测清单（只要 logcat，不需要 root、不注入、不改设备）
adb logcat -b all > logcat.txt
python $S/probe_inventory.py --logcat logcat.txt --json inv.json --out INVENTORY.md

# ② 设备结构面门禁：13 类硬阻断 + 清单逐条可达性判定，退出码 1 = NO-GO
python $S/ace_gate.py --serial <设备> --inventory inv.json --json g.json --out GATE.md
python $S/ace_gate.py --serial <设备> --diff g_old.json      # 与基线对比，看改了什么

# ③ 环境一致性探针（10 项破绽，可与基线 diff）
python $S/env_probe.py --serial 127.0.0.1:7555 --json base.json
python $S/env_probe.py --serial <设备> --diff base.json

# ④ 静态：库里有哪些检测能力 / 特征串（附上下文）
python $S/ace_scan.py libtersafe.so libtprt.so libturinggame.so --json ace.json

# ⑤ 静态：从大 .so 里抽网络常量（比 strings|grep 快一个量级，能跨 4KB 边界）
python $S/so_scan.py libUE4.so --top 200 --json so.json

# ⑥ 流量：pcap/pcapng → 域名 / SNI / Host / 端点排名 / QUIC
python $S/pcap_analyze.py capture.pcap --json net.json

# ⑦ 流量：UDP 流四问（流数 / tick rate / 载荷长度分布 / 是否加密）
python $S/udp_flow.py capture.pcap --json udp.json

# ⑧ 流量：从下行快照里找"固定 stride 记录数组"和"浮点列"
python $S/snapshot_miner.py capture.pcap --json snap.json

# ⑨ 会话时间线（把 logcat + 截图 + 状态采样打成一条时间轴，事后能对账）
python $S/session_recorder.py watch  --session s1 --duration 900
python $S/session_recorder.py report --session s1
```

`udp_flow.py` / `snapshot_miner.py` 复用 `pcap_analyze.py` 的 `read_pcap` / `strip_l2` / `parse_ipv4` / `parse_l4`，
三者必须放在同一个 `scripts/` 目录下。

## 典型工作流

1. **先判这条路值不值得走**。看两个数字：这个库有没有 `ptrace` / `inotify` / `process_vm_readv`，
   以及它的路径串是不是明文。`ace_scan.py` 的第一节直接给答案。
   - 路径串命中 ≤1 条 → **静态拿不到清单，直接转运行时**（不要花时间逆字符串解密）。
2. **被动采集清单**。`adb logcat -b all`（自带历史缓冲，抓晚了也能捞回来），
   过滤 `app=<包名>` 且含 `avc:  denied`，交给 `probe_inventory.py` 去重归一化。
   - 关键前提：设备 SELinux 是 **Permissive**。Enforcing 下这些 `denied` 不会写进 logcat。
   - 去重是必须的：同一事件会被 `auditd` 和 `init` 各打一遍，直接 `grep -c` 数字翻倍。
3. **给清单分类**，见 `references/probe_taxonomy.md` 的三类模型。
   分类决定结论强度：`getattr`（只 stat）和 `open`/`read`/`map`（真读到内容）不是一回事，
   混着数会得出"它有 64 项检测能力"这种错结论（真实是 8 项）。
4. **每条字符串都要定归属**。这一步跳过就会重演本项目最大的错：
   7 个库里 4 个判错（阿里 MNN 被当成硬件画像库、TapTap SDK 被当成 ACE 加密核心）。
   硬判据和假阳性清理见 `references/attribution_rules.md`。
5. **门禁 + 基线**。`ace_gate.py` 输出 PASS/FAIL 与退出码，`--json` 存基线，`--diff` 看变化。
   门禁不是"通过了就能规避"，而是**保证对照组干净**：没有它，
   "观测是否安全"和"设备是否干净"两件事会混在一起，两组结论同时失真。

## 三类探针模型（本 skill 的核心判据）

| 类型 | 系统调用形态 | 清单里的例子 | 抗伪装强度 |
|---|---|---|---|
| **存在性探测** | `getattr` | `/data/adb`、`/dev/vga_arbiter`、`/proc/kallsyms` | 弱：目标在不在是客观事实，改它要动文件系统 |
| **能力探针** | `open` / `read` / `map` / `execmod` | `/proc/iomem` 读到内容、`/dev/ashmem` 打开成功、属性区 mmap 成功 | **强**：只能让"本该成功的失败"，即 hook，而 hook 自身可被字节比对 |
| **无文件对象** | netlink / 纯 syscall | `nlmsg_readpriv`（枚举虚拟网卡） | **强**：没有路径，不在文件表里，删无可删 |

**强抗伪装的意思是：对防守方更硬，对任何试图隐藏的人更绝望。** 这也是为什么"环境检测的主战场是你还能做什么"。

## 三个漏项：为什么清单永远不是全集

| 漏什么 | 原因 | 后果 |
|---|---|---|
| 策略**允许**的访问 | 不产生 avc 记录 | `/proc/cpuinfo`、sysfs、读属性（走 socket）、`pm list packages` 全都不在表里 |
| **别的域代劳** | 审计按 `scontext` 归因 | 通过 binder 让系统服务代读，记的是服务的域，不是 `app=` |
| **无文件对象** | 没有 `path=` | 只能靠 `tclass` 认出来 |

所以 `probe_inventory.py` 的 64 项是**文件面子集**。属性面 / 包面 / CPU 面必须另外补——
`ace_gate.py` 里那 13 条硬阻断，有一半是手工从这个缺口补出来的。

还有个**反向偏差**：permissive 不只"记录了本应被拒的访问"，它还**让探测继续往下走**。
真机上 `open("/proc/iomem")` 被拒后程序可能就此打住；permissive 下它拿到 fd 会继续读、继续进深分支。
所以这 64 项对"它查过什么"是**可靠下界**，对"它总共查什么"不是全集。

## Reference

- `references/probe_taxonomy.md` —— 三类探针的完整判据、64 项实测清单快照（四分类）、
  13 条硬阻断的分层（L1 DAC / L2 SELinux / L3 syscall 不可判）、以及每条为什么"能判 / 不能判"。
- `references/attribution_rules.md` —— 库与字符串的**归属硬判据**（JNI 命名空间 / CI 构建路径 /
  Itanium mangled / DEX 类描述符）、7 库 4 错的完整案例、五类假阳性（`clone` / `proxy` / `GOT` /
  `parallel` / X.509 扩展名）。**判归属必读。**
- `references/pcap_protocol_mining.md` —— pcapng 结构、`strip_l2` 的 linktype 表、UDP 流四问、
  快照结构挖掘三步法（列方差 / 自相关 / 浮点列筛选）、ACE 20 字节封装层的定界规则、
  以及"熵高 ≠ 加密"的误判模式。

## Notes

- **纯标准库**：不需要 `scapy` / `tcpdump` / `frida` / `jadx`，Python 3.8+ 即可。
  `ace_gate.py` / `env_probe.py` / `session_recorder.py` 需要 `adb`。
- **`probe_inventory.py` 只读 logcat**，不连设备、不注入、不改任何东西。
- **审计可以信，但归因要小心**：avc 是 LSM 层写的，App 侧无法伪造；
  但 `comm=` 只是线程名，`app=` 才是包名归因，两者都要看。
- **`ace_gate.py` 的退出码就是结论**：0 = 无硬阻断，1 = NO-GO。脚本不带任何修复动作，
  只报告事实——能不能改、改了会崩在哪，属于 `apk-reverse-master` 的决策范围。
- **不要用裸字符串扫描代替归属判定**：本项目三次栽在同一件事上——
  `getRootState` / `magisk` 来自极光推送内嵌的 RootBeer，`test-keys` / `goldfish` 来自 Sentry 与性能监控，
  `frida` 来自极验。全部与目标 App 的反作弊无关。
- **`so_scan.py` 的域名提取走 TLD 白名单**：不加会抓到 `libc.so` 这类文件名。
  关键域名仍要在原始字节里 `count()` 二次确认。
- **`snapshot_miner.py` 只输出统计证据，不猜语义**。它给出"这里可能有 stride=72 的记录数组"，
  至于第 33 字节是蹲还是趴，必须靠外部对照实验（见 `apk-reverse-master` 的动作注入剧本）。

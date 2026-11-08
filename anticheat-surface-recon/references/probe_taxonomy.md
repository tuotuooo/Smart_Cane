# 检测面分类：三类探针 + 一类盲区

> 用途：把一份 avc 审计清单（`probe_inventory.py` 的产出）翻译成**结论强度**。
> 同样是"探测了 64 个路径"，按操作类型分开数，能得出的判断差一个量级。
>
> 实测基线：`com.tencent.tmgp.dfm`，MuMu 模拟器，SELinux=Permissive，20:27–21:12 共 156 条审计。

---

## 一、为什么必须分类

第一版清单只报了"64 项"，读起来像是"它有 64 个检测点"。按操作拆开之后：

| 操作 | 含义 | 条数 |
|---|---|---|
| `getattr` | 只 stat，问"存在吗 / 权限什么" | 56 |
| `open` / `read` / `map` / `execmod` | **真把内容读出来了** | 8 |
| `nlmsg_readpriv`（无 path） | 纯 syscall / netlink | 1 |

**这 8 项才是"能力泄露"，其余 56 项只是"存在性反馈"。** 前者是主战场，后者是噪音——
噪音多不是问题，问题是把噪音当信号去追。

代码里的判据（`ace_gate.py`）：

```python
CONTENT_OPS = {"open", "map", "read", "execmod"}   # 能力
# 其余（getattr / connectto / …）按存在性处理
```

---

## 二、四分类

| 类 | 系统调用形态 | 判据 | 抗伪装强度 | 例 |
|---|---|---|---|---|
| **A 能力探针** | `open`/`read`/`map`/`execmod` **成功** | 操作 ∈ `CONTENT_OPS` | **强** | `/proc/iomem` 读到内容、属性区 `mmap` 成功、`libhoudini.so` `execmod` |
| **B 存在性探测** | `getattr`（或 `connectto`） | 操作 ∉ `CONTENT_OPS` | 弱 | `/data/adb`、`/dev/vga_arbiter`、`/proc/kallsyms` |
| **C 无文件对象** | netlink / 纯 syscall | 无 `path=`，只有 `tclass` | **强** | `nlmsg_readpriv` |
| **D 审计盲区** | 策略**允许**的访问 / 别的域代读 | 不产生 avc | — | `/proc/cpuinfo`、sysfs、读属性、`pm list packages` |

**"强"是防守方视角**：强 = 这个信号难被抹掉，所以它作为判据更可靠。
反过来说——A 类和 C 类**不存在"藏起来"的路径**，因为它们的语义是"我做到了某件不该做到的事"，
而不是"我这里有个文件"。

- A 类要让它失败，只能 hook `open()` 的返回值；而 hook 自身会被库里的
  `inline_hook_opcode_dismatch` / `ms_hook_opcode` / `g_tprt_ori_array` 原始函数指针比对抓住 → 闭环。
- C 类连路径都没有，删除、改名、挂载遮蔽全部无效。

---

## 三、A 类：8 项能力探针（逐条）

| # | 路径 | 操作 | 首次 | 泄露什么 |
|---|---|---|---|---|
| 1 | `/system/lib64/libhoudini.so` | execmod | 20:27:01.656 | x86 转译层实体存在且可执行（ARM 真机无此文件） |
| 2 | `/proc/iomem` | getattr, open | 20:27:12.880 | **物理内存布局**（DMA 外挂的前置条件） |
| 3 | `/proc/misc` | getattr, open | 20:27:12.880 | misc 设备全表（含 QEMU 专有节点） |
| 4 | `/` | read | 20:27:16.788 | 根目录可读（容器/模拟器常见） |
| 5 | `/dev` | open | 20:27:16.788 | 设备节点全枚举 |
| 6 | `/dev/ashmem` | open | 20:27:46.828 | 匿名共享内存可开（注入常用载体） |
| 7 | `/dev/__properties__/…:aac_drc_prop:s0` | getattr, map, open | 20:27:46.900 | **属性数据区 mmap 成功** = 可绕过 property_service 直读全部属性 |
| 8 | `/dev/__properties__/…:ab_update_gki_prop:s0` | open | 20:27:46.900 | 同上 |

第 7 项最值钱：`/dev/__properties__/` 是 `0444`，但 `untrusted_app` 不应能 `open`/`mmap`
（SELinux `property_data_file` 拒绝）。**能 mmap 就意味着所有 `getprop` 都能被绕过**，
包括那些只在属性里写、不走 property_service 的判据。

---

## 四、B 类：56 项存在性探测（按语义分组）

`/dev/tty<N>` 循环枚举已合并为 1 项（实测 9 个）、`/dev/vcsu<N>` 合并 1 项。

| 语义组 | n | 路径 |
|---|---|---|
| root 残留 | 1 | `/data/adb` |
| 虚拟化 / 模拟器 | 5 | `/dev/tty<N>`、`/dev/vga_arbiter`、`/dev/ttyS1`、`/dev/ttyS2`、`/dev/ttyS3` |
| 内核信息面 | 14 | `/proc/{keys,kmsg,locks,swaps,cgroups,cmdline,modules,kallsyms,config.gz,bootconfig,kpageflags,timer_list,pagetypeinfo,sysrq-trigger}` |
| 系统指纹 | 7 | `/proc/{uptime,vmstat,loadavg,buddyinfo,slabinfo,softirqs,zoneinfo}` |
| 设备枚举 | 21 | `/dev/{socket/property_service,binderfs/vndbinder,event-log-tags,fscklogs,vcs,uhid,loop-control,rtc0,cpu_dma_latency,fuse,rfkill,port,vcsu<N>,console,userfaultfd,hpet,uinput,block,input,kmsg,dm-user}` |
| 属性区 | 8 | `/dev/__properties__/…:{virtualizationservice,vold_post_fs_data,wifi_config,wifi_hal,wifi,zram_config,zram_control,virtual_fingerprint}_prop:s0` |

**别看语义组成，看语义组背后的意图**。这张表最有信息量的地方是"设备枚举 21 项"——
它不是在找某个特定文件，是在**把 `/dev` 整个摸一遍**，用于拼设备画像。
拼画像是目的，路径是手段，所以删掉其中几个不影响它。

---

## 五、C 类：无文件对象（1 项）

| 操作 | 首次 | 含义 |
|---|---|---|
| `nlmsg_readpriv` | 20:29:48.188 | netlink 读路由/网卡的**特权**信息 → 枚举虚拟网卡 |

这一条在审计里没有 `path=`，只能靠 `tclass` 认。它也是"删不掉"的典型：
没有文件、没有目录，只有一次系统调用。

---

## 六、D 类：审计盲区（清单外的面）

`probe_inventory.py` 拿不到的，必须另补。这是"64 项不是全集"的根因：

| 面 | 为什么不在清单里 | 怎么补 |
|---|---|---|
| **CPU 面** | `/proc/cpuinfo` 对 `untrusted_app` 是可读的 → 不产生 avc | 直接 `grep model name`：出现 `Intel`/`AMD` = 宿主 CPU 直通 |
| **属性面** | 读属性走 socket 到 `property_service`，由服务代读 | `getprop` 抽样 + 与机型档位对照 |
| **包面** | `pm list packages` 由 `system_server` 代读 | 直接列包：`nemu`=网易模拟器、`topjohnwu`=Magisk |
| **时钟面** | `/sys/devices/system/clocksource/*` 只读可读 | `current_clocksource`：`kvm-clock` = 内核自述在 KVM 里 |
| **进程面** | `/proc/<pid>/status` 自己的可读 | `Seccomp: 0` = 无沙箱过滤；`CapEff≠0` = 有 capability |

`ace_gate.py` 的结构判据一半是从这个缺口手工补的，见下一节。

---

## 七、结构面判据（约 20 项，其中 11 项带 ★）

按"能否被改"分三层。**★ = 改了就不能执行**，不是"改起来费劲"：

| 层 | 判据 | 实测取值 | 为什么在这一层 |
|---|---|---|---|
| L1 物理事实 | ★ 主 ABI | `x86_64` / abilist 含 x86 | 真机必 arm64；改它要 resetprop(=root)，而 root 又留下 `/data/adb` |
| L1 | ★ 转译层 native bridge | `ro.dalvik.vm.native.bridge` 非空 | 比 ABI 更硬：`libnb`/`houdini` 存在即说明在跑 x86 翻译 |
| L1 | ★ houdini 库文件 | `/system/lib64/libhoudini.so` 存在 | 转译层实体，真 ARM 机不存在 |
| L1 | ★ CPU 架构事实 | `model name: Intel` | 宿主 CPU 直通；真机只有 `CPU implementer 0x41` |
| L1 | ★ 时钟源 | `kvm-clock` | 内核自述跑在 KVM 里；真机是 `arch_sys_counter` |
| L1 | ★ x86 定时器 | `/dev/hpet` 存在 | HPET 是 x86 高精度定时器，ARM 真机无此节点 |
| L2 文件/策略 | ★ SELinux 强制态 | `Permissive` | 它把整份探测清单的答案翻成"成功"，一条配置错误放大成整类信号 |
| L2 | ★ root 残留 `/data/adb` | 存在 | 目录存在即命中 root 探测，且删它需要 root |
| L2 | ★ 虚拟化 `/dev/vga_arbiter` | 存在 | QEMU 专有节点 |
| L2 | ★ 虚拟化 `/dev/port` | 存在 | x86 I/O 端口设备 |
| L3 包面 | ★ 模拟器/root 包 | `com.nemu.*`、`topjohnwu.magisk` | 包名即自证；删包要挂载 `/system` |
| L3 | QEMU 属性 | `ro.kernel.qemu` 等非空 | 明文属性 |
| L3 | OAID 链路 | 缺 `com.mdid.msa` | 实测上报 `deviceInfo not found:OAID`；`untrusted_app` 不应能 open/mmap |
| 进程面 | 目标进程 Seccomp | `0` | 真机 app 应为 `2`（启用过滤器）；`0` = 无沙箱 |
| 进程面 | 目标进程 SELinux 域 | 非 `untrusted_app` | 域本身可读 |
| 进程面 | 目标进程 CapEff | ≠ 0 | 有 capability = 提权 |
| — | 构建自洽性 | `user`/`release-keys`/`debuggable=0` | 非标准构建 → WARN |
| — | `ro.boot.hardware` / `ro.board.platform` | 需与机型档位自洽 | 量产机正常属性，只做对照 |
| — | `ro.hardware` 形态 | 应填芯片代号（qcom/mt/…）不填厂商名 | 形态判据 |
| — | SDK 一致性 | `ro.build.version.sdk` == `ro.system.build.version.sdk` | 分区不一致 = 拼装镜像 |

**L1 的三条（ABI / native bridge / Seccomp）是死结**：它们不是"某个文件不对"，
而是"这个进程的形态与目标平台不同"。要改就是换设备，不是改配置。

---

## 八、30 条"真机上 untrusted_app 应当读不到"的路径

`ace_gate.py` 的 `SHOULD_BE_DENIED` 表。这不是"检测清单"，是**AOSP 公认预期**——
列出来的每一条，在干净真机上 `untrusted_app` 都拿不到内容。清单里的路径命中这张表的比例，
就是这台设备"额外多泄露了多少"。

| 类别 | 路径 |
|---|---|
| root 痕迹 | `/data/adb` |
| 虚拟化 | `/dev/vga_arbiter`、`/dev/port`、`/dev/vcs`、`/dev/vcsu`、`/dev/ttyS1`、`/dev/ttyS2`、`/dev/console` |
| 物理内存 | `/dev/mem`、`/proc/iomem`、`/proc/kpageflags`、`/proc/pagetypeinfo`、`/proc/buddyinfo`、`/proc/slabinfo` |
| 内核布局 | `/proc/kallsyms`、`/proc/kmsg`、`/proc/modules`、`/proc/timer_list`、`/proc/config.gz`、`/proc/bootconfig`、`/proc/keys`、`/proc/sysrq-trigger` |
| 注入载体 | `/dev/ashmem`、`/dev/userfaultfd`、`/dev/uhid`、`/dev/cpu_dma_latency` |
| 系统服务 | `/dev/socket/property_service`、`/dev/binderfs/vndbinder` |
| 属性数据区 | `/dev/__properties__/*` |

> 注：`/dev/ashmem` 在部分厂商 ROM 上对 `untrusted_app` 是**允许**的（走 `ashmem_device` 标签），
> 命中不等于一定是破绽——但 `open` 成功这一事实本身仍然进可用于设备画像。

---

## 九、口径警告（三条，都会让结论偏）

1. **清单可能比真机更长。** permissive 不只是"记录了本应被拒的访问"，它还**让探测继续往下走**。
   真机上 `open("/proc/iomem")` 被拒后程序可能就此打住；permissive 下它拿到 fd 会继续读、进深分支。
   所以对"它查过什么"是**可靠下界**，对"它总共查什么"不是全集。
2. **别用条数做纵向对比。** 内核会限流 avc，不同 run 的条数不可比；要比就**比集合**（哪些路径出现过）。
3. **归因看 `app=` 不看 `comm=`。** `comm=` 是线程名（本样本里出现过 `encent.tmgp.dfm` 这种被截断的），
   `app=` 才是包名。另外 binder 代读会把归因记到服务进程的域上，那一条根本不会带 `app=`。

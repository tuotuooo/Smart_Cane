---
name: linux-license-recon
description: 当目标不是 APK 而是**原生 Linux 程序 / 服务端授权系统**时使用——桌面软件激活器、License 服务端、离线授权码算法、麒麟/统信等信创软件的 KMS 授权、`.so` 扩展模块（Cython/Boost.Python）、ELF 可执行文件反汇编、容器化授权服务（Flask + DB）、GPG/证书闸门判定、造码器（oracle）搭建、激活码布局反推、返回值与落盘副作用不一致的排查。触发词包括：激活码、注册码、序列号、license、授权、许可证、离线激活、永久激活、造码、算码、校验函数、返回 ret=、kylin_activate、KMS 授权、服务端许可、授权服务器、反汇编 so、ctypes 加载 so、oracle、校验通过但没生效、ret=0 但没激活。本 skill 全部脚本纯标准库（ctypes + argparse），不需要 IDA/Ghidra/radare2。
agent_created: true
---

# Linux License Recon（原生二进制 + 服务端授权逆向）

## Overview

`apk-analyzer` 那一套针对的是「一个自包含的 APK 文件」；**本 skill 针对的是另一种对象边界**：
授权判定分散在 **客户端 ELF（校验器）+ 服务端进程（发码者）+ 数据库（事实源）** 三处，
而且往往还有一层 GPG/证书闸门在旁边干扰判断。

这四种东西的逆向手段完全不同，混着搞就会出现「客户端明明 ret=0，系统却没激活」这类事故。
本 skill 的核心不是"怎么反汇编"，而是**先判断该啃哪一层，以及用什么做判据**。

> 适用：桌面软件/服务端授权系统、离线激活码、License 服务。
> 不适用：Android APK（→ `apk-analyzer`）、纯网页接口（→ `web-js-reverse`）、
> 固件/设备（→ `ble-device-recon`）。

## When to Use

- 拿到一个「激活/注册/授权」黑盒，不知道从客户端还是服务端下手。
- 已经逆到客户端 ret=0，但功能没解锁 / 状态没变 → 判据选错了，见 §判据 4。
- 要造一批合法激活码（测试、批量授权、迁移），需要离线 oracle。
- 授权码格式（分段、后缀、日期段）猜不出来，想从比对点反推。
- `.so` 是 Cython/Boost.Python 编译产物，源码不可读，只能靠 `dir()`/`inspect` + ctypes 探。
- 碰到 GPG 签名、证书、加密 LICENSE BLOCK，判断它到底在不在关键路径上。

## 五条判据（先看这个）

1. **服务端优先于客户端。** 授权系统里客户端只是**校验器**，事实源在服务端（明文脚本 / DB / 接口）。
   优先级：**服务端明文源码 > 字节码或 Cython 扩展 > 客户端 ELF 反汇编**。
   K-KMS 实测：容器里 `daemon.py` 是明文 Python，直接读到关联字段与校验函数行号，
   省掉整条客户端反汇编路线。（详见 `references/license_system_map.md` §1）

2. **不重写算法，直接调用真实函数。** 造码器/穷举器不要"照着算法再实现一遍"——
   用 `ctypes` 把真实 `.so` 加载进来，把真实校验函数包成**离线 oracle**，让它自己判对错。
   重写等于引入第二份语义，错了你永远不知道是算法错还是实现错。
   → `scripts/oracle_harness.py --lib x.so --func validate --args c_char_p,c_char_p,c_char_p,c_char_p`

3. **码结构从「比对点」反推，不从算法反推。** 找 `strncmp` / `memcmp` / `substr` 比较的
   偏移与长度（如 `strncmp(a, b, 14)` + `strncmp(a+18, b+18, 2)`），一次就能得到
   整条码的字段布局；逐字节啃编码算法通常是十倍工作量且更易错。
   **日期段常常只用于展示，不参与比对**——别为它卡住。

4. **返回值 ≠ 效果。** 唯一可信的判据是**落盘/持久化的副作用**：写进去的文件内容、DB 行、
   服务端返回的授权池结构。原因：① 实现里常有"escape 旁路"直接 `return 0`；
   ② `LD_PRELOAD` hook 截断 `save` 会让"业务成功 → 落盘失败 → 返回错误码"；
   ③ 返回值类型被注释搞反（1 才是有效）。
   判据：`ret=0` 之后**必须核对落盘文件内容**，而不是打印"激活成功"。

5. **环境会骗你：以目标机为权威。** 单例缓存（`_instance`/`manager`）、进程内缓存（DB 改了要重启）、
   hook 残留（摘掉再跑）、PIE/ASLR 导致本地与目标机地址布局不一致（本地 RE 只作辅助）、
   IP 漂移（靶机重启换地址）。**任何"本地推出来的地址"在目标机上都要重新确认。**

## 决策树

```
一个"授权/激活"黑盒
├─ 服务端在本机可达？（进程 / docker / 端口 / DB）
│   └─ 是 → 直接读服务端源码 + DB 结构，先把「数据模型」画出来
│            （谁存 license、父子/归属字段是什么、发码入口在哪）
│            ↳ 90% 的判定逻辑在这一步就清楚了，不用碰二进制
├─ 关键逻辑在 .so / 字节码扩展里？
│   └─ 是 → dir() / inspect.signature() 摸签名 → ctypes 加载 → 建 oracle（判据 2）
├─ 只有客户端 ELF？
│   └─ 是 → 找校验入口：错误码字符串、返回路径、算法常量 → 反汇编 → 造码或打补丁
└─ 还有 GPG / 证书 / 加密 LICENSE BLOCK？
    └─ 先判它是否在关键路径上（多半不在）→ 用「绕过它是否仍能达成目标」来证伪
```

## Quick Start

```bash
# 1) 摸服务端：容器/进程/端口/DB（先把数据模型画出来）
docker ps --format "{{.Names}} | {{.Status}}"
ss -tlnp | head

# 2) 摸 .so 扩展的真实签名（Cython 产物只能靠运行时探）
python -c "import sys; sys.path.insert(0,'/usr/share/xxx'); import core; print(dir(core))"

# 3) 把真实校验函数包成离线 oracle，反复调用
python scripts/oracle_harness.py --lib /usr/lib/liblicense.so --func validate \
       --args c_char_p,c_char_p,c_char_p,c_char_p --call "AA:BB:CC:DD:EE:FF,200017888,CODE,02" \
       --expect 1 --repeat 3

# 4) 判定"到底生效没有"——看落盘，不看返回值
cat /etc/.kyactivation; ls -la /etc/.kyactivation*

# 5) 探数据段里的字典表（算法依赖的编码表通常躺在 .bss/.rodata 固定偏移）
objdump -h target.so | grep -E "rodata|bss"
```

## 硬前置

- Python 3.8+（`ctypes` 标准库，无需第三方）
- 目标 `.so` 与目标机架构一致（跨架构请直接在目标机上跑）
- 反汇编用目标机自带的 `objdump`/`nm`（本地没有 binutils 就别硬装，见 `references/pitfalls.md` 坑 7）

## 文档索引

- `references/license_system_map.md` — 授权系统对象地图：三层优先级、oracle 化方法、比对点反推、字典表提取、副作用判据
- `references/pitfalls.md` — 8 个实测坑（返回值骗人、hook 残留、缓存、PIE 布局、日期多对一、占位名误导…）
- `references/case_kms_kylin.md` — 完整案例：麒麟 KMS 厂商授权，从"以为做不到"到 `ret=0 永久激活`，含被推翻的三个结论
- 沉淀规范不在此处维护——见 `reverse-sediment/references/writing_rules.md`（四卡点：置信度 / 可复现 / 冲突 / 推翻记录）

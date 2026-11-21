# 案例：麒麟 KMS 厂商授权（原生客户端 + 服务端许可服务）

> **范围声明**：本案例来自**自有测试环境**（本地虚拟机 + 自建 docker 服务端）的安全研究，
> 仅用于演示方法论。文中不含可直接复用的造码实现——**方法留下，配方不带走**。
> 关联：`license_system_map.md`（方法）、`pitfalls.md`（坑）

---

## 一、这个案例为什么值得放进矩阵

它同时踩中了本 skill 的全部五条判据，而且**三次误判都是"看起来很合理的推理"**——
正好用来验证 `reverse-sediment` 的四卡点不是空话。

对象边界：`客户端 ELF（kylin_activate）` + `服务端许可服务（Python daemon + Cython .so + MariaDB）`
+ `上游签名/证书（GPG）`。这是 Android/Web/BLE 三件套完全覆盖不到的一类。

---

## 二、起点：三个"看起来已经确定"的结论（全部被推翻）

| # | 当初的结论 | 为什么错 | 怎么推翻的 |
|---|---|---|---|
| 1 | 厂商级「永久激活」**客户端无法自造**，必须依赖服务端/厂商签发 | 把"需要厂商 GPG 私钥"当成了必要条件 | 画出 CLI 激活链后发现 GPG 闸门在 **worker 线程**，不在激活链上（判据 5：闸门存在 ≠ 闸门在路径上） |
| 2 | 某序列号**因为在首位**才激活成功 | 把"列表顺序"与"可行性"混为一谈 | 换一个完全无关的随机纯数字序列号，同样 `ret=0`（**对照实验**：证明位置无关） |
| 3 | 校验函数返回 **0 = 有效** | 早期笔记把语义记反了 | 用已知有效码 vs 明显无效码各跑一次（坑 1） |

> 这三条如果按 `reverse-sediment` 的四卡点标注，都过不了「可复现」+「冲突」两关：
> 没有一条能附上"换个输入仍然成立"的命令。

---

## 三、五条判据各自在案例里的落点

| 判据 | 案例中的具体形态 |
|---|---|
| **1 服务端优先** | 容器内 `daemon.py` 是明文 Python：父子归属字段（pipe 分隔）、发码入口、`f_platform` 标量、错误码分支全部可读。**客户端反汇编两周 → 服务端读源码两小时** |
| **2 oracle 化** | 造码器不重写算法，而是 `ctypes` 加载真实 `.so`，调用真实校验函数判对错；`--validate` 返回 1 才算合法 |
| **3 比对点反推** | 校验实体的骨架是 `strncmp(code, gen, 14)` + `strncmp(code+18, gen_suffix, 2)` → 直接得到 `[0:14 主体][14:18 日期][18:20 后缀]` 的布局，**日期段不参与比对** |
| **4 副作用判据** | `ret=0` 之后必须 `cat /etc/.kyactivation` 看码原文；escape 旁路只写 `.place` 文件（坑 2）。另外 `LD_PRELOAD` 截断 save 会让业务成功、返回 13（坑 3） |
| **5 以目标机为权威** | 本地 `capstone` 对 `.so` 反汇编（VA == 文件偏移）只用于理解逻辑；`kylin_activate` 是 PIE，段布局与本地不一致，**地址一律以目标机 `objdump` 为准**（坑 5） |

---

## 四、结构结论（可复用的认知模型）

授权体系是**两层身份 + 平级兄弟**，不是三层树：

```
第 1 层：Gxxxxx（厂商 license 身份，G 开头）
         · 上游签发，存于加密 cert；本地 DB / Redis / 接口全程不可见
         · 不参与客户端激活（含字母，客户端格式门直接挡掉）
         · 作用是「跨架构的逻辑分组壳」
            ↓  派生（DB 里用 pipe 分隔的归属字段表达）
第 2 层：纯数字服务序列号（2000xxxxx / 99000xxx …）
         · 彼此平级兄弟，各自绑单一架构（x86 / arm / mips）
         · 客户端激活的驱动者：纯数字 serial + 算法匹配码
```

**两个通用教训：**

1. **"1 个标识 = 1 个属性"的标量字段，是跨维度需求的原生短板。**
   服务端每条序列号只有一个 `f_platform`，想表达"一个逻辑授权覆盖多架构"，
   原生模型做不到 → 于是引入一个上层壳做分组。**看到"为什么要有这么一层"时，
   先去找哪个字段是标量**（`daemon.py` 里 `serial_row.f_platform` 的读取与排序）。
2. **字段名不可信。** `f_activate_for` 名字像"激活对象"，实际是**父子归属字段**（子序列号列表）；
   `f_type=1/2` 看着像层级，实际只是内部记账标记。→ 判据：读**谁在用它**（`grep -n` 到调用点），
   不看名字。

---

## 五、可复现的最小验证集（脱敏）

```bash
# 1) 服务端数据模型（归属字段是什么）
docker exec <db> mariadb -u<u> -p<p> <schema> -e "DESCRIBE serial;"
# 2) 归属关系枚举（谁是谁的 child）
docker exec <db> mariadb -u<u> -p<p> <schema> -e \
  "SELECT p.f_serial, c.f_serial, c.f_platform FROM serial p
   JOIN serial c ON p.f_activate_for LIKE CONCAT('%', c.f_serial, '%') WHERE p.f_type=1;"
# 3) 校验函数语义（1 还是 0 才有效）
python scripts/oracle_harness.py --lib <lib>.so --func <validate> \
  --args c_char_p,c_char_p,c_char_p,c_char_p --call "<hw>,<serial>,<code>,<pt>" --repeat 3
# 4) 生效判据（落盘内容，不是返回值）
cat /etc/.kyactivation; ls -la /etc/.kyactivation*
```

---

## 六、这条线里"逆不出来"的部分（诚实边界）

| 目标 | 为什么做不到 | 替代路径 |
|---|---|---|
| 解 LICENSE BLOCK 加密体 | 外部密钥/私钥不在客户端 | 读**明文头**（serial / 模式 / 额度 / 产品型）就够用（`license_system_map.md` §8） |
| 伪造厂商 GPG 签名 | 无私钥 | 先判闸门是否在关键路径（案例里不在） |
| 拿到厂商真实身份 ↔ 序列号绑定 | 只在上游 | 走**厂商一手资料**路线（发行版 src.rpm / 官方文档 / 错误码表），三条交叉验证 |

> 最后一条是 `apk-reverse-master/references/vendor_hunting.md` 的同类方法：
> 二进制里逆不出来的东西，厂商的打包产物里往往就有。

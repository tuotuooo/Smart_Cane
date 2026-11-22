# 靶机接入：VMware 虚拟机 + SSH（授权逆向的硬前置）

> 适用：目标跑在本地 VMware/VirtualBox 虚拟机里（Linux 服务端 + docker），宿主机是 Windows。
> **不适用**：Android 模拟器（→ `android-emulator-adb`）、云主机/物理机（直接 SSH 即可，没有"VM 没开机"这一层）。
> 关联：`license_system_map.md`（决策树第一步就依赖本文）、`pitfalls.md`

---

## 一、先记住这几句

1. **"连不上"先分三层：VM 没开机 / IP 漂了 / SSH 拒了。** 顺序排查，不要跳层——
   全段 ping 只剩网关存活 = VM 关机/挂起，**不是**服务端进程挂了。
2. **IP 会漂移，永远不要硬编码。** DHCP 重启后 132 → 133 是常态；探测要"轮询候选 + 全段扫描"双兜底。
3. **先看宿主机网卡确定网段，再扫。** VMnet1（host-only）和 VMnet8（NAT）是两个不同网段，
   桥接则挂在物理网段上——扫错网段等于全白扫。
4. **判断依据以文档为准，不猜。** "测试机没有 X"这类结论，先核对环境记录再下——
   实测中"以为靶机没起服务"实为 VM 整个挂起，与容器无关。

---

## 二、现象 → 判读表

| 现象 | 判读 | 动作 |
|---|---|---|
| ping 全网段只有网关 `.1` 存活 | VM 关机/挂起（**不是**服务挂了） | `vmrun list` → `vmrun start <vmx> nogui` |
| VM 运行但原 IP 连不上 | DHCP 漂移 | ping sweep 重定位（§四） |
| ping 通但 SSH 拒绝/超时 | 端口非 22 或密钥不匹配 | 试 22/2222，`BatchMode=yes` 快速失败 |
| 宿主机查不到 VMnet1/VMnet8 | VM 桥接到物理网卡 | 扫宿主机所在物理网段 |
| `vmrun list` 显示 running 但 ping 不通 | 刚开机还没拿到 IP | 轮询等待（见脚本循环） |

---

## 三、定位与启动 VM

```powershell
# 1) 找 vmrun（不在 PATH 时在安装目录）
Get-ChildItem "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

# 2) 看哪些 VM 在跑 / 全部关机
& "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" list

# 3) 找 .vmx（VM 配置文件，路径即 VM 身份）
Get-ChildItem "$env:USERPROFILE\Documents\Virtual Machines" -Recurse -Filter *.vmx
```

```bash
# 4) 读 .vmx 判网段与归属（hostonly = VMnet1，nat = VMnet8）
grep -iE "displayName|ethernet0.connectionType|guestOS" "<路径>/Ubuntu.vmx"
```

**判据**：`connectionType = hostonly` 且 `guestOS = ubuntu-64` → 这就是要找的 Linux 服务端靶机；
同目录下其余 `nat` 的 VM 是别的用途，别启动错。

```bash
# 5) 无界面启动（nogui 不弹窗口；关机状态的 VM 这一步才需要）
"/c/Program Files (x86)/VMware/VMware Workstation/vmrun.exe" start "<路径>/Ubuntu.vmx" nogui
```

---

## 四、重定位 IP（DHCP 漂移兜底）

```bash
# 先枚举宿主机网段，确定该扫哪几个
ipconfig | grep -iE "adapter|IPv4"        # VMnet1=192.168.139.x host-only / VMnet8=192.168.142.x NAT

# 并发 ping sweep（快速失败，-w 短超时）
> /tmp/live.txt
for i in $(seq 1 254); do
  ( ping -n 1 -w 300 192.168.139.$i >/dev/null 2>&1 && echo "192.168.139.$i" >> /tmp/live.txt ) &
done
wait

# 对存活主机逐个试 SSH（密钥认证、禁交互、短超时）
for ip in $(cat /tmp/live.txt); do
  ssh -i ~/.ssh/<key> -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=yes root@$ip "echo SSHOK" && break
done
```

**启动后的等待循环**（VM 开机到 SSH 就绪要一两分钟）：

```bash
OK=""
for t in $(seq 1 24); do
  sleep 5
  for ip in 192.168.139.132 192.168.139.133 192.168.139.134; do
    ssh -i ~/.ssh/<key> -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes root@$ip "echo SSHOK" 2>/dev/null && { OK=$ip; break 2; }
  done
done
# 兜底：候选全失败 → 回到 ping sweep 全段扫
```

---

## 五、连上之后的第一件事

```bash
# 1) 确认这是不是目标机（别在错的 VM 上干活）
hostname; cat /etc/os-release | head -2; docker ps --format "{{.Names}} | {{.Status}}"

# 2) 记录本次 IP 与容器状态（IP 漂移会污染后续记录，先钉死）
hostname -I
```

**纪律**：把"本次会话的 IP、密钥路径、容器清单"写进项目环境文档（environment 类），
下个会话直接读它，不要凭记忆——**IP 漂移后旧记录里的 IP 不再可信，但"哪些容器在跑"仍然可信。**

---

## 六、与授权逆向的衔接

靶机在线只是入场券。进入 `license_system_map.md` 决策树第一步
（"服务端在本机可达？"）后，按顺序拿三样东西：

1. **docker 容器清单**（哪个是许可服务、哪个是 DB）
2. **DB 凭据**（容器 env：`docker inspect <db> | grep -iE "MYSQL_.*PASSWORD|DATABASE"`）
3. **DB 客户端真实名字**（MariaDB 容器里叫 `mariadb` 不是 `mysql`——名字不对会白排查一轮）

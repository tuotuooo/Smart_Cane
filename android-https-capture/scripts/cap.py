#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cap.py - Android HTTPS 抓包主控（mitmproxy + 系统级 CA + adb reverse）

子命令:
    info        设备画像 + 判定该走哪条证书路
    ca          生成/复用 mitmproxy CA，算出 subject_hash_old 文件名
    install     把 CA 注入系统证书区（APEX bind 或 /system 落盘）
    uninstall   卸载证书
    proxy       on / off / status   （adb reverse + http_proxy）
    run         启动 mitmdump 抓包
    stop        停掉 daemon 模式启动的 mitmdump
    dump        解析 flows.mitm（总览 / 详情 / 导出 markdown）

设计原则:
  1. 所有 adb 调用走 subprocess 列表形式，不经 Git Bash —— 彻底躲开 MSYS 路径转换。
  2. 设备侧命令统一走 sh() / shu()，su 的参数用 shlex.quote 包好再拼。
  3. 证书方案不猜，先探测（root / magisk / apex / /system 写探针）再选。
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_CONFDIR = Path.home() / ".workbuddy" / "capture-mitm"
DEFAULT_PORT = 8080
PKG_CACHE = Path.home() / ".workbuddy" / "capture-mitm" / "last_pkg.txt"

# ---------------------------------------------------------------- adb 定位

ADB_FIXED = [
    r"C:\leidian\LDPlayer14\adb.exe",
    r"C:\leidian\LDPlayer9\adb.exe",
    r"C:\LDPlayer\LDPlayer14\adb.exe",
    r"C:\LDPlayer\LDPlayer9\adb.exe",
    r"C:\Program Files\Nox\bin\adb.exe",
    r"C:\Program Files\BlueStacks_nxt\HD-Adb.exe",
    "/Applications/Android/sdk/platform-tools/adb",
    "/usr/local/bin/adb",
    "/usr/bin/adb",
]
ADB_GLOBS = [
    r"C:\leidian\*\adb.exe",
    r"C:\LDPlayer\*\adb.exe",
    r"C:\Program Files\Nox\bin\adb.exe",
]
if os.environ.get("LOCALAPPDATA"):
    ADB_FIXED.append(os.path.join(os.environ["LOCALAPPDATA"], "Android", "Sdk",
                                  "platform-tools", "adb.exe"))
if os.environ.get("ANDROID_HOME"):
    ADB_FIXED.append(os.path.join(os.environ["ANDROID_HOME"], "platform-tools",
                                  "adb.exe" if os.name == "nt" else "adb"))


def find_adb(explicit=None):
    if explicit:
        if not Path(explicit).exists() and not shutil.which(explicit):
            sys.exit("找不到 adb: %s" % explicit)
        return explicit
    for name in ("adb", "adb.exe"):
        w = shutil.which(name)
        if w:
            return w
    for p in ADB_FIXED:
        if Path(p).exists():
            return p
    import glob as _glob
    for g in ADB_GLOBS:
        hits = _glob.glob(g)
        if hits:
            return hits[0]
    sys.exit("找不到 adb。用 --adb 指定，或先装 platform-tools。")


ADB = None
SERIAL = None
VERBOSE = False


def _run(cmd, timeout=90):
    if VERBOSE:
        print("  $ " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss" % timeout
    return p.returncode, p.stdout or "", p.stderr or ""


def adb(args, timeout=90):
    cmd = [ADB]
    if SERIAL:
        cmd += ["-s", SERIAL]
    cmd += args
    return _run(cmd, timeout)


def sh(cmd, timeout=90):
    """设备侧普通 shell。cmd 里可以有空格/分号 —— adb 会拼成一行交给设备 sh。"""
    return adb(["shell", cmd], timeout)


def shu(cmd, timeout=90):
    """设备侧 root shell。su -c 只吃一个参数，所以整体 quote。"""
    return adb(["shell", "su -c " + shlex.quote(cmd)], timeout)


def out_of(res):
    return (res[1] or "").strip()


# ---------------------------------------------------------------- 设备探测

def pick_serial(explicit=None):
    global SERIAL
    if explicit:
        SERIAL = explicit
        return explicit
    rc, so, se = adb(["devices"])
    devs = [l.split("\t")[0].strip() for l in so.splitlines()
            if "\tdevice" in l]
    if not devs:
        sys.exit("没有已连接设备。先 `adb connect <ip:port>`（或用 android-emulator-adb 技能）。")
    SERIAL = devs[0]
    if len(devs) > 1:
        print("[!] 检测到 %d 台设备，默认用 %s（可用 --serial 指定）" % (len(devs), SERIAL))
    return SERIAL


def dev_info(explicit_pkg=None):
    keys = ["ro.build.version.sdk", "ro.build.version.release",
            "ro.product.cpu.abi", "ro.product.model", "ro.build.type",
            "ro.debuggable", "ro.build.tags", "ro.product.manufacturer"]
    cmd = "; ".join("echo '%s='$(getprop %s)" % (k, k) for k in keys)
    rc, so, se = sh(cmd)
    props = {}
    for line in so.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()

    info = {"props": props}
    info["sdk"] = int(props.get("ro.build.version.sdk") or 0)

    # root
    rc, so, se = shu("id")
    info["root"] = ("uid=0" in so)
    info["root_err"] = se.strip()[:120] if not info["root"] else ""

    # magisk
    info["magisk"] = False
    if info["root"]:
        rc, so, se = shu("command -v magisk >/dev/null 2>&1 && magisk -V || true")
        v = out_of((rc, so, se))
        if v and re.match(r"^\d", v):
            info["magisk"] = True
            info["magisk_ver"] = v.splitlines()[0]

    # APEX cacerts
    info["apex_dir"] = None
    info["apex_mounted"] = False
    for d in ("/apex/com.android.conscrypt/cacerts",
              "/apex/com.android.conscrypt@*/cacerts"):
        rc, so, se = sh("ls -d %s 2>/dev/null | head -1" % d)
        p = out_of((rc, so, se))
        if p:
            info["apex_dir"] = p
            rc, so, se = sh("ls %s | wc -l" % p)
            info["apex_count"] = out_of((rc, so, se))
            # 是否已经被 bind 挂载（多半是上次的 mitm 证书还在）
            rc, so, se = sh("mount 2>/dev/null | grep -c ' %s '" % p)
            info["apex_mounted"] = out_of((rc, so, se)) not in ("0", "")
            break

    # /system 可写探针（不要用 mount 字符串判断！remount 失败信息里没有 read-only）
    info["system_rw"] = False
    info["cacerts_dir"] = None
    rc, so, se = sh("ls -d /system/etc/security/cacerts 2>/dev/null")
    if out_of((rc, so, se)):
        info["cacerts_dir"] = "/system/etc/security/cacerts"
        probe = ("touch /system/etc/security/cacerts/.zz_probe 2>/dev/null && "
                 "rm -f /system/etc/security/cacerts/.zz_probe && echo WRITABLE "
                 "|| echo READONLY")
        rc, so, se = shu(probe)
        info["system_rw"] = ("WRITABLE" in so)

    # 当前前台包名 + targetSdk
    info["pkg"] = None
    info["target_sdk"] = None
    info["pkg_src"] = None
    if explicit_pkg:
        info["pkg"] = explicit_pkg
        info["pkg_src"] = "--pkg"
    if not info["pkg"]:
        rc, so, se = sh("dumpsys window 2>/dev/null | grep -E 'mCurrentFocus|mFocusedApp' | head -2")
        m = re.search(r"([a-zA-Z][\w.]*\.[a-zA-Z][\w.]*)/[\w.$]+", so)
        if m:
            pkg = m.group(1)
            if pkg not in ("android", "com.android.systemui", "com.android.launcher3"):
                info["pkg"] = pkg
                info["pkg_src"] = "前台"
    if not info["pkg"] and PKG_CACHE.exists():
        info["pkg"] = PKG_CACHE.read_text(encoding="utf-8").strip() or None
        info["pkg_src"] = "上次记录"
    if info["pkg"]:
        if info["pkg_src"] == "前台":
            try:
                PKG_CACHE.parent.mkdir(parents=True, exist_ok=True)
                PKG_CACHE.write_text(info["pkg"], encoding="utf-8")
            except Exception:
                pass
        rc, so, se = sh("dumpsys package %s 2>/dev/null | grep -E 'targetSdk' | head -2"
                        % info["pkg"])
        m = re.search(r"targetSdk[=:\s]+(\d+)", so)
        if m:
            info["target_sdk"] = int(m.group(1))
    return info


def decide_plan(info):
    """返回 (方案名, 人话说明, 是否可行)"""
    sdk = info["sdk"]
    if info["target_sdk"] is not None and info["target_sdk"] < 24:
        return ("user_cert",
                "targetSdk=%d < 24，App 仍信任用户 CA。直接把 cert 装到用户证书区即可，"
                "不需要 root。" % info["target_sdk"], True)
    if sdk < 24:
        return ("user_cert", "系统 SDK %d < 24，App 默认信任用户 CA。" % sdk, True)
    if not info["root"]:
        return ("no_root",
                "targetSdk>=24 且无 root：系统证书装不进去。只能改包"
                "（apk-mitm / 加 network_security_config 重签）或用 frida 绕 pinning。", False)
    if info["magisk"]:
        return ("magisk",
                "有 root + Magisk：优先用 Magisk 证书模块（可持久化，重启不丢）。"
                "手头这条路径未实测，见 references/cert_paths.md。", True)
    if info["apex_dir"]:
        return ("apex",
                "有 root 无 Magisk，Android %s (SDK %d)：走 APEX bind mount 到 %s "
                "（当前 %s 个证书）。这是 Android 10+ 动态分区设备唯一实测可行的路。"
                % (info["props"].get("ro.build.version.release"), sdk,
                   info["apex_dir"], info.get("apex_count")), True)
    if info["system_rw"]:
        return ("system", "有 root，/system/etc/security/cacerts 可写，直接落盘。", True)
    return ("system_ro",
            "有 root 但 /system 只读且找不到 APEX cacerts：尝试 remount 或改走 Magisk 模块。",
            False)


def cmd_info(a):
    pick_serial(a.serial)
    info = dev_info(getattr(a, "pkg", None))
    p = info["props"]
    print("=" * 66)
    print("设备: %s  %s" % (p.get("ro.product.manufacturer", ""), p.get("ro.product.model", "")))
    print("系统: Android %s (SDK %d)  %s  build=%s"
          % (p.get("ro.build.version.release"), info["sdk"],
             p.get("ro.product.cpu.abi"), p.get("ro.build.type")))
    print("root: %s%s" % ("可用 (uid=0)" if info["root"] else "不可用",
                          "" if info["root"] else "  " + info["root_err"]))
    if info["root"]:
        print("Magisk: %s" % ("有 " + info.get("magisk_ver", "") if info["magisk"] else "无"))
    apex_line = "不存在"
    if info["apex_dir"]:
        apex_line = "%s (%s 个)" % (info["apex_dir"], info.get("apex_count"))
        if info["apex_mounted"]:
            apex_line += "  ← 已 bind 挂载（多半是上次注入的 mitm CA 还在）"
    print("APEX cacerts: %s" % apex_line)
    print("/system cacerts 可写: %s" % ("是" if info["system_rw"] else "否（动态分区常态）"))
    if info["pkg"]:
        print("目标 App: %s  targetSdk=%s  [来源: %s]"
              % (info["pkg"], info["target_sdk"] if info["target_sdk"] else "未知",
                 info.get("pkg_src")))
    else:
        print("目标 App: 未识别（前台是桌面）。抓某个 App 时用 --pkg <包名> 指定")
    name, why, ok = decide_plan(info)
    print("-" * 66)
    print("→ 方案: %s  [%s]" % (name, "可行" if ok else "需改道"))
    print("  " + why)
    if ok and name in ("apex", "system"):
        print("  下一步: cap.py ca && cap.py install")
    elif ok and name == "user_cert":
        print("  下一步: cap.py ca  然后把 cert 装成用户证书（或仍可走 install）")
    print("=" * 66)
    if a.json:
        print(json.dumps(info, ensure_ascii=False, indent=2, default=str))


# ---------------------------------------------------------------- CA

def find_mitmdump():
    for n in ("mitmdump", "mitmdump.exe"):
        w = shutil.which(n)
        if w:
            return w
    cands = [Path(sys.executable).parent / n for n in ("mitmdump.exe", "mitmdump")]
    try:
        import sysconfig
        sp = Path(sysconfig.get_path("scripts") or "")
        cands += [sp / "mitmdump.exe", sp / "mitmdump"]
    except Exception:
        pass
    for c in cands:
        if c.exists():
            return str(c)
    sys.exit("找不到 mitmdump。装一下: python -m pip install mitmproxy "
             "-i https://mirrors.aliyun.com/pypi/simple/")


def ensure_ca(confdir):
    confdir = Path(confdir)
    confdir.mkdir(parents=True, exist_ok=True)
    pem = confdir / "mitmproxy-ca-cert.pem"
    if pem.exists():
        return pem
    md = find_mitmdump()
    print("[*] 首次运行，生成 mitmproxy CA ...")
    p = subprocess.Popen([md, "--set", "confdir=%s" % confdir, "-p", "0"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            time.sleep(0.25)
            if pem.exists():
                break
        else:
            sys.exit("CA 生成超时")
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:
            p.kill()
    return pem


def subject_hash_old(pem_path):
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(Path(pem_path).read_bytes())
    der = cert.subject.public_bytes()
    d = hashlib.md5(der).digest()
    # Android 要的是 subject_hash_old：取 MD5 前 4 字节并按小端打印
    return "".join("%02x" % b for b in reversed(d[:4]))


def cmd_ca(a):
    confdir = Path(a.confdir)
    pem = ensure_ca(confdir)
    h = subject_hash_old(pem)
    dst = confdir / (h + ".0")
    dst.write_bytes(pem.read_bytes())
    print("CA pem     : %s" % pem)
    print("hash 文件名: %s" % dst.name)
    print("             (subject_hash_old = MD5(DER(subject))[:4] 小端，不是 subject_hash)")
    if a.json:
        print(json.dumps({"pem": str(pem), "hash_name": dst.name}, ensure_ascii=False))


# ---------------------------------------------------------------- 安装 / 卸载

APEX_SRC = "/apex/com.android.conscrypt/cacerts"
STAGE = "/data/local/tmp/mitm_cacerts"


def install_apex(serial, local_cert, apex_dir):
    """先 push，再在设备上一次跑完（umount → 复制原有 → 加新 → chcon → bind）。"""
    rc, so, se = adb(["push", str(local_cert), "/data/local/tmp/mitm_ca.0"])
    if rc != 0:
        sys.exit("push 失败: %s" % se)
    script = """
set -e
SRC=%(src)s
STAGE=%(stage)s
# 1) 先解掉可能存在的旧 bind，否则下面 cp 会把空目录当原件复制（会丢光系统证书）
umount "$SRC" 2>/dev/null || true
rm -rf "$STAGE"
mkdir -p "$STAGE"
# 2) 复制系统原有证书
cp -f "$SRC"/* "$STAGE"/ 2>/dev/null || true
BEFORE=$(ls "$STAGE" | wc -l)
# 3) 放入我们的 CA
cp -f /data/local/tmp/mitm_ca.0 "$STAGE"/%(hash)s.0
# 4) 权限 + SELinux 标签（不打标签 conscrypt 读不到）
chown root:root "$STAGE"/* 2>/dev/null || true
chmod 644 "$STAGE"/*
chcon u:object_r:system_security_cacerts_file:s0 "$STAGE"/* 2>/dev/null || true
# 5) 挂上去
mount --bind "$STAGE" "$SRC"
AFTER=$(ls "$SRC" | wc -l)
echo "BEFORE=$BEFORE AFTER=$AFTER"
""" % {"src": apex_dir, "stage": STAGE, "hash": local_cert.stem}
    rc, so, se = shu(script, timeout=180)
    print(out_of((rc, so, se)) or se.strip()[:400])
    if rc != 0:
        sys.exit("APEX 安装失败（rc=%d）。多半是 SELinux 或 APEX 未可写，详见 references/pitfalls.md" % rc)
    m = re.search(r"AFTER=(\d+)", so)
    if m:
        print("[ok] 系统证书区现在有 %s 个（应比原来多 1）" % m.group(1))


def install_system(serial, local_cert):
    rc, so, se = adb(["push", str(local_cert), "/data/local/tmp/mitm_ca.0"])
    if rc != 0:
        sys.exit("push 失败: %s" % se)
    script = """
mount -o rw,remount /system 2>/dev/null || mount -o rw,remount / 2>/dev/null || true
cp -f /data/local/tmp/mitm_ca.0 /system/etc/security/cacerts/%(hash)s.0
chmod 644 /system/etc/security/cacerts/%(hash)s.0
chown root:root /system/etc/security/cacerts/%(hash)s.0 2>/dev/null || true
chcon u:object_r:system_security_cacerts_file:s0 /system/etc/security/cacerts/%(hash)s.0 2>/dev/null || true
ls /system/etc/security/cacerts/%(hash)s.0 && echo OK
""" % {"hash": local_cert.stem}
    rc, so, se = shu(script, timeout=120)
    print(out_of((rc, so, se)) or se.strip()[:400])
    if "OK" not in so:
        sys.exit("落盘失败：/system 只读且 remount 被拒。改走 APEX 或 Magisk 模块。")


def cmd_install(a):
    pick_serial(a.serial)
    info = dev_info(getattr(a, "pkg", None))
    name, why, ok = decide_plan(info)
    print("[*] 判定方案: %s —— %s" % (name, why))
    if not ok:
        sys.exit("[!] 当前设备无法注入系统证书，见 references/cert_paths.md 的替代路线")

    confdir = Path(a.confdir)
    pem = ensure_ca(confdir)
    h = subject_hash_old(pem)
    local_cert = confdir / (h + ".0")
    local_cert.write_bytes(pem.read_bytes())
    print("[*] CA: %s" % local_cert)

    if name in ("apex", "user_cert"):
        if name == "user_cert" and not info["apex_dir"]:
            print("[!] 目标 App targetSdk<24，用户证书就够；但系统证书更通用，继续按可用的路走")
        if info["apex_dir"]:
            install_apex(a.serial, local_cert, info["apex_dir"])
        elif info["system_rw"]:
            install_system(a.serial, local_cert)
        else:
            sys.exit("[!] 既无 APEX 也不可写 /system")
    elif name == "system":
        install_system(a.serial, local_cert)
    elif name == "magisk":
        print("[!] Magisk 模块路线需手动：把 %s 放到模块的 system/etc/security/cacerts/ 下" % local_cert.name)
        print("    参考 references/cert_paths.md#magisk")

    # 验证：从设备侧读一下
    target = info["apex_dir"] or "/system/etc/security/cacerts"
    rc, so, se = sh("ls %s | grep -c %s" % (target, h))
    print("[%s] 设备端可读到 %s: %s" % ("ok" if out_of((rc, so, se)) == "1" else "!!",
                                       h + ".0", out_of((rc, so, se)) or "0"))


def cmd_uninstall(a):
    pick_serial(a.serial)
    info = dev_info()
    done = False
    for d in filter(None, [info.get("apex_dir"), APEX_SRC]):
        rc, so, se = shu("mount | grep -c ' %s '" % d)
        if out_of((rc, so, se)) not in ("0", ""):
            rc, so, se = shu("umount %s && echo UM" % d)
            print("[ok] 已卸载 %s" % d)
            done = True
            break
    confdir = Path(a.confdir)
    pem = confdir / "mitmproxy-ca-cert.pem"
    if pem.exists():
        h = subject_hash_old(pem)
        shu("rm -f /system/etc/security/cacerts/%s.0 %s/%s.0; rm -rf %s"
            % (h, STAGE, h, STAGE))
        print("[ok] 已清理落盘证书（如果有）")
    if not done:
        print("[i] 没有检测到 APEX bind 挂载，无需卸载")
    rc, so, se = sh("ls /apex/com.android.conscrypt/cacerts 2>/dev/null | wc -l")
    print("[i] 当前系统证书数: %s" % out_of((rc, so, se)))


# ---------------------------------------------------------------- 代理

def cmd_proxy(a):
    pick_serial(a.serial)
    action = a.action
    if action == "status":
        rc, so, se = adb(["reverse", "--list"])
        print("adb reverse: %s" % (out_of((rc, so, se)) or "(空)"))
        rc, so, se = sh("settings get global http_proxy")
        print("http_proxy : %s" % out_of((rc, so, se)))
        return
    if action == "on":
        port = a.port
        adb(["reverse", "tcp:%d" % port, "tcp:%d" % port])
        shu("settings put global http_proxy 127.0.0.1:%d" % port)
        rc, so, se = adb(["reverse", "--list"])
        print("[ok] adb reverse:\n%s" % out_of((rc, so, se)))
        rc, so, se = sh("settings get global http_proxy")
        print("[ok] http_proxy = %s" % out_of((rc, so, se)))
        print()
        print("[!] 重要：如果 App 还没启动，现在启动它。**带代理冷启动可能黑屏**——")
        print("    正确顺序是「先启动 App 到目标页面，再执行本命令」。")
    else:
        shu("settings put global http_proxy :0")
        adb(["reverse", "--remove", "tcp:%d" % a.port])
        rc, so, se = sh("settings get global http_proxy")
        print("[ok] 代理已关闭，http_proxy = %s" % out_of((rc, so, se)))


# ---------------------------------------------------------------- 抓包进程

def cmd_run(a):
    md = find_mitmdump()
    confdir = Path(a.confdir)
    ensure_ca(confdir)
    out = Path(a.out).resolve()
    cmd = [md, "--set", "confdir=%s" % confdir, "-p", str(a.port),
           "--set", "block_global=false", "-w", str(out)]
    if a.filter:
        cmd += ["--set", "view_filter=" + a.filter]
    if a.script:
        for s in ([a.script] if isinstance(a.script, str) else a.script):
            cmd += ["-s", s]
    print("[*] " + " ".join(cmd))
    print("[*] flows -> %s" % out)
    if not a.daemon:
        print("[*] 抓包中... Ctrl-C 结束")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            pass
        return
    log = confdir / "mitmdump.log"
    with open(log, "wb") as lf:
        kw = {}
        if os.name == "nt":
            kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        p = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT, **kw)
    (confdir / "mitmdump.pid").write_text(str(p.pid))
    time.sleep(2)
    print("[ok] daemon pid=%d  log=%s" % (p.pid, log))
    if p.poll() is not None:
        sys.exit("[!] 进程立刻退出了，看日志: %s" % log.read_text(encoding="utf-8", errors="replace")[-800:])


def cmd_stop(a):
    confdir = Path(a.confdir)
    pidf = confdir / "mitmdump.pid"
    if pidf.exists():
        pid = int(pidf.read_text().strip())
        try:
            if os.name == "nt":
                # /T 连子进程一起杀：mitmdump.exe 是个 launcher，真正监听的是它的子进程
                _run(["taskkill", "/PID", str(pid), "/T", "/F"])
            else:
                os.kill(pid, 15)
            print("[ok] 已停止 pid=%d" % pid)
        except Exception as e:
            print("[!] 按 pid 停止失败: %s" % e)
        pidf.unlink(missing_ok=True)
    else:
        print("[i] 没有 pid 文件")
    # 兜底：按端口清理可能残留的监听进程
    if os.name == "nt":
        rc, so, se = _run(["netstat", "-ano"])
        for line in so.splitlines():
            if (":%d " % a.port) in line and "LISTENING" in line:
                tail = line.split()[-1]
                if tail.isdigit():
                    _run(["taskkill", "/PID", tail, "/T", "/F"])
                    print("[ok] 已清理端口 %d 上的残留进程 pid=%s" % (a.port, tail))


# ---------------------------------------------------------------- flows 解析

def load_flows(path):
    from mitmproxy import io as mio
    flows = []
    with open(path, "rb") as f:
        try:
            for fl in mio.FlowReader(f).stream():
                flows.append(fl)
        except Exception as e:
            print("[!] 读取中断（文件可能还在写）: %s" % type(e).__name__)
    return flows


def flow_host(fl):
    from urllib.parse import urlparse
    try:
        return urlparse(fl.request.pretty_url).hostname or "?"
    except Exception:
        return "?"


def cmd_dump(a):
    path = Path(a.file)
    if not path.exists():
        sys.exit("找不到 %s" % path)
    flows = load_flows(path)
    if a.host:
        flows = [f for f in flows if a.host.lower() in flow_host(f).lower()]
    if a.grep:
        g = a.grep.lower()
        keep = []
        for f in flows:
            blob = (f.request.pretty_url + " "
                    + (f.request.content or b"").decode("utf-8", "replace") + " "
                    + ((f.response.content or b"") if f.response else b"").decode("utf-8", "replace"))
            if g in blob.lower():
                keep.append(f)
        flows = keep

    err = [f for f in flows if f.error]
    print("共 %d 个 flow，其中 %d 个失败" % (len(flows), len(err)))
    from collections import Counter
    c = Counter(flow_host(f) for f in flows)
    if len(c) > 1:
        print("域名分布: " + "  ".join("%s(%d)" % (h, n) for h, n in c.most_common()))
    if err:
        print("--- 失败明细（若有 Client TLS handshake failed，说明有 SSL Pinning）---")
        for f in err[:15]:
            print("  %-52s %s" % (f.request.pretty_url[:52], str(f.error.msg)[:70]))
    print()

    if not a.detail and not a.md:
        for f in flows:
            st = f.response.status_code if f.response else ("ERR" if f.error else "-")
            print("%-5s %-6s %s" % (st, f.request.method, f.request.pretty_url[:110]))

    if a.detail:
        for f in flows:
            print("=" * 72)
            print(f.request.method, f.request.pretty_url)
            for k, v in f.request.headers.items():
                print("  > %s: %s" % (k, v[:110]))
            b = f.request.content or b""
            if b:
                print("  BODY:", b.decode("utf-8", "replace")[:1200])
            if f.response:
                print("  < %d  %s" % (f.response.status_code,
                                      f.response.headers.get("content-type", "")))
                print("  RESP:", (f.response.content or b"").decode("utf-8", "replace")[:1000])
            if f.error:
                print("  ERR:", f.error.msg)

    if a.md:
        L = ["# 抓包记录", "",
             "> 文件: `%s` ｜ 共 %d 个请求，%d 个失败" % (path.name, len(flows), len(err)),
             "", "## 总览", "", "| # | 方法 | URL | 状态 |", "|---|------|-----|------|"]
        for i, f in enumerate(flows, 1):
            st = f.response.status_code if f.response else ("ERR" if f.error else "-")
            L.append("| %d | %s | `%s` | %s |" % (i, f.request.method,
                                                  f.request.pretty_url[:110], st))
        L += ["", "## 明细", ""]
        for f in flows:
            L += ["### %s %s" % (f.request.method, f.request.pretty_url), "",
                  "请求头：", "```"]
            L += ["%s: %s" % (k, v) for k, v in f.request.headers.items()]
            L += ["```"]
            b = f.request.content or b""
            if b:
                L += ["请求体：", "```", b.decode("utf-8", "replace")[:3000], "```"]
            if f.response:
                L += ["响应 %d：" % f.response.status_code, "```",
                      (f.response.content or b"").decode("utf-8", "replace")[:3000], "```"]
            if f.error:
                L += ["错误：`%s`" % f.error.msg]
            L.append("")
        Path(a.md).write_text("\n".join(L), encoding="utf-8")
        print("\n[ok] 已导出 %s（%d 行）" % (a.md, len(L)))


# ---------------------------------------------------------------- main

def main():
    global ADB, VERBOSE
    ap = argparse.ArgumentParser(
        description="Android HTTPS 抓包主控（mitmproxy + 系统 CA + adb reverse）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""典型流程:
  cap.py info                 # 先看设备该走哪条证书路
  cap.py ca                   # 生成 CA，拿到 hash 文件名
  cap.py install              # 注入系统证书区
  cap.py proxy on             # 设代理（先启动 App 到目标页面！）
  cap.py run --daemon         # 开始抓
  ... 操作 App ...
  cap.py dump flows.mitm --detail
  cap.py proxy off            # 收工
""")
    ap.add_argument("--adb", help="adb 可执行文件路径")
    ap.add_argument("--serial", "-s", help="设备 serial")
    ap.add_argument("--confdir", default=str(DEFAULT_CONFDIR), help="mitmproxy confdir")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="设备画像 + 判定证书方案")
    p.add_argument("--pkg", help="目标 App 包名（默认自动取前台/上次记录）")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("ca", help="生成/复用 CA 并算 hash 文件名")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_ca)

    p = sub.add_parser("install", help="注入系统证书区")
    p.add_argument("--pkg", help="目标 App 包名")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("uninstall", help="卸载证书")
    p.set_defaults(func=cmd_uninstall)

    p = sub.add_parser("proxy", help="代理开关")
    p.add_argument("action", choices=["on", "off", "status"])
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.set_defaults(func=cmd_proxy)

    p = sub.add_parser("run", help="启动 mitmdump")
    p.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    p.add_argument("-w", "--out", default="flows.mitm")
    p.add_argument("--daemon", action="store_true")
    p.add_argument("--filter", help="mitmproxy view_filter 表达式")
    p.add_argument("--script", action="append", help="附加 mitmproxy 脚本 (-s)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("stop", help="停止 daemon")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("dump", help="解析 flows.mitm")
    p.add_argument("file", nargs="?", default="flows.mitm")
    p.add_argument("--detail", action="store_true", help="打印完整报文")
    p.add_argument("--host", help="按域名过滤")
    p.add_argument("--grep", help="在 URL + 请求体 + 响应体里搜")
    p.add_argument("--md", help="导出 markdown 到该路径")
    p.set_defaults(func=cmd_dump)

    a = ap.parse_args()
    VERBOSE = a.verbose
    ADB = find_adb(a.adb)
    a.func(a)


if __name__ == "__main__":
    main()

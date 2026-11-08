#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
session_recorder.py — 对局/登录会话的时间线记录器

目的：把"启动 → 登录 → 大厅 → 对局 → 被封"这条链上的时间点全部打成机器可读的时间线，
      事后才能回答三个问题：多久触发、触发在哪个阶段、封的是账号还是环境。

子命令：
  watch  轮询设备状态，写 timeline.jsonl（前台运行，Ctrl-C 停）
  report 从 timeline.jsonl + logcat + pcap 生成 SESSION_REPORT.md

用法：
  python session_recorder.py watch  --session sessions/20261107-2035 --interval 3
  python session_recorder.py report --session sessions/20261107-2035
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

ADB_CANDIDATES = [
    r"C:\Program Files\Netease\MuMu\nx_main\adb.exe",
    r"C:\Program Files\Netease\MuMuPlayer-12.0\shell\adb.exe",
    "adb",
]
PKG = "com.tencent.tmgp.dfm"

# 封禁/处罚相关关键词。命中不代表封禁，只代表"值得人看"。
BAN_PAT = re.compile(
    r"(环境异常|使用第三方|账号异常|封禁|封停|封号|违规|处罚|限制登录|"
    r"安全验证|安全检查|"
    r"ban(ned)?|forbid|suspend|restrict)",
    re.I,
)
# 环境类只认"具体可指向模拟器/调试"的词，且排除 SELinux 内核审计噪声
ENV_PAT = re.compile(r"(permissive|goldfish|qemu|emu64|nox|bluestacks|mumu)", re.I)
NOISE_PAT = re.compile(r"(auditd|avc:|FastPrintWriter|SELinux: Loaded|ServiceManager)", re.I)


def find_adb():
    for p in ADB_CANDIDATES:
        if os.path.sep in p:
            if os.path.exists(p):
                return p
        else:
            return p
    return "adb"


class Dev:
    def __init__(self, serial=None):
        self.adb = find_adb()
        self.serial = serial or "127.0.0.1:7555"
        self._connected = False

    def _ensure(self):
        if self._connected:
            return
        subprocess.run([self.adb, "connect", self.serial],
                       capture_output=True, timeout=15)
        self._connected = True

    def sh(self, cmd, timeout=12):
        self._ensure()
        try:
            r = subprocess.run([self.adb, "-s", self.serial, "shell", cmd],
                               capture_output=True, timeout=timeout)
            out = r.stdout.decode("utf-8", "replace")
            if not out.strip() and r.returncode != 0:
                out = r.stderr.decode("utf-8", "replace")
            return out.replace("\r", "").strip()
        except subprocess.TimeoutExpired:
            return "<timeout>"
        except Exception as e:  # adb server 被杀是常态，重新连
            self._connected = False
            return "<err:%s>" % e.__class__.__name__


def one_tick(dev):
    """采集一个时间点的状态。字段少而稳定，便于事后对齐。"""
    raw = dev.sh(
        'cat /proc/uptime; '
        'dumpsys window 2>/dev/null | grep -m1 mCurrentFocus; '
        'echo "PID=$(pidof %s)"; '
        'echo "TC=$(( $(wc -l < /proc/net/tcp) + $(wc -l < /proc/net/udp) ))"'
        % PKG
    )
    rec = {
        "t": time.time(),
        "wall": datetime.now().strftime("%H:%M:%S"),
        "uptime": None,
        "focus": None,
        "pid": None,
        "conn": None,
    }
    for line in raw.splitlines():
        line = line.strip()
        if re.match(r"^\d+\.\d+ \d+\.\d+$", line):
            rec["uptime"] = round(float(line.split()[0]), 1)
        elif "mCurrentFocus" in line:
            m = re.search(r"mCurrentFocus=(.+)$", line)
            if m:
                s = m.group(1).strip()
                s = s[:-1] if s.endswith("}") else s
                rec["focus"] = s
        elif line.startswith("PID="):
            v = line[4:]
            rec["pid"] = int(v.split()[0]) if v.strip() else None
        elif line.startswith("TC="):
            try:
                rec["conn"] = int(line[3:])
            except ValueError:
                pass
    return rec


def scan_logcat_tail(path, offset, max_bytes=4 * 1024 * 1024):
    """从 offset 起读新增日志，找封禁/环境类关键词。返回 (hits, new_offset)"""
    if not os.path.exists(path):
        return [], offset
    size = os.path.getsize(path)
    if size <= offset:
        # 文件被截断/重建
        offset = 0 if size < offset else offset
    start = max(offset, size - max_bytes) if size - offset > max_bytes else offset
    hits = []
    try:
        with open(path, "rb") as f:
            f.seek(start)
            blob = f.read()
    except OSError:
        return [], offset
    text = blob.decode("utf-8", "replace")
    for line in text.splitlines():
        if NOISE_PAT.search(line):
            continue
        if BAN_PAT.search(line):
            hits.append({"t": time.time(), "kind": "ban_kw", "line": line[:400]})
        elif ENV_PAT.search(line):
            hits.append({"t": time.time(), "kind": "env_kw", "line": line[:400]})
    return hits, size


def cmd_watch(a):
    os.makedirs(a.session, exist_ok=True)
    tl = os.path.join(a.session, "timeline.jsonl")
    dev = Dev(a.serial)
    logpath = os.path.join(a.session, "logcat.txt")
    # 从当前文件末尾开始，不然第一轮会把历史日志全当成本次命中
    log_off = os.path.getsize(logpath) if os.path.exists(logpath) else 0
    last_focus, last_pid = "<init>", "<init>"
    t0 = time.time()
    n = 0
    print("[*] 记录到 %s（间隔 %ss，Ctrl-C 停）" % (tl, a.interval))
    try:
        while True:
            rec = one_tick(dev)
            hits, log_off = scan_logcat_tail(logpath, log_off)
            with open(tl, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                for h in hits:
                    h["t"] = round(h["t"], 3)
                    f.write(json.dumps(h, ensure_ascii=False) + "\n")
            # 只在变化时打屏，避免刷屏
            if rec["focus"] != last_focus or rec["pid"] != last_pid:
                print("  [%s] focus=%s pid=%s" % (rec["wall"], rec["focus"], rec["pid"]))
                last_focus, last_pid = rec["focus"], rec["pid"]
            for h in hits[:5]:
                print("  ! [%s] %s" % (h["kind"], h["line"][:160]))
            n += 1
            if a.duration and time.time() - t0 > a.duration:
                print("[*] 到时退出，共 %d 个采样" % n)
                break
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print("\n[*] 手动停止，共 %d 个采样" % n)


def cmd_report(a):
    s = a.session
    tl = os.path.join(s, "timeline.jsonl")
    lines = []
    if os.path.exists(tl):
        for ln in open(tl, encoding="utf-8"):
            ln = ln.strip()
            if ln:
                try:
                    lines.append(json.loads(ln))
                except json.JSONDecodeError:
                    pass
    snaps = [r for r in lines if "focus" in r]
    evts = [r for r in lines if "kind" in r]

    out = []
    out.append("# 会话记录：%s\n" % os.path.basename(s))
    if snaps:
        t_first, t_last = snaps[0]["wall"], snaps[-1]["wall"]
        out.append("采样 %d 个，%s → %s\n" % (len(snaps), t_first, t_last))

        # 阶段切分：focus 或 pid 变化即为事件边界
        out.append("## 阶段切分\n")
        out.append("| 时刻 | 前台 | 游戏PID | 连接数 | 持续 |")
        out.append("|---|---|---|---|---|")
        seg_start = snaps[0]
        prev = snaps[0]
        for cur in snaps[1:]:
            if cur.get("focus") != prev.get("focus") or (cur.get("pid") is None) != (prev.get("pid") is None):
                dur = cur["t"] - seg_start["t"]
                out.append("| %s | %s | %s | %s | %.0fs |" % (
                    seg_start["wall"],
                    (seg_start.get("focus") or "-").split("/")[-1].replace("}", ""),
                    seg_start.get("pid") or "-",
                    seg_start.get("conn") or "-",
                    dur))
                seg_start = cur
            prev = cur
        dur = prev["t"] - seg_start["t"]
        out.append("| %s | %s | %s | %s | %.0fs |" % (
            seg_start["wall"],
            (seg_start.get("focus") or "-").split("/")[-1].replace("}", ""),
            seg_start.get("pid") or "-",
            seg_start.get("conn") or "-",
            dur))

        # 进程死亡时刻
        deaths = []
        for i in range(1, len(snaps)):
            if snaps[i - 1].get("pid") and not snaps[i].get("pid"):
                deaths.append(snaps[i])
        if deaths:
            out.append("\n## 游戏进程消失\n")
            for d in deaths:
                out.append("- **%s**（进程在两次采样间退出，PID 消失）" % d["wall"])

    if evts:
        ban = [e for e in evts if e["kind"] == "ban_kw"]
        env = [e for e in evts if e["kind"] == "env_kw"]
        out.append("\n## 日志关键词命中\n")
        out.append("- 封禁/处罚类：**%d** 条" % len(ban))
        out.append("- 环境/反调试类：**%d** 条" % len(env))
        seen = set()
        for e in ban[:40]:
            key = e["line"][:80]
            if key in seen:
                continue
            seen.add(key)
            out.append("\n```\n%s\n```" % e["line"][:300])

    # 抓包清单
    pcs = sorted(f for f in os.listdir(s) if f.startswith(("udp_0", "tcp_0", "probe")))
    if pcs:
        out.append("\n## 抓包文件\n")
        tot = 0
        for f in pcs:
            sz = os.path.getsize(os.path.join(s, f))
            tot += sz
            out.append("- `%s` %.1f MB" % (f, sz / 1048576.0))
        out.append("- 合计 %.1f MB" % (tot / 1048576.0))

    md = "\n".join(out) + "\n"
    dst = os.path.join(s, "SESSION_REPORT.md")
    open(dst, "w", encoding="utf-8").write(md)
    print(md)
    print("[*] 已写 %s" % dst)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("watch")
    w.add_argument("--session", required=True)
    w.add_argument("--interval", type=float, default=3.0)
    w.add_argument("--duration", type=float, default=0)
    w.add_argument("--serial", default=None)
    r = sub.add_parser("report")
    r.add_argument("--session", required=True)
    a = ap.parse_args()
    if a.cmd == "watch":
        cmd_watch(a)
    else:
        cmd_report(a)


if __name__ == "__main__":
    main()

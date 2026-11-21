#!/usr/bin/env python3
"""oracle_harness.py — 把真实 .so 里的函数包成离线 oracle（纯标准库）。

设计原则（见 ../references/license_system_map.md §三）：
  不重写算法。造码器/穷举器应当是「真实校验函数的调用方」，而不是它的第二实现。
  重写 = 引入第二份语义；错了永远分不清是算法错还是实现错。

三个核心用途：
  1) 钉死返回码语义      --expect 1        （用已知有效/无效样本各跑一次）
  2) 检测非确定性        --repeat 5        （同一输入多次调用，输出是否稳定）
  3) 批量筛选候选码      --verify-file f   （每行一组逗号分隔参数）

用法：
  # 单次调用
  python oracle_harness.py --lib lib.so --func validate \\
         --args c_char_p,c_char_p,c_char_p,c_char_p \\
         --call "AA:BB:CC:DD:EE:FF,200017888,CODE,02"

  # 确认 "1 才是有效"：有效样本 expect=1，无效样本 expect!=1
  python oracle_harness.py ... --call "<已知有效>" --expect 1

  # 检测随机性（输出不同 → 必须"生成→校验→重试"循环）
  python oracle_harness.py --lib lib.so --func gen_key --args c_char_p,c_char_p --call "REG,SERIAL" --repeat 5

  # 批量：每行是完整的参数组
  python oracle_harness.py --lib lib.so --func validate --args c_char_p,c_char_p,c_char_p,c_char_p \\
         --verify-file candidates.txt --expect 1

  # 签名不熟、怕段错误：每次调用起子进程，崩了不影响主进程
  python oracle_harness.py ... --isolate

退出码：0 = 全部符合预期；1 = 有不符合；2 = 环境/参数错误。
"""

import argparse
import ctypes
import json
import os
import subprocess
import sys

TYPES = {
    "c_char_p": ctypes.c_char_p,
    "c_int": ctypes.c_int,
    "c_uint": ctypes.c_uint,
    "c_long": ctypes.c_long,
    "c_ulong": ctypes.c_ulong,
    "c_ulonglong": ctypes.c_ulonglong,
    "c_void_p": ctypes.c_void_p,
    "c_double": ctypes.c_double,
}


def die(msg):
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def parse_argspec(spec):
    """'c_char_p,c_int' -> [ctypes type, ...]"""
    if not spec:
        return []
    out = []
    for name in [x.strip() for x in spec.split(",") if x.strip()]:
        if name not in TYPES:
            die("未知类型 %r，可选：%s" % (name, ", ".join(sorted(TYPES))))
        out.append(TYPES[name])
    return out


def coerce(value, ctype):
    """把命令行字符串转成对应 ctypes 值。c_char_p 走 encode，其余按 int（支持 0x）。"""
    if ctype is ctypes.c_char_p:
        return value.encode("utf-8", "surrogateescape")
    if ctype is ctypes.c_void_p:
        return int(value, 0)
    if ctype is ctypes.c_double:
        return float(value)
    return int(value, 0)


def load(lib_path):
    if not os.path.exists(lib_path):
        die("库不存在：%s" % lib_path)
    try:
        return ctypes.CDLL(lib_path)
    except OSError as exc:
        die("dlopen 失败：%s" % exc)


def resolve(lib, candidates):
    """按候选名逐个 dlsym；返回 (符号名, 函数)。用于函数名不完全确定的情况。"""
    for name in candidates:
        try:
            return name, getattr(lib, name)
        except AttributeError:
            continue
    die("符号都找不到：%s（用 nm -D 或 objdump -T 确认导出名）"
        % ", ".join(candidates))


def call_once(lib, func_name, argtypes, values):
    fn = resolve(lib, func_name.split(","))
    fn_name, fn = fn
    fn.argtypes = argtypes
    fn.restype = ctypes.c_void_p  # 不预设；按返回类型决定下面怎么读
    cvalues = [coerce(v, t) for v, t in zip(values, argtypes)]
    raw = fn(*cvalues)
    return fn_name, raw


def call_isolated(lib_path, func_name, argspec, values):
    """子进程内调用：段错误只杀掉子进程，主进程拿到退出码。"""
    cmd = [sys.executable, os.path.abspath(__file__), "--emit",
           "--lib", lib_path, "--func", func_name, "--args", argspec or "",
           "--call", ",".join(values)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return None, {"error": "子进程退出码 %d" % proc.returncode,
                      "stderr": (proc.stderr or "").strip()[-400:]}
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1]), None
    except Exception:
        return None, {"error": "子进程输出无法解析", "stdout": proc.stdout[-400:]}


def main():
    ap = argparse.ArgumentParser(description="把真实 .so 函数包成离线 oracle")
    ap.add_argument("--lib", required=True, help="目标动态库路径")
    ap.add_argument("--func", required=True, help="函数名；可逗号分隔多个候选名")
    ap.add_argument("--args", default="", help="参数类型列表，如 c_char_p,c_char_p,c_int")
    ap.add_argument("--call", default="", help="参数值，逗号分隔，与 --args 一一对应")
    ap.add_argument("--expect", type=int, default=None,
                    help="期望返回值；不符则退出码 1（用于钉死返回码语义）")
    ap.add_argument("--repeat", type=int, default=1,
                    help="重复调用次数；>1 时检测非确定性（输出不一致即告警）")
    ap.add_argument("--verify-file", default=None,
                    help="批量：文件每行一组逗号分隔参数，逐行调用")
    ap.add_argument("--isolate", action="store_true", help="每次调用起子进程，防段错误带崩")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--emit", action="store_true", help=argparse.SUPPRESS)
    ns = ap.parse_args()

    argtypes = parse_argspec(ns.args)

    # ---- 子进程模式：只执行一次调用并把结果打到 stdout ----
    if ns.emit:
        lib = load(ns.lib)
        values = [v for v in ns.call.split(",")] if ns.call != "" else []
        if len(values) != len(argtypes):
            die("参数个数不匹配：args=%d call=%d" % (len(argtypes), len(values)))
        name, raw = call_once(lib, ns.func, argtypes, values)
        print(json.dumps({"func": name, "ret": raw if isinstance(raw, (int, type(None)))
                          else repr(raw)}, ensure_ascii=False))
        return 0

    # ---- 组装调用批次 ----
    if ns.verify_file:
        with open(ns.verify_file, "r", encoding="utf-8") as fh:
            batches = [[c.strip() for c in line.rstrip("\n").split(",")]
                       for line in fh if line.strip() and not line.startswith("#")]
    else:
        batches = [[v for v in ns.call.split(",")] if ns.call != "" else []]

    for values in batches:
        if len(values) != len(argtypes):
            die("参数个数不匹配：args=%d call=%d（%r）"
                % (len(argtypes), len(values), values))

    lib = None if ns.isolate else load(ns.lib)
    results, mismatches = [], 0

    for values in batches:
        rets = []
        for _ in range(max(1, ns.repeat)):
            if ns.isolate:
                data, err = call_isolated(ns.lib, ns.func, ns.args, values)
                if err:
                    results.append({"call": values, "error": err})
                    break
                rets.append(data["ret"])
            else:
                _, raw = call_once(lib, ns.func, argtypes, values)
                rets.append(raw if isinstance(raw, (int, type(None))) else repr(raw))

        if not rets:
            continue
        entry = {"call": values, "ret": rets[0], "stable": len(set(map(str, rets))) == 1}
        if not entry["stable"]:
            entry["observed"] = rets
        results.append(entry)

        if ns.expect is not None:
            ok = all(str(r) == str(ns.expect) for r in rets)
            entry["expect_ok"] = ok
            if not ok:
                mismatches += 1

    # ---- 报告 ----
    nondeterministic = [r for r in results if r.get("stable") is False]
    if ns.json:
        print(json.dumps({"results": results,
                          "mismatches": mismatches,
                          "nondeterministic": len(nondeterministic)},
                         ensure_ascii=False, indent=2))
    else:
        print("== oracle 调用结果 ==")
        for r in results:
            if "error" in r:
                print("  [CRASH] %r -> %s" % (r["call"], r["error"]))
                continue
            flag = ""
            if r.get("stable") is False:
                flag += "  ⚠ 非确定性：" + str(r.get("observed"))
            if "expect_ok" in r:
                flag += "  ✓" if r["expect_ok"] else "  ✗ 与 expect=%s 不符" % ns.expect
            print("  %r -> %r%s" % (r["call"], r["ret"], flag))
        print()
        if nondeterministic:
            print("⚠ 检测到非确定性：不要\"生成一次就信\"，改用 生成→校验→失败重试 循环。")
        if ns.expect is not None:
            print("expect=%s：%d/%d 条符合" % (ns.expect, len(results) - mismatches, len(results)))

    if any("error" in r for r in results):
        return 2
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())

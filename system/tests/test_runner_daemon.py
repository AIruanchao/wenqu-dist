#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_runner_daemon.py——P0-8：Runner daemon 化逃逸对抗自测（Codex 第四轮实锤复刻）。

洞（修复前 3/3 实锤）：孙进程 os.setsid() + double-fork 后中间进程退出、
daemon 被 PID 1 收养；TrustedRunner 超时时 _descendants(root_pid) 从已死
root 按 PPID 图找后代——daemon 的 ppid 已是 1，进程树快照必漏；killpg 对
非本组进程无效；marker 落盘。

根修：每次 run() 注入唯一 run token（__WENQU_RUN_TOKEN__，环境白名单剥除
之后追加的内部哨兵）；超时击杀 = killpg + 进程树扫荡（保留为兜底）+
按 token 全系统扫杀（darwin：ps -AxE -o pid=,command= 含环境输出逐行匹配；
linux：逐 pid 读 /proc/<pid>/environ）。reparent 后的 daemon 在 environ
里仍携带 token——照样命中。

验收铁律（Codex 探针复刻）：孙进程 setsid+double-fork+睡过 timeout+写
marker → marker 必须不落盘，连续 3/3；全部现有测试不破坏。

纯标准库；`python3 system/tests/test_runner_daemon.py`（exit 0=全绿）。
"""
import os
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.runner import (  # noqa: E402
    DEFAULT_ENV_KEYS,  # noqa: F401
    RUN_TOKEN_ENV,
    TrustedRunner,
)

PASS_N, FAIL_N, FAILURES = 0, 0, []


def _ck(name, cond, detail=""):
    global PASS_N, FAIL_N
    if cond:
        PASS_N += 1
        print(f"  ✓ {name}")
    else:
        FAIL_N += 1
        FAILURES.append(name)
        print(f"  ✗ {name} {detail}")


#: double-fork 攻击脚本模板：setsid + double-fork + 中间退出 + daemon
#: 睡过 timeout 后写 marker（Codex 第四轮实锤同款形态）
_DAEMON_ATTACK = (
    "import os, time\n"
    "pid = os.fork()\n"
    "if pid == 0:\n"
    "    os.setsid()\n"              # 逃逸 runner 的进程组（killpg 盲区）
    "    pid2 = os.fork()\n"
    "    if pid2 == 0:\n"            # daemon：中间进程退出后被 PID 1 收养
    "        time.sleep(3)\n"        # 睡过 runner timeout=1s
    "        open({marker!r}, 'w').write('daemon survived')\n"
    "        time.sleep(30)\n"
    "    else:\n"
    "        os._exit(0)\n"          # 中间进程退出 → daemon reparent
    "else:\n"
    "    os.waitpid(pid, 0)\n"
)


def _write_attack(td):
    attack = os.path.join(td, "attack.py")
    with open(attack, "w", encoding="utf-8") as fh:
        fh.write(_DAEMON_ATTACK.format(marker=os.path.join(td, "ESCAPED")))
    return attack


# ══════════════════════════════════════════════════════════════════════
# 探针 1：python 直接子进程形态——marker 必须 3/3 不落盘
# ══════════════════════════════════════════════════════════════════════
def test_daemon_escape_direct_child_3_of_3():
    ok, timed_out_all = 0, True
    for i in range(3):
        with tempfile.TemporaryDirectory(prefix="wq-daemon-direct-") as td:
            attack = _write_attack(td)
            marker = os.path.join(td, "ESCAPED")
            ev = TrustedRunner(timeout=1.0).run([sys.executable, attack])
            timed_out_all = timed_out_all and ev.timed_out is True
            time.sleep(3.5)  # daemon 的 marker 落盘窗口（t+3s）
            ok += 1 if not os.path.exists(marker) else 0
            print(f"    round {i + 1}: timed_out={ev.timed_out} "
                  f"marker_exists={os.path.exists(marker)}")
    _ck("P0-8 daemon（直接子进程形态）marker 3/3 不落盘", ok == 3, f"{ok}/3")
    _ck("P0-8 daemon 攻击被记 timed_out（证据不丢）", timed_out_all)


# ══════════════════════════════════════════════════════════════════════
# 探针 2：Codex 实测两级形态（sh 直接子进程 + python 孙进程）——3/3
# ══════════════════════════════════════════════════════════════════════
def test_daemon_escape_sh_wrapper_3_of_3():
    ok, timed_out_all = 0, True
    for i in range(3):
        with tempfile.TemporaryDirectory(prefix="wq-daemon-sh-") as td:
            attack = _write_attack(td)
            marker = os.path.join(td, "ESCAPED")
            # `; true` 使 sh 走 fork 而非 exec 优化（Codex 实测同款）——
            # python 孙进程非会话首领导，setsid 必成功
            argv = ["/bin/sh", "-c", f"{sys.executable} {attack}; true"]
            ev = TrustedRunner(timeout=1.0).run(argv)
            timed_out_all = timed_out_all and ev.timed_out is True
            time.sleep(3.5)
            ok += 1 if not os.path.exists(marker) else 0
            print(f"    round {i + 1}: timed_out={ev.timed_out} "
                  f"marker_exists={os.path.exists(marker)}")
    _ck("P0-8 daemon（sh 两级形态）marker 3/3 不落盘", ok == 3, f"{ok}/3")
    _ck("P0-8 sh 两级形态同样记 timed_out", timed_out_all)


# ══════════════════════════════════════════════════════════════════════
# 单元面：token 扫杀的命中与收敛（含 reparent 后的 daemon）
# ══════════════════════════════════════════════════════════════════════
def test_token_scan_finds_reparented_daemon():
    """手动起一个 setsid+double-fork daemon（带 token env）——token 扫描
    必须命中它（即便 ppid=1），kill 后扫描收敛为空。"""
    import signal
    token_value = os.urandom(16).hex()
    token_pair = f"{RUN_TOKEN_ENV}={token_value}"
    code = (
        "import os, time\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    os.setsid()\n"
        "    pid2 = os.fork()\n"
        "    if pid2 == 0:\n"
        "        time.sleep(20)\n"
        "        os._exit(0)\n"
        "    else:\n"
        "        os._exit(0)\n"
        "else:\n"
        "    os.waitpid(pid, 0)\n"
    )
    env = {k: os.environ.get(k, "") for k in ("PATH",)}
    env[RUN_TOKEN_ENV] = token_value
    proc = subprocess.Popen([sys.executable, "-c", code], env=env)
    try:
        proc.wait(timeout=10)  # 攻击脚本本身即刻退出（daemon 已 reparent）
        time.sleep(0.4)        # 等 reparent 完成
        hits = TrustedRunner._scan_token_pids(token_pair)
        daemon_pids = {p for p in hits
                       if p != os.getpid() and p != proc.pid}
        _ck("P0-8 token 扫描命中 reparent 后的 daemon", len(daemon_pids) >= 1,
            f"hits={hits}")
        for pid in daemon_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        time.sleep(0.2)
        left = TrustedRunner._scan_token_pids(token_pair)
        _ck("P0-8 kill 后 token 扫描收敛为空", not left, f"left={left}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# ══════════════════════════════════════════════════════════════════════
# 非回归面：token 注入不破坏「env 白名单剥除」语义 + 正常执行不受影响
# ══════════════════════════════════════════════════════════════════════
def test_token_injection_keeps_env_whitelist_semantics():
    """token 是内部哨兵不是用户变量：敏感变量照常剥除；token 本身随子进程
    环境（这是设计——超时扫杀的锚点）；runner 自身 os.environ 不被写入。"""
    with tempfile.TemporaryDirectory(prefix="wq-daemon-env-") as td:
        out = os.path.join(td, "env.json")
        probe = [sys.executable, "-c",
                 f"import os, json; open({out!r}, 'w').write("
                 "json.dumps(sorted(os.environ.keys())))"]
        os.environ["WQ_SECRET_TOKEN"] = "leak-me-if-you-can"
        try:
            TrustedRunner().run(probe)
            with open(out, encoding="utf-8") as fh:
                import json
                keys = set(json.load(fh))
            _ck("P0-8 token 注入下敏感变量仍被剥除（白名单语义不破）",
                "WQ_SECRET_TOKEN" not in keys)
            _ck("P0-8 run token 哨兵随子进程环境（扫杀锚点在位）",
                RUN_TOKEN_ENV in keys)
            _ck("P0-8 runner 自身环境未被写入 token",
                RUN_TOKEN_ENV not in os.environ)
        finally:
            del os.environ["WQ_SECRET_TOKEN"]


def test_normal_run_unaffected():
    """正控：无超时路径不受 token/扫杀影响——退出码/证据语义保持。"""
    ev = TrustedRunner().run(["/bin/echo", "daemon-test-ok"])
    _ck("P0-8 正常执行退出码不变", ev.actual_exit_code == 0, str(ev))
    _ck("P0-8 正常执行不记 timed_out", ev.timed_out is False)
    with tempfile.TemporaryDirectory(prefix="wq-daemon-timeout-") as td:
        out = os.path.join(td, "slept")
        ev = TrustedRunner(timeout=0.5).run(
            [sys.executable, "-c",
             f"import time, pathlib; time.sleep(3); "
             f"pathlib.Path({out!r}).write_text('alive')"])
        _ck("P0-8 普通超时仍记 timed_out", ev.timed_out is True)
        time.sleep(3.0)
        _ck("P0-8 普通超时子进程同样被杀（marker 不落盘）",
            not os.path.exists(out))


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    print(f"== Runner daemon 化逃逸对抗自测（{len(tests)} 组）==")
    for t in tests:
        print(f"-- {t.__name__}")
        try:
            t()
        except Exception as exc:  # 测试自身崩溃=失败（不静默）
            import traceback
            traceback.print_exc()
            FAIL_N += 1
            FAILURES.append(f"{t.__name__} (CRASH: {exc!r})")
    print("=" * 40)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        for f in FAILURES:
            print(f"  ✗ {f}")
    sys.exit(1 if FAIL_N else 0)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_linux_proc_path.py——Runner Linux /proc token 扫杀通路实测。

背景（八轮验收遗留项「Runner Linux /proc 通路未实测」）：
wenqu_core/runner.py:_scan_token_pids 的 linux 分支（逐 pid 读
``/proc/<pid>/environ``，按完整 ``NAME=<crypto 随机值>`` 串匹配）此前只在
darwin（``ps -AxE`` 通路）被真实执行过；acceptance CI（ubuntu-latest）
从不运行 system 测试——linux /proc 真腿零覆盖。

本文件两条腿：
- 真腿（仅 ``sys.platform == 'linux'``，CI Ubuntu 真跑，darwin 上 SKIP 标注）：
  1. 直接注入 token 的 setsid+double-fork daemon（被 PID 1 收养、killpg 与
     PPID 图双盲区形态）必须被 ``/proc`` 扫描命中；SIGKILL 后扫描收敛为空；
  2. ``TrustedRunner(timeout=…)`` 全链路超时击杀：逃逸 daemon 必须死透
     （pid 消失）且证据记 ``timed_out``——这正是只有 token 扫杀能兜住的形态。
- 结构腿（darwin+linux 均跑）：monkeypatch /proc 布局（isdir/listdir/open
  三点桩）直接驱动 linux 分支，断言解析语义：仅完整 ``NAME=value`` 命中；
  裸名 / 异值 / 前缀撞车不误杀；不可读 pid（EACCES）跳过不炸；非数字
  目录项跳过。

用法：
  python3 -m pytest system/tests/test_linux_proc_path.py -v
  python3 system/tests/test_linux_proc_path.py            # 自跑器 exit 0=全绿
"""
import builtins
import io
import os
import subprocess
import sys
import time

try:
    import pytest
except ImportError:  # 自跑器模式下允许无 pytest（CI/本地 pytest 腿不受影响）
    pytest = None

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.runner import RUN_TOKEN_ENV, TrustedRunner  # noqa: E402

PASS_N, FAIL_N, FAILURES = 0, 0, []

LINUX_ONLY_REASON = (
    "真腿仅 Linux /proc 实测（CI ubuntu-latest 执行；darwin 见结构腿）"
)

_IS_LINUX = sys.platform == "linux"


def _linux_only(func):
    """pytest 下挂 skipif（darwin 显示 SKIP）；无 pytest 的直跑模式为恒等。"""
    if pytest is not None:
        return pytest.mark.skipif(
            not _IS_LINUX, reason=LINUX_ONLY_REASON)(func)
    return func


def _ck(name, cond, detail=""):
    global PASS_N, FAIL_N
    if cond:
        PASS_N += 1
        print(f"  ✓ {name}")
    else:
        FAIL_N += 1
        FAILURES.append(name)
        print(f"  ✗ {name} {detail}")


# ---------------------------------------------------------------------------
# 共用：setsid + double-fork daemon 载荷（P0-8 对抗形态——killpg 盲区 +
# 中间进程退出后被 PID 1 收养 → PPID 图断裂，唯一收网锚点是 environ token）
# ---------------------------------------------------------------------------
def _daemon_code(pid_file: str, marker_file: str, root_sleeps: bool) -> str:
    """生成 daemon 攻击载荷源码。

    - daemon（孙进程）：setsid 后 fork，写自身 pid 到 pid_file，睡 4s；若活过
      击杀窗口则写 marker_file（幸存铁证），再睡 60s；
    - 中间进程：_exit(0) → daemon 被 PID 1 收养；
    - root：root_sleeps=True 时睡 60s（触发 TrustedRunner 超时路径），
      否则 waitpid 后正常退出（供直接扫描腿使用）。
    """
    tail = "time.sleep(60)" if root_sleeps else f"os.waitpid(pid, 0)"
    return (
        "import os, time\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    os.setsid()\n"                       # 逃逸进程组（killpg 盲区）
        "    pid2 = os.fork()\n"
        "    if pid2 == 0:\n"                     # daemon：reparent 后 ppid=1
        f"        open({pid_file!r}, 'w').write(str(os.getpid()))\n"
        "        time.sleep(4)\n"                 # 睡过 timeout=1s 击杀窗
        f"        open({marker_file!r}, 'w').write('daemon survived')\n"
        "        time.sleep(60)\n"
        "    else:\n"
        "        os._exit(0)\n"                   # 中间进程退出 → daemon reparent
        "else:\n"
        f"    {tail}\n"
    )


def _wait_pid_file(pid_file, deadline_s: float = 10.0):
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            return int(open(pid_file, encoding="utf-8").read().strip())
        except (FileNotFoundError, ValueError):
            time.sleep(0.05)
    return None


def _pid_dead(pid: int) -> bool:
    """Linux 语义的死透判定：pid 消失，或 /proc/<pid>/stat 状态为 Z。

    Z（僵尸）= 已被 SIGKILL、仅未被当前 PID 1 收割——容器入口是 bash 且
    阻塞在 waitpid(前台) 时不异步收割领养子进程，此时 kill(pid,0) 仍成功；
    用 stat 状态判定避免把「已杀死未收割」误报为存活。"""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return True  # 已死但收割者非本用户——同样视为不可达
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
        rparen = data.rfind(b")")  # comm 可含空格/括号——状态位取末个 ) 后第 2 字节
        if rparen >= 0 and data[rparen + 2:rparen + 3] == b"Z":
            return True
    except OSError:
        pass
    return False


def _wait_pid_gone(pid: int, deadline_s: float = 10.0) -> bool:
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        if _pid_dead(pid):
            return True
        time.sleep(0.1)
    return False


# ══════════════════════════════════════════════════════════════════════
# 真腿 1：/proc 扫描命中 reparent 后的 token daemon + kill 后收敛
# ══════════════════════════════════════════════════════════════════════
def _real_scan_and_converge(td: str) -> None:
    import signal

    token_value = os.urandom(24).hex()
    token_pair = f"{RUN_TOKEN_ENV}={token_value}"
    pid_file = os.path.join(td, "daemon.pid")
    marker_file = os.path.join(td, "SURVIVED-scan")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           RUN_TOKEN_ENV: token_value}
    proc = subprocess.Popen(
        [sys.executable, "-c",
         _daemon_code(pid_file, marker_file, root_sleeps=False)],
        env=env, start_new_session=True,
    )
    try:
        proc.wait(timeout=15)               # 攻击脚本自身即刻退出（daemon 已逃逸）
        time.sleep(0.4)                     # 等 reparent 完成（ppid→1）
        daemon_pid = _wait_pid_file(pid_file)
        _ck("linux 真腿：daemon pid 文件在位", daemon_pid is not None,
            f"pid_file={pid_file}")
        if daemon_pid is None:
            return
        hits = TrustedRunner._scan_token_pids(token_pair)
        _ck("linux 真腿：/proc 扫描命中 reparent 后的 daemon",
            daemon_pid in hits and daemon_pid != os.getpid(),
            f"daemon={daemon_pid} hits={sorted(hits)}")
        miss = TrustedRunner._scan_token_pids(
            f"{RUN_TOKEN_ENV}={os.urandom(24).hex()}")
        _ck("linux 真腿：异值 token 不误杀（完整 NAME=value 匹配语义）",
            daemon_pid not in miss, f"miss_hits={sorted(miss)}")
        try:
            os.kill(daemon_pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.time() + 10
        left = {daemon_pid}
        while time.time() < deadline and daemon_pid in left:
            time.sleep(0.2)
            left = TrustedRunner._scan_token_pids(token_pair)
        _ck("linux 真腿：SIGKILL 后 token 扫描收敛为空", not left,
            f"left={sorted(left)}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


@_linux_only
def test_linux_real_token_scan_hits_and_converges(tmp_path):
    """真腿（仅 Linux，darwin 上 SKIP 标注）：/proc token 扫描命中+收敛。"""
    before = len(FAILURES)
    _real_scan_and_converge(str(tmp_path))
    assert len(FAILURES) == before, f"失败项: {FAILURES[before:]}"


# ══════════════════════════════════════════════════════════════════════
# 真腿 2：TrustedRunner 超时全链路——逃逸 daemon 死透 + 证据记 timed_out
# ══════════════════════════════════════════════════════════════════════
def _real_runner_timeout_kills_daemon(td: str) -> None:
    pid_file = os.path.join(td, "daemon.pid")
    marker_file = os.path.join(td, "SURVIVED-timeout")
    ev = TrustedRunner(timeout=1.0).run(
        [sys.executable, "-c",
         _daemon_code(pid_file, marker_file, root_sleeps=True)],
        cwd=td,
    )
    _ck("linux 真腿：超时证据记 timed_out（证据不丢）", ev.timed_out is True,
        f"ev={ev.to_json()[:200]}")
    _ck("linux 真腿：超时退出码语义=None（不伪造）",
        ev.actual_exit_code is None)
    daemon_pid = _wait_pid_file(pid_file)
    _ck("linux 真腿：daemon pid 文件在位", daemon_pid is not None,
        f"pid_file={pid_file}")
    if daemon_pid is None:
        return
    killed = _wait_pid_gone(daemon_pid)
    # marker 铁证：daemon 活过击杀窗（t=4s）才会写 SURVIVED 文件——与僵尸
    # 收割语义无关的独立幸存证据（Codex 探针复刻形态）。
    time.sleep(max(0.0, 6.0 - (time.time() - ev.timestamp)))
    marker_exists = os.path.exists(marker_file)
    _ck("linux 真腿：幸存 marker 不落盘（击杀窗内死透的铁证）",
        not marker_exists, f"marker={marker_file}")
    _ck("linux 真腿：setsid+double-fork 逃逸 daemon 被击杀死透",
        killed and not marker_exists,
        f"daemon={daemon_pid} state_probe={'dead' if killed else 'alive'} "
        f"marker={'present' if marker_exists else 'absent'}")


@_linux_only
def test_linux_real_runner_timeout_kills_escaped_daemon(tmp_path):
    """真腿（仅 Linux，darwin 上 SKIP 标注）：TrustedRunner 超时 token 收网。"""
    before = len(FAILURES)
    _real_runner_timeout_kills_daemon(str(tmp_path))
    assert len(FAILURES) == before, f"失败项: {FAILURES[before:]}"


# ══════════════════════════════════════════════════════════════════════
# 结构腿（darwin+linux 均跑）：monkeypatch /proc 布局驱动 linux 分支解析
# ══════════════════════════════════════════════════════════════════════
def _structural_linux_branch(monkeypatch, td: str) -> None:
    token_value = "cafe" * 16
    needle_pair = f"{RUN_TOKEN_ENV}={token_value}"
    # 假 /proc 布局：42=完整命中；314=同长异值；271=裸名；1=无关环境；
    # 7=不可读（EACCES 跳过不炸）；另有非数字目录项（self/acpi/stat）必跳过。
    # 注：「同前缀更长值」按子串语义也命中——那是实现细节不钉死，负例只覆盖
    # 语义上必须不命中的形态（裸名 / 异值）。
    envs = {
        "1":   b"PATH=/usr/bin\0HOME=/root\0",
        "7":   None,  # PermissionError 载体
        "42":  f"PATH=/usr/bin\0{RUN_TOKEN_ENV}={token_value}\0".encode(),
        "271": f"{RUN_TOKEN_ENV}\0".encode(),
        "314": f"{RUN_TOKEN_ENV}={'bead' * 16}\0".encode(),
    }
    real_open = builtins.open
    real_isdir = os.path.isdir
    real_listdir = os.listdir

    def fake_isdir(path):
        return True if os.fspath(path) == "/proc" else real_isdir(path)

    def fake_listdir(path):
        if os.fspath(path) == "/proc":
            return list(envs.keys()) + ["self", "acpi", "stat"]
        return real_listdir(path)

    def fake_open(file, mode="r", *args, **kwargs):
        s = os.fspath(file)
        if s.startswith("/proc/") and s.endswith("/environ"):
            pid = s.split("/")[2]
            data = envs.get(pid)
            if data is None:
                raise PermissionError(13, "Permission denied", s)
            return io.BytesIO(data)
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(os.path, "isdir", fake_isdir)
    monkeypatch.setattr(os, "listdir", fake_listdir)
    monkeypatch.setattr(builtins, "open", fake_open)

    hits = TrustedRunner._scan_token_pids(needle_pair)
    _ck("结构腿：linux 分支仅完整 NAME=value 命中（42 且仅 42）",
        hits == {42}, f"hits={sorted(hits)}")
    _ck("结构腿：裸名/异值/前缀撞车/不可读/非数字目录全部不误杀",
        not (hits & {1, 7, 271, 314}), f"hits={sorted(hits)}")
    # 异值不命中（结构面复述真腿负例，防桩位漂移）
    miss = TrustedRunner._scan_token_pids(
        f"{RUN_TOKEN_ENV}={'beef' * 16}")
    _ck("结构腿：异值 token 零命中", miss == set(), f"miss={sorted(miss)}")


def test_scan_token_pids_linux_branch_structural(monkeypatch, tmp_path):
    """结构腿：monkeypatch /proc 布局，断言 linux 分支解析语义。"""
    before = len(FAILURES)
    _structural_linux_branch(monkeypatch, str(tmp_path))
    assert len(FAILURES) == before, f"失败项: {FAILURES[before:]}"


# ══════════════════════════════════════════════════════════════════════
# 自跑器（与仓内其他 test_* 双模一致：python3 直跑 exit 0=全绿）
# ══════════════════════════════════════════════════════════════════════
class _StubMonkeyPatch:
    """__main__ 模式的 monkeypatch 最小替身（setattr 后不还原，进程即弃）。"""

    def setattr(self, target, name, value):
        if isinstance(target, str):
            raise NotImplementedError("按对象打桩即可")
        setattr(target, name, value)


if __name__ == "__main__":
    import tempfile

    print("== Runner Linux /proc token 扫杀通路测试 ==")
    with tempfile.TemporaryDirectory(prefix="wq-linux-proc-") as td:
        if _IS_LINUX:
            print("-- test_linux_real_token_scan_hits_and_converges（真腿）")
            _real_scan_and_converge(td)
            print("-- test_linux_real_runner_timeout_kills_escaped_daemon（真腿）")
            _real_runner_timeout_kills_daemon(td)
        else:
            print(f"  ⏭ SKIP（非 Linux 平台）：{LINUX_ONLY_REASON}")
        print("-- test_scan_token_pids_linux_branch_structural（结构腿）")
        _structural_linux_branch(_StubMonkeyPatch(), td)
    print("=" * 40)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        for f in FAILURES:
            print(f"  ✗ {f}")
    sys.exit(1 if FAIL_N else 0)

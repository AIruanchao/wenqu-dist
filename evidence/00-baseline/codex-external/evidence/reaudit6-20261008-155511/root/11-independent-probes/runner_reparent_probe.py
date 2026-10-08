#!/usr/bin/env python3
"""第六轮独立 Runner 后台重挂接探针；只清理本探针记录的 PID。"""
from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(os.environ["WQ_FROZEN_REPO"])
sys.path.insert(0, str(REPO / "system"))
from wenqu_core.runner import RUN_TOKEN_ENV, TrustedRunner


PARENT = r'''
import os, subprocess, sys, time
worker, marker, pidfile = sys.argv[1:]
p = subprocess.Popen([sys.executable, worker, marker], start_new_session=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, close_fds=True)
open(pidfile, "w").write(str(p.pid))
# 保持直接父存活至 runner timeout；后台 worker 已逃离进程组。
time.sleep(30)
'''

WORKER = r'''
import os, sys, time
time.sleep(1.8)
open(sys.argv[1], "w").write(os.environ.get("__WENQU_RUN_TOKEN__", "MISSING"))
time.sleep(30)
'''


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def main():
    results = []
    for i in range(3):
        with tempfile.TemporaryDirectory(prefix=f"reaudit6-runner-{i}-") as td:
            parent = Path(td, "parent.py")
            worker = Path(td, "worker.py")
            marker = Path(td, "LATE_MARKER")
            pidfile = Path(td, "worker.pid")
            parent.write_text(PARENT, encoding="utf-8")
            worker.write_text(WORKER, encoding="utf-8")
            # 外部同名假值必须被 runner 内部随机哨兵覆盖；父/后台继承真实 token。
            os.environ[RUN_TOKEN_ENV] = "ATTACKER_CONTROLLED_SENTINEL"
            ev = TrustedRunner(timeout=0.45).run(
                [sys.executable, str(parent), str(worker), str(marker), str(pidfile)])
            time.sleep(2.3)
            pid = int(pidfile.read_text()) if pidfile.exists() else -1
            is_alive = alive(pid) if pid > 1 else False
            marker_exists = marker.exists()
            # 若产品失败，仅杀本探针自己记录的后台 PID，不作任何广泛扫描/清理。
            if is_alive:
                os.kill(pid, signal.SIGKILL)
            row = {
                "round": i + 1, "timed_out": ev.timed_out,
                "actual_exit_code": ev.actual_exit_code,
                "worker_pid": pid, "worker_alive_after_window": is_alive,
                "marker_exists": marker_exists,
            }
            results.append(row)
            print(json.dumps(row, ensure_ascii=False, sort_keys=True))
    os.environ.pop(RUN_TOKEN_ENV, None)
    assert all(r["timed_out"] is True for r in results)
    assert all(not r["worker_alive_after_window"] for r in results)
    assert all(not r["marker_exists"] for r in results)
    print(json.dumps({"result": "PASS", "rounds": len(results)}, sort_keys=True))


if __name__ == "__main__":
    main()

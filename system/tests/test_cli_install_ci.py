#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F4 第四轮三洞回归夹具——安装断链 / CI 挂载缺失 / gate 接线（Codex 四审复验面）。

洞 -> 测试映射：
  F4-CLI-001  安装体 wenquctl 断链（壳找 $PREFIX/wenqu_core，实体在 lib）
    -> test_h1_source_tree_wenquctl_runs
    -> test_h1_install_body_wenquctl_green_and_missing_cli_red
  F4-CI-001   对抗/加固自测不在 required CI（删双文件 acceptance 仍绿）
    -> test_h2_acceptance_red_when_adversarial_and_hardening_deleted
  F4-GATE-001 GateAggregator 无生产调用方
    -> test_h3_gate_two_legal_v2_pass_exit_0
    -> test_h3_gate_malformed_result_blocked_exit_2
    -> test_h3_gate_missing_required_station_blocked_exit_2
    -> test_h3_gate_exit_code_map_conditional_and_error

纯标准库；`python3 system/tests/test_cli_install_ci.py`（exit 0=全绿），兼容 pytest。
所有破坏性验证均在 tempfile 隔离副本上进行，绝不触碰真仓与真实 $HOME。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
DIST_ROOT = os.path.dirname(REPO)                                    # 发行包根
sys.path.insert(0, REPO)

from wenqu_core.bugscan_orchestrator import build_station_result  # noqa: E402

SHA = "1f" + "0" * 38
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


def _tail(text, n=200):
    return (text or "").replace("\n", " | ")[-n:]


def _copy_system(td, name="system"):
    dst = os.path.join(td, name)
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def _run_install(src_system, prefix, fake_home):
    """隔离安装（镜像 test_infra_hardening._run_install 的最小 env 口径）。"""
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": fake_home,
        "TMPDIR": tempfile.gettempdir(),
    }
    return subprocess.run(
        ["bash", os.path.join(src_system, "install.sh"), "--prefix", prefix],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=os.path.dirname(prefix.rstrip("/")))


def _run_ctl(argv, cwd, timeout=120):
    """经 bin/wenquctl 壳调 CLI（顺带回归壳的双布局解析——源树分支）。"""
    return subprocess.run(
        ["bash", os.path.join(REPO, "bin", "wenquctl")] + argv,
        capture_output=True, text=True, timeout=timeout, cwd=cwd)


# ══════════════════════════════════════════════════════════════════════
# H1：安装体 wenquctl 断链（F4-CLI-001）
# ══════════════════════════════════════════════════════════════════════
def test_h1_source_tree_wenquctl_runs():
    r = _run_ctl(["--help"], cwd=tempfile.gettempdir())
    _ck("H1 源树 wenquctl --help rc=0（双布局解析不伤源树运行）",
        r.returncode == 0, _tail(r.stderr))


def test_h1_install_body_wenquctl_green_and_missing_cli_red():
    with tempfile.TemporaryDirectory(prefix="wq_h1_") as td:
        syscopy = _copy_system(td)
        prefix = os.path.join(td, "prefix")
        fake_home = os.path.join(td, "home")
        os.makedirs(prefix)
        os.makedirs(fake_home)

        r = _run_install(syscopy, prefix, fake_home)
        _ck("H1 隔离安装 rc=0", r.returncode == 0, _tail(r.stdout + r.stderr))
        _ck("H1 安装日志含安装体 wenquctl 验证行",
            "安装体 wenquctl 验证通过" in (r.stdout + r.stderr),
            _tail(r.stdout + r.stderr))

        help_rc = subprocess.run(
            [os.path.join(prefix, "bin", "wenquctl"), "--help"],
            capture_output=True, text=True, timeout=60,
            cwd=td, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                         "HOME": fake_home, "TMPDIR": tempfile.gettempdir()})
        _ck("H1 安装体 <prefix>/bin/wenquctl --help rc=0（断链已修）",
            help_rc.returncode == 0, _tail(help_rc.stderr))

        # 红探针：源副本删 cli.py -> 安装必须 fail-closed（rc!=0）
        os.remove(os.path.join(syscopy, "wenqu_core", "cli.py"))
        prefix2 = os.path.join(td, "prefix2")
        fake_home2 = os.path.join(td, "home2")
        os.makedirs(prefix2)
        os.makedirs(fake_home2)
        r2 = _run_install(syscopy, prefix2, fake_home2)
        _ck("H1 删 wenqu_core/cli.py 后安装 rc!=0（安装体断链即安装失败）",
            r2.returncode != 0, _tail(r2.stdout + r2.stderr))
        _ck("H1 失败原因指向 wenquctl 断链",
            "wenquctl" in (r2.stdout + r2.stderr), _tail(r2.stderr))


# ══════════════════════════════════════════════════════════════════════
# H2：对抗/加固自测接入 required CI（F4-CI-001）
# ══════════════════════════════════════════════════════════════════════
def test_h2_acceptance_red_when_adversarial_and_hardening_deleted():
    with tempfile.TemporaryDirectory(prefix="wq_h2_") as td:
        tree = os.path.join(td, "tree")
        os.makedirs(tree)
        for d in ("cli", "probes", "system", "tests", "tools", "evidence", "docs"):
            shutil.copytree(os.path.join(DIST_ROOT, d), os.path.join(tree, d),
                            ignore=shutil.ignore_patterns("__pycache__"))
        os.remove(os.path.join(tree, "system", "tests",
                               "test_wenqu_adversarial.py"))
        os.remove(os.path.join(tree, "system", "tests",
                               "test_infra_hardening.py"))
        fake_home = os.path.join(td, "fakehome")
        os.makedirs(fake_home)
        r = subprocess.run(
            ["bash", os.path.join(tree, "tests", "acceptance.sh")],
            capture_output=True, text=True, timeout=600, cwd=tree,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                 "HOME": fake_home, "TMPDIR": tempfile.gettempdir()})
        out = r.stdout + r.stderr
        _ck("H2 删双测文件后 acceptance rc!=0",
            r.returncode != 0, _tail(out, 300))
        _ck("H2 P1d 红（adversarial 被删必红）",
            "test_wenqu_adversarial.py 不存在" in out, _tail(out, 300))
        _ck("H2 P1e 红（infra hardening 被删必红）",
            "test_infra_hardening.py 不存在" in out, _tail(out, 300))


# ══════════════════════════════════════════════════════════════════════
# H3：gate 子命令——GateAggregator 首个生产消费者（F4-GATE-001）
# ══════════════════════════════════════════════════════════════════════
def _mk_v2(station_id, verdict="PASS", run_id="run-gate-cli-1",
           sha=SHA, env="staging"):
    """经 build_station_result 构造合法 v2 站结果（schema 可执行等价物把关）。"""
    return build_station_result(
        run_id=run_id, station_id=station_id, attempt_id=f"att-{station_id}",
        execution_status="COMPLETED", policy_verdict=verdict,
        identity={"project_id": "acme/erp", "commit_sha": sha,
                  "environment": env, "scope_hash": "0" * 64,
                  "ruleset_hash": "0" * 64},
        tool={"name": "cli-gate-fixture", "version": "1.0"},
        execution={"argv_digest": "b" * 64,
                   "started_at": "2026-10-08T00:00:00Z",
                   "ended_at": "2026-10-08T00:00:01Z",
                   "actual_exit_code": 0, "expected_exit_set": [0],
                   "assertion_verdict": "PASS"},
        coverage={"denominator": 3, "scanned": 3},
        artifacts=[{"cas_digest": "sha256:" + "c" * 64, "size": 128}])


def _write(doc, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False)


def test_h3_gate_two_legal_v2_pass_exit_0():
    with tempfile.TemporaryDirectory(prefix="wq_h3a_") as td:
        # 站 2 落单文件、站 7 落目录（顺带验目录展开语义）
        _write(_mk_v2(2), os.path.join(td, "s2.json"))
        batch = os.path.join(td, "batch")
        os.makedirs(batch)
        _write(_mk_v2(7), os.path.join(batch, "s7.json"))
        r = _run_ctl(["gate", "--results",
                      os.path.join(td, "s2.json"), batch,
                      "--allow-self-declared"], cwd=td)
        _ck("H3 两合法 v2 站 -> rc=0", r.returncode == 0,
            f"rc={r.returncode} {_tail(r.stderr)}")
        try:
            agg = json.loads(r.stdout)
        except json.JSONDecodeError:
            agg = {}
        _ck("H3 聚合输出 policy_verdict=PASS", agg.get("policy_verdict") == "PASS",
            _tail(r.stdout))
        _ck("H3 聚合输出 aggregate_outcome=PASS 且 2 必报站齐",
            agg.get("aggregate_outcome") == "PASS"
            and agg.get("counts", {}).get("required_total") == 2,
            _tail(r.stdout))
        _ck("H3 dashboard 契约字段在（generated_at+policy_verdict）",
            bool(agg.get("generated_at")) and "policy_verdict" in agg,
            _tail(r.stdout))


def test_h3_gate_malformed_result_blocked_exit_2():
    with tempfile.TemporaryDirectory(prefix="wq_h3b_") as td:
        _write(_mk_v2(2), os.path.join(td, "s2.json"))
        bad = _mk_v2(3, run_id="run-gate-cli-2")
        bad.pop("identity")        # 残缺：无身份绑定
        bad.pop("artifacts")       # 残缺：PASS 无工件凭证
        _write(bad, os.path.join(td, "bad.json"))
        r = _run_ctl(["gate", "--results", os.path.join(td, "s2.json"),
                      os.path.join(td, "bad.json"),
                      "--allow-self-declared"], cwd=td)
        _ck("H3 残缺结果 -> rc=2", r.returncode == 2,
            f"rc={r.returncode} {_tail(r.stderr)}")
        try:
            agg = json.loads(r.stdout)
        except json.JSONDecodeError:
            agg = {}
        _ck("H3 残缺结果聚合 BLOCKED（schema violation 计入 reason）",
            agg.get("aggregate_outcome") == "BLOCKED"
            and "schema violation" in (agg.get("reason") or ""),
            _tail(r.stdout))


def test_h3_gate_missing_required_station_blocked_exit_2():
    with tempfile.TemporaryDirectory(prefix="wq_h3c_") as td:
        _write(_mk_v2(2), os.path.join(td, "s2.json"))
        r = _run_ctl(["gate", "--results", os.path.join(td, "s2.json"),
                      "--required", "2,7",
                      "--allow-self-declared"], cwd=td)
        _ck("H3 required 站缺报（只报 2 缺 7）-> rc=2", r.returncode == 2,
            f"rc={r.returncode} {_tail(r.stderr)}")
        try:
            agg = json.loads(r.stdout)
        except json.JSONDecodeError:
            agg = {}
        _ck("H3 分母缩水 BLOCKED（denominator_shrinkage）",
            agg.get("aggregate_outcome") == "BLOCKED"
            and "denominator_shrinkage" in "".join(agg.get("reasons", [])),
            _tail(r.stdout))


def test_h3_gate_exit_code_map_conditional_and_error():
    with tempfile.TemporaryDirectory(prefix="wq_h3d_") as td:
        _write(_mk_v2(4, verdict="CONDITIONAL"), os.path.join(td, "cond.json"))
        r = _run_ctl(["gate", "--results", os.path.join(td, "cond.json"),
                     "--allow-self-declared"], cwd=td)
        _ck("H3 CONDITIONAL -> rc=1（软条件绝不上绿）", r.returncode == 1,
            f"rc={r.returncode} {_tail(r.stderr)}")
        r2 = _run_ctl(["gate", "--results", os.path.join(td, "nope.json")],
                      cwd=td)
        _ck("H3 输入不可读 -> rc=3（ERROR 与 BLOCKED 分流）",
            r2.returncode == 3, f"rc={r2.returncode} {_tail(r2.stderr)}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_h") and callable(v)]
    print(f"== F4 三洞回归夹具（{len(tests)} 组）==")
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

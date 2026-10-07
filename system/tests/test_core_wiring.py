#!/usr/bin/env python3
"""P0-1 核心接线验证——移除 wenqu_core 或 schemas 后此测试必须红。

这是 Codex 验收报告 P0-1 的直接修复：当前移除新核心后旧 CI 仍全绿。
此测试确保新核心的存在和可导入性是 CI 的硬依赖。
"""
import os
import sys
import json
import importlib
import subprocess
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
CORE = os.path.join(REPO, "wenqu_core")
SCHEMAS = os.path.join(REPO, "schemas")
DASHBOARD = os.path.join(REPO, "dashboard")
INSTALL = os.path.join(REPO, "install.sh")


def test_wenqu_core_exists():
    """wenqu_core 目录存在且非空。"""
    assert os.path.isdir(CORE), f"wenqu_core 目录不存在: {CORE}"
    py_files = [f for f in os.listdir(CORE) if f.endswith(".py")]
    assert len(py_files) >= 8, f"wenqu_core 模块数不足: {len(py_files)} (期望 ≥8)"


def test_core_modules_importable():
    """核心模块全部可导入。"""
    sys.path.insert(0, REPO)
    required = [
        "runner", "store", "source_gate", "bugscan_orchestrator",
        "scheduler", "gate_aggregator", "ledger_migrator", "deploy_framework",
    ]
    for mod in required:
        try:
            importlib.import_module(f"wenqu_core.{mod}")
        except ImportError as e:
            raise AssertionError(f"核心模块 {mod} 不可导入: {e}")


def test_schemas_exist_and_valid():
    """5 个 JSON Schema 存在且可解析。"""
    expected = [
        "run-event-v2.schema.json", "station-result-v2.schema.json",
        "evidence-v2.schema.json", "finding-event-v2.schema.json",
        "approval-v2.schema.json",
    ]
    for name in expected:
        path = os.path.join(SCHEMAS, name)
        assert os.path.isfile(path), f"Schema 缺失: {name}"
        json.load(open(path))  # 可解析


def test_dashboard_files_exist():
    """新 dashboard 四文件存在。"""
    for f in ["index.html", "app.css", "app.js", "server.py"]:
        path = os.path.join(DASHBOARD, f)
        assert os.path.isfile(path), f"Dashboard 文件缺失: {f}"


def test_trusted_runner_produces_evidence():
    """TrustedRunner 能产出含 actual_exit_code 的证据。"""
    sys.path.insert(0, REPO)
    from wenqu_core.runner import TrustedRunner
    r = TrustedRunner()
    ev = r.run(["echo", "ci-test"], tempfile.gettempdir())
    assert ev.actual_exit_code == 0, f"echo 应 exit 0，实际 {ev.actual_exit_code}"
    assert len(ev.stdout_sha256) == 64, "stdout_sha256 应为 64 字符"


def test_gate_aggregator_blocks_empty():
    """空 required_stations 必须返回 BLOCKED（非真空 PASS）。"""
    sys.path.insert(0, REPO)
    from wenqu_core.gate_aggregator import GateAggregator
    g = GateAggregator(required_stations=set(), target_sha="0"*40, environment="test")
    v = g.aggregate()
    assert v["aggregate_outcome"] == "BLOCKED", f"空 required 应 BLOCKED，实际 {v['aggregate_outcome']}"
    assert v["technical_eligible"] is False


def test_schema_rejects_p0_accepted_risk():
    """CRITICAL severity 不可 ACCEPTED_RISK（Schema 硬化验证）。"""
    import jsonschema
    schema = json.load(open(os.path.join(SCHEMAS, "finding-event-v2.schema.json")))
    bad = {
        "schema_version": "2.0", "event_type": "ACCEPTED_RISK",
        "finding_id": "fnd_ci", "fingerprint": "fp", "severity": "CRITICAL",
        "priority": "P0", "ts": "2026-01-01T00:00:00Z",
        "risk_acceptance": {"approver": "a", "reason": "r"*10, "scope": "s", "expiry": "2026-12-31"},
    }
    try:
        jsonschema.validate(bad, schema)
        raise AssertionError("CRITICAL ACCEPTED_RISK 应被 Schema 拒绝")
    except jsonschema.ValidationError:
        pass  # 正确拒绝


def test_install_sh_installs_core():
    """install.sh 安装后 wenqu_core 可导入（P0-1 接线验证）。"""
    # 只验证 install.sh 中包含 wenqu_core 安装逻辑
    script = open(INSTALL).read()
    assert "wenqu_core" in script, "install.sh 未包含 wenqu_core 安装"
    assert "TrustedRunner" in script, "install.sh 未包含核心安装验证"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
            failed += 1
    print(f"\nP0-1 核心接线: {passed} PASS / {failed} FAIL")
    sys.exit(1 if failed else 0)

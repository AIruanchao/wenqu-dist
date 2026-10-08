#!/usr/bin/env python3
"""第六轮独立 Gate/Schema 探针。

注意：不导入、调用任何修复方 test_*；仅调用生产模块/API，并用独立
Draft-07 校验器、subprocess CLI 与 dashboard 读取函数交叉验证。
"""
from __future__ import annotations
import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

if len(sys.argv) != 2:
    raise SystemExit("usage: independent_gate_schema_probe.py ISOLATED_REPO")
ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "system"))

from jsonschema import Draft7Validator, FormatChecker  # type: ignore
from wenqu_core.gate_aggregator import (  # noqa: E402
    GateAggregator,
    mirror_validate_station_result_v2,
)

SHA = "a" * 40
ART_A = "sha256:" + "b" * 64
ART_B = "sha256:" + "c" * 64

# 独立注册 RFC3339 date-time 格式。当前宿主未安装 rfc3339-validator，
# jsonschema 默认 FormatChecker 会对 date-time 空转；审计不能把依赖缺失当合法。
STRICT_FORMAT = FormatChecker()
@STRICT_FORMAT.checks("date-time")
def _strict_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return False
    # RFC3339 date-time 必须含 T/t 与 Z/z 或数值 offset；纯日期、naive 时间非法。
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})",
        value,
    ):
        return False
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        datetime.fromisoformat(text.replace("t", "T"))
        return True
    except ValueError:
        return False


def load_schema(name: str) -> dict:
    return json.loads((ROOT / "system" / "schemas" / name).read_text())

STATION_SCHEMA = load_schema("station-result-v2.schema.json")
EVIDENCE_SCHEMA = load_schema("evidence-v2.schema.json")
FINDING_SCHEMA = load_schema("finding-event-v2.schema.json")
RUN_SCHEMA = load_schema("run-event-v2.schema.json")


def errors(schema: dict, doc: object) -> List[str]:
    validator = Draft7Validator(schema, format_checker=STRICT_FORMAT)
    return [f"{list(e.path)}: {e.message}" for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.path))]


def station(
    sid: int = 0,
    *,
    verdict: str = "PASS",
    execution_status: str = "COMPLETED",
    denom: int = 3,
    scanned: int = 3,
    attempt: str = "attempt-independent-1",
    scope_hash: str = "scope-frozen-001",
    started: str = "2026-10-08T00:00:00Z",
    ended: str = "2026-10-08T00:00:01Z",
    exit_code: int = 0,
    assertion: str = "PASS",
    artifact: str = ART_A,
) -> dict:
    return {
        "schema_version": "2.0",
        "run_id": "run_independent_6",
        "station_id": sid,
        "attempt_id": attempt,
        "execution_status": execution_status,
        "policy_verdict": verdict,
        "identity": {
            "commit_sha": SHA,
            "environment": "local",
            "scope_hash": scope_hash,
        },
        "tool": {"name": "independent-probe", "version": "6"},
        "execution": {
            "argv_digest": "argv-independent",
            "started_at": started,
            "ended_at": ended,
            "actual_exit_code": exit_code,
            "expected_exit_set": [0],
            "assertion_verdict": assertion,
        },
        "coverage": {"denominator": denom, "scanned": scanned},
        "finding_ids": [],
        "artifacts": [{"cas_digest": artifact, "size": 17}],
    }


def evidence(*, verdict: str = "PASS", exit_code: int = 0, finished: str = "2026-10-08T00:00:01Z") -> dict:
    return {
        "schema_version": "2.0",
        "evidence_id": "ev_independent_6",
        "run_id": "run_independent_6",
        "identity": {"commit_sha": SHA, "environment": "local", "scope_hash": "scope-frozen-001"},
        "tool": {"name": "probe", "version": "6"},
        "runner": {"runner_id": "runner-independent", "version": "6"},
        "execution": {
            "argv_digest": "argv-independent",
            "started_at": "2026-10-08T00:00:00Z",
            "finished_at": finished,
            "actual_exit_code": exit_code,
        },
        "verdict": verdict,
        "artifact": {"artifact_sha256": "d" * 64, "artifact_size": 17},
        "fresh_until": "2026-10-09T00:00:00Z",
    }


def finding(event_type: str, **over: object) -> dict:
    d: Dict[str, object] = {
        "schema_version": "2.0",
        "event_type": event_type,
        "finding_id": "fnd_independent_6",
        "fingerprint": "fp-independent",
        "severity": "MEDIUM",
        "priority": "P2",
        "ts": "2026-10-08T00:00:00Z",
    }
    d.update(over)
    return d


def run_event(execution_status: str = "COMPLETED", verdict: str = "PASS") -> dict:
    return {
        "schema_version": "2.0",
        "event_type": "RUN_COMPLETED",
        "run_id": "run_independent_6",
        "execution_status": execution_status,
        "policy_verdict": verdict,
        "identity": {"commit_sha": SHA, "environment": "local", "scope_hash": "scope-frozen-001"},
    }


def aggregate(docs: List[dict], required: set[str]) -> dict:
    agg = GateAggregator(required, SHA, "local")
    for doc in docs:
        agg.add(doc)
    return agg.aggregate()


def run_cli(docs: List[object], required: str | None = None, *, raw_path: str | None = None) -> Tuple[int, str, str, dict | None]:
    with tempfile.TemporaryDirectory(prefix="reaudit6-cli-") as td:
        if raw_path is None:
            paths = []
            for i, doc in enumerate(docs):
                p = Path(td) / f"result-{i}.json"
                p.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
                paths.append(str(p))
        else:
            paths = [raw_path]
        argv = [str(ROOT / "system" / "bin" / "wenquctl"), "gate", "--results", *paths]
        if required is not None:
            argv += ["--required", required]
        proc = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True)
        payload = None
        if proc.stdout.strip():
            try:
                payload = json.loads(proc.stdout.strip().splitlines()[-1])
            except json.JSONDecodeError:
                pass
        return proc.returncode, proc.stdout, proc.stderr, payload


rows: List[Tuple[str, bool, str]] = []
findings: List[str] = []

def check(name: str, cond: bool, detail: object = "", *, finding: str | None = None) -> None:
    rows.append((name, cond, str(detail)))
    print(("PASS" if cond else "FAIL") + f" | {name} | {detail}")
    if not cond and finding:
        findings.append(f"{finding}: {name}: {detail}")


print("=== 环境 ===")
print("repo=", ROOT)
print("python=", sys.version.replace("\n", " "))
try:
    import importlib.metadata
    print("jsonschema=", importlib.metadata.version("jsonschema"))
except Exception as exc:
    print("jsonschema-version-error=", repr(exc))
print("default_format_checker_has_datetime=", "date-time" in FormatChecker().checkers)

print("\n=== 旧探针08：合法 station-v2 -> aggregator -> dashboard / CLI ===")
valid_docs = [station(i, attempt=f"a-{i}", artifact="sha256:" + format(i + 1, "064x")) for i in (0, 3, 6)]
for d in valid_docs:
    check(f"station-{d['station_id']} Draft-07合法", not errors(STATION_SCHEMA, d), errors(STATION_SCHEMA, d))
    check(f"station-{d['station_id']}镜像合法", not mirror_validate_station_result_v2(d), mirror_validate_station_result_v2(d))
valid_agg = aggregate(valid_docs, {"0", "3", "6"})
check("合法三站聚合 PASS", valid_agg["aggregate_outcome"] == "PASS" and valid_agg["technical_eligible"] is True, valid_agg)
rc, out, err, p = run_cli(valid_docs, "0,3,6")
check("wenquctl gate 合法三站 rc=0", rc == 0 and p and p.get("aggregate_outcome") == "PASS", {"rc": rc, "stdout": out, "stderr": err})

# 独立加载 dashboard server，只调用只读解析函数。
spec = importlib.util.spec_from_file_location("reaudit6_dashboard_server", ROOT / "system" / "dashboard" / "server.py")
dash = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(dash)
with tempfile.TemporaryDirectory(prefix="reaudit6-dashboard-") as td:
    snap = Path(td) / "gate.json"
    snap.write_text(json.dumps(valid_agg), encoding="utf-8")
    old = os.environ.get("WENQU_GATE_AGGREGATE")
    os.environ["WENQU_GATE_AGGREGATE"] = str(snap)
    try:
        dash_read = dash.read_gate_aggregate()
    finally:
        if old is None:
            os.environ.pop("WENQU_GATE_AGGREGATE", None)
        else:
            os.environ["WENQU_GATE_AGGREGATE"] = old
check("dashboard 接受合法聚合快照", dash_read.get("ok") is True and dash_read.get("data", {}).get("policy_verdict") == "PASS", dash_read)

print("\n=== F4-GATE-001 基础 fail-closed 与分母/重复/coverage 对抗 ===")
minimal = {
    "schema_version": "2.0", "run_id": "run_independent_6", "station_id": 0,
    "attempt_id": "a", "execution_status": "COMPLETED", "policy_verdict": "PASS",
    "identity": {"commit_sha": SHA, "environment": "local", "scope_hash": "s"},
}
minimal_schema_errors = errors(STATION_SCHEMA, minimal)
minimal_out = aggregate([minimal], {"0"})
check("残缺 v2 被正式 schema 拒", bool(minimal_schema_errors), minimal_schema_errors)
check("残缺 v2 聚合 BLOCKED/technical=false/malformed", minimal_out["aggregate_outcome"] == "BLOCKED" and minimal_out["technical_eligible"] is False and minimal_out["counts"]["malformed"] >= 1, minimal_out)
rc, out, err, p = run_cli([minimal], "0")
check("残缺 v2 wenquctl rc=2", rc == 2 and p and p.get("technical_eligible") is False, {"rc": rc, "payload": p, "stderr": err})

missing_out = aggregate([station(0), station(3)], {"0", "3", "6"})
check("显式 required 缺站 BLOCKED", missing_out["aggregate_outcome"] == "BLOCKED" and missing_out["counts"]["required_missing"] == 1, missing_out)
empty_out = aggregate([station(0)], set())
check("空 required 直接聚合 BLOCKED", empty_out["aggregate_outcome"] == "BLOCKED" and empty_out["technical_eligible"] is False, empty_out)
rc, out, err, p = run_cli([station(0)], ",")
check("空 --required CLI ERROR rc=3", rc == 3 and p and p.get("aggregate_outcome") == "ERROR", {"rc": rc, "payload": p, "stderr": err})

conflict_b = station(0, verdict="CONDITIONAL", attempt="attempt-conflict")
conflict_out = aggregate([station(0), conflict_b], {"0"})
check("同站冲突裁决 BLOCKED", conflict_out["aggregate_outcome"] == "BLOCKED" and conflict_out["counts"]["conflicts"] == 1, conflict_out)

# 代码注释称“内容完全一致才幂等”。构造 outcome/SHA/env 相同，但 attempt、scope、
# coverage、artifact 全不同；若仍被当成 identical，是弱等价键导致的证据冲突吞没。
dup_a = station(0, attempt="attempt-A", scope_hash="scope-A", denom=1, scanned=1, artifact=ART_A)
dup_b = station(0, attempt="attempt-B", scope_hash="scope-B", denom=7, scanned=7, artifact=ART_B)
weak_dup_out = aggregate([dup_a, dup_b], {"0"})
check(
    "语义不同重复站不得被当作完全相同幂等上报",
    weak_dup_out["aggregate_outcome"] == "BLOCKED" and weak_dup_out["counts"]["conflicts"] == 1,
    weak_dup_out,
    finding="R6-GATE-DUP-001",
)

# 不传 --required 时，只提供一个本应属于更大 required 集合的站。CLI 没有 manifest/
# frozen plan 输入，无法得知缺站，当前会把“已上报集合”反推成分母并 PASS。
rc, out, err, p = run_cli([station(0)], None)
check(
    "省略 --required 时单站不能自举为完整分母 PASS",
    rc != 0 and p and p.get("aggregate_outcome") != "PASS",
    {"rc": rc, "payload": p, "stderr": err},
    finding="R6-GATE-SCOPE-001",
)

# coverage 是自报 1/1；schema/聚合器无 registry/run-manifest 分母绑定，无法识别真实
# 分母 99。这里记录可重放事实，不用文档声明代替实跑。
fake_cov = station(0, denom=1, scanned=1, scope_hash="caller-chosen-scope")
rc, out, err, p = run_cli([fake_cov], "0")
check(
    "自报 coverage=1/1 且 scope_hash 未绑定权威 manifest 不得 PASS",
    rc != 0 and p and p.get("aggregate_outcome") != "PASS",
    {"rc": rc, "payload": p, "declared_expected_denominator": 99},
    finding="R6-GATE-COVERAGE-001",
)

print("\n=== Draft-07 全量镜像差分：format/date-time 与合法扩展 ===")
# RFC3339 的 date-time 必须有时间+offset。datetime.fromisoformat 接受纯日期，
# 生产 mirror 也会接受，形成 schema-invalid -> PASS。
for bad_ts in ("2026-10-08", "2026-10-08T00:00:00"):
    d = station(0, started=bad_ts, ended=bad_ts)
    e = errors(STATION_SCHEMA, d)
    m = mirror_validate_station_result_v2(d)
    a = aggregate([d], {"0"})
    rc, out, err, p = run_cli([d], "0")
    check(f"严格 Draft-07 format 拒绝 {bad_ts!r}", bool(e), e)
    check(
        f"镜像/聚合/CLI 同步拒绝 schema-invalid date-time {bad_ts!r}",
        bool(m) and a["aggregate_outcome"] == "BLOCKED" and rc == 2,
        {"mirror_errors": m, "aggregate": a, "cli_rc": rc, "cli_payload": p},
        finding="R6-GATE-FORMAT-001",
    )

# schema 嵌套对象默认允许扩展。生产 mirror 接受；CLI 的另一套内置 validator
# 私自收紧 identity/execution/coverage，导致正式 schema 合法输入被 BLOCKED。
extended = station(0)
extended["identity"]["future_binding"] = "v3-forward-field"
check("带嵌套扩展的 station 是正式 schema 合法输入", not errors(STATION_SCHEMA, extended), errors(STATION_SCHEMA, extended))
check("镜像接受正式 schema 合法扩展", not mirror_validate_station_result_v2(extended), mirror_validate_station_result_v2(extended))
rc, out, err, p = run_cli([extended], "0")
check(
    "wenquctl 不得拒绝正式 schema 合法扩展",
    rc == 0 and p and p.get("aggregate_outcome") == "PASS",
    {"rc": rc, "payload": p, "stderr": err},
    finding="R6-GATE-EQUIV-001",
)

print("\n=== 四态 CLI 退出码与 NOT_APPLICABLE 边界 ===")
rc0 = run_cli([station(0)], "0")
rc1 = run_cli([station(0, verdict="CONDITIONAL")], "0")
rc2 = run_cli([station(0)], "0,1")
with tempfile.TemporaryDirectory(prefix="reaudit6-error-") as td:
    absent = str(Path(td) / "absent.json")
    rc3 = run_cli([], "0", raw_path=absent)
check("PASS -> rc0", rc0[0] == 0 and rc0[3] and rc0[3].get("aggregate_outcome") == "PASS", {"rc": rc0[0], "payload": rc0[3]})
check("CONDITIONAL -> rc1 且 technical=false", rc1[0] == 1 and rc1[3] and rc1[3].get("aggregate_outcome") == "CONDITIONAL" and rc1[3].get("technical_eligible") is False, {"rc": rc1[0], "payload": rc1[3]})
check("BLOCKED -> rc2", rc2[0] == 2 and rc2[3] and rc2[3].get("aggregate_outcome") == "BLOCKED", {"rc": rc2[0], "payload": rc2[3]})
check("ERROR -> rc3", rc3[0] == 3 and rc3[3] and rc3[3].get("aggregate_outcome") == "ERROR", {"rc": rc3[0], "payload": rc3[3], "stderr": rc3[2]})
na_completed = station(0, verdict="NOT_APPLICABLE")
rc, out, err, p = run_cli([na_completed], "0")
check("COMPLETED+NOT_APPLICABLE -> CONDITIONAL/rc1/不上绿", not errors(STATION_SCHEMA, na_completed) and rc == 1 and p and p.get("aggregate_outcome") == "CONDITIONAL" and p.get("technical_eligible") is False, {"schema_errors": errors(STATION_SCHEMA, na_completed), "rc": rc, "payload": p})
na_timeout = station(0, verdict="NOT_APPLICABLE", execution_status="TIMEOUT", exit_code=124, assertion="FAIL")
rc, out, err, p = run_cli([na_timeout], "0")
check("TIMEOUT+NOT_APPLICABLE 保留 schema 语义但聚合硬 BLOCKED", not errors(STATION_SCHEMA, na_timeout) and rc == 2 and p and p.get("aggregate_outcome") == "BLOCKED", {"schema_errors": errors(STATION_SCHEMA, na_timeout), "rc": rc, "payload": p})

print("\n=== F4-SCHEMA-001 五类与组合变异（独立 Draft-07） ===")
# evidence PASS + exit != 0
for name, doc, expect_valid in [
    ("evidence PASS+exit7", evidence(verdict="PASS", exit_code=7), False),
    ("evidence PASS+exit0", evidence(verdict="PASS", exit_code=0), True),
    ("evidence FAIL+exit7", evidence(verdict="FAIL", exit_code=7), True),
    ("evidence PASS+date-only", evidence(verdict="PASS", exit_code=0, finished="2026-10-08"), False),
]:
    e = errors(EVIDENCE_SCHEMA, doc)
    check(name + (" 合法" if expect_valid else " 拒绝"), (not e) == expect_valid, e)

# station PASS coverage / exit / assertion / status
schema_cases = [
    ("station PASS 2/3", station(0, denom=3, scanned=2), False),
    ("station PASS 3/3", station(0, denom=3, scanned=3), True),
    ("station PASS exit9", station(0, exit_code=9), False),
    ("station PASS assertion FAIL", station(0, assertion="FAIL"), False),
    ("station TIMEOUT+CONDITIONAL", station(0, execution_status="TIMEOUT", verdict="CONDITIONAL", exit_code=124, assertion="FAIL"), False),
    ("station COMPLETED+CONDITIONAL", station(0, verdict="CONDITIONAL"), True),
    ("station PASS 0/0", station(0, denom=0, scanned=0), False),
]
for name, doc, expect_valid in schema_cases:
    e = errors(STATION_SCHEMA, doc)
    check(name + (" 合法" if expect_valid else " 拒绝"), (not e) == expect_valid, e)

# 1..64 级联之外的自创组合：契约称 PASS 必须 scanned==denominator，
# 但 schema 对 scanned>64 无 equality/maximum，65/66 可直接过正式 validator。
big_shrink = station(0, denom=66, scanned=65)
big_err = errors(STATION_SCHEMA, big_shrink)
big_mirror = mirror_validate_station_result_v2(big_shrink)
check(
    "正式 station schema 对任意整数域都拒绝 PASS 65/66",
    bool(big_err),
    {"schema_errors": big_err, "mirror_errors": big_mirror},
    finding="R6-SCHEMA-BOUND-001",
)
check("聚合镜像补拦 PASS 65/66", bool(big_mirror) and aggregate([big_shrink], {"0"})["aggregate_outcome"] == "BLOCKED", {"mirror_errors": big_mirror, "aggregate": aggregate([big_shrink], {"0"})})

# finding 转移
finding_cases = [
    ("RISK_INVALIDATED 缺 state_from/state_to", finding("RISK_INVALIDATED"), False),
    ("RISK_INVALIDATED 完整", finding("RISK_INVALIDATED", state_from="ACCEPTED_RISK", state_to="OPEN"), True),
    ("SUPERSEDED 缺 state_from", finding("SUPERSEDED"), False),
    ("SUPERSEDED 从 OPEN", finding("SUPERSEDED", state_from="OPEN"), True),
    ("SUPERSEDED 伪 CLOSED 来源", finding("SUPERSEDED", state_from="CLOSED"), False),
    ("CLOSED 伪 RISK_INVALIDATED", finding("RISK_INVALIDATED", state_from="CLOSED", state_to="OPEN"), False),
]
for name, doc, expect_valid in finding_cases:
    e = errors(FINDING_SCHEMA, doc)
    check(name + (" 合法" if expect_valid else " 拒绝"), (not e) == expect_valid, e)

# 自创状态组合：FINDING_REOPENED 语义为转回 OPEN；从 ACCEPTED_RISK 时当前 schema
# 只要求 state_from，不要求 state_to，导致不完整转移被正式 schema 接受。
reopen_incomplete = finding("FINDING_REOPENED", state_from="ACCEPTED_RISK")
reopen_err = errors(FINDING_SCHEMA, reopen_incomplete)
check(
    "FINDING_REOPENED 从 ACCEPTED_RISK 必带 state_to=OPEN",
    bool(reopen_err),
    {"schema_errors": reopen_err, "document": reopen_incomplete},
    finding="R6-SCHEMA-REOPEN-001",
)

# run-event 双轴
for name, doc, expect_valid in [
    ("run TIMEOUT+CONDITIONAL", run_event("TIMEOUT", "CONDITIONAL"), False),
    ("run ERROR+PASS", run_event("ERROR", "PASS"), False),
    ("run COMPLETED+CONDITIONAL", run_event("COMPLETED", "CONDITIONAL"), True),
    ("run CANCELLED+NOT_EVALUATED", run_event("CANCELLED", "NOT_EVALUATED"), True),
]:
    e = errors(RUN_SCHEMA, doc)
    check(name + (" 合法" if expect_valid else " 拒绝"), (not e) == expect_valid, e)

print("\n=== 结果汇总 ===")
passed = sum(1 for _, ok, _ in rows if ok)
failed = len(rows) - passed
print(json.dumps({"checks": len(rows), "passed": passed, "failed": failed, "findings": findings}, ensure_ascii=False, indent=2))
# 审计语义：出现独立 finding 时非零，避免“脚本跑完=全绿”。
raise SystemExit(1 if findings else 0)

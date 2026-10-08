#!/usr/bin/env python3
"""第四轮独立复审：第三轮 12 项失败探针的异源反例。

只在 WENQU_REPO_COPY 指向的 /tmp git-archive 副本加载代码；所有数据库、
CAS、进程 marker 与部署树均建在 tempfile 目录，不写产物仓。
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import sqlite3
import stat
import sys
import tempfile
import time
from typing import Any, Callable


REPO = os.environ.get("WENQU_REPO_COPY", "")
if not REPO or not os.path.isdir(REPO) or not REPO.startswith("/tmp/"):
    raise SystemExit("WENQU_REPO_COPY 必须指向 /tmp 下的隔离仓副本")
SYSTEM = os.path.join(REPO, "system")
sys.path.insert(0, SYSTEM)

from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope
from wenqu_core.deploy_framework import DeployError, DeployManager
from wenqu_core.gate_aggregator import GateAggregator
from wenqu_core.runner import Evidence, EvidenceStore, IntegrityError, TrustedRunner
import wenqu_core.runner as runner_mod
from wenqu_core.store import EventStore
import wenqu_core.wenqu_pipeline as wp
from wenqu_core.wenqu_pipeline import (
    ApprovalPreconditionError,
    ApprovalRejected,
    ApprovalReuseError,
    PipelineCorruptionError,
    PipelineError,
    RunManager,
    SevenStageStateMachine as SM,
)


KEY_ID = "key_reaudit4_independent"
TEST_SECRET = "reaudit4-ephemeral-test-secret-not-production"
KEYRING = ApprovalKeyring({KEY_ID: TEST_SECRET})
IDENT = {
    "commit_sha": "c" * 40,
    "environment": "staging",
    "scope_hash": "scope:reaudit4:isolated",
    "repo_id": "internal/wenqu-isolated",
    "ruleset_hash": "rules:reaudit4",
    "policy_hash": "policy:reaudit4",
}


class AuditFailure(AssertionError):
    pass


class Recorder:
    def __init__(self, probe: str, title: str) -> None:
        self.probe = probe
        self.title = title
        self.checks: list[dict[str, Any]] = []

    def require(self, condition: bool, check: str, **detail: Any) -> None:
        row = {"check": check, "ok": bool(condition), **detail}
        self.checks.append(row)
        print(json.dumps(row, ensure_ascii=False, sort_keys=True))
        if not condition:
            raise AuditFailure(f"{check}: {detail}")

    def expect(self, exc_type: type[BaseException], fn: Callable[[], Any],
               check: str, contains: str | None = None) -> BaseException:
        try:
            value = fn()
        except exc_type as exc:
            text = f"{type(exc).__name__}: {exc}"
            ok = contains is None or contains in str(exc)
            self.require(ok, check, observed=text, expected_exception=exc_type.__name__)
            return exc
        except BaseException as exc:
            self.require(False, check, observed=f"{type(exc).__name__}: {exc}",
                         expected_exception=exc_type.__name__)
            raise
        self.require(False, check, observed=repr(value),
                     expected_exception=exc_type.__name__)
        raise AuditFailure(check)

    def done(self, **detail: Any) -> None:
        summary = {
            "probe": self.probe,
            "title": self.title,
            "result": "PASS",
            "checks": len(self.checks),
            "repo_copy": REPO,
            "loaded_pipeline": wp.__file__,
            **detail,
        }
        print("PROBE_RESULT=" + json.dumps(summary, ensure_ascii=False, sort_keys=True))


def fresh(prefix: str) -> tuple[str, EventStore, RunManager]:
    td = tempfile.mkdtemp(prefix=f"reaudit4-{prefix}-", dir="/tmp")
    store = EventStore(os.path.join(td, "events.sqlite3"))
    return td, store, RunManager(store, keyring=KEYRING)


def resign(ap: dict[str, Any]) -> dict[str, Any]:
    ap = copy.deepcopy(ap)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(TEST_SECRET, ap)
    return ap


def waiting_run(mgr: RunManager, task: str, stop_type: str,
                reason: str = "reaudit4 independent wait") -> tuple[str, dict[str, Any]]:
    run_id = mgr.create_run(task, IDENT)["run_id"]
    mgr.advance_stage(run_id)
    wait = mgr.raise_waiting(run_id, stop_type, reason)
    return run_id, wait


def make_resume(mgr: RunManager, run_id: str, wait: dict[str, Any],
                pre: dict[str, Any], *, nonce: str, approval_id: str,
                actor: str = "independent-reviewer") -> dict[str, Any]:
    state = mgr.get_run(run_id)
    ap = {
        "schema_version": "2.0",
        "approval_id": approval_id,
        "approval_type": "resume",
        "key_id": KEY_ID,
        "run_id": run_id,
        "task_id": state.task_id,
        "stop_event_id": wait["stop_event_id"],
        "stop_type": wait["stop_type"],
        "stage": wait["stage"],
        "environment": state.identity["environment"],
        "authorized_scope": state.identity["scope_hash"],
        "policy_hash": state.identity["policy_hash"],
        "ruleset_hash": state.identity["ruleset_hash"],
        "input_watermark": state.identity["commit_sha"],
        "expected_state_version": state.state_version,
        "actor": actor,
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "nonce": nonce,
        "decision": "approve",
        "payload": {
            "stop_event_id": wait["stop_event_id"],
            "stop_type": wait["stop_type"],
            "objective_precondition_hash": SM.objective_precondition_hash(pre),
        },
    }
    return resign(ap)


def make_risk(mgr: RunManager, run_id: str, *, nonce: str, approval_id: str,
              expected_version: int | None = None,
              fingerprints: list[str] | None = None,
              severity: str = "LOW") -> dict[str, Any]:
    state = mgr.get_run(run_id)
    anchor = state.current_stage or "S7_GATE"
    ap = {
        "schema_version": "2.0",
        "approval_id": approval_id,
        "approval_type": "risk",
        "key_id": KEY_ID,
        "run_id": run_id,
        "task_id": state.task_id,
        "stop_event_id": "risk-anchor-independent",
        "stop_type": "scope",
        "stage": anchor,
        "environment": state.identity["environment"],
        "authorized_scope": state.identity["scope_hash"],
        "policy_hash": state.identity["policy_hash"],
        "ruleset_hash": state.identity["ruleset_hash"],
        "input_watermark": state.identity["commit_sha"],
        "expected_state_version": (
            state.state_version if expected_version is None else expected_version
        ),
        "actor": "independent-reviewer",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "nonce": nonce,
        "decision": "approve",
        "payload": {
            "finding_fingerprints": list(fingerprints or []),
            "severity": severity,
            "reason": "independent fourth-round bounded risk",
            "compensating_controls": ["isolated-probe-only"],
            "expiry": "2098-12-31T00:00:00Z",
        },
    }
    return resign(ap)


def pass_first_six(mgr: RunManager, task: str) -> str:
    run_id = mgr.create_run(task, IDENT)["run_id"]
    for idx in range(6):
        out = mgr.advance_stage(run_id, execution_status="COMPLETED",
                                policy_verdict="PASS",
                                evidence_refs=[f"cas:reaudit4:{idx}"])
        if out.get("attempt_status") != "PASSED":
            raise AuditFailure(f"S{idx + 1} did not pass: {out}")
    return run_id


def probe01() -> None:
    r = Recorder("01", "伪签名+缺绑定：跨信封签名替换与已签缺字段均拒绝")
    _td, _store, mgr = fresh("p01")
    pre = {
        "dependency_probe_ref": "probe://dependency/recovered",
        "probe_recovered": True,
        "evidence_freshness_reverified": True,
    }
    run_id, wait = waiting_run(mgr, "reaudit4_p01", "ext-unavail")
    ap_a = make_resume(mgr, run_id, wait, pre,
                       nonce="reaudit4-p01-envelope-a-0001",
                       approval_id="apr_reaudit4_p01_a", actor="reviewer-A")
    ap_b = make_resume(mgr, run_id, wait, pre,
                       nonce="reaudit4-p01-envelope-b-0002",
                       approval_id="apr_reaudit4_p01_b", actor="reviewer-B")
    substituted = copy.deepcopy(ap_a)
    substituted["signature"] = ap_b["signature"]
    r.expect(ApprovalRejected,
             lambda: mgr.resume_waiting(run_id, substituted, pre),
             "完整信封替换另一有效信封的签名仍被 HMAC 拒绝", "signature")

    missing = copy.deepcopy(ap_a)
    del missing["policy_hash"]
    missing = resign(missing)  # 即便由已知测试 key 对缺字段信封重签，结构仍应拒绝
    r.expect(ApprovalRejected,
             lambda: mgr.resume_waiting(run_id, missing, pre),
             "已签但缺 exact policy_hash 绑定的信封被结构层拒绝",
             "policy_hash")
    state = mgr.get_run(run_id)
    r.require(state.state == "WAITING", "两次拒绝均未改变 run 状态",
              run_state=state.state, state_version=state.state_version)
    r.require(mgr.broker.consumed_approvals(run_id=run_id) == [],
              "两次拒绝均未消费 nonce")
    ok = mgr.resume_waiting(run_id, ap_a, pre)
    r.require(ok["resumed"] is True and mgr.get_run(run_id).state == "RUNNING",
              "同一基础信封的正确签名正例仍可恢复")
    r.done()


def probe02() -> None:
    r = Recorder("02", "risk 冒充 resume：API 路由与 payload 判别联合双层拒绝")
    _td, _store, mgr = fresh("p02")
    pre = {"gate_reference": "gate://reaudit4/p02", "rollback_level": "R2"}
    run_id, wait = waiting_run(mgr, "reaudit4_p02", "prod-write")

    risk = make_risk(mgr, run_id, nonce="reaudit4-p02-risk-route-0001",
                     approval_id="apr_reaudit4_p02_risk")
    r.expect(ApprovalRejected,
             lambda: mgr.resume_waiting(run_id, risk, pre),
             "结构合法的 risk 信封投递到 resume API 被路由拒绝", "resume")

    resume = make_resume(mgr, run_id, wait, pre,
                         nonce="reaudit4-p02-mixed-0002",
                         approval_id="apr_reaudit4_p02_resume")
    mixed = copy.deepcopy(resume)
    mixed["payload"]["severity"] = "LOW"  # resume 专属键齐全，再混入 risk 键
    mixed = resign(mixed)
    schema_path = os.path.join(SYSTEM, "schemas", "approval-v2.schema.json")
    import jsonschema
    schema = json.load(open(schema_path, encoding="utf-8"))
    schema_rejected = False
    try:
        jsonschema.Draft7Validator(schema).validate(mixed)
    except jsonschema.ValidationError as exc:
        schema_rejected = True
        print("SCHEMA_REJECTION=" + exc.message)
    r.require(schema_rejected, "正式 approval-v2 Schema 拒绝混合 payload")
    r.expect(ApprovalRejected,
             lambda: mgr.resume_waiting(run_id, mixed, pre),
             "Broker 镜像校验也拒绝混合 payload", "payload")
    r.require(mgr.get_run(run_id).state == "WAITING",
              "risk 路由/混合 payload 均未恢复 run")
    r.require(not mgr.broker.consumed_approvals(run_id=run_id),
              "拒绝路径无 nonce 消费副作用")
    r.require(mgr.resume_waiting(run_id, resume, pre)["resumed"] is True,
              "纯 resume 正例仍可恢复")
    r.done()


def probe03() -> None:
    r = Recorder("03", "未恢复资源：另一停等类型的大小写/空白字符串假布尔被拒")
    _td, _store, mgr = fresh("p03")
    bad_pre = {
        "dependency_probe_ref": "probe://ext-api/down",
        "probe_recovered": True,
        "evidence_freshness_reverified": " FALSE ",
    }
    run_id, wait = waiting_run(mgr, "reaudit4_p03", "ext-unavail")
    bad_ap = make_resume(mgr, run_id, wait, bad_pre,
                         nonce="reaudit4-p03-false-string-0001",
                         approval_id="apr_reaudit4_p03_bad")
    r.expect(ApprovalPreconditionError,
             lambda: mgr.resume_waiting(run_id, bad_ap, bad_pre),
             "字符串 ' FALSE ' 不能冒充客观布尔真值", "boolean")
    r.require(mgr.get_run(run_id).state == "WAITING",
              "假布尔拒绝后 run 保持 WAITING")
    r.require(not mgr.broker.consumed_approvals(run_id=run_id),
              "假布尔拒绝不占用 nonce")
    good_pre = dict(bad_pre, evidence_freshness_reverified=True)
    good_ap = make_resume(mgr, run_id, wait, good_pre,
                          nonce="reaudit4-p03-true-bool-0002",
                          approval_id="apr_reaudit4_p03_good")
    r.require(mgr.resume_waiting(run_id, good_ap, good_pre)["resumed"] is True,
              "真实 bool 正例可恢复")
    r.done()


def probe04() -> None:
    r = Recorder("04", "非 resume CAS：风险授权的历史版本拒绝且不消费")
    _td, _store, mgr = fresh("p04")
    run_id = mgr.create_run("reaudit4_p04", IDENT)["run_id"]
    mgr.advance_stage(run_id)  # state_version >=2，当前锚仍为 S1
    state = mgr.get_run(run_id)
    stale = make_risk(mgr, run_id, nonce="reaudit4-p04-stale-risk-0001",
                      approval_id="apr_reaudit4_p04_stale",
                      expected_version=state.state_version - 1,
                      fingerprints=[], severity="LOW")
    r.expect(ApprovalRejected, lambda: mgr.authorize_risk(run_id, stale),
             "历史 state_version 的 risk 授权被 CAS 拒绝", "state_version")
    state_after = mgr.get_run(run_id)
    r.require(state_after.state_version == state.state_version,
              "CAS 拒绝不推进 state_version",
              before=state.state_version, after=state_after.state_version)
    r.require(not mgr.broker.consumed_approvals(run_id=run_id),
              "CAS 拒绝不消费 risk nonce")
    current = make_risk(mgr, run_id, nonce="reaudit4-p04-current-risk-0002",
                        approval_id="apr_reaudit4_p04_current",
                        expected_version=state_after.state_version,
                        fingerprints=[], severity="LOW")
    r.require(mgr.authorize_risk(run_id, current)["consumed"] is True,
              "当前版本 risk 正例可消费")
    r.done()


def probe05() -> None:
    r = Recorder("05", "TIMEOUT/P1 洗白：执行轴与优先级终态两层都 fail-closed")
    _td, _store, mgr = fresh("p05a")
    timed = pass_first_six(mgr, "reaudit4_p05_timeout")
    out = mgr.advance_stage(timed, execution_status="TIMEOUT",
                            policy_verdict="CONDITIONAL",
                            findings=["fnd_timeout_independent"])
    r.require(out["attempt_status"] == "FAILED",
              "S7 TIMEOUT+CONDITIONAL 映射 FAILED 而非软终态",
              attempt_status=out["attempt_status"])
    terminal = mgr.complete_run(timed)
    r.require(terminal["final_state"] == "FAILED",
              "TIMEOUT run 最终为 FAILED 而非 COMPLETED_CONDITIONAL",
              final_state=terminal["final_state"])

    _td2, _store2, mgr2 = fresh("p05b")
    p1run = pass_first_six(mgr2, "reaudit4_p05_p1")
    soft = mgr2.advance_stage(p1run, execution_status="COMPLETED",
                              policy_verdict="CONDITIONAL",
                              findings=["fnd_p1_independent"])
    r.require(soft["attempt_status"] == "COMPLETED_CONDITIONAL",
              "对照：执行完成的 S7 条件项形成软终态")
    mgr2.register_finding(p1run, "fnd_p1_low", "fp-p1-low", "LOW", "P1")
    claimed = make_risk(mgr2, p1run, nonce="reaudit4-p05-p1-claim-0001",
                        approval_id="apr_reaudit4_p05_claim",
                        fingerprints=["fp-p1-low"], severity="LOW")
    r.expect(ApprovalRejected, lambda: mgr2.authorize_risk(p1run, claimed),
             "LOW/P1 指纹不能进入可风险接受集合", "精确匹配")

    empty_scope = make_risk(mgr2, p1run, nonce="reaudit4-p05-empty-scope-0002",
                            approval_id="apr_reaudit4_p05_empty",
                            fingerprints=[], severity="LOW")
    r.require(mgr2.authorize_risk(p1run, empty_scope)["consumed"] is True,
              "空覆盖面的合法授权作为终态三层校验对照已消费")
    r.expect(PipelineError, lambda: mgr2.complete_run(p1run),
             "即使存在授权，LOW/P1 finding 仍阻断条件完成", "P0/P1")
    r.require(mgr2.get_run(p1run).state == "RUNNING",
              "P1 终态拒绝后 run 未被洗为完成态",
              run_state=mgr2.get_run(p1run).state)
    r.done()


def probe06() -> None:
    r = Recorder("06", "控制事件直写：公共入口拒绝，绕过入口的偷 seal 事件重放拒绝")
    _td, store, mgr = fresh("p06a")
    run_id = mgr.create_run("reaudit4_p06_public", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    state = mgr.get_run(run_id)
    count_before = store._conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
    forged = {
        "schema_version": "2.0", "event_type": "SUPERSEDED",
        "run_id": run_id, "task_id": state.task_id,
        "execution_status": "CANCELLED", "policy_verdict": "NOT_EVALUATED",
        "identity": dict(state.identity), "state_version": state.state_version + 1,
        "ts": "2026-10-08T04:00:00Z", "actor": "untrusted-direct-writer",
        "supersede_reason": "forged terminal control",
    }
    r.expect(ValueError, lambda: store.append(forged),
             "公共 EventStore.append 拒绝伪造 SUPERSEDED 控制事件")
    count_after = store._conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
    r.require(count_after == count_before and mgr.get_run(run_id).state == "RUNNING",
              "入口拒绝无事件/状态副作用", before=count_before, after=count_after)

    _td2, store2, mgr2 = fresh("p06b")
    run2 = mgr2.create_run("reaudit4_p06_seal", IDENT)["run_id"]
    mgr2.advance_stage(run2)
    state2 = mgr2.get_run(run2)
    last_payload = json.loads(store2._conn.execute(
        "SELECT payload FROM pipeline_events ORDER BY seq DESC LIMIT 1"
    ).fetchone()[0])
    forged2 = dict(forged)
    forged2.update({"run_id": run2, "task_id": state2.task_id,
                    "identity": dict(state2.identity),
                    "state_version": state2.state_version + 1,
                    "seal": last_payload["seal"]})  # 复制合法事件 seal，但正文不同
    wp._PipelineDb.append_event(mgr2._db._conn, forged2)
    r.require(store2.verify_chain()["ok"] is True,
              "绕过公共 API 后哈希链本身仍可为真（攻击窗口成立）")
    r.expect(PipelineCorruptionError, lambda: mgr2.get_run(run2),
             "偷用另一事件 seal 的控制事件在重放层被拒", "seal")
    r.done()


def probe07() -> None:
    r = Recorder("07", "仅事件重放：risk nonce 在旁表为空的新库仍保持已消费")
    td, store1, mgr1 = fresh("p07-src")
    run_id = mgr1.create_run("reaudit4_p07", IDENT)["run_id"]
    mgr1.advance_stage(run_id)
    ap = make_risk(mgr1, run_id, nonce="reaudit4-p07-replay-risk-0001",
                   approval_id="apr_reaudit4_p07", fingerprints=[], severity="LOW")
    r.require(mgr1.authorize_risk(run_id, ap)["consumed"] is True,
              "源库 risk nonce 已消费")

    db2 = os.path.join(td, "events-only.sqlite3")
    store2 = EventStore(db2)
    rows = store1._conn.execute(
        "SELECT event_id,payload,prev_event_hash,event_hash,created_at "
        "FROM pipeline_events ORDER BY seq"
    ).fetchall()
    store2._conn.execute("BEGIN IMMEDIATE")
    for row in rows:
        store2._conn.execute(
            "INSERT INTO pipeline_events "
            "(event_id,payload,prev_event_hash,event_hash,created_at) "
            "VALUES (?,?,?,?,?)", row)
    store2._conn.execute("COMMIT")
    r.require(store2.verify_chain()["ok"] is True,
              "仅复制 pipeline_events 后哈希链有效", copied_rows=len(rows))
    mgr2 = RunManager(store2, keyring=KEYRING)
    side_rows = mgr2.broker.consumed_approvals(run_id=run_id)
    replay = mgr2.get_run(run_id)
    expected_digest = hashlib.sha256(ap["nonce"].encode()).hexdigest()
    r.require(side_rows == [], "新库消费旁表确为空", side_rows=len(side_rows))
    r.require(expected_digest in replay.consumed_nonce_digests,
              "重放由 APPROVAL_CONSUMED 事件还原 nonce 摘要")
    r.expect(ApprovalReuseError, lambda: mgr2.authorize_risk(run_id, ap),
             "旁表为空时同 risk nonce 仍由事件正源拒绝", "事件正源")
    r.done()


def _station(sid: int, sha: str, cas_char: str) -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "run_id": "run_reaudit4_station_chain",
        "station_id": sid,
        "attempt_id": f"attempt-independent-{sid}",
        "execution_status": "COMPLETED",
        "policy_verdict": "PASS",
        "identity": {
            "commit_sha": sha,
            "environment": "staging",
            "scope_hash": "scope:station-chain",
            "ruleset_hash": "rules:station-chain",
        },
        "tool": {"name": f"independent-tool-{sid}", "version": "4.0"},
        "execution": {
            "argv_digest": f"argv-{sid}",
            "started_at": "2026-10-08T04:00:00Z",
            "ended_at": "2026-10-08T04:00:01Z",
            "actual_exit_code": 0,
            "expected_exit_set": [0],
            "assertion_verdict": "PASS",
        },
        "coverage": {"denominator": 9 + sid, "scanned": 9 + sid},
        "artifacts": [{"cas_digest": "sha256:" + cas_char * 64,
                       "size": 100 + sid}],
    }


def probe08() -> None:
    r = Recorder("08", "station v2 链：手工合法 v2 三站到 aggregator/dashboard")
    sha = "d" * 40
    stations = [_station(0, sha, "a"), _station(3, sha, "b"), _station(6, sha, "c")]
    import jsonschema
    schema = json.load(open(os.path.join(SYSTEM, "schemas", "station-result-v2.schema.json"),
                            encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = []
    for station in stations:
        errors.extend([e.message for e in validator.iter_errors(station)])
    r.require(not errors, "三份手工 v2 station 通过正式 Schema", errors=errors)
    agg = GateAggregator({0, 3, 6}, sha, "staging")
    for station in stations:
        agg.add(station)
    out = agg.aggregate()
    r.require(out["aggregate_outcome"] == "PASS" and out["policy_verdict"] == "PASS",
              "aggregator 正式消费 v2 并聚合 PASS", aggregate=out)
    r.require(out["counts"]["required_reported"] == 3
              and out["counts"]["malformed"] == 0,
              "v2 字段未被误判为 legacy/malformed", counts=out["counts"])

    with tempfile.TemporaryDirectory(prefix="reaudit4-p08-dashboard-", dir="/tmp") as td:
        snapshot = os.path.join(td, "gate-aggregate.json")
        with open(snapshot, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, sort_keys=True)
        old = os.environ.get("WENQU_GATE_AGGREGATE")
        os.environ["WENQU_GATE_AGGREGATE"] = snapshot
        try:
            server_path = os.path.join(SYSTEM, "dashboard", "server.py")
            spec = importlib.util.spec_from_file_location("reaudit4_dashboard_p08", server_path)
            module = importlib.util.module_from_spec(spec)
            assert spec and spec.loader
            spec.loader.exec_module(module)
            dash = module.read_gate_aggregate()
        finally:
            if old is None:
                os.environ.pop("WENQU_GATE_AGGREGATE", None)
            else:
                os.environ["WENQU_GATE_AGGREGATE"] = old
    r.require(dash.get("ok") is True
              and dash.get("data", {}).get("policy_verdict") == "PASS",
              "dashboard 接受 aggregator 实际输出契约", dashboard=dash)
    r.done()


def probe09() -> None:
    r = Recorder("09", "EventStore 重试：跨 reopen、三条干扰后重试首事件")
    td = tempfile.mkdtemp(prefix="reaudit4-p09-", dir="/tmp")
    db = os.path.join(td, "events.sqlite3")
    alpha = {"kind": "alpha", "payload": {"z": 1, "a": [3, 2, 1]}}
    s1 = EventStore(db)
    h_alpha, ins_alpha = s1.append(alpha)
    s1.close()
    s2 = EventStore(db)
    h_beta, ins_beta = s2.append({"kind": "beta", "n": 2})
    h_gamma, ins_gamma = s2.append({"kind": "gamma", "n": 3})
    h_delta, ins_delta = s2.append({"kind": "delta", "n": 4})
    h_retry, ins_retry = s2.append({"payload": {"a": [3, 2, 1], "z": 1},
                                    "kind": "alpha"})  # 键序变化、规范化后同事件
    rows = s2._conn.execute(
        "SELECT seq,event_hash,payload FROM pipeline_events ORDER BY seq"
    ).fetchall()
    head_hash, total = s2.head()
    r.require(all((ins_alpha, ins_beta, ins_gamma, ins_delta)),
              "四个唯一事件均插入")
    r.require(ins_retry is False, "跨 reopen 重试 alpha 被识别为 duplicate")
    r.require(h_retry == h_alpha and any(row[1] == h_retry for row in rows),
              "duplicate 返回数据库中原 alpha 的真实 hash",
              original=h_alpha, retry=h_retry)
    r.require(total == 4 and len(rows) == 4,
              "重试未增加行", total=total, rows=len(rows))
    r.require(head_hash == h_delta and head_hash != h_alpha,
              "head 指向最后唯一事件 delta 而非首事件",
              head=head_hash, expected=h_delta)
    r.require(s2.verify_chain()["ok"] is True, "四事件哈希链验证通过")
    r.done()


def _evidence(label: str) -> Evidence:
    return Evidence(
        argv=("/usr/bin/printf", label), cwd="/tmp", actual_exit_code=0,
        stdout_sha256=hashlib.sha256(label.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        argv_digest=hashlib.sha256(("argv:" + label).encode()).hexdigest(),
        timestamp=1700000000.0, fresh_until=4102444800.0, timed_out=False,
    )


def probe10() -> None:
    r = Recorder("10", "CAS 父目录竞态：mkdir 返回瞬间换 shard 为 symlink")
    with tempfile.TemporaryDirectory(prefix="reaudit4-p10-", dir="/tmp") as td:
        root = os.path.join(td, "cas")
        outside = os.path.join(td, "outside")
        os.mkdir(outside)
        store = EvidenceStore(root)
        ev = _evidence("p10-independent")
        digest = store.digest_for(ev)
        shard = digest[:2]
        backup = shard + ".real"
        real_mkdir = runner_mod.os.mkdir
        attacked = {"done": False}

        def swap_after_mkdir(path: Any, mode: int = 0o777, *, dir_fd: int | None = None):
            result = real_mkdir(path, mode, dir_fd=dir_fd)
            if path == shard and dir_fd == store._root_fd and not attacked["done"]:
                attacked["done"] = True
                os.rename(shard, backup, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                os.symlink(outside, shard, dir_fd=dir_fd)
            return result

        runner_mod.os.mkdir = swap_after_mkdir
        try:
            r.expect(IntegrityError, lambda: store.put(ev),
                     "mkdir/open 间 shard symlink 替换被 O_NOFOLLOW 拒绝")
        finally:
            runner_mod.os.mkdir = real_mkdir
        leaked = list(pathlib.Path(outside).iterdir())
        r.require(attacked["done"], "竞态注入点确已命中")
        r.require(leaked == [], "竞态攻击未向 CAS 根外写入", leaked=[str(x) for x in leaked])
        store.close()

    # 独立变体：打开 root dirfd 后将路径名整体换成根外 symlink；操作仍锁定原 fd。
    with tempfile.TemporaryDirectory(prefix="reaudit4-p10-root-", dir="/tmp") as td:
        root = os.path.join(td, "cas")
        held = os.path.join(td, "cas-held")
        outside = os.path.join(td, "outside")
        os.mkdir(outside)
        store = EvidenceStore(root)
        os.rename(root, held)
        os.symlink(outside, root)
        ev = _evidence("p10-root-dirfd")
        digest = store.put(ev)
        r.require(not list(pathlib.Path(outside).iterdir()),
                  "CAS 根路径被 symlink 替换后仍无根外写入")
        expected = pathlib.Path(held) / digest[:2] / f"{digest}.json"
        r.require(expected.is_file(), "持久 root dirfd 将内容写入原始目录对象",
                  expected=str(expected))
        store.close()
    r.done()


def probe11() -> None:
    r = Recorder("11", "Runner 逃逸：setsid+double-fork 预先脱离 PPID 树")
    # 对照组：仍挂在 root PID 下的 setsid 子进程，应被三轮 PPID 树扫描补杀。
    with tempfile.TemporaryDirectory(prefix="reaudit4-p11-attached-", dir="/tmp") as td:
        marker = os.path.join(td, "ATTACHED_SET_SID_MARKER")
        child_pidfile = os.path.join(td, "attached.pid")
        attack = os.path.join(td, "attached_setsid.py")
        code = f'''import os, time\n
pid = os.fork()\n
if pid == 0:\n
    os.setsid()\n
    with open({child_pidfile!r}, "w") as f:\n
        f.write(str(os.getpid()))\n
    time.sleep(1.2)\n
    with open({marker!r}, "w") as f:\n
        f.write("attached setsid survived")\n
    time.sleep(5)\n
    os._exit(0)\n
time.sleep(20)\n
'''
        with open(attack, "w", encoding="utf-8") as fh:
            fh.write(code)
        ev = TrustedRunner(timeout=0.45, allowlist={sys.executable}).run(
            [sys.executable, attack])
        r.require(ev.timed_out is True, "对照组 attached-setsid 根进程触发 timeout")
        time.sleep(1.5)
        attached_survived = os.path.exists(marker)
        attached_pid = None
        try:
            if os.path.isfile(child_pidfile):
                attached_pid = int(open(child_pidfile, encoding="utf-8").read().strip())
        except (OSError, ValueError):
            attached_pid = None
        if attached_pid:
            try:
                os.kill(attached_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        r.require(not attached_survived,
                  "仍保留 PPID 关系的 setsid 子进程已被补杀",
                  marker_exists=attached_survived, child_pid=attached_pid)

    with tempfile.TemporaryDirectory(prefix="reaudit4-p11-", dir="/tmp") as td:
        marker = os.path.join(td, "ESCAPED_MARKER")
        pidfile = os.path.join(td, "daemon.pid")
        attack = os.path.join(td, "double_fork_attack.py")
        code = f'''import os, time\n
pid = os.fork()\n
if pid == 0:\n
    os.setsid()\n
    pid2 = os.fork()\n
    if pid2 > 0:\n
        os._exit(0)\n
    with open({pidfile!r}, "w") as f:\n
        f.write(str(os.getpid()))\n
        f.flush()\n
        os.fsync(f.fileno())\n
    time.sleep(1.4)\n
    with open({marker!r}, "w") as f:\n
        f.write("daemon survived timeout")\n
    time.sleep(8)\n
    os._exit(0)\n
os.waitpid(pid, 0)\n
time.sleep(20)\n
'''
        with open(attack, "w", encoding="utf-8") as fh:
            fh.write(code)
        runner = TrustedRunner(timeout=0.45, allowlist={sys.executable})
        ev = runner.run([sys.executable, attack])
        r.require(ev.timed_out is True, "攻击根进程触发 runner timeout",
                  timed_out=ev.timed_out, actual_exit_code=ev.actual_exit_code)
        deadline = time.time() + 3.2
        while time.time() < deadline and not os.path.exists(marker):
            time.sleep(0.05)
        escaped = os.path.exists(marker)
        daemon_pid = None
        try:
            if os.path.isfile(pidfile):
                daemon_pid = int(open(pidfile, encoding="utf-8").read().strip())
        except (OSError, ValueError):
            daemon_pid = None
        # 清理独立副本中可能逃逸的探针进程，避免遗留。
        if daemon_pid:
            try:
                os.kill(daemon_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        r.require(not escaped,
                  "setsid+double-fork 后代在 timeout 后不得落 marker",
                  marker_exists=escaped, daemon_pid=daemon_pid,
                  note="若此项失败，说明 PPID 枚举无法处理超时前已 reparent 的 daemon")
    r.done()


def _deploy_source(root: str, name: str, healthy: bool) -> str:
    src = os.path.join(root, name)
    os.makedirs(src)
    with open(os.path.join(src, "health.json"), "w", encoding="utf-8") as fh:
        json.dump({"healthy": healthy, "name": name}, fh)
    exe = os.path.join(src, "runner")
    with open(exe, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nexit 0\n")
    os.chmod(exe, 0o755)
    return src


def probe12() -> None:
    r = Recorder("12", "升级回滚：release 与深层 current 分离拓扑的相对链接回切")
    with tempfile.TemporaryDirectory(prefix="reaudit4-p12-", dir="/tmp") as td:
        releases = os.path.join(td, "release pool with spaces")
        current = os.path.join(td, "runtime", "nested", "links", "current")
        source_root = os.path.join(td, "sources")
        os.makedirs(source_root)
        v1 = _deploy_source(source_root, "v1-good", True)
        v2 = _deploy_source(source_root, "v2-bad", False)
        checked: list[str] = []

        def self_check(release: str) -> bool:
            checked.append(os.path.realpath(release))
            with open(os.path.join(release, "health.json"), encoding="utf-8") as fh:
                return json.load(fh)["healthy"] is True

        mgr = DeployManager(releases, current, install_self_check=self_check)
        first = mgr.deploy(v1)
        v1_real = os.path.realpath(first["release_dir"])
        link_v1 = os.readlink(current)
        r.require(not os.path.isabs(link_v1) and ".." in link_v1,
                  "深层 current 使用跨目录相对链接（攻击拓扑成立）",
                  link_value=link_v1)
        old_cwd = os.getcwd()
        os.chdir("/")
        try:
            r.expect(DeployError, lambda: mgr.deploy(v2),
                     "v2 自检失败对外返回部署失败", "rolled back")
        finally:
            os.chdir(old_cwd)
        active = os.path.realpath(current)
        r.require(active == v1_real,
                  "失败升级后 current 精确回到 v1",
                  active=active, expected=v1_real)
        r.require(self_check(active) is True,
                  "回滚目标内容健康")
        r.require(checked.count(v1_real) >= 2,
                  "v1 至少经历首次自检和回滚后再验",
                  self_check_calls=checked)
    r.done()


PROBES: dict[str, Callable[[], None]] = {
    "01": probe01, "02": probe02, "03": probe03, "04": probe04,
    "05": probe05, "06": probe06, "07": probe07, "08": probe08,
    "09": probe09, "10": probe10, "11": probe11, "12": probe12,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", required=True, choices=sorted(PROBES))
    args = parser.parse_args()
    print("PROBE_ENV=" + json.dumps({
        "probe": args.probe,
        "python": sys.version,
        "repo_copy": REPO,
        "system": SYSTEM,
        "pipeline_sha256": hashlib.sha256(
            open(wp.__file__, "rb").read()).hexdigest(),
    }, ensure_ascii=False, sort_keys=True))
    try:
        PROBES[args.probe]()
        return 0
    except BaseException as exc:
        print("PROBE_RESULT=" + json.dumps({
            "probe": args.probe,
            "result": "FAIL",
            "exception": type(exc).__name__,
            "detail": str(exc),
        }, ensure_ascii=False, sort_keys=True))
        raise


if __name__ == "__main__":
    raise SystemExit(main())

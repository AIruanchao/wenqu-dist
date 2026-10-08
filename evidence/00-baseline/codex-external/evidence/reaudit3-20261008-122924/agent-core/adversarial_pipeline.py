#!/usr/bin/env python3
# 第三轮独立验收：仅使用 tempfile SQLite，不修改产物仓。
import copy
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone

REPO = "/Users/maccc/Documents/wenqu-dist/system"
sys.path.insert(0, REPO)
from wenqu_core.store import EventStore
from wenqu_core.wenqu_pipeline import (
    RunManager, SevenStageStateMachine as SM, ApprovalRejected,
    ApprovalReuseError, ApprovalPreconditionError, PipelineCorruptionError,
)

IDENT = {
    "commit_sha": "a" * 40,
    "environment": "staging",
    "scope_hash": "scope-A",
    "repo_id": "example/repo",
    "ruleset_hash": "rules-A",
    "data_config_hash": "data-A",
}

counter = 0

def fresh():
    d = tempfile.mkdtemp(prefix="reaudit3-pipeline-")
    db = os.path.join(d, "events.db")
    store = EventStore(db)
    return d, db, store, RunManager(store)

def waiting(mgr, task, stop="prod-write"):
    rid = mgr.create_run(task, IDENT)["run_id"]
    mgr.advance_stage(rid)
    w = mgr.raise_waiting(rid, stop, "reaudit3")
    return rid, w, mgr.get_run(rid).state_version

def approval(rid, w, version, pre, *, nonce, approval_type="resume", **updates):
    global counter
    counter += 1
    a = {
        "schema_version": "2.0",
        "approval_id": f"apr_reaudit_{counter}",
        "approval_type": approval_type,
        "run_id": rid,
        "task_id": "unused-unless-overridden",
        "stop_event_id": w["stop_event_id"],
        "stop_type": w["stop_type"],
        "stage": w["stage"],
        "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": "policy-A",
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "actor": "independent-human",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_state_version": version,
        "nonce": nonce,
        "decision": "approve",
        "signature": "S" * 64,
        "payload": {
            "stop_event_id": w["stop_event_id"],
            "stop_type": w["stop_type"],
            "objective_precondition_hash": SM.objective_precondition_hash(pre),
        },
    }
    # task_id must bind actual state for fully-bound baseline
    a["task_id"] = mgr_task_id_placeholder = ""
    a.update(updates)
    return a

def bound_approval(mgr, rid, w, version, pre, *, nonce, **updates):
    a = approval(rid, w, version, pre, nonce=nonce)
    a["task_id"] = mgr.get_run(rid).task_id
    a.update(updates)
    return a

def result(name, secure_expected, observed, ok, detail):
    print(json.dumps({
        "probe": name,
        "security_expectation": secure_expected,
        "observed": observed,
        "expectation_met": bool(ok),
        "detail": detail,
    }, ensure_ascii=False, sort_keys=True))
    if not ok:
        vulnerabilities.append(name)

vulnerabilities = []
secure_checks = []

# 1. 指定样例：跨 run nonce 必须拒绝。
d, db, s, m = fresh()
pre = {"gate_reference": "g", "rollback_level": "R2"}
r1, w1, v1 = waiting(m, "cross_nonce_a")
r2, w2, v2 = waiting(m, "cross_nonce_b")
nonce = "same-nonce-across-runs-0001"
a1 = bound_approval(m, r1, w1, v1, pre, nonce=nonce)
a2 = bound_approval(m, r2, w2, v2, pre, nonce=nonce)
m.resume_waiting(r1, a1, pre)
try:
    m.resume_waiting(r2, a2, pre)
    rejected = False
except ApprovalReuseError as exc:
    rejected = True
    err = type(exc).__name__ + ": " + str(exc)
state2 = m.get_run(r2)
ok = rejected and state2.state == "WAITING" and state2.state_version == v2
result("cross_run_nonce", "REJECT", f"rejected={rejected}", ok,
       {"error": err if rejected else None, "run2_state": state2.state, "run2_version": state2.state_version})
secure_checks.append(ok)

# 2. 指定样例：审批包签发后 run 被 cancel，再消费必须拒绝且 nonce 不占用。
d, db, s, m = fresh()
rid, w, v = waiting(m, "cancel_after_approval")
a = bound_approval(m, rid, w, v, pre, nonce="cancel-after-package-0001")
m.cancel_run(rid, "cancel before approval consumption")
try:
    m.resume_waiting(rid, a, pre)
    rejected = False
except ApprovalRejected as exc:
    rejected = True
    err = type(exc).__name__ + ": " + str(exc)
consumed = m.broker.consumed_approvals(run_id=rid)
ok = rejected and m.get_run(rid).state == "CANCELLED" and consumed == []
result("approved_package_then_run_cancelled", "REJECT", f"rejected={rejected}", ok,
       {"error": err if rejected else None, "consumption_rows": len(consumed)})
secure_checks.append(ok)

# 3. 指定样例：state_version 回绕/旧版本必须拒绝。
d, db, s, m = fresh()
rid, w, v = waiting(m, "state_version_rewind")
a = bound_approval(m, rid, w, v, pre, nonce="state-version-rewind-0001",
                   expected_state_version=v - 1)
try:
    m.resume_waiting(rid, a, pre)
    rejected = False
except ApprovalRejected as exc:
    rejected = True
    err = type(exc).__name__ + ": " + str(exc)
ok = rejected and m.get_run(rid).state_version == v and not m.broker.consumed_approvals(run_id=rid)
result("state_version_rewind", "REJECT", f"rejected={rejected}", ok,
       {"error": err if rejected else None, "version": m.get_run(rid).state_version})
secure_checks.append(ok)

# 4. 漏洞：方案列为公共 envelope 的绑定字段全可省略，伪签名仍可恢复。
d, db, s, m = fresh()
rid, w, v = waiting(m, "missing_bindings")
a = bound_approval(m, rid, w, v, pre, nonce="missing-bindings-0001")
for k in ("task_id", "stage", "environment", "authorized_scope", "policy_hash",
          "ruleset_hash", "input_watermark"):
    a.pop(k, None)
a["actor"] = "mallory"
a["signature"] = "X" * 32
accepted = False
try:
    rec = m.resume_waiting(rid, a, pre)
    accepted = rec["resumed"]
except Exception as exc:
    err = type(exc).__name__ + ": " + str(exc)
ok = not accepted
result("missing_identity_bindings_and_fake_signature", "REJECT", f"accepted={accepted}", ok,
       {"error": None if accepted else err, "run_state": m.get_run(rid).state})

# 5. 漏洞：risk discriminator + resume 专属字段混装，可被 consume() 当 resume 使用。
d, db, s, m = fresh()
rid, w, v = waiting(m, "cross_type_payload")
a = bound_approval(m, rid, w, v, pre, nonce="cross-type-risk-resume-0001")
a["approval_type"] = "risk"
a["payload"].update({
    "finding_fingerprints": ["fp-unrelated"], "severity": "LOW",
    "reason": "unrelated risk", "compensating_controls": ["none"],
    "expiry": "2099-01-01T00:00:00Z",
})
accepted = False
try:
    rec = m.resume_waiting(rid, a, pre)
    accepted = rec["resumed"]
except Exception as exc:
    err = type(exc).__name__ + ": " + str(exc)
ok = not accepted
result("cross_type_risk_payload_resumes_waiting", "REJECT", f"accepted={accepted}", ok,
       {"error": None if accepted else err,
        "consumed_type": m.broker.consumed_approvals(run_id=rid)[0]["approval_type"] if accepted else None})

# 6. 漏洞：resource 客观条件字符串 "false" 被当真，STOP-02 被绕过。
d, db, s, m = fresh()
false_pre = {"resource_probe_ref": "probe:down", "probe_recovered": "false",
             "safety_margin_met": "false"}
rid, w, v = waiting(m, "false_objective_condition", "resource")
a = bound_approval(m, rid, w, v, false_pre, nonce="false-objective-0001")
accepted = False
try:
    rec = m.resume_waiting(rid, a, false_pre)
    accepted = rec["resumed"]
except Exception as exc:
    err = type(exc).__name__ + ": " + str(exc)
ok = not accepted
result("resource_not_recovered_string_false", "REJECT", f"accepted={accepted}", ok,
       {"error": None if accepted else err, "preconditions": false_pre})

# 7. 漏洞：非法 input_watermark 不是 SHA 时绕过跨 SHA 比对。
d, db, s, m = fresh()
rid, w, v = waiting(m, "invalid_watermark")
a = bound_approval(m, rid, w, v, pre, nonce="invalid-watermark-0001",
                   input_watermark="not-a-sha")
accepted = False
try:
    rec = m.resume_waiting(rid, a, pre)
    accepted = rec["resumed"]
except Exception as exc:
    err = type(exc).__name__ + ": " + str(exc)
ok = not accepted
result("malformed_input_watermark_bypasses_sha_binding", "REJECT", f"accepted={accepted}", ok,
       {"error": None if accepted else err, "input_watermark": a["input_watermark"]})

# 8. 漏洞：TIMEOUT+CONDITIONAL 被洗为完成；HIGH(P1) 风险接受且 finding 集不匹配仍终态条件完成。
d, db, s, m = fresh()
rid = m.create_run("timeout_conditional", IDENT)["run_id"]
for _ in range(6):
    m.advance_stage(rid, execution_status="COMPLETED", policy_verdict="PASS")
out = m.advance_stage(rid, execution_status="TIMEOUT", policy_verdict="CONDITIONAL",
                      findings=["fnd_timeout_actual"])
risk = {
    "schema_version": "2.0", "approval_id": "apr_p1_timeout", "approval_type": "risk",
    "run_id": rid, "stop_event_id": "not-a-stop", "stop_type": "scope",
    "actor": "mallory", "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z", "nonce": "risk-timeout-p1-0001",
    "decision": "approve", "signature": "Z" * 32,
    "payload": {"finding_fingerprints": ["fp_different_from_actual"],
                "severity": "HIGH", "reason": "accept P1 timeout",
                "compensating_controls": ["none"],
                "expiry": "2099-01-01T00:00:00Z"},
}
accepted = False
try:
    m.authorize_risk(rid, risk)
    done = m.complete_run(rid)
    accepted = done["final_state"] == "COMPLETED_CONDITIONAL"
except Exception as exc:
    err = type(exc).__name__ + ": " + str(exc)
ok = not accepted
result("timeout_conditional_p1_unbound_risk_laundered", "REJECT", f"accepted={accepted}", ok,
       {"error": None if accepted else err, "attempt_status": out.get("attempt_status"),
        "final": done if accepted else None})

# 9. 漏洞：EventStore 公共 append 可绕过 RunManager，S1 RUNNING 时直接伪造 SUCCEEDED。
d, db, s, m = fresh()
rid = m.create_run("forged_completion", IDENT)["run_id"]
m.advance_stage(rid)
st = m.get_run(rid)
forged = {
    "schema_version": "2.0", "event_type": "RUN_COMPLETED", "run_id": rid,
    "task_id": st.task_id, "execution_status": "COMPLETED", "policy_verdict": "PASS",
    "identity": dict(st.identity), "state_version": st.state_version + 1,
    "ts": "2026-10-08T00:00:00Z", "actor": "untrusted-direct-writer",
}
s.append(forged)
accepted = False
try:
    forged_state = m.get_run(rid)
    accepted = forged_state.state == "SUCCEEDED"
except Exception as exc:
    err = type(exc).__name__ + ": " + str(exc)
ok = not accepted
result("direct_event_append_forges_success", "REJECT", f"accepted={accepted}", ok,
       {"error": None if accepted else err,
        "run_state": forged_state.state if accepted else None,
        "stage_statuses": forged_state.stage_statuses() if accepted else None,
        "chain_ok": s.verify_chain()["ok"]})

# 10. 漏洞：cancel RUNNING run 后，stage attempt 仍为 RUNNING（终态投影不一致）。
d, db, s, m = fresh()
rid = m.create_run("cancel_running_attempt", IDENT)["run_id"]
m.advance_stage(rid)
m.cancel_run(rid, "cancel active")
st = m.get_run(rid)
inconsistent = st.state == "CANCELLED" and st.stages["S1_REQUIREMENT"].status == "RUNNING"
ok = not inconsistent
result("cancelled_run_leaves_running_attempt", "ATTEMPT_CANCELLED", st.stages["S1_REQUIREMENT"].status, ok,
       {"run_state": st.state, "stage_statuses": st.stage_statuses()})

# 11. 漏洞：approval_consumptions 是事件流之外的第二可变正源；只重放事件后同 nonce 可再次消费。
d, db, s, m = fresh()
rid, w, v = waiting(m, "second_source")
a = bound_approval(m, rid, w, v, pre, nonce="event-replay-nonce-0001")
m.resume_waiting(rid, a, pre)
# 让原 run 再次进入 WAITING，以便比较原库与仅事件重放库的 nonce 语义。
m.advance_stage(rid, execution_status="COMPLETED", policy_verdict="PASS")
w2 = m.raise_waiting(rid, "prod-write", "second wait")
st2 = m.get_run(rid)
a2 = bound_approval(m, rid, w2, st2.state_version, pre, nonce="event-replay-nonce-0001")
try:
    m.resume_waiting(rid, a2, pre)
    original_rejected = False
except ApprovalReuseError:
    original_rejected = True
# 只复制 pipeline_events，不复制 approval_consumptions。
d2, db2, s2, m2 = fresh()
for (payload_text,) in s._conn.execute("SELECT payload FROM pipeline_events ORDER BY seq"):
    s2.append(json.loads(payload_text))
replay_state = m2.get_run(rid)
replay_accepted = False
try:
    rec = m2.resume_waiting(rid, a2, pre)
    replay_accepted = rec["resumed"]
except Exception as exc:
    replay_err = type(exc).__name__ + ": " + str(exc)
ok = original_rejected and not replay_accepted
result("event_replay_loses_nonce_consumption_second_source", "REPLAY_PRESERVES_REJECTION",
       f"original_rejected={original_rejected}, replay_accepted={replay_accepted}", ok,
       {"replay_error": None if replay_accepted else replay_err,
        "original_consumptions": len(m.broker.consumed_approvals(run_id=rid)),
        "replayed_consumptions_before": 0,
        "replayed_state_before": replay_state.state})

# 12. 契约漂移：实现生成的 WAITING_RAISED 不符合正式 run-event schema additionalProperties=false。
try:
    import jsonschema
    d, db, s, m = fresh()
    rid, w, v = waiting(m, "waiting_schema_drift")
    payloads = [json.loads(x[0]) for x in s._conn.execute(
        "SELECT payload FROM pipeline_events ORDER BY seq")]
    waiting_event = [p for p in payloads if p.get("event_type") == "WAITING_RAISED"][0]
    schema = json.load(open(os.path.join(REPO, "schemas", "run-event-v2.schema.json")))
    try:
        jsonschema.validate(waiting_event, schema)
        schema_rejected = False
        schema_err = None
    except jsonschema.ValidationError as exc:
        schema_rejected = True
        schema_err = exc.message
    ok = not schema_rejected
    result("emitted_waiting_event_violates_run_schema", "SCHEMA_ACCEPT", f"schema_rejected={schema_rejected}", ok,
           {"validation_error": schema_err, "extra_keys": sorted(set(waiting_event) - set(schema.get("properties", {})))})
except ImportError as exc:
    result("emitted_waiting_event_violates_run_schema", "SCHEMA_ACCEPT", "jsonschema unavailable", False,
           {"error": str(exc)})

print(json.dumps({
    "summary": {
        "specified_secure_checks_passed": sum(secure_checks),
        "specified_secure_checks_total": len(secure_checks),
        "security_failures_demonstrated": len(vulnerabilities),
        "failure_probe_names": vulnerabilities,
    }
}, ensure_ascii=False, sort_keys=True))
# 该 harness 以 0 表示探针完整执行；每项安全成败由 expectation_met 字段表达。
sys.exit(0)

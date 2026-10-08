#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wenqu_pipeline P0-2 行为自测——全流程/规则/拒绝路径/并发双消费/哈希链。

P0-2 接线锚点：删除 wenqu_core/wenqu_pipeline.py 后此测试必红
（acceptance.sh P1b 节硬依赖，CI 必红）。

P0-4 加固后的契约更新（诚实更新，不删断言）：
- approval envelope 全字段 required + HMAC-SHA256 真实验签——测试审批由
  tests/fixtures/approval-keys.json 的测试密钥签发（key_test_1）；
- bool 类客观前置字段（probe_recovered 等）必须真 bool——原 "yes" 字符串
  自报值改为 True；
- identity 必含 policy_hash/ruleset_hash（审批 exact 绑定的锚点）；
- risk 授权需与 run 登记面 finding 指纹精确匹配——CONDITIONAL 场景先
  register_finding（MEDIUM/P2）再授权；
- 新增多条拒绝断言（伪签名/未知 key/非 40-hex watermark/policy/ruleset
  绑定等），原有断言全部保留。
"""
import os
import sys
import json
import tempfile
import threading

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.store import EventStore, ChainIntegrityError
from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope
from wenqu_core.wenqu_pipeline import (
    SevenStageStateMachine as SM, NineStopTypes, ApprovalBroker, RunManager,
    StageOrderError, InvalidTransitionError, InvalidOutcomeError,
    PipelineError, TerminalRunError, ApprovalRejected, ApprovalReuseError,
    ApprovalPreconditionError, AttemptImmutabilityError, RunNotFoundError,
    STAGES,
)

PASS_N, FAIL_N = 0, 0
def check(name, fn):
    global PASS_N, FAIL_N
    try:
        fn()
        print(f"  ok  {name}")
        PASS_N += 1
    except Exception as e:
        print(f"  FAIL {name}: {type(e).__name__}: {e}")
        FAIL_N += 1

def expect(exc, fn):
    try:
        fn()
    except exc:
        return
    except Exception as e:
        raise AssertionError(f"expected {exc.__name__}, got {type(e).__name__}: {e}")
    raise AssertionError(f"expected {exc.__name__}, nothing raised")

IDENT = {
    "commit_sha": "a" * 40,
    "environment": "staging",
    "scope_hash": "scope-hash-001",
    "repo_id": "qisemi-erp",
    "ruleset_hash": "rules-7",
    "policy_hash": "policy-sha-001",
}

# P0-4：测试密钥登记（fixtures 只供测试签发；生产必须独立生成并隔离）
KEYRING = ApprovalKeyring.from_path(
    os.path.join(REPO, "tests", "fixtures", "approval-keys.json"))
KEY_ID = "key_test_1"
SECRET = KEYRING.get(KEY_ID)

def fresh():
    tmp = tempfile.mkdtemp(prefix="wenqu-pipe-")
    store = EventStore(os.path.join(tmp, "events.db"))
    mgr = RunManager(store, keyring=KEYRING)
    return store, mgr

def resign(ap):
    """改字段后重签（保持 HMAC 与内容一致，用于精确测试单一拒绝面）。"""
    ap = dict(ap)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(SECRET, ap)
    return ap

# ------------------------------------------------------------------ #
def t_rule_engine():
    assert SM.stages() == STAGES and len(STAGES) == 7
    assert SM.next_stage("S1_REQUIREMENT") == "S2_SOLUTION"
    assert SM.next_stage("S7_GATE") is None
    expect(StageOrderError, lambda: SM.stage_index("S8_NOPE"))
    expect(StageOrderError, lambda: SM.next_stage("S9"))
    # 前段非 PASSED 不得启动后段（含 CONDITIONAL 也不行）
    for bad in ("PENDING", "RUNNING", "COMPLETED_CONDITIONAL", "FAILED", "WAITING"):
        sts = {"S1_REQUIREMENT": bad, "S2_SOLUTION": "PENDING"}
        expect(StageOrderError, lambda s=bad: SM.ensure_prior_stages_passed(
            {"S1_REQUIREMENT": s}, "S2_SOLUTION"))
    SM.ensure_prior_stages_passed({"S1_REQUIREMENT": "PASSED"}, "S2_SOLUTION")
    # 转换表
    SM.validate_run_transition("CREATED", "RUNNING")
    SM.validate_run_transition("WAITING", "RUNNING")
    SM.validate_run_transition("RUNNING", "SUCCEEDED")
    expect(InvalidTransitionError, lambda: SM.validate_run_transition("CREATED", "WAITING"))
    expect(InvalidTransitionError, lambda: SM.validate_run_transition("SUCCEEDED", "RUNNING"))
    expect(InvalidTransitionError, lambda: SM.validate_run_transition("WAITING", "SUCCEEDED"))
    SM.validate_attempt_transition("PENDING", "RUNNING")
    SM.validate_attempt_transition("RUNNING", "WAITING")
    expect(InvalidTransitionError, lambda: SM.validate_attempt_transition("WAITING", "RUNNING"))
    # 双轴：非 COMPLETED 不得 PASS；PASS 不得带 findings
    SM.validate_outcome("COMPLETED", "PASS")
    expect(InvalidOutcomeError, lambda: SM.validate_outcome("ERROR", "PASS"))
    expect(InvalidOutcomeError, lambda: SM.validate_outcome("TIMEOUT", "PASS"))
    expect(InvalidOutcomeError, lambda: SM.validate_outcome("COMPLETED", "PASS", ["fnd_x"]))
    expect(InvalidOutcomeError, lambda: SM.validate_outcome("COMPLETED", "GREEN"))
    # P0-4 双轴根修：execution 非 COMPLETED 一律 FAILED（TIMEOUT+CONDITIONAL 洗白关闭）
    assert SM.outcome_to_attempt_status("TIMEOUT", "CONDITIONAL") == "FAILED"
    assert SM.outcome_to_attempt_status("ERROR", "NOT_APPLICABLE") == "FAILED"
    assert SM.outcome_to_attempt_status("COMPLETED", "CONDITIONAL") == "COMPLETED_CONDITIONAL"
    assert SM.outcome_to_attempt_status("COMPLETED", "PASS") == "PASSED"
    # 九类停等 + 前置规格（含 exm-fuse 的 either-or）
    assert len(list(NineStopTypes)) == 9
    assert set(SM.stop_types()) == {
        "ambiguity", "prod-write", "ddl", "release", "scope",
        "fund-auth", "exm-fuse", "resource", "ext-unavail"}
    SM.validate_preconditions("ambiguity", {"requirement_four_elements": "四要素", "scope_hash": "sh"})
    expect(ApprovalPreconditionError, lambda: SM.validate_preconditions("ambiguity", {"scope_hash": "sh"}))
    expect(ApprovalPreconditionError, lambda: SM.validate_preconditions("ambiguity", None))
    SM.validate_preconditions("exm-fuse", {"adjudication_ref": "EXM-1", "fuse_lifted_evidence": "probe"})
    SM.validate_preconditions("exm-fuse", {"adjudication_ref": "EXM-1", "independent_ruling_ref": "ruling-9"})
    SM.validate_preconditions("exm-fuse", {"adjudication_ref": "EXM-1", "fuse_lifted": True})
    expect(ApprovalPreconditionError, lambda: SM.validate_preconditions("exm-fuse", {"adjudication_ref": "EXM-1"}))
    # P0-4 前置客观化：bool 类字段必须真 bool——字符串/数字自报一律拒
    expect(ApprovalPreconditionError, lambda: SM.validate_preconditions(
        "resource", {"resource_probe_ref": "p", "probe_recovered": "false",
                     "safety_margin_met": True}))
    expect(ApprovalPreconditionError, lambda: SM.validate_preconditions(
        "resource", {"resource_probe_ref": "p", "probe_recovered": "yes",
                     "safety_margin_met": True}))
    expect(ApprovalPreconditionError, lambda: SM.validate_preconditions(
        "resource", {"resource_probe_ref": "p", "probe_recovered": 1,
                     "safety_margin_met": True}))
    expect(ApprovalPreconditionError, lambda: SM.validate_preconditions(
        "resource", {"resource_probe_ref": "p", "probe_recovered": False,
                     "safety_margin_met": True}))
    SM.validate_preconditions("resource", {"resource_probe_ref": "p",
                                           "probe_recovered": True,
                                           "safety_margin_met": True})
    h = SM.objective_precondition_hash({"a": 1})
    assert len(h) == 64 and h == SM.objective_precondition_hash({"a": 1})

# ------------------------------------------------------------------ #
def t_happy_path():
    store, mgr = fresh()
    r = mgr.create_run("task_p02", IDENT)
    run_id = r["run_id"]
    assert r["state"] == "CREATED" and r["state_version"] == 1
    st = mgr.get_run(run_id)
    assert st.state == "CREATED" and st.stage_statuses() == {s: "PENDING" for s in STAGES}
    # 推进 7 段：首次不带 outcome 启动 S1，随后逐段 PASS
    out = mgr.advance_stage(run_id)  # 启动 S1
    assert out["stage"] == "S1_REQUIREMENT" and "started_attempt_id" in out
    assert mgr.get_run(run_id).state == "RUNNING"
    for i, stage in enumerate(STAGES):
        cur = mgr.get_run(run_id).current_stage
        assert cur == stage, f"current={cur} expect={stage}"
        out = mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="PASS")
        assert out["attempt_status"] == "PASSED"
        if i < 6:
            assert out.get("next_stage") == STAGES[i + 1]
        else:
            assert out.get("next_stage") is None and out["ready_for_completion"] is True
    st = mgr.get_run(run_id)
    assert st.current_stage is None
    assert all(v == "PASSED" for v in st.stage_statuses().values())
    done = mgr.complete_run(run_id)
    assert done["final_state"] == "SUCCEEDED" and done["policy_verdict"] == "PASS"
    expect(TerminalRunError, lambda: mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="PASS"))
    expect(TerminalRunError, lambda: mgr.complete_run(run_id))
    assert store.verify_chain()["ok"]
    st = mgr.get_run(run_id)  # 终态后重取快照再比对
    # 重放一致性：第二个 RunManager（独立连接）看到同一状态
    mgr2 = RunManager(store, keyring=KEYRING)
    st2 = mgr2.get_run(run_id)
    assert st2.state == "SUCCEEDED" and st2.state_version == st.state_version
    assert st2.stage_statuses() == st.stage_statuses()

# ------------------------------------------------------------------ #
def t_retry_new_attempt():
    store, mgr = fresh()
    run_id = mgr.create_run("task_retry", IDENT)["run_id"]
    mgr.advance_stage(run_id)  # S1 RUNNING
    out = mgr.advance_stage(run_id, execution_status="ERROR", policy_verdict="FAIL")
    assert out["attempt_status"] == "FAILED"
    st = mgr.get_run(run_id)
    s1 = st.stages["S1_REQUIREMENT"]
    assert s1.status == "FAILED" and len(s1.attempts) == 1
    old_id = s1.attempts[0].attempt_id
    # 重试：新 attempt_id，旧 attempt 不可变
    out = mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="PASS")
    assert out["attempt_id"] != old_id and out["attempt_status"] == "PASSED"
    assert out.get("next_stage") == "S2_SOLUTION"
    st = mgr.get_run(run_id)
    s1 = st.stages["S1_REQUIREMENT"]
    assert len(s1.attempts) == 2
    assert s1.attempts[0].attempt_id == old_id and s1.attempts[0].status == "FAILED"
    assert s1.attempts[1].status == "PASSED"
    assert st.stages["S2_SOLUTION"].status == "RUNNING"
    assert store.verify_chain()["ok"]

# ------------------------------------------------------------------ #
PRECONDITIONS = {
    "gate_reference": "gate:sha-abc", "rollback_level": "R3",
}
def make_resume_approval(run_id, stop_event_id, stop_type, state_version,
                         task_id, stage="S1_REQUIREMENT",
                         preconditions=None, **over):
    """构造完整 approval-v2 信封（全字段 required）并用测试密钥 HMAC 签名。

    P0-4 语义更新：task_id/stage/policy_hash/ruleset_hash 必填并参与签名；
    签名在应用全部覆盖项之后计算——篡改任何字段都会使验签失败。
    """
    pre = dict(preconditions if preconditions is not None else PRECONDITIONS)
    ph = SM.objective_precondition_hash(pre)
    ap = {
        "schema_version": "2.0",
        "approval_id": "apr_resume_1",
        "approval_type": "resume",
        "key_id": KEY_ID,
        "run_id": run_id,
        "task_id": task_id,
        "stop_event_id": stop_event_id,
        "stop_type": stop_type,
        "stage": stage,
        "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "actor": "chaoge",
        "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_state_version": state_version,
        "nonce": "nonce-0123456789abcdef",
        "decision": "approve",
        "signature": "",
        "payload": {
            "stop_event_id": stop_event_id,
            "stop_type": stop_type,
            "objective_precondition_hash": ph,
        },
    }
    ap.update(over)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(SECRET, ap)
    return ap, pre

def t_waiting_resume_happy():
    store, mgr = fresh()
    run_id = mgr.create_run("task_wait", IDENT)["run_id"]
    mgr.advance_stage(run_id)  # S1 RUNNING
    w = mgr.raise_waiting(run_id, "prod-write", "需要生产写授权：批量修数")
    assert w["stop_type"] == "prod-write" and w["run_state"] == "WAITING"
    assert set(w["required_preconditions"]) == {"gate_reference", "rollback_level"}
    st = mgr.get_run(run_id)
    assert st.state == "WAITING" and st.waiting.stop_event_id == w["stop_event_id"]
    assert st.stages["S1_REQUIREMENT"].status == "WAITING"
    old_att = st.stages["S1_REQUIREMENT"].current_attempt.attempt_id
    v_before = st.state_version
    # WAITING 中不得推进/complete
    expect(PipelineError, lambda: mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="PASS"))
    expect(PipelineError, lambda: mgr.complete_run(run_id))
    # 合法 resume：一次性授权 + 客观前置条件（必要且充分）
    ap, pre = make_resume_approval(run_id, w["stop_event_id"], "prod-write",
                                   v_before, "task_wait")
    rec = mgr.resume_waiting(run_id, ap, pre)
    assert rec["resumed"] is True and rec["run_state"] == "RUNNING"
    st = mgr.get_run(run_id)
    assert st.state == "RUNNING" and st.waiting is None
    s1 = st.stages["S1_REQUIREMENT"]
    assert s1.current_attempt.attempt_id != old_att  # attempt 不可变→新 id
    assert s1.attempts[-2].status == "WAITING" and s1.attempts[-1].status == "RUNNING"
    assert len(s1.attempts) == 2 and st.state_version == v_before + 1
    # 九类停等逐类走一遍（raise→resume；每类用独立 run）
    for stop_type in SM.stop_types():
        task_id = f"task_{stop_type.replace('-','_')}"
        rid = mgr.create_run(task_id, IDENT)["run_id"]
        mgr.advance_stage(rid)
        pre_map = {
            "ambiguity": {"requirement_four_elements": "四要素冻结", "scope_hash": IDENT["scope_hash"]},
            "prod-write": {"gate_reference": "g1", "rollback_level": "R2"},
            "ddl": {"ddl_statement_digest": "d" * 8, "environment": "staging",
                    "verification_fresh": True, "verification_legacy": True,
                    "verification_minimal": True, "rollback_verified": True},
            "release": {"release_id": "rel-1", "commit_sha": IDENT["commit_sha"],
                        "environment": "staging", "gate_reference": "g",
                        "manifest_sha256": "m" * 8, "rollback_plan": "rp"},
            "scope": {"new_scope_hash": "nsh-2", "risk_refrozen": True,
                      "required_set_refrozen": True, "evidence_refrozen": True},
            "fund-auth": {"fund_subject_role": "ops", "positive_test_ref": "p",
                          "negative_test_ref": "n", "conservation_check": True,
                          "audit_target": "a"},
            "exm-fuse": {"adjudication_ref": "EXM-7", "fuse_lifted_evidence": "probe-ok"},
            "resource": {"resource_probe_ref": "p", "probe_recovered": True,
                         "safety_margin_met": True},
            "ext-unavail": {"dependency_probe_ref": "p", "probe_recovered": True,
                            "evidence_freshness_reverified": True},
        }[stop_type]
        w2 = mgr.raise_waiting(rid, stop_type, f"停等测试 {stop_type}")
        v = mgr.get_run(rid).state_version
        ap2, pre2 = make_resume_approval(
            rid, w2["stop_event_id"], stop_type, v, task_id,
            preconditions=pre_map,
            nonce=f"nonce-{stop_type}-0011223344",
            approval_id=f"apr_{stop_type.replace('-','_')}")
        rec2 = mgr.resume_waiting(rid, ap2, pre2)
        assert rec2["resumed"] is True, stop_type
        assert mgr.get_run(rid).state == "RUNNING", stop_type
    assert store.verify_chain()["ok"]

# ------------------------------------------------------------------ #
def t_approval_rejections():
    store, mgr = fresh()
    run_id = mgr.create_run("task_rej", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    w = mgr.raise_waiting(run_id, "prod-write", "拒绋试验")
    v = mgr.get_run(run_id).state_version

    def resume(ap, pre=None):
        _p = pre if pre is not None else PRECONDITIONS
        return mgr.resume_waiting(run_id, ap, _p)

    base = make_resume_approval(run_id, w["stop_event_id"], "prod-write", v,
                                "task_rej")[0]
    # 1) 结构类
    bad = dict(base); del bad["nonce"]
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["schema_version"] = "1.0"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["nonce"] = "short"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["signature"] = "tiny"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["unknown_field"] = 1
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["stop_type"] = "no-such-stop"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["approval_type"] = "merge"  # payload 判别联合不符
    expect(ApprovalRejected, lambda: resume(bad))
    bad = json.loads(json.dumps(base)); del bad["payload"]["objective_precondition_hash"]
    expect(ApprovalRejected, lambda: resume(bad))
    # 1b) P0-4 新增：envelope 全封闭——缺任一绑定字段即拒（伪签名+缺绑定关闭）
    for missing in ("task_id", "stage", "environment", "authorized_scope",
                    "policy_hash", "ruleset_hash", "input_watermark",
                    "expected_state_version", "key_id"):
        bad = json.loads(json.dumps(base)); del bad[missing]
        expect(ApprovalRejected, lambda b=bad: resume(b))
    # 1c) P0-4 新增：伪签名（长度够但 HMAC 不对）/未知 key_id 一律拒
    bad = dict(base); bad["signature"] = "0" * 64
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["signature"] = ("0" if base["signature"][0] != "0"
                                          else "1") + base["signature"][1:]
    expect(ApprovalRejected, lambda: resume(bad))
    bad = resign(dict(base)); bad["key_id"] = "key_nope_1"
    expect(ApprovalRejected, lambda: resume(bad))
    # 1d) P0-4 新增：非 40-hex watermark 结构层即拒（不再跳过比较）
    bad = dict(base); bad["input_watermark"] = "short-watermark"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["input_watermark"] = "a" * 39
    expect(ApprovalRejected, lambda: resume(bad))
    # 1e) P0-4 新增：错 policy/ruleset 重签后仍拒——证明是绑定比较而非签名拦截
    bad = resign(dict(base, policy_hash="policy-OTHER"))
    try:
        resume(bad)
        raise AssertionError("policy_hash mismatch 应被拒")
    except ApprovalRejected as e:
        assert "policy_hash" in str(e), str(e)
    bad = resign(dict(base, ruleset_hash="rules-OTHER"))
    try:
        resume(bad)
        raise AssertionError("ruleset_hash mismatch 应被拒")
    except ApprovalRejected as e:
        assert "ruleset_hash" in str(e), str(e)
    # 2) decision / TTL
    bad = dict(base); bad["decision"] = "deny"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["decision"] = "conditional"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["expires_at"] = "2026-10-01T00:00:00Z"  # 已过期
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["issued_at"] = "2098-01-01T00:00:00Z"
    bad["expires_at"] = "2099-01-01T00:00:00Z"  # 未生效
    expect(ApprovalRejected, lambda: resume(bad))
    # 3) 绑定：scope/环境/SHA/stop_event/stop_type/stage/task
    bad = dict(base); bad["authorized_scope"] = "other-scope"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["environment"] = "production"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["input_watermark"] = "b" * 40
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["stop_event_id"] = "f" * 64
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["stop_type"] = "ddl"; bad["payload"] = dict(base["payload"], stop_type="ddl")
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["stage"] = "S4_IMPLEMENT"
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["run_id"] = "run_other"
    expect(ApprovalRejected, lambda: resume(bad))
    # 4) state_version CAS
    bad = dict(base); del bad["expected_state_version"]
    expect(ApprovalRejected, lambda: resume(bad))
    bad = dict(base); bad["expected_state_version"] = v + 5
    expect(ApprovalRejected, lambda: resume(bad))
    # 5) 前置条件：缺键 / 哈希不匹配
    expect(ApprovalPreconditionError, lambda: resume(base, {"gate_reference": "g"}))
    tampered = dict(PRECONDITIONS, rollback_level="R0")  # 哈希绑定之外的内容
    expect(ApprovalPreconditionError, lambda: resume(base, tampered))
    # 全部拒绝后：状态未变、nonce 未占用、无事件消耗
    st = mgr.get_run(run_id)
    assert st.state == "WAITING" and st.state_version == v
    assert mgr.broker.consumed_approvals(run_id=run_id) == []
    # 一次性消费：同一审批二次使用 → ApprovalReuseError
    ok_pre = dict(PRECONDITIONS)
    rec = mgr.resume_waiting(run_id, base, ok_pre)
    assert rec["resumed"] is True
    expect(ApprovalReuseError, lambda: mgr.resume_waiting(run_id, base, ok_pre))
    # resume 后再 raise 一次，用新 stop_event 验证旧 nonce 不可跨事件复用
    # （重签保持 HMAC 有效——精确命中 nonce 复用而非签名拦截）
    mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="PASS")  # S1 done→S2 running
    w2 = mgr.raise_waiting(run_id, "resource", "第二次停等")
    v2 = mgr.get_run(run_id).state_version
    pre2 = {"resource_probe_ref": "p", "probe_recovered": True, "safety_margin_met": True}
    ap2, _ = make_resume_approval(
        run_id, w2["stop_event_id"], "resource", v2, "task_rej",
        stage="S2_SOLUTION", preconditions=pre2,
        nonce="nonce-0123456789abcdef")  # 旧 nonce，新签名
    expect(ApprovalReuseError, lambda: mgr.resume_waiting(run_id, ap2, pre2))
    assert store.verify_chain()["ok"]

# ------------------------------------------------------------------ #
def t_concurrent_double_consume():
    tmp = tempfile.mkdtemp(prefix="wenqu-pipe-cc-")
    db = os.path.join(tmp, "events.db")
    store = EventStore(db)
    mgr = RunManager(store, keyring=KEYRING)
    run_id = mgr.create_run("task_cc", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    w = mgr.raise_waiting(run_id, "prod-write", "并发双消费")
    v = mgr.get_run(run_id).state_version
    ap, pre = make_resume_approval(run_id, w["stop_event_id"], "prod-write", v,
                                   "task_cc", nonce="nonce-cc-00112233445566")
    # 第二个独立管理器（独立连接，模拟并发进程）
    mgr_b = RunManager(EventStore(db), keyring=KEYRING)
    results, errors = [], []
    def worker(m):
        try:
            results.append(m.resume_waiting(run_id, ap, dict(pre)))
        except Exception as e:
            errors.append(e)
    t1 = threading.Thread(target=worker, args=(mgr,))
    t2 = threading.Thread(target=worker, args=(mgr_b,))
    t1.start(); t2.start(); t1.join(); t2.join()
    succ = [r for r in results if r.get("resumed")]
    reuse = [e for e in errors if isinstance(e, ApprovalReuseError)]
    assert len(succ) == 1, f"expected exactly 1 success, got {len(succ)} (errors={errors})"
    assert len(reuse) == 1, f"expected 1 ApprovalReuseError, got {errors!r}"
    st = mgr.get_run(run_id)
    assert st.state == "RUNNING" and st.state_version == v + 1
    assert len(mgr.broker.consumed_approvals(run_id=run_id)) == 1
    assert store.verify_chain()["ok"]

# ------------------------------------------------------------------ #
def make_risk_approval(run_id, task_id, state_version, **over):
    """risk 授权全信封（MEDIUM/P2 与 run 登记面指纹精确匹配）+ HMAC 签名。"""
    ap = {
        "schema_version": "2.0", "approval_id": "apr_risk_1",
        "approval_type": "risk", "key_id": KEY_ID,
        "run_id": run_id, "task_id": task_id,
        "stop_event_id": "n/a-soft-terminal", "stop_type": "scope",
        "stage": "S7_GATE",
        "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "actor": "chaoge", "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_state_version": state_version,
        "nonce": "nonce-risk-0011223344", "decision": "approve",
        "signature": "",
        "payload": {"finding_fingerprints": ["fp1"], "severity": "MEDIUM",
                    "reason": "r" * 12, "compensating_controls": ["c1"],
                    "expiry": "2099-12-31T00:00:00Z"},
    }
    ap.update(over)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(SECRET, ap)
    return ap

def t_conditional_terminal():
    store, mgr = fresh()
    run_id = mgr.create_run("task_cond", IDENT)["run_id"]
    for i in range(6):  # S1..S6 PASS
        mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="PASS")
    out = mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="CONDITIONAL")
    assert out["attempt_status"] == "COMPLETED_CONDITIONAL"
    assert out.get("next_stage") is None
    st = mgr.get_run(run_id)
    assert st.current_stage == "S7_GATE"  # 软终态段仍阻塞推进
    out = mgr.advance_stage(run_id)  # 软终态可重试：attempt 不可变 → 新 attempt
    assert out.get("started_attempt_id"), out
    out = mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="CONDITIONAL")
    # P0-4：登记面登记可风险接受 finding（MEDIUM/P2）——risk 授权的匹配锚点
    mgr.register_finding(run_id, "fnd_s7_soft", "fp1", "MEDIUM", "P2",
                         detail="S7 条件通过伴随的中危遗留项")
    # 无 risk 授权 → complete_run fail-closed
    expect(PipelineError, lambda: mgr.complete_run(run_id))
    v = mgr.get_run(run_id).state_version
    rec = mgr.authorize_risk(run_id, make_risk_approval(run_id, "task_cond", v))
    assert rec["consumed"] is True
    # risk 审批不可复用
    expect(ApprovalReuseError, lambda: mgr.authorize_risk(
        run_id, make_risk_approval(run_id, "task_cond", v)))
    done = mgr.complete_run(run_id)
    assert done["final_state"] == "COMPLETED_CONDITIONAL"
    assert done["policy_verdict"] == "CONDITIONAL"
    expect(TerminalRunError, lambda: mgr.complete_run(run_id))
    assert store.verify_chain()["ok"]
    # 重放一致性：登记面与 risk 授权随事件流重建
    st = mgr.get_run(run_id)
    assert set(st.findings) == {"fnd_s7_soft"}
    assert len(st.risk_authorizations) == 1
    assert st.risk_authorizations[0]["finding_fingerprints"] == ["fp1"]

# ------------------------------------------------------------------ #
def t_cancel_supersede_notfound():
    store, mgr = fresh()
    run_id = mgr.create_run("task_cancel", IDENT)["run_id"]
    out = mgr.cancel_run(run_id)
    assert out["final_state"] == "CANCELLED"
    st = mgr.get_run(run_id)
    assert st.terminal and st.state == "CANCELLED"
    run2 = mgr.create_run("task_sup", IDENT)["run_id"]
    mgr.advance_stage(run2)
    out = mgr.supersede_run(run2, "commit_sha 变更，旧证据失效（不变量 #3）")
    assert out["final_state"] == "SUPERSEDED"
    expect(RunNotFoundError, lambda: mgr.get_run("run_ghost"))
    # FAILED 终态：中途放弃
    run3 = mgr.create_run("task_fail", IDENT)["run_id"]
    mgr.advance_stage(run3)
    mgr.advance_stage(run3, execution_status="ERROR", policy_verdict="FAIL")
    done = mgr.complete_run(run3)
    assert done["final_state"] == "FAILED"
    assert store.verify_chain()["ok"]

# ------------------------------------------------------------------ #
def t_eventstore_interop():
    """broker/manager 的链式插入与 EventStore.append 交错后链仍完整。

    P0-4 后公共 append 对控制事件类型直接 ValueError——外部普通事件
    （无控制 event_type）不受影响，交错链完整性保持。
    """
    store, mgr = fresh()
    run_id = mgr.create_run("task_mix", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    store.append({"external": "probe", "n": 1})      # EventStore 直写
    mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="PASS")
    store.append({"external": "probe", "n": 2})
    w = mgr.raise_waiting(run_id, "resource", "mix")  # 停在 S2
    v = mgr.get_run(run_id).state_version
    pre = {"resource_probe_ref": "p", "probe_recovered": True,
           "safety_margin_met": True}
    ap, _ = make_resume_approval(
        run_id, w["stop_event_id"], "resource", v, "task_mix",
        stage="S2_SOLUTION", preconditions=pre,
        nonce="nonce-mix-00011122233344", approval_id="apr_mix_1")
    assert mgr.resume_waiting(run_id, ap, pre)["resumed"]
    store.append({"external": "probe", "n": 3})
    assert store.verify_chain()["ok"]
    assert mgr.get_run(run_id).state == "RUNNING"

# ------------------------------------------------------------------ #
def t_schema_crosscheck():
    """结构校验器与 approval-v2.schema.json 交叉验证（jsonschema 可用时）。"""
    try:
        import jsonschema
    except ImportError:
        print("  (skip) jsonschema 未安装，跳过交叉验证")
        return
    schema = json.load(open(os.path.join(REPO, "schemas", "approval-v2.schema.json")))
    store, mgr = fresh()
    run_id = mgr.create_run("task_x", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    w = mgr.raise_waiting(run_id, "prod-write", "x")
    v = mgr.get_run(run_id).state_version
    ap, pre = make_resume_approval(run_id, w["stop_event_id"], "prod-write", v,
                                   "task_x")
    # 合法样例：schema 与内置校验器都放行
    jsonschema.validate(ap, schema)
    ApprovalBroker.validate_structure(ap)
    # 篡改样例：两者都拒绝
    for mut in (lambda a: a.update({"schema_version": "1.9"}),
                lambda a: a.update({"decision": "maybe"}),
                lambda a: a.update({"nonce": "short"}),
                lambda a: a.pop("actor"),
                lambda a: a["payload"].pop("objective_precondition_hash"),
                # P0-4 新增：缺绑定字段 / 跨类型混字段 / 非 40-hex watermark
                lambda a: a.pop("key_id"),
                lambda a: a.pop("policy_hash"),
                lambda a: a.pop("stage"),
                lambda a: a.update({"input_watermark": "zz-not-a-sha"}),
                lambda a: a["payload"].update({"repo_id": "cross-type"})):
        bad = json.loads(json.dumps(ap))
        mut(bad)
        try:
            jsonschema.validate(bad, schema)
            schema_rejects = False
        except jsonschema.ValidationError:
            schema_rejects = True
        try:
            ApprovalBroker.validate_structure(bad)
            mine_rejects = False
        except ApprovalRejected:
            mine_rejects = True
        assert schema_rejects and mine_rejects, f"分歧: schema={schema_rejects} mine={mine_rejects} on {bad}"

TESTS = [
    ("规则引擎（七段/转换/双轴/九类前置/bool 客观化）", t_rule_engine),
    ("全流程七段 PASS → SUCCEEDED + 重放一致", t_happy_path),
    ("FAIL 重试 → 新 attempt_id，旧 attempt 不可变", t_retry_new_attempt),
    ("九类停等 raise→resume（必要且充分）", t_waiting_resume_happy),
    ("审批拒绝路径（结构/TTL/绑定/CAS/前置/哈希/验签）", t_approval_rejections),
    ("并发双消费：恰好一个成功", t_concurrent_double_consume),
    ("COMPLETED_CONDITIONAL 终态 + risk 授权指纹匹配", t_conditional_terminal),
    ("cancel/supersede/not_found/FAILED", t_cancel_supersede_notfound),
    ("与 EventStore.append 交错链完整性", t_eventstore_interop),
    ("与 approval-v2 schema 交叉验证", t_schema_crosscheck),
]
if __name__ == "__main__":
    for name, fn in TESTS:
        check(name, fn)
    print(f"\nP0-2 状态机+审批 Broker: {PASS_N} PASS / {FAIL_N} FAIL")
    sys.exit(1 if FAIL_N else 0)

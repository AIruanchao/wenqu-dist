#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_wenqu_adversarial.py——Codex 第三轮（38/100 BLOCKED）十条对抗实锤的
逐条 fail-closed 回归。每条测试对应一个已被实证可打穿的洞；现在必须全拒。

  #1  伪签名+缺绑定：删 envelope 字段 + 伪 actor/signature 仍可 resume
  #2  跨类型 payload：risk payload 混入 resume 字段同时过 Schema 和 Broker
  #3  前置自报：probe_recovered="false"（字符串）被当真
  #4  绑定绕过：非 40 位 input_watermark 跳过 SHA 比较；错 policy/ruleset 被忽略
  #5  非 resume 无 CAS：risk 授权不比较 expected_state_version
  #6  双轴洗白：S7 TIMEOUT+CONDITIONAL → COMPLETED_CONDITIONAL；HIGH 风险包可消费
  #7  控制事件直写：公共 EventStore.append 注入 RUN_COMPLETED/PASS
  #8  第二正源：仅复制 pipeline_events 后同一 nonce 可再消费
  #9  自产事件不过 run-event-v2（WAITING 扩展字段 additionalProperties=false 拒绝）
  #10 action saga（ACTION_* control_outbox、receipt 对账）
  #11 F4-AUTH-001（Codex 第四轮实锤）：ActionSaga 无授权可提交——
      approval_consumptions=0 时 reserve→start→commit 对 release/production
      照样走通、receipt 为调用方自报字符串。根修后：reserve_action 必传
      action 类型 HMAC 审批（consume_authorization 路径：验签+绑定+payload
      判别+state_version CAS）；自报 receipt 只能 PROVISIONAL，commit 必须
      外部正源对账（action-execution-receipt 验签+水印/动作一致性）；
      重放校验授权消费链（reserved 必须有对应 APPROVAL_CONSUMED）。
      adv10 同步升级为授权链语义（原断言保留/诚实更新，只增不减）。

另含：K 项 CLI 端到端链（wenquctl create→…→complete）。
"""
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope
from wenqu_core.store import (EventStore, is_control_event)
from wenqu_core.wenqu_pipeline import (
    SevenStageStateMachine as SM, ApprovalBroker, RunManager, ActionSaga,
    PipelineCorruptionError, PipelineError, ApprovalRejected,
    ApprovalReuseError, ApprovalPreconditionError, ActionError, STAGES,
    RECEIPT_PROVISIONAL, RECEIPT_RECONCILED,
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

def expect(exc, fn, contains=None):
    try:
        fn()
    except exc as e:
        if contains is not None and contains not in str(e):
            raise AssertionError(
                f"expected {exc.__name__} containing {contains!r}, got: {e}")
        return
    except Exception as e:
        raise AssertionError(f"expected {exc.__name__}, got {type(e).__name__}: {e}")
    raise AssertionError(f"expected {exc.__name__}, nothing raised")

KEYRING = ApprovalKeyring.from_path(
    os.path.join(REPO, "tests", "fixtures", "approval-keys.json"))
KEY_ID = "key_test_1"
SECRET = KEYRING.get(KEY_ID)

IDENT = {
    "commit_sha": "a" * 40,
    "environment": "staging",
    "scope_hash": "scope-hash-001",
    "repo_id": "qisemi-erp",
    "ruleset_hash": "rules-7",
    "policy_hash": "policy-sha-001",
}

def fresh():
    tmp = tempfile.mkdtemp(prefix="wenqu-adv-")
    store = EventStore(os.path.join(tmp, "events.db"))
    return store, RunManager(store, keyring=KEYRING)

def resign(ap):
    ap = dict(ap)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(SECRET, ap)
    return ap

SECRET2 = KEYRING.get("key_test_2")  # 第二签发人 key（fixtures 双 active key）


def cosign(ap, *, second_key_id="key_test_2", second_actor="erge",
           primary_actor="chaoge"):
    """R7-AUTH-DUAL-CONSUME-005：给已主签的信封补嵌入联签数组。

    联签条目各对「信封体」（envelope 去掉 signature/cosignatures）独立
    HMAC——主签条目复用 envelope.signature（同一信封体同一 key），第二
    条目用第二 key 现算。返回新 dict（原信封不变）。
    """
    body = {k: v for k, v in ap.items()
            if k not in ("signature", "cosignatures")}
    out = dict(ap)
    out["cosignatures"] = [
        {"key_id": ap["key_id"], "actor": primary_actor,
         "signature": ap["signature"]},
        {"key_id": second_key_id, "actor": second_actor,
         "signature": sign_envelope(KEYRING.get(second_key_id), body)},
    ]
    return out


def descriptor_of(ap):
    """exact action descriptor：调用方实参声明的动作描述（=审批 payload 副本）。"""
    return dict(ap["payload"])

def make_resume(run_id, stop_event_id, stop_type, state_version, task_id,
                stage="S1_REQUIREMENT", preconditions=None, **over):
    pre = dict(preconditions if preconditions is not None
               else {"gate_reference": "g1", "rollback_level": "R2"})
    ap = {
        "schema_version": "2.0", "approval_id": "apr_adv_resume",
        "approval_type": "resume", "key_id": KEY_ID,
        "run_id": run_id, "task_id": task_id,
        "stop_event_id": stop_event_id, "stop_type": stop_type,
        "stage": stage, "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "actor": "attacker", "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_state_version": state_version,
        "nonce": "nonce-adv-000011112222", "decision": "approve",
        "signature": "",
        "payload": {"stop_event_id": stop_event_id, "stop_type": stop_type,
                    "objective_precondition_hash":
                        SM.objective_precondition_hash(pre)},
    }
    ap.update(over)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(SECRET, ap)
    return ap, pre

def make_risk(run_id, task_id, state_version, *, fingerprints=None,
              severity="MEDIUM", **over):
    ap = {
        "schema_version": "2.0", "approval_id": "apr_adv_risk",
        "approval_type": "risk", "key_id": KEY_ID,
        "run_id": run_id, "task_id": task_id,
        "stop_event_id": "n/a-soft-terminal", "stop_type": "scope",
        "stage": "S7_GATE", "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "actor": "attacker", "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_state_version": state_version,
        "nonce": "nonce-adv-risk-0001", "decision": "approve",
        "signature": "",
        "payload": {"finding_fingerprints":
                        list(fingerprints if fingerprints is not None else ["fp-soft"]),
                    "severity": severity, "reason": "risk" * 4,
                    "compensating_controls": ["ctrl-1"],
                    "expiry": "2099-12-31T00:00:00Z"},
    }
    ap.update(over)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(SECRET, ap)
    return ap

# ====================================================================== #
# F4-AUTH-001：action 类型审批与外部正源回执构造器
# ====================================================================== #
_ACTION_TYPE_TO_APPROVAL = {
    "prod-write": "prod_write", "prod_write": "prod_write",
    "fund-auth": "fund_auth", "fund_auth": "fund_auth",
    "merge": "merge", "release": "release", "ddl": "ddl",
    "rollback": "rollback",
}
ACTION_PAYLOADS = {
    "merge": {"repo_id": "qisemi-erp", "base_sha": "b" * 40,
              "head_sha": "c" * 40, "merge_method": "merge"},
    "release": {"release_id": "rel-77", "artifact_sha256": "d" * 64,
                "manifest_sha256": "e" * 64,
                "environment": IDENT["environment"],
                "previous_release_id": "rel-76"},
    "ddl": {"database_identity": "db://staging/erp",
            "statement_digest": "f" * 64, "before_schema_hash": "1" * 64,
            "after_schema_hash": "2" * 64, "backup_id": "bak-1",
            "rollback_plan_hash": "3" * 64},
    "prod_write": {"operation_digest": "4" * 64, "data_scope_digest": "5" * 64,
                   "idempotency_key": "idem-77", "conservation_hash": "6" * 64},
    "fund_auth": {"subject_role": "ops", "amount_scope_digest": "9" * 64,
                  "positive_negative_test_hash": "8" * 64,
                  "audit_target": "audit-1"},
    "rollback": {"failed_deployment_id": "dep-9",
                 "exact_previous_release_id": "rel-70", "trigger": "gate-red",
                 "schema_compatibility_hash": "7" * 64},
}

def make_action_approval(run_id, task_id, state_version, action_type, *,
                         stage="S1_REQUIREMENT", nonce=None, payload=None,
                         **over):
    """action 类型审批（approval-v2 全信封 + 测试密钥 HMAC 签名）。"""
    ap_type = _ACTION_TYPE_TO_APPROVAL[action_type]
    ap = {
        "schema_version": "2.0",
        "approval_id": f"apr_act_{ap_type}_{os.urandom(3).hex()}",
        "approval_type": ap_type, "key_id": KEY_ID,
        "run_id": run_id, "task_id": task_id,
        "stop_event_id": "n/a-action-reserve", "stop_type": "prod-write",
        "stage": stage, "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "actor": "chaoge", "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_state_version": state_version,
        "nonce": nonce or f"nonce-act-{ap_type}-{os.urandom(6).hex()}",
        "decision": "approve", "signature": "",
        "payload": dict(payload if payload is not None
                        else ACTION_PAYLOADS[ap_type]),
    }
    ap.update(over)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(SECRET, ap)
    return ap

def make_external_receipt(action, run_id, watermark, *, outcome="COMMITTED",
                          external_ref="ext-deploy-77", **over):
    """外部正源回执（action-execution-receipt v1.0 + 测试密钥 HMAC 签名）。

    action 传 reserve_action 的返回 dict（取 action_id/action_type/
    action_target 做一致性绑定）。
    """
    rc = {
        "schema_version": "1.0", "receipt_type": "action-execution-receipt",
        "action_id": action["action_id"], "run_id": run_id,
        "action_type": action["action_type"],
        "action_target": action["action_target"],
        "watermark": watermark, "outcome": outcome,
        "external_ref": external_ref, "ts": "2026-10-08T00:00:00Z",
        "key_id": KEY_ID, "signature": "",
    }
    rc.update(over)
    rc.pop("signature", None)
    rc["signature"] = sign_envelope(SECRET, rc)
    return rc

def soft_s7_run(mgr, task_id="task_adv_soft"):
    """S1..S6 PASS（S7 自动启动），S7 CONDITIONAL（软终态），登记 MEDIUM/P2 finding。"""
    run_id = mgr.create_run(task_id, IDENT)["run_id"]
    for _ in range(6):
        mgr.advance_stage(run_id, execution_status="COMPLETED",
                          policy_verdict="PASS")
    mgr.advance_stage(run_id, execution_status="COMPLETED",
                      policy_verdict="CONDITIONAL")  # S7 已 RUNNING，直接出结果
    mgr.register_finding(run_id, "fnd_soft_1", "fp-soft", "MEDIUM", "P2")
    return run_id

# ====================================================================== #
# Codex 实锤 #1：伪签名 + 缺绑定
# ====================================================================== #
def adv1_envelope_closure():
    store, mgr = fresh()
    run_id = mgr.create_run("task_adv1", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    w = mgr.raise_waiting(run_id, "prod-write", "adv1")
    v = mgr.get_run(run_id).state_version
    base, pre = make_resume(run_id, w["stop_event_id"], "prod-write", v,
                            "task_adv1")
    # 每删一个绑定字段（即便剩余签名/actor 全伪造得再像样）都必拒
    for field in ("task_id", "stage", "environment", "authorized_scope",
                  "policy_hash", "ruleset_hash", "input_watermark",
                  "expected_state_version", "key_id", "nonce", "signature"):
        bad = json.loads(json.dumps(base))
        bad["signature"] = "f" * 64  # 伪签名（形状合法）
        bad["actor"] = "ceo-forged"
        del bad[field]
        expect(ApprovalRejected,
               lambda b=bad: mgr.resume_waiting(run_id, b, pre))
    # 伪造但格式合法的签名（64-hex 但 HMAC 不对）→ 验签失败
    bad = dict(base); bad["signature"] = "0" * 64
    expect(ApprovalRejected, lambda: mgr.resume_waiting(run_id, bad, pre),
           contains="signature")
    # 未知 key_id（用真 secret 自签也不行——key 未登记）→ 拒
    bad = dict(base); bad["key_id"] = "key_rogue_1"
    bad = resign(bad)
    expect(ApprovalRejected, lambda: mgr.resume_waiting(run_id, bad, pre),
           contains="key_id")
    # 原样（正确签名）放行——fail-closed 不是 fail-everything
    rec = mgr.resume_waiting(run_id, base, pre)
    assert rec["resumed"] is True

# ====================================================================== #
# Codex 实锤 #2：跨类型 payload + API 路由
# ====================================================================== #
def adv2_payload_discrimination():
    store, mgr = fresh()
    run_id = mgr.create_run("task_adv2", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    w = mgr.raise_waiting(run_id, "prod-write", "adv2")
    v = mgr.get_run(run_id).state_version
    # risk payload 混入 resume 专属字段：Broker 结构层拒（键集封闭）
    mixed = make_risk(run_id, "task_adv2", v,
                      payload={"finding_fingerprints": ["fp"], "severity":
                               "MEDIUM", "reason": "x" * 12,
                               "compensating_controls": ["c"],
                               "expiry": "2099-12-31T00:00:00Z",
                               # 混入他类字段：
                               "stop_event_id": w["stop_event_id"],
                               "objective_precondition_hash": "a" * 64})
    expect(ApprovalRejected, lambda: mgr.authorize_risk(run_id, mixed),
           contains="payload")
    # schema 层同样拒（jsonschema 可用时双验证）
    try:
        import jsonschema
        schema = json.load(open(os.path.join(REPO, "schemas",
                                             "approval-v2.schema.json")))
        try:
            jsonschema.validate(mixed, schema)
            raise AssertionError("schema 应拒绝混入字段")
        except jsonschema.ValidationError:
            pass
    except ImportError:
        pass
    # API 路由：合法签名的 risk 审批喂给 resume_waiting → 拒（只收 resume）
    risk = make_risk(run_id, "task_adv2", v)
    expect(ApprovalRejected, lambda: mgr.resume_waiting(run_id, risk, {}),
           contains="resume")
    # API 路由：合法签名的 resume 审批喂给 authorize_risk → 拒
    resume_ap, pre = make_resume(run_id, w["stop_event_id"], "prod-write", v,
                                 "task_adv2")
    expect(ApprovalRejected, lambda: mgr.authorize_risk(run_id, resume_ap),
           contains="resume")
    # 合法 resume 仍可走通（无假阳性）
    assert mgr.resume_waiting(run_id, resume_ap, pre)["resumed"] is True

# ====================================================================== #
# Codex 实锤 #3：前置自报（字符串 "false" 被当真）
# ====================================================================== #
def adv3_precondition_bool():
    store, mgr = fresh()
    run_id = mgr.create_run("task_adv3", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    w = mgr.raise_waiting(run_id, "resource", "adv3")
    v = mgr.get_run(run_id).state_version
    for probe in ("false", "no", "0", "yes", "true", 1, [True]):
        pre = {"resource_probe_ref": "probe-1", "probe_recovered": probe,
               "safety_margin_met": True}
        ap = make_resume(run_id, w["stop_event_id"], "resource", v,
                         "task_adv3", preconditions=pre)[0]
        expect(ApprovalPreconditionError,
               lambda a=ap, p=pre: mgr.resume_waiting(run_id, a, p))
    # 真 bool True + 哈希绑定正确 → 放行
    pre = {"resource_probe_ref": "probe-1", "probe_recovered": True,
           "safety_margin_met": True}
    ap = make_resume(run_id, w["stop_event_id"], "resource", v, "task_adv3",
                     preconditions=pre)[0]
    assert mgr.resume_waiting(run_id, ap, pre)["resumed"] is True

# ====================================================================== #
# Codex 实锤 #4：绑定绕过（非 40 位 watermark 跳过比较；错 policy/ruleset 忽略）
# ====================================================================== #
def adv4_binding_bypass():
    store, mgr = fresh()
    run_id = mgr.create_run("task_adv4", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    w = mgr.raise_waiting(run_id, "prod-write", "adv4")
    v = mgr.get_run(run_id).state_version
    base, pre = make_resume(run_id, w["stop_event_id"], "prod-write", v,
                            "task_adv4")
    # 非 40-hex watermark（结构层拒——不再存在"格式不对就不比较"的旁路）
    for bad_wm in ("not-a-sha", "a" * 39, "a" * 41, "A" * 40, "z" * 40, 12345):
        bad = dict(base); bad["input_watermark"] = bad_wm
        expect(ApprovalRejected, lambda b=bad: mgr.resume_waiting(run_id, b, pre),
               contains="input_watermark")
    # 40-hex 但错 SHA → 拒（无条件比较；重签保证签名有效）
    bad = resign(dict(base, input_watermark="b" * 40))
    expect(ApprovalRejected, lambda: mgr.resume_waiting(run_id, bad, pre),
           contains="commit_sha")
    # 错 policy_hash / ruleset_hash：重签保证签名有效——证明是绑定在拒
    bad = resign(dict(base, policy_hash="policy-EVIL"))
    expect(ApprovalRejected, lambda: mgr.resume_waiting(run_id, bad, pre),
           contains="policy_hash")
    bad = resign(dict(base, ruleset_hash="rules-EVIL"))
    expect(ApprovalRejected, lambda: mgr.resume_waiting(run_id, bad, pre),
           contains="ruleset_hash")
    # 正确值放行
    assert mgr.resume_waiting(run_id, base, pre)["resumed"] is True

# ====================================================================== #
# Codex 实锤 #5：非 resume 无 CAS
# ====================================================================== #
def adv5_risk_cas():
    store, mgr = fresh()
    run_id = soft_s7_run(mgr, "task_adv5")
    v = mgr.get_run(run_id).state_version
    # 缺 expected_state_version → 结构层拒（全 required）
    ap = make_risk(run_id, "task_adv5", v)
    del ap["expected_state_version"]
    expect(ApprovalRejected, lambda: mgr.authorize_risk(run_id, ap),
           contains="expected_state_version")
    # 错版本 → CAS 拒（重签保持其他全部有效）
    ap = resign(make_risk(run_id, "task_adv5", v + 99))
    expect(ApprovalRejected, lambda: mgr.authorize_risk(run_id, ap),
           contains="state_version")
    # 正确版本 + 指纹匹配 → 放行
    rec = mgr.authorize_risk(run_id, make_risk(run_id, "task_adv5", v))
    assert rec["consumed"] is True

# ====================================================================== #
# Codex 实锤 #6：双轴洗白（TIMEOUT+CONDITIONAL → 软终态/CONDITIONAL 完成；
#                    HIGH 风险包消费；完全不匹配指纹完成 run）
# ====================================================================== #
def adv6_dual_axis():
    store, mgr = fresh()
    # (a) attempt 层：S7 TIMEOUT + CONDITIONAL → FAILED（不是软终态）
    run_id = mgr.create_run("task_adv6a", IDENT)["run_id"]
    for _ in range(6):
        mgr.advance_stage(run_id, execution_status="COMPLETED",
                          policy_verdict="PASS")
    out = mgr.advance_stage(run_id, execution_status="TIMEOUT",
                            policy_verdict="CONDITIONAL")
    assert out["attempt_status"] == "FAILED", out
    done = mgr.complete_run(run_id)
    assert done["final_state"] == "FAILED", done
    # (b) 事件层：RUN_COMPLETED 带 TIMEOUT+CONDITIONAL → 重放即 Corruption
    run_id2 = mgr.create_run("task_adv6b", IDENT)["run_id"]
    mgr.advance_stage(run_id2)
    st = mgr.get_run(run_id2)
    forged = {
        "schema_version": "2.0", "event_type": "RUN_COMPLETED",
        "run_id": run_id2, "task_id": "task_adv6b",
        "execution_status": "TIMEOUT", "policy_verdict": "CONDITIONAL",
        "identity": dict(st.identity), "state_version": st.state_version + 1,
        "ts": "2026-10-08T00:00:00Z", "actor": "attacker",
        "terminal_reason": "wash"}
    sealed = {k: v for k, v in forged.items()}
    sealed["seal"] = "0" * 64  # 伪 seal
    import wenqu_core.wenqu_pipeline as wp
    wp._PipelineDb.append_event(mgr._db._conn, sealed)
    expect(PipelineCorruptionError, lambda: mgr.get_run(run_id2))
    # (c) HIGH finding：authorize_risk 机器拒绝 + complete 拒绝
    store2, mgr2 = fresh()
    run_id3 = soft_s7_run(mgr2, "task_adv6c")
    mgr2.register_finding(run_id3, "fnd_high_1", "fp-high", "HIGH", "P1")
    v3 = mgr2.get_run(run_id3).state_version
    ap_high = make_risk(run_id3, "task_adv6c", v3, fingerprints=["fp-high"],
                        severity="HIGH")
    expect(ApprovalRejected, lambda: mgr2.authorize_risk(run_id3, ap_high),
           contains="不可风险接受")
    # 用 MEDIUM severity 声明但指纹声称覆盖 HIGH finding → 精确匹配拒绝
    ap_spoof = make_risk(run_id3, "task_adv6c", v3,
                         fingerprints=["fp-high", "fp-soft"], severity="MEDIUM")
    expect(ApprovalRejected, lambda: mgr2.authorize_risk(run_id3, ap_spoof),
           contains="精确匹配")
    # complete：run 有 HIGH/P1 finding → CONDITIONAL 机器拒绝（即使有
    # 覆盖 MEDIUM 面的有效 risk 授权）
    ok_risk = make_risk(run_id3, "task_adv6c", v3, fingerprints=["fp-soft"])
    assert mgr2.authorize_risk(run_id3, ok_risk)["consumed"] is True
    expect(PipelineError, lambda: mgr2.complete_run(run_id3),
           contains="不得风险接受")
    assert mgr2.get_run(run_id3).state == "RUNNING"  # 未被洗白成终态
    # 对照组：仅 MEDIUM/P2 finding + 匹配授权 → COMPLETED_CONDITIONAL 成立
    store3, mgr3 = fresh()
    run_id4 = soft_s7_run(mgr3, "task_adv6d")
    v4 = mgr3.get_run(run_id4).state_version
    assert mgr3.authorize_risk(run_id4, make_risk(run_id4, "task_adv6d", v4))[
        "consumed"] is True
    assert mgr3.complete_run(run_id4)["final_state"] == "COMPLETED_CONDITIONAL"

# ====================================================================== #
# Codex 实锤 #7：控制事件直写（公共 EventStore.append 注入）
# ====================================================================== #
def adv7_control_event_injection():
    store, mgr = fresh()
    run_id = mgr.create_run("task_adv7", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    st = mgr.get_run(run_id)
    # 公共 append 注入 RUN_COMPLETED/PASS → ValueError（写入口守卫）
    forged = {"schema_version": "2.0", "event_type": "RUN_COMPLETED",
              "run_id": run_id, "task_id": "task_adv7",
              "execution_status": "COMPLETED", "policy_verdict": "PASS",
              "identity": dict(st.identity),
              "state_version": st.state_version + 1,
              "ts": "2026-10-08T00:00:00Z", "actor": "attacker"}
    expect(ValueError, lambda: store.append(forged))
    for etype in ("WAITING_RAISED", "APPROVAL_CONSUMED", "ACTION_STARTED",
                  "STAGE_COMPLETED", "SUPERSEDED", "FINDING_REGISTERED",
                  "RUN_CREATED"):
        bad = dict(forged); bad["event_type"] = etype
        expect(ValueError, lambda b=bad: store.append(b))
    # 外部普通事件不受影响（写入口保持可用）
    store.append({"external": "probe", "n": 1})
    # 绕过 append 直插（模拟 SQL 级注入，带正确链哈希但无 seal）
    # → 重放逐条验封 → PipelineCorruptionError
    import wenqu_core.wenqu_pipeline as wp
    st = mgr.get_run(run_id)
    forged["state_version"] = st.state_version + 1
    wp._PipelineDb.append_event(mgr._db._conn, forged)  # 无 seal 直插
    expect(PipelineCorruptionError, lambda: mgr.get_run(run_id))
    assert is_control_event(forged) and not is_control_event({"x": 1})

# ====================================================================== #
# Codex 实锤 #8：第二正源（仅复制 pipeline_events 后 nonce 可再消费）
# ====================================================================== #
def adv8_event_source_of_truth():
    tmp = tempfile.mkdtemp(prefix="wenqu-adv8-")
    db1 = os.path.join(tmp, "a.db")
    store1 = EventStore(db1)
    mgr1 = RunManager(store1, keyring=KEYRING)
    run_id = mgr1.create_run("task_adv8", IDENT)["run_id"]
    mgr1.advance_stage(run_id)
    w = mgr1.raise_waiting(run_id, "prod-write", "adv8")
    v = mgr1.get_run(run_id).state_version
    ap, pre = make_resume(run_id, w["stop_event_id"], "prod-write", v,
                          "task_adv8")
    assert mgr1.resume_waiting(run_id, ap, pre)["resumed"] is True
    # 同库二次消费 → 拒（旁表路径）
    expect(ApprovalReuseError, lambda: mgr1.resume_waiting(run_id, ap, pre))
    # 仅复制 pipeline_events 到新库（模拟"正源迁移/旁表丢失"）
    db2 = os.path.join(tmp, "b.db")
    store2 = EventStore(db2)
    rows = store1._conn.execute(
        "SELECT event_id, payload, prev_event_hash, event_hash, created_at "
        "FROM pipeline_events ORDER BY seq ASC").fetchall()
    store2._conn.execute("BEGIN IMMEDIATE")
    for row in rows:
        store2._conn.execute(
            "INSERT INTO pipeline_events (event_id, payload, prev_event_hash, "
            "event_hash, created_at) VALUES (?, ?, ?, ?, ?)", row)
    store2._conn.execute("COMMIT")
    assert store2.verify_chain()["ok"]
    mgr2 = RunManager(store2, keyring=KEYRING)
    st2 = mgr2.get_run(run_id)
    assert st2.state == "RUNNING"          # 事件流重放还原全部状态
    assert st2.consumed_nonce_digests, "APPROVAL_CONSUMED 应折叠进消费面"
    assert mgr2.broker.consumed_approvals(run_id=run_id) == []  # 旁表为空
    # 同一 nonce 在新库再消费 → 拒（事件正源，不依赖旁表）
    w2 = mgr2.raise_waiting(run_id, "resource", "adv8-second")
    v2 = mgr2.get_run(run_id).state_version
    pre2 = {"resource_probe_ref": "p", "probe_recovered": True,
            "safety_margin_met": True}
    ap_old_nonce = make_resume(run_id, w2["stop_event_id"], "resource", v2,
                               "task_adv8", preconditions=pre2,
                               nonce="nonce-adv-000011112222")[0]
    expect(ApprovalReuseError,
           lambda: mgr2.resume_waiting(run_id, ap_old_nonce, pre2))
    # risk 消费同样以事件为正源（新库中已消费 risk 不可再消费）
    r = soft_s7_run(mgr2, "task_adv8_risk")
    vr = mgr2.get_run(r).state_version
    risk_ap = make_risk(r, "task_adv8_risk", vr)
    assert mgr2.authorize_risk(r, risk_ap)["consumed"] is True
    risk_ap2 = resign(risk_ap)  # 同 nonce 同内容（签名重算一致）
    expect(ApprovalReuseError, lambda: mgr2.authorize_risk(r, risk_ap2))

# ====================================================================== #
# Codex 实锤 #9：自产事件全部通过 run-event-v2（含 WAITING 扩展字段 + seal）
# ====================================================================== #
def adv9_schema_roundtrip():
    try:
        import jsonschema
        from jsonschema import FormatChecker
    except ImportError:
        print("  (skip) jsonschema 未安装，跳过 schema 往返验证")
        return
    # jsonschema 的 date-time 检查依赖 rfc3339-validator（未装则空转）——
    # 注册严格 ISO8601 检查，保证 FormatChecker 用例是真验证。
    from datetime import datetime as _dt

    @FormatChecker.cls_checks("date-time")
    def _strict_date_time(value):
        if not isinstance(value, str):
            return True
        text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
        try:
            _dt.fromisoformat(text)
            return True
        except ValueError:
            return False
    schema = json.load(open(os.path.join(REPO, "schemas",
                                         "run-event-v2.schema.json")))
    validator = jsonschema.Draft7Validator(schema,
                                           format_checker=FormatChecker())
    tmp = tempfile.mkdtemp(prefix="wenqu-adv9-")
    store = EventStore(os.path.join(tmp, "events.db"))
    mgr = RunManager(store, keyring=KEYRING)
    # 富事件流：create/advance/raise/resume/finding/risk/complete/action saga
    run_id = mgr.create_run("task_adv9", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    # F4-AUTH-001（诚实更新）：action 预留必传审批——原 "deploy" 无审批类型
    # 映射，改用 release 动作 + 签发的 release 审批（锚定 S1 RUNNING/版本 2）。
    # R7 诚实更新：release 高危——补双联签 + exact descriptor（原断言保留）
    rel_ap = cosign(make_action_approval(run_id, "task_adv9", 2, "release"))
    mgr.reserve_action(run_id, "release", "db://prod/erp", rel_ap,
                       actor="adv9",
                       action_descriptor=descriptor_of(rel_ap))
    mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="PASS")
    w = mgr.raise_waiting(run_id, "prod-write", "adv9")
    v = mgr.get_run(run_id).state_version
    pre = {"gate_reference": "g1", "rollback_level": "R2"}
    ap = make_resume(run_id, w["stop_event_id"], "prod-write", v, "task_adv9",
                     preconditions=pre, stage="S2_SOLUTION")[0]
    assert mgr.resume_waiting(run_id, ap, pre)["resumed"] is True
    mgr.register_finding(run_id, "fnd_adv9", "fp-adv9", "MEDIUM", "P2")
    # 逐事件过 run-event-v2 + FormatChecker
    n = 0
    for _seq, _hash, payload in store._conn.execute(
            "SELECT seq, event_hash, payload FROM pipeline_events "
            "ORDER BY seq ASC"):
        validator.validate(json.loads(payload))
        n += 1
    assert n >= 8, f"expect rich event stream, got {n}"
    # 负例：扩展字段时代已过去——ERROR+PASS / PASS+findings / 未知字段全拒
    base_ev = {"schema_version": "2.0", "event_type": "RUN_COMPLETED",
               "run_id": "run_x", "task_id": "t",
               "identity": dict(IDENT), "state_version": 2,
               "ts": "2026-10-08T00:00:00Z", "actor": "a",
               "seal": "0" * 64}
    validator.validate(dict(base_ev, execution_status="COMPLETED",
                            policy_verdict="CONDITIONAL"))  # 正例过
    for bad in (dict(base_ev, execution_status="ERROR", policy_verdict="PASS"),
                dict(base_ev, execution_status="COMPLETED",
                     policy_verdict="PASS", findings=["fnd_x"]),
                dict(base_ev, execution_status="COMPLETED",
                     policy_verdict="PASS", rogue_field=1)):
        try:
            validator.validate(bad)
            raise AssertionError(f"schema 应拒绝: {bad}")
        except jsonschema.ValidationError:
            pass
    # FormatChecker：坏日期拒绝
    bad = dict(base_ev, execution_status="COMPLETED", policy_verdict="FAIL",
               ts="not-a-date")
    try:
        validator.validate(bad)
        raise AssertionError("FormatChecker 应拒绝坏日期")
    except jsonschema.ValidationError:
        pass

# ====================================================================== #
# Codex 实锤 #10：action saga（control_outbox + receipt 对账）
# F4-AUTH-001 升级：授权消费链 + receipt 分级 + 外部正源对账
# （原断言保留/诚实更新：commit 与 reconcile 语义按授权链根修更新，只增不减）
# ====================================================================== #
def adv10_action_saga():
    store, mgr = fresh()
    run_id = mgr.create_run("task_adv10", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    v = mgr.get_run(run_id).state_version
    target = "db://prod/erp#batch-77"
    # 纯规则引擎（原断言保留）
    ActionSaga.validate_transition("RESERVED", "STARTED")
    ActionSaga.validate_transition("STARTED", "COMMITTED")
    expect(ActionError, lambda: ActionSaga.validate_transition(
        "RESERVED", "COMMITTED"))
    expect(ActionError, lambda: ActionSaga.validate_transition(
        "COMMITTED", "STARTED"))
    # F4-AUTH-001：零审批预留必拒；无审批类型映射的 action_type 必拒；
    # 类型不符审批（真密钥签发的 ddl 审批喂 prod-write action）必拒
    expect(ActionError, lambda: mgr.reserve_action(run_id, "prod-write", target))
    expect(ActionError, lambda: mgr.reserve_action(
        run_id, "deploy", target,
        make_action_approval(run_id, "task_adv10", v, "release")))
    wrong = make_action_approval(run_id, "task_adv10", v, "ddl")
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, wrong))
    # 生命周期（授权链版）：签发 prod-write 审批（R7：高危补双联签）→ RESERVED
    ap = cosign(make_action_approval(run_id, "task_adv10", v, "prod-write"))
    r = mgr.reserve_action(run_id, "prod-write", target, ap,
                           action_descriptor=descriptor_of(ap))
    aid = r["action_id"]
    assert r["action_state"] == "RESERVED"
    assert r["approval_id"].startswith("apr_") and len(r["nonce_digest"]) == 64
    st = mgr.get_run(run_id)
    assert st.actions[aid]["approval_id"] == r["approval_id"]
    assert st.actions[aid]["nonce_digest"] == r["nonce_digest"]
    # 审批一次性：同一审批（同 nonce）二次预留 → 复用拒绝
    expect(ApprovalReuseError,
           lambda: mgr.reserve_action(run_id, "prod-write", target, ap))
    # RESERVED → STARTED（自报 receipt 只能 PROVISIONAL 分级）
    s = mgr.start_action(run_id, aid, receipt="deploy-77 started by caller")
    assert s["action_state"] == "STARTED"
    st = mgr.get_run(run_id)
    assert st.actions[aid]["receipt_status"] == RECEIPT_PROVISIONAL
    assert st.actions[aid]["receipt"].startswith("PROVISIONAL|")
    # 非法：重复 START（原断言保留）
    expect(ActionError, lambda: mgr.start_action(run_id, aid))
    # F4-AUTH-001：自报字符串 commit 必拒——必须停在 PROVISIONAL 不可 COMMITTED
    expect(ActionError, lambda: mgr.commit_action(run_id, aid, "receipt:deploy-77:ok"))
    st = mgr.get_run(run_id)
    assert st.actions[aid]["action_state"] == "STARTED"
    assert st.actions[aid]["receipt_status"] == RECEIPT_PROVISIONAL
    # 伪签名外部回执必拒；水印不一致必拒；target 移花接木必拒
    bad = make_external_receipt(r, run_id, IDENT["commit_sha"])
    bad["signature"] = "0" * 64
    expect(ActionError, lambda: mgr.commit_action(run_id, aid, bad))
    expect(ActionError, lambda: mgr.commit_action(
        run_id, aid, make_external_receipt(r, run_id, "b" * 40)))
    expect(ActionError, lambda: mgr.commit_action(
        run_id, aid, make_external_receipt(
            r, run_id, IDENT["commit_sha"],
            action_target="db://prod/EVIL#batch-77")))
    # 对账实装：验签+水印/动作一致 → reconciled=True；commit → COMMITTED
    good = make_external_receipt(r, run_id, IDENT["commit_sha"])
    rec = mgr.reconcile_receipt(run_id, aid, good)
    assert rec["reconciled"] is True and rec["outcome"] == "COMMITTED"
    c = mgr.commit_action(run_id, aid, good)
    assert c["action_state"] == "COMMITTED"
    assert c["receipt_status"] == RECEIPT_RECONCILED
    st = mgr.get_run(run_id)
    assert st.actions[aid]["receipt"].startswith("RECONCILED|")
    assert st.actions[aid]["receipt_status"] == RECEIPT_RECONCILED
    # 终态后不可再变更（原断言保留，语义升级为授权链终态）
    expect(ActionError, lambda: mgr.commit_action(run_id, aid, good))
    expect(ActionError, lambda: mgr.start_action(run_id, aid))
    # FAILED_UNKNOWN 终态路径（另一个 action：ddl 审批 + 对账不了收口；
    # R7 诚实更新：ddl 高危补双联签 + descriptor）
    ap2 = cosign(make_action_approval(run_id, "task_adv10",
                                      mgr.get_run(run_id).state_version,
                                      "ddl"))
    r2 = mgr.reserve_action(run_id, "ddl", "db://staging/schema", ap2,
                            action_descriptor=descriptor_of(ap2))
    aid2 = r2["action_id"]
    mgr.start_action(run_id, aid2)
    f = mgr.fail_action(run_id, aid2, "runner crash; outcome unknown")
    assert f["action_state"] == "FAILED_UNKNOWN"
    expect(ActionError, lambda: mgr.start_action(run_id, aid2))
    # FAILED_UNKNOWN 终态：reconcile 不再裁决（reconciled=None，终态收口）
    rec = mgr.reconcile_receipt(run_id, aid2, {"anything": 1})
    assert rec["reconciled"] is None and "FAILED_UNKNOWN" in rec["note"]
    expect(ActionError, lambda: mgr.reconcile_receipt(
        run_id, "act_ghost", {"x": 1}))
    # 伪签名回执在 STARTED 动作上同样 reconciled=False（原 TAMPERED 断言语义升级）
    # （merge 低危：无联签要求——descriptor 仍必填）
    ap3 = make_action_approval(run_id, "task_adv10",
                               mgr.get_run(run_id).state_version, "merge")
    r3 = mgr.reserve_action(run_id, "merge", "repo://qisemi-erp/pr-9", ap3,
                            action_descriptor=descriptor_of(ap3))
    aid3 = r3["action_id"]
    mgr.start_action(run_id, aid3, receipt="merge attempt started")
    tampered = make_external_receipt(r3, run_id, IDENT["commit_sha"])
    tampered["external_ref"] = "ext-TAMPERED"  # 签名后篡改 → 验签失败
    rec = mgr.reconcile_receipt(run_id, aid3, tampered)
    assert rec["reconciled"] is False
    # 重放一致性：action 聚合（含授权消费链与 receipt 分级）随事件流重建
    mgr2 = RunManager(store, keyring=KEYRING)
    st2 = mgr2.get_run(run_id)
    assert st2.actions[aid]["action_state"] == "COMMITTED"
    assert st2.actions[aid]["receipt"] == mgr.get_run(run_id).actions[aid]["receipt"]
    assert st2.actions[aid]["receipt_status"] == RECEIPT_RECONCILED
    assert st2.actions[aid]["approval_id"] == r["approval_id"]
    assert st2.actions[aid2]["action_state"] == "FAILED_UNKNOWN"
    assert len(st2.consumed_nonce_types) >= 3  # 授权消费链随事件流重建
    # 未知 action 推进 → ActionError（原断言保留）
    expect(ActionError, lambda: mgr.start_action(run_id, "act_nope"))
    assert store.verify_chain()["ok"]
    # 伪造面：带正确 seal 的 ACTION_COMMITTED + 裸串 receipt → 重放 Corruption
    # （receipt 分级由重放强校验——即使 seal 派生规则泄露也伪造不出 COMMITTED）
    import wenqu_core.wenqu_pipeline as wp
    st_now = mgr.get_run(run_id)
    forged = mgr._base_event(
        "ACTION_COMMITTED", st_now, "COMPLETED", "NOT_EVALUATED",
        actor="attacker", state_version=st_now.state_version,
        action_id=aid3, action_type="merge", receipt="receipt:bare:self-report")
    wp._PipelineDb.append_event(mgr._db._conn, wp._seal_event(run_id, forged))
    expect(PipelineCorruptionError, lambda: mgr.get_run(run_id))

# ====================================================================== #
# Codex 第四轮 F4-AUTH-001：ActionSaga 无授权可提交（探针三连复刻）
# ====================================================================== #
def adv11_action_auth_gate():
    """Codex 探针复刻铁律：
    (1) 零审批 reserve 必须拒绝（approval_consumptions 保持 0、事件面零 ACTION_*）；
    (2) 自报 receipt 的 commit 必须停在 PROVISIONAL 不可 COMMITTED；
    (3) 合法链（签发的 action 审批 + 对账回执）能走通。"""
    # -- 探针 (1)：零审批（含未登记密钥自签的伪审批）reserve 必拒 --
    tmp = tempfile.mkdtemp(prefix="wenqu-adv11a-")
    store0 = EventStore(os.path.join(tmp, "events.db"))
    mgr0 = RunManager(store0)  # 无 keyring → 空 keyring（零登记密钥）
    rid0 = mgr0.create_run("task_adv11a", IDENT)["run_id"]
    mgr0.advance_stage(rid0)
    v0 = mgr0.get_run(rid0).state_version
    expect(ActionError,
           lambda: mgr0.reserve_action(rid0, "release", "prod://erp/rel-77"))
    rogue = make_action_approval(rid0, "task_adv11a", v0, "release")
    rogue["key_id"] = "key_rogue_9"
    rogue = resign(rogue)
    expect(ApprovalRejected, lambda: mgr0.reserve_action(
        rid0, "release", "prod://erp/rel-77", rogue))
    assert mgr0.broker.consumed_approvals(run_id=rid0) == []  # 零消费
    assert not mgr0.get_run(rid0).actions                     # 事件面零 ACTION_*
    assert store0.verify_chain()["ok"]

    # -- 探针 (2)+(3)：合法链走通 + 自报 receipt 停 PROVISIONAL --
    store, mgr = fresh()
    run_id = mgr.create_run("task_adv11b", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    v = mgr.get_run(run_id).state_version
    # R7 诚实更新：release 高危补双联签 + descriptor
    ap = cosign(make_action_approval(run_id, "task_adv11b", v, "release"))
    r = mgr.reserve_action(run_id, "release", "prod://erp/rel-77", ap,
                           action_descriptor=descriptor_of(ap))
    aid = r["action_id"]
    assert r["action_state"] == "RESERVED"
    assert len(mgr.broker.consumed_approvals(run_id=run_id)) == 1  # 授权已消费
    mgr.start_action(run_id, aid, receipt="caller self report")
    # 自报字符串 commit 必拒且状态不动
    expect(ActionError, lambda: mgr.commit_action(run_id, aid, "receipt:self:report"))
    st = mgr.get_run(run_id)
    assert st.actions[aid]["action_state"] == "STARTED"
    assert st.actions[aid]["receipt_status"] == RECEIPT_PROVISIONAL
    # 合法收口：签发的外部回执（验签+水印/动作一致）→ COMMITTED
    good = make_external_receipt(r, run_id, IDENT["commit_sha"])
    assert mgr.reconcile_receipt(run_id, aid, good)["reconciled"] is True
    assert mgr.commit_action(run_id, aid, good)["action_state"] == "COMMITTED"

    # -- 重放授权消费链：伪造无 APPROVAL_CONSUMED 的 RESERVED → Corruption --
    import wenqu_core.wenqu_pipeline as wp
    tmp2 = tempfile.mkdtemp(prefix="wenqu-adv11c-")
    store2 = EventStore(os.path.join(tmp2, "events.db"))
    mgr2 = RunManager(store2, keyring=KEYRING)
    rid2 = mgr2.create_run("task_adv11c", IDENT)["run_id"]
    mgr2.advance_stage(rid2)
    st2 = mgr2.get_run(rid2)
    forged = mgr2._base_event(
        "ACTION_AUTH_RESERVED", st2, "COMPLETED", "NOT_EVALUATED",
        actor="attacker", state_version=st2.state_version,
        action_id="act_forge000001", action_type="prod-write",
        action_target="db://prod/erp")
    wp._PipelineDb.append_event(mgr2._db._conn, wp._seal_event(rid2, forged))
    expect(PipelineCorruptionError, lambda: mgr2.get_run(rid2))
    # 伪造面：合法审批预留后，攻击者拿别的 nonce_digest 移花接木 → 重放拒
    store3, mgr3 = fresh()
    rid3 = mgr3.create_run("task_adv11d", IDENT)["run_id"]
    mgr3.advance_stage(rid3)
    v3 = mgr3.get_run(rid3).state_version
    risk_ap = make_risk(rid3, "task_adv11d", v3, stage="S1_REQUIREMENT",
                        fingerprints=[])  # run 无登记 finding → 空覆盖面
    assert mgr3.authorize_risk(rid3, risk_ap)["consumed"] is True
    st3 = mgr3.get_run(rid3)
    risk_digest = st3.consumed_nonce_types and next(
        d for d, t in st3.consumed_nonce_types.items() if t == "risk")
    forged2 = mgr3._base_event(
        "ACTION_AUTH_RESERVED", st3, "COMPLETED", "NOT_EVALUATED",
        actor="attacker", state_version=st3.state_version,
        action_id="act_forge000002", action_type="prod-write",
        action_target="db://prod/erp",
        approval_id="apr_act_prod_write_stolen",
        nonce_digest=risk_digest)  # 移花接木：拿 risk 消费的 nonce 冒充 prod_write
    wp._PipelineDb.append_event(mgr3._db._conn, wp._seal_event(rid3, forged2))
    expect(PipelineCorruptionError, lambda: mgr3.get_run(rid3))
    assert store.verify_chain()["ok"]

# ====================================================================== #
# R7-AUTH-DUAL-CONSUME-005（Codex 第七轮 P0）：高危联签未进消费契约 +
# payload 未绑 reserve_action 实参——消费端双门复验
# ====================================================================== #
def adv12_r7_dual_consume_gates():
    store, mgr = fresh()
    run_id = mgr.create_run("task_r7dual", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    v = mgr.get_run(run_id).state_version
    target = "db://prod/erp#r7"
    good = cosign(make_action_approval(run_id, "task_r7dual", v,
                                       "prod-write"))

    # (1) 高危单签（无 cosignatures——第七轮攻击原样：一名 key 自签自发）
    #     → 消费拒绝，零落账
    single = make_action_approval(run_id, "task_r7dual", v, "prod-write",
                                  nonce="nonce-r7-single-0001")
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, single,
                                      action_descriptor=descriptor_of(single)),
           contains="cosignatures")
    # (1b) 单条联签（数组只有第二 key 一条）= 仍是单签 → 拒
    one_entry = dict(single)
    one_entry["cosignatures"] = [cosign(single)["cosignatures"][1]]
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, one_entry,
                                      action_descriptor=descriptor_of(single)),
           contains="cosignatures")
    # (2) 双签但同 key（两条都真、都 key_test_1）→ 拒
    body = {k: v2 for k, v2 in single.items()
            if k not in ("signature", "cosignatures")}
    same_key = dict(single)
    same_key["cosignatures"] = [
        {"key_id": "key_test_1", "actor": "chaoge",
         "signature": single["signature"]},
        {"key_id": "key_test_1", "actor": "erge",
         "signature": sign_envelope(SECRET, body)}]
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, same_key,
                                      action_descriptor=descriptor_of(single)),
           contains="同 key")
    # (3) cosign 之一 revoked → 拒（第二 key 已吊销的 keyring 上消费）
    store_rev, mgr_rev = fresh()
    rid_rev = mgr_rev.create_run("task_r7rev", IDENT)["run_id"]
    mgr_rev.advance_stage(rid_rev)
    v_rev = mgr_rev.get_run(rid_rev).state_version
    from wenqu_core.approval_keys import KEY_STATUS_REVOKED
    kr_rev = ApprovalKeyring(
        {"key_test_1": SECRET, "key_test_2": SECRET2},
        metadata={"key_test_2": {
            "status": KEY_STATUS_REVOKED,
            "revoked_at": "2026-10-08T00:00:00Z"}})
    mgr_rev2 = RunManager(store_rev, keyring=kr_rev)
    ap_rev = cosign(make_action_approval(rid_rev, "task_r7rev", v_rev,
                                         "prod-write"))
    expect(ApprovalRejected,
           lambda: mgr_rev2.reserve_action(
               rid_rev, "prod-write", target, ap_rev,
               action_descriptor=descriptor_of(ap_rev)),
           contains="联签验签失败")
    # (3b) 联签 key 未登记 → 拒（手工构造——key 不在 keyring，签不出真值）
    rogue = cosign(good)
    rogue["cosignatures"][1] = {"key_id": "key_rogue_2", "actor": "ghost",
                                "signature": "a" * 64}
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, rogue,
                                      action_descriptor=descriptor_of(good)),
           contains="未登记")
    # (3c) 联签伪签名（64-hex 但 HMAC 不对）→ 拒
    forged = cosign(good)
    forged["cosignatures"][1]["signature"] = "0" * 64
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, forged,
                                      action_descriptor=descriptor_of(good)),
           contains="联签验签失败")
    # (4) 低危类型携带 cosignatures → 结构层拒（防「已联签」错觉）
    low_cos = cosign(make_action_approval(run_id, "task_r7dual", v, "merge"))
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "merge", "repo://x/pr-1",
                                      low_cos,
                                      action_descriptor=descriptor_of(low_cos)),
           contains="非高危")
    # (5) payload 与实参不符（descriptor 单字段漂移）→ 拒
    drift = dict(descriptor_of(good), idempotency_key="idem-EVIL")
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, good,
                                      action_descriptor=drift),
           contains="descriptor mismatch")
    # (5b) descriptor 缺失 / 键集不全 / 混入他类字段 → 拒
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, good))
    short = {k: v2 for k, v2 in descriptor_of(good).items()
             if k != "conservation_hash"}
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, good,
                                      action_descriptor=short),
           contains="缺字段")
    foreign = dict(descriptor_of(good), repo_id="erp-evil")
    expect(ApprovalRejected,
           lambda: mgr.reserve_action(run_id, "prod-write", target, good,
                                      action_descriptor=foreign),
           contains="非本类型字段")
    # 全部拒绝面零落账（nonce 未消费、零 ACTION_*、消费台账空）
    st = mgr.get_run(run_id)
    assert not st.actions and not st.consumed_nonce_digests
    assert mgr.broker.consumed_approvals(run_id=run_id) == []

    # (6) 低危（merge/rollback）无联签仍可消费——不误伤
    for act, apv in (("merge", make_action_approval(run_id, "task_r7dual",
                                                    v, "merge")),
                     ("rollback", make_action_approval(
                         run_id, "task_r7dual", v, "rollback"))):
        rec = mgr.reserve_action(run_id, act, f"plan://{act}/r7", apv,
                                 action_descriptor=descriptor_of(apv))
        assert rec["action_state"] == "RESERVED", act
    # (7) 正例：高危双联签 + descriptor 匹配 → 消费成功，事件带对账面
    v_now = mgr.get_run(run_id).state_version
    good = cosign(make_action_approval(run_id, "task_r7dual", v_now,
                                       "prod-write"))
    r = mgr.reserve_action(run_id, "prod-write", target, good,
                           action_descriptor=descriptor_of(good))
    assert r["action_state"] == "RESERVED"
    import hashlib as _hl
    assert r["payload_digest"] == _hl.sha256(json.dumps(
        good["payload"], sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()
    consumed = [json.loads(row[0]) for row in store._conn.execute(
        "SELECT payload FROM pipeline_events").fetchall()
        if json.loads(row[0]).get("event_type") == "APPROVAL_CONSUMED"
        and json.loads(row[0]).get("approval_id") == good["approval_id"]]
    assert len(consumed) == 1
    ev = consumed[0]
    assert ev["payload_digest"] == r["payload_digest"] and len(
        ev["payload_digest"]) == 64
    assert len(ev["cosign_digests"]) == 2
    assert {c["key_id"] for c in ev["cosign_digests"]} == {
        "key_test_1", "key_test_2"}
    assert all(len(c["signature_digest"]) == 64
               for c in ev["cosign_digests"])
    # (8) 篡改消费事件（payload_digest 改一字，不动 seal）→ 重放即 Corruption。
    #     事件表 append-only 触发器挡 UPDATE——模拟具备 DB 写权限的攻击者
    #     （触发器对可直写 SQL 的攻击者不设防，此为既有诚实边界）：
    #     临时摘除触发器改行后再装回，验证 seal+重放对账面双闸仍红。
    rows = store._conn.execute(
        "SELECT rowid, payload FROM pipeline_events ORDER BY seq ASC"
    ).fetchall()
    row = next(r for r in rows
               if json.loads(r[1]).get("event_type") == "APPROVAL_CONSUMED"
               and json.loads(r[1]).get("approval_id")
               == good["approval_id"])
    tampered = dict(json.loads(row[1]), payload_digest="f" * 64)
    store._conn.execute("DROP TRIGGER pipeline_events_append_only_no_update")
    store._conn.execute(
        "UPDATE pipeline_events SET payload = ? WHERE rowid = ?",
        (json.dumps(tampered, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False), row[0]))
    store._conn.execute(
        "CREATE TRIGGER pipeline_events_append_only_no_update BEFORE UPDATE"
        " ON pipeline_events BEGIN SELECT RAISE(ABORT, 'pipeline_events is"
        " append-only: UPDATE is forbidden'); END")
    expect(PipelineCorruptionError, lambda: mgr.get_run(run_id))


# ====================================================================== #
# R7-AUTH-KEY-PERM-006（Codex 第七轮 P1）：0644 keyring 可加载 → loader
# fail-closed（0600/0700）+ 显式豁免清单（tests/fixtures）+ env 通道
# ====================================================================== #
def adv13_r7_keyring_permission_gate():
    import stat as _stat
    from wenqu_core.approval_keys import (
        KEYRING_DEV_FIXTURES_ENV, KeyringPermissionError)
    from wenqu_core import wenqu_pipeline as _wp

    tmp = tempfile.mkdtemp(prefix="wenqu-r7perm-")
    wide = os.path.join(tmp, "wide-keyring.json")
    with open(wide, "w") as fh:
        json.dump({"keys": {"key_wide_1": "s" * 64}}, fh)
    os.chmod(wide, 0o644)

    saved_env = {k: os.environ.get(k) for k in
                 (KEYRING_DEV_FIXTURES_ENV, "WENQU_APPROVAL_KEYRING")}
    try:
        # (1) 0644 keyring（清单外）→ loader 拒（fail-closed）
        os.environ.pop(KEYRING_DEV_FIXTURES_ENV, None)
        expect(KeyringPermissionError,
               lambda: ApprovalKeyring.from_path(wide), contains="0600")
        # (2) fixtures 豁免通道正例：清单内路径 0644 仍可载（发行包自测）
        kr = ApprovalKeyring.from_path(os.path.join(
            REPO, "tests", "fixtures", "approval-keys.json"))
        assert kr.key_ids() == ["key_test_1", "key_test_2"]
        # (3) env=1 显式开豁免 → 同一 0644 路径可载（dev 联调正门）
        os.environ[KEYRING_DEV_FIXTURES_ENV] = "1"
        assert ApprovalKeyring.from_path(wide).key_ids() == ["key_wide_1"]
        # (4) env=0 strict → 连清单内也拒（豁免可自证关闭）
        os.environ[KEYRING_DEV_FIXTURES_ENV] = "0"
        expect(KeyringPermissionError, lambda: ApprovalKeyring.from_path(
            os.path.join(REPO, "tests", "fixtures",
                         "approval-keys.json")))
        os.environ.pop(KEYRING_DEV_FIXTURES_ENV, None)
        # (5) 0755 目录 → 拒；0700 目录 + 0600 成员 → 可载
        kdir = os.path.join(tmp, "keyring-dir")
        os.makedirs(kdir, mode=0o700)
        with open(os.path.join(kdir, "key_d_1.secret"), "w") as fh:
            fh.write("t" * 64 + "\n")
        os.chmod(os.path.join(kdir, "key_d_1.secret"), 0o600)
        assert ApprovalKeyring.from_path(kdir).key_ids() == ["key_d_1"]
        os.chmod(kdir, 0o755)
        expect(KeyringPermissionError,
               lambda: ApprovalKeyring.from_path(kdir), contains="0700")
        # 目录 0700 但成员 secret 0644 → 拒
        os.chmod(kdir, 0o700)
        os.chmod(os.path.join(kdir, "key_d_1.secret"), 0o644)
        expect(KeyringPermissionError,
               lambda: ApprovalKeyring.from_path(kdir), contains="0600")
        # (6) 消费端默认 keyring（WENQU_APPROVAL_KEYRING→0644）→ 空 keyring
        #     fail-closed：一切验签拒绝（未知 key）
        os.environ["WENQU_APPROVAL_KEYRING"] = wide
        empty_kr = _wp.default_keyring()
        assert len(empty_kr) == 0
        store0 = EventStore(os.path.join(tmp, "events.db"))
        mgr0 = RunManager(store0, keyring=empty_kr)
        run0 = mgr0.create_run("task_r7perm", IDENT)["run_id"]
        mgr0.advance_stage(run0)
        v0 = mgr0.get_run(run0).state_version
        ap0 = cosign(make_action_approval(run0, "task_r7perm", v0,
                                          "prod-write"))
        expect(ApprovalRejected,
               lambda: mgr0.reserve_action(
                   run0, "prod-write", "db://prod/erp", ap0,
                   action_descriptor=descriptor_of(ap0)),
               contains="key_id")
    finally:
        for key, val in saved_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        os.chmod(wide, 0o600)  # 收敛 tmp 路径权限（离开时不再宽权限）
    # 豁免不改变受管 keyring 红线：save_json 落盘即 0600
    kr_ok = ApprovalKeyring.generate("key_save_1", secret="u" * 64)
    path600 = os.path.join(tmp, "saved.json")
    kr_ok.save_json(path600)
    assert _stat.S_IMODE(os.stat(path600).st_mode) == 0o600
    assert ApprovalKeyring.from_path(path600).key_ids() == ["key_save_1"]



# ====================================================================== #
# R8（Codex 第八轮 P0-2 残余三洞）：key 生命周期按 issued_at 执法 +
# actual-target 运行时重算绑定 + signer principal 绑定——五拒一通复验
# ====================================================================== #
def adv14_r8_lifecycle_principal_actual_target():
    import hashlib as _hl

    SEC_A = "r8a" + "a" * 61   # 64-char HMAC secrets（本测试私有，用后即弃）
    SEC_B = "r8b" + "b" * 61

    def sign_with(secret, ap):
        ap = dict(ap)
        ap.pop("signature", None)
        ap.pop("cosignatures", None)
        ap["signature"] = sign_envelope(secret, ap)
        return ap

    def cosign_with(kr, ap, primary_actor, second_key_id, second_actor):
        body = {k: v for k, v in ap.items()
                if k not in ("signature", "cosignatures")}
        out = dict(ap)
        out["cosignatures"] = [
            {"key_id": ap["key_id"], "actor": primary_actor,
             "signature": ap["signature"]},
            {"key_id": second_key_id, "actor": second_actor,
             "signature": sign_envelope(kr.get(second_key_id), body)},
        ]
        return out

    def new_mgr(kr, tag):
        tmpdir = tempfile.mkdtemp(prefix=f"wenqu-adv14-{tag}-")
        store = EventStore(os.path.join(tmpdir, "events.db"))
        return store, RunManager(store, keyring=kr)

    def new_run(mgr, task):
        run_id = mgr.create_run(task, IDENT)["run_id"]
        mgr.advance_stage(run_id)
        return run_id, mgr.get_run(run_id).state_version

    # ------------------------------------------------------------------
    # 变体 1：退休时刻后签发（envelope.issued_at > rotated_at/expiry）→ 拒
    # ------------------------------------------------------------------
    kr_rot = ApprovalKeyring(
        {"key_r8_a": SEC_A, "key_r8_b": SEC_B},
        metadata={
            "key_r8_a": {"status": "rotated",
                         "created_at": "2026-10-01T00:00:00Z",
                         "rotated_at": "2026-10-05T00:00:00Z",
                         "rotated_to": "key_r8_b",
                         "owner": "chaoge", "actors": ["chaoge"]},
            "key_r8_b": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "erge", "actors": ["erge"]}})
    store1, mgr1 = new_mgr(kr_rot, "rot")
    run1, v1 = new_run(mgr1, "task_r8_rot")
    ap1 = cosign_with(kr_rot, sign_with(SEC_A, make_action_approval(
        run1, "task_r8_rot", v1, "prod-write", key_id="key_r8_a")),
        "chaoge", "key_r8_b", "erge")
    expect(ApprovalRejected,
           lambda: mgr1.reserve_action(run1, "prod-write",
                                       "db://prod/erp#r8", ap1,
                                       action_descriptor=descriptor_of(ap1)),
           contains="生命周期")
    # 1b：expiry 后签发（active 但已过期于 10-03，手签 issued 10-08）→ 拒
    kr_exp = ApprovalKeyring(
        {"key_r8_a": SEC_A, "key_r8_b": SEC_B},
        metadata={
            "key_r8_a": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "expiry": "2026-10-03T00:00:00Z",
                         "owner": "chaoge", "actors": ["chaoge"]},
            "key_r8_b": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "erge", "actors": ["erge"]}})
    store1b, mgr1b = new_mgr(kr_exp, "exp")
    run1b, v1b = new_run(mgr1b, "task_r8_exp")
    ap1b = cosign_with(kr_exp, sign_with(SEC_A, make_action_approval(
        run1b, "task_r8_exp", v1b, "prod-write", key_id="key_r8_a")),
        "chaoge", "key_r8_b", "erge")
    expect(ApprovalRejected,
           lambda: mgr1b.reserve_action(run1b, "prod-write",
                                        "db://prod/erp#r8", ap1b,
                                        action_descriptor=descriptor_of(ap1b)),
           contains="生命周期")
    # 1c：resume 消费路径同款执法（主签 key 已轮换、issued 晚于 rotated_at）
    w1 = mgr1.raise_waiting(run1, "prod-write", "r8-rot-resume")
    v1c = mgr1.get_run(run1).state_version
    ap1c, pre1 = make_resume(run1, w1["stop_event_id"], "prod-write", v1c,
                             "task_r8_rot", actor="chaoge")
    ap1c = sign_with(SEC_A, dict(ap1c, key_id="key_r8_a"))
    expect(ApprovalRejected,
           lambda: mgr1.resume_waiting(run1, ap1c, pre1), contains="生命周期")
    # 1d：联签 key 退休后手签（主 key 健康）→ 联签名生命周期门拒
    store1d, mgr1d = new_mgr(ApprovalKeyring(
        {"key_r8_a": SEC_A, "key_r8_b": SEC_B},
        metadata={
            "key_r8_a": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "chaoge", "actors": ["chaoge"]},
            "key_r8_b": {"status": "rotated",
                         "created_at": "2026-10-01T00:00:00Z",
                         "rotated_at": "2026-10-05T00:00:00Z",
                         "rotated_to": "key_r8_a",
                         "owner": "erge", "actors": ["erge"]}}), "rotcos")
    run1d, v1d = new_run(mgr1d, "task_r8_rotcos")
    ap1d = cosign_with(kr_rot, sign_with(SEC_A, make_action_approval(
        run1d, "task_r8_rotcos", v1d, "prod-write", key_id="key_r8_a")),
        "chaoge", "key_r8_b", "erge")
    expect(ApprovalRejected,
           lambda: mgr1d.reserve_action(run1d, "prod-write",
                                        "db://prod/erp#r8", ap1d,
                                        action_descriptor=descriptor_of(ap1d)),
           contains="生命周期")
    # 拒绝面零落账
    assert mgr1.broker.consumed_approvals(run_id=run1) == []
    assert not mgr1.get_run(run1).actions

    # ------------------------------------------------------------------
    # 变体 2：穿越签发（issued_at 早于 key created_at）→ 拒
    # ------------------------------------------------------------------
    kr_future = ApprovalKeyring(
        {"key_r8_a": SEC_A, "key_r8_b": SEC_B},
        metadata={
            "key_r8_a": {"status": "active",
                         "created_at": "2026-10-10T00:00:00Z",  # 未来才建
                         "owner": "chaoge", "actors": ["chaoge"]},
            "key_r8_b": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "erge", "actors": ["erge"]}})
    store2, mgr2 = new_mgr(kr_future, "tt")
    run2, v2 = new_run(mgr2, "task_r8_tt")
    ap2 = cosign_with(kr_future, sign_with(SEC_A, make_action_approval(
        run2, "task_r8_tt", v2, "prod-write", key_id="key_r8_a")),
        "chaoge", "key_r8_b", "erge")  # issued_at=10-08 < created_at=10-10
    expect(ApprovalRejected,
           lambda: mgr2.reserve_action(run2, "prod-write",
                                       "db://prod/erp#r8", ap2,
                                       action_descriptor=descriptor_of(ap2)),
           contains="生命周期")
    assert mgr2.broker.consumed_approvals(run_id=run2) == []

    # ------------------------------------------------------------------
    # 变体 3：descriptor 与运行时实参不符（caller 双自报关闭）→ 拒
    # ------------------------------------------------------------------
    store3, mgr3 = fresh()
    run3, v3 = new_run(mgr3, "task_r8_tgt")
    # 3a：release payload.environment 声明 production、run 实况 staging
    #     （hint descriptor 与 payload 完全一致——一致性不能替代运行时重算）
    bad_env = cosign(make_action_approval(
        run3, "task_r8_tgt", v3, "release",
        payload=dict(ACTION_PAYLOADS["release"], environment="production")))
    expect(ApprovalRejected,
           lambda: mgr3.reserve_action(run3, "release", "prod://erp/rel-77",
                                       bad_env,
                                       action_descriptor=descriptor_of(bad_env)),
           contains="actual-target")
    # 3b：merge head_sha 与「当前 HEAD 实查」（RUN_HEAD 哨兵=run commit_sha）不符
    v3b = mgr3.get_run(run3).state_version
    ap_m = make_action_approval(run3, "task_r8_tgt", v3b, "merge")
    expect(ApprovalRejected,
           lambda: mgr3.reserve_action(run3, "merge",
                                       "repo://qisemi-erp/pr-9", ap_m,
                                       action_descriptor=descriptor_of(ap_m),
                                       runtime_evidence={"head_sha": "RUN_HEAD"}),
           contains="actual-target")
    # 3c：artifact 路径实算 hash 与 payload 声明不符（真实文件、真实哈希）
    art = os.path.join(tempfile.mkdtemp(prefix="wenqu-adv14-art-"),
                       "artifact-r8.bin")
    with open(art, "wb") as fh:
        fh.write(b"r8-real-artifact-bytes")
    real_hash = _hl.sha256(open(art, "rb").read()).hexdigest()
    assert real_hash != "d" * 64
    v3c = mgr3.get_run(run3).state_version
    rel_bad = cosign(make_action_approval(
        run3, "task_r8_tgt", v3c, "release",
        payload=dict(ACTION_PAYLOADS["release"])))
    expect(ApprovalRejected,
           lambda: mgr3.reserve_action(run3, "release", "prod://erp/rel-77",
                                       rel_bad,
                                       action_descriptor=descriptor_of(rel_bad),
                                       runtime_evidence={
                                           "artifact_paths": {
                                               "artifact_sha256": art}}),
           contains="actual-target")
    # 3d：runtime_evidence 混入非本类型字段 → 拒（键集封闭）
    v3d = mgr3.get_run(run3).state_version
    pw = cosign(make_action_approval(run3, "task_r8_tgt", v3d, "prod-write"))
    expect(ApprovalRejected,
           lambda: mgr3.reserve_action(run3, "prod-write",
                                       "db://prod/erp#r8", pw,
                                       action_descriptor=descriptor_of(pw),
                                       runtime_evidence={"repo_id": "evil"}),
           contains="runtime_evidence")
    assert mgr3.broker.consumed_approvals(run_id=run3) == []
    assert not mgr3.get_run(run3).actions

    # ------------------------------------------------------------------
    # 变体 4：actor 冒用他人 key（envelope.actor ∉ key.actors）→ 拒
    # ------------------------------------------------------------------
    kr_p = ApprovalKeyring(
        {"key_r8_a": SEC_A, "key_r8_b": SEC_B},
        metadata={
            "key_r8_a": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "boss", "actors": ["boss"]},
            "key_r8_b": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "erge", "actors": ["erge"]}})
    store4, mgr4 = new_mgr(kr_p, "prin")
    run4, v4 = new_run(mgr4, "task_r8_prin")
    # 4a：主签 key 属 boss，信封 actor 自报 chaoge（HMAC 为真——持 secret 手签）
    ap4 = cosign_with(kr_p, sign_with(SEC_A, make_action_approval(
        run4, "task_r8_prin", v4, "prod-write", key_id="key_r8_a",
        actor="chaoge")), "chaoge", "key_r8_b", "erge")
    expect(ApprovalRejected,
           lambda: mgr4.reserve_action(run4, "prod-write",
                                       "db://prod/erp#r8", ap4,
                                       action_descriptor=descriptor_of(ap4)),
           contains="signer principal")
    # 4b：联签条目 actor 冒用（key_r8_b 属 erge，条目自报 mallory）
    ap4b = cosign_with(kr_p, sign_with(SEC_A, make_action_approval(
        run4, "task_r8_prin", v4, "prod-write", key_id="key_r8_a",
        actor="boss")), "boss", "key_r8_b", "mallory")
    expect(ApprovalRejected,
           lambda: mgr4.reserve_action(run4, "prod-write",
                                       "db://prod/erp#r8", ap4b,
                                       action_descriptor=descriptor_of(ap4b)),
           contains="登记面")
    assert mgr4.broker.consumed_approvals(run_id=run4) == []

    # ------------------------------------------------------------------
    # 变体 5：联签两条目同 actor（两把不同 key、同一人）→ 拒
    # ------------------------------------------------------------------
    store5, mgr5 = fresh()
    run5, v5 = new_run(mgr5, "task_r8_same")
    single5 = make_action_approval(run5, "task_r8_same", v5, "prod-write")
    body5 = {k: v for k, v in single5.items()
             if k not in ("signature", "cosignatures")}
    same_actor = dict(single5)
    same_actor["cosignatures"] = [
        {"key_id": "key_test_1", "actor": "chaoge",
         "signature": single5["signature"]},
        {"key_id": "key_test_2", "actor": "chaoge",
         "signature": sign_envelope(SECRET2, body5)},
    ]
    expect(ApprovalRejected,
           lambda: mgr5.reserve_action(run5, "prod-write",
                                       "db://prod/erp#r8", same_actor,
                                       action_descriptor=descriptor_of(single5)),
           contains="同 actor")
    assert mgr5.broker.consumed_approvals(run_id=run5) == []

    # ------------------------------------------------------------------
    # 变体 6：合法链（真 actors + 生命周期窗内 + 实时 descriptor）→ 通过
    # ------------------------------------------------------------------
    kr_legit = ApprovalKeyring(
        {"key_r8_a": SEC_A, "key_r8_b": SEC_B},
        metadata={
            "key_r8_a": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "chaoge", "actors": ["chaoge", "boss"]},
            "key_r8_b": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "erge", "actors": ["erge"]}})
    store6, mgr6 = new_mgr(kr_legit, "ok")
    run6, v6 = new_run(mgr6, "task_r8_ok")
    # 6a：高危 prod_write——真 actors（chaoge/erge 各属其 key）+ 窗内 issued
    ap6 = cosign_with(kr_legit, sign_with(SEC_A, make_action_approval(
        run6, "task_r8_ok", v6, "prod-write", key_id="key_r8_a")),
        "chaoge", "key_r8_b", "erge")
    r6 = mgr6.reserve_action(run6, "prod-write", "db://prod/erp#r8ok", ap6,
                             actor="runner",
                             action_descriptor=descriptor_of(ap6))
    assert r6["action_state"] == "RESERVED"
    # 6b：release——artifact 路径实算 hash 相符 + env 实况相符 + 观测等值
    v6b = mgr6.get_run(run6).state_version
    rel_payload = dict(ACTION_PAYLOADS["release"], artifact_sha256=real_hash)
    rel6 = cosign_with(kr_legit, sign_with(SEC_A, make_action_approval(
        run6, "task_r8_ok", v6b, "release", key_id="key_r8_a",
        payload=rel_payload)), "chaoge", "key_r8_b", "erge")
    r6b = mgr6.reserve_action(
        run6, "release", "prod://erp/rel-r8", rel6,
        actor="runner", action_descriptor=descriptor_of(rel6),
        runtime_evidence={
            "artifact_paths": {"artifact_sha256": art},
            "environment": IDENT["environment"],
            "release_id": rel_payload["release_id"]})
    assert r6b["action_state"] == "RESERVED"
    # 6c：merge——RUN_HEAD 哨兵实查=run commit_sha，payload head_sha 与之一致
    v6c = mgr6.get_run(run6).state_version
    m6 = sign_with(SEC_A, make_action_approval(
        run6, "task_r8_ok", v6c, "merge", key_id="key_r8_a",
        payload=dict(ACTION_PAYLOADS["merge"], head_sha=IDENT["commit_sha"])))
    r6c = mgr6.reserve_action(
        run6, "merge", "repo://qisemi-erp/pr-9", m6, actor="runner",
        action_descriptor=descriptor_of(m6),
        runtime_evidence={"head_sha": "RUN_HEAD"})
    assert r6c["action_state"] == "RESERVED"
    # 6d：resume 消费路径——actors 登记面 + 生命周期窗内全过
    w6 = mgr6.raise_waiting(run6, "prod-write", "r8-ok-wait")
    v6d = mgr6.get_run(run6).state_version
    ap6d, pre6 = make_resume(run6, w6["stop_event_id"], "prod-write", v6d,
                             "task_r8_ok", actor="chaoge")
    ap6d = sign_with(SEC_A, dict(ap6d, key_id="key_r8_a"))
    assert mgr6.resume_waiting(run6, ap6d, pre6)["resumed"] is True
    # 合法链落账恰三次授权消费 + 一次 resume，链完好
    assert len(mgr6.broker.consumed_approvals(run_id=run6)) == 4
    assert store6.verify_chain()["ok"]


def adv_cli_end_to_end():
    tmp = tempfile.mkdtemp(prefix="wenqu-adv-cli-")
    db = os.path.join(tmp, "events.db")
    ctl = os.path.join(REPO, "bin", "wenquctl")
    keys = os.path.join(REPO, "tests", "fixtures", "approval-keys.json")

    def run(*args, expect_rc=0):
        proc = subprocess.run(["bash", ctl, *args, "--db", db, "--keys", keys],
                              capture_output=True, text=True)
        assert proc.returncode == expect_rc, (
            f"wenquctl {' '.join(args[:2])} rc={proc.returncode} "
            f"expect={expect_rc}: {proc.stderr}")
        return json.loads(proc.stdout) if proc.stdout.strip() and (
            expect_rc == 0) else proc.stderr

    out = run("create", "--task", "task_cli",
              "--commit-sha", IDENT["commit_sha"],
              "--environment", IDENT["environment"],
              "--scope-hash", IDENT["scope_hash"],
              "--policy-hash", IDENT["policy_hash"],
              "--ruleset-hash", IDENT["ruleset_hash"])
    run_id = out["run_id"]
    assert out["state"] == "CREATED"
    # 六段 PASS + 停等/恢复 + S7 CONDITIONAL + risk + complete 全链
    run("advance", "--run", run_id)
    for _ in range(5):
        run("advance", "--run", run_id, "--execution-status", "COMPLETED",
            "--policy-verdict", "PASS")
    w = run("raise-waiting", "--run", run_id, "--stop-type", "prod-write",
            "--reason", "cli e2e 停等")
    assert w["run_state"] == "WAITING"
    v = run("status", "--run", run_id)["state_version"]
    pre = {"gate_reference": "gate-cli", "rollback_level": "R2"}
    pre_f = os.path.join(tmp, "pre.json")
    with open(pre_f, "w") as fh:
        json.dump(pre, fh)
    ap = make_resume(run_id, w["stop_event_id"], "prod-write", v, "task_cli",
                     preconditions=pre, stage="S6_EQS_FULL")[0]
    ap_f = os.path.join(tmp, "ap.json")
    with open(ap_f, "w") as fh:
        json.dump(ap, fh)
    rec = run("resume", "--run", run_id, "--approval", ap_f,
              "--preconditions", pre_f)
    assert rec["resumed"] is True
    run("advance", "--run", run_id, "--execution-status", "COMPLETED",
        "--policy-verdict", "PASS")  # S6 完成 → S7 启动
    run("advance", "--run", run_id, "--execution-status", "COMPLETED",
        "--policy-verdict", "CONDITIONAL")  # S7 软终态
    run("register-finding", "--run", run_id, "--finding-id", "fnd_cli",
        "--fingerprint", "fp-cli", "--severity", "MEDIUM",
        "--priority", "P2")
    v = run("status", "--run", run_id)["state_version"]
    risk = make_risk(run_id, "task_cli", v, fingerprints=["fp-cli"])
    risk_f = os.path.join(tmp, "risk.json")
    with open(risk_f, "w") as fh:
        json.dump(risk, fh)
    run("authorize-risk", "--run", run_id, "--approval", risk_f)
    done = run("complete", "--run", run_id)
    assert done["final_state"] == "COMPLETED_CONDITIONAL"
    st = run("status", "--run", run_id)
    assert st["state"] == "COMPLETED_CONDITIONAL" and st["terminal"]
    # CLI 拒绝面：同一 risk 再消费 → rc=1
    err = run("authorize-risk", "--run", run_id, "--approval", risk_f,
              expect_rc=1)
    assert "ApprovalReuseError" in err
    # CLI 拒绝面：终态后 advance → rc=1
    err = run("advance", "--run", run_id, "--execution-status", "COMPLETED",
              "--policy-verdict", "PASS", expect_rc=1)
    assert "TerminalRunError" in err

TESTS = [
    ("#1 伪签名+缺绑定 → envelope 封闭+HMAC 验签", adv1_envelope_closure),
    ("#2 跨类型 payload → 判别封闭+API 路由", adv2_payload_discrimination),
    ("#3 前置自报字符串 → bool 客观化", adv3_precondition_bool),
    ("#4 绑定绕过 → watermark 强制 40-hex+policy/ruleset exact", adv4_binding_bypass),
    ("#5 risk 无 CAS → action 类授权同样 CAS", adv5_risk_cas),
    ("#6 双轴洗白 → 非 COMPLETED 无完成态+P0/P1 机器拒绝", adv6_dual_axis),
    ("#7 控制事件直写 → append 守卫+重放验封", adv7_control_event_injection),
    ("#8 第二正源 → APPROVAL_CONSUMED 事件为唯一正源", adv8_event_source_of_truth),
    ("#9 自产事件全过 run-event-v2（FormatChecker）", adv9_schema_roundtrip),
    ("#10 action saga（授权链/outbox/receipt 分级对账/重放）", adv10_action_saga),
    ("#11 F4-AUTH-001 无授权提交 → 审批消费+PROVISIONAL+对账门", adv11_action_auth_gate),
    ("R7-005 高危联签消费门+exact descriptor+消费对账面", adv12_r7_dual_consume_gates),
    ("R7-006 0644 keyring loader fail-closed+豁免通道", adv13_r7_keyring_permission_gate),
    ("R8 生命周期 issued_at 执法+actual-target 运行时重算+signer principal 绑定（五拒一通）", adv14_r8_lifecycle_principal_actual_target),
    ("K：wenquctl CLI 端到端链", adv_cli_end_to_end),
]
if __name__ == "__main__":
    for name, fn in TESTS:
        check(name, fn)
    print(f"\nP0-4 对抗回归: {PASS_N} PASS / {FAIL_N} FAIL")
    sys.exit(1 if FAIL_N else 0)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_approval_issue.py——审批签发端（P0-2 残余，Codex 六轮）全链自测。

锚点：删除 system/wenqu_core/approval_issue.py（或 approval_keys.py 的
生命周期扩展）后此测试必红。覆盖面（任务冻结的验收链）：

  签发 → 消费 → 重放拒 → 轮换 → 吊销 → 联签 → 审计对账

分项：
- 契约零漂移：payload 判别封闭表与 wenqu_pipeline 单一正源一致；
- keyring 元数据：status/rotated_at/expiry（静态夹具 + 运行时受管目录：
  0700 目录/0600 secret/事件账本 append-only）；
- 签发：结构预检（ApprovalBroker.validate_structure）+ HMAC 自验 +
  nonce crypto 随机 + payload 判别封闭（多/缺/空字段全拒）；
- 高危类型（prod_write/ddl/release/fund_auth）：双人规则（缺确认/缺第二
  key/缺第二签发人/同 key 假联签/第二 key 不可签发 全拒）+ 联签双验真；
- 消费：resume 全链（RunManager.resume_waiting）→ 重放拒
  （ApprovalReuseError）→ 哈希链完好；
- 轮换：旧 key 标 rotated 可验存量（TTL 内已签审批仍可消费）、新签发用
  新 key、旧 key 再签被拒；
- 吊销：revoked 验签即拒（fail-closed）+ 拒绝事件记入 keyring-events.jsonl；
- 对账：签发审计 × EventStore APPROVAL_CONSUMED 双向（批了未用-在期/
  未用过期/用了没批/摘要不匹配/审计哈希链断裂）；
- CLI：wenquctl keys create/rotate/revoke/list + approve 签发/对账 +
  --source feishu 占位 + 输出绝不回显 secret 明文；
- FeishuApprovalSource submit/callback 占位（SKIP：架构裁定本地签发为
  默认案，飞书留接口）。

红线自证：审计账本不落 nonce 明文（只落 sha256 摘要）；keys list 输出
不含任何 secret 材料；测试密钥仅 tests/fixtures/（动态生命周期用临时目录）。
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import (  # noqa: E402
    ISSUE_RECEIPTS_FILENAME, KEYRING_EVENTS_FILENAME,
    RECEIPT_GENESIS_RECORD_TYPE, ApprovalKeyring, IssueReceiptLedger,
    KeyExpiredError, KeyNotFoundError, KeyRevokedError,
    KeyRotatedError, KeyStateError, append_keyring_event, ensure_keyring_dir,
    generate_secret, save_key_meta, sign_envelope, verify_envelope,
    write_key_to_dir,
)
from wenqu_core.approval_issue import (  # noqa: E402
    HIGH_RISK_APPROVAL_TYPES, PAYLOAD_FIELDS_FOR_TYPE, ApprovalIssuer,
    FeishuApprovalSource, IssuanceAudit, IssuanceError, LocalApprovalSource,
    TwoPersonRuleError, issue_from_preconditions_payload,
    reconcile_issuance,
)
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    _APPROVAL_PAYLOAD_DISCRIMINATOR, ApprovalBroker, ApprovalRejected,
    ApprovalReuseError, RunManager,
)

PASS_N, FAIL_N, SKIP_N = 0, 0, 0


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
        raise AssertionError(
            f"expected {exc.__name__}, got {type(e).__name__}: {e}")
    raise AssertionError(f"expected {exc.__name__}, nothing raised")


IDENT = {
    "commit_sha": "a" * 40,
    "environment": "staging",
    "scope_hash": "scope-hash-001",
    "repo_id": "qisemi-erp",
    "ruleset_hash": "rules-7",
    "policy_hash": "policy-sha-001",
}
FIXTURE_KEYS = os.path.join(REPO, "tests", "fixtures", "approval-keys.json")
FIXTURE_META = os.path.join(REPO, "tests", "fixtures",
                            "approval-keys-meta.json")
PRECONDITIONS = {"gate_reference": "gate:sha-abc", "rollback_level": "R3"}

PROD_WRITE_PAYLOAD = {
    "operation_digest": "4" * 64, "data_scope_digest": "5" * 64,
    "idempotency_key": "idem-p2", "conservation_hash": "6" * 64,
}


def fresh(keyring=None, prefix="wenqu-iss-"):
    """新事件库 + RunManager（缺省用 fixtures 双 active key keyring）。"""
    tmp = tempfile.mkdtemp(prefix=prefix)
    store = EventStore(os.path.join(tmp, "events.db"))
    kr = keyring if keyring is not None else ApprovalKeyring.from_path(
        FIXTURE_KEYS)
    mgr = RunManager(store, keyring=kr)
    return tmp, store, mgr, kr


def make_waiting_run(mgr, task_id="task_iss", stop_type="prod-write"):
    """create → advance(S1 RUNNING) → raise_waiting → (run_id, stop_event_id, v)。"""
    run_id = mgr.create_run(task_id, IDENT)["run_id"]
    mgr.advance_stage(run_id)
    w = mgr.raise_waiting(run_id, stop_type, "签发端测试停等")
    v = mgr.get_run(run_id).state_version
    return run_id, w["stop_event_id"], v


def issue_resume(issuer, run_id, stop_event_id, v, task_id="task_iss",
                 key_id="key_test_1", **kw):
    """签发 resume 审批（前置条件默认 PRECONDITIONS）。

    key_id 缺省锚定 key_test_1——fixtures keyring 有两个 active key
    （自动选择=歧义拒），成功路径必须显式锚定；显式传 key_id=None
    可走「不指定 key」的歧义/无 key 测试路径。
    """
    payload = issue_from_preconditions_payload(
        stop_event_id, "prod-write",
        kw.pop("preconditions", PRECONDITIONS))
    return issuer.issue(
        actor=kw.pop("actor", "chaoge"), approval_type="resume",
        run_id=run_id, task_id=task_id, stage="S1_REQUIREMENT",
        environment=IDENT["environment"], authorized_scope=IDENT["scope_hash"],
        policy_hash=IDENT["policy_hash"], ruleset_hash=IDENT["ruleset_hash"],
        input_watermark=IDENT["commit_sha"], expected_state_version=v,
        payload=payload, stop_type="prod-write",
        stop_event_id=stop_event_id, key_id=key_id, **kw)


# ====================================================================== #
# 1. 契约零漂移
# ====================================================================== #
def test_payload_table_no_drift():
    assert PAYLOAD_FIELDS_FOR_TYPE is _APPROVAL_PAYLOAD_DISCRIMINATOR or \
        dict(PAYLOAD_FIELDS_FOR_TYPE) == dict(_APPROVAL_PAYLOAD_DISCRIMINATOR)
    assert HIGH_RISK_APPROVAL_TYPES == frozenset(
        {"prod_write", "ddl", "release", "fund_auth"})
    assert HIGH_RISK_APPROVAL_TYPES <= set(PAYLOAD_FIELDS_FOR_TYPE)


# ====================================================================== #
# 2. keyring 元数据（静态夹具）
# ====================================================================== #
def test_keyring_meta_fixture():
    kr = ApprovalKeyring.from_path(FIXTURE_META)
    assert kr.meta("key_meta_active")["status"] == "active"
    assert kr.meta("key_meta_rotated")["status"] == "rotated"
    assert kr.meta("key_meta_rotated")["rotated_to"] == "key_meta_active"
    assert kr.meta("key_meta_revoked")["status"] == "revoked"
    assert kr.active_key_ids() == ["key_meta_active"]
    assert kr.get_for_signing("key_meta_active")  # active 可签
    expect(KeyRotatedError, lambda: kr.get_for_signing("key_meta_rotated"))
    expect(KeyRevokedError, lambda: kr.get_for_signing("key_meta_revoked"))
    expect(KeyNotFoundError, lambda: kr.get_for_signing("key_meta_nope"))
    # rotated 可验存量：旧 key 签的名仍真
    old = {"key_id": "key_meta_rotated", "approval_id": "apr_meta_old"}
    old["signature"] = sign_envelope(kr.get("key_meta_rotated"), old)
    assert kr.verify(old) is True
    # revoked 验签即拒（JSON 夹具无事件账本路径——拒绝不受影响）
    bad = {"key_id": "key_meta_revoked", "approval_id": "apr_meta_bad"}
    bad["signature"] = sign_envelope(kr.get("key_meta_revoked"), bad)
    assert kr.verify(bad) is False
    # R8-KEY-LIFECYCLE-001：rotated 可验「存量」收窄为 issued_at 时间窗内——
    # 退休时刻之后手签（HMAC 为真）→ 拒；created_at 之前（时间穿越）→ 拒；
    # 过期后签发 → 拒（增断言，只增不减）
    late = {"key_id": "key_meta_rotated", "approval_id": "apr_meta_late",
            "issued_at": "2026-10-02T00:00:00Z"}  # > rotated_at 10-01
    late["signature"] = sign_envelope(kr.get("key_meta_rotated"), late)
    assert kr.verify(late) is False
    timetravel = {"key_id": "key_meta_active",
                  "approval_id": "apr_meta_early",
                  "issued_at": "2026-09-30T00:00:00Z"}  # < created_at 10-01
    timetravel["signature"] = sign_envelope(
        kr.get("key_meta_active"), timetravel)
    assert kr.verify(timetravel) is False
    # 坏元数据（未知字段/缺 rotated_at/未知 key）拒绝加载 → 见
    # test_keyring_bad_meta_rejected（本仓测试无 pytest 依赖）


def test_keyring_bad_meta_rejected():
    expect(ValueError, lambda: ApprovalKeyring(
        {"key_x_1": "s" * 32}, metadata={"key_x_1": {"status": "zombie"}}))
    expect(ValueError, lambda: ApprovalKeyring(
        {"key_x_1": "s" * 32},
        metadata={"key_x_1": {"status": "rotated"}}))  # 缺 rotated_at
    expect(ValueError, lambda: ApprovalKeyring(
        {"key_x_1": "s" * 32},
        metadata={"key_ghost": {"status": "active"}}))  # 未知 key


# ====================================================================== #
# 3. 受管 keyring 目录（0700/0600/事件账本/过期）
# ====================================================================== #
def test_managed_keyring_dir_lifecycle():
    tmp = tempfile.mkdtemp(prefix="wenqu-kr-")
    kdir = os.path.join(tmp, "keyring")
    write_key_to_dir(kdir, "key_life_a", generate_secret(),
                     {"status": "active"})
    write_key_to_dir(kdir, "key_life_r", generate_secret(),
                     {"status": "rotated", "rotated_at": "2026-10-01T00:00:00Z",
                      "rotated_to": "key_life_a"})
    write_key_to_dir(kdir, "key_life_v", generate_secret(),
                     {"status": "revoked", "revoked_at": "2026-10-02T00:00:00Z"})
    # 权限红线：目录 owner-only（0700——目录需 x 位），secret/meta 0600
    assert stat.S_IMODE(os.stat(kdir).st_mode) == 0o700
    for kid in ("key_life_a", "key_life_r", "key_life_v"):
        assert stat.S_IMODE(
            os.stat(os.path.join(kdir, f"{kid}.secret")).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(
            os.path.join(kdir, f"{kid}.meta.json")).st_mode) == 0o600
    kr = ApprovalKeyring.from_path(kdir)
    assert kr.active_key_ids() == ["key_life_a"]
    # revoked 验签即拒 + 事件账本记录（目录型才有账本路径）
    ap = {"key_id": "key_life_v", "approval_id": "apr_life_v",
          "approval_type": "merge", "run_id": "run_v"}
    ap["signature"] = sign_envelope(kr.get("key_life_v"), ap)
    assert kr.verify(ap) is False
    events = [json.loads(l) for l in
              open(os.path.join(kdir, KEYRING_EVENTS_FILENAME))]
    rec = [e for e in events
           if e["record_type"] == "REVOKED_KEY_VERIFY_REJECTED"]
    assert rec and rec[-1]["approval_id"] == "apr_life_v" \
        and rec[-1]["key_id"] == "key_life_v"
    # 过期 key：不得签发（expiry 只阻断新签发）
    write_key_to_dir(kdir, "key_life_e", generate_secret(),
                     {"status": "active", "expiry": "2020-01-01T00:00:00Z"})
    kr2 = ApprovalKeyring.from_path(kdir)
    assert "key_life_e" not in kr2.active_key_ids()
    expect(KeyExpiredError, lambda: kr2.get_for_signing("key_life_e"))
    # append_keyring_event 追加式（不覆盖）
    before = len(events)
    append_keyring_event(os.path.join(kdir, KEYRING_EVENTS_FILENAME),
                         {"record_type": "PROBE", "ts": "2026-10-08T00:00:00Z"})
    assert len([l for l in
                open(os.path.join(kdir, KEYRING_EVENTS_FILENAME))]) == before + 1


# ====================================================================== #
# 4. 签发：结构/自验/审计
# ====================================================================== #
def test_issue_resume_structure_and_audit():
    tmp, store, mgr, kr = fresh()
    audit = os.path.join(tmp, "issuance-audit.jsonl")
    issuer = ApprovalIssuer(kr, audit)
    run_id, stop_evt, v = make_waiting_run(mgr)
    r = issue_resume(issuer, run_id, stop_evt, v)
    ap = r["approval"]
    # 消费端结构预检必然通过（签发预检已跑；此处独立复验）
    ApprovalBroker.validate_structure(ap)
    assert kr.verify(ap) is True
    assert ap["key_id"] == "key_test_1" and ap["decision"] == "approve"
    assert ap["schema_version"] == "2.0"
    assert len(ap["nonce"]) >= 16 and ap["approval_id"].startswith("apr_")
    assert ap["payload"]["objective_precondition_hash"] == \
        __import__("wenqu_core.wenqu_pipeline", fromlist=["x"]).\
        SevenStageStateMachine.objective_precondition_hash(PRECONDITIONS)
    # 审计：谁/何时/批了什么/TTL
    rec = r["audit_record"]
    assert rec["record_type"] == "APPROVAL_ISSUED"
    assert rec["actor"] == "chaoge" and rec["approval_type"] == "resume"
    assert rec["run_id"] == run_id and rec["task_id"] == "task_iss"
    assert rec["ttl_seconds"] == 3600 and rec["issued_at"] and rec["expires_at"]
    assert rec["high_risk"] is False and rec["two_person"] is False
    assert rec["source"] == "local"
    # 红线：nonce 明文绝不落审计（只有 sha256 摘要）
    assert "nonce" not in rec
    assert len(rec["nonce_digest"]) == 64
    records = IssuanceAudit.read_records(audit)
    assert len(records) == 1 and "nonce" not in records[0]
    assert IssuanceAudit.verify_chain(audit)["ok"] is True
    # 审计文件权限 0600
    assert stat.S_IMODE(os.stat(audit).st_mode) == 0o600
    store.close()


def test_issue_payload_closed():
    tmp, store, mgr, kr = fresh()
    issuer = ApprovalIssuer(kr, os.path.join(tmp, "a.jsonl"))
    base = dict(actor="a", approval_type="prod_write", run_id="r1",
                task_id="t1", stage="S1_REQUIREMENT", environment="staging",
                authorized_scope="s", policy_hash="p", ruleset_hash="ru",
                input_watermark="a" * 40, expected_state_version=1,
                key_id="key_test_1")
    # 多字段（混入他类）→ 拒
    expect(IssuanceError, lambda: issuer.issue(
        payload={**PROD_WRITE_PAYLOAD, "repo_id": "x"}, **base))
    # 缺字段 → 拒
    expect(IssuanceError, lambda: issuer.issue(
        payload={"operation_digest": "1" * 64}, **base))
    # 空值 → 拒
    expect(IssuanceError, lambda: issuer.issue(
        payload={**PROD_WRITE_PAYLOAD, "idempotency_key": ""}, **base))
    # 非法类型/decision/枚举 → 拒
    expect(IssuanceError, lambda: issuer.issue(
        approval_type="deploy", payload=PROD_WRITE_PAYLOAD, **{
            k: v for k, v in base.items() if k != "approval_type"}))
    expect(IssuanceError, lambda: issuer.issue(decision="maybe",
                                                payload=PROD_WRITE_PAYLOAD,
                                                **{k: v for k, v in base.items()
                                                   if k != "decision"}))
    # TTL 边界
    expect(IssuanceError, lambda: issuer.issue(
        payload=PROD_WRITE_PAYLOAD, ttl_seconds=0,
        **{k: v for k, v in base.items() if k != "ttl_seconds"}))
    # 失败签发不落审计
    assert IssuanceAudit.read_records(
        os.path.join(tmp, "a.jsonl")) == []
    store.close()


def test_issue_key_selection():
    tmp, store, mgr, kr = fresh()
    issuer = ApprovalIssuer(kr, os.path.join(tmp, "a.jsonl"))
    run_id, stop_evt, v = make_waiting_run(mgr)
    # fixtures 有两个 active key——不指定即拒（歧义 fail-closed）
    expect(IssuanceError, lambda: issue_resume(
        issuer, run_id, stop_evt, v, key_id=None))
    # 无可签发 key：只留 rotated/revoked（FIXTURE_META 的 active 剔除后重组）
    src = ApprovalKeyring.from_path(FIXTURE_META)
    kr_dead = ApprovalKeyring(
        {"key_meta_rotated": src.get("key_meta_rotated"),
         "key_meta_revoked": src.get("key_meta_revoked")},
        metadata={"key_meta_rotated": src.meta("key_meta_rotated"),
                  "key_meta_revoked": src.meta("key_meta_revoked")})
    assert kr_dead.active_key_ids() == []
    issuer2 = ApprovalIssuer(kr_dead, os.path.join(tmp, "a2.jsonl"))
    expect(IssuanceError, lambda: issue_resume(
        issuer2, run_id, stop_evt, v, key_id=None))
    expect(IssuanceError, lambda: issue_resume(
        issuer2, run_id, stop_evt, v, key_id="key_meta_rotated"))
    store.close()


# ====================================================================== #
# 5. 高危双人规则 + 联签双验真
# ====================================================================== #
def test_two_person_rule():
    tmp, store, mgr, kr = fresh()
    issuer = ApprovalIssuer(kr, os.path.join(tmp, "a.jsonl"))
    base = dict(actor="chaoge", approval_type="prod_write", run_id="r1",
                task_id="t1", stage="S1_REQUIREMENT", environment="staging",
                authorized_scope="s", policy_hash="p", ruleset_hash="ru",
                input_watermark="a" * 40, expected_state_version=1,
                key_id="key_test_1", payload=dict(PROD_WRITE_PAYLOAD))
    # 缺确认旗标 → 拒
    expect(TwoPersonRuleError, lambda: issuer.issue(**base))
    # 有旗标缺第二 key → 拒
    expect(TwoPersonRuleError, lambda: issuer.issue(
        confirm_two_persons=True, **base))
    # 缺第二签发人 → 拒
    expect(TwoPersonRuleError, lambda: issuer.issue(
        confirm_two_persons=True, second_key_id="key_test_2", **base))
    # 同 key 假联签 → 拒
    expect(TwoPersonRuleError, lambda: issuer.issue(
        confirm_two_persons=True, second_key_id="key_test_1",
        second_actor="erge", **base))
    # 第二 key 不可签发（revoked）→ 拒（组装含 revoked key 的 keyring——
    # FIXTURE_KEYS 只有 active key，联签资格测不了 revoked 语义）
    kr_mixed = ApprovalKeyring(
        {"key_test_1": kr.get("key_test_1"),
         "key_test_2": kr.get("key_test_2"),
         "key_dead": generate_secret()},
        metadata={"key_dead": {
            "status": "revoked", "revoked_at": "2026-10-01T00:00:00Z"}})
    audit_m = os.path.join(tmp, "a_mixed.jsonl")
    issuer_m = ApprovalIssuer(kr_mixed, audit_m)
    expect(IssuanceError, lambda: issuer_m.issue(
        confirm_two_persons=True, second_key_id="key_dead",
        second_actor="erge", **base))
    assert IssuanceAudit.read_records(audit_m) == []  # fail-closed 不落审计
    # 非高危带双人参数 → 拒（防「已联签」错觉）
    expect(TwoPersonRuleError, lambda: issuer.issue(
        approval_type="merge", payload={"repo_id": "r", "base_sha": "b" * 40,
                                        "head_sha": "c" * 40,
                                        "merge_method": "merge"},
        confirm_two_persons=True, second_key_id="key_test_2",
        second_actor="erge",
        **{k: v for k, v in base.items()
           if k not in ("approval_type", "payload")}))
    # 合法联签：两签名均验真
    r = issuer.issue(confirm_two_persons=True, second_key_id="key_test_2",
                     second_actor="erge", **base)
    co = r["co_signature"]
    assert co and co["second_key_id"] == "key_test_2" \
        and co["second_actor"] == "erge"
    ap = r["approval"]
    assert verify_envelope(kr.get("key_test_1"), ap, ap["signature"])
    assert verify_envelope(kr.get("key_test_2"), ap, co["co_signature"])
    # R7-AUTH-DUAL-CONSUME-005：联签必须嵌入信封（消费端契约）——
    # 两名不同 key、键集封闭、逐条独立可验（对信封体 detached HMAC）
    env_cos = ap.get("cosignatures")
    assert env_cos and len(env_cos) == 2
    assert {c["key_id"] for c in env_cos} == {"key_test_1", "key_test_2"}
    assert {c["actor"] for c in env_cos} == {"chaoge", "erge"}
    assert all(set(c) == {"key_id", "actor", "signature"} for c in env_cos)
    body = {k: v for k, v in ap.items()
            if k not in ("signature", "cosignatures")}
    assert all(kr.verify_detached(c["key_id"], body, c["signature"])
               for c in env_cos)
    assert r["audit_record"]["two_person"] is True \
        and r["audit_record"]["high_risk"] is True \
        and r["audit_record"]["second_key_id"] == "key_test_2"
    assert r["audit_record"]["cosign_key_ids"] == ["key_test_1", "key_test_2"]
    # 篡改信封后两个签名都失效（同体联签——改一字全崩）
    tampered = dict(ap)
    tampered["decision"] = "deny"
    assert not verify_envelope(kr.get("key_test_1"), tampered,
                               ap["signature"])
    assert not verify_envelope(kr.get("key_test_2"), tampered,
                               co["co_signature"])
    # 篡改联签名本身（替换为伪签名）→ detached 验签失败
    bad_cos = [dict(c) for c in env_cos]
    bad_cos[1]["signature"] = "0" * 64
    assert not kr.verify_detached("key_test_2", body, bad_cos[1]["signature"])
    store.close()


# ====================================================================== #
# 6. 全链：签发 → 消费 → 重放拒
# ====================================================================== #
def test_issue_consume_replay():
    tmp, store, mgr, kr = fresh()
    audit = os.path.join(tmp, "issuance-audit.jsonl")
    issuer = ApprovalIssuer(kr, audit)
    run_id, stop_evt, v = make_waiting_run(mgr)
    r = issue_resume(issuer, run_id, stop_evt, v)
    ap = r["approval"]
    with open(os.path.join(tmp, "ap.json"), "w") as fh:
        json.dump(ap, fh)
    rec = mgr.resume_waiting(run_id, ap, PRECONDITIONS)
    assert rec["resumed"] is True and rec["run_state"] == "RUNNING"
    assert mgr.get_run(run_id).waiting is None
    # 重放：同一 nonce 再消费 → 拒（不变量 #5，事件正源）
    expect(ApprovalReuseError, lambda: mgr.resume_waiting(
        run_id, ap, PRECONDITIONS))
    # 事件库哈希链完好 + 审计链完好
    assert store.verify_chain()["ok"]
    assert IssuanceAudit.verify_chain(audit)["ok"]
    store.close()


# ====================================================================== #
# 7. 轮换：旧 key 可验存量、新签发用新 key
# ====================================================================== #
def test_rotation_semantics():
    tmp = tempfile.mkdtemp(prefix="wenqu-rot-")
    kdir = os.path.join(tmp, "keyring")
    write_key_to_dir(kdir, "key_old", generate_secret(),
                     {"status": "active"})
    write_key_to_dir(kdir, "key_second", generate_secret(),
                     {"status": "active"})
    kr = ApprovalKeyring.from_path(kdir)
    store = EventStore(os.path.join(tmp, "events.db"))
    mgr = RunManager(store, keyring=kr)
    audit = os.path.join(kdir, "issuance-audit.jsonl")
    issuer = ApprovalIssuer(kr, audit)
    # 用旧 key 签一份长 TTL 审批（存量）
    run_id, stop_evt, v = make_waiting_run(mgr)
    r_old = issue_resume(issuer, run_id, stop_evt, v, key_id="key_old",
                         ttl_seconds=86400)
    # 轮换：旧 → 新（R8-KEY-LIFECYCLE-001：rotated_at 取轮换时刻的真实
    # 时间——语义即「先签发后轮换」，存量审批 issued_at ≤ rotated_at
    # 落在时间窗内可继续消费；退休后手签的批才拒）
    rotated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_key_meta(kdir, "key_old", {
        "status": "rotated", "rotated_at": rotated_at,
        "rotated_to": "key_new"})
    write_key_to_dir(kdir, "key_new", generate_secret(),
                     {"status": "active"})
    kr2 = ApprovalKeyring.from_path(kdir)  # 重载后旧 key rotated
    assert kr2.meta("key_old")["rotated_to"] == "key_new"
    assert kr2.active_key_ids() == ["key_new", "key_second"]
    # 旧 key 不得再签发
    issuer2 = ApprovalIssuer(kr2, audit)
    run2 = mgr.create_run("task_rot2", IDENT)["run_id"]
    mgr.advance_stage(run2)
    w2 = mgr.raise_waiting(run2, "prod-write", "轮换后停等")
    v2 = mgr.get_run(run2).state_version
    expect(IssuanceError, lambda: issue_resume(
        issuer2, run2, w2["stop_event_id"], v2, key_id="key_old"))
    # 新签发自动用唯一...（此刻两个 active）——显式新 key 可签
    r_new = issue_resume(issuer2, run2, w2["stop_event_id"], v2,
                         key_id="key_new")
    assert r_new["approval"]["key_id"] == "key_new"
    # 存量可验：旧 key 签的审批在轮换后仍可消费（RunManager 用重载 keyring）
    mgr2 = RunManager(store, keyring=kr2)
    rec = mgr2.resume_waiting(run_id, r_old["approval"], PRECONDITIONS)
    assert rec["resumed"] is True
    # R8-KEY-LIFECYCLE-001：退休后手签的批不能消费——持旧 secret 直签、
    # issued_at 晚于 rotated_at 的信封，即使 HMAC 为真也必须拒（keyring
    # 面与消费端 Broker 面双拒）
    late_issued = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() + 3600))  # rotated_at 之后（真实时钟 +1h）
    bypass = {
        "schema_version": "2.0",
        "approval_id": "apr_rot_late_1", "approval_type": "resume",
        "key_id": "key_old", "run_id": run2, "task_id": "task_rot2",
        "stop_event_id": w2["stop_event_id"], "stop_type": "prod-write",
        "stage": "S1_REQUIREMENT", "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "expected_state_version": mgr2.get_run(run2).state_version,
        "actor": "chaoge",
        "issued_at": late_issued,
        "expires_at": "2099-01-01T00:00:00Z",
        "nonce": "nonce-rot-late-0001", "decision": "approve",
        "payload": issue_from_preconditions_payload(
            w2["stop_event_id"], "prod-write", PRECONDITIONS),
    }
    bypass.pop("signature", None)
    bypass["signature"] = sign_envelope(kr2.get("key_old"), bypass)
    assert kr2.verify(bypass) is False  # keyring 面：生命周期窗外即拒
    expect(ApprovalRejected, lambda: mgr2.resume_waiting(
        run2, bypass, PRECONDITIONS))  # 消费端 Broker 面同样拒
    assert store.verify_chain()["ok"]
    store.close()


# ====================================================================== #
# 8. 吊销：验签即拒 + 拒绝事件记录
# ====================================================================== #
def test_revocation_semantics():
    tmp = tempfile.mkdtemp(prefix="wenqu-rev-")
    kdir = os.path.join(tmp, "keyring")
    write_key_to_dir(kdir, "key_doomed", generate_secret(),
                     {"status": "active"})
    kr = ApprovalKeyring.from_path(kdir)
    store = EventStore(os.path.join(tmp, "events.db"))
    mgr = RunManager(store, keyring=kr)
    issuer = ApprovalIssuer(kr, os.path.join(kdir, "issuance-audit.jsonl"))
    run_id, stop_evt, v = make_waiting_run(mgr)
    r = issue_resume(issuer, run_id, stop_evt, v, key_id="key_doomed",
                     ttl_seconds=86400)
    ap = r["approval"]
    # 吊销（签名当时合法——吊销后即拒）
    save_key_meta(kdir, "key_doomed", {
        "status": "revoked", "revoked_at": "2026-10-08T00:00:00Z"})
    kr2 = ApprovalKeyring.from_path(kdir)
    assert kr2.verify(ap) is False
    mgr2 = RunManager(store, keyring=kr2)
    expect(ApprovalRejected, lambda: mgr2.resume_waiting(
        run_id, ap, PRECONDITIONS))
    # 拒绝事件已记录（keyring-events.jsonl，含 approval_id）
    events = [json.loads(l) for l in
              open(os.path.join(kdir, KEYRING_EVENTS_FILENAME))]
    rec = [e for e in events
           if e["record_type"] == "REVOKED_KEY_VERIFY_REJECTED"]
    assert rec and rec[-1]["approval_id"] == ap["approval_id"]
    # 吊销后不得再签发
    issuer2 = ApprovalIssuer(kr2, os.path.join(kdir, "issuance-audit.jsonl"))
    run2 = mgr.create_run("task_rev2", IDENT)["run_id"]
    mgr.advance_stage(run2)
    w2 = mgr.raise_waiting(run2, "prod-write", "吊销后停等")
    expect(IssuanceError, lambda: issue_resume(
        issuer2, run2, w2["stop_event_id"],
        mgr.get_run(run2).state_version, key_id="key_doomed"))
    store.close()


# ====================================================================== #
# 9. 高危联签审批（信封内嵌 cosignatures）→ reserve_action 消费 → 重放拒
# ====================================================================== #
def test_high_risk_cosigned_reserve_action():
    tmp, store, mgr, kr = fresh()
    issuer = ApprovalIssuer(kr, os.path.join(tmp, "a.jsonl"))
    run_id = mgr.create_run("task_hr", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    v = mgr.get_run(run_id).state_version
    r = issuer.issue(
        actor="chaoge", approval_type="prod_write", run_id=run_id,
        task_id="task_hr", stage="S1_REQUIREMENT",
        environment=IDENT["environment"], authorized_scope=IDENT["scope_hash"],
        policy_hash=IDENT["policy_hash"], ruleset_hash=IDENT["ruleset_hash"],
        input_watermark=IDENT["commit_sha"], expected_state_version=v,
        payload=dict(PROD_WRITE_PAYLOAD), key_id="key_test_1",
        confirm_two_persons=True, second_key_id="key_test_2",
        second_actor="erge")
    # R7-AUTH-DUAL-CONSUME-005：联签嵌入信封——两名不同 key、各自可验
    cos = r["approval"]["cosignatures"]
    assert len(cos) == 2
    assert {c["key_id"] for c in cos} == {"key_test_1", "key_test_2"}
    assert {c["actor"] for c in cos} == {"chaoge", "erge"}
    assert r["co_signature"]["second_key_id"] == "key_test_2"  # 外置面兼容
    assert r["audit_record"]["payload_digest"] and \
        len(r["audit_record"]["payload_digest"]) == 64
    # 消费必须凭 exact action descriptor（payload 与实参逐字段等值）+
    # R8-AUTH-TARGET-UNBOUND-006：runtime evidence 必填（全字段运行时观测
    # + action_target 实际执行目标）
    rec = mgr.reserve_action(run_id, "prod-write", "erp://prod/batch-77",
                             r["approval"], actor="system",
                             action_descriptor=dict(PROD_WRITE_PAYLOAD),
                             runtime_evidence={**PROD_WRITE_PAYLOAD,
                                               "action_target":
                                                   "erp://prod/batch-77"})
    assert rec["action_state"] == "RESERVED" \
        and rec["approval_id"] == r["approval"]["approval_id"]
    assert rec["payload_digest"] == r["audit_record"]["payload_digest"]
    # 消费侧回读：prod_write 消费折叠入 consumed_nonce_*/actions
    # （risk_authorizations 只收集 risk 类授权——消费端正源语义）
    st = mgr.get_run(run_id)
    assert rec["nonce_digest"] in st.consumed_nonce_digests
    assert st.consumed_nonce_types[rec["nonce_digest"]] == "prod_write"
    assert st.actions[rec["action_id"]]["approval_id"] == \
        r["approval"]["approval_id"]
    # APPROVAL_CONSUMED 事件携带 payload_digest + 双联签摘要（对账面）
    rows = store._conn.execute(  # noqa: SLF001 —— 测试读事件正源
        "SELECT payload FROM pipeline_events WHERE json_extract("
        "payload, '$.event_type') = 'APPROVAL_CONSUMED'").fetchall()
    consumed_ev = json.loads(next(rw[0] for rw in rows
                                  if json.loads(rw[0]).get("run_id")
                                  == run_id))
    assert consumed_ev["payload_digest"] == \
        r["audit_record"]["payload_digest"]
    assert len(consumed_ev["cosign_digests"]) == 2
    assert {c["key_id"] for c in consumed_ev["cosign_digests"]} == \
        {"key_test_1", "key_test_2"}
    # 重放：同一 nonce 再 reserve → 拒
    expect(ApprovalReuseError, lambda: mgr.reserve_action(
        run_id, "prod-write", "erp://prod/batch-77", r["approval"],
        action_descriptor=dict(PROD_WRITE_PAYLOAD)))
    assert store.verify_chain()["ok"]
    store.close()


# ====================================================================== #
# 10. 审计对账：批了 vs 用了 vs 未用过期 + 旁路/篡改检出
# ====================================================================== #
def test_audit_reconciliation():
    tmp, store, mgr, kr = fresh()
    audit = os.path.join(tmp, "issuance-audit.jsonl")
    issuer = ApprovalIssuer(kr, audit)
    now = time.time()

    # #1 批了且用：resume 消费
    run1, evt1, v1 = make_waiting_run(mgr, "task_rec1")
    ap1 = issue_resume(issuer, run1, evt1, v1, task_id="task_rec1")["approval"]
    mgr.resume_waiting(run1, ap1, PRECONDITIONS)
    # #2 批了未用过期（签发即已过期：now_epoch 回拨 + 短 TTL）
    run2, evt2, v2 = make_waiting_run(mgr, "task_rec2")
    issue_resume(issuer, run2, evt2, v2, task_id="task_rec2",
                 now_epoch=now - 7200, ttl_seconds=3600)
    # #3 批了未用在期
    run3, evt3, v3 = make_waiting_run(mgr, "task_rec3")
    issue_resume(issuer, run3, evt3, v3, task_id="task_rec3")

    report = reconcile_issuance(audit, os.path.join(tmp, "events.db"))
    assert report["ok"] is True and report["chain_ok"] is True
    assert report["issued_total"] == 3 and report["consumed_total"] == 1
    assert report["used_ok"] == [ap1["approval_id"]]
    assert len(report["issued_unused_active"]) == 1
    assert report["issued_unused_active"][0]["run_id"] == run3
    assert len(report["issued_unused_expired"]) == 1
    assert report["issued_unused_expired"][0]["run_id"] == run2
    assert report["consumed_without_issuance"] == []

    # 旁路签发：手搓信封（不经签发端）消费 → 用了没批
    run4, evt4, v4 = make_waiting_run(mgr, "task_rec4")
    bypass = {
        "schema_version": "2.0",
        "approval_id": "apr_bypass_1", "approval_type": "resume",
        "key_id": "key_test_1", "run_id": run4, "task_id": "task_rec4",
        "stop_event_id": evt4, "stop_type": "prod-write",
        "stage": "S1_REQUIREMENT", "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"], "expected_state_version": v4,
        # actor 取登记面内字符串（G9-04/C 后 fixture 登记 principal——
        # 旁路场景的要点是「不经签发端手搓信封」而非冒名 actor）
        "actor": "chaoge",
        "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "nonce": "nonce-bypass-0000000001", "decision": "approve",
        "signature": "",
        "payload": issue_from_preconditions_payload(
            evt4, "prod-write", PRECONDITIONS),
    }
    bypass.pop("signature", None)
    bypass["signature"] = sign_envelope(kr.get("key_test_1"), bypass)
    mgr.resume_waiting(run4, bypass, PRECONDITIONS)
    report2 = reconcile_issuance(audit, os.path.join(tmp, "events.db"))
    assert report2["ok"] is False
    assert len(report2["consumed_without_issuance"]) == 1
    assert report2["consumed_without_issuance"][0][
        "approval_id"] == "apr_bypass_1"

    # 审计篡改：改一个字符 → 哈希链断裂
    lines = open(audit).read().splitlines(True)
    tampered = lines[0].replace("task_rec1", "task_evil")
    assert tampered != lines[0]
    with open(audit, "w") as fh:
        fh.write(tampered + "".join(lines[1:]))
    report3 = reconcile_issuance(audit, os.path.join(tmp, "events.db"))
    assert report3["chain_ok"] is False and report3["ok"] is False
    store.close()


# ====================================================================== #
# 11b. R8：principal 登记面（owner/actors）+ 同 actor 假双人 + 生命周期
#      过期边界（Codex 第八轮 P0-2 残余①③ 签发端预检面；权威门在消费端）
# ====================================================================== #
def test_r8_principal_registration_and_issuance_gates():
    tmp = tempfile.mkdtemp(prefix="wenqu-r8-iss-")
    # 坏登记面（actors 空/重复、owner 不在 actors）→ 元数据规范化拒绝
    expect(ValueError, lambda: ApprovalKeyring(
        {"key_x_1": "s" * 32}, metadata={"key_x_1": {"actors": []}}))
    expect(ValueError, lambda: ApprovalKeyring(
        {"key_x_1": "s" * 32},
        metadata={"key_x_1": {"actors": ["a", "a"]}}))
    expect(ValueError, lambda: ApprovalKeyring(
        {"key_x_1": "s" * 32},
        metadata={"key_x_1": {"owner": "boss", "actors": ["chaoge"]}}))
    kr = ApprovalKeyring(
        {"key_r8_a": generate_secret(), "key_r8_b": generate_secret()},
        metadata={
            "key_r8_a": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "chaoge", "actors": ["chaoge", "boss"]},
            "key_r8_b": {"status": "active",
                         "created_at": "2026-10-01T00:00:00Z",
                         "owner": "erge", "actors": ["erge"]}})
    assert kr.key_actors("key_r8_a") == ("chaoge", "boss")
    assert kr.key_actors("key_r8_b") == ("erge",)
    issuer = ApprovalIssuer(kr, os.path.join(tmp, "a.jsonl"))
    store = EventStore(os.path.join(tmp, "events.db"))
    mgr = RunManager(store, keyring=kr)
    run_id, stop_evt, v = make_waiting_run(mgr, "task_r8_iss")
    # actor 不在主签 key 的 actors 登记面 → 签发端预检拒（fail-closed）
    expect(IssuanceError, lambda: issue_resume(
        issuer, run_id, stop_evt, v, task_id="task_r8_iss",
        key_id="key_r8_a", actor="mallory"))
    # 登记面内 actor（boss 属 key_r8_a.actors）→ 可签
    r = issue_resume(issuer, run_id, stop_evt, v, task_id="task_r8_iss",
                     key_id="key_r8_a", actor="boss")
    assert r["approval"]["actor"] == "boss"
    assert mgr.resume_waiting(run_id, r["approval"], PRECONDITIONS)[
        "resumed"] is True
    # 高危同 actor 假双人（两把不同 key、同一 actor）→ 拒（真双人）
    base = dict(actor="chaoge", approval_type="prod_write", run_id="r1",
                task_id="t1", stage="S1_REQUIREMENT", environment="staging",
                authorized_scope="s", policy_hash="p", ruleset_hash="ru",
                input_watermark="a" * 40, expected_state_version=1,
                key_id="key_r8_a", payload=dict(PROD_WRITE_PAYLOAD))
    expect(TwoPersonRuleError, lambda: issuer.issue(
        confirm_two_persons=True, second_key_id="key_r8_b",
        second_actor="chaoge", **base))
    # 第二签发人不在第二 key 的 actors 登记面 → 签发端预检拒
    expect(IssuanceError, lambda: issuer.issue(
        confirm_two_persons=True, second_key_id="key_r8_b",
        second_actor="chaoge2", **base))
    # 合法联签：chaoge（∈key_r8_a）+ erge（∈key_r8_b）→ 双验真 + 消费端收
    r2 = issuer.issue(confirm_two_persons=True, second_key_id="key_r8_b",
                      second_actor="erge", **base)
    cos = r2["approval"]["cosignatures"]
    assert {c["actor"] for c in cos} == {"chaoge", "erge"}
    body = {k: v for k, v in r2["approval"].items()
            if k not in ("signature", "cosignatures")}
    assert all(kr.verify_detached(c["key_id"], body, c["signature"])
               for c in cos)
    assert IssuanceAudit.read_records(
        os.path.join(tmp, "a.jsonl"))  # 合法路径有审计
    # 过期边界（增断言）：expiry 早于 issued_at 的手签批 → keyring 面拒
    kr_exp = ApprovalKeyring(
        {"key_r8_e": generate_secret()},
        metadata={"key_r8_e": {
            "status": "active", "created_at": "2026-10-01T00:00:00Z",
            "expiry": "2026-10-03T00:00:00Z"}})
    expired = {"key_id": "key_r8_e", "approval_id": "apr_r8_exp",
               "issued_at": "2026-10-08T00:00:00Z"}
    expired["signature"] = sign_envelope(kr_exp.get("key_r8_e"), expired)
    assert kr_exp.verify(expired) is False
    store.close()


# ====================================================================== #
# 11b2. G9-04（第九轮 W2）：退休 key receipt 不可回填 + actual-target
#       强制绑定 + principal 强制登记——A/B/C 三门红绿面
# ====================================================================== #
RELEASE_TARGET = "prod://erp/rel-g904"


def _g9_release_payload(tmp):
    """release payload（artifact/manifest sha256 来自真实文件的实算）。"""
    art = os.path.join(tmp, "rel-artifact.bin")
    man = os.path.join(tmp, "rel-manifest.json")
    with open(art, "wb") as fh:
        fh.write(b"artifact-bytes-g9-04")
    with open(man, "wb") as fh:
        fh.write(b'{"manifest": "g9-04"}')
    import hashlib as _hl
    return {
        "release_id": "rel-g904-1",
        "artifact_sha256": _hl.sha256(open(art, "rb").read()).hexdigest(),
        "manifest_sha256": _hl.sha256(open(man, "rb").read()).hexdigest(),
        "environment": IDENT["environment"],
        "previous_release_id": "rel-g904-0",
    }, {"artifact_sha256": art, "manifest_sha256": man}


def _g9_issue_high_risk(issuer, mgr, run_id, task, payload, *,
                        atype="prod_write", key_id="key_g9_a",
                        second_key_id="key_g9_b"):
    run_state = mgr.get_run(run_id)
    return issuer.issue(
        actor="alice", approval_type=atype, run_id=run_id, task_id=task,
        stage=run_state.current_stage or "S1_REQUIREMENT",
        environment=IDENT["environment"], authorized_scope=IDENT["scope_hash"],
        policy_hash=IDENT["policy_hash"], ruleset_hash=IDENT["ruleset_hash"],
        input_watermark=IDENT["commit_sha"],
        expected_state_version=run_state.state_version,
        payload=dict(payload), key_id=key_id,
        confirm_two_persons=True, second_key_id=second_key_id,
        second_actor="bob")


def test_r9_g9_04_receipts_target_principal():
    tmp = tempfile.mkdtemp(prefix="wenqu-g904-")
    kdir = os.path.join(tmp, "keyring")
    # created_at 取旧时刻：回填窗口（created_at, rotated_at) 内的 issued_at
    # 才构成退休回填攻击而非时间穿越
    write_key_to_dir(kdir, "key_g9_a", generate_secret(),
                     {"status": "active", "created_at": "2026-01-01T00:00:00Z",
                      "owner": "alice", "actors": ["alice"]})
    write_key_to_dir(kdir, "key_g9_b", generate_secret(),
                     {"status": "active", "owner": "bob", "actors": ["bob"]})
    kr = ApprovalKeyring.from_path(kdir)
    store = EventStore(os.path.join(tmp, "events.db"))
    mgr = RunManager(store, keyring=kr)
    issuer = ApprovalIssuer(kr, os.path.join(kdir, "issuance-audit.jsonl"))

    # ---- A 正例：受控 issuer 签发 → 信封携带 receipt seq → 链完整可消费 ----
    run_id = mgr.create_run("task_g904_a", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    r1 = _g9_issue_high_risk(issuer, mgr, run_id, "task_g904_a",
                             PROD_WRITE_PAYLOAD)
    ap1 = r1["approval"]
    assert isinstance(ap1.get("issue_receipt"), dict) \
        and ap1["issue_receipt"]["seq"] >= 1
    assert r1["audit_record"]["issue_receipt_seq"] == \
        ap1["issue_receipt"]["seq"]
    ledger = IssueReceiptLedger(os.path.join(kdir, ISSUE_RECEIPTS_FILENAME),
                                secret_of={k: kr.get(k)
                                           for k in kr.key_ids()})
    chain = ledger.verify_chain()
    assert chain["ok"] is True and chain["length"] >= 1
    line = ledger.by_seq(ap1["issue_receipt"]["seq"])
    assert line and line["approval_id"] == ap1["approval_id"] \
        and line["key_id"] == "key_g9_a"
    rec = mgr.reserve_action(run_id, "prod-write", "erp://prod/batch-g9",
                             ap1, actor="probe",
                             action_descriptor=dict(PROD_WRITE_PAYLOAD),
                             runtime_evidence={**PROD_WRITE_PAYLOAD,
                                               "action_target":
                                                   "erp://prod/batch-g9"})
    assert rec["action_state"] == "RESERVED"

    # ---- A 负例：rotate 后持旧 secret 新签 + issued_at 回填退休前 → 拒
    #      （带全套 runtime evidence——隔离出 receipt 门本身）----
    r2 = _g9_issue_high_risk(issuer, mgr, run_id, "task_g904_a",
                             {**PROD_WRITE_PAYLOAD, "idempotency_key": "idem-2"})
    ap2 = r2["approval"]  # 退休前存量（rotation 后仍应可消费）
    rotated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # 与 CLI rotate 同款合并写（principal 登记面随轮换保留——换密钥不换人）
    save_key_meta(kdir, "key_g9_a", {
        **kr.meta("key_g9_a"), "status": "rotated",
        "rotated_at": rotated_at, "rotated_to": "key_g9_b"})
    kr2 = ApprovalKeyring.from_path(kdir)
    assert kr2.meta("key_g9_a")["retired_receipt_seq"] >= \
        ap2["issue_receipt"]["seq"]  # 轮换盘点已落 meta
    mgr2 = RunManager(store, keyring=kr2)
    # 存量（receipt.seq <= retired_receipt_seq 且 issued_at 在窗内）→ 可消费
    rec2 = mgr2.reserve_action(run_id, "prod-write", "erp://prod/batch-g9b",
                               ap2, actor="probe",
                               action_descriptor=dict(ap2["payload"]),
                               runtime_evidence={**ap2["payload"],
                                                 "action_target":
                                                     "erp://prod/batch-g9b"})
    assert rec2["action_state"] == "RESERVED"
    # 攻击信封：旧 secret 直签 + 新 nonce + issued_at 回填（< rotated_at）
    secret_a = kr2.get("key_g9_a")
    backdated = {
        "schema_version": "2.0", "approval_id": "apr_g904_backdate",
        "approval_type": "prod_write", "key_id": "key_g9_a",
        "run_id": run_id, "task_id": "task_g904_a",
        "stop_event_id": "n/a-prod-write", "stop_type": "prod-write",
        "stage": "S1_REQUIREMENT", "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "expected_state_version": mgr2.get_run(run_id).state_version,
        "actor": "alice",
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                   time.gmtime(time.time() - 3600)),
        "expires_at": "2099-01-01T00:00:00Z",
        "nonce": "nonce-g904-backdate-0001", "decision": "approve",
        "payload": dict(PROD_WRITE_PAYLOAD),
    }
    backdated["signature"] = sign_envelope(secret_a, backdated)
    body = {k: v for k, v in backdated.items()
            if k not in ("signature", "cosignatures")}
    backdated["cosignatures"] = [
        {"key_id": "key_g9_a", "actor": "alice",
         "signature": backdated["signature"]},
        {"key_id": "key_g9_b", "actor": "bob",
         "signature": sign_envelope(kr2.get("key_g9_b"), body)}]
    before_events = store._conn.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
    exc = None
    try:
        mgr2.reserve_action(run_id, "prod-write", "erp://prod/batch-g9",
                            backdated, actor="probe",
                            action_descriptor=dict(PROD_WRITE_PAYLOAD),
                            runtime_evidence={**PROD_WRITE_PAYLOAD,
                                              "action_target":
                                                  "erp://prod/batch-g9"})
    except ApprovalRejected as e:
        exc = e
    assert exc is not None and "receipt" in str(exc), \
        f"退休回填必须被 receipt 门拒绝: {exc}"
    after_events = store._conn.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
    assert after_events == before_events  # 零副作用（无消费事件/无预留）
    # receipt 结构负例：畸形 seq 结构层拒
    bad_receipt = json.loads(json.dumps(ap1))
    bad_receipt["issue_receipt"] = {"seq": 0}
    expect(ApprovalRejected, lambda: mgr2.reserve_action(
        run_id, "prod-write", "erp://prod/batch-g9x", bad_receipt,
        action_descriptor=dict(PROD_WRITE_PAYLOAD),
        runtime_evidence={**PROD_WRITE_PAYLOAD,
                          "action_target": "erp://prod/batch-g9x"}))

    # ---- B：actual-target 强制绑定（release 类型：artifact 实算哈希）----
    rel_payload, art_paths = _g9_release_payload(tmp)
    run_b = mgr2.create_run("task_g904_b", IDENT)["run_id"]
    mgr2.advance_stage(run_b)
    # 双人签发用 key_g9_a（已 rotated——不可签）→ 换 key_g9_b 当主签 +
    # 无第二 key……改用 prod_write 已覆盖 A 门；release 主签用新 active key：
    # key_g9_a 已退休，直接补一把新 active key 当 release 主签
    write_key_to_dir(kdir, "key_g9_c", generate_secret(),
                     {"status": "active", "owner": "carol",
                      "actors": ["carol"]})
    kr3 = ApprovalKeyring.from_path(kdir)
    mgr3 = RunManager(store, keyring=kr3)
    issuer3 = ApprovalIssuer(kr3, os.path.join(kdir, "issuance-audit.jsonl"))
    st_b = mgr3.get_run(run_b)
    r_rel = issuer3.issue(
        actor="carol", approval_type="release", run_id=run_b,
        task_id="task_g904_b", stage=st_b.current_stage or "S1_REQUIREMENT",
        environment=IDENT["environment"], authorized_scope=IDENT["scope_hash"],
        policy_hash=IDENT["policy_hash"], ruleset_hash=IDENT["ruleset_hash"],
        input_watermark=IDENT["commit_sha"],
        expected_state_version=st_b.state_version,
        payload=rel_payload, key_id="key_g9_c",
        confirm_two_persons=True, second_key_id="key_g9_b",
        second_actor="bob")
    ap_rel = r_rel["approval"]
    ev_ok = {"release_id": rel_payload["release_id"],
             "environment": rel_payload["environment"],
             "previous_release_id": rel_payload["previous_release_id"],
             "action_target": RELEASE_TARGET,
             "artifact_paths": dict(art_paths)}
    # B-1 省略 runtime evidence → ApprovalRejected（零副作用）
    before_b = store._conn.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
    exc = None
    try:
        mgr3.reserve_action(run_b, "release", RELEASE_TARGET, ap_rel,
                            actor="probe", action_descriptor=dict(rel_payload))
    except ApprovalRejected as e:
        exc = e
    assert exc is not None and "runtime evidence 缺失" in str(exc)
    assert store._conn.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == before_b
    # B-2 evidence 的 action_target 与实际执行 target 不符 → 拒（A 目标
    #     evidence 不得挪用到 B 执行）
    exc = None
    try:
        mgr3.reserve_action(
            run_b, "release", "prod://erp/rel-OTHER", ap_rel, actor="probe",
            action_descriptor=dict(rel_payload),
            runtime_evidence={**ev_ok, "action_target": RELEASE_TARGET})
    except ApprovalRejected as e:
        exc = e
    assert exc is not None and "action_target" in str(exc)
    # B-3 *_sha256 字段自报哈希（不经 artifact_paths 实算）→ 拒
    self_reported = {k: v for k, v in ev_ok.items() if k != "artifact_paths"}
    self_reported["artifact_sha256"] = rel_payload["artifact_sha256"]
    self_reported["manifest_sha256"] = rel_payload["manifest_sha256"]
    exc = None
    try:
        mgr3.reserve_action(run_b, "release", RELEASE_TARGET, ap_rel,
                            actor="probe", action_descriptor=dict(rel_payload),
                            runtime_evidence=self_reported)
    except ApprovalRejected as e:
        exc = e
    assert exc is not None and "artifact_paths" in str(exc)
    # B-4 全字段覆盖缺失（少 previous_release_id）→ 拒
    partial = {k: v for k, v in ev_ok.items()
               if k not in ("artifact_paths", "previous_release_id")}
    partial["artifact_paths"] = dict(art_paths)
    expect(ApprovalRejected, lambda: mgr3.reserve_action(
        run_b, "release", RELEASE_TARGET, ap_rel, actor="probe",
        action_descriptor=dict(rel_payload), runtime_evidence=partial))
    # B-5 正例：全量 evidence + artifact 实算 → RESERVED
    rec_rel = mgr3.reserve_action(run_b, "release", RELEASE_TARGET, ap_rel,
                                  actor="probe",
                                  action_descriptor=dict(rel_payload),
                                  runtime_evidence=ev_ok)
    assert rec_rel["action_state"] == "RESERVED"

    # ---- C：principal 强制登记（联签面）----
    s1, s2 = generate_secret(), generate_secret()
    kr_unreg = ApprovalKeyring({"key_g9_u1": s1, "key_g9_u2": s2})
    mgr_u = RunManager(store, keyring=kr_unreg)
    run_c = mgr_u.create_run("task_g904_c", IDENT)["run_id"]
    mgr_u.advance_stage(run_c)
    v_c = mgr_u.get_run(run_c).state_version
    # 两把无登记 key 自报不同人名（alice/bob）联签 → 拒（同 actor 双 key
    # 已拒保持；本腿为 G9-04 新增面）
    env_c = {
        "schema_version": "2.0", "approval_id": "apr_g904_unreg",
        "approval_type": "prod_write", "key_id": "key_g9_u1",
        "run_id": run_c, "task_id": "task_g904_c",
        "stop_event_id": "n/a-prod-write", "stop_type": "prod-write",
        "stage": "S1_REQUIREMENT", "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "expected_state_version": v_c, "actor": "alice",
        "issued_at": "2026-10-09T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "nonce": "nonce-g904-unreg-0001", "decision": "approve",
        "payload": dict(PROD_WRITE_PAYLOAD),
    }
    env_c["signature"] = sign_envelope(s1, env_c)
    cbody = {k: v for k, v in env_c.items()
             if k not in ("signature", "cosignatures")}
    env_c["cosignatures"] = [
        {"key_id": "key_g9_u1", "actor": "alice",
         "signature": env_c["signature"]},
        {"key_id": "key_g9_u2", "actor": "bob",
         "signature": sign_envelope(s2, cbody)}]
    before_c = store._conn.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
    exc = None
    try:
        mgr_u.reserve_action(run_c, "prod-write", "erp://prod/batch-g9c",
                             env_c, actor="probe",
                             action_descriptor=dict(PROD_WRITE_PAYLOAD),
                             runtime_evidence={**PROD_WRITE_PAYLOAD,
                                               "action_target":
                                                   "erp://prod/batch-g9c"})
    except ApprovalRejected as e:
        exc = e
    assert exc is not None and "principal" in str(exc), \
        f"无登记 principal 联签必须拒绝: {exc}"
    assert store._conn.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == before_c
    # 签发端对称：无登记 key 的双人签发也拒（早失败）
    issuer_u = ApprovalIssuer(kr_unreg, os.path.join(tmp, "unreg-audit.jsonl"))
    base_u = dict(actor="alice", approval_type="prod_write", run_id=run_c,
                  task_id="task_g904_c", stage="S1_REQUIREMENT",
                  environment=IDENT["environment"],
                  authorized_scope=IDENT["scope_hash"],
                  policy_hash=IDENT["policy_hash"],
                  ruleset_hash=IDENT["ruleset_hash"],
                  input_watermark=IDENT["commit_sha"],
                  expected_state_version=v_c, key_id="key_g9_u1",
                  payload=dict(PROD_WRITE_PAYLOAD))
    expect(TwoPersonRuleError, lambda: issuer_u.issue(
        confirm_two_persons=True, second_key_id="key_g9_u2",
        second_actor="bob", **base_u))
    # 两名已登记不同 principal 的正例已在 A/B 腿全链通过（alice/bob、
    # carol/bob 双人签发+联签消费 RESERVED）
    assert store.verify_chain()["ok"]
    store.close()


# ====================================================================== #
# 11b3. T1（第九轮整改）：receipt genesis 锚 fail-closed + 并发分配安全
#       ——R9-AUTH-RECEIPT-COLDSTART-001 / R9-AUTH-RECEIPT-CONCURRENCY-013
# ====================================================================== #
def test_r9_t1_receipt_genesis_failclosed_concurrency():
    tmp = tempfile.mkdtemp(prefix="wenqu-t1-")
    kdir = os.path.join(tmp, "keyring")
    ledger_path = os.path.join(kdir, ISSUE_RECEIPTS_FILENAME)

    # ---- 1. genesis 锚：keyring 出生（首个 key 落盘）即写入，形状可验 ----
    write_key_to_dir(kdir, "key_t1_a", generate_secret(),
                     {"status": "active", "created_at": "2026-01-01T00:00:00Z",
                      "owner": "alice", "actors": ["alice"]})
    write_key_to_dir(kdir, "key_t1_b", generate_secret(),
                     {"status": "active", "owner": "bob", "actors": ["bob"]})
    assert os.path.exists(ledger_path), "受管 keyring 出生即须有 genesis 锚"
    kr = ApprovalKeyring.from_path(kdir)
    view = {k: kr.get(k) for k in kr.key_ids()}
    ledger = IssueReceiptLedger(ledger_path, secret_of=view)
    genesis = ledger.records()[0]
    assert genesis["record_type"] == RECEIPT_GENESIS_RECORD_TYPE
    assert genesis["seq"] == 0 and genesis["chain_prev"] == "0" * 64
    assert len(genesis["epoch"]) == 32 and int(genesis["epoch"], 16) >= 0
    assert genesis["key_id"] in view and genesis["created_at"]
    assert ledger.verify_chain()["ok"] is True  # genesis-only 链可验
    # 幂等：再次 ensure_genesis 不改写、不重复
    same = IssueReceiptLedger(ledger_path, secret_of=view).ensure_genesis(
        anchor_key_id="key_t1_b")
    assert same["epoch"] == genesis["epoch"]
    assert len(ledger.records()) == 1

    store = EventStore(os.path.join(tmp, "events.db"))
    mgr = RunManager(store, keyring=kr)
    issuer = ApprovalIssuer(kr, os.path.join(kdir, "issuance-audit.jsonl"))
    run_id = mgr.create_run("task_t1_a", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    r1 = _g9_issue_high_risk(issuer, mgr, run_id, "task_t1_a",
                             PROD_WRITE_PAYLOAD, key_id="key_t1_a",
                             second_key_id="key_t1_b")
    ap1 = r1["approval"]
    assert ledger.verify_chain()["ok"] is True \
        and ledger.verify_chain()["length"] == 2  # genesis + 1 receipt
    # 受控签发的 receipt 链到 genesis 上（chain_prev=genesis 行摘要）
    line1 = ledger.by_seq(1)
    import hashlib as _hl
    assert line1["chain_prev"] == _hl.sha256(json.dumps(
        genesis, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()

    # 轮换（盘点落 meta）
    save_key_meta(kdir, "key_t1_a", {
        **kr.meta("key_t1_a"), "status": "rotated",
        "rotated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rotated_to": "key_t1_b"})
    kr2 = ApprovalKeyring.from_path(kdir)
    assert kr2.meta("key_t1_a")["retired_receipt_seq"] == 1
    mgr2 = RunManager(store, keyring=kr2)

    # ---- 2. 冷启动负例（红→绿主案）：删账本后旧 key 回填新签必须拒 ----
    orig_text = open(ledger_path, encoding="utf-8").read()  # 完整链快照
    os.remove(ledger_path)
    secret_a = kr2.get("key_t1_a")
    backdated = {
        "schema_version": "2.0", "approval_id": "apr_t1_cold",
        "approval_type": "prod_write", "key_id": "key_t1_a",
        "run_id": run_id, "task_id": "task_t1_a",
        "stop_event_id": "n/a-prod-write", "stop_type": "prod-write",
        "stage": "S1_REQUIREMENT", "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "expected_state_version": mgr2.get_run(run_id).state_version,
        "actor": "alice",
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                   time.gmtime(time.time() - 3600)),
        "expires_at": "2099-01-01T00:00:00Z",
        "nonce": "nonce-t1-cold-0001", "decision": "approve",
        "payload": dict(PROD_WRITE_PAYLOAD),
    }
    backdated["signature"] = sign_envelope(secret_a, backdated)
    bbody = {k: v for k, v in backdated.items()
             if k not in ("signature", "cosignatures")}
    backdated["cosignatures"] = [
        {"key_id": "key_t1_a", "actor": "alice",
         "signature": backdated["signature"]},
        {"key_id": "key_t1_b", "actor": "bob",
         "signature": sign_envelope(kr2.get("key_t1_b"), bbody)}]
    before = store._conn.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
    exc = None
    try:
        mgr2.reserve_action(run_id, "prod-write", "erp://prod/batch-t1",
                            backdated, actor="probe",
                            action_descriptor=dict(PROD_WRITE_PAYLOAD),
                            runtime_evidence={**PROD_WRITE_PAYLOAD,
                                              "action_target":
                                                  "erp://prod/batch-t1"})
    except ApprovalRejected as e:
        exc = e
    assert exc is not None and "COLDSTART-001" in str(exc), \
        f"删账本后回填新签必须 fail-closed 拒绝: {exc}"
    assert store._conn.execute(  # noqa: SLF001
        "SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == before
    # regime 破损对合法存量同样关闸（fail-closed 不择优）
    exc = None
    try:
        mgr2.reserve_action(run_id, "prod-write", "erp://prod/batch-t1",
                            ap1, actor="probe",
                            action_descriptor=dict(ap1["payload"]),
                            runtime_evidence={**ap1["payload"],
                                              "action_target":
                                                  "erp://prod/batch-t1"})
    except ApprovalRejected as e:
        exc = e
    assert exc is not None and "COLDSTART-001" in str(exc)

    # ---- 3. 截断负例：抹掉 genesis 行（保留 receipt）→ 链验失败拒 ----
    kept_lines = [l for l in orig_text.splitlines() if l.strip()]
    assert len(kept_lines) == 2  # genesis + 1 receipt
    with open(ledger_path, "w", encoding="utf-8") as fh:  # 只回填 receipt 行
        fh.write(kept_lines[1] + "\n")
    os.chmod(ledger_path, 0o600)
    bad = IssueReceiptLedger(ledger_path, secret_of=view).verify_chain()
    assert bad["ok"] is False and "genesis" in (bad["reason"] or "")
    kr3 = ApprovalKeyring.from_path(kdir)
    mgr3 = RunManager(store, keyring=kr3)
    exc = None
    try:
        mgr3.reserve_action(run_id, "prod-write", "erp://prod/batch-t1",
                            ap1, actor="probe",
                            action_descriptor=dict(ap1["payload"]),
                            runtime_evidence={**ap1["payload"],
                                              "action_target":
                                                  "erp://prod/batch-t1"})
    except ApprovalRejected as e:
        exc = e
    assert exc is not None and "审计链校验失败" in str(exc)
    # 签发端对称 fail-closed：不向无 genesis 的账本续签
    expect(ValueError, lambda: IssueReceiptLedger(
        ledger_path, secret_of=view).append(
        key_id="key_t1_b", approval_id="apr_x", nonce_digest="0" * 64,
        issued_at="2026-10-10T00:00:00Z"))
    expect(ValueError, lambda: IssueReceiptLedger(
        ledger_path, secret_of=view).ensure_genesis(
        anchor_key_id="key_t1_b"))

    # ---- 4. 退休盘点缺失负例：meta 被 stripped 后存量消费拒 ----
    # 恢复完整链（重建 keyring 账本——genesis+receipt 由 append 一次性重建）
    os.remove(ledger_path)
    rebuilt = IssueReceiptLedger(ledger_path, secret_of=view)
    rebuilt.append(key_id="key_t1_a", approval_id=ap1["approval_id"],
                   nonce_digest=_hl.sha256(
                       ap1["nonce"].encode()).hexdigest(),
                   issued_at=ap1["issued_at"])
    # ap1 现锚定 seq=1（重建链）；攻击：直接抹 meta 的退休盘点
    meta_file = os.path.join(kdir, "key_t1_a.meta.json")
    stripped = json.load(open(meta_file))
    stripped.pop("retired_receipt_seq", None)
    fd = os.open(meta_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(stripped, fh, ensure_ascii=False, indent=2, sort_keys=True)
    os.chmod(meta_file, 0o600)
    kr4 = ApprovalKeyring.from_path(kdir)
    mgr4 = RunManager(store, keyring=kr4)
    exc = None
    try:
        mgr4.reserve_action(run_id, "prod-write", "erp://prod/batch-t1",
                            ap1, actor="probe",
                            action_descriptor=dict(ap1["payload"]),
                            runtime_evidence={**ap1["payload"],
                                              "action_target":
                                                  "erp://prod/batch-t1"})
    except ApprovalRejected as e:
        exc = e
    assert exc is not None and "退休盘点" in str(exc), \
        f"退休 key 缺 retired_receipt_seq 必须 fail-closed: {exc}"

    # ---- 5. 并发分配：32 线程 × 2 轮 → 唯一连续 seq + 链无分叉 ----
    conc_dir = os.path.join(tmp, "conc")
    os.makedirs(conc_dir)
    csecret = generate_secret()
    cleared = IssueReceiptLedger(
        os.path.join(conc_dir, ISSUE_RECEIPTS_FILENAME),
        secret_of={"key_t1_c": csecret})
    rounds_n, threads_n = 2, 32
    worker_errors: list = []

    def _burst(ledger_obj, n):
        barrier = threading.Barrier(n)
        got: list = [None] * n

        def _w(i):
            try:
                barrier.wait(timeout=30)
                got[i] = ledger_obj.append(
                    key_id="key_t1_c", approval_id=f"apr_t1_c_{i}_"
                    f"{os.urandom(4).hex()}",
                    nonce_digest=os.urandom(16).hex(),
                    issued_at="2026-10-10T00:00:00Z")["seq"]
            except Exception as e:  # noqa: BLE001
                worker_errors.append(f"{type(e).__name__}: {e}")
        ts = [threading.Thread(target=_w, args=(i,)) for i in range(n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=60)
        return [s for s in got if s is not None]

    all_seqs: list = []
    for _ in range(rounds_n):
        all_seqs.extend(_burst(cleared, threads_n))
    assert not worker_errors, worker_errors
    assert sorted(all_seqs) == list(range(1, rounds_n * threads_n + 1)), \
        "32 线程并发签发必须分到唯一连续 seq（无重复/无空洞）"
    chain = cleared.verify_chain()
    assert chain["ok"] is True and chain["length"] == \
        rounds_n * threads_n + 1  # +genesis
    store.close()


# ====================================================================== #
# 11. CLI 端到端：keys/approve/消费/对账/来源占位（子进程 bash wenquctl）
# ====================================================================== #
CTL = os.path.join(REPO, "bin", "wenquctl")


def _cli(*args, expect_rc=0):
    proc = subprocess.run(["bash", CTL, *args], capture_output=True,
                          text=True)
    assert proc.returncode == expect_rc, (
        f"wenquctl {' '.join(args[:3])} rc={proc.returncode} "
        f"expect={expect_rc}: {proc.stderr[-400:]}")
    return proc


def test_cli_end_to_end():
    tmp = tempfile.mkdtemp(prefix="wenqu-cli-iss-")
    kdir = os.path.join(tmp, "keyring")
    db = os.path.join(tmp, "events.db")
    env_sha = "a" * 40

    # keys create x2（主签发 key + 第二签发人 key；G9-04/C：--principal
    # 强制登记 owner/actors——无登记 principal 的 key 不得参与高危联签）
    out = _cli("keys", "--keyring", kdir, "create", "--key-id", "key_cli_a",
               "--principal", "chaoge", "--actor", "boss")
    assert json.loads(out.stdout)["created"] is True
    _cli("keys", "--keyring", kdir, "create", "--key-id", "key_cli_b",
         "--principal", "erge", "--actor", "boss")
    listing = _cli("keys", "--keyring", kdir, "list")
    listed = json.loads(listing.stdout)
    assert {k["key_id"] for k in listed["keys"]} == {
        "key_cli_a", "key_cli_b"}
    # 红线：list 输出不含任何 secret 材料
    for kid in ("key_cli_a", "key_cli_b"):
        secret = open(os.path.join(kdir, f"{kid}.secret")).read().strip()
        assert secret not in listing.stdout

    # run 准备：create → advance → raise-waiting → status
    out = _cli("create", "--db", db, "--task", "task_cli_iss",
               "--commit-sha", env_sha, "--environment", "staging",
               "--scope-hash", IDENT["scope_hash"],
               "--policy-hash", IDENT["policy_hash"],
               "--ruleset-hash", IDENT["ruleset_hash"], "--actor", "chaoge")
    run_id = json.loads(out.stdout)["run_id"]
    _cli("advance", "--db", db, "--run", run_id, "--keys", kdir,
         "--actor", "chaoge")
    out = _cli("raise-waiting", "--db", db, "--run", run_id,
               "--stop-type", "prod-write", "--reason", "cli 签发端 e2e",
               "--actor", "chaoge")
    stop_evt = json.loads(out.stdout)["stop_event_id"]
    v = json.loads(_cli("status", "--db", db, "--run", run_id,
                        "--keys", kdir).stdout)["state_version"]
    pre_f = os.path.join(tmp, "pre.json")
    with open(pre_f, "w") as fh:
        json.dump(PRECONDITIONS, fh)
    ap_f = os.path.join(tmp, "ap.json")

    # approve 签发（resume；目录型 keyring 审计缺省 <dir>/issuance-audit.jsonl）
    out = _cli("approve", "--keyring", kdir, "--approval-type", "resume",
               "--run", run_id, "--task", "task_cli_iss",
               "--stage", "S1_REQUIREMENT", "--environment", "staging",
               "--scope", IDENT["scope_hash"],
               "--policy-hash", IDENT["policy_hash"],
               "--ruleset-hash", IDENT["ruleset_hash"],
               "--watermark", env_sha, "--state-version", str(v),
               "--actor", "chaoge", "--stop-type", "prod-write",
               "--stop-event-id", stop_evt, "--key-id", "key_cli_a",
               "--preconditions", pre_f, "--out", ap_f)
    receipt = json.loads(out.stdout)
    assert receipt["issued"] is True and receipt["two_person"] is False
    assert os.path.exists(os.path.join(kdir, "issuance-audit.jsonl"))
    # 信封文件 0600（含 nonce 凭据）且可被消费端读
    assert stat.S_IMODE(os.stat(ap_f).st_mode) == 0o600
    rec = json.loads(_cli("resume", "--db", db, "--run", run_id,
                          "--approval", ap_f, "--preconditions", pre_f,
                          "--keys", kdir, "--actor", "chaoge").stdout)
    assert rec["resumed"] is True
    # 重放拒（CLI rc=1）
    _cli("resume", "--db", db, "--run", run_id, "--approval", ap_f,
         "--preconditions", pre_f, "--keys", kdir, "--actor", "chaoge",
         expect_rc=1)

    # 高危 ddl：缺双人确认拒（rc=1）；联签成功（rc=0）
    ddl_f = os.path.join(tmp, "ddl.json")
    with open(ddl_f, "w") as fh:
        json.dump({"database_identity": "db://staging/erp",
                   "statement_digest": "f" * 64,
                   "before_schema_hash": "1" * 64,
                   "after_schema_hash": "2" * 64, "backup_id": "bak-1",
                   "rollback_plan_hash": "3" * 64}, fh)
    common = ["--keyring", kdir, "--approval-type", "ddl",
              "--run", run_id, "--task", "task_cli_iss",
              "--stage", "S1_REQUIREMENT", "--environment", "staging",
              "--scope", IDENT["scope_hash"],
              "--policy-hash", IDENT["policy_hash"],
              "--ruleset-hash", IDENT["ruleset_hash"],
              "--watermark", env_sha, "--state-version",
              str(mgr_free_version(db, run_id, kdir)), "--actor", "chaoge",
              "--key-id", "key_cli_a", "--payload", ddl_f,
              "--out", os.path.join(tmp, "ddl_ap.json")]
    _cli("approve", *common, expect_rc=1)
    out = _cli("approve", *common, "--confirm-two-persons",
               "--second-key-id", "key_cli_b", "--second-actor", "erge")
    assert json.loads(out.stdout)["two_person"] is True

    # --source feishu：占位接口 rc=2 + 明确报错
    merge_f = os.path.join(tmp, "merge.json")
    with open(merge_f, "w") as fh:
        json.dump({"repo_id": "qisemi-erp", "base_sha": "b" * 40,
                   "head_sha": "c" * 40, "merge_method": "merge"}, fh)
    proc = _cli("approve", "--keyring", kdir, "--approval-type", "merge",
                "--run", run_id, "--task", "task_cli_iss",
                "--stage", "S1_REQUIREMENT", "--environment", "staging",
                "--scope", IDENT["scope_hash"],
                "--policy-hash", IDENT["policy_hash"],
                "--ruleset-hash", IDENT["ruleset_hash"],
                "--watermark", env_sha, "--state-version", "99",
                "--actor", "chaoge", "--key-id", "key_cli_a",
                "--source", "feishu", "--payload", merge_f,
                "--out", os.path.join(tmp, "m.json"), expect_rc=2)
    assert "未接线" in proc.stderr

    # rotate + revoke：CLI 面
    out = _cli("keys", "--keyring", kdir, "rotate", "--key-id", "key_cli_b",
               "--actor", "boss")
    rot = json.loads(out.stdout)
    assert rot["rotated"] is True and rot["new_key_id"]
    _cli("keys", "--keyring", kdir, "revoke", "--key-id", rot["new_key_id"],
         "--actor", "boss")
    listing = _cli("keys", "--keyring", kdir, "list")
    statuses = {k["key_id"]: k["status"]
                for k in json.loads(listing.stdout)["keys"]}
    assert statuses["key_cli_b"] == "rotated" \
        and statuses[rot["new_key_id"]] == "revoked"
    for kid, _s in statuses.items():
        secret = open(os.path.join(kdir, f"{kid}.secret")).read().strip()
        assert secret not in listing.stdout

    # 对账模式：批了/用了闭环（只有第一份 resume 被消费）
    out = _cli("approve", "--keyring", kdir, "--reconcile-db", db)
    report = json.loads(out.stdout)
    assert report["ok"] is True and len(report["used_ok"]) == 1
    assert len(report["issued_unused_active"]) >= 1


def mgr_free_version(db, run_id, kdir):
    """CLI 测试助手：读当前 state_version（只读快照）。"""
    out = _cli("status", "--db", db, "--run", run_id, "--keys", kdir)
    return json.loads(out.stdout)["state_version"]


# ====================================================================== #
# 12. FeishuApprovalSource 占位（SKIP 语义）
# ====================================================================== #
def test_feishu_source_placeholder():
    src = FeishuApprovalSource()
    expect(NotImplementedError, lambda: src.submit({}, None))
    expect(NotImplementedError, lambda: src.callback({}))
    # 本地来源：submit 可用、callback 无通道（占位语义对称）
    local = LocalApprovalSource()
    assert local.submit({"approval_id": "apr_x"}, None)["delivered"] is True
    expect(NotImplementedError, lambda: local.callback({}))
    global SKIP_N
    SKIP_N += 1
    print("    ⏭ SKIP 飞书审批流未接线（架构裁定：本地 keyring+CLI 签发为"
          "默认案，飞书留接口——submit/callback 占位 NotImplementedError）")


TESTS = [
    ("契约零漂移：payload 判别表单一正源 + 高危类型集", test_payload_table_no_drift),
    ("keyring 元数据（静态夹具：active/rotated/revoked）", test_keyring_meta_fixture),
    ("keyring 坏元数据拒绝（未知字段/缺 rotated_at/未知 key）", test_keyring_bad_meta_rejected),
    ("受管 keyring 目录：0700/0600/事件账本/过期", test_managed_keyring_dir_lifecycle),
    ("签发：结构预检+HMAC 自验+审计（谁/何时/批了什么/TTL）", test_issue_resume_structure_and_audit),
    ("签发：payload 判别封闭（多/缺/空/坏枚举/坏 TTL 全拒且不落审计）", test_issue_payload_closed),
    ("签发：key 选择（多 active 歧义拒/无 active 拒/rotated 拒）", test_issue_key_selection),
    ("高危双人规则：缺旗标/缺第二 key/缺第二人/同 key 假联签全拒+联签双验真", test_two_person_rule),
    ("全链：签发→消费→重放拒→哈希链完好", test_issue_consume_replay),
    ("轮换：旧 key 可验存量、不得再签、新签发用新 key", test_rotation_semantics),
    ("吊销：验签即拒+拒绝事件记录+不得再签发", test_revocation_semantics),
    ("高危联签审批：reserve_action 消费→重放拒", test_high_risk_cosigned_reserve_action),
    ("R8：principal 登记面（owner/actors）+同 actor 假双人+生命周期过期边界", test_r8_principal_registration_and_issuance_gates),
    ("G9-04：退休key receipt不可回填+actual-target强制绑定+principal强制登记", test_r9_g9_04_receipts_target_principal),
    ("T1：receipt genesis锚fail-closed（冷启动/截断/盘点缺失）+并发分配安全", test_r9_t1_receipt_genesis_failclosed_concurrency),
    ("审计对账：批了/用了/未用过期/旁路签发/篡改断链", test_audit_reconciliation),
    ("CLI 端到端：keys/approve/消费/重放拒/联签/feishu 占位/对账", test_cli_end_to_end),
    ("FeishuApprovalSource 占位接口（SKIP）", test_feishu_source_placeholder),
]


if __name__ == "__main__":
    for name, fn in TESTS:
        check(name, fn)
    print(f"\n审批签发端全链: {PASS_N} PASS / {FAIL_N} FAIL / {SKIP_N} SKIP")
    sys.exit(1 if FAIL_N else 0)

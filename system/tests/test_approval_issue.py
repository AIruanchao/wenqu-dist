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
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import (  # noqa: E402
    KEYRING_EVENTS_FILENAME, ApprovalKeyring, KeyExpiredError,
    KeyNotFoundError, KeyRevokedError, KeyRotatedError, KeyStateError,
    append_keyring_event, ensure_keyring_dir, generate_secret,
    save_key_meta, sign_envelope, verify_envelope, write_key_to_dir,
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
    # 轮换：旧 → 新
    save_key_meta(kdir, "key_old", {
        "status": "rotated", "rotated_at": "2026-10-08T00:00:00Z",
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
    # 消费必须凭 exact action descriptor（payload 与实参逐字段等值）
    rec = mgr.reserve_action(run_id, "prod-write", "erp://prod/batch-77",
                             r["approval"], actor="system",
                             action_descriptor=dict(PROD_WRITE_PAYLOAD))
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
        "actor": "attacker",
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

    # keys create x2（主签发 key + 第二签发人 key）
    out = _cli("keys", "--keyring", kdir, "create", "--key-id", "key_cli_a",
               "--actor", "boss")
    assert json.loads(out.stdout)["created"] is True
    _cli("keys", "--keyring", kdir, "create", "--key-id", "key_cli_b",
         "--actor", "boss")
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
    ("审计对账：批了/用了/未用过期/旁路签发/篡改断链", test_audit_reconciliation),
    ("CLI 端到端：keys/approve/消费/重放拒/联签/feishu 占位/对账", test_cli_end_to_end),
    ("FeishuApprovalSource 占位接口（SKIP）", test_feishu_source_placeholder),
]


if __name__ == "__main__":
    for name, fn in TESTS:
        check(name, fn)
    print(f"\n审批签发端全链: {PASS_N} PASS / {FAIL_N} FAIL / {SKIP_N} SKIP")
    sys.exit(1 if FAIL_N else 0)

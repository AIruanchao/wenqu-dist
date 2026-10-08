#!/usr/bin/env python3
"""第六轮独立动作授权链探针；仅操作临时 SQLite。"""
from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path

REPO = Path(os.environ["WQ_FROZEN_REPO"])
import sys
sys.path.insert(0, str(REPO / "system"))

from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope
from wenqu_core.store import EventStore
from wenqu_core.wenqu_pipeline import (
    ActionError, ApprovalRejected, ApprovalReuseError, RunManager,
    RECEIPT_PROVISIONAL, RECEIPT_RECONCILED,
)

KEYRING = ApprovalKeyring.from_path(
    str(REPO / "system/tests/fixtures/approval-keys.json"))
KEY_ID = "key_test_1"
SECRET = KEYRING.get(KEY_ID)
IDENT = {
    "commit_sha": "6" * 40,
    "environment": "staging",
    "scope_hash": "reaudit6-scope",
    "repo_id": "reaudit6-local",
    "ruleset_hash": "rules-v6",
    "policy_hash": "policy-v6",
}


def sign(obj):
    value = copy.deepcopy(obj)
    value.pop("signature", None)
    value["signature"] = sign_envelope(SECRET, value)
    return value


def approval(run_id, task_id, version, *, nonce, **changes):
    value = {
        "schema_version": "2.0",
        "approval_id": "apr_reaudit6_" + nonce[-8:].replace("-", "_"),
        "approval_type": "release",
        "key_id": KEY_ID,
        "run_id": run_id,
        "task_id": task_id,
        "stop_event_id": "n/a-action-reserve",
        "stop_type": "prod-write",
        "stage": "S1_REQUIREMENT",
        "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "actor": "reaudit6",
        "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_state_version": version,
        "nonce": nonce,
        "decision": "approve",
        "payload": {
            "release_id": "rel-independent-6",
            "artifact_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
            "environment": IDENT["environment"],
            "previous_release_id": "rel-independent-5",
        },
    }
    value.update(changes)
    return sign(value)


def receipt(action, run_id, *, outcome="COMMITTED", **changes):
    value = {
        "schema_version": "1.0",
        "receipt_type": "action-execution-receipt",
        "action_id": action["action_id"],
        "run_id": run_id,
        "action_type": action["action_type"],
        "action_target": action["action_target"],
        "watermark": IDENT["commit_sha"],
        "outcome": outcome,
        "external_ref": "external-independent-6",
        "ts": "2026-10-08T00:00:00Z",
        "key_id": KEY_ID,
    }
    value.update(changes)
    return sign(value)


def rejected(exc_type, func, label):
    try:
        func()
    except exc_type as exc:
        print(f"PASS reject {label}: {type(exc).__name__}: {exc}")
        return
    raise AssertionError(f"未拒绝: {label}")


def event_types(store):
    return [p.get("event_type") for _, _, p in store._db.read_events(store._conn)] \
        if hasattr(store, "_db") else [
            json.loads(r[0]).get("event_type")
            for r in store._conn.execute("SELECT payload FROM pipeline_events ORDER BY seq")
        ]


def new_manager(prefix):
    td = tempfile.mkdtemp(prefix=prefix)
    store = EventStore(os.path.join(td, "events.db"))
    return td, store, RunManager(store, keyring=KEYRING)


def main():
    task = "task_reaudit6_auth"
    td, store, mgr = new_manager("reaudit6-auth-")
    run_id = mgr.create_run(task, IDENT)["run_id"]
    mgr.advance_stage(run_id)
    version = mgr.get_run(run_id).state_version
    before_events = event_types(store)

    rejected(ActionError,
             lambda: mgr.reserve_action(run_id, "release", "prod://release/6"),
             "无审批 reserve")
    assert event_types(store) == before_events
    assert mgr.broker.consumed_approvals(run_id=run_id) == []

    mixed = approval(run_id, task, version,
                     nonce="nonce-reaudit6-mixed-0001")
    mixed["payload"]["operation_digest"] = "c" * 64
    mixed = sign(mixed)
    rejected(ApprovalRejected,
             lambda: mgr.reserve_action(run_id, "release", "prod://release/6", mixed),
             "release payload 混入 prod_write 字段")

    stale = approval(run_id, task, version + 1,
                     nonce="nonce-reaudit6-stale-0002")
    rejected(ApprovalRejected,
             lambda: mgr.reserve_action(run_id, "release", "prod://release/6", stale),
             "state_version CAS 错位")

    expired = approval(
        run_id, task, version, nonce="nonce-reaudit6-expired-03",
        issued_at="2020-01-01T00:00:00Z", expires_at="2020-01-02T00:00:00Z")
    rejected(ApprovalRejected,
             lambda: mgr.reserve_action(run_id, "release", "prod://release/6", expired),
             "过期授权")
    assert mgr.broker.consumed_approvals(run_id=run_id) == []

    # 故障注入：先让 APPROVAL_CONSUMED 写入，再在 ACTION_AUTH_RESERVED 发射点抛错。
    # 若二者不是同一事务，nonce/控制事件会留下“单只”。
    atomic = approval(run_id, task, version,
                      nonce="nonce-reaudit6-atomic-04")
    original_emit = mgr._emit
    def fail_reserved(conn, state, event):
        if event.get("event_type") == "ACTION_AUTH_RESERVED":
            raise RuntimeError("reaudit6 injected failure after approval consume")
        return original_emit(conn, state, event)
    mgr._emit = fail_reserved
    rejected(RuntimeError,
             lambda: mgr.reserve_action(run_id, "release", "prod://release/atomic", atomic),
             "授权消费后预留写故障")
    mgr._emit = original_emit
    assert mgr.broker.consumed_approvals(run_id=run_id) == []
    assert event_types(store) == before_events
    # 同一 nonce 可重试成功，证明失败事务未消费。
    atomic_action = mgr.reserve_action(
        run_id, "release", "prod://release/atomic", atomic)
    assert atomic_action["action_state"] == "RESERVED"
    types = event_types(store)
    assert types[-2:] == ["APPROVAL_CONSUMED", "ACTION_AUTH_RESERVED"], types[-4:]
    rejected(ApprovalReuseError,
             lambda: mgr.reserve_action(run_id, "release", "prod://release/atomic", atomic),
             "nonce 重放")

    started = mgr.start_action(run_id, atomic_action["action_id"],
                               receipt="caller says done")
    assert started["action_state"] == "STARTED"
    current = mgr.get_run(run_id).actions[atomic_action["action_id"]]
    assert current["receipt_status"] == RECEIPT_PROVISIONAL
    rejected(ActionError,
             lambda: mgr.commit_action(run_id, atomic_action["action_id"], "caller receipt"),
             "调用方字符串回执直接 commit")

    forged = receipt(atomic_action, run_id)
    forged["external_ref"] = "tampered-after-signing"
    rec = mgr.reconcile_receipt(run_id, atomic_action["action_id"], forged)
    assert rec["reconciled"] is False
    assert mgr.get_run(run_id).actions[atomic_action["action_id"]]["action_state"] == "STARTED"

    good = receipt(atomic_action, run_id)
    assert mgr.reconcile_receipt(run_id, atomic_action["action_id"], good)["reconciled"] is True
    committed = mgr.commit_action(run_id, atomic_action["action_id"], good)
    assert committed["action_state"] == "COMMITTED"
    assert committed["receipt_status"] == RECEIPT_RECONCILED

    # 第二动作验证 FAILED_UNKNOWN 是不可逆终态。
    v2 = mgr.get_run(run_id).state_version
    ap2 = approval(run_id, task, v2, nonce="nonce-reaudit6-unknown-05")
    a2 = mgr.reserve_action(run_id, "release", "prod://release/unknown", ap2)
    mgr.start_action(run_id, a2["action_id"])
    failed = mgr.fail_action(run_id, a2["action_id"], "external outcome unavailable")
    assert failed["action_state"] == "FAILED_UNKNOWN"
    terminal = mgr.reconcile_receipt(run_id, a2["action_id"], {"junk": 1})
    assert terminal["reconciled"] is None
    rejected(ActionError,
             lambda: mgr.start_action(run_id, a2["action_id"]),
             "FAILED_UNKNOWN 后再启动")

    # 重建状态，验证授权消费链与 receipt 分级不是内存假象。
    replay = RunManager(store, keyring=KEYRING).get_run(run_id)
    assert replay.actions[atomic_action["action_id"]]["action_state"] == "COMMITTED"
    assert replay.actions[atomic_action["action_id"]]["receipt_status"] == RECEIPT_RECONCILED
    assert replay.actions[a2["action_id"]]["action_state"] == "FAILED_UNKNOWN"
    assert len(replay.consumed_nonce_digests) == 2
    assert store.verify_chain()["ok"] is True

    print(json.dumps({
        "result": "PASS", "temp_db_dir": td, "run_id": run_id,
        "event_types": event_types(store),
        "consumed_count": len(mgr.broker.consumed_approvals(run_id=run_id)),
        "final_actions": {k: v["action_state"] for k, v in replay.actions.items()},
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

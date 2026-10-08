#!/usr/bin/env python3
"""验证签名 action payload 是否与 reserve_action 的实际目标精确绑定。"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import auth_chain_probe as base


def main():
    _td, store, mgr = base.new_manager("reaudit6-auth-target-")
    task = "task_reaudit6_exact_target"
    run_id = mgr.create_run(task, base.IDENT)["run_id"]
    mgr.advance_stage(run_id)
    version = mgr.get_run(run_id).state_version

    signed = base.approval(
        run_id, task, version, nonce="nonce-reaudit6-target-bypass-01")
    authorized_payload = signed["payload"]
    # 该实际目标不出现在已签名 envelope/payload 中；payload 授权的是
    # rel-independent-6 及固定 artifact/manifest/previous_release。
    actual_target = "prod://release/UNAUTHORIZED-TARGET-NOT-IN-PAYLOAD"
    assert actual_target not in json.dumps(signed, sort_keys=True)

    action = mgr.reserve_action(run_id, "release", actual_target, signed)
    mgr.start_action(run_id, action["action_id"], receipt="caller started other target")
    external = base.receipt(action, run_id)
    committed = mgr.commit_action(run_id, action["action_id"], external)

    events = [
        json.loads(row[0])
        for row in store._conn.execute(
            "SELECT payload FROM pipeline_events ORDER BY seq")
    ]
    consumed = next(e for e in events if e.get("event_type") == "APPROVAL_CONSUMED")
    reserved = next(e for e in events if e.get("event_type") == "ACTION_AUTH_RESERVED")
    # 消费事件也不保存已签 payload，重放只看 approval_type/id/nonce，无法证明
    # release_id/artifact/manifest 与实际 target 的对应关系。
    result = {
        "result": "VULNERABLE",
        "signed_release_payload": authorized_payload,
        "actual_action_target": actual_target,
        "reserved_state": action["action_state"],
        "committed_state": committed["action_state"],
        "receipt_status": committed["receipt_status"],
        "consumed_event_has_payload": "payload" in consumed,
        "reserved_event_approval_id": reserved.get("approval_id"),
        "reserved_event_action_target": reserved.get("action_target"),
        "chain_ok": store.verify_chain()["ok"],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    # 审计探针以非零表示发现绕过。
    if committed["action_state"] == "COMMITTED" and not result["consumed_event_has_payload"]:
        raise SystemExit(1)
    raise SystemExit(0)


if __name__ == "__main__":
    main()

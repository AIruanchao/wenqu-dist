#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第七轮独立审批签发/消费对抗探针；只在 /tmp 中创建临时库和密钥。"""
import copy
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import sys
import tempfile
from pathlib import Path

REPO = "/tmp/wenqu-reaudit7-f6p0-22971"
sys.path.insert(0, os.path.join(REPO, "system"))
from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope  # noqa:E402
from wenqu_core.approval_issue import ApprovalIssuer, IssuanceAudit, reconcile_issuance  # noqa:E402
from wenqu_core.store import EventStore  # noqa:E402
from wenqu_core.wenqu_pipeline import RunManager  # noqa:E402

IDENT = {
    "commit_sha": "a" * 40,
    "environment": "staging",
    "scope_hash": "scope-independent-7",
    "repo_id": "independent-audit",
    "ruleset_hash": "rules-independent-7",
    "policy_hash": "policy-independent-7",
}
PAYLOAD = {
    "release_id": "rel-approved-A",
    "artifact_sha256": "b" * 64,
    "manifest_sha256": "c" * 64,
    "environment": "staging",
    "previous_release_id": "rel-prev",
}

def mode(path):
    return oct(stat.S_IMODE(os.stat(path).st_mode))

def digest(s):
    return hashlib.sha256(s.encode()).hexdigest()

def make_single_signed_from(template, *, run_id, task_id, secret):
    ap = copy.deepcopy(template)
    ap.update({
        "approval_id": "apr_manual_single_" + secrets.token_hex(8),
        "run_id": run_id,
        "task_id": task_id,
        "expected_state_version": 1,
        "nonce": secrets.token_hex(16),
        "actor": "single-signer-bypass",
    })
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(secret, ap)
    return ap

def main():
    out = {"probe": "approval-independent-v1", "repo_head": None}
    with tempfile.TemporaryDirectory(prefix="reaudit7-approval-") as td:
        db_path = os.path.join(td, "events.db")
        audit_path = os.path.join(td, "issuance-audit.jsonl")
        # secrets 仅存在此 TemporaryDirectory / 内存；输出只记 key id、权限、指纹。
        primary_secret = secrets.token_hex(32)
        second_secret = secrets.token_hex(32)
        kr = ApprovalKeyring({"key_primary_7": primary_secret,
                              "key_second_7": second_secret})
        store = EventStore(db_path)
        mgr = RunManager(store, keyring=kr)
        issuer = ApprovalIssuer(kr, audit_path)

        r1 = mgr.create_run("task_target_mismatch", IDENT)
        issued = issuer.issue(
            actor="auditor-A", approval_type="release",
            run_id=r1["run_id"], task_id="task_target_mismatch",
            stage="S1_REQUIREMENT", environment="staging",
            authorized_scope=IDENT["scope_hash"],
            policy_hash=IDENT["policy_hash"], ruleset_hash=IDENT["ruleset_hash"],
            input_watermark=IDENT["commit_sha"], expected_state_version=1,
            payload=PAYLOAD, key_id="key_primary_7",
            confirm_two_persons=True, second_key_id="key_second_7",
            second_actor="auditor-B")
        # 对抗 1：信封批准 release_id=A，但预留完全不同的 action target=B；
        # 消费 API 不接收 co_signature，也不对 target 与 payload 做任何绑定。
        reserved1 = mgr.reserve_action(
            r1["run_id"], "release", "prod://release/UNAUTHORIZED-B",
            approval=issued["approval"], actor="probe")
        out["two_person_issued"] = {
            "co_signature_returned": issued["co_signature"] is not None,
            "envelope_has_co_signature": "co_signature" in issued["approval"],
            "audit_two_person": issued["audit_record"].get("two_person"),
        }
        out["target_binding_probe"] = {
            "reserved": True,
            "approved_payload_release_id": PAYLOAD["release_id"],
            "reserved_action_target": reserved1["action_target"],
            "different": reserved1["action_target"] != PAYLOAD["release_id"],
        }

        # 对抗 2：绕过 ApprovalIssuer 与双人联签，直接用一把 active HMAC key
        # 构造合法高危 release envelope；消费端应当 fail-closed，但实际接受。
        r2 = mgr.create_run("task_single_signer", IDENT)
        single_ap = make_single_signed_from(
            issued["approval"], run_id=r2["run_id"],
            task_id="task_single_signer", secret=primary_secret)
        reserved2 = mgr.reserve_action(
            r2["run_id"], "release", "prod://release/SINGLE-SIGNER",
            approval=single_ap, actor="probe")
        out["single_signer_high_risk_probe"] = {
            "reserved": True,
            "action_id_present": bool(reserved2.get("action_id")),
            "approval_has_co_signature": "co_signature" in single_ap,
            "approval_id_fingerprint": digest(single_ap["approval_id"]),
        }

        # 事件面只含 approval_id/nonce/type，不含 payload 摘要、联签信息或 target 绑定。
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT payload FROM pipeline_events ORDER BY seq"
        ).fetchall()
        events = [json.loads(x[0]) for x in rows]
        consumed = [e for e in events if e.get("event_type") == "APPROVAL_CONSUMED"]
        reserved = [e for e in events if e.get("event_type") == "ACTION_AUTH_RESERVED"]
        conn.close()
        out["event_surface"] = {
            "consumed_count": len(consumed),
            "reserved_count": len(reserved),
            "consumed_keys": sorted(consumed[-1].keys()),
            "consumed_has_payload_digest": any(k in consumed[-1] for k in
                ("payload", "payload_digest", "co_signature", "second_key_id")),
            "reserved_has_approval_payload_digest": any(k in reserved[-1] for k in
                ("approval_payload", "approval_payload_digest", "co_signature", "second_key_id")),
        }
        rec = reconcile_issuance(audit_path, db_path)
        out["reconciliation_after_bypass"] = {
            "ok": rec["ok"],
            "used_ok_count": len(rec["used_ok"]),
            "consumed_without_issuance_count": len(rec["consumed_without_issuance"]),
            "chain_ok": rec["chain_ok"],
        }
        out["audit_chain"] = IssuanceAudit.verify_chain(audit_path)

        # 对抗 3：加载器不校验现存 keyring/secret 的权限。只输出模式与指纹。
        loose_file = os.path.join(td, "loose-keyring.json")
        Path(loose_file).write_text(json.dumps({"keys": {"key_loose_7": primary_secret}}), encoding="utf-8")
        os.chmod(loose_file, 0o644)
        loaded_file = ApprovalKeyring.from_path(loose_file)
        loose_dir = os.path.join(td, "loose-dir")
        os.mkdir(loose_dir, 0o755)
        loose_secret_file = os.path.join(loose_dir, "key_loose_dir_7.secret")
        Path(loose_secret_file).write_text(second_secret + "\n", encoding="utf-8")
        os.chmod(loose_dir, 0o755)
        os.chmod(loose_secret_file, 0o644)
        loaded_dir = ApprovalKeyring.from_path(loose_dir)
        out["loose_permission_probe"] = {
            "json_mode": mode(loose_file),
            "json_loaded_key_ids": loaded_file.key_ids(),
            "json_key_fingerprint": digest(loaded_file.get("key_loose_7")),
            "dir_mode": mode(loose_dir),
            "secret_mode": mode(loose_secret_file),
            "dir_loaded_key_ids": loaded_dir.key_ids(),
            "dir_key_fingerprint": digest(loaded_dir.get("key_loose_dir_7")),
            "raw_secret_emitted": False,
        }
        store.close()
    print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))
    # 漏洞被成功触发时，探针本身 rc=0；判定由字段 reserved/different 表示。
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第九轮授权域探针 P3：signer principal 绑定（actor∈key.actors，新变体）。

正例：
  pos1 actor∈actors（非 owner 成员亦放行——membership 语义）
  pos2 未登记 actors 的存量 key 单签路径 opt-in 放行（诚实边界，非漏洞）
新负例：
  N1 大小写变体 actor="Alice"（精确匹配）→拒
  N2 尾随空格 actor="alice " →拒
  N3 冒用非成员 actor="mallory"（HMAC 真）→拒 + 事件账本落 PRINCIPAL 拒绝
  N4 篡改 actor 后不改签名（crypto 优先归因）→验签失败拒
  N5 broker 消费路径（RunManager.resume_waiting）冒用 actor →拒
"""
import json
import os
import sys
import tempfile
import time

REPO = "/private/tmp/wenqu-auth9-20261014-093158/system"
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import (  # noqa: E402
    KEYRING_EVENTS_FILENAME, ApprovalKeyring, generate_secret,
    sign_envelope, write_key_to_dir)
from wenqu_core.approval_issue import (  # noqa: E402
    ApprovalIssuer, IssuanceError)
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ApprovalRejected, RunManager)

IDENT = {
    "commit_sha": "7" * 40, "environment": "local",
    "scope_hash": "scope-p3", "repo_id": "repo-p3",
    "ruleset_hash": "rules-p3", "policy_hash": "pol-p3",
}
RESULTS = []


def case(name, ok, note=""):
    verdict = "PASS" if ok else "FAIL"
    RESULTS.append((verdict, name))
    print(f"  [{verdict}] {name} {note}")


TMP = tempfile.mkdtemp(prefix="auth9-p3-")

# 内存 keyring：登记面 {alice,bob}；key2 无登记面（opt-in 边界）
KR = ApprovalKeyring(
    {"key_p3_ab": generate_secret(), "key_p3_bare": generate_secret()},
    metadata={"key_p3_ab": {"status": "active", "owner": "alice",
                            "actors": ["alice", "bob"]}})

env = {"key_id": "key_p3_ab", "approval_id": "apr_p3_x",
       "actor": "bob", "issued_at": "2026-10-14T01:00:00Z"}
env["signature"] = sign_envelope(KR.get("key_p3_ab"), env)
case("P3-pos1 非 owner 成员 bob∈actors 单签验签放行", KR.verify(env) is True)

bare = {"key_id": "key_p3_bare", "approval_id": "apr_p3_bare",
        "actor": "whoever-unregistered", "issued_at": "2026-10-14T01:00:00Z"}
bare["signature"] = sign_envelope(KR.get("key_p3_bare"), bare)
case("P3-pos2 未登记 actors 的 key（opt-in 边界）放行（登记面未强制）",
     KR.verify(bare) is True)

n1 = dict(env); n1["actor"] = "Alice"
n1["signature"] = sign_envelope(KR.get("key_p3_ab"), n1)
case("P3-N1 大小写变体 Alice（HMAC 重算真）→拒", KR.verify(n1) is False)

n2 = dict(env); n2["actor"] = "alice "
n2["signature"] = sign_envelope(KR.get("key_p3_ab"), n2)
case("P3-N2 尾随空格 actor →拒（精确 membership）", KR.verify(n2) is False)

# 受管目录 keyring：事件账本取证
kdir = os.path.join(TMP, "keyring")
write_key_to_dir(kdir, "key_p3_dir", generate_secret(),
                 {"status": "active", "owner": "carol",
                  "actors": ["carol", "dave"]})
krd = ApprovalKeyring.from_path(kdir)
n3 = {"key_id": "key_p3_dir", "approval_id": "apr_p3_n3",
      "approval_type": "merge", "run_id": "run_p3",
      "actor": "mallory",
      "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                 time.gmtime(time.time() + 3600))}
n3["signature"] = sign_envelope(krd.get("key_p3_dir"), n3)
rejected = krd.verify(n3) is False
evlog = os.path.join(kdir, KEYRING_EVENTS_FILENAME)
principal_logged = False
if os.path.exists(evlog):
    for line in open(evlog):
        rec = json.loads(line)
        if rec.get("record_type") == "PRINCIPAL_VERIFY_REJECTED" \
                and rec.get("actor") == "mallory":
            principal_logged = True
case("P3-N3 冒用 mallory（HMAC 真）→拒+账本落 PRINCIPAL 拒绝",
     rejected and principal_logged)

n4 = dict(env); n4["actor"] = "mallory"  # 不重签——篡改
case("P3-N4 篡改 actor 不重签 →验签失败拒（crypto 先于 membership）",
     KR.verify(n4) is False)

# broker 全链：resume_waiting 冒用他人 actor
# （签发端正门会先拒——见下方 N6；此例手造信封测消费端权威门）
store = EventStore(os.path.join(TMP, "ev.db"))
mgr = RunManager(store, keyring=KR)
run_id = mgr.create_run("task_p3", IDENT)["run_id"]
mgr.advance_stage(run_id)
w = mgr.raise_waiting(run_id, "prod-write", "p3 停等")
v = mgr.get_run(run_id).state_version

issuer = ApprovalIssuer(KR, os.path.join(TMP, "audit.jsonl"))
from wenqu_core.approval_issue import issue_from_preconditions_payload  # noqa: E402
from wenqu_core.wenqu_pipeline import SevenStageStateMachine  # noqa: E402
pre = {"gate_reference": "gate:p3", "rollback_level": "R2"}
pre_hash = SevenStageStateMachine.objective_precondition_hash(dict(pre))
ap = {
    "schema_version": "2.0", "approval_id": "apr_p3_hand",
    "approval_type": "resume", "key_id": "key_p3_ab",
    "run_id": run_id, "task_id": "task_p3",
    "stop_event_id": w["stop_event_id"], "stop_type": "prod-write",
    "stage": "S1_REQUIREMENT", "environment": IDENT["environment"],
    "authorized_scope": IDENT["scope_hash"], "policy_hash": IDENT["policy_hash"],
    "ruleset_hash": IDENT["ruleset_hash"],
    "input_watermark": IDENT["commit_sha"],
    "expected_state_version": v, "actor": "carol",  # 不在 {alice,bob}
    "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                time.gmtime(time.time() + 3600)),
    "nonce": "p3-hand-crafted-nonce-0001", "decision": "approve",
    "payload": {"stop_event_id": w["stop_event_id"], "stop_type": "prod-write",
                "objective_precondition_hash": pre_hash},
}
ap["signature"] = sign_envelope(KR.get("key_p3_ab"), ap)
try:
    mgr.resume_waiting(run_id, ap, pre)
    broker_rejected = False
except ApprovalRejected as exc:
    broker_rejected = "principal" in str(exc) or "actors" in str(exc)
    print(f"    (N5 broker) {str(exc)[:110]}")
case("P3-N5 broker 消费路径冒用 actor →principal 拒", broker_rejected)

# 签发端预检：actor 不在登记面 → IssuanceError（早失败）
try:
    issuer.issue(
        actor="eve", approval_type="merge", run_id="run_x", task_id="t",
        stop_type="scope", stage="S1_REQUIREMENT", environment="local",
        authorized_scope="s", policy_hash="p", ruleset_hash="r",
        input_watermark="a" * 40, expected_state_version=1,
        payload={"repo_id": "r1", "base_sha": "b" * 40, "head_sha": "c" * 40,
                 "merge_method": "merge"},
        key_id="key_p3_ab")
    issue_rejected = False
except IssuanceError:
    issue_rejected = True
case("P3-N6 签发端预检 actor∉actors →IssuanceError", issue_rejected)

fails = [r for r in RESULTS if r[0] == "FAIL"]
print(f"\nP3 SUMMARY: total={len(RESULTS)} pass={len(RESULTS)-len(fails)} "
      f"fail={len(fails)}")
sys.exit(1 if fails else 0)

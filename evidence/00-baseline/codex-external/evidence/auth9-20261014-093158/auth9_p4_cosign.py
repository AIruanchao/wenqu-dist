#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第九轮授权域探针 P4（v2 修正版）：联签消费强制。

修正：动态 TTL（issued=now-60s, expires=now+3600s）+ **拒绝原因关键词断言**
（防止因无关原因被拒造成的空洞 PASS）。
"""
import json
import os
import sys
import tempfile
import time

REPO = "/private/tmp/wenqu-auth9-20261014-093158/system"
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import (  # noqa: E402
    ApprovalKeyring, generate_secret, sign_envelope)
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ApprovalRejected, RunManager)

IDENT = {
    "commit_sha": "5" * 40, "environment": "staging",
    "scope_hash": "scope-p4", "repo_id": "repo-p4",
    "ruleset_hash": "rules-p4", "policy_hash": "pol-p4",
}
RESULTS = []
TMP = tempfile.mkdtemp(prefix="auth9-p4v2-")
NOW = time.time()
ISSUED = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - 60))
EXPIRES = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW + 3600))

PW = {"operation_digest": "a" * 64, "data_scope_digest": "b" * 64,
      "idempotency_key": "idem-p4", "conservation_hash": "c" * 64}
TARGET = "db://staging/erp#p4"


def utc(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def case(name, ok, note=""):
    verdict = "PASS" if ok else "FAIL"
    RESULTS.append((verdict, name))
    print(f"  [{verdict}] {name} {note}")


def build_keyring(rot_second=False, same_actor=False, bare_second=False):
    meta = {
        "key_p4_one": {"status": "active", "owner": "alice",
                       "actors": ["alice", "alex"]},
        "key_p4_two": {"status": ("rotated" if rot_second else "active"),
                       "owner": "bob",
                       "actors": (["bob", "alice"] if same_actor
                                  else ["bob"]),
                       **({"rotated_at": "2026-10-13T00:00:00Z",
                           "rotated_to": "key_p4_one"} if rot_second
                          else {})},
    }
    if bare_second:
        meta["key_p4_two"] = {"status": "active"}
    return ApprovalKeyring(
        {"key_p4_one": generate_secret(), "key_p4_two": generate_secret()},
        metadata=meta)


def make_env(kr, run_id, v, task, actor="alice",
             cosign_actors=(("key_p4_one", "alice"),
                            ("key_p4_two", "bob")),
             swap_sigs=False, issued_at=ISSUED):
    body = {
        "schema_version": "2.0",
        "approval_id": f"apr_p4_{abs(hash(task)) % 10**8}",
        "approval_type": "prod_write", "key_id": "key_p4_one",
        "run_id": run_id, "task_id": task, "stop_event_id": "n/a-prod_write",
        "stop_type": "prod-write", "stage": "S1_REQUIREMENT",
        "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "expected_state_version": v, "actor": actor,
        "issued_at": issued_at, "expires_at": EXPIRES,
        "nonce": "n" * 24 + task[-4:], "decision": "approve",
        "payload": dict(PW, idempotency_key=f"idem-{task}"),
    }
    sigs = {kid: sign_envelope(kr.get(kid), body) for kid, _ in cosign_actors}
    entries = [{"key_id": kid, "actor": act, "signature": sigs[kid]}
               for kid, act in cosign_actors]
    if swap_sigs and len(entries) == 2:
        entries[0]["signature"] = sigs[entries[1]["key_id"]]
        entries[1]["signature"] = sigs[entries[0]["key_id"]]
    body["cosignatures"] = entries
    body["signature"] = sign_envelope(kr.get("key_p4_one"), body)
    return body


def consumed(store):
    n = 0
    for _s, _h, p in store._conn.execute(
            "SELECT seq, event_hash, payload FROM pipeline_events"):
        if json.loads(p).get("event_type") == "APPROVAL_CONSUMED":
            n += 1
    return n


def run_case(tag, kr, ap_builder, want_keyword=None):
    """want_keyword=None → 期望成功 RESERVED；否则期望被拒且消息含关键词。"""
    store = EventStore(os.path.join(TMP, f"ev-{tag}.db"))
    mgr = RunManager(store, keyring=kr)
    run_id = mgr.create_run(f"task_{tag}", IDENT)["run_id"]
    mgr.advance_stage(run_id)
    v = mgr.get_run(run_id).state_version
    ap = ap_builder(kr, run_id, v, f"task_{tag}")
    ev = dict(ap["payload"])
    ev["action_target"] = TARGET
    try:
        r = mgr.reserve_action(run_id, "prod-write", TARGET, ap,
                               action_descriptor=dict(ap["payload"]),
                               runtime_evidence=ev)
        if want_keyword is None:
            ok = r["action_state"] == "RESERVED" and consumed(store) == 1
            note = "RESERVED + 1 APPROVAL_CONSUMED"
        else:
            ok = False
            note = f"UNEXPECTED SUCCESS (want reject w/ {want_keyword!r})"
    except ApprovalRejected as exc:
        msg = str(exc)
        if want_keyword is None:
            ok, note = False, f"UNEXPECTED REJECT: {msg[:100]}"
        else:
            ok = (want_keyword in msg) and consumed(store) == 0
            note = f"rejected(0-consumed): {msg[:100]}"
    case(f"P4-{tag}", ok, f":: {note}")


run_case("pos1-标准双联签", build_keyring(),
         lambda kr, r, v, t: make_env(kr, r, v, t))
run_case("N1-跨行换签", build_keyring(),
         lambda kr, r, v, t: make_env(kr, r, v, t, swap_sigs=True),
         want_keyword="联签验签失败")
run_case("N2-同key双签", build_keyring(),
         lambda kr, r, v, t: make_env(
             kr, r, v, t,
             cosign_actors=(("key_p4_one", "alice"),
                            ("key_p4_one", "alex"))),
         want_keyword="同 key")
run_case("N3-同actor两key", build_keyring(same_actor=True),
         lambda kr, r, v, t: make_env(
             kr, r, v, t,
             cosign_actors=(("key_p4_one", "alice"),
                            ("key_p4_two", "alice"))),
         want_keyword="同 actor")


def three_cosign(kr, run_id, v, task):
    ap = make_env(kr, run_id, v, task)
    third = {"key_id": "key_p4_one", "actor": "alex",
             "signature": sign_envelope(kr.get("key_p4_one"), {
                 k: v2 for k, v2 in ap.items()
                 if k not in ("signature", "cosignatures")})}
    ap["cosignatures"].append(third)
    ap["signature"] = sign_envelope(kr.get("key_p4_one"), ap)
    return ap


run_case("N4-第二key无登记面", build_keyring(bare_second=True),
         lambda kr, r, v, t: make_env(kr, r, v, t),
         want_keyword="登记")
run_case("N5-退休key联签", build_keyring(rot_second=True),
         lambda kr, r, v, t: make_env(kr, r, v, t),
         want_keyword="生命周期")
run_case("N6-三条目重复key", build_keyring(), three_cosign,
         want_keyword="同 key")


def no_cosign(kr, run_id, v, task):
    ap = make_env(kr, run_id, v, task)
    ap.pop("cosignatures")
    ap["signature"] = sign_envelope(kr.get("key_p4_one"), ap)
    return ap


run_case("N7-无联签高危消费", build_keyring(), no_cosign,
         want_keyword="cosignatures")
run_case("N8-主签actor冒用", build_keyring(),
         lambda kr, r, v, t: make_env(kr, r, v, t, actor="mallory"),
         want_keyword="principal")

# N9 broker 直连路径
kr9 = build_keyring()
store9 = EventStore(os.path.join(TMP, "ev-N9.db"))
mgr9 = RunManager(store9, keyring=kr9)
run9 = mgr9.create_run("task_N9", IDENT)["run_id"]
mgr9.advance_stage(run9)
v9 = mgr9.get_run(run9).state_version
ap9 = no_cosign(kr9, run9, v9, "task_N9")
try:
    mgr9.broker.consume_authorization(
        ap9, run_loader=mgr9._fenced_loader(run9),
        expected_approval_type="prod_write")
    ok9, note9 = False, "UNEXPECTED SUCCESS"
except ApprovalRejected as exc:
    ok9 = "cosignatures" in str(exc) and consumed(store9) == 0
    note9 = f"rejected(0-consumed): {str(exc)[:90]}"
case("P4-N9-broker直连无联签", ok9, f":: {note9}")

# N10（新增）：联签 key 与主 key 相同但 actors 不同且各自登记——key_one 上
# alice/alex 联签（已在 N2 覆盖同 key 拒）；此处验证主 key==联签 key 时
# 主签名与联签签名可互换仍过不了同 key 门（key 集合基数 1）
run_case("N10-主key重复计入联签", build_keyring(),
         lambda kr, r, v, t: make_env(
             kr, r, v, t,
             cosign_actors=(("key_p4_one", "alice"),
                            ("key_p4_one", "alex"))),
         want_keyword="同 key")

fails = [r for r in RESULTS if r[0] == "FAIL"]
print(f"\nP4 SUMMARY: total={len(RESULTS)} pass={len(RESULTS)-len(fails)} "
      f"fail={len(fails)}")
sys.exit(1 if fails else 0)

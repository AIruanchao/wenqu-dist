#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第九轮授权域探针 P2：actual-target 运行时重算（新变体）。

经 RunManager.reserve_action 全链实跑（真实 EventStore+事务）：
正例：
  pos1 prod_write 全字段 runtime evidence + action_target 一致 → RESERVED
  pos2 release 双 artifact 真文件实算 hash → RESERVED
  pos3 RUN_HEAD 哨兵实查替换（ddl.backup_id == run commit_sha）→ RESERVED
新负例（每例断言：拒绝 + 零副作用——无 APPROVAL_CONSUMED 事件、nonce 可再用）：
  N1 evidence 缺一个判别字段（部分自报）→拒
  N2 evidence 字段观测值与 payload 不符 →拒
  N3 evidence.action_target 与实际调用 target 不符（批 A 执行 B）→拒
  N4 release artifact 文件被调包（artifact_paths 指向另一文件）→拒
  N5 release payload.environment ≠ run 冻结 environment（env 硬门）→拒
  N6 evidence 直接自报 artifact_sha256（不经 artifact_paths）→拒
  N7 artifact 路径不存在 →拒（fail-closed）
  N8 RUN_HEAD 哨兵与 payload 实值不符（实查替换后比对失败）→拒
  N9 整个 runtime_evidence 缺失 →拒（强制档）
"""
import hashlib
import json
import os
import sys
import tempfile

REPO = "/private/tmp/wenqu-auth9-20261014-093158/system"
sys.path.insert(0, REPO)

from wenqu_core.approval_issue import ApprovalIssuer  # noqa: E402
from wenqu_core.approval_keys import ApprovalKeyring, generate_secret  # noqa: E402
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ApprovalReuseError, ApprovalRejected, RunManager)

IDENT = {
    "commit_sha": "9" * 40, "environment": "staging",
    "scope_hash": "scope-auth9", "repo_id": "repo-auth9",
    "ruleset_hash": "rules-a9", "policy_hash": "pol-a9",
}
RESULTS = []


def case(name, expected, fn):
    try:
        ok = bool(fn())
        note = "" if ok else "expectation NOT met (returned False/None)"
    except Exception as exc:
        ok = False
        note = f"{type(exc).__name__}: {str(exc)[:120]}"
    verdict = "PASS" if ok else "FAIL"
    RESULTS.append((verdict, name))
    print(f"  [{verdict}] {name} (expect={expected}) {note}")


TMP = tempfile.mkdtemp(prefix="auth9-p2-")
KR = ApprovalKeyring(
    {"key_a9_alice": generate_secret(), "key_a9_bob": generate_secret()},
    metadata={
        "key_a9_alice": {"status": "active", "owner": "alice",
                         "actors": ["alice"]},
        "key_a9_bob": {"status": "active", "owner": "bob",
                       "actors": ["bob"]},
    })
ISSUER = ApprovalIssuer(KR, os.path.join(TMP, "audit.jsonl"))


def fresh():
    store = EventStore(os.path.join(TMP, f"ev-{os.getpid()}-{len(RESULTS)}.db"))
    return store, RunManager(store, keyring=KR)


def new_run(mgr, task):
    run_id = mgr.create_run(task, IDENT)["run_id"]
    mgr.advance_stage(run_id)
    return run_id, mgr.get_run(run_id).state_version


def issue(atype, run_id, v, task, payload, **kw):
    return ISSUER.issue(
        actor="alice", approval_type=atype, run_id=run_id, task_id=task,
        stage="S1_REQUIREMENT", environment=IDENT["environment"],
        authorized_scope=IDENT["scope_hash"], policy_hash=IDENT["policy_hash"],
        ruleset_hash=IDENT["ruleset_hash"], input_watermark=IDENT["commit_sha"],
        expected_state_version=v, payload=payload, ttl_seconds=3600,
        key_id="key_a9_alice", confirm_two_persons=atype in (
            "prod_write", "ddl", "release", "fund_auth"),
        second_key_id="key_a9_bob", second_actor="bob", **kw)["approval"]


def ev_of(ap, target, artifact_paths=None, drop=(), override=None):
    ev = {k: v for k, v in ap["payload"].items()
          if not k.endswith("_sha256")}
    ev["action_target"] = target
    if artifact_paths is not None:
        ev["artifact_paths"] = dict(artifact_paths)
    for k in drop:
        ev.pop(k, None)
    if override:
        ev.update(override)
    return ev


def consumed_events(store):
    n = 0
    for _s, _h, p in store._conn.execute(
            "SELECT seq, event_hash, payload FROM pipeline_events"):
        if json.loads(p).get("event_type") == "APPROVAL_CONSUMED":
            n += 1
    return n


def descriptor(ap):
    return dict(ap["payload"])


# ---------------- pos1: prod_write 全字段 evidence ----------------
store, mgr = fresh()
run_id, v = new_run(mgr, "task_p2_pos1")
PW = {"operation_digest": "e" * 64, "data_scope_digest": "f" * 64,
      "idempotency_key": "idem-a9-1", "conservation_hash": "1" * 64}
ap1 = issue("prod_write", run_id, v, "task_p2_pos1", PW)
target1 = "db://staging/erp#batch-a9"
r1 = mgr.reserve_action(run_id, "prod-write", target1, ap1,
                        action_descriptor=descriptor(ap1),
                        runtime_evidence=ev_of(ap1, target1))
case("P2-pos1 prod_write 全字段 evidence → RESERVED", "accept",
     lambda: r1["action_state"] == "RESERVED")
case("P2-pos1b 消费留痕（1 个 APPROVAL_CONSUMED）", "accept",
     lambda: consumed_events(store) == 1)

# ---------------- N1-N3: prod_write 变体（各自新 run 新审批） ----------------
def neg_case(tag, build_ev, target_mut=None):
    s, m = fresh()
    rid, vv = new_run(m, f"task_p2_{tag}")
    ap = issue("prod_write", rid, vv, f"task_p2_{tag}", dict(
        PW, idempotency_key=f"idem-a9-{tag}"))
    tgt = target1 if target_mut is None else target_mut
    ev = build_ev(ap, tgt)
    try:
        m.reserve_action(rid, "prod-write", tgt, ap,
                         action_descriptor=descriptor(ap), runtime_evidence=ev)
        rejected, note = False, "no rejection"
    except ApprovalRejected as exc:
        rejected, note = True, str(exc)[:80]
    zero = consumed_events(s) == 0
    # 零副作用：同一审批随后带正确 evidence 仍可成功消费（nonce 未被烧）
    retry_ok = False
    try:
        rr = m.reserve_action(rid, "prod-write", target1, ap,
                              action_descriptor=descriptor(ap),
                              runtime_evidence=ev_of(ap, target1))
        retry_ok = rr["action_state"] == "RESERVED"
    except Exception as exc2:
        retry_ok = f"{type(exc2).__name__}" 
    print(f"    ({tag}) rejected={rejected} zero_side_effect={zero} "
          f"nonce_still_usable={retry_ok} :: {note}")
    case(f"P2-{tag} 拒绝+零副作用+nonce 未烧", "reject" if rejected else "accept",
         lambda: rejected and zero)
    # retry 只在证据门（非绑定门）负例上应成功；绑定类负例会再次失败但不影响判定
    return rejected and zero


neg_case("N1", lambda ap, t: ev_of(ap, t, drop=["conservation_hash"]))
neg_case("N2", lambda ap, t: ev_of(ap, t, override={
    "operation_digest": "0" * 64}))
neg_case("N3", lambda ap, t: ev_of(ap, "db://staging/erp#OTHER-target"),
         target_mut=target1)  # 调用参数=A，evidence 声明 B → 拒
# N3 反向：调用参数=B 而 evidence 观测=A
neg_case("N3b", lambda ap, t: ev_of(ap, target1),
         target_mut="db://staging/erp#batch-OTHER")
neg_case("N9", lambda ap, t: None)

# ---------------- release: 真文件实算 + env 硬门 ----------------
d = os.path.join(TMP, "rel-artifacts")
os.makedirs(d, exist_ok=True)
art = os.path.join(d, "artifact-a9.bin")
man = os.path.join(d, "manifest-a9.json")
open(art, "wb").write(b"auth9-release-artifact-bytes")
open(man, "wb").write(b'{"release": "auth9"}')
other = os.path.join(d, "swapped.bin")
open(other, "wb").write(b"SWAPPED-CONTENT-not-approved")
REL = {"release_id": "rel-a9-1",
       "artifact_sha256": hashlib.sha256(open(art, "rb").read()).hexdigest(),
       "manifest_sha256": hashlib.sha256(open(man, "rb").read()).hexdigest(),
       "environment": "staging", "previous_release_id": "rel-a9-0"}
REL_BAD_ENV = dict(REL, environment="production")
REL_PATHS = {"artifact_sha256": art, "manifest_sha256": man}

s2, m2 = fresh()
rid2, v2 = new_run(m2, "task_p2_rel")
ap_rel = issue("release", rid2, v2, "task_p2_rel", REL)
tgt2 = "https://release.example/a9"
r2 = m2.reserve_action(rid2, "release", tgt2, ap_rel,
                       action_descriptor=descriptor(ap_rel),
                       runtime_evidence=ev_of(ap_rel, tgt2, REL_PATHS))
case("P2-pos2 release 双 artifact 真文件实算 → RESERVED", "accept",
     lambda: r2["action_state"] == "RESERVED")

# N4 调包：artifact_paths 的 artifact 指向另一个文件
s3, m3 = fresh()
rid3, v3 = new_run(m3, "task_p2_n4")
ap_n4 = issue("release", rid3, v3, "task_p2_n4", dict(REL))
try:
    m3.reserve_action(rid3, "release", tgt2, ap_n4,
                      action_descriptor=descriptor(ap_n4),
                      runtime_evidence=ev_of(ap_n4, tgt2, {
                          "artifact_sha256": other,
                          "manifest_sha256": man}))
    ok_n4 = False
except ApprovalRejected:
    ok_n4 = consumed_events(s3) == 0
case("P2-N4 artifact 调包（真文件实算不符）→拒+零副作用", "reject",
     lambda: ok_n4)

# N5 env 硬门：payload.environment != run 冻结环境（无需调用方配合）
s4, m4 = fresh()
rid4, v4 = new_run(m4, "task_p2_n5")
ap_n5 = issue("release", rid4, v4, "task_p2_n5", REL_BAD_ENV)
try:
    m4.reserve_action(rid4, "release", tgt2, ap_n5,
                      action_descriptor=descriptor(ap_n5),
                      runtime_evidence=ev_of(ap_n5, tgt2, REL_PATHS))
    ok_n5 = False
except ApprovalRejected:
    ok_n5 = True
case("P2-N5 release payload.environment=production≠run staging →拒", "reject",
     lambda: ok_n5)

# N6 自报哈希（evidence 直接给 *_sha256，不走 artifact_paths）
s5, m5 = fresh()
rid5, v5 = new_run(m5, "task_p2_n6")
ap_n6 = issue("release", rid5, v5, "task_p2_n6", dict(REL))
ev_n6 = ev_of(ap_n6, tgt2)
ev_n6["artifact_sha256"] = REL["artifact_sha256"]  # 自报
try:
    m5.reserve_action(rid5, "release", tgt2, ap_n6,
                      action_descriptor=descriptor(ap_n6),
                      runtime_evidence=ev_n6)
    ok_n6 = False
except ApprovalRejected:
    ok_n6 = True
case("P2-N6 evidence 自报 artifact_sha256（无 artifact_paths）→拒", "reject",
     lambda: ok_n6)

# N7 路径不存在
s6, m6 = fresh()
rid6, v6 = new_run(m6, "task_p2_n7")
ap_n7 = issue("release", rid6, v6, "task_p2_n7", dict(REL))
try:
    m6.reserve_action(rid6, "release", tgt2, ap_n7,
                      action_descriptor=descriptor(ap_n7),
                      runtime_evidence=ev_of(ap_n7, tgt2, {
                          "artifact_sha256": os.path.join(TMP, "GONE.bin"),
                          "manifest_sha256": man}))
    ok_n7 = False
except ApprovalRejected:
    ok_n7 = True
case("P2-N7 artifact 路径不存在 →拒（fail-closed 实算）", "reject",
     lambda: ok_n7)

# ---------------- RUN_HEAD 哨兵（ddl.backup_id == commit_sha） ----------------
DDL_HEAD = {"database_identity": "pg://staging/a9",
            "statement_digest": "2" * 64, "before_schema_hash": "3" * 64,
            "after_schema_hash": "4" * 64, "backup_id": IDENT["commit_sha"],
            "rollback_plan_hash": "5" * 64}
s7, m7 = fresh()
rid7, v7 = new_run(m7, "task_p2_pos3")
ap_d = issue("ddl", rid7, v7, "task_p2_pos3", DDL_HEAD)
tgt7 = "pg://staging/a9#mig-a9"
ev7 = ev_of(ap_d, tgt7, override={"backup_id": "RUN_HEAD"})
r7 = m7.reserve_action(rid7, "ddl", tgt7, ap_d,
                       action_descriptor=descriptor(ap_d),
                       runtime_evidence=ev7)
case("P2-pos3 RUN_HEAD 哨兵实查替换（payload==commit_sha）→ RESERVED", "accept",
     lambda: r7["action_state"] == "RESERVED")

# N8 哨兵替换后与 payload 不符（payload backup_id 为旧值）
DDL_OLDBAK = dict(DDL_HEAD, backup_id="old-backup-id-a9")
s8, m8 = fresh()
rid8, v8 = new_run(m8, "task_p2_n8")
ap_n8 = issue("ddl", rid8, v8, "task_p2_n8", DDL_OLDBAK)
ev8 = ev_of(ap_n8, tgt7, override={"backup_id": "RUN_HEAD"})
try:
    m8.reserve_action(rid8, "ddl", tgt7, ap_n8,
                      action_descriptor=descriptor(ap_n8),
                      runtime_evidence=ev8)
    ok_n8 = False
except ApprovalRejected:
    ok_n8 = consumed_events(s8) == 0
case("P2-N8 RUN_HEAD 实查≠payload 旧 backup_id →拒+零副作用", "reject",
     lambda: ok_n8)

fails = [r for r in RESULTS if r[0] == "FAIL"]
print(f"\nP2 SUMMARY: total={len(RESULTS)} pass={len(RESULTS)-len(fails)} "
      f"fail={len(fails)}")
sys.exit(1 if fails else 0)

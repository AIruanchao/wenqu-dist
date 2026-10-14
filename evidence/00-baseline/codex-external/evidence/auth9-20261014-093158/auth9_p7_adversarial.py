#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第九轮授权域探针 P7（对抗补充）：receipt 跨内容复用攻击面。

假设：IssueReceipt 只绑定 (key_id, approval_id, nonce_digest, issued_at)，
不绑定信封内容摘要。持退休 key 旧 secret 的攻击者（无 keyring 目录写权限）
可对「退休前合法签发且未消费」的信封做内容变异（payload/expires_at/
run 绑定字段全可改），保留四个 receipt 绑定字段并重签——若消费链放行，
则 R8-AUTH-RETIRED-KEY-005 的「退休后签的批不能消费/无法伪造链上锚点」
闭合声明被部分击穿。

攻击链（merge 低危单签，规避联签门）：
  1. 受管 keyring 签发 merge 审批（receipt 落链）；
  2. 轮换该 key（retired_receipt_seq 盘点）；
  3. 「攻击者」取原信封：改 payload.merge_method/head_sha + 改 expires_at
     延寿 + 保留 approval_id/nonce/issued_at/issue_receipt + 旧 secret 重签；
  4. 经 reserve_action 消费——观察是否放行。
对照：全新伪造信封（无 receipt）→ 拒（既有闭合面，作对照）。
"""
import json
import os
import sys
import tempfile
import time

REPO = "/private/tmp/wenqu-auth9-20261014-093158/system"
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import (  # noqa: E402
    ApprovalKeyring, generate_secret, save_key_meta, sign_envelope,
    write_key_to_dir)
from wenqu_core.approval_issue import ApprovalIssuer  # noqa: E402
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ApprovalRejected, RunManager)

IDENT = {
    "commit_sha": "3" * 40, "environment": "staging",
    "scope_hash": "scope-p7", "repo_id": "repo-p7",
    "ruleset_hash": "rules-p7", "policy_hash": "pol-p7",
}
TMP = tempfile.mkdtemp(prefix="auth9-p7-")
kdir = os.path.join(TMP, "keyring")
write_key_to_dir(kdir, "key_p7_m", generate_secret(),
                 {"status": "active", "owner": "mallory-pre",
                  "actors": ["mallory-pre"]})
kr = ApprovalKeyring.from_path(kdir)
secret = kr.get("key_p7_m")
issuer = ApprovalIssuer(kr, os.path.join(TMP, "audit.jsonl"))

store = EventStore(os.path.join(TMP, "ev.db"))
mgr = RunManager(store, keyring=kr)
run_id = mgr.create_run("task_p7", IDENT)["run_id"]
mgr.advance_stage(run_id)
v = mgr.get_run(run_id).state_version

LEGIT = {"repo_id": "repo-p7", "base_sha": "1" * 40, "head_sha": "2" * 40,
         "merge_method": "squash"}
ap = issuer.issue(
    actor="mallory-pre", approval_type="merge", run_id=run_id,
    task_id="task_p7", stop_type="scope", stage="S1_REQUIREMENT",
    environment=IDENT["environment"], authorized_scope=IDENT["scope_hash"],
    policy_hash=IDENT["policy_hash"], ruleset_hash=IDENT["ruleset_hash"],
    input_watermark=IDENT["commit_sha"], expected_state_version=v,
    payload=LEGIT, key_id="key_p7_m", ttl_seconds=600,
    issued_at="2026-10-14T00:30:00Z")["approval"]
print(f"# 合法签发：approval_id={ap['approval_id']} "
      f"receipt={ap.get('issue_receipt')}")

# 轮换（retired 盘点）
save_key_meta(kdir, "key_p7_m", {
    "status": "rotated", "rotated_at": "2026-10-14T01:00:00Z",
    "rotated_to": "key_p7_m2", "owner": "mallory-pre",
    "actors": ["mallory-pre"]})
write_key_to_dir(kdir, "key_p7_m2", generate_secret(),
                 {"status": "active", "owner": "next", "actors": ["next"]})
kr_rot = ApprovalKeyring.from_path(kdir)

# ---- 攻击：变异信封（保留 receipt 四绑定字段）----
forged = json.loads(json.dumps(ap))
forged["payload"]["merge_method"] = "merge"          # 内容变异
forged["payload"]["head_sha"] = "e" * 40             # 目标变异
forged["expires_at"] = time.strftime(
    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400))  # 延寿 1 天
forged.pop("signature", None)
forged["signature"] = sign_envelope(secret, forged)  # 旧 secret 重签

# 单步门检查（解剖）
print("# lifecycle:", kr_rot.key_lifecycle_rejection(
    "key_p7_m", forged["issued_at"]))
print("# receipt  :", kr_rot.issue_receipt_rejection(forged))
print("# verify   :", kr_rot.verify(forged))

# 全链消费
ev = dict(forged["payload"])
ev["action_target"] = "https://vcs.example/repo-p7/pr/9"
try:
    r = mgr_rot = RunManager(store, keyring=kr_rot).reserve_action(
        run_id, "merge", ev["action_target"], forged,
        action_descriptor=dict(forged["payload"]), runtime_evidence=ev)
    print(f"# P7 攻击结果：消费成功 action_id={r['action_id']} —— 闭合被击穿")
    ATTACK_PASSED = True
except ApprovalRejected as exc:
    print(f"# P7 攻击结果：拒绝 —— {str(exc)[:160]}")
    ATTACK_PASSED = False

# 对照 1：全新伪造（无 receipt）→ 应拒
fresh = json.loads(json.dumps(ap))
fresh["approval_id"] = "apr_p7_fresh_0001"
fresh["nonce"] = "p7-fresh-nonce-000000001"
fresh.pop("issue_receipt", None)
fresh.pop("signature", None)
fresh["signature"] = sign_envelope(secret, fresh)
try:
    RunManager(store, keyring=kr_rot).reserve_action(
        run_id, "merge", ev["action_target"], fresh,
        action_descriptor=dict(fresh["payload"]), runtime_evidence=dict(
            fresh["payload"], action_target=ev["action_target"]))
    print("# 对照1（无 receipt 全新伪造）：放行 —— 异常")
except ApprovalRejected as exc:
    print(f"# 对照1（无 receipt 全新伪造）：拒 —— {str(exc)[:80]}")

# 对照 2：原信封本身消费（nonce 已被变异件烧掉 → 复用拒，反证变异件真实消费）
try:
    r2 = RunManager(store, keyring=kr_rot).reserve_action(
        run_id, "merge", "https://vcs.example/repo-p7/pr/8", ap,
        action_descriptor=dict(ap["payload"]),
        runtime_evidence=dict(ap["payload"], action_target=(
            "https://vcs.example/repo-p7/pr/8")))
    print("# 对照2（原信封消费）：成功")
except ApprovalRejected as exc:
    print(f"# 对照2（原信封消费）：ApprovalRejected —— {str(exc)[:90]}")
except Exception as exc:
    print(f"# 对照2（原信封消费）：{type(exc).__name__} —— {str(exc)[:90]}"
          f"（nonce 已被变异件烧掉——反证变异件完成了真实消费）")

print(f"\nP7 VERDICT: receipt_reuse_attack_bypassed={ATTACK_PASSED}")
sys.exit(0)   # 探针本身总 rc0；判定看 VERDICT 行

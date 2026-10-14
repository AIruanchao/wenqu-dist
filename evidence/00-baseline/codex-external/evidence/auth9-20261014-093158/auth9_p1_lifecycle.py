#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第九轮授权域探针 P1：key 生命周期按 issued_at 执法（新变体）。

正例：轮换前签发、轮换后消费（闭区间存量放行）。
新负例（非仓内测试语料）：
  N1 时区伪装——issued_at 字典序早于 rotated_at 但 epoch 实际晚于（+/-偏移）
  N2 秒级小数时间戳晚于轮换点
  N3 created_at 之前 1 秒（时间穿越边界-1s）
  N4 expiry 后签发（受管目录 keyring，经 receipt 门之前的 lifecycle 门）
  N5 受管 keyring 账本被删（R9-COLDSTART fail-closed）
  N6 退休 key meta 缺 retired_receipt_seq（手改元数据）
边界正例：
  B1 issued_at == rotated_at（闭区间存量放行）
  B2 issued_at == created_at（边界放行）
  B3 时区换算等价存量（+09:00 表示、epoch 早于轮换点）→ 放行（epoch 执法）
"""
import json
import os
import shutil
import sys
import tempfile
import time

REPO = "/private/tmp/wenqu-auth9-20261014-093158/system"
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import (  # noqa: E402
    ApprovalKeyring, IssueReceiptLedger, generate_secret, save_key_meta,
    sign_envelope, write_key_to_dir,
)
from wenqu_core.approval_issue import ApprovalIssuer  # noqa: E402

RESULTS = []


def case(name, expected, fn):
    """expected: 'accept' | 'reject'——fn() 返回 True=放行。"""
    try:
        ok = bool(fn())
    except Exception as exc:  # 拒绝路径允许异常
        ok = False
        note = f"{type(exc).__name__}: {str(exc)[:140]}"
    else:
        note = "" if ok else "returned False"
    verdict = "PASS" if ok == (expected == "accept") else "FAIL"
    RESULTS.append((verdict, name, expected, note))
    print(f"  [{verdict}] {name} (expect={expected}) {note}")


def utc(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


BASE = time.mktime(time.strptime("2026-10-13T10:00:00Z", "%Y-%m-%dT%H:%M:%SZ"))
CREATED = utc(BASE)             # 10:00Z
ROTATED_AT = utc(BASE + 8 * 3600)   # 18:00Z
EXPIRY = utc(BASE + 12 * 3600)      # 22:00Z

tmp = tempfile.mkdtemp(prefix="auth9-p1-")
kdir = os.path.join(tmp, "keyring")

# 主 key（active，登记 actors）+ 待轮换 key R
write_key_to_dir(kdir, "key_a9_main", generate_secret(),
                 {"status": "active", "created_at": CREATED,
                  "owner": "alice", "actors": ["alice"]})
write_key_to_dir(kdir, "key_a9_rot", generate_secret(),
                 {"status": "active", "created_at": CREATED,
                  "owner": "rex", "actors": ["rex"]})

kr = ApprovalKeyring.from_path(kdir)
secret_rot = kr.get("key_a9_rot")

# ---------- 正例：轮换前经正门签发（receipt 落链） ----------
issuer = ApprovalIssuer(kr, os.path.join(tmp, "audit.jsonl"))
common = dict(
    actor="rex", approval_type="merge", run_id="run_a9_p1", task_id="task_a9",
    stop_type="scope", stage="S1_REQUIREMENT", environment="staging",
    authorized_scope="scope-a9", policy_hash="pol-a9", ruleset_hash="rule-a9",
    input_watermark="b" * 40, expected_state_version=1,
    payload={"repo_id": "repo-a9", "base_sha": "c" * 40,
             "head_sha": "d" * 40, "merge_method": "squash"},
)
issued_before = issuer.issue(key_id="key_a9_rot", issued_at=utc(BASE + 3600),
                             ttl_seconds=36000, **common)["approval"]

# 轮换（save_key_meta 自动盘点 retired_receipt_seq）
save_key_meta(kdir, "key_a9_rot", {
    "status": "rotated", "rotated_at": ROTATED_AT, "rotated_to": "key_a9_main",
    "created_at": CREATED, "owner": "rex", "actors": ["rex"]})
kr2 = ApprovalKeyring.from_path(kdir)
meta_after = kr2.meta("key_a9_rot")
print(f"# retired_receipt_seq after rotation: "
      f"{meta_after.get('retired_receipt_seq')}")

# P-正例：轮换前签发、轮换后消费——验签通过（闭区间存量）
case("P1-pos1 轮换前签发存量验签放行", "accept",
     lambda: kr2.verify(issued_before))
case("P1-pos2 受管 keyring 上带 receipt 的存量通过 receipt 门", "accept",
     lambda: kr2.issue_receipt_rejection(issued_before) is None)

# ---------- N1 时区伪装（字典序早、epoch 晚） ----------
# issued_at 字符串 "2026-10-13T11:00:00-08:00" 字典序 < rotated_at
# "2026-10-13T18:00:00Z"，但 epoch = 10-14T19:00Z >> 轮换点 → 必拒
tz_spoof = dict(issued_before)
tz_spoof["issued_at"] = "2026-10-13T11:00:00-08:00"
tz_spoof.pop("signature", None)
tz_spoof.pop("issue_receipt", None)
tz_spoof["signature"] = sign_envelope(secret_rot, tz_spoof)
case("P1-N1a 时区伪装：字典序早但 epoch 晚于轮换（裸 keyring）→拒", "reject",
     lambda: kr2.verify(tz_spoof))
case("P1-N1b 时区伪装走 broker 消费路径（lifecycle 先于 receipt）→拒", "reject",
     lambda: kr2.issue_receipt_rejection(tz_spoof) is None
     and kr2.key_lifecycle_rejection("key_a9_rot", tz_spoof["issued_at"])
     is None)

# ---------- N2 秒级小数时间戳晚于轮换点 ----------
frac = dict(tz_spoof)
frac["issued_at"] = "2026-10-13T18:00:00.500Z"
frac["signature"] = sign_envelope(secret_rot, frac)
case("P1-N2 小数秒晚于轮换点 →拒（epoch 解析不受小数干扰）", "reject",
     lambda: kr2.verify(frac))

# ---------- B1/B2/B3 边界正例 ----------
b1 = dict(tz_spoof); b1["issued_at"] = ROTATED_AT
b1["signature"] = sign_envelope(secret_rot, b1)
case("P1-B1 issued_at==rotated_at 闭区间存量 →放行", "accept",
     lambda: kr2.verify(b1))
b2 = dict(tz_spoof); b2["issued_at"] = CREATED
b2["signature"] = sign_envelope(secret_rot, b2)
case("P1-B2 issued_at==created_at 边界 →放行", "accept",
     lambda: kr2.verify(b2))
b3 = dict(tz_spoof); b3["issued_at"] = "2026-10-13T12:00:00+09:00"  # 03:00Z
b3["signature"] = sign_envelope(secret_rot, b3)
case("P1-B3 +09:00 表示的轮换前存量（epoch 早于轮换）→放行", "accept",
     lambda: kr2.verify(b3))

# ---------- N3 时间穿越（created_at - 1s） ----------
tv = dict(tz_spoof); tv["issued_at"] = utc(BASE - 1)
tv["signature"] = sign_envelope(secret_rot, tv)
case("P1-N3 created_at 前 1 秒时间穿越 →拒", "reject",
     lambda: kr2.verify(tv))

# ---------- N4 expiry 后签发（active key + expiry） ----------
write_key_to_dir(kdir, "key_a9_exp", generate_secret(),
                 {"status": "active", "created_at": CREATED,
                  "expiry": EXPIRY, "owner": "eve", "actors": ["eve"]})
kr3 = ApprovalKeyring.from_path(kdir)
exp_ap = {"key_id": "key_a9_exp", "approval_id": "apr_a9_exp",
          "issued_at": utc(BASE + 12 * 3600 + 60)}
exp_ap["signature"] = sign_envelope(kr3.get("key_a9_exp"), exp_ap)
case("P1-N4 expiry 后签发（HMAC 真）→拒", "reject", lambda: kr3.verify(exp_ap))
exp_ok = dict(exp_ap); exp_ok["issued_at"] = utc(BASE + 3600)
exp_ok["signature"] = sign_envelope(kr3.get("key_a9_exp"), exp_ok)
case("P1-N4b expiry 前签发 →放行", "accept", lambda: kr3.verify(exp_ok))

# ---------- N5 受管账本被删（R9-COLDSTART fail-closed） ----------
shutil.copytree(kdir, os.path.join(tmp, "keyring-nodelger"))
kdir5 = os.path.join(tmp, "keyring-nodelger")
os.remove(os.path.join(kdir5, "issue-receipts.jsonl"))
kr5 = ApprovalKeyring.from_path(kdir5)
case("P1-N5 删除 issue-receipts.jsonl 后存量消费 →拒（fail-closed）", "reject",
     lambda: kr5.issue_receipt_rejection(issued_before) is None)

# ---------- N6 退休 key meta 缺 retired_receipt_seq（手改元数据） ----------
kdir6 = os.path.join(tmp, "keyring-tampered")
shutil.copytree(kdir, kdir6)
meta6 = json.load(open(os.path.join(kdir6, "key_a9_rot.meta.json")))
del meta6["retired_receipt_seq"]
json.dump(meta6, open(os.path.join(kdir6, "key_a9_rot.meta.json"), "w"))
kr6 = ApprovalKeyring.from_path(kdir6)
case("P1-N6 退休 key 抹掉 retired_receipt_seq →拒", "reject",
     lambda: kr6.issue_receipt_rejection(issued_before) is None)

# ---------- 附加：退休后手签（无 receipt）在 broker 语义下必拒 ----------
late = dict(tz_spoof); late["issued_at"] = utc(BASE + 9 * 3600)
late["signature"] = sign_envelope(secret_rot, late)
case("P1-N7 退休后手签无 receipt（裸 secret 回填）→拒", "reject",
     lambda: kr2.verify(late))

fails = [r for r in RESULTS if r[0] == "FAIL"]
print(f"\nP1 SUMMARY: total={len(RESULTS)} pass={len(RESULTS)-len(fails)} "
      f"fail={len(fails)}")
sys.exit(1 if fails else 0)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R7 第七轮两洞（Gate 面 P0）对抗复验正本——manifest 可信根 + 等价键全语义身份。

洞 -> 测试映射（正源：Codex 第七轮验收 findings；本文件是它们的对抗复验正本）：
  R7-GATE-MANIFEST-AUTH-001（P0）  manifest 无可信根——纯 manifest_hash 任何人
    都能重算：改顶层 required=[0,1]→[0]、删 TTL、自行重算 hash、保留冲突的
    planner.required=[0,1]，只交站0 曾得 rc0/PASS
    -> test_r7auth001_signed_manifest_front_door_pass      （对照：合法签名 PASS）
    -> test_r7auth001_required_tamper_rehash                （变体1：改 required 重算 hash）
    -> test_r7auth001_ttl_deleted_rehash                    （变体2：删 TTL 重算 hash）
    -> test_r7auth001_internal_inconsistency_valid_signature（变体3：内部不一致·合法签名）
    -> test_r7auth001_unsigned_refusals_and_downgrade       （无签名默认拒/降级口径）
    -> test_r7auth001_unknown_and_revoked_key_rejected      （未知 key/吊销 key）
    -> test_r7auth001_load_level_signature_semantics        （RunManifest.load API 面）
    -> test_r7auth001_freeze_key_resolution_fail_closed     （签发 key 解析 fail-closed）
  R7-GATE-DUP-EQUIV-002（P0）  等价键不全——同站重复件的 ruleset_hash/
    data_config_hash/tool name+digest/execution argv_digest/finding_ids 任一
    漂移曾仍 duplicates_ignored PASS
    -> test_r7dup002_field_drift_variants_all_blocked        （逐字段漂移注入 ≥6 变体）
    -> test_r7dup002_true_idempotent_resend_ignored_pass     （真幂等重发仍 ignored+PASS）

纯标准库；`python3 system/tests/test_gate_manifest_trust.py`（exit 0=全绿），兼容 pytest。
"""

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import (  # noqa: E402
    ApprovalKeyring, save_key_meta, sign_envelope, write_key_to_dir,
)
from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    BugscanPlanner, ManifestFreezeError, RunManifest,
    default_registry, validate_manifest_consistency,
)
from wenqu_core.gate_aggregator import BLOCKED, GateAggregator  # noqa: E402

CLI = os.path.join(REPO, "wenqu_core", "cli.py")
SHA = "7a" + "0" * 38
PASS_N, FAIL_N, FAILURES = 0, 0, []


def _ck(name, cond, detail=""):
    global PASS_N, FAIL_N
    if cond:
        PASS_N += 1
        print(f"  ✓ {name}")
    else:
        FAIL_N += 1
        FAILURES.append(name)
        print(f"  ✗ {name} {detail}")


def _tail(text, n=220):
    return (text or "").replace("\n", " | ")[-n:]


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _attacker_rehash(doc):
    """第七轮攻击者手法：无密钥自行重算 manifest_hash（纯 hash 无信任根）。"""
    body = {k: v for k, v in doc.items() if k != "manifest_hash"}
    doc["manifest_hash"] = hashlib.sha256(
        _canonical(body).encode("utf-8")).hexdigest()
    return doc


def _freeze_signed(keyring, key_id="key_r7_manifest", run_id="run-r7-auth"):
    planner = BugscanPlanner(default_registry())
    plan = planner.plan("FAST")  # required={0,1}
    return planner.freeze_run_manifest(
        plan, run_id=run_id, project_id="r7/erp",
        commit_sha=SHA, environment="staging",
        scope=["src/**", "tests/**", "tools/**"],
        ruleset={"version": "w6a-r7"}, data_config={"profile": "default"},
        signing_keyring=keyring, signing_key_id=key_id)


def _freeze_unsigned(run_id="run-r7-unsigned"):
    planner = BugscanPlanner(default_registry())
    plan = planner.plan("FAST")
    return planner.freeze_run_manifest(
        plan, run_id=run_id, project_id="r7/erp",
        commit_sha=SHA, environment="staging",
        scope=["src/**", "tests/**", "tools/**"],
        ruleset={"version": "w6a-r7"}, data_config={"profile": "default"})


def _bound(manifest, station, **over):
    """与 manifest 完全对账的合法 station-result-v2（含全语义身份字段）。"""
    doc = {
        "schema_version": "2.0", "run_id": manifest.run_id,
        "station_id": station, "attempt_id": f"att-r7-{station}",
        "execution_status": "COMPLETED", "policy_verdict": "PASS",
        "identity": {"project_id": "r7/erp", "commit_sha": manifest.commit_sha,
                     "environment": manifest.environment,
                     "scope_hash": manifest.scope_hash,
                     "ruleset_hash": manifest.ruleset_hash,
                     "data_config_hash": manifest.data_config_hash},
        "tool": {"name": "r7-fixture", "version": "1.0",
                 "digest": "d" * 64},
        "execution": {"argv_digest": "b" * 64,
                      "started_at": "2026-10-08T00:00:00Z",
                      "ended_at": "2026-10-08T00:00:01Z",
                      "actual_exit_code": 0, "expected_exit_set": [0],
                      "assertion_verdict": "PASS"},
        "coverage": {"denominator": manifest.denominator,
                     "scanned": manifest.denominator},
        "finding_ids": [],
        "artifacts": [{"cas_digest": "sha256:" + "c" * 64, "size": 128}],
    }
    doc.update(over)
    return doc


def _write(doc, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False)
    return path


def _gate(argv, timeout=120):
    r = subprocess.run([sys.executable, CLI, "gate"] + argv,
                       capture_output=True, text=True, timeout=timeout)
    try:
        payload = json.loads(r.stdout)
    except (json.JSONDecodeError, TypeError):
        payload = {}
    return r.returncode, payload


# ══════════════════════════════════════════════════════════════════════
# R7-GATE-MANIFEST-AUTH-001：manifest 无可信根（P0）
# ══════════════════════════════════════════════════════════════════════
def test_r7auth001_signed_manifest_front_door_pass():
    """对照：合法签名 manifest + 正确 keyring → 全对账 rc=0 PASS。"""
    with tempfile.TemporaryDirectory(prefix="wq_r7a_") as td:
        keyring = ApprovalKeyring.generate("key_r7_manifest")
        manifest = _freeze_signed(keyring)
        mpath = os.path.join(td, "run-manifest.json")
        manifest.save(mpath)
        kpath = os.path.join(td, "keys.json")
        keyring.save_json(kpath)
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1), os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath,
                         "--verify-key", kpath])
        _ck("R7-AUTH-001 合法签名 manifest 正门 rc=0 PASS",
            rc == 0 and out.get("policy_verdict") == "PASS",
            f"rc={rc} {_tail(out.get('reason'))}")
        sig = out.get("manifest", {}).get("signature", {})
        _ck("R7-AUTH-001 输出落签名证据（signed/verified/key_id）",
            sig.get("signed") is True and sig.get("verified") is True
            and sig.get("key_id") == "key_r7_manifest"
            and sig.get("allow_unsigned_downgrade") is False,
            _tail(json.dumps(sig)))
        _ck("R7-AUTH-001 合法签名件一致性违例=0",
            out.get("manifest", {}).get("consistency_violations") == 0)


def test_r7auth001_required_tamper_rehash():
    """变体1（第七轮本体）：改顶层 required=[0,1]→[0] + 无密钥重算 hash
    （保留旧签名/planner.required=[0,1]），只交站0。
    正门（--verify-key）→ 签名洗不白 → ERROR(3)；
    无 keyring 的 --allow-unsigned 诊断腿 → hash 过但一致性校验 → BLOCKED(2)。
    """
    with tempfile.TemporaryDirectory(prefix="wq_r7b_") as td:
        keyring = ApprovalKeyring.generate("key_r7_manifest")
        manifest = _freeze_signed(keyring)
        mpath = os.path.join(td, "run-manifest.json")
        manifest.save(mpath)
        kpath = os.path.join(td, "keys.json")
        keyring.save_json(kpath)
        doc = json.load(open(mpath, encoding="utf-8"))
        doc["required_stations"] = [0]          # 顶层缩水
        doc["station_ttls"] = {"0": doc["station_ttls"]["0"]}  # TTL 同步缩水
        _attacker_rehash(doc)                    # 无密钥重算 hash
        tpath = _write(doc, os.path.join(td, "tampered.json"))
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        # 腿一：正门验签——内容与签发时不符 → ERROR
        rc, out = _gate(["--results", s0, "--manifest", tpath,
                         "--verify-key", kpath])
        _ck("R7-AUTH-001 改 required 重算 hash（正门验签）rc=3 ERROR",
            rc == 3 and out.get("aggregate_outcome") == "ERROR",
            f"rc={rc} {_tail(out.get('reason'))}")
        _ck("R7-AUTH-001 ERROR 理由指向验签/manifest",
            "manifest" in (out.get("reason") or ""),
            _tail(out.get("reason")))
        # 腿二：无 keyring 的 --allow-unsigned 诊断降级 → 一致性 BLOCKED
        rc2, out2 = _gate(["--results", s0, "--manifest", tpath,
                           "--allow-unsigned"])
        reasons = "".join(out2.get("reasons", []))
        _ck("R7-AUTH-001 改 required（allow-unsigned 腿）rc=2 BLOCKED",
            rc2 == 2 and out2.get("aggregate_outcome") == BLOCKED,
            f"rc={rc2} {_tail(out2.get('reason'))}")
        _ck("R7-AUTH-001 记 required_stations_conflict（一致性独立于签名）",
            "required_stations_conflict" in reasons,
            _tail(reasons))
        _ck("R7-AUTH-001 绝不 PASS（第七轮 rc0/PASS 反例被封死）",
            out2.get("policy_verdict") != "PASS")


def test_r7auth001_ttl_deleted_rehash():
    """变体2：删 station_ttls + 无密钥重算 hash。
    正门 → ERROR；allow-unsigned 诊断腿 → station_ttls_conflict BLOCKED。
    """
    with tempfile.TemporaryDirectory(prefix="wq_r7c_") as td:
        keyring = ApprovalKeyring.generate("key_r7_manifest")
        manifest = _freeze_signed(keyring)
        mpath = os.path.join(td, "run-manifest.json")
        manifest.save(mpath)
        kpath = os.path.join(td, "keys.json")
        keyring.save_json(kpath)
        doc = json.load(open(mpath, encoding="utf-8"))
        doc.pop("station_ttls")                  # 删 TTL
        _attacker_rehash(doc)
        tpath = _write(doc, os.path.join(td, "no-ttl.json"))
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1), os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", s0, s1, "--manifest", tpath,
                         "--verify-key", kpath])
        _ck("R7-AUTH-001 删 TTL 重算 hash（正门验签）rc=3 ERROR",
            rc == 3 and out.get("aggregate_outcome") == "ERROR",
            f"rc={rc}")
        rc2, out2 = _gate(["--results", s0, s1, "--manifest", tpath,
                           "--allow-unsigned"])
        reasons = "".join(out2.get("reasons", []))
        _ck("R7-AUTH-001 删 TTL（allow-unsigned 腿）rc=2 BLOCKED + "
            "station_ttls 违例",
            rc2 == 2 and "station_ttls" in reasons,
            f"rc={rc2} {_tail(reasons)}")


def test_r7auth001_internal_inconsistency_valid_signature():
    """变体3：顶层 required=[0] 但 planner=[0,1]，**用真密钥重签**（模拟
    签发侧被污染/内部不一致仍持有合法签名）——验签通过但一致性校验
    独立拦截 → BLOCKED（证明一致性不依赖签名兜底）。
    """
    with tempfile.TemporaryDirectory(prefix="wq_r7d_") as td:
        key_id = "key_r7_manifest"
        keyring = ApprovalKeyring.generate(key_id)
        manifest = _freeze_signed(keyring)
        mpath = os.path.join(td, "run-manifest.json")
        manifest.save(mpath)
        kpath = os.path.join(td, "keys.json")
        keyring.save_json(kpath)
        doc = json.load(open(mpath, encoding="utf-8"))
        doc["required_stations"] = [0]           # 顶层缩水，planner 保持 [0,1]
        doc["station_ttls"] = {"0": doc["station_ttls"]["0"]}
        # 真密钥重签 + 重算 hash（内容对 key 而言完全合法）
        secret = keyring.get_for_signing(key_id)
        doc["key_id"] = key_id
        doc.pop("signature", None)
        body = {k: v for k, v in doc.items()
                if k not in ("manifest_hash", "signature")}
        doc["signature"] = sign_envelope(secret, body)
        doc = _attacker_rehash(doc)
        tpath = _write(doc, os.path.join(td, "resigned.json"))
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        rc, out = _gate(["--results", s0, "--manifest", tpath,
                         "--verify-key", kpath])
        reasons = "".join(out.get("reasons", []))
        _ck("R7-AUTH-001 内部不一致·合法签名 → rc=2 BLOCKED（非 ERROR）",
            rc == 2 and out.get("aggregate_outcome") == BLOCKED,
            f"rc={rc} {_tail(out.get('reason'))}")
        _ck("R7-AUTH-001 记 manifest_consistency_violation + required 冲突",
            "manifest_consistency_violation" in reasons
            and "required_stations_conflict" in reasons,
            _tail(reasons))
        _ck("R7-AUTH-001 签名本身验签通过（verified=True，拦截来自一致性）",
            out.get("manifest", {}).get("signature", {}).get("verified") is True)


def test_r7auth001_unsigned_refusals_and_downgrade():
    """无签名 manifest：正门默认拒（须 --verify-key）；--verify-key 无签名
    拒；--allow-unsigned 显式降级才放行且如实标注。"""
    with tempfile.TemporaryDirectory(prefix="wq_r7e_") as td:
        keyring = ApprovalKeyring.generate("key_r7_manifest")
        manifest = _freeze_unsigned()
        mpath = os.path.join(td, "run-manifest.json")
        manifest.save(mpath)
        kpath = os.path.join(td, "keys.json")
        keyring.save_json(kpath)
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1), os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath])
        _ck("R7-AUTH-001 无 --verify-key 的 --manifest rc=3 "
            "(mode=manifest_key_required)",
            rc == 3 and out.get("mode") == "manifest_key_required",
            f"rc={rc} mode={out.get('mode')}")
        rc2, out2 = _gate(["--results", s0, s1, "--manifest", mpath,
                           "--verify-key", kpath])
        _ck("R7-AUTH-001 无签名 manifest + --verify-key rc=3（默认拒）",
            rc2 == 3 and out2.get("mode") == "manifest_invalid"
            and "无签名" in (out2.get("reason") or ""),
            f"rc={rc2} {_tail(out2.get('reason'))}")
        rc3, out3 = _gate(["--results", s0, s1, "--manifest", mpath,
                           "--verify-key", kpath, "--allow-unsigned"])
        sig = out3.get("manifest", {}).get("signature", {})
        _ck("R7-AUTH-001 --allow-unsigned 显式降级放行且如实标注",
            rc3 == 0 and out3.get("policy_verdict") == "PASS"
            and sig.get("signed") is False
            and sig.get("allow_unsigned_downgrade") is True,
            f"rc={rc3} {_tail(json.dumps(sig))}")
        rc4, out4 = _gate(["--results", s0, "--allow-self-declared",
                           "--verify-key", kpath])
        _ck("R7-AUTH-001 --verify-key 无 --manifest → flag_conflict rc=3",
            rc4 == 3 and out4.get("mode") == "flag_conflict", f"rc={rc4}")


def test_r7auth001_unknown_and_revoked_key_rejected():
    """key 未知（换 keyring）→ ERROR；key 已吊销 → 验签即拒 ERROR。"""
    with tempfile.TemporaryDirectory(prefix="wq_r7f_") as td:
        keyring = ApprovalKeyring.generate("key_r7_manifest")
        manifest = _freeze_signed(keyring)
        mpath = os.path.join(td, "run-manifest.json")
        manifest.save(mpath)
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1), os.path.join(td, "s1.json"))
        other = ApprovalKeyring.generate("key_other")
        opath = os.path.join(td, "other-keys.json")
        other.save_json(opath)
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath,
                         "--verify-key", opath])
        _ck("R7-AUTH-001 未知 key（验签 keyring 不含签发 key）rc=3 ERROR",
            rc == 3 and out.get("aggregate_outcome") == "ERROR"
            and ("未在验签 keyring 登记" in (out.get("reason") or "")
                 or "key" in (out.get("reason") or "")),
            f"rc={rc} {_tail(out.get('reason'))}")
        # 目录型 keyring：签发 key 标 revoked → 验签即拒
        rdir = os.path.join(td, "rk")
        write_key_to_dir(rdir, "key_r7_manifest", "s" * 32,
                         {"status": "active"})
        save_key_meta(rdir, "key_r7_manifest",
                      {"status": "revoked",
                       "revoked_at": "2026-10-08T00:00:00Z"})
        rc2, out2 = _gate(["--results", s0, s1, "--manifest", mpath,
                           "--verify-key", rdir])
        _ck("R7-AUTH-001 已吊销 key 验签即拒 rc=3 ERROR",
            rc2 == 3 and out2.get("aggregate_outcome") == "ERROR",
            f"rc={rc2} {_tail(out2.get('reason'))}")


def test_r7auth001_load_level_signature_semantics():
    """RunManifest.load API 面：keyring 验签/未知 key/无签名拒/降级/legacy。"""
    with tempfile.TemporaryDirectory(prefix="wq_r7g_") as td:
        key_id = "key_r7_manifest"
        keyring = ApprovalKeyring.generate(key_id)
        manifest = _freeze_signed(keyring)
        path = os.path.join(td, "signed.json")
        manifest.save(path)
        loaded = RunManifest.load(path, keyring=keyring)
        _ck("R7-AUTH-001 load+keyring 验签通过且签名字段在",
            loaded.manifest_hash == manifest.manifest_hash
            and loaded.signature == manifest.signature
            and loaded.key_id == key_id)
        other = ApprovalKeyring.generate("key_other")
        try:
            RunManifest.load(path, keyring=other)
            _ck("R7-AUTH-001 load 未知 key 拒", False, "no raise")
        except ManifestFreezeError:
            _ck("R7-AUTH-001 load 未知 key 拒（ManifestFreezeError）", True)
        unsigned = _freeze_unsigned()
        upath = os.path.join(td, "unsigned.json")
        unsigned.save(upath)
        try:
            RunManifest.load(upath, keyring=keyring)
            _ck("R7-AUTH-001 load 无签名默认拒", False, "no raise")
        except ManifestFreezeError as exc:
            _ck("R7-AUTH-001 load 无签名默认拒（除非 allow_unsigned）",
                "无签名" in str(exc))
        legacy = RunManifest.load(upath)  # 无 keyring：legacy 口径可读
        _ck("R7-AUTH-001 load 无 keyring 保持 legacy 口径（hash 复核）",
            legacy.manifest_hash == unsigned.manifest_hash)
        downgraded = RunManifest.load(upath, keyring=keyring,
                                      allow_unsigned=True)
        _ck("R7-AUTH-001 load allow_unsigned 显式降级可读",
            downgraded.manifest_hash == unsigned.manifest_hash)
        # 篡改 + 重算 hash：无 keyring 时 hash 复核兜底仍然防篡改（老语义保持）
        doc = json.load(open(upath, encoding="utf-8"))
        doc["identity"]["commit_sha"] = "9" * 40
        _attacker_rehash(doc)
        tpath = _write(doc, os.path.join(td, "rehashed.json"))
        m2 = RunManifest.load(tpath)  # hash 被攻击者重算 → 复核过了……
        _ck("R7-AUTH-001 重算 hash 可骗过纯 hash 复核（复刻第七轮前提）",
            m2.commit_sha == "9" * 40,
            "前提不成立则洞描述失真")
        # ……但骗不过签名：对**已签名件**篡改+重算 hash 后，即使显式
        # allow-unsigned，坏签名（signature 与内容不符）也必须拒——
        # allow-unsigned 只容忍「无签名」，绝不容忍「坏签名」。
        sdoc = json.load(open(path, encoding="utf-8"))
        sdoc["identity"]["commit_sha"] = "9" * 40
        _attacker_rehash(sdoc)
        stpath = _write(sdoc, os.path.join(td, "signed-rehashed.json"))
        try:
            RunManifest.load(stpath, keyring=keyring, allow_unsigned=True)
            _ck("R7-AUTH-001 重算 hash 骗不过签名验签（allow-unsigned 也拒坏签名）",
                False, "no raise")
        except ManifestFreezeError:
            _ck("R7-AUTH-001 重算 hash 骗不过签名验签（allow-unsigned 也拒坏签名）",
                True)


def test_r7auth001_freeze_key_resolution_fail_closed():
    """freeze 签发面 fail-closed：多 active key 不猜/rotated/revoked 拒签。"""
    planner = BugscanPlanner(default_registry())
    plan = planner.plan("FAST")
    kwargs = dict(run_id="run-r7-fc", project_id="r7/erp", commit_sha=SHA,
                  environment="staging", scope=["src/**"],
                  ruleset={"v": 1}, data_config={"p": "d"})
    multi = ApprovalKeyring({"key_a": "a" * 32, "key_b": "b" * 32})
    try:
        planner.freeze_run_manifest(plan, signing_keyring=multi, **kwargs)
        _ck("R7-AUTH-001 多 active key 未显式 key_id 拒（不猜 key）", False,
            "no raise")
    except ManifestFreezeError as exc:
        _ck("R7-AUTH-001 多 active key 未显式 key_id 拒（不猜 key）",
            "signing_key_id" in str(exc))
    rotated = ApprovalKeyring(
        {"key_r": "r" * 32},
        metadata={"key_r": {"status": "rotated",
                            "rotated_at": "2026-10-01T00:00:00Z"}})
    try:
        planner.freeze_run_manifest(plan, signing_keyring=rotated,
                                    signing_key_id="key_r", **kwargs)
        _ck("R7-AUTH-001 rotated key 不得签发新 manifest", False, "no raise")
    except ManifestFreezeError:
        _ck("R7-AUTH-001 rotated key 不得签发新 manifest", True)
    try:
        planner.freeze_run_manifest(plan, signing_keyring=multi,
                                    signing_key_id="key_missing", **kwargs)
        _ck("R7-AUTH-001 未登记 key_id 拒", False, "no raise")
    except ManifestFreezeError:
        _ck("R7-AUTH-001 未登记 key_id 拒", True)
    # 唯一 active key：免显式 key_id 可签（合法人机工程）
    single = ApprovalKeyring.generate("key_only")
    m = planner.freeze_run_manifest(plan, signing_keyring=single, **kwargs)
    _ck("R7-AUTH-001 唯一 active key 免显式 key_id 可签且 key_id 落账",
        m.signature is not None and m.key_id == "key_only")


# ══════════════════════════════════════════════════════════════════════
# R7-GATE-DUP-EQUIV-002：等价键不全（P0）
# ══════════════════════════════════════════════════════════════════════
def _dup_base():
    """携带全语义身份字段的合法 v2 站结果（F6 旧键全等域之外再带
    ruleset/data_config/tool digest/argv_digest/finding_ids）。"""
    return {
        "schema_version": "2.0", "run_id": "r-r7-dup", "station_id": 2,
        "attempt_id": "att-dup-1", "execution_status": "COMPLETED",
        "policy_verdict": "PASS",
        "identity": {"commit_sha": SHA, "environment": "staging",
                     "scope_hash": "0" * 64,
                     "ruleset_hash": "1" * 64, "data_config_hash": "2" * 64},
        "tool": {"name": "t7", "version": "1", "digest": "3" * 64},
        "execution": {"argv_digest": "b" * 64,
                      "started_at": "2026-10-08T00:00:00Z",
                      "ended_at": "2026-10-08T00:00:01Z",
                      "actual_exit_code": 0, "expected_exit_set": [0],
                      "assertion_verdict": "PASS"},
        "coverage": {"denominator": 3, "scanned": 3},
        "finding_ids": ["fnd_a1", "fnd_b2"],
        "artifacts": [{"cas_digest": "sha256:" + "c" * 64, "size": 1}],
    }


def test_r7dup002_field_drift_variants_all_blocked():
    """逐字段漂移注入（第六轮旧键全等域之外的 6 个新维度）：任一漂移 →
    duplicate_conflict + BLOCKED（不再 duplicates_ignored PASS）。"""
    base = _dup_base()
    variants = {
        "identity.ruleset_hash 漂移":
            {"identity": {**base["identity"], "ruleset_hash": "9" * 64}},
        "identity.data_config_hash 漂移":
            {"identity": {**base["identity"], "data_config_hash": "8" * 64}},
        "tool.name 漂移":
            {"tool": {**base["tool"], "name": "t7-rogue"}},
        "tool.digest 漂移":
            {"tool": {**base["tool"], "digest": "7" * 64}},
        "execution.argv_digest 漂移（命令身份漂移）":
            {"execution": {**base["execution"], "argv_digest": "e" * 64}},
        "finding_ids 漂移（多报一个发现）":
            {"finding_ids": ["fnd_a1", "fnd_b2", "fnd_c3"]},
        "tool.version 漂移":
            {"tool": {**base["tool"], "version": "2"}},
    }
    _ck("R7-DUP-002 漂移变体数 ≥ 6（任务下限）", len(variants) >= 6,
        f"n={len(variants)}")
    for label, over in variants.items():
        agg = GateAggregator({"2"}, SHA, "staging")
        agg.add(copy.deepcopy(base))
        second = copy.deepcopy(base)
        second.update(copy.deepcopy(over))
        agg.add(second)
        out = agg.aggregate()
        reasons = "".join(out.get("reasons", []))
        _ck(f"R7-DUP-002 {label} → duplicate_conflict BLOCKED",
            out["counts"]["conflicts"] == 1
            and out["counts"]["duplicates_ignored"] == 0
            and out["aggregate_outcome"] == BLOCKED
            and "duplicate_conflict" in reasons,
            _tail(out.get("reason")))


def test_r7dup002_true_idempotent_resend_ignored_pass():
    """真幂等重发（全语义身份逐字段全等）→ duplicates_ignored + PASS；
    finding_ids 换序（排序摘要语义）仍算幂等。"""
    base = _dup_base()
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(copy.deepcopy(base)).add(copy.deepcopy(base))
    out = agg.aggregate()
    _ck("R7-DUP-002 全等重发幂等（ignored=1/conflicts=0/PASS）",
        out["counts"]["duplicates_ignored"] == 1
        and out["counts"]["conflicts"] == 0
        and out["aggregate_outcome"] == "PASS", _tail(out.get("reason")))
    reordered = copy.deepcopy(base)
    reordered["finding_ids"] = ["fnd_b2", "fnd_a1"]  # 仅顺序不同
    agg2 = GateAggregator({"2"}, SHA, "staging")
    agg2.add(copy.deepcopy(base)).add(reordered)
    out2 = agg2.aggregate()
    _ck("R7-DUP-002 finding_ids 换序仍幂等（排序摘要，不误报冲突）",
        out2["counts"]["duplicates_ignored"] == 1
        and out2["counts"]["conflicts"] == 0
        and out2["aggregate_outcome"] == "PASS", _tail(out2.get("reason")))
    # CLI 纵深：同一文件交两次 + 一致性完好的正门同形复验不再需要——
    # 直接以聚合 API 为对抗复验正本（CLI 只做一层包装）。
    _ck("R7-DUP-002 幂等重发不双绿（counts.required_reported 不虚增）",
        out["counts"]["required_reported"] == 1)


# ══════════════════════════════════════════════════════════════════════
# 自跑器
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_r7") and callable(v)]
    print(f"== R7 第七轮两洞对抗复验（{len(tests)} 组）==")
    for t in tests:
        print(f"-- {t.__name__}")
        try:
            t()
        except Exception as exc:  # 测试自身崩溃=失败（不静默）
            import traceback
            traceback.print_exc()
            FAIL_N += 1
            FAILURES.append(f"{t.__name__} (CRASH: {exc})")
    print("=" * 64)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        for f in FAILURES:
            print(f"  ✗ {f}")
        sys.exit(1)
    print("ALL GREEN")
    sys.exit(0)

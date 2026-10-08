#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F6 第六轮四洞加固回归——gate 范围自报 / 镜像格式等价 / PASS 分母等值边界 / 追踪 parser fail-open。

洞 -> 测试映射（正源：Codex 第六轮验收 findings；本文件是它们的对抗复验正本）：
  F6-GATE-SCOPE-001（P0）  wenquctl gate 的 required 站集合/coverage 分母由结果自报
    -> test_f6_scope001_manifest_front_door_full_pass          （正门对照：全对账 PASS）
    -> test_f6_scope001_missing_station_blocked                （缺站=分母缩水 BLOCKED）
    -> test_f6_scope001_self_declared_denominator_blocked      （自报分母 BLOCKED）
    -> test_f6_scope001_scope_hash_mismatch_blocked            （scope_hash 不符 BLOCKED）
    -> test_f6_scope001_bare_invocation_refused_and_diagnostic （裸调用默认拒绝/显式诊断）
    -> test_f6_scope001_tampered_manifest_and_flag_conflicts   （篡改 manifest/旗标互斥）
    -> test_f6_scope001_legacy_result_not_manifest_bound       （legacy 结果无法对账 BLOCKED）
  F6-GATE-FORMAT-DUP-002    镜像非 Draft-07 全量等价 + 重复站幂等等价键过松
    -> test_f6_format002_mirror_rfc3339_strict_datetime        （纯日期/无时区拒）
    -> test_f6_format002_duplicate_equivalence_key             （attempt/scope/coverage/artifact 全等才算幂等）
    -> test_f6_format002_cli_no_false_reject_schema_legal_nesting（CLI 私有校验误拒消除）
  F6-SCHEMA-BOUND-001       PASS 分母等值 schema 级联只到 64
    -> test_f6_schema001_mirror_unbounded_and_65_66_machine_red（65/66 任意缩水
       镜像机器红 + 1..64 级联内两侧一致性自测 + >64 声明边界）
  F6-TRC-PARSER-002         ac_traceability parser fail-open
    -> test_f6_trc002_missing_plan_check_exit2                 （--plan 缺失 --check 必 exit 2）
    -> test_f6_trc002_duplicate_and_poison_rows_detected       （重复相同行/先毒后正必红）
    -> test_f6_trc002_plan_sha256_computed_for_real            （PLAN_SHA256 实算 + 完整性 FAIL 联动）

纯标准库；`python3 system/tests/test_gate_scope_binding.py`（exit 0=全绿），兼容 pytest。
jsonschema 不可用时 schema 断言按仓内惯例降级跳过（镜像断言仍执行）。
"""
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
ROOT = os.path.dirname(REPO)                                        # 仓根
sys.path.insert(0, REPO)

from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    BugscanPlanner, RunManifest, default_registry,
)
from wenqu_core.gate_aggregator import (  # noqa: E402
    BLOCKED, GateAggregator, mirror_validate_station_result_v2,
)

CLI = os.path.join(REPO, "wenqu_core", "cli.py")
TRACE = os.path.join(ROOT, "tools", "ac_traceability.py")
SCHEMA_PATH = os.path.join(REPO, "schemas", "station-result-v2.schema.json")
PLAN = os.path.join(ROOT, "evidence", "00-baseline", "codex-external", "方案.md")
SHA = "1f" + "0" * 38
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


def _tail(text, n=200):
    return (text or "").replace("\n", " | ")[-n:]


# ───────────────────────── fixture：冻结 manifest + 绑定结果 ─────────────────────────
def _freeze(tmp):
    """冻结一个 FAST run（required={0,1}，scope 3 路径 → denominator=3）。"""
    planner = BugscanPlanner(default_registry())
    plan = planner.plan("FAST")
    manifest = planner.freeze_run_manifest(
        plan, run_id="run-f6-scope", project_id="f6/erp",
        commit_sha=SHA, environment="staging",
        scope=["src/**", "tests/**", "tools/**"],
        ruleset={"version": "w6a-f6"}, data_config={"profile": "default"})
    path = os.path.join(tmp, "run-manifest.json")
    manifest.save(path)
    return manifest, path


def _bound(manifest, station, **over):
    """与 manifest 完全对账的合法 station-result-v2（coverage 分母=冻结分母）。"""
    doc = {
        "schema_version": "2.0", "run_id": manifest.run_id,
        "station_id": station, "attempt_id": f"att-f6-{station}",
        "execution_status": "COMPLETED", "policy_verdict": "PASS",
        "identity": {"project_id": "f6/erp", "commit_sha": manifest.commit_sha,
                     "environment": manifest.environment,
                     "scope_hash": manifest.scope_hash},
        "tool": {"name": "f6-fixture", "version": "1.0"},
        "execution": {"argv_digest": "b" * 64,
                      "started_at": "2026-10-08T00:00:00Z",
                      "ended_at": "2026-10-08T00:00:01Z",
                      "actual_exit_code": 0, "expected_exit_set": [0],
                      "assertion_verdict": "PASS"},
        "coverage": {"denominator": manifest.denominator,
                     "scanned": manifest.denominator},
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


def _jsonschema_validator():
    import jsonschema
    schema = json.load(open(SCHEMA_PATH, encoding="utf-8"))
    return jsonschema.Draft7Validator(schema)


def _is_invalid(validator, doc):
    import jsonschema
    try:
        validator.validate(doc)
        return False
    except jsonschema.ValidationError:
        return True


# ══════════════════════════════════════════════════════════════════════
# F6-GATE-SCOPE-001：required/scope/coverage 自报（P0）
# ══════════════════════════════════════════════════════════════════════
def test_f6_scope001_manifest_front_door_full_pass():
    """正门对照：required/分母/身份全部对账冻结 manifest → PASS rc=0。"""
    with tempfile.TemporaryDirectory(prefix="wq_f6a_") as td:
        manifest, mpath = _freeze(td)
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1), os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath])
        _ck("F6-SCOPE-001 正门全对账 rc=0 PASS", rc == 0 and out.get("policy_verdict") == "PASS",
            f"rc={rc} {_tail(out.get('reason'))}")
        _ck("F6-SCOPE-001 mode=manifest + scope_binding 就位",
            out.get("mode") == "manifest"
            and out.get("scope_binding", {}).get("mode") == "manifest"
            and out.get("scope_binding", {}).get("expected_denominator") == manifest.denominator,
            _tail(json.dumps(out.get("scope_binding"))))
        _ck("F6-SCOPE-001 manifest 证据落输出（hash/run_id/required）",
            out.get("manifest", {}).get("manifest_hash") == manifest.manifest_hash
            and out.get("manifest", {}).get("required_stations") == [0, 1]
            and out.get("manifest", {}).get("denominator") == 3,
            _tail(json.dumps(out.get("manifest"))))


def test_f6_scope001_missing_station_blocked():
    """反例：manifest required={0,1} 但站 1 缺报 → BLOCKED rc=2。"""
    with tempfile.TemporaryDirectory(prefix="wq_f6b_") as td:
        manifest, mpath = _freeze(td)
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        rc, out = _gate(["--results", s0, "--manifest", mpath])
        reasons = "".join(out.get("reasons", []))
        _ck("F6-SCOPE-001 缺站 rc=2 BLOCKED + denominator_shrinkage",
            rc == 2 and out.get("aggregate_outcome") == BLOCKED
            and "denominator_shrinkage" in reasons,
            f"rc={rc} {_tail(reasons)}")


def test_f6_scope001_self_declared_denominator_blocked():
    """反例：站结果自报 coverage 分母（≠manifest 冻结分母）→ BLOCKED rc=2。"""
    with tempfile.TemporaryDirectory(prefix="wq_f6c_") as td:
        manifest, mpath = _freeze(td)
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        shrunk = _bound(manifest, 1)
        shrunk["coverage"] = {"denominator": 2, "scanned": 2}  # 自报缩水分母
        s1 = _write(shrunk, os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath])
        reasons = "".join(out.get("reasons", []))
        _ck("F6-SCOPE-001 自报分母 rc=2 BLOCKED + self_declared_denominator",
            rc == 2 and out.get("aggregate_outcome") == BLOCKED
            and "self_declared_denominator" in reasons,
            f"rc={rc} {_tail(reasons)}")
        # 腿二：FAIL 结果不带 coverage（schema 合法）——正门下同样记
        # missing_coverage_denominator（无法对账冻结分母即违规）
        no_cov = _bound(manifest, 0)
        no_cov["policy_verdict"] = "FAIL"
        no_cov["execution"] = dict(no_cov["execution"], assertion_verdict="FAIL")
        no_cov.pop("coverage")
        no_cov.pop("artifacts")
        agg = GateAggregator(
            {"0"}, manifest.commit_sha, manifest.environment,
            expected_scope_hash=manifest.scope_hash,
            expected_denominator=manifest.denominator)
        agg.add(no_cov)
        out2 = agg.aggregate()
        _ck("F6-SCOPE-001 缺 coverage（合法 FAIL 形态）→ missing_coverage_denominator",
            out2["aggregate_outcome"] == BLOCKED
            and "missing_coverage_denominator" in "".join(out2["reasons"]),
            _tail("".join(out2["reasons"])))


def test_f6_scope001_scope_hash_mismatch_blocked():
    """反例：站结果 identity.scope_hash 与冻结 manifest 不符 → BLOCKED rc=2。"""
    with tempfile.TemporaryDirectory(prefix="wq_f6d_") as td:
        manifest, mpath = _freeze(td)
        rogue = _bound(manifest, 0)
        rogue["identity"] = dict(rogue["identity"], scope_hash="9" * 64)
        s0 = _write(rogue, os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1), os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath])
        reasons = "".join(out.get("reasons", []))
        _ck("F6-SCOPE-001 scope_hash 不符 rc=2 BLOCKED + scope_hash_mismatch",
            rc == 2 and out.get("aggregate_outcome") == BLOCKED
            and "scope_hash_mismatch" in reasons,
            f"rc={rc} {_tail(reasons)}")
        # 腿二：commit_sha 与 manifest 不符（C2 既有面在正门下保持）
        rogue2 = _bound(manifest, 0)
        rogue2["identity"] = dict(rogue2["identity"], commit_sha="2" * 40)
        s0b = _write(rogue2, os.path.join(td, "s0b.json"))
        rc2, out2 = _gate(["--results", s0b, s1, "--manifest", mpath])
        _ck("F6-SCOPE-001 commit_sha 不符（正门）rc=2 BLOCKED",
            rc2 == 2 and out2.get("aggregate_outcome") == BLOCKED
            and "sha_evidence_violation" in "".join(out2.get("reasons", [])),
            f"rc={rc2}")


def test_f6_scope001_bare_invocation_refused_and_diagnostic():
    """反例复刻（P0 本体）：无 manifest 裸调用默认拒绝（rc=3）；
    显式 --allow-self-declared 才走诊断路径（自报口径，仅诊断）。"""
    with tempfile.TemporaryDirectory(prefix="wq_f6e_") as td:
        manifest, _mpath = _freeze(td)
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1), os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", s0, s1])
        _ck("F6-SCOPE-001 裸调用默认拒绝 rc=3",
            rc == 3 and out.get("mode") == "self_declared_refused",
            f"rc={rc} mode={out.get('mode')}")
        _ck("F6-SCOPE-001 拒绝理由指向 --manifest/--allow-self-declared",
            "--allow-self-declared" in (out.get("reason") or "")
            and "--manifest" in (out.get("reason") or ""),
            _tail(out.get("reason")))
        _ck("F6-SCOPE-001 拒绝输出非绿（ERROR 不冒充 PASS）",
            out.get("policy_verdict") == "ERROR"
            and out.get("technical_eligible") is False)
        rc2, out2 = _gate(["--results", s0, s1, "--allow-self-declared"])
        _ck("F6-SCOPE-001 显式诊断豁免 rc=0（自报 required={0,1} 全报）",
            rc2 == 0 and out2.get("mode") == "self_declared_diagnostic"
            and out2.get("policy_verdict") == "PASS",
            f"rc={rc2} {_tail(out2.get('reason'))}")
        _ck("F6-SCOPE-001 诊断模式 scope_binding 如实标注 self_declared",
            out2.get("scope_binding", {}).get("mode") == "self_declared")


def test_f6_scope001_tampered_manifest_and_flag_conflicts():
    """反例：篡改 manifest（manifest_hash 防篡改复核拒）/旗标互斥全 ERROR(3)。"""
    with tempfile.TemporaryDirectory(prefix="wq_f6f_") as td:
        manifest, mpath = _freeze(td)
        s0 = _write(_bound(manifest, 0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1), os.path.join(td, "s1.json"))
        tampered = json.load(open(mpath, encoding="utf-8"))
        tampered["scope"]["paths"].append("rogue/**")  # 缩水攻击：悄悄扩/改范围
        tpath = _write(tampered, os.path.join(td, "tampered.json"))
        rc, out = _gate(["--results", s0, s1, "--manifest", tpath])
        _ck("F6-SCOPE-001 篡改 manifest rc=3（hash 复核拒绝）",
            rc == 3 and "manifest" in (out.get("reason") or "").lower(),
            f"rc={rc} {_tail(out.get('reason'))}")
        rc2, out2 = _gate(["--results", s0, "--manifest", mpath,
                           "--allow-self-declared"])
        _ck("F6-SCOPE-001 --manifest 与 --allow-self-declared 互斥 rc=3",
            rc2 == 3 and out2.get("mode") == "flag_conflict", f"rc={rc2}")
        rc3, out3 = _gate(["--results", s0, "--manifest", mpath,
                           "--required", "0"])
        _ck("F6-SCOPE-001 --manifest 与自报 --required 互斥 rc=3",
            rc3 == 3 and out3.get("mode") == "flag_conflict", f"rc={rc3}")
        rc4, out4 = _gate(["--results", s0, s1, "--manifest", mpath,
                           "--sha", "2" * 40])
        _ck("F6-SCOPE-001 --sha 与冻结 SHA 冲突 rc=3（身份以 manifest 为正源）",
            rc4 == 3 and out4.get("mode") == "manifest_identity_conflict",
            f"rc={rc4}")


def test_f6_scope001_legacy_result_not_manifest_bound():
    """反例：正门下混入 legacy 结果（无法证明 scope 绑定）→ BLOCKED。"""
    with tempfile.TemporaryDirectory(prefix="wq_f6g_") as td:
        manifest, mpath = _freeze(td)
        legacy = _write({"station": "0", "outcome": "PASS", "sha": SHA,
                         "environment": "staging"},
                        os.path.join(td, "legacy0.json"))
        s1 = _write(_bound(manifest, 1), os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", legacy, s1, "--manifest", mpath])
        reasons = "".join(out.get("reasons", []))
        _ck("F6-SCOPE-001 legacy 结果正门下 BLOCKED",
            rc == 2 and "legacy_result_not_manifest_bound" in reasons,
            f"rc={rc} {_tail(reasons)}")


# ══════════════════════════════════════════════════════════════════════
# F6-GATE-FORMAT-DUP-002：镜像 RFC3339 + 重复站等价键 + CLI 误拒
# ══════════════════════════════════════════════════════════════════════
def test_f6_format002_mirror_rfc3339_strict_datetime():
    """镜像 RFC3339 严格 date-time：纯日期/无时区拒；偏移/毫秒形式收。"""
    def _doc(started_at):
        return {
            "schema_version": "2.0", "run_id": "r1", "station_id": 2,
            "attempt_id": "a1", "execution_status": "COMPLETED",
            "policy_verdict": "PASS",
            "identity": {"commit_sha": SHA, "environment": "staging",
                         "scope_hash": "0" * 64},
            "tool": {"name": "t", "version": "1"},
            "execution": {"argv_digest": "b" * 64, "started_at": started_at,
                          "ended_at": "2026-10-08T00:00:01Z",
                          "actual_exit_code": 0, "expected_exit_set": [0],
                          "assertion_verdict": "PASS"},
            "coverage": {"denominator": 3, "scanned": 3},
            "artifacts": [{"cas_digest": "sha256:" + "c" * 64, "size": 1}],
        }
    for bad in ("2026-10-08",                       # 纯日期
                "2026-10-08T00:00:00",              # 无时区
                "2026-10-08 00:00:00Z",             # 空格分隔（非 RFC3339 T 分隔）
                "not-a-date"):
        errs = mirror_validate_station_result_v2(_doc(bad))
        _ck(f"F6-FORMAT-002 镜像拒非 RFC3339 date-time {bad!r}",
            bool(errs) and any("date-time" in e for e in errs), str(errs[:2]))
    for good in ("2026-10-08T00:00:00Z", "2026-10-08T00:00:00+08:00",
                 "2026-10-08T00:00:00.123456Z"):
        _ck(f"F6-FORMAT-002 镜像收合法 RFC3339 {good!r}",
            not mirror_validate_station_result_v2(_doc(good)))
    # 聚合纵深：纯日期 → malformed → BLOCKED
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(_doc("2026-10-08"))
    out = agg.aggregate()
    _ck("F6-FORMAT-002 纯日期聚合 BLOCKED",
        out["aggregate_outcome"] == BLOCKED, out["reason"])


def test_f6_format002_duplicate_equivalence_key():
    """重复站等价键：attempt_id+scope_hash+coverage+artifact 摘要全等才算幂等重发。"""
    base = {
        "schema_version": "2.0", "run_id": "r1", "station_id": 2,
        "attempt_id": "att-1", "execution_status": "COMPLETED",
        "policy_verdict": "PASS",
        "identity": {"commit_sha": SHA, "environment": "staging",
                     "scope_hash": "0" * 64},
        "tool": {"name": "t", "version": "1"},
        "execution": {"argv_digest": "b" * 64, "started_at": "2026-10-08T00:00:00Z",
                      "ended_at": "2026-10-08T00:00:01Z", "actual_exit_code": 0,
                      "expected_exit_set": [0], "assertion_verdict": "PASS"},
        "coverage": {"denominator": 3, "scanned": 3},
        "artifacts": [{"cas_digest": "sha256:" + "c" * 64, "size": 1}],
    }

    # 幂等重发：逐字节同内容 → 只记 duplicate，仍 PASS
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(base).add(base)
    out = agg.aggregate()
    _ck("F6-FORMAT-002 同内容重发幂等（duplicate 不双绿不冲突）",
        out["counts"]["duplicates_ignored"] == 1
        and out["counts"]["conflicts"] == 0
        and out["aggregate_outcome"] == "PASS", out["reason"])

    # 等价键不等 1：attempt_id 不同（换批次重发）
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(base).add({**base, "attempt_id": "att-2"})
    out = agg.aggregate()
    _ck("F6-FORMAT-002 换 attempt_id 重发 → duplicate_conflict BLOCKED",
        out["counts"]["conflicts"] == 1 and out["aggregate_outcome"] == BLOCKED
        and "duplicate_conflict" in "".join(out["reasons"]), out["reason"])

    # 等价键不等 2：coverage 自报不同分母（3/3 vs 4/4，均 schema 合法 PASS）
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(base).add({**base, "coverage": {"denominator": 4, "scanned": 4}})
    out = agg.aggregate()
    _ck("F6-FORMAT-002 coverage 异分母重发 → duplicate_conflict BLOCKED",
        out["counts"]["conflicts"] == 1 and out["aggregate_outcome"] == BLOCKED)

    # 等价键不等 3：artifact 摘要不同（换工件重发）
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(base).add({**base, "artifacts": [
        {"cas_digest": "sha256:" + "d" * 64, "size": 1}]})
    out = agg.aggregate()
    _ck("F6-FORMAT-002 换 artifact 摘要重发 → duplicate_conflict BLOCKED",
        out["counts"]["conflicts"] == 1 and out["aggregate_outcome"] == BLOCKED)

    # 等价键不等 4：同 attempt 翻转裁决（PASS→FAIL，其余全等）——绝不静默择优
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(base).add({**base, "policy_verdict": "FAIL"})
    out = agg.aggregate()
    _ck("F6-FORMAT-002 同 attempt 翻转裁决 → duplicate_conflict BLOCKED",
        out["counts"]["conflicts"] == 1 and out["aggregate_outcome"] == BLOCKED)


def test_f6_format002_cli_no_false_reject_schema_legal_nesting():
    """CLI 私有校验误拒消除：schema 合法嵌套（execution/artifact 附加键、
    非 fnd_ 前缀 finding_ids）经 wenquctl gate 不再被强制 BLOCKED。"""
    doc = {
        "schema_version": "2.0", "run_id": "r-nest", "station_id": 2,
        "attempt_id": "att-nest", "execution_status": "COMPLETED",
        "policy_verdict": "PASS",
        "identity": {"commit_sha": SHA, "environment": "staging",
                     "scope_hash": "0" * 64},
        "tool": {"name": "t", "version": "1"},
        "execution": {"argv_digest": "b" * 64, "started_at": "2026-10-08T00:00:00Z",
                      "ended_at": "2026-10-08T00:00:01Z", "actual_exit_code": 0,
                      "expected_exit_set": [0], "assertion_verdict": "PASS",
                      "env_snapshot_digest": "e" * 64},   # schema 合法嵌套附加键
        "coverage": {"denominator": 3, "scanned": 3,
                     "window": "24h"},                     # 同上
        "finding_ids": ["GHSA-1111-2222-3333"],            # 非 fnd_ 前缀（schema 仅要求 string）
        "artifacts": [{"cas_digest": "sha256:" + "c" * 64, "size": 1,
                       "path": "out/report.json"}],        # artifact 项附加键
    }
    _ck("F6-FORMAT-002 镜像收 schema 合法嵌套",
        not mirror_validate_station_result_v2(doc),
        str(mirror_validate_station_result_v2(doc)[:3]))
    try:
        v = _jsonschema_validator()
        _ck("F6-FORMAT-002 正式 Draft-07 同收（复刻前提）",
            not _is_invalid(v, doc))
    except ImportError:
        print("  (skip) jsonschema 未安装，schema 断言降级")
    with tempfile.TemporaryDirectory(prefix="wq_f6h_") as td:
        path = _write(doc, os.path.join(td, "nested.json"))
        rc, out = _gate(["--results", path, "--allow-self-declared"])
        _ck("F6-FORMAT-002 CLI 不再误拒 schema 合法嵌套（rc=0 PASS）",
            rc == 0 and out.get("policy_verdict") == "PASS"
            and out.get("inputs", {}).get("schema_invalid") == 0,
            f"rc={rc} {_tail(out.get('reason'))}")


# ══════════════════════════════════════════════════════════════════════
# F6-SCHEMA-BOUND-001：PASS 分母等值只到 64（镜像无界等式分支 + 一致性自测）
# ══════════════════════════════════════════════════════════════════════
def test_f6_schema001_mirror_unbounded_and_65_66_machine_red():
    """F6 规格的镜像无界等式分支：schema const 级联维持 1..64（F4 既有边界，
    test_gate_schema_hardening 锁定），65/66 等任意缩水由镜像机器强制红；
    1..64 级联内做镜像↔schema 两侧一致性自测；>64 为声明边界（schema 不判）。
    """
    schema = json.load(open(SCHEMA_PATH, encoding="utf-8"))
    cascade = schema["allOf"][1]["then"]["properties"]["coverage"]["allOf"]
    consts = [e["if"]["properties"]["scanned"]["const"] for e in cascade]
    _ck("F6-SCHEMA-001 schema const 级联 1..64（F4 边界保持——>64 走镜像）",
        consts == list(range(1, 65)),
        f"n={len(consts)} head={consts[:2]} tail={consts[-2:]}")
    _ck("F6-SCHEMA-001 $comment 写明 65/66 机器红 + 镜像无界等式 + 本测试为复验正本",
        "65/66" in schema["$comment"] and "无界等式" in schema["$comment"]
        and "test_gate_scope_binding" in schema["$comment"])

    def _pass_doc(scanned, denominator):
        return {
            "schema_version": "2.0", "run_id": "r65", "station_id": 2,
            "attempt_id": "a65", "execution_status": "COMPLETED",
            "policy_verdict": "PASS",
            "identity": {"commit_sha": SHA, "environment": "staging",
                         "scope_hash": "0" * 64},
            "tool": {"name": "t", "version": "1"},
            "execution": {"argv_digest": "b" * 64,
                          "started_at": "2026-10-08T00:00:00Z",
                          "ended_at": "2026-10-08T00:00:01Z",
                          "actual_exit_code": 0, "expected_exit_set": [0],
                          "assertion_verdict": "PASS"},
            "coverage": {"denominator": denominator, "scanned": scanned},
            "artifacts": [{"cas_digest": "sha256:" + "c" * 64, "size": 1}],
        }
    # 任意缩水（含 >64 级联外）镜像必拒——65/66 是 Codex 第六轮原样反例
    red = [(65, 66), (66, 65), (255, 256), (256, 255), (300, 299)]
    green = [(65, 65), (256, 256), (300, 300)]
    for sc, dn in red:
        _ck(f"F6-SCHEMA-001 镜像拒 PASS {sc}/{dn}（无界等式机器红）",
            bool(mirror_validate_station_result_v2(_pass_doc(sc, dn))))
    for sc, dn in green:
        _ck(f"F6-SCHEMA-001 镜像收 PASS {sc}/{dn}（合法全扫）",
            not mirror_validate_station_result_v2(_pass_doc(sc, dn)))
    try:
        v = _jsonschema_validator()
        mismatch = []
        # 两侧一致性自测（级联内 1..64 全量）：等值两收 / 缩水两拒
        for n in range(1, 65):
            equal_doc = _pass_doc(n, n)
            shrink_doc = _pass_doc(n, n - 1) if n >= 2 else _pass_doc(1, 2)
            if bool(mirror_validate_station_result_v2(equal_doc)) \
                    or _is_invalid(v, equal_doc):
                mismatch.append(f"{n}/{n}: equal not both-accepted")
            if not mirror_validate_station_result_v2(shrink_doc) \
                    or not _is_invalid(v, shrink_doc):
                mismatch.append(
                    f"{shrink_doc['coverage']}: shrink not both-rejected")
        _ck("F6-SCHEMA-001 级联内 1..64 两侧一致性（等值两收/缩水两拒，全量）",
            not mismatch, "; ".join(mismatch[:4]))
        # 声明边界：>64 schema 不判（F4 契约），镜像兜底
        for sc, dn in ((65, 66), (255, 256), (300, 299)):
            _ck(f"F6-SCHEMA-001 schema 对 {sc}/{dn} 不判（声明边界，镜像兜底）",
                _is_invalid(v, _pass_doc(sc, dn)) is False)
        for sc, dn in ((3, 2), (64, 63)):
            _ck(f"F6-SCHEMA-001 schema 级联内拒 {sc}/{dn}",
                _is_invalid(v, _pass_doc(sc, dn)) is True)
        for sc, dn in ((65, 65), (300, 300), (64, 64)):
            _ck(f"F6-SCHEMA-001 schema 收 PASS {sc}/{dn}",
                not _is_invalid(v, _pass_doc(sc, dn)))
    except ImportError:
        print("  (skip) jsonschema 未安装，schema 断言降级（镜像断言已执行）")
    # 聚合纵深：65/66 PASS → BLOCKED（不产出绿）——机器强制的最终落点
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(_pass_doc(65, 66))
    out = agg.aggregate()
    _ck("F6-SCHEMA-001 65/66 PASS 聚合 BLOCKED",
        out["aggregate_outcome"] == BLOCKED and out["technical_eligible"] is False,
        out["reason"])


# ══════════════════════════════════════════════════════════════════════
# F6-TRC-PARSER-002：ac_traceability parser fail-open
# ══════════════════════════════════════════════════════════════════════
def _run_trace(plan_path, json_path):
    proc = subprocess.run(
        [sys.executable, TRACE, "--check", "--plan", plan_path,
         "--json", json_path],
        capture_output=True, text=True, timeout=300)
    meta = {}
    try:
        meta = json.load(open(json_path, encoding="utf-8"))["meta"]
    except Exception:
        pass
    return proc.returncode, meta


def test_f6_trc002_missing_plan_check_exit2():
    """--plan 给定但不存在 → --check 必须 exit 2（旧版静默 SKIP 全绿）。"""
    if not os.path.isfile(PLAN):
        print(f"  (skip) 方案快照不存在: {PLAN}")
        return
    with tempfile.TemporaryDirectory(prefix="wq_f6i_") as td:
        rc, meta = _run_trace(os.path.join(td, "nope.md"),
                              os.path.join(td, "m.json"))
        _ck("F6-TRC-002 --plan 不存在 + --check → rc=2",
            rc == 2, f"rc={rc}")
        _ck("F6-TRC-002 meta.catalog_integrity=FAIL（缺失即校验失败）",
            meta.get("catalog_integrity") == "FAIL", str(meta.get("catalog_integrity")))


def test_f6_trc002_duplicate_and_poison_rows_detected():
    """重复相同行 / 先毒后正重复 ID 行 → problem → rc=2（旧版后行覆盖=掩蔽）。"""
    if not os.path.isfile(PLAN):
        print(f"  (skip) 方案快照不存在: {PLAN}")
        return
    text = open(PLAN, encoding="utf-8").read()
    marker = "| GATE-04 | 内层 exit 7、自报零 finding | assertion FAIL/BLOCKED |"
    assert marker in text, "GATE-04 行锚点漂移，需同步测试"
    with tempfile.TemporaryDirectory(prefix="wq_f6j_") as td:
        # 重复相同行（整行原样复制）
        p1 = os.path.join(td, "dup.md")
        with open(p1, "w", encoding="utf-8") as fh:
            fh.write(text.replace(marker, marker + "\n" + marker))
        rc1, meta1 = _run_trace(p1, os.path.join(td, "m1.json"))
        _ck("F6-TRC-002 重复相同行 → rc=2",
            rc1 == 2, f"rc={rc1}")
        _ck("F6-TRC-002 重复行计入 problems + catalog_integrity=FAIL",
            any("重复" in p for p in meta1.get("catalog_problems", []))
            and meta1.get("catalog_integrity") == "FAIL")
        # 先毒后正：篡改行插在正行之前（旧版 dict 后行覆盖 → 正行赢 → 全绿）
        poison = "| GATE-04 | 内层 exit 0、一切正常 | assertion FAIL/BLOCKED |"
        p2 = os.path.join(td, "poison.md")
        with open(p2, "w", encoding="utf-8") as fh:
            fh.write(text.replace(marker, poison + "\n" + marker))
        rc2, _ = _run_trace(p2, os.path.join(td, "m2.json"))
        _ck("F6-TRC-002 先毒后正重复 ID 行 → rc=2（fail-open 已闭）",
            rc2 == 2, f"rc={rc2}")
        # 基线对照：未篡改副本仍 rc=0
        p0 = os.path.join(td, "base.md")
        with open(p0, "w", encoding="utf-8") as fh:
            fh.write(text)
        rc0, meta0 = _run_trace(p0, os.path.join(td, "m0.json"))
        _ck("F6-TRC-002 基线方案副本 rc=0（无误报）",
            rc0 == 0 and meta0.get("catalog_integrity") == "OK", f"rc={rc0}")


def test_f6_trc002_plan_sha256_computed_for_real():
    """PLAN_SHA256 对方案文件实算：语义归一折叠的空白篡改（双空格）必红；
    meta 落 plan_sha256_actual==文件真实哈希（非摆设常量）。"""
    import hashlib
    if not os.path.isfile(PLAN):
        print(f"  (skip) 方案快照不存在: {PLAN}")
        return
    text = open(PLAN, encoding="utf-8").read()
    with tempfile.TemporaryDirectory(prefix="wq_f6k_") as td:
        p0 = os.path.join(td, "base.md")
        with open(p0, "w", encoding="utf-8") as fh:
            fh.write(text)
        rc0, meta0 = _run_trace(p0, os.path.join(td, "m0.json"))
        real = hashlib.sha256(open(p0, "rb").read()).hexdigest()
        _ck("F6-TRC-002 meta.plan_sha256_actual==文件实算哈希（真算非常量）",
            meta0.get("plan_sha256_actual") == real
            and meta0.get("plan_sha256_match") is True,
            f"actual={meta0.get('plan_sha256_actual')}")
        # 空白级篡改：语义归一折叠（不触 §20/§25.1 比对），仅 sha256 变化
        p1 = os.path.join(td, "ws.md")
        with open(p1, "w", encoding="utf-8") as fh:
            fh.write(text.replace("内层 exit 7、自报零 finding",
                                  "内层  exit 7、自报零 finding"))
        rc1, meta1 = _run_trace(p1, os.path.join(td, "m1.json"))
        _ck("F6-TRC-002 空白级篡改（语义归一不报）→ sha256 实算必红 rc=2",
            rc1 == 2 and meta1.get("plan_sha256_match") is False
            and meta1.get("catalog_integrity") == "FAIL",
            f"rc={rc1}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    print(f"== F6 四洞加固回归（gate-scope/format-dup/schema-bound/trc-parser，{len(tests)} 组）==")
    for t in tests:
        print(f"-- {t.__name__}")
        try:
            t()
        except Exception as exc:  # 测试自身崩溃=失败（不静默）
            import traceback
            traceback.print_exc()
            FAIL_N += 1
            FAILURES.append(f"{t.__name__} (CRASH: {exc!r})")
    print("=" * 64)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        for name in FAILURES:
            print(f"  ✗ {name}")
        sys.exit(1)
    print("ALL GREEN")

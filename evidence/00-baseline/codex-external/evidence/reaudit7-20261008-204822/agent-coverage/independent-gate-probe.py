#!/usr/bin/env python3
"""第七轮独立 Gate/Schema 对抗探针；不调用开发方测试函数。"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "system"))

from wenqu_core.bugscan_orchestrator import BugscanPlanner, default_registry
from wenqu_core.gate_aggregator import GateAggregator, mirror_validate_station_result_v2

SHA = "d32c859f9043798d9e8a4984e8f57aa64567e33c"
CLI = ROOT / "system" / "wenqu_core" / "cli.py"
SCHEMA = ROOT / "system" / "schemas" / "station-result-v2.schema.json"

failures: list[str] = []

def check(name: str, cond: bool, detail) -> None:
    marker = "PASS" if cond else "FAIL"
    print(f"[{marker}] {name}: {detail}")
    if not cond:
        failures.append(name)

def write(path: Path, value) -> Path:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return path

def cli(*args: str):
    p = subprocess.run([sys.executable, str(CLI), "gate", *map(str, args)],
                       cwd=ROOT, text=True, capture_output=True)
    try:
        body = json.loads(p.stdout)
    except Exception:
        body = {"raw": p.stdout, "stderr": p.stderr}
    return p.returncode, body

with tempfile.TemporaryDirectory(prefix="reaudit7-gate-") as raw_td:
    td = Path(raw_td)
    planner = BugscanPlanner(default_registry())
    plan = planner.plan("FAST")
    manifest = planner.freeze_run_manifest(
        plan, run_id="r7-independent", project_id="audit/wenqu",
        commit_sha=SHA, environment="staging",
        scope=["alpha/**", "beta/**", "gamma/**", "delta/**"],
        ruleset={"version": "reaudit7-independent"},
        data_config={"version": "reaudit7-independent"},
    )
    mp = td / "manifest.json"
    manifest.save(mp)
    assert tuple(manifest.required_stations) == (0, 1)
    assert manifest.denominator == 4

    def station(sid: int):
        return {
            "schema_version": "2.0",
            "run_id": manifest.run_id,
            "station_id": sid,
            "attempt_id": f"independent-attempt-{sid}",
            "execution_status": "COMPLETED",
            "policy_verdict": "PASS",
            "identity": {
                "project_id": manifest.project_id,
                "commit_sha": manifest.commit_sha,
                "environment": manifest.environment,
                "scope_hash": manifest.scope_hash,
            },
            "tool": {"name": "reaudit7-independent", "version": "7"},
            "execution": {
                "argv_digest": "a" * 64,
                "started_at": "2026-10-08T12:34:56+08:00",
                "ended_at": "2026-10-08T12:34:57+08:00",
                "actual_exit_code": 0,
                "expected_exit_set": [0],
                "assertion_verdict": "PASS",
            },
            "coverage": {"denominator": 4, "scanned": 4},
            "artifacts": [{"cas_digest": "sha256:" + f"{sid + 1:x}" * 64,
                            "size": 7}],
        }

    s0, s1 = station(0), station(1)
    p0, p1 = write(td / "s0.json", s0), write(td / "s1.json", s1)

    rc, out = cli("--results", p0, p1, "--manifest", mp)
    check("manifest 正门全对账", rc == 0 and out.get("aggregate_outcome") == "PASS",
          {"rc": rc, "verdict": out.get("aggregate_outcome"), "counts": out.get("counts")})

    rc, out = cli("--results", p0, "--manifest", mp)
    check("required 缺站必红", rc == 2 and out.get("aggregate_outcome") == "BLOCKED"
          and "denominator_shrinkage" in " ".join(out.get("reasons", [])),
          {"rc": rc, "reasons": out.get("reasons")})

    shrink = copy.deepcopy(s1)
    shrink["coverage"] = {"denominator": 3, "scanned": 3}
    ps = write(td / "shrink.json", shrink)
    rc, out = cli("--results", p0, ps, "--manifest", mp)
    check("自报 coverage 分母缩水必红", rc == 2 and "self_declared_denominator"
          in " ".join(out.get("reasons", [])), {"rc": rc, "reasons": out.get("reasons")})

    rogue_scope = copy.deepcopy(s1)
    rogue_scope["identity"]["scope_hash"] = "f" * 64
    pr = write(td / "scope.json", rogue_scope)
    rc, out = cli("--results", p0, pr, "--manifest", mp)
    check("scope_hash 漂移必红", rc == 2 and "scope_hash_mismatch"
          in " ".join(out.get("reasons", [])), {"rc": rc, "reasons": out.get("reasons")})

    raw_manifest = json.loads(mp.read_text(encoding="utf-8"))
    raw_manifest["required_stations"] = [0]
    mt = write(td / "manifest-tampered.json", raw_manifest)
    rc, out = cli("--results", p0, "--manifest", mt)
    check("manifest required 篡改 hash 复核必红", rc == 3 and out.get("mode") == "manifest_invalid",
          {"rc": rc, "mode": out.get("mode"), "reason": out.get("reason")})

    # 对抗：manifest_hash 是无密钥摘要。攻击者缩 required 后自行重算摘要；
    # 同时故意保留 planner.required_stations 原值，检验 loader 是否做内部一致性校验。
    import hashlib
    forged = json.loads(mp.read_text(encoding="utf-8"))
    forged["required_stations"] = [0]
    forged["station_ttls"] = {"0": forged["station_ttls"]["0"]}
    canonical = json.dumps({k: v for k, v in forged.items() if k != "manifest_hash"},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    forged["manifest_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
    pf = write(td / "manifest-rehashed-shrink.json", forged)
    rc, out = cli("--results", p0, "--manifest", pf)
    check("对抗缺口：required 缩件后自算摘要仍假绿", rc == 0
          and out.get("aggregate_outcome") == "PASS"
          and forged["planner"]["required_stations"] != forged["required_stations"],
          {"rc": rc, "verdict": out.get("aggregate_outcome"),
           "top_required": forged["required_stations"],
           "planner_required": forged["planner"]["required_stations"]})

    rc, out = cli("--results", p0, p1)
    check("无 manifest 裸调用拒绝", rc == 3 and out.get("mode") == "self_declared_refused",
          {"rc": rc, "mode": out.get("mode")})

    rc, out = cli("--results", p0, p0, p1, "--manifest", mp)
    check("全等等价重复仅按幂等重发", rc == 0 and out.get("counts", {}).get("duplicates_ignored") == 1,
          {"rc": rc, "counts": out.get("counts")})

    conflict = copy.deepcopy(s0)
    conflict["attempt_id"] = "different-attempt"
    pc = write(td / "conflict.json", conflict)
    rc, out = cli("--results", p0, pc, p1, "--manifest", mp)
    check("重复站 attempt 不同必红", rc == 2 and out.get("counts", {}).get("conflicts") == 1,
          {"rc": rc, "reasons": out.get("reasons"), "counts": out.get("counts")})

    conflict2 = copy.deepcopy(s0)
    conflict2["artifacts"][0]["cas_digest"] = "sha256:" + "e" * 64
    pc2 = write(td / "conflict-artifact.json", conflict2)
    rc, out = cli("--results", p0, pc2, p1, "--manifest", mp)
    check("重复站 artifact 不同必红", rc == 2 and out.get("counts", {}).get("conflicts") == 1,
          {"rc": rc, "reasons": out.get("reasons"), "counts": out.get("counts")})

    # 对抗：保持当前等价键字段不变，仅漂移其他影响语义的字段。
    semantic_conflict = copy.deepcopy(s1)
    semantic_conflict["identity"]["ruleset_hash"] = "9" * 64
    semantic_conflict["identity"]["data_config_hash"] = "8" * 64
    semantic_conflict["tool"]["digest"] = "7" * 64
    semantic_conflict["tool"]["name"] = "different-scanner"
    semantic_conflict["execution"]["argv_digest"] = "6" * 64
    semantic_conflict["finding_ids"] = ["fnd_semantic_conflict"]
    psc = write(td / "duplicate-semantic-conflict.json", semantic_conflict)
    rc, out = cli("--results", p0, p1, psc, "--manifest", mp)
    check("对抗缺口：重复站非键语义漂移仍被忽略", rc == 0
          and out.get("aggregate_outcome") == "PASS"
          and out.get("counts", {}).get("duplicates_ignored") == 1
          and out.get("counts", {}).get("conflicts") == 0,
          {"rc": rc, "verdict": out.get("aggregate_outcome"), "counts": out.get("counts")})

    bad_time = copy.deepcopy(s1)
    bad_time["execution"]["started_at"] = "2026-10-08"
    pt = write(td / "bad-time.json", bad_time)
    rc, out = cli("--results", p0, pt, "--manifest", mp)
    check("非 RFC3339 纯日期必红", rc == 2 and out.get("counts", {}).get("malformed", 0) >= 1,
          {"rc": rc, "reasons": out.get("reasons"), "counts": out.get("counts")})

    # F6-SCHEMA-BOUND：独立揭示两层边界。Draft-07 正式 schema 对 >64 不等值
    # 仍无法做跨字段比较；但生产镜像与聚合器必须无界拒绝。
    large = copy.deepcopy(s0)
    large["coverage"] = {"denominator": 10007, "scanned": 10006}
    import jsonschema
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    formal_errors = list(jsonschema.Draft7Validator(schema).iter_errors(large))
    mirror_errors = mirror_validate_station_result_v2(large)
    check("正式 Draft-07 >64 边界如实存在", not formal_errors,
          {"formal_error_count": len(formal_errors), "coverage": large["coverage"]})
    check("镜像无界等值强制拒绝", bool(mirror_errors) and any("scanned" in e and "denominator" in e
          for e in mirror_errors), {"mirror_errors": mirror_errors[:4]})
    agg = GateAggregator({"0"}, SHA, "staging")
    agg.add(large)
    aout = agg.aggregate()
    check("聚合器把 >64 不等值强制 BLOCKED", aout.get("aggregate_outcome") == "BLOCKED"
          and aout.get("counts", {}).get("malformed") == 1,
          {"verdict": aout.get("aggregate_outcome"), "reasons": aout.get("reasons")})

    large_ok = copy.deepcopy(s0)
    large_ok["coverage"] = {"denominator": 10007, "scanned": 10007}
    check("镜像接受 >64 等值正控", not mirror_validate_station_result_v2(large_ok),
          {"coverage": large_ok["coverage"]})

    # 正式 schema 的嵌套 object 默认允许扩展；镜像不得反向误拒。
    extended = copy.deepcopy(s0)
    extended["identity"]["future_identity_extension"] = {"v": 1}
    extended["execution"]["future_execution_extension"] = "ok"
    extended["coverage"]["future_coverage_extension"] = ["ok"]
    extended["artifacts"][0]["future_artifact_extension"] = True
    formal_ext = list(jsonschema.Draft7Validator(schema).iter_errors(extended))
    mirror_ext = mirror_validate_station_result_v2(extended)
    ext_agg = GateAggregator({"0"}, SHA, "staging")
    ext_agg.add(extended)
    ext_out = ext_agg.aggregate()
    check("schema 合法嵌套扩展不被镜像误拒", not formal_ext and not mirror_ext
          and ext_out.get("aggregate_outcome") == "PASS",
          {"formal_errors": [e.message for e in formal_ext],
           "mirror_errors": mirror_ext, "verdict": ext_out.get("aggregate_outcome")})

print(f"SUMMARY total=18 failures={len(failures)}")
if failures:
    print("FAILED_CASES=" + ",".join(failures), file=sys.stderr)
    raise SystemExit(1)

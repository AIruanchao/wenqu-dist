#!/usr/bin/env python3
"""第七轮独立 Gate/Schema 探针；只在传入的临时副本和临时目录运行。"""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

repo = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(repo / "system"))

from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    BugscanPlanner, build_station_result,
)
from wenqu_core.gate_aggregator import mirror_validate_station_result_v2  # noqa: E402


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def run_gate(args):
    p = subprocess.run(
        [sys.executable, str(repo / "system/wenqu_core/cli.py"), "gate", *args],
        cwd=repo, text=True, capture_output=True,
    )
    out = None
    for line in reversed(p.stdout.splitlines()):
        try:
            out = json.loads(line)
            break
        except json.JSONDecodeError:
            pass
    return p.returncode, out, p.stdout, p.stderr


def dump(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def summary(name, rc, out):
    print(json.dumps({
        "probe": name,
        "rc": rc,
        "outcome": (out or {}).get("aggregate_outcome"),
        "mode": (out or {}).get("mode"),
        "reason": (out or {}).get("reason"),
        "counts": (out or {}).get("counts"),
    }, ensure_ascii=False, sort_keys=True))


with tempfile.TemporaryDirectory(prefix="reaudit7-gate-") as td:
    td = Path(td)
    sha = "d32c859f9043798d9e8a4984e8f57aa64567e33c"
    planner = BugscanPlanner()
    plan = planner.plan("FAST")
    manifest = planner.freeze_run_manifest(
        plan,
        run_id="run_reaudit7_gate",
        project_id="wenqu-dist",
        commit_sha=sha,
        environment="local",
        scope=["system/wenqu_core/gate_aggregator.py"],
        ruleset={"version": "reaudit7"},
        data_config={"version": "reaudit7"},
    )
    mp = td / "run-manifest.json"
    manifest.save(mp)
    s0 = manifest.to_station_result(attempt_id="att-gate-s0")
    identity = {
        "project_id": manifest.project_id,
        "commit_sha": manifest.commit_sha,
        "environment": manifest.environment,
        "scope_hash": manifest.scope_hash,
        "ruleset_hash": manifest.ruleset_hash,
        "data_config_hash": manifest.data_config_hash,
    }
    s1 = build_station_result(
        run_id=manifest.run_id,
        station_id=1,
        attempt_id="att-gate-s1",
        execution_status="COMPLETED",
        policy_verdict="PASS",
        identity=identity,
        tool={"name": "independent-probe", "version": "1", "digest": "1" * 64},
        execution={
            "argv_digest": "2" * 64,
            "started_at": "2026-10-08T12:00:00Z",
            "ended_at": "2026-10-08T12:00:01Z",
            "timeout_s": 30,
            "actual_exit_code": 0,
            "expected_exit_set": [0],
            "assertion_verdict": "PASS",
        },
        coverage={"denominator": 1, "scanned": 1, "exclusions": []},
        artifacts=[{"cas_digest": "sha256:" + "3" * 64, "size": 1}],
    )
    p0, p1 = td / "s0.json", td / "s1.json"
    dump(p0, s0); dump(p1, s1)

    # 正控：真实冻结 manifest + 两 required 站应 PASS。
    rc, out, so, se = run_gate(["--results", str(p0), str(p1), "--manifest", str(mp)])
    summary("legitimate_manifest_control", rc, out)
    assert rc == 0 and out["aggregate_outcome"] == "PASS"

    # 新对抗 1：manifest_hash 只是无密钥自校验。删 required 站后自行重算即可上绿；
    # planner.required_stations 仍保持 [0,1]，还证明 load 未做内部一致性校验。
    forged = json.loads(mp.read_text(encoding="utf-8"))
    forged["required_stations"] = [0]
    forged["station_ttls"] = {"0": forged["station_ttls"]["0"]}
    body = {k: v for k, v in forged.items() if k != "manifest_hash"}
    forged["manifest_hash"] = hashlib.sha256(canonical(body).encode()).hexdigest()
    fp = td / "forged-manifest.json"
    dump(fp, forged)
    rc, out, so, se = run_gate(["--results", str(p0), "--manifest", str(fp)])
    summary("rehashed_required_shrink", rc, out)
    print("forged_top_required=", forged["required_stations"],
          "planner_required=", forged["planner"]["required_stations"])
    assert rc == 0 and out["aggregate_outcome"] == "PASS", (
        "若实现已修，此断言应失败；当前证明可重算 hash 缩 required 后假绿")

    # 新对抗 2：所谓重复站“全等等价键”漏掉 ruleset/data_config/tool/execution/
    # finding_ids。保持局部键相同、改语义字段，仍被当幂等重复忽略并 PASS。
    s1b = copy.deepcopy(s1)
    s1b["identity"]["ruleset_hash"] = "9" * 64
    s1b["identity"]["data_config_hash"] = "8" * 64
    s1b["tool"]["digest"] = "7" * 64
    s1b["execution"]["argv_digest"] = "6" * 64
    s1b["finding_ids"] = ["fnd_semantic_conflict"]
    p1b = td / "s1-semantic-conflict.json"
    dump(p1b, s1b)
    rc, out, so, se = run_gate([
        "--results", str(p0), str(p1), str(p1b), "--manifest", str(mp)])
    summary("duplicate_semantic_conflict_ignored", rc, out)
    assert rc == 0 and out["aggregate_outcome"] == "PASS" \
        and out["counts"]["duplicates_ignored"] == 1 \
        and out["counts"]["conflicts"] == 0

    # 正向收口证据：无时区/纯日期必须被镜像和 CLI 拦下。
    bad_time = copy.deepcopy(s1)
    bad_time["execution"]["started_at"] = "2026-10-08"
    btp = td / "bad-time.json"; dump(btp, bad_time)
    rc, out, so, se = run_gate(["--results", str(p0), str(btp), "--manifest", str(mp)])
    summary("rfc3339_pure_date_rejected", rc, out)
    assert rc == 2 and out["aggregate_outcome"] == "BLOCKED"

    # F6-SCHEMA-BOUND：正式 Draft-07 schema 仍接受 >64 的 65/66；镜像/CLI 会拒。
    # 分开记录两层，禁止把补偿镜像表述成 schema 自身闭环。
    bad_bound = copy.deepcopy(s1)
    bad_bound["coverage"] = {"denominator": 66, "scanned": 65, "exclusions": []}
    schema = json.loads((repo / "system/schemas/station-result-v2.schema.json").read_text())
    try:
        import jsonschema
        schema_errors = list(jsonschema.Draft7Validator(schema).iter_errors(bad_bound))
        print("formal_schema_65_66_error_count=", len(schema_errors))
        assert len(schema_errors) == 0
    except ImportError:
        print("formal_schema_65_66_error_count=UNAVAILABLE(jsonschema missing)")
    mirror_errors = mirror_validate_station_result_v2(bad_bound)
    print("mirror_65_66_error_count=", len(mirror_errors),
          "first=", mirror_errors[0] if mirror_errors else None)
    assert mirror_errors
    bbp = td / "bad-bound.json"; dump(bbp, bad_bound)
    rc, out, so, se = run_gate(["--results", str(bbp), "--allow-self-declared"])
    summary("gate_mirror_65_66_rejected", rc, out)
    assert rc == 2 and out["aggregate_outcome"] == "BLOCKED"

print("RESULT: independent gate probes completed; two bypasses reproduced")

import json, os, stat, tempfile
from pathlib import Path
from jsonschema import Draft7Validator
from wenqu_core.gate_aggregator import GateAggregator
from wenqu_core.store import EventStore
from wenqu_core.deploy_framework import DeployManager, DeployError

ROOT = Path(os.environ["WENQU_ROOT"])
out = {}

# Gate: zero denominator and un-attested CONDITIONAL eligibility.
g0 = GateAggregator(set(), "a"*40, "staging").aggregate()
out["gate_empty_required"] = {
    "aggregate_outcome": g0["aggregate_outcome"],
    "technical_eligible": g0["technical_eligible"],
    "reason": g0["reason"],
}
gc = GateAggregator({"s1"}, "a"*40, "staging")
gc.add({"station":"s1","outcome":"CONDITIONAL","sha":"a"*40,"environment":"staging"})
gcr = gc.aggregate()
out["gate_conditional"] = {
    "aggregate_outcome": gcr["aggregate_outcome"],
    "technical_eligible": gcr["technical_eligible"],
}

# Store: repeat exact logical event after it was appended; should be idempotent but isn't.
with tempfile.TemporaryDirectory() as td:
    db = str(Path(td)/"events.db")
    with EventStore(db) as s:
        h1, i1 = s.append({"type":"SAME","idempotency_key":"k1"})
        h2, i2 = s.append({"type":"SAME","idempotency_key":"k1"})
        out["store_retry"] = {
            "first_inserted": i1, "second_inserted": i2,
            "hash_equal": h1 == h2, "chain_length": s.verify_chain()["length"],
        }

# Deploy: executable mode is destroyed; first-release self-check failure leaves current active.
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    src = td/"src"; src.mkdir()
    sh = src/"tool.sh"; sh.write_text("#!/bin/sh\nexit 0\n"); sh.chmod(0o755)
    mgr = DeployManager(str(td/"releases"), str(td/"current"))
    b = mgr.build(str(src))
    mode = stat.S_IMODE((Path(b["release_dir"])/"tool.sh").stat().st_mode)
    out["deploy_exec_mode"] = {"source_mode":"0755", "release_mode":oct(mode), "executable": bool(mode & 0o111)}

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    src = td/"src"; src.mkdir(); (src/"a.txt").write_text("x")
    current = td/"current"
    mgr = DeployManager(str(td/"releases"), str(current), install_self_check=lambda _: False)
    error = None
    try:
        mgr.deploy(str(src))
    except DeployError as e:
        error = str(e)
    out["deploy_first_selfcheck_failure"] = {
        "raised": error is not None,
        "current_exists": current.is_symlink(),
        "current_target_exists": current.resolve().exists() if current.is_symlink() else False,
        "error_mentions_stays_failed": "stays on failed release" in (error or ""),
    }

def validate(schema_name, instance):
    schema = json.loads((ROOT/"system"/"schemas"/schema_name).read_text())
    errs = sorted(Draft7Validator(schema).iter_errors(instance), key=lambda e: list(e.path))
    return {"accepted": not errs, "errors": [e.message for e in errs[:3]]}

common_approval = {
    "schema_version":"2.0","approval_id":"apr_123","approval_type":"merge",
    "run_id":"r","stop_event_id":"stop1","stop_type":"release","actor":"alice",
    "issued_at":"2026-10-07T00:00:00Z","expires_at":"2026-10-08T00:00:00Z",
    "nonce":"1234567890abcdef","decision":"approve","signature":"x"*32
}
out["schema_approval_missing_payload"] = validate("approval-v2.schema.json", common_approval)
cross = dict(common_approval)
cross["payload"] = {
    "approval_type":"risk",
    "finding_fingerprints":["f"],"severity":"LOW","reason":"long enough reason",
    "compensating_controls":["c"],"expiry":"2026-10-08T00:00:00Z"
}
out["schema_approval_cross_type_payload"] = validate("approval-v2.schema.json", cross)

evidence = {
    "evidence_id":"ev_x","run_id":"r",
    "identity":{"commit_sha":"a"*40,"environment":"staging","scope_hash":"s"},
    "tool":{"name":"t","version":"1"},
    "runner":{"runner_id":"r","version":"1"},
    "execution":{"argv_digest":"a","started_at":"2026-10-07T00:00:00Z",
                 "finished_at":"2026-10-07T00:00:01Z","actual_exit_code":0},
    "fresh_until":"2026-10-08T00:00:00Z"
}
out["schema_evidence_no_artifact_or_verdict"] = validate("evidence-v2.schema.json", evidence)

station = {
    "schema_version":"2.0","run_id":"r","station_id":2,"attempt_id":"a",
    "execution_status":"COMPLETED","policy_verdict":"PASS",
    "identity":{"commit_sha":"a"*40,"environment":"staging","scope_hash":"s"},
    "tool":{"name":"t","version":"1"},
    "execution":{"argv_digest":"x","started_at":"2026-10-07T00:00:00Z",
                 "ended_at":"2026-10-07T00:00:01Z","actual_exit_code":0,
                 "expected_exit_set":[0],"assertion_verdict":"PASS"}
}
out["schema_station_pass_no_coverage_or_artifacts"] = validate("station-result-v2.schema.json", station)

finding = {
    "schema_version":"2.0","event_type":"ACCEPTED_RISK","finding_id":"fnd_x",
    "fingerprint":"fp","severity":"CRITICAL","priority":"P0",
    "state_from":"OPEN","state_to":"ACCEPTED_RISK",
    "risk_acceptance":{"approver":"alice","reason":"long enough reason","scope":"all",
                       "expiry":"2026-10-08T00:00:00Z"},
    "ts":"2026-10-07T00:00:00Z"
}
out["schema_p0_accepted_risk"] = validate("finding-event-v2.schema.json", finding)

closed = {
    "schema_version":"2.0","event_type":"CLOSED","finding_id":"fnd_y",
    "fingerprint":"fp","severity":"LOW","priority":"P3",
    "state_from":"OPEN","state_to":"CLOSED","ts":"2026-10-07T00:00:00Z"
}
out["schema_open_directly_closed"] = validate("finding-event-v2.schema.json", closed)

print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))

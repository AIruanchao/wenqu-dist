#!/usr/bin/env python3
"""第六轮独立验收：旧探针 01-07/09-10 与 F4-AUTH-001 新变体。

本脚本只导入 WENQU_REPO_COPY 指向的 git-archive 隔离副本，不调用仓内测试函数。
每个 probe 使用独立临时 SQLite/CAS，打印完整 JSON 结果；安全目标不满足时 rc=1。
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Dict, Mapping


COPY = Path(os.environ["WENQU_REPO_COPY"]).resolve()
sys.path.insert(0, str(COPY / "system"))

from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope  # noqa: E402
from wenqu_core.runner import Evidence, EvidenceStore, IntegrityError  # noqa: E402
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ActionError,
    ApprovalPreconditionError,
    ApprovalRejected,
    ApprovalReuseError,
    PipelineCorruptionError,
    RunManager,
    SevenStageStateMachine,
    _PipelineDb,
)


KEYRING = ApprovalKeyring.from_path(
    str(COPY / "system/tests/fixtures/approval-keys.json"))
KEY_ID = "key_test_1"
SECRET = KEYRING.get(KEY_ID)
IDENT = {
    "commit_sha": "b259dac000000000000000000000000000000000",
    "environment": "staging",
    "scope_hash": "scope-reaudit6-auth-a",
    "repo_id": "wenqu-dist",
    "policy_hash": "policy-reaudit6-v1",
    "ruleset_hash": "ruleset-reaudit6-v1",
}

PAYLOADS: Dict[str, Dict[str, Any]] = {
    "merge": {
        "repo_id": "org/authorized-repo",
        "base_sha": "1" * 40,
        "head_sha": IDENT["commit_sha"],
        "merge_method": "merge",
    },
    "release": {
        "release_id": "rel-authorized-20261008",
        "artifact_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
        "environment": "staging",
        "previous_release_id": "rel-authorized-previous",
    },
    "ddl": {
        "database_identity": "db://staging/authorized",
        "statement_digest": "c" * 64,
        "before_schema_hash": "d" * 64,
        "after_schema_hash": "e" * 64,
        "backup_id": "backup-authorized",
        "rollback_plan_hash": "f" * 64,
    },
    "prod_write": {
        "operation_digest": "0" * 64,
        "data_scope_digest": "1" * 64,
        "idempotency_key": "idem-authorized-reaudit6",
        "conservation_hash": "2" * 64,
    },
    "fund_auth": {
        "subject_role": "authorized-operator",
        "amount_scope_digest": "3" * 64,
        "positive_negative_test_hash": "4" * 64,
        "audit_target": "audit-authorized",
    },
    "rollback": {
        "failed_deployment_id": "dep-authorized-failed",
        "exact_previous_release_id": "rel-authorized-previous",
        "trigger": "gate-red",
        "schema_compatibility_hash": "5" * 64,
    },
}

TYPE_STOP = {
    "merge": "scope",
    "release": "release",
    "ddl": "ddl",
    "prod_write": "prod-write",
    "fund_auth": "fund-auth",
    "rollback": "release",
}


def iso(seconds: float) -> str:
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def sign(obj: Mapping[str, Any]) -> Dict[str, Any]:
    out = dict(obj)
    out.pop("signature", None)
    out["signature"] = sign_envelope(SECRET, out)
    return out


def expect(exc_type, fn, *args, **kwargs) -> str:
    try:
        fn(*args, **kwargs)
    except exc_type as exc:
        return f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        raise AssertionError(
            f"期望 {exc_type.__name__}，实际 {type(exc).__name__}: {exc}") from exc
    raise AssertionError(f"期望 {exc_type.__name__}，实际未抛异常")


def fresh(root: Path, name: str = "events.db"):
    store = EventStore(str(root / name))
    mgr = RunManager(store, keyring=KEYRING)
    return store, mgr


def running(mgr: RunManager, task: str):
    run_id = mgr.create_run(task, IDENT)["run_id"]
    mgr.advance_stage(run_id)
    state = mgr.get_run(run_id)
    return run_id, state


def waiting(mgr: RunManager, task: str, stop_type: str):
    run_id, _ = running(mgr, task)
    wait = mgr.raise_waiting(run_id, stop_type, f"reaudit6-{stop_type}")
    return run_id, wait, mgr.get_run(run_id)


def approval_base(run_id: str, task: str, state, approval_type: str,
                  payload: Mapping[str, Any], *, nonce: str | None = None,
                  **over: Any) -> Dict[str, Any]:
    now = time.time()
    ap: Dict[str, Any] = {
        "schema_version": "2.0",
        "approval_id": f"apr_reaudit6_{uuid.uuid4().hex}",
        "approval_type": approval_type,
        "key_id": KEY_ID,
        "run_id": run_id,
        "task_id": task,
        "stop_event_id": "n/a-action-reaudit6",
        "stop_type": TYPE_STOP.get(approval_type, "scope"),
        "stage": state.current_stage or "S7_GATE",
        "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "expected_state_version": state.state_version,
        "actor": "independent-human-approver",
        "issued_at": iso(now - 30),
        "expires_at": iso(now + 900),
        "nonce": nonce or f"nonce-reaudit6-{uuid.uuid4().hex}",
        "decision": "approve",
        "payload": dict(payload),
    }
    ap.update(over)
    return sign(ap)


def action_approval(mgr: RunManager, run_id: str, task: str,
                    approval_type: str, *, nonce: str | None = None,
                    payload: Mapping[str, Any] | None = None,
                    **over: Any) -> Dict[str, Any]:
    return approval_base(
        run_id, task, mgr.get_run(run_id), approval_type,
        dict(payload if payload is not None else PAYLOADS[approval_type]),
        nonce=nonce, **over)


def resume_approval(mgr: RunManager, run_id: str, task: str,
                    preconditions: Mapping[str, Any], *,
                    nonce: str | None = None, **over: Any) -> Dict[str, Any]:
    state = mgr.get_run(run_id)
    assert state.waiting is not None
    ap = approval_base(
        run_id, task, state, "resume",
        {
            "stop_event_id": state.waiting.stop_event_id,
            "stop_type": state.waiting.stop_type,
            "objective_precondition_hash":
                SevenStageStateMachine.objective_precondition_hash(preconditions),
        },
        nonce=nonce,
        stop_event_id=state.waiting.stop_event_id,
        stop_type=state.waiting.stop_type,
        stage=state.waiting.stage,
        **over,
    )
    return ap


def risk_approval(mgr: RunManager, run_id: str, task: str,
                  fps: list[str], severity: str = "LOW", **over: Any):
    now = time.time()
    payload = {
        "finding_fingerprints": fps,
        "severity": severity,
        "reason": "independent-risk-test",
        "compensating_controls": ["independent-control"],
        "expiry": iso(now + 600),
    }
    return approval_base(run_id, task, mgr.get_run(run_id), "risk", payload,
                         stop_type="scope", **over)


def receipt(action: Mapping[str, Any], run_id: str, *,
            outcome: str = "COMMITTED", **over: Any) -> Dict[str, Any]:
    rc: Dict[str, Any] = {
        "schema_version": "1.0",
        "receipt_type": "action-execution-receipt",
        "action_id": action["action_id"],
        "run_id": run_id,
        "action_type": action["action_type"],
        "action_target": action["action_target"],
        "watermark": IDENT["commit_sha"],
        "outcome": outcome,
        "external_ref": f"external-{uuid.uuid4().hex}",
        "ts": iso(time.time()),
        "key_id": KEY_ID,
    }
    rc.update(over)
    return sign(rc)


def rows(mgr: RunManager, run_id: str) -> list[dict[str, Any]]:
    got = []
    for (raw,) in mgr._db._conn.execute(  # noqa: SLF001
            "SELECT payload FROM pipeline_events ORDER BY seq"):
        p = json.loads(raw)
        if p.get("run_id") == run_id:
            got.append(p)
    return got


def probe01(root: Path) -> Dict[str, Any]:
    """Unicode 字节篡改、未知 audience、重签异环境均拒；拒绝不消费 nonce。"""
    _, mgr = fresh(root)
    task = "reaudit6_p01"
    run_id, _, _ = waiting(mgr, task, "ambiguity")
    pre = {"requirement_four_elements": "r/a/c/e", "scope_hash": IDENT["scope_hash"]}
    nonce = f"nonce-unicode-{uuid.uuid4().hex}"
    good = resume_approval(mgr, run_id, task, pre, nonce=nonce,
                           actor="审批者-é")
    nfd = dict(good)
    nfd["actor"] = unicodedata.normalize("NFD", good["actor"])
    assert nfd["actor"] != good["actor"]
    e1 = expect(ApprovalRejected, mgr.resume_waiting, run_id, nfd, pre)

    with_audience = dict(good)
    with_audience["audience"] = "wenqu-controller"
    with_audience = sign(with_audience)
    e2 = expect(ApprovalRejected, mgr.resume_waiting, run_id, with_audience, pre)

    wrong_env = dict(good)
    wrong_env["environment"] = "production"
    wrong_env = sign(wrong_env)
    e3 = expect(ApprovalRejected, mgr.resume_waiting, run_id, wrong_env, pre)
    assert mgr.broker.consumed_approvals(run_id=run_id) == []
    ok = mgr.resume_waiting(run_id, good, pre)
    assert ok["resumed"] is True and ok["run_state"] == "RUNNING"
    return {"verdict": "PASS", "unicode_mutation": e1,
            "signed_unknown_audience": e2, "resigned_wrong_environment": e3,
            "same_nonce_after_rejections_resumed": True}


def probe02(root: Path) -> Dict[str, Any]:
    """resume/risk API 双向路由与跨 payload 判别。"""
    _, mgr = fresh(root)
    task = "reaudit6_p02"
    run_id, _, _ = waiting(mgr, task, "scope")
    pre = {"new_scope_hash": "scope-new", "risk_refrozen": True,
           "required_set_refrozen": True, "evidence_refrozen": True}
    risk = risk_approval(mgr, run_id, task, [], severity="LOW")
    e1 = expect(ApprovalRejected, mgr.resume_waiting, run_id, risk, pre)
    resume = resume_approval(mgr, run_id, task, pre)
    e2 = expect(ApprovalRejected, mgr.authorize_risk, run_id, resume)

    mixed = dict(resume)
    mixed["payload"] = dict(mixed["payload"])
    mixed["payload"]["severity"] = "LOW"
    mixed = sign(mixed)
    e3 = expect(ApprovalRejected, mgr.resume_waiting, run_id, mixed, pre)
    assert mgr.broker.consumed_approvals(run_id=run_id) == []
    mgr.resume_waiting(run_id, resume, pre)
    return {"verdict": "PASS", "risk_via_resume": e1,
            "resume_via_risk": e2, "mixed_payload": e3,
            "rejection_paths_zero_consumption": True}


def probe03(root: Path) -> Dict[str, Any]:
    """数字 1/自定义 truthy 对象不能冒充客观 bool，且失败不耗 nonce。"""
    _, mgr = fresh(root)
    task = "reaudit6_p03"
    run_id, _, _ = waiting(mgr, task, "resource")
    bad = {"resource_probe_ref": "probe://r6", "probe_recovered": 1,
           "safety_margin_met": 1}
    nonce = f"nonce-bool-{uuid.uuid4().hex}"
    ap_bad = resume_approval(mgr, run_id, task, bad, nonce=nonce)
    e = expect(ApprovalPreconditionError, mgr.resume_waiting,
               run_id, ap_bad, bad)
    assert mgr.broker.consumed_approvals(run_id=run_id) == []
    good = {"resource_probe_ref": "probe://r6", "probe_recovered": True,
            "safety_margin_met": True}
    ap_good = resume_approval(mgr, run_id, task, good, nonce=nonce)
    out = mgr.resume_waiting(run_id, ap_good, good)
    return {"verdict": "PASS", "numeric_truthy_rejected": e,
            "same_nonce_valid_bool_resumed": out["resumed"]}


def probe04(root: Path) -> Dict[str, Any]:
    """action 类旧 CAS+旧 stage 授权拒绝；失败不耗 nonce。"""
    _, mgr = fresh(root)
    task = "reaudit6_p04"
    run_id, old = running(mgr, task)
    nonce = f"nonce-action-cas-{uuid.uuid4().hex}"
    stale = action_approval(mgr, run_id, task, "release", nonce=nonce)
    mgr.advance_stage(run_id, execution_status="COMPLETED", policy_verdict="PASS")
    now = mgr.get_run(run_id)
    assert now.state_version > old.state_version and now.current_stage != old.current_stage
    e = expect(ApprovalRejected, mgr.reserve_action, run_id, "release",
               "release://authorized", stale)
    assert mgr.broker.consumed_approvals(run_id=run_id) == []
    current = action_approval(mgr, run_id, task, "release", nonce=nonce)
    reserved = mgr.reserve_action(run_id, "release", "release://authorized", current)
    return {"verdict": "PASS", "stale_action_authorization": e,
            "old_version": old.state_version, "new_version": now.state_version,
            "same_nonce_current_cas_reserved": reserved["action_state"]}


def probe05(root: Path) -> Dict[str, Any]:
    """TIMEOUT+CONDITIONAL 必落 FAILED；P1 finding 不可风险接受。"""
    _, mgr = fresh(root)
    run_timeout, _ = running(mgr, "reaudit6_p05_timeout")
    r = mgr.advance_stage(run_timeout, execution_status="TIMEOUT",
                          policy_verdict="CONDITIONAL",
                          findings=["timeout-not-green"])
    assert r["attempt_status"] == "FAILED"
    done = mgr.complete_run(run_timeout)
    assert done["final_state"] == "FAILED" and done["policy_verdict"] == "FAIL"

    task = "reaudit6_p05_p1"
    run_p1, _ = running(mgr, task)
    mgr.register_finding(run_p1, "fnd_reaudit6p1", "fp-p1-reaudit6",
                         "MEDIUM", "P1")
    ap = risk_approval(mgr, run_p1, task, ["fp-p1-reaudit6"], severity="MEDIUM")
    e = expect(ApprovalRejected, mgr.authorize_risk, run_p1, ap)
    assert mgr.broker.consumed_approvals(run_id=run_p1) == []
    return {"verdict": "PASS", "timeout_conditional_attempt": r["attempt_status"],
            "timeout_run_terminal": done["final_state"],
            "medium_p1_risk_rejected": e}


def probe06(root: Path) -> Dict[str, Any]:
    """公共控制事件入口全拒；跨 run 移植已 seal 事件重放损坏。"""
    store, mgr = fresh(root)
    before = store.head()
    rejected: Dict[str, str] = {}
    for et in ("RUN_COMPLETED", "APPROVAL_CONSUMED", "SUPERSEDED",
               "ACTION_COMMITTED"):
        rejected[et] = expect(ValueError, store.append,
                              {"event_type": et, "run_id": "attacker"})
    assert store.head() == before

    run_a = mgr.create_run("reaudit6_p06_a", IDENT)["run_id"]
    run_b = mgr.create_run("reaudit6_p06_b", IDENT)["run_id"]
    raw = mgr._db._conn.execute(  # noqa: SLF001
        "SELECT payload FROM pipeline_events WHERE json_extract(payload,'$.run_id')=? "
        "ORDER BY seq LIMIT 1", (run_a,)).fetchone()[0]
    transplanted = json.loads(raw)
    transplanted["run_id"] = run_b  # seal remains bound to run_a/body
    _PipelineDb.append_event(mgr._db._conn, transplanted)  # noqa: SLF001
    e = expect(PipelineCorruptionError, mgr.get_run, run_b)
    return {"verdict": "PASS", "public_guard_rejections": rejected,
            "head_unchanged_after_public_rejections": True,
            "cross_run_sealed_transplant": e}


def copy_event_rows(src: RunManager, dest: EventStore) -> None:
    data = src._db._conn.execute(  # noqa: SLF001
        "SELECT event_id,payload,prev_event_hash,event_hash,created_at "
        "FROM pipeline_events ORDER BY seq").fetchall()
    dest._conn.execute("BEGIN IMMEDIATE")  # noqa: SLF001
    try:
        for row in data:
            dest._conn.execute(  # noqa: SLF001
                "INSERT INTO pipeline_events(event_id,payload,prev_event_hash,event_hash,created_at) "
                "VALUES(?,?,?,?,?)", row)
        dest._conn.execute("COMMIT")  # noqa: SLF001
    except BaseException:
        dest._conn.execute("ROLLBACK")  # noqa: SLF001
        raise


def probe07(root: Path) -> Dict[str, Any]:
    """事件-only 重建后，换 approval_id/payload/target 重签但复用 nonce 仍拒。"""
    src_store, mgr = fresh(root, "source.db")
    task = "reaudit6_p07"
    run_id, _ = running(mgr, task)
    nonce = f"nonce-events-only-{uuid.uuid4().hex}"
    ap1 = action_approval(mgr, run_id, task, "release", nonce=nonce)
    act = mgr.reserve_action(run_id, "release", "release://authorized/one", ap1)
    assert act["action_state"] == "RESERVED"

    dst = EventStore(str(root / "replayed.db"))
    copy_event_rows(mgr, dst)
    replay = RunManager(dst, keyring=KEYRING)
    assert replay.broker.consumed_approvals(run_id=run_id) == []  # 旁表确实空
    changed = dict(PAYLOADS["release"])
    changed["release_id"] = "rel-different-but-same-nonce"
    ap2 = action_approval(replay, run_id, task, "release", nonce=nonce,
                          payload=changed)
    e = expect(ApprovalReuseError, replay.reserve_action, run_id, "release",
               "release://different/target", ap2)
    restored = replay.get_run(run_id)
    assert len(restored.actions) == 1
    return {"verdict": "PASS", "side_table_rows_after_events_only_copy": 0,
            "different_signed_envelope_same_nonce_rejected": e,
            "restored_action_count": len(restored.actions),
            "chain": dst.verify_chain()}


def event_worker(args) -> int:
    db, ready, go, idx = map(Path, args[:3]) + [args[3]]  # pragma: no cover
    return 0


def probe09_worker(ns) -> int:
    store = EventStore(ns.db)
    Path(ns.ready).write_text("ready\n", encoding="utf-8")
    deadline = time.time() + 15
    while not Path(ns.go).exists():
        if time.time() > deadline:
            raise TimeoutError("worker barrier timeout")
        time.sleep(0.01)
    payload = json.loads(ns.payload)
    h, inserted = store.append(payload)
    print(json.dumps({"worker": ns.worker, "hash": h, "inserted": inserted},
                     sort_keys=True))
    return 0


def probe09(root: Path) -> Dict[str, Any]:
    """四进程同时 append 同 payload：恰一插入、同真实 hash、链尖正确。"""
    db = root / "concurrent-events.db"
    EventStore(str(db)).close()
    go = root / "go"
    payload = {"kind": "reaudit6-concurrent", "nested": {"z": 1, "a": [3, 2, 1]}}
    ps = []
    for i in range(4):
        ready = root / f"ready-{i}"
        cmd = [sys.executable, __file__, "--event-worker", "--db", str(db),
               "--ready", str(ready), "--go", str(go), "--worker", str(i),
               "--payload", json.dumps(payload, ensure_ascii=False)]
        ps.append((i, ready, subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, text=True,
                                               env=dict(os.environ))))
    deadline = time.time() + 15
    while not all(r.exists() for _, r, _ in ps):
        if time.time() > deadline:
            raise TimeoutError("parent barrier timeout")
        time.sleep(0.02)
    go.write_text("go\n", encoding="utf-8")
    outs = []
    for i, _, p in ps:
        out, err = p.communicate(timeout=20)
        if p.returncode != 0:
            raise AssertionError(f"worker {i} rc={p.returncode} stderr={err}")
        outs.append(json.loads(out.strip().splitlines()[-1]))
    hashes = {o["hash"] for o in outs}
    assert len(hashes) == 1 and sum(bool(o["inserted"]) for o in outs) == 1
    store = EventStore(str(db))
    h_first = next(iter(hashes))
    h_other, ins_other = store.append({"kind": "interference", "n": 1})
    h_retry, ins_retry = store.append(dict(reversed(list(payload.items()))))
    head, total = store.head()
    chain = store.verify_chain()
    assert not ins_other is False
    assert h_retry == h_first and ins_retry is False
    assert head == h_other and total == 2 and chain["head"] == h_other
    return {"verdict": "PASS", "workers": outs, "unique_hashes": len(hashes),
            "inserted_count": sum(bool(o["inserted"]) for o in outs),
            "retry_after_interference": {"hash": h_retry, "inserted": ins_retry},
            "head": head, "rows": total, "chain": chain}


def make_evidence(tag: str) -> Evidence:
    now = time.time()
    return Evidence(argv=("/bin/echo", tag), cwd="/tmp", actual_exit_code=0,
                    stdout_sha256=hashlib.sha256(tag.encode()).hexdigest(),
                    stderr_sha256=hashlib.sha256(b"").hexdigest(),
                    argv_digest=hashlib.sha256(("argv-" + tag).encode()).hexdigest(),
                    timestamp=now, fresh_until=now + 300, timed_out=False)


def probe10(root: Path) -> Dict[str, Any]:
    """最终叶子 check/use 窗口注入 symlink/hardlink；写不越界，读 O_NOFOLLOW 拒。"""
    outside = root / "outside.txt"
    outside.write_text("OUTSIDE-SENTINEL", encoding="utf-8")
    outcomes: Dict[str, Any] = {}

    # 写竞态 1：lstat 后、rename 前放入 symlink；replace 只能替换目录项，不跟随。
    cas1 = EvidenceStore(str(root / "cas-symlink-write"))
    ev1 = make_evidence("symlink-write-race")
    orig1 = cas1._atomic_write  # noqa: SLF001
    def symlink_race(dirfd, fname, data):
        try:
            os.symlink(str(outside), fname, dir_fd=dirfd)
        except FileExistsError:
            pass
        return orig1(dirfd, fname, data)
    cas1._atomic_write = symlink_race  # type: ignore[attr-defined]  # noqa: SLF001
    d1 = cas1.put(ev1)
    assert outside.read_text(encoding="utf-8") == "OUTSIDE-SENTINEL"
    assert cas1.get(d1) == ev1
    outcomes["write_symlink_after_lstat"] = "contained; outside unchanged"

    # 写竞态 2：同窗口放入根外 hardlink；rename 替换本目录项，不改根外 inode。
    cas2 = EvidenceStore(str(root / "cas-hardlink-write"))
    ev2 = make_evidence("hardlink-write-race")
    orig2 = cas2._atomic_write  # noqa: SLF001
    def hardlink_race(dirfd, fname, data):
        try:
            os.link(str(outside), fname, dst_dir_fd=dirfd)
        except FileExistsError:
            pass
        return orig2(dirfd, fname, data)
    cas2._atomic_write = hardlink_race  # type: ignore[attr-defined]  # noqa: SLF001
    d2 = cas2.put(ev2)
    assert outside.read_text(encoding="utf-8") == "OUTSIDE-SENTINEL"
    assert cas2.get(d2) == ev2
    outcomes["write_hardlink_after_lstat"] = "contained; outside unchanged"

    # 读竞态：lstat 看到普通文件后、open 前换成 symlink；O_NOFOLLOW 必拒。
    cas3 = EvidenceStore(str(root / "cas-symlink-read"))
    ev3 = make_evidence("symlink-read-race")
    d3 = cas3.put(ev3)
    orig_open = cas3._open_file  # noqa: SLF001
    armed = {"value": True}
    def read_race(dirfd, fname, flags):
        if armed["value"] and flags == os.O_RDONLY:
            armed["value"] = False
            os.unlink(fname, dir_fd=dirfd)
            os.symlink(str(outside), fname, dir_fd=dirfd)
        return orig_open(dirfd, fname, flags)
    cas3._open_file = read_race  # type: ignore[attr-defined]  # noqa: SLF001
    e = expect(IntegrityError, cas3.get, d3)
    assert outside.read_text(encoding="utf-8") == "OUTSIDE-SENTINEL"
    outcomes["read_symlink_after_lstat"] = e
    return {"verdict": "PASS", "outcomes": outcomes,
            "outside_final": outside.read_text(encoding="utf-8")}


def probe_auth(root: Path) -> Dict[str, Any]:
    """F4-AUTH-001 专项；安全子链通过，但独立语义变体揭示 exact-target 缺口。"""
    store, mgr = fresh(root)
    task = "reaudit6_auth"
    run_id, _ = running(mgr, task)
    baseline_count = len(rows(mgr, run_id))
    checks: Dict[str, Any] = {}

    # 无授权、未知动作、类型错配都必须拒绝且零动作落账。
    checks["no_approval"] = expect(ActionError, mgr.reserve_action, run_id,
                                    "merge", "repo://authorized/pr/7")
    rel = action_approval(mgr, run_id, task, "release")
    checks["unknown_action"] = expect(ActionError, mgr.reserve_action, run_id,
                                       "deploy", "deploy://something", rel)
    ddl = action_approval(mgr, run_id, task, "ddl")
    checks["wrong_type"] = expect(ApprovalRejected, mgr.reserve_action, run_id,
                                   "merge", "repo://authorized/pr/7", ddl)
    assert len(rows(mgr, run_id)) == baseline_count

    # envelope exact binding 矩阵：每例重签，排除“只是验签失败”。
    mismatch_cases = {
        "run_id": "run_nonexistent_exact_binding",
        "task_id": "different_task",
        "environment": "production",
        "authorized_scope": "scope-expanded",
        "policy_hash": "policy-other",
        "ruleset_hash": "rules-other",
        "input_watermark": "9" * 40,
        "stage": "S2_SOLUTION",
        "expected_state_version": mgr.get_run(run_id).state_version + 1,
    }
    for field, value in mismatch_cases.items():
        ap = action_approval(mgr, run_id, task, "release", **{field: value})
        checks[f"envelope_{field}"] = expect(
            ApprovalRejected, mgr.reserve_action, run_id, "release",
            "release://authorized", ap)
    assert mgr.broker.consumed_approvals(run_id=run_id) == []

    # TTL 两端、nonce 复用、事务原子对。
    now = time.time()
    expired = action_approval(mgr, run_id, task, "release",
                              issued_at=iso(now - 120), expires_at=iso(now - 60))
    checks["expired"] = expect(ApprovalRejected, mgr.reserve_action, run_id,
                                "release", "release://authorized", expired)
    future = action_approval(mgr, run_id, task, "release",
                             issued_at=iso(now + 60), expires_at=iso(now + 120))
    checks["not_yet_valid"] = expect(ApprovalRejected, mgr.reserve_action, run_id,
                                      "release", "release://authorized", future)

    atomic_nonce = f"nonce-atomic-{uuid.uuid4().hex}"
    atomic_ap = action_approval(mgr, run_id, task, "release", nonce=atomic_nonce)
    original_emit = mgr._emit  # noqa: SLF001
    def injected_crash(*_a, **_kw):
        raise RuntimeError("injected-after-consumption-before-reserved")
    mgr._emit = injected_crash  # type: ignore[method-assign]  # noqa: SLF001
    checks["atomic_injected_crash"] = expect(
        RuntimeError, mgr.reserve_action, run_id, "release",
        "release://atomic", atomic_ap)
    mgr._emit = original_emit  # type: ignore[method-assign]  # noqa: SLF001
    assert not any(e.get("event_type") == "APPROVAL_CONSUMED"
                   and e.get("nonce_digest") == hashlib.sha256(
                       atomic_nonce.encode()).hexdigest() for e in rows(mgr, run_id))
    assert all(x["nonce"] != atomic_nonce for x in mgr.broker.consumed_approvals(
        run_id=run_id))
    atomic_reserved = mgr.reserve_action(run_id, "release", "release://atomic",
                                         atomic_ap)
    checks["atomic_retry_same_nonce"] = atomic_reserved["action_state"]

    # 同 nonce 改 approval_id/payload 后重签也不可再次消费。
    changed_payload = dict(PAYLOADS["release"])
    changed_payload["release_id"] = "rel-replay-different"
    replay_ap = action_approval(mgr, run_id, task, "release",
                                nonce=atomic_nonce, payload=changed_payload)
    checks["nonce_reuse_resigned"] = expect(
        ApprovalReuseError, mgr.reserve_action, run_id, "release",
        "release://different", replay_ap)

    # receipt 子链：自报只能 provisional；伪签/跨 action 拒；有效签名才 commit。
    aid = atomic_reserved["action_id"]
    started = mgr.start_action(run_id, aid, receipt="caller-only-observation")
    assert started["action_state"] == "STARTED"
    checks["string_commit_rejected"] = expect(
        ActionError, mgr.commit_action, run_id, aid, "caller-self-asserted")
    assert mgr.get_run(run_id).actions[aid]["receipt_status"] == "PROVISIONAL"
    good_rc = receipt(atomic_reserved, run_id)
    forged = dict(good_rc)
    forged["external_ref"] = "tampered-after-sign"
    checks["forged_receipt_reconcile"] = mgr.reconcile_receipt(run_id, aid, forged)
    assert checks["forged_receipt_reconcile"]["reconciled"] is False
    cross = receipt(atomic_reserved, run_id, action_id="act_not_this_action")
    checks["cross_action_receipt"] = mgr.reconcile_receipt(run_id, aid, cross)
    assert checks["cross_action_receipt"]["reconciled"] is False
    assert mgr.get_run(run_id).actions[aid]["action_state"] == "STARTED"
    checks["valid_receipt_reconcile"] = mgr.reconcile_receipt(run_id, aid, good_rc)
    committed = mgr.commit_action(run_id, aid, good_rc)
    assert committed["action_state"] == "COMMITTED"
    checks["valid_receipt_commit"] = committed["receipt_status"]

    # FAILED receipt + 显式 fail_action 路径确实封为终态。
    ap_fail = action_approval(mgr, run_id, task, "ddl")
    act_fail = mgr.reserve_action(run_id, "ddl", "db://staging/authorized", ap_fail)
    mgr.start_action(run_id, act_fail["action_id"], receipt="ddl-attempt")
    failed_rc = receipt(act_fail, run_id, outcome="FAILED")
    rec = mgr.reconcile_receipt(run_id, act_fail["action_id"], failed_rc)
    assert rec["reconciled"] is False
    failed = mgr.fail_action(run_id, act_fail["action_id"], "external FAILED")
    assert failed["action_state"] == "FAILED_UNKNOWN"
    checks["failed_receipt_explicit_terminal"] = failed["action_state"]
    checks["failed_terminal_no_revive"] = mgr.reconcile_receipt(
        run_id, act_fail["action_id"], failed_rc)
    assert checks["failed_terminal_no_revive"]["reconciled"] is None

    # --- 独立新变体：签发时即存在语义不一致（不是签后篡改） ---
    vulnerabilities = []

    # A. payload head/repo/method 与 envelope watermark/target 无 semantic binding。
    semantic_merge = dict(PAYLOADS["merge"])
    semantic_merge.update({"repo_id": "org/approved-repo",
                           "head_sha": "8" * 40,
                           "merge_method": "squash"})
    ap_sem_merge = action_approval(mgr, run_id, task, "merge",
                                   payload=semantic_merge)
    try:
        escaped = mgr.reserve_action(
            run_id, "merge", "repo://org/not-approved-repo/pr/999", ap_sem_merge)
    except ApprovalRejected as exc:
        checks["semantic_merge_mismatch_rejected"] = str(exc)
    else:
        vulnerabilities.append({
            "id": "F6-AUTH-SEMANTIC-BINDING",
            "case": "signed merge payload repo/head/method not tied to run watermark/action_target",
            "result": escaped,
            "approved_payload": semantic_merge,
            "executed_target": "repo://org/not-approved-repo/pr/999",
        })

    # B. broker 镜像未实现 Draft-07 的 release hash pattern，schema-invalid signed payload 可预留。
    malformed_release = dict(PAYLOADS["release"])
    malformed_release.update({"artifact_sha256": "not-a-sha256",
                              "manifest_sha256": 7,
                              "environment": "production"})
    ap_malformed = action_approval(mgr, run_id, task, "release",
                                   payload=malformed_release)
    try:
        escaped2 = mgr.reserve_action(
            run_id, "release", "release://production/not-authorized",
            ap_malformed)
    except ApprovalRejected as exc:
        checks["malformed_release_payload_rejected"] = str(exc)
    else:
        vulnerabilities.append({
            "id": "F6-AUTH-PAYLOAD-SCHEMA-DIVERGENCE",
            "case": "signed release payload violates schema hash types and payload env differs from envelope",
            "result": escaped2,
            "payload": malformed_release,
        })

    # C. reconcile 返回失败本身不转 FAILED_UNKNOWN；仓内产品调用者不存在。
    ap_stuck = action_approval(mgr, run_id, task, "rollback")
    stuck = mgr.reserve_action(run_id, "rollback", "release://rollback/authorized",
                               ap_stuck)
    mgr.start_action(run_id, stuck["action_id"], receipt="attempted")
    bad_rc = receipt(stuck, run_id)
    bad_rc["signature"] = "0" * 64
    rbad = mgr.reconcile_receipt(run_id, stuck["action_id"], bad_rc)
    after_bad = mgr.get_run(run_id).actions[stuck["action_id"]]["action_state"]
    if rbad["reconciled"] is False and after_bad == "STARTED":
        vulnerabilities.append({
            "id": "F6-AUTH-FAILED-RECONCILE-NOT-TERMINAL",
            "case": "reconcile failure is read-only; action remains STARTED until caller explicitly calls fail_action",
            "reconcile_result": rbad,
            "state_after": after_bad,
        })

    # 重放授权链的类型错配：直接构造有 seal 的错配 RESERVED，也必须 corruption。
    run_guard, _ = running(mgr, "reaudit6_auth_guard")
    ap_guard = action_approval(mgr, run_guard, "reaudit6_auth_guard", "release")
    guard = mgr.reserve_action(run_guard, "release", "release://guard", ap_guard)
    # 事件流已有 release consumption；伪造同 digest 配 merge action，新 action id。
    st_guard = mgr.get_run(run_guard)
    forged = mgr._base_event(  # noqa: SLF001
        "ACTION_AUTH_RESERVED", st_guard, "COMPLETED", "NOT_EVALUATED",
        actor="adversary", state_version=st_guard.state_version,
        action_id="act_reaudit6_typeconfuse", action_type="merge",
        action_target="repo://type-confuse",
        approval_id=guard["approval_id"], nonce_digest=guard["nonce_digest"])
    from wenqu_core.wenqu_pipeline import _seal_event
    _PipelineDb.append_event(mgr._db._conn, _seal_event(run_guard, forged))  # noqa: SLF001
    checks["replay_type_mismatch"] = expect(PipelineCorruptionError,
                                              mgr.get_run, run_guard)

    chain = store.verify_chain()
    return {"verdict": "FAIL" if vulnerabilities else "PASS",
            "checks": checks, "vulnerabilities": vulnerabilities,
            "chain_integrity": chain,
            "note": "hash chain integrity does not imply replay semantics for deliberately sealed internal injections"}


PROBES = {
    "01": probe01, "02": probe02, "03": probe03, "04": probe04,
    "05": probe05, "06": probe06, "07": probe07, "09": probe09,
    "10": probe10, "auth": probe_auth,
}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--probe", choices=sorted(PROBES))
    p.add_argument("--event-worker", action="store_true")
    p.add_argument("--db")
    p.add_argument("--ready")
    p.add_argument("--go")
    p.add_argument("--worker")
    p.add_argument("--payload")
    ns = p.parse_args()
    if ns.event_worker:
        return probe09_worker(ns)
    if not ns.probe:
        p.error("--probe required")
    root = Path(tempfile.mkdtemp(prefix=f"reaudit6-{ns.probe}-"))
    try:
        result = PROBES[ns.probe](root)
        result = {"probe": ns.probe, "isolated_root": str(root), **result}
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True,
                         default=str))
        return 0 if result.get("verdict") == "PASS" else 1
    except Exception as exc:
        import traceback
        traceback.print_exc()
        print(json.dumps({"probe": ns.probe, "verdict": "ERROR",
                          "error": f"{type(exc).__name__}: {exc}"},
                         ensure_ascii=False))
        return 2
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W12-05｜承接 W11-10：CAS 生产位持久化与 Gate 强制回读——回归正本。

R11 硬阻断⑤（八站 run 的 12 个 cas_digest 在 station-*.json 里，但 .bin
对象全在 /tmp 已被清；Gate 只验格式大小不回读）→ 两根修面：

  A. CAS 生产位=受管持久化路径（~/.wenqu-dist-release/cas/，与 WENQU_HOME
     scratch 根解耦）——production_tick 的 paths.cas_root 落持久化位
       -> test_w12_05_cas_root_managed_persistent_default
       -> test_w12_05_cas_root_resolution_precedence
       -> test_w12_05_production_tick_receipts_land_in_cas_root
  B. Gate 强制回读：对每个 cas_digest 必须能从 CAS 位回读 .bin 并验 hash
     （缺失=cas_orphan→BLOCKED；毒化=cas_corrupted；字节长度与登记
     size 不符=cas_size_mismatch）
       -> test_w12_05_gate_pass_requires_readable_receipts（正例 rc0）
       -> test_w12_05_gate_missing_receipt_cas_orphan_blocked（删 .bin rc2）
       -> test_w12_05_gate_corrupted_receipt_blocked（毒化 .bin rc2）
       -> test_w12_05_gate_size_mismatch_blocked（登记 size 造假 rc2）
       -> test_w12_05_aggregator_readback_library（库面 verifier 语义）

纯标准库；`python3 system/tests/test_w12_05_cas_readback.py`（exit 0=全绿），
兼容 pytest。
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
ROOT = os.path.dirname(REPO)                                        # 仓根
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import ApprovalKeyring  # noqa: E402
from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    BugscanPlanner, default_registry,
)
from wenqu_core.runner import EvidenceStore  # noqa: E402

CLI = os.path.join(REPO, "wenqu_core", "cli.py")
SHA = "3f" + "0" * 38
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


# ───────────────────────── fixture：冻结 manifest + 真 CAS receipt ─────────────────────────

def _freeze(tmp, *, run_id="run-w12-05"):
    """冻结 FAST run（required={0,1}）+ 签名 keyring + tmp CAS（真 receipt）。"""
    planner = BugscanPlanner(default_registry())
    plan = planner.plan("FAST")
    keyring = ApprovalKeyring.generate("key_w12_05_manifest")
    manifest = planner.freeze_run_manifest(
        plan, run_id=run_id, project_id="w12-05/erp",
        commit_sha=SHA, environment="staging",
        scope=["src/**", "tests/**", "tools/**"],
        ruleset={"version": "w6a-w12-05"}, data_config={"profile": "default"},
        signing_keyring=keyring, signing_key_id="key_w12_05_manifest")
    mpath = os.path.join(tmp, "run-manifest.json")
    manifest.save(mpath)
    kpath = os.path.join(tmp, "manifest-keys.json")
    keyring.save_json(kpath)
    cas_root = os.path.join(tmp, "cas")
    return manifest, mpath, kpath, cas_root


def _receipt(cas_root, payload: bytes):
    """真 CAS receipt：入库（create-if-absent）→ (digest, size)。"""
    cas = EvidenceStore(cas_root)
    try:
        digest = cas.put_bytes(payload)
    finally:
        cas.close()
    return f"sha256:{digest}", len(payload)


def _bound(manifest, station, artifact, **over):
    """与 manifest 完全对账的合法 station-result-v2（工件=真 CAS receipt）。"""
    digest, size = artifact
    doc = {
        "schema_version": "2.0", "run_id": manifest.run_id,
        "station_id": station, "attempt_id": f"att-w1205-{station}",
        "execution_status": "COMPLETED", "policy_verdict": "PASS",
        "identity": {"project_id": "w12-05/erp", "commit_sha": manifest.commit_sha,
                     "environment": manifest.environment,
                     "scope_hash": manifest.scope_hash},
        "tool": {"name": "w12-05-fixture", "version": "1.0"},
        "execution": {"argv_digest": "d" * 64,
                      "started_at": "2026-10-13T00:00:00Z",
                      "ended_at": "2026-10-13T00:00:01Z",
                      "actual_exit_code": 0, "expected_exit_set": [0],
                      "assertion_verdict": "PASS"},
        "coverage": {"denominator": manifest.denominator,
                     "scanned": manifest.denominator},
        "artifacts": [{"cas_digest": digest, "size": size}],
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


def _bin_path(cas_root, digest):
    h = digest.split(":", 1)[1]
    return os.path.join(cas_root, h[:2], f"{h}.bin")


# ══════════════════════════════════════════════════════════════════════
# A. CAS 生产位=受管持久化路径（与 WENQU_HOME scratch 解耦）
# ══════════════════════════════════════════════════════════════════════

def test_w12_05_cas_root_managed_persistent_default():
    """ProductionPaths.cas_root 缺省落受管持久化位 <release_home>/cas
    （release_home 缺省 ~/.wenqu-dist-release）——绝不再跟随 WENQU_HOME
    scratch 根（R11 硬阻断⑤：/tmp scratch 清理吞掉全部 .bin）。"""
    from wenqu_core import scheduler as sched

    saved = {k: os.environ.pop(k, None) for k in
             ("WENQU_CAS_ROOT", "WENQU_RELEASE_HOME", "WENQU_HOME")}
    try:
        release = os.path.join(os.path.expanduser("~"), ".wenqu-dist-release")
        paths = sched.ProductionPaths(repo_root=ROOT,
                                      wenqu_home=os.path.join("/tmp",
                                                              "wq-scratch-dead"))
        _ck("W12-05 cas_root 缺省=受管持久化位（~/.wenqu-dist-release/cas）",
            paths.cas_root == os.path.join(release, "cas"),
            f"cas_root={paths.cas_root}")
        _ck("W12-05 cas_root 与 WENQU_HOME scratch 根解耦",
            not paths.cas_root.startswith(
                os.path.join("/tmp", "wq-scratch-dead")),
            f"cas_root={paths.cas_root}")
        # WENQU_RELEASE_HOME 整根可迁移（受管位部署面）
        os.environ["WENQU_RELEASE_HOME"] = os.path.join("/tmp", "wq-release-x")
        paths2 = sched.ProductionPaths(repo_root=ROOT, wenqu_home="/tmp/wh2")
        _ck("W12-05 WENQU_RELEASE_HOME 迁移受管根生效",
            paths2.cas_root == os.path.join("/tmp", "wq-release-x", "cas"),
            f"cas_root={paths2.cas_root}")
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


def test_w12_05_cas_root_resolution_precedence():
    """解析优先级：WENQU_CAS_ROOT（显式）> WENQU_RELEASE_HOME/cas > 缺省
    受管位；测试构造面可用显式 cas_root 参数整体注入隔离。"""
    from wenqu_core import scheduler as sched

    saved = {k: os.environ.pop(k, None) for k in
             ("WENQU_CAS_ROOT", "WENQU_RELEASE_HOME")}
    try:
        os.environ["WENQU_RELEASE_HOME"] = os.path.join("/tmp", "wq-release-y")
        os.environ["WENQU_CAS_ROOT"] = os.path.join("/tmp", "wq-cas-explicit")
        paths = sched.ProductionPaths(repo_root=ROOT, wenqu_home="/tmp/wh3")
        _ck("W12-05 WENQU_CAS_ROOT 显式位最优先",
            paths.cas_root == os.path.join("/tmp", "wq-cas-explicit"),
            f"cas_root={paths.cas_root}")
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
    with tempfile.TemporaryDirectory(prefix="wq_w1205_paths_") as td:
        explicit = os.path.join(td, "cas-injected")
        paths = sched.ProductionPaths(repo_root=ROOT, wenqu_home=os.path.join(td, "wh"),
                                      cas_root=explicit)
        _ck("W12-05 构造器显式 cas_root 参数（测试/部署隔离面）",
            paths.cas_root == explicit, f"cas_root={paths.cas_root}")


def test_w12_05_production_tick_receipts_land_in_cas_root():
    """production_tick 全链：站工件 .bin 必须落 paths.cas_root（受管位语义，
    tick 内 gate 子进程对账同一根）。"""
    from wenqu_core import scheduler as sched

    with tempfile.TemporaryDirectory(prefix="wq_w1205_tick_") as td:
        cas_root = os.path.join(td, "managed-cas")
        paths = sched.ProductionPaths(
            repo_root=ROOT, wenqu_home=os.path.join(td, "wenqu-home"),
            cas_root=cas_root)
        sample_bytes = b'{"kind": "w12-05-prod-sample", "v": 1}'
        writer = os.path.join(td, "sample-writer.py")
        with open(writer, "w", encoding="utf-8") as fh:
            fh.write(
                "import os, sys\n"
                "path = sys.argv[1]\n"
                f"open(path, 'wb').write({sample_bytes!r})\n"
            )
        job_argv = (sys.executable, writer,
                    os.path.join(paths.samples_dir, "sample-fixed.json"))
        _noop = lambda payload: None  # noqa: E731
        tick = sched.production_tick(paths=paths, now=time.time(),
                                     job_argv=job_argv, macos_sender=_noop)
        station_file = os.path.join(paths.station_results_dir, "0.json")
        sr = {}
        try:
            with open(station_file, encoding="utf-8") as fh:
                sr = json.load(fh)
        except (OSError, ValueError):
            pass
        arts = sr.get("artifacts") or []
        _ck("W12-05 tick 站结果携带工件", len(arts) == 1, str(arts))
        if arts:
            digest = arts[0]["cas_digest"].split(":", 1)[1]
            bin_path = os.path.join(cas_root, digest[:2], f"{digest}.bin")
            _ck("W12-05 tick 工件 .bin 落受管 cas_root",
                os.path.isfile(bin_path), bin_path)
            cas = EvidenceStore(cas_root)
            try:
                _ck("W12-05 tick 工件受管位回读全等+hash 复验",
                    cas.get_bytes(digest) == sample_bytes)
            finally:
                cas.close()
        # tick 内 gate 刷新（子进程）必须用同一 cas 根：快照带 cas_readback
        # 且无 cas_orphan（工件在位时不得因回读误红）。
        snap = {}
        try:
            with open(paths.gate_aggregate, encoding="utf-8") as fh:
                snap = json.load(fh)
        except (OSError, ValueError):
            pass
        rb = snap.get("cas_readback") or {}
        _ck("W12-05 tick gate 快照携带 cas_readback（同根对账）",
            rb.get("checked", 0) >= 1 and rb.get("ok", 0) == rb.get("checked"),
            _tail(json.dumps(rb)))


# ══════════════════════════════════════════════════════════════════════
# B. Gate 强制回读（缺失=cas_orphan→BLOCKED）
# ══════════════════════════════════════════════════════════════════════

def test_w12_05_gate_pass_requires_readable_receipts():
    """正例：全部 receipt 可从 CAS 位回读+hash 验证 → rc0 PASS，
    cas_readback 记账 checked==ok。"""
    with tempfile.TemporaryDirectory(prefix="wq_w1205_pos_") as td:
        manifest, mpath, kpath, cas_root = _freeze(td)
        a0 = _receipt(cas_root, b'{"artifact": "w12-05-st0", "n": 1}')
        a1 = _receipt(cas_root, b'{"artifact": "w12-05-st1", "n": 2}')
        s0 = _write(_bound(manifest, 0, a0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1, a1), os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath,
                         "--verify-key", kpath, "--cas-root", cas_root])
        rb = out.get("cas_readback") or {}
        _ck("W12-05 正例 rc0 PASS（receipt 全可回读）",
            rc == 0 and out.get("policy_verdict") == "PASS",
            f"rc={rc} {_tail(out.get('reason'))}")
        _ck("W12-05 正例 cas_readback checked==ok==2",
            rb.get("checked") == 2 and rb.get("ok") == 2
            and rb.get("violations") == [],
            _tail(json.dumps(rb)))


def test_w12_05_gate_missing_receipt_cas_orphan_blocked():
    """负例（R11 硬阻断⑤ 本体）：删一个 .bin → cas_orphan → rc2 BLOCKED，
    绝不因「格式+大小对」就上绿。"""
    with tempfile.TemporaryDirectory(prefix="wq_w1205_orphan_") as td:
        manifest, mpath, kpath, cas_root = _freeze(td)
        a0 = _receipt(cas_root, b'{"artifact": "w12-05-st0", "n": 1}')
        a1 = _receipt(cas_root, b'{"artifact": "w12-05-st1", "n": 2}')
        s0 = _write(_bound(manifest, 0, a0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1, a1), os.path.join(td, "s1.json"))
        # 先证全在位可绿（同根对照）
        rc_ok, _out_ok = _gate(["--results", s0, s1, "--manifest", mpath,
                                "--verify-key", kpath, "--cas-root", cas_root])
        _ck("W12-05 负例前置：全在位 rc0", rc_ok == 0, f"rc={rc_ok}")
        os.unlink(_bin_path(cas_root, a1[0]))
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath,
                         "--verify-key", kpath, "--cas-root", cas_root])
        reasons = "".join(out.get("reasons", []))
        rb = out.get("cas_readback") or {}
        _ck("W12-05 删 .bin → rc2 BLOCKED + cas_orphan",
            rc == 2 and out.get("aggregate_outcome") == "BLOCKED"
            and "cas_orphan" in reasons,
            f"rc={rc} {_tail(reasons)}")
        _ck("W12-05 cas_readback 记账缺失明细（station+digest）",
            any(v.get("reason") == "cas_orphan" and v.get("station") == "1"
                for v in rb.get("violations", [])),
            _tail(json.dumps(rb)))


def test_w12_05_gate_corrupted_receipt_blocked():
    """负例：毒化 .bin（同 digest 异内容）→ cas_corrupted → rc2 BLOCKED。"""
    with tempfile.TemporaryDirectory(prefix="wq_w1205_corr_") as td:
        manifest, mpath, kpath, cas_root = _freeze(td)
        a0 = _receipt(cas_root, b'{"artifact": "w12-05-st0", "n": 1}')
        a1 = _receipt(cas_root, b'{"artifact": "w12-05-st1", "n": 2}')
        s0 = _write(_bound(manifest, 0, a0), os.path.join(td, "s0.json"))
        s1 = _write(_bound(manifest, 1, a1), os.path.join(td, "s1.json"))
        with open(_bin_path(cas_root, a1[0]), "wb") as fh:
            fh.write(b"W12-05-POISON-BIN")
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath,
                         "--verify-key", kpath, "--cas-root", cas_root])
        reasons = "".join(out.get("reasons", []))
        _ck("W12-05 毒化 .bin → rc2 BLOCKED + cas 回读违例",
            rc == 2 and out.get("aggregate_outcome") == "BLOCKED"
            and ("cas_corrupted" in reasons
                 or "cas_receipt_readback_violation" in reasons),
            f"rc={rc} {_tail(reasons)}")


def test_w12_05_gate_size_mismatch_blocked():
    """负例：登记 size 造假（digest 真对象在位，size 与实际字节不符）→
    cas_size_mismatch → rc2 BLOCKED。"""
    with tempfile.TemporaryDirectory(prefix="wq_w1205_size_") as td:
        manifest, mpath, kpath, cas_root = _freeze(td)
        a0 = _receipt(cas_root, b'{"artifact": "w12-05-st0", "n": 1}')
        a1 = _receipt(cas_root, b'{"artifact": "w12-05-st1", "n": 2}')
        forged = _bound(manifest, 1, a1)
        forged["artifacts"] = [{"cas_digest": a1[0], "size": a1[1] + 7}]
        s0 = _write(_bound(manifest, 0, a0), os.path.join(td, "s0.json"))
        s1 = _write(forged, os.path.join(td, "s1.json"))
        rc, out = _gate(["--results", s0, s1, "--manifest", mpath,
                         "--verify-key", kpath, "--cas-root", cas_root])
        reasons = "".join(out.get("reasons", []))
        _ck("W12-05 size 造假 → rc2 BLOCKED + cas_size_mismatch",
            rc == 2 and "cas_size_mismatch" in reasons,
            f"rc={rc} {_tail(reasons)}")


def test_w12_05_aggregator_readback_library():
    """库面（GateAggregator）：cas_receipt_verifier 给定即强制回读——
    orphan→BLOCKED cas_orphan；全可回读→PASS。"""
    from wenqu_core.gate_aggregator import BLOCKED, GateAggregator

    data = b'{"artifact": "w12-05-lib", "n": 3}'
    digest_hex = hashlib.sha256(data).hexdigest()

    def _verify(d):
        if d == digest_hex:
            return ("ok", len(data))
        return ("missing", None)

    def _mk(artifact):
        return {
            "schema_version": "2.0", "run_id": "run-w12-05-lib",
            "station_id": 0, "attempt_id": "att-w1205-lib",
            "execution_status": "COMPLETED", "policy_verdict": "PASS",
            "identity": {"commit_sha": SHA, "environment": "staging",
                         "scope_hash": "e" * 64},
            "tool": {"name": "lib-fixture", "version": "1.0"},
            "execution": {"argv_digest": "f" * 64,
                          "started_at": "2026-10-13T00:00:00Z",
                          "ended_at": "2026-10-13T00:00:01Z",
                          "actual_exit_code": 0, "expected_exit_set": [0],
                          "assertion_verdict": "PASS"},
            "coverage": {"denominator": 1, "scanned": 1},
            "artifacts": [artifact],
        }

    good = _mk({"cas_digest": f"sha256:{digest_hex}", "size": len(data)})
    orphan = _mk({"cas_digest": "sha256:" + "0" * 64, "size": len(data)})

    agg = GateAggregator({"0"}, SHA, "staging",
                         cas_receipt_verifier=_verify)
    agg.add(good)
    out = agg.aggregate()
    _ck("W12-05 库面：receipt 可回读 → PASS",
        out["aggregate_outcome"] == "PASS"
        and (out.get("cas_readback") or {}).get("ok") == 1,
        _tail(json.dumps(out.get("cas_readback"))))

    agg2 = GateAggregator({"0"}, SHA, "staging",
                          cas_receipt_verifier=_verify)
    agg2.add(orphan)
    out2 = agg2.aggregate()
    _ck("W12-05 库面：orphan → BLOCKED + cas_orphan",
        out2["aggregate_outcome"] == BLOCKED
        and "cas_orphan" in "".join(out2["reasons"]),
        _tail("".join(out2.get("reasons", []))))


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_w12_05") and callable(v)]
    print(f"== W12-05 CAS 持久化+Gate 强制回读回归（{len(tests)} 组）==")
    for t in tests:
        print(f"-- {t.__name__}")
        try:
            t()
        except Exception as exc:  # 测试自身崩溃=失败（不静默）
            import traceback
            traceback.print_exc()
            FAIL_N += 1
            FAILURES.append(f"{t.__name__} (CRASH: {exc!r})")
    print("=" * 40)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        for f in FAILURES:
            print(f"  ✗ {f}")
    sys.exit(1 if FAIL_N else 0)

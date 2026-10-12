#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W11-02 验收测试——运行时漂移检测、告警、熔断及自动恢复。

正源：/private/tmp/wq11-plan.md「W11-02｜运行时漂移检测、告警、熔断及
自动恢复」节（覆盖 R10-REL-ACTIVE-TREE-DRIFT-001）。

被测体：
    system/wenqu_core/release_drift.py（新增）
        audit_tree（内容+mode 双对账）/ resolve_release（结构门）/
        scan_cycle（current+previous 全树对账+runtime overlay）/
        monitor_tick（状态原子发布+告警链+熔断+自动恢复）
    system/sentinels/release-integrity-watch.py（新增；扫描器/daemon 入口）
    system/launchd/com.wenqu.integrity.plist.template（新增）
    system/dashboard/server.py（Gate overlay：漂移即聚合 BLOCKED）
    system/wenqu_core/scheduler.py（定时监控入口：完整性快照陈旧/漂移告警）
    system/install-release.sh（熔断：fuse OPEN 冻结激活/回滚入口）

验收判据（逐条对齐方案节）：
    1. 复刻 server.py 内容和 mode 漂移 → 检测出 DRIFT，Gate/health 变红
       （静态 PASS 不能覆盖 tree drift）；
    2. 静态 Gate PASS 不能覆盖 FUNCTION_DEAD / capacity BLOCKED；
    3. 漂移后一个扫描周期内：CRITICAL 告警 + incident bundle 封存 +
       活动观察窗作废 + 熔断（冻结激活/回滚）；
    4. 坏 cache / 坏 roots / 无（或过期/错 SHA）permit 时绝不自动恢复，
       漂移现场原样保留；
    5. 合法恢复只形成新 epoch（新目录全新解压+原现场隔离更名保留），
       恢复后重验树/字节/auth；
    6. 自动恢复失败后不无限循环（一漂移一尝试，失败熔断等人工）；
    7. 退出码：扫描器 0 clean / 2 monitor error / 3 drift 或策略阻断；
       daemon tick 0=检测裁决完成（含 BLOCKED），2=监控自身失败。

边界登记：W11-01（release_integrity verifier）与 W11-03（双 pin 激活
事务/activation-state-v2）均未合流 main——本文件按方案对
`system/wenqu_core/release_drift.py` 的独立可衔接形态测试（journal 语义
见模块 docstring），W11-03 合流后由其 activation-state-v2 收编。
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import stat as statmod
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SYSTEM_DIR = HERE.parent
REPO_ROOT = SYSTEM_DIR.parent
if str(SYSTEM_DIR) not in sys.path:
    sys.path.insert(0, str(SYSTEM_DIR))

SENTINEL = REPO_ROOT / "system" / "sentinels" / "release-integrity-watch.py"
PLIST_TPL = REPO_ROOT / "system" / "launchd" / "com.wenqu.integrity.plist.template"
INSTALL_SH = REPO_ROOT / "system" / "install-release.sh"
RELEASE_ATTEST = REPO_ROOT / "tools" / "release_attest.py"

PLAN_MEMBER = "evidence/00-baseline/codex-external/方案.md"


# ---------------------------------------------------------------------- #
# 测试语料：合成四件套 + 部署位布局
# ---------------------------------------------------------------------- #
def _load_release_attest():
    tools_dir = str(REPO_ROOT / "tools")
    if tools_dir not in sys.path:  # release_attest 顶注 import ac_traceability
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location(
        "wq_test_release_attest", str(RELEASE_ATTEST))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_RA = _load_release_attest()


def _sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _default_tree_files(commit: str) -> dict:
    """最小但形态逼真的发行树（含 server.py/scheduler.py/approval_keys）。"""
    return {
        "system/VERSION": f"3.99.{commit[:4]}\n".encode(),
        "system/dashboard/server.py": (
            b"# -*- coding: utf-8 -*-\n"
            b"SERVER_VERSION = 'wenqu-dashboard-test'\n"
            b"def app():\n    return 'ok'\n"),
        "system/wenqu_core/scheduler.py": (
            b"# scheduler stub\nPROD_TICK_INTERVAL = 300\n"),
        "system/wenqu_core/approval_keys.py": (
            b"# approval_keys stub\nclass ApprovalKeyring:\n    pass\n"),
        "tools/release_attest.py": RELEASE_ATTEST.read_bytes(),
        "system/scripts/heartbeat_svc.py": b"import time\ntime.sleep(60)\n",
        PLAN_MEMBER: "方案快照：W11-02 测试正文\n".encode("utf-8"),
        "README.md": b"wenqu-dist test release\n",
    }


def _build_release(home: Path, commit: str, files: dict | None = None,
                   *, name: str = "wenqu-dist-abc1234") -> dict:
    """在 home/releases/<commit>/ 构建四件套+tree 并 chmod -R a-w。

    复用 tools/release_attest 的 _iter_tar_records/_manifest_core_digest
    正源函数产 manifest（与安装链同一对账语义）。
    """
    files = files if files is not None else _default_tree_files(commit)
    reldir = home / "releases" / commit
    tree = reldir / "tree"
    tree.mkdir(parents=True)
    for rel, blob in files.items():
        dst = tree / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(blob)

    tar_path = reldir / f"{name}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        for rel in sorted(files):
            ti = tf.gettarinfo(str(tree / rel), arcname=rel)
            ti.mode = 0o644
            with open(tree / rel, "rb") as fh:
                tf.addfile(ti, fh)

    records, unexpected = _RA._iter_tar_records(str(tar_path))
    assert not unexpected, f"合成 tar 含意外成员: {unexpected}"
    plan_sha = next(r["sha256"] for r in records if r["path"] == PLAN_MEMBER)
    import hashlib
    manifest = {
        "schema": _RA.MANIFEST_SCHEMA,
        "name": name,
        "source_commit": commit,
        "artifact": {
            "path": f"{name}.tar.gz",
            "sha256": _sha256_bytes(tar_path.read_bytes()),
            "size": tar_path.stat().st_size,
        },
        "policy_hash": {"plan_sha256": plan_sha, "plan_member": PLAN_MEMBER},
        "files": records,
        "build_id": f"test-{commit[:8]}",
        "built_at": "2026-10-11T00:00:00Z",
    }
    manifest_path = reldir / f"{name}.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    (reldir / f"{name}.release.sig").write_text(
        json.dumps({"schema": _RA.SIG_SCHEMA, "key_id": "test-key",
                    "signature": "0" * 64}) + "\n", encoding="utf-8")
    (reldir / f"{name}.sbom.spdx.json").write_text(
        json.dumps({"spdxVersion": "SPDX-2.3", "name": name}) + "\n",
        encoding="utf-8")
    core_digest = _RA._manifest_core_digest(manifest)
    for p in reldir.rglob("*"):
        os.chmod(p, statmod.S_IMODE(p.stat().st_mode) & ~0o222)
    return {"release_dir": str(reldir), "tree": str(tree),
            "manifest": str(manifest_path), "commit": commit,
            "core_digest": core_digest, "name": name}


def _mk_roots(path: Path, entries: dict, plan_sha: str, *,
              mode: int = 0o600) -> None:
    path.write_text(json.dumps({
        "schema": _RA.RELEASE_ROOTS_SCHEMA,
        "plan_sha256": plan_sha,
        "allowed_commit": [{"commit": c, "manifest_sha256": d}
                           for c, d in entries.items()],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, mode)


def _mk_permit(path: Path, commit: str, *, expires_in: float = 3600.0,
               mode: int = 0o600, schema: str | None = None,
               issued_by: str = "test-op") -> None:
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    payload = {
        "schema": schema or "wenqu-release-recovery-permit/1",
        "commit": commit,
        "issued_by": issued_by,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=expires_in)).isoformat(),
        "note": "W11-02 test permit",
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
    os.chmod(path, mode)


def _plan_sha(files: dict) -> str:
    return _sha256_bytes(files[PLAN_MEMBER])


@pytest.fixture
def layout(tmp_path):
    """标准部署位：current=A、previous=B、roots+permit 齐、无漂移。"""
    from wenqu_core.release_drift import IntegrityPaths

    home = tmp_path / "home"
    (home / "state").mkdir(parents=True)
    (home / "observation" / "alerts").mkdir(parents=True)
    (home / "observation" / "windows").mkdir(parents=True)
    (home / "incidents").mkdir(parents=True)

    sha_a = "a1" * 20
    sha_b = "b2" * 20
    files_a = _default_tree_files(sha_a)
    files_b = _default_tree_files(sha_b)
    ra = _build_release(home, sha_a, files_a)
    rb = _build_release(home, sha_b, files_b)

    (home / "releases" / ".last-current").write_text(
        rb["tree"] + "\n", encoding="utf-8")
    os.symlink(ra["tree"], home / "current")

    _mk_roots(home / "release-roots.json",
              {sha_a: ra["core_digest"], sha_b: rb["core_digest"]},
              _plan_sha(files_a))
    _mk_permit(home / "release-recovery-permit.json", sha_a)

    paths = IntegrityPaths.for_home(str(home))
    paths.release_attest_path = str(RELEASE_ATTEST)
    return {"home": home, "paths": paths, "ra": ra, "rb": rb,
            "sha_a": sha_a, "sha_b": sha_b, "files_a": files_a}


# ---------------------------------------------------------------------- #
# 面 1：干净扫描 + 内容/mode 漂移检测（R10-REL-ACTIVE-TREE-DRIFT-001）
# ---------------------------------------------------------------------- #
def test_clean_scan_green(layout):
    from wenqu_core import release_drift as rd
    finding = rd.scan_cycle(layout["paths"], now=time.time())
    assert finding["verdict"] == "CLEAN", finding
    assert finding["current"]["ok"] is True
    assert finding["terms"]["current_tree_clean"] is True
    tick = rd.monitor_tick(layout["paths"], now=time.time())
    assert tick["rc"] == 0
    state = rd.read_state(layout["paths"])
    assert state["verdict"] == "CLEAN"
    assert state["fuse"] == "CLOSED"
    assert rd.scan_exit_code("CLEAN") == 0


def _unlock(path: Path) -> None:
    """给路径及其全部祖先目录放开 u+w（测试搭建用；复刻同 UID chmod 边界）。"""
    p = path
    while True:
        try:
            os.chmod(p, statmod.S_IMODE(p.stat().st_mode) | 0o200)
        except OSError:
            pass
        if p.parent == p:
            break
        p = p.parent


def _tamper_file(tree: Path, rel: str, *, content: bytes | None = None,
                 chmod: int | None = None) -> None:
    """复刻敌对外部会话的热改：同 UID chmod 后改写（0444 非 UID 边界）。"""
    target = tree / rel
    _unlock(target)
    if content is not None:
        target.write_bytes(content)
    if chmod is not None:
        os.chmod(target, chmod)


def test_content_drift_detected_and_gate_blocked(layout):
    from wenqu_core import release_drift as rd
    # 复刻事故形态：server.py 字节被换
    _tamper_file(Path(layout["ra"]["tree"]), "system/dashboard/server.py",
                 content=b"# hot-patched by external session\nEVIL = 1\n")
    finding = rd.scan_cycle(layout["paths"], now=time.time())
    assert finding["verdict"] == "DRIFT"
    assert "system/dashboard/server.py" in finding["current"]["drifted"]
    assert finding["terms"]["current_tree_clean"] is False
    # 扫描器退出码：漂移=3
    assert rd.scan_exit_code(finding["verdict"]) == 3
    # Gate overlay：静态 PASS 不能覆盖 tree drift
    state = {"verdict": "DRIFT", "fuse": "OPEN"}
    snap = {"policy_verdict": "PASS", "target_sha": "ab" * 20,
            "generated_at": "2026-10-11T00:00:00Z"}
    out = _overlay(snap, state)
    assert out["policy_verdict"] == "BLOCKED"
    assert "tree_drift" in out["dashboard_downgrade"]["flags"]


def test_mode_drift_detected(layout):
    from wenqu_core import release_drift as rd
    # 复刻事故形态：0444 → 0644（字节不变，仅 mode 漂移）
    _tamper_file(Path(layout["ra"]["tree"]), "system/dashboard/server.py",
                 chmod=0o644)
    finding = rd.scan_cycle(layout["paths"], now=time.time())
    assert finding["verdict"] == "DRIFT"
    assert "system/dashboard/server.py" in finding["current"]["mode_drifted"]
    assert finding["current"]["drifted"] == []


def test_missing_extra_and_special_files(layout):
    from wenqu_core import release_drift as rd
    tree = Path(layout["ra"]["tree"])
    _tamper_file(tree, "system/VERSION")  # 解锁写位后删除 → missing
    os.unlink(tree / "system" / "VERSION")
    (tree / "INTRUDER.txt").write_bytes(b"extra file\n")
    finding = rd.scan_cycle(layout["paths"], now=time.time())
    assert finding["verdict"] == "DRIFT"
    assert "system/VERSION" in finding["current"]["missing"]
    assert "INTRUDER.txt" in finding["current"]["extra"]


def test_current_redirection_blocked(layout):
    from wenqu_core import release_drift as rd
    # current 重定向到受管 releases 根之外的目录
    outside = layout["home"].parent / "outside-tree"
    outside.mkdir(exist_ok=True)
    (layout["home"] / "current").unlink()
    os.symlink(outside, layout["home"] / "current")
    finding = rd.scan_cycle(layout["paths"], now=time.time())
    assert finding["verdict"] in ("DRIFT", "BLOCKED")
    assert finding["identity"]["ok"] is False


def test_previous_tree_drift_blocks_rollback_readiness(layout):
    from wenqu_core import release_drift as rd
    _tamper_file(Path(layout["rb"]["tree"]), "system/VERSION",
                 content=b"tampered previous\n")
    finding = rd.scan_cycle(layout["paths"], now=time.time())
    # current 干净但回滚场景被污染 → 策略阻断（rc3），不是 CLEAN
    assert finding["verdict"] == "BLOCKED"
    assert finding["terms"]["rollback_ready"] is False
    assert rd.scan_exit_code(finding["verdict"]) == 3


# ---------------------------------------------------------------------- #
# 面 2：runtime overlay——静态 PASS 不能覆盖 FUNCTION_DEAD / capacity
# ---------------------------------------------------------------------- #
def _write_heartbeat(home: Path, *, function_dead=False,
                     capacity_gate="OPEN", tick_rc=0, age_seconds=0.0):
    hb = {
        "tick_at": "2026-10-11T00:00:00Z",
        "tick_epoch": time.time() - age_seconds,
        "tick_rc": tick_rc,
        "health": [{"job_id": "w4.observation-sample",
                    "state": "FUNCTION_DEAD" if function_dead else "FRESH",
                    "healthy": not function_dead,
                    "severity": "CRITICAL" if function_dead else None}],
        "capacity_gate": {"gate": capacity_gate},
    }
    (home / "observation" / "heartbeat.json").write_text(
        json.dumps(hb, ensure_ascii=False), encoding="utf-8")


def test_static_pass_cannot_override_function_dead(layout):
    from wenqu_core import release_drift as rd
    _write_heartbeat(layout["home"], function_dead=True)
    finding = rd.scan_cycle(layout["paths"], now=time.time())
    assert finding["terms"]["function_dead"] is False
    assert finding["runtime_verdict"] == "BLOCKED"
    assert finding["verdict"] == "BLOCKED"
    out = _overlay({"policy_verdict": "PASS", "target_sha": "ab" * 20,
                    "generated_at": "2026-10-11T00:00:00Z"},
                   {"verdict": "BLOCKED", "fuse": "CLOSED"})
    assert out["policy_verdict"] == "BLOCKED"


def test_static_pass_cannot_override_capacity_blocked(layout):
    from wenqu_core import release_drift as rd
    _write_heartbeat(layout["home"], capacity_gate="BLOCKED")
    finding = rd.scan_cycle(layout["paths"], now=time.time())
    assert finding["terms"]["capacity_open_and_fresh"] is False
    assert finding["runtime_verdict"] == "BLOCKED"


def _overlay(snap, integrity):
    import importlib
    spec = importlib.util.spec_from_file_location(
        "wq_dash_server_overlay", str(REPO_ROOT / "system" / "dashboard" / "server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.conservative_health_snapshot(snap, integrity=integrity)


# ---------------------------------------------------------------------- #
# 面 3：告警链 + incident bundle + 观察窗作废 + 熔断
# ---------------------------------------------------------------------- #
def _open_active_window(home: Path, epoch: str = "e-w11-02") -> str:
    spec = importlib.util.spec_from_file_location(
        "wq_window_manifest", str(REPO_ROOT / "tools" / "window_manifest.py"))
    wm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wm)
    sha40 = "c3" * 20
    sha64 = "d4" * 32
    prereqs = {
        "sfinal": sha40, "tree": sha64, "roots": sha64, "registry": sha64,
        "branch": sha64, "evidence_schema": sha64, "observer": sha64,
        "ci_run_id": "1234567890", "health_target_sha": sha40,
        "health_scope": "authoritative", "capacity_gate": "OPEN",
    }
    root = str(home / "observation")
    m = wm.open_window(root, epoch_id=epoch, prerequisites=prereqs)
    return m["window_id"]


def test_drift_alarm_chain_incident_and_fuse(layout):
    from wenqu_core import release_drift as rd
    wid = _open_active_window(layout["home"])
    _tamper_file(Path(layout["ra"]["tree"]), "system/dashboard/server.py",
                 content=b"# evil swap\n")
    # 本用例观察漂移即刻态：禁用自动恢复（授权恢复链由
    # test_legal_recovery_new_epoch 验证）
    tick = rd.monitor_tick(layout["paths"], now=time.time(),
                           allow_recovery=False)
    assert tick["rc"] == 0  # tick：检测+裁决完成即 0，即使 BLOCKED
    state = rd.read_state(layout["paths"])
    assert state["verdict"] == "DRIFT"
    assert state["fuse"] == "OPEN"
    # CRITICAL 告警已投递（文本投递箱 + 回执）
    alerts = list((layout["home"] / "observation" / "alerts").glob("*.txt"))
    assert alerts, "漂移必须产生告警文件"
    alert_text = alerts[0].read_text(encoding="utf-8")
    assert "CRITICAL" in alert_text
    receipts = (layout["home"] / "observation" / "alerts" / "receipts.jsonl")
    assert receipts.exists()
    # incident bundle 封存（不删除现场）
    incidents = list((layout["home"] / "incidents").iterdir())
    assert incidents, "漂移必须封存 incident bundle"
    snap_files = [p.name for p in incidents[0].rglob("*")]
    assert any("release-integrity" in n or n.endswith(".json") for n in snap_files)
    # 活动观察窗作废
    inv = (layout["home"] / "observation" / "windows"
           / f"{wid}.invalidated.json")
    assert inv.exists(), "漂移必须作废活动观察窗"
    # 熔断：readiness/Gateway 侧 fuse 打开
    assert rd.fuse_open(layout["paths"]) is True


def test_fuse_freezes_install_and_rollback(layout):
    from wenqu_core import release_drift as rd
    _tamper_file(Path(layout["ra"]["tree"]), "system/dashboard/server.py",
                 content=b"# evil swap\n")
    # 观察熔断即刻态：禁自动恢复（授权恢复后熔断解除属合法路径，
    # 由 test_legal_recovery_new_epoch 覆盖）
    rd.monitor_tick(layout["paths"], now=time.time(),
                    allow_recovery=False)
    assert rd.fuse_open(layout["paths"])
    env = dict(os.environ,
               WENQU_INSTALL_ROOT=str(layout["home"]),
               WENQU_RELEASE_ROOTS=str(layout["home"] / "release-roots.json"))
    for argv in (["--rollback"], []):
        p = subprocess.run(
            ["bash", str(INSTALL_SH)] + argv, env=env,
            capture_output=True, text=True, timeout=120, cwd=str(REPO_ROOT))
        assert p.returncode != 0, f"熔断开启时入口必须拒绝: argv={argv}"
        assert ("熔断" in (p.stdout + p.stderr)
                or "fuse" in (p.stdout + p.stderr).lower() or "integrity" in (p.stdout+p.stderr).lower()), \
            f"拒绝原因必须注明熔断: argv={argv} out={p.stdout} err={p.stderr}"


# ---------------------------------------------------------------------- #
# 面 4：自动恢复拒绝矩阵（坏 cache/坏 roots/无 permit 绝不恢复）
# ---------------------------------------------------------------------- #
def _drifted(layout, *, tamper_tar=False):
    from wenqu_core import release_drift as rd
    _tamper_file(Path(layout["ra"]["tree"]), "system/dashboard/server.py",
                 content=b"# evil swap\n")
    if tamper_tar:
        tar = Path(layout["ra"]["release_dir"]) / \
            f"{layout['ra']['name']}.tar.gz"
        _unlock(tar)
        blob = bytearray(tar.read_bytes())
        blob[-200:] = b"\x00" * 200  # 破坏尾部 → 解压/对账必败（坏 cache）
        tar.write_bytes(bytes(blob))
    return rd.scan_cycle(layout["paths"], now=time.time())


def test_recovery_refused_without_permit(layout):
    from wenqu_core import release_drift as rd
    finding = _drifted(layout)
    os.unlink(layout["home"] / "release-recovery-permit.json")
    with pytest.raises(rd.RecoveryRefused) as ei:
        rd.attempt_auto_recovery(layout["paths"], finding, now=time.time())
    assert any("permit" in r for r in ei.value.reasons)
    # 现场原样保留（无新目录、无切换）
    assert os.readlink(layout["home"] / "current") == layout["ra"]["tree"]


def test_recovery_refused_with_expired_permit(layout):
    from wenqu_core import release_drift as rd
    finding = _drifted(layout)
    _mk_permit(layout["home"] / "release-recovery-permit.json",
               layout["sha_a"], expires_in=-60)
    with pytest.raises(rd.RecoveryRefused) as ei:
        rd.attempt_auto_recovery(layout["paths"], finding, now=time.time())
    assert any("expired" in r or "permit" in r for r in ei.value.reasons)


def test_recovery_refused_with_wrong_sha_permit(layout):
    from wenqu_core import release_drift as rd
    finding = _drifted(layout)
    _mk_permit(layout["home"] / "release-recovery-permit.json", "ff" * 20)
    with pytest.raises(rd.RecoveryRefused) as ei:
        rd.attempt_auto_recovery(layout["paths"], finding, now=time.time())
    assert any("permit" in r for r in ei.value.reasons)


def test_recovery_refused_with_permit_mode_wide(layout):
    from wenqu_core import release_drift as rd
    finding = _drifted(layout)
    _mk_permit(layout["home"] / "release-recovery-permit.json",
               layout["sha_a"], mode=0o644)
    with pytest.raises(rd.RecoveryRefused) as ei:
        rd.attempt_auto_recovery(layout["paths"], finding, now=time.time())
    assert any("permit" in r for r in ei.value.reasons)


def test_recovery_refused_with_unauthorized_sha(layout):
    from wenqu_core import release_drift as rd
    finding = _drifted(layout)
    # roots 只授权 B：漂移的 A 不在授权清单
    _mk_roots(layout["home"] / "release-roots.json",
              {layout["sha_b"]: layout["rb"]["core_digest"]},
              _plan_sha(layout["files_a"]))
    with pytest.raises(rd.RecoveryRefused) as ei:
        rd.attempt_auto_recovery(layout["paths"], finding, now=time.time())
    assert any("allowed_commit" in r or "授权" in r for r in ei.value.reasons)


def test_recovery_refused_with_bad_roots(layout):
    from wenqu_core import release_drift as rd
    finding = _drifted(layout)
    _mk_roots(layout["home"] / "release-roots.json",
              {layout["sha_a"]: layout["ra"]["core_digest"]},
              _plan_sha(layout["files_a"]), mode=0o644)
    with pytest.raises(rd.RecoveryRefused) as ei:
        rd.attempt_auto_recovery(layout["paths"], finding, now=time.time())
    assert any("roots" in r for r in ei.value.reasons)


def test_recovery_refused_with_bad_cache(layout):
    from wenqu_core import release_drift as rd
    finding = _drifted(layout, tamper_tar=True)
    with pytest.raises(rd.RecoveryRefused) as ei:
        rd.attempt_auto_recovery(layout["paths"], finding, now=time.time())
    assert any("cache" in r or "tar" in r or "四件套" in r
               for r in ei.value.reasons)
    # 坏 cache 时漂移现场与坏制品都原样保留
    assert os.path.isdir(layout["ra"]["release_dir"])


# ---------------------------------------------------------------------- #
# 面 5：合法自动恢复（新目录+新 epoch+隔离现场+恢复后重验）
# ---------------------------------------------------------------------- #
def test_legal_recovery_new_epoch(layout):
    from wenqu_core import release_drift as rd
    finding = _drifted(layout)
    result = rd.attempt_auto_recovery(layout["paths"], finding,
                                      now=time.time())
    assert result["status"] == "recovered"
    epoch = result["epoch"]
    assert epoch >= 1
    new_dir = layout["home"] / "releases" / f"{layout['sha_a']}.r{epoch}"
    assert new_dir.is_dir()
    assert os.readlink(layout["home"] / "current") == str(new_dir / "tree")
    # 全新解压的树与 manifest 逐字节对账（恢复后重验）
    post = result["post_verify"]
    assert post["tree_audit"]["ok"] is True
    assert post["auth_import_ok"] is True
    # 漂移现场被隔离（更名保留，不删除、不覆盖）
    quarantined = list((layout["home"] / "releases").glob(
        f"{layout['sha_a']}.quarantine-*"))
    assert len(quarantined) == 1
    evil = quarantined[0] / "tree" / "system" / "dashboard" / "server.py"
    assert b"evil swap" in evil.read_bytes(), "漂移现场字节必须原样保留"
    # journal：recovery 记录含新 epoch（W11-03 可衔接）
    journal = rd.journal_read(layout["paths"])
    kinds = [e["kind"] for e in journal]
    assert "recovery_started" in kinds and "recovery_succeeded" in kinds
    rec = next(e for e in journal if e["kind"] == "recovery_succeeded")
    assert rec["epoch"] == epoch and rec["commit"] == layout["sha_a"]
    # 恢复后状态 CLEAN + 新 epoch + 熔断闭合
    state = rd.read_state(layout["paths"])
    assert state["verdict"] == "CLEAN"
    assert state["deployment_epoch"] == epoch
    assert state["fuse"] == "CLOSED"
    # 恢复后 current 树再次全量对账干净
    finding2 = rd.scan_cycle(layout["paths"], now=time.time())
    assert finding2["verdict"] == "CLEAN", finding2


def test_recovery_single_attempt_no_infinite_loop(layout):
    from wenqu_core import release_drift as rd
    finding = _drifted(layout)
    # 破坏切换步：安装根失去写位 → 原子切换（symlink+rename）必败
    # （前门全过、尝试已开始、执行失败——一次尝试后熔断）
    home = layout["home"]
    os.chmod(home, 0o555)
    try:
        with pytest.raises(rd.RecoveryError):
            rd.attempt_auto_recovery(layout["paths"], finding,
                                     now=time.time())
    finally:
        os.chmod(home, 0o755)
    journal = rd.journal_read(layout["paths"])
    attempts = [e for e in journal if e["kind"] in
                ("recovery_started", "recovery_failed")]
    assert len(attempts) >= 2  # started + failed
    # 第二次尝试（同漂移事件）：journal 已有尝试记录 → 拒绝，不无限循环
    with pytest.raises(rd.RecoveryRefused) as ei:
        rd.attempt_auto_recovery(layout["paths"], finding, now=time.time())
    assert any("attempt" in r or "一次" in r for r in ei.value.reasons)
    # monitor_tick 也不重试
    tick = rd.monitor_tick(layout["paths"], now=time.time())
    state = rd.read_state(layout["paths"])
    assert state["fuse"] == "OPEN"
    assert tick["rc"] == 0
    again = [e for e in rd.journal_read(layout["paths"])
             if e["kind"] == "recovery_started"]
    assert len(again) == 1, "自动恢复最多一次"


# ---------------------------------------------------------------------- #
# 面 6：退出码与监控自身失败
# ---------------------------------------------------------------------- #
def test_monitor_error_rc2_and_state_published(layout):
    from wenqu_core import release_drift as rd
    # releases 根不可读 → 扫描链自身失败（非漂移判定）
    os.chmod(layout["home"] / "releases", 0o000)
    try:
        tick = rd.monitor_tick(layout["paths"], now=time.time())
        assert tick["rc"] == 2
        state = rd.read_state(layout["paths"])
        assert state["verdict"] == "MONITOR_ERROR"
        assert rd.scan_exit_code("MONITOR_ERROR") == 2
    finally:
        os.chmod(layout["home"] / "releases", 0o755)


def test_sentinel_cli_exit_codes(layout):
    assert SENTINEL.exists(), "sentinel 脚本必须存在"
    env = dict(os.environ, WENQU_HOME=str(layout["home"]),
               WENQU_RELEASE_ATTEST=str(RELEASE_ATTEST))
    # clean → scan rc0
    p = subprocess.run([sys.executable, str(SENTINEL), "scan"],
                       env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    # drift → scan rc3, tick rc0（检测裁决完成）
    _tamper_file(Path(layout["ra"]["tree"]), "system/dashboard/server.py",
                 content=b"# evil\n")
    p = subprocess.run([sys.executable, str(SENTINEL), "scan"],
                       env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 3, p.stderr
    # 撤销 permit → tick 走拒绝恢复路径（仍 rc0=检测裁决完成）+ 熔断开启
    os.unlink(layout["home"] / "release-recovery-permit.json")
    p = subprocess.run([sys.executable, str(SENTINEL), "tick"],
                       env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    state = json.loads((layout["home"] / "state" / "release-integrity.json")
                       .read_text(encoding="utf-8"))
    assert state["fuse"] == "OPEN"
    # 人工 unfuse（留痕）
    p = subprocess.run(
        [sys.executable, str(SENTINEL), "unfuse",
         "--operator", "test-op", "--note", "manual review done"],
        env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    state = json.loads((layout["home"] / "state" / "release-integrity.json")
                       .read_text(encoding="utf-8"))
    assert state["fuse"] == "CLOSED"


# ---------------------------------------------------------------------- #
# 面 7：PID/argv/脚本字节运行时对账
# ---------------------------------------------------------------------- #
def test_pid_argv_script_bytes_match(layout):
    from wenqu_core import release_drift as rd
    tree = Path(layout["ra"]["tree"])
    script = tree / "system" / "scripts" / "heartbeat_svc.py"
    assert script.is_file()  # 发行树自带（manifest 内）
    proc = subprocess.Popen([sys.executable, str(script)])
    try:
        services = [{"label": "w4-heartbeat",
                     "argv_contains": str(script),  # 全路径匹配：隔离其他用例残留进程
                     "script_relpath": "system/scripts/heartbeat_svc.py",
                     "must_be_running": True}]
        result = rd.audit_processes(str(tree), services)
        assert result["terms"]["pid_argv_and_script_bytes_match"] is True
        assert result["services"][0]["running_pid"] == proc.pid
        # 进程退出 → must_be_running 服务缺位 → 项 False
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    result = rd.audit_processes(str(tree), services)
    assert result["terms"]["pid_argv_and_script_bytes_match"] is False


def test_scan_cycle_includes_process_terms(layout):
    from wenqu_core import release_drift as rd
    tree = Path(layout["ra"]["tree"])
    script = tree / "system" / "scripts" / "heartbeat_svc.py"
    assert script.is_file()  # 发行树自带（manifest 内）
    proc = subprocess.Popen([sys.executable, str(script)])
    try:
        cfg = layout["home"] / "release-integrity-services.json"
        cfg.write_text(json.dumps([{
            "label": "w4-heartbeat",
            "argv_contains": str(script),
            "script_relpath": "system/scripts/heartbeat_svc.py",
            "must_be_running": True}]), encoding="utf-8")
        finding = rd.scan_cycle(layout["paths"], now=time.time())
        assert finding["terms"]["pid_argv_and_script_bytes_match"] is True
        assert finding["verdict"] == "CLEAN"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# ---------------------------------------------------------------------- #
# 面 8：dashboard HTTP 面（真子进程）——health 变红 + /api/v1/integrity
# ---------------------------------------------------------------------- #
def test_dashboard_health_red_under_drift(tmp_path):
    dash = REPO_ROOT / "system" / "dashboard" / "server.py"
    agg = tmp_path / "gate-aggregate.json"
    integ = tmp_path / "release-integrity.json"
    home = tmp_path / "wenqu-home"
    (home / "state").mkdir(parents=True)
    agg.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy_verdict": "PASS", "aggregate_outcome": "PASS",
        "target_sha": "ab" * 20, "mode": "manifest",
        "scope_binding": {"mode": "manifest"},
        "reason": "static eight-station PASS", "reasons": [],
    }, ensure_ascii=False), encoding="utf-8")
    integ_state = {
        "schema": "wenqu-release-integrity/v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_at_epoch": time.time(),
        "verdict": "DRIFT", "fuse": "OPEN", "deployment_epoch": 0,
        "current": {"ok": False, "drifted": ["system/dashboard/server.py"]},
    }
    integ.write_text(json.dumps(integ_state, ensure_ascii=False),
                     encoding="utf-8")
    port = _free_port()
    env = dict(os.environ, WENQU_HOME=str(home),
               WENQU_GATE_AGGREGATE=str(agg),
               WENQU_RELEASE_INTEGRITY=str(integ),
               WENQU_INTEGRITY_TTL="900")
    proc = subprocess.Popen(
        [sys.executable, str(dash), "--port", str(port)], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 60
        ready = False
        while time.monotonic() < deadline:
            try:
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/api/v1/ping")
                r = conn.getresponse()
                r.read()
                conn.close()
                if r.status == 200:
                    ready = True
                    break
            except OSError:
                pass
            time.sleep(0.2)
        assert ready, "dashboard 60s 内未就绪"
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/health")
        r = conn.getresponse()
        body = json.loads(r.read().decode("utf-8"))
        conn.close()
        assert r.status == 200
        assert body["policy_verdict"] == "BLOCKED", body
        assert "tree_drift" in body["dashboard_downgrade"]["flags"]
        assert body["dashboard_downgrade"]["raw_policy_verdict"] == "PASS"
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/integrity")
        r = conn.getresponse()
        j = json.loads(r.read().decode("utf-8"))
        conn.close()
        assert r.status == 200
        assert j["verdict"] == "DRIFT"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------- #
# 面 9：scheduler 定时监控接线（只读 + CRITICAL 告警）
# ---------------------------------------------------------------------- #
def test_scheduler_tick_wires_integrity(tmp_path):
    from wenqu_core import scheduler as sched
    from wenqu_core.release_drift import IntegrityPaths
    home = tmp_path / "wenqu-home"
    for sub in ("state", "observation/alerts", "observation/samples",
                "observation/shadow", "observation/logs",
                "observation/windows", "observation/drills", "incidents"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    sha = "e5" * 20
    files = _default_tree_files(sha)
    r = _build_release(home, sha, files)
    os.symlink(r["tree"], home / "current")
    # 哨兵先发布 DRIFT 状态
    _tamper_file(Path(r["tree"]), "system/dashboard/server.py",
                 content=b"# evil\n")
    paths = IntegrityPaths.for_home(str(home))
    paths.release_attest_path = str(RELEASE_ATTEST)
    from wenqu_core import release_drift as rd
    rd.monitor_tick(paths, now=time.time())

    stub = tmp_path / "sampler.py"
    stub.write_text("import sys\nsys.exit(0)\n")
    sp = sched.ProductionPaths(repo_root=str(REPO_ROOT),
                               wenqu_home=str(home))
    tick = sched.production_tick(
        paths=sp, now=time.time(),
        job_argv=(sys.executable, str(stub), sp.samples_dir, sp.shadow_dir),
        macos_sender=lambda p: None)
    assert tick["tick_rc"] == 0
    integ = tick["release_integrity"]
    assert integ["status"] in ("drift", "blocked", "fuse_open"), integ
    # scheduler 自身的 CRITICAL 投递（区别于哨兵先发的告警）：receipts 里
    # 须有 scheduler 通道的完整性告警回执
    receipts = (home / "observation" / "alerts" / "receipts.jsonl")
    assert receipts.exists()
    lines = receipts.read_text(encoding="utf-8")
    assert ("release 完整性异常" in lines) or ("release_integrity" in lines), \
        "scheduler tick 必须对漂移快照投递自己的 CRITICAL 告警"
    alerts = list((home / "observation" / "alerts").glob("*CRITICAL*.txt"))
    assert alerts, "scheduler tick 必须对漂移快照发 CRITICAL 告警"


# ---------------------------------------------------------------------- #
# 面 10：launchd 模板与注册表纪律
# ---------------------------------------------------------------------- #
def test_launchd_template_exists_and_registered():
    assert PLIST_TPL.exists(), "com.wenqu.integrity.plist.template 必须入仓"
    text = PLIST_TPL.read_text(encoding="utf-8")
    assert "com.wenqu.integrity" in text
    assert "release-integrity-watch" in text
    assert "StartInterval" in text
    # 注册表（README）必须登记 com.wenqu.integrity
    readme = (REPO_ROOT / "system" / "launchd" / "README.md").read_text(
        encoding="utf-8")
    assert "com.wenqu.integrity" in readme
    # 禁止注册表外 label：模板不得定义退役作业
    for banned in ("com.wenqu.observation-window", "com.wenqu.observation"):
        assert f"<string>{banned}</string>" not in text


# ---------------------------------------------------------------------- #
# 面 11：状态文件契约 + journal 可衔接性（W11-03 接口）
# ---------------------------------------------------------------------- #
def test_state_contract_and_journal_schema(layout):
    from wenqu_core import release_drift as rd
    rd.monitor_tick(layout["paths"], now=time.time())
    state = rd.read_state(layout["paths"])
    for key in ("schema", "generated_at", "verdict", "fuse",
                "deployment_epoch", "current", "previous",
                "runtime_overlay"):
        assert key in state, f"state 缺字段 {key}"
    assert state["schema"] == rd.INTEGRITY_SCHEMA
    terms = state["runtime_overlay"]["terms"]
    for key in ("static_gate_pass", "current_tree_clean", "rollback_ready",
                "pid_argv_and_script_bytes_match", "scheduler_pass_and_fresh",
                "capacity_open_and_fresh"):
        assert key in terms, f"runtime overlay 缺六项之一 {key}"
    journal = rd.journal_read(layout["paths"])
    assert any(e["kind"] == "scan_clean" for e in journal)

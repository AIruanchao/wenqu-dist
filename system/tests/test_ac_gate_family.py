#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——GATE/MRG/CI 族（test_ac_gate_family）。

覆盖 Codex 方案 §20.1/§20.5 中 GATE-01~08/12、MRG-01~07、CI-05/07/08/09
共 20 条：每条按「注入→期望」逐字对齐方案表格，真实构造场景（真实 git
仓/tmp fixture、真实调用产品码）并断言结果，绝不空转。

被测正源（不改动任何产品码）：
- system/wenqu_core/source_gate.py    fresh_fetch / merge_base_diff /
                                      affected_scope / execute_gate /
                                      validate_exact_sha（GATE-01~04、
                                      MRG-05/06/07、CI-05 本地等价）
- system/wenqu_core/runner.py         EvidenceStore CAS（GATE-05/06：
                                      symlink/hardlink/根外/哈希篡改拒绝）
- system/wenqu_core/store.py          EventStore 控制事件 seal 守卫
                                      （GATE-12：unsigned flip/adjudication）
- system/wenqu_core/approval_keys.py  HMAC 验签（GATE-12 附属腿）
- system/wenqu_core/bugscan_orchestrator.py
                                      冻结身份/TTL/SourceGateAdapter/
                                      station-result-v2 schema（GATE-07/08、
                                      CI-07/09、MRG-06b）
- system/wenqu_core/gate_aggregator.py
                                      C1~C5 硬约束 + GitHub 状态映射
                                      （MRG-01~04、CI-05a/08）
- system/daemons/auto-merge.sh        P0 封存 stub（MRG-01 执行器腿：不合流）

本地等价映射说明（CI 族依赖真实 GitHub API 的部分）：
- CI-05 fork/merge_group → SourceGate.validate_exact_sha 对非目标 head 的
  SHA（fork PR SHA、merge_group 临时 SHA）一律 StaleShaError（T-02 旧/异
  SHA 绿灯拒合）；「check 不产生」→ GateAggregator required 站缺失 =
  denominator_shrinkage → BLOCKED（无 SKIP/无静默通过语义）。
- CI-07 未授权 App 自报同名 context → SourceGateAdapter 身份三源一律取
  冻结 manifest 正源、绝不采信 gate_result 自报身份：自报 SHA 与冻结
  不符 → SourceGateShaMismatch（不可信、阻断）。
- CI-08 Wenqu Gate 缺失但 Bugscan 绿 → 站1（源闸）未上报、站2 绿 →
  GateAggregator denominator_shrinkage BLOCKED → GitHub failure（不合流）。
- CI-09 S7 递归聚合/重复发布 → station-result-v2 additionalProperties
  schema 拒绝 + 聚合输出回灌聚合器缺 station_id 结构 → malformed BLOCKED。

明确未实现（本文件不硬凑、不 xfail，见交付报告「不可实现清单」）：
GATE-09（N=0/超上限非产品参数错误）、GATE-10（N+1 上限无实现）、
GATE-11（异源轮 S 标签追踪无实现）、CI-06（CODEOWNERS/ruleset doctor 无实现）。

独立运行：python3 system/tests/test_ac_gate_family.py [--json OUT.json]
exit 0 = 全部用例绿；--json 额外输出逐 ID 结果数组 {id, test, passed}。
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

SYSTEM_DIR = Path(__file__).resolve().parent.parent  # system/
if str(SYSTEM_DIR) not in sys.path:
    sys.path.insert(0, str(SYSTEM_DIR))

from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope  # noqa: E402
from wenqu_core import bugscan_orchestrator as bo  # noqa: E402
from wenqu_core.gate_aggregator import BLOCKED, CONDITIONAL, PASS, GateAggregator  # noqa: E402
from wenqu_core.runner import Evidence, EvidenceStore, IntegrityError  # noqa: E402
from wenqu_core.source_gate import (  # noqa: E402
    EXIT_BLOCKED,
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_PASS,
    EXIT_TIMEOUT,
    SourceGate,
    SourceGateError,
    StaleShaError,
)
from wenqu_core.store import EventStore  # noqa: E402

AUTO_MERGE_STUB = SYSTEM_DIR / "daemons" / "auto-merge.sh"

_UTC = timezone.utc


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def _ok(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)


def _expect_raise(exc_type: type, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Exception:
    """调用 fn，期望抛出 exc_type；返回异常对象供断言细节。"""
    try:
        fn(*args, **kwargs)
    except exc_type as exc:  # type: ignore[misc]
        return exc
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(f"expected {exc_type.__name__} to be raised, but call returned")


@contextlib.contextmanager
def _tmp(root: Optional[Path] = None):
    """测试临时目录：外部传入（main 调度）或自建自清（pytest/独立调用兼容）。"""
    if root is not None:
        yield Path(root)
        return
    own = tempfile.mkdtemp(prefix="ac-gate-family-")
    try:
        yield Path(own)
    finally:
        shutil.rmtree(own, ignore_errors=True)


def _git(repo: Path, *argv: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", *argv], cwd=str(repo), capture_output=True, text=True, check=False
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(argv)} failed rc={proc.returncode}: {proc.stderr.strip()}"
        )
    return proc


def _commit(repo: Path, files: Dict[str, str], message: str) -> None:
    for name, content in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)


def _head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD").stdout.strip().lower()


def _make_repo(root: Path, *, behavioral_commit: bool = True) -> Path:
    """真实 git fixture：main 两提交 + 定格在基线的 bare origin。

    提交1：README.md（基线）；提交2（可选）：app.py + notes.md 混合变更。
    origin 是提交1 时刻的 bare 克隆——本地 head 前进不影响 origin/main，
    保证 merge-base diff 恒为「基线→head」的真实变更集。
    """
    repo = root / f"repo-{uuid.uuid4().hex[:8]}"
    repo.mkdir(parents=True)
    _git(repo, "init")
    # 隔离本机全局 git 配置（签名/hooks 不参与注入场景）
    _git(repo, "config", "user.email", "gate-family@example.com")
    _git(repo, "config", "user.name", "gate-family-tester")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "core.hooksPath", "/dev/null")
    _commit(repo, {"README.md": "baseline\n"}, "base")
    _git(repo, "branch", "-M", "main")
    origin = root / f"{repo.name}-origin.git"
    _git(repo, "clone", "--bare", ".", str(origin))  # 远端定格在提交1
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "fetch", "origin")  # refs/remotes/origin/main -> 提交1
    if behavioral_commit:
        _commit(repo, {"app.py": "print('behavior')\n", "notes.md": "doc\n"}, "change")
    return repo


def _legacy(station: str, outcome: str, sha: str, env: str = "test") -> Dict[str, str]:
    """GateAggregator legacy 契约条目（station/outcome/sha/environment）。"""
    return {"station": station, "outcome": outcome, "sha": sha, "environment": env}


def _freeze_manifest(
    now: datetime,
    *,
    commit_sha: str = "1" * 40,
    run_id: str = "gatefam-run",
    ruleset: Optional[Dict[str, Any]] = None,
    scope: Optional[List[str]] = None,
) -> "bo.RunManifest":
    """站0 冻结件（FAST 档）——SourceGateAdapter/复用拒绝测试的身份正源。"""
    planner = bo.BugscanPlanner()
    plan = planner.plan("FAST")
    return planner.freeze_run_manifest(
        plan,
        run_id=run_id,
        project_id="gate-family",
        commit_sha=commit_sha,
        environment="local",
        scope=scope if scope is not None else ["src/**"],
        ruleset=ruleset if ruleset is not None else {"version": 1},
        data_config={"profile": "default"},
        now=now,
    )


def _gate_result(
    commit_sha: str, ended: datetime, *, exit_code: int = 0, started: Optional[datetime] = None
) -> Dict[str, Any]:
    """SourceGateAdapter 消费的源闸结果载荷（components 全 COMPLETED）。"""
    start = started if started is not None else ended - timedelta(minutes=10)
    return {
        "commit_sha": commit_sha,
        "exit_code": exit_code,
        "tool": {"name": "ci-fast", "version": "1"},
        "started_at": start.isoformat(),
        "ended_at": ended.isoformat(),
        "components": [
            {"name": "lint", "status": "COMPLETED", "exit_code": 0},
            {"name": "unit", "status": "COMPLETED", "exit_code": 0},
        ],
    }


def _github_failure(agg: GateAggregator, aggregate: Dict[str, Any]) -> Dict[str, str]:
    return agg.to_github_status(aggregate)


# ---------------------------------------------------------------------------
# GATE 族（§20.1）
# ---------------------------------------------------------------------------
def test_GATE_01_fetch_fail_or_missing_base_ref_is_error(root: Optional[Path] = None) -> None:
    """GATE-01｜注入：base ref 不存在/fetch 失败｜期望：ERROR/BLOCKED。"""
    with _tmp(root) as td:
        # 腿一：remote 指向不存在的路径 → git fetch 非零 → ERROR(2)，绝不 SKIP
        repo = _make_repo(td)
        broken = td / f"nowhere-{uuid.uuid4().hex[:8]}"
        _git(repo, "remote", "add", "broken", str(broken))
        out_json = td / "g01a.json"
        gate = SourceGate(str(repo), remote="broken", result_path=str(out_json))
        result = gate.execute_gate()
        _ok(result["exit_code"] == EXIT_ERROR, f"fetch 失败须 exit 2，got {result['exit_code']}")
        _ok(result["execution_status"] == "ERROR", "fetch 失败须 execution_status=ERROR")
        _ok(result["policy_verdict"] == "NOT_EVALUATED", "ERROR 时不得给策略判定")
        _ok(result["error"]["type"] == "SourceGateError", "错误类型须为 SourceGateError")
        _ok("fetch" in result["error"]["message"], "错误信息须指向 fetch")
        _ok(out_json.exists(), "失败证据工件必须照常落盘")
        # 腿二：fetch 成功但 base ref 不存在 → verify 阶段 ERROR(2)
        gate2 = SourceGate(str(repo), base_ref="origin/definitely-missing-ref")
        exc = _expect_raise(SourceGateError, gate2.fresh_fetch)
        _ok(exc.execution_status == "ERROR" and exc.exit_code == EXIT_ERROR,
            f"base ref 不存在须 ERROR/2，got {exc.execution_status}/{exc.exit_code}")


def test_GATE_02_zero_tests_scope_not_pure_docs_is_blocked(root: Optional[Path] = None) -> None:
    """GATE-02｜注入：零测试、scope 未证明纯文档｜期望：BLOCKED。"""
    with _tmp(root) as td:
        repo = _make_repo(td)  # 提交2：app.py + notes.md（行为+文档混合）
        # 影响图只认 src/*.py，app.py 不可解析 → 升级 full；未配置全量套件 → BLOCKED
        gate = SourceGate(
            str(repo),
            impact_graph={"src/*.py": [["true"]]},
            result_path=str(td / "g02.json"),
        )
        result = gate.execute_gate()
        _ok(result["exit_code"] == EXIT_BLOCKED, f"须 BLOCKED exit 3，got {result['exit_code']}")
        _ok(result["execution_status"] == "BLOCKED", "须 execution_status=BLOCKED")
        _ok(result["policy_verdict"] == "NOT_EVALUATED", "BLOCKED 不得带策略判定")
        _ok("FULL gate" in result["error"]["message"],
            "缺全量套件报错须点名 FULL gate（零测试绝不静默放行）")
        scope = result["scope"]
        _ok(scope["mode"] == "full" and scope["escalated"], "不可解析影响图须升级 full")
        _ok("app.py" in scope["behavioral_files"], "app.py 是行为变更")
        _ok("notes.md" in scope["non_behavioral_files"], "notes.md 归非行为面")
        _ok(result["policy_verdict"] != "NOT_APPLICABLE",
            "scope 未证明纯文档，不得记 NOT_APPLICABLE（唯一合法『无测试』）")


def test_GATE_03_missing_runner_or_dependency_is_error(root: Optional[Path] = None) -> None:
    """GATE-03｜注入：test runner/依赖缺失｜期望：ERROR。"""
    with _tmp(root) as td:
        repo = _make_repo(td)
        # 腿一：测试器可执行不存在于 PATH → ERROR(2)（不是 SKIP）
        missing_tool = f"wenqu-no-such-tester-{uuid.uuid4().hex[:8]}"
        gate = SourceGate(
            str(repo),
            impact_graph={"app.py": [[missing_tool]]},
            result_path=str(td / "g03a.json"),
        )
        result = gate.execute_gate()
        _ok(result["exit_code"] == EXIT_ERROR, f"缺测试器须 ERROR 2，got {result['exit_code']}")
        _ok(result["execution_status"] == "ERROR", "缺测试器须 ERROR")
        _ok("missing on PATH" in result["error"]["message"]
            and "not SKIP" in result["error"]["message"],
            "报错须显式声明 ERROR, not SKIP")
        # 腿二：required_paths 依赖目录缺失（如 node_modules）→ ERROR(2)
        gate2 = SourceGate(
            str(repo),
            impact_graph={"app.py": [["true"]]},
            required_paths=["node_modules"],
            result_path=str(td / "g03b.json"),
        )
        result2 = gate2.execute_gate()
        _ok(result2["exit_code"] == EXIT_ERROR, "缺依赖路径须 ERROR 2")
        _ok("node_modules" in result2["error"]["message"], "报错须点名缺失依赖")
        _ok(result2["error"]["detail"].get("missing_paths") == ["node_modules"],
            "missing_paths 证据须落账")


def test_GATE_04_inner_exit7_selfreport_zero_findings_fails(root: Optional[Path] = None) -> None:
    """GATE-04｜注入：内层 exit 7、自报零 finding｜期望：assertion FAIL/BLOCKED。"""
    with _tmp(root) as td:
        repo = _make_repo(td)
        # 注入体：内层工具自报零 finding（stdout JSON 一片绿）却 exit 7
        payload_line = json.dumps({"findings": 0, "verdict": "PASS"})
        script = td / "fake_scanner.py"
        script.write_text(
            "import json, sys\n"
            f"print({payload_line!r})\n"
            "sys.exit(7)\n",
            encoding="utf-8",
        )
        gate = SourceGate(
            str(repo),
            impact_graph={"app.py": [["python3", str(script)]]},
            result_path=str(td / "g04.json"),
        )
        result = gate.execute_gate()
        _ok(result["exit_code"] == EXIT_FAIL, f"内层 exit 7 须 FAIL exit 1，got {result['exit_code']}")
        _ok(result["execution_status"] == "COMPLETED" and result["policy_verdict"] == "FAIL",
            "真实退出码驱动的判定必须是 COMPLETED/FAIL")
        checks = result["checks"]
        _ok(len(checks) == 1 and checks[0]["exit_code"] == 7,
            "checks 须记录真实 returncode=7（TrustedRunner 唯一退出码来源）")
        expected_stdout_sha = hashlib.sha256((payload_line + "\n").encode("utf-8")).hexdigest()
        _ok(checks[0]["stdout_sha256"] == expected_stdout_sha,
            "自报『零 finding』的 stdout 已入证据，但不得据此放行（自报不作数）")


def test_GATE_05_artifact_symlink_hardlink_outside_root_blocked(root: Optional[Path] = None) -> None:
    """GATE-05｜注入：artifact symlink/hardlink/根外｜期望：BLOCKED（拒绝）。"""
    with _tmp(root) as td:
        cas_root = td / "cas"
        store = EvidenceStore(str(cas_root))

        def _evidence(n: int) -> Evidence:
            return Evidence(
                argv=("tool", f"--case={n}"),
                cwd=str(td),
                actual_exit_code=0,
                stdout_sha256=hashlib.sha256(f"out{n}".encode()).hexdigest(),
                stderr_sha256=hashlib.sha256(b"").hexdigest(),
                argv_digest=hashlib.sha256(f"argv{n}".encode()).hexdigest(),
                timestamp=float(n),
                fresh_until=float(n) + 1,
            )

        ev_symlink = _evidence(1)
        d_symlink = EvidenceStore.digest_for(ev_symlink)
        shard = cas_root / d_symlink[:2]
        shard.mkdir(parents=True, exist_ok=True)
        outside = td / "outside-secret.json"
        outside.write_text("root-external payload\n", encoding="utf-8")
        os.symlink(outside, shard / f"{d_symlink}.json")  # 根外 symlink 占位
        exc = _expect_raise(IntegrityError, store.put, ev_symlink)
        _ok("symlink" in str(exc), "symlink 占位必须 IntegrityError 拒绝写入")

        ev_hard = _evidence(2)
        d_hard = EvidenceStore.digest_for(ev_hard)
        hard_shard = cas_root / d_hard[:2]
        hard_shard.mkdir(parents=True, exist_ok=True)
        link_src = td / "hardlink-source.json"
        link_src.write_text("alias payload\n", encoding="utf-8")
        os.link(link_src, hard_shard / f"{d_hard}.json")  # st_nlink=2 预置
        exc2 = _expect_raise(IntegrityError, store.put, ev_hard)
        _ok("hardlink" in str(exc2), "预置 hardlink（st_nlink>1）必须拒绝")

        # 根外/穿越：digest 必须是 64-hex，任何路径形 digest 直接拒绝
        for bad in ("../evil", "..%2f", "a" * 63, "/etc/passwd"):
            exc3 = _expect_raise(IntegrityError, store.get, bad)
            _ok("invalid digest" in str(exc3), f"digest 穿越 {bad!r} 必须在寻址层拒绝")
        store.close()


def test_GATE_06_artifact_hash_tamper_blocked(root: Optional[Path] = None) -> None:
    """GATE-06｜注入：artifact hash 篡改｜期望：BLOCKED（拒绝消费）。"""
    with _tmp(root) as td:
        # 腿一：CAS 内容篡改 → get() 哈希复核拒绝
        store = EvidenceStore(str(td / "cas"))
        ev = Evidence(
            argv=("tool",),
            cwd=str(td),
            actual_exit_code=0,
            stdout_sha256=hashlib.sha256(b"out").hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            argv_digest=hashlib.sha256(b"argv").hexdigest(),
            timestamp=1.0,
            fresh_until=2.0,
        )
        digest = store.put(ev)
        stored_path = td / "cas" / digest[:2] / f"{digest}.json"
        stored_path.write_text('{"tampered": true}', encoding="utf-8")  # 攻击者改字节
        exc = _expect_raise(IntegrityError, store.get, digest)
        _ok("hash mismatch" in str(exc), "内容寻址复核必须检出篡改并拒绝")
        store.close()
        # 腿二：冻结 manifest 篡改 → load() manifest_hash 复核拒绝
        now = datetime.now(_UTC)
        manifest = _freeze_manifest(now)
        path = td / "run-manifest.json"
        manifest.save(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["identity"]["commit_sha"] = "9" * 40  # 篡改身份
        path.write_text(json.dumps(raw), encoding="utf-8")
        exc2 = _expect_raise(bo.ManifestFreezeError, bo.RunManifest.load, path)
        _ok("manifest_hash mismatch" in str(exc2), "冻结件被篡改必须拒绝加载")


def test_GATE_07_commit_env_scope_ruleset_mismatch_blocked(root: Optional[Path] = None) -> None:
    """GATE-07｜注入：commit/env/scope/ruleset 不符｜期望：BLOCKED。"""
    with _tmp(root) as td:
        sha = "a" * 40
        # 腿一：commit SHA 不符 → C2 证据绑定违规 → 整线 BLOCKED
        agg = GateAggregator({"1"}, target_sha=sha, environment="staging")
        agg.add(_legacy("1", "PASS", "c" * 40, "staging"))
        verdict = agg.aggregate()
        _ok(verdict["aggregate_outcome"] == BLOCKED, "SHA 不符必须整线 BLOCKED")
        _ok("sha_evidence_violation" in verdict["reasons"][0], "须记 sha_evidence_violation")
        # 腿二：environment 不符 → C5 → BLOCKED
        agg2 = GateAggregator({"1"}, target_sha=sha, environment="staging")
        agg2.add(_legacy("1", "PASS", sha, "production"))
        verdict2 = agg2.aggregate()
        _ok(verdict2["aggregate_outcome"] == BLOCKED, "环境不符必须整线 BLOCKED")
        _ok(any("environment_evidence_violation" in r for r in verdict2["reasons"]),
            "须记 environment_evidence_violation")
        # 腿三：ruleset/scope 变化 → 冻结件不可复用（不得静默换规则继续跑）
        now = datetime.now(_UTC)
        m_ruleset_a = _freeze_manifest(now, ruleset={"version": 1})
        path = td / "run-manifest.json"
        m_ruleset_a.save(path)
        m_ruleset_b = _freeze_manifest(now, ruleset={"version": 2})
        exc = _expect_raise(bo.ManifestFreezeError, m_ruleset_b.save, path)
        _ok("DIFFERENT frozen manifest" in str(exc), "ruleset 不符的冻结件不得覆写复用")
        m_scope_b = _freeze_manifest(now, scope=["tests/**"])
        exc2 = _expect_raise(bo.ManifestFreezeError, m_scope_b.save, path)
        _ok("DIFFERENT frozen manifest" in str(exc2), "scope 不符的冻结件不得覆写复用")


def test_GATE_08_evidence_past_ttl_refused(root: Optional[Path] = None) -> None:
    """GATE-08｜注入：evidence 过 TTL｜期望：BLOCKED（拒绝消费）。"""
    with _tmp(root) as td:
        now = datetime.now(_UTC)
        manifest = _freeze_manifest(now)
        adapter = bo.SourceGateAdapter(manifest, now=now)
        ttl_days = bo.default_registry().ttl_for(bo.SourceGateAdapter.STATION_ID)
        _ok(ttl_days == 30, "站1 源闸 TTL 应为 general 30 天上限")
        # 对照组：TTL 内的证据可正常适配为 PASS
        fresh = adapter.adapt(_gate_result(manifest.commit_sha, now - timedelta(days=1)))
        _ok(fresh["policy_verdict"] == "PASS", "TTL 内证据应正常消费（对照）")
        # 注入：ended_at + TTL < now → EvidenceStaleError（铁律 4 fail-closed）
        stale_gate = _gate_result(manifest.commit_sha, now - timedelta(days=ttl_days + 1))
        exc = _expect_raise(bo.EvidenceStaleError, adapter.adapt, stale_gate)
        _ok("aged out" in str(exc) and "TTL" in str(exc), "过期证据报错须点名 TTL 时效")


def test_GATE_12_unsigned_flip_or_adjudication_blocked(root: Optional[Path] = None) -> None:
    """GATE-12｜注入：unsigned flip/adjudication｜期望：BLOCKED（拒绝）。"""
    with _tmp(root) as td:
        # 腿一：未带内部 seal 的控制事件（终态翻转/审批裁定）裸 append → 一律 ValueError
        store = EventStore(str(td / "events.db"))
        for etype in ("RUN_COMPLETED", "APPROVAL_GRANTED", "FINDING_CLOSED", "SUPERSEDED"):
            unsigned = {"event_type": etype, "run_id": "r1", "verdict": "PASS"}
            exc = _expect_raise(ValueError, store.append, unsigned)
            _ok("must be injected via RunManager._emit" in str(exc),
                f"unsigned flip/adjudication（{etype}）必须被 seal 守卫拒绝")
        _, inserted = store.append({"event_type": "NOTE", "note": "ordinary"})
        _ok(inserted, "普通事件不受影响（对照组）")
        store.close()
        # 腿二：审批 envelope 无签名/伪签名 → 验签失败（fail-closed）
        ring = ApprovalKeyring.generate("key_g12")
        envelope = {"key_id": "key_g12", "decision": "APPROVE", "scope": "merge"}
        good_sig = sign_envelope(ring.get("key_g12"), envelope)
        _ok(ring.verify({**envelope, "signature": good_sig}), "正确签名应通过（对照）")
        _ok(ring.verify(envelope) is False, "无签名 envelope 必须验签失败")
        _ok(ring.verify({**envelope, "signature": "0" * 64}) is False, "伪签名必须验签失败")
        tampered = {**envelope, "decision": "APPROVE_ALL"}
        _ok(ring.verify({**tampered, "signature": good_sig}) is False,
            "签名后篡改 payload 必须验签失败")


# ---------------------------------------------------------------------------
# MRG 族（§20.1 + §20.5 MRG-07）
# ---------------------------------------------------------------------------
def test_MRG_01_fast_green_security_red_no_merge(root: Optional[Path] = None) -> None:
    """MRG-01｜注入：Fast 绿、Security 红｜期望：不合流。"""
    with _tmp(root) as td:
        sha = "a" * 40
        agg = GateAggregator(required_stations={"1", "2"}, target_sha=sha, environment="test")
        agg.add(_legacy("1", "PASS", sha))   # Fast（站1 源闸）绿
        agg.add(_legacy("2", "FAIL", sha))   # Security（站2 静态与供应链）红
        verdict = agg.aggregate()
        _ok(verdict["aggregate_outcome"] == BLOCKED, "Security 红必须整线 BLOCKED")
        _ok(any("station_hard_failure" in r for r in verdict["reasons"]), "须记 station_hard_failure")
        _ok(verdict["technical_eligible"] is False, "技术放行必须为 False")
        status = agg.to_github_status(verdict)
        _ok(status["state"] == "failure" and status["conclusion"] == "failure",
            "GitHub 双口径必须是 failure（不合流）")
        # 执行器腿：真实 auto-merge stub（P0 封存）在该场景下同样拒绝合流
        proc = subprocess.run(
            ["bash", str(AUTO_MERGE_STUB), "ignored"],
            capture_output=True, text=True, check=False,
        )
        _ok(proc.returncode == 1 and "permanently disabled" in proc.stderr,
            "auto-merge stub 必须拒绝执行（不合流）")


def test_MRG_02_missing_fast_and_gate_red_no_merge(root: Optional[Path] = None) -> None:
    """MRG-02｜注入：没有 Fast、Gate 红｜期望：不合流。"""
    with _tmp(root) as td:
        sha = "a" * 40
        agg = GateAggregator(required_stations={"1", "2"}, target_sha=sha, environment="test")
        # Fast（站1）未上报；站2 红 —— 双重违规
        agg.add(_legacy("2", "FAIL", sha))
        verdict = agg.aggregate()
        _ok(verdict["aggregate_outcome"] == BLOCKED, "缺 Fast + Gate 红必须 BLOCKED")
        reasons = " | ".join(verdict["reasons"])
        _ok("denominator_shrinkage" in reasons, "缺 required 站须记 denominator_shrinkage")
        _ok("station_hard_failure" in reasons, "红站须记 station_hard_failure")
        _ok(verdict["counts"]["required_missing"] == 1, "缺报站数须为 1（站1）")
        _ok(agg.to_github_status(verdict)["conclusion"] == "failure", "GitHub 结论必须 failure")


def test_MRG_03_same_name_forgery_or_old_sha_no_merge(root: Optional[Path] = None) -> None:
    """MRG-03｜注入：check 同名伪造/旧 SHA｜期望：不合流。"""
    with _tmp(root) as td:
        sha = "a" * 40
        # 腿一：旧 SHA 的 check 证据 → C2 绑定违规 → BLOCKED
        agg = GateAggregator({"1"}, target_sha=sha, environment="test")
        agg.add(_legacy("1", "PASS", "b" * 40))  # 旧提交 SHA 的绿灯
        verdict = agg.aggregate()
        _ok(verdict["aggregate_outcome"] == BLOCKED, "旧 SHA 证据必须 BLOCKED")
        _ok(verdict["counts"].get("required_reported", 0) == 1
            and verdict["stations"]["1"]["sha_bound"] is False,
            "证据已登记但 SHA 未绑定目标（不静默丢弃也不放行）")
        # 腿二：同名 check 二次伪造（不同 SHA）→ 冲突证据 → BLOCKED，绝不静默择优
        agg2 = GateAggregator({"1"}, target_sha=sha, environment="test")
        agg2.add(_legacy("1", "PASS", sha))
        agg2.add(_legacy("1", "PASS", "e" * 40))  # 同名伪造
        verdict2 = agg2.aggregate()
        _ok(verdict2["aggregate_outcome"] == BLOCKED, "同名冲突证据必须 BLOCKED")
        _ok(verdict2["counts"]["conflicts"] == 1, "冲突须落账 duplicate_station_conflict")
        _ok(any("duplicate_station_conflict" in r for r in verdict2["reasons"]),
            "须记 duplicate_station_conflict")


def test_MRG_04_pending_skipped_neutral_cancelled_no_merge(root: Optional[Path] = None) -> None:
    """MRG-04｜注入：pending/skipped/neutral/cancelled｜期望：不合流。"""
    with _tmp(root) as td:
        sha = "a" * 40
        # legacy outcome 归一：非绿非软枚举（PENDING/SKIPPED/NEUTRAL/CANCELLED）一律硬失败
        for bad_outcome in ("PENDING", "SKIPPED", "NEUTRAL", "CANCELLED"):
            agg = GateAggregator({"1"}, target_sha=sha, environment="test")
            agg.add(_legacy("1", bad_outcome, sha))
            verdict = agg.aggregate()
            _ok(verdict["aggregate_outcome"] == BLOCKED,
                f"{bad_outcome} 不得视作绿/软——必须整线 BLOCKED")
            _ok(agg.to_github_status(verdict)["conclusion"] == "failure",
                f"{bad_outcome} 的 GitHub 结论必须 failure")
        # v2 契约腿：execution_status=CANCELLED（check run 被取消）→ 铁律2 硬失败
        agg2 = GateAggregator({"1"}, target_sha=sha, environment="test")
        agg2.add({
            "schema_version": "2.0",
            "station_id": 1,
            "execution_status": "CANCELLED",
            "policy_verdict": "NOT_APPLICABLE",
            "identity": {"commit_sha": sha, "environment": "test"},
        })
        verdict2 = agg2.aggregate()
        _ok(verdict2["aggregate_outcome"] == BLOCKED, "v2 CANCELLED 必须硬失败")
        _ok(verdict2["stations"]["1"]["outcome"] == BLOCKED, "站级 outcome 须归一为 BLOCKED")


def test_MRG_05_head_moves_during_aggregation_invalidates(root: Optional[Path] = None) -> None:
    """MRG-05｜注入：head 在聚合后改变｜期望：旧结论失效。"""
    with _tmp(root) as td:
        repo = _make_repo(td)
        # 注入体：『测试命令』本身就是一次 git commit——内层全绿（exit 0）但 head 移动
        gate = SourceGate(
            str(repo),
            full_test_commands=[["git", "commit", "--allow-empty", "-m", "head-moved-mid-run"]],
            result_path=str(td / "m05.json"),
        )
        result = gate.execute_gate()
        _ok(result["checks"] and result["checks"][0]["exit_code"] == 0,
            "内层命令真实退出码为 0（若无 head 复核将产生假绿）")
        _ok(result["head_stable"] is False, "head 稳定性复核必须判 False")
        _ok(result["head_sha"] != result["head_sha_final"], "起跑前后 head SHA 必须不同")
        _ok(result["error"]["type"] == "StaleShaError", "必须以 StaleShaError 失效本次全部证据")
        _ok(result["exit_code"] == EXIT_ERROR and result["policy_verdict"] == "NOT_EVALUATED",
            "旧结论失效：exit 2 + NOT_EVALUATED，绝不得记 PASS")


def test_MRG_06_remote_429_empty_json_timeout_circuit_breaker(root: Optional[Path] = None) -> None:
    """MRG-06｜注入：GitHub 429/空 JSON/超时｜期望：断路，不合流。"""
    with _tmp(root) as td:
        # 腿一：上游超时（远端不可达/限流的本地等价）→ TIMEOUT(124) 断路
        repo = _make_repo(td, behavioral_commit=False)
        gate = SourceGate(
            str(repo), git_timeout=0.00001, result_path=str(td / "m06.json")
        )
        result = gate.execute_gate()
        _ok(result["exit_code"] == EXIT_TIMEOUT, f"超时须断路 exit 124，got {result['exit_code']}")
        _ok(result["execution_status"] == "TIMEOUT", "execution_status 须 TIMEOUT")
        # 腿二：空 JSON 载荷 → 适配器 fail-closed 拒绝（绝不猜）
        now = datetime.now(_UTC)
        adapter = bo.SourceGateAdapter(_freeze_manifest(now), now=now)
        exc = _expect_raise(bo.GateResultMalformed, adapter.adapt, {})
        _ok("missing fields" in str(exc), "空 JSON 必须报 GateResultMalformed")
        # 腿三：聚合层收到空 JSON/非对象 → malformed → BLOCKED（不合流）
        agg = GateAggregator({"1"}, target_sha="a" * 40, environment="test")
        agg.add({})
        verdict = agg.aggregate()
        _ok(verdict["aggregate_outcome"] == BLOCKED and verdict["counts"]["malformed"] == 1,
            "空 JSON 站结果必须记 malformed 并整线 BLOCKED")
        _ok(agg.to_github_status(verdict)["conclusion"] == "failure", "GitHub 结论必须 failure")


def test_MRG_07_head_changed_after_final_validation_atomic_reject(root: Optional[Path] = None) -> None:
    """MRG-07｜注入：最后校验后 head 变化｜期望：expected-SHA 原子拒绝。"""
    with _tmp(root) as td:
        repo = _make_repo(td)
        gate = SourceGate(str(repo))
        head_now = _head(repo)
        parent = _git(repo, "rev-parse", "HEAD~1").stdout.strip().lower()
        _ok(gate.validate_exact_sha(head_now) == head_now, "当前 head 精确匹配应放行（对照）")
        # 最后校验后 head 又前进：旧校验结论（parent 的绿灯）必须被原子拒绝
        exc = _expect_raise(StaleShaError, gate.validate_exact_sha, parent)
        _ok(exc.exit_code == EXIT_ERROR, "StaleShaError 必须 ERROR 传播")
        _ok(exc.detail.get("check_sha") == parent and exc.detail.get("head_sha") == head_now,
            "拒绝证据须同时落 check_sha 与当前 head_sha（expected-SHA 原子比对）")
        # head 再变一次：上一轮刚验过的 head 也立刻失效
        _git(repo, "commit", "--allow-empty", "-m", "moves-again")
        exc2 = _expect_raise(StaleShaError, gate.validate_exact_sha, head_now)
        _ok(exc2.detail.get("head_sha") == _head(repo), "复核必须取现场重解的 fresh head")


# ---------------------------------------------------------------------------
# CI 族（§20.5，本地等价映射见模块 docstring）
# ---------------------------------------------------------------------------
def test_CI_05_fork_merge_group_or_missing_check_explicit_failure(root: Optional[Path] = None) -> None:
    """CI-05｜注入：fork、merge_group、check 不产生｜期望：明确 FAILURE/BLOCKED。"""
    with _tmp(root) as td:
        # 腿一：check 不产生（required 站零上报）→ 明确 BLOCKED，绝不静默通过
        agg = GateAggregator(required_stations={"1", "2"}, target_sha="a" * 40, environment="test")
        verdict = agg.aggregate()
        _ok(verdict["aggregate_outcome"] == BLOCKED, "零上报必须明确 BLOCKED")
        _ok("denominator_shrinkage" in verdict["reasons"][0], "须点名 denominator_shrinkage")
        _ok(verdict["counts"]["required_missing"] == 2, "缺报数须如实=2")
        _ok(agg.to_github_status(verdict)["conclusion"] == "failure", "必须发布明确 failure")
        # 腿二/三：fork PR head SHA、merge_group 临时 SHA ≠ 目标 head → 原子拒绝
        repo = _make_repo(td, behavioral_commit=False)
        gate = SourceGate(str(repo))
        head = _head(repo)
        fork_sha = ("deadc0de" * 5)[:40]
        merge_group_sha = ("f00dcafe" * 5)[:40]
        for label, foreign in (("fork", fork_sha), ("merge_group", merge_group_sha)):
            exc = _expect_raise(StaleShaError, gate.validate_exact_sha, foreign)
            _ok(exc.detail.get("head_sha") == head,
                f"{label} 的异源 SHA 必须被拒，且证据绑定真实 head")


def test_CI_07_unauthorized_app_same_context_untrusted_blocked(root: Optional[Path] = None) -> None:
    """CI-07｜注入：未授权 App 发布同名 context/旧 details URL｜期望：不可信、阻断。"""
    with _tmp(root) as td:
        now = datetime.now(_UTC)
        manifest = _freeze_manifest(now)
        adapter = bo.SourceGateAdapter(manifest, now=now)
        # 对照：身份与冻结 manifest 一致的自报结果可被消费（自报被忽略但等值）
        ok_result = adapter.adapt(_gate_result(manifest.commit_sha, now - timedelta(hours=1)))
        _ok(ok_result["identity"]["commit_sha"] == manifest.commit_sha,
            "消费的身份必须取冻结 manifest 正源（对照组）")
        # 注入：未授权 App 自报同名 context——形状完全合法但 SHA 是旧的（旧 details URL）
        forged = _gate_result("9" * 40, now - timedelta(hours=1))
        exc = _expect_raise(bo.SourceGateShaMismatch, adapter.adapt, forged)
        _ok("不得跨 SHA 复用" in str(exc) or "cross SHA" in str(exc).lower() or "re-run" in str(exc),
            "冒名/旧 SHA 自报必须判不可信并阻断")
        # 注入：同名 station context 被另一发布源以不同 environment 重发 → 冲突阻断
        sha = "a" * 40
        agg = GateAggregator({"1"}, target_sha=sha, environment="test")
        agg.add(_legacy("1", "PASS", sha, "test"))
        agg.add(_legacy("1", "PASS", sha, "production"))  # 同名异源 context
        verdict = agg.aggregate()
        _ok(verdict["aggregate_outcome"] == BLOCKED and verdict["counts"]["conflicts"] == 1,
            "同名异源 context 必须判冲突并阻断")


def test_CI_08_wenqu_gate_missing_bugscan_green_no_merge(root: Optional[Path] = None) -> None:
    """CI-08｜注入：Wenqu Gate 缺失但 Bugscan 绿｜期望：不合流。"""
    with _tmp(root) as td:
        sha = "a" * 40
        # 站1=Wenqu Gate（源闸）、站2=Bugscan（静态与供应链）：仅站2 上报且绿
        agg = GateAggregator(required_stations={"1", "2"}, target_sha=sha, environment="test")
        agg.add(_legacy("2", "PASS", sha))
        verdict = agg.aggregate()
        _ok(verdict["aggregate_outcome"] == BLOCKED,
            "Wenqu Gate 缺失时 Bugscan 再绿也不得合流（C3 分母缩水）")
        _ok("missing required stations [1]" in verdict["reasons"][0],
            "须点名缺失的 required 站=站1")
        _ok(verdict["counts"]["required_missing"] == 1, "缺报数须=1（仅站1）")
        status = agg.to_github_status(verdict)
        _ok(status["state"] == "failure" and status["conclusion"] == "failure",
            "GitHub 状态必须 failure（不合流）")


def test_CI_09_recursive_aggregate_or_duplicate_publish_rejected(root: Optional[Path] = None) -> None:
    """CI-09｜注入：S7 把 Wenqu Required Gate 当自身输入、重复发布或递归聚合｜期望：schema/DAG 校验拒绝并发布 FAILURE。"""
    with _tmp(root) as td:
        ts = "2026-10-08T00:00:00+00:00"
        # 腿一：schema 拒绝——station-result 携带非法输入引用字段（S7 吃 Required Gate）
        good = bo.build_station_result(
            run_id="ci09run",
            station_id=7,
            attempt_id="att-ci09",
            execution_status="COMPLETED",
            policy_verdict="PASS",
            identity={
                "project_id": "gate-family",
                "commit_sha": "1" * 40,
                "environment": "local",
                "scope_hash": "2" * 64,
                "ruleset_hash": "3" * 64,
                "data_config_hash": "4" * 64,
            },
            tool={"name": "runtime-sentinel", "version": "1"},
            execution={
                "argv_digest": "5" * 64,
                "started_at": ts,
                "ended_at": ts,
                "timeout_s": 60,
                "actual_exit_code": 0,
                "expected_exit_set": [0],
                "assertion_verdict": "PASS",
            },
            coverage={"denominator": 3, "scanned": 3},
            finding_ids=[],
            artifacts=[{"cas_digest": "sha256:" + "6" * 64, "size": 16}],
        )
        bo.validate_station_result(good)  # 对照：合法结果通过
        recursive = dict(good)
        recursive["consumes_wenqu_required_gate"] = True  # S7 递归引用注入
        exc = _expect_raise(bo.StationResultValidationError, bo.validate_station_result, recursive)
        _ok("additional properties" in str(exc), "schema 必须拒绝非法输入引用（additionalProperties=false）")
        # 腿二：递归聚合——聚合输出回灌聚合器（无 station 结构）→ malformed BLOCKED
        sha = "a" * 40
        agg_inner = GateAggregator({"1"}, target_sha=sha, environment="test")
        agg_inner.add(_legacy("1", "PASS", sha))
        aggregate_output = agg_inner.aggregate()
        agg_outer = GateAggregator({"1"}, target_sha=sha, environment="test")
        agg_outer.add(aggregate_output)  # DAG 违规：聚合结果不是站点结果
        verdict = agg_outer.aggregate()
        _ok(verdict["aggregate_outcome"] == BLOCKED and verdict["counts"]["malformed"] == 1,
            "聚合输出不得作为站点结果再入聚合（DAG 校验拒绝）")
        _ok(agg_outer.to_github_status(verdict)["conclusion"] == "failure",
            "拒绝时必须发布 failure 而非静默")
        # 腿三：重复发布不同内容（同站名异证据）→ 冲突 BLOCKED；幂等重发不产生第二绿
        agg_dup = GateAggregator({"1"}, target_sha=sha, environment="test")
        agg_dup.add(_legacy("1", "PASS", sha))
        agg_dup.add(_legacy("1", "PASS", sha))          # 幂等重发：忽略，不双绿
        agg_dup.add(_legacy("1", "FAIL", sha))          # 异内容重发：冲突
        verdict_dup = agg_dup.aggregate()
        _ok(verdict_dup["counts"]["duplicates_ignored"] == 1, "幂等重发只记 duplicate")
        _ok(verdict_dup["aggregate_outcome"] == BLOCKED and verdict_dup["counts"]["conflicts"] == 1,
            "异内容重复发布必须冲突 BLOCKED")


# ---------------------------------------------------------------------------
# 运行器
# ---------------------------------------------------------------------------
_TEST_NAME_RE = re.compile(r"^test_(GATE|MRG|CI)_(\d{2})_")

# 不可实现清单（产品未实现该语义，不硬凑；详见模块 docstring 与交付报告）
NOT_IMPLEMENTABLE: Dict[str, str] = {
    "GATE-09": "N=-1 已被 tests/acceptance.sh（--convergence -1 拒绝）覆盖；"
               "N=0 在 cli/wenqu 是合法『关闭收敛要求』开关而非参数错误、N 超上限无上限校验——注入面后两态无产品语义",
    "GATE-10": "超过 N+1 轮 BLOCKED 等人工裁定：仓内无可执行的轮数上限/人工裁定实现（仅 dashboard 文案）",
    "GATE-11": "同命令换 S 标签不计异源轮：无可执行的异源轮来源追踪/命令身份判定实现",
    "CI-06": "CODEOWNERS 存在但 ruleset 未强制 → doctor ERROR：hardening-doctor.sh 体检 launchd/哨兵/CI 卡死，"
             "无 CODEOWNERS/ruleset 校验语义",
}


def _collect_tests() -> List[Tuple[str, Callable[..., None]]]:
    return [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn) and _TEST_NAME_RE.match(name)
    ]


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    json_out: Optional[str] = None
    if "--json" in argv:
        json_out = argv[argv.index("--json") + 1]
    tests = _collect_tests()
    print("=" * 72)
    print("§20 GATE/MRG/CI 族专属验收测试（实现 20 条；跳过 4 条见 NOT_IMPLEMENTABLE）")
    for tid, reason in NOT_IMPLEMENTABLE.items():
        print(f"  SKIP {tid}: {reason}")
    print("-" * 72)
    records: List[Dict[str, Any]] = []
    failed: List[str] = []
    for name, fn in tests:
        match = _TEST_NAME_RE.match(name)
        assert match is not None
        test_id = f"{match.group(1)}-{match.group(2)}"
        with tempfile.TemporaryDirectory(prefix="ac-gate-family-") as td:
            try:
                fn(Path(td))
                records.append({"id": test_id, "test": name, "passed": True})
                print(f"  PASS {test_id}  {name}")
            except Exception as exc:  # noqa: BLE001
                failed.append(name)
                records.append({"id": test_id, "test": name, "passed": False})
                print(f"  FAIL {test_id}  {name}: {type(exc).__name__}: {exc}")
    print("-" * 72)
    print(f"结果: {len(records) - len(failed)}/{len(records)} passed"
          f"{'' if not failed else '；失败: ' + ', '.join(failed)}")
    if json_out is not None:
        out_path = Path(json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"逐 ID 结果已写: {out_path}")
    print("=" * 72)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——GATE/MRG/CI 族（test_ac_gate_family）。

覆盖 Codex 方案 §20.1/§20.5 中 GATE-01~12、MRG-01~07、CI-05/06/07/08/09
共 24 条：每条按「注入→期望」逐字对齐方案表格，真实构造场景（真实 git
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
                                      CI-07/09、MRG-06b）+
                                      validate_convergence_rounds /
                                      ConvergenceTracker（GATE-09/10/11：
                                      N 值域参数错误、N+1 轮熔断 BLOCKED
                                      等人工裁定、同命令换 S 标签不计
                                      异源轮）
- system/wenqu_core/gate_aggregator.py
                                      C1~C5 硬约束 + GitHub 状态映射
                                      （MRG-01~04、CI-05a/08）
- system/daemons/auto-merge.sh        P0 封存 stub（MRG-01 执行器腿：不合流）
- system/bin/codeowners-ruleset-doctor.py
                                      CI-06 诊断件：CODEOWNERS 存在但
                                      ruleset 未强制 review → doctor ERROR
                                      （本地 fixture 模拟未强制/已强制两态）

本地等价映射说明（CI 族依赖真实 GitHub API 的部分）：
- CI-05 fork/merge_group → SourceGate.validate_exact_sha 对非目标 head 的
  SHA（fork PR SHA、merge_group 临时 SHA）一律 StaleShaError（T-02 旧/异
  SHA 绿灯拒合）；「check 不产生」→ GateAggregator required 站缺失 =
  denominator_shrinkage → BLOCKED（无 SKIP/无静默通过语义）。
- CI-06 ruleset 证据 → GitHub REST /rulesets（或老式 /branches/*/protection）
  同构 JSON fixture（evidence/08 回读件形状），不依赖网络与真实远端。
- CI-07 未授权 App 自报同名 context → SourceGateAdapter 身份三源一律取
  冻结 manifest 正源、绝不采信 gate_result 自报身份：自报 SHA 与冻结
  不符 → SourceGateShaMismatch（不可信、阻断）。
- CI-08 Wenqu Gate 缺失但 Bugscan 绿 → 站1（源闸）未上报、站2 绿 →
  GateAggregator denominator_shrinkage BLOCKED → GitHub failure（不合流）。
- CI-09 S7 递归聚合/重复发布 → station-result-v2 additionalProperties
  schema 拒绝 + 聚合输出回灌聚合器缺 station_id 结构 → malformed BLOCKED。

GATE-09 语义边界（与 cli/wenqu 的显式区分）：cli/wenqu verify
--convergence 0 是查询侧「关闭收敛要求」开关；进入 bugscan 编排契约的 N
（BugscanPlanner.plan/ConvergenceTracker）0 与 -1、超上限一律参数错误
（ConvergenceRoundsError）——编排器域内不存在免检收敛。

独立运行：python3 system/tests/test_ac_gate_family.py [--json OUT.json]
exit 0 = 全部用例绿；--json 额外输出逐 ID 结果数组 {id, test, passed}。
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import replace
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
CODEOWNERS_DOCTOR = SYSTEM_DIR / "bin" / "codeowners-ruleset-doctor.py"

_UTC = timezone.utc


def _load_doctor():
    """按路径加载 CI-06 诊断件（bin 脚本名含连字符，importlib 显式装载）。"""
    spec = importlib.util.spec_from_file_location(
        "wenqu_codeowners_ruleset_doctor", str(CODEOWNERS_DOCTOR)
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # __main__ 守卫内才跑 CLI，装载无副作用
    return module


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


def test_GATE_09_convergence_rounds_domain_minus1_zero_over_cap_rejected(root: Optional[Path] = None) -> None:
    """GATE-09｜注入：N=-1/0/超上限｜期望：参数错误。

    编排器入口（validate_convergence_rounds / BugscanPlanner.plan）值域检查：
    -1 与 0（编排器域内非「关闭收敛」开关——那是 cli/wenqu verify
    --convergence 0 的查询侧语义）、超过最高档上限（3）、非 int/布尔一律
    ConvergenceRoundsError 拒绝开跑，绝不静默钳制。
    """
    # 注入逐值：-1/0/4（超上限）→ 参数错误；对照组 1/2/3 通过并原样返回
    for bad in (-1, 0, 4, 99, True, False, "2", 2.0, None):
        exc = _expect_raise(bo.ConvergenceRoundsError, bo.validate_convergence_rounds, bad)
        _ok("参数错误" in str(exc) or "GATE-09" in str(exc),
            f"N={bad!r} 报错须点名参数错误/GATE-09，got {exc}")
    for good in (1, 2, 3):
        _ok(bo.validate_convergence_rounds(good) == good,
            f"合法 N={good} 应原样通过（边界 3=INCIDENT 契约值）")
    # 档位语义：低于生效档契约 N = 弱化收敛环 → 参数错误；更严（≤上限）通过
    _ok(bo.validate_convergence_rounds(1, lane="FAST") == 1, "FAST N=1 契约值通过")
    exc = _expect_raise(bo.ConvergenceRoundsError, bo.validate_convergence_rounds, 1, lane="STANDARD")
    _ok("低于" in str(exc) or "契约" in str(exc), "低于档位契约须点名弱化语义")
    _ok(bo.validate_convergence_rounds(3, lane="STANDARD") == 3, "STANDARD 收紧到 3 合法（≤上限）")
    _expect_raise(bo.ConvergenceRoundsError, bo.validate_convergence_rounds, 4, lane="INCIDENT")
    _expect_raise(bo.BugscanPlanError, bo.validate_convergence_rounds, 1, lane="NOPE")
    # 编排器 planner 入口：convergence_rounds 覆盖参数同值域
    planner = bo.BugscanPlanner()
    for bad in (-1, 0, 4):
        _expect_raise(bo.ConvergenceRoundsError, planner.plan, "FAST", convergence_rounds=bad)
    _expect_raise(bo.ConvergenceRoundsError, planner.plan, "STANDARD", convergence_rounds=1)
    plan = planner.plan("STANDARD", convergence_rounds=3)
    _ok(plan.convergence_rounds == 3, "合法覆盖 N=3 应落进计划")
    _ok(planner.plan("FAST").convergence_rounds == 1 and
        planner.plan("INCIDENT").convergence_rounds == 3,
        "未覆盖时取档位表值（FAST=1/INCIDENT=3 回归对照）")
    # 对抗负例：伪造 plan（N=0）绕过 planner 直构 tracker → 构造期同样拒绝
    forged = replace(planner.plan("FAST"), convergence_rounds=0)
    exc2 = _expect_raise(bo.ConvergenceRoundsError, bo.ConvergenceTracker, forged)
    _ok("N=0" in str(exc2) or ">= 1" in str(exc2),
        "伪造 plan 的 N=0 须在 tracker 构造期被拒（双保险）")


def test_GATE_10_round_cap_n_plus_1_blocks_awaiting_human_adjudication(root: Optional[Path] = None) -> None:
    """GATE-10｜注入：超过 N+1｜期望：BLOCKED 等人工裁定（非自动重试）。"""
    planner = bo.BugscanPlanner()
    # FAST：N=1，熔断预算 N+1=2。轮1 有发现、轮2 仍有发现 → 跑满预算未收敛
    tracker = bo.ConvergenceTracker(planner.plan("FAST"))
    tracker.record_round(argv=["scanner-a"], source_label="S1", new_findings=1)
    status = tracker.record_round(argv=["scanner-b"], source_label="S1", new_findings=2)
    _ok(status["state"] == "BLOCKED", f"跑满 N+1 未收敛须 BLOCKED，got {status['state']}")
    waiting = status["awaiting_human_adjudication"]
    _ok(waiting is not None and waiting["required"] is True,
        "BLOCKED 必须携带『等待人工裁定』记录")
    _ok(waiting["reason"] == "round_cap_exceeded" and waiting["n"] == 1
        and waiting["round_cap"] == 2,
        "等待记录须落 n/round_cap/reason 证据")
    _ok("人工裁定" in waiting["note"], "等待记录须声明转人工、非自动重试")
    # 非自动重试：BLOCKED 后任何追加轮（含换命令/换标签/同命令）一律拒绝
    for kwargs in (
        {"argv": ["scanner-c"], "source_label": "S1", "new_findings": 0},
        {"argv": ["scanner-a"], "source_label": "S9", "new_findings": 0},  # 同命令重跑
    ):
        exc = _expect_raise(bo.ConvergenceRoundCapExceeded, tracker.record_round, **kwargs)
        _ok("人工裁定" in str(exc) and "禁止自动重试" in str(exc),
            "BLOCKED 态追加轮须显式拒绝并指向人工裁定唯一通道")
    # 人工裁定腿一：STOP → 终态；再追加/再裁定均拒
    stopped = tracker.adjudicate("STOP", approver="risk-owner")
    _ok(stopped["state"] == "STOPPED", "裁定 STOP 须转终态 STOPPED")
    _ok(stopped["adjudications"][0]["approver"] == "risk-owner", "裁定须留痕裁定人")
    _expect_raise(bo.ConvergenceRoundCapExceeded, tracker.record_round,
                  argv=["scanner-d"], source_label="S1", new_findings=0)
    _expect_raise(bo.ConvergenceRoundCapExceeded, tracker.adjudicate, "CONTINUE", approver="x")
    # 人工裁定腿二：CONTINUE → 恰好 +1 轮预算回到 RUNNING；补一轮零发现即收敛
    tracker2 = bo.ConvergenceTracker(planner.plan("FAST"))
    tracker2.record_round(argv=["scanner-a"], source_label="S1", new_findings=1)
    tracker2.record_round(argv=["scanner-b"], source_label="S1", new_findings=1)
    resumed = tracker2.adjudicate("continue", approver="risk-owner")
    _ok(resumed["state"] == "RUNNING" and resumed["round_cap"] == 3,
        "CONTINUE 须回到 RUNNING 且预算恰好 +1（2→3），不放大不自动续")
    converged = tracker2.record_round(argv=["scanner-c"], source_label="S1", new_findings=0)
    _ok(converged["state"] == "CONVERGED", "放行轮零发现应收敛（最近 N=1 轮零新发现）")
    _expect_raise(bo.ConvergenceRoundCapExceeded, tracker2.record_round,
                  argv=["scanner-e"], source_label="S1", new_findings=0,
                  now=datetime.now(_UTC))  # 收敛后不再接受轮次——新发现须新 run
    # 对抗负例：裁定本体不可伪造/不可匿名/无第三走向
    tracker3 = bo.ConvergenceTracker(planner.plan("FAST"))
    tracker3.record_round(argv=["a"], source_label="S1", new_findings=1)
    tracker3.record_round(argv=["b"], source_label="S1", new_findings=1)
    _expect_raise(ValueError, tracker3.adjudicate, "MAYBE", approver="x")
    _expect_raise(ValueError, tracker3.adjudicate, "CONTINUE", approver="  ")
    _expect_raise(ValueError, tracker3.adjudicate, "CONTINUE", approver="")
    _expect_raise(bo.ConvergenceRoundCapExceeded, bo.ConvergenceTracker(planner.plan("FAST")).adjudicate,
                  "CONTINUE", approver="x")  # RUNNING 态不可裁定（须先熔断）
    # 对照：恰在最后一轮收敛则不熔断（A 有发现、B/C 零发现 → N=2 窗口干净）
    tracker4 = bo.ConvergenceTracker(planner.plan("STANDARD"))
    tracker4.record_round(argv=["a"], source_label="S1", new_findings=1)
    tracker4.record_round(argv=["b"], source_label="S1", new_findings=0)
    final = tracker4.record_round(argv=["c"], source_label="S1", new_findings=0)
    _ok(final["state"] == "CONVERGED" and final["heterogeneous_rounds"] == 3,
        "第 N+1 轮达成收敛窗口应判 CONVERGED 而非熔断")


def test_GATE_11_same_command_relabel_not_new_heterogeneous_round(root: Optional[Path] = None) -> None:
    """GATE-11｜注入：同命令换 S 标签｜期望：不计异源轮。"""
    planner = bo.BugscanPlanner()
    tracker = bo.ConvergenceTracker(planner.plan("STANDARD"))  # N=2
    # 轮1：命令 A（label S1，有发现）→ 异源轮 1
    s1 = tracker.record_round(argv=["python3", "scan.py"], source_label="S1", new_findings=5)
    _ok(s1["heterogeneous_rounds"] == 1 and s1["state"] == "RUNNING", "首轮计异源 1")
    # 注入：同命令换 S 标签（S1→S2）→ 不计新异源轮，只记 relabel 重复
    s2 = tracker.record_round(argv=["python3", "scan.py"], source_label="S2", new_findings=0)
    _ok(s2["heterogeneous_rounds"] == 1,
        f"同命令换标签不得新增异源轮，got {s2['heterogeneous_rounds']}")
    _ok(s2["duplicate_rounds_ignored"] == 1 and s2["relabel_only_duplicates"] == 1,
        "换标签重复须落 duplicate+relabel 双计数")
    _ok(s2["total_rounds_recorded"] == 2, "提交总数如实记账（审计不丢）")
    # 注入变体：解释器绝对路径前缀（规范化归一）+ 空白/空串扰动 → 仍同命令身份
    s3 = tracker.record_round(argv=["/usr/bin/python3", "scan.py"], source_label="S3", new_findings=0)
    _ok(s3["heterogeneous_rounds"] == 1, "argv 规范化摘要须把路径前缀差异归一为同命令")
    s3b = tracker.record_round(argv=["  python3 ", "scan.py", ""], source_label="S1", new_findings=0)
    _ok(s3b["heterogeneous_rounds"] == 1 and s3b["duplicate_rounds_ignored"] == 3,
        "空白/空串扰动不改变命令身份")
    # 对照：命令身份真变（不同 argv）→ 计新异源轮；即使沿用同一 S 标签
    s4 = tracker.record_round(argv=["python3", "other.py"], source_label="S1", new_findings=0)
    _ok(s4["heterogeneous_rounds"] == 2,
        "不同命令（标签相同）必须计新异源轮——标签不是身份")
    # 去重与收敛判据联动：重复轮不推进窗口；真异源轮 B/C 零发现才收敛
    s5 = tracker.record_round(argv=["scanner-x"], source_label="S9", new_findings=0)
    _ok(s5["state"] == "CONVERGED" and s5["heterogeneous_rounds"] == 3,
        "最近 N=2 个异源轮（other.py/scanner-x）零发现须收敛")
    _ok(s5["total_rounds_recorded"] == 6 and s5["duplicate_rounds_ignored"] == 3,
        "重复轮（含换标签）绝不进入收敛窗口（GATE-11 反向：防标签刷轮）")
    # 对抗负例：刷轮攻击——同命令反复换标签无法把异源轮数刷到熔断或收敛
    tracker2 = bo.ConvergenceTracker(planner.plan("FAST"))  # N=1, cap 2
    tracker2.record_round(argv=["same-tool"], source_label="S1", new_findings=9)
    for i in range(5):  # 5 次换标签重跑同一命令
        st = tracker2.record_round(argv=["same-tool"], source_label=f"S{i+2}", new_findings=9)
        _ok(st["heterogeneous_rounds"] == 1,
            f"第 {i+2} 次换标签重跑仍不得计异源轮")
        _ok(st["state"] == "RUNNING", "重复轮既不熔断也不收敛（未产生新异源证据）")
    # argv 身份校验负例：命令字符串/空 argv/非 str 元素 → 拒绝
    for bad_argv in ("python3 scan.py", [], ["a", 3], ()):
        _expect_raise(ValueError, bo.normalized_argv_digest, bad_argv)


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


def test_CI_06_codeowners_present_ruleset_not_enforced_doctor_error(root: Optional[Path] = None) -> None:
    """CI-06｜注入：CODEOWNERS 文件存在但 ruleset 未强制｜期望：doctor ERROR。"""
    with _tmp(root) as td:
        doctor = _load_doctor()
        repo = td / "repo"
        (repo / ".github").mkdir(parents=True)
        (repo / ".github" / "CODEOWNERS").write_text("* @owners/team\n", encoding="utf-8")

        def _ruleset(enforcement="active", branch="refs/heads/main", count=1,
                     code_owner=False, has_pr_rule=True):
            rules = ([{"type": "pull_request", "parameters": {
                "required_approving_review_count": count,
                "require_code_owner_review": code_owner}}]
                if has_pr_rule else
                [{"type": "non_fast_forward", "parameters": {}}])
            conditions = ({"ref_name": {"include": [branch], "exclude": []}}
                          if branch is not None else None)
            rs = {"id": 1, "name": "fixture-ruleset", "enforcement": enforcement,
                  "rules": rules}
            if conditions is not None:
                rs["conditions"] = conditions
            return [rs]

        # 状态一（注入正例）：CODEOWNERS 存在 + 零 ruleset（镜像本仓真实回读
        # evidence/08 rulesets-count=0）→ doctor ERROR
        report = doctor.check(repo, rulesets=[], default_branch="main")
        _ok(report["status"] == "ERROR", f"零 ruleset 须 ERROR，got {report['status']}")
        _ok(report["codeowners_found"] and report["codeowners_found"][0].endswith("CODEOWNERS"),
            "须定位到 CODEOWNERS 文件")
        _ok("NO active ruleset enforces review" in report["findings"][0],
            "finding 须点名 CODEOWNERS 存在但 ruleset 未强制")
        # 状态二（对照）：active ruleset 对默认分支强制 review → PASS
        report_ok = doctor.check(repo, rulesets=_ruleset(), default_branch="main")
        _ok(report_ok["status"] == "PASS" and report_ok["review_enforced_by"]["kind"] == "ruleset",
            "active pull_request 强制应 PASS 并记强制证据")
        # 对抗负例矩阵（全部仍是「未强制」→ ERROR）：
        not_enforced = {
            "evaluate 干跑不拦": _ruleset(enforcement="evaluate"),
            "disabled": _ruleset(enforcement="disabled"),
            "无 pull_request 规则": _ruleset(has_pr_rule=False),
            "批准数 0 且不要求 code owner 审": _ruleset(count=0, code_owner=False),
            "只覆盖 release/* 分支": _ruleset(branch="refs/heads/release/*"),
            "排除默认分支": lambda: [{
                **_ruleset()[0],
                "conditions": {"ref_name": {"include": ["refs/heads/*"],
                                            "exclude": ["~DEFAULT_BRANCH"]}}}],
        }
        for label, fixture in not_enforced.items():
            rulesets = fixture() if callable(fixture) else fixture
            rep = doctor.check(repo, rulesets=rulesets, default_branch="main")
            _ok(rep["status"] == "ERROR", f"{label} 必须判未强制 ERROR")
        # 合法强制变体（对照）：require_code_owner_review / ~DEFAULT_BRANCH /
        # 老式分支保护 required_pull_request_reviews
        _ok(doctor.check(repo, rulesets=_ruleset(count=0, code_owner=True))["status"] == "PASS",
            "require_code_owner_review=true 是合法强制")
        _ok(doctor.check(repo, rulesets=_ruleset(branch="~DEFAULT_BRANCH"))["status"] == "PASS",
            "~DEFAULT_BRANCH 专属 token 应命中默认分支")
        _ok(doctor.check(repo, rulesets=[],
                         branch_protection={"required_pull_request_reviews":
                                            {"required_approving_review_count": 1}})["status"] == "PASS",
            "老式分支保护批准数>=1 是等价强制")
        _ok(doctor.check(repo, rulesets=[],
                         branch_protection={"required_pull_request_reviews":
                                            {"required_approving_review_count": 0}})["status"] == "ERROR",
            "老式分支保护批准数 0 仍判未强制")
        # 反向对照：无 CODEOWNERS → 不适用，绝不 ERROR
        bare = td / "bare-repo"
        bare.mkdir()
        _ok(doctor.check(bare, rulesets=[], default_branch="main")["status"] == "PASS",
            "无 CODEOWNERS 时本检查不适用（PASS），不得借故 ERROR")
        # CLI 腿：两种 fixture 状态各跑真脚本，断言退出码与 --json 报告
        unf = td / "unforced.json"
        unf.write_text(json.dumps([]), encoding="utf-8")  # 空规则集
        enf = td / "enforced.json"
        enf.write_text(json.dumps(_ruleset()), encoding="utf-8")
        out_unf = td / "report-unforced.json"
        out_enf = td / "report-enforced.json"
        proc_bad = subprocess.run(
            [sys.executable, str(CODEOWNERS_DOCTOR), "--repo", str(repo),
             "--ruleset-file", str(unf), "--json", str(out_unf)],
            capture_output=True, text=True, check=False,
        )
        _ok(proc_bad.returncode == 1, f"未强制状态 doctor 退出码须 1，got {proc_bad.returncode}")
        _ok(json.loads(out_unf.read_text(encoding="utf-8"))["status"] == "ERROR",
            "--json 工件须落 ERROR 报告")
        proc_good = subprocess.run(
            [sys.executable, str(CODEOWNERS_DOCTOR), "--repo", str(repo),
             "--ruleset-file", str(enf), "--json", str(out_enf)],
            capture_output=True, text=True, check=False,
        )
        _ok(proc_good.returncode == 0, f"已强制状态退出码须 0，got {proc_good.returncode}")
        _ok(json.loads(out_enf.read_text(encoding="utf-8"))["status"] == "PASS",
            "--json 工件须落 PASS 报告")


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

# 不可实现清单（产品未实现该语义，不硬凑；详见模块 docstring 与交付报告）。
# 2026-10-08 wave6/p1f-gate：GATE-09/10/11、CI-06 已由 bugscan_orchestrator
# 收敛环契约与 system/bin/codeowners-ruleset-doctor.py 落地为本文件真实用例，
# 登记清零；此后新增登记仅限「产品确无对应语义」的 ID。
NOT_IMPLEMENTABLE: Dict[str, str] = {}


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
    print(f"§20 GATE/MRG/CI 族专属验收测试（实现 {len(tests)} 条"
          f"{'；跳过 ' + str(len(NOT_IMPLEMENTABLE)) + ' 条见 NOT_IMPLEMENTABLE' if NOT_IMPLEMENTABLE else '；NOT_IMPLEMENTABLE 登记已清零'}）")
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

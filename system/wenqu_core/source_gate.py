"""source_gate.py——W3A 源闸基础件（Codex 方案 §12.2）。

职责：在合流/发布判定之前，对「源」执行可审计的快速验证门：
1. fresh_fetch()        git fetch origin 后验证 base ref 存在（不存在=ERROR 非 SKIP）；
2. merge_base_diff()    git merge-base + git diff --name-only 得到变更文件列表；
3. affected_scope()     由变更文件计算受影响测试范围（affected vs full）；
4. execute_gate()       基于 TrustedRunner 执行测试（affected 或 full），
                        产出 source-gate-result.json（统一双轴结果 + 统一退出码）；
5. validate_exact_sha() 验证 check 的 commit SHA 等于目标 head SHA
                        （威胁 T-02：旧 SHA 绿灯 → stale 拒合）。

硬约束（违反任一=实现缺陷）：
- 任一 git 命令失败必须传播：非零退出码/超时/可执行缺失一律 ERROR（超时记 TIMEOUT），
  禁止把失败命令的空 stdout 当作「无变化」（威胁 T-07：空输出=ERROR 非零+断路）。
  例外仅一处：merge-base == head 时 diff 为空是真实的零变更。
- 缺 node_modules/测试器/凭据等前置条件是 ERROR，不是 SKIP；本模块不存在 SKIP 语义
  （统一结果双轴 execution_status × policy_verdict 均无 SKIP 枚举，见契约 §2）。
- 「无测试」仅在纯非行为变更（或零变更）时记 COMPLETED+NOT_APPLICABLE；
  存在行为变更时必须跑测试：影响图未知/不可解析 → 升级 full；
  需要全量却无全量套件 → BLOCKED（exit 3），绝不静默放行。
- affected 与 full 是两道不同的门：结果 gate_scope 字段区分两者；
  affected PASS 只覆盖受影响面，不等于 full PASS，下游不得混用。
- 起跑后 head 移动 → 本次全部证据立即失效（契约 §8 不变量 3），记 StaleShaError。
- git 元数据命令经 subprocess.run(list, shell=False) 直接执行（需要 stdout 内容做解析），
  退出码一律取真实 returncode，每次调用落入结果 git_calls 证据清单（含输出哈希）；
  测试命令一律经 TrustedRunner 执行——不可伪造退出码的唯一来源（ADR-001/002）。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:  # 包内正则导入（wenqu_core.source_gate）
    from .runner import EvidenceStore, TrustedRunner
except ImportError:  # 顶层直接加载兜底（如 python3 wenqu_core/source_gate.py）
    from runner import EvidenceStore, TrustedRunner

__all__ = [
    "SourceGate",
    "SourceGateError",
    "StaleShaError",
    "ScopeDecision",
    "EXIT_PASS",
    "EXIT_FAIL",
    "EXIT_ERROR",
    "EXIT_BLOCKED",
    "EXIT_TIMEOUT",
    "DEFAULT_NON_BEHAVIORAL_PATTERNS",
]

# ---------------------------------------------------------------------------
# 统一退出码（契约 §7 的子集；源闸不产生 CONDITIONAL=4）
# ---------------------------------------------------------------------------
EXIT_PASS = 0  # 执行完成且策略 PASS / NOT_APPLICABLE
EXIT_FAIL = 1  # 执行完成但有 FAIL（测试失败）
EXIT_ERROR = 2  # 工具、输入、网络、格式或证据 ERROR
EXIT_BLOCKED = 3  # 权限、审批或依赖 BLOCKED
EXIT_TIMEOUT = 124  # TIMEOUT

# 40 位（SHA-1）或 64 位（SHA-256）小写十六进制 commit SHA
_HEX_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")

# 纯非行为变更的保守默认分类：仅文档/许可/编辑器元数据。
# 刻意不含 *.txt/*.json/配置文件——数据与配置可能影响行为，保守归入行为面
# （触发测试）；接入方可通过 non_behavioral_patterns 参数按仓收紧或放宽。
DEFAULT_NON_BEHAVIORAL_PATTERNS: Tuple[str, ...] = (
    "*.md",
    "*.markdown",
    "*.rst",
    "*.adoc",
    "docs/**",
    "doc/**",
    "LICENSE*",
    "COPYING*",
    ".gitignore",
    ".editorconfig",
    ".mailmap",
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex_sha(value: str) -> bool:
    return bool(_HEX_SHA_RE.fullmatch(value.strip().lower()))


def _dedupe_commands(
    commands: Iterable[Sequence[str]],
) -> List[Tuple[str, ...]]:
    """按 argv 元组去重并保持首次出现顺序。"""
    seen: set = set()
    ordered: List[Tuple[str, ...]] = []
    for command in commands:
        key = tuple(command)
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


@dataclass(frozen=True)
class ScopeDecision:
    """affected_scope() 的判定结果。

    mode 三值（affected 与 full 是两道不同的门）：
    - "none"     纯非行为变更（或零变更）——源闸测试 NOT_APPLICABLE；
    - "affected" 影响图可完整解析——只跑受影响测试命令；
    - "full"     影响图缺失/不可解析/映射为空——升级全量（escalated=True）。
    """

    mode: str
    reason: str
    escalated: bool = False
    selected_commands: Tuple[Tuple[str, ...], ...] = ()
    behavioral_files: Tuple[str, ...] = ()
    non_behavioral_files: Tuple[str, ...] = ()
    unmatched_files: Tuple[str, ...] = ()

    @property
    def requires_tests(self) -> bool:
        return self.mode in ("affected", "full")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "reason": self.reason,
            "escalated": self.escalated,
            "selected_commands": [list(command) for command in self.selected_commands],
            "behavioral_files": list(self.behavioral_files),
            "non_behavioral_files": list(self.non_behavioral_files),
            "unmatched_files": list(self.unmatched_files),
        }


class SourceGateError(RuntimeError):
    """源闸的可预期失败（ERROR / BLOCKED / TIMEOUT）。

    execution_status 与 exit_code 遵循统一双轴与统一退出码表：
    ERROR→2，BLOCKED→3，TIMEOUT→124。任何失败都以非零退出码传播，
    本模块没有 SKIP 语义。
    """

    def __init__(
        self,
        message: str,
        *,
        execution_status: str = "ERROR",
        exit_code: int = EXIT_ERROR,
        detail: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.execution_status = execution_status
        self.exit_code = exit_code
        self.detail: Dict[str, Any] = dict(detail or {})


class StaleShaError(SourceGateError):
    """check 记录的 commit SHA ≠ 目标 head SHA（T-02：旧 SHA 绿灯，拒合）。"""

    def __init__(
        self, message: str, *, detail: Optional[Mapping[str, Any]] = None
    ) -> None:
        super().__init__(
            message, execution_status="ERROR", exit_code=EXIT_ERROR, detail=detail
        )


class SourceGate:
    """W3A 源闸：fetch → merge-base diff → 范围判定 → TrustedRunner 执行 → 结果工件。

    用法（最小）::

        gate = SourceGate(
            "/path/to/repo",
            impact_graph={"src/*.py": [["pytest", "-q", "tests/"]]},
            full_test_commands=[["pytest", "-q"]],
            required_paths=["node_modules"],   # 缺失=ERROR 非 SKIP（按需配置）
        )
        result = gate.execute_gate()           # 产出 source-gate-result.json
        sys.exit(result["exit_code"])

    工件位置注意：结果默认写在仓根 source-gate-result.json（CI 拾取惯例）。
    闸自身的 diff 是树对树（merge-base vs head），不受该未跟踪文件影响；但若
    工作流用 `git add -A` 提交，工件会混入提交并在下次运行被当作行为变更
    （保守升级测试范围）。不希望污染工作树时：用 result_path 指向仓外路径，
    或将工件加入 .gitignore。
    """

    def __init__(
        self,
        repo_path: str,
        runner: Optional[TrustedRunner] = None,
        *,
        remote: str = "origin",
        base_ref: str = "origin/main",
        head_ref: str = "HEAD",
        impact_graph: Optional[Mapping[str, Sequence[Sequence[str]]]] = None,
        full_test_commands: Optional[Sequence[Sequence[str]]] = None,
        non_behavioral_patterns: Sequence[str] = DEFAULT_NON_BEHAVIORAL_PATTERNS,
        required_paths: Sequence[str] = (),
        git_timeout: float = 120.0,
        test_timeout: Optional[float] = None,
        result_path: Optional[str] = None,
        evidence_store: Optional[EvidenceStore] = None,
    ) -> None:
        repo = Path(repo_path)
        if not repo.is_dir():
            raise SourceGateError(f"repo_path is not a directory: {repo_path}")
        if not remote:
            raise SourceGateError("remote must be a non-empty string")
        if not base_ref or not head_ref:
            raise SourceGateError("base_ref/head_ref must be non-empty")
        if git_timeout <= 0:
            raise SourceGateError("git_timeout must be positive")
        if test_timeout is not None and test_timeout <= 0:
            raise SourceGateError("test_timeout must be positive when provided")
        if impact_graph is not None:
            for pattern, commands in impact_graph.items():
                self._validate_commands(commands, label=f"impact_graph[{pattern!r}]")
        if full_test_commands is not None:
            self._validate_commands(full_test_commands, label="full_test_commands")

        self._repo = repo
        self._runner = runner if runner is not None else TrustedRunner(
            default_cwd=str(repo), timeout=test_timeout
        )
        if not isinstance(self._runner, TrustedRunner):
            raise TypeError(
                "runner must be a TrustedRunner instance "
                "(unforgeable exit-code source, ADR-001/002)"
            )
        self._remote = remote
        self._base_ref = base_ref
        self._head_ref = head_ref
        self._impact_graph: Optional[Dict[str, List[Tuple[str, ...]]]] = (
            {
                pattern: [tuple(command) for command in commands]
                for pattern, commands in impact_graph.items()
            }
            if impact_graph is not None
            else None
        )
        self._full_test_commands: List[Tuple[str, ...]] = (
            [tuple(command) for command in full_test_commands]
            if full_test_commands is not None
            else []
        )
        self._non_behavioral_patterns = tuple(non_behavioral_patterns)
        self._required_paths = tuple(required_paths)
        self._git_timeout = git_timeout
        self._evidence_store = evidence_store

        if result_path is None:
            resolved = repo / "source-gate-result.json"
        else:
            candidate = Path(result_path)
            resolved = candidate if candidate.is_absolute() else repo / candidate
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self._result_path = resolved

        self._git_calls: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 内部：命令形状校验 / git 执行（失败必须传播）
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_commands(commands: Sequence[Sequence[str]], *, label: str) -> None:
        if isinstance(commands, (str, bytes)):
            raise SourceGateError(
                f"{label} must be a sequence of argv lists, not a command string"
            )
        for index, command in enumerate(commands):
            if isinstance(command, (str, bytes)) or not command:
                raise SourceGateError(
                    f"{label}[{index}] must be a non-empty argv list of strings"
                )
            for position, item in enumerate(command):
                if not isinstance(item, str):
                    raise SourceGateError(
                        f"{label}[{index}][{position}] must be str, "
                        f"got {type(item).__name__}"
                    )

    def _record_git_call(self, entry: Dict[str, Any]) -> None:
        self._git_calls.append(entry)

    def _git(self, args: Sequence[str], *, purpose: str) -> Tuple[int, str, str]:
        """执行 git 子命令；任何失败以 SourceGateError 传播（绝不当 SKIP/无变化）。

        - 可执行缺失 / 启动失败      → ERROR(2)
        - 超时                       → TIMEOUT(124)
        - 非零退出码                 → ERROR(2)，信息含 purpose 与 argv 便于审计
        stdout/stderr 只落 sha256 摘要进 git_calls（不落原文，防日志膨胀/泄漏）；
        返回值给出解码后的 stdout/stderr 供调用方解析。
        """
        argv = ["git", *args]
        started = time.time()
        try:
            completed = subprocess.run(
                argv,
                cwd=str(self._repo),
                shell=False,
                capture_output=True,
                timeout=self._git_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self._record_git_call(
                {
                    "purpose": purpose,
                    "argv": argv,
                    "exit_code": None,
                    "stdout_sha256": _sha256_hex(b""),
                    "stderr_sha256": _sha256_hex(b""),
                    "timed_out": True,
                    "timestamp": started,
                }
            )
            raise SourceGateError(
                f"git {purpose} timed out after {self._git_timeout}s "
                "(timeout must propagate; empty output is NOT 'no changes')",
                execution_status="TIMEOUT",
                exit_code=EXIT_TIMEOUT,
                detail={"purpose": purpose, "argv": argv},
            ) from None
        except FileNotFoundError:
            self._record_git_call(
                {
                    "purpose": purpose,
                    "argv": argv,
                    "exit_code": None,
                    "stdout_sha256": _sha256_hex(b""),
                    "stderr_sha256": _sha256_hex(b""),
                    "timed_out": False,
                    "timestamp": started,
                    "error": "git executable not found",
                }
            )
            raise SourceGateError(
                "git executable not found on PATH (ERROR, not SKIP)",
                detail={"purpose": purpose, "argv": argv},
            ) from None
        except OSError as exc:
            self._record_git_call(
                {
                    "purpose": purpose,
                    "argv": argv,
                    "exit_code": None,
                    "stdout_sha256": _sha256_hex(b""),
                    "stderr_sha256": _sha256_hex(b""),
                    "timed_out": False,
                    "timestamp": started,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            raise SourceGateError(
                f"git {purpose} failed to start: {type(exc).__name__}: {exc}",
                detail={"purpose": purpose, "argv": argv},
            ) from None

        stdout_text = completed.stdout.decode("utf-8", errors="replace")
        stderr_text = completed.stderr.decode("utf-8", errors="replace")
        self._record_git_call(
            {
                "purpose": purpose,
                "argv": argv,
                "exit_code": completed.returncode,
                "stdout_sha256": _sha256_hex(completed.stdout),
                "stderr_sha256": _sha256_hex(completed.stderr),
                "timed_out": False,
                "timestamp": started,
            }
        )
        if completed.returncode != 0:
            raise SourceGateError(
                f"git {purpose} failed with exit code {completed.returncode} "
                "(failure must propagate; empty stdout is NOT 'no changes')",
                detail={
                    "purpose": purpose,
                    "argv": argv,
                    "exit_code": completed.returncode,
                },
            )
        return completed.returncode, stdout_text, stderr_text

    def _resolve_commitish(self, ref: str, *, purpose: str) -> str:
        """把 ref 解析为 commit SHA；空/畸形输出 = ERROR（T-07 断路）。"""
        _rc, out, _err = self._git(
            ["rev-parse", "--verify", f"{ref}^{{commit}}"], purpose=purpose
        )
        sha = out.strip().lower()
        if not _is_hex_sha(sha):
            raise SourceGateError(
                f"{purpose}: git rev-parse output for {ref!r} is empty or not a "
                "valid commit SHA (malformed output = ERROR, not 'no changes')",
                detail={"ref": ref, "purpose": purpose},
            )
        return sha

    def _is_non_behavioral(self, filepath: str) -> bool:
        return any(
            fnmatch(filepath, pattern)
            for pattern in self._non_behavioral_patterns
        )

    def _lookup_impact(
        self, filepath: str
    ) -> Optional[List[Tuple[str, ...]]]:
        """在影响图中查找文件命中的全部测试命令（多 pattern 命中取并集）。

        返回 None 表示没有任何 pattern 命中（影响图不可解析该文件）。
        """
        graph = self._impact_graph
        if graph is None:
            return None
        hits: List[Tuple[str, ...]] = []
        matched = False
        for pattern, commands in graph.items():
            if fnmatch(filepath, pattern):
                matched = True
                hits.extend(commands)
        return hits if matched else None

    # ------------------------------------------------------------------
    # 公开能力 1：fresh_fetch
    # ------------------------------------------------------------------
    def fresh_fetch(self) -> str:
        """git fetch origin，然后验证 base ref 存在；返回 base SHA。

        - fetch 失败/超时 → 传播（ERROR/TIMEOUT）；
        - base ref 不存在 → ERROR（绝不 SKIP）；
        - rev-parse 输出空/畸形 → ERROR（T-07）。
        """
        self._git(["fetch", self._remote], purpose=f"fetch {self._remote}")
        return self._resolve_commitish(
            self._base_ref, purpose=f"verify base ref {self._base_ref!r} after fetch"
        )

    # ------------------------------------------------------------------
    # 公开能力 2：merge_base_diff
    # ------------------------------------------------------------------
    def merge_base_diff(
        self,
        base_sha: Optional[str] = None,
        head_sha: Optional[str] = None,
    ) -> Tuple[str, List[str]]:
        """git merge-base + git diff --name-only；返回 (merge_base, 变更文件列表)。

        - merge-base 失败（无共同祖先等）→ ERROR；空/畸形输出 → ERROR；
        - diff 失败 → ERROR；
        - merge_base != head 而 diff 输出为空 → ERROR（T-07：空输出≠无变化，
          空提交也会被拦——对门 deliberately conservative）；
        - merge_base == head 而 diff 输出为空 → 真实零变更，返回空列表。
        """
        base = (
            base_sha
            if base_sha is not None
            else self._resolve_commitish(
                self._base_ref, purpose="resolve base SHA for merge-base diff"
            )
        )
        head = (
            head_sha
            if head_sha is not None
            else self._resolve_commitish(
                self._head_ref, purpose="resolve head SHA for merge-base diff"
            )
        )
        _rc, out, _err = self._git(
            ["merge-base", base, head], purpose="merge-base"
        )
        merge_base = out.strip().lower()
        if not _is_hex_sha(merge_base):
            raise SourceGateError(
                "git merge-base output is empty or not a valid commit SHA "
                "(malformed output = ERROR, not 'no changes')",
                detail={"base": base, "head": head},
            )
        _rc, out, _err = self._git(
            ["diff", "--name-only", "-z", merge_base, head],
            purpose="diff --name-only (merge-base → head)",
        )
        files = [name for name in out.split("\x00") if name]
        if not files and merge_base != head:
            raise SourceGateError(
                "git diff --name-only returned empty output while merge-base != head "
                "(empty output = ERROR, not 'no changes'; T-07 circuit breaker)",
                detail={"merge_base": merge_base, "head": head},
            )
        return merge_base, files

    # ------------------------------------------------------------------
    # 公开能力 3：affected_scope
    # ------------------------------------------------------------------
    def affected_scope(self, changed_files: Sequence[str]) -> ScopeDecision:
        """由变更文件列表计算测试范围（affected vs full vs none）。

        判定规则（保守优先）：
        1. 零变更                    → none（NOT_APPLICABLE）；
        2. 全部为非行为变更          → none（NOT_APPLICABLE，唯一合法的"无测试"）；
        3. 存在行为变更：
           - 影响图未配置            → full（升级，escalated）；
           - 有行为文件无法解析      → full（升级，escalated，列出未解析文件）；
           - 命中测试命令并集为空    → full（升级——模式命中但零命令不是免测）；
           - 否则                    → affected（只跑并集命令）。
        """
        behavioral: List[str] = []
        non_behavioral: List[str] = []
        for filepath in changed_files:
            if self._is_non_behavioral(filepath):
                non_behavioral.append(filepath)
            else:
                behavioral.append(filepath)

        if not changed_files:
            return ScopeDecision(
                mode="none",
                reason="no changed files (merge-base == head); nothing to test",
            )
        if not behavioral:
            return ScopeDecision(
                mode="none",
                reason=(
                    "pure non-behavioral changes only "
                    f"({len(non_behavioral)} file(s)); source-gate tests "
                    "NOT_APPLICABLE"
                ),
                non_behavioral_files=tuple(non_behavioral),
            )

        graph = self._impact_graph
        if graph is None:
            return ScopeDecision(
                mode="full",
                reason=(
                    "impact graph not configured; unknown impact graph "
                    "escalates to full"
                ),
                escalated=True,
                behavioral_files=tuple(behavioral),
                non_behavioral_files=tuple(non_behavioral),
            )

        matched: List[Tuple[str, ...]] = []
        unmatched: List[str] = []
        for filepath in behavioral:
            hits = self._lookup_impact(filepath)
            if hits is None:
                unmatched.append(filepath)
            else:
                matched.extend(hits)
        if unmatched:
            return ScopeDecision(
                mode="full",
                reason=(
                    f"impact graph cannot resolve {len(unmatched)} behavioral "
                    "file(s); escalate to full"
                ),
                escalated=True,
                behavioral_files=tuple(behavioral),
                non_behavioral_files=tuple(non_behavioral),
                unmatched_files=tuple(unmatched),
            )
        selected = _dedupe_commands(matched)
        if not selected:
            return ScopeDecision(
                mode="full",
                reason=(
                    "impact graph matched zero test commands for behavioral "
                    "changes; escalate to full (a pattern match with no commands "
                    "is not a test exemption)"
                ),
                escalated=True,
                behavioral_files=tuple(behavioral),
                non_behavioral_files=tuple(non_behavioral),
            )
        return ScopeDecision(
            mode="affected",
            reason=(
                f"impact graph resolved {len(selected)} test command(s) for "
                f"{len(behavioral)} behavioral file(s)"
            ),
            selected_commands=tuple(selected),
            behavioral_files=tuple(behavioral),
            non_behavioral_files=tuple(non_behavioral),
        )

    # ------------------------------------------------------------------
    # 公开能力 5：validate_exact_sha
    # ------------------------------------------------------------------
    def validate_exact_sha(
        self, check_sha: str, *, head_sha: Optional[str] = None
    ) -> str:
        """验证 check 记录的 commit SHA 精确等于目标 head SHA。

        - check_sha 空/畸形           → ERROR（不是"未变更"）；
        - 不相等（含大小写归一后）    → StaleShaError（旧 SHA 绿灯拒合，T-02）；
        - 相等                        → 返回当前 head SHA。
        head_sha 未提供时现场重解 head_ref（fresh），防止拿缓存值自比自。
        """
        if not isinstance(check_sha, str) or not _is_hex_sha(check_sha):
            raise SourceGateError(
                "check_sha is empty or not a valid commit SHA "
                "(malformed input = ERROR)",
                detail={"check_sha": repr(check_sha)},
            )
        current = (
            head_sha
            if head_sha is not None
            else self._resolve_commitish(
                self._head_ref, purpose="resolve head for exact-SHA validation"
            )
        )
        if check_sha.strip().lower() != current:
            raise StaleShaError(
                "check commit SHA != target head SHA; evidence is stale and "
                "must not gate a merge (T-02)",
                detail={
                    "check_sha": check_sha.strip().lower(),
                    "head_sha": current,
                    "head_ref": self._head_ref,
                },
            )
        return current

    # ------------------------------------------------------------------
    # 公开能力 4：execute_gate
    # ------------------------------------------------------------------
    def execute_gate(self) -> Dict[str, Any]:
        """执行完整源闸并产出 source-gate-result.json；返回结果字典。

        流程：fresh_fetch → 解析 head → merge-base diff → affected_scope
              →（需要时）preflight + TrustedRunner 执行测试
              → 起跑后 head 稳定性复核 → 写结果工件。
        结果携带统一双轴（execution_status × policy_verdict）与统一退出码；
        失败路径同样写工件（失败证据不可丢），调用方按 result["exit_code"] 退出。
        """
        self._git_calls = []  # 每次 execute_gate 独立成账
        run_id = uuid.uuid4().hex
        result: Dict[str, Any] = {
            "schema": "wenqu/source-gate-result/1",
            "gate": "source-gate",
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repo": str(self._repo),
            "remote": self._remote,
            "base_ref": self._base_ref,
            "head_ref": self._head_ref,
            "impact_graph_configured": self._impact_graph is not None,
            "full_commands_configured": bool(self._full_test_commands),
            "base_sha": None,
            "head_sha": None,
            "head_sha_final": None,
            "head_stable": None,
            "merge_base": None,
            "changed_files": [],
            "changed_file_count": 0,
            "behavioral_files": [],
            "non_behavioral_files": [],
            "gate_scope": None,
            "scope": None,
            "preflight": {
                "required_paths": list(self._required_paths),
                "executables_expected": [],
                "ok": None,
            },
            "git_calls": [],
            "checks": [],
            "execution_status": None,
            "policy_verdict": None,
            "exit_code": None,
            "error": None,
        }
        try:
            base_sha = self.fresh_fetch()
            result["base_sha"] = base_sha
            head_before = self._resolve_commitish(
                self._head_ref, purpose="resolve head (pre-tests)"
            )
            result["head_sha"] = head_before

            merge_base, changed_files = self.merge_base_diff(base_sha, head_before)
            result["merge_base"] = merge_base
            result["changed_files"] = changed_files
            result["changed_file_count"] = len(changed_files)

            scope = self.affected_scope(changed_files)
            result["scope"] = scope.to_dict()
            result["gate_scope"] = scope.mode
            result["behavioral_files"] = list(scope.behavioral_files)
            result["non_behavioral_files"] = list(scope.non_behavioral_files)

            if scope.mode == "none":
                # 唯一合法的"无测试"：纯非行为变更/零变更（NOT_APPLICABLE）
                result["preflight"]["ok"] = True
                result["execution_status"] = "COMPLETED"
                result["policy_verdict"] = "NOT_APPLICABLE"
                result["exit_code"] = EXIT_PASS
            else:
                if scope.mode == "affected":
                    commands = list(scope.selected_commands)
                else:  # full
                    commands = list(self._full_test_commands)
                    if not commands:
                        raise SourceGateError(
                            "behavioral changes require the FULL gate but no "
                            "full test commands are configured (BLOCKED, not "
                            "SKIP; a missing suite never silently passes)",
                            execution_status="BLOCKED",
                            exit_code=EXIT_BLOCKED,
                            detail={"gate_scope": "full"},
                        )
                self._preflight(commands, result)
                any_timeout, any_failure = self._run_checks(commands, result)
                if any_timeout:
                    result["execution_status"] = "TIMEOUT"
                    result["policy_verdict"] = "NOT_EVALUATED"
                    result["exit_code"] = EXIT_TIMEOUT
                elif any_failure:
                    result["execution_status"] = "COMPLETED"
                    result["policy_verdict"] = "FAIL"
                    result["exit_code"] = EXIT_FAIL
                else:
                    result["execution_status"] = "COMPLETED"
                    result["policy_verdict"] = "PASS"
                    result["exit_code"] = EXIT_PASS
                    if scope.mode == "affected":
                        result["coverage_note"] = (
                            "affected-scope PASS covers only the impacted set; "
                            "it is NOT a full-suite PASS (affected and full are "
                            "separate gates)"
                        )

            # 起跑后 head 稳定性复核（契约 §8 不变量 3：范围变化即证据失效）
            head_after = self._resolve_commitish(
                self._head_ref, purpose="re-resolve head (post-tests, evidence freshness)"
            )
            result["head_sha_final"] = head_after
            result["head_stable"] = head_after == head_before
            if head_after != head_before:
                raise StaleShaError(
                    "head SHA moved during the gate run; all evidence from "
                    "this run is invalidated",
                    detail={
                        "head_sha_before": head_before,
                        "head_sha_after": head_after,
                    },
                )
        except SourceGateError as exc:
            result["execution_status"] = exc.execution_status
            result["policy_verdict"] = "NOT_EVALUATED"
            result["exit_code"] = exc.exit_code
            result["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
                "detail": exc.detail,
            }
        except (OSError, TypeError, ValueError) as exc:
            # TrustedRunner 前置校验（缺测试器/allowlist 拒绝/argv 形状）等：
            # 一律 ERROR（缺执行器是 ERROR 不是 SKIP），失败证据照常落工件。
            result["execution_status"] = "ERROR"
            result["policy_verdict"] = "NOT_EVALUATED"
            result["exit_code"] = EXIT_ERROR
            result["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
        result["git_calls"] = list(self._git_calls)
        self._write_result(result)
        return result

    # ------------------------------------------------------------------
    # 内部：preflight 与测试执行（TrustedRunner 唯一执行通道）
    # ------------------------------------------------------------------
    def _preflight(
        self, commands: Sequence[Tuple[str, ...]], result: Dict[str, Any]
    ) -> None:
        """前置条件检查：缺 node_modules/测试器 = ERROR，不是 SKIP。"""
        missing_paths: List[str] = []
        for required in self._required_paths:
            candidate = Path(required)
            target = candidate if candidate.is_absolute() else self._repo / candidate
            if not target.exists():
                missing_paths.append(required)
        expected_executables = sorted({command[0] for command in commands})
        result["preflight"]["executables_expected"] = expected_executables
        if missing_paths:
            raise SourceGateError(
                "required path(s) missing (ERROR, not SKIP; e.g. node_modules "
                "absent — dependency problems are never a skip): "
                f"{missing_paths}",
                detail={"missing_paths": missing_paths},
            )
        missing_executables = [
            name for name in expected_executables if shutil.which(name) is None
        ]
        if missing_executables:
            raise SourceGateError(
                "tester executable(s) missing on PATH (ERROR, not SKIP): "
                f"{missing_executables}",
                detail={"missing_executables": missing_executables},
            )
        result["preflight"]["ok"] = True

    def _run_checks(
        self, commands: Sequence[Tuple[str, ...]], result: Dict[str, Any]
    ) -> Tuple[bool, bool]:
        """经 TrustedRunner 逐条执行测试命令；证据逐条入 result["checks"]。

        返回 (any_timeout, any_failure)。全部命令都执行完（不因单条失败中断），
        保证失败画像完整；退出码一律取 TrustedRunner 捕获的真实 returncode。
        """
        any_timeout = False
        any_failure = False
        for index, argv in enumerate(commands, start=1):
            evidence = self._runner.run(list(argv))
            entry: Dict[str, Any] = {
                "name": f"check_{index}",
                "argv": list(argv),
                "cwd": evidence.cwd,
                "exit_code": evidence.actual_exit_code,  # None 当且仅当 timed_out
                "timed_out": evidence.timed_out,
                "stdout_sha256": evidence.stdout_sha256,
                "stderr_sha256": evidence.stderr_sha256,
                "argv_digest": evidence.argv_digest,
                "timestamp": evidence.timestamp,
                "fresh_until": evidence.fresh_until,
            }
            if self._evidence_store is not None:
                entry["evidence_digest"] = self._evidence_store.put(evidence)
            result["checks"].append(entry)
            if evidence.timed_out:
                any_timeout = True
            elif evidence.actual_exit_code != 0:
                any_failure = True
        return any_timeout, any_failure

    # ------------------------------------------------------------------
    # 内部：结果工件写入（原子替换；O_EXCL+O_NOFOLLOW 防 symlink 重定向）
    # ------------------------------------------------------------------
    def _write_result(self, result: Dict[str, Any]) -> str:
        target = self._result_path
        tmp = target.with_name(
            f".{target.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
        )
        data = json.dumps(
            result, sort_keys=True, indent=2, ensure_ascii=False
        ).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(tmp, flags, 0o640)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        finally:
            os.close(fd)
        os.replace(tmp, target)
        return str(target)

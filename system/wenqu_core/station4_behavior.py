# -*- coding: utf-8 -*-
"""station4_behavior.py——Codex 方案 W6D：Bug 八站·站4 行为面适配器。

血统与契约正源：
- Codex 方案 W6D（站4-7 批次）·站4 行为面：e2e 套件 + 路由动态腿 +
  真实浏览器抽检。
- 《问渠轨道规范（发行版 v2.0）》§1 站4 判据：pass=套件全绿/每测试点有
  已看证据；fail=任一 e2e 红/证据缺失；error=环境起不来/驱动缺失。
- schemas/station-result-v2.schema.json：每腿与整站产出严格合规
  （additionalProperties:false；经 build_station_result 内置校验器 +
  jsonschema 双保险）。

三条腿（每腿独立产出一份 station_id=4 的 station-result-v2，可单独留证；
整站结果由 combine_station4_results 合并为单一条目——GateAggregator 同站
只接受一条，内容不一即冲突证据）：

- E2eScanner：经 TrustedRunner 调 vitest e2e。TrustedRunner 只保留
  stdout/stderr 哈希，因此测试明细一律经 ``--outputFile`` 报告文件落盘
  后解析。分母 = tests/ 目录动态发现的测试文件总数；scanned = vitest
  实际执行的文件数（缩水→BLOCKED，铁律2）；分子 = 通过的文件数——
  policy PASS 当且仅当 分子==分母 且 actual_exit_code==0。
- RouteDynamicScanner：路由完整性动态腿——对运行中服务发真实 HTTP 请求，
  按路由清单核对响应状态（静态腿在站2；本腿只认运行态事实）。
- WebGuiScanner：真实浏览器抽检——消费 web-gui-tester 范式的检查报告：
  真实浏览器、真实点击流、真实后端与鉴权、刷新后回读，console 错误与
  失败请求作为诊断工件随报告归档。场景通过 = passed==true 且
  console_errors/failed_requests 双空。

安全构造（by construction）：
- 纯 stdlib；一切外部命令经 TrustedRunner（argv 列表、shell=False，
  actual_exit_code 只取 waitpid 真值）；无 shell 拼接、无 eval/exec。
- 分母缩水守卫交由 build_station_result 强制：scanned<denominator →
  BLOCKED/NOT_EVALUATED，整站绝不记 PASS。
- actual_exit_code=-1 是本文件唯一的非进程哨兵值：只用于「进程未起
  （可执行缺失/不在允许清单）」与「超时被杀（waitpid 无返回）」两种
  场景，且只能伴随 ERROR/TIMEOUT（或缩水强制的 BLOCKED）出现——结构上
  不可能支撑 PASS。
- 环境起不来/目标不可达 = 探不到证据 → 按未扫计（缩水 BLOCKED），
  绝不折算为 FAIL/PASS（宁可阻断，不猜证据）。
- 进程内完成的腿（路由动态腿）actual_exit_code=0 采用 RunManifest.
  to_station_result 同一先例：能走到结果构造的那次进程内执行必然成功。
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import socket
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .bugscan_orchestrator import (
    RunManifest,
    StationResultValidationError,
    build_station_result,
    validate_station_result,
)
from .runner import TrustedRunner

__all__ = [
    "STATION_ID",
    "E2eScanner",
    "RouteDynamicScanner",
    "WebGuiScanner",
    "combine_station4_results",
    "scan_station4",
    "BehaviorStationError",
    "E2eSetupError",
    "RouteSpecError",
    "WebGuiSetupError",
]

__version__ = "1.0.0"

STATION_ID = 4

#: 站4 收敛语义（INCIDENT 档不含站4；STANDARD 档 required）。
COUNTS_TOWARD_CONVERGENCE: bool = True

#: e2e 测试文件发现模式（vitest 默认包含规则的可执行近似）。
DEFAULT_TEST_PATTERNS: Tuple[str, ...] = (
    "*.test.ts", "*.spec.ts",
    "*.test.tsx", "*.spec.tsx",
    "*.test.js", "*.spec.js",
    "*.test.jsx", "*.spec.jsx",
    "*.test.mjs", "*.spec.mjs",
)

#: vitest 退出码契约：0=全绿，1=存在失败；其余=套件/环境错误。
_E2E_OK_EXITS = (0, 1)

# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class BehaviorStationError(ValueError):
    """站4 适配器基类错误——一律 fail-closed。"""


class E2eSetupError(BehaviorStationError):
    """e2e 腿配置/环境非法：tests 目录缺失、发现分母为空、argv 模板缺占位符。"""


class RouteSpecError(BehaviorStationError):
    """路由动态腿清单非法：缺字段、方法/状态码形态错。"""


class WebGuiSetupError(BehaviorStationError):
    """浏览器抽检腿配置非法：缺报告契约或分母来源。"""


# ---------------------------------------------------------------------------
# 基础工具（与 bugscan_orchestrator 同算法的小型本地实现，保持模块自包含）
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_obj(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _sha256_hex(canonical.encode("utf-8"))


def _attempt_id(run_id: str, tag: str) -> str:
    seed = _hash_obj({"run_id": run_id, "tag": tag, "ts": _iso_z(_utc_now())})
    return f"att-{tag}-{seed[:12]}"


def _finding_id(prefix: str, seed: str) -> str:
    safe = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in prefix)
    return f"fnd_{safe}_{_sha256_hex(seed.encode('utf-8'))[:12]}"


def _require_manifest(manifest: RunManifest) -> RunManifest:
    if not isinstance(manifest, RunManifest):
        raise BehaviorStationError(
            f"manifest must be RunManifest, got {type(manifest).__name__}"
        )
    return manifest


def _manifest_identity(manifest: RunManifest) -> Dict[str, Any]:
    """身份三源一律取冻结 manifest 正源，绝不采信工具自报身份。"""
    identity: Dict[str, Any] = {
        "project_id": manifest.project_id,
        "commit_sha": manifest.commit_sha,
        "environment": manifest.environment,
        "scope_hash": manifest.scope_hash,
        "ruleset_hash": manifest.ruleset_hash,
        "data_config_hash": manifest.data_config_hash,
    }
    if manifest.lockfile_hash:
        identity["lockfile_hash"] = manifest.lockfile_hash
    return identity


def _cas_artifact(payload: bytes) -> Optional[Dict[str, Any]]:
    """字节载荷 → CAS 工件条目；空载荷（0B）无证据价值，返回 None
    （schema 要求 size ≥ 1，空文件不作为工件登记）。"""
    if not payload:
        return None
    return {"cas_digest": f"sha256:{_sha256_hex(payload)}", "size": len(payload)}


# -- 多腿合并判定（worst-of 语义，站4/站7 合并共用同一套优先级约定） --------

_EXEC_SEVERITY = ("BLOCKED", "ERROR", "TIMEOUT", "CANCELLED")


def _worst_execution_status(statuses: Iterable[str]) -> str:
    seen = set(statuses)
    for token in _EXEC_SEVERITY:
        if token in seen:
            return token
    return "COMPLETED"


def _worst_policy(verdicts: Iterable[str]) -> str:
    active = [v for v in verdicts if v != "NOT_APPLICABLE"]
    if not active:
        return "NOT_APPLICABLE"
    for token in ("FAIL", "NOT_EVALUATED", "CONDITIONAL"):
        if token in active:
            return token
    return "PASS" if all(v == "PASS" for v in active) else "NOT_EVALUATED"


def _worst_assertion(verdicts: Iterable[str]) -> str:
    seen = list(verdicts)
    if "FAIL" in seen:
        return "FAIL"
    if seen and all(v == "PASS" for v in seen):
        return "PASS"
    return "ERROR"


def _merge_exit_codes(codes: List[int]) -> int:
    """全 0 → 0；否则按腿顺序传播首个非零真实退出码（只用真值，不造值）。"""
    for code in codes:
        if code != 0:
            return code
    return 0


# ---------------------------------------------------------------------------
# E2eScanner——站4 腿1：vitest e2e 套件
# ---------------------------------------------------------------------------


class E2eScanner:
    """经 TrustedRunner 调 vitest e2e，报告走 ``--outputFile`` 落盘后解析。

    覆盖口径（任务冻结）：
    - denominator：``repo_root/tests_dir`` 下按 ``test_patterns`` 动态发现的
      测试文件总数（排除 ``exclusions`` 模式，排除项落 coverage.exclusions）；
    - scanned：vitest 报告中实际执行（status∈{passed,failed}）且属于发现集
      的文件数——未出现在报告中的文件按未扫计，触发分母缩水守卫；
    - 分子（通过文件数）驱动判定：PASS ⇔ 分子==分母 且 exit==0。

    vitest_argv 模板占位符：``{output_file}``（必含，报告契约）与
    ``{tests_dir}``（可选）。默认模板::

        ["npx", "vitest", "run", "--reporter=json",
         "--outputFile={output_file}", "{tests_dir}"]
    """

    STATION_ID = STATION_ID
    LEG = "e2e"

    DEFAULT_ARGV: Tuple[str, ...] = (
        "npx", "vitest", "run", "--reporter=json",
        "--outputFile={output_file}", "{tests_dir}",
    )

    def __init__(
        self,
        manifest: RunManifest,
        *,
        repo_root: str,
        tests_dir: str = "tests",
        test_patterns: Iterable[str] = DEFAULT_TEST_PATTERNS,
        exclusions: Iterable[str] = (),
        vitest_argv: Optional[Iterable[str]] = None,
        runner: Optional[TrustedRunner] = None,
        timeout_s: int = 1800,
        tool_name: str = "vitest",
        now: Optional[datetime] = None,
    ) -> None:
        _require_manifest(manifest)
        if not isinstance(repo_root, str) or not repo_root.strip():
            raise E2eSetupError("repo_root must be a non-empty string")
        if not isinstance(tests_dir, str) or not tests_dir.strip():
            raise E2eSetupError("tests_dir must be a non-empty string")
        self._manifest = manifest
        self._repo_root = Path(repo_root).resolve()
        self._tests_dir = tests_dir
        self._tests_root = self._repo_root / tests_dir
        self._patterns = tuple(test_patterns) or DEFAULT_TEST_PATTERNS
        self._exclusions = tuple(exclusions)
        self._argv_template = tuple(vitest_argv) if vitest_argv is not None else self.DEFAULT_ARGV
        if not self._argv_template or not any("{output_file}" in a for a in self._argv_template):
            raise E2eSetupError(
                "vitest_argv template must be a non-empty argv list containing "
                "the {output_file} placeholder (report contract)"
            )
        if runner is not None and not isinstance(runner, TrustedRunner):
            raise E2eSetupError(
                f"runner must be TrustedRunner, got {type(runner).__name__}"
            )
        self._runner = runner or TrustedRunner(
            default_cwd=str(self._repo_root), timeout=float(timeout_s)
        )
        self._timeout_s = max(1, int(timeout_s))
        self._tool_name = tool_name
        self._now = now
        self.last_breakdown: Dict[str, Any] = {}

    # -- 分母：tests/ 目录动态发现 ------------------------------------------------
    def discover_test_files(self) -> List[str]:
        """动态发现 e2e 测试文件（分母唯一正源；相对 tests 根的 posix 路径）。"""
        if not self._tests_root.is_dir():
            raise E2eSetupError(
                f"tests dir not found: {self._tests_root}（站4 判据 error=环境起不来；"
                "分母无法建立时 fail-closed 拒绝产出结果）"
            )
        found = set()
        for pattern in self._patterns:
            for path in self._tests_root.rglob(pattern):
                if path.is_file():
                    found.add(path.relative_to(self._tests_root).as_posix())
        files = sorted(
            rel for rel in found
            if not any(fnmatch.fnmatch(rel, pat) for pat in self._exclusions)
        )
        if not files:
            raise E2eSetupError(
                f"no e2e test files discovered under {self._tests_root} with "
                f"patterns {list(self._patterns)}——空分母不得进入行为面"
                "（vacuous pass 禁止）"
            )
        return files

    def _normalize_report_name(self, name: Any, discovered: List[str]) -> Optional[str]:
        """把报告里的文件名归一到发现集（绝对路径 → 仓库相对；后备后缀匹配）。"""
        if not isinstance(name, str) or not name:
            return None
        candidate = Path(name.replace("\\", "/"))
        try:
            rel = candidate.resolve().relative_to(self._repo_root).as_posix()
        except (ValueError, OSError):
            rel = None
        if rel is not None and rel in discovered:
            return rel
        text = candidate.as_posix()
        for file in discovered:
            if text.endswith(file) or file.endswith(text):
                return file
        return None

    def _build_argv(self, report_path: str) -> List[str]:
        return [
            arg.replace("{output_file}", report_path).replace(
                "{tests_dir}", self._tests_dir
            )
            for arg in self._argv_template
        ]

    # -- 执行 ---------------------------------------------------------------------
    def scan(self) -> Dict[str, Any]:
        started = _iso_z(self._now or _utc_now())
        files = self.discover_test_files()
        denominator = len(files)
        fd, report_path = tempfile.mkstemp(prefix="wenqu-e2e-report-", suffix=".json")
        os.close(fd)
        argv = self._build_argv(report_path)

        evidence = None
        launch_error: Optional[str] = None
        try:
            evidence = self._runner.run(argv)
        except (FileNotFoundError, PermissionError) as exc:
            launch_error = f"{type(exc).__name__}: {exc}"

        exit_code: int
        timed_out = False
        if evidence is None:
            exit_code = -1  # 哨兵：进程未起（可执行缺失/不在允许清单）
        elif evidence.timed_out:
            timed_out = True
            exit_code = -1  # 哨兵：超时被杀，waitpid 无返回
        else:
            exit_code = int(evidence.actual_exit_code)  # waitpid 真值

        report_raw: Optional[bytes] = None
        report: Optional[Dict[str, Any]] = None
        report_error: Optional[str] = None
        try:
            report_raw = Path(report_path).read_bytes()
            report = json.loads(report_raw.decode("utf-8"))
            if not isinstance(report, Mapping):
                report, report_error = None, "report is not a JSON object"
        except (OSError, ValueError) as exc:
            report_error = f"{type(exc).__name__}: {exc}"

        executed: Dict[str, str] = {}
        extras: List[str] = []
        if report is not None and timed_out is False:
            test_results = report.get("testResults")
            if isinstance(test_results, list):
                for entry in test_results:
                    if not isinstance(entry, Mapping):
                        continue
                    status = str(entry.get("status", "")).lower()
                    rel = self._normalize_report_name(entry.get("name"), files)
                    if rel is None:
                        extras.append(str(entry.get("name")))
                    elif status in ("passed", "failed"):
                        executed[rel] = status
                    # 其他状态（skipped 等）按未执行计 → 缩水守卫

        missing = [f for f in files if f not in executed]
        failed = sorted(f for f, s in executed.items() if s != "passed")
        passed = sorted(f for f, s in executed.items() if s == "passed")
        scanned = len(executed)

        if evidence is None or timed_out or report is None or exit_code not in _E2E_OK_EXITS:
            # 超时被杀→TIMEOUT；进程未起/退出码越契约/套件退出码看似正常但
            # 报告不可读（证据缺失）→ ERROR；明细一律按未扫计（缩水守卫接管）
            execution_status = "TIMEOUT" if timed_out else "ERROR"
            policy_verdict = "NOT_EVALUATED"
            assertion = "ERROR"
        elif missing:
            execution_status = "COMPLETED"
            policy_verdict = "FAIL" if failed else "NOT_EVALUATED"
            assertion = "FAIL" if failed else "ERROR"
        elif failed or exit_code != 0:
            execution_status = "COMPLETED"
            policy_verdict = "FAIL"
            assertion = "FAIL"
        else:
            execution_status = "COMPLETED"
            policy_verdict = "PASS"
            assertion = "PASS"

        finding_ids = (
            [_finding_id("e2e", f) for f in failed]
            + [_finding_id("e2e_missing", f) for f in missing]
        )

        artifacts: List[Dict[str, Any]] = []
        report_artifact = _cas_artifact(report_raw) if report_raw else None
        if report_artifact:
            artifacts.append(report_artifact)
        if evidence is not None:
            evidence_artifact = _cas_artifact(evidence.to_json().encode("utf-8"))
            if evidence_artifact:
                artifacts.append(evidence_artifact)

        tool_version = "unknown"
        if report is not None and report.get("vitestVersion"):
            tool_version = str(report["vitestVersion"])

        ended = _iso_z(_utc_now())
        self.last_breakdown = {
            "leg": self.LEG,
            "files_total": denominator,
            "files_executed": scanned,
            "files_passed": len(passed),
            "files_failed": failed,
            "files_missing": missing,
            "files_extra_executed": sorted(set(extras)),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "launch_error": launch_error,
            "report_error": report_error,
            "report_path": report_path,
        }

        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st4-e2e"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=_manifest_identity(self._manifest),
            tool={"name": self._tool_name, "version": tool_version},
            execution={
                "argv_digest": TrustedRunner.argv_digest(list(argv)),
                "started_at": started,
                "ended_at": ended,
                "timeout_s": self._timeout_s,
                "actual_exit_code": exit_code,
                "expected_exit_set": [0],
                "assertion_verdict": assertion,
            },
            coverage={
                "denominator": denominator,
                "scanned": scanned,
                **({"exclusions": list(self._exclusions)} if self._exclusions else {}),
            },
            finding_ids=finding_ids,
            artifacts=artifacts,
        )


# ---------------------------------------------------------------------------
# RouteDynamicScanner——站4 腿2：路由完整性动态腿
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """路由完整性要看直接响应状态：3xx 不跟随，原样呈现给判定。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class RouteDynamicScanner:
    """对运行中服务发真实 HTTP 请求，按路由清单核对响应状态。

    清单项契约::

        {"name": "home", "method": "GET", "path": "/",
         "expected_status": 200}          # 或 [200, 204]

    覆盖口径：denominator=清单路由数；scanned=拿到传输层响应（含 4xx/5xx，
    HTTPError 也是响应）的路由数；通过 = 状态码 ∈ expected_status。
    传输层不可达 = 探不到证据 → 未扫（缩水 BLOCKED），不折算 FAIL/PASS。
    本腿在进程内完成（无子进程）：actual_exit_code=0 采用 RunManifest
    to_station_result 同一先例——能走到结果构造的那次执行必然成功；
    路由失败体现为 assertion/policy FAIL，绝不体现为假退出码。
    """

    STATION_ID = STATION_ID
    LEG = "route-dynamic"

    def __init__(
        self,
        manifest: RunManifest,
        *,
        routes: Iterable[Mapping[str, Any]],
        base_url: str,
        request_timeout_s: float = 10.0,
        now: Optional[datetime] = None,
    ) -> None:
        _require_manifest(manifest)
        if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
            raise RouteSpecError(
                f"base_url must be an http(s) URL, got {base_url!r}"
            )
        if request_timeout_s <= 0:
            raise RouteSpecError("request_timeout_s must be positive")
        self._manifest = manifest
        self._base_url = base_url.rstrip("/")
        self._request_timeout_s = float(request_timeout_s)
        self._now = now
        self._routes: List[Dict[str, Any]] = [
            self._validate_route(dict(r), i) for i, r in enumerate(routes)
        ]
        if not self._routes:
            raise RouteSpecError("routes must contain at least one entry（空分母禁止）")
        self.last_breakdown: Dict[str, Any] = {}

    @staticmethod
    def _validate_route(route: Mapping[str, Any], index: int) -> Dict[str, Any]:
        if not isinstance(route, Mapping):
            raise RouteSpecError(f"routes[{index}] must be a mapping")
        name = route.get("name")
        path = route.get("path")
        method = str(route.get("method", "GET")).upper()
        expected = route.get("expected_status", 200)
        if not isinstance(name, str) or not name.strip():
            raise RouteSpecError(f"routes[{index}].name must be a non-empty string")
        if not isinstance(path, str) or not path.startswith("/"):
            raise RouteSpecError(
                f"routes[{index}].path must start with '/', got {path!r}"
            )
        if isinstance(expected, bool) or isinstance(expected, int):
            expected_set = [int(expected)]
        elif isinstance(expected, (list, tuple)) and expected:
            expected_set = [int(s) for s in expected]
        else:
            raise RouteSpecError(
                f"routes[{index}].expected_status must be an int or list of ints"
            )
        for code in expected_set:
            if not 100 <= code <= 599:
                raise RouteSpecError(
                    f"routes[{index}].expected_status contains invalid code {code}"
                )
        return {
            "name": name.strip(),
            "method": method,
            "path": path,
            "expected_status": sorted(set(expected_set)),
        }

    @staticmethod
    def load_routes(path: str) -> List[Dict[str, Any]]:
        """从 JSON 装载路由清单（``{"routes": [...]}`` 或裸数组）。"""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, Mapping):
            data = data.get("routes")
        if not isinstance(data, list):
            raise RouteSpecError(f"{path}: routes must be a JSON array or {{'routes': [...]}}")
        return [dict(r) for r in data]

    def _probe(self, route: Mapping[str, Any]) -> Dict[str, Any]:
        url = f"{self._base_url}{route['path']}"
        request = urllib.request.Request(
            url, method=route["method"],
            headers={"User-Agent": "wenqu-st4-route-dynamic/1.0"},
        )
        try:
            with _OPENER.open(request, timeout=self._request_timeout_s) as response:
                code = int(getattr(response, "status", None) or response.getcode())
        except urllib.error.HTTPError as exc:  # HTTPError 也是一次真实响应
            code = int(exc.code)
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            return {"probed": False, "status": None, "ok": False, "detail": str(exc)}
        return {
            "probed": True,
            "status": code,
            "ok": code in route["expected_status"],
            "detail": None,
        }

    def scan(self) -> Dict[str, Any]:
        started = _iso_z(self._now or _utc_now())
        outcomes = [(route, self._probe(route)) for route in self._routes]
        denominator = len(self._routes)
        scanned = sum(1 for _, o in outcomes if o["probed"])
        mismatched = [r for r, o in outcomes if o["probed"] and not o["ok"]]
        unreachable = [r for r, o in outcomes if not o["probed"]]

        if unreachable:
            # 环境起不来=探不到证据 → 缩水守卫接管（BLOCKED/NOT_EVALUATED）
            execution_status = "COMPLETED"
            policy_verdict = "FAIL" if mismatched else "NOT_EVALUATED"
            assertion = "FAIL" if mismatched else "ERROR"
        elif mismatched:
            execution_status, policy_verdict, assertion = "COMPLETED", "FAIL", "FAIL"
        else:
            execution_status, policy_verdict, assertion = "COMPLETED", "PASS", "PASS"

        plan_payload = json.dumps(
            {"base_url": self._base_url,
             "routes": [dict(r) for r in self._routes]},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")

        finding_ids = [_finding_id("route", f'{r["name"]}:{r["method"]}:{r["path"]}')
                       for r in mismatched]
        finding_ids += [_finding_id("route_unreachable", f'{r["name"]}:{r["path"]}')
                        for r in unreachable]

        ended = _iso_z(_utc_now())
        self.last_breakdown = {
            "leg": self.LEG,
            "routes_total": denominator,
            "routes_probed": scanned,
            "routes_matched": scanned - len(mismatched),
            "routes_mismatched": [
                {**r, "got": o["status"], "expected": r["expected_status"]}
                for r, o in outcomes if o["probed"] and not o["ok"]
            ],
            "routes_unreachable": [
                {**r, "detail": o["detail"]} for r, o in outcomes if not o["probed"]
            ],
        }

        argv = ["wenqu_core.station4_behavior", "route-probe", self._base_url] + sorted(
            f'{r["method"]} {r["path"]}' for r in self._routes
        )
        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st4-route"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=_manifest_identity(self._manifest),
            tool={"name": "wenqu_core.station4_behavior.RouteDynamicScanner",
                  "version": __version__},
            execution={
                "argv_digest": TrustedRunner.argv_digest(argv),
                "started_at": started,
                "ended_at": ended,
                "actual_exit_code": 0,  # 进程内完成先例（见类 docstring）
                "expected_exit_set": [0],
                "assertion_verdict": assertion,
            },
            coverage={"denominator": denominator, "scanned": scanned},
            finding_ids=finding_ids,
            artifacts=[_cas_artifact(plan_payload)],
        )


# ---------------------------------------------------------------------------
# WebGuiScanner——站4 腿3：真实浏览器抽检（web-gui-tester 范式）
# ---------------------------------------------------------------------------


class WebGuiScanner:
    """真实浏览器抽检：经 TrustedRunner 执行检查命令并消费其 JSON 报告。

    范式（web-gui-tester）：真实浏览器打开真实 URL、真实点击流、真实后端
    与鉴权、刷新/重登后的 UI 回读；console 错误与失败请求作为诊断工件。
    场景通过 = ``passed == true`` 且 ``console_errors``/``failed_requests``
    双空——任何控制台错误或失败业务请求都不得记通过。

    报告契约（check_argv 产出的 JSON，路径即 report_path）::

        {
          "browser": "chromium-131",
          "base_url": "https://staging.example.com",
          "planned": ["login-flow", "order-create"],       # 可选分母正源
          "scenarios": [
            {"name": "login-flow", "passed": true,
             "console_errors": [], "failed_requests": [],
             "artifacts": [{"cas_digest": "sha256:<64hex>", "size": 12345}]}
          ]
        }

    分母正源优先级：构造器 required_scenarios > 报告 planned >（两者皆缺
    → WebGuiSetupError fail-closed）。scanned = 报告中出现且属于分母的
    场景数；缺席场景按未扫计（缩水 BLOCKED）。

    check_argv 模板可含 ``{report_file}`` 占位符（替换为 report_path）；
    退出码契约与 vitest 对齐：0=全过，1=有失败，≥2=框架/环境错误。
    """

    STATION_ID = STATION_ID
    LEG = "web-gui"

    def __init__(
        self,
        manifest: RunManifest,
        *,
        check_argv: Iterable[str],
        report_path: str,
        required_scenarios: Optional[Iterable[str]] = None,
        runner: Optional[TrustedRunner] = None,
        timeout_s: int = 900,
        now: Optional[datetime] = None,
    ) -> None:
        _require_manifest(manifest)
        self._argv_template = tuple(check_argv)
        if not self._argv_template or not all(isinstance(a, str) for a in self._argv_template):
            raise WebGuiSetupError(
                "check_argv must be a non-empty list of strings (argv 列表，shell=False)"
            )
        if not isinstance(report_path, str) or not report_path.strip():
            raise WebGuiSetupError("report_path must be a non-empty string")
        if runner is not None and not isinstance(runner, TrustedRunner):
            raise WebGuiSetupError(
                f"runner must be TrustedRunner, got {type(runner).__name__}"
            )
        self._manifest = manifest
        self._report_path = report_path
        self._required = (
            [str(s) for s in required_scenarios] if required_scenarios is not None else None
        )
        if self._required is not None and not self._required:
            raise WebGuiSetupError("required_scenarios must be non-empty when provided（空分母禁止）")
        self._runner = runner or TrustedRunner(timeout=float(timeout_s))
        self._timeout_s = max(1, int(timeout_s))
        self._now = now
        self.last_breakdown: Dict[str, Any] = {}

    def scan(self) -> Dict[str, Any]:
        started = _iso_z(self._now or _utc_now())
        argv = [a.replace("{report_file}", self._report_path) for a in self._argv_template]

        evidence = None
        launch_error: Optional[str] = None
        try:
            evidence = self._runner.run(argv)
        except (FileNotFoundError, PermissionError) as exc:
            launch_error = f"{type(exc).__name__}: {exc}"

        if evidence is None:
            exit_code, timed_out = -1, False
        elif evidence.timed_out:
            exit_code, timed_out = -1, True
        else:
            exit_code, timed_out = int(evidence.actual_exit_code), False

        report_raw: Optional[bytes] = None
        report: Optional[Dict[str, Any]] = None
        report_error: Optional[str] = None
        try:
            report_raw = Path(self._report_path).read_bytes()
            parsed = json.loads(report_raw.decode("utf-8"))
            if isinstance(parsed, Mapping):
                report = dict(parsed)
            else:
                report_error = "report is not a JSON object"
        except (OSError, ValueError) as exc:
            report_error = f"{type(exc).__name__}: {exc}"

        scenarios: List[Mapping[str, Any]] = []
        if report is not None and isinstance(report.get("scenarios"), list):
            scenarios = [s for s in report["scenarios"] if isinstance(s, Mapping)]

        if self._required is not None:
            required = list(self._required)
        elif report is not None and isinstance(report.get("planned"), list):
            required = [str(s) for s in report["planned"]]
        elif report is not None:
            raise WebGuiSetupError(
                "no denominator source: required_scenarios not given and report "
                "lacks 'planned'（分母无法建立，fail-closed）"
            )
        else:
            required = []

        denominator = len(required)
        if denominator == 0 and report is not None and not timed_out and evidence is not None:
            raise WebGuiSetupError(
                "denominator resolved to zero（空分母禁止 vacuous pass）"
            )

        by_name: Dict[str, Mapping[str, Any]] = {}
        for scenario in scenarios:
            name = scenario.get("name")
            if isinstance(name, str) and name:
                by_name[name] = scenario

        executed = {name: by_name[name] for name in required if name in by_name}
        scanned = len(executed)
        missing = [n for n in required if n not in by_name]

        def _scenario_ok(scenario: Mapping[str, Any]) -> bool:
            return (
                scenario.get("passed") is True
                and not scenario.get("console_errors")
                and not scenario.get("failed_requests")
            )

        failed = sorted(n for n, s in executed.items() if not _scenario_ok(s))

        if evidence is None or timed_out or report is None or exit_code not in (0, 1):
            execution_status = "TIMEOUT" if timed_out else "ERROR"
            policy_verdict = "NOT_EVALUATED"
            assertion = "ERROR"
        elif missing:
            execution_status = "COMPLETED"
            policy_verdict = "FAIL" if failed else "NOT_EVALUATED"
            assertion = "FAIL" if failed else "ERROR"
        elif failed or exit_code != 0:
            execution_status, policy_verdict, assertion = "COMPLETED", "FAIL", "FAIL"
        else:
            execution_status, policy_verdict, assertion = "COMPLETED", "PASS", "PASS"

        finding_ids = (
            [_finding_id("gui", n) for n in failed]
            + [_finding_id("gui_missing", n) for n in missing]
        )

        artifacts: List[Dict[str, Any]] = []
        report_artifact = _cas_artifact(report_raw) if report_raw else None
        if report_artifact:
            artifacts.append(report_artifact)
        if evidence is not None:
            evidence_artifact = _cas_artifact(evidence.to_json().encode("utf-8"))
            if evidence_artifact:
                artifacts.append(evidence_artifact)
        extra_artifacts = 0
        for scenario in executed.values():
            for art in scenario.get("artifacts", ()) or ():
                if (
                    isinstance(art, Mapping)
                    and isinstance(art.get("cas_digest"), str)
                    and art["cas_digest"].startswith("sha256:")
                    and isinstance(art.get("size"), int)
                    and art["size"] >= 1
                ):
                    artifacts.append({"cas_digest": art["cas_digest"], "size": art["size"]})
                else:
                    extra_artifacts += 1

        ended = _iso_z(_utc_now())
        self.last_breakdown = {
            "leg": self.LEG,
            "scenarios_total": denominator,
            "scenarios_executed": scanned,
            "scenarios_passed": scanned - len(failed),
            "scenarios_failed": failed,
            "scenarios_missing": missing,
            "browser": report.get("browser") if report else None,
            "base_url": report.get("base_url") if report else None,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "launch_error": launch_error,
            "report_error": report_error,
            "invalid_scenario_artifacts_dropped": extra_artifacts,
        }

        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st4-gui"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=_manifest_identity(self._manifest),
            tool={
                "name": "wenqu_core.station4_behavior.WebGuiScanner",
                "version": str(report.get("browser") or "unknown") if report else "unknown",
            },
            execution={
                "argv_digest": TrustedRunner.argv_digest(list(argv)),
                "started_at": started,
                "ended_at": ended,
                "timeout_s": self._timeout_s,
                "actual_exit_code": exit_code,
                "expected_exit_set": [0],
                "assertion_verdict": assertion,
            },
            coverage={"denominator": denominator, "scanned": scanned},
            finding_ids=finding_ids,
            artifacts=artifacts,
        )


# ---------------------------------------------------------------------------
# 整站合并——三条腿 → 单一 station-result-v2
# ---------------------------------------------------------------------------


def combine_station4_results(leg_results: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """把站4 各腿结果合并为单一条目（GateAggregator 同站只接受一条）。

    合并规则（全部沿用真实腿值，不造值）：
    - coverage：denominator/scanned 逐腿求和；exclusions 顺序去重拼接；
    - execution_status：worst-of（BLOCKED > ERROR > TIMEOUT > CANCELLED >
      COMPLETED；缩水守卫在 build_station_result 内再次强制）；
    - policy_verdict：NOT_APPLICABLE 腿不参与；任一 FAIL→FAIL，任一
      NOT_EVALUATED→NOT_EVALUATED，任一 CONDITIONAL→CONDITIONAL，其余
      全 PASS→PASS；
    - actual_exit_code：全 0→0，否则按腿顺序传播首个非零值；
    - started_at/ended_at：min/max；timeout_s：max（缺省腿不计入）；
    - finding_ids/artifacts：顺序去重拼接。

    一致性硬门：各腿 run_id / station_id(==4) / identity(commit_sha,
    environment, scope_hash) 必须一致，不一致抛 BehaviorStationError
    （宁可阻断，不猜证据）。
    """
    results = [dict(r) for r in leg_results]
    if not results:
        raise BehaviorStationError("combine_station4_results needs at least one leg result")

    for index, result in enumerate(results):
        try:
            validate_station_result(result)
        except StationResultValidationError as exc:
            raise BehaviorStationError(f"leg[{index}] failed validation: {exc}") from exc

    first = results[0]
    if first["station_id"] != STATION_ID:
        raise BehaviorStationError(
            f"combine_station4_results only merges station {STATION_ID} legs, "
            f"got station_id={first['station_id']}"
        )
    run_id = first["run_id"]
    anchor = first["identity"]
    anchor_keys = ("commit_sha", "environment", "scope_hash")
    for index, result in enumerate(results):
        if result["station_id"] != STATION_ID or result["run_id"] != run_id:
            raise BehaviorStationError(
                f"leg[{index}] station/run mismatch: expected station {STATION_ID} "
                f"run {run_id!r}, got station {result['station_id']} run {result['run_id']!r}"
            )
        for key in anchor_keys:
            if result["identity"].get(key) != anchor.get(key):
                raise BehaviorStationError(
                    f"leg[{index}] identity.{key} mismatch: "
                    f"{result['identity'].get(key)!r} != {anchor.get(key)!r}"
                    "（证据身份不一致，拒绝合并）"
                )

    denominator = sum(int(r["coverage"].get("denominator", 0)) for r in results)
    scanned = sum(int(r["coverage"].get("scanned", 0)) for r in results)
    exclusions: List[str] = []
    for result in results:
        for item in result["coverage"].get("exclusions", ()) or ():
            if item not in exclusions:
                exclusions.append(item)

    execution_status = _worst_execution_status(r["execution_status"] for r in results)
    policy_verdict = _worst_policy(r["policy_verdict"] for r in results)
    assertion = _worst_assertion(
        r["execution"].get("assertion_verdict") for r in results
    )
    exit_code = _merge_exit_codes(
        [int(r["execution"].get("actual_exit_code", 0)) for r in results]
    )
    started_at = min(r["execution"]["started_at"] for r in results)
    ended_at = max(r["execution"]["ended_at"] for r in results)
    timeouts = [
        int(r["execution"]["timeout_s"]) for r in results
        if isinstance(r["execution"].get("timeout_s"), int)
        and r["execution"]["timeout_s"] >= 1
    ]

    finding_ids: List[str] = []
    for result in results:
        for finding in result.get("finding_ids", ()):
            if finding not in finding_ids:
                finding_ids.append(finding)
    artifacts: List[Dict[str, Any]] = []
    seen_digests = set()
    for result in results:
        for art in result.get("artifacts", ()):
            digest = art.get("cas_digest")
            if digest not in seen_digests:
                seen_digests.add(digest)
                artifacts.append({"cas_digest": digest, "size": art["size"]})

    leg_digests = sorted(r["execution"]["argv_digest"] for r in results)
    argv = ["wenqu_core.station4_behavior:combine", run_id] + leg_digests

    combined = build_station_result(
        run_id=run_id,
        station_id=STATION_ID,
        attempt_id=_attempt_id(run_id, "st4-combined"),
        execution_status=execution_status,
        policy_verdict=policy_verdict,
        identity=dict(anchor),
        tool={"name": "wenqu_core.station4_behavior", "version": __version__},
        execution={
            "argv_digest": TrustedRunner.argv_digest(argv),
            "started_at": started_at,
            "ended_at": ended_at,
            **({"timeout_s": max(timeouts)} if timeouts else {}),
            "actual_exit_code": exit_code,
            "expected_exit_set": [0],
            "assertion_verdict": assertion,
        },
        coverage={
            "denominator": denominator,
            "scanned": scanned,
            **({"exclusions": exclusions} if exclusions else {}),
        },
        finding_ids=finding_ids,
        artifacts=artifacts,
    )
    return combined


def scan_station4(
    *,
    e2e: Optional[E2eScanner] = None,
    routes: Optional[RouteDynamicScanner] = None,
    gui: Optional[WebGuiScanner] = None,
) -> Dict[str, Any]:
    """站4 门面：顺序执行给定的腿扫描器并合并为单一 station-result-v2。"""
    legs = []
    for scanner in (e2e, routes, gui):
        if scanner is not None:
            legs.append(scanner.scan())
    if not legs:
        raise BehaviorStationError("scan_station4 needs at least one leg scanner")
    return combine_station4_results(legs)


# ---------------------------------------------------------------------------
# 端到端自证（python3 -m wenqu_core.station4_behavior）
# ---------------------------------------------------------------------------


def _self_test() -> int:  # noqa: C901——自测允许长函数
    import http.server
    import sys
    import threading

    from .bugscan_orchestrator import BugscanPlanner, default_registry

    registry = default_registry()
    registry.validate()
    planner = BugscanPlanner(registry)
    plan = planner.plan("STANDARD")
    assert plan.required_stations == (0, 1, 2, 3, 4), plan.required_stations

    sha = "1" * 40
    manifest = planner.freeze_run_manifest(
        plan,
        run_id="selftest-st4-001",
        project_id="wenqu-selftest",
        commit_sha=sha,
        environment="local",
        scope=["src/**", "tests/**"],
        ruleset={"version": "w6d", "rules": ["W6A-ST4"]},
        data_config={"profile": "default"},
    )

    import tempfile as _tf

    with _tf.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)

        # -- 伪 vitest：按发现文件写 jest 风格报告 -----------------------------
        repo = tmpdir / "repo"
        (repo / "tests").mkdir(parents=True)
        for name in ("a.test.ts", "b.spec.ts", "c.test.ts"):
            (repo / "tests" / name).write_text("// fake e2e\n", encoding="utf-8")
        fake_vitest = tmpdir / "fake_vitest.py"
        fake_vitest.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "out = [a for a in args if a.startswith('--outputFile=')][0].split('=', 1)[1]\n"
            "tests_dir = [a for a in args if not a.startswith('-')][0]\n"
            "root = (Path.cwd() / tests_dir).resolve()\n"
            "fail = next((a.split('=', 1)[1] for a in args if a.startswith('--fail=')), None)\n"
            "limit = int(next((a.split('=', 1)[1] for a in args if a.startswith('--limit=')), '0'))\n"
            "files = sorted(p for p in root.rglob('*.test.ts'))\n"
            "files += sorted(p for p in root.rglob('*.spec.ts'))\n"
            "if limit:\n"
            "    files = files[:limit]\n"
            "results = []\n"
            "any_fail = False\n"
            "for f in files:\n"
            "    bad = f.name == fail\n"
            "    any_fail = any_fail or bad\n"
            "    results.append({'name': str(f), 'status': 'failed' if bad else 'passed'})\n"
            "Path(out).write_text(json.dumps({'success': not any_fail, 'testResults': results}))\n"
            "sys.exit(1 if any_fail else 0)\n",
            encoding="utf-8",
        )
        vitest_argv = [
            sys.executable, str(fake_vitest), "--outputFile={output_file}", "{tests_dir}",
        ]

        # [1] 全绿路径
        e2e = E2eScanner(
            manifest, repo_root=str(repo),
            runner=TrustedRunner(default_cwd=str(repo), timeout=60.0),
            vitest_argv=vitest_argv, timeout_s=60,
        )
        st = e2e.scan()
        validate_station_result(st)
        assert st["policy_verdict"] == "PASS" and st["execution_status"] == "COMPLETED"
        assert st["coverage"] == {"denominator": 3, "scanned": 3}
        assert e2e.last_breakdown["files_passed"] == 3
        print(f"[1] e2e PASS OK: coverage {st['coverage']['scanned']}/"
              f"{st['coverage']['denominator']}, exit={st['execution']['actual_exit_code']}")

        # [2] 失败路径（--fail=b.spec.ts → exit 1）
        e2e_fail = E2eScanner(
            manifest, repo_root=str(repo),
            runner=TrustedRunner(default_cwd=str(repo), timeout=60.0),
            vitest_argv=vitest_argv + ["--fail=b.spec.ts"], timeout_s=60,
        )
        st = e2e_fail.scan()
        assert st["policy_verdict"] == "FAIL" and st["execution_status"] == "COMPLETED"
        assert st["coverage"]["scanned"] == 3 and len(st["finding_ids"]) == 1
        assert st["finding_ids"][0].startswith("fnd_e2e_")
        print(f"[2] e2e FAIL OK: findings={st['finding_ids']}")

        # [3] 缩水路径（--limit=2 → 只执行 2/3 → BLOCKED/NOT_EVALUATED）
        e2e_shrink = E2eScanner(
            manifest, repo_root=str(repo),
            runner=TrustedRunner(default_cwd=str(repo), timeout=60.0),
            vitest_argv=vitest_argv + ["--limit=2"], timeout_s=60,
        )
        st = e2e_shrink.scan()
        assert st["execution_status"] == "BLOCKED" and st["policy_verdict"] == "NOT_EVALUATED"
        assert st["coverage"]["scanned"] == 2 < st["coverage"]["denominator"]
        print(f"[3] e2e shrink OK: {st['coverage']['scanned']}/"
              f"{st['coverage']['denominator']} → BLOCKED (铁律2)")

        # [4] 超时路径（睡眠 5s、timeout 1s → 哨兵 -1 + 缩水 BLOCKED）
        sleeper = tmpdir / "sleeper.py"
        sleeper.write_text("import time; time.sleep(5)\n", encoding="utf-8")
        e2e_to = E2eScanner(
            manifest, repo_root=str(repo),
            runner=TrustedRunner(default_cwd=str(repo), timeout=1.0),
            vitest_argv=[sys.executable, str(sleeper), "--outputFile={output_file}"],
            timeout_s=1,
        )
        st = e2e_to.scan()
        assert st["coverage"]["scanned"] == 0 and st["policy_verdict"] == "NOT_EVALUATED"
        assert st["execution"]["actual_exit_code"] == -1
        print(f"[4] e2e timeout OK: exit=-1 sentinel → {st['execution_status']}/"
              f"{st['policy_verdict']}")

        # [5] 路由动态腿：本地真实 HTTP 服务 -------------------------------
        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/":
                    self.send_response(200)
                else:
                    self.send_response(404)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):  # 静音
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            routes = RouteDynamicScanner(
                manifest,
                routes=[
                    {"name": "home", "method": "GET", "path": "/", "expected_status": 200},
                    {"name": "missing", "method": "GET", "path": "/nope",
                     "expected_status": [404]},
                ],
                base_url=base,
            )
            st = routes.scan()
            validate_station_result(st)
            assert st["policy_verdict"] == "PASS" and st["coverage"]["scanned"] == 2
            print(f"[5a] route PASS OK: 2/2 probed on {base}")

            bad = RouteDynamicScanner(
                manifest,
                routes=[{"name": "home", "path": "/", "expected_status": 200}],
                base_url=base,
            )
            bad._routes[0]["expected_status"] = [500]  # 注入不匹配期望
            st = bad.scan()
            assert st["policy_verdict"] == "FAIL" and st["finding_ids"][0].startswith("fnd_route_")
            print(f"[5b] route FAIL OK: mismatch → {st['finding_ids']}")

            dead = RouteDynamicScanner(
                manifest,
                routes=[{"name": "home", "path": "/", "expected_status": 200}],
                base_url="http://127.0.0.1:1",  # 不可达端口
                request_timeout_s=1.0,
            )
            st = dead.scan()
            assert st["execution_status"] == "BLOCKED" and st["policy_verdict"] == "NOT_EVALUATED"
            print("[5c] route unreachable OK: 环境探不到证据 → BLOCKED（不猜证据）")

            # [6] 整站合并 + 门面（服务仍在运行：路由腿可探）
            combined = scan_station4(
                e2e=E2eScanner(
                    manifest, repo_root=str(repo),
                    runner=TrustedRunner(default_cwd=str(repo), timeout=60.0),
                    vitest_argv=vitest_argv, timeout_s=60,
                ),
                routes=RouteDynamicScanner(
                    manifest,
                    routes=[{"name": "home", "path": "/", "expected_status": 200}],
                    base_url=base,
                ),
            )
            validate_station_result(combined)
            assert combined["station_id"] == 4 and combined["policy_verdict"] == "PASS"
            assert combined["coverage"]["denominator"] == 4  # 3 e2e + 1 route
            print(f"[6] combine OK: station-4 single result "
                  f"{combined['coverage']['scanned']}/{combined['coverage']['denominator']} → "
                  f"{combined['execution_status']}/{combined['policy_verdict']}")

            # [7] 一致性硬门：异 run 腿合并必拒
            other_manifest = planner.freeze_run_manifest(
                plan, run_id="selftest-st4-OTHER", project_id="wenqu-selftest",
                commit_sha="2" * 40, environment="local",
                scope=["src/**"], ruleset={"version": "w6d"}, data_config={"p": 1},
            )
            other_e2e = E2eScanner(
                other_manifest, repo_root=str(repo),
                runner=TrustedRunner(default_cwd=str(repo), timeout=60.0),
                vitest_argv=vitest_argv, timeout_s=60,
            )
            try:
                combine_station4_results([e2e.scan(), other_e2e.scan()])
                raise AssertionError("cross-run legs must be refused")
            except BehaviorStationError:
                print("[7] combine consistency OK: 跨 run/SHA 腿拒绝合并")
        finally:
            server.shutdown()
            server.server_close()

        # [8] 浏览器抽检腿：伪 gui 检查器（web-gui-tester 范式报告） ---------
        fake_gui = tmpdir / "fake_gui.py"
        fake_gui.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "out = [a for a in args if a.startswith('--report=')][0].split('=', 1)[1]\n"
            "fail = next((a.split('=', 1)[1] for a in args if a.startswith('--fail=')), None)\n"
            "omit = next((a.split('=', 1)[1] for a in args if a.startswith('--omit=')), None)\n"
            "names = ['login-flow', 'order-create']\n"
            "scenarios = []\n"
            "any_fail = False\n"
            "for n in names:\n"
            "    if n == omit:\n"
            "        continue\n"
            "    ok = n != fail\n"
            "    any_fail = any_fail or not ok\n"
            "    scenarios.append({'name': n, 'passed': ok, 'console_errors': [],\n"
            "                      'failed_requests': [], 'steps': 3})\n"
            "Path(out).write_text(json.dumps({'browser': 'chromium-selftest',\n"
            "    'base_url': 'http://local', 'planned': names, 'scenarios': scenarios}))\n"
            "sys.exit(1 if any_fail else 0)\n",
            encoding="utf-8",
        )
        gui_report = tmpdir / "gui-report.json"

        def _gui(extra=()):
            return WebGuiScanner(
                manifest,
                check_argv=[sys.executable, str(fake_gui), "--report={report_file}", *extra],
                report_path=str(gui_report),
                runner=TrustedRunner(timeout=60.0),
                timeout_s=60,
            )

        st = _gui().scan()
        validate_station_result(st)
        assert st["policy_verdict"] == "PASS" and st["coverage"] == {"denominator": 2, "scanned": 2}
        print(f"[8a] web-gui PASS OK: {st['coverage']['scanned']}/"
              f"{st['coverage']['denominator']} scenarios on chromium-selftest")

        st = _gui(("--fail=order-create",)).scan()
        assert st["policy_verdict"] == "FAIL" and st["finding_ids"][0].startswith("fnd_gui_")
        print(f"[8b] web-gui FAIL OK: {st['finding_ids']}")

        st = _gui(("--omit=order-create",)).scan()
        assert st["execution_status"] == "BLOCKED" and st["coverage"]["scanned"] == 1
        print("[8c] web-gui missing-scenario OK: 1/2 → BLOCKED")

    print("SELF-TEST PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

# -*- coding: utf-8 -*-
"""station2_static.py——Codex 方案 W6B：Bug 八站·站2（静态与供应链）适配器。

血统与契约正源：
- Codex 方案 W6B（站2 适配）；W6A §7.1 注册表站2 定义（slug=static_supply，
  判据 pass=克隆≤基线/CVE 零 HIGH+/探测器零 FAIL；error=环境错不落账不计通过；
  evidence_class=permission_vulnerability → TTL 7 天）。
- 《问渠轨道规范（发行版 v2.0）》§1 八站骨架·站2 与探测器 rc 契约：
  exit 1=命中自动落账 OPEN；exit ≥2=环境错误不落账不计通过。
- wenqu-vNext-contract §7 统一退出码（0=PASS/1=FAIL/2=ERROR/3=BLOCKED/124=TIMEOUT）。
- 每站输出严格遵循 schemas/station-result-v2.schema.json（复用 W6A 的
  build_station_result/validate_station_result 构造与双重校验——不另造校验器）。

四个扫描适配器（编排层不造扫描工具，只包装既有件）：
- SupplyChainScanner     npm audit --json（经 TrustedRunner）→ 解析 vulnerabilities
                         列表；有效 JSON + HIGH/CRITICAL→FAIL；空输出/解析失败/
                         自报计数与解析列表不一致/超时→ERROR 类（绝非 PASS）。
                         两个可选产品面（默认关闭）：SC-03 lockfile 变更差异
                         （新增依赖单独计入 finding/分母；resolved/integrity/
                         install script 变化→HIGH/P1→FAIL/人工审）；SC-05 离线
                         快照签名+时效校验（build_snapshot_envelope 信封，
                         验签失败/过期→该源数据不可用→BLOCKED，fail-closed）。
- DuplicateCodeScanner   jscpd（经 TrustedRunner，钉版本口径）→ 读 jscpd-report.json
                         → 与 dupscan 基线（JSON）棘轮比对（只减不增，超基线=FAIL）。
- EngineFiveTypesScanner 持续修复引擎五类（ENUM/CTX/MSG/DUALWRITE/DOMAIN）——
                         状态正源=engine-state.json（或经 runner 跑引擎扫描命令，
                         stdout JSON 同构解析）；判据=五类 0 open。
- RouteIntegrityScanner  路由完整性静态腿——执行 stations.json 风格探测器
                         （argv 直执行；rc 契约 0=净/1=命中/≥2=环境错），
                         命中项 stdout 为 JSON findings 列表时逐条落账。

硬约束（违反任一=实现缺陷）：
1. 空输出/解析失败=ERROR（T-07：空输出≠零发现）；工具缺失/超时同样不得记 PASS。
2. coverage.denominator 一律动态计算（依赖总数取自 npm metadata、源文件数取自
   本模块独立 os.walk、五类宇宙=已知五类∪state queue、路由入口数取自 os.walk）——
   任何位置不得硬编码分母。
3. findings 计数一律取自解析后的列表（len(parsed)），绝不采信工具自报数字；
   npm audit 的 metadata.vulnerabilities 自报 HIGH+CRITICAL 计数与解析列表
   不一致时按证据损坏处理（ERROR，fail-closed）。
4. 站内任一执行件 BLOCKED/ERROR/TIMEOUT→整站不得记 PASS（铁律 2；聚合层以
   执行件数分母 + 分母缩水守卫机械实现——见 Station2Static）。
5. 所有命令经 TrustedRunner 系执行（argv 列表、shell=False、真实 returncode）；
   RawTrustedRunner 为其原始输出捕获扩展——安全构造不变（继承 _validate_argv：
   只接受 argv 列表、拒绝整串 shell 命令），仅额外保留 stdout/stderr 字节供解析。
   注入普通 TrustedRunner 时，需原始输出的扫描器一律 fail-closed 记 ERROR。
6. 超时无 returncode 可取：execution.actual_exit_code 记 §7 契约的 TIMEOUT=124
   （契约映射，与 source_gate 的 EXIT_TIMEOUT 同语义，非推测美化）。
7. 分母缩水守卫（W6A 冻结）：scanned<denominator → 整站/子件强制 BLOCKED——
   文件级分母已知时，超时/错误会被折叠为 BLOCKED（语义=证据不完整）。

用法（最小）::

    st2 = Station2Static(
        run_id="run-20261007-001",
        identity={"project_id": "acme/erp", "commit_sha": "<40hex>",
                  "environment": "local", "scope_hash": "<64hex>",
                  "ruleset_hash": "<64hex>", "data_config_hash": "<64hex>"},
        repo_dir="/path/to/repo",
        baseline_path="/path/to/dupscan-baseline.json",
        route_probe_argv=["node", "scripts/argus/route-scan.mjs", "--static"],
    )
    report = st2.scan()
    report["station_result"]        # 站2 聚合 station-result-v2（schema 合规）
    report["scanner_results"]       # {"supply": {...}, "dupscan": {...}, ...} 子件结果
    report["findings"]              # 解析后 finding 明细（fingerprint/severity/priority）
    report["notes"]                 # 各子件 ERROR/BLOCKED 原因（审计用）
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

try:  # 包内正则导入（wenqu_core.station2_static）
    from .bugscan_orchestrator import (
        StationResultValidationError,
        build_station_result,
        validate_station_result,
    )
    from .runner import Evidence, TrustedRunner
except ImportError:  # 顶层直接加载兜底（如 python3 wenqu_core/station2_static.py）
    from bugscan_orchestrator import (  # type: ignore
        StationResultValidationError,
        build_station_result,
        validate_station_result,
    )
    from runner import Evidence, TrustedRunner  # type: ignore

__all__ = [
    "STATION_ID",
    "STATION2_VERSION",
    "SCAN_SLUGS",
    "ENGINE_FIVE_TYPES",
    "DEFAULT_NPM_AUDIT_ARGV",
    "DEFAULT_ENGINE_STATE_PATH",
    "JSCPD_PINNED_VERSION",
    "DEFAULT_JSCPD_MIN_TOKENS",
    "SNAPSHOT_KIND",
    "DEFAULT_SNAPSHOT_MAX_AGE_S",
    "Station2Error",
    "Station2ConfigError",
    "RawTrustedRunner",
    "CapturedRun",
    "ScanFinding",
    "ScannerReport",
    "build_snapshot_envelope",
    "SupplyChainScanner",
    "DuplicateCodeScanner",
    "EngineFiveTypesScanner",
    "RouteIntegrityScanner",
    "Station2Static",
]

__version__ = "1.0.0"

STATION_ID = 2
STATION2_VERSION = "w6b-1.0.0"

#: 站2 四个执行件 slug（聚合分母=启用件数——动态，随构造参数变化）。
SCAN_SLUGS: Tuple[str, ...] = ("supply", "dupscan", "engine", "route")

#: 持续修复引擎五类（bug-scan-pipeline §1 站2 行：ENUM/CTX/MSG/DUALWRITE/DOMAIN）。
#: 这是引擎的版本化分类法种子；分母宇宙=该集合 ∪ engine-state queue 实际 slug
#: （引擎扩类时分母自动增长——动态，非硬编码分母）。
ENGINE_FIVE_TYPES: Tuple[str, ...] = ("enum", "ctx", "msg", "dualwrite", "envdomain")

#: engine-state.json 状态串的「已收口」标记词表（状态串是引擎自由文本；
#: 刻意保守——只有命中这些标记才算闭环，歧义状态一律按 open 计，fail-closed）。
_ENGINE_CLOSED_MARKERS: Tuple[str, ...] = (
    "MERGED", "收官", "✅", "CLOSED", "DONE", "VERIFIED", "闭环",
)

#: 状态正源默认路径（bug-scan-pipeline §1：engine-state.json；可用参数覆写）。
DEFAULT_ENGINE_STATE_PATH = (
    Path.home() / "Documents" / "ERP）Zcode" / "持续修复引擎" / "engine-state.json"
)

DEFAULT_NPM_AUDIT_ARGV: Tuple[str, ...] = ("npm", "audit", "--json")
JSCPD_PINNED_VERSION = "5.1.2"  # dupscan-fullscan skill：jscpd 钉版本钉口径
DEFAULT_JSCPD_MIN_TOKENS = 50
JSCPD_REPORT_NAME = "jscpd-report.json"

#: 统一退出码（wenqu-vNext-contract §7 子集；与 source_gate EXIT_* 同源）。
_EXIT_PASS, _EXIT_FAIL, _EXIT_ERROR, _EXIT_BLOCKED, _EXIT_TIMEOUT = 0, 1, 2, 3, 124

_RE_RUN_ID = re.compile(r"^[a-zA-Z0-9_-]+$")
_RE_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RE_JSCPD_VER = re.compile(r"jscpd@([0-9][0-9A-Za-z.\-]*)")

_ST2_IDENTITY_KEYS = frozenset({
    "project_id", "commit_sha", "environment", "scope_hash",
    "ruleset_hash", "data_config_hash", "lockfile_hash",
})

#: npm severity → (severity, priority)；未知 severity 保守升 HIGH/P1（fail-closed 方向）。
_NPM_SEV_MAP: Dict[str, Tuple[str, str]] = {
    "critical": ("CRITICAL", "P0"),
    "high": ("HIGH", "P1"),
    "moderate": ("MEDIUM", "P2"),
    "medium": ("MEDIUM", "P2"),
    "low": ("LOW", "P3"),
    "info": ("LOW", "P3"),
}

#: 探测器 finding severity → (severity, priority)；缺失/未知→MEDIUM/P2。
_PROBE_SEV_MAP: Dict[str, Tuple[str, str]] = {
    "critical": ("CRITICAL", "P0"),
    "high": ("HIGH", "P1"),
    "medium": ("MEDIUM", "P2"),
    "moderate": ("MEDIUM", "P2"),
    "low": ("LOW", "P3"),
    "info": ("LOW", "P3"),
}

_WALK_SKIP_DIRS: FrozenSet[str] = frozenset({
    ".git", ".wenqu", "node_modules", "__pycache__", ".venv", "venv",
    ".tmp", "dist", "build", "out", "coverage", ".next",
})

_JSCPD_SOURCE_EXTS: Tuple[str, ...] = (
    ".ts", ".tsx", ".js", ".jsx", ".py", ".sh", ".go", ".rs", ".java",
)

_ROUTE_EXTS: Tuple[str, ...] = (".ts", ".tsx", ".js", ".jsx")

#: finding 明细默认上限（防 2909 对级克隆洪泛账本；计数仍取全量解析列表）。
DEFAULT_FINDING_DETAIL_CAP = 50

#: 离线依赖快照信封 kind（SC-05：签名+时效校验的信封契约）。
SNAPSHOT_KIND = "wenqu-npm-audit-snapshot/1"

#: 快照默认新鲜度窗口（7 天——对齐站2 evidence_class=permission_vulnerability
#: 的 TTL 严档；过期=依赖基线陈旧→fail-closed 该源数据不可用）。
DEFAULT_SNAPSHOT_MAX_AGE_S = 7 * 86400

#: 快照 captured_at 允许的时钟偏移容忍（未来时间戳超过该窗=回放/伪造迹象）。
_SNAPSHOT_FUTURE_SKEW_S = 60.0


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------

class Station2Error(RuntimeError):
    """站2 适配器基类异常（fail-closed：绝不折算为 PASS）。"""


class Station2ConfigError(Station2Error, ValueError):
    """构造参数非法（run_id/identity/repo_dir/scanners 等）——快速失败。"""


class _PayloadError(ValueError):
    """原始输出解析失败——一律映射 ERROR（空输出≠零发现，T-07）。"""


class _SnapshotVerificationError(ValueError):
    """离线快照验签/时效失败（SC-05）——该源数据不可用，fail-closed 映射
    BLOCKED（§20.5 期望；绝不折算 PASS，也绝不采信未验签的载荷内容）。"""


# ---------------------------------------------------------------------------
# 基础工具：canonical JSON + 哈希 + 时间
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_obj(obj: Any) -> str:
    return _sha256_hex(_canonical_json(obj).encode("utf-8"))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ts_to_iso(ts: float) -> str:
    return _iso_z(datetime.fromtimestamp(float(ts), tz=timezone.utc))


def _argv_digest(argv: Sequence[str]) -> str:
    """与 runner.TrustedRunner.argv_digest 同算法（canonical JSON of argv list）。"""
    canonical = json.dumps(list(argv), separators=(",", ":"), ensure_ascii=False)
    return _sha256_hex(canonical.encode("utf-8"))


def _parse_iso_dt(value: Any) -> Optional[datetime]:
    """宽松 ISO-8601 解析（接受 Z 后缀）；失败返回 None（不抛）。"""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:  # 无时区=不可比较——拒绝（fail-closed）
        return None
    return parsed


def build_snapshot_envelope(
    payload: Any,
    *,
    key: str,
    captured_at: Any,
) -> Dict[str, Any]:
    """离线依赖快照信封生产端（与 SupplyChainScanner.verify_snapshot_envelope
    对偶的签名通道，SC-05）。

    信封契约::

        {"snapshot": {"kind": SNAPSHOT_KIND,
                      "captured_at": "…Z",
                      "content_hash": sha256(canonical(payload)),
                      "signature": hmac_sha256(key, "<content_hash>.<captured_at>")},
         "payload": {…npm audit JSON…}}

    content_hash 绑定 canonical JSON（键序无关），signature 再绑
    hash+时间戳——载荷被签名后改动任何字节、换时间戳、换 hash 三者
    任一都会在验签面失配。
    """
    if not isinstance(key, str) or not key:
        raise Station2ConfigError("snapshot signing key must be a non-empty string")
    captured_iso = (
        captured_at if isinstance(captured_at, str) else _iso_z(captured_at)
    )
    if not isinstance(payload, Mapping):
        raise Station2ConfigError(
            f"snapshot payload must be a mapping, got {type(payload).__name__}"
        )
    content_hash = _sha256_hex(_canonical_json(dict(payload)).encode("utf-8"))
    signature = hmac.new(
        key.encode("utf-8"),
        f"{content_hash}.{captured_iso}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "snapshot": {
            "kind": SNAPSHOT_KIND,
            "captured_at": captured_iso,
            "content_hash": content_hash,
            "signature": signature,
        },
        "payload": dict(payload),
    }


def _attempt_id(run_id: str, tag: str) -> str:
    seed = _hash_obj({"run_id": run_id, "tag": tag, "ts": _iso_z(_utc_now())})
    return f"att-{tag}-{seed[:12]}"


def _validate_identity(identity: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(identity, Mapping):
        raise Station2ConfigError(
            f"identity must be a mapping, got {type(identity).__name__}"
        )
    extra = set(identity) - set(_ST2_IDENTITY_KEYS)
    if extra:
        raise Station2ConfigError(
            f"identity additional properties not allowed: {sorted(extra)} "
            f"(allowed: {sorted(_ST2_IDENTITY_KEYS)})"
        )
    commit_sha = identity.get("commit_sha")
    if not isinstance(commit_sha, str) or not _RE_SHA40.match(commit_sha):
        raise Station2ConfigError(
            f"identity.commit_sha must be a 40-char lowercase hex SHA, got {commit_sha!r}"
        )
    for key in ("environment", "scope_hash"):
        value = identity.get(key)
        if not isinstance(value, str) or not value:
            raise Station2ConfigError(f"identity.{key} must be a non-empty string")
    for key in ("project_id", "ruleset_hash", "data_config_hash", "lockfile_hash"):
        if key in identity and not isinstance(identity[key], str):
            raise Station2ConfigError(f"identity.{key} must be a string")
    return dict(identity)


def _validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RE_RUN_ID.match(run_id):
        raise Station2ConfigError(f"run_id must match {_RE_RUN_ID.pattern}, got {run_id!r}")
    return run_id


def _mk_finding(
    *,
    rule_id: str,
    file_path: str,
    line_start: int,
    severity: str,
    priority: str,
    snippet: str,
    message: str,
) -> "ScanFinding":
    """构造 finding——fingerprint 对齐 finding-event-v2 语义：
    sha256(file_path | line_start | rule_id | sha256(code_snippet))。
    finding_id=fnd_+指纹前 16 位（确定性：同缺陷跨轮重扫得到同 id，幂等去重）。
    """
    snippet_hash = _sha256_hex(snippet.encode("utf-8"))
    fingerprint = _sha256_hex(
        f"{file_path}|{int(line_start)}|{rule_id}|{snippet_hash}".encode("utf-8")
    )
    return ScanFinding(
        rule_id=rule_id,
        file_path=file_path,
        line_start=int(line_start),
        severity=severity,
        priority=priority,
        fingerprint=fingerprint,
        message=message,
    )


def _walk_source_files(
    repo_dir: Path, roots: Sequence[str], exts: Sequence[str]
) -> List[str]:
    """独立 os.walk 计数（分母正源之一——不信任工具自报的 files 数）。"""
    matched: List[str] = []
    ext_tuple = tuple(exts)
    for root in roots:
        base = repo_dir / root
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(
                d for d in dirnames if d not in _WALK_SKIP_DIRS and not d.startswith(".")
            )
            for name in sorted(filenames):
                if name.endswith(ext_tuple):
                    matched.append(os.path.relpath(os.path.join(dirpath, name), repo_dir))
    return sorted(set(matched))


def _walk_route_entries(repo_dir: Path) -> List[str]:
    """动态计算路由入口分母：App Router（app/**/page.*|route.*）+ Pages Router
    （pages/** 下非 _ 前缀页面文件）。独立 walk，不依赖任何自报数字。"""
    entries: List[str] = []
    ext_tuple = tuple(_ROUTE_EXTS)
    for marker in ("app", "src/app"):
        base = repo_dir / marker
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(
                d for d in dirnames if d not in _WALK_SKIP_DIRS and not d.startswith(".")
            )
            for name in sorted(filenames):
                stem, ext = os.path.splitext(name)
                if stem in ("page", "route") and ext in ext_tuple:
                    entries.append(os.path.relpath(os.path.join(dirpath, name), repo_dir))
    for marker in ("pages", "src/pages"):
        base = repo_dir / marker
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(
                d for d in dirnames if d not in _WALK_SKIP_DIRS and not d.startswith(".")
            )
            for name in sorted(filenames):
                stem, ext = os.path.splitext(name)
                if ext in ext_tuple and not stem.startswith("_"):
                    entries.append(os.path.relpath(os.path.join(dirpath, name), repo_dir))
    return sorted(set(entries))


def _unified_exit(execution_status: str, policy_verdict: str) -> int:
    """双轴 → §7 统一退出码（契约映射，与 source_gate/SOURCE_GATE 映射同源）。"""
    if execution_status == "TIMEOUT":
        return _EXIT_TIMEOUT
    if execution_status == "ERROR":
        return _EXIT_ERROR
    if execution_status == "BLOCKED":
        return _EXIT_BLOCKED
    if policy_verdict == "FAIL":
        return _EXIT_FAIL
    if policy_verdict == "CONDITIONAL":
        return 4
    return _EXIT_PASS


# ---------------------------------------------------------------------------
# RawTrustedRunner——TrustedRunner 的原始输出捕获扩展
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CapturedRun:
    """一次受信执行的完整记录：不可伪造 Evidence + 原始 stdout/stderr 字节。

    原始字节仅用于 finding 解析（空/畸形→ERROR）；退出码语义以 Evidence 为准。
    """

    evidence: Evidence
    stdout: Optional[bytes]
    stderr: Optional[bytes]

    def stdout_text(self) -> Optional[str]:
        return None if self.stdout is None else self.stdout.decode("utf-8", errors="replace")


class RawTrustedRunner(TrustedRunner):
    """在不动 runner.py 安全构造的前提下保留原始输出。

    - argv 校验复用 TrustedRunner._validate_argv（只接受 argv 列表、可执行必须在
      PATH、allowlist 拒绝）——继承而非重写，防口径漂移。
    - 执行同样是 subprocess.run(list, shell=False, capture_output=True)；
      actual_exit_code 仍取真实 returncode（不可伪造语义不变）。
    - 与父类的差异仅在：完成后额外返回 stdout/stderr 原始字节（父类只留哈希）。
    - timeout/cwd 由本类构造参数自持副本（父类未暴露读取器，不从父类私有态取值）。
    """

    def __init__(
        self,
        *,
        default_cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        freshness_seconds: float = 300.0,
        allowed_executables: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(
            default_cwd=default_cwd,
            timeout=timeout,
            freshness_seconds=freshness_seconds,
            allowed_executables=allowed_executables,
        )
        self._raw_default_cwd = default_cwd
        self._raw_timeout = timeout

    def run_captured(self, argv: List[str], cwd: Optional[str] = None) -> CapturedRun:
        self._validate_argv(argv)
        workdir = cwd or self._raw_default_cwd or os.getcwd()
        timestamp = time.time()
        fresh_until = timestamp + 300.0  # 与父类默认 freshness 一致（仅用于 Evidence 构造）
        argv_digest = TrustedRunner.argv_digest(list(argv))
        try:
            completed = subprocess.run(
                list(argv),
                cwd=workdir,
                shell=False,
                capture_output=True,
                timeout=self._raw_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            partial_out = bytes(exc.stdout or b"")
            partial_err = bytes(exc.stderr or b"")
            evidence = Evidence(
                argv=tuple(argv),
                cwd=workdir,
                actual_exit_code=None,
                stdout_sha256=_sha256_hex(partial_out),
                stderr_sha256=_sha256_hex(partial_err),
                argv_digest=argv_digest,
                timestamp=timestamp,
                fresh_until=fresh_until,
                timed_out=True,
            )
            return CapturedRun(evidence=evidence, stdout=partial_out, stderr=partial_err)
        evidence = Evidence(
            argv=tuple(argv),
            cwd=workdir,
            actual_exit_code=completed.returncode,
            stdout_sha256=_sha256_hex(completed.stdout),
            stderr_sha256=_sha256_hex(completed.stderr),
            argv_digest=argv_digest,
            timestamp=timestamp,
            fresh_until=fresh_until,
            timed_out=False,
        )
        return CapturedRun(evidence=evidence, stdout=completed.stdout, stderr=completed.stderr)


# ---------------------------------------------------------------------------
# ScanFinding / ScannerReport
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScanFinding:
    """解析后的单条 finding（对齐 finding-event-v2 的 fingerprint/severity/priority）。"""

    rule_id: str
    file_path: str
    line_start: int
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW
    priority: str        # P0 / P1 / P2 / P3（默认 CRITICAL→P0、HIGH→P1，不降级）
    fingerprint: str     # sha256(file_path|line_start|rule_id|snippet_hash)
    message: str

    @property
    def finding_id(self) -> str:
        return "fnd_" + self.fingerprint[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "priority": self.priority,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "message": self.message,
        }


@dataclass(frozen=True)
class ScannerReport:
    """单个执行件的产物：schema 合规子结果 + finding 明细 + 审计备注。"""

    slug: str
    result: Dict[str, Any]
    findings: Tuple[ScanFinding, ...] = ()
    note: str = ""


# ---------------------------------------------------------------------------
# 执行件基座
# ---------------------------------------------------------------------------

class _Station2Scanner:
    """站2 执行件基座：身份绑定、runner 执行通道、station-result 组装。"""

    slug: str = ""
    tool_name: str = ""

    def __init__(
        self,
        *,
        run_id: str,
        identity: Mapping[str, Any],
        repo_dir: "str | os.PathLike[str]",
        runner: TrustedRunner,
        timeout_s: int = 300,
    ) -> None:
        repo = Path(repo_dir)
        if not repo.is_dir():
            raise Station2ConfigError(f"repo_dir is not a directory: {repo}")
        self._run_id = run_id
        self._identity: Dict[str, Any] = dict(identity)
        self._repo_dir = repo
        self._runner = runner
        self._timeout_s = max(1, int(timeout_s))

    # -- 执行通道 ------------------------------------------------------------
    def _execute(self, argv: Sequence[str]) -> CapturedRun:
        """任意 TrustedRunner 可用（原始输出不可得时 stdout=None，调用方 fail-closed）。"""
        if isinstance(self._runner, RawTrustedRunner):
            return self._runner.run_captured(list(argv))
        evidence = self._runner.run(list(argv))
        return CapturedRun(evidence=evidence, stdout=None, stderr=None)

    def _execute_raw(self, argv: Sequence[str]) -> Optional[CapturedRun]:
        """需原始 stdout 的件专用：普通 TrustedRunner 无原始输出→None→ERROR。"""
        if isinstance(self._runner, RawTrustedRunner):
            return self._runner.run_captured(list(argv))
        return None

    # -- 结果组装 ------------------------------------------------------------
    def _finalize(
        self,
        *,
        execution_status: str,
        policy_verdict: str,
        findings: Sequence[ScanFinding],
        denominator: int,
        scanned: int,
        expected_exit_set: Sequence[int],
        actual_exit_code: int,
        argv_digest: str,
        started_at: str,
        ended_at: str,
        tool_version: str,
        tool_digest: Optional[str] = None,
        exclusions: Sequence[str] = (),
        note: str = "",
    ) -> ScannerReport:
        if execution_status == "COMPLETED" and policy_verdict in ("PASS", "NOT_APPLICABLE"):
            assertion = "PASS"
        elif policy_verdict == "FAIL":
            assertion = "FAIL"
        else:
            assertion = "ERROR"
        execution: Dict[str, Any] = {
            "argv_digest": argv_digest,
            "cwd_digest": _sha256_hex(str(self._repo_dir.resolve()).encode("utf-8")),
            "started_at": started_at,
            "ended_at": ended_at,
            "timeout_s": self._timeout_s,
            "actual_exit_code": int(actual_exit_code),
            "expected_exit_set": sorted({int(x) for x in expected_exit_set}),
            "assertion_verdict": assertion,
        }
        tool: Dict[str, Any] = {"name": self.tool_name, "version": tool_version}
        if tool_digest:
            tool["digest"] = tool_digest
        coverage: Dict[str, Any] = {
            "denominator": int(denominator),
            "scanned": int(scanned),
        }
        if exclusions:
            coverage["exclusions"] = sorted(set(exclusions))
        # 工件契约（station-result-v2）：PASS 必须携带非空 artifacts——以报告主体
        # （tool/execution/coverage/finding_ids）的规范化内容摘要作为该扫描器
        # 报告工件，与站0 manifest 工件、站1 gate 工件同一寻址范式
        artifact_body = json.dumps(
            {"tool": tool, "execution": execution, "coverage": coverage,
             "finding_ids": [f.finding_id for f in findings]},
            separators=(",", ":"), ensure_ascii=False, sort_keys=True,
        ).encode("utf-8")
        result = build_station_result(
            run_id=self._run_id,
            station_id=STATION_ID,
            attempt_id=_attempt_id(self._run_id, f"st2-{self.slug}"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=self._identity,
            tool=tool,
            execution=execution,
            coverage=coverage,
            finding_ids=[f.finding_id for f in findings],
            artifacts=[{
                "cas_digest": f"sha256:{_sha256_hex(artifact_body)}",
                "size": len(artifact_body),
            }],
        )
        validate_station_result(result)
        return ScannerReport(
            slug=self.slug, result=result, findings=tuple(findings), note=note
        )

    def _error_report(
        self,
        reason: str,
        *,
        argv: Sequence[str],
        expected_exit_set: Sequence[int],
        denominator: int = 0,
        scanned: int = 0,
        tool_version: str = "unavailable",
        actual_exit_code: Optional[int] = None,
    ) -> ScannerReport:
        now_iso = _iso_z(_utc_now())
        return self._finalize(
            execution_status="ERROR",
            policy_verdict="NOT_EVALUATED",
            findings=[],
            denominator=denominator,
            scanned=scanned,
            expected_exit_set=expected_exit_set,
            actual_exit_code=_EXIT_ERROR if actual_exit_code is None else int(actual_exit_code),
            argv_digest=_argv_digest(argv),
            started_at=now_iso,
            ended_at=now_iso,
            tool_version=tool_version,
            note=reason,
        )

    def _timeout_report(
        self,
        reason: str,
        *,
        argv: Sequence[str],
        expected_exit_set: Sequence[int],
        timestamp: float,
        denominator: int = 0,
        scanned: int = 0,
        tool_version: str = "unavailable",
    ) -> ScannerReport:
        ts_iso = _ts_to_iso(timestamp)
        return self._finalize(
            execution_status="TIMEOUT",
            policy_verdict="NOT_EVALUATED",
            findings=[],
            denominator=denominator,
            scanned=scanned,
            expected_exit_set=expected_exit_set,
            actual_exit_code=_EXIT_TIMEOUT,  # §7 契约 TIMEOUT=124（超时无 returncode）
            argv_digest=_argv_digest(argv),
            started_at=ts_iso,
            ended_at=ts_iso,
            tool_version=tool_version,
            note=reason,
        )

    def scan(self) -> ScannerReport:  # pragma: no cover - 抽象基座
        raise NotImplementedError


# ---------------------------------------------------------------------------
# SupplyChainScanner——npm audit（供应链 CVE）
# ---------------------------------------------------------------------------

class SupplyChainScanner(_Station2Scanner):
    """npm audit --json 适配：exit code 双轴映射 + 解析列表为 findings 正源。

    判定矩阵（判据正源=W6A 站2：CVE 零 HIGH 及以上（含 CRITICAL））：
    - 超时（Evidence.timed_out）           → TIMEOUT / NOT_EVALUATED（ERROR 类）
    - exit ≥2                              → ERROR（环境错：registry 不可达/锁缺失等）
    - stdout 空 / 非 JSON / 缺 vulnerabilities / 缺 metadata    → ERROR（T-07）
    - 有效 JSON + 解析列表含 HIGH/CRITICAL → FAIL（findings=解析列表逐条）
    - 有效 JSON + 仅 MODERATE/LOW/INFO      → PASS（findings 照落账，策略轴不红）
    - metadata 自报 HIGH+CRITICAL 计数 ≠ 解析列表计数 → ERROR（证据损坏，不猜）
    coverage：denominator=scanned=metadata.dependencies.total（动态，npm 自报依赖
    总数——这是分母的合法正源；漏洞「发现数」才必须取解析列表）。

    两个可选产品面（默认关闭；开启时不影响上述基础矩阵）：
    - SC-03 lockfile 变更差异（lockfile_baseline_path 给出即开启）：解析
      package-lock.json（v2/v3 packages 面 + v1 dependencies 面兜底）与基线
      lockfile 的依赖指纹（resolved/integrity/hasInstallScript）——新增依赖
      每个单独计入 finding 与分母（denominator += 新增数）；resolved/integrity
      变化与新增 install script 各落一条 HIGH/P1 finding（§20.3：install
      script/resolved/integrity 变化→FAIL/人工审）。基线/当前 lockfile 缺失
      或畸形=无锚点→ERROR（fail-closed，同 dupscan 基线纪律）。
    - SC-05 快照签名/时效（snapshot_verify_key 给出即开启）：stdout 必须是
      build_snapshot_envelope 信封（content_hash+captured_at+HMAC 签名）；
      验签失败/内容哈希失配/时间戳非法或未来/过期（captured_at 距今超
      snapshot_max_age_s）→ 该源数据不可用 → BLOCKED（§20.5；分母不采信
      未验签载荷，0/0+原因入 note）。分页不全天性由 parse_audit_payload 的
      pagination 门（R7-SC-PAGINATION-008：complete 非 true/page<pages_total
      → ERROR）与 ADV-02 的自报计数交叉核对机制共同覆盖（截断=证据损坏
      ERROR，绝不折算 PASS）。
    """

    slug = "supply"
    tool_name = "npm-audit"

    def __init__(
        self,
        *,
        lockfile_name: str = "package-lock.json",
        npm_argv: Optional[Sequence[str]] = None,
        lockfile_baseline_path: Optional[str] = None,
        snapshot_verify_key: Optional[str] = None,
        snapshot_max_age_s: float = DEFAULT_SNAPSHOT_MAX_AGE_S,
        **base_kwargs: Any,
    ) -> None:
        super().__init__(**base_kwargs)
        self._lockfile_name = lockfile_name or "package-lock.json"
        self._lockfile_baseline_path = (
            Path(lockfile_baseline_path) if lockfile_baseline_path else None
        )
        if snapshot_verify_key is not None and (
            not isinstance(snapshot_verify_key, str) or not snapshot_verify_key
        ):
            raise Station2ConfigError(
                "snapshot_verify_key must be a non-empty string when provided"
            )
        self._snapshot_verify_key = snapshot_verify_key
        if not isinstance(snapshot_max_age_s, (int, float)) \
                or isinstance(snapshot_max_age_s, bool) \
                or snapshot_max_age_s <= 0:
            raise Station2ConfigError(
                f"snapshot_max_age_s must be a positive number, got {snapshot_max_age_s!r}"
            )
        self._snapshot_max_age_s = float(snapshot_max_age_s)
        argv = list(npm_argv) if npm_argv else list(DEFAULT_NPM_AUDIT_ARGV)
        if "--json" not in argv:  # 解析契约要求 JSON stdout（缺则补，禁裸文本）
            argv.append("--json")
        self._argv: List[str] = argv

    # -- 解析（纯函数，自测直接覆盖） ----------------------------------------
    @staticmethod
    def parse_audit_stdout(text: str) -> Dict[str, Any]:
        """npm audit --json stdout → {findings, dep_total, reported_high_plus}。

        空输出/畸形/缺关键字段一律抛 _PayloadError（→ERROR，绝不折算零发现）。
        """
        if not isinstance(text, str) or not text.strip():
            raise _PayloadError("npm audit stdout is empty (empty output = ERROR, not zero findings)")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise _PayloadError(f"npm audit stdout is not valid JSON: {exc}") from exc
        return SupplyChainScanner.parse_audit_payload(payload)

    @staticmethod
    def parse_audit_payload(payload: Any) -> Dict[str, Any]:
        """已解析的 npm audit JSON 对象 → {findings, dep_total, reported_high_plus}。

        与 parse_audit_stdout 同契约，供快照信封通道复用（SC-05：载荷先验签
        再解析，本函数只消费验签后的可信对象）。
        """
        if not isinstance(payload, dict):
            raise _PayloadError(f"npm audit JSON must be an object, got {type(payload).__name__}")
        vulns = payload.get("vulnerabilities")
        if not isinstance(vulns, dict):
            raise _PayloadError("npm audit JSON missing 'vulnerabilities' object")
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            raise _PayloadError("npm audit JSON missing 'metadata' object")
        deps = metadata.get("dependencies")
        if not isinstance(deps, dict) or not isinstance(deps.get("total"), int) \
                or isinstance(deps.get("total"), bool) or deps["total"] < 0:
            raise _PayloadError(
                "npm audit metadata.dependencies.total missing/invalid "
                "(dynamic denominator unavailable -> ERROR)"
            )
        # R7-SC-PAGINATION-008 根修：载荷自带分页元数据时必须声明「已完整收集」。
        # complete 非 true、page<pages_total（pages 覆盖不全）或字段形态非法
        # → 证据损坏 ERROR（fail-closed：分页不全的载荷绝不是已见全集，绝不
        # 折算 PASS）。无 pagination 字段=单页 npm audit 正常形态，不受影响；
        # ADV-02 的自报计数交叉核对机制保持不变。对离线快照通道同样生效
        # （信封验签后 payload 走本函数——合法签名+hash 也救不了分页不全）。
        pagination = payload.get("pagination")
        if pagination is not None:
            if not isinstance(pagination, dict):
                raise _PayloadError(
                    f"npm audit JSON 'pagination' must be an object when present, "
                    f"got {type(pagination).__name__} (malformed pagination -> ERROR)"
                )
            page = pagination.get("page")
            pages_total = pagination.get("pages_total")
            page_int = isinstance(page, int) and not isinstance(page, bool)
            total_int = isinstance(pages_total, int) and not isinstance(pages_total, bool)
            if page_int and total_int and page < pages_total:
                raise _PayloadError(
                    f"pagination coverage incomplete: page {page} < pages_total "
                    f"{pages_total} (pages not fully collected -> ERROR, not PASS)"
                )
            if pagination.get("complete") is not True:
                raise _PayloadError(
                    "pagination.complete is not true (incomplete page "
                    "collection = corrupt evidence -> ERROR, not PASS)"
                )
        lockfile = "package-lock.json"
        findings: List[ScanFinding] = []
        for name in sorted(vulns):
            entry = vulns[name]
            if not isinstance(entry, dict):
                raise _PayloadError(f"vulnerabilities[{name!r}] is not an object")
            sev_raw = str(entry.get("severity") or "").strip().lower()
            severity, priority = _NPM_SEV_MAP.get(sev_raw, ("HIGH", "P1"))  # 未知→保守升
            rng = str(entry.get("range") or "")
            via = entry.get("via")
            ref = ""
            if isinstance(via, list) and via:
                first = via[0]
                if isinstance(first, Mapping):
                    ref = str(first.get("title") or first.get("url") or first.get("name") or "")
                elif isinstance(first, str):
                    ref = first
            findings.append(
                _mk_finding(
                    rule_id="npm-audit",
                    file_path=lockfile,
                    line_start=0,
                    severity=severity,
                    priority=priority,
                    snippet=f"{name}|{sev_raw}|{rng}|{ref}",
                    message=f"{name}: {sev_raw or 'unknown'} severity, range {rng or '?'}"
                            + (f", via {ref}" if ref else ""),
                )
            )
        reported = metadata.get("vulnerabilities")
        reported_high_plus = -1  # -1 = 自报缺失（不做交叉核对，见 scan()）
        if isinstance(reported, Mapping):
            try:
                reported_high_plus = int(reported.get("critical", 0)) + int(reported.get("high", 0))
            except (TypeError, ValueError):
                reported_high_plus = -1
        return {
            "findings": findings,
            "dep_total": int(deps["total"]),
            "reported_high_plus": reported_high_plus,
        }

    # -- SC-03：lockfile 依赖指纹与 diff（纯函数） ---------------------------
    @staticmethod
    def parse_lockfile_dependencies(payload: Any) -> Dict[str, Dict[str, Any]]:
        """package-lock.json → {name: {resolved, integrity, has_install_script}}。

        - v2/v3 ``packages`` 面：键 ``node_modules/<name>``（嵌套
          ``…/node_modules/b`` 取叶子包名）；键 ``""``（工程根包自述）跳过；
          每条取 resolved/integrity/hasInstallScript 三指纹。
        - v1 ``dependencies`` 面兜底（packages 面未覆盖的名字才补）。
        - 结构不认识（两个面都缺失）/条目类型错 → _PayloadError（→ERROR，
          fail-closed：无锚点不得声明通过）。
        """
        if not isinstance(payload, dict):
            raise _PayloadError(
                f"lockfile must be a JSON object, got {type(payload).__name__}"
            )
        deps: Dict[str, Dict[str, Any]] = {}
        packages = payload.get("packages")
        has_packages_face = packages is not None
        if has_packages_face:
            if not isinstance(packages, dict):
                raise _PayloadError("lockfile.packages must be an object (npm lockfile v2/v3)")
            for key, entry in packages.items():
                if not isinstance(key, str) or not isinstance(entry, dict):
                    raise _PayloadError(
                        f"lockfile.packages[{key!r}] must be a str->object entry"
                    )
                name = key.rsplit("node_modules/", 1)[-1].strip()
                if not name:  # ""=根包自述（工程本身，非依赖）——不入指纹表
                    continue
                deps[name] = {
                    "resolved": str(entry.get("resolved") or ""),
                    "integrity": str(entry.get("integrity") or ""),
                    "has_install_script": entry.get("hasInstallScript") is True,
                }
        legacy = payload.get("dependencies")
        has_legacy_face = isinstance(legacy, dict)
        if has_legacy_face:
            for name, entry in legacy.items():
                if name in deps:  # packages 面优先，v1 面只补缺
                    continue
                if not isinstance(entry, dict):
                    raise _PayloadError(
                        f"lockfile.dependencies[{name!r}] must be an object"
                    )
                deps[name] = {
                    "resolved": str(entry.get("resolved") or ""),
                    "integrity": str(entry.get("integrity") or ""),
                    "has_install_script": entry.get("hasInstallScript") is True,
                }
        if not has_packages_face and not has_legacy_face:
            raise _PayloadError(
                "lockfile format unrecognized: neither 'packages' (v2/v3) nor "
                "'dependencies' (v1) present (no diff anchor -> ERROR)"
            )
        return deps

    @staticmethod
    def diff_lockfile_dependencies(
        baseline: Mapping[str, Mapping[str, Any]],
        current: Mapping[str, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """依赖指纹 diff：新增/删除名单 + 逐包 aspect 变化列表。

        aspect ∈ {resolved, integrity, install_script}——§20.3 注入面的三个
        语义位：resolved/integrity 任一变化即一条；install_script 只报
        false→true（出现安装脚本=新攻击面）；true→false 是收敛，不报。
        删除名单只入 note（移除依赖不新增供应链攻击面，不计分母）。
        """
        added = sorted(set(current) - set(baseline))
        removed = sorted(set(baseline) - set(current))
        changes: List[Dict[str, Any]] = []
        for name in sorted(set(baseline) & set(current)):
            before, after = baseline[name], current[name]
            if before["resolved"] != after["resolved"]:
                changes.append({
                    "name": name, "aspect": "resolved",
                    "before": before["resolved"], "after": after["resolved"],
                })
            if before["integrity"] != after["integrity"]:
                changes.append({
                    "name": name, "aspect": "integrity",
                    "before": before["integrity"], "after": after["integrity"],
                })
            if not before["has_install_script"] and after["has_install_script"]:
                changes.append({
                    "name": name, "aspect": "install_script",
                    "before": False, "after": True,
                })
        return {"added": added, "removed": removed, "changes": changes}

    # -- SC-05：快照信封验签/时效（纯函数） ---------------------------------
    @staticmethod
    def verify_snapshot_envelope(
        envelope: Any,
        *,
        key: str,
        now: datetime,
        max_age_s: float,
    ) -> Dict[str, Any]:
        """验签+时效+内容哈希三重校验；任一失配抛 _SnapshotVerificationError。

        检查序（失败原因逐面可辨，供 note 审计）：
        1. 信封结构/kind/payload 存在；
        2. content_hash == sha256(canonical(payload))——签名后被改的载荷失配；
        3. captured_at 可解析、带时区、不早于 now+偏移容忍窗（未来=回放迹象）；
        4. 时效：now-captured_at ≤ max_age_s（过期=依赖基线陈旧）；
        5. signature == HMAC-SHA256(key, "<content_hash>.<captured_at>")。
        通过返回 {captured_at, age_s, content_hash}（审计元数据）。
        """
        if not isinstance(envelope, Mapping):
            raise _SnapshotVerificationError(
                f"snapshot envelope must be a JSON object, got "
                f"{type(envelope).__name__} (unsigned source -> unusable, BLOCKED)"
            )
        snap = envelope.get("snapshot")
        if not isinstance(snap, Mapping):
            raise _SnapshotVerificationError(
                "snapshot envelope missing 'snapshot' metadata "
                "(unsigned source -> unusable, BLOCKED)"
            )
        if snap.get("kind") != SNAPSHOT_KIND:
            raise _SnapshotVerificationError(
                f"unknown snapshot kind {snap.get('kind')!r} "
                f"(expected {SNAPSHOT_KIND!r}; unverified source -> BLOCKED)"
            )
        payload = envelope.get("payload")
        if not isinstance(payload, Mapping):
            raise _SnapshotVerificationError(
                "snapshot envelope missing 'payload' object -> BLOCKED"
            )
        content_hash = snap.get("content_hash")
        if not isinstance(content_hash, str) or not _RE_HEX64.match(content_hash):
            raise _SnapshotVerificationError(
                f"snapshot content_hash must be 64-char lowercase hex, "
                f"got {content_hash!r} -> BLOCKED"
            )
        actual_hash = _sha256_hex(_canonical_json(dict(payload)).encode("utf-8"))
        if content_hash != actual_hash:
            raise _SnapshotVerificationError(
                f"snapshot content_hash mismatch: envelope {content_hash} != "
                f"payload sha256 {actual_hash} (payload tampered after signing "
                "-> source unusable, BLOCKED)"
            )
        captured_raw = snap.get("captured_at")
        captured_dt = _parse_iso_dt(captured_raw)
        if captured_dt is None:
            raise _SnapshotVerificationError(
                f"snapshot captured_at missing/invalid/not timezone-aware: "
                f"{captured_raw!r} -> BLOCKED"
            )
        if captured_dt > now + timedelta(seconds=_SNAPSHOT_FUTURE_SKEW_S):
            raise _SnapshotVerificationError(
                f"snapshot captured_at {captured_raw} is in the future "
                "(clock skew or replay -> source unusable, BLOCKED)"
            )
        age_s = (now - captured_dt).total_seconds()
        if age_s > max_age_s:
            raise _SnapshotVerificationError(
                f"snapshot expired: captured_at {captured_raw} age "
                f"{int(age_s)}s > max {int(max_age_s)}s (stale dependency "
                "baseline -> source unusable, fail-closed BLOCKED)"
            )
        signature = snap.get("signature")
        if not isinstance(signature, str) or not signature:
            raise _SnapshotVerificationError(
                "snapshot signature missing (unsigned source -> unusable, BLOCKED)"
            )
        expected_sig = hmac.new(
            str(key).encode("utf-8"),
            f"{content_hash}.{captured_raw}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            raise _SnapshotVerificationError(
                "snapshot signature verification failed (key mismatch or "
                "tampered hash/timestamp -> source unusable, BLOCKED)"
            )
        return {
            "captured_at": str(captured_raw),
            "age_s": age_s,
            "content_hash": content_hash,
        }

    # -- 执行 ----------------------------------------------------------------
    def _source_blocked_report(
        self,
        reason: str,
        *,
        argv: Sequence[str],
        expected_exit_set: Sequence[int],
        actual_exit_code: int,
    ) -> ScannerReport:
        """SC-05 fail-closed 出口：该源数据不可用 → BLOCKED（§20.5）。

        分母刻意记 0/0——未通过验签的载荷内容一律不采信（连 metadata 自报
        依赖总数都不进 coverage），失败原因入 note 供审计。
        """
        now_iso = _iso_z(_utc_now())
        return self._finalize(
            execution_status="BLOCKED",
            policy_verdict="NOT_EVALUATED",
            findings=[],
            denominator=0,
            scanned=0,
            expected_exit_set=expected_exit_set,
            actual_exit_code=_EXIT_BLOCKED,
            argv_digest=_argv_digest(argv),
            started_at=now_iso,
            ended_at=now_iso,
            tool_version="npm-audit/snapshot",
            note=reason,
        )

    def scan(self) -> ScannerReport:
        expected = (0, 1)  # npm audit：0=净 / 1=存在漏洞；≥2=环境错
        cap = self._execute_raw(self._argv)
        if cap is None:
            return self._error_report(
                f"runner is a plain TrustedRunner without raw-output capture; "
                f"{self.tool_name} requires stdout parsing (fail-closed)",
                argv=self._argv, expected_exit_set=expected,
            )
        evidence = cap.evidence
        if evidence.timed_out:
            return self._timeout_report(
                f"npm audit timed out after {self._timeout_s}s (timeout = ERROR-class, never PASS)",
                argv=self._argv, expected_exit_set=expected, timestamp=evidence.timestamp,
            )
        rc = evidence.actual_exit_code
        if rc is None or rc >= 2:
            return self._error_report(
                f"npm audit exit code {rc} (>=2 = environment error; not recorded as pass)",
                argv=self._argv, expected_exit_set=expected,
                actual_exit_code=rc if rc is not None else _EXIT_ERROR,
            )

        stdout_text = cap.stdout_text() or ""
        snapshot_note = ""
        if self._snapshot_verify_key is not None:
            # SC-05：快照模式——stdout 必须是验签信封；任何验签/时效失配都
            # 让该源数据不可用（BLOCKED），绝不解析未验签内容。
            try:
                envelope = json.loads(stdout_text)
            except json.JSONDecodeError as exc:
                return self._source_blocked_report(
                    f"snapshot envelope is not valid JSON: {exc} "
                    "(fail-closed: unsigned/unusable source snapshot)",
                    argv=self._argv, expected_exit_set=expected, actual_exit_code=rc,
                )
            try:
                meta = self.verify_snapshot_envelope(
                    envelope,
                    key=self._snapshot_verify_key,
                    now=_utc_now(),
                    max_age_s=self._snapshot_max_age_s,
                )
            except _SnapshotVerificationError as exc:
                return self._source_blocked_report(
                    str(exc), argv=self._argv, expected_exit_set=expected,
                    actual_exit_code=rc,
                )
            snapshot_note = (
                f"verified snapshot: captured_at {meta['captured_at']} "
                f"(age {int(meta['age_s'])}s, content sha256:{meta['content_hash'][:16]}…)"
            )
            stdout_text = _canonical_json(envelope["payload"])

        try:
            parsed = self.parse_audit_stdout(stdout_text)
        except _PayloadError as exc:
            return self._error_report(
                str(exc), argv=self._argv, expected_exit_set=expected,
                actual_exit_code=rc,
            )

        findings: List[ScanFinding] = list(parsed["findings"])
        high_plus = sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH"))
        # 不信任自报数字：metadata 计数与解析列表不一致=证据损坏→ERROR（宁可阻断不猜）
        if parsed["reported_high_plus"] >= 0 and parsed["reported_high_plus"] != high_plus:
            return self._error_report(
                f"self-reported high+critical count {parsed['reported_high_plus']} != "
                f"parsed list count {high_plus} (parsed list is the source of truth; "
                f"mismatch = corrupt evidence -> ERROR)",
                argv=self._argv, expected_exit_set=expected,
                denominator=parsed["dep_total"], scanned=parsed["dep_total"],
                actual_exit_code=rc,
            )

        # SC-03：lockfile 变更差异分析（基线路径给出即开启）。
        diff_added_count = 0
        extra_notes: List[str] = ([snapshot_note] if snapshot_note else [])
        if self._lockfile_baseline_path is not None:
            try:
                current_payload = json.loads(
                    (self._repo_dir / self._lockfile_name).read_text(encoding="utf-8")
                )
                baseline_payload = json.loads(
                    self._lockfile_baseline_path.read_text(encoding="utf-8")
                )
                current_deps = self.parse_lockfile_dependencies(current_payload)
                baseline_deps = self.parse_lockfile_dependencies(baseline_payload)
            except (OSError, json.JSONDecodeError, _PayloadError) as exc:
                return self._error_report(
                    f"lockfile diff anchor unavailable: {exc} "
                    "(baseline/current lockfile missing or malformed = no "
                    "ratchet anchor -> ERROR, not PASS)",
                    argv=self._argv, expected_exit_set=expected,
                    actual_exit_code=rc,
                )
            diff = self.diff_lockfile_dependencies(baseline_deps, current_deps)
            for name in diff["added"]:
                info = current_deps[name]
                findings.append(
                    _mk_finding(
                        rule_id="supply/lockfile-diff-added",
                        file_path=self._lockfile_name,
                        line_start=0,
                        severity="HIGH",
                        priority="P1",
                        snippet=(
                            f"added|{name}|resolved={info['resolved']}"
                            f"|integrity={info['integrity']}"
                            f"|install_script={info['has_install_script']}"
                        ),
                        message=(
                            f"lockfile diff: new dependency {name} "
                            f"(resolved {info['resolved'] or '?'}, integrity "
                            f"{info['integrity'] or 'MISSING'}, install script "
                            f"{info['has_install_script']}) — FAIL/manual review"
                        ),
                    )
                )
            for change in diff["changes"]:
                findings.append(
                    _mk_finding(
                        rule_id=f"supply/lockfile-diff-{change['aspect']}",
                        file_path=self._lockfile_name,
                        line_start=0,
                        severity="HIGH",
                        priority="P1",
                        snippet=(
                            f"{change['aspect']}|{change['name']}"
                            f"|{change['before']}|{change['after']}"
                        ),
                        message=(
                            f"lockfile diff: {change['name']} {change['aspect']} "
                            f"changed ({change['before']!r} -> {change['after']!r})"
                            " — FAIL/manual review"
                        ),
                    )
                )
            diff_added_count = len(diff["added"])
            if diff["removed"]:
                extra_notes.append(
                    f"lockfile removed deps (note only, not counted): "
                    f"{', '.join(diff['removed'])}"
                )

        verdict = "FAIL" if (high_plus or any(
            f.rule_id.startswith("supply/lockfile-diff") for f in findings
        )) else "PASS"
        denominator = parsed["dep_total"] + diff_added_count  # 新增依赖单独计入分母
        return self._finalize(
            execution_status="COMPLETED",
            policy_verdict=verdict,
            findings=findings,
            denominator=denominator,
            scanned=denominator,  # audit 覆盖在账依赖 + diff 逐一分析了每个新增依赖
            expected_exit_set=expected,
            actual_exit_code=rc,
            argv_digest=evidence.argv_digest,
            started_at=_ts_to_iso(evidence.timestamp),
            ended_at=_ts_to_iso(evidence.timestamp),
            tool_version="npm-audit/json",
            note="; ".join(extra_notes),
        )


# ---------------------------------------------------------------------------
# DuplicateCodeScanner——jscpd 克隆检测（基线棘轮）
# ---------------------------------------------------------------------------

class DuplicateCodeScanner(_Station2Scanner):
    """jscpd 适配：报告文件解析 + dupscan 基线棘轮（只减不增）。

    - 命令：默认钉版本 npx jscpd@<JSCPD_PINNED_VERSION>（口径稳定，dupscan 铁律）；
      report 落 --output 目录（jscpd 原生文件输出——不需要原始 stdout）。
    - 分母：本模块独立 os.walk（jscpd_paths×源扩展名）——不信任报告自报 files 数；
      scanned：报告 statistics.total.files（解析值）。scanned<denominator → 缩水守卫
      BLOCKED。
    - 计数：clone 对数=len(解析 duplicates 列表)；与 statistics.total.duplicates
      自报数不一致→ERROR（证据损坏）。
    - 判定（W6A 站2：克隆≤基线）：pairs 或重复行数超基线→FAIL；否则 PASS。
    - findings：超基线时落 1 条 ratchet 汇总 finding（MEDIUM/P2，可被风险接受）
      + 最长 top_k 对明细（防数千对洪泛账本；账面计数仍取全量解析列表）。
      基线内=零 finding（存量债由棘轮基线跟踪，不逐条入账）。
    - 基线文件缺失/畸形 → ERROR（无锚点不得声明通过——fail-closed；此时扫描
      已完成、coverage 齐全）。工具崩溃/超时/报告缺失→分母已知+scanned=0→
      缩水守卫折叠 BLOCKED（原因在 note）。
    """

    slug = "dupscan"
    tool_name = "jscpd"

    def __init__(
        self,
        *,
        baseline_path: Optional[str] = None,
        jscpd_argv: Optional[Sequence[str]] = None,
        jscpd_paths: Sequence[str] = ("src",),
        min_tokens: int = DEFAULT_JSCPD_MIN_TOKENS,
        top_k: int = 20,
        **base_kwargs: Any,
    ) -> None:
        super().__init__(**base_kwargs)
        self._baseline_path = Path(baseline_path) if baseline_path else None
        self._jscpd_paths = tuple(jscpd_paths) or ("src",)
        self._min_tokens = int(min_tokens)
        self._top_k = max(0, int(top_k))
        self._output_dir = Path(tempfile.mkdtemp(prefix="wenqu-st2-jscpd-"))
        if jscpd_argv is not None:
            argv = list(jscpd_argv)
        else:
            argv = [
                "npx", "--yes", f"jscpd@{JSCPD_PINNED_VERSION}",
                *self._jscpd_paths,
                "--min-tokens", str(self._min_tokens),
            ]
        for flag, value in (("--reporter", "json"), ("--output", str(self._output_dir)),
                            ("--silent", None)):
            if flag not in argv:
                argv.append(flag)
                if value is not None:
                    argv.append(value)
        self._argv: List[str] = argv

    # -- 解析（纯函数） ------------------------------------------------------
    @staticmethod
    def parse_jscpd_report(payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise _PayloadError(f"jscpd report must be an object, got {type(payload).__name__}")
        duplicates = payload.get("duplicates")
        if not isinstance(duplicates, list):
            raise _PayloadError("jscpd report missing 'duplicates' list")
        statistics = payload.get("statistics")
        if not isinstance(statistics, dict) or not isinstance(statistics.get("total"), dict):
            raise _PayloadError("jscpd report missing 'statistics.total' object")
        total = statistics["total"]
        dup_lines = 0
        for idx, dup in enumerate(duplicates):
            if not isinstance(dup, dict):
                raise _PayloadError(f"duplicates[{idx}] is not an object")
            try:
                dup_lines += int(dup.get("lines") or 0)
            except (TypeError, ValueError) as exc:
                raise _PayloadError(f"duplicates[{idx}].lines invalid: {exc}") from exc
        files_reported = total.get("files")
        if not isinstance(files_reported, int) or isinstance(files_reported, bool) or files_reported < 0:
            raise _PayloadError("statistics.total.files missing/invalid")
        self_dup = total.get("duplicates")
        if isinstance(self_dup, int) and not isinstance(self_dup, bool) and self_dup != len(duplicates):
            raise _PayloadError(
                f"self-reported duplicate count {self_dup} != parsed list count "
                f"{len(duplicates)} (parsed list is the source of truth; mismatch -> ERROR)"
            )
        return {
            "duplicates": duplicates,
            "pairs": len(duplicates),       # 计数取解析列表
            "dup_lines": dup_lines,
            "files_reported": files_reported,
            "percentage": str(total.get("percentage") or ""),
        }

    @staticmethod
    def load_baseline(path: Path) -> Dict[str, int]:
        if not path.is_file():
            raise _PayloadError(
                f"dupscan baseline missing: {path} (no ratchet anchor -> ERROR, not PASS)"
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise _PayloadError(f"dupscan baseline unreadable/corrupt: {exc}") from exc
        if not isinstance(payload, dict):
            raise _PayloadError("dupscan baseline must be a JSON object")
        out: Dict[str, int] = {}
        for key in ("clone_pairs", "duplicated_lines"):
            value = payload.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise _PayloadError(f"dupscan baseline.{key} missing/invalid (need int >= 0)")
            out[key] = value
        return out

    # -- 执行 ----------------------------------------------------------------
    def _tool_version(self) -> str:
        for token in self._argv:
            m = _RE_JSCPD_VER.search(token)
            if m:
                return f"jscpd@{m.group(1)}"
        return "jscpd"

    def scan(self) -> ScannerReport:
        expected = (0,)
        # 分母：独立 walk（先算——即使工具失败，分母口径也已固定可审计）
        denominator_files = _walk_source_files(
            self._repo_dir, self._jscpd_paths, _JSCPD_SOURCE_EXTS
        )
        denominator = len(denominator_files)

        cap = self._execute(self._argv)
        evidence = cap.evidence
        if evidence.timed_out:
            return self._timeout_report(
                f"jscpd timed out after {self._timeout_s}s",
                argv=self._argv, expected_exit_set=expected, timestamp=evidence.timestamp,
                denominator=denominator, scanned=0, tool_version=self._tool_version(),
            )
        rc = evidence.actual_exit_code
        if rc is None or rc != 0:
            return self._error_report(
                f"jscpd exit code {rc} (nonzero = environment/tool error)",
                argv=self._argv, expected_exit_set=expected,
                denominator=denominator, scanned=0, tool_version=self._tool_version(),
                actual_exit_code=rc if rc is not None else _EXIT_ERROR,
            )
        report_path = self._output_dir / JSCPD_REPORT_NAME
        if not report_path.is_file():
            return self._error_report(
                f"jscpd report file missing after exit 0: {report_path} "
                "(empty output = ERROR, not zero duplicates)",
                argv=self._argv, expected_exit_set=expected,
                denominator=denominator, scanned=0, tool_version=self._tool_version(),
                actual_exit_code=rc,
            )
        try:
            parsed = self.parse_jscpd_report(
                json.loads(report_path.read_text(encoding="utf-8"))
            )
        except (OSError, json.JSONDecodeError) as exc:
            return self._error_report(
                f"jscpd report unreadable/corrupt: {exc}",
                argv=self._argv, expected_exit_set=expected,
                denominator=denominator, scanned=0, tool_version=self._tool_version(),
                actual_exit_code=rc,
            )
        except _PayloadError as exc:
            return self._error_report(
                str(exc), argv=self._argv, expected_exit_set=expected,
                denominator=denominator, scanned=0, tool_version=self._tool_version(),
                actual_exit_code=rc,
            )
        try:
            baseline = self.load_baseline(self._baseline_path or (self._repo_dir / "dupscan-baseline.json"))
        except _PayloadError as exc:
            return self._error_report(
                str(exc), argv=self._argv, expected_exit_set=expected,
                denominator=denominator, scanned=parsed["files_reported"],
                tool_version=self._tool_version(),
            )

        scanned = parsed["files_reported"]
        over_pairs = parsed["pairs"] > baseline["clone_pairs"]
        over_lines = parsed["dup_lines"] > baseline["duplicated_lines"]
        findings: List[ScanFinding] = []
        note = ""
        if over_pairs or over_lines:
            findings.append(
                _mk_finding(
                    rule_id="dupscan/ratchet-exceeded",
                    file_path="jscpd-report.json",
                    line_start=0,
                    severity="MEDIUM",
                    priority="P2",
                    snippet=(
                        f"pairs={parsed['pairs']}|baseline_pairs={baseline['clone_pairs']}"
                        f"|dup_lines={parsed['dup_lines']}"
                        f"|baseline_lines={baseline['duplicated_lines']}"
                    ),
                    message=(
                        f"clone ratchet exceeded: pairs {parsed['pairs']} > baseline "
                        f"{baseline['clone_pairs']}" if over_pairs else
                        f"clone ratchet exceeded: duplicated lines {parsed['dup_lines']} "
                        f"> baseline {baseline['duplicated_lines']}"
                    ),
                )
            )
            for dup in sorted(
                parsed["duplicates"], key=lambda d: -int(d.get("lines") or 0)
            )[: self._top_k]:
                first = dup.get("firstFile") if isinstance(dup.get("firstFile"), Mapping) else {}
                second = dup.get("secondFile") if isinstance(dup.get("secondFile"), Mapping) else {}
                findings.append(
                    _mk_finding(
                        rule_id="dupscan/clone-pair",
                        file_path=str(first.get("path") or first.get("name") or "unknown"),
                        line_start=int(first.get("start") or 0),
                        severity="MEDIUM",
                        priority="P2",
                        snippet=(
                            f"{first.get('path', first.get('name', '?'))}|"
                            f"{second.get('path', second.get('name', '?'))}|{dup.get('lines')}"
                        ),
                        message=(
                            f"clone pair ({dup.get('lines')} lines): "
                            f"{first.get('path', first.get('name', '?'))} <-> "
                            f"{second.get('path', second.get('name', '?'))}"
                        ),
                    )
                )
            note = (
                f"ratchet exceeded: pairs {parsed['pairs']}/{baseline['clone_pairs']}, "
                f"lines {parsed['dup_lines']}/{baseline['duplicated_lines']}"
            )
        return self._finalize(
            execution_status="COMPLETED",
            policy_verdict="FAIL" if (over_pairs or over_lines) else "PASS",
            findings=findings,
            denominator=denominator,
            scanned=scanned,
            expected_exit_set=expected,
            actual_exit_code=rc,
            argv_digest=evidence.argv_digest,
            started_at=_ts_to_iso(evidence.timestamp),
            ended_at=_ts_to_iso(evidence.timestamp),
            tool_version=self._tool_version(),
            exclusions=sorted(_WALK_SKIP_DIRS),
            note=note,
        )


# ---------------------------------------------------------------------------
# EngineFiveTypesScanner——持续修复引擎五类
# ---------------------------------------------------------------------------

class EngineFiveTypesScanner(_Station2Scanner):
    """持续修复引擎五类扫描适配（ENUM/CTX/MSG/DUALWRITE/DOMAIN）。

    两种输入（优先 engine_argv——新鲜扫描；否则读 engine_state_path 状态正源）：
    - engine_argv：经 runner 执行的引擎扫描命令，stdout=engine-state 同构 JSON；
      超时/非零退出/空输出/解析失败 → TIMEOUT/ERROR。
    - engine_state_path 文件：读失败/JSON 畸形 → ERROR。文件读取无子进程
      returncode，execution.actual_exit_code 记适配器统一退出码（0/2）——与
      source_gate 结果件 exit_code 同语义（契约映射，非 waitpid 实测）。

    判定（W6A 站2：引擎五类 0 open）：queue 内任一卡未收口 → FAIL（每卡一条
    finding，MEDIUM/P2）；全收口 → PASS。
    coverage：denominator=五类宇宙（ENGINE_FIVE_TYPES ∪ queue 实际 slug——动态）；
    scanned=宇宙中有卡的类数。宇宙类缺卡 → 缩水守卫 BLOCKED（引擎删卡=覆盖缺口，
    fail-closed 待查）。
    """

    slug = "engine"
    tool_name = "engine-five-types"

    _STATE_ARGV: Tuple[str, ...] = (
        "wenqu_core.station2_static", "EngineFiveTypesScanner", "read-state",
    )

    def __init__(
        self,
        *,
        engine_state_path: Optional[str] = None,
        engine_argv: Optional[Sequence[str]] = None,
        **base_kwargs: Any,
    ) -> None:
        super().__init__(**base_kwargs)
        self._state_path = Path(engine_state_path) if engine_state_path else DEFAULT_ENGINE_STATE_PATH
        self._engine_argv: Optional[List[str]] = list(engine_argv) if engine_argv else None

    # -- 解析（纯函数） ------------------------------------------------------
    @staticmethod
    def parse_engine_state(payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise _PayloadError(f"engine state must be an object, got {type(payload).__name__}")
        queue = payload.get("queue")
        if not isinstance(queue, list):
            raise _PayloadError("engine state missing 'queue' list")
        cards: Dict[str, Dict[str, Any]] = {}
        for idx, item in enumerate(queue):
            if not isinstance(item, dict):
                raise _PayloadError(f"queue[{idx}] is not an object")
            slug = str(item.get("slug") or "").strip() or str(item.get("id") or "").strip().lower()
            if not slug:
                raise _PayloadError(f"queue[{idx}] missing slug/id")
            status = str(item.get("status") or "")
            closed = any(marker in status for marker in _ENGINE_CLOSED_MARKERS)
            cards[slug] = {
                "id": str(item.get("id") or slug),
                "title": str(item.get("title") or ""),
                "status": status,
                "open": not closed,
            }
        inflight = payload.get("cursor_inflight")
        if isinstance(inflight, Mapping):
            slug = str(inflight.get("slug") or "").strip()
            if slug in cards:
                cards[slug]["open"] = True
        universe = sorted(set(ENGINE_FIVE_TYPES) | set(cards))
        return {"cards": cards, "universe": universe}

    # -- 执行 ----------------------------------------------------------------
    def scan(self) -> ScannerReport:
        if self._engine_argv is not None:
            return self._scan_via_command()
        return self._scan_via_state_file()

    def _scan_via_command(self) -> ScannerReport:
        expected = (0,)
        cap = self._execute_raw(self._engine_argv)
        if cap is None:
            return self._error_report(
                "runner is a plain TrustedRunner without raw-output capture; "
                "engine scan command requires stdout parsing (fail-closed)",
                argv=self._engine_argv, expected_exit_set=expected,
                tool_version="engine-scan",
            )
        evidence = cap.evidence
        if evidence.timed_out:
            return self._timeout_report(
                f"engine scan timed out after {self._timeout_s}s",
                argv=self._engine_argv, expected_exit_set=expected,
                timestamp=evidence.timestamp, tool_version="engine-scan",
            )
        rc = evidence.actual_exit_code
        if rc is None or rc != 0:
            return self._error_report(
                f"engine scan exit code {rc} (nonzero = environment error)",
                argv=self._engine_argv, expected_exit_set=expected,
                tool_version="engine-scan",
                actual_exit_code=rc if rc is not None else _EXIT_ERROR,
            )
        try:
            payload = json.loads(cap.stdout_text() or "")
        except json.JSONDecodeError as exc:
            return self._error_report(
                f"engine scan stdout is not valid JSON: {exc} (empty/broken output = ERROR)",
                argv=self._engine_argv, expected_exit_set=expected,
                tool_version="engine-scan",
                actual_exit_code=rc,
            )
        return self._verdict_from_state(
            payload,
            argv_digest=evidence.argv_digest,
            argv_for_digest=self._engine_argv,
            actual_exit_code=rc,
            started_at=_ts_to_iso(evidence.timestamp),
            ended_at=_ts_to_iso(evidence.timestamp),
            tool_version="engine-scan/json",
        )

    def _scan_via_state_file(self) -> ScannerReport:
        expected = (0,)
        argv = [*self._STATE_ARGV, str(self._state_path)]
        started = time.time()
        try:
            raw = self._state_path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            return self._error_report(
                f"engine state unreadable/corrupt at {self._state_path}: {exc} "
                "(missing/broken state = ERROR, not all-closed)",
                argv=argv, expected_exit_set=expected,
                tool_version="engine-state/1",
            )
        return self._verdict_from_state(
            payload,
            argv_digest=_argv_digest(argv),
            argv_for_digest=argv,
            actual_exit_code=_EXIT_PASS,
            started_at=_ts_to_iso(started),
            ended_at=_iso_z(_utc_now()),
            tool_version="engine-state/1",
        )

    def _verdict_from_state(
        self,
        payload: Any,
        *,
        argv_digest: str,
        argv_for_digest: Sequence[str],
        actual_exit_code: int,
        started_at: str,
        ended_at: str,
        tool_version: str,
    ) -> ScannerReport:
        expected = (0,)
        try:
            parsed = self.parse_engine_state(payload)
        except _PayloadError as exc:
            return self._error_report(
                str(exc), argv=argv_for_digest, expected_exit_set=expected,
                tool_version=tool_version,
            )
        cards = parsed["cards"]
        universe = parsed["universe"]
        denominator = len(universe)
        scanned = sum(1 for slug in universe if slug in cards)
        findings: List[ScanFinding] = []
        for slug in sorted(cards):
            card = cards[slug]
            if not card["open"]:
                continue
            findings.append(
                _mk_finding(
                    rule_id=f"engine-five-types/{slug}",
                    file_path="engine-state.json",
                    line_start=0,
                    severity="MEDIUM",
                    priority="P2",
                    snippet=f"{card['id']}|{card['status'][:120]}",
                    message=f"engine card OPEN [{card['id']}] {card['title']}: {card['status'][:160]}",
                )
            )
        open_count = len(findings)
        return self._finalize(
            execution_status="COMPLETED",
            policy_verdict="FAIL" if open_count else "PASS",
            findings=findings,
            denominator=denominator,
            scanned=scanned,
            expected_exit_set=expected,
            actual_exit_code=actual_exit_code,
            argv_digest=argv_digest,
            started_at=started_at,
            ended_at=ended_at,
            tool_version=tool_version,
            tool_digest=_hash_obj({"universe": universe}),
            note="" if not open_count else f"{open_count} engine card(s) open",
        )


# ---------------------------------------------------------------------------
# RouteIntegrityScanner——路由完整性静态腿
# ---------------------------------------------------------------------------

class RouteIntegrityScanner(_Station2Scanner):
    """路由完整性静态腿适配：执行 stations.json 风格探测器（rc 契约）。

    - 探测器 argv 直执行（经 TrustedRunner；rc 契约：0=净/1=命中（自动落账
      OPEN）/≥2=环境错（不落账不计通过））。
    - 命中（rc=1）时 stdout 为 JSON（finding 对象列表或 {"findings":[...]}）→
      逐条解析落账（每条 rule/file/line/severity/message）；stdout 空=契约自相
      矛盾→ERROR；非 JSON 文本→落 1 条保守 HIGH 合成 finding（证据哈希入指纹）。
    - 分母：独立 walk 路由入口（app/**/page.*|route.* + pages/**）——动态；
      scanned=分母（探测器完成时覆盖全部入口）；错误/超时 scanned=0→分母已知，
      W6A 缩水守卫折叠为 BLOCKED（语义=证据不完整；细粒度原因在 note）。
    - 零路由入口（非 Next.js 仓）→ COMPLETED+NOT_APPLICABLE（唯一合法免跑）。
    - 探测器未配置 → 非 PASS 硬失败（缺执行器不是 SKIP——fail-closed；
      分母已知时折叠 BLOCKED，原因入 note）。
    """

    slug = "route"
    tool_name = "route-integrity-static"

    def __init__(
        self,
        *,
        route_probe_argv: Optional[Sequence[str]] = None,
        default_severity: str = "HIGH",
        **base_kwargs: Any,
    ) -> None:
        super().__init__(**base_kwargs)
        self._probe_argv: Optional[List[str]] = (
            list(route_probe_argv) if route_probe_argv else None
        )
        sev = str(default_severity or "HIGH").strip().upper()
        self._default_sev, self._default_pri = _PROBE_SEV_MAP.get(sev, ("HIGH", "P1"))

    # -- 解析（纯函数） ------------------------------------------------------
    @staticmethod
    def parse_probe_findings(text: str) -> List[ScanFinding]:
        """探测器 stdout JSON → findings（缺省字段保守补齐：severity→默认档 MEDIUM/P2）。"""
        stripped = (text or "").strip()
        if not stripped:
            raise _PayloadError("probe stdout is empty")
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise _PayloadError(f"probe stdout is not valid JSON: {exc}") from exc
        if isinstance(payload, dict):
            items = payload.get("findings")
        else:
            items = payload
        if not isinstance(items, list):
            raise _PayloadError("probe JSON must be a findings list or {'findings': [...]}")
        findings: List[ScanFinding] = []
        for idx, item in enumerate(items):
            if not isinstance(item, Mapping):
                raise _PayloadError(f"findings[{idx}] is not an object")
            rule_id = str(item.get("rule") or item.get("rule_id") or "route-integrity/finding")
            file_path = str(item.get("file") or item.get("file_path") or "unknown")
            try:
                line_start = int(item.get("line") or item.get("line_start") or 0)
            except (TypeError, ValueError):
                line_start = 0
            sev_raw = str(item.get("severity") or "").strip().lower()
            severity, priority = _PROBE_SEV_MAP.get(sev_raw, ("MEDIUM", "P2"))
            message = str(item.get("message") or item.get("title") or rule_id)
            findings.append(
                _mk_finding(
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=max(0, line_start),
                    severity=severity,
                    priority=priority,
                    snippet=f"{rule_id}|{file_path}|{line_start}|{message[:160]}",
                    message=message[:400],
                )
            )
        return findings

    # -- 执行 ----------------------------------------------------------------
    def _tool_version(self) -> str:
        if self._probe_argv:
            return f"route-probe/{Path(self._probe_argv[0]).name}"
        return "route-probe/unconfigured"

    def scan(self) -> ScannerReport:
        expected = (0, 1)
        entries = _walk_route_entries(self._repo_dir)
        denominator = len(entries)
        if self._probe_argv is None:
            return self._error_report(
                "route probe argv not configured (missing executor is a hard failure, "
                "not SKIP; folded to BLOCKED when denominator is known)",
                argv=["wenqu_core.station2_static", "RouteIntegrityScanner", "probe"],
                expected_exit_set=expected,
                denominator=denominator, scanned=0,
                tool_version=self._tool_version(),
            )
        if denominator == 0:
            # 非路由仓：唯一合法免跑（对齐 source_gate 纯非行为变更→NOT_APPLICABLE）
            now_iso = _iso_z(_utc_now())
            return self._finalize(
                execution_status="COMPLETED",
                policy_verdict="NOT_APPLICABLE",
                findings=[],
                denominator=0,
                scanned=0,
                expected_exit_set=expected,
                actual_exit_code=_EXIT_PASS,
                argv_digest=_argv_digest(self._probe_argv),
                started_at=now_iso,
                ended_at=now_iso,
                tool_version=self._tool_version(),
                note="zero route entries under app/pages roots -> NOT_APPLICABLE",
            )

        cap = self._execute_raw(self._probe_argv)
        if cap is None:
            return self._error_report(
                "runner is a plain TrustedRunner without raw-output capture; "
                "route probe requires stdout parsing (fail-closed)",
                argv=self._probe_argv, expected_exit_set=expected,
                denominator=denominator, scanned=0, tool_version=self._tool_version(),
            )
        evidence = cap.evidence
        if evidence.timed_out:
            return self._timeout_report(
                f"route probe timed out after {self._timeout_s}s",
                argv=self._probe_argv, expected_exit_set=expected,
                timestamp=evidence.timestamp,
                denominator=denominator, scanned=0, tool_version=self._tool_version(),
            )
        rc = evidence.actual_exit_code
        if rc is None or rc >= 2:
            return self._error_report(
                f"route probe exit code {rc} (>=2 = environment error; not counted as pass)",
                argv=self._probe_argv, expected_exit_set=expected,
                denominator=denominator, scanned=0, tool_version=self._tool_version(),
                actual_exit_code=rc if rc is not None else _EXIT_ERROR,
            )
        stdout_text = cap.stdout_text() or ""
        if rc == 1:
            findings: List[ScanFinding]
            if not stdout_text.strip():
                return self._error_report(
                    "route probe exit 1 with empty stdout contradicts rc contract "
                    "(hit must carry findings; empty output = ERROR)",
                    argv=self._probe_argv, expected_exit_set=expected,
                    denominator=denominator, scanned=0, tool_version=self._tool_version(),
                    actual_exit_code=rc,
                )
            try:
                findings = self.parse_probe_findings(stdout_text)
            except _PayloadError:
                # 命中但输出不可结构化：保守落 1 条 HIGH 合成 finding（不丢命中事实）
                out_hash = _sha256_hex(stdout_text.encode("utf-8", errors="replace"))
                findings = [
                    _mk_finding(
                        rule_id="route-integrity/probe-hit",
                        file_path="<probe-stdout>",
                        line_start=0,
                        severity=self._default_sev,
                        priority=self._default_pri,
                        snippet=f"unparsed|{out_hash}",
                        message=f"route probe hit with unparseable stdout "
                                f"(sha256:{out_hash[:16]}…): {stdout_text[:200]!r}",
                    )
                ]
            return self._finalize(
                execution_status="COMPLETED",
                policy_verdict="FAIL",
                findings=findings,
                denominator=denominator,
                scanned=denominator,
                expected_exit_set=expected,
                actual_exit_code=rc,
                argv_digest=evidence.argv_digest,
                started_at=_ts_to_iso(evidence.timestamp),
                ended_at=_ts_to_iso(evidence.timestamp),
                tool_version=self._tool_version(),
                note=f"probe hit: {len(findings)} finding(s) from parsed list",
            )
        # rc == 0：净（空 stdout 为净探测的正常形态；非空噪声不折算发现）
        return self._finalize(
            execution_status="COMPLETED",
            policy_verdict="PASS",
            findings=[],
            denominator=denominator,
            scanned=denominator,
            expected_exit_set=expected,
            actual_exit_code=rc,
            argv_digest=evidence.argv_digest,
            started_at=_ts_to_iso(evidence.timestamp),
            ended_at=_ts_to_iso(evidence.timestamp),
            tool_version=self._tool_version(),
            note="",
        )


# ---------------------------------------------------------------------------
# Station2Static——站2 聚合适配器（Codex W6B）
# ---------------------------------------------------------------------------

class Station2Static:
    """站2（静态与供应链）聚合适配器：四执行件 → 站级 station-result-v2。

    聚合规则（铁律 2「站内任一件 BLOCKED/ERROR→整站不得记 PASS」的机械实现）：
    - coverage：denominator=启用执行件数（len(scanners)——动态，构造参数决定）；
      scanned=execution_status==COMPLETED 的件数。任一件未完成 → scanned<
      denominator → W6A 分母缩水守卫强制整站 BLOCKED/NOT_EVALUATED（schema
      $comment 的设计行为；细粒度 TIMEOUT/ERROR 保留在各子件结果里）。
    - verdict：全部 COMPLETED 时取最差（任一 FAIL→FAIL；否则 PASS）；否则
      NOT_EVALUATED。finding_ids=各件解析列表合并去重（保序）。
    - 聚合 execution.actual_exit_code=§7 统一退出码（契约映射，与 source_gate
      结果件 exit_code 同语义）；argv_digest=各件 argv_digest 的规范化哈希。
    - 刻意省略某执行件（scanners 子集）= 显式范围决策，缺口记入
      coverage.exclusions 与返回值 notes——分母语义仍是「启用件数」。
    """

    STATION_ID = STATION_ID

    def __init__(
        self,
        run_id: str,
        *,
        identity: Mapping[str, Any],
        repo_dir: str,
        runner: Optional[TrustedRunner] = None,
        timeout_s: int = 300,
        scanners: Sequence[str] = SCAN_SLUGS,
        # -- supply --
        npm_argv: Optional[Sequence[str]] = None,
        lockfile_name: str = "package-lock.json",
        supply_lockfile_baseline_path: Optional[str] = None,
        supply_snapshot_verify_key: Optional[str] = None,
        supply_snapshot_max_age_s: float = DEFAULT_SNAPSHOT_MAX_AGE_S,
        # -- dupscan --
        baseline_path: Optional[str] = None,
        jscpd_argv: Optional[Sequence[str]] = None,
        jscpd_paths: Sequence[str] = ("src",),
        jscpd_min_tokens: int = DEFAULT_JSCPD_MIN_TOKENS,
        jscpd_top_k: int = 20,
        # -- engine --
        engine_state_path: Optional[str] = None,
        engine_argv: Optional[Sequence[str]] = None,
        # -- route --
        route_probe_argv: Optional[Sequence[str]] = None,
        route_default_severity: str = "HIGH",
        finding_detail_cap: int = DEFAULT_FINDING_DETAIL_CAP,
    ) -> None:
        _validate_run_id(run_id)
        _validate_identity(identity)
        repo = Path(repo_dir)
        if not repo.is_dir():
            raise Station2ConfigError(f"repo_dir is not a directory: {repo}")
        if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or timeout_s < 1:
            raise Station2ConfigError("timeout_s must be an int >= 1")
        requested = tuple(dict.fromkeys(scanners))
        unknown = [s for s in requested if s not in SCAN_SLUGS]
        if unknown:
            raise Station2ConfigError(f"unknown scanner slug(s) {unknown}; known: {list(SCAN_SLUGS)}")
        if not requested:
            raise Station2ConfigError("scanners must be non-empty (drop-scan is an explicit decision)")

        self._run_id = run_id
        self._identity = dict(identity)
        self._repo_dir = repo
        self._runner = runner if runner is not None else RawTrustedRunner(
            default_cwd=str(repo), timeout=float(timeout_s)
        )
        if not isinstance(self._runner, TrustedRunner):
            raise Station2ConfigError(
                "runner must be a TrustedRunner instance (unforgeable exit-code source)"
            )
        self._timeout_s = timeout_s
        self._scanners = requested
        self._finding_detail_cap = max(0, int(finding_detail_cap))

        base = dict(
            run_id=run_id, identity=self._identity, repo_dir=repo,
            runner=self._runner, timeout_s=timeout_s,
        )
        # 只构造启用的执行件（禁用件不产生副作用，如 jscpd 报告临时目录）
        registry: Dict[str, _Station2Scanner] = {}
        if "supply" in requested:
            registry["supply"] = SupplyChainScanner(
                npm_argv=npm_argv, lockfile_name=lockfile_name,
                lockfile_baseline_path=supply_lockfile_baseline_path,
                snapshot_verify_key=supply_snapshot_verify_key,
                snapshot_max_age_s=supply_snapshot_max_age_s,
                **base
            )
        if "dupscan" in requested:
            registry["dupscan"] = DuplicateCodeScanner(
                baseline_path=baseline_path, jscpd_argv=jscpd_argv,
                jscpd_paths=jscpd_paths, min_tokens=jscpd_min_tokens,
                top_k=jscpd_top_k, **base
            )
        if "engine" in requested:
            registry["engine"] = EngineFiveTypesScanner(
                engine_state_path=engine_state_path, engine_argv=engine_argv, **base
            )
        if "route" in requested:
            registry["route"] = RouteIntegrityScanner(
                route_probe_argv=route_probe_argv,
                default_severity=route_default_severity, **base
            )
        self._scanner_impls = registry

    # ------------------------------------------------------------------
    def scan(self) -> Dict[str, Any]:
        """执行全部启用件并聚合；返回
        {station_result, scanner_results, findings, notes, station2_version}。

        单件意外异常不炸整站：折叠为该件 ERROR 子结果（失败证据必须保留）。
        """
        reports: Dict[str, ScannerReport] = {}
        for slug in self._scanners:
            scanner = self._scanner_impls[slug]
            try:
                reports[slug] = scanner.scan()
            except Exception as exc:  # noqa: BLE001——单件失败不得吞掉整站证据
                impl = self._scanner_impls[slug]
                reports[slug] = impl._error_report(
                    f"scanner crashed: {type(exc).__name__}: {exc}",
                    argv=["wenqu_core.station2_static", slug],
                    expected_exit_set=(0,),
                    tool_version="crashed",
                )

        sub_results = {slug: reports[slug].result for slug in self._scanners}
        all_findings: List[ScanFinding] = []
        seen_ids: set = set()
        notes: Dict[str, str] = {}
        for slug in self._scanners:
            report = reports[slug]
            if report.note:
                notes[slug] = report.note
            for finding in report.findings:
                if finding.finding_id not in seen_ids:
                    seen_ids.add(finding.finding_id)
                    all_findings.append(finding)

        statuses = [reports[slug].result["execution_status"] for slug in self._scanners]
        verdicts = [reports[slug].result["policy_verdict"] for slug in self._scanners]
        if "TIMEOUT" in statuses:
            intended_status = "TIMEOUT"
        elif "ERROR" in statuses:
            intended_status = "ERROR"
        elif "BLOCKED" in statuses:
            intended_status = "BLOCKED"
        else:
            intended_status = "COMPLETED"
        if intended_status != "COMPLETED":
            aggregate_verdict = "NOT_EVALUATED"
        elif "FAIL" in verdicts:
            aggregate_verdict = "FAIL"
        else:
            aggregate_verdict = "PASS"

        completed = sum(1 for s in statuses if s == "COMPLETED")
        disabled = sorted(set(SCAN_SLUGS) - set(self._scanners))

        started_list = [sub["execution"]["started_at"] for sub in sub_results.values()]
        ended_list = [sub["execution"]["ended_at"] for sub in sub_results.values()]
        argv_digest_map = {
            slug: sub_results[slug]["execution"]["argv_digest"] for slug in self._scanners
        }

        aggregate_body = json.dumps(
            {"argv_digest_map": argv_digest_map, "statuses": statuses,
             "finding_ids": [f.finding_id for f in all_findings]},
            separators=(",", ":"), ensure_ascii=False, sort_keys=True,
        ).encode("utf-8")
        aggregate = build_station_result(
            run_id=self._run_id,
            station_id=STATION_ID,
            attempt_id=_attempt_id(self._run_id, "st2"),
            execution_status=intended_status,
            policy_verdict=aggregate_verdict,
            identity=self._identity,
            tool={
                "name": "wenqu_core.station2_static",
                "version": STATION2_VERSION,
                "digest": _hash_obj(argv_digest_map),
            },
            execution={
                "argv_digest": _hash_obj(argv_digest_map),
                "cwd_digest": _sha256_hex(str(self._repo_dir.resolve()).encode("utf-8")),
                "started_at": min(started_list),
                "ended_at": max(ended_list),
                "timeout_s": self._timeout_s,
                "actual_exit_code": _unified_exit(intended_status, aggregate_verdict),
                "expected_exit_set": [_EXIT_PASS],
                "assertion_verdict": (
                    "PASS" if aggregate_verdict in ("PASS", "NOT_APPLICABLE")
                    else ("FAIL" if aggregate_verdict == "FAIL" else "ERROR")
                ),
            },
            coverage={
                "denominator": len(self._scanners),
                "scanned": completed,
                **({"exclusions": disabled} if disabled else {}),
            },
            finding_ids=[f.finding_id for f in all_findings],
            artifacts=[{
                "cas_digest": f"sha256:{_sha256_hex(aggregate_body)}",
                "size": len(aggregate_body),
            }],
        )
        validate_station_result(aggregate)

        return {
            "station_result": aggregate,
            "scanner_results": sub_results,
            "findings": [f.to_dict() for f in all_findings[: self._finding_detail_cap]],
            "finding_count": len(all_findings),  # 计数取解析列表全量（明细可能截断）
            "notes": notes,
            "station2_version": STATION2_VERSION,
        }


# ---------------------------------------------------------------------------
# 端到端自证（python3 -m wenqu_core.station2_static；全桩执行，零网络零副作用）
# ---------------------------------------------------------------------------

def _self_test() -> int:  # pragma: no cover - 自证入口
    class _StubRunner(RawTrustedRunner):
        """self-test 专用桩：不执行任何真实命令，按 argv 匹配返回 canned 应答。"""

        def __init__(self, script):
            super().__init__(timeout=30)
            self._script = list(script)

        def run_captured(self, argv, cwd=None):
            for match, respond in self._script:
                if match(list(argv)):
                    evidence, out, err = respond(list(argv))
                    return CapturedRun(evidence=evidence, stdout=out, stderr=err)
            raise AssertionError(f"stub runner: no canned response for {argv}")

    def _ev(argv, rc, ts=None):
        return Evidence(
            argv=tuple(argv), cwd="/tmp", actual_exit_code=rc,
            stdout_sha256=_sha256_hex(b""), stderr_sha256=_sha256_hex(b""),
            argv_digest=_argv_digest(argv), timestamp=ts if ts is not None else time.time(),
            fresh_until=time.time() + 300.0, timed_out=False,
        )

    def _ev_timeout(argv):
        return Evidence(
            argv=tuple(argv), cwd="/tmp", actual_exit_code=None,
            stdout_sha256=_sha256_hex(b""), stderr_sha256=_sha256_hex(b""),
            argv_digest=_argv_digest(argv), timestamp=time.time(),
            fresh_until=time.time() + 300.0, timed_out=True,
        )

    def _j(v):
        return json.dumps(v).encode("utf-8")

    identity = {
        "project_id": "wenqu-selftest",
        "commit_sha": "1" * 40,
        "environment": "local",
        "scope_hash": "a" * 64,
        "ruleset_hash": "b" * 64,
        "data_config_hash": "c" * 64,
    }

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo = tmp_path / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "app" / "x").mkdir(parents=True)
        (repo / "pages").mkdir(parents=True)
        for name in ("a.ts", "b.ts", "c.ts"):
            (repo / "src" / name).write_text("const x = 1\n", encoding="utf-8")
        (repo / "app" / "x" / "page.tsx").write_text("export default function P(){}\n", encoding="utf-8")
        (repo / "pages" / "y.tsx").write_text("export default function Y(){}\n", encoding="utf-8")

        engine_state = tmp_path / "engine-state.json"
        baseline = tmp_path / "dupscan-baseline.json"

        def _engine_state(open_idx=None, drop=None):
            cards = [
                {"id": "ENUM-LITERALS", "slug": "enum", "status": "MERGED(PR#458 批A)"},
                {"id": "CTX-PENETRATION", "slug": "ctx", "status": "MERGED(PR#459)——CTX 卡闭环"},
                {"id": "MSG-STATIC", "slug": "msg", "status": "✅MSG 卡收官(七批)"},
                {"id": "API-ACTION-DUALWRITE", "slug": "dualwrite", "status": "批A/B MERGED(#495/#499)——收官"},
                {"id": "HARDCODED-DOMAIN-ENV", "slug": "envdomain", "status": "✅审计收官——非债"},
            ]
            if drop is not None:
                cards = [c for c in cards if c["slug"] != drop]
            if open_idx is not None:
                cards[open_idx]["status"] = "IN-FLIGHT 批B 进行中"
            return {"created": "2026-09-14T15:50:00+08:00", "updated": "2026-10-07T00:00:00+08:00",
                    "queue": cards, "cursor_inflight": None}

        jscpd_report = {
            "duplicates": [
                {"firstFile": {"name": "a.ts", "path": "src/a.ts", "lines": 10, "start": 1},
                 "secondFile": {"name": "b.ts", "path": "src/b.ts", "lines": 10, "start": 5},
                 "lines": 10, "tokens": 50},
            ],
            "statistics": {"total": {"clones": 1, "duplicates": 1, "files": 3,
                                     "lines": 1000, "percentage": "1.00%"}},
        }
        npm_clean = {
            "auditReportVersion": 2, "vulnerabilities": {},
            "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0},
                         "dependencies": {"prod": 10, "dev": 2, "optional": 0, "peer": 0, "total": 12}},
        }
        npm_high = {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "lodash": {"name": "lodash", "severity": "high", "range": "<4.17.21",
                           "via": [{"title": "Prototype Pollution",
                                    "url": "https://npmjs.com/advisories/1"}],
                           "effects": [], "fixAvailable": True},
            },
            "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 1, "critical": 0},
                         "dependencies": {"prod": 10, "dev": 2, "optional": 0, "peer": 0, "total": 12}},
        }
        route_hit = [
            {"rule": "shadowed-route", "file": "app/sales/[id]/page.tsx", "line": 3,
             "severity": "HIGH", "message": "dead route /sales/sale-exchanges swallowed by dynamic [id]"},
        ]

        def jscpd_respond(report):
            def _respond(argv):
                out_dir = Path(argv[argv.index("--output") + 1])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / JSCPD_REPORT_NAME).write_text(_canonical_json(report), encoding="utf-8")
                return _ev(argv, 0), b"", b""
            return _respond

        base_kwargs = dict(run_id="selftest-st2-001", identity=identity, repo_dir=repo)

        # ---- [1] supply：净 → PASS；分母=metadata.dependencies.total（动态） ----
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 0), _j(npm_clean), b"")),
        ])
        rep = SupplyChainScanner(runner=runner, **base_kwargs).scan()
        assert rep.result["policy_verdict"] == "PASS", rep
        assert rep.result["coverage"]["denominator"] == 12, rep.result["coverage"]
        assert rep.result["coverage"]["scanned"] == 12
        assert rep.result["finding_ids"] == []
        validate_station_result(rep.result)
        print("[1] supply clean OK: PASS, dynamic denominator=12 (metadata.dependencies.total)")

        # ---- [2] supply：HIGH → FAIL；findings 计数取解析列表（非自报） ----
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 1), _j(npm_high), b"")),
        ])
        rep = SupplyChainScanner(runner=runner, **base_kwargs).scan()
        assert rep.result["policy_verdict"] == "FAIL", rep
        assert rep.result["execution_status"] == "COMPLETED"
        assert len(rep.findings) == 1 and rep.findings[0].severity == "HIGH"
        assert rep.findings[0].priority == "P1"
        assert rep.result["finding_ids"] == [rep.findings[0].finding_id]
        validate_station_result(rep.result)
        print("[2] supply HIGH OK: FAIL, 1 finding HIGH/P1 counted from parsed list")

        # ---- [3] supply：空输出/自报不一致/超时/exit>=2 → ERROR 类（非 PASS） ----
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 0), b"", b"")),
        ])
        rep = SupplyChainScanner(runner=runner, **base_kwargs).scan()
        assert rep.result["execution_status"] == "ERROR" and "empty" in rep.note, rep.note
        mismatch = dict(npm_high)
        mismatch["metadata"] = dict(npm_high["metadata"])
        mismatch["metadata"]["vulnerabilities"] = dict(npm_high["metadata"]["vulnerabilities"], high=0)
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 1), _j(mismatch), b"")),
        ])
        rep = SupplyChainScanner(runner=runner, **base_kwargs).scan()
        assert rep.result["execution_status"] == "ERROR" and "self-reported" in rep.note, rep.note
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev_timeout(a), b"", b"")),
        ])
        rep = SupplyChainScanner(runner=runner, **base_kwargs).scan()
        assert rep.result["execution_status"] == "TIMEOUT", rep
        assert rep.result["execution"]["actual_exit_code"] == 124
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 2), b"some error", b"")),
        ])
        rep = SupplyChainScanner(runner=runner, **base_kwargs).scan()
        assert rep.result["execution_status"] == "ERROR" and "exit code 2" in rep.note
        for r in (rep,):
            validate_station_result(r.result)
        print("[3] supply negative OK: empty-json=ERROR / self-report mismatch=ERROR / "
              "timeout=TIMEOUT(124) / exit>=2=ERROR")

        # ---- [4] dupscan：基线内 PASS / 超基线 FAIL / 基线缺失 ERROR / 自报不一致 ERROR ----
        baseline.write_text(_canonical_json({"clone_pairs": 1, "duplicated_lines": 10}), encoding="utf-8")
        runner = _StubRunner([(lambda a: a[0] == "npx", jscpd_respond(jscpd_report))])
        rep = DuplicateCodeScanner(runner=runner, baseline_path=str(baseline), **base_kwargs).scan()
        assert rep.result["policy_verdict"] == "PASS", rep
        assert rep.result["coverage"]["denominator"] == 3, rep.result["coverage"]  # 独立 walk
        assert rep.result["coverage"]["scanned"] == 3
        assert not rep.findings
        validate_station_result(rep.result)
        print("[4a] dupscan within-baseline OK: PASS, denominator=3 from independent walk")

        baseline.write_text(_canonical_json({"clone_pairs": 0, "duplicated_lines": 0}), encoding="utf-8")
        runner = _StubRunner([(lambda a: a[0] == "npx", jscpd_respond(jscpd_report))])
        rep = DuplicateCodeScanner(runner=runner, baseline_path=str(baseline), **base_kwargs).scan()
        assert rep.result["policy_verdict"] == "FAIL", rep
        assert len(rep.findings) == 2  # 1 ratchet 汇总 + 1 对明细（top_k=20）
        assert rep.findings[0].rule_id == "dupscan/ratchet-exceeded"
        validate_station_result(rep.result)
        runner = _StubRunner([(lambda a: a[0] == "npx", jscpd_respond(jscpd_report))])
        rep = DuplicateCodeScanner(runner=runner, baseline_path=str(tmp_path / "nope.json"), **base_kwargs).scan()
        assert rep.result["execution_status"] == "ERROR" and "baseline missing" in rep.note
        bad_report = dict(jscpd_report)
        bad_report["statistics"] = {"total": dict(jscpd_report["statistics"]["total"], duplicates=5)}
        runner = _StubRunner([(lambda a: a[0] == "npx", jscpd_respond(bad_report))])
        rep = DuplicateCodeScanner(runner=runner, baseline_path=str(baseline), **base_kwargs).scan()
        assert rep.result["execution_status"] == "BLOCKED" and "self-reported" in rep.note, (
            rep.result["execution_status"], rep.note)  # 分母已知+scanned=0→缩水守卫折叠
        print("[4b] dupscan negative OK: over-baseline=FAIL / missing-baseline=ERROR / "
              "self-report mismatch=BLOCKED(shrink guard; reason in note)")

        # ---- [5] engine：全收口 PASS / 有 open FAIL / 删卡缩水 BLOCKED / 缺文件 ERROR ----
        engine_state.write_text(_canonical_json(_engine_state()), encoding="utf-8")
        rep = EngineFiveTypesScanner(runner=_StubRunner([]), engine_state_path=str(engine_state), **base_kwargs).scan()
        assert rep.result["policy_verdict"] == "PASS", rep
        assert rep.result["coverage"] == {"denominator": 5, "scanned": 5}, rep.result["coverage"]
        validate_station_result(rep.result)
        print("[5a] engine all-closed OK: PASS, denominator=5 (five-type universe, dynamic)")

        engine_state.write_text(_canonical_json(_engine_state(open_idx=4)), encoding="utf-8")
        rep = EngineFiveTypesScanner(runner=_StubRunner([]), engine_state_path=str(engine_state), **base_kwargs).scan()
        assert rep.result["policy_verdict"] == "FAIL" and len(rep.findings) == 1
        assert rep.findings[0].rule_id == "engine-five-types/envdomain"
        validate_station_result(rep.result)

        engine_state.write_text(_canonical_json(_engine_state(drop="msg")), encoding="utf-8")
        rep = EngineFiveTypesScanner(runner=_StubRunner([]), engine_state_path=str(engine_state), **base_kwargs).scan()
        assert rep.result["execution_status"] == "BLOCKED", rep  # 宇宙缺卡→缩水守卫
        assert rep.result["coverage"]["scanned"] == 4 < rep.result["coverage"]["denominator"] == 5

        rep = EngineFiveTypesScanner(runner=_StubRunner([]), engine_state_path=str(tmp_path / "absent.json"), **base_kwargs).scan()
        assert rep.result["execution_status"] == "ERROR" and "unreadable" in rep.note
        print("[5b] engine negative OK: open-card=FAIL / dropped-card=BLOCKED(shrink) / "
              "missing-state=ERROR")

        # ---- [6] route：命中 FAIL / 环境错 ERROR / 净 PASS / 零路由 NOT_APPLICABLE / 未配置 ERROR ----
        probe = ["route-probe", "--static"]
        runner = _StubRunner([
            (lambda a: a[0] == "route-probe", lambda a: (_ev(a, 1), _j(route_hit), b"")),
        ])
        rep = RouteIntegrityScanner(runner=runner, route_probe_argv=probe, **base_kwargs).scan()
        assert rep.result["policy_verdict"] == "FAIL" and len(rep.findings) == 1
        assert rep.findings[0].severity == "HIGH" and rep.findings[0].priority == "P1"
        assert rep.result["coverage"]["denominator"] == 2, rep.result["coverage"]  # app+pages walk
        validate_station_result(rep.result)
        runner = _StubRunner([
            (lambda a: a[0] == "route-probe", lambda a: (_ev(a, 2), b"", b"err")),
        ])
        rep = RouteIntegrityScanner(runner=runner, route_probe_argv=probe, **base_kwargs).scan()
        assert rep.result["execution_status"] == "BLOCKED", rep  # 分母已知→缩水守卫折叠
        assert rep.result["execution"]["actual_exit_code"] == 2  # 真实 rc 保留
        runner = _StubRunner([
            (lambda a: a[0] == "route-probe", lambda a: (_ev(a, 1), b"", b"")),
        ])
        rep = RouteIntegrityScanner(runner=runner, route_probe_argv=probe, **base_kwargs).scan()
        assert rep.result["execution_status"] == "BLOCKED" and "empty stdout" in rep.note
        runner = _StubRunner([
            (lambda a: a[0] == "route-probe", lambda a: (_ev(a, 0), b"", b"")),
        ])
        rep = RouteIntegrityScanner(runner=runner, route_probe_argv=probe, **base_kwargs).scan()
        assert rep.result["policy_verdict"] == "PASS" and not rep.findings
        rep = RouteIntegrityScanner(runner=_StubRunner([]), route_probe_argv=None, **base_kwargs).scan()
        assert rep.result["execution_status"] == "BLOCKED" and "not configured" in rep.note
        empty_repo = tmp_path / "empty-repo"
        empty_repo.mkdir()
        rep = RouteIntegrityScanner(
            runner=_StubRunner([]), route_probe_argv=probe,
            run_id="selftest-st2-001", identity=identity, repo_dir=empty_repo,
        ).scan()
        assert rep.result["policy_verdict"] == "NOT_APPLICABLE", rep
        validate_station_result(rep.result)
        print("[6] route OK: hit=FAIL(parsed findings) / env-error=BLOCKED(real rc kept) / "
              "exit1-empty=BLOCKED / clean=PASS / unconfigured=BLOCKED / "
              "non-route-repo=NOT_APPLICABLE")

        # ---- [7] 聚合：任一 FAIL→FAIL；任一未完成→BLOCKED（缩水守卫）；全绿→PASS ----
        engine_state.write_text(_canonical_json(_engine_state()), encoding="utf-8")
        baseline.write_text(_canonical_json({"clone_pairs": 1, "duplicated_lines": 10}), encoding="utf-8")
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 1), _j(npm_high), b"")),
            (lambda a: a[0] == "npx", jscpd_respond(jscpd_report)),
            (lambda a: a[0] == "route-probe", lambda a: (_ev(a, 0), b"", b"")),
        ])
        report = Station2Static(
            "selftest-st2-001", identity=identity, repo_dir=str(repo), runner=runner,
            baseline_path=str(baseline), engine_state_path=str(engine_state),
            route_probe_argv=probe,
        ).scan()
        agg = report["station_result"]
        validate_station_result(agg)
        assert agg["station_id"] == 2
        assert agg["policy_verdict"] == "FAIL" and agg["execution_status"] == "COMPLETED"
        assert agg["coverage"] == {"denominator": 4, "scanned": 4}, agg["coverage"]
        assert len(agg["finding_ids"]) == 1 and report["finding_count"] == 1
        assert set(report["scanner_results"]) == set(SCAN_SLUGS)
        for sub in report["scanner_results"].values():
            validate_station_result(sub)
        print("[7a] aggregate OK: supply FAIL -> station FAIL, coverage 4/4 scanners, "
              "all sub-results schema-valid")

        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 0), b"", b"")),  # 空输出=ERROR
            (lambda a: a[0] == "npx", jscpd_respond(jscpd_report)),
            (lambda a: a[0] == "route-probe", lambda a: (_ev(a, 0), b"", b"")),
        ])
        report = Station2Static(
            "selftest-st2-002", identity=identity, repo_dir=str(repo), runner=runner,
            baseline_path=str(baseline), engine_state_path=str(engine_state),
            route_probe_argv=probe,
        ).scan()
        agg = report["station_result"]
        validate_station_result(agg)
        assert agg["execution_status"] == "BLOCKED" and agg["policy_verdict"] == "NOT_EVALUATED"
        assert agg["coverage"]["scanned"] == 3 < agg["coverage"]["denominator"] == 4
        assert report["scanner_results"]["supply"]["execution_status"] == "ERROR"
        assert "supply" in report["notes"]
        print("[7b] aggregate negative OK: any non-COMPLETED scanner -> station BLOCKED "
              "(denominator-shrink guard), granular ERROR preserved in sub-result")

        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 0), _j(npm_clean), b"")),
            (lambda a: a[0] == "npx", jscpd_respond(jscpd_report)),
            (lambda a: a[0] == "route-probe", lambda a: (_ev(a, 0), b"", b"")),
        ])
        report = Station2Static(
            "selftest-st2-003", identity=identity, repo_dir=str(repo), runner=runner,
            baseline_path=str(baseline), engine_state_path=str(engine_state),
            route_probe_argv=probe,
        ).scan()
        agg = report["station_result"]
        validate_station_result(agg)
        assert agg["policy_verdict"] == "PASS" and agg["execution_status"] == "COMPLETED"
        assert agg["execution"]["actual_exit_code"] == 0
        assert report["finding_count"] == 0
        print("[7c] aggregate all-green OK: station PASS, unified exit 0")

        # ---- [8] 构造参数负例 + 显式缩件 ----
        for bad_kwargs in (
            dict(run_id="bad id!", identity=identity, repo_dir=str(repo)),
            dict(run_id="ok-run", identity={"commit_sha": "xyz"}, repo_dir=str(repo)),
            dict(run_id="ok-run", identity=identity, repo_dir=str(tmp_path / "nope")),
        ):
            try:
                Station2Static(**bad_kwargs)
                raise AssertionError(f"config error must raise: {bad_kwargs}")
            except Station2ConfigError:
                pass
        report = Station2Static(
            "selftest-st2-004", identity=identity, repo_dir=str(repo),
            runner=_StubRunner([
                (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 0), _j(npm_clean), b"")),
            ]),
            scanners=("supply",),
        ).scan()
        agg = report["station_result"]
        assert agg["coverage"] == {"denominator": 1, "scanned": 1, "exclusions": ["dupscan", "engine", "route"]}
        validate_station_result(agg)
        print("[8] config negatives OK: bad run_id/identity/repo_dir rejected; "
              "explicit scanner subset recorded in coverage.exclusions")

    print("SELF-TEST PASS")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())

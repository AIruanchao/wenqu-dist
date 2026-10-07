# -*- coding: utf-8 -*-
"""station3_contract.py——Codex 方案 W6C：站3「契约与数据」适配器。

正源与契约：
- Codex 方案 W6C：站3 = 契约与数据（API 契约对账 / 权限矩阵 / schema 漂移，
  按栈选件）。
- 《问渠轨道规范（发行版 v2.0）》§1 站3 判据：无未归属端点；负例全拦 +
  正例全通；漂移白名单制。evidence_class=permission_vulnerability
  （TTL ≤7 天——铁律 4 双上限的严档）。
- 输出严格遵循 schemas/station-result-v2.schema.json：复用
  bugscan_orchestrator.build_station_result / validate_station_result
  （内置结构校验 + jsonschema 双保险）；本模块不自造判定第二正源。

四个适配器（编排层不造扫描工具——只消费底层件结果并做机械映射，一律
fail-closed：载荷畸形 / 身份绑定失败 / 证据过期即抛错，绝不折算为 PASS）：

- OpenApiReconciler    openapi.json ↔ 实际路由对账。
                       denominator=端点总数（spec ∪ 实际路由的并集），
                       scanned=已对账端点数；规格有而实现缺（SPEC_ONLY）与
                       实现有而规格无（ROUTE_ONLY=未归属端点）都是 FAIL 发现。
- OrgGuardScanner      每端点 org 过滤正例+负例：正例=本 org 合法访问必须通，
                       负例=跨 org 越权必须被拒。denominator=端点数×2
                       （正例+负例用例矩阵），scanned=已执行且结果可判定的
                       用例数；负例放行 / 正例未通 → FAIL。
- PermissionMatrixScanner  权限矩阵三源仲裁（runtime > DB > static）：
                       逐格取最高优先源的值，源间冲突落 finding；DB 源与
                       DbDriftScanner 同款只读纪律。
- DbDriftScanner       消费 judge_drift.py 报告：零变化才 CLEAN；
                       DROP=HIGH、未知变更类型=HIGH（fail-closed）；
                       白名单绑定对象 identity + 内容 hash + 到期时间
                       （30 天日落；hash 不匹配 / 已过期 = 条目无效）。

安全构造（by construction）：
- 纯 stdlib；无 shell 拼接、无 eval/exec；所有哈希走 canonical JSON。
- DB 连接身份 / 只读状态 / diff 方向进入 evidence identity：
  db_identity 三要素哈希入账（tool.digest + details 工件），read_only
  非 True 一律 NonReadOnlyDataSource 拒绝——绝不带可写身份出 PASS；
  connection_identity 疑似含凭据字段（password/token/…）直接拒绝入库。
- 分母动态生成：denominator 从 Prisma DMMF 或 openapi.json 现算
  （derive_dynamic_denominator），不采信载荷自报分母；报告分母或模型
  监控面小于动态分母 → 整站 BLOCKED（分母缩水守卫，schema $comment）。
- 白名单三绑定缺一即失效：对象 identity、内容 hash、未过期到期时间。
- 身份三源（commit_sha/environment/scope_hash 等）一律取自冻结
  RunManifest 正源，绝不采信载荷自报身份（与站1 同款纪律）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # 包内正则导入（wenqu_core.station3_contract）
    from .bugscan_orchestrator import (
        BugscanPlanner,
        RunManifest,
        StationRegistry,
        _argv_digest,
        _hash_obj,
        _iso_z,
        _make_attempt_id,
        _parse_iso,
        _sha256_hex,
        _utc_now,
        build_station_result,
        default_registry,
        validate_station_result,
        EvidenceStaleError,
    )
except ImportError:  # 顶层直接加载兜底（如 python3 wenqu_core/station3_contract.py）
    from bugscan_orchestrator import (  # type: ignore
        BugscanPlanner,
        RunManifest,
        StationRegistry,
        _argv_digest,
        _hash_obj,
        _iso_z,
        _make_attempt_id,
        _parse_iso,
        _sha256_hex,
        _utc_now,
        build_station_result,
        default_registry,
        validate_station_result,
        EvidenceStaleError,
    )

__all__ = [
    "STATION_ID",
    "PERMISSION_SOURCE_PRECEDENCE",
    "DRIFT_CHANGE_SEVERITY",
    "UNKNOWN_CHANGE_SEVERITY",
    "DIFF_DIRECTIONS",
    "ALLOWLIST_MAX_DAYS",
    "Station3Contract",
    "OpenApiReconciler",
    "OrgGuardScanner",
    "PermissionMatrixScanner",
    "DbDriftScanner",
    "DriftAllowlist",
    "openapi_spec_endpoints",
    "prisma_dmmf_model_count",
    "derive_dynamic_denominator",
    "Station3Error",
    "ContractPayloadMalformed",
    "OpenApiSpecMalformed",
    "OrgGuardResultMalformed",
    "PermissionMatrixMalformed",
    "DriftReportMalformed",
    "EvidenceIdentityError",
    "EvidenceIdentityMismatch",
    "NonReadOnlyDataSource",
    "AllowlistEntryInvalid",
]

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# 契约常量
# ---------------------------------------------------------------------------

#: 站3 固定编号（schemas/station-result-v2.station_id ∈ [0,7]）。
STATION_ID = 3

#: 权限矩阵三源仲裁优先级：runtime（运行时实测）> DB > static（静态声明）。
PERMISSION_SOURCE_PRECEDENCE: Tuple[str, ...] = ("runtime", "db", "static")

#: judge_drift 变更类型 → 严重级；DROP=HIGH（任务冻结语义），未知类型一律
#: HIGH（fail-closed：无法定级按最坏处理）。零变化才 CLEAN。
DRIFT_CHANGE_SEVERITY: Dict[str, str] = {
    "CREATE": "MEDIUM",
    "ADD": "MEDIUM",
    "ALTER": "MEDIUM",
    "MODIFY": "MEDIUM",
    "COLUMN_ADD": "MEDIUM",
    "COLUMN_DROP": "HIGH",
    "TABLE_DROP": "HIGH",
    "RENAME": "LOW",
    "DROP": "HIGH",
}
UNKNOWN_CHANGE_SEVERITY = "HIGH"

#: 白名单条目到期窗口上限（与降档风险接受记录同款 30 天日落纪律）。
ALLOWLIST_MAX_DAYS = 30

#: diff 方向合法枚举——方向进入 evidence identity（翻向=不同证据，不可混用）。
DIFF_DIRECTIONS: Tuple[str, ...] = ("actual_vs_expected", "expected_vs_actual")

#: 适配器可映射为结果内层退出码的执行状态集（对齐 §7 契约：
#: 0=完成且零发现 / 1=完成但有发现（落账） / 2=环境错 / 3=阻断 / 124=超时）。
_EXIT_BY_STATUS: Dict[str, int] = {
    "COMPLETED": 0,
    "ERROR": 2,
    "BLOCKED": 3,
    "TIMEOUT": 124,
    "CANCELLED": 4,
}

_HTTP_METHODS = frozenset(
    ("get", "put", "post", "delete", "options", "head", "patch", "trace")
)
_UPPER_METHODS = frozenset(m.upper() for m in _HTTP_METHODS)

_RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RE_FND_TOKEN = re.compile(r"[^A-Za-z0-9_]+")
#: connection_identity 里疑似凭据字段——证据身份拒绝入库（不得带凭据出账）。
_RE_CREDENTIALISH = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|credential)"
)

_DEFAULT_TIMEOUT_S = 600


# ---------------------------------------------------------------------------
# 异常（一律 fail-closed）
# ---------------------------------------------------------------------------

class Station3Error(ValueError):
    """站3 适配基类——任何输入不合法都拒绝，绝不折算为 PASS。"""


class ContractPayloadMalformed(Station3Error):
    """底层件载荷畸形：缺字段、类型错、自报分母与内容矛盾等。"""


class OpenApiSpecMalformed(ContractPayloadMalformed):
    """openapi.json 或路由清单畸形。"""


class OrgGuardResultMalformed(ContractPayloadMalformed):
    """org-guard 检查结果畸形。"""


class PermissionMatrixMalformed(ContractPayloadMalformed):
    """权限矩阵载荷畸形（源名/格值非法等）。"""


class DriftReportMalformed(ContractPayloadMalformed):
    """judge_drift.py 报告畸形。"""


class EvidenceIdentityError(Station3Error):
    """证据身份绑定失败（DB 连接身份/数据配置与冻结正源不一致等）。"""


class EvidenceIdentityMismatch(EvidenceIdentityError):
    """载荷携带的 data_config 与冻结 manifest.data_config_hash 不一致。"""


class NonReadOnlyDataSource(EvidenceIdentityError):
    """数据源只读状态不成立——可写身份一律拒绝，绝不带写身份出 PASS。"""


class AllowlistEntryInvalid(Station3Error):
    """白名单条目结构非法或到期超出 30 天日落窗口。"""


# ---------------------------------------------------------------------------
# 工具函数：finding id / 工件 / 动态分母
# ---------------------------------------------------------------------------

def _finding_id(prefix: str, *parts: object) -> str:
    """构造 schema 合法（^fnd_[a-zA-Z0-9_]+$）的发现 id。"""
    token = "_".join(
        _RE_FND_TOKEN.sub("_", str(p)).strip("_")
        for p in parts
        if p is not None and str(p)
    ).strip("_")
    return f"fnd_{prefix}_{token}" if token else f"fnd_{prefix}"


def _details_artifact(details: Mapping[str, Any]) -> Dict[str, Any]:
    """把 details 映射变成 CAS 工件记录（sha256 内容寻址 + 字节数）。"""
    import json

    payload = json.dumps(
        dict(details), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return {"cas_digest": f"sha256:{_sha256_hex(payload)}", "size": len(payload)}


def openapi_spec_endpoints(openapi_spec: Mapping[str, Any]) -> List[Tuple[str, str]]:
    """展开 openapi.json → 排序去重后的 (METHOD, path) 端点清单。

    只认 paths.<path> 下的 HTTP 方法键（parameters/summary 等忽略）；
    paths 缺失/为空/无任何方法键 → OpenApiSpecMalformed（空契约=非法）。
    """
    if not isinstance(openapi_spec, Mapping):
        raise OpenApiSpecMalformed(
            f"openapi_spec must be a mapping (openapi.json 内容), "
            f"got {type(openapi_spec).__name__}"
        )
    paths = openapi_spec.get("paths")
    if not isinstance(paths, Mapping) or not paths:
        raise OpenApiSpecMalformed("openapi_spec.paths must be a non-empty object")
    endpoints: List[Tuple[str, str]] = []
    for path, item in paths.items():
        if not isinstance(item, Mapping):
            raise OpenApiSpecMalformed(f"openapi_spec.paths[{path!r}] must be an object")
        for key in item:
            if str(key).lower() in _HTTP_METHODS:
                endpoints.append((str(key).upper(), str(path)))
    if not endpoints:
        raise OpenApiSpecMalformed("openapi_spec declares no HTTP endpoints")
    return sorted(set(endpoints))


def prisma_dmmf_model_count(dmmf: Mapping[str, Any]) -> int:
    """Prisma DMMF → 受监控数据模型数（DB 漂移分母的动态正源）。"""
    if not isinstance(dmmf, Mapping):
        raise Station3Error(
            f"prisma_dmmf must be a mapping (DMMF JSON), got {type(dmmf).__name__}"
        )
    datamodel = dmmf.get("datamodel")
    if not isinstance(datamodel, Mapping):
        raise Station3Error("prisma_dmmf.datamodel must be an object")
    models = datamodel.get("models")
    if not isinstance(models, list) or not models:
        raise Station3Error("prisma_dmmf.datamodel.models must be a non-empty list")
    names: List[str] = []
    for i, model in enumerate(models):
        if (
            not isinstance(model, Mapping)
            or not isinstance(model.get("name"), str)
            or not model["name"].strip()
        ):
            raise Station3Error(
                f"prisma_dmmf.datamodel.models[{i}] must have a non-empty name"
            )
        names.append(model["name"].strip())
    if len(set(names)) != len(names):
        raise Station3Error("prisma_dmmf.datamodel.models contains duplicate names")
    return len(names)


def derive_dynamic_denominator(
    *,
    openapi_spec: Optional[Mapping[str, Any]] = None,
    prisma_dmmf: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """动态分母：优先 openapi.json 端点数，其次 Prisma DMMF 模型数。

    返回 {"denominator", "source", "source_digest"}；两者皆缺 → Station3Error
    （分母必须有正源，不采信载荷自报数字）。
    """
    if openapi_spec is not None:
        endpoints = openapi_spec_endpoints(openapi_spec)
        return {
            "denominator": len(endpoints),
            "source": "openapi",
            "source_digest": _hash_obj({"endpoints": endpoints}),
        }
    if prisma_dmmf is not None:
        count = prisma_dmmf_model_count(prisma_dmmf)
        return {
            "denominator": count,
            "source": "prisma_dmmf",
            "source_digest": _hash_obj(prisma_dmmf),
        }
    raise Station3Error(
        "denominator source required: openapi_spec 或 prisma_dmmf 必给其一"
    )


def _require_str(value: Any, *, what: str, exc: type = ContractPayloadMalformed) -> str:
    if not isinstance(value, str) or not value.strip():
        raise exc(f"{what} must be a non-empty string, got {value!r}")
    return value.strip()


def _require_int(
    value: Any, *, what: str, minimum: int = 0, exc: type = ContractPayloadMalformed
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise exc(f"{what} must be an int >= {minimum}, got {value!r}")
    return value


# ---------------------------------------------------------------------------
# DriftAllowlist——schema 漂移白名单（三绑定：对象 identity + hash + 到期）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DriftAllowlist:
    """白名单条目：对象 identity + 内容 hash + 到期时间，缺一即失效。

    - content_hash 绑定对象变更后仍可验证的一方内容（一般取 actual_hash；
      DROP 等对象已不可再现的取 expected_hash）——hash 不匹配=条目对该变更
      无效，漂移照常 FAIL。
    - expires_at 必须 ISO-8601 且落在 (now, now+30d] 日落窗口内；已过期 =
      条目无效（不是载荷错误——时间过了而已，漂移照常 FAIL）。
    - approver/reason 为审计要素，建议填写（与风险接受记录同款纪律）。
    """

    object_identity: str
    content_hash: str
    expires_at: str
    approver: str = ""
    reason: str = ""

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "DriftAllowlist":
        if not isinstance(data, Mapping):
            raise AllowlistEntryInvalid(
                f"allowlist entry must be a mapping, got {type(data).__name__}"
            )
        missing = [
            k for k in ("object_identity", "content_hash", "expires_at")
            if not data.get(k)
        ]
        if missing:
            raise AllowlistEntryInvalid(
                f"allowlist entry missing required fields: {missing} "
                "(对象 identity / 内容 hash / 到期时间 三绑定缺一不可)"
            )
        content_hash = data["content_hash"]
        if not isinstance(content_hash, str) or not _RE_HEX64.match(content_hash):
            raise AllowlistEntryInvalid(
                f"allowlist content_hash must be 64-char lowercase hex, "
                f"got {content_hash!r}"
            )
        try:
            _parse_iso(str(data["expires_at"]), what="allowlist expires_at")
        except ValueError as exc:
            raise AllowlistEntryInvalid(str(exc)) from exc
        return cls(
            object_identity=_require_str(
                data["object_identity"], what="allowlist object_identity",
                exc=AllowlistEntryInvalid,
            ),
            content_hash=content_hash,
            expires_at=str(data["expires_at"]),
            approver=str(data.get("approver", "")),
            reason=str(data.get("reason", "")),
        )

    def validate_window(self, now: Optional[Any] = None) -> Any:
        """校验日落窗口：到期不得晚于 now+30d（晚于=条目非法，直接拒绝）。"""
        from datetime import datetime

        now_dt = now if isinstance(now, datetime) else _utc_now()
        expiry = _parse_iso(self.expires_at, what="allowlist expires_at")
        if expiry > now_dt + timedelta(days=ALLOWLIST_MAX_DAYS):
            raise AllowlistEntryInvalid(
                f"allowlist for {self.object_identity!r} expires "
                f"{self.expires_at} — beyond {ALLOWLIST_MAX_DAYS}d sunset window"
            )
        return expiry

    def effective_through(self, now: Optional[Any] = None) -> Optional[Any]:
        """返回仍有效的到期时刻；已过期返回 None（条目对该时刻无效）。"""
        from datetime import datetime

        now_dt = now if isinstance(now, datetime) else _utc_now()
        expiry = _parse_iso(self.expires_at, what="allowlist expires_at")
        return expiry if expiry > now_dt else None

    def matches(self, *, object_identity: str, binding_hash: Optional[str]) -> bool:
        """三绑定匹配：对象 identity 相同且内容 hash 相同（hash 缺位=不匹配）。"""
        if not binding_hash:
            return False
        return (
            self.object_identity == object_identity
            and self.content_hash == binding_hash
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "object_identity": self.object_identity,
            "content_hash": self.content_hash,
            "expires_at": self.expires_at,
        }
        if self.approver:
            out["approver"] = self.approver
        if self.reason:
            out["reason"] = self.reason
        return out


# ---------------------------------------------------------------------------
# 站3 子适配器基类
# ---------------------------------------------------------------------------

class _Station3Adapter:
    """站3 四件套共同纪律：manifest 身份正源 + TTL 时效 + 统一结果构造。

    - 身份三源一律取冻结 RunManifest；载荷自报身份只作绑定校验对象。
    - 时效：ended_at + 站 TTL（7 天）≥ now，过期抛 EvidenceStaleError。
    - 结果构造：findings 非空 → COMPLETED/FAIL（exit 1，发现自动落账语义）；
      分母缩水（scanned < denominator）→ BLOCKED/NOT_EVALUATED（铁律 2）；
      全绿 → COMPLETED/PASS（exit 0）。
    """

    STATION_ID = STATION_ID
    slug = "station3"
    tag = "st3"

    def __init__(
        self,
        manifest: RunManifest,
        *,
        registry: Optional[StationRegistry] = None,
        now: Optional[Any] = None,
    ) -> None:
        if not isinstance(manifest, RunManifest):
            raise Station3Error(
                f"manifest must be RunManifest, got {type(manifest).__name__}"
            )
        registry = registry or default_registry()
        spec = registry.get(STATION_ID)  # 站未注册 → KeyError（fail-closed）
        self._manifest = manifest
        self._registry = registry
        self._spec = spec
        self._now = now

    # -- 基本信息 -----------------------------------------------------------
    @property
    def manifest(self) -> RunManifest:
        return self._manifest

    @property
    def ttl_days(self) -> int:
        return self._spec.ttl_days

    # -- 公共校验 -----------------------------------------------------------
    def _manifest_identity(self) -> Dict[str, Any]:
        m = self._manifest
        identity: Dict[str, Any] = {
            "project_id": m.project_id,
            "commit_sha": m.commit_sha,
            "environment": m.environment,
            "scope_hash": m.scope_hash,
            "ruleset_hash": m.ruleset_hash,
            "data_config_hash": m.data_config_hash,
        }
        if m.lockfile_hash:
            identity["lockfile_hash"] = m.lockfile_hash
        return identity

    def _check_freshness(self, ended_at: str, *, what: str) -> None:
        ended = _parse_iso(ended_at, what=f"{what}.ended_at")
        now = self._now or _utc_now()
        if ended + timedelta(days=self._spec.ttl_days) < now:
            raise EvidenceStaleError(
                f"{what}: evidence aged out (ended {ended_at} + TTL "
                f"{self._spec.ttl_days}d < now {_iso_z(now)})——重跑底层件后重新适配"
            )

    def _extract_common(self, payload: Any, *, what: str) -> Dict[str, Any]:
        """公共字段抽取：tool{name,version} + ISO 时间戳 + 可选 argv/timeout。"""
        if not isinstance(payload, Mapping):
            raise ContractPayloadMalformed(
                f"{what} must be a mapping, got {type(payload).__name__}"
            )
        tool = payload.get("tool")
        if (
            not isinstance(tool, Mapping)
            or not tool.get("name")
            or not tool.get("version")
        ):
            raise ContractPayloadMalformed(
                f"{what}.tool must be an object with non-empty name/version"
            )
        out: Dict[str, Any] = {"tool": dict(tool)}
        for ts_key in ("started_at", "ended_at"):
            if ts_key not in payload:
                raise ContractPayloadMalformed(f"{what} missing {ts_key}")
            try:
                _parse_iso(payload[ts_key], what=f"{what}.{ts_key}")
            except ValueError as exc:
                raise ContractPayloadMalformed(str(exc)) from exc
            out[ts_key] = payload[ts_key]
        if payload.get("argv_digest"):
            out["argv_digest"] = str(payload["argv_digest"])
        if payload.get("timeout_s") is not None:
            out["timeout_s"] = _require_int(
                payload["timeout_s"], what=f"{what}.timeout_s", minimum=1
            )
        self._check_freshness(out["ended_at"], what=what)
        return out

    # -- 统一结果构造 -------------------------------------------------------
    def _build_result(
        self,
        *,
        parsed: Mapping[str, Any],
        findings: Sequence[str],
        denominator: int,
        scanned: int,
        details: Optional[Mapping[str, Any]] = None,
        exclusions: Sequence[str] = (),
        tool_digest: Optional[str] = None,
    ) -> Dict[str, Any]:
        """映射为站3 单件 station-result-v2（经 build/validate 双保险）。"""
        findings_list = list(dict.fromkeys(findings))  # 去重保序
        shrink = scanned < denominator
        if shrink:
            # 分母缩水守卫：整件 BLOCKED，绝不记 PASS（schema $comment + 铁律 2）。
            execution_status, policy_verdict = "BLOCKED", "NOT_EVALUATED"
            assertion = "ERROR"
        elif findings_list:
            execution_status, policy_verdict = "COMPLETED", "FAIL"
            assertion = "FAIL"
        else:
            execution_status, policy_verdict = "COMPLETED", "PASS"
            assertion = "PASS"

        tool = {
            "name": str(parsed["tool"]["name"]),
            "version": str(parsed["tool"]["version"]),
        }
        tool["digest"] = str(
            tool_digest
            or parsed["tool"].get("digest")
            or _hash_obj(dict(parsed["tool"]))
        )

        exit_code = (
            1 if (execution_status == "COMPLETED" and findings_list)
            else _EXIT_BY_STATUS[execution_status]
        )
        execution = {
            "argv_digest": str(
                parsed.get("argv_digest")
                or _argv_digest([tool["name"], self._manifest.run_id, self.tag])
            ),
            "started_at": parsed["started_at"],
            "ended_at": parsed["ended_at"],
            "timeout_s": int(parsed.get("timeout_s", _DEFAULT_TIMEOUT_S)),
            "actual_exit_code": exit_code,
            "expected_exit_set": [0, 1],  # 0=零发现 / 1=有发现落账；≥2=环境错（抛错路径）
            "assertion_verdict": assertion,
        }

        artifacts: List[Dict[str, Any]] = []
        if details is not None:
            artifacts.append(_details_artifact(details))

        coverage: Dict[str, Any] = {
            "denominator": int(denominator),
            "scanned": int(scanned),
        }
        if exclusions:
            coverage["exclusions"] = list(exclusions)

        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=STATION_ID,
            attempt_id=_make_attempt_id(self._manifest.run_id, self.tag),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=self._manifest_identity(),
            tool=tool,
            execution=execution,
            coverage=coverage,
            finding_ids=findings_list,
            artifacts=artifacts,
        )


# ---------------------------------------------------------------------------
# OpenApiReconciler——API 契约对账
# ---------------------------------------------------------------------------

class OpenApiReconciler(_Station3Adapter):
    """openapi.json ↔ 实际路由对账（denominator=端点总数，scanned=已对账数）。

    payload 契约（adapt 的入参）::

        {
          "tool": {"name": …, "version": …},          # 必填
          "started_at"/"ended_at": ISO-8601,           # 必填（TTL 时效校验）
          "argv_digest"?: str, "timeout_s"?: int,
          "openapi_spec": {…openapi.json…},            # 或构造器注入，二选一
          "actual_routes": [{"method": "GET", "path": "/api/orders"}, …],
          "reconciled"?: [{"method": …, "path": …}, …] # 底层件实际已对账的端点；
                                                       # 缺省=清单齐全可全量判定
        }

    判定（规范 §1 站3）：
    - SPEC_ONLY（规格有、实现缺）与 ROUTE_ONLY（实现有、规格无=未归属端点）
      都是 FAIL 发现；
    - reconciled 只覆盖部分端点 → scanned < denominator → BLOCKED；
      reconciled 含 universe 外端点 → 载荷自矛盾，直接拒绝；
    - denominator = |spec 端点 ∪ 实际路由|（动态现算，不采信自报数字）。
    """

    slug = "openapi_reconcile"
    tag = "st3-openapi"

    def __init__(
        self,
        manifest: RunManifest,
        *,
        registry: Optional[StationRegistry] = None,
        now: Optional[Any] = None,
        openapi_spec: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(manifest, registry=registry, now=now)
        self._openapi_spec = openapi_spec

    # -- 端点清单 -----------------------------------------------------------
    @staticmethod
    def spec_endpoints(openapi_spec: Mapping[str, Any]) -> List[Tuple[str, str]]:
        return openapi_spec_endpoints(openapi_spec)

    @staticmethod
    def _norm_routes(routes_raw: Any) -> List[Tuple[str, str]]:
        if not isinstance(routes_raw, list):
            raise OpenApiSpecMalformed(
                "actual_routes must be a list of {method, path} objects"
            )
        seen: set = set()
        for i, route in enumerate(routes_raw):
            if not isinstance(route, Mapping):
                raise OpenApiSpecMalformed(
                    f"actual_routes[{i}] must be an object, "
                    f"got {type(route).__name__}"
                )
            method = str(route.get("method", "")).upper()
            path = str(route.get("path", ""))
            if method not in _UPPER_METHODS or not path.strip():
                raise OpenApiSpecMalformed(
                    f"actual_routes[{i}] must carry a valid HTTP method and path, "
                    f"got {route!r}"
                )
            key = (method, path)
            if key in seen:
                raise OpenApiSpecMalformed(
                    f"actual_routes contains duplicate endpoint {method} {path}"
                )
            seen.add(key)
        return sorted(seen)

    # -- 适配 ---------------------------------------------------------------
    def adapt(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        parsed = self._extract_common(payload, what="openapi_reconciler payload")
        openapi_spec = (
            payload["openapi_spec"] if "openapi_spec" in payload
            else self._openapi_spec
        )
        if openapi_spec is None:
            raise OpenApiSpecMalformed(
                "openapi_spec required（payload.openapi_spec 或构造器注入，二选一）"
            )
        spec_eps = set(openapi_spec_endpoints(openapi_spec))
        actual_eps = set(self._norm_routes(payload.get("actual_routes")))

        universe = spec_eps | actual_eps
        reconciled_raw = payload.get("reconciled")
        if reconciled_raw is None:
            # 两份清单都在手 → 对账可全量判定（scanned=denominator）。
            scanned_eps = set(universe)
        else:
            if not isinstance(reconciled_raw, list):
                raise OpenApiSpecMalformed(
                    "reconciled must be a list of {method, path} objects"
                )
            declared = set(self._norm_routes(reconciled_raw))
            outside = declared - universe
            if outside:
                # fail-closed：对账了既不在规格也不在路由清单里的端点=载荷自矛盾。
                raise OpenApiSpecMalformed(
                    f"reconciled contains endpoints outside the universe "
                    f"(spec ∪ actual_routes): "
                    f"{sorted(f'{m} {p}' for m, p in outside)}"
                )
            scanned_eps = declared

        spec_only = sorted(spec_eps - actual_eps)
        unowned = sorted(actual_eps - spec_eps)
        findings = [
            _finding_id("st3_openapi_spec_only", m, p) for m, p in spec_only
        ] + [
            _finding_id("st3_openapi_unowned", m, p) for m, p in unowned
        ]

        details = {
            "kind": "station3/openapi-reconcile",
            "spec_digest": _hash_obj(dict(openapi_spec)),
            "spec_endpoint_count": len(spec_eps),
            "actual_route_count": len(actual_eps),
            "universe_count": len(universe),
            "spec_only": [f"{m} {p}" for m, p in spec_only],
            "unowned": [f"{m} {p}" for m, p in unowned],
        }
        return self._build_result(
            parsed=parsed,
            findings=findings,
            denominator=len(universe),
            scanned=len(scanned_eps),
            details=details,
            exclusions=payload.get("exclusions", ()),
        )


# ---------------------------------------------------------------------------
# OrgGuardScanner——org 过滤正例+负例
# ---------------------------------------------------------------------------

class OrgGuardScanner(_Station3Adapter):
    """每端点 org 过滤检查：正例（本 org 合法访问通）+ 负例（跨 org 越权拒）。

    payload 契约（adapt 的入参）::

        {
          "tool": {"name": …, "version": …}, "started_at"/"ended_at": ISO,
          "argv_digest"?: str, "timeout_s"?: int,
          "probe_identity": {"base_url": …, "positive_principal": …,
                             "negative_principal": …},        # 进 evidence 身份
          "endpoints": [
            {"method": "GET", "path": "/api/orders",
             "positive": {"executed": true, "outcome": "ALLOWED"},
             "negative": {"executed": true, "outcome": "DENIED", "status_code": 403}},
            …],
        }

    判定：
    - 正例 outcome 必须 ALLOWED（否则「正例未通」FAIL）；负例必须 DENIED
      （否则「负例放行=越权」FAIL——最严重面）。
    - 用例未执行或结果不可判定 → 不计入 scanned；端点整段缺失 → 分母缩水
      → BLOCKED。
    - denominator = 端点数×2（正例+负例）；端点全集 = openapi 端点 ∪ 实际
      探测端点（openapi_spec 经构造器/payload 注入时动态现算）。
    """

    slug = "org_guard"
    tag = "st3-orgguard"

    _CASE_OUTCOMES = frozenset(("ALLOWED", "DENIED"))

    def __init__(
        self,
        manifest: RunManifest,
        *,
        registry: Optional[StationRegistry] = None,
        now: Optional[Any] = None,
        openapi_spec: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(manifest, registry=registry, now=now)
        self._openapi_spec = openapi_spec

    def _norm_case(self, case: Any) -> Dict[str, Any]:
        """单用例 → {executed, outcome}；outcome 只认 ALLOWED/DENIED，其余=不可判定。"""
        if not isinstance(case, Mapping) or case.get("executed") is not True:
            return {"executed": False, "outcome": None}
        raw = str(case.get("outcome", "")).strip().upper()
        return {
            "executed": True,
            "outcome": raw if raw in self._CASE_OUTCOMES else None,
        }

    def adapt(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        parsed = self._extract_common(payload, what="org_guard payload")
        openapi_spec = (
            payload["openapi_spec"] if "openapi_spec" in payload
            else self._openapi_spec
        )
        expected_eps = (
            set(openapi_spec_endpoints(openapi_spec))
            if openapi_spec is not None else set()
        )

        endpoints_raw = payload.get("endpoints")
        if not isinstance(endpoints_raw, list) or not endpoints_raw:
            raise OrgGuardResultMalformed(
                "org_guard.endpoints must be a non-empty list of endpoint results"
            )
        probed: set = set()
        scanned = 0
        findings: List[str] = []
        inconclusive = 0
        per_endpoint: List[Dict[str, Any]] = []
        for i, ep in enumerate(endpoints_raw):
            if not isinstance(ep, Mapping):
                raise OrgGuardResultMalformed(
                    f"org_guard.endpoints[{i}] must be an object, "
                    f"got {type(ep).__name__}"
                )
            method = str(ep.get("method", "")).upper()
            path = str(ep.get("path", ""))
            if method not in _UPPER_METHODS or not path.strip():
                raise OrgGuardResultMalformed(
                    f"org_guard.endpoints[{i}] must carry a valid method and path"
                )
            key = (method, path)
            if key in probed:
                raise OrgGuardResultMalformed(
                    f"org_guard.endpoints has duplicate endpoint {method} {path}"
                )
            probed.add(key)
            positive = self._norm_case(ep.get("positive"))
            negative = self._norm_case(ep.get("negative"))

            # 已判定用例（ALLOWED/DENIED）计入 scanned——结论错误是策略 FAIL，
            # 不是覆盖缺口；只有未执行/不可判定的用例才是分母缩水面。
            if positive["outcome"] is not None:
                scanned += 1
                if positive["outcome"] == "DENIED":
                    findings.append(
                        _finding_id("st3_orgguard_positive_rejected", method, path)
                    )
            elif positive["executed"]:
                inconclusive += 1

            if negative["outcome"] is not None:
                scanned += 1
                if negative["outcome"] == "ALLOWED":
                    findings.append(
                        _finding_id("st3_orgguard_negative_allowed", method, path)
                    )
            elif negative["executed"]:
                inconclusive += 1

            per_endpoint.append(
                {"method": method, "path": path,
                 "positive": positive["outcome"], "negative": negative["outcome"]}
            )

        universe = expected_eps | probed
        denominator = 2 * len(universe)
        probe_identity = payload.get("probe_identity")
        details = {
            "kind": "station3/org-guard",
            "probe_identity_digest": (
                _hash_obj(dict(probe_identity))
                if isinstance(probe_identity, Mapping) else None
            ),
            "endpoint_universe_count": len(universe),
            "expected_from_openapi": len(expected_eps),
            "probed_count": len(probed),
            "unprobed_expected": sorted(
                f"{m} {p}" for m, p in (expected_eps - probed)
            ),
            "inconclusive_cases": inconclusive,
            "endpoints": per_endpoint,
        }
        return self._build_result(
            parsed=parsed,
            findings=findings,
            denominator=denominator,
            scanned=scanned,
            details=details,
            exclusions=payload.get("exclusions", ()),
        )


# ---------------------------------------------------------------------------
# PermissionMatrixScanner——权限矩阵三源仲裁
# ---------------------------------------------------------------------------

class PermissionMatrixScanner(_Station3Adapter):
    """权限矩阵三源仲裁（runtime > DB > static）。

    payload 契约（adapt 的入参）::

        {
          "tool": {"name": …, "version": …}, "started_at"/"ended_at": ISO,
          "argv_digest"?: str, "timeout_s"?: int,
          "sources": {                       # 至少一个；键只能是三源之一
            "runtime": {"cells": {"<cell>": "ALLOW"|"DENY"},
                        "probe_identity"?: {…}},
            "db":     {"cells": {…}, "connection_identity": "…",
                       "read_only": true},   # DB 源走只读纪律
            "static": {"cells": {…}, "source_path"?: "…"},
          },
          "expected_verdicts"?: {"<cell>": "ALLOW"|"DENY"},  # 契约期望（可选）
          "matrix_cell_count"?: int,          # 自报矩阵格数（只允许被动态分母超越）
        }

    判定：
    - 逐格取最高优先源的值为仲裁结果；源间取值不一致 → 冲突 finding（FAIL，
      三源不一致=矩阵不可信）；与 expected_verdicts 不符 → mismatch finding。
    - DB 源必须 connection_identity + read_only=true（可写身份直接拒绝）。
    - denominator = max(三源格并集, 自报格数)；scanned = 完成仲裁的格数。
    """

    slug = "permission_matrix"
    tag = "st3-perm"

    _CELL_VALUES = frozenset(("ALLOW", "DENY"))
    _KNOWN_SOURCES = frozenset(PERMISSION_SOURCE_PRECEDENCE)

    def _norm_cells(self, cells: Any, *, source: str) -> Dict[str, str]:
        if not isinstance(cells, Mapping):
            raise PermissionMatrixMalformed(
                f"sources.{source}.cells must be a mapping cell→ALLOW/DENY"
            )
        out: Dict[str, str] = {}
        for cell, value in cells.items():
            key = str(cell)
            if not key.strip():
                raise PermissionMatrixMalformed(
                    f"sources.{source}.cells has an empty cell key"
                )
            norm = str(value).strip().upper()
            if norm not in self._CELL_VALUES:
                raise PermissionMatrixMalformed(
                    f"sources.{source}.cells[{cell!r}] must be ALLOW or DENY, "
                    f"got {value!r}（探针必须把每格判成二元结论）"
                )
            out[key] = norm
        return out

    def adapt(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        parsed = self._extract_common(payload, what="permission_matrix payload")
        sources_raw = payload.get("sources")
        if not isinstance(sources_raw, Mapping) or not sources_raw:
            raise PermissionMatrixMalformed(
                "permission_matrix.sources must be a non-empty object with "
                "subset of {runtime, db, static}"
            )
        unknown = set(map(str, sources_raw)) - self._KNOWN_SOURCES
        if unknown:
            raise PermissionMatrixMalformed(
                f"unknown permission sources {sorted(unknown)}; "
                f"expected subset of {list(PERMISSION_SOURCE_PRECEDENCE)}"
            )

        cells_by_source: Dict[str, Dict[str, str]] = {}
        source_meta: Dict[str, Dict[str, Any]] = {}
        for name in PERMISSION_SOURCE_PRECEDENCE:
            if name not in sources_raw:
                continue
            src = sources_raw[name]
            if not isinstance(src, Mapping):
                raise PermissionMatrixMalformed(
                    f"sources.{name} must be an object, got {type(src).__name__}"
                )
            cells_by_source[name] = self._norm_cells(src.get("cells"), source=name)
            meta: Dict[str, Any] = {"cells": len(cells_by_source[name])}
            if name == "db":
                conn = _require_str(
                    src.get("connection_identity"),
                    what=f"sources.db.connection_identity",
                    exc=PermissionMatrixMalformed,
                )
                if _RE_CREDENTIALISH.search(conn):
                    raise PermissionMatrixMalformed(
                        "sources.db.connection_identity 疑似含凭据字段——"
                        "证据身份拒绝入库"
                    )
                if src.get("read_only") is not True:
                    raise NonReadOnlyDataSource(
                        "permission matrix 的 DB 源必须以只读身份读取"
                        "（read_only=true），可写身份一律拒绝"
                    )
                meta["connection_identity_digest"] = _hash_obj(
                    {"connection_identity": conn, "read_only": True}
                )
            if isinstance(src.get("probe_identity"), Mapping):
                meta["probe_identity_digest"] = _hash_obj(dict(src["probe_identity"]))
            source_meta[name] = meta

        if not any(cells_by_source.values()):
            raise PermissionMatrixMalformed(
                "permission_matrix.sources 所有源的 cells 均为空——无矩阵可仲裁"
            )

        universe = sorted(
            set().union(*[set(cells) for cells in cells_by_source.values()])
        )
        conflicts: List[Dict[str, Any]] = []
        mismatches: List[Dict[str, Any]] = []
        arbitrated: Dict[str, str] = {}
        findings: List[str] = []
        for cell in universe:
            values = {
                name: cells[cell]
                for name, cells in cells_by_source.items() if cell in cells
            }
            for name in PERMISSION_SOURCE_PRECEDENCE:
                if cell in cells_by_source.get(name, {}):
                    arbitrated[cell] = values[name]
                    break
            if len(set(values.values())) > 1:
                conflicts.append({"cell": cell, "values": values})
                findings.append(_finding_id("st3_perm_conflict", cell))

        expected_raw = payload.get("expected_verdicts")
        if expected_raw is not None:
            expected = self._norm_cells(expected_raw, source="expected_verdicts")
            for cell, want in expected.items():
                got = arbitrated.get(cell)
                if got is not None and got != want:
                    mismatches.append(
                        {"cell": cell, "arbitrated": got, "expected": want}
                    )
                    findings.append(_finding_id("st3_perm_mismatch", cell))

        declared = payload.get("matrix_cell_count")
        if declared is not None:
            declared = _require_int(
                declared, what="permission_matrix.matrix_cell_count"
            )
        denominator = max(len(universe), declared or 0)
        scanned = len(universe)

        details = {
            "kind": "station3/permission-matrix",
            "precedence": list(PERMISSION_SOURCE_PRECEDENCE),
            "sources": source_meta,
            "cell_universe": len(universe),
            "conflicts": conflicts,
            "expected_mismatches": mismatches,
            "deny_count": sum(1 for v in arbitrated.values() if v == "DENY"),
            "allow_count": sum(1 for v in arbitrated.values() if v == "ALLOW"),
        }
        return self._build_result(
            parsed=parsed,
            findings=findings,
            denominator=denominator,
            scanned=scanned,
            details=details,
            exclusions=payload.get("exclusions", ()),
        )


# ---------------------------------------------------------------------------
# DbDriftScanner——judge_drift.py schema 漂移（CLEAN=零变化；DROP=HIGH）
# ---------------------------------------------------------------------------

class DbDriftScanner(_Station3Adapter):
    """消费 judge_drift.py 报告（不自行 diff、不碰数据库）。

    payload 契约（adapt 的入参）::

        {
          "tool": {"name": "judge_drift.py", "version": …},
          "started_at"/"ended_at": ISO, "argv_digest"?: str, "timeout_s"?: int,
          "db_identity": {                       # 三要素进 evidence identity
            "connection_identity": "host=db-x;db=erp;user=ro_scan",
            "read_only": true,                   # 非 True 一律拒绝
            "diff_direction": "actual_vs_expected"},
          "data_config"?: {…},                   # 若给出，哈希须等于冻结
                                                 # manifest.data_config_hash
          "prisma_dmmf"?: {…},                   # 或构造器注入；模型数=分母下限
          "expected_objects"?: ["public.orders", …],   # 受监控对象全集
          "objects_total": 42, "objects_scanned": 42,
          "changes": [{"object": "public.orders", "change_type": "DROP",
                       "expected_hash"?: 64hex, "actual_hash"?: 64hex|None}, …],
          "allowlist": [{"object_identity": "public.orders",
                         "content_hash": 64hex, "expires_at": ISO,
                         "approver"?: …, "reason"?: …}, …],
        }

    判定（任务冻结语义）：
    - 零变化才 CLEAN；DROP=HIGH；未知变更类型=HIGH（fail-closed）。
    - 白名单三绑定（对象 identity + 内容 hash + 未过期）全中 → 该漂移受治理，
      不产生 finding；任一不中 → 漂移照常 FAIL。
    - denominator = max(objects_total, DMMF 模型数)——监控面小于 Prisma 模型数
      = 分母缩水 → BLOCKED；objects_scanned < denominator 同样 BLOCKED。
    """

    slug = "db_drift"
    tag = "st3-drift"

    def __init__(
        self,
        manifest: RunManifest,
        *,
        registry: Optional[StationRegistry] = None,
        now: Optional[Any] = None,
        prisma_dmmf: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(manifest, registry=registry, now=now)
        self._prisma_dmmf = prisma_dmmf

    # -- 载荷校验 -----------------------------------------------------------
    def _extract_db_identity(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        db_identity = payload.get("db_identity")
        if not isinstance(db_identity, Mapping):
            raise DriftReportMalformed(
                f"db_identity must be a mapping (connection_identity/read_only/"
                f"diff_direction), got {type(db_identity).__name__}"
            )
        conn = _require_str(
            db_identity.get("connection_identity"),
            what="db_identity.connection_identity",
            exc=DriftReportMalformed,
        )
        if _RE_CREDENTIALISH.search(conn):
            raise DriftReportMalformed(
                "db_identity.connection_identity 疑似含凭据字段——"
                "证据身份拒绝入库"
            )
        if db_identity.get("read_only") is not True:
            raise NonReadOnlyDataSource(
                "DB 漂移证据必须来自只读连接（read_only=true）；"
                "可写身份一律拒绝，绝不带写身份出 PASS"
            )
        direction = str(db_identity.get("diff_direction", ""))
        if direction not in DIFF_DIRECTIONS:
            raise DriftReportMalformed(
                f"db_identity.diff_direction must be one of {DIFF_DIRECTIONS}, "
                f"got {direction!r}"
            )
        return {"connection_identity": conn, "read_only": True,
                "diff_direction": direction}

    def _norm_change(self, raw: Any, *, index: int) -> Dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise DriftReportMalformed(
                f"changes[{index}] must be an object, got {type(raw).__name__}"
            )
        obj = _require_str(
            raw.get("object"), what=f"changes[{index}].object", exc=DriftReportMalformed
        )
        change_type = _require_str(
            raw.get("change_type"), what=f"changes[{index}].change_type",
            exc=DriftReportMalformed,
        ).upper()
        out: Dict[str, Any] = {"object": obj, "change_type": change_type}
        for hash_key in ("expected_hash", "actual_hash"):
            value = raw.get(hash_key)
            if value is None:
                continue
            if not isinstance(value, str) or not _RE_HEX64.match(value):
                raise DriftReportMalformed(
                    f"changes[{index}].{hash_key} must be 64-char lowercase hex, "
                    f"got {value!r}"
                )
            out[hash_key] = value
        return out

    @staticmethod
    def _change_binding_hash(change: Mapping[str, Any]) -> Optional[str]:
        """白名单绑定的内容 hash：优先 actual_hash；DROP 等取 expected_hash。"""
        return change.get("actual_hash") or change.get("expected_hash")

    # -- 适配 ---------------------------------------------------------------
    def adapt(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        parsed = self._extract_common(payload, what="db_drift payload")
        db_identity = self._extract_db_identity(payload)
        db_identity_digest = _hash_obj(db_identity)

        # data_config 绑定：载荷自带的数据配置必须与冻结 manifest 同哈希。
        data_config = payload.get("data_config")
        if data_config is not None:
            if not isinstance(data_config, Mapping):
                raise DriftReportMalformed("data_config must be a mapping")
            if _hash_obj(dict(data_config)) != self._manifest.data_config_hash:
                raise EvidenceIdentityMismatch(
                    "db_drift payload 的 data_config 哈希与冻结 manifest."
                    "data_config_hash 不一致——数据配置漂移，证据不得入库；"
                    "请重冻 run 或在冻结配置下重跑 judge_drift"
                )

        # 动态分母：DMMF 模型数为监控面下限（分母缩水守卫）。
        dmmf = payload["prisma_dmmf"] if "prisma_dmmf" in payload else self._prisma_dmmf
        model_floor = prisma_dmmf_model_count(dmmf) if dmmf is not None else 0

        expected_objects = payload.get("expected_objects")
        if expected_objects is not None:
            if not isinstance(expected_objects, list):
                raise DriftReportMalformed(
                    "expected_objects must be a list of object identities"
                )
            names = [
                _require_str(o, what="expected_objects[]", exc=DriftReportMalformed)
                for o in expected_objects
            ]
            if len(set(names)) != len(names):
                raise DriftReportMalformed(
                    "expected_objects contains duplicate identities"
                )

        objects_total = payload.get("objects_total")
        if objects_total is None and expected_objects is not None:
            objects_total = len(expected_objects)
        objects_total = _require_int(
            objects_total, what="db_drift.objects_total", minimum=1
        )
        if expected_objects is not None and len(expected_objects) != objects_total:
            raise DriftReportMalformed(
                f"expected_objects ({len(expected_objects)}) 与 objects_total "
                f"({objects_total}) 自相矛盾"
            )
        objects_scanned = _require_int(
            payload.get("objects_scanned", objects_total),
            what="db_drift.objects_scanned",
        )
        if objects_scanned > objects_total:
            raise DriftReportMalformed(
                f"objects_scanned ({objects_scanned}) > objects_total "
                f"({objects_total})——自相矛盾"
            )
        denominator = max(objects_total, model_floor)

        changes_raw = payload.get("changes", [])
        if not isinstance(changes_raw, list):
            raise DriftReportMalformed("changes must be a list")
        changes = [
            self._norm_change(raw, index=i) for i, raw in enumerate(changes_raw)
        ]

        allowlist_raw = payload.get("allowlist", [])
        if not isinstance(allowlist_raw, list):
            raise DriftReportMalformed("allowlist must be a list of entries")
        now = self._now or _utc_now()
        allowlist = [
            DriftAllowlist.from_mapping(entry) for entry in allowlist_raw
        ]
        for entry in allowlist:
            entry.validate_window(now)

        findings: List[str] = []
        drift_records: List[Dict[str, Any]] = []
        for change in changes:
            severity = DRIFT_CHANGE_SEVERITY.get(
                change["change_type"], UNKNOWN_CHANGE_SEVERITY
            )
            binding_hash = self._change_binding_hash(change)
            matched = next(
                (
                    entry for entry in allowlist
                    if entry.matches(
                        object_identity=change["object"],
                        binding_hash=binding_hash,
                    )
                    and entry.effective_through(now) is not None
                ),
                None,
            )
            record: Dict[str, Any] = {
                "object": change["object"],
                "change_type": change["change_type"],
                "severity": severity,
                "whitelisted": matched is not None,
                "binding_hash": binding_hash,
            }
            if matched is not None:
                # 受治理漂移：三绑定全中——details 留痕，不产生 finding。
                record["allowlist_expires_at"] = matched.expires_at
            else:
                findings.append(
                    _finding_id(
                        "st3_drift", change["object"], change["change_type"]
                    )
                )
            drift_records.append(record)

        if not changes:
            verdict = "CLEAN"                    # 零变化才 CLEAN
        elif len(findings) == 0:
            verdict = "WHITELISTED"              # 全部漂移都在白名单
        else:
            verdict = "DRIFT"

        details = {
            "kind": "station3/db-drift",
            "db_identity_digest": db_identity_digest,
            "connection_identity": db_identity["connection_identity"],
            "read_only": True,
            "diff_direction": db_identity["diff_direction"],
            "objects_total": objects_total,
            "objects_scanned": objects_scanned,
            "prisma_model_floor": model_floor or None,
            "verdict": verdict,
            "changes": drift_records,
            "allowlist": [entry.to_dict() for entry in allowlist],
        }
        return self._build_result(
            parsed=parsed,
            findings=findings,
            denominator=denominator,
            scanned=objects_scanned,
            details=details,
            exclusions=payload.get("exclusions", ()),
            tool_digest=db_identity_digest,
        )


# ---------------------------------------------------------------------------
# Station3Contract——站3 总适配（四件套工厂 + 聚合）
# ---------------------------------------------------------------------------

class Station3Contract:
    """站3「契约与数据」总适配：四个子适配器的工厂 + 聚合为单一 station-result-v2。

    用法::

        contract = Station3Contract(manifest)          # 冻结 run 的 manifest
        st_openapi = contract.openapi_reconciler(openapi_spec=spec) \\
                             .adapt(payload)
        final = contract.run(openapi=…, org_guard=…,
                             permission_matrix=…, db_drift=…)

    聚合规则（按栈选件——未提供的组件记入 coverage.exclusions，不折算失败；
    但至少要选一件，空选件无法验收）：
    - coverage：denominator/scanned 取各组件之和；缺席组件入 exclusions。
    - execution_status：任一 BLOCKED→BLOCKED，否则 ERROR>TIMEOUT>CANCELLED 选取。
    - policy_verdict：FAIL > NOT_EVALUATED > CONDITIONAL > NOT_APPLICABLE > PASS。
    - finding_ids / artifacts：各组件有序去重合并 + 聚合 details 工件。
    - 身份一律取自冻结 manifest；工具 digest=四组件结果 canonical 哈希。
    """

    STATION_ID = STATION_ID

    COMPONENTS: Tuple[str, ...] = (
        "openapi", "org_guard", "permission_matrix", "db_drift",
    )

    _STATUS_PRECEDENCE: Tuple[str, ...] = (
        "ERROR", "BLOCKED", "TIMEOUT", "CANCELLED",
    )
    _POLICY_PRECEDENCE: Tuple[str, ...] = (
        "FAIL", "NOT_EVALUATED", "CONDITIONAL", "NOT_APPLICABLE", "PASS",
    )
    _ASSERTION_PRECEDENCE: Tuple[str, ...] = ("FAIL", "ERROR", "PASS")

    def __init__(
        self,
        manifest: RunManifest,
        *,
        registry: Optional[StationRegistry] = None,
        now: Optional[Any] = None,
    ) -> None:
        if not isinstance(manifest, RunManifest):
            raise Station3Error(
                f"manifest must be RunManifest, got {type(manifest).__name__}"
            )
        registry = registry or default_registry()
        registry.get(STATION_ID)  # 站未注册 → KeyError（fail-closed）
        self._manifest = manifest
        self._registry = registry
        self._now = now
        #: run() 最近一次聚合所用的各组件 station-result（审计用）。
        self.last_component_results: Tuple[Dict[str, Any], ...] = ()

    # -- 基本信息 -----------------------------------------------------------
    @property
    def manifest(self) -> RunManifest:
        return self._manifest

    @property
    def ttl_days(self) -> int:
        return self._registry.ttl_for(STATION_ID)

    # -- 四件套工厂（共享 manifest/registry/now 身份正源） -------------------
    def openapi_reconciler(self, **kwargs: Any) -> OpenApiReconciler:
        return OpenApiReconciler(
            self._manifest, registry=self._registry, now=self._now, **kwargs
        )

    def org_guard_scanner(self, **kwargs: Any) -> OrgGuardScanner:
        return OrgGuardScanner(
            self._manifest, registry=self._registry, now=self._now, **kwargs
        )

    def permission_matrix_scanner(self, **kwargs: Any) -> PermissionMatrixScanner:
        return PermissionMatrixScanner(
            self._manifest, registry=self._registry, now=self._now, **kwargs
        )

    def db_drift_scanner(self, **kwargs: Any) -> DbDriftScanner:
        return DbDriftScanner(
            self._manifest, registry=self._registry, now=self._now, **kwargs
        )

    # -- 聚合 ---------------------------------------------------------------
    def run(
        self,
        *,
        openapi: Optional[Mapping[str, Any]] = None,
        org_guard: Optional[Mapping[str, Any]] = None,
        permission_matrix: Optional[Mapping[str, Any]] = None,
        db_drift: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """消费四份底层载荷 → 聚合为站3 单一 station-result-v2。

        任一组件载荷非法/身份绑定失败/时效过期 → 直接抛错（fail-closed，
        绝不静默跳过该组件——那等于分母缩水造假）。
        """
        payloads: Dict[str, Optional[Mapping[str, Any]]] = {
            "openapi": openapi,
            "org_guard": org_guard,
            "permission_matrix": permission_matrix,
            "db_drift": db_drift,
        }
        factories = {
            "openapi": self.openapi_reconciler,
            "org_guard": self.org_guard_scanner,
            "permission_matrix": self.permission_matrix_scanner,
            "db_drift": self.db_drift_scanner,
        }
        selected = [slug for slug in self.COMPONENTS if payloads[slug] is not None]
        if not selected:
            raise Station3Error(
                "站3 至少选一件（按栈选件——空选件无法验收契约与数据面）"
            )

        sub_results: List[Tuple[str, Dict[str, Any]]] = []
        for slug in selected:
            sub = factories[slug]().adapt(payloads[slug])
            validate_station_result(sub)
            sub_results.append((slug, sub))
        self.last_component_results = tuple(sub for _, sub in sub_results)

        denominator = sum(
            sub["coverage"]["denominator"] for _, sub in sub_results
        )
        scanned = sum(sub["coverage"]["scanned"] for _, sub in sub_results)
        exclusions = [
            f"component_not_selected:{slug}"
            for slug in self.COMPONENTS if payloads[slug] is None
        ]
        for _, sub in sub_results:
            exclusions.extend(sub["coverage"].get("exclusions", ()))

        statuses = [sub["execution_status"] for _, sub in sub_results]
        execution_status = "COMPLETED"
        for candidate in self._STATUS_PRECEDENCE:
            if candidate in statuses:
                execution_status = candidate
                break
        policies = [sub["policy_verdict"] for _, sub in sub_results]
        policy_verdict = "PASS"
        for candidate in self._POLICY_PRECEDENCE:
            if candidate in policies:
                policy_verdict = candidate
                break
        assertions = [sub["execution"]["assertion_verdict"] for _, sub in sub_results]
        assertion = "PASS"
        for candidate in self._ASSERTION_PRECEDENCE:
            if candidate in assertions:
                assertion = candidate
                break

        finding_ids: List[str] = []
        for _, sub in sub_results:
            for fid in sub.get("finding_ids", []):
                if fid not in finding_ids:
                    finding_ids.append(fid)

        artifacts: List[Dict[str, Any]] = []
        seen_digests: set = set()
        for _, sub in sub_results:
            for art in sub.get("artifacts", []):
                if art["cas_digest"] not in seen_digests:
                    seen_digests.add(art["cas_digest"])
                    artifacts.append(art)

        started = min(
            _parse_iso(sub["execution"]["started_at"], what="started_at")
            for _, sub in sub_results
        )
        ended = max(
            _parse_iso(sub["execution"]["ended_at"], what="ended_at")
            for _, sub in sub_results
        )
        exit_code = (
            _EXIT_BY_STATUS[execution_status]
            if execution_status != "COMPLETED"
            else (1 if policy_verdict == "FAIL" else 0)
        )

        component_summary = {
            slug: {
                "attempt_id": sub["attempt_id"],
                "execution_status": sub["execution_status"],
                "policy_verdict": sub["policy_verdict"],
                "coverage": sub["coverage"],
                "tool": sub["tool"]["name"],
            }
            for slug, sub in sub_results
        }
        details = {
            "kind": "station3/aggregate",
            "selected_components": selected,
            "excluded_components": [
                slug for slug in self.COMPONENTS if payloads[slug] is None
            ],
            "components": component_summary,
            "registry_criteria": {
                "pass": ["无未归属端点", "负例全拦+正例全通", "漂移全部在白名单"],
                "fail": ["存在未归属端点", "负例放行或正例未通", "漂移未白名单"],
            },
        }
        artifacts.append(_details_artifact(details))

        result = build_station_result(
            run_id=self._manifest.run_id,
            station_id=STATION_ID,
            attempt_id=_make_attempt_id(self._manifest.run_id, "st3"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=dict(sub_results[0][1]["identity"]),
            tool={
                "name": "wenqu_core.station3_contract",
                "version": __version__,
                "digest": _hash_obj([sub for _, sub in sub_results]),
            },
            execution={
                "argv_digest": _argv_digest(
                    ["wenqu_core.station3_contract", self._manifest.run_id]
                    + sorted(selected)
                ),
                "started_at": _iso_z(started),
                "ended_at": _iso_z(ended),
                "timeout_s": max(
                    sub["execution"].get("timeout_s", _DEFAULT_TIMEOUT_S)
                    for _, sub in sub_results
                ),
                "actual_exit_code": exit_code,
                "expected_exit_set": [0, 1],
                "assertion_verdict": assertion,
            },
            coverage={
                "denominator": denominator,
                "scanned": scanned,
                "exclusions": exclusions,
            },
            finding_ids=finding_ids,
            artifacts=artifacts,
        )
        validate_station_result(result)
        return result


# ---------------------------------------------------------------------------
# 端到端自证（python3 station3_contract.py）
# ---------------------------------------------------------------------------

def _self_test() -> int:
    from datetime import datetime, timezone

    registry = default_registry()
    planner = BugscanPlanner(registry)
    plan = planner.plan("STANDARD")
    assert 3 in plan.required_stations, "STANDARD 档必须含站3"

    data_config = {
        "db": {
            "connection_identity": "host=db-local;db=erp;user=ro_scan",
            "read_only": True,
            "diff_direction": "actual_vs_expected",
        }
    }
    now = _utc_now()
    manifest = planner.freeze_run_manifest(
        plan,
        run_id="selftest-st3-001",
        project_id="wenqu-selftest",
        commit_sha="3" * 40,
        environment="local",
        scope=["src/**", "tests/**"],
        ruleset={"version": "w6c", "rules": ["W6A-ST3"]},
        data_config=data_config,
        now=now,
    )
    contract = Station3Contract(manifest, registry=registry, now=now)
    ts = manifest.frozen_at
    print(f"[1] manifest frozen: run={manifest.run_id} ttl={contract.ttl_days}d "
          f"(permission_vulnerability 严档)")

    # ---- [2] OpenApiReconciler -------------------------------------------
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/orders": {"get": {"responses": {}}, "post": {"responses": {}}},
            "/api/users": {"get": {"responses": {}}},
        },
    }
    routes_full = [
        {"method": "GET", "path": "/api/orders"},
        {"method": "POST", "path": "/api/orders"},
        {"method": "GET", "path": "/api/users"},
    ]
    base = {"tool": {"name": "openapi-reconciler", "version": "1.0"},
            "started_at": ts, "ended_at": ts}

    st = contract.openapi_reconciler(openapi_spec=spec).adapt(
        {**base, "actual_routes": routes_full}
    )
    validate_station_result(st)
    assert st["policy_verdict"] == "PASS" and st["coverage"] == {
        "denominator": 3, "scanned": 3}
    print(f"[2] openapi reconcile PASS: coverage "
          f"{st['coverage']['scanned']}/{st['coverage']['denominator']}")

    st_bad = contract.openapi_reconciler(openapi_spec=spec).adapt({
        **base,
        "actual_routes": [
            {"method": "GET", "path": "/api/orders"},
            {"method": "GET", "path": "/api/users"},
            {"method": "GET", "path": "/api/healthz"},   # 未归属端点
        ],
    })
    assert st_bad["policy_verdict"] == "FAIL"
    assert any("unowned" in f for f in st_bad["finding_ids"])
    assert any("spec_only" in f for f in st_bad["finding_ids"])
    st_shrink = contract.openapi_reconciler(openapi_spec=spec).adapt({
        **base, "actual_routes": routes_full,
        "reconciled": [{"method": "GET", "path": "/api/orders"}],  # 只对账了 1 个
    })
    assert st_shrink["execution_status"] == "BLOCKED"
    assert st_shrink["policy_verdict"] != "PASS"
    print("[3] openapi negative paths OK: unowned+spec_only→FAIL / "
          "partial reconcile→BLOCKED")

    # ---- [3] OrgGuardScanner ---------------------------------------------
    def _og(eps):
        return {**base, "tool": {"name": "org-guard", "version": "1.0"},
                "probe_identity": {"base_url": "http://app.local",
                                   "positive_principal": "orgA/user",
                                   "negative_principal": "orgB/user"},
                "endpoints": eps}

    good_eps = [
        {"method": m, "path": p,
         "positive": {"executed": True, "outcome": "ALLOWED"},
         "negative": {"executed": True, "outcome": "DENIED"}}
        for m, p in sorted((m, p) for m, p in [
            ("GET", "/api/orders"), ("POST", "/api/orders"), ("GET", "/api/users")])
    ]
    st_og = contract.org_guard_scanner(openapi_spec=spec).adapt(_og(good_eps))
    validate_station_result(st_og)
    assert st_og["policy_verdict"] == "PASS"
    assert st_og["coverage"]["denominator"] == 6 and st_og["coverage"]["scanned"] == 6

    leaked = [{**good_eps[0], "negative": {"executed": True, "outcome": "ALLOWED"}},
              *good_eps[1:]]
    st_og_bad = contract.org_guard_scanner(openapi_spec=spec).adapt(_og(leaked))
    assert st_og_bad["policy_verdict"] == "FAIL"
    assert any("negative_allowed" in f for f in st_og_bad["finding_ids"])

    st_og_miss = contract.org_guard_scanner(openapi_spec=spec).adapt(
        _og(good_eps[:2])   # 漏探 /api/users → 分母缩水
    )
    assert st_og_miss["execution_status"] == "BLOCKED"
    print("[4] org-guard OK: 正例全通+负例全拦→PASS / 越权放行→FAIL / "
          "漏探端点→BLOCKED")

    # ---- [4] PermissionMatrixScanner -------------------------------------
    perm = {**base, "tool": {"name": "perm-matrix", "version": "1.0"},
            "sources": {
                "runtime": {"cells": {
                    "GET /api/orders|admin": "ALLOW",
                    "GET /api/orders|viewer": "DENY"},
                    "probe_identity": {"base_url": "http://app.local"}},
                "db": {"cells": {"GET /api/orders|admin": "DENY"},
                       "connection_identity": "host=db-local;user=ro_scan",
                       "read_only": True},
                "static": {"cells": {
                    "GET /api/orders|admin": "ALLOW",
                    "GET /api/orders|viewer": "DENY"}},
            },
            "expected_verdicts": {"GET /api/orders|admin": "ALLOW",
                                  "GET /api/orders|viewer": "DENY"}}
    st_pm = contract.permission_matrix_scanner().adapt(perm)
    validate_station_result(st_pm)
    assert st_pm["policy_verdict"] == "FAIL"      # runtime vs db 冲突
    assert any("conflict" in f for f in st_pm["finding_ids"])

    st_pm_ok = contract.permission_matrix_scanner().adapt({
        **perm, "sources": {
            "runtime": perm["sources"]["runtime"],
            "static": perm["sources"]["static"]}})
    assert st_pm_ok["policy_verdict"] == "PASS"
    assert st_pm_ok["coverage"] == {"denominator": 2, "scanned": 2}
    try:
        contract.permission_matrix_scanner().adapt({
            **perm, "sources": {"db": {**perm["sources"]["db"], "read_only": False}}})
        raise AssertionError("writable db source must raise")
    except NonReadOnlyDataSource:
        pass
    print("[5] perm-matrix OK: runtime>db>static 仲裁+冲突→FAIL / "
          "可写 DB 源拒绝")

    # ---- [5] DbDriftScanner ----------------------------------------------
    db_id = {"connection_identity": "host=db-local;db=erp;user=ro_scan",
             "read_only": True, "diff_direction": "actual_vs_expected"}
    drift_base = {**base, "tool": {"name": "judge_drift.py", "version": "1.1"},
                  "db_identity": db_id, "data_config": data_config,
                  "objects_total": 3, "objects_scanned": 3}
    drop = {"object": "public.orders", "change_type": "DROP",
            "expected_hash": "a" * 64}
    wl_entry = {"object_identity": "public.orders", "content_hash": "a" * 64,
                "expires_at": _iso_z(now + timedelta(days=7)),
                "approver": "dba-owner", "reason": "归档下线已审批"}

    st_clean = contract.db_drift_scanner().adapt({**drift_base, "changes": []})
    validate_station_result(st_clean)
    assert st_clean["policy_verdict"] == "PASS" and not st_clean["finding_ids"]

    st_drop = contract.db_drift_scanner().adapt({**drift_base, "changes": [drop]})
    assert st_drop["policy_verdict"] == "FAIL"   # DROP=HIGH，未白名单

    st_wl = contract.db_drift_scanner().adapt(
        {**drift_base, "changes": [drop], "allowlist": [wl_entry]})
    assert st_wl["policy_verdict"] == "PASS"     # 三绑定全中 → 受治理漂移
    assert not st_wl["finding_ids"]

    expired = {**wl_entry, "expires_at": _iso_z(now - timedelta(days=1))}
    st_wl_exp = contract.db_drift_scanner().adapt(
        {**drift_base, "changes": [drop], "allowlist": [expired]})
    assert st_wl_exp["policy_verdict"] == "FAIL"  # 过期白名单=无效

    try:
        contract.db_drift_scanner().adapt(
            {**drift_base, "db_identity": {**db_id, "read_only": False}})
        raise AssertionError("writable identity must raise")
    except NonReadOnlyDataSource:
        pass
    try:
        contract.db_drift_scanner().adapt(
            {**drift_base, "data_config": {"db": {"connection_identity": "other"}}})
        raise AssertionError("data_config mismatch must raise")
    except EvidenceIdentityMismatch:
        pass
    dmmf = {"datamodel": {"models": [{"name": m} for m in
                                      ("Order", "User", "Invoice", "Tenant", "Audit")]}}
    st_floor = contract.db_drift_scanner(prisma_dmmf=dmmf).adapt(
        {**drift_base, "changes": []})
    assert st_floor["execution_status"] == "BLOCKED"   # 监控面 3 < 模型数 5
    try:
        contract.db_drift_scanner().adapt(
            {**drift_base, "db_identity": {**db_id, "diff_direction": "reversed"}})
        raise AssertionError("unknown diff direction must raise")
    except DriftReportMalformed:
        pass
    try:
        contract.db_drift_scanner().adapt(
            {**drift_base, "changes": [], "allowlist": [
                {**wl_entry, "expires_at": _iso_z(now + timedelta(days=90))}]})
        raise AssertionError("allowlist beyond 30d sunset must raise")
    except AllowlistEntryInvalid:
        pass
    print("[6] db-drift OK: 零变化=CLEAN / DROP未白名单=FAIL(HIGH) / "
          "三绑定白名单=PASS / 过期=FAIL / 只读+data_config+DMMF 分母守卫全负例拦截")

    # ---- [6] Station3Contract.run 聚合 ------------------------------------
    final = contract.run(
        openapi={**base, "openapi_spec": spec, "actual_routes": routes_full},
        org_guard=_og(good_eps),
        permission_matrix={**perm, "sources": {
            "runtime": perm["sources"]["runtime"],
            "static": perm["sources"]["static"]}},
        db_drift={**drift_base, "changes": []},
    )
    validate_station_result(final)
    assert final["policy_verdict"] == "PASS" and final["execution_status"] == "COMPLETED"
    assert final["coverage"]["denominator"] == 3 + 6 + 2 + 3
    assert final["coverage"]["scanned"] == 3 + 6 + 2 + 3
    assert len(contract.last_component_results) == 4

    final_bad = contract.run(
        openapi={**base, "openapi_spec": spec, "actual_routes": [
            {"method": "GET", "path": "/api/healthz"}]},
        db_drift={**drift_base, "changes": [drop]},
    )
    assert final_bad["policy_verdict"] == "FAIL"
    assert len(final_bad["coverage"]["exclusions"]) == 2   # 按栈选件缺席记账
    try:
        contract.run()
        raise AssertionError("empty selection must raise")
    except Station3Error:
        pass
    print(f"[7] aggregate OK: 全绿→PASS (coverage "
          f"{final['coverage']['scanned']}/{final['coverage']['denominator']}); "
          f"混入坏件→FAIL; 空选件拒绝")
    print("SELF-TEST PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

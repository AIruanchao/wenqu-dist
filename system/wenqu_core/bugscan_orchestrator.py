"""bugscan_orchestrator.py——Codex 方案 W6A：Bug 八站 Planner/Registry/站0-站1 适配。

血统与契约正源：
- Codex 方案 W6A §7.1（八站 Planner/Registry）与 §15.2（站0 冻结/站1 源闸适配）。
- 《问渠轨道规范（发行版 v2.0）》§0 铁律、§1 八站骨架（站序=成本×确定性递增）。
- wenqu-vNext-contract.md §7 统一退出码、§8 不可变安全不变量。
- 每站输出严格遵循 schemas/station-result-v2.schema.json（本文件内置结构校验器，
  jsonschema 可用时叠加真实 schema 复核——双保险，但绝不依赖第三方包）。

职责边界（编排层不造扫描工具）：
- StationRegistry：版本化八站注册表——每站含入口/覆盖分母/工具插槽/规则/
  PASS-FAIL-ERROR 判据/证据 TTL（铁律 4：权限/漏洞类 ≤7 天、其余 ≤30 天）。
- BugscanPlanner：按风险定级生成 required 站集合（W6A 档位映射：
  FAST=0+1 / STANDARD=0+1+2+3+4 / INCIDENT=0+1+2+3+4+6+7）。
  风险只允许自动升档（铁律 1：涉权限/资金/租户/迁移/公共基础层自动拉档）；
  降档必须携带风险接受记录（负责人/理由/范围/到期，30 天日落），
  且站 0（范围冻结）与站 1（源闸）任何情况下不可省略。
- freeze_run_manifest()：站0 冻结 run-manifest.json——项目身份/commit SHA/
  scope/ruleset/data config/required 站集合全部哈希绑定；冻结后不可变
  （同内容幂等、异内容拒绝覆写）。
- SourceGateAdapter：站1 源闸适配——只消费 SourceGate 在 exact-SHA 上的
  既有结果并按 §7 退出码契约机械映射，不自行判定、不重跑；SHA 不匹配/
  证据过期/载荷畸形一律 fail-closed 抛错，绝不折算为 PASS（不变量：审批与
  证据不得跨 SHA 复用）。

安全构造（by construction）：
- 纯 stdlib；无 shell 拼接、无 eval/exec；所有哈希走 canonical JSON。
- 所有产出 dict 严格按 schema 白名单键构造，additionalProperties:false 对齐。
- 分母缩水守卫：coverage.scanned < denominator 时该站不得记 PASS，
  执行状态强制 BLOCKED（schema $comment 与铁律 2）。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "SCHEMA_VERSION",
    "REGISTRY_VERSION",
    "LANES",
    "LANE_REQUIRED_STATIONS",
    "LANE_CONVERGENCE_ROUNDS",
    "SCOPE_FLAG_ESCALATION",
    "EVIDENCE_TTL_CAP_DAYS",
    "SOURCE_GATE_EXIT_CODE_MAPPING",
    "StationSpec",
    "StationCriteria",
    "StationRegistry",
    "RiskAcceptance",
    "BugscanPlan",
    "BugscanPlanner",
    "RunManifest",
    "SourceGateAdapter",
    "build_station_result",
    "validate_station_result",
    "freeze_run_manifest",
    "default_registry",
    "BugscanPlanError",
    "RiskDowngradeError",
    "ManifestFreezeError",
    "SourceGateError",
    "SourceGateShaMismatch",
    "EvidenceStaleError",
    "GateResultMalformed",
    "StationResultValidationError",
]

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# 契约常量
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "2.0"

#: 注册表版本——站定义/判据/TTL 任何变更必须递增并同步 schemas/ 与规范文档。
REGISTRY_VERSION = "w6a-1.0.0"

LANE_FAST = "FAST"
LANE_STANDARD = "STANDARD"
LANE_INCIDENT = "INCIDENT"
LANES: Tuple[str, ...] = (LANE_FAST, LANE_STANDARD, LANE_INCIDENT)
_LANE_ORDER = {LANE_FAST: 0, LANE_STANDARD: 1, LANE_INCIDENT: 2}

#: W6A 档位×站点矩阵（§7.1 冻结；对应规范 §1 的 PR 档/周档+行为面/事件档收敛）。
#: 站5（实弹面）不在任何自动档——生产写须所有者明确口令（一次性 exact-scope 授权）。
LANE_REQUIRED_STATIONS: Dict[str, Tuple[int, ...]] = {
    LANE_FAST: (0, 1),
    LANE_STANDARD: (0, 1, 2, 3, 4),
    LANE_INCIDENT: (0, 1, 2, 3, 4, 6, 7),
}

#: 收敛环轮数（规范 §0 铁律 5：FAST=1 / STANDARD=2 / INCIDENT=3 异源轮）。
LANE_CONVERGENCE_ROUNDS: Dict[str, int] = {
    LANE_FAST: 1,
    LANE_STANDARD: 2,
    LANE_INCIDENT: 3,
}

#: 自动升档触发器（规范 §0 铁律 1——只升不降）。
#: 值为该标志触发的最低档位。
SCOPE_FLAG_ESCALATION: Dict[str, str] = {
    "touches_public_infra": LANE_STANDARD,   # 公共基础层 → 至少 STANDARD
    "touches_migration": LANE_STANDARD,      # 迁移 → 至少 STANDARD
    "touches_tenant": LANE_STANDARD,         # 租户 → 至少 STANDARD
    "touches_permissions": LANE_INCIDENT,    # 权限类 → INCIDENT
    "touches_funds": LANE_INCIDENT,          # 资金类 → INCIDENT
}

#: 证据时效双上限（规范 §0 铁律 4：权限/漏洞类 ≤7 天、其余 ≤30 天）。
EVIDENCE_TTL_CAP_DAYS: Dict[str, int] = {
    "permission_vulnerability": 7,
    "general": 30,
}

#: 站1 源闸退出码映射（wenqu-vNext-contract §7 统一退出码→双轴）。
SOURCE_GATE_EXIT_CODE_MAPPING: Dict[int, Tuple[str, str]] = {
    0: ("COMPLETED", "PASS"),
    1: ("COMPLETED", "FAIL"),
    2: ("ERROR", "NOT_EVALUATED"),
    3: ("BLOCKED", "NOT_EVALUATED"),
    4: ("COMPLETED", "CONDITIONAL"),
    124: ("TIMEOUT", "NOT_EVALUATED"),
}

#: 降档不可移除的底线站（规范 §1：站 0 与收敛环不可省；PR 档最小集=0+1）。
DOWNGRADE_FLOOR_STATIONS: FrozenSet[int] = frozenset({0, 1})

#: 风险接受记录日落窗口（规范 §6 豁免纪律：30 天日落失效）。
RISK_ACCEPTANCE_MAX_DAYS = 30

#: run-event-v2 identity.environment 枚举（manifest 采用其严格子集）。
ENVIRONMENTS: Tuple[str, ...] = ("local", "staging", "production")

_RE_RUN_ID = re.compile(r"^[a-zA-Z0-9_-]+$")
_RE_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_RE_SHA64 = re.compile(r"^[0-9a-f]{64}$")
_RE_CAS_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RE_FND = re.compile(r"^fnd_[a-zA-Z0-9_]+$")

_STATION_RESULT_TOP_KEYS = frozenset({
    "schema_version", "run_id", "station_id", "attempt_id",
    "execution_status", "policy_verdict", "identity", "tool",
    "execution", "coverage", "finding_ids", "artifacts",
})
_IDENTITY_KEYS = frozenset({
    "project_id", "commit_sha", "environment", "scope_hash",
    "ruleset_hash", "data_config_hash", "lockfile_hash",
})
_EXECUTION_KEYS = frozenset({
    "argv_digest", "cwd_digest", "started_at", "ended_at",
    "timeout_s", "actual_exit_code", "expected_exit_set", "assertion_verdict",
})
_COVERAGE_KEYS = frozenset({"denominator", "scanned", "exclusions"})


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------

class BugscanPlanError(ValueError):
    """定级/计划非法：未知档位、未知范围标志、底线站被移除等。"""


class RiskDowngradeError(BugscanPlanError):
    """降档缺少合法风险接受记录，或记录不满足五要素/日落约束。"""


class ManifestFreezeError(ValueError):
    """站0 冻结失败：身份字段非法、哈希不匹配、冻结件被异内容覆写等。"""


class SourceGateError(ValueError):
    """站1 源闸适配基类——一律 fail-closed，绝不折算为 PASS。"""


class SourceGateShaMismatch(SourceGateError):
    """源闸结果不属于冻结 manifest 的 exact-SHA（证据不得跨 SHA 复用）。"""


class EvidenceStaleError(SourceGateError):
    """源闸证据超出站 TTL（权限/漏洞类 ≤7 天、其余 ≤30 天）。"""


class GateResultMalformed(SourceGateError):
    """源闸载荷畸形：缺字段、类型错、退出码不在 §7 契约内。"""


class StationResultValidationError(ValueError):
    """station-result-v2 结构/不变量校验失败（聚合全部问题一次性抛出）。"""


# ---------------------------------------------------------------------------
# 基础工具：canonical JSON + 哈希 + 时间
# ---------------------------------------------------------------------------

def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_obj(obj: Any) -> str:
    return _sha256_hex(_canonical_json(obj).encode("utf-8"))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(value: str, *, what: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} must be a non-empty ISO-8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{what} is not valid ISO-8601: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _require_sha40(value: str, *, what: str) -> str:
    if not isinstance(value, str) or not _RE_SHA40.match(value):
        raise ValueError(f"{what} must be a 40-char lowercase hex commit SHA, got {value!r}")
    return value


def _hash_or_digest(value: Any, *, what: str, required: bool = True) -> Optional[str]:
    """dict → canonical 哈希；64-hex 字符串 → 原样；None 且非必需 → None。"""
    if value is None:
        if required:
            raise ValueError(f"{what} is required (dict or 64-hex digest)")
        return None
    if isinstance(value, Mapping):
        return _hash_obj(dict(value))
    if isinstance(value, str) and _RE_SHA64.match(value):
        return value
    raise ValueError(f"{what} must be a mapping or 64-hex digest, got {type(value).__name__}")


# ---------------------------------------------------------------------------
# StationRegistry——版本化八站注册表（Codex W6A §7.1）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StationCriteria:
    """PASS / FAIL / ERROR 三态判据（铁律 2：BLOCKED/ERROR 时整站不得记 PASS）。"""

    pass_: Tuple[str, ...]
    fail: Tuple[str, ...]
    error: Tuple[str, ...]

    def to_dict(self) -> Dict[str, List[str]]:
        return {
            "pass": list(self.pass_),
            "fail": list(self.fail),
            "error": list(self.error),
        }


@dataclass(frozen=True)
class StationSpec:
    """单站定义：入口/覆盖分母/工具插槽/规则/判据/TTL。"""

    station_id: int
    name: str                 # 中文名（规范 §1 表）
    slug: str                 # 英文标识
    entry: str                # 入口（执行件插槽的调用方式）
    coverage_denominator: str # 覆盖分母语义（分母缩水守卫的计量对象）
    tools: Tuple[str, ...]    # 工具插槽（按仓配置，注册表给默认件）
    rules: Tuple[str, ...]    # 规则引用（判据的规则正源编号）
    criteria: StationCriteria
    evidence_class: str       # "permission_vulnerability" | "general"（铁律 4 双上限）
    ttl_days: int             # 证据时效上限（天），≤ EVIDENCE_TTL_CAP_DAYS[evidence_class]
    notes: Tuple[str, ...] = field(default=())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "station_id": self.station_id,
            "name": self.name,
            "slug": self.slug,
            "entry": self.entry,
            "coverage_denominator": self.coverage_denominator,
            "tools": list(self.tools),
            "rules": list(self.rules),
            "criteria": self.criteria.to_dict(),
            "evidence_class": self.evidence_class,
            "ttl_days": self.ttl_days,
            "notes": list(self.notes),
        }


#: 默认八站定义——逐字收敛《问渠轨道规范 v2.0》§1 骨架表。
_DEFAULT_STATIONS: Tuple[StationSpec, ...] = (
    StationSpec(
        station_id=0,
        name="范围冻结",
        slug="scope_freeze",
        entry="freeze_run_manifest()（对齐 `wenqu init` 的 sha256 范围哈希语义；"
              "commit SHA/环境/定级理由由 manifest 落账）",
        coverage_denominator="scope 冻结清单内路径数（denominator=len(paths)）",
        tools=("wenqu_core.bugscan_orchestrator.freeze_run_manifest",),
        rules=("W6A-ST0", "规范§1-站0"),
        criteria=StationCriteria(
            pass_=("范围分母齐全", "身份三源一致（commit SHA/环境/范围哈希）"),
            fail=("范围分母缺失", "身份三源不一致"),
            error=("指纹计算失败（git 不可用/哈希异常）"),
        ),
        evidence_class="general",
        ttl_days=30,
    ),
    StationSpec(
        station_id=1,
        name="源闸",
        slug="source_gate",
        entry="SourceGateAdapter（消费仓 CI 快速门的 exact-SHA 结果，不自行判定）",
        coverage_denominator="CI 快速门组件数（lint/typecheck/unit/守卫棘轮等）",
        tools=("ci-fast.yml", "iron-gate.sh"),
        rules=("W6A-ST1", "规范§1-站1", "退出码契约=wenqu-vNext-contract§7"),
        criteria=StationCriteria(
            pass_=("全绿", "棘轮不升"),
            fail=("任一门红", "棘轮回退或异常升级"),
            error=("工具缺失/超时/环境错（exit 2/3/124）"),
        ),
        evidence_class="general",
        ttl_days=30,
    ),
    StationSpec(
        station_id=2,
        name="静态与供应链",
        slug="static_supply",
        entry="`wenqu run <station>`（内置 py-static/sh-static/tests/supply + 域探测器）",
        coverage_denominator="scope 内可扫文件数（按语言分母）",
        tools=("wenqu run py-static", "wenqu run sh-static", "wenqu run tests",
               "wenqu run supply", "stations.json 域探测器", "克隆检测", "CVE 审计"),
        rules=("W6A-ST2", "规范§1-站2", "探测器 rc 契约：exit1=命中落账/exit≥2=环境错"),
        criteria=StationCriteria(
            pass_=("克隆≤基线", "CVE 零 HIGH+", "探测器零 FAIL"),
            fail=("任一探测器命中（自动落账 OPEN）", "CVE HIGH+", "克隆超基线"),
            error=("探测器 exit≥2 环境错（不落账不计通过）"),
        ),
        evidence_class="permission_vulnerability",
        ttl_days=7,
    ),
    StationSpec(
        station_id=3,
        name="契约与数据",
        slug="contract_data",
        entry="按栈选件：API 契约对账 / 权限矩阵 / schema 漂移",
        coverage_denominator="对外端点×用例矩阵（正例+负例）数",
        tools=("API 契约对账", "权限矩阵", "schema 漂移检测"),
        rules=("W6A-ST3", "规范§1-站3"),
        criteria=StationCriteria(
            pass_=("无未归属端点", "负例全拦+正例全通", "漂移全部在白名单"),
            fail=("存在未归属端点", "负例放行或正例未通", "漂移未白名单"),
            error=("对账件不可用/依赖服务未起"),
        ),
        evidence_class="permission_vulnerability",
        ttl_days=7,
    ),
    StationSpec(
        station_id=4,
        name="行为面",
        slug="behavior",
        entry="e2e 套件 + 浏览器抽检",
        coverage_denominator="e2e 测试点数",
        tools=("e2e 套件", "浏览器抽检"),
        rules=("W6A-ST4", "规范§1-站4"),
        criteria=StationCriteria(
            pass_=("套件全绿", "每测试点有已看证据"),
            fail=("任一 e2e 红", "证据缺失"),
            error=("环境起不来/驱动缺失"),
        ),
        evidence_class="general",
        ttl_days=30,
    ),
    StationSpec(
        station_id=5,
        name="实弹面",
        slug="live_fire",
        entry="真实业务流全链操作（生产写须所有者明确口令——一次性 exact-scope 授权）",
        coverage_denominator="业务流断言点数",
        tools=("真实业务流全链操作",),
        rules=("W6A-ST5", "规范§1-站5", "停等类型=prod-write/fund-auth"),
        criteria=StationCriteria(
            pass_=("状态断言全 PASS", "数据回基线"),
            fail=("状态断言失败", "数据未回基线"),
            error=("生产写授权缺失（BLOCKED，不算通过）"),
        ),
        evidence_class="general",
        ttl_days=30,
        notes=("不在任何自动档 required 集内——必须显式授权后加入",),
    ),
    StationSpec(
        station_id=6,
        name="对抗面",
        slug="adversarial",
        entry="`wenqu charter` 发射反方评审（异构端点优先）+ `wenqu ingest` 回收产物",
        coverage_denominator="对抗轴问题数（每轴必问）",
        tools=("wenqu charter", "wenqu ingest"),
        rules=("W6A-ST6", "规范§1-站6", "二审定律：零发现结论须 ≥2 独立上下文"),
        criteria=StationCriteria(
            pass_=("每轴必问全覆盖", "零发现结论出自 ≥2 独立上下文"),
            fail=("轴覆盖缺失", "单上下文零发现声明"),
            error=("异源端点宕机（降级须登记豁免，恢复后补一次异源审）"),
        ),
        evidence_class="permission_vulnerability",
        ttl_days=7,
        notes=("上游 charter 模板内嵌 wsl.exe 探测命令——跨平台使用须改本机等价只读探测",),
    ),
    StationSpec(
        station_id=7,
        name="运行时",
        slug="runtime",
        entry="常驻哨兵/探针/告警链（不参与收敛声明，事件回流站6）",
        coverage_denominator="哨兵×探针检查项数",
        tools=("常驻哨兵", "探针", "告警链"),
        rules=("W6A-ST7", "规范§1-站7"),
        criteria=StationCriteria(
            pass_=("哨兵活着", "真的会叫（告警链实测）"),
            fail=("哨兵死", "告警链断"),
            error=("探针不可用"),
        ),
        evidence_class="general",
        ttl_days=30,
        notes=("INCIDENT 档 required；不参与收敛声明",),
    ),
)


class StationRegistry:
    """版本化八站注册表：站 0-7 全集定义 + 一致性自检。

    任何站定义变更（判据/TTL/工具插槽）都必须：递增 REGISTRY_VERSION、
    同步 schemas/station-result-v2.schema.json 与规范文档、并重新冻结
    已在跑的 run manifest（指纹变化即失效重跑——铁律 4）。
    """

    def __init__(self, stations: Iterable[StationSpec] = _DEFAULT_STATIONS) -> None:
        specs = tuple(stations)
        by_id: Dict[int, StationSpec] = {}
        for spec in specs:
            if not isinstance(spec.station_id, int) or not 0 <= spec.station_id <= 7:
                raise ValueError(f"station_id must be int in [0,7], got {spec.station_id!r}")
            if spec.station_id in by_id:
                raise ValueError(f"duplicate station_id: {spec.station_id}")
            by_id[spec.station_id] = spec
        if sorted(by_id) != list(range(8)):
            raise ValueError(
                f"registry must define exactly stations 0..7, got {sorted(by_id)}"
            )
        self._stations = by_id
        self.validate()

    # -- 查询 ---------------------------------------------------------------
    def get(self, station_id: int) -> StationSpec:
        try:
            return self._stations[station_id]
        except KeyError:
            raise KeyError(f"unknown station_id: {station_id}") from None

    def all(self) -> Tuple[StationSpec, ...]:
        return tuple(self._stations[i] for i in range(8))

    def required_for(self, lane: str) -> Tuple[int, ...]:
        if lane not in LANE_REQUIRED_STATIONS:
            raise BugscanPlanError(f"unknown lane {lane!r}; expected one of {LANES}")
        return LANE_REQUIRED_STATIONS[lane]

    def ttl_for(self, station_id: int) -> int:
        return self.get(station_id).ttl_days

    def snapshot(self) -> Dict[str, Any]:
        """注册表快照（嵌入 manifest 存档，保证判定可复现）。"""
        return {
            "registry_version": REGISTRY_VERSION,
            "stations": {i: self._stations[i].to_dict() for i in range(8)},
        }

    def registry_digest(self) -> str:
        return _hash_obj(self.snapshot())

    # -- 自检 ---------------------------------------------------------------
    def validate(self) -> None:
        """一致性自检：TTL 双上限、判据三态齐全、工具/规则非空。"""
        for spec in self.all():
            cap = EVIDENCE_TTL_CAP_DAYS.get(spec.evidence_class)
            if cap is None:
                raise ValueError(
                    f"station {spec.station_id}: unknown evidence_class "
                    f"{spec.evidence_class!r} (expected one of "
                    f"{sorted(EVIDENCE_TTL_CAP_DAYS)})"
                )
            if not 1 <= spec.ttl_days <= cap:
                raise ValueError(
                    f"station {spec.station_id} ({spec.slug}): ttl_days="
                    f"{spec.ttl_days} violates 铁律4 cap {cap}d for "
                    f"{spec.evidence_class}"
                )
            if not (spec.criteria.pass_ and spec.criteria.fail and spec.criteria.error):
                raise ValueError(
                    f"station {spec.station_id} ({spec.slug}): PASS/FAIL/ERROR "
                    "criteria must all be non-empty"
                )
            if not spec.tools or not spec.rules:
                raise ValueError(
                    f"station {spec.station_id} ({spec.slug}): tools and rules "
                    "must be non-empty"
                )


_DEFAULT_REGISTRY: Optional[StationRegistry] = None


def default_registry() -> StationRegistry:
    """进程级默认注册表（惰性单例；定义不可变，可安全共享）。"""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = StationRegistry()
    return _DEFAULT_REGISTRY


# ---------------------------------------------------------------------------
# 风险接受记录（降档唯一合法通道）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RiskAcceptance:
    """降档风险接受记录——五要素对齐 finding-event-v2 risk_acceptance。

    approver（风险负责人）/ reason（理由，≥10 字）/ scope（影响范围）/
    expiry（到期日，≤30 天日落）。缺任一要素或已过期 = 降档非法。
    """

    approver: str
    reason: str
    scope: str
    expiry: str  # ISO-8601 date-time
    compensating_controls: Tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RiskAcceptance":
        if not isinstance(data, Mapping):
            raise RiskDowngradeError(
                f"risk acceptance must be a mapping, got {type(data).__name__}"
            )
        missing = [k for k in ("approver", "reason", "scope", "expiry") if not data.get(k)]
        if missing:
            raise RiskDowngradeError(
                f"risk acceptance missing required fields: {missing} "
                "(负责人/理由/范围/到期 缺一不可)"
            )
        return cls(
            approver=str(data["approver"]),
            reason=str(data["reason"]),
            scope=str(data["scope"]),
            expiry=str(data["expiry"]),
            compensating_controls=tuple(str(c) for c in data.get("compensating_controls", ())),
        )

    def validate(self, now: Optional[datetime] = None) -> datetime:
        """校验五要素 + 日落约束；返回到期时刻。"""
        now = now or _utc_now()
        if not self.approver.strip():
            raise RiskDowngradeError("risk acceptance approver (风险负责人) is empty")
        if len(self.reason.strip()) < 10:
            raise RiskDowngradeError(
                f"risk acceptance reason too short ({len(self.reason.strip())} chars; "
                "须 ≥10 字，对齐 finding-event-v2 minLength)"
            )
        if not self.scope.strip():
            raise RiskDowngradeError("risk acceptance scope (影响范围) is empty")
        expiry = _parse_iso(self.expiry, what="risk acceptance expiry")
        if expiry <= now:
            raise RiskDowngradeError(
                f"risk acceptance expired at {self.expiry} (30 天日落——过期降档非法)"
            )
        if expiry > now + timedelta(days=RISK_ACCEPTANCE_MAX_DAYS):
            raise RiskDowngradeError(
                f"risk acceptance expiry {self.expiry} exceeds "
                f"{RISK_ACCEPTANCE_MAX_DAYS}d sunset window"
            )
        return expiry

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "approver": self.approver,
            "reason": self.reason,
            "scope": self.scope,
            "expiry": self.expiry,
        }
        if self.compensating_controls:
            out["compensating_controls"] = list(self.compensating_controls)
        return out


# ---------------------------------------------------------------------------
# BugscanPlanner——风险定级 → required 站集合
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BugscanPlan:
    """一次 bugscan 的冻结计划（manifest 的 planning 段正源）。"""

    lane_requested: str
    lane_effective: str
    required_stations: Tuple[int, ...]
    convergence_rounds: int
    escalated: bool
    escalation_reasons: Tuple[str, ...]
    downgrade: Optional[RiskAcceptance]
    dropped_stations: Tuple[int, ...]
    registry_version: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lane_requested": self.lane_requested,
            "lane_effective": self.lane_effective,
            "required_stations": list(self.required_stations),
            "convergence_rounds": self.convergence_rounds,
            "escalated": self.escalated,
            "escalation_reasons": list(self.escalation_reasons),
            "downgrade": self.downgrade.to_dict() if self.downgrade else None,
            "dropped_stations": list(self.dropped_stations),
            "registry_version": self.registry_version,
        }


class BugscanPlanner:
    """根据风险定级生成 required 站集合（Codex W6A §7.1）。

    升档：自动、只增不减——任何 SCOPE_FLAG_ESCALATION 命中即把档位拉到
    该标志的最低档（铁律 1）。

    降档：永不自动。必须显式给出 RiskAcceptance（负责人/理由/范围/到期，
    30 天日落）且被移除站不得触碰底线 {0,1}；计划内嵌该记录以供审计。
    """

    def __init__(self, registry: Optional[StationRegistry] = None) -> None:
        self._registry = registry or default_registry()

    @property
    def registry(self) -> StationRegistry:
        return self._registry

    # -- 定级 ---------------------------------------------------------------
    @staticmethod
    def resolve_lane(
        lane: str,
        scope_flags: Iterable[str] = (),
    ) -> Tuple[str, bool, Tuple[str, ...]]:
        """请求档 + 范围标志 → 生效档（只升不降）。"""
        if lane not in _LANE_ORDER:
            raise BugscanPlanError(f"unknown lane {lane!r}; expected one of {LANES}")
        flags = tuple(scope_flags or ())
        unknown = [f for f in flags if f not in SCOPE_FLAG_ESCALATION]
        if unknown:
            # fail-closed：未知范围标志意味着定级模型失配，禁止猜测。
            raise BugscanPlanError(
                f"unknown scope flags {unknown}; known: {sorted(SCOPE_FLAG_ESCALATION)}"
            )
        effective = lane
        reasons: List[str] = []
        for flag in flags:
            floor = SCOPE_FLAG_ESCALATION[flag]
            if _LANE_ORDER[floor] > _LANE_ORDER[effective]:
                effective = floor
                reasons.append(f"{flag}→{floor}")
        return effective, effective != lane, tuple(reasons)

    def plan(
        self,
        lane: str,
        *,
        scope_flags: Iterable[str] = (),
        downgrade: Optional[Mapping[str, Any] | RiskAcceptance] = None,
        downgrade_stations: Iterable[int] = (),
        now: Optional[datetime] = None,
    ) -> BugscanPlan:
        """生成冻结计划。

        - scope_flags 命中 → 自动升档（只增不减）。
        - downgrade（映射或 RiskAcceptance）+ downgrade_stations → 显式降档：
          记录五要素校验 + 日落校验；站 0/1 不可移除；只能移除生效档
          required 集内的站。
        """
        effective, escalated, reasons = self.resolve_lane(lane, scope_flags)
        base_set = set(self._registry.required_for(effective))
        dropped: List[int] = []
        drop_req = tuple(downgrade_stations or ())
        acceptance: Optional[RiskAcceptance] = None
        if downgrade is None:
            if drop_req:
                raise RiskDowngradeError(
                    f"removing stations {list(drop_req)} requires a risk acceptance "
                    "record (降档须记录负责人/理由/范围/到期)"
                )
        else:
            acceptance = (
                downgrade
                if isinstance(downgrade, RiskAcceptance)
                else RiskAcceptance.from_mapping(downgrade)
            )
            acceptance.validate(now)
            if not drop_req:
                raise RiskDowngradeError(
                    "downgrade record provided but downgrade_stations is empty"
                )
            for station_id in drop_req:
                if station_id not in base_set:
                    raise RiskDowngradeError(
                        f"cannot drop station {station_id}: not in "
                        f"{effective} required set {sorted(base_set)}"
                    )
                if station_id in DOWNGRADE_FLOOR_STATIONS:
                    raise RiskDowngradeError(
                        f"cannot drop station {station_id}: stations "
                        f"{sorted(DOWNGRADE_FLOOR_STATIONS)} are never removable "
                        "(站0 范围冻结与站1 源闸不可省)"
                    )
                dropped.append(station_id)
            base_set -= set(dropped)
        required = tuple(sorted(base_set))
        return BugscanPlan(
            lane_requested=lane,
            lane_effective=effective,
            required_stations=required,
            convergence_rounds=LANE_CONVERGENCE_ROUNDS[effective],
            escalated=escalated,
            escalation_reasons=reasons,
            downgrade=acceptance,
            dropped_stations=tuple(dropped),
            registry_version=REGISTRY_VERSION,
        )

    # -- 站0 冻结（委托模块级函数，见下） -----------------------------------
    def freeze_run_manifest(
        self,
        plan: BugscanPlan,
        *,
        run_id: str,
        project_id: str,
        commit_sha: str,
        environment: str,
        scope: Iterable[str] | Mapping[str, Any],
        ruleset: Mapping[str, Any] | str,
        data_config: Mapping[str, Any] | str,
        base_sha: Optional[str] = None,
        lockfile_hash: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> "RunManifest":
        return freeze_run_manifest(
            plan,
            run_id=run_id,
            project_id=project_id,
            commit_sha=commit_sha,
            environment=environment,
            scope=scope,
            ruleset=ruleset,
            data_config=data_config,
            base_sha=base_sha,
            lockfile_hash=lockfile_hash,
            now=now,
            registry=self._registry,
        )


# ---------------------------------------------------------------------------
# RunManifest——站0 冻结件
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RunManifest:
    """冻结后的 run manifest（不可变值对象）。

    - manifest_hash = sha256(canonical(内容 sans manifest_hash))。
    - save() 幂等且防篡改：已存在文件与本次内容逐字节一致 → no-op；
      不一致 → ManifestFreezeError（冻结后不可变）。
    - to_station_result() 产出站0 的 station-result-v2 结果。
    """

    run_id: str
    created_at: str
    frozen_at: str
    registry_version: str
    registry_digest: str
    plan: BugscanPlan
    project_id: str
    commit_sha: str
    base_sha: Optional[str]
    environment: str
    scope_hash: str
    ruleset_hash: str
    data_config_hash: str
    lockfile_hash: Optional[str]
    scope_paths: Tuple[str, ...]
    scope_exclusions: Tuple[str, ...]
    required_stations: Tuple[int, ...]
    station_ttls: Dict[int, int]
    manifest_hash: str

    # -- 序列化 -------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "manifest_kind": "bugscan/run-manifest",
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "frozen_at": self.frozen_at,
            "planner": self.plan.to_dict(),
            "identity": {
                "project_id": self.project_id,
                "commit_sha": self.commit_sha,
                "environment": self.environment,
                "scope_hash": self.scope_hash,
                "ruleset_hash": self.ruleset_hash,
                "data_config_hash": self.data_config_hash,
            },
            "scope": {
                "paths": list(self.scope_paths),
                "exclusions": list(self.scope_exclusions),
                "denominator": len(self.scope_paths),
            },
            "required_stations": list(self.required_stations),
            "station_ttls": {str(k): v for k, v in sorted(self.station_ttls.items())},
            "manifest_hash": self.manifest_hash,
        }
        if self.base_sha is not None:
            out["identity"]["base_sha"] = self.base_sha
        if self.lockfile_hash is not None:
            out["identity"]["lockfile_hash"] = self.lockfile_hash
        return out

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @property
    def denominator(self) -> int:
        return len(self.scope_paths)

    def artifact_cas_digest(self) -> Tuple[str, int]:
        """manifest 自身作为站0 工件：CAS digest + 字节数。"""
        payload = self.to_json().encode("utf-8")
        return f"sha256:{_sha256_hex(payload)}", len(payload)

    # -- 落盘 ---------------------------------------------------------------
    def save(self, path: str | os.PathLike[str]) -> Path:
        """原子写 run-manifest.json；冻结语义=同内容幂等、异内容拒绝。"""
        target = Path(path)
        payload = self.to_json().encode("utf-8")
        if target.exists():
            existing = target.read_bytes()
            if existing == payload:
                return target  # 幂等：同一冻结件重复保存
            raise ManifestFreezeError(
                f"{target} already holds a DIFFERENT frozen manifest "
                f"({len(existing)}B vs {len(payload)}B)——冻结后不可变；"
                "如需变更请新建 run（指纹变化即失效重跑）"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(target.parent), prefix=".run-manifest-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        return target

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "RunManifest":
        """读回并校验 manifest_hash（防篡改）。"""
        raw = Path(path).read_bytes()
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, Mapping):
            raise ManifestFreezeError(f"{path}: manifest must be a JSON object")
        stored_hash = data.get("manifest_hash")
        body = {k: v for k, v in data.items() if k != "manifest_hash"}
        recomputed = _hash_obj(body)
        if stored_hash != recomputed:
            raise ManifestFreezeError(
                f"{path}: manifest_hash mismatch (stored {stored_hash!r} != "
                f"recomputed {recomputed!r})——冻结件被篡改或损坏"
            )
        return cls._from_verified_dict(data)

    @classmethod
    def _from_verified_dict(cls, data: Mapping[str, Any]) -> "RunManifest":
        plan_data = data["planner"]
        downgrade = (
            RiskAcceptance.from_mapping(plan_data["downgrade"])
            if plan_data.get("downgrade") else None
        )
        identity = data["identity"]
        plan = BugscanPlan(
            lane_requested=plan_data["lane_requested"],
            lane_effective=plan_data["lane_effective"],
            required_stations=tuple(plan_data["required_stations"]),
            convergence_rounds=int(plan_data["convergence_rounds"]),
            escalated=bool(plan_data["escalated"]),
            escalation_reasons=tuple(plan_data.get("escalation_reasons", ())),
            downgrade=downgrade,
            dropped_stations=tuple(plan_data.get("dropped_stations", ())),
            registry_version=data["registry_version"],
        )
        return cls(
            run_id=data["run_id"],
            created_at=data["created_at"],
            frozen_at=data["frozen_at"],
            registry_version=data["registry_version"],
            registry_digest=data["registry_digest"],
            plan=plan,
            project_id=identity["project_id"],
            commit_sha=identity["commit_sha"],
            base_sha=identity.get("base_sha"),
            environment=identity["environment"],
            scope_hash=identity["scope_hash"],
            ruleset_hash=identity["ruleset_hash"],
            data_config_hash=identity["data_config_hash"],
            lockfile_hash=identity.get("lockfile_hash"),
            scope_paths=tuple(data["scope"]["paths"]),
            scope_exclusions=tuple(data["scope"].get("exclusions", ())),
            required_stations=tuple(data["required_stations"]),
            station_ttls={int(k): int(v) for k, v in data["station_ttls"].items()},
            manifest_hash=data["manifest_hash"],
        )

    # -- 站0 station-result --------------------------------------------------
    def to_station_result(
        self,
        *,
        attempt_id: Optional[str] = None,
        timeout_s: int = 60,
    ) -> Dict[str, Any]:
        """把冻结成功映射为站0 的 station-result-v2 结果。

        执行语义：freeze_run_manifest 在本进程内完成；任何冻结失败都以
        异常上抛、绝不产出结果——因此能够走到这里的那次"执行"必然成功
        （actual_exit_code=0 只在成功路径可达，等价 trusted runner 语义）。
        """
        cas, size = self.artifact_cas_digest()
        attempt = attempt_id or _make_attempt_id(self.run_id, "st0")
        argv = ["wenqu_core.bugscan_orchestrator", "freeze_run_manifest", self.run_id]
        result = build_station_result(
            run_id=self.run_id,
            station_id=0,
            attempt_id=attempt,
            execution_status="COMPLETED",
            policy_verdict="PASS",
            identity={
                "project_id": self.project_id,
                "commit_sha": self.commit_sha,
                "environment": self.environment,
                "scope_hash": self.scope_hash,
                "ruleset_hash": self.ruleset_hash,
                "data_config_hash": self.data_config_hash,
                **({"lockfile_hash": self.lockfile_hash} if self.lockfile_hash else {}),
            },
            tool={
                "name": "wenqu_core.bugscan_orchestrator",
                "version": __version__,
                "digest": self.manifest_hash,
            },
            execution={
                "argv_digest": _argv_digest(argv),
                "started_at": self.created_at,
                "ended_at": self.frozen_at,
                "timeout_s": timeout_s,
                "actual_exit_code": 0,
                "expected_exit_set": [0],
                "assertion_verdict": "PASS",
            },
            coverage={
                "denominator": self.denominator,
                "scanned": self.denominator,
                "exclusions": list(self.scope_exclusions),
            },
            finding_ids=[],
            artifacts=[{"cas_digest": cas, "size": size}],
        )
        return result


def _make_attempt_id(run_id: str, tag: str) -> str:
    seed = _hash_obj({"run_id": run_id, "tag": tag, "ts": _iso_z(_utc_now())})
    return f"att-{tag}-{seed[:12]}"


def _argv_digest(argv: Sequence[str]) -> str:
    """与 runner.TrustedRunner.argv_digest 同算法（canonical JSON of argv list）。"""
    canonical = json.dumps(list(argv), separators=(",", ":"), ensure_ascii=False)
    return _sha256_hex(canonical.encode("utf-8"))


# ---------------------------------------------------------------------------
# freeze_run_manifest——模块级入口（Codex W6A §15.2 站0）
# ---------------------------------------------------------------------------

def freeze_run_manifest(
    plan: BugscanPlan,
    *,
    run_id: str,
    project_id: str,
    commit_sha: str,
    environment: str,
    scope: Iterable[str] | Mapping[str, Any],
    ruleset: Mapping[str, Any] | str,
    data_config: Mapping[str, Any] | str,
    base_sha: Optional[str] = None,
    lockfile_hash: Optional[str] = None,
    now: Optional[datetime] = None,
    registry: Optional[StationRegistry] = None,
) -> RunManifest:
    """冻结 run-manifest.json 的内容（返回 RunManifest，由调用方 .save() 落盘）。

    绑定（不变量 #2/#3）：run_id + commit_sha + environment + scope_hash +
    ruleset_hash + data_config_hash + required 站集合 + 各站 TTL。
    run 起跑后任一指纹变化 → 旧证据立即失效，须重新冻结（新 run）。
    """
    registry = registry or default_registry()
    if not isinstance(plan, BugscanPlan):
        raise ManifestFreezeError(f"plan must be BugscanPlan, got {type(plan).__name__}")
    if not isinstance(run_id, str) or not _RE_RUN_ID.match(run_id):
        raise ManifestFreezeError(
            f"run_id must match {_RE_RUN_ID.pattern}, got {run_id!r}"
        )
    if not isinstance(project_id, str) or not project_id.strip():
        raise ManifestFreezeError("project_id must be a non-empty string")
    try:
        _require_sha40(commit_sha, what="commit_sha")
        if base_sha is not None:
            _require_sha40(base_sha, what="base_sha")
    except ValueError as exc:
        if isinstance(exc, ManifestFreezeError):
            raise
        raise ManifestFreezeError(str(exc)) from exc
    if environment not in ENVIRONMENTS:
        raise ManifestFreezeError(
            f"environment must be one of {ENVIRONMENTS}, got {environment!r}"
        )

    # scope：list → paths（无排除）；mapping → {"paths":…, "exclusions":…}
    if isinstance(scope, Mapping):
        paths_raw = scope.get("paths", ())
        exclusions_raw = scope.get("exclusions", ())
    else:
        paths_raw, exclusions_raw = scope, ()
    if not isinstance(paths_raw, (list, tuple)):
        raise ManifestFreezeError("scope.paths must be a list/tuple of strings")
    if not isinstance(exclusions_raw, (list, tuple)):
        raise ManifestFreezeError("scope.exclusions must be a list/tuple of strings")
    paths = tuple(sorted({str(p) for p in paths_raw if str(p).strip()}))
    exclusions = tuple(sorted({str(e) for e in exclusions_raw if str(e).strip()}))
    if not paths:
        raise ManifestFreezeError(
            "scope must contain at least one path (范围分母齐全——空 scope 冻结非法)"
        )
    scope_hash = _hash_obj({"paths": list(paths), "exclusions": list(exclusions)})

    try:
        ruleset_hash = _hash_or_digest(ruleset, what="ruleset")
        data_config_hash = _hash_or_digest(data_config, what="data_config")
        lockfile_digest = _hash_or_digest(lockfile_hash, what="lockfile_hash", required=False)
    except ValueError as exc:
        raise ManifestFreezeError(str(exc)) from exc

    # required 站与计划一致 + TTL 全部落账
    required = tuple(sorted(set(plan.required_stations)))
    for station_id in required:
        registry.get(station_id)  # 未注册站 → KeyError（fail-closed）
    station_ttls = {i: registry.ttl_for(i) for i in required}

    started = now or _utc_now()
    created_at = _iso_z(started)
    frozen_at = _iso_z(_utc_now())
    if _parse_iso(frozen_at, what="frozen_at") < _parse_iso(created_at, what="created_at"):
        frozen_at = created_at  # 时钟回拨保护：结束不得早于开始

    body: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "manifest_kind": "bugscan/run-manifest",
        "registry_version": REGISTRY_VERSION,
        "registry_digest": registry.registry_digest(),
        "run_id": run_id,
        "created_at": created_at,
        "frozen_at": frozen_at,
        "planner": plan.to_dict(),
        "identity": {
            "project_id": project_id,
            "commit_sha": commit_sha,
            "environment": environment,
            "scope_hash": scope_hash,
            "ruleset_hash": ruleset_hash,
            "data_config_hash": data_config_hash,
        },
        "scope": {
            "paths": list(paths),
            "exclusions": list(exclusions),
            "denominator": len(paths),
        },
        "required_stations": list(required),
        "station_ttls": {str(k): v for k, v in sorted(station_ttls.items())},
    }
    if base_sha is not None:
        body["identity"]["base_sha"] = base_sha
    if lockfile_digest is not None:
        body["identity"]["lockfile_hash"] = lockfile_digest
    manifest_hash = _hash_obj(body)
    return RunManifest(
        run_id=run_id,
        created_at=created_at,
        frozen_at=frozen_at,
        registry_version=REGISTRY_VERSION,
        registry_digest=registry.registry_digest(),
        plan=plan,
        project_id=project_id,
        commit_sha=commit_sha,
        base_sha=base_sha,
        environment=environment,
        scope_hash=scope_hash,
        ruleset_hash=ruleset_hash,
        data_config_hash=data_config_hash,
        lockfile_hash=lockfile_digest,
        scope_paths=paths,
        scope_exclusions=exclusions,
        required_stations=required,
        station_ttls=station_ttls,
        manifest_hash=manifest_hash,
    )


# ---------------------------------------------------------------------------
# station-result-v2 构造与校验
# ---------------------------------------------------------------------------

def build_station_result(
    *,
    run_id: str,
    station_id: int,
    attempt_id: str,
    execution_status: str,
    policy_verdict: str,
    identity: Mapping[str, Any],
    tool: Mapping[str, Any],
    execution: Mapping[str, Any],
    coverage: Mapping[str, Any],
    finding_ids: Iterable[str] = (),
    artifacts: Iterable[Mapping[str, Any]] = (),
) -> Dict[str, Any]:
    """按 schema 白名单构造 station-result-v2，并强制安全不变量：

    1. 分母缩水守卫：scanned < denominator → 强制 BLOCKED/NOT_EVALUATED
       （铁律 2 与 schema $comment——该站绝不能记 PASS）。
    2. 执行非完成态（ERROR/BLOCKED/TIMEOUT/CANCELLED）→ 禁止 PASS。
    3. policy PASS 必须有 assertion_verdict=PASS 支撑。
    """
    if coverage.get("scanned", 0) < coverage.get("denominator", 0):
        execution_status = "BLOCKED"
        policy_verdict = "NOT_EVALUATED"
    if execution_status in ("ERROR", "BLOCKED", "TIMEOUT", "CANCELLED"):
        if policy_verdict == "PASS":
            raise StationResultValidationError(
                f"station {station_id}: execution_status={execution_status} "
                "forbids policy_verdict=PASS（铁律2：站内任一件 BLOCKED/ERROR"
                "→整站不得记 PASS）"
            )
    if policy_verdict == "PASS" and execution.get("assertion_verdict") != "PASS":
        raise StationResultValidationError(
            f"station {station_id}: policy PASS requires assertion_verdict=PASS"
        )

    result: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "station_id": station_id,
        "attempt_id": attempt_id,
        "execution_status": execution_status,
        "policy_verdict": policy_verdict,
        "identity": dict(identity),
        "tool": dict(tool),
        "execution": dict(execution),
        "coverage": {
            "denominator": coverage.get("denominator", 0),
            "scanned": coverage.get("scanned", 0),
            **({"exclusions": list(coverage["exclusions"])}
               if coverage.get("exclusions") else {}),
        },
        "finding_ids": list(finding_ids),
    }
    artifacts_list = [dict(a) for a in artifacts]
    if artifacts_list:
        result["artifacts"] = artifacts_list
    validate_station_result(result)
    return result


def validate_station_result(result: Any) -> None:
    """结构校验（schema 的可执行等价物）+ 不变量复核；失败聚合抛出。

    可用时额外用 jsonschema 对 schemas/station-result-v2.schema.json
    做全量复核（双保险）；jsonschema 不可用时以本内置校验器为准。
    """
    issues: List[str] = []

    def _check(condition: bool, message: str) -> None:
        if not condition:
            issues.append(message)

    if not isinstance(result, Mapping):
        raise StationResultValidationError(
            f"station result must be a mapping, got {type(result).__name__}"
        )
    extra = set(result) - set(_STATION_RESULT_TOP_KEYS)
    _check(not extra, f"additional properties not allowed: {sorted(extra)}")
    for key in ("schema_version", "run_id", "station_id", "attempt_id",
                "execution_status", "policy_verdict", "identity", "tool",
                "execution"):
        _check(key in result, f"missing required property: {key}")

    _check(result.get("schema_version") == SCHEMA_VERSION,
           f"schema_version must be {SCHEMA_VERSION!r}")
    _check(isinstance(result.get("run_id"), str) and bool(_RE_RUN_ID.match(result.get("run_id", ""))),
           f"run_id must match {_RE_RUN_ID.pattern}")
    sid = result.get("station_id")
    _check(isinstance(sid, int) and not isinstance(sid, bool) and 0 <= sid <= 7,
           f"station_id must be int in [0,7], got {sid!r}")
    _check(isinstance(result.get("attempt_id"), str) and result.get("attempt_id") != "",
           "attempt_id must be a non-empty string")
    _check(result.get("execution_status") in
           ("COMPLETED", "ERROR", "BLOCKED", "TIMEOUT", "CANCELLED"),
           f"invalid execution_status: {result.get('execution_status')!r}")
    _check(result.get("policy_verdict") in
           ("PASS", "FAIL", "CONDITIONAL", "NOT_APPLICABLE", "NOT_EVALUATED"),
           f"invalid policy_verdict: {result.get('policy_verdict')!r}")

    identity = result.get("identity")
    if isinstance(identity, Mapping):
        extra_i = set(identity) - set(_IDENTITY_KEYS)
        _check(not extra_i, f"identity additional properties: {sorted(extra_i)}")
        _check(isinstance(identity.get("commit_sha"), str)
               and bool(_RE_SHA40.match(identity.get("commit_sha", ""))),
               "identity.commit_sha must be 40-char lowercase hex")
        _check(isinstance(identity.get("environment"), str)
               and identity.get("environment") != "",
               "identity.environment must be a non-empty string")
        _check(isinstance(identity.get("scope_hash"), str)
               and identity.get("scope_hash") != "",
               "identity.scope_hash must be a non-empty string")
        for opt in ("project_id", "ruleset_hash", "data_config_hash", "lockfile_hash"):
            if opt in identity:
                _check(isinstance(identity[opt], str), f"identity.{opt} must be a string")
    else:
        issues.append("identity must be an object")

    tool = result.get("tool")
    if isinstance(tool, Mapping):
        _check(isinstance(tool.get("name"), str) and tool.get("name") != "",
               "tool.name must be a non-empty string")
        _check(isinstance(tool.get("version"), str) and tool.get("version") != "",
               "tool.version must be a non-empty string")
        if "digest" in tool:
            _check(isinstance(tool["digest"], str), "tool.digest must be a string")
    else:
        issues.append("tool must be an object")

    execution = result.get("execution")
    if isinstance(execution, Mapping):
        extra_e = set(execution) - set(_EXECUTION_KEYS)
        _check(not extra_e, f"execution additional properties: {sorted(extra_e)}")
        for key in ("argv_digest", "started_at", "ended_at", "actual_exit_code",
                    "expected_exit_set", "assertion_verdict"):
            _check(key in execution, f"execution missing required property: {key}")
        _check(isinstance(execution.get("argv_digest"), str)
               and execution.get("argv_digest") != "",
               "execution.argv_digest must be a non-empty string")
        for ts_key in ("started_at", "ended_at"):
            value = execution.get(ts_key)
            ok = isinstance(value, str)
            if ok:
                try:
                    _parse_iso(value, what=f"execution.{ts_key}")
                except ValueError:
                    ok = False
            _check(ok, f"execution.{ts_key} must be an ISO-8601 date-time")
        exit_code = execution.get("actual_exit_code")
        _check(isinstance(exit_code, int) and not isinstance(exit_code, bool),
               f"execution.actual_exit_code must be an int, got {exit_code!r}")
        expected = execution.get("expected_exit_set")
        _check(isinstance(expected, list)
               and all(isinstance(x, int) and not isinstance(x, bool) for x in expected),
               "execution.expected_exit_set must be a list of ints")
        _check(execution.get("assertion_verdict") in ("PASS", "FAIL", "ERROR"),
               f"invalid execution.assertion_verdict: {execution.get('assertion_verdict')!r}")
        if "timeout_s" in execution:
            _check(isinstance(execution["timeout_s"], int)
                   and not isinstance(execution["timeout_s"], bool)
                   and execution["timeout_s"] >= 1,
                   "execution.timeout_s must be an int >= 1")
        if "cwd_digest" in execution:
            _check(isinstance(execution["cwd_digest"], str),
                   "execution.cwd_digest must be a string")
    else:
        issues.append("execution must be an object")

    coverage = result.get("coverage")
    if coverage is not None:
        if isinstance(coverage, Mapping):
            extra_c = set(coverage) - set(_COVERAGE_KEYS)
            _check(not extra_c, f"coverage additional properties: {sorted(extra_c)}")
            for key in ("denominator", "scanned"):
                if key in coverage:
                    value = coverage[key]
                    _check(isinstance(value, int) and not isinstance(value, bool)
                           and value >= 0,
                           f"coverage.{key} must be an int >= 0")
            if "exclusions" in coverage:
                _check(isinstance(coverage["exclusions"], list)
                       and all(isinstance(x, str) for x in coverage["exclusions"]),
                       "coverage.exclusions must be a list of strings")
        else:
            issues.append("coverage must be an object")

    findings = result.get("finding_ids", [])
    _check(isinstance(findings, list)
           and all(isinstance(x, str) and _RE_FND.match(x) for x in findings),
           "finding_ids must be a list of strings matching ^fnd_[a-zA-Z0-9_]+$")

    artifacts = result.get("artifacts", [])
    if isinstance(artifacts, list):
        for idx, art in enumerate(artifacts):
            if isinstance(art, Mapping):
                _check(isinstance(art.get("cas_digest"), str)
                       and bool(_RE_CAS_DIGEST.match(art.get("cas_digest", ""))),
                       f"artifacts[{idx}].cas_digest must match sha256:<64hex>")
                size = art.get("size")
                _check(isinstance(size, int) and not isinstance(size, bool) and size >= 1,
                       f"artifacts[{idx}].size must be an int >= 1")
                extra_a = set(art) - {"cas_digest", "size"}
                _check(not extra_a,
                       f"artifacts[{idx}] additional properties: {sorted(extra_a)}")
            else:
                issues.append(f"artifacts[{idx}] must be an object")
    else:
        issues.append("artifacts must be a list")

    # -- 不变量复核（schema $comment + 铁律 2）-------------------------------
    if isinstance(coverage, Mapping) and isinstance(execution, Mapping):
        denom = coverage.get("denominator", 0)
        scanned = coverage.get("scanned", 0)
        if isinstance(denom, int) and isinstance(scanned, int) and scanned < denom:
            _check(result.get("execution_status") == "BLOCKED",
                   "coverage shrink (scanned<denominator) requires execution_status=BLOCKED")
            _check(result.get("policy_verdict") != "PASS",
                   "coverage shrink (scanned<denominator) forbids policy_verdict=PASS")
        if result.get("execution_status") in ("ERROR", "BLOCKED", "TIMEOUT", "CANCELLED"):
            _check(result.get("policy_verdict") != "PASS",
                   "non-COMPLETED execution_status forbids policy_verdict=PASS")

    if issues:
        raise StationResultValidationError(
            "station-result-v2 validation failed: " + "; ".join(issues)
        )

    # -- 双保险：jsonschema 可用时对真实 schema 全量复核 ----------------------
    _cross_check_with_jsonschema(result)


def _cross_check_with_jsonschema(result: Mapping[str, Any]) -> None:
    schema_path = (
        Path(__file__).resolve().parent.parent / "schemas" / "station-result-v2.schema.json"
    )
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return  # 第三方不可用：内置校验器即正源
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(result, schema)
    except FileNotFoundError:
        return  # schema 文件不存在（嵌入部署等）——内置校验器兜底
    except Exception as exc:  # noqa: BLE001——任何复核失败都不得静默
        raise StationResultValidationError(
            f"jsonschema cross-check against {schema_path} failed: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# SourceGateAdapter——站1 源闸适配（Codex W6A §15.2）
# ---------------------------------------------------------------------------

class SourceGateAdapter:
    """站1 适配器：消费 SourceGate 在 exact-SHA 上的既有结果。

    本适配器不运行任何门禁、不重新解释工具输出——只做三件事：
    1. 绑定校验：gate_result.commit_sha 必须等于冻结 manifest 的 commit_sha
       （证据/审批不得跨 SHA 复用——不变量 #5），不匹配即抛
       SourceGateShaMismatch。
    2. 时效校验：gate 结束时刻 + 站 TTL ≥ now（铁律 4），过期抛
       EvidenceStaleError。
    3. 机械映射：退出码 → (execution_status, policy_verdict)，按
       wenqu-vNext-contract §7 契约表（SOURCE_GATE_EXIT_CODE_MAPPING）；
       退出码不在契约内 → GateResultMalformed（fail-closed）。

    身份三源（commit_sha/environment/scope_hash 等）一律取自冻结 manifest
    正源，绝不采信 gate_result 自报身份。
    """

    STATION_ID = 1

    def __init__(
        self,
        manifest: RunManifest,
        *,
        registry: Optional[StationRegistry] = None,
        now: Optional[datetime] = None,
    ) -> None:
        if not isinstance(manifest, RunManifest):
            raise SourceGateError(
                f"manifest must be RunManifest, got {type(manifest).__name__}"
            )
        self._manifest = manifest
        self._registry = registry or default_registry()
        self._now = now

    # -- 输入契约 -----------------------------------------------------------
    @staticmethod
    def _extract_gate_fields(gate_result: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(gate_result, Mapping):
            raise GateResultMalformed(
                f"gate_result must be a mapping, got {type(gate_result).__name__}"
            )
        missing = [k for k in ("commit_sha", "exit_code") if k not in gate_result]
        if missing:
            raise GateResultMalformed(f"gate_result missing fields: {missing}")
        try:
            sha = _require_sha40(gate_result["commit_sha"], what="gate_result.commit_sha")
        except ValueError as exc:
            raise GateResultMalformed(str(exc)) from exc
        exit_code = gate_result["exit_code"]
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise GateResultMalformed(
                f"gate_result.exit_code must be an int, got {exit_code!r}"
            )
        if exit_code not in SOURCE_GATE_EXIT_CODE_MAPPING:
            raise GateResultMalformed(
                f"gate_result.exit_code {exit_code} not in §7 contract "
                f"{sorted(SOURCE_GATE_EXIT_CODE_MAPPING)} (fail-closed)"
            )
        tool = gate_result.get("tool")
        if not isinstance(tool, Mapping) or not tool.get("name") or not tool.get("version"):
            raise GateResultMalformed(
                "gate_result.tool must be an object with non-empty name/version"
            )
        for ts_key in ("started_at", "ended_at"):
            if ts_key not in gate_result:
                raise GateResultMalformed(f"gate_result missing {ts_key}")
            try:
                _parse_iso(gate_result[ts_key], what=f"gate_result.{ts_key}")
            except ValueError as exc:
                raise GateResultMalformed(str(exc)) from exc
        components = gate_result.get("components", [])
        if not isinstance(components, list) or not all(
            isinstance(c, Mapping) and isinstance(c.get("name"), str) for c in components
        ):
            raise GateResultMalformed(
                "gate_result.components must be a list of objects with a name"
            )
        return {
            "commit_sha": sha,
            "exit_code": exit_code,
            "tool": dict(tool),
            "started_at": gate_result["started_at"],
            "ended_at": gate_result["ended_at"],
            "argv_digest": gate_result.get("argv_digest"),
            "components": [dict(c) for c in components],
        }

    # -- 适配 ---------------------------------------------------------------
    def adapt(self, gate_result: Mapping[str, Any]) -> Dict[str, Any]:
        """消费源闸结果 → 站1 station-result-v2（严格 schema 合规）。"""
        parsed = self._extract_gate_fields(gate_result)

        # 1) exact-SHA 绑定（不匹配=证据不属于本 run，拒绝而非降级）
        if parsed["commit_sha"] != self._manifest.commit_sha:
            raise SourceGateShaMismatch(
                f"gate ran at {parsed['commit_sha']} but manifest froze "
                f"{self._manifest.commit_sha}——证据不得跨 SHA 复用，请在冻结 SHA 重跑源闸"
            )

        # 2) 时效（铁律 4 双上限，按站 TTL）
        now = self._now or _utc_now()
        ttl_days = self._registry.ttl_for(self.STATION_ID)
        ended = _parse_iso(parsed["ended_at"], what="gate_result.ended_at")
        fresh_until = ended + timedelta(days=ttl_days)
        if fresh_until < now:
            raise EvidenceStaleError(
                f"gate evidence aged out: ended {parsed['ended_at']} + TTL "
                f"{ttl_days}d < now {_iso_z(now)}——重跑源闸后重新适配"
            )

        # 3) §7 退出码 → 双轴（机械映射，不自行判定）
        execution_status, policy_verdict = SOURCE_GATE_EXIT_CODE_MAPPING[parsed["exit_code"]]

        # 覆盖：组件级分母（未给组件时以门整体为单件——denominator 不缩水）
        components = parsed["components"]
        if components:
            denominator = len(components)
            scanned = sum(
                1 for c in components
                if str(c.get("status", "COMPLETED")).upper() != "NOT_RUN"
            )
        else:
            denominator = scanned = 1
        shrink = scanned < denominator
        if shrink:
            # 分母缩水守卫：整站 BLOCKED，绝不记 PASS（schema $comment）。
            execution_status = "BLOCKED"
            policy_verdict = "NOT_EVALUATED"
        assertion = "PASS" if (policy_verdict == "PASS" and not shrink) else (
            "FAIL" if policy_verdict == "FAIL" else "ERROR"
        )

        manifest_identity: Dict[str, Any] = {
            "project_id": self._manifest.project_id,
            "commit_sha": self._manifest.commit_sha,
            "environment": self._manifest.environment,
            "scope_hash": self._manifest.scope_hash,
            "ruleset_hash": self._manifest.ruleset_hash,
            "data_config_hash": self._manifest.data_config_hash,
        }
        if self._manifest.lockfile_hash:
            manifest_identity["lockfile_hash"] = self._manifest.lockfile_hash

        tool = {
            "name": str(parsed["tool"]["name"]),
            "version": str(parsed["tool"]["version"]),
        }
        if parsed["tool"].get("digest"):
            tool["digest"] = str(parsed["tool"]["digest"])

        execution: Dict[str, Any] = {
            "argv_digest": str(parsed["argv_digest"]) if parsed["argv_digest"]
            else _argv_digest([tool["name"], self._manifest.run_id]),
            "started_at": parsed["started_at"],
            "ended_at": parsed["ended_at"],
            "actual_exit_code": parsed["exit_code"],
            "expected_exit_set": [0],
            "assertion_verdict": assertion,
        }

        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_make_attempt_id(self._manifest.run_id, "st1"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=manifest_identity,
            tool=tool,
            execution=execution,
            coverage={"denominator": denominator, "scanned": scanned},
            finding_ids=[],
        )


# ---------------------------------------------------------------------------
# 端到端自证（python3 bugscan_orchestrator.py）
# ---------------------------------------------------------------------------

def _self_test() -> int:
    """端到端冒烟：planner 升档 → 冻结 → 站0/站1 结果 → 双重校验。"""
    registry = default_registry()
    registry.validate()
    print(f"[1] registry {REGISTRY_VERSION} OK: 8 stations, "
          f"digest={registry.registry_digest()[:12]}…")

    planner = BugscanPlanner(registry)
    plan = planner.plan("FAST", scope_flags=("touches_migration",))
    assert plan.lane_effective == "STANDARD" and plan.escalated
    assert plan.required_stations == (0, 1, 2, 3, 4)
    assert plan.convergence_rounds == 2
    print(f"[2] planner auto-escalation OK: FAST --touches_migration--> "
          f"STANDARD, required={plan.required_stations}, rounds={plan.convergence_rounds}")

    sha = "1" * 40
    manifest = planner.freeze_run_manifest(
        plan,
        run_id="selftest-run-001",
        project_id="wenqu-selftest",
        commit_sha=sha,
        environment="local",
        scope=["src/**", "tests/**"],
        ruleset={"version": "w6a", "rules": ["W6A-ST0", "W6A-ST1"]},
        data_config={"profile": "default"},
    )
    st0 = manifest.to_station_result()
    validate_station_result(st0)
    print(f"[3] freeze OK: run={manifest.run_id} scope_hash={manifest.scope_hash[:12]}… "
          f"manifest_hash={manifest.manifest_hash[:12]}… ; station-0 result PASS "
          f"(coverage {st0['coverage']['scanned']}/{st0['coverage']['denominator']})")

    gate = {
        "commit_sha": sha,
        "exit_code": 0,
        "tool": {"name": "ci-fast", "version": "1"},
        "started_at": manifest.frozen_at,
        "ended_at": manifest.frozen_at,
        "components": [
            {"name": "lint", "status": "COMPLETED", "exit_code": 0},
            {"name": "typecheck", "status": "COMPLETED", "exit_code": 0},
            {"name": "unit", "status": "COMPLETED", "exit_code": 0},
        ],
    }
    adapter = SourceGateAdapter(manifest, registry=registry)
    st1 = adapter.adapt(gate)
    validate_station_result(st1)
    print(f"[4] source-gate adapt OK: exit 0 → COMPLETED/PASS "
          f"(coverage {st1['coverage']['scanned']}/{st1['coverage']['denominator']})")

    # 负例快检：跨 SHA 必拒 / 缩水必 BLOCKED / 降档必录五要素
    try:
        adapter.adapt({**gate, "commit_sha": "2" * 40})
        raise AssertionError("sha mismatch must raise")
    except SourceGateShaMismatch:
        pass
    st1_shrink = adapter.adapt({
        **gate,
        "components": [
            {"name": "lint", "status": "COMPLETED", "exit_code": 0},
            {"name": "unit", "status": "NOT_RUN"},
        ],
    })
    assert st1_shrink["execution_status"] == "BLOCKED"
    assert st1_shrink["policy_verdict"] != "PASS"
    try:
        planner.plan("STANDARD", downgrade_stations=(4,))
        raise AssertionError("downgrade without record must raise")
    except RiskDowngradeError:
        pass
    try:  # 到期超出 30 天日落窗口 → 拒绝
        planner.plan(
            "STANDARD",
            downgrade={"approver": "risk-owner", "reason": "行为面环境维护窗口暂停",
                       "scope": "station 4 only", "expiry": "2099-01-01T00:00:00Z"},
            downgrade_stations=(4,),
        )
        raise AssertionError("downgrade beyond 30d sunset must raise")
    except RiskDowngradeError:
        pass
    try:  # 站0 不可降档移除
        planner.plan(
            "STANDARD",
            downgrade={"approver": "risk-owner", "reason": "试图跳过范围冻结",
                       "scope": "station 0", "expiry": _iso_z(_utc_now() + timedelta(days=7))},
            downgrade_stations=(0,),
        )
        raise AssertionError("dropping station 0 must raise")
    except RiskDowngradeError:
        pass
    good = planner.plan(
        "STANDARD",
        downgrade={"approver": "risk-owner", "reason": "行为面环境维护窗口暂停",
                   "scope": "station 4 only", "expiry": _iso_z(_utc_now() + timedelta(days=7))},
        downgrade_stations=(4,),
    )
    assert good.required_stations == (0, 1, 2, 3)
    assert good.downgrade is not None and good.dropped_stations == (4,)
    print("[5] negative paths OK: cross-SHA refused / shrink→BLOCKED / "
          "downgrade requires valid 5-element record (30d sunset + floor {0,1} enforced)")

    import tempfile as _tf
    with _tf.TemporaryDirectory() as tmp:
        path = Path(tmp) / "run-manifest.json"
        manifest.save(path)
        manifest.save(path)  # 幂等
        loaded = RunManifest.load(path)
        assert loaded.manifest_hash == manifest.manifest_hash
        print(f"[6] manifest save/load OK: {path.name} idempotent + hash verified")
    print("SELF-TEST PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

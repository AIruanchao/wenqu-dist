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
- R7-GATE-MANIFEST-AUTH-001（第七轮洞1 根修，2026-10-08）：manifest 无可信根
  ——纯 manifest_hash 任何人都能重算，篡改顶层 required/删 TTL 后自行重算
  hash 即可让 gate 按缩水口径上绿。修法三件套：
  1. freeze_run_manifest 增签名面（signing_keyring/signing_key_id）：以
     wenqu_core.approval_keys 的 HMAC-SHA256 对 manifest 签发
     ``signature`` + ``key_id`` 字段（release/manifest 专用 key——只读
     import，不引入写路径）；``manifest_hash`` 改为覆盖**含签名的整体
     内容**（重算 hash 不再能洗白篡改——签名覆盖 key_id 外全部内容）。
  2. RunManifest.load(path, keyring=…, allow_unsigned=…)：keyring 给定时
     验签——无签名默认拒（仅诊断可显式 allow_unsigned）、key 未知/已吊销/
     验签失败一律 ManifestFreezeError（fail-closed）。
  3. validate_manifest_consistency()：顶层与 planner 的 required/TTL/scope/
     分母自一致性校验（独立于签名——即使合法签名/诊断降级路径，任何不一致
     由 CLI 记 manifest_consistency_violation 并整线 BLOCKED）。
- SourceGateAdapter：站1 源闸适配——只消费 SourceGate 在 exact-SHA 上的
  既有结果并按 §7 退出码契约机械映射，不自行判定、不重跑；SHA 不匹配/
  证据过期/载荷畸形一律 fail-closed 抛错，绝不折算为 PASS（不变量：审批与
  证据不得跨 SHA 复用）。
- 收敛环契约（§20.1 GATE-09/10/11）：validate_convergence_rounds 在编排器
  入口执行 N 值域检查（-1/0/超上限=参数错误拒绝开跑）；ConvergenceTracker
  按命令身份（argv 规范化摘要）计异源轮——同命令换 S 标签不铸造新异源轮
  （GATE-11）；异源轮跑满 N+1 未收敛即 BLOCKED 等人工裁定、拒绝任何自动
  重试，人工 CONTINUE 每次恰好放行 +1 轮预算（GATE-10）。

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

# R7-GATE-MANIFEST-AUTH-001：只读复用审批密钥域（HMAC 签名/验签原语与 keyring
# 生命周期语义——revoked 验签即拒）。独立脚本执行（python3 bugscan_orchestrator.py）
# 时补 sys.path，包内导入时零副作用。
try:  # pragma: no cover —— 分支取决于执行形态
    from wenqu_core.approval_keys import (  # noqa: E402
        ApprovalKeyring, KeyNotFoundError, KeyStateError, sign_envelope,
    )
except ImportError:  # pragma: no cover —— 脚本直跑回退
    import sys as _sys
    _PKG_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _PKG_PARENT not in _sys.path:
        _sys.path.insert(0, _PKG_PARENT)
    from wenqu_core.approval_keys import (  # noqa: E402
        ApprovalKeyring, KeyNotFoundError, KeyStateError, sign_envelope,
    )

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
    "validate_manifest_consistency",
    "default_registry",
    "CONVERGENCE_ROUNDS_MIN",
    "CONVERGENCE_ROUNDS_MAX",
    "TRACKER_STATE_RUNNING",
    "TRACKER_STATE_CONVERGED",
    "TRACKER_STATE_BLOCKED",
    "TRACKER_STATE_STOPPED",
    "validate_convergence_rounds",
    "normalized_argv_digest",
    "ConvergenceTracker",
    "BugscanPlanError",
    "RiskDowngradeError",
    "ConvergenceRoundsError",
    "ConvergenceRoundCapExceeded",
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

#: GATE-09（§20.1）：收敛轮数 N 的值域。下界=1（N=-1/0 一律参数错误拒绝；
#: 编排器域内不存在「N=0 合法开关」——cli/wenqu verify --convergence 0 的
#: 「关闭收敛要求」是 CLI 查询侧开关语义，进入 bugscan 编排契约的 N 必须
#: ≥1）。上界=最高档 INCIDENT 的收敛轮数——超过即试图把「N+1 熔断上限」
#: 推成无限递归，同为参数错误。
CONVERGENCE_ROUNDS_MIN = 1
CONVERGENCE_ROUNDS_MAX = max(LANE_CONVERGENCE_ROUNDS.values())  # = 3

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


class ConvergenceRoundsError(BugscanPlanError):
    """GATE-09：收敛轮数 N 值域违规（-1/0/超上限/非整数/布尔/低于档位契约）。

    编排器入口参数错误——拒绝开跑，绝不静默钳制到合法值（钳制会掩盖
    调用方对收敛契约的误解，产生假收敛声明）。
    """


class ConvergenceRoundCapExceeded(RuntimeError):
    """GATE-10：跑满 N+1 轮未收敛已转 BLOCKED 后仍尝试追加轮次。

    BLOCKED=停止递归、等待人工裁定（adjudicate）；任何未经人工裁定的
    自动重试（含同命令重复轮）都在此拒绝。
    """


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
        convergence_rounds: Optional[int] = None,
    ) -> BugscanPlan:
        """生成冻结计划。

        - scope_flags 命中 → 自动升档（只增不减）。
        - downgrade（映射或 RiskAcceptance）+ downgrade_stations → 显式降档：
          记录五要素校验 + 日落校验；站 0/1 不可移除；只能移除生效档
          required 集内的站。
        - convergence_rounds（GATE-09）：显式覆盖收敛轮数 N 时必须过
          validate_convergence_rounds 值域检查（int 且 1≤N≤最高档上限、
          且不得低于生效档契约 N——降档收敛是弱化，按参数错误拒绝）；
          未提供时取生效档表值。N=-1/0/超上限一律 ConvergenceRoundsError。
        """
        effective, escalated, reasons = self.resolve_lane(lane, scope_flags)
        if convergence_rounds is None:
            rounds = LANE_CONVERGENCE_ROUNDS[effective]
        else:
            rounds = validate_convergence_rounds(convergence_rounds, lane=effective)
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
            convergence_rounds=rounds,
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
        signing_keyring: Optional[ApprovalKeyring] = None,
        signing_key_id: Optional[str] = None,
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
            signing_keyring=signing_keyring,
            signing_key_id=signing_key_id,
        )


# ---------------------------------------------------------------------------
# RunManifest——站0 冻结件
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RunManifest:
    """冻结后的 run manifest（不可变值对象）。

    - R7-GATE-MANIFEST-AUTH-001：``signature``/``key_id``（可选）为
      release/manifest 专用 key 的 HMAC-SHA256 签名——签名覆盖
      key_id 外的全部 manifest 内容；``manifest_hash`` 覆盖**含签名的
      整体内容**。未签名（legacy/诊断）manifest 两者为 None，hash 语义
      退化为不含签名字段的旧口径。
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
    signature: Optional[str] = None   # R7-GATE-MANIFEST-AUTH-001（HMAC hex）
    key_id: Optional[str] = None      # 签发 key（keyring 验签用）

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
        if self.key_id is not None:
            out["key_id"] = self.key_id
        if self.signature is not None:
            out["signature"] = self.signature
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
    def load(cls, path: str | os.PathLike[str], *,
             keyring: Optional[ApprovalKeyring] = None,
             allow_unsigned: bool = False) -> "RunManifest":
        """读回并校验（R7-GATE-MANIFEST-AUTH-001：hash 复核 + 可选 HMAC 验签）。

        - manifest_hash 复核（始终执行，覆盖含签名的整体内容）：不符即
          ManifestFreezeError——冻结件被篡改或损坏。
        - keyring 给定时验签：无签名默认拒（仅诊断可显式 allow_unsigned
          降级）；signature/key_id 残缺、key 未登记、key 已吊销、HMAC
          不符一律 ManifestFreezeError（fail-closed——重算 manifest_hash
          洗不掉签名，无密钥不可伪造）。
        - keyring 缺省：hash 复核即全部信任根（legacy 口径；正门验签由
          CLI --verify-key 强制，见 wenquctl gate）。
        """
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
        signature = data.get("signature")
        key_id = data.get("key_id")
        if keyring is not None:
            if signature is None and key_id is None:
                if not allow_unsigned:
                    raise ManifestFreezeError(
                        f"{path}: manifest 无签名（R7-GATE-MANIFEST-AUTH-001："
                        "正门冻结件必须由 release/manifest 专用 key 签发；"
                        "仅诊断用途可显式 allow-unsigned）"
                    )
            elif signature is None or key_id is None:
                raise ManifestFreezeError(
                    f"{path}: manifest 签名字段残缺（signature/key_id 必须成对）"
                )
            elif not isinstance(key_id, str) or not keyring.has(key_id):
                raise ManifestFreezeError(
                    f"{path}: manifest 签名 key_id {key_id!r} 未在验签 keyring "
                    "登记（未知 key——fail-closed 拒绝）"
                )
            else:
                # HMAC 覆盖 manifest_hash 外全部内容（含 key_id）；
                # keyring.verify 同时执行 revoked 验签即拒 + 常量时间比对。
                envelope = {k: v for k, v in data.items() if k != "manifest_hash"}
                if not keyring.verify(envelope):
                    raise ManifestFreezeError(
                        f"{path}: manifest 签名验签失败（R7-GATE-MANIFEST-"
                        "AUTH-001：内容与签发时不符或 key 已吊销——冻结件"
                        "被篡改/伪造）"
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
            # R7-GATE-MANIFEST-AUTH-001：station_ttls 容缺失读入（默认空），
            # 删 TTL 类攻击交 validate_manifest_consistency 记 BLOCKED，
            # 而不是在解析层塌缩成 ERROR（结构面/语义面分流）。
            station_ttls={int(k): int(v)
                          for k, v in dict(data.get("station_ttls") or {}).items()},
            manifest_hash=data["manifest_hash"],
            signature=data.get("signature"),
            key_id=data.get("key_id"),
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
    signing_keyring: Optional[ApprovalKeyring] = None,
    signing_key_id: Optional[str] = None,
) -> RunManifest:
    """冻结 run-manifest.json 的内容（返回 RunManifest，由调用方 .save() 落盘）。

    绑定（不变量 #2/#3）：run_id + commit_sha + environment + scope_hash +
    ruleset_hash + data_config_hash + required 站集合 + 各站 TTL。
    run 起跑后任一指纹变化 → 旧证据立即失效，须重新冻结（新 run）。

    签名面（R7-GATE-MANIFEST-AUTH-001）：signing_keyring 给定时以
    release/manifest 专用 key 对 manifest 签发 ``signature``+``key_id``
    （HMAC-SHA256，覆盖 key_id 外全部内容）；``manifest_hash`` 覆盖含签名
    的整体内容。key 解析 fail-closed：多 active key 未显式指定
    signing_key_id、key rotated/revoked/expired/未登记一律
    ManifestFreezeError（绝不猜 key、绝不用不可签发态的 key）。
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

    # -- 签名面（R7-GATE-MANIFEST-AUTH-001）---------------------------------
    # 签发 key 解析：显式 signing_key_id > 唯一 active key；绝不猜。
    resolved_key_id: Optional[str] = None
    signature: Optional[str] = None
    if signing_keyring is not None:
        if not isinstance(signing_keyring, ApprovalKeyring):
            raise ManifestFreezeError(
                "signing_keyring must be an ApprovalKeyring, got "
                f"{type(signing_keyring).__name__}"
            )
        active = signing_keyring.active_key_ids()
        if signing_key_id is None:
            if len(active) != 1:
                raise ManifestFreezeError(
                    "signing_key_id 必须显式指定（active key 数="
                    f"{len(active)}：{active or '无 active key'}）——"
                    "manifest 签发不得猜 key（R7-GATE-MANIFEST-AUTH-001）"
                )
            resolved_key_id = active[0]
        else:
            resolved_key_id = signing_key_id
        try:
            secret = signing_keyring.get_for_signing(resolved_key_id)
        except (KeyNotFoundError, KeyStateError) as exc:
            raise ManifestFreezeError(
                f"manifest 签发 key 不可用（{resolved_key_id!r}）: {exc}"
            ) from exc

    if resolved_key_id is not None:
        # 签名覆盖 key_id 外全部内容；manifest_hash 覆盖含签名的整体。
        signature = sign_envelope(secret, {**body, "key_id": resolved_key_id})
        manifest_hash = _hash_obj(
            {**body, "key_id": resolved_key_id, "signature": signature})
    else:
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
        signature=signature,
        key_id=resolved_key_id,
    )


# ---------------------------------------------------------------------------
# manifest 自一致性校验（R7-GATE-MANIFEST-AUTH-001 洞1 修·独立于签名）
# ---------------------------------------------------------------------------

def validate_manifest_consistency(data: Any) -> List[str]:
    """run-manifest 冻结面的自一致性校验（对原始 JSON dict）；返回违例清单。

    第七轮反例（R7-GATE-MANIFEST-AUTH-001）：篡改顶层 required=[0,1]→[0]
    保留 planner.required=[0,1]、删 station_ttls、自报 scope.denominator——
    攻击者无密钥也可重算 manifest_hash（纯 hash 无信任根）。本校验独立于
    签名：顶层与 planner 的 required/TTL、scope 与分母、identity 三源任何
    不一致都记违例，由 CLI 记 manifest_consistency_violation 并整线
    BLOCKED（即使签名合法或显式 --allow-unsigned 诊断降级也不例外）。
    """
    issues: List[str] = []

    def _err(msg: str) -> None:
        issues.append(msg)

    if not isinstance(data, Mapping):
        return ["manifest must be a JSON object"]

    if data.get("schema_version") != SCHEMA_VERSION:
        _err(f"schema_version must be {SCHEMA_VERSION!r}, got {data.get('schema_version')!r}")
    if data.get("manifest_kind") != "bugscan/run-manifest":
        _err(f"manifest_kind must be 'bugscan/run-manifest', got {data.get('manifest_kind')!r}")

    top_req = data.get("required_stations")
    if not isinstance(top_req, list) or not top_req or not all(
            isinstance(i, int) and not isinstance(i, bool) and 0 <= i <= 7
            for i in top_req):
        _err(f"required_stations must be a non-empty list of station ids 0-7, "
             f"got {top_req!r}")
        top_req = None
    elif sorted(set(top_req)) != sorted(top_req):
        _err(f"required_stations must be sorted-unique, got {top_req!r}")

    planner = data.get("planner")
    if not isinstance(planner, Mapping):
        _err("planner section missing/malformed")
    else:
        plan_req = planner.get("required_stations")
        if not isinstance(plan_req, list) or not plan_req:
            _err(f"planner.required_stations must be a non-empty list, got {plan_req!r}")
        elif top_req is not None and sorted(plan_req) != sorted(top_req):
            _err(f"required_stations_conflict: top-level {sorted(top_req)} != "
                 f"planner {sorted(plan_req)}（第七轮反例：顶层缩水 required 洗白）")
        if planner.get("lane_effective") not in LANE_REQUIRED_STATIONS:
            _err(f"planner.lane_effective must be one of {LANES}, "
                 f"got {planner.get('lane_effective')!r}")
        rounds = planner.get("convergence_rounds")
        if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 1:
            _err(f"planner.convergence_rounds must be an int >= 1, got {rounds!r}")

    ttls = data.get("station_ttls")
    if not isinstance(ttls, Mapping):
        _err(f"station_ttls must be an object, got {type(ttls).__name__}")
    else:
        expected_keys = sorted(str(i) for i in (top_req or []))
        if sorted(ttls) != expected_keys:
            _err(f"station_ttls_conflict: keys {sorted(ttls)} != required set "
                 f"{expected_keys}（删 TTL/漂移 TTL 都不得按缩水口径上绿）")
        for key, value in ttls.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                _err(f"station_ttls[{key!r}] must be an int >= 1, got {value!r}")

    scope = data.get("scope")
    if not isinstance(scope, Mapping):
        _err(f"scope section missing/malformed, got {type(scope).__name__}")
    else:
        paths = scope.get("paths")
        if (not isinstance(paths, list) or not paths
                or not all(isinstance(p, str) and p.strip() for p in paths)):
            _err("scope.paths must be a non-empty list of non-empty strings")
            paths = None
        denom = scope.get("denominator")
        if (paths is not None
                and (isinstance(denom, bool) or not isinstance(denom, int)
                     or denom != len(paths))):
            _err(f"scope_denominator_conflict: denominator {denom!r} != "
                 f"len(paths)={len(paths) if paths is not None else '?'}")
        exclusions = scope.get("exclusions", [])
        if not isinstance(exclusions, list) or not all(
                isinstance(e, str) for e in exclusions):
            _err("scope.exclusions must be a list of strings")

    identity = data.get("identity")
    if not isinstance(identity, Mapping):
        _err(f"identity section missing/malformed, got {type(identity).__name__}")
    else:
        sha = identity.get("commit_sha")
        if not isinstance(sha, str) or not _RE_SHA40.match(sha):
            _err("identity.commit_sha must be a 40-char lowercase hex commit SHA")
        if identity.get("environment") not in ENVIRONMENTS:
            _err(f"identity.environment must be one of {ENVIRONMENTS}, "
                 f"got {identity.get('environment')!r}")
        for hash_field in ("scope_hash", "ruleset_hash", "data_config_hash"):
            value = identity.get(hash_field)
            if not isinstance(value, str) or not _RE_SHA64.match(value):
                _err(f"identity.{hash_field} must be a 64-hex digest, got {value!r}")

    for text_field in ("registry_version", "registry_digest"):
        value = data.get(text_field)
        if not isinstance(value, str) or not value.strip():
            _err(f"{text_field} must be a non-empty string")
    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not _RE_RUN_ID.match(run_id):
        _err(f"run_id must match {_RE_RUN_ID.pattern}, got {run_id!r}")

    signature = data.get("signature")
    key_id = data.get("key_id")
    if (signature is None) != (key_id is None):
        _err("signature/key_id must appear as a pair (half-signed manifest)")

    return issues


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

        # 站1 工件：gate 原始结果自身的内容寻址摘要（PASS 必须携带非空工件——
        # station-result-v2 契约；非 PASS 附带同样合法且利于审计对账）
        gate_payload = json.dumps(
            dict(gate_result), separators=(",", ":"),
            ensure_ascii=False, sort_keys=True).encode("utf-8")
        artifact = [{
            "cas_digest": f"sha256:{_sha256_hex(gate_payload)}",
            "size": len(gate_payload),
        }]

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
            artifacts=artifact,
        )


# ---------------------------------------------------------------------------
# 收敛环参数域与轮数熔断（GATE-09/GATE-10/GATE-11，§20.1）
# ---------------------------------------------------------------------------

def validate_convergence_rounds(
    rounds: Any,
    *,
    lane: Optional[str] = None,
    upper: Optional[int] = None,
) -> int:
    """GATE-09：编排器入口的收敛轮数 N 值域检查（§20.1 注入：-1/0/超上限）。

    - 非整数/布尔 → 参数错误（bool 是 int 子类，显式拒绝）；
    - N < 1（含 -1、0）→ 参数错误。编排器域内 N=0 不是「关闭收敛」开关
      （那是 cli/wenqu verify --convergence 0 的查询侧语义）；bugscan 收敛
      契约要求至少 1 轮异源实扫，0 轮即免检；
    - N > 上限 → 参数错误。上限缺省=最高档 INCIDENT 收敛轮数
      （CONVERGENCE_ROUNDS_MAX=3）——更大的 N 等于把「N+1 熔断」推成
      无限递归；
    - 给定 lane 时：lane 必须已知，且 N 不得低于该档契约轮数
      （降档收敛环=弱化铁律 5，按参数错误拒绝，降档须走风险接受）。

    返回通过校验的 N（int）；违规抛 ConvergenceRoundsError（参数错误，
    拒绝开跑——绝不静默钳制）。
    """
    if isinstance(rounds, bool) or not isinstance(rounds, int):
        raise ConvergenceRoundsError(
            f"convergence rounds N must be an int (not bool), got {rounds!r} "
            "(GATE-09 参数错误)"
        )
    cap = CONVERGENCE_ROUNDS_MAX if upper is None else int(upper)
    if rounds < CONVERGENCE_ROUNDS_MIN:
        raise ConvergenceRoundsError(
            f"convergence rounds N={rounds} 非法（GATE-09 参数错误）：须 "
            f"N >= {CONVERGENCE_ROUNDS_MIN}（-1/0 一律拒绝；编排器域内不存在"
            "『N=0 关闭收敛』开关——收敛契约至少 1 轮异源实扫）"
        )
    if rounds > cap:
        raise ConvergenceRoundsError(
            f"convergence rounds N={rounds} 超上限（GATE-09 参数错误）："
            f"须 N <= {cap}（N+1 轮熔断上限的递归预算不得放大）"
        )
    if lane is not None:
        if lane not in LANE_CONVERGENCE_ROUNDS:
            raise BugscanPlanError(
                f"unknown lane {lane!r}; expected one of {LANES}"
            )
        floor = LANE_CONVERGENCE_ROUNDS[lane]
        if rounds < floor:
            raise ConvergenceRoundsError(
                f"convergence rounds N={rounds} 低于 {lane} 档收敛契约 "
                f"N={floor}（GATE-09 参数错误：降档收敛环须风险接受记录，"
                "不得以参数覆盖弱化）"
            )
    return rounds


def normalized_argv_digest(argv: Any) -> str:
    """GATE-11：命令身份摘要（argv 规范化摘要）。

    规范化规则（确定性、无环境依赖）：
    1. 必须是非空序列且逐元素为 str（拒绝单个命令字符串/空 argv/非 str 元素）；
    2. 逐元素 strip 并丢弃空串；
    3. argv[0] 取 basename——`/usr/bin/python3 scan.py` 与 `python3 scan.py`
       是同一命令身份（解释器/工具的安装路径前缀不构成异源）；
    4. 摘要 = 规范化 argv 列表的 canonical JSON sha256（hex）。

    同摘要 = 同命令身份 = 同一异源轮来源；换 S 标签不改变摘要。
    """
    if isinstance(argv, (str, bytes)):
        raise ValueError(
            "argv must be a sequence of argument strings, not a single "
            f"command string (got {type(argv).__name__})"
        )
    try:
        items = list(argv)
    except TypeError as exc:
        raise ValueError(
            f"argv must be an iterable of strings, got {type(argv).__name__}"
        ) from exc
    if not items:
        raise ValueError("argv must not be empty")
    normalized: List[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError(
                f"argv elements must be str, got {type(item).__name__}: {item!r}"
            )
        text = item.strip()
        if text:
            normalized.append(text)
    if not normalized:
        raise ValueError("argv normalizes to empty (all elements are whitespace)")
    normalized[0] = os.path.basename(normalized[0])
    return _sha256_hex(
        json.dumps(normalized, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )


#: 追踪器状态机：RUNNING →（收敛）CONVERGED /（跑满 N+1 未收敛）BLOCKED
#: →（人工裁定）CONTINUE→RUNNING（预算恰好 +1 轮）/ STOP→STOPPED（终态）。
TRACKER_STATE_RUNNING = "RUNNING"
TRACKER_STATE_CONVERGED = "CONVERGED"
TRACKER_STATE_BLOCKED = "BLOCKED"
TRACKER_STATE_STOPPED = "STOPPED"


class ConvergenceTracker:
    """GATE-10/GATE-11：异源收敛环轮数追踪器（§20.1）。

    - 异源轮身份（GATE-11）：一轮异源实扫的身份=命令身份
      （normalized_argv_digest）。同命令重跑/换 S 标签 → duplicate，不推进
      异源轮计数、不进入收敛窗口（「同命令换 S 标签不计异源轮」）；
      命令身份不同才计新异源轮（来源标签只是审计元数据）。
    - 收敛判据（铁律 5）：最近连续 N 个异源轮 new_findings 全为 0。
    - 轮数熔断（GATE-10）：异源轮数达到 N+1 仍未收敛 → 状态 BLOCKED +
      「等待人工裁定」记录；此后任何 record_round（含自动重试）抛
      ConvergenceRoundCapExceeded——不自动重试、不自动扩预算；
      人工裁定 adjudicate(CONTINUE) 每次恰好放行 +1 轮预算，
      adjudicate(STOP) 终态关闭。

    状态只进不退：CONVERGED/STOPPED 后不再接受任何轮次（新发现须新 run）。
    """

    def __init__(self, plan: BugscanPlan, *, now: Optional[datetime] = None) -> None:
        if not isinstance(plan, BugscanPlan):
            raise TypeError(
                f"plan must be BugscanPlan, got {type(plan).__name__}"
            )
        # GATE-09 双保险：伪造 plan（N=-1/0/超上限）在构造期即参数错误。
        self._n = validate_convergence_rounds(
            plan.convergence_rounds, lane=plan.lane_effective
        )
        self._state: str = TRACKER_STATE_RUNNING
        self._hetero: List[Dict[str, Any]] = []   # 异源轮序列（每身份一条）
        self._log: List[Dict[str, Any]] = []      # 全部提交记录（含重复轮）
        self._identities: Dict[str, str] = {}     # argv_digest → 首见来源标签
        self._duplicates = 0
        self._relabels = 0
        self._extensions = 0                      # 人工裁定放行预算（每次 +1）
        self._awaiting: Optional[Dict[str, Any]] = None
        self._adjudications: List[Dict[str, Any]] = []
        self._now = now

    # -- 属性 ---------------------------------------------------------------
    @property
    def n(self) -> int:
        return self._n

    @property
    def round_cap(self) -> int:
        """当前异源轮预算上限 = N + 1 + 人工裁定放行数（GATE-10）。"""
        return self._n + 1 + self._extensions

    @property
    def state(self) -> str:
        return self._state

    # -- 记轮 ---------------------------------------------------------------
    def record_round(
        self,
        *,
        argv: Sequence[str],
        source_label: str,
        new_findings: int,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """记录一轮实扫提交；返回最新 status 快照。

        - source_label（S 标签）必须非空 str——标签参与审计但不参与身份；
        - new_findings 必须为 ≥0 的 int（bool 拒绝）；
        - BLOCKED/CONVERGED/STOPPED 态下一律拒绝追加（GATE-10 非自动重试；
          CONVERGED/STOPPED 后新发现须开新 run）。
        """
        if not isinstance(source_label, str) or not source_label.strip():
            raise ValueError(
                "source_label (S 标签) must be a non-empty string"
            )
        if isinstance(new_findings, bool) or not isinstance(new_findings, int) \
                or new_findings < 0:
            raise ValueError(
                f"new_findings must be an int >= 0, got {new_findings!r}"
            )
        if self._state == TRACKER_STATE_BLOCKED:
            raise ConvergenceRoundCapExceeded(
                f"round cap 已跑满（N={self._n}，cap={self.round_cap}）且未收敛："
                "状态=BLOCKED 等待人工裁定——禁止自动重试追加轮次（GATE-10）；"
                "解锁唯一通道=adjudicate(decision, approver=…)"
            )
        if self._state == TRACKER_STATE_STOPPED:
            raise ConvergenceRoundCapExceeded(
                "人工裁定 STOP 已终态关闭本收敛环——新扫描须开新 run（GATE-10）"
            )
        if self._state == TRACKER_STATE_CONVERGED:
            raise ConvergenceRoundCapExceeded(
                "收敛环已 CONVERGED 关闭——收敛后追加轮次无契约意义，新扫描须开新 run"
            )

        digest = normalized_argv_digest(argv)
        label = source_label.strip()
        ts = _iso_z(now if now is not None else (self._now or _utc_now()))
        counted = digest not in self._identities
        relabel_only = False
        if counted:
            self._identities[digest] = label
            self._hetero.append({
                "seq": len(self._hetero) + 1,
                "argv_digest": digest,
                "source_label": label,
                "new_findings": new_findings,
                "recorded_at": ts,
            })
        else:
            self._duplicates += 1
            relabel_only = self._identities[digest] != label
            if relabel_only:
                self._relabels += 1  # GATE-11：换标签不铸造新异源轮，只记账
        self._log.append({
            "seq": len(self._log) + 1,
            "argv_digest": digest,
            "source_label": label,
            "new_findings": new_findings,
            "counted_as_heterogeneous": counted,
            "relabel_only_duplicate": relabel_only,
            "recorded_at": ts,
        })

        # 收敛判据：最近连续 N 个异源轮零新发现（铁律 5）
        converged = (
            len(self._hetero) >= self._n
            and all(r["new_findings"] == 0 for r in self._hetero[-self._n:])
        )
        if converged:
            self._state = TRACKER_STATE_CONVERGED
        elif len(self._hetero) >= self.round_cap:
            # GATE-10：跑满 N+1（含人工放行预算）未收敛 → 熔断等人工裁定
            self._state = TRACKER_STATE_BLOCKED
            self._awaiting = {
                "required": True,
                "reason": "round_cap_exceeded",
                "n": self._n,
                "round_cap": self.round_cap,
                "heterogeneous_rounds": len(self._hetero),
                "decision": None,
                "escalated_at": ts,
                "note": "跑满 N+1 轮未收敛——停止递归转人工裁定，禁止自动重试",
            }
        return self.status()

    # -- 人工裁定（GATE-10 唯一解锁通道）------------------------------------
    def adjudicate(
        self,
        decision: str,
        *,
        approver: str,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """人工裁定：CONTINUE=放行恰好 +1 轮预算回到 RUNNING；STOP=终态。

        只在 BLOCKED（等待人工裁定）态可调用；approver 必须非空（裁定留痕）；
        decision 只认 CONTINUE/STOP（大小写不敏感）。
        """
        if self._state != TRACKER_STATE_BLOCKED:
            raise ConvergenceRoundCapExceeded(
                f"adjudicate 仅在 BLOCKED 等人工裁定态可调用，当前 state={self._state}"
            )
        if not isinstance(approver, str) or not approver.strip():
            raise ValueError(
                "人工裁定必须登记裁定人（approver 非空）——匿名裁定无效"
            )
        verdict = (
            decision.strip().upper() if isinstance(decision, str) else ""
        )
        if verdict not in ("CONTINUE", "STOP"):
            raise ValueError(
                f"decision 只认 CONTINUE/STOP，got {decision!r}（GATE-10："
                "熔断后不存在第三种机器可执行的走向）"
            )
        ts = _iso_z(now if now is not None else (self._now or _utc_now()))
        record = {
            "decision": verdict,
            "approver": approver.strip(),
            "decided_at": ts,
            "heterogeneous_rounds": len(self._hetero),
        }
        self._adjudications.append(record)
        assert self._awaiting is not None  # BLOCKED 态必已建账
        self._awaiting = {
            **self._awaiting,
            "decision": verdict,
            "decided_by": approver.strip(),
            "decided_at": ts,
        }
        if verdict == "CONTINUE":
            self._extensions += 1  # 每次人工放行恰好 +1 轮，不放大不自动续
            self._state = TRACKER_STATE_RUNNING
        else:
            self._state = TRACKER_STATE_STOPPED
        return self.status()

    # -- 快照 ---------------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        return {
            "n": self._n,
            "round_cap": self.round_cap,
            "state": self._state,
            "converged": self._state == TRACKER_STATE_CONVERGED,
            "heterogeneous_rounds": len(self._hetero),
            "total_rounds_recorded": len(self._log),
            "duplicate_rounds_ignored": self._duplicates,
            "relabel_only_duplicates": self._relabels,
            "awaiting_human_adjudication": (
                dict(self._awaiting) if self._awaiting else None
            ),
            "adjudications": [dict(a) for a in self._adjudications],
            "heterogeneous_sequence": [dict(r) for r in self._hetero],
            "round_log": [dict(r) for r in self._log],
        }


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

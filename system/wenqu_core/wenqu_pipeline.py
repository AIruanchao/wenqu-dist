# -*- coding: utf-8 -*-
"""wenqu_pipeline.py——P0-2 七段状态机 + 九类停等 + 审批消费（Codex 方案 W5）。

机器可判定契约正源：``docs/specs/wenqu-vNext-contract.md``（冻结 v1.0）。
任何与此契约不一致的实现均为实现缺陷。本模块实现其中四件核心：

1. ``SevenStageStateMachine``——七段枚举与转换规则（纯规则引擎，无 IO）：
   - 七段：S1_REQUIREMENT → S2_SOLUTION → S3_EQS_PRE → S4_IMPLEMENT
     → S5_CONVERGENCE → S6_EQS_FULL → S7_GATE，顺序不可倒；
   - 前段非 PASSED 不得启动后段（字面从严：CONDITIONAL 亦不可放行后段）；
   - Run 状态机：CREATED | RUNNING | WAITING | FAILED | SUCCEEDED
     | COMPLETED_CONDITIONAL | CANCELLED | SUPERSEDED（契约 §3/§5）；
   - 段 attempt 状态机：PENDING | RUNNING | PASSED | COMPLETED_CONDITIONAL
     | FAILED | WAITING | CANCELLED——attempt 一旦终态即不可变，
     重试/恢复一律创建新 attempt_id（契约 §5，"attempt 不可变"）；
   - 注意：契约 §5 的 attempt 转换表中不存在 WAITING → RUNNING——
     因此 WAITING 恢复时旧 attempt 停留在 WAITING，由新 attempt 继续。

2. ``NineStopTypes``——九类停等（契约 §6）与各类恢复的必要且充分条件：
   - 必要：一次性授权（nonce 一次性消费）+ 客观前置条件齐备，两者缺一不可；
   - 充分：两者齐备后 resume 必须放行——实现不得附加任何自由裁量阻断。

3. ``ApprovalBroker``——消费 approval-v2 schema（``schemas/approval-v2.schema.json``）
   格式的审批事件。fail-closed 校验（任一不过即拒绝，绝不静默择优）：
   - 结构校验：镜像 schema 的 required/enum/pattern/minLength/payload 判别联合；
   - 一次性：nonce 经 ``approval_consumptions`` 表 PRIMARY KEY 约束原子消费，
     并发双消费第二个必然失败（不变量 #4/#5"审批不能复用"）；
   - 绑定：run_id / stop_event_id（精确锚定引发停等的那条链上事件）/
     stop_type / stage / environment / authorized_scope（=scope_hash，
     不得扩范围）/ input_watermark（=commit_sha，不得跨 SHA）；
   - TTL：issued_at <= now < expires_at；
   - state_version CAS：approval.expected_state_version 必须等于消费时的
     run 当前 state_version（不得跨状态版本消费）；
   - 原子性：nonce 消费与 WAITING_RESUMED 事件追加在**同一个**
     BEGIN IMMEDIATE 事务内对同一 SQLite 文件完成——事务持有独占写锁，
     "校验→占 nonce→链式插入事件"三步不可分割，崩溃即整体回滚。

4. ``RunManager``——七段 run 的编排与终态判定（事件正源 = EventStore）：
   - 全部可变状态由 ``pipeline_events`` 重放（replay）推导，本模块不持有
     任何 run 的第二份正源；控制事件只追加（不变量 #6）；
   - 每个状态变更事件携带 state_version（单调 +1），重放时校验单调性，
     与 BEGIN IMMEDIATE 一起构成全转换的乐观并发控制；
   - ``complete_run`` 终态判定：七段全 PASSED → SUCCEEDED；
     末段 COMPLETED_CONDITIONAL 且存在已消费、未过期的 risk 授权 →
     COMPLETED_CONDITIONAL（否则 fail-closed 拒绝）；其余 → FAILED。

事件载荷遵守 ``schemas/run-event-v2.schema.json`` 词表。已知扩展（内部字段，
对外交换仍以 schema 为准，此处显式声明偏离）：WAITING_RAISED/WAITING_RESUMED
携带 ``stop_type``/``stop_reason``/``required_preconditions``/``approval_id``/
``nonce_digest``/``preconditions_hash`` 等停等元数据——schema 的 run 事件
词表未覆盖停等绑定信息，而 approval-v2 的 stop_event_id 需要可锚定的正源。
stop_event_id 取值为对应 WAITING_RAISED 事件在哈希链中的 event_hash（64 hex）。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .store import GENESIS_HASH, EventStore

__all__ = [
    "SevenStageStateMachine",
    "NineStopTypes",
    "ApprovalBroker",
    "RunManager",
    "RunState",
    "StageState",
    "StageAttempt",
    "WaitingInfo",
    "PipelineError",
    "InvalidTransitionError",
    "StageOrderError",
    "AttemptImmutabilityError",
    "RunNotFoundError",
    "TerminalRunError",
    "InvalidOutcomeError",
    "InvalidIdentityError",
    "PipelineCorruptionError",
    "ApprovalError",
    "ApprovalRejected",
    "ApprovalReuseError",
    "ApprovalPreconditionError",
]

# ====================================================================== #
# 契约常量（wenqu-vNext-contract.md §1/§3/§4/§5/§6 逐字收敛）
# ====================================================================== #

STAGES: Tuple[str, ...] = (
    "S1_REQUIREMENT",
    "S2_SOLUTION",
    "S3_EQS_PRE",
    "S4_IMPLEMENT",
    "S5_CONVERGENCE",
    "S6_EQS_FULL",
    "S7_GATE",
)

# Run 总状态（契约 §3）
RUN_CREATED_S = "CREATED"
RUN_RUNNING_S = "RUNNING"
RUN_WAITING_S = "WAITING"
RUN_FAILED_S = "FAILED"
RUN_SUCCEEDED_S = "SUCCEEDED"
RUN_COMPLETED_CONDITIONAL_S = "COMPLETED_CONDITIONAL"
RUN_CANCELLED_S = "CANCELLED"
RUN_SUPERSEDED_S = "SUPERSEDED"

RUN_STATES: Tuple[str, ...] = (
    RUN_CREATED_S, RUN_RUNNING_S, RUN_WAITING_S, RUN_FAILED_S,
    RUN_SUCCEEDED_S, RUN_COMPLETED_CONDITIONAL_S, RUN_CANCELLED_S,
    RUN_SUPERSEDED_S,
)
TERMINAL_RUN_STATES = frozenset(
    {RUN_FAILED_S, RUN_SUCCEEDED_S, RUN_COMPLETED_CONDITIONAL_S,
     RUN_CANCELLED_S, RUN_SUPERSEDED_S}
)

# Run 允许转换（契约 §5，唯一）
RUN_TRANSITIONS: Dict[str, frozenset] = {
    RUN_CREATED_S: frozenset({RUN_RUNNING_S, RUN_CANCELLED_S}),
    RUN_RUNNING_S: frozenset({
        RUN_WAITING_S, RUN_FAILED_S, RUN_SUCCEEDED_S,
        RUN_COMPLETED_CONDITIONAL_S, RUN_CANCELLED_S, RUN_SUPERSEDED_S,
    }),
    RUN_WAITING_S: frozenset({
        RUN_RUNNING_S, RUN_FAILED_S, RUN_CANCELLED_S, RUN_SUPERSEDED_S,
    }),
}

# 段 attempt 状态（契约 §4）
ATTEMPT_PENDING = "PENDING"
ATTEMPT_RUNNING = "RUNNING"
ATTEMPT_PASSED = "PASSED"
ATTEMPT_COMPLETED_CONDITIONAL = "COMPLETED_CONDITIONAL"
ATTEMPT_FAILED = "FAILED"
ATTEMPT_WAITING = "WAITING"
ATTEMPT_CANCELLED = "CANCELLED"

ATTEMPT_STATES: Tuple[str, ...] = (
    ATTEMPT_PENDING, ATTEMPT_RUNNING, ATTEMPT_PASSED,
    ATTEMPT_COMPLETED_CONDITIONAL, ATTEMPT_FAILED, ATTEMPT_WAITING,
    ATTEMPT_CANCELLED,
)
TERMINAL_ATTEMPT_STATES = frozenset(
    {ATTEMPT_PASSED, ATTEMPT_COMPLETED_CONDITIONAL, ATTEMPT_FAILED,
     ATTEMPT_WAITING, ATTEMPT_CANCELLED}
)

# 段 attempt 允许转换（契约 §5，唯一）
ATTEMPT_TRANSITIONS: Dict[str, frozenset] = {
    ATTEMPT_PENDING: frozenset({ATTEMPT_RUNNING, ATTEMPT_CANCELLED}),
    ATTEMPT_RUNNING: frozenset({
        ATTEMPT_PASSED, ATTEMPT_COMPLETED_CONDITIONAL, ATTEMPT_FAILED,
        ATTEMPT_WAITING, ATTEMPT_CANCELLED,
    }),
}

# 统一结果双轴（契约 §2 / run-event-v2）
EXECUTION_STATUSES = frozenset(
    {"COMPLETED", "ERROR", "BLOCKED", "TIMEOUT", "CANCELLED"}
)
POLICY_VERDICTS = frozenset(
    {"PASS", "FAIL", "CONDITIONAL", "NOT_APPLICABLE", "NOT_EVALUATED"}
)
ENVIRONMENTS = frozenset({"local", "staging", "production"})


class NineStopTypes(str, Enum):
    """九类停等（契约 §6）——枚举值与 approval-v2 schema 的 stop_type 完全一致。"""

    AMBIGUITY = "ambiguity"        # 需求歧义：授权 + 新需求四要素与 scope hash 冻结
    PROD_WRITE = "prod-write"      # 生产写：exact-scope 授权 + 前置 Gate + 回滚级别
    DDL = "ddl"                    # DDL：exact DDL/环境授权 + 四重验证 + 回滚
    RELEASE = "release"            # 发布：exact release/SHA/env 授权 + Gate/manifest/回滚预案
    SCOPE = "scope"                # 范围变更：新 scope 授权 + 风险/required 集/证据重冻结
    FUND_AUTH = "fund-auth"        # 资金/权限：授权 + 正负测试 + 守恒/审计
    EXM_FUSE = "exm-fuse"          # 豁免熔断：裁定授权 + 实际解除或独立治理裁定
    RESOURCE = "resource"          # 资源不足：恢复授权 + 探针恢复 + 安全余量
    EXT_UNAVAIL = "ext-unavail"    # 外部依赖不可用：恢复授权 + 依赖探针恢复 + 证据重验

    def __str__(self) -> str:  # str 枚举直接以值参与 JSON 序列化
        return self.value


# 各停等类型的客观前置条件规格（恢复的"必要且充分条件"的客观半边）。
# required：全部键必须存在且取值非空；any_of：至少一组全部非空。
# 一次性授权（审批消费）是另一半边——两者同时满足 = 充分，缺一 = 不必要地阻断。
STOP_PRECONDITION_SPECS: Dict[str, Dict[str, Tuple[Tuple[str, ...], ...]]] = {
    "ambiguity": {
        "description": "一次性授权 + 新需求四要素与 scope hash 冻结",
        "required": (("requirement_four_elements",), ("scope_hash",)),
        "any_of": (),
    },
    "prod-write": {
        "description": "一次性 exact-scope 授权 + 对应前置 Gate + 回滚级别",
        "required": (("gate_reference",), ("rollback_level",)),
        "any_of": (),
    },
    "ddl": {
        "description": "一次性 exact DDL/环境授权 + fresh/legacy/minimal/回滚验证",
        "required": (
            ("ddl_statement_digest", "environment"),
            ("verification_fresh", "verification_legacy", "verification_minimal"),
            ("rollback_verified",),
        ),
        "any_of": (),
    },
    "release": {
        "description": "一次性 exact release/SHA/env 授权 + Gate/manifest/回滚预案",
        "required": (
            ("release_id", "commit_sha", "environment"),
            ("gate_reference", "manifest_sha256", "rollback_plan"),
        ),
        "any_of": (),
    },
    "scope": {
        "description": "一次性新 scope 授权 + 风险、required 集和证据重新冻结",
        "required": (
            ("new_scope_hash",),
            ("risk_refrozen", "required_set_refrozen", "evidence_refrozen"),
        ),
        "any_of": (),
    },
    "fund-auth": {
        "description": "一次性资金/权限授权 + 正负测试 + 守恒/审计",
        "required": (
            ("fund_subject_role", "positive_test_ref", "negative_test_ref"),
            ("conservation_check", "audit_target"),
        ),
        "any_of": (),
    },
    "exm-fuse": {
        "description": "一次性裁定授权 + 实际解除熔断或完成独立治理裁定",
        "required": (("adjudication_ref",),),
        "any_of": ((("fuse_lifted_evidence",), ("independent_ruling_ref",)),),
    },
    "resource": {
        "description": "一次性恢复授权 + 资源探针恢复并满足安全余量",
        "required": (("resource_probe_ref", "probe_recovered", "safety_margin_met"),),
        "any_of": (),
    },
    "ext-unavail": {
        "description": "一次性恢复授权 + 外部依赖健康探针恢复并重验证据新鲜度",
        "required": (("dependency_probe_ref", "probe_recovered",
                      "evidence_freshness_reverified"),),
        "any_of": (),
    },
}

# ====================================================================== #
# approval-v2 结构规格（镜像 schemas/approval-v2.schema.json）
# ====================================================================== #

_APPROVAL_SCHEMA_VERSION = "2.0"
_APPROVAL_REQUIRED_TOP = (
    "schema_version", "approval_id", "approval_type", "run_id", "stop_event_id",
    "stop_type", "actor", "issued_at", "expires_at", "nonce", "decision",
    "signature", "payload",
)
_APPROVAL_ALLOWED_TOP = frozenset(_APPROVAL_REQUIRED_TOP) | frozenset({
    "task_id", "stage", "environment", "authorized_scope", "policy_hash",
    "ruleset_hash", "input_watermark", "expected_state_version",
})
_APPROVAL_TYPES = frozenset({
    "resume", "risk", "merge", "release", "ddl", "prod_write",
    "fund_auth", "rollback",
})
_APPROVAL_DECISIONS = frozenset({"approve", "deny", "conditional"})
# payload 判别联合：按 approval_type 必须含的专属字段（schema oneOf）
_APPROVAL_PAYLOAD_DISCRIMINATOR: Dict[str, Tuple[str, ...]] = {
    "resume": ("stop_event_id", "stop_type", "objective_precondition_hash"),
    "risk": ("finding_fingerprints", "severity", "reason",
             "compensating_controls", "expiry"),
    "merge": ("repo_id", "base_sha", "head_sha", "merge_method"),
    "release": ("release_id", "artifact_sha256", "manifest_sha256",
                "environment", "previous_release_id"),
    "ddl": ("database_identity", "statement_digest", "before_schema_hash",
            "after_schema_hash", "backup_id", "rollback_plan_hash"),
    "prod_write": ("operation_digest", "data_scope_digest",
                   "idempotency_key", "conservation_hash"),
    "fund_auth": ("subject_role", "amount_scope_digest",
                  "positive_negative_test_hash", "audit_target"),
    "rollback": ("failed_deployment_id", "exact_previous_release_id",
                 "trigger", "schema_compatibility_hash"),
}

# ====================================================================== #
# 异常
# ====================================================================== #


class PipelineError(RuntimeError):
    """管线基础错误。"""


class InvalidTransitionError(PipelineError):
    """违反契约 §5 允许转换表的状态跳变。"""

    def __init__(self, kind: str, current: str, new: str) -> None:
        super().__init__(
            f"illegal {kind} transition: {current} -> {new} "
            f"(allowed table: contract §5)"
        )
        self.kind, self.current, self.new = kind, current, new


class StageOrderError(PipelineError):
    """违反"前段非 PASSED 不得启动后段"。"""


class AttemptImmutabilityError(PipelineError):
    """attempt 已终态仍被复用（重试必须创建新 attempt_id）。"""


class RunNotFoundError(PipelineError):
    """run_id 在事件正源中不存在。"""


class TerminalRunError(PipelineError):
    """run 已处于终态，拒绝继续变更。"""


class InvalidOutcomeError(PipelineError):
    """双轴结果非法（如非 COMPLETED 执行配 PASS 策略）。"""


class InvalidIdentityError(PipelineError):
    """run 身份（commit_sha/environment/scope_hash）不满足 run-event-v2 契约。"""


class PipelineCorruptionError(PipelineError):
    """重放时检出不单调 state_version 或与转换表矛盾的事件序列（疑遭篡改）。"""


class ApprovalError(PipelineError):
    """审批消费基础错误。"""


class ApprovalRejected(ApprovalError):
    """审批未通过校验（结构/TTL/绑定/CAS/判别联合任一失败）——fail-closed。"""

    def __init__(self, reason: str, detail: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(f"approval rejected: {reason}")
        self.reason = reason
        self.detail = detail or {}


class ApprovalReuseError(ApprovalError):
    """nonce 已被消费——审批不可复用（不变量 #5）。"""


class ApprovalPreconditionError(ApprovalError):
    """客观前置条件不满足"必要且充分"规格，或与授权哈希不匹配。"""


# ====================================================================== #
# 通用小工具
# ====================================================================== #


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _utc_now_epoch() -> float:
    return time.time()


def _parse_iso_ts(value: str) -> datetime:
    """解析 ISO8601；容忍 Z 后缀；naive 视为 UTC（schema format: date-time）。"""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid date-time: {value!r}")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _truthy(value: Any) -> bool:
    """客观前置条件取值必须"非空"：空串/空列表/空字典/None/False 均不满足。"""
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) > 0
    return value is not None and value is not False


_HEX40 = set("0123456789abcdef")
_HEX64 = set("0123456789abcdef")


def _is_sha1_hex(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 40
            and all(c in _HEX40 for c in value.lower()) and value == value.lower())


def _is_sha256_hex(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in _HEX64 for c in value.lower()) and value == value.lower())


# ====================================================================== #
# 状态数据结构（重放产物，只读快照）
# ====================================================================== #


@dataclass(frozen=True)
class StageAttempt:
    """一次段尝试——终态后不可变，重试/恢复必须创建新 attempt_id。"""

    attempt_id: str
    stage: str
    status: str
    started_at: str
    finished_at: Optional[str] = None
    execution_status: Optional[str] = None
    policy_verdict: Optional[str] = None
    evidence_refs: Tuple[str, ...] = ()
    findings: Tuple[str, ...] = ()


@dataclass
class StageState:
    """单段聚合状态：由该段全部 attempt 序列推导。"""

    stage: str
    attempts: List[StageAttempt] = field(default_factory=list)

    @property
    def current_attempt(self) -> Optional[StageAttempt]:
        return self.attempts[-1] if self.attempts else None

    @property
    def status(self) -> str:
        """PENDING（未启动）｜RUNNING｜WAITING｜最近终态。"""
        cur = self.current_attempt
        if cur is None:
            return ATTEMPT_PENDING
        return cur.status

    @property
    def passed(self) -> bool:
        return self.status == ATTEMPT_PASSED


@dataclass(frozen=True)
class WaitingInfo:
    """run 处于 WAITING 时的停等绑定信息。"""

    stop_type: str
    stop_event_id: str          # 引发停等的 WAITING_RAISED 事件链上哈希（审批锚点）
    stage: str
    reason: str
    raised_at: str
    required_preconditions: Tuple[str, ...]


@dataclass
class RunState:
    """由 pipeline_events 重放推导的 run 只读状态（无第二正源）。"""

    run_id: str
    task_id: str
    identity: Dict[str, Any]
    state: str
    state_version: int
    stages: Dict[str, StageState]
    waiting: Optional[WaitingInfo] = None
    created_at: Optional[str] = None
    finished_at: Optional[str] = None
    terminal_reason: Optional[str] = None

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_RUN_STATES

    @property
    def current_stage(self) -> Optional[str]:
        """最早的未 PASSED 段（全 PASSED 时为 None）。"""
        for stage in STAGES:
            if self.stages[stage].status != ATTEMPT_PASSED:
                return stage
        return None

    def stage_statuses(self) -> Dict[str, str]:
        return {s: self.stages[s].status for s in STAGES}


# ====================================================================== #
# SevenStageStateMachine——纯规则引擎（无 IO，可独立复用/测试）
# ====================================================================== #


class SevenStageStateMachine:
    """七段状态机规则（契约 §1/§3/§4/§5/§6 的可判定实现）。

    本类只做规则判定，不持有状态、不做 IO——状态正源在 EventStore 事件流，
    由 RunManager 重放。所有校验失败即抛错，绝不返回"宽松默认值"。
    """

    # ---------------- §1 七段枚举 ----------------
    STAGES: Tuple[str, ...] = STAGES

    @classmethod
    def stages(cls) -> Tuple[str, ...]:
        return cls.STAGES

    @classmethod
    def stage_index(cls, stage: str) -> int:
        try:
            return cls.STAGES.index(stage)
        except ValueError:
            raise StageOrderError(
                f"unknown stage {stage!r}; valid stages: {' -> '.join(cls.STAGES)}"
            ) from None

    @classmethod
    def next_stage(cls, stage: str) -> Optional[str]:
        idx = cls.stage_index(stage)
        return cls.STAGES[idx + 1] if idx + 1 < len(cls.STAGES) else None

    @classmethod
    def first_stage(cls) -> str:
        return cls.STAGES[0]

    @classmethod
    def last_stage(cls) -> str:
        return cls.STAGES[-1]

    # ---------------- §5 转换表 ----------------
    @staticmethod
    def validate_run_transition(current: str, new: str) -> None:
        if current not in RUN_TRANSITIONS:
            raise InvalidTransitionError("run", current, new)
        if new not in RUN_TRANSITIONS[current]:
            raise InvalidTransitionError("run", current, new)

    @staticmethod
    def validate_attempt_transition(current: str, new: str) -> None:
        if current not in ATTEMPT_TRANSITIONS:
            raise InvalidTransitionError("attempt", current, new)
        if new not in ATTEMPT_TRANSITIONS[current]:
            raise InvalidTransitionError("attempt", current, new)

    # ---------------- §1 前段非 PASSED 不得启动后段 ----------------
    @classmethod
    def ensure_prior_stages_passed(
        cls, stage_statuses: Mapping[str, str], stage: str
    ) -> None:
        idx = cls.stage_index(stage)
        for prior in cls.STAGES[:idx]:
            if stage_statuses.get(prior) != ATTEMPT_PASSED:
                raise StageOrderError(
                    f"cannot start {stage}: prior stage {prior} is "
                    f"{stage_statuses.get(prior)!r}, not PASSED "
                    f"(contract §1: 前段非 PASSED 不得启动后段)"
                )

    # ---------------- §6 九类停等 / 客观前置条件 ----------------
    @staticmethod
    def stop_types() -> Tuple[str, ...]:
        return tuple(t.value for t in NineStopTypes)

    @staticmethod
    def precondition_spec(stop_type: str) -> Dict[str, Any]:
        if stop_type not in STOP_PRECONDITION_SPECS:
            raise StageOrderError(
                f"unknown stop_type {stop_type!r}; valid: "
                f"{sorted(STOP_PRECONDITION_SPECS)}"
            )
        return STOP_PRECONDITION_SPECS[stop_type]

    @classmethod
    def validate_preconditions(
        cls, stop_type: str, supplied: Optional[Mapping[str, Any]]
    ) -> Dict[str, Any]:
        """校验客观前置条件是否齐备（必要条件的客观半边）。

        - supplied 必须是非空映射；
        - spec.required 的每个键组内所有键必须存在且取值非空；
        - spec.any_of 至少一组全部非空（exm-fuse 的"实际解除或独立裁定"）。
        返回规范化副本；任何缺失即抛 ApprovalPreconditionError。
        """
        spec = cls.precondition_spec(stop_type)
        if not isinstance(supplied, Mapping) or not supplied:
            raise ApprovalPreconditionError(
                "objective preconditions missing/empty",
                {"stop_type": stop_type, "spec": spec["description"]},
            )
        supplied = dict(supplied)
        missing: List[str] = []
        for group in spec["required"]:
            missing.extend(k for k in group if not _truthy(supplied.get(k)))
        if missing:
            raise ApprovalPreconditionError(
                "objective preconditions not satisfied",
                {"stop_type": stop_type, "missing_keys": sorted(set(missing)),
                 "spec": spec["description"]},
            )
        for alternatives in spec["any_of"]:
            if not any(all(_truthy(supplied.get(k)) for k in group)
                       for group in alternatives):
                raise ApprovalPreconditionError(
                    "objective preconditions not satisfied (no alternative met)",
                    {"stop_type": stop_type,
                     "any_of": [list(g) for group in alternatives for g in [group]],
                     "spec": spec["description"]},
                )
        return supplied

    @staticmethod
    def objective_precondition_hash(supplied: Mapping[str, Any]) -> str:
        """客观前置条件的内容哈希——审批授权精确绑定到这组条件。"""
        return _sha256_hex(_canonical_json(dict(supplied)))

    # ---------------- 双轴结果合法性 ----------------
    @staticmethod
    def validate_outcome(execution_status: str, policy_verdict: str,
                         findings: Sequence[str] = ()) -> None:
        if execution_status not in EXECUTION_STATUSES:
            raise InvalidOutcomeError(
                f"invalid execution_status {execution_status!r}; "
                f"valid: {sorted(EXECUTION_STATUSES)}")
        if policy_verdict not in POLICY_VERDICTS:
            raise InvalidOutcomeError(
                f"invalid policy_verdict {policy_verdict!r}; "
                f"valid: {sorted(POLICY_VERDICTS)}")
        # 契约 §2：阻断态不得折算为 PASS——执行非 COMPLETED 时策略不得 PASS
        if policy_verdict == "PASS" and execution_status != "COMPLETED":
            raise InvalidOutcomeError(
                f"policy PASS requires execution COMPLETED, got {execution_status}"
            )
        # 契约 §7 退出码语义：有 findings 即非 0——PASS 不得携带 findings
        if policy_verdict == "PASS" and findings:
            raise InvalidOutcomeError(
                f"policy PASS cannot carry findings ({len(findings)} present); "
                f"至少应为 CONDITIONAL/FAIL"
            )

    @staticmethod
    def verdict_to_attempt_status(policy_verdict: str) -> str:
        """双轴 verdict → 段终态（契约 §2 从严映射：只有 PASS 是 PASSED）。"""
        if policy_verdict == "PASS":
            return ATTEMPT_PASSED
        if policy_verdict in ("CONDITIONAL", "NOT_APPLICABLE"):
            # CONDITIONAL ≠ PASS（契约 §2）；N/A 仅由受保护 applicability rule
            # 生成，执行完成但策略未判过——均入软终态，不得放行后段。
            return ATTEMPT_COMPLETED_CONDITIONAL
        return ATTEMPT_FAILED  # FAIL / NOT_EVALUATED


# ====================================================================== #
# _PipelineDb——EventStore 之上的事务/读写内部件
# ====================================================================== #


class _PipelineDb:
    """与 EventStore 同库（同 SQLite 文件）的内部连接件。

    - 事务：``transact()`` 用 BEGIN IMMEDIATE 取独占写锁，"重放校验→写事件"
      在同一事务内原子完成——SQLite 单写者模型保证并发下无交错；
    - 链式插入：``append_event`` 与 store.EventStore.append 的哈希链规则
      完全一致（复用其 canonical/hash 静态方法，杜绝双实现漂移）；
    - 限制：不支持 EventStore(":memory:")——每个 :memory: 连接是独立库，
      必须使用文件路径（WAL 持久于文件）。
    """

    _BUSY_TIMEOUT_MS = 10000

    def __init__(self, db_path: str) -> None:
        if not db_path or db_path == ":memory:":
            raise PipelineError(
                "in-memory EventStore unsupported: pipeline state requires a "
                "persistent WAL database file"
            )
        self.db_path = db_path
        # check_same_thread=False：允许"每线程一个 RunManager/连接"的合法用法；
        # 并发写由 BEGIN IMMEDIATE + busy_timeout 在 SQLite 层串行化。
        self._conn = sqlite3.connect(db_path, isolation_level=None,
                                     timeout=self._BUSY_TIMEOUT_MS / 1000.0,
                                     check_same_thread=False)
        self._conn.execute(f"PRAGMA busy_timeout={self._BUSY_TIMEOUT_MS}")

    # ------------------------------------------------------------------ #
    @staticmethod
    def from_store(store: EventStore) -> "_PipelineDb":
        """从既有 EventStore 实例推导其底层库文件路径并打开伴随连接。"""
        # store._conn 为同包内已知实现细节；正源库文件路径经 PRAGMA database_list
        row = store._conn.execute("PRAGMA database_list").fetchone()  # noqa: SLF001
        db_path = row[2] if row else ""
        return _PipelineDb(db_path)

    # ------------------------------------------------------------------ #
    def transact(self, body: Callable[[sqlite3.Connection], Any]) -> Any:
        """BEGIN IMMEDIATE 事务：body 抛错即整体回滚。"""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            result = body(self._conn)
            self._conn.execute("COMMIT")
            return result
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ #
    @staticmethod
    def append_event(conn: sqlite3.Connection,
                     event: Mapping[str, Any]) -> Tuple[str, bool]:
        """在已开启的事务内链式插入一条事件（与 EventStore.append 同规则）。"""
        payload = EventStore._canonical_payload(event)  # noqa: SLF001
        event_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        row = conn.execute(
            "SELECT event_hash FROM pipeline_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev = row[0] if row else GENESIS_HASH
        event_hash = EventStore._compute_hash(prev, payload)  # noqa: SLF001
        cur = conn.execute(
            "INSERT OR IGNORE INTO pipeline_events "
            "(event_id, payload, prev_event_hash, event_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (event_id, payload, prev, event_hash, time.time()),
        )
        return event_hash, cur.rowcount == 1

    # ------------------------------------------------------------------ #
    @staticmethod
    def read_events(
        conn: sqlite3.Connection,
    ) -> List[Tuple[int, str, Dict[str, Any]]]:
        """按 seq 升序读取全部事件 (seq, event_hash, payload)。"""
        rows = conn.execute(
            "SELECT seq, event_hash, payload FROM pipeline_events ORDER BY seq ASC"
        ).fetchall()
        return [(seq, eh, json.loads(payload)) for seq, eh, payload in rows]

    def close(self) -> None:
        self._conn.close()


# ====================================================================== #
# ApprovalBroker——approval-v2 审批消费
# ====================================================================== #


class ApprovalBroker:
    """消费 approval-v2 审批事件：fail-closed 校验 + 一次性原子消费。

    校验链（任一失败即抛 ApprovalRejected/ApprovalPreconditionError，
    且不消费 nonce、不写任何事件）：
        1. 结构（镜像 schema：required/enum/pattern/minLength/判别联合/
           additionalProperties=false）；
        2. decision 必须为 approve（deny/conditional 不足以 resume）；
        3. TTL：issued_at <= now < expires_at；
        4. run 绑定：run_id / stop_event_id / stop_type / stage /
           environment / authorized_scope(=scope_hash) / input_watermark(=commit_sha)；
        5. state_version CAS：expected_state_version == run 当前版本；
        6. 客观前置条件：满足该 stop_type 的必要且充分规格，且其内容哈希
           == payload.objective_precondition_hash（授权精确绑定条件内容）。

    原子消费：第 4-6 步的 run 状态读取、nonce 占用（PRIMARY KEY 冲突即
    ApprovalReuseError）与 WAITING_RESUMED 事件链式插入全部发生在同一个
    BEGIN IMMEDIATE 事务内——并发双消费第二个必然撞 nonce 主键失败。
    """

    _CONSUMPTION_SCHEMA = """
    CREATE TABLE IF NOT EXISTS approval_consumptions (
        nonce             TEXT PRIMARY KEY,
        approval_id       TEXT NOT NULL,
        approval_type     TEXT NOT NULL,
        run_id            TEXT NOT NULL,
        stop_type         TEXT NOT NULL,
        decision          TEXT NOT NULL,
        expires_at        TEXT NOT NULL,
        consumed_at       REAL NOT NULL,
        preconditions_hash TEXT,
        resume_event_hash TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_approval_consumptions_run
        ON approval_consumptions(run_id);
    """

    def __init__(self, store: EventStore,
                 db: Optional[_PipelineDb] = None) -> None:
        self._store = store
        self._db = db if db is not None else _PipelineDb.from_store(store)
        self._db._conn.executescript(self._CONSUMPTION_SCHEMA)  # noqa: SLF001

    # ------------------------------------------------------------------ #
    # 结构校验（镜像 approval-v2.schema.json，无外部依赖）
    # ------------------------------------------------------------------ #
    @staticmethod
    def validate_structure(approval: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(approval, Mapping):
            raise ApprovalRejected("approval is not a JSON object")
        ap = dict(approval)
        for key in _APPROVAL_REQUIRED_TOP:
            if key not in ap:
                raise ApprovalRejected(f"missing required field: {key}")
        unknown = sorted(set(ap) - _APPROVAL_ALLOWED_TOP)
        if unknown:
            raise ApprovalRejected(
                "additional properties forbidden by schema",
                {"unknown_fields": unknown},
            )
        if ap["schema_version"] != _APPROVAL_SCHEMA_VERSION:
            raise ApprovalRejected(
                f"schema_version must be {_APPROVAL_SCHEMA_VERSION!r}, "
                f"got {ap['schema_version']!r}")
        if not (isinstance(ap["approval_id"], str)
                and ap["approval_id"].startswith("apr_")
                and len(ap["approval_id"]) > 4
                and all(c.isalnum() or c == "_" for c in ap["approval_id"][4:])):
            raise ApprovalRejected(
                "approval_id must match ^apr_[a-zA-Z0-9_]+$")
        if ap["approval_type"] not in _APPROVAL_TYPES:
            raise ApprovalRejected(
                f"invalid approval_type {ap['approval_type']!r}; "
                f"valid: {sorted(_APPROVAL_TYPES)}")
        if ap["stop_type"] not in STOP_PRECONDITION_SPECS:
            raise ApprovalRejected(
                f"invalid stop_type {ap['stop_type']!r}; "
                f"valid: {SevenStageStateMachine.stop_types()}")
        if ap["decision"] not in _APPROVAL_DECISIONS:
            raise ApprovalRejected(
                f"invalid decision {ap['decision']!r}; "
                f"valid: {sorted(_APPROVAL_DECISIONS)}")
        if not (isinstance(ap["run_id"], str) and ap["run_id"]):
            raise ApprovalRejected("run_id must be a non-empty string")
        if not (isinstance(ap["stop_event_id"], str) and ap["stop_event_id"]):
            raise ApprovalRejected("stop_event_id must be a non-empty string")
        if not (isinstance(ap["actor"], str) and ap["actor"].strip()):
            raise ApprovalRejected("actor must be a non-empty string")
        if not (isinstance(ap["nonce"], str) and len(ap["nonce"]) >= 16):
            raise ApprovalRejected("nonce must be a string of >= 16 chars")
        if not (isinstance(ap["signature"], str) and len(ap["signature"]) >= 32):
            raise ApprovalRejected("signature must be a string of >= 32 chars")
        for ts_field in ("issued_at", "expires_at"):
            try:
                _parse_iso_ts(ap[ts_field])
            except ValueError as exc:
                raise ApprovalRejected(
                    f"invalid date-time in {ts_field}: {exc}") from None
        if _parse_iso_ts(ap["expires_at"]) <= _parse_iso_ts(ap["issued_at"]):
            raise ApprovalRejected("expires_at must be after issued_at")
        # payload 判别联合（schema oneOf：按 approval_type 必须含专属字段）
        payload = ap["payload"]
        if not isinstance(payload, Mapping):
            raise ApprovalRejected("payload must be a JSON object")
        required_payload = _APPROVAL_PAYLOAD_DISCRIMINATOR[ap["approval_type"]]
        missing = [k for k in required_payload if k not in payload]
        if missing:
            raise ApprovalRejected(
                f"payload discriminator mismatch for "
                f"approval_type={ap['approval_type']!r}: missing {missing}")
        empty = [k for k in required_payload if not _truthy(payload.get(k))]
        if empty:
            raise ApprovalRejected(
                "payload discriminator fields must be non-empty",
                {"empty_fields": empty},
            )
        if (ap["approval_type"] == "resume"
                and not _is_sha256_hex(payload.get("objective_precondition_hash"))):
            raise ApprovalRejected(
                "payload.objective_precondition_hash must be sha256 hex (64)")
        if (ap["approval_type"] == "resume"
                and payload.get("stop_type") != ap["stop_type"]):
            raise ApprovalRejected(
                "payload.stop_type conflicts with top-level stop_type")
        if (ap["approval_type"] == "resume"
                and payload.get("stop_event_id") != ap["stop_event_id"]):
            raise ApprovalRejected(
                "payload.stop_event_id conflicts with top-level stop_event_id")
        if "environment" in ap and ap["environment"] not in ENVIRONMENTS:
            raise ApprovalRejected(
                f"invalid environment {ap['environment']!r}; "
                f"valid: {sorted(ENVIRONMENTS)}")
        if "expected_state_version" in ap and not (
            isinstance(ap["expected_state_version"], int)
            and not isinstance(ap["expected_state_version"], bool)
            and ap["expected_state_version"] >= 1
        ):
            raise ApprovalRejected("expected_state_version must be integer >= 1")
        return ap

    # ------------------------------------------------------------------ #
    # 绑定/TTL/CAS/前置条件校验（对给定 run 快照）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_resume_binding(ap: Mapping[str, Any], state: RunState,
                                 now_epoch: float) -> Dict[str, Any]:
        if state.terminal:
            raise ApprovalRejected(
                "run is terminal; approval cannot resume a finished run",
                {"run_state": state.state})
        if state.state != RUN_WAITING_S or state.waiting is None:
            raise ApprovalRejected(
                f"run is {state.state}, not WAITING——无可恢复停等",
                {"run_state": state.state})
        if ap["decision"] != "approve":
            raise ApprovalRejected(
                f"decision {ap['decision']!r} 不足以 resume（须 approve）")
        issued = _parse_iso_ts(ap["issued_at"]).timestamp()
        expires = _parse_iso_ts(ap["expires_at"]).timestamp()
        if not (issued <= now_epoch < expires):
            raise ApprovalRejected(
                "approval outside TTL window (issued_at <= now < expires_at)",
                {"now": now_epoch, "issued_at_epoch": issued,
                 "expires_at_epoch": expires},
            )
        if ap["run_id"] != state.run_id:
            raise ApprovalRejected(
                "run_id mismatch（审批不得跨 run 复用）",
                {"approval_run_id": ap["run_id"], "run_id": state.run_id})
        waiting = state.waiting
        if ap["stop_event_id"] != waiting.stop_event_id:
            raise ApprovalRejected(
                "stop_event_id mismatch——审批必须锚定当前停等事件",
                {"approval_stop_event_id": ap["stop_event_id"],
                 "waiting_stop_event_id": waiting.stop_event_id})
        if ap["stop_type"] != waiting.stop_type:
            raise ApprovalRejected(
                "stop_type mismatch",
                {"approval_stop_type": ap["stop_type"],
                 "waiting_stop_type": waiting.stop_type})
        if "stage" in ap and ap["stage"] != waiting.stage:
            raise ApprovalRejected(
                "stage mismatch",
                {"approval_stage": ap["stage"], "waiting_stage": waiting.stage})
        if "task_id" in ap and ap["task_id"] != state.task_id:
            raise ApprovalRejected("task_id mismatch")
        identity = state.identity
        if "environment" in ap and ap["environment"] != identity["environment"]:
            raise ApprovalRejected(
                "environment mismatch（审批不得跨环境）",
                {"approval_environment": ap["environment"],
                 "run_environment": identity["environment"]})
        if ("authorized_scope" in ap
                and ap["authorized_scope"] != identity["scope_hash"]):
            raise ApprovalRejected(
                "authorized_scope != run scope_hash（审批不得扩范围）",
                {"authorized_scope": ap["authorized_scope"],
                 "run_scope_hash": identity["scope_hash"]})
        if ("input_watermark" in ap
                and _is_sha1_hex(ap["input_watermark"])
                and ap["input_watermark"] != identity["commit_sha"]):
            raise ApprovalRejected(
                "input_watermark(sha) != run commit_sha（审批不得跨 SHA）",
                {"input_watermark": ap["input_watermark"],
                 "commit_sha": identity["commit_sha"]})
        if "expected_state_version" not in ap:
            raise ApprovalRejected(
                "resume 审批必须携带 expected_state_version（CAS）")
        if ap["expected_state_version"] != state.state_version:
            raise ApprovalRejected(
                "state_version CAS failure（审批不得跨状态版本）",
                {"expected": ap["expected_state_version"],
                 "actual": state.state_version})
        return dict(ap)

    # ------------------------------------------------------------------ #
    # 原子消费（nonce + WAITING_RESUMED 同事务）
    # ------------------------------------------------------------------ #
    def consume(
        self,
        approval: Mapping[str, Any],
        *,
        run_loader: Callable[[sqlite3.Connection], RunState],
        resume_event_builder: Callable[[RunState, Dict[str, Any], str],
                                       Mapping[str, Any]],
        objective_preconditions: Optional[Mapping[str, Any]],
        now_epoch: Optional[float] = None,
    ) -> Dict[str, Any]:
        """校验并在单事务内一次性消费审批，返回消费记录。

        参数：
            run_loader           —— 在事务连接内重放目标 run（保证 CAS 读的是
                                    事务内新鲜状态，杜绝校验-消费间隙竞态）；
            resume_event_builder —— (run_state, normalized_approval, nonce_digest)
                                    → WAITING_RESUMED 事件（由 RunManager 构造）；
            objective_preconditions —— 客观前置条件（将对其做规格校验+哈希比对）。
        """
        ap = self.validate_structure(approval)          # 1. 结构（纯函数）
        now = now_epoch if now_epoch is not None else _utc_now_epoch()

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = run_loader(conn)                    # 事务内新鲜快照
            # 重放检测优先：nonce 是防重放原语——已消费即复用，无论 run 现状；
            # 并发首次消费的竞态仍由下方 INSERT 主键兜底。
            if conn.execute("SELECT 1 FROM approval_consumptions WHERE nonce = ?",
                            (ap["nonce"],)).fetchone() is not None:
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {ap['approval_id']} "
                    f"不可复用——不变量 #5)")
            bound = self._validate_resume_binding(ap, state, now)  # 2-5 绑定/TTL/CAS
            # 6. 客观前置条件：必要且充分规格 + 授权哈希精确绑定
            supplied = SevenStageStateMachine.validate_preconditions(
                bound["stop_type"], objective_preconditions)
            precond_hash = SevenStageStateMachine.objective_precondition_hash(
                supplied)
            if precond_hash != bound["payload"]["objective_precondition_hash"]:
                raise ApprovalPreconditionError(
                    "objective_precondition_hash mismatch——授权绑定的前置条件"
                    "与提交内容不一致",
                    {"expected": bound["payload"]["objective_precondition_hash"],
                     "actual": precond_hash},
                )
            nonce_digest = _sha256_hex(bound["nonce"])
            event = resume_event_builder(state, bound, nonce_digest)
            # —— 写半边：先占 nonce（主键冲突=复用），再链式插入事件；同事务 ——
            try:
                conn.execute(
                    "INSERT INTO approval_consumptions "
                    "(nonce, approval_id, approval_type, run_id, stop_type, "
                    " decision, expires_at, consumed_at, preconditions_hash, "
                    " resume_event_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (bound["nonce"], bound["approval_id"],
                     bound["approval_type"], state.run_id, bound["stop_type"],
                     bound["decision"], bound["expires_at"], time.time(),
                     precond_hash),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {bound['approval_id']} "
                    f"不可复用——不变量 #5): {exc}") from None
            event_hash, _inserted = _PipelineDb.append_event(conn, event)
            conn.execute(
                "UPDATE approval_consumptions SET resume_event_hash = ? "
                "WHERE nonce = ?",
                (event_hash, bound["nonce"]),
            )
            return {
                "approval_id": bound["approval_id"],
                "approval_type": bound["approval_type"],
                "nonce_digest": nonce_digest,
                "run_id": state.run_id,
                "stop_type": bound["stop_type"],
                "stop_event_id": bound["stop_event_id"],
                "preconditions_hash": precond_hash,
                "state_version_before": state.state_version,
                "resumed": True,
                "event_hash": event_hash,
            }

        return self._db.transact(_body)

    # ------------------------------------------------------------------ #
    # 非停等类授权（risk 等）的一次性消费——供 COMPLETED_CONDITIONAL 前置核验
    # ------------------------------------------------------------------ #
    def consume_authorization(
        self,
        approval: Mapping[str, Any],
        *,
        run_loader: Callable[[sqlite3.Connection], RunState],
        now_epoch: Optional[float] = None,
    ) -> Dict[str, Any]:
        """一次性消费非停等授权（approval_type != resume，如 risk）。

        与 consume() 同样的 fail-closed 纪律：结构校验（含该类型的 payload
        判别联合）→ decision=approve → TTL → run 绑定（run_id/environment/
        scope/SHA/task_id，不要求 WAITING）→ 同事务原子占 nonce。
        不产生管线事件——授权进入消费台账，供 complete_run 等终态判定核验。
        """
        ap = self.validate_structure(approval)
        if ap["approval_type"] == "resume":
            raise ApprovalRejected(
                "resume 审批必须经 consume() 与停等事件绑定消费")
        now = now_epoch if now_epoch is not None else _utc_now_epoch()

        def _binding(ap: Mapping[str, Any], state: RunState) -> None:
            if ap["decision"] != "approve":
                raise ApprovalRejected(
                    f"decision {ap['decision']!r} 不足以授权（须 approve）")
            issued = _parse_iso_ts(ap["issued_at"]).timestamp()
            expires = _parse_iso_ts(ap["expires_at"]).timestamp()
            if not (issued <= now < expires):
                raise ApprovalRejected(
                    "approval outside TTL window",
                    {"now": now, "expires_at_epoch": expires})
            if ap["run_id"] != state.run_id:
                raise ApprovalRejected(
                    "run_id mismatch",
                    {"approval_run_id": ap["run_id"], "run_id": state.run_id})
            if "task_id" in ap and ap["task_id"] != state.task_id:
                raise ApprovalRejected("task_id mismatch")
            if state.terminal:
                raise ApprovalRejected(
                    "run is terminal; authorization has no target",
                    {"run_state": state.state})
            ident = state.identity
            if "environment" in ap and ap["environment"] != ident["environment"]:
                raise ApprovalRejected("environment mismatch（审批不得跨环境）")
            if ("authorized_scope" in ap
                    and ap["authorized_scope"] != ident["scope_hash"]):
                raise ApprovalRejected(
                    "authorized_scope != run scope_hash（审批不得扩范围）")
            if ("input_watermark" in ap
                    and _is_sha1_hex(ap["input_watermark"])
                    and ap["input_watermark"] != ident["commit_sha"]):
                raise ApprovalRejected("input_watermark(sha) != run commit_sha")
            if "stage" in ap and ap["stage"] not in state.stages:
                raise ApprovalRejected(f"unknown stage {ap['stage']!r}")

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = run_loader(conn)
            # 重放检测优先（同 consume）
            if conn.execute("SELECT 1 FROM approval_consumptions WHERE nonce = ?",
                            (ap["nonce"],)).fetchone() is not None:
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {ap['approval_id']} "
                    f"不可复用——不变量 #5)")
            _binding(ap, state)
            try:
                conn.execute(
                    "INSERT INTO approval_consumptions "
                    "(nonce, approval_id, approval_type, run_id, stop_type, "
                    " decision, expires_at, consumed_at, preconditions_hash, "
                    " resume_event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                    (ap["nonce"], ap["approval_id"], ap["approval_type"],
                     state.run_id, ap["stop_type"], ap["decision"],
                     ap["expires_at"], time.time()),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {ap['approval_id']} "
                    f"不可复用——不变量 #5): {exc}") from None
            return {
                "approval_id": ap["approval_id"],
                "approval_type": ap["approval_type"],
                "nonce_digest": _sha256_hex(ap["nonce"]),
                "run_id": state.run_id,
                "stop_type": ap["stop_type"],
                "consumed": True,
            }

        return self._db.transact(_body)

    # ------------------------------------------------------------------ #
    def consumed_approvals(self, run_id: Optional[str] = None,
                           approval_type: Optional[str] = None
                           ) -> List[Dict[str, Any]]:
        """查询消费台账（nonce 一次性占用的可审计正源）。"""
        sql = ("SELECT nonce, approval_id, approval_type, run_id, stop_type, "
               "decision, expires_at, consumed_at, preconditions_hash, "
               "resume_event_hash FROM approval_consumptions")
        conds, args = [], []
        if run_id is not None:
            conds.append("run_id = ?")
            args.append(run_id)
        if approval_type is not None:
            conds.append("approval_type = ?")
            args.append(approval_type)
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY consumed_at ASC"
        rows = self._db._conn.execute(sql, args).fetchall()  # noqa: SLF001
        keys = ("nonce", "approval_id", "approval_type", "run_id", "stop_type",
                "decision", "expires_at", "consumed_at", "preconditions_hash",
                "resume_event_hash")
        return [dict(zip(keys, r)) for r in rows]

    def has_unexpired_risk_authorization(self, run_id: str,
                                         now_epoch: Optional[float] = None
                                         ) -> Optional[Dict[str, Any]]:
        """查找 run 已消费、未过期的 risk 授权（COMPLETED_CONDITIONAL 前置）。"""
        now = now_epoch if now_epoch is not None else _utc_now_epoch()
        for row in self.consumed_approvals(run_id=run_id,
                                           approval_type="risk"):
            try:
                if _parse_iso_ts(row["expires_at"]).timestamp() > now:
                    return row
            except ValueError:
                continue
        return None


# ====================================================================== #
# RunManager——七段 run 编排（事件正源 = EventStore）
# ====================================================================== #


class RunManager:
    """七段 run 生命周期编排：create/advance/raise_waiting/resume/complete。

    一切状态变更 = 单个 BEGIN IMMEDIATE 事务内「重放 → 状态机校验 → 追加
    事件（state_version +1）」。重放严格校验 state_version 单调与转换表
    合法性，矛盾即 PipelineCorruptionError（事件流疑遭篡改）。
    """

    def __init__(self, store: EventStore,
                 broker: Optional[ApprovalBroker] = None) -> None:
        self._store = store
        self._db = _PipelineDb.from_store(store)
        self.broker = broker if broker is not None else ApprovalBroker(
            store, db=self._db)

    # ------------------------------------------------------------------ #
    # 身份校验（run-event-v2.identity）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_identity(identity: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(identity, Mapping):
            raise InvalidIdentityError("identity must be a JSON object")
        ident = dict(identity)
        for key in ("commit_sha", "environment", "scope_hash"):
            if not (isinstance(ident.get(key), str) and ident[key].strip()):
                raise InvalidIdentityError(
                    f"identity.{key} must be a non-empty string")
        if not _is_sha1_hex(ident["commit_sha"]):
            raise InvalidIdentityError(
                "identity.commit_sha must be a 40-hex git sha")
        if ident["environment"] not in ENVIRONMENTS:
            raise InvalidIdentityError(
                f"identity.environment must be one of {sorted(ENVIRONMENTS)}")
        if "base_sha" in ident and not _is_sha1_hex(ident["base_sha"]):
            raise InvalidIdentityError("identity.base_sha must be 40-hex sha")
        return ident

    # ------------------------------------------------------------------ #
    # 事件构造
    # ------------------------------------------------------------------ #
    @staticmethod
    def _base_event(event_type: str, state: RunState,
                    execution_status: str, policy_verdict: str, *,
                    stage: Optional[str] = None,
                    attempt_id: Optional[str] = None,
                    actor: str = "system", **extra: Any) -> Dict[str, Any]:
        event: Dict[str, Any] = {
            "schema_version": "2.0",
            "event_type": event_type,
            "run_id": state.run_id,
            "task_id": state.task_id,
            "execution_status": execution_status,
            "policy_verdict": policy_verdict,
            "identity": dict(state.identity),
            "state_version": state.state_version,  # 调用方提交前 +1
            "ts": _utc_now_iso(),
            "actor": actor,
        }
        if stage is not None:
            event["stage"] = stage
        if attempt_id is not None:
            event["attempt_id"] = attempt_id
        event.update(extra)
        return event

    # ------------------------------------------------------------------ #
    # 重放：事件流 → RunState（唯一状态推导路径）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _replay_fold(state: Optional[RunState], event_hash: str,
                     ev: Mapping[str, Any]) -> RunState:
        etype = ev.get("event_type")
        if state is None:
            if etype != "RUN_CREATED":
                raise PipelineCorruptionError(
                    f"run {ev.get('run_id')!r} 首事件非 RUN_CREATED: {etype}")
            ident = ev.get("identity") or {}
            stages = {s: StageState(stage=s) for s in STAGES}
            state = RunState(
                run_id=ev["run_id"], task_id=ev.get("task_id", ""),
                identity=dict(ident), state=RUN_CREATED_S,
                state_version=int(ev.get("state_version", 1)),
                stages=stages, created_at=ev.get("ts"),
            )
            return state
        # state_version 单调 CAS：每个事件 = +1
        incoming = ev.get("state_version")
        if not isinstance(incoming, int) or incoming != state.state_version + 1:
            raise PipelineCorruptionError(
                f"run {state.run_id}: non-monotonic state_version at "
                f"{etype}: expected {state.state_version + 1}, got {incoming!r}")
        state.state_version = incoming

        if etype == "STAGE_STARTED":
            stage = ev.get("stage")
            SevenStageStateMachine.stage_index(stage)
            ss = state.stages[stage]
            cur = ss.current_attempt
            if cur is not None and cur.status not in TERMINAL_ATTEMPT_STATES:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: STAGE_STARTED while attempt "
                    f"{cur.attempt_id} still {cur.status}（attempt 不可变被破坏）")
            SevenStageStateMachine.ensure_prior_stages_passed(
                {k: v.status for k, v in state.stages.items()}, stage)
            ss.attempts.append(StageAttempt(
                attempt_id=ev.get("attempt_id", ""), stage=stage,
                status=ATTEMPT_RUNNING, started_at=ev.get("ts", "")))
            if state.state == RUN_CREATED_S:
                SevenStageStateMachine.validate_run_transition(
                    state.state, RUN_RUNNING_S)
                state.state = RUN_RUNNING_S
            elif state.state != RUN_RUNNING_S:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: STAGE_STARTED while run {state.state}")
        elif etype == "STAGE_COMPLETED":
            stage = ev.get("stage")
            ss = state.stages[stage]
            cur = ss.current_attempt
            if cur is None or cur.status != ATTEMPT_RUNNING:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: STAGE_COMPLETED without RUNNING attempt"
                    f" on {stage}（current={cur.status if cur else None}）")
            attempt_status = SevenStageStateMachine.verdict_to_attempt_status(
                ev.get("policy_verdict", "NOT_EVALUATED"))
            SevenStageStateMachine.validate_attempt_transition(
                cur.status, attempt_status)
            new_attempt = StageAttempt(
                attempt_id=cur.attempt_id, stage=stage,
                status=attempt_status, started_at=cur.started_at,
                finished_at=ev.get("ts"),
                execution_status=ev.get("execution_status"),
                policy_verdict=ev.get("policy_verdict"),
                evidence_refs=tuple(ev.get("evidence_refs") or ()),
                findings=tuple(ev.get("findings") or ()),
            )
            ss.attempts[-1] = new_attempt
        elif etype == "WAITING_RAISED":
            cur_stage = ev.get("stage")
            ss = state.stages[cur_stage]
            cur = ss.current_attempt
            if cur is None or cur.status != ATTEMPT_RUNNING:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: WAITING_RAISED without RUNNING attempt")
            SevenStageStateMachine.validate_attempt_transition(
                cur.status, ATTEMPT_WAITING)
            ss.attempts[-1] = StageAttempt(
                attempt_id=cur.attempt_id, stage=cur_stage,
                status=ATTEMPT_WAITING, started_at=cur.started_at,
                finished_at=ev.get("ts"))
            SevenStageStateMachine.validate_run_transition(
                state.state, RUN_WAITING_S)
            state.state = RUN_WAITING_S
            state.waiting = WaitingInfo(
                stop_type=ev["stop_type"], stop_event_id=event_hash,
                stage=cur_stage, reason=ev.get("stop_reason", ""),
                raised_at=ev.get("ts", ""),
                required_preconditions=tuple(
                    ev.get("required_preconditions") or ()),
            )
        elif etype == "WAITING_RESUMED":
            if state.state != RUN_WAITING_S or state.waiting is None:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: WAITING_RESUMED while {state.state}")
            SevenStageStateMachine.validate_run_transition(
                state.state, RUN_RUNNING_S)
            resumed_stage = ev.get("stage") or state.waiting.stage
            rs = state.stages[resumed_stage]
            prior = rs.current_attempt
            if prior is not None and prior.status not in TERMINAL_ATTEMPT_STATES:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: WAITING_RESUMED while attempt "
                    f"{prior.attempt_id} still {prior.status}（attempt 不可变被破坏）")
            rs.attempts.append(StageAttempt(
                attempt_id=ev.get("attempt_id", ""), stage=resumed_stage,
                status=ATTEMPT_RUNNING, started_at=ev.get("ts", "")))
            state.state = RUN_RUNNING_S
            state.waiting = None
        elif etype == "RUN_COMPLETED":
            execution = ev.get("execution_status")
            verdict = ev.get("policy_verdict")
            if execution == "CANCELLED":
                final = RUN_CANCELLED_S
            elif verdict == "PASS":
                final = RUN_SUCCEEDED_S
            elif verdict == "CONDITIONAL":
                final = RUN_COMPLETED_CONDITIONAL_S
            else:
                final = RUN_FAILED_S
            SevenStageStateMachine.validate_run_transition(state.state, final)
            state.state = final
            state.finished_at = ev.get("ts")
            state.terminal_reason = ev.get("terminal_reason")
        elif etype == "SUPERSEDED":
            SevenStageStateMachine.validate_run_transition(
                state.state, RUN_SUPERSEDED_S)
            state.state = RUN_SUPERSEDED_S
            state.finished_at = ev.get("ts")
            state.terminal_reason = ev.get("supersede_reason", "superseded")
        else:
            raise PipelineCorruptionError(
                f"run {state.run_id}: unknown event_type {etype!r}")
        return state

    def _load_state(self, run_id: str,
                    conn: Optional[sqlite3.Connection] = None) -> RunState:
        c = conn if conn is not None else self._db._conn  # noqa: SLF001
        state: Optional[RunState] = None
        for _seq, event_hash, payload in _PipelineDb.read_events(c):
            if payload.get("run_id") != run_id:
                continue
            state = self._replay_fold(state, event_hash, payload)
        if state is None:
            raise RunNotFoundError(f"run not found in event store: {run_id}")
        return state

    def _require_mutable(self, state: RunState) -> None:
        if state.terminal:
            raise TerminalRunError(
                f"run {state.run_id} is terminal ({state.state})——"
                f"控制事件只追加，纠错须 supersede/reopen（不变量 #6）")

    def _emit(self, conn: sqlite3.Connection, state: RunState,
              event: Mapping[str, Any]) -> str:
        """追加事件并立即重放折叠进内存 state——校验与正源重放共用同一规则。

        事件须携带 state.state_version + 1；_replay_fold 内部会校验单调性、
        转换表与段序，因此本方法之后的内存状态与事后重放严格一致。
        """
        event_hash, _ = _PipelineDb.append_event(conn, event)
        self._replay_fold(state, event_hash, event)
        return event_hash

    # ------------------------------------------------------------------ #
    # attempt_id 生成（不可变语义：每次新建即新 id）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _new_attempt_id(stage: str, seq: int) -> str:
        return f"att_{stage.lower()}_{seq}_{uuid.uuid4().hex[:8]}"

    # ------------------------------------------------------------------ #
    # 公开 API
    # ------------------------------------------------------------------ #
    def create_run(self, task_id: str, identity: Mapping[str, Any],
                   actor: str = "system") -> Dict[str, Any]:
        """创建七段 run：状态 CREATED，S1..S7 全 PENDING，state_version=1。"""
        if not (isinstance(task_id, str) and task_id.strip()
                and len(task_id) <= 64
                and all(c.isalnum() or c in "-_" for c in task_id)):
            raise PipelineError(
                "task_id must match ^[a-zA-Z0-9_-]+$ and be <= 64 chars")
        ident = self._validate_identity(identity)
        run_id = f"run_{time.strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"
        if len(run_id) > 64:
            run_id = run_id[:64]

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            seed = RunState(
                run_id=run_id, task_id=task_id, identity=ident,
                state=RUN_CREATED_S, state_version=1,
                stages={s: StageState(stage=s) for s in STAGES},
            )
            event = self._base_event(
                "RUN_CREATED", seed, "COMPLETED", "NOT_EVALUATED", actor=actor)
            event_hash, _ = _PipelineDb.append_event(conn, event)
            # 用与重放完全相同的规则自证事件可折叠（不一致立即失败回滚）
            self._replay_fold(None, event_hash, event)
            return {"run_id": run_id, "task_id": task_id,
                    "state": RUN_CREATED_S, "state_version": 1,
                    "stages": dict.fromkeys(STAGES, ATTEMPT_PENDING)}

        return self._db.transact(_body)

    def get_run(self, run_id: str) -> RunState:
        """只读快照（重放推导，无缓存）。"""
        return self._load_state(run_id)

    def advance_stage(
        self,
        run_id: str,
        *,
        execution_status: Optional[str] = None,
        policy_verdict: Optional[str] = None,
        evidence_refs: Sequence[str] = (),
        findings: Sequence[str] = (),
        actor: str = "system",
    ) -> Dict[str, Any]:
        """推进管线（前段 PASSED 后启动后段；attempt 不可变，重试即新 id）。

        两种形态（同一方法，显式优于隐式）：
        - 不带 outcome：为当前段启动新 attempt（首启/重试）；要求无 RUNNING
          attempt、前序全 PASSED、run 非终态；
        - 带 outcome：完成当前 RUNNING attempt（双轴结果），若 PASS 且存在
          后段则**同事务**自动启动后段新 attempt；S7 PASS 后返回
          ready_for_completion=True，由 complete_run 做终态判定。
          若当前段 attempt 已终态（如 FAILED）则先创建新 attempt 再完成——
          重试使用新 attempt_id，旧 attempt 永不改写。
        """
        refs = tuple(evidence_refs or ())
        fnds = tuple(findings or ())
        if (execution_status is None) != (policy_verdict is None):
            raise PipelineError(
                "execution_status 与 policy_verdict 必须同时提供或同时省略")
        if execution_status is not None:
            SevenStageStateMachine.validate_outcome(
                execution_status, policy_verdict, fnds)

        def _append_completed(conn: sqlite3.Connection, state: RunState,
                              stage: str, attempt_id: str,
                              result: Dict[str, Any]) -> None:
            """完成 stage 的 RUNNING attempt（双轴结果 → 段终态），事件折叠自证。"""
            attempt_status = SevenStageStateMachine. \
                verdict_to_attempt_status(policy_verdict)
            SevenStageStateMachine.validate_attempt_transition(
                ATTEMPT_RUNNING, attempt_status)
            event = self._base_event(
                "STAGE_COMPLETED", state, execution_status, policy_verdict,
                stage=stage, attempt_id=attempt_id, actor=actor,
                state_version=state.state_version + 1,
                evidence_refs=list(refs), findings=list(fnds))
            self._emit(conn, state, event)
            result["attempt_id"] = attempt_id
            result["attempt_status"] = attempt_status
            result["policy_verdict"] = policy_verdict

        def _append_started(conn: sqlite3.Connection, state: RunState,
                            stage: str, result: Dict[str, Any]) -> str:
            """为 stage 启动新 attempt（首启/重试/推进），事件折叠自证。"""
            SevenStageStateMachine.ensure_prior_stages_passed(
                {k: v.status for k, v in state.stages.items()}, stage)
            ss = state.stages[stage]
            cur = ss.current_attempt
            if cur is not None and cur.status not in TERMINAL_ATTEMPT_STATES:
                raise AttemptImmutabilityError(
                    f"attempt {cur.attempt_id} 尚未终态（{cur.status}），"
                    f"不得叠加新 attempt")
            attempt_id = self._new_attempt_id(stage, len(ss.attempts) + 1)
            event = self._base_event(
                "STAGE_STARTED", state, "COMPLETED", "NOT_EVALUATED",
                stage=stage, attempt_id=attempt_id, actor=actor,
                state_version=state.state_version + 1)
            self._emit(conn, state, event)
            result["started_attempt_id"] = attempt_id
            return attempt_id

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            if state.state == RUN_WAITING_S:
                raise PipelineError(
                    f"run {run_id} WAITING（stop_type="
                    f"{state.waiting.stop_type if state.waiting else '?'}）——"
                    f"须 resume_waiting/cancel 后推进")
            stage = state.current_stage
            if stage is None:
                raise PipelineError(
                    f"run {run_id} 七段全 PASSED——无可推进段，调用 complete_run")
            ss = state.stages[stage]
            cur = ss.current_attempt
            result: Dict[str, Any] = {"run_id": run_id, "stage": stage}

            if cur is not None and cur.status == ATTEMPT_RUNNING:
                if execution_status is None:
                    raise PipelineError(
                        f"attempt {cur.attempt_id} RUNNING——须提供双轴结果完成它")
                _append_completed(conn, state, stage, cur.attempt_id, result)
            elif execution_status is None:
                # 启动模式：当前段 PENDING（首启）或 attempt 已终态（重试）
                _append_started(conn, state, stage, result)
                result["run_state"] = state.state
                result["state_version"] = state.state_version
                result["ready_for_completion"] = (
                    state.current_stage is None and not state.terminal)
                return result
            else:
                # 重试模式：旧 attempt 已终态——新 attempt_id 承接本次双轴结果
                attempt_id = _append_started(conn, state, stage, result)
                _append_completed(conn, state, stage, attempt_id, result)

            # PASS 且有后段 → 同事务自动启动后段（"前段 PASSED 后推进"）；
            # 折叠后 state.stages[stage].status 已是 PASSED，段序校验基于新鲜状态。
            nxt = SevenStageStateMachine.next_stage(stage)
            if (state.stages[stage].status == ATTEMPT_PASSED and nxt is not None
                    and state.state == RUN_RUNNING_S):
                _append_started(conn, state, nxt, result)
                result["next_stage"] = nxt
                result["next_attempt_id"] = result.pop("started_attempt_id")
            result["run_state"] = state.state
            result["state_version"] = state.state_version
            result["ready_for_completion"] = (
                state.current_stage is None and not state.terminal)
            return result

        return self._db.transact(_body)

    def raise_waiting(self, run_id: str, stop_type: str, reason: str,
                      actor: str = "system") -> Dict[str, Any]:
        """触发停等：run RUNNING→WAITING，当前段 attempt RUNNING→WAITING。

        stop_event_id 取 WAITING_RAISED 事件的链上 event_hash——审批的
        stop_event_id 必须精确锚定该值。
        """
        SevenStageStateMachine.precondition_spec(stop_type)  # 校验九类之一
        if not (isinstance(reason, str) and reason.strip()):
            raise PipelineError("reason must be a non-empty string")

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            if state.state != RUN_RUNNING_S:
                raise InvalidTransitionError("run", state.state, RUN_WAITING_S)
            stage = state.current_stage
            if stage is None:
                raise PipelineError("七段全 PASSED 的 run 无处停等")
            cur = state.stages[stage].current_attempt
            if cur is None or cur.status != ATTEMPT_RUNNING:
                raise PipelineError(
                    f"raise_waiting 需要 RUNNING attempt（当前 "
                    f"{cur.status if cur else 'PENDING'}）")
            spec = SevenStageStateMachine.precondition_spec(stop_type)
            required_keys = sorted({k for group in spec["required"]
                                    for k in group})
            event = self._base_event(
                "WAITING_RAISED", state, "BLOCKED", "NOT_EVALUATED",
                stage=stage, attempt_id=cur.attempt_id, actor=actor,
                state_version=state.state_version + 1,
                stop_type=stop_type, stop_reason=reason,
                required_preconditions=required_keys)
            event_hash = self._emit(conn, state, event)  # 折叠内校验全部转换
            return {
                "run_id": run_id, "stage": stage, "stop_type": stop_type,
                "stop_event_id": event_hash,
                "required_preconditions": required_keys,
                "state_version": state.state_version,
                "run_state": state.state,
            }

        return self._db.transact(_body)

    def resume_waiting(
        self,
        run_id: str,
        approval: Mapping[str, Any],
        objective_preconditions: Mapping[str, Any],
        *,
        actor: str = "system",
    ) -> Dict[str, Any]:
        """消费一次性授权后恢复 WAITING：九类停等的必要且充分条件在此会合。

        - 必要：一次性授权（ApprovalBroker 原子消费）+ 客观前置条件规格齐备
          + 哈希绑定 + TTL + scope/SHA/env/state_version CAS——缺一即拒；
        - 充分：以上全部满足后没有任何自由裁量阻断——直接恢复 RUNNING；
        - attempt 不可变：旧 attempt 停留 WAITING，恢复创建新 attempt_id。
        """
        def _loader(conn: sqlite3.Connection) -> RunState:
            return self._load_state(run_id, conn)

        def _resume_event(state: RunState, ap: Mapping[str, Any],
                          nonce_digest: str) -> Mapping[str, Any]:
            if state.state != RUN_WAITING_S or state.waiting is None:
                raise ApprovalRejected(
                    f"run is {state.state}, not WAITING——无可恢复停等")
            waiting = state.waiting
            stage_ss = state.stages[waiting.stage]
            attempt_id = self._new_attempt_id(waiting.stage,
                                              len(stage_ss.attempts) + 1)
            return self._base_event(
                "WAITING_RESUMED", state, "COMPLETED", "NOT_EVALUATED",
                stage=waiting.stage, attempt_id=attempt_id, actor=actor,
                state_version=state.state_version + 1,
                stop_type=waiting.stop_type,
                stop_event_id=waiting.stop_event_id,
                approval_id=ap["approval_id"], nonce_digest=nonce_digest)

        record = self.broker.consume(
            approval,
            run_loader=_loader,
            resume_event_builder=_resume_event,
            objective_preconditions=objective_preconditions,
        )
        state = self.get_run(run_id)
        record["run_state"] = state.state
        cur_stage = state.current_stage
        record["resumed_attempt_id"] = (
            state.stages[cur_stage].current_attempt.attempt_id
            if cur_stage is not None else None)
        return record

    def authorize_risk(self, run_id: str,
                       approval: Mapping[str, Any]) -> Dict[str, Any]:
        """消费一次性 risk 授权进台账——COMPLETED_CONDITIONAL 的前置。"""
        return self.broker.consume_authorization(
            approval, run_loader=lambda conn: self._load_state(run_id, conn))

    def complete_run(self, run_id: str, *, risk_approval_id: Optional[str] = None,
                     reason: str = "", actor: str = "system") -> Dict[str, Any]:
        """终态判定（契约 §3/§5 映射到 run-event-v2 双轴）：
        七段全 PASSED → SUCCEEDED；末段软终态 + 已消费未过期 risk 授权 →
        COMPLETED_CONDITIONAL（无授权即 fail-closed 拒绝）；其余 → FAILED。
        WAITING 中的 run 不得直接 complete（先 resume/cancel）。
        """
        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            if state.state == RUN_WAITING_S:
                raise PipelineError(
                    f"run {run_id} WAITING——先 resume_waiting 或 cancel_run")
            statuses = state.stage_statuses()
            all_passed = all(v == ATTEMPT_PASSED for v in statuses.values())
            soft = [s for s, v in statuses.items()
                    if v == ATTEMPT_COMPLETED_CONDITIONAL]
            unfinished = [s for s, v in statuses.items()
                          if v in (ATTEMPT_PENDING, ATTEMPT_RUNNING,
                                   ATTEMPT_FAILED, ATTEMPT_WAITING)]
            if all_passed:
                final, execution, verdict = (
                    RUN_SUCCEEDED_S, "COMPLETED", "PASS")
                terminal_reason = reason or "七段全 PASSED"
            elif soft and not unfinished:
                risk = self.broker.has_unexpired_risk_authorization(run_id)
                if risk is None or (risk_approval_id is not None
                                    and risk["approval_id"] != risk_approval_id):
                    raise PipelineError(
                        f"run {run_id} 存在软终态段 {soft} 但无可用的已消费、"
                        f"未过期 risk 授权——COMPLETED_CONDITIONAL fail-closed")
                final, execution, verdict = (
                    RUN_COMPLETED_CONDITIONAL_S, "COMPLETED", "CONDITIONAL")
                terminal_reason = reason or (
                    f"risk authorization {risk['approval_id']} active; "
                    f"soft stages: {soft}")
            else:
                if state.state == RUN_CREATED_S:
                    raise InvalidTransitionError(
                        "run", RUN_CREATED_S, RUN_FAILED_S)
                final, execution, verdict = RUN_FAILED_S, "COMPLETED", "FAIL"
                terminal_reason = reason or (
                    f"unfinished/failed stages: {unfinished or soft}")
            event = self._base_event(
                "RUN_COMPLETED", state, execution, verdict, actor=actor,
                state_version=state.state_version + 1,
                terminal_reason=terminal_reason)
            event_hash = self._emit(conn, state, event)  # 折叠内校验终态转换
            return {
                "run_id": run_id, "final_state": final,
                "execution_status": execution, "policy_verdict": verdict,
                "terminal_reason": terminal_reason,
                "state_version": state.state_version,
                "event_hash": event_hash,
            }

        return self._db.transact(_body)

    def cancel_run(self, run_id: str, reason: str = "",
                   actor: str = "system") -> Dict[str, Any]:
        """取消（CREATED/RUNNING/WAITING → CANCELLED；attempt 亦 CANCELLED 由重放推导）。"""
        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            event = self._base_event(
                "RUN_COMPLETED", state, "CANCELLED", "NOT_EVALUATED",
                actor=actor, state_version=state.state_version + 1,
                terminal_reason=reason or "cancelled")
            event_hash = self._emit(conn, state, event)
            return {"run_id": run_id, "final_state": RUN_CANCELLED_S,
                    "state_version": state.state_version,
                    "event_hash": event_hash}

        return self._db.transact(_body)

    def supersede_run(self, run_id: str, reason: str,
                      actor: str = "system") -> Dict[str, Any]:
        """作废（不变量 #3：commit/环境/规则集/范围变化 → 旧 run SUPERSEDED + 新建 run）。"""
        if not (isinstance(reason, str) and reason.strip()):
            raise PipelineError("supersede reason must be non-empty")

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            event = self._base_event(
                "SUPERSEDED", state, "CANCELLED", "NOT_EVALUATED",
                actor=actor, state_version=state.state_version + 1,
                supersede_reason=reason)
            event_hash = self._emit(conn, state, event)
            return {"run_id": run_id, "final_state": RUN_SUPERSEDED_S,
                    "state_version": state.state_version,
                    "event_hash": event_hash}

        return self._db.transact(_body)

    def close(self) -> None:
        self._db.close()

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

事件载荷遵守 ``schemas/run-event-v2.schema.json`` 词表。P0-4 加固后停等
元数据（``stop_type``/``stop_reason``/``required_preconditions``/
``approval_id``/``nonce_digest`` 等）已正式声明进 schema（含 ``seal`` 内部
封印字段），自产事件全部通过 schema 校验。stop_event_id 取值为对应
WAITING_RAISED 事件在哈希链中的 event_hash（64 hex）。

P0-2/P0-4 加固（Codex 第三轮 38/100 BLOCKED 对抗实锤 → 全 fail-closed）：
  #1 伪签名+缺绑定 → envelope 全字段 required + HMAC-SHA256 真实验签
      （keyring 见 ``approval_keys.py``；input_watermark 强制 40-hex 且
      无条件比较；policy/ruleset/env/scope/task/stage 全部 exact 绑定）；
  #2 跨类型 payload → 8 类 payload 互斥封闭（键集封闭），consume() 只收
      resume、consume_authorization() 只收 risk（按 API 路由强制）；
  #3 前置自报 → bool 类客观前置字段（probe_recovered 等）必须真 bool；
  #4 绑定绕过 → 非 40-hex watermark 结构层即拒；policy/ruleset 不再忽略；
  #5 非 resume 无 CAS → risk 授权同样强制 expected_state_version CAS；
  #6 双轴洗白 → execution 非 COMPLETED 不得产出任何完成态（含 CONDITIONAL，
      事件层与 attempt 层双重强制）；P0/P1/CRITICAL/HIGH finding 机器拒绝
      风险接受（authorize_risk 拒绝 + complete_run 拒绝），risk 授权的
      finding_fingerprints 必须与 run 登记面精确匹配；
  #7 控制事件直写 → EventStore.append 控制类型一律 ValueError；
      RunManager._emit 注入内部 seal，重放逐条验封（不合法即
      PipelineCorruptionError）；
  #8 第二正源 → nonce/risk 消费以 pipeline_events 的 APPROVAL_CONSUMED
      事件为唯一正源（approval_consumptions 旁表仅加速），仅复制事件到
      新库后已消费 nonce 仍被拒；
  #9 自产事件不过 schema → run-event-v2 正式声明全部扩展字段；
  #10 action saga 缺失 → ``ActionSaga`` 最小可用实现（RESERVED→STARTED→
      COMMITTED / FAILED_UNKNOWN；control_outbox 事件；receipt 对账占位）。

F4-AUTH-001 根修（Codex 第四轮验收实锤：``approval_consumptions=0`` 时
reserve→start→commit 对 release/production 照样走通、receipt 为调用方
自报字符串）：
  - ``reserve_action`` 必传 approval——消费 action 类型 HMAC 审批（复用
    ``ApprovalBroker.consume_authorization`` 路径：结构/验签/envelope 绑定/
    payload 判别（merge/release/ddl/prod_write/fund_auth/rollback 封闭
    映射）+ expected_state_version CAS），无授权/验签失败/类型不符一律拒。
    授权消费（APPROVAL_CONSUMED）与 ACTION_AUTH_RESERVED 同事务原子成对；
  - receipt 分级：调用方自报 receipt 只能记 PROVISIONAL（事件 receipt
    字符串带内前缀 ``PROVISIONAL|…``，不扩 schema），start 后停在该态；
    COMMITTED 必须凭外部正源回执（action-execution-receipt：键集封闭 +
    HMAC-SHA256 keyring 验签 + 与 ACTION_STARTED 事件的水印/动作一致性），
    事件 receipt 记 ``RECONCILED|<sha256>|<外部引用>``；对账不了/外部声明
    失败的动作走 fail_action → FAILED_UNKNOWN 终态；
  - 重放一致：ACTION_* 折叠校验授权消费链（RESERVED 必须有对应
    APPROVAL_CONSUMED 且 approval_type 与 action_type 匹配）与 receipt
    分级（COMMITTED 出现非 RECONCILED 分级回执即 Corruption）。

W6/P1F（wave6 产品面补缺——§20 验收 ID STATE-02/05/09/11 对应语义）：
  - STATE-02（ID/路径校验面）：全部调用方可控 ID 做结构校验——
    ``create_run`` task_id（^ alphanumeric/-/_ 且 ≤64）、
    ``register_finding`` finding_id（^fnd_ 且 ≤64）、以及 ``_load_state``
    入口的 run_id（^run_[A-Za-z0-9_-]+$ 且 ≤64）。路径穿越（``../``）、
    绝对路径、NUL、超长一律 ``InvalidRunIdError``/``PipelineError`` 拒绝，
    绝不进入事件流寻址；
  - STATE-05（writer epoch fencing）：``RunManager(writer_epoch=N)`` 启用
    写者栅栏。启用者发出的每个控制事件携带 ``writer_epoch`` 扩展字段；
    重放维护流内最大 epoch（单调，旧 epoch 事件即
    ``PipelineCorruptionError``），任何 writer 对 epoch 已被超越的 run 的
    全部变更（advance/raise/resume/authorize/finding/cancel/supersede/
    complete/adjudicate）一律 ``FencedWriterError``。未启用 fencing 的
    存量调用零变化（不盖章、不比较——字节级兼容）；
    诚实边界：fenced 模式事件的 ``writer_epoch`` 字段超出冻结
    run-event-v2 词表（默认模式仍 100% 过 schema）；fencing 作用域=单
    run 事件流（被接管的流整体拒绝旧写者，新流/新 run 不受旧租约牵连）；
    epoch 唯一性由租约发放方保证（同 epoch 视为同一租约）；
  - STATE-09（重放侧身份不变量）：run 事件流内 identity 必须全程逐字
    一致——RUN_CREATED 冻结身份后，任何携带漂移 identity（commit_sha/
    scope_hash/policy_hash/ruleset_hash/environment 等任一变化）或缺
    identity 的 run 事件，重放即 ``PipelineCorruptionError``。SHA/scope/
    policy 变化的唯一正道仍是既有不变量 #3：supersede 旧 run + 新建 run；
  - STATE-11（S7 CONDITIONAL 缺授权终判）：新增
    ``adjudicate_gate_conditional``——S7 软终态且无已消费、未过期、指纹
    精确匹配的 risk 授权时，将该 run 终判 FAILED（RUN_COMPLETED/
    COMPLETED/FAIL）。终态后一切写入（含 WAITING）拒绝，迟到的批准只能
    指向新 run。``complete_run`` 的 fail-closed 拒绝语义保持不变（授权
    到位后 COMPLETED_CONDITIONAL 的正道不受影响）。

R7 审批消费双洞根修（Codex 第七轮，2026-10-08）：
  - R7-AUTH-DUAL-CONSUME-005（P0）——消费侧联签 + payload 绑定实参：
    1) 高危类型（prod_write/ddl/release/fund_auth，单一正源
       ``HIGH_RISK_APPROVAL_TYPES``）的 envelope 必须携带 ``cosignatures``
       数组——至少两名不同 key 的独立联签（各自可验、key_id 互异、均非
       revoked）；缺失/单签/同 key 双签/联签之一 revoked 或验签失败一律
       ``ApprovalRejected``。签发端（approval_issue）已产联签并嵌入信封；
       消费端在 envelope 绑定校验之后、nonce 占位之前补验（拒绝零落账）。
       低危类型携带 cosignatures 在结构层即拒（防「已联签」错觉——与
       签发端 TwoPersonRuleError 同语义）；
    2) exact action descriptor 绑定：``reserve_action`` 新增必填
       ``action_descriptor``（调用方实参声明的动作描述，键集=该类型
       payload 判别字段全集）——与审批 payload 逐字段等值比对，任何
       不符 ``ApprovalRejected``（不再只信 envelope 绑定面）；
    3) 消费事件持久化对账面：APPROVAL_CONSUMED 事件新增
       ``payload_digest``（canonical payload sha256）与
       ``cosign_digests``（联签摘要列表）；重放侧强校验（缺失/形状不符
       /高危缺双联签摘要即 ``PipelineCorruptionError``）。
  - R7-AUTH-KEY-PERM-006（P1）：keyring loader 权限 fail-closed 见
    ``approval_keys.from_path``（0600/0700 + DEV_FIXTURE_EXEMPT_ROOTS
    豁免清单 + ``WENQU_KEYRING_DEV_FIXTURES`` 显式通道）。
  - 诚实边界：envelope 顶层新增可选键 ``cosignatures``、消费事件新增
    ``payload_digest``/``cosign_digests`` 已同步声明进两个 schema 镜像
    （schemas/approval-v2、schemas/run-event-v2）；冻结契约文档
    docs/specs/wenqu-vNext-contract.md 的 v1.0 文本未随行更新（本仓
    工单范围外，登记为后续契约升版工作项）。

R8 审批消费三洞根修（Codex 第八轮 P0-2 残余，2026-10-08）：
  - R8-KEY-LIFECYCLE-001（残余①：退休后新签仍可消费）——key 生命周期按
    **envelope.issued_at** 执法：消费点验签时取 key 元数据时间窗，
    ``issued_at`` 晚于 ``rotated_at``/``expiry`` → ApprovalRejected
    （退休后签的批不能消费）；早于 ``created_at`` → 拒（时间穿越）；
    revoked 保持无条件拒（优先级最高）。执法在
    ``ApprovalBroker._verify_signature``（主签，先于 HMAC 比对）与
    ``_verify_cosignatures``（联签，经 ``verify_detached`` 前的同款
    预检）双面闭合；实现于 ``approval_keys.key_lifecycle_rejection``。
  - R8-ACTUAL-TARGET-003（残余②：actual target 与批准内容未绑定——
    caller 双自报）——``reserve_action`` 的绑定不再双自报：消费点以
    **运行时实参重算 descriptor** 与 payload 等值比对（
    ``_consume_authorization_txn._runtime_descriptor_semantics``）：
    1) kind ← action_type 封闭映射（运行时实参，既有）；
    2) env 实况 ← run 事件流冻结的 identity.environment——payload 携带
       environment 字段的类型（release）必须等值（硬门，无需调用方
       配合）；
    3) artifact 路径实算 hash ← ``runtime_evidence["artifact_paths"]``
       指向的真实文件由消费点现场 sha256（不接受调用方自报哈希）；
    4) 其余运行时观测（head_sha 等）← ``runtime_evidence[field]``（执行
       面现场观测；哨兵 ``"RUN_HEAD"`` = 消费点以 run identity.commit_sha
       实查替换——「当前 HEAD 实查」）。
    caller 传入的 ``action_descriptor`` 降为**提示（hint）**——形状与
    等值比对保留为一致性防线（既有拒绝面不回退），但绑定决策以本门
    重算结果为准，hint 一致不构成授权依据。
  - R8-SIGNER-PRINCIPAL-004（残余③：两个 key 可由同一自报 actor 使用）——
    key 元数据登记 ``owner``/``actors``（签发时登记，
    ``approval_keys._normalize_meta`` 校验）；消费点执法：
    envelope.actor 必须 ∈ 主签 key 的 actors（``_verify_signature``），
    联签条目 actor 各自 ∈ 其 key 的 actors 且**两条目 actor 必须不同**
    （``_verify_cosignatures``——同一 actor 不能用两把不属于他的 key
    凑联签）；未登记 actors 的存量 key 不受 membership 限制（登记面
    opt-in 诚实边界），但联签 actor 互异是硬门。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .approval_keys import ApprovalKeyring, sign_envelope
from .store import GENESIS_HASH, EventStore, is_control_event

__all__ = [
    "SevenStageStateMachine",
    "NineStopTypes",
    "ApprovalBroker",
    "RunManager",
    "ActionSaga",
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
    "ActionError",
    "FencedWriterError",
    "InvalidRunIdError",
    "RECEIPT_PROVISIONAL",
    "RECEIPT_RECONCILED",
    "HIGH_RISK_APPROVAL_TYPES",
    "COSIGNATURE_ENTRY_REQUIRED",
    "approval_payload_digest",
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

# W6/STATE-02：调用方可控 ID 的结构校验面。
# run_id 由 create_run 生成（run_ + 时间戳 + uuid hex 片段，≤64）；任何
# 路径穿越（../）、绝对路径、NUL、超长（>64）或含路径分隔符/非法字符的
# run_id 在进入事件流寻址前直接拒绝——不把不可信 ID 当作"查不到就算了"。
_RUN_ID_PATTERN = re.compile(r"^run_[A-Za-z0-9_-]{1,60}$")   # 总长 ≤ 64
_ID_MAX_LEN = 64


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
# required：全部键必须存在且取值非空；any_of：至少一组全部非空；
# bool_fields：语义为布尔客观事实的字段——取值必须是真正的 bool 类型
# （Codex 实锤 #3：字符串 "false"/"yes" 等自报值一律 ApprovalPreconditionError）。
# 一次性授权（审批消费）是另一半边——两者同时满足 = 充分，缺一 = 不必要地阻断。
STOP_PRECONDITION_SPECS: Dict[str, Dict[str, Any]] = {
    "ambiguity": {
        "description": "一次性授权 + 新需求四要素与 scope hash 冻结",
        "required": (("requirement_four_elements",), ("scope_hash",)),
        "any_of": (),
        "bool_fields": (),
    },
    "prod-write": {
        "description": "一次性 exact-scope 授权 + 对应前置 Gate + 回滚级别",
        "required": (("gate_reference",), ("rollback_level",)),
        "any_of": (),
        "bool_fields": (),
    },
    "ddl": {
        "description": "一次性 exact DDL/环境授权 + fresh/legacy/minimal/回滚验证",
        "required": (
            ("ddl_statement_digest", "environment"),
            ("verification_fresh", "verification_legacy", "verification_minimal"),
            ("rollback_verified",),
        ),
        "any_of": (),
        "bool_fields": ("verification_fresh", "verification_legacy",
                        "verification_minimal", "rollback_verified"),
    },
    "release": {
        "description": "一次性 exact release/SHA/env 授权 + Gate/manifest/回滚预案",
        "required": (
            ("release_id", "commit_sha", "environment"),
            ("gate_reference", "manifest_sha256", "rollback_plan"),
        ),
        "any_of": (),
        "bool_fields": (),
    },
    "scope": {
        "description": "一次性新 scope 授权 + 风险，required 集和证据重新冻结",
        "required": (
            ("new_scope_hash",),
            ("risk_refrozen", "required_set_refrozen", "evidence_refrozen"),
        ),
        "any_of": (),
        "bool_fields": ("risk_refrozen", "required_set_refrozen",
                        "evidence_refrozen"),
    },
    "fund-auth": {
        "description": "一次性资金/权限授权 + 正负测试 + 守恒/审计",
        "required": (
            ("fund_subject_role", "positive_test_ref", "negative_test_ref"),
            ("conservation_check", "audit_target"),
        ),
        "any_of": (),
        "bool_fields": ("conservation_check",),
    },
    "exm-fuse": {
        "description": "一次性裁定授权 + 实际解除熔断（bool）或完成独立治理裁定",
        "required": (("adjudication_ref",),),
        "any_of": ((("fuse_lifted",), ("fuse_lifted_evidence",),
                    ("independent_ruling_ref",)),),
        "bool_fields": ("fuse_lifted",),
    },
    "resource": {
        "description": "一次性恢复授权 + 资源探针恢复并满足安全余量",
        "required": (("resource_probe_ref", "probe_recovered",
                      "safety_margin_met"),),
        "any_of": (),
        "bool_fields": ("probe_recovered", "safety_margin_met"),
    },
    "ext-unavail": {
        "description": "一次性恢复授权 + 外部依赖健康探针恢复并重验证据新鲜度",
        "required": (("dependency_probe_ref", "probe_recovered",
                      "evidence_freshness_reverified"),),
        "any_of": (),
        "bool_fields": ("probe_recovered", "evidence_freshness_reverified"),
    },
}

# ====================================================================== #
# approval-v2 结构规格（镜像 schemas/approval-v2.schema.json）
# P0-4 加固：envelope 全封闭——绑定字段全部 required，无可选豁免；
# payload 按 approval_type 互斥封闭（键集=该类型专属字段，混入他类即拒）。
# ====================================================================== #

_APPROVAL_SCHEMA_VERSION = "2.0"
#: 全部公共字段 required（Codex 实锤 #1：删除绑定字段+伪签名不可再过）
_APPROVAL_REQUIRED_TOP = (
    "schema_version", "approval_id", "approval_type", "key_id", "run_id",
    "task_id", "stop_event_id", "stop_type", "stage", "environment",
    "authorized_scope", "policy_hash", "ruleset_hash", "input_watermark",
    "expected_state_version", "actor", "issued_at", "expires_at", "nonce",
    "decision", "signature", "payload",
)
#: 键集封闭：envelope 顶层唯一可选键为 cosignatures（R7-AUTH-DUAL-
# CONSUME-005：高危类型消费时必携带；低危类型携带即结构层拒）
_APPROVAL_ALLOWED_TOP = frozenset(_APPROVAL_REQUIRED_TOP) | frozenset(
    {"cosignatures"})
_APPROVAL_TYPES = frozenset({
    "resume", "risk", "merge", "release", "ddl", "prod_write",
    "fund_auth", "rollback",
})
_APPROVAL_DECISIONS = frozenset({"approve", "deny", "conditional"})
#: payload 判别封闭（Codex 实锤 #2）：每类 payload 的键集 = 专属字段全集，
# additionalProperties 语义——出现任何他类/未知字段即 ApprovalRejected。
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
_APPROVAL_PAYLOAD_ALLOWED: Dict[str, frozenset] = {
    atype: frozenset(fields)
    for atype, fields in _APPROVAL_PAYLOAD_DISCRIMINATOR.items()
}

# ====================================================================== #
# R7-AUTH-DUAL-CONSUME-005：高危类型联签消费契约（单一正源——签发端
# approval_issue 与本消费端共用；approval_issue 从此处导入再导出）。
# ====================================================================== #

#: 高危审批类型——消费时 envelope 必须携带 ≥2 名不同 key 的独立联签
#: （cosignatures 数组；缺失/单签/同 key 双签/revoked 一律 ApprovalRejected）。
#: 与签发端双人规则（--confirm-two-persons + 第二 key 联签）同一集合。
HIGH_RISK_APPROVAL_TYPES = frozenset({
    "prod_write", "ddl", "release", "fund_auth",
})

#: 联签条目键集封闭：{key_id, actor, signature}——signature 为该 key 对
#: 「信封体」（envelope 去掉 signature/cosignatures）的独立 HMAC-SHA256。
COSIGNATURE_ENTRY_REQUIRED: Tuple[str, ...] = ("key_id", "actor", "signature")
_COSIGNATURE_ENTRY_ALLOWED = frozenset(COSIGNATURE_ENTRY_REQUIRED)
#: 消费端要求的最少独立联签数（两名不同 key——单人双签无效）
_MIN_COSIGNATURES = 2


def approval_payload_digest(payload: Mapping[str, Any]) -> str:
    """canonical payload 的 sha256（R7 消费事件对账面——payload_digest）。"""
    return hashlib.sha256(
        _canonical_json(dict(payload)).encode("utf-8")).hexdigest()

# ====================================================================== #
# P0-4 加固：finding/severity/priority 与风险接受边界（Codex 实锤 #6）
# ====================================================================== #

_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_PRIORITIES = frozenset({"P0", "P1", "P2", "P3"})
#: P0/P1 不得风险接受——HIGH/CRITICAL severity 一律机器拒绝授权
_RISK_REFUSED_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
_RISK_REFUSED_PRIORITIES = frozenset({"P0", "P1"})
#: 可风险接受的 finding 面（与 finding-event-v2 ACCEPTED_RISK 契约一致）
_RISK_ACCEPTABLE_SEVERITIES = frozenset({"MEDIUM", "LOW"})
_RISK_ACCEPTABLE_PRIORITIES = frozenset({"P2", "P3"})

# ====================================================================== #
# P0-4 加固：内部 seal（Codex 实锤 #7）与控制事件密封
# ====================================================================== #

#: seal 派生根（固定胡椒）——seal 密钥按 run 确定性派生：
#: _run_seal_secret(run_id) = HMAC-SHA256(_SEAL_ROOT, run_id)。
#: 确定性派生的理由（工程取舍，诚实边界）：
#: - "仅复制 pipeline_events 重建新库"（Codex 实锤 #8 的正源迁移场景）必须
#:   能重放验封——密钥不能只落在旁表 pipeline_meta（不随事件流迁移）；
#: - 因此 seal 的威胁模型是「公共 API 注入 + 内部 API 误用直写 + 不知道
#:   派生规则的注入」，不防可读源码且可直写 SQL 的 DB 级攻击者——后者由
#:   哈希链（verify_chain）、append-only 触发器与审计承担。
_SEAL_ROOT = hashlib.sha256(
    b"wenqu-pipeline-control-event-seal|v1|7c1f0a2e").hexdigest()


def _run_seal_secret(run_id: str) -> str:
    """按 run_id 确定性派生 seal 密钥（同库/跨库重放一致）。"""
    return hmac.new(_SEAL_ROOT.encode("utf-8"),
                    str(run_id).encode("utf-8"), hashlib.sha256).hexdigest()


def _seal_event(run_id: str, event: Mapping[str, Any]) -> Dict[str, Any]:
    """给控制事件打内部 HMAC 封印（幂等：覆盖旧 seal）。"""
    sealed = {k: v for k, v in dict(event).items() if k != "seal"}
    secret = _run_seal_secret(run_id)
    sealed["seal"] = hmac.new(
        secret.encode("utf-8"),
        _canonical_json(sealed).encode("utf-8"), hashlib.sha256).hexdigest()
    return sealed


def _verify_seal(run_id: Any, event: Mapping[str, Any]) -> bool:
    """重算并常量时间比对事件的 seal；缺失/形状不符/不匹配即 False。"""
    if not isinstance(run_id, str) or not run_id:
        return False
    seal = event.get("seal")
    if not isinstance(seal, str) or len(seal) != 64:
        return False
    body = {k: v for k, v in dict(event).items() if k != "seal"}
    secret = _run_seal_secret(run_id)
    expected = hmac.new(
        secret.encode("utf-8"),
        _canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, seal)


def default_keyring() -> ApprovalKeyring:
    """默认 keyring：环境变量 ``WENQU_APPROVAL_KEYRING`` 指向目录/JSON 文件。

    未配置或路径不存在 → 空 keyring（登记 0 把密钥）——fail-closed：
    任何带 key_id 的审批都因"未知 key"被拒，绝不静默放行。
    """
    import os

    path = os.environ.get("WENQU_APPROVAL_KEYRING", "").strip()
    if not path:
        return ApprovalKeyring()
    try:
        return ApprovalKeyring.from_path(path)
    except (OSError, ValueError):
        return ApprovalKeyring()

# ====================================================================== #
# P0-4 加固：ActionSaga（Codex 实锤 #10）——action 编排最小 saga
# ====================================================================== #

ACTION_RESERVED = "RESERVED"
ACTION_STARTED = "STARTED"
ACTION_COMMITTED = "COMMITTED"
ACTION_FAILED_UNKNOWN = "FAILED_UNKNOWN"

ACTION_STATES: Tuple[str, ...] = (
    ACTION_RESERVED, ACTION_STARTED, ACTION_COMMITTED, ACTION_FAILED_UNKNOWN,
)
TERMINAL_ACTION_STATES = frozenset({ACTION_COMMITTED, ACTION_FAILED_UNKNOWN})
#: saga 转换表：RESERVED→STARTED|FAILED_UNKNOWN；STARTED→COMMITTED|FAILED_UNKNOWN
ACTION_TRANSITIONS: Dict[str, frozenset] = {
    ACTION_RESERVED: frozenset({ACTION_STARTED, ACTION_FAILED_UNKNOWN}),
    ACTION_STARTED: frozenset({ACTION_COMMITTED, ACTION_FAILED_UNKNOWN}),
}

# ----------------------------------------------------------------------
# F4-AUTH-001：action 预留的审批消费封闭映射与 receipt 分级
# ----------------------------------------------------------------------
#: action_type → 必须消费的 approval-v2 审批类型（封闭映射）。resume/risk
#: 走 consume()/consume_authorization(risk) 专属 API 通道，不得用于 action
#: 预留；未知 action_type（如 "deploy"）无对应审批类型——一律拒绝。
_ACTION_APPROVAL_TYPE: Dict[str, str] = {
    "merge": "merge",
    "release": "release",
    "ddl": "ddl",
    "prod-write": "prod_write",
    "prod_write": "prod_write",
    "fund-auth": "fund_auth",
    "fund_auth": "fund_auth",
    "rollback": "rollback",
}

#: receipt 分级（F4-AUTH-001）：run-event-v2 的 receipt 是 string 字段——
#: 分级以带内前缀自证（不扩 schema）：
#:   ``PROVISIONAL|<调用方自报文本>``    ACTION_STARTED 携带的自报回执；
#:   ``RECONCILED|<sha256>|<外部引用>``  ACTION_COMMITTED 携带的外部正源
#:   已验签对账回执（commit_action 验签+一致性通过后落账）。
#: 重放按前缀强校验：COMMITTED 出现非 RECONCILED 分级的回执即 Corruption。
RECEIPT_PROVISIONAL = "PROVISIONAL"
RECEIPT_RECONCILED = "RECONCILED"

#: 外部正源回执（action-execution-receipt v1.0）——执行系统对动作结果的
#: 签名声明。键集封闭；signature = HMAC-SHA256(keyring[key_id],
#: canonical_json(除 signature 外全字段))，与审批验签同一 keyring 体系。
#: watermark 必须等于 run identity.commit_sha（与 ACTION_STARTED 事件的
#: 水印一致——回执不得跨 SHA/跨 run 移花接木）。
_EXTERNAL_RECEIPT_REQUIRED = (
    "schema_version", "receipt_type", "action_id", "run_id", "action_type",
    "action_target", "watermark", "outcome", "external_ref", "ts", "key_id",
    "signature",
)
_EXTERNAL_RECEIPT_ALLOWED = frozenset(_EXTERNAL_RECEIPT_REQUIRED)
_EXTERNAL_RECEIPT_SCHEMA_VERSION = "1.0"
_EXTERNAL_RECEIPT_TYPE = "action-execution-receipt"
_EXTERNAL_RECEIPT_OUTCOMES = frozenset({"COMMITTED", "FAILED"})

#: 观察类控制事件：登记面事件（不改状态机、不递增 state_version），
#: 重放时要求 state_version == 当前值（一致性），侧记入 run 聚合状态。
OBSERVATION_EVENT_TYPES = frozenset({
    "APPROVAL_CONSUMED", "FINDING_REGISTERED",
    "ACTION_AUTH_RESERVED", "ACTION_STARTED", "ACTION_COMMITTED",
    "ACTION_FAILED_UNKNOWN",
})

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


class ActionError(PipelineError):
    """ActionSaga 编排违规（未知 action / 非法转换 / 终态后变更）。"""


class FencedWriterError(PipelineError):
    """writer epoch 落后于事件流当前 epoch——本 writer 对该 run 的全部写入被拒。

    W6/STATE-05（双 writer epoch）：新 writer 以更高 epoch 接管 run 事件流后，
    旧 epoch writer（含未启用 epoch 的 writer，视为 epoch 0）对该 run 的一切
    变更路径（advance/raise/resume/authorize/finding/cancel/supersede/
    complete/adjudicate）均以此错误拒绝；恢复只能由 ≥ 流内 epoch 的 writer 或
    新建 run 承接。
    """


class InvalidRunIdError(PipelineError):
    """run_id 结构非法（路径穿越/绝对路径/NUL/超长/非规范形态）。

    W6/STATE-02：拒绝 ``../``、绝对路径、NUL、超过 64 字符及一切含路径
    分隔符的 ID——不可信 ID 不进入事件流寻址。
    """


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


def _sha256_file(path: str) -> str:
    """对真实文件流式实算 sha256（R8-ACTUAL-TARGET-003：artifact 路径
    实算 hash——不接受调用方自报哈希）。路径不可读/不存在抛 OSError
    （消费点收敛为 ApprovalRejected，fail-closed）。"""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _validate_external_receipt_structure(receipt: Any) -> Dict[str, Any]:
    """action-execution-receipt v1.0 结构校验（键集封闭，全字段 required）。

    纯结构校验（无验签、无一致性比较）——验签在
    ``RunManager._verify_external_receipt``（keyring），一致性比对同处。
    """
    if not isinstance(receipt, Mapping):
        raise ActionError("external receipt must be a JSON object")
    rc = dict(receipt)
    missing = [k for k in _EXTERNAL_RECEIPT_REQUIRED if k not in rc]
    if missing:
        raise ActionError(f"external receipt missing fields: {missing}")
    stray = sorted(set(rc) - _EXTERNAL_RECEIPT_ALLOWED)
    if stray:
        raise ActionError(f"external receipt forbidden fields: {stray}（键集封闭）")
    if rc["schema_version"] != _EXTERNAL_RECEIPT_SCHEMA_VERSION:
        raise ActionError(
            f"external receipt schema_version must be "
            f"{_EXTERNAL_RECEIPT_SCHEMA_VERSION!r}, got {rc['schema_version']!r}")
    if rc["receipt_type"] != _EXTERNAL_RECEIPT_TYPE:
        raise ActionError(
            f"external receipt receipt_type must be {_EXTERNAL_RECEIPT_TYPE!r}")
    if not (isinstance(rc["action_id"], str) and rc["action_id"].startswith("act_")):
        raise ActionError("external receipt action_id must match ^act_*")
    if not (isinstance(rc["run_id"], str) and rc["run_id"].strip()):
        raise ActionError("external receipt run_id must be a non-empty string")
    for key in ("action_type", "action_target", "external_ref"):
        if not (isinstance(rc[key], str) and rc[key].strip()):
            raise ActionError(
                f"external receipt {key} must be a non-empty string")
    if not _is_sha1_hex(rc["watermark"]):
        raise ActionError(
            "external receipt watermark must be a 40-hex git sha（强制绑定）")
    if rc["outcome"] not in _EXTERNAL_RECEIPT_OUTCOMES:
        raise ActionError(
            f"external receipt outcome must be one of "
            f"{sorted(_EXTERNAL_RECEIPT_OUTCOMES)}, got {rc['outcome']!r}")
    if not (isinstance(rc["ts"], str) and rc["ts"].strip()):
        raise ActionError("external receipt ts must be a non-empty string")
    try:
        _parse_iso_ts(rc["ts"])
    except ValueError as exc:
        raise ActionError(f"external receipt ts invalid: {exc}") from None
    if not (isinstance(rc["key_id"], str) and rc["key_id"].startswith("key_")):
        raise ActionError("external receipt key_id must match ^key_*（验签必填）")
    if not (isinstance(rc["signature"], str) and len(rc["signature"]) == 64
            and all(c in _HEX64 for c in rc["signature"].lower())
            and rc["signature"] == rc["signature"].lower()):
        raise ActionError(
            "external receipt signature must be a lowercase 64-hex HMAC-SHA256")
    return rc


def _reconciled_receipt_str(rc: Mapping[str, Any]) -> str:
    """外部回执 → 事件流登记的 RECONCILED 分级 receipt 字符串。"""
    return "{0}|{1}|{2}".format(
        RECEIPT_RECONCILED, _sha256_hex(_canonical_json(dict(rc))),
        rc["external_ref"])


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
    """由 pipeline_events 重放推导的 run 只读状态（无第二正源）。

    P0-4 加固新增登记面（全部由事件流折叠推导，非第二正源）：
    - findings：run 级 finding 登记面（FINDING_REGISTERED 事件）；
    - consumed_nonce_digests / risk_authorizations：审批消费正源
      （APPROVAL_CONSUMED 事件——approval_consumptions 旁表仅加速查询）；
    - actions：ActionSaga 聚合状态（ACTION_* control_outbox 事件）；
    - writer_epoch：流内已见最大 writer epoch（W6/STATE-05 fencing——由
      各事件 writer_epoch 字段折叠，0=未启用/未被接管）。
    """

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
    findings: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    consumed_nonce_digests: set = field(default_factory=set)
    # F4-AUTH-001：nonce_digest → 已消费 approval_type（ACTION_AUTH_RESERVED
    # 重放校验授权消费链的类型匹配半边）
    consumed_nonce_types: Dict[str, str] = field(default_factory=dict)
    risk_authorizations: List[Dict[str, Any]] = field(default_factory=list)
    actions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # W6/STATE-05：流内最大 writer epoch（fencing 判定锚点，重放折叠推导）
    writer_epoch: int = 0

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
        - spec.any_of 至少一组全部非空（exm-fuse 的"实际解除或独立裁定"）；
        - P0-4 加固（Codex 实锤 #3）：spec.bool_fields 语义为布尔客观事实，
          取值必须是真正的 bool——字符串 "false"/"yes"、数字 1 等自报值
          一律 ApprovalPreconditionError（真 false 视为不满足，同规格拒绝）。
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
        # P0-4：bool 类字段客观化——非 bool（含 "false"/"yes"/1）即拒
        for bool_key in spec.get("bool_fields", ()):  # type: ignore[union-attr]
            if bool_key in supplied and not isinstance(supplied[bool_key], bool):
                raise ApprovalPreconditionError(
                    f"objective precondition {bool_key!r} must be a real "
                    f"boolean, got {type(supplied[bool_key]).__name__} "
                    f"{supplied[bool_key]!r}（自报字符串/数字不作数）",
                    {"stop_type": stop_type, "field": bool_key,
                     "got_type": type(supplied[bool_key]).__name__},
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
        """双轴 verdict → 段终态（契约 §2 从严映射：只有 PASS 是 PASSED）。

        注意：本方法只看策略轴；执行轴的强约束由
        :meth:`outcome_to_attempt_status` 承担（P0-4 Codex 实锤 #6 根修：
        execution 非 COMPLETED 不得产出任何完成态，含软终态）。
        """
        if policy_verdict == "PASS":
            return ATTEMPT_PASSED
        if policy_verdict in ("CONDITIONAL", "NOT_APPLICABLE"):
            # CONDITIONAL ≠ PASS（契约 §2）；N/A 仅由受保护 applicability rule
            # 生成，执行完成但策略未判过——均入软终态，不得放行后段。
            return ATTEMPT_COMPLETED_CONDITIONAL
        return ATTEMPT_FAILED  # FAIL / NOT_EVALUATED

    @staticmethod
    def outcome_to_attempt_status(execution_status: str,
                                  policy_verdict: str) -> str:
        """双轴 → 段终态（P0-4 Codex 实锤 #6 根修）。

        执行非 COMPLETED（ERROR/BLOCKED/TIMEOUT/CANCELLED）一律 FAILED——
        TIMEOUT+CONDITIONAL 之类的"双轴洗白"不再可能映射成软终态，
        进而在 complete_run 也不可能产出 COMPLETED_CONDITIONAL。
        """
        if execution_status != "COMPLETED":
            return ATTEMPT_FAILED
        return SevenStageStateMachine.verdict_to_attempt_status(policy_verdict)


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
        1. 结构（镜像 schema：全字段 required/enum/pattern/键集封闭/
           payload 判别封闭/additionalProperties=false）；
        2. P0-4：HMAC-SHA256 真实验签（key_id → keyring secret → 重算比对；
           无 key_id/未知 key/验签失败一律 ApprovalRejected）；
        3. API 路由（Codex 实锤 #2）：consume() 只收 approval_type=resume，
           consume_authorization() 只收其 expected_type（默认 risk）；
        4. decision 必须为 approve（deny/conditional 不足以消费）；
        5. TTL：issued_at <= now < expires_at；
        6. run 绑定（全 required，exact 比较——Codex 实锤 #1/#4）：
           run_id / task_id / stop_event_id / stop_type / stage /
           environment / authorized_scope(=scope_hash) / policy_hash /
           ruleset_hash / input_watermark(=commit_sha，强制 40-hex)；
        7. state_version CAS：expected_state_version == run 当前版本
           （resume 与 risk 等 action 类授权同样强制——Codex 实锤 #5）；
        8. 客观前置条件（resume）：满足该 stop_type 的必要且充分规格，
           且内容哈希 == payload.objective_precondition_hash。

    原子消费（Codex 实锤 #8）：**同一** BEGIN IMMEDIATE 事务内完成
    「占 nonce 旁表（加速索引）+ 追加 APPROVAL_CONSUMED 控制事件（唯一
    正源，带 seal）+（resume 时）追加 WAITING_RESUMED 事件」。nonce 是否
    已消费以事件流为正源判定——仅复制 pipeline_events 重建的新库中，
    同一 nonce 依旧被拒；approval_consumptions 旁表只是查询加速。

    risk 授权（Codex 实锤 #6）：HIGH/CRITICAL severity 一律机器拒绝
    （P0/P1 不得风险接受）；payload.finding_fingerprints 必须与 run
    登记面中"可风险接受 finding"（MEDIUM/LOW 且 P2/P3）的指纹精确匹配。
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
        resume_event_hash TEXT,
        finding_fingerprints TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_approval_consumptions_run
        ON approval_consumptions(run_id);
    """

    def __init__(self, store: EventStore,
                 db: Optional[_PipelineDb] = None,
                 keyring: Optional[ApprovalKeyring] = None) -> None:
        self._store = store
        self._db = db if db is not None else _PipelineDb.from_store(store)
        self._db._conn.executescript(self._CONSUMPTION_SCHEMA)  # noqa: SLF001
        # P0-4：keyring 缺省取环境默认；无任何登记密钥时验签必然拒绝
        # （fail-closed——未知 key_id 即拒，不因 keyring 为空而放行）。
        self._keyring = keyring if keyring is not None else default_keyring()

    # ------------------------------------------------------------------ #
    # 结构校验（镜像 approval-v2.schema.json，无外部依赖；纯结构不含验签）
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
        if not (isinstance(ap["task_id"], str) and ap["task_id"].strip()):
            raise ApprovalRejected("task_id must be a non-empty string")
        if not (isinstance(ap["stop_event_id"], str) and ap["stop_event_id"]):
            raise ApprovalRejected("stop_event_id must be a non-empty string")
        if ap["stage"] not in STAGES:
            raise ApprovalRejected(
                f"invalid stage {ap['stage']!r}; valid: {list(STAGES)}")
        if ap["environment"] not in ENVIRONMENTS:
            raise ApprovalRejected(
                f"invalid environment {ap['environment']!r}; "
                f"valid: {sorted(ENVIRONMENTS)}")
        if not (isinstance(ap["authorized_scope"], str)
                and ap["authorized_scope"].strip()):
            raise ApprovalRejected(
                "authorized_scope must be a non-empty string")
        for hash_field in ("policy_hash", "ruleset_hash"):
            if not (isinstance(ap[hash_field], str)
                    and ap[hash_field].strip()):
                raise ApprovalRejected(
                    f"{hash_field} must be a non-empty string（绑定字段必填）")
        # P0-4（Codex 实锤 #4）：watermark 必须 40-hex sha1——非 40 位不再
        # 被当作"可跳过比较的可选字段"，结构层直接拒绝。
        if not _is_sha1_hex(ap["input_watermark"]):
            raise ApprovalRejected(
                "input_watermark must be a 40-hex git sha（强制绑定 commit_sha）",
                {"input_watermark": ap["input_watermark"]})
        if ap["expected_state_version"] is None or not (
            isinstance(ap["expected_state_version"], int)
            and not isinstance(ap["expected_state_version"], bool)
            and ap["expected_state_version"] >= 1
        ):
            raise ApprovalRejected("expected_state_version must be integer >= 1")
        if not (isinstance(ap["actor"], str) and ap["actor"].strip()):
            raise ApprovalRejected("actor must be a non-empty string")
        if not (isinstance(ap["nonce"], str) and len(ap["nonce"]) >= 16):
            raise ApprovalRejected("nonce must be a string of >= 16 chars")
        # P0-4（Codex 实锤 #1）：signature 必须是 HMAC-SHA256 hex（64 位），
        # 真实验签在 _verify_signature（keyring 查 key 重算比对）。
        if not (isinstance(ap["signature"], str)
                and len(ap["signature"]) == 64
                and all(c in _HEX64 for c in ap["signature"].lower())
                and ap["signature"] == ap["signature"].lower()):
            raise ApprovalRejected(
                "signature must be a lowercase 64-hex HMAC-SHA256")
        if not (isinstance(ap["key_id"], str)
                and ap["key_id"].startswith("key_")
                and len(ap["key_id"]) > 4
                and all(c.isalnum() or c in "-_" for c in ap["key_id"][4:])):
            raise ApprovalRejected(
                "key_id must match ^key_[a-zA-Z0-9_-]+$（验签密钥必填）")
        for ts_field in ("issued_at", "expires_at"):
            try:
                _parse_iso_ts(ap[ts_field])
            except ValueError as exc:
                raise ApprovalRejected(
                    f"invalid date-time in {ts_field}: {exc}") from None
        if _parse_iso_ts(ap["expires_at"]) <= _parse_iso_ts(ap["issued_at"]):
            raise ApprovalRejected("expires_at must be after issued_at")
        # payload 判别封闭（Codex 实锤 #2）：键集 = 该 approval_type 的专属
        # 字段全集——混入他类字段/未知字段即拒（schema additionalProperties=false）
        payload = ap["payload"]
        if not isinstance(payload, Mapping):
            raise ApprovalRejected("payload must be a JSON object")
        atype = ap["approval_type"]
        required_payload = _APPROVAL_PAYLOAD_DISCRIMINATOR[atype]
        allowed_payload = _APPROVAL_PAYLOAD_ALLOWED[atype]
        stray = sorted(set(payload) - allowed_payload)
        if stray:
            raise ApprovalRejected(
                f"payload not closed for approval_type={atype!r}: "
                f"foreign/unknown fields {stray}（判别联合互斥封闭）",
                {"foreign_fields": stray})
        missing = [k for k in required_payload if k not in payload]
        if missing:
            raise ApprovalRejected(
                f"payload discriminator mismatch for "
                f"approval_type={atype!r}: missing {missing}")
        # 非空校验：risk.finding_fingerprints 允许空列表（精确匹配语义：
        # run 无可风险接受 finding 时授权必须声明空覆盖面），其余必非空
        nonempty_fields = [k for k in required_payload
                           if k != "finding_fingerprints"]
        empty = [k for k in nonempty_fields if not _truthy(payload.get(k))]
        if empty:
            raise ApprovalRejected(
                "payload discriminator fields must be non-empty",
                {"empty_fields": empty},
            )
        if atype == "resume":
            if not _is_sha256_hex(payload.get("objective_precondition_hash")):
                raise ApprovalRejected(
                    "payload.objective_precondition_hash must be sha256 hex (64)")
            if payload.get("stop_type") != ap["stop_type"]:
                raise ApprovalRejected(
                    "payload.stop_type conflicts with top-level stop_type")
            if payload.get("stop_event_id") != ap["stop_event_id"]:
                raise ApprovalRejected(
                    "payload.stop_event_id conflicts with top-level stop_event_id")
        if atype == "risk":
            fps = payload.get("finding_fingerprints")
            if (not isinstance(fps, list)
                    or not all(isinstance(f, str) and f.strip() for f in fps)):
                raise ApprovalRejected(
                    "payload.finding_fingerprints must be a list of "
                    "non-empty strings")
            if payload.get("severity") not in _SEVERITIES:
                raise ApprovalRejected(
                    f"invalid risk severity {payload.get('severity')!r}; "
                    f"valid: {sorted(_SEVERITIES)}")
            if not (isinstance(payload.get("compensating_controls"), list)
                    and all(isinstance(c, str) and c.strip()
                            for c in payload["compensating_controls"])):
                raise ApprovalRejected(
                    "payload.compensating_controls must be a list of "
                    "non-empty strings")
            try:
                _parse_iso_ts(payload["expiry"])
            except ValueError as exc:
                raise ApprovalRejected(
                    f"invalid date-time in payload.expiry: {exc}") from None
        if atype == "release" and payload.get("environment") not in ENVIRONMENTS:
            raise ApprovalRejected(
                f"invalid payload.environment {payload.get('environment')!r}")
        # R7-AUTH-DUAL-CONSUME-005：cosignatures（可选顶层键）结构校验——
        # 键集封闭 {key_id, actor, signature}；仅高危类型可携带（低危携带
        # 即拒，防「已联签」错觉——与签发端 TwoPersonRuleError 同语义）。
        # 深度语义（≥2 名不同 key、各自可验、非 revoked）由消费门
        # _verify_cosignatures 在 keyring 上终审。
        if "cosignatures" in ap:
            if atype not in HIGH_RISK_APPROVAL_TYPES:
                raise ApprovalRejected(
                    f"approval_type={atype!r} 非高危类型"
                    f"（高危={sorted(HIGH_RISK_APPROVAL_TYPES)}），"
                    "不得携带 cosignatures（防「已联签」错觉）")
            cosigns = ap["cosignatures"]
            if not isinstance(cosigns, list) or not cosigns:
                raise ApprovalRejected(
                    "cosignatures must be a non-empty array of "
                    "{key_id, actor, signature}")
            for idx, entry in enumerate(cosigns):
                if not isinstance(entry, Mapping):
                    raise ApprovalRejected(
                        f"cosignatures[{idx}] must be a JSON object")
                stray = sorted(set(entry) - _COSIGNATURE_ENTRY_ALLOWED)
                if stray:
                    raise ApprovalRejected(
                        f"cosignatures[{idx}] not closed: unknown fields "
                        f"{stray}（键集={list(COSIGNATURE_ENTRY_REQUIRED)}）")
                missing = [k for k in COSIGNATURE_ENTRY_REQUIRED
                           if k not in entry]
                if missing:
                    raise ApprovalRejected(
                        f"cosignatures[{idx}] missing {missing}")
                kid = entry["key_id"]
                if not (isinstance(kid, str) and kid.startswith("key_")
                        and len(kid) > 4
                        and all(c.isalnum() or c in "-_" for c in kid[4:])):
                    raise ApprovalRejected(
                        f"cosignatures[{idx}].key_id must match "
                        "^key_[a-zA-Z0-9_-]+$")
                if not (isinstance(entry["actor"], str)
                        and entry["actor"].strip()):
                    raise ApprovalRejected(
                        f"cosignatures[{idx}].actor must be a non-empty "
                        "string")
                sig = entry["signature"]
                if not (isinstance(sig, str) and len(sig) == 64
                        and all(c in _HEX64 for c in sig.lower())
                        and sig == sig.lower()):
                    raise ApprovalRejected(
                        f"cosignatures[{idx}].signature must be a lowercase "
                        "64-hex HMAC-SHA256")
        return ap

    # ------------------------------------------------------------------ #
    # P0-4：HMAC-SHA256 真实验签（Codex 实锤 #1/#4）
    # R8-KEY-LIFECYCLE-001：验签前对 issued_at 执法 key 生命周期时间窗
    # R8-SIGNER-PRINCIPAL-004：验签后执法 envelope.actor ∈ key.actors
    # ------------------------------------------------------------------ #
    def _verify_signature(self, ap: Mapping[str, Any]) -> None:
        key_id = ap.get("key_id")
        if not self._keyring.has(key_id):
            raise ApprovalRejected(
                f"unknown signing key_id {key_id!r}（未登记的签发密钥一律拒）",
                {"key_id": key_id,
                 "known_keys": self._keyring.key_ids()})
        # R8-KEY-LIFECYCLE-001：退休后手签的批不能消费（结构校验已保证
        # 消费路径 issued_at 在位——时间窗执法在消费链闭合）。
        lifecycle = self._keyring.key_lifecycle_rejection(
            key_id, ap.get("issued_at"))
        if lifecycle is not None:
            raise ApprovalRejected(
                f"key 生命周期执法拒绝（R8-KEY-LIFECYCLE-001）：{lifecycle}",
                {"key_id": key_id, "approval_id": ap.get("approval_id"),
                 "issued_at": ap.get("issued_at")})
        # R8-SIGNER-PRINCIPAL-004：actor 冒用他人 key 一律拒（登记面
        # opt-in——未登记 actors 的存量 key 不受 membership 限制）。
        # 先于 keyring.verify 的显式门（keyring.verify 内另有同语义兜底，
        # 此处先行以给出精确拒绝消息）。
        actors = self._keyring.key_actors(key_id)
        if actors is not None and ap.get("actor") not in actors:
            raise ApprovalRejected(
                f"signer principal 绑定拒绝（R8-SIGNER-PRINCIPAL-004）："
                f"envelope.actor {ap.get('actor')!r} 不在 key {key_id!r} "
                f"的 actors 登记面 {list(actors)}（actor 冒用他人 key）",
                {"key_id": key_id, "actor": ap.get("actor"),
                 "registered_actors": list(actors),
                 "approval_id": ap.get("approval_id")})
        if not self._keyring.verify(ap):
            raise ApprovalRejected(
                "HMAC-SHA256 signature verification failed（伪签名拒绝）",
                {"key_id": key_id, "approval_id": ap.get("approval_id")})

    # ------------------------------------------------------------------ #
    # R7-AUTH-DUAL-CONSUME-005：高危联签消费门（在 envelope 绑定校验之后、
    # nonce 占位之前调用——拒绝零落账、零 nonce 消耗）
    # ------------------------------------------------------------------ #
    def _verify_cosignatures(self, ap: Mapping[str, Any]) -> None:
        """高危类型 envelope 必须携带 ≥2 名不同 key 的独立联签。

        - 缺失 / 空数组 / 单签（<2 条）→ ApprovalRejected；
        - 同 key 双签（key_id 重复）→ ApprovalRejected；
        - **联签两条目 actor 必须不同**（R8-SIGNER-PRINCIPAL-004 硬门：
          同一 actor 不能用两把 key 凑联签——同 actor 即拒）；
        - 任一联签 key 未登记 / revoked / **issued_at 时间窗外**
          （R8-KEY-LIFECYCLE-001：退休后手签的联签不能消费）/ HMAC 验签
          失败 / **actor ∉ 该 key 的 actors 登记面**（R8-SIGNER-PRINCIPAL-
          004：冒用他人 key 联签）→ ApprovalRejected（fail-closed，绝不
          静默择优）。
        调用方须已通过 validate_structure（cosignatures 形状已校验）。
        """
        atype = ap["approval_type"]
        if atype not in HIGH_RISK_APPROVAL_TYPES:
            return  # 低危类型：无联签要求（结构层已拒「低危携带联签」）
        cosigns = ap.get("cosignatures")
        if not isinstance(cosigns, list) or len(cosigns) < _MIN_COSIGNATURES:
            raise ApprovalRejected(
                f"高危类型 {atype!r} 必须携带 ≥{_MIN_COSIGNATURES} 名不同 "
                "key 的 cosignatures 联签（R7-AUTH-DUAL-CONSUME-005："
                "缺失/单签拒绝——不再只信 envelope 主签名）",
                {"approval_type": atype,
                 "cosign_count": len(cosigns) if isinstance(cosigns, list)
                 else None})
        body = {k: v for k, v in dict(ap).items()
                if k not in ("signature", "cosignatures")}
        seen_key_ids: List[str] = []
        seen_actors: List[str] = []
        for idx, entry in enumerate(cosigns):
            key_id = entry["key_id"]
            if key_id in seen_key_ids:
                raise ApprovalRejected(
                    f"cosignatures[{idx}] 与此前条目同 key（{key_id!r}）——"
                    "同 key 双签不是联签（真双人，R7-AUTH-DUAL-CONSUME-005）",
                    {"duplicate_key_id": key_id})
            seen_key_ids.append(key_id)
            actor = entry["actor"]
            # R8-SIGNER-PRINCIPAL-004：联签两条目的 actor 必须不同——
            # 同一 actor 不能用两把不属于他的 key 凑联签（硬门，与
            # actors 登记面无关）。
            if actor in seen_actors:
                raise ApprovalRejected(
                    f"cosignatures[{idx}] 与此前条目同 actor（{actor!r}）——"
                    "联签两条目的 actor 必须不同（同一 actor 不能用两把 "
                    "key 凑联签，R8-SIGNER-PRINCIPAL-004）",
                    {"duplicate_actor": actor, "cosign_index": idx})
            seen_actors.append(actor)
            if not self._keyring.has(key_id):
                raise ApprovalRejected(
                    f"联签 key_id {key_id!r} 未登记（fail-closed 一律拒）",
                    {"cosign_index": idx, "key_id": key_id})
            # R8-SIGNER-PRINCIPAL-004：actor 必须在该联签 key 的登记面内
            # （登记面 opt-in——未登记 actors 的存量 key 不受限制）。
            actors = self._keyring.key_actors(key_id)
            if actors is not None and actor not in actors:
                raise ApprovalRejected(
                    f"联签 actor {actor!r} 不在 key {key_id!r} 的 actors "
                    f"登记面 {list(actors)}（冒用他人 key 联签——"
                    "R8-SIGNER-PRINCIPAL-004）",
                    {"cosign_index": idx, "key_id": key_id, "actor": actor,
                     "registered_actors": list(actors)})
            # R8-KEY-LIFECYCLE-001：联签与主签同一时间窗执法面——
            # 退休后手签的联签不能消费（verify_detached 内同款兜底）。
            lifecycle = self._keyring.key_lifecycle_rejection(
                key_id, body.get("issued_at"))
            if lifecycle is not None:
                raise ApprovalRejected(
                    f"联签 key 生命周期执法拒绝（R8-KEY-LIFECYCLE-001）："
                    f"{lifecycle}",
                    {"cosign_index": idx, "key_id": key_id,
                     "approval_id": ap.get("approval_id")})
            if not self._keyring.verify_detached(key_id, body,
                                                 entry["signature"]):
                raise ApprovalRejected(
                    f"联签验签失败（cosignatures[{idx}] key_id={key_id}）——"
                    "revoked key / 伪联签一律拒绝",
                    {"cosign_index": idx, "key_id": key_id,
                     "approval_id": ap.get("approval_id")})

    # ------------------------------------------------------------------ #
    # 绑定/TTL/CAS/前置条件校验（对给定 run 快照）——全字段 exact 绑定
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
        if ap["stage"] != waiting.stage:
            raise ApprovalRejected(
                "stage mismatch（审批必须锚定停等段）",
                {"approval_stage": ap["stage"], "waiting_stage": waiting.stage})
        if ap["task_id"] != state.task_id:
            raise ApprovalRejected(
                "task_id mismatch",
                {"approval_task_id": ap["task_id"],
                 "run_task_id": state.task_id})
        identity = state.identity
        if ap["environment"] != identity["environment"]:
            raise ApprovalRejected(
                "environment mismatch（审批不得跨环境）",
                {"approval_environment": ap["environment"],
                 "run_environment": identity["environment"]})
        if ap["authorized_scope"] != identity["scope_hash"]:
            raise ApprovalRejected(
                "authorized_scope != run scope_hash（审批不得扩范围）",
                {"authorized_scope": ap["authorized_scope"],
                 "run_scope_hash": identity["scope_hash"]})
        if ap["policy_hash"] != identity.get("policy_hash"):
            raise ApprovalRejected(
                "policy_hash mismatch（审批必须绑定 run policy）",
                {"approval_policy_hash": ap["policy_hash"],
                 "run_policy_hash": identity.get("policy_hash")})
        if ap["ruleset_hash"] != identity.get("ruleset_hash"):
            raise ApprovalRejected(
                "ruleset_hash mismatch（审批必须绑定 run 规则集）",
                {"approval_ruleset_hash": ap["ruleset_hash"],
                 "run_ruleset_hash": identity.get("ruleset_hash")})
        # 无条件比较（结构层已强制 40-hex——非 40 位根本到不了这里）
        if ap["input_watermark"] != identity["commit_sha"]:
            raise ApprovalRejected(
                "input_watermark != run commit_sha（审批不得跨 SHA）",
                {"input_watermark": ap["input_watermark"],
                 "commit_sha": identity["commit_sha"]})
        if ap["expected_state_version"] != state.state_version:
            raise ApprovalRejected(
                "state_version CAS failure（审批不得跨状态版本）",
                {"expected": ap["expected_state_version"],
                 "actual": state.state_version})
        return dict(ap)

    # ------------------------------------------------------------------ #
    # 事件正源查询（Codex 实锤 #8）：nonce 消费以事件流为唯一正源
    # ------------------------------------------------------------------ #
    @staticmethod
    def _nonce_consumed_from_events(conn: sqlite3.Connection,
                                    nonce: str) -> bool:
        digest = _sha256_hex(nonce)
        for _seq, _event_hash, payload in _PipelineDb.read_events(conn):
            if (payload.get("event_type") == "APPROVAL_CONSUMED"
                    and payload.get("nonce_digest") == digest):
                return True
        return False

    @staticmethod
    def _approval_consumed_event(
        state: RunState, ap: Mapping[str, Any], nonce_digest: str,
        preconditions_hash: Optional[str],
    ) -> Dict[str, Any]:
        """APPROVAL_CONSUMED 控制事件（nonce/risk 消费的唯一正源，观察类）。"""
        event: Dict[str, Any] = {
            "schema_version": "2.0",
            "event_type": "APPROVAL_CONSUMED",
            "run_id": state.run_id,
            "task_id": state.task_id,
            "execution_status": "COMPLETED",
            "policy_verdict": "NOT_EVALUATED",
            "identity": dict(state.identity),
            "state_version": state.state_version,
            "ts": _utc_now_iso(),
            "actor": ap["actor"],
            "approval_id": ap["approval_id"],
            "approval_type": ap["approval_type"],
            "nonce_digest": nonce_digest,
            "stop_type": ap["stop_type"],
            "stop_event_id": ap["stop_event_id"],
            "expires_at": ap["expires_at"],
        }
        if preconditions_hash is not None:
            event["preconditions_hash"] = preconditions_hash
        if ap["approval_type"] == "risk":
            event["finding_fingerprints"] = list(
                ap["payload"].get("finding_fingerprints") or [])
        # R7-AUTH-DUAL-CONSUME-005：消费对账面——canonical payload 摘要 +
        # 联签摘要列表（key 归属 + 签名 sha256 指纹；无联签=空列表）。
        # 重放侧强校验其存在与形状（缺失/高危缺双联签摘要即 Corruption）。
        event["payload_digest"] = approval_payload_digest(ap["payload"])
        event["cosign_digests"] = [
            {"key_id": entry.get("key_id"),
             "actor": entry.get("actor"),
             "signature_digest": _sha256_hex(
                 entry.get("signature") if isinstance(
                     entry.get("signature"), str) else "")}
            for entry in (ap.get("cosignatures") or [])
            if isinstance(entry, Mapping)]
        return event

    # ------------------------------------------------------------------ #
    # 原子消费（resume 专用：nonce + APPROVAL_CONSUMED + WAITING_RESUMED 同事务）
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
        """校验并在单事务内一次性消费 resume 审批，返回消费记录。

        P0-4（Codex 实锤 #2）：本方法只接受 approval_type=resume——risk 等
        action 类授权必须走 consume_authorization（按 API 路由强制的判别）。

        参数：
            run_loader           —— 在事务连接内重放目标 run（保证 CAS 读的是
                                    事务内新鲜状态，杜绝校验-消费间隙竞态）；
            resume_event_builder —— (run_state, normalized_approval, nonce_digest)
                                    → WAITING_RESUMED 事件（由 RunManager 构造，
                                    本方法负责打 seal 后链式插入）；
            objective_preconditions —— 客观前置条件（将对其做规格校验+哈希比对）。
        """
        ap = self.validate_structure(approval)          # 1. 结构（纯函数）
        self._verify_signature(ap)                      # 2. HMAC 真实验签
        if ap["approval_type"] != "resume":             # 3. API 路由判别
            raise ApprovalRejected(
                f"consume() only accepts approval_type=resume; got "
                f"{ap['approval_type']!r}（risk/action 类走 consume_authorization）")
        now = now_epoch if now_epoch is not None else _utc_now_epoch()

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = run_loader(conn)                    # 事务内新鲜快照
            # 重放检测优先（事件流=正源）：已消费即复用，无论 run 现状；
            # 旁表命中同样拒绝（旧库兼容）；并发首消费竞态由 INSERT 主键兜底。
            if self._nonce_consumed_from_events(conn, ap["nonce"]):
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {ap['approval_id']} "
                    f"不可复用——不变量 #5, 事件正源已登记)")
            if conn.execute("SELECT 1 FROM approval_consumptions WHERE nonce = ?",
                            (ap["nonce"],)).fetchone() is not None:
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {ap['approval_id']} "
                    f"不可复用——不变量 #5)")
            bound = self._validate_resume_binding(ap, state, now)  # 4-7 绑定/TTL/CAS
            # 8. 客观前置条件：必要且充分规格 + 授权哈希精确绑定
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
            # —— 写半边（同事务）：旁表索引 → APPROVAL_CONSUMED 正源事件
            #    → WAITING_RESUMED 控制事件（均带 seal）——
            try:
                conn.execute(
                    "INSERT INTO approval_consumptions "
                    "(nonce, approval_id, approval_type, run_id, stop_type, "
                    " decision, expires_at, consumed_at, preconditions_hash, "
                    " resume_event_hash, finding_fingerprints) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                    (bound["nonce"], bound["approval_id"],
                     bound["approval_type"], state.run_id, bound["stop_type"],
                     bound["decision"], bound["expires_at"], time.time(),
                     precond_hash),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {bound['approval_id']} "
                    f"不可复用——不变量 #5): {exc}") from None
            consumed_event = _seal_event(
                state.run_id,
                self._approval_consumed_event(state, bound, nonce_digest,
                                              precond_hash))
            _PipelineDb.append_event(conn, consumed_event)
            event = _seal_event(
                state.run_id,
                dict(resume_event_builder(state, bound, nonce_digest)))
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
    # 非停等类授权（risk 等）的一次性消费——COMPLETED_CONDITIONAL 前置核验
    # ------------------------------------------------------------------ #
    def consume_authorization(
        self,
        approval: Mapping[str, Any],
        *,
        run_loader: Callable[[sqlite3.Connection], RunState],
        now_epoch: Optional[float] = None,
        expected_approval_type: str = "risk",
    ) -> Dict[str, Any]:
        """一次性消费非停等授权（默认 risk；Codex 实锤 #2/#5/#6 加固）。

        fail-closed 纪律：结构校验（键集封闭）→ HMAC 验签 → API 路由
        （只收 expected_approval_type，resume 一律拒）→ decision=approve →
        TTL → run 绑定（run_id/task_id/environment/scope/policy/ruleset/
        watermark/stage 全 exact）→ **expected_state_version CAS（同样强制）**
        → risk 语义（HIGH/CRITICAL 机器拒绝 + 指纹与 run 登记面精确匹配）
        → 同事务原子「旁表索引 + APPROVAL_CONSUMED 正源事件（带 seal）」。
        """
        ap = self.validate_structure(approval)
        self._verify_signature(ap)
        if ap["approval_type"] == "resume":
            raise ApprovalRejected(
                "resume 审批必须经 consume() 与停等事件绑定消费")
        if ap["approval_type"] != expected_approval_type:
            raise ApprovalRejected(
                f"authorization route mismatch: expected approval_type="
                f"{expected_approval_type!r}, got {ap['approval_type']!r}")
        now = now_epoch if now_epoch is not None else _utc_now_epoch()
        return self._db.transact(
            lambda conn: self._consume_authorization_txn(
                conn, ap, run_loader, now, expected_approval_type))

    # ------------------------------------------------------------------ #
    def _consume_authorization_txn(
        self,
        conn: sqlite3.Connection,
        ap: Mapping[str, Any],
        run_loader: Callable[[sqlite3.Connection], RunState],
        now: float,
        expected_approval_type: str,
        action_descriptor: Optional[Mapping[str, Any]] = None,
        require_descriptor: bool = False,
        runtime_evidence: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """consume_authorization 的事务体（在已开启的 BEGIN IMMEDIATE 内执行）。

        F4-AUTH-001：暴露给同文件 ``RunManager.reserve_action`` 在**同一**
        事务内复用——授权消费（旁表 + APPROVAL_CONSUMED 正源事件）与
        ACTION_AUTH_RESERVED 原子成对，中途失败整体回滚。
        调用方须已完成结构校验、验签与 approval_type 路由判定。

        R7-AUTH-DUAL-CONSUME-005（校验次序即拒绝消息语义，勿重排）：
        nonce 复用 → envelope 绑定（env/scope/policy/ruleset/watermark/
        stage/CAS 的既有拒绝消息保持不变）→ **高危联签门**（缺失/单签/
        同 key/revoked/同 actor/actor 冒用/生命周期窗外全拒）→ risk 语义
        → **action_descriptor 提示一致性门**（形状与等值比对保留——既有
        拒绝面不回退；hint 非绑定权威）→ **actual-target 运行时重算门**
        （R8-ACTUAL-TARGET-003：env 实况硬门 + runtime_evidence 重算实参
        与 payload 等值比对）→ 全过后才占 nonce 落事件。
        """

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
            if ap["task_id"] != state.task_id:
                raise ApprovalRejected(
                    "task_id mismatch",
                    {"approval_task_id": ap["task_id"],
                     "run_task_id": state.task_id})
            if state.terminal:
                raise ApprovalRejected(
                    "run is terminal; authorization has no target",
                    {"run_state": state.state})
            ident = state.identity
            if ap["environment"] != ident["environment"]:
                raise ApprovalRejected("environment mismatch（审批不得跨环境）")
            if ap["authorized_scope"] != ident["scope_hash"]:
                raise ApprovalRejected(
                    "authorized_scope != run scope_hash（审批不得扩范围）")
            if ap["policy_hash"] != ident.get("policy_hash"):
                raise ApprovalRejected(
                    "policy_hash mismatch（审批必须绑定 run policy）")
            if ap["ruleset_hash"] != ident.get("ruleset_hash"):
                raise ApprovalRejected(
                    "ruleset_hash mismatch（审批必须绑定 run 规则集）")
            # 无条件比较（结构层已强制 40-hex）
            if ap["input_watermark"] != ident["commit_sha"]:
                raise ApprovalRejected(
                    "input_watermark != run commit_sha（审批不得跨 SHA）")
            # stage exact 绑定：须锚定 run 当前活跃段（全 PASSED 时锚定末段）
            anchor_stage = (state.current_stage if state.current_stage is not None
                            else STAGES[-1])
            if ap["stage"] != anchor_stage:
                raise ApprovalRejected(
                    "stage mismatch（授权必须锚定 run 当前活跃段）",
                    {"approval_stage": ap["stage"], "anchor_stage": anchor_stage})
            # P0-4（Codex 实锤 #5）：action 类授权同样强制 state_version CAS
            if ap["expected_state_version"] != state.state_version:
                raise ApprovalRejected(
                    "state_version CAS failure（action 类授权同样不得跨状态版本）",
                    {"expected": ap["expected_state_version"],
                     "actual": state.state_version})

        def _risk_semantics(ap: Mapping[str, Any], state: RunState) -> None:
            """risk 专属：HIGH/CRITICAL 机器拒绝 + 指纹与登记面精确匹配。"""
            severity = ap["payload"]["severity"]
            if severity in _RISK_REFUSED_SEVERITIES:
                raise ApprovalRejected(
                    f"severity {severity} 不可风险接受（P0/P1 不得风险接受"
                    "——机器拒绝，无人工豁免）",
                    {"severity": severity})
            eligible = sorted({
                f["fingerprint"] for f in state.findings.values()
                if f.get("severity") in _RISK_ACCEPTABLE_SEVERITIES
                and f.get("priority") in _RISK_ACCEPTABLE_PRIORITIES})
            claimed = sorted(set(ap["payload"]["finding_fingerprints"]))
            if claimed != eligible:
                raise ApprovalRejected(
                    "risk payload.finding_fingerprints 必须与 run 实际"
                    "可风险接受 finding 指纹精确匹配",
                    {"claimed": claimed, "run_eligible": eligible})

        def _action_descriptor_semantics() -> None:
            """R7-AUTH-DUAL-CONSUME-005 洞 1a（R8 降级为**提示**）：hint 一致性。

            caller 传入的 ``action_descriptor`` 与审批 payload 逐字段等值
            比对（形状/键集/等值任一不符即 ApprovalRejected——既有拒绝面
            不回退）。R8-ACTUAL-TARGET-003 起本门只是 hint 一致性防线：
            payload 与 descriptor 同为调用方自报（caller 双自报），一致
            **不构成**绑定依据——绑定决策以
            ``_runtime_descriptor_semantics`` 的运行时重算为准。
            """
            if not require_descriptor:
                return
            if not isinstance(action_descriptor, Mapping):
                raise ApprovalRejected(
                    "reserve_action requires action_descriptor（调用方实参"
                    "声明的动作描述，键集=该类型 payload 判别字段全集）——"
                    "R7-AUTH-DUAL-CONSUME-005：payload 必须与实参 exact 绑定")
            expected_fields = _APPROVAL_PAYLOAD_DISCRIMINATOR[
                expected_approval_type]
            descriptor = dict(action_descriptor)
            payload = dict(ap["payload"])
            stray = sorted(set(descriptor) - set(expected_fields))
            if stray:
                raise ApprovalRejected(
                    f"action_descriptor 含非本类型字段 {stray}（"
                    f"approval_type={expected_approval_type!r} 的判别字段全集"
                    f"为 {list(expected_fields)}）")
            missing = [k for k in expected_fields if k not in descriptor]
            if missing:
                raise ApprovalRejected(
                    f"action_descriptor 缺字段 {missing}（须覆盖该类型 "
                    "payload 判别字段全集并与审批 payload 等值）")
            for field in expected_fields:
                if descriptor[field] != payload.get(field):
                    raise ApprovalRejected(
                        f"action descriptor mismatch：审批 payload 的 "
                        f"{field!r}={payload.get(field)!r} 与 reserve_action "
                        f"实参 {descriptor[field]!r} 不符——exact action "
                        "descriptor 绑定拒绝（R7-AUTH-DUAL-CONSUME-005）",
                        {"field": field,
                         "approval_value": payload.get(field),
                         "caller_value": descriptor[field]})

        def _runtime_descriptor_semantics(state: RunState) -> None:
            """R8-ACTUAL-TARGET-003：消费点以**运行时实参重算 descriptor**
            与 payload 等值比对——actual target 绑定不再 caller 双自报。

            重算源（全部独立于 caller 的 payload 自报）：
            1) kind：action_type 封闭映射 → expected_approval_type
               （运行时实参；reserve_action 路由门已强制，此处不重复）；
            2) env 实况：run 事件流冻结的 identity.environment——payload
               携带 environment 字段的类型（release）必须等值（硬门，
               无需调用方配合）；
            3) artifact 路径实算 hash：``runtime_evidence["artifact_paths"]``
               的 {字段: 路径}——消费点对真实文件现场 sha256（不接受
               调用方自报哈希；路径不可读 fail-closed 拒）；
            4) 其余运行时观测：``runtime_evidence[字段]``（执行面现场
               观测值；哨兵 ``"RUN_HEAD"`` = 消费点以 run
               identity.commit_sha 实查替换——「当前 HEAD 实查」）。
            诚实边界：evidence 的非哨兵值仍是执行面自报观测（与 payload
            分属两个角色通道，非免验正源）；env/kind/文件哈希三项由消费
            点独立取得，不受调用方文本控制。
            """
            payload = dict(ap["payload"])
            fields = _APPROVAL_PAYLOAD_DISCRIMINATOR[expected_approval_type]
            # (2) env 实况硬门：payload 声明的目标环境必须等于 run 冻结环境
            if "environment" in fields and \
                    payload.get("environment") != state.identity["environment"]:
                raise ApprovalRejected(
                    "actual-target 绑定拒绝（R8-ACTUAL-TARGET-003）：审批 "
                    f"payload 的 environment={payload.get('environment')!r} "
                    "与运行时实况（run 冻结 environment="
                    f"{state.identity['environment']!r}）不符——批准内容"
                    "不得指向另一环境",
                    {"field": "environment",
                     "approval_value": payload.get("environment"),
                     "runtime_value": state.identity["environment"]})
            if runtime_evidence is None:
                return
            if not isinstance(runtime_evidence, Mapping):
                raise ApprovalRejected(
                    "runtime_evidence 必须是 JSON 对象（字段→运行时实况"
                    "观测值；artifact_paths={字段:路径} 由消费点实算）")
            evidence = dict(runtime_evidence)
            allowed_keys = set(fields) | {"artifact_paths"}
            stray = sorted(set(evidence) - allowed_keys)
            if stray:
                raise ApprovalRejected(
                    f"runtime_evidence 含非本类型字段 {stray}（"
                    f"approval_type={expected_approval_type!r} 的判别字段"
                    f"全集为 {sorted(fields)}，另有保留键 artifact_paths）")
            for field, observed in evidence.items():
                if field == "artifact_paths":
                    continue
                actual = observed
                if isinstance(actual, str) and actual == "RUN_HEAD":
                    actual = state.identity["commit_sha"]  # 当前 HEAD 实查
                if payload.get(field) != actual:
                    raise ApprovalRejected(
                        "actual-target 绑定拒绝（R8-ACTUAL-TARGET-003）："
                        f"审批 payload 的 {field!r}={payload.get(field)!r} "
                        f"与运行时实参 {actual!r} 不符——descriptor 以运行"
                        "时实参重算比对（caller 自报 payload/descriptor "
                        "不再是绑定依据）",
                        {"field": field,
                         "approval_value": payload.get(field),
                         "runtime_value": actual})
            art_paths = evidence.get("artifact_paths")
            if art_paths is None:
                return
            if not isinstance(art_paths, Mapping):
                raise ApprovalRejected(
                    "runtime_evidence.artifact_paths 必须是 {字段: 路径} "
                    "对象（消费点对真实文件现场实算 sha256）")
            for field, path in art_paths.items():
                if field not in fields or not field.endswith("_sha256"):
                    raise ApprovalRejected(
                        f"runtime_evidence.artifact_paths 的键 {field!r} "
                        f"必须是 {expected_approval_type!r} payload 的 "
                        "*_sha256 字段（实算 hash 只对哈希字段开放）")
                if not (isinstance(path, str) and path.strip()):
                    raise ApprovalRejected(
                        f"runtime_evidence.artifact_paths[{field!r}] "
                        "必须是非空文件路径（实算 hash fail-closed）")
                try:
                    computed = _sha256_file(path)
                except OSError as exc:
                    raise ApprovalRejected(
                        f"artifact 路径实算失败（{field!r} → {path!r}）："
                        f"{exc}——fail-closed 拒绝（不采信任何自报哈希）",
                        {"field": field, "path": path}) from None
                if payload.get(field) != computed:
                    raise ApprovalRejected(
                        "actual-target 绑定拒绝（R8-ACTUAL-TARGET-003）："
                        f"审批 payload 的 {field!r}={payload.get(field)!r} "
                        f"与 artifact 路径实算 sha256（{path!r} → "
                        f"{computed!r}）不符",
                        {"field": field, "path": path,
                         "approval_value": payload.get(field),
                         "computed_sha256": computed})

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = run_loader(conn)
            # 重放检测优先（事件正源 + 旁表，同 consume）
            if self._nonce_consumed_from_events(conn, ap["nonce"]):
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {ap['approval_id']} "
                    f"不可复用——不变量 #5, 事件正源已登记)")
            if conn.execute("SELECT 1 FROM approval_consumptions WHERE nonce = ?",
                            (ap["nonce"],)).fetchone() is not None:
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {ap['approval_id']} "
                    f"不可复用——不变量 #5)")
            _binding(ap, state)
            self._verify_cosignatures(ap)
            if expected_approval_type == "risk":
                _risk_semantics(ap, state)
            _action_descriptor_semantics()
            _runtime_descriptor_semantics(state)
            try:
                conn.execute(
                    "INSERT INTO approval_consumptions "
                    "(nonce, approval_id, approval_type, run_id, stop_type, "
                    " decision, expires_at, consumed_at, preconditions_hash, "
                    " resume_event_hash, finding_fingerprints) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
                    (ap["nonce"], ap["approval_id"], ap["approval_type"],
                     state.run_id, ap["stop_type"], ap["decision"],
                     ap["expires_at"], time.time(),
                     json.dumps(ap["payload"].get("finding_fingerprints")
                                or [])),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalReuseError(
                    f"nonce already consumed (approval {ap['approval_id']} "
                    f"不可复用——不变量 #5): {exc}") from None
            consumed_event = _seal_event(
                state.run_id,
                self._approval_consumed_event(
                    state, ap, _sha256_hex(ap["nonce"]), None))
            _PipelineDb.append_event(conn, consumed_event)
            return {
                "approval_id": ap["approval_id"],
                "approval_type": ap["approval_type"],
                "nonce_digest": _sha256_hex(ap["nonce"]),
                "run_id": state.run_id,
                "stop_type": ap["stop_type"],
                "consumed": True,
            }

        return _body(conn)

    # ------------------------------------------------------------------ #
    def consumed_approvals(self, run_id: Optional[str] = None,
                           approval_type: Optional[str] = None
                           ) -> List[Dict[str, Any]]:
        """查询消费台账（加速索引；正源是 APPROVAL_CONSUMED 事件流）。"""
        sql = ("SELECT nonce, approval_id, approval_type, run_id, stop_type, "
               "decision, expires_at, consumed_at, preconditions_hash, "
               "resume_event_hash, finding_fingerprints "
               "FROM approval_consumptions")
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
                "resume_event_hash", "finding_fingerprints")
        return [dict(zip(keys, r)) for r in rows]

    @staticmethod
    def risk_authorizations_from_events(
        conn: sqlite3.Connection, run_id: str,
        now_epoch: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """从事件流（唯一正源）重建 run 的 risk 授权记录。

        仅复制 pipeline_events 重建的新库中，该方法同样还原消费面——
        旁表 approval_consumptions 不在场也不影响判定。
        """
        now = now_epoch if now_epoch is not None else _utc_now_epoch()
        found: List[Dict[str, Any]] = []
        for _seq, _event_hash, payload in _PipelineDb.read_events(conn):
            if (payload.get("event_type") != "APPROVAL_CONSUMED"
                    or payload.get("approval_type") != "risk"
                    or payload.get("run_id") != run_id):
                continue
            try:
                expires = _parse_iso_ts(payload.get("expires_at", ""))
            except ValueError:
                continue
            found.append({
                "approval_id": payload.get("approval_id"),
                "nonce_digest": payload.get("nonce_digest"),
                "expires_at": payload.get("expires_at"),
                "expires_at_epoch": expires.timestamp(),
                "finding_fingerprints": sorted(
                    payload.get("finding_fingerprints") or []),
                "unexpired": expires.timestamp() > now,
            })
        return found

    def has_unexpired_risk_authorization(self, run_id: str,
                                         now_epoch: Optional[float] = None
                                         ) -> Optional[Dict[str, Any]]:
        """查找 run 已消费、未过期的 risk 授权（事件流正源重建）。"""
        for row in self.risk_authorizations_from_events(
                self._db._conn, run_id, now_epoch):  # noqa: SLF001
            if row["unexpired"]:
                return row
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
                 broker: Optional[ApprovalBroker] = None,
                 keyring: Optional[ApprovalKeyring] = None,
                 writer_epoch: Optional[int] = None) -> None:
        """
        writer_epoch（W6/STATE-05，可选）：启用写者栅栏——本 writer 以该
        epoch 写入（控制事件盖章 ``writer_epoch``），对事件流 epoch 已被更高
        writer 接管的 run 的全部变更一律 FencedWriterError。None（默认，存量
        调用）不启用：不盖章、不比较，行为字节级不变。
        """
        if writer_epoch is not None and (
                not isinstance(writer_epoch, int)
                or isinstance(writer_epoch, bool) or writer_epoch < 1):
            raise PipelineError(
                "writer_epoch must be an integer >= 1 or None (lease token)")
        self._writer_epoch = writer_epoch
        self._store = store
        self._db = _PipelineDb.from_store(store)
        # seal 密钥按 run 确定性派生（_run_seal_secret）——_emit 打封印，
        # 重放逐条验封（Codex 实锤 #7）；跨库复制事件流仍可验证。
        self.broker = broker if broker is not None else ApprovalBroker(
            store, db=self._db, keyring=keyring)

    # ------------------------------------------------------------------ #
    # W6/STATE-02：run_id 结构校验（路径穿越/绝对路径/NUL/超长一律拒绝）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_run_id(run_id: Any) -> str:
        if not isinstance(run_id, str) or not _RUN_ID_PATTERN.match(run_id):
            raise InvalidRunIdError(
                f"run_id 结构非法（须 ^run_[A-Za-z0-9_-]+$ 且 ≤{_ID_MAX_LEN} 字符；"
                f"拒绝 ../、绝对路径、NUL、超长 ID——STATE-02）: {run_id!r}")
        return run_id

    # ------------------------------------------------------------------ #
    # W6/STATE-05：writer epoch fencing（旧 epoch 写者对被接管 run 全写入拒绝）
    # ------------------------------------------------------------------ #
    @property
    def writer_epoch(self) -> Optional[int]:
        """本 writer 的租约 epoch（None=未启用 fencing）。"""
        return self._writer_epoch

    def _fence_check(self, state: RunState) -> None:
        mine = self._writer_epoch if self._writer_epoch is not None else 0
        if state.writer_epoch > mine:
            raise FencedWriterError(
                f"run {state.run_id} 事件流已被 writer epoch "
                f"{state.writer_epoch} 接管，本 writer（epoch={mine or '0，未启用'}）"
                f"的全部写入被拒（STATE-05 双 writer fencing）——恢复须由不低于"
                f"流内 epoch 的 writer 或新 run 承接")

    def _fenced_loader(
            self, run_id: str) -> Callable[[sqlite3.Connection], RunState]:
        """带 fencing 核验的 run_loader（broker 消费路径共用 _load_state，
        其变更入口不经 _require_mutable——在 loader 内补栅栏核验）。"""
        def _loader(conn: sqlite3.Connection) -> RunState:
            st = self._load_state(run_id, conn)
            self._fence_check(st)
            return st
        return _loader

    # ------------------------------------------------------------------ #
    # 身份校验（run-event-v2.identity）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_identity(identity: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(identity, Mapping):
            raise InvalidIdentityError("identity must be a JSON object")
        ident = dict(identity)
        for key in ("commit_sha", "environment", "scope_hash",
                    "policy_hash", "ruleset_hash"):
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
    # P0-4 加固：每个控制事件先验内部 seal（Codex 实锤 #7）——缺失/不合法
    # 即 PipelineCorruptionError；观察类事件（APPROVAL_CONSUMED/
    # FINDING_REGISTERED/ACTION_*）不递增 state_version，侧记入登记面。
    # ------------------------------------------------------------------ #
    def _replay_fold(self, state: Optional[RunState], event_hash: str,
                     ev: Mapping[str, Any]) -> RunState:
        etype = ev.get("event_type")
        # seal 验封：管线控制事件必须携带合法内部 seal（_emit 注入）。
        # 密钥按事件 run_id 确定性派生——跨库复制事件流后仍可验证。
        if is_control_event(ev) and not _verify_seal(ev.get("run_id"), ev):
            raise PipelineCorruptionError(
                f"event {etype!r} (hash {event_hash[:16]}…) missing/invalid "
                f"internal seal——事件流疑遭直写注入（Codex 实锤 #7）")
        if state is None:
            if etype != "RUN_CREATED":
                raise PipelineCorruptionError(
                    f"run {ev.get('run_id')!r} 首事件非 RUN_CREATED: {etype}")
            ident = ev.get("identity") or {}
            stages = {s: StageState(stage=s) for s in STAGES}
            epoch0 = ev.get("writer_epoch")
            if epoch0 is not None and (not isinstance(epoch0, int)
                                       or isinstance(epoch0, bool)
                                       or epoch0 < 1):
                raise PipelineCorruptionError(
                    f"run {ev.get('run_id')!r}: RUN_CREATED writer_epoch 非法 "
                    f"{epoch0!r}（须 >= 1 的整数——STATE-05）")
            state = RunState(
                run_id=ev["run_id"], task_id=ev.get("task_id", ""),
                identity=dict(ident), state=RUN_CREATED_S,
                state_version=int(ev.get("state_version", 1)),
                stages=stages, created_at=ev.get("ts"),
                writer_epoch=epoch0 if isinstance(epoch0, int) else 0,
            )
            return state

        # ---- W6/STATE-09：run 事件流 identity 不变量（重放侧）----
        # RUN_CREATED 冻结身份后，流内任何事件携带的 identity 必须逐字一致。
        # SHA/scope/policy（及环境/规则集等）任一漂移或缺 identity 的 run 事件
        # 即 Corruption——身份变化没有"原地改"路径，唯一正道是
        # supersede + 新建 run（不变量 #3）。
        ident_ev = ev.get("identity")
        if not isinstance(ident_ev, Mapping) or dict(ident_ev) != state.identity:
            raise PipelineCorruptionError(
                f"run {state.run_id}: event {etype!r} identity 漂移/缺失"
                f"（流内身份必须全程一致；SHA/scope/policy 变化强制新 run"
                f"——STATE-09）。流身份={_canonical_json(state.identity)}，"
                f"事件身份={_canonical_json(ident_ev) if isinstance(ident_ev, Mapping) else repr(ident_ev)}")

        # ---- W6/STATE-05：writer epoch fencing（重放侧）----
        # 携带 writer_epoch 的事件参与流内 epoch 单调性：低于已见最大 epoch
        # 即旧 epoch 写入/重放被拒（Corruption）；更高则接管（流内 epoch 前移）。
        epoch_ev = ev.get("writer_epoch")
        if epoch_ev is not None:
            if not isinstance(epoch_ev, int) or isinstance(epoch_ev, bool) \
                    or epoch_ev < 1:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: event {etype!r} writer_epoch 非法 "
                    f"{epoch_ev!r}（须 >= 1 的整数——STATE-05）")
            if epoch_ev < state.writer_epoch:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: event {etype!r} writer_epoch "
                    f"{epoch_ev} < 流内当前 epoch {state.writer_epoch}"
                    f"（旧 epoch 写入/重放被拒——STATE-05 双 writer fencing）")
            if epoch_ev > state.writer_epoch:
                state.writer_epoch = epoch_ev

        # ---- 观察类控制事件：登记面侧记，不推进状态机 ----
        if etype in OBSERVATION_EVENT_TYPES:
            observed_version = ev.get("state_version")
            if (not isinstance(observed_version, int)
                    or isinstance(observed_version, bool)
                    or observed_version != state.state_version):
                raise PipelineCorruptionError(
                    f"run {state.run_id}: observation event {etype} "
                    f"state_version {observed_version!r} != current "
                    f"{state.state_version}（登记面事件必须锚定当前版本）")
            if etype == "APPROVAL_CONSUMED":
                digest = ev.get("nonce_digest")
                if not (isinstance(digest, str) and len(digest) == 64):
                    raise PipelineCorruptionError(
                        f"run {state.run_id}: APPROVAL_CONSUMED 缺合法 "
                        f"nonce_digest（消费正源事件损坏）")
                atype = ev.get("approval_type")
                if not (isinstance(atype, str) and atype):
                    raise PipelineCorruptionError(
                        f"run {state.run_id}: APPROVAL_CONSUMED 缺合法 "
                        f"approval_type（F4-AUTH-001 授权消费链损坏）")
                # R7-AUTH-DUAL-CONSUME-005：消费对账面强校验——payload_digest
                # 必在且 64-hex；cosign_digests 必为形状合法列表；高危类型
                # 必须携带 ≥2 名不同 key 的联签摘要（缺失/缩水=事件损坏）。
                pd = ev.get("payload_digest")
                if not _is_sha256_hex(pd):
                    raise PipelineCorruptionError(
                        f"run {state.run_id}: APPROVAL_CONSUMED 缺合法 "
                        f"payload_digest（R7 消费对账面损坏）")
                cds = ev.get("cosign_digests")
                if not isinstance(cds, list):
                    raise PipelineCorruptionError(
                        f"run {state.run_id}: APPROVAL_CONSUMED 缺合法 "
                        f"cosign_digests（R7 消费对账面损坏）")
                for cd in cds:
                    if not (isinstance(cd, Mapping)
                            and isinstance(cd.get("key_id"), str)
                            and cd.get("key_id")
                            and isinstance(cd.get("actor"), str)
                            and _is_sha256_hex(cd.get("signature_digest"))):
                        raise PipelineCorruptionError(
                            f"run {state.run_id}: APPROVAL_CONSUMED "
                            f"cosign_digests 条目形状非法（R7 对账面损坏）")
                if atype in HIGH_RISK_APPROVAL_TYPES:
                    cd_keys = [cd.get("key_id") for cd in cds]
                    if len(cd_keys) < _MIN_COSIGNATURES or \
                            len(set(cd_keys)) != len(cd_keys):
                        raise PipelineCorruptionError(
                            f"run {state.run_id}: 高危 {atype} 的 "
                            f"APPROVAL_CONSUMED 联签摘要不足/同 key 双签"
                            f"（须 ≥{_MIN_COSIGNATURES} 名不同 key——R7 "
                            "消费对账面损坏）")
                state.consumed_nonce_digests.add(digest)
                # F4-AUTH-001：记录 nonce→审批类型，供 ACTION_AUTH_RESERVED
                # 重放校验「授权消费类型与 action_type 匹配」。
                state.consumed_nonce_types[digest] = atype
                if ev.get("approval_type") == "risk":
                    state.risk_authorizations.append({
                        "approval_id": ev.get("approval_id"),
                        "nonce_digest": digest,
                        "expires_at": ev.get("expires_at"),
                        "finding_fingerprints": sorted(
                            ev.get("finding_fingerprints") or []),
                    })
            elif etype == "FINDING_REGISTERED":
                fid = ev.get("finding_id")
                if not (isinstance(fid, str) and fid.startswith("fnd_")):
                    raise PipelineCorruptionError(
                        f"run {state.run_id}: FINDING_REGISTERED 非法 "
                        f"finding_id {fid!r}")
                if (ev.get("severity") not in _SEVERITIES
                        or ev.get("priority") not in _PRIORITIES
                        or not (isinstance(ev.get("fingerprint"), str)
                                and ev["fingerprint"].strip())):
                    raise PipelineCorruptionError(
                        f"run {state.run_id}: FINDING_REGISTERED {fid} "
                        f"severity/priority/fingerprint 非法")
                if fid in state.findings:
                    raise PipelineCorruptionError(
                        f"run {state.run_id}: finding {fid} 重复登记"
                        f"（登记面 append-only，一条 finding 只登记一次）")
                state.findings[fid] = {
                    "finding_id": fid,
                    "fingerprint": ev["fingerprint"],
                    "severity": ev["severity"],
                    "priority": ev["priority"],
                    "stage": ev.get("stage"),
                    "registered_at": ev.get("ts"),
                }
            else:  # ACTION_* control_outbox 事件
                action_id = ev.get("action_id")
                if not (isinstance(action_id, str) and action_id):
                    raise PipelineCorruptionError(
                        f"run {state.run_id}: {etype} 缺 action_id")
                self._replay_fold_action(state, etype, ev)
            return state

        # state_version 单调 CAS：每个状态转换事件 = +1
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
            # P0-4（Codex 实锤 #6）：双轴→attempt 终态须过 outcome 级映射
            # ——execution 非 COMPLETED 一律 FAILED，TIMEOUT+CONDITIONAL
            # 之类的洗白在重放层同样被拒。
            attempt_status = SevenStageStateMachine.outcome_to_attempt_status(
                ev.get("execution_status", ""), ev.get("policy_verdict", ""))
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
            # 双轴合法性自证：非 COMPLETED 不得 PASS；PASS 不得带 findings
            try:
                SevenStageStateMachine.validate_outcome(
                    execution or "", verdict or "", ev.get("findings") or ())
            except InvalidOutcomeError as exc:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: RUN_COMPLETED 双轴非法: {exc}") from None
            if execution == "CANCELLED":
                final = RUN_CANCELLED_S
            elif execution == "COMPLETED":
                if verdict == "PASS":
                    final = RUN_SUCCEEDED_S
                elif verdict == "CONDITIONAL":
                    final = RUN_COMPLETED_CONDITIONAL_S
                else:
                    final = RUN_FAILED_S
            else:
                # P0-4（Codex 实锤 #6）：execution 非 COMPLETED（且非 CANCELLED）
                # 不得产出任何完成态——含 COMPLETED_CONDITIONAL。
                raise PipelineCorruptionError(
                    f"run {state.run_id}: RUN_COMPLETED execution_status="
                    f"{execution!r} 不得产出完成态（TIMEOUT/ERROR/BLOCKED "
                    f"只能走 FAILED/CANCELLED）")
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

    @staticmethod
    def _replay_fold_action(state: RunState, etype: str,
                            ev: Mapping[str, Any]) -> None:
        """ACTION_* control_outbox 事件的 saga 折叠（非法转换即 Corruption）。

        F4-AUTH-001：折叠含授权消费链与 receipt 分级校验——
        - RESERVED 必须携带 approval_id + nonce_digest，且事件流中此前存在
          对应 APPROVAL_CONSUMED（其 approval_type 与 action_type 匹配）；
        - STARTED 的自报 receipt 必须是 PROVISIONAL 分级（带内前缀）；
        - COMMITTED 的 receipt 必须是 RECONCILED|<sha256>|<外部引用> 分级
          ——自报裸串/PROVISIONAL 分级出现在 COMMITTED 即 Corruption。
        """
        action_id = ev["action_id"]
        target_state = {
            "ACTION_AUTH_RESERVED": ACTION_RESERVED,
            "ACTION_STARTED": ACTION_STARTED,
            "ACTION_COMMITTED": ACTION_COMMITTED,
            "ACTION_FAILED_UNKNOWN": ACTION_FAILED_UNKNOWN,
        }[etype]
        current = state.actions.get(action_id)
        if target_state == ACTION_RESERVED:
            if current is not None:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: action {action_id} 重复 RESERVED")
            approval_id = ev.get("approval_id")
            nonce_digest = ev.get("nonce_digest")
            action_type = ev.get("action_type", "")
            if not (isinstance(approval_id, str)
                    and approval_id.startswith("apr_")):
                raise PipelineCorruptionError(
                    f"run {state.run_id}: ACTION_AUTH_RESERVED {action_id} "
                    f"缺合法 approval_id（无授权预留——F4-AUTH-001）")
            if not _is_sha256_hex(nonce_digest):
                raise PipelineCorruptionError(
                    f"run {state.run_id}: ACTION_AUTH_RESERVED {action_id} "
                    f"缺合法 nonce_digest（授权消费链断链——F4-AUTH-001）")
            consumed_type = state.consumed_nonce_types.get(nonce_digest)
            if consumed_type is None:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: action {action_id} RESERVED 无对应 "
                    f"APPROVAL_CONSUMED（授权消费链缺失——F4-AUTH-001）")
            expected = _ACTION_APPROVAL_TYPE.get(action_type)
            if expected is None or consumed_type != expected:
                raise PipelineCorruptionError(
                    f"run {state.run_id}: action {action_id} 的授权消费类型 "
                    f"{consumed_type!r} 与 action_type {action_type!r} 不匹配"
                    f"（F4-AUTH-001 授权消费链）")
            state.actions[action_id] = {
                "action_id": action_id,
                "action_type": action_type,
                "action_target": ev.get("action_target", ""),
                "action_state": ACTION_RESERVED,
                "approval_id": approval_id,
                "nonce_digest": nonce_digest,
                "receipt": None,
                "receipt_status": None,
                "reserved_at": ev.get("ts"),
            }
            return
        if current is None:
            raise PipelineCorruptionError(
                f"run {state.run_id}: action {action_id} {etype} 无 RESERVED 前置")
        if target_state not in ACTION_TRANSITIONS.get(current["action_state"],
                                                      frozenset()):
            raise PipelineCorruptionError(
                f"run {state.run_id}: action {action_id} 非法转换 "
                f"{current['action_state']} -> {target_state}")
        if target_state == ACTION_STARTED:
            receipt = ev.get("receipt")
            if receipt is not None:
                if not (isinstance(receipt, str) and receipt.startswith(
                        RECEIPT_PROVISIONAL + "|")):
                    raise PipelineCorruptionError(
                        f"run {state.run_id}: action {action_id} STARTED 携带"
                        f"非 PROVISIONAL 分级 receipt（自报分级越权"
                        f"——F4-AUTH-001）")
                current["receipt"] = receipt
                current["receipt_status"] = RECEIPT_PROVISIONAL
        elif target_state == ACTION_COMMITTED:
            receipt = ev.get("receipt")
            parts = receipt.split("|") if isinstance(receipt, str) else []
            if (len(parts) != 3 or parts[0] != RECEIPT_RECONCILED
                    or not _is_sha256_hex(parts[1]) or not parts[2].strip()):
                raise PipelineCorruptionError(
                    f"run {state.run_id}: action {action_id} COMMITTED receipt "
                    f"非外部正源对账分级（RECONCILED|<sha256>|<外部引用>）"
                    f"——自报回执不可 COMMITTED（F4-AUTH-001）")
            current["receipt"] = receipt
            current["receipt_status"] = RECEIPT_RECONCILED
        current["action_state"] = target_state
        current[f"{target_state.lower()}_at"] = ev.get("ts")

    def _load_state(self, run_id: str,
                    conn: Optional[sqlite3.Connection] = None) -> RunState:
        # W6/STATE-02：run_id 结构校验先于寻址（路径穿越/绝对路径/NUL/超长
        # 一律拒绝，不进入事件流过滤）——单闸口覆盖全部公开 API。
        self._validate_run_id(run_id)
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
        # W6/STATE-05：终态检查后补写者栅栏——旧 epoch writer 对该 run 的
        # 全部变更路径在此统一拒绝（各变更 API 均先 _require_mutable）。
        self._fence_check(state)

    def _emit(self, conn: sqlite3.Connection, state: RunState,
              event: Mapping[str, Any]) -> str:
        """打内部 seal 后追加事件并立即重放折叠进内存 state。

        事件须携带 state.state_version + 1；_replay_fold 内部会校验 seal、
        单调性、转换表与段序，因此本方法之后的内存状态与事后重放严格一致。
        seal 密钥按 run_id 确定性派生——控制事件不可经公共
        EventStore.append 注入（append 对控制类型直接 ValueError）。
        W6/STATE-05：启用 writer_epoch 的 writer 在此盖章（写前再核栅栏，
        观测面事件与状态面事件同一闸口）；未启用者不盖章（字节级兼容）。
        """
        ev = dict(event)
        if self._writer_epoch is not None:
            self._fence_check(state)
            ev["writer_epoch"] = self._writer_epoch
        sealed = _seal_event(state.run_id, ev)
        event_hash, _ = _PipelineDb.append_event(conn, sealed)
        self._replay_fold(state, event_hash, sealed)
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
                and len(task_id) <= _ID_MAX_LEN
                and all(c.isalnum() or c in "-_" for c in task_id)):
            raise PipelineError(
                "task_id must match ^[a-zA-Z0-9_-]+$ and be <= 64 chars"
                "（拒绝 ../、绝对路径、NUL、超长 ID——STATE-02）")
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
            raw = self._base_event(
                "RUN_CREATED", seed, "COMPLETED", "NOT_EVALUATED", actor=actor)
            if self._writer_epoch is not None:   # W6/STATE-05：fenced 写者盖章
                raw["writer_epoch"] = self._writer_epoch
            event = _seal_event(run_id, raw)
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
            """完成 stage 的 RUNNING attempt（双轴结果 → 段终态），事件折叠自证。

            P0-4（Codex 实锤 #6）：outcome 级映射——execution 非 COMPLETED
            一律 FAILED（TIMEOUT+CONDITIONAL 不得洗白成软终态）。
            """
            attempt_status = SevenStageStateMachine.outcome_to_attempt_status(
                execution_status, policy_verdict)
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
            run_loader=self._fenced_loader(run_id),   # W6/STATE-05：栅栏核验
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
            approval, run_loader=self._fenced_loader(run_id))  # W6/STATE-05

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
                # P0-4（Codex 实锤 #6 根修）：run 登记面带 P0/P1/CRITICAL/HIGH
                # finding 时机器拒绝——P0/P1 不得风险接受，无人工豁免路径。
                severe = {fid: f for fid, f in state.findings.items()
                          if f.get("severity") in _RISK_REFUSED_SEVERITIES
                          or f.get("priority") in _RISK_REFUSED_PRIORITIES}
                if severe:
                    raise PipelineError(
                        f"run {run_id} 存在不可风险接受 finding "
                        f"{sorted(severe)}（P0/P1/CRITICAL/HIGH）——"
                        f"COMPLETED_CONDITIONAL 机器拒绝（P0/P1 不得风险接受）")
                # risk 授权以事件流为正源（state.risk_authorizations 由
                # APPROVAL_CONSUMED 折叠而来），且指纹必须与当前可风险接受
                # finding 面精确匹配（防过期授权/移花接木的覆盖）。
                eligible = sorted({
                    f["fingerprint"] for f in state.findings.values()
                    if f.get("severity") in _RISK_ACCEPTABLE_SEVERITIES
                    and f.get("priority") in _RISK_ACCEPTABLE_PRIORITIES})
                now = _utc_now_epoch()
                risk = None
                for auth in state.risk_authorizations:
                    try:
                        unexpired = (_parse_iso_ts(auth["expires_at"]).timestamp()
                                     > now)
                    except (ValueError, TypeError):
                        continue
                    if unexpired and sorted(auth["finding_fingerprints"]) == eligible:
                        risk = auth
                        break
                if risk is None or (risk_approval_id is not None
                                    and risk["approval_id"] != risk_approval_id):
                    raise PipelineError(
                        f"run {run_id} 存在软终态段 {soft} 但无可用的已消费、"
                        f"未过期且指纹精确匹配的 risk 授权——"
                        f"COMPLETED_CONDITIONAL fail-closed")
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
            # 双轴终态事件合法性自证（非 COMPLETED 不得 PASS 等）
            SevenStageStateMachine.validate_outcome(execution, verdict)
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

    def adjudicate_gate_conditional(self, run_id: str, *, reason: str = "",
                                    actor: str = "system") -> Dict[str, Any]:
        """STATE-11｜S7 CONDITIONAL 缺 risk authorization → run 终判 FAILED。

        语义（与 ``complete_run`` 互补，二者均保持 fail-closed）：
        - 适用面：末段 S7 处于 COMPLETED_CONDITIONAL（软终态），且不存在
          已消费、未过期、finding 指纹与 run 登记面精确匹配的 risk 授权
          （判据与 ``complete_run`` 的 COMPLETED_CONDITIONAL 半边完全一致）；
        - 终判：RUN_COMPLETED（execution=COMPLETED，policy_verdict=FAIL）
          → run 终态 FAILED。S7 attempt 证据保持不可变（COMPLETED_CONDITIONAL
          留档——attempt 一旦终态不可改写），终判落在 run 层；
        - 终态后不得写 WAITING：raise_waiting/advance/resume/register_finding
          等全部变更拒绝（TerminalRunError/ApprovalRejected），迟到的批准
          （authorize_risk/resume_waiting）对该 run 无目标——只能创建新 run
          重新授权（新 run_id + 新 state_version CAS 绑定）；
        - 误用防护：存在可用 risk 授权时本方法拒绝（应走 complete_run →
          COMPLETED_CONDITIONAL）；S7 非软终态时拒绝。
        """
        def _usable_risk(state: RunState) -> Optional[Dict[str, Any]]:
            eligible = sorted({
                f["fingerprint"] for f in state.findings.values()
                if f.get("severity") in _RISK_ACCEPTABLE_SEVERITIES
                and f.get("priority") in _RISK_ACCEPTABLE_PRIORITIES})
            now = _utc_now_epoch()
            for auth in state.risk_authorizations:
                try:
                    unexpired = (_parse_iso_ts(auth["expires_at"]).timestamp()
                                 > now)
                except (ValueError, TypeError):
                    continue
                if unexpired and sorted(auth["finding_fingerprints"]) == eligible:
                    return auth
            return None

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            if state.state == RUN_WAITING_S:
                raise PipelineError(
                    f"run {run_id} WAITING——先 resume_waiting 或 cancel_run")
            last = STAGES[-1]
            s7_status = state.stages[last].status
            if s7_status != ATTEMPT_COMPLETED_CONDITIONAL:
                raise PipelineError(
                    f"{last} 状态为 {s7_status}（非 COMPLETED_CONDITIONAL）——"
                    f"本终判仅针对 S7 软终态缺 risk authorization（STATE-11）")
            risk = _usable_risk(state)
            if risk is not None:
                raise PipelineError(
                    f"run {run_id} 存在可用（已消费/未过期/指纹匹配）risk 授权 "
                    f"{risk['approval_id']}——应走 complete_run → "
                    f"COMPLETED_CONDITIONAL，而非终判 FAILED（STATE-11 误用防护）")
            terminal_reason = reason or (
                f"{last} COMPLETED_CONDITIONAL 缺可用 risk authorization——"
                f"S7/run 终判 FAILED（STATE-11；后续批准只能创建新 run）")
            SevenStageStateMachine.validate_outcome("COMPLETED", "FAIL")
            event = self._base_event(
                "RUN_COMPLETED", state, "COMPLETED", "FAIL", actor=actor,
                state_version=state.state_version + 1,
                terminal_reason=terminal_reason)
            event_hash = self._emit(conn, state, event)  # 折叠内校验终态转换
            return {
                "run_id": run_id, "final_state": RUN_FAILED_S,
                "execution_status": "COMPLETED", "policy_verdict": "FAIL",
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

    # ------------------------------------------------------------------ #
    # P0-4：run 级 finding 登记面（Codex 实锤 #6——CONDITIONAL 完成的核验基础）
    # ------------------------------------------------------------------ #
    def register_finding(self, run_id: str, finding_id: str, fingerprint: str,
                         severity: str, priority: str, *,
                         detail: str = "",
                         actor: str = "system") -> Dict[str, Any]:
        """在 run 登记面追加一条 finding（FINDING_REGISTERED 观察事件）。

        登记面是 authorize_risk 指纹精确匹配与 complete_run 机器拒绝
        （P0/P1/CRITICAL/HIGH）的核验基础；append-only——同一 finding_id
        只能登记一次。
        """
        if not (isinstance(finding_id, str) and finding_id.startswith("fnd_")
                and 4 < len(finding_id) <= _ID_MAX_LEN      # W6/STATE-02：超长拒
                and all(c.isalnum() or c == "_" for c in finding_id[4:])):
            raise PipelineError(
                f"finding_id must match ^fnd_[a-zA-Z0-9_]+$ and be "
                f"<={_ID_MAX_LEN} chars（拒绝 ../、绝对路径、NUL、超长 ID"
                f"——STATE-02）, got {finding_id!r}")
        if not (isinstance(fingerprint, str) and fingerprint.strip()):
            raise PipelineError("fingerprint must be a non-empty string")
        if severity not in _SEVERITIES:
            raise PipelineError(
                f"invalid severity {severity!r}; valid: {sorted(_SEVERITIES)}")
        if priority not in _PRIORITIES:
            raise PipelineError(
                f"invalid priority {priority!r}; valid: {sorted(_PRIORITIES)}")

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            if finding_id in state.findings:
                raise PipelineError(
                    f"finding {finding_id} 已登记——登记面 append-only，"
                    f"不得重复登记")
            event = self._base_event(
                "FINDING_REGISTERED", state, "COMPLETED", "NOT_EVALUATED",
                actor=actor, state_version=state.state_version,
                finding_id=finding_id, fingerprint=fingerprint,
                severity=severity, priority=priority, finding_detail=detail)
            event_hash = self._emit(conn, state, event)
            return {"run_id": run_id, "finding_id": finding_id,
                    "fingerprint": fingerprint, "severity": severity,
                    "priority": priority, "event_hash": event_hash}

        return self._db.transact(_body)

    # ------------------------------------------------------------------ #
    # P0-4：ActionSaga（Codex 实锤 #10）——action 编排最小 saga
    # RESERVED → STARTED → COMMITTED / FAILED_UNKNOWN（终态）
    # F4-AUTH-001：预留强制审批消费 + receipt 分级 + 外部正源对账
    # ------------------------------------------------------------------ #
    def reserve_action(self, run_id: str, action_type: str, target: str,
                       approval: Optional[Mapping[str, Any]] = None, *,
                       actor: str = "system",
                       action_descriptor: Optional[Mapping[str, Any]] = None,
                       runtime_evidence: Optional[Mapping[str, Any]] = None,
                       ) -> Dict[str, Any]:
        """预留一个授权动作（ACTION_AUTH_RESERVED control_outbox 事件）。

        F4-AUTH-001 根修：预留必须消费一份 action 类型 HMAC 审批
        （approval-v2：结构校验 → HMAC 验签 → approval_type 与 action_type
        封闭映射匹配 → ``consume_authorization`` 路径的 envelope 绑定
        （run_id/task_id/environment/scope/policy/ruleset/watermark/stage
        全 exact）+ expected_state_version CAS + TTL + 一次性 nonce）。
        无授权 / 验签失败 / 类型不符 / nonce 复用一律拒绝，绝不落事件。

        授权消费（APPROVAL_CONSUMED 正源事件）与 ACTION_AUTH_RESERVED 在
        **同一** BEGIN IMMEDIATE 事务内原子成对；重放侧校验授权消费链
        （reserved 必须有对应 APPROVAL_CONSUMED 且类型匹配）。

        R7-AUTH-DUAL-CONSUME-005（两道消费门，均在 envelope 绑定之后、
        nonce 占位之前——拒绝零落账零消费）：
        - ``action_descriptor``（必填实参，**R8 起降为提示 hint**）：调用
          方声明的动作描述（键集=该审批类型 payload 判别字段全集），与
          审批 payload 逐字段等值比对——形状/等值不符即拒（既有拒绝面
          不回退），但一致不构成绑定依据（caller 双自报）；
        - 高危类型（prod_write/ddl/release/fund_auth）envelope 必须携带
          ≥2 名不同 key 的 cosignatures 联签（各自可验、非 revoked、
          issued_at 在 key 生命周期窗内、条目 actor 互异且各自 ∈ 其
          key 的 actors 登记面）——签发端双人联签进入消费契约。

        R8-ACTUAL-TARGET-003（actual target 绑定，权威门）：消费点以
        **运行时实参重算 descriptor** 与 payload 等值比对——
        - env 实况硬门：release 类 payload.environment 必须 == run 冻结
          environment（无需调用方配合即执法）；
        - ``runtime_evidence``（可选实参）：执行面运行时观测值
          ``{字段: 观测}``（哨兵 ``"RUN_HEAD"`` = 消费点以 run
          identity.commit_sha 实查替换）+ ``artifact_paths={字段: 路径}``
          （消费点对真实文件现场实算 sha256）——任一字段与 payload 不符
          即 ApprovalRejected；含非本类型字段即拒；路径不可读 fail-closed。
        """
        ActionSaga.validate_descriptor(action_type, target)
        if approval is None:
            raise ActionError(
                "reserve_action requires 对应 action 类型的 HMAC 审批"
                "（approval 参数，F4-AUTH-001）——无授权预留一律拒绝")
        expected = _ACTION_APPROVAL_TYPE.get(action_type)
        if expected is None:
            raise ActionError(
                f"unknown action_type {action_type!r}：必须是 "
                f"{sorted(set(_ACTION_APPROVAL_TYPE))} 之一（带连字符/下划线"
                f"等价变体）且携带匹配类型的审批")
        ap = self.broker.validate_structure(approval)
        self.broker._verify_signature(ap)  # noqa: SLF001 —— 同模块受管复用
        if ap["approval_type"] != expected:
            raise ApprovalRejected(
                f"action_type={action_type!r} 要求 approval_type="
                f"{expected!r}，got {ap['approval_type']!r}（类型不符拒绝）")
        now = _utc_now_epoch()

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            # 同事务消费授权（旁表 + APPROVAL_CONSUMED 正源事件）——
            # 任一步失败整体回滚，授权与预留绝不成单只。事务体内依次：
            # nonce 复用 → envelope 绑定 → 高危联签门 → risk 语义（N/A）→
            # action_descriptor 提示门 → actual-target 运行时重算门 →
            # 占 nonce 落事件。
            self.broker._consume_authorization_txn(  # noqa: SLF001
                conn, ap, self._fenced_loader(run_id), now, expected,
                action_descriptor=action_descriptor, require_descriptor=True,
                runtime_evidence=runtime_evidence)
            state = self._load_state(run_id, conn)  # 折叠入 APPROVAL_CONSUMED
            action_id = f"act_{uuid.uuid4().hex[:12]}"
            event = self._base_event(
                "ACTION_AUTH_RESERVED", state, "COMPLETED", "NOT_EVALUATED",
                actor=actor, state_version=state.state_version,
                action_id=action_id, action_type=action_type,
                action_target=target,
                approval_id=ap["approval_id"],
                nonce_digest=_sha256_hex(ap["nonce"]))
            event_hash = self._emit(conn, state, event)
            return {"run_id": run_id, "action_id": action_id,
                    "action_state": ACTION_RESERVED,
                    "action_type": action_type, "action_target": target,
                    "approval_id": ap["approval_id"],
                    "nonce_digest": _sha256_hex(ap["nonce"]),
                    "payload_digest": approval_payload_digest(ap["payload"]),
                    "event_hash": event_hash}

        return self._db.transact(_body)

    def _advance_action(self, run_id: str, action_id: str, new_state: str,
                        *, event_type: str, actor: str,
                        **extra: Any) -> Dict[str, Any]:

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            action = state.actions.get(action_id)
            if action is None:
                raise ActionError(f"unknown action_id {action_id!r} on {run_id}")
            ActionSaga.validate_transition(action["action_state"], new_state)
            event = self._base_event(
                event_type, state, "COMPLETED", "NOT_EVALUATED",
                actor=actor, state_version=state.state_version,
                action_id=action_id, action_type=action["action_type"],
                **extra)
            event_hash = self._emit(conn, state, event)
            return {"run_id": run_id, "action_id": action_id,
                    "action_state": new_state, "event_hash": event_hash}

        return self._db.transact(_body)

    def start_action(self, run_id: str, action_id: str, *,
                     receipt: Optional[str] = None,
                     actor: str = "system") -> Dict[str, Any]:
        """启动已预留的动作（RESERVED → STARTED）。

        F4-AUTH-001 receipt 分级：调用方可附带自报 receipt——但只能以
        PROVISIONAL 分级登记（事件 receipt 记 ``PROVISIONAL|<自报文本>``），
        start 后停在该态；COMMITTED 必须另行通过外部正源回执对账
        （commit_action）。自报文本不得自带分级前缀（分级由管线落账）。
        """
        extra: Dict[str, Any] = {}
        if receipt is not None:
            if not (isinstance(receipt, str) and receipt.strip()):
                raise ActionError("receipt must be a non-empty string")
            if receipt.startswith((RECEIPT_PROVISIONAL + "|",
                                   RECEIPT_RECONCILED + "|")):
                raise ActionError(
                    "自报 receipt 不得自带分级前缀（分级由管线落账，"
                    "非调用方声明）")
            extra["receipt"] = f"{RECEIPT_PROVISIONAL}|{receipt}"
        return self._advance_action(run_id, action_id, ACTION_STARTED,
                                    event_type="ACTION_STARTED", actor=actor,
                                    **extra)

    def commit_action(self, run_id: str, action_id: str,
                      receipt: Mapping[str, Any], *,
                      actor: str = "system") -> Dict[str, Any]:
        """提交动作——必须凭外部正源已对账回执（STARTED → COMMITTED）。

        F4-AUTH-001 根修：调用方自报回执（裸字符串）只能停在 PROVISIONAL
        （start_action 登记），本方法一律拒绝；COMMITTED 必须凭外部
        action-execution-receipt 通过对账：结构（键集封闭）→ HMAC-SHA256
        验签（keyring；伪回执拒绝）→ 与 ACTION_STARTED 事件的一致性
        （run_id/action_id/action_type/action_target/watermark=commit_sha）。
        对账不了 / 外部声明 FAILED 的动作走 fail_action → FAILED_UNKNOWN
        终态。事件 receipt 记 ``RECONCILED|<sha256>|<外部引用>``（重放强校验）。
        """
        if not isinstance(receipt, Mapping):
            raise ActionError(
                "commit_action requires 外部正源回执（action-execution-"
                "receipt JSON 对象）；调用方自报字符串回执不可 COMMITTED"
                "（只能 PROVISIONAL——F4-AUTH-001）")

        def _body(conn: sqlite3.Connection) -> Dict[str, Any]:
            state = self._load_state(run_id, conn)
            self._require_mutable(state)
            action = state.actions.get(action_id)
            if action is None:
                raise ActionError(f"unknown action_id {action_id!r} on {run_id}")
            ActionSaga.validate_transition(action["action_state"],
                                           ACTION_COMMITTED)
            rc = self._verify_external_receipt(state, action, receipt)
            if rc["outcome"] != "COMMITTED":
                raise ActionError(
                    f"外部回执 outcome={rc['outcome']!r} 非 COMMITTED——"
                    f"对账为失败：动作应 fail_action → FAILED_UNKNOWN 终态")
            receipt_str = _reconciled_receipt_str(rc)
            event = self._base_event(
                "ACTION_COMMITTED", state, "COMPLETED", "NOT_EVALUATED",
                actor=actor, state_version=state.state_version,
                action_id=action_id, action_type=action["action_type"],
                receipt=receipt_str)
            event_hash = self._emit(conn, state, event)
            return {"run_id": run_id, "action_id": action_id,
                    "action_state": ACTION_COMMITTED,
                    "receipt": receipt_str,
                    "receipt_status": RECEIPT_RECONCILED,
                    "event_hash": event_hash}

        return self._db.transact(_body)

    def fail_action(self, run_id: str, action_id: str, detail: str = "",
                    *, actor: str = "system") -> Dict[str, Any]:
        """动作结果未知（RESERVED/STARTED → FAILED_UNKNOWN 终态）。

        F4-AUTH-001：对账不了（拿不到可验签的外部回执）或外部正源声明
        FAILED 的动作走本方法收口——终态不可再变更。"""
        return self._advance_action(run_id, action_id, ACTION_FAILED_UNKNOWN,
                                    event_type="ACTION_FAILED_UNKNOWN",
                                    actor=actor, action_detail=detail or
                                    "outcome unknown; pending reconcile")

    # ------------------------------------------------------------------ #
    # F4-AUTH-001：外部正源回执验签 + 一致性对账
    # ------------------------------------------------------------------ #
    def _verify_external_receipt(self, state: RunState,
                                 action: Mapping[str, Any],
                                 receipt: Mapping[str, Any]) -> Dict[str, Any]:
        """外部正源回执对账校验链（与 commit_action 完全一致）：
        结构（键集封闭）→ HMAC-SHA256 验签（keyring）→ 与 ACTION_STARTED
        事件的水印/动作一致性。任一失败即 ActionError（fail-closed）。"""
        rc = _validate_external_receipt_structure(receipt)
        key_id = rc["key_id"]
        keyring = self.broker._keyring  # noqa: SLF001 —— 同模块受管复用
        if not keyring.has(key_id):
            raise ActionError(
                f"external receipt unknown signing key_id {key_id!r}"
                f"（未登记密钥的回执一律拒——fail-closed）")
        if not keyring.verify(rc):
            raise ActionError(
                "external receipt HMAC-SHA256 signature verification failed"
                f"（伪回执/篡改回执拒绝：action {action['action_id']}）")
        if rc["run_id"] != state.run_id:
            raise ActionError("receipt.run_id 与动作所属 run 不一致（回执不得跨 run）")
        if rc["action_id"] != action["action_id"]:
            raise ActionError("receipt.action_id 与目标动作不一致")
        if rc["action_type"] != action["action_type"]:
            raise ActionError(
                f"receipt.action_type {rc['action_type']!r} 与预留动作类型 "
                f"{action['action_type']!r} 不一致")
        if rc["action_target"] != action["action_target"]:
            raise ActionError(
                f"receipt.action_target 与预留动作目标不一致"
                f"（{rc['action_target']!r} != {action['action_target']!r}）")
        if rc["watermark"] != state.identity.get("commit_sha"):
            raise ActionError(
                "receipt.watermark 与 run commit_sha 不一致（须与 "
                "ACTION_STARTED 事件水印一致——回执不得跨 SHA）")
        return rc

    def reconcile_receipt(self, run_id: str, action_id: str,
                          receipt: Mapping[str, Any]) -> Dict[str, Any]:
        """外部正源回执对账（F4-AUTH-001 实装；只读，不修改事件流）。

        - 校验链与 commit_action 完全一致：结构 → HMAC 验签（keyring）→
          与 ACTION_STARTED 事件的水印/动作一致性；
        - 对账通过（outcome=COMMITTED）→ reconciled=True——同回执可经
          commit_action 落 COMMITTED；
        - 验签/一致性失败或 outcome=FAILED → reconciled=False——对账不了
          的动作走 fail_action → FAILED_UNKNOWN 终态；
        - FAILED_UNKNOWN 终态动作 → reconciled=None（终态不可再裁决）。
        """
        state = self.get_run(run_id)
        action = state.actions.get(action_id)
        if action is None:
            raise ActionError(f"unknown action_id {action_id!r} on {run_id}")
        if action["action_state"] == ACTION_FAILED_UNKNOWN:
            return {"run_id": run_id, "action_id": action_id,
                    "reconciled": None,
                    "note": "FAILED_UNKNOWN 终态——不可再对账，须外部正源/"
                            "人工收口"}
        if action["action_state"] != ACTION_STARTED:
            raise ActionError(
                f"action {action_id} 状态 {action['action_state']} 非 STARTED"
                f"——无在途动作可对账")
        try:
            rc = self._verify_external_receipt(state, action, receipt)
        except ActionError as exc:
            return {"run_id": run_id, "action_id": action_id,
                    "reconciled": False, "reason": str(exc),
                    "note": "对账失败：fail_action → FAILED_UNKNOWN 终态"}
        if rc["outcome"] != "COMMITTED":
            return {"run_id": run_id, "action_id": action_id,
                    "reconciled": False, "outcome": rc["outcome"],
                    "note": "外部正源声明非 COMMITTED：fail_action → "
                            "FAILED_UNKNOWN 终态"}
        return {"run_id": run_id, "action_id": action_id,
                "reconciled": True, "outcome": "COMMITTED",
                "receipt_ref": _reconciled_receipt_str(rc),
                "note": "对账通过：同回执经 commit_action 可 COMMITTED"}

    def close(self) -> None:
        self._db.close()


# ====================================================================== #
# ActionSaga——纯规则引擎（Codex 实锤 #10 最小可用实现的状态半边）
# ====================================================================== #


class ActionSaga:
    """action 编排 saga 规则：RESERVED→STARTED→COMMITTED / FAILED_UNKNOWN。

    事件半边由 RunManager.reserve/start/commit/fail_action 写入
    control_outbox（ACTION_* 事件，带 seal），重放由
    ``RunManager._replay_fold_action`` 按同一转换表折叠——本类只做规则判定，
    不持有状态、不做 IO（与 SevenStageStateMachine 同构）。
    """

    STATES: Tuple[str, ...] = ACTION_STATES
    TRANSITIONS: Dict[str, frozenset] = ACTION_TRANSITIONS
    TERMINAL_STATES = TERMINAL_ACTION_STATES

    @staticmethod
    def validate_transition(current: str, new: str) -> None:
        if new not in ACTION_TRANSITIONS.get(current, frozenset()):
            raise ActionError(
                f"illegal action transition: {current} -> {new} "
                f"(allowed: RESERVED→STARTED|FAILED_UNKNOWN, "
                f"STARTED→COMMITTED|FAILED_UNKNOWN)")

    @staticmethod
    def validate_descriptor(action_type: str, target: str) -> None:
        if not (isinstance(action_type, str) and action_type.strip()):
            raise ActionError("action_type must be a non-empty string")
        if not (isinstance(target, str) and target.strip()):
            raise ActionError("target must be a non-empty string")

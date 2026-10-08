# -*- coding: utf-8 -*-
"""approval_issue.py——审批签发端（P0-2 残余，Codex 六轮收口）。

架构裁定（超哥授权默认案，2026-10-08）：**本地 keyring + CLI 签发**；
飞书审批流只留抽象接口（``FeishuApprovalSource``——submit/callback 两方法，
NotImplemented 占位），后续接线时替换实现、签发语义不变。

与消费端（``wenqu_pipeline.ApprovalBroker``）的权限分离：
- 消费端只验不签（cli.py 既有注释：CLI 只消费不签发）；
- 本模块只签不消费——产出严格符合 approval-v2 契约的信封（HMAC-SHA256
  签名 + crypto 随机 nonce + payload 按类型判别封闭），签发前经
  ``ApprovalBroker.validate_structure`` 预检（纯静态方法，不触库），
  保证签出来的审批消费端一定收。

签发安全语义：
1. 高危类型（prod_write/ddl/release/fund_auth）强制双人规则：
   ``--confirm-two-persons`` + 第二签发人 key 联签（co-signature）——
   第二 key 对同一信封体再算一个独立 HMAC，**两个签名都验**才落审计。
   R7-AUTH-DUAL-CONSUME-005 根修（2026-10-08）：联签不再只落签发审计
   账本——**嵌入信封**（envelope.cosignatures：主签人 + 第二签发人，
   两名不同 key 对同一信封体的独立 HMAC）；消费端
   （wenqu_pipeline.ApprovalBroker）对高危类型强制验证 ≥2 名不同、
   各自可验、非 revoked key 的联签，缺失/单签/同 key 双签一律拒。
   兼容面：联签记录同时以外置 dict 返回（result["co_signature"]）并落
   审计账本（who/when/批了什么的既有对账面零变化）。
2. 签发审计账本（append-only jsonl + 哈希链）：谁（actor）/何时（ts）/
   批了什么（approval_id/type/run_id/task_id/decision/payload 摘要）/
   TTL（issued_at/expires_at/ttl_seconds）+ key_id + nonce 摘要（**不落
   nonce 明文**——nonce 是消费凭据，审计只留 sha256 指纹供对账）。
3. 密钥生命周期经 ``approval_keys``（active/rotated/revoked/expiry）：
   只有 active 且未过期的 key 可签发；rotated 可验存量；revoked 验签即拒。
   R8-KEY-LIFECYCLE-001：消费端进一步按 envelope.issued_at 执法时间窗
   （退休后手签的批不能消费）——签发端 ``get_for_signing`` 挡不住持
   secret 手签的旁路面，由消费端闭合。
   R8-SIGNER-PRINCIPAL-004：key 元数据登记 owner/actors——签发时预检
   actor ∈ 签名 key 的 actors（登记面 opt-in；消费端 ``_verify_signature``
   为权威门），联签第二人同理且 second_actor 必须 ≠ actor（真双人）。
4. 对账（``reconcile_issuance``）：签发审计（批了）× EventStore
   APPROVAL_CONSUMED 事件（用了）双向核对——批了未用（在期/已过期）、
   用了没批（无签发记录的消费=旁路签发或账本损坏）、nonce 指纹不匹配、
   审计链断裂，全部显式分类报告。

纯标准库实现；不触碰 wenqu_pipeline.py（消费端零改动）。
"""

from __future__ import annotations

import abc
import hashlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional

from .approval_keys import (  # noqa: F401 —— re-export 供 CLI/测试消费
    KEY_STATUS_ACTIVE,
    KEY_STATUS_REVOKED,
    KEY_STATUS_ROTATED,
    KEYRING_EVENTS_FILENAME,
    ApprovalKeyring,
    KeyExpiredError,
    KeyNotFoundError,
    KeyRevokedError,
    KeyRotatedError,
    KeyStateError,
    append_keyring_event,
    ensure_keyring_dir,
    generate_secret,
    save_key_meta,
    sign_envelope,
    verify_envelope,
    write_key_to_dir,
)
from .wenqu_pipeline import (  # noqa: F401 —— 单一正源，杜绝规格漂移
    _APPROVAL_DECISIONS,
    _APPROVAL_PAYLOAD_DISCRIMINATOR,
    _APPROVAL_SCHEMA_VERSION,
    _APPROVAL_TYPES,
    ApprovalBroker,
    ApprovalRejected,
    HIGH_RISK_APPROVAL_TYPES,
    SevenStageStateMachine,
    STOP_PRECONDITION_SPECS,
    STAGES,
    approval_payload_digest,
)

__all__ = [
    "HIGH_RISK_APPROVAL_TYPES",
    "DEFAULT_STOP_TYPE",
    "PAYLOAD_FIELDS_FOR_TYPE",
    "IssuanceError",
    "TwoPersonRuleError",
    "ApprovalSource",
    "LocalApprovalSource",
    "FeishuApprovalSource",
    "IssuanceAudit",
    "ApprovalIssuer",
    "reconcile_issuance",
    "issue_from_preconditions_payload",
    "APPROVAL_ISSUANCE_SCHEMA_VERSION",
]

#: 签发审计账本格式版本
APPROVAL_ISSUANCE_SCHEMA_VERSION = "1.0"

#: 高危审批类型——强制双人规则（--confirm-two-persons + 第二 key 联签）。
#: R7-AUTH-DUAL-CONSUME-005 起单一正源=wenqu_pipeline（消费端同集合），
#: 此处为再导出（CLI/测试既有导入路径不变）。
HIGH_RISK_APPROVAL_TYPES = HIGH_RISK_APPROVAL_TYPES  # noqa: F811 —— re-export

#: 非停等类审批的 stop_type 缺省（结构必填但语义弱；resume 必须显式给真实停等）
DEFAULT_STOP_TYPE: Dict[str, str] = {
    "risk": "scope",
    "merge": "scope",
    "release": "release",
    "ddl": "ddl",
    "prod_write": "prod-write",
    "fund_auth": "fund-auth",
    "rollback": "release",
}

#: payload 判别封闭规格（单一正源=wenqu_pipeline，此处仅别名导出）
PAYLOAD_FIELDS_FOR_TYPE = _APPROVAL_PAYLOAD_DISCRIMINATOR

#: 审计账本文件名（目录型 keyring 的缺省落点）
ISSUANCE_AUDIT_FILENAME = "issuance-audit.jsonl"

_DEFAULT_TTL_SECONDS = 3600
_MAX_TTL_SECONDS = 30 * 24 * 3600  # 30 天封顶（防手滑签出十年期审批）
_AUDIT_FILE_MODE = 0o600
_GENESIS = "0" * 64


# ====================================================================== #
# 异常
# ====================================================================== #

class IssuanceError(RuntimeError):
    """签发失败（契约/参数/密钥资格任一不满足）——fail-closed，不落审计。"""


class TwoPersonRuleError(IssuanceError):
    """高危类型双人规则不满足（缺确认旗标/第二 key/第二签发人）。"""


def _utc_now_iso(epoch: Optional[float] = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(epoch if epoch is not None
                                     else time.time()))


def _parse_iso_epoch(value: Any) -> float:
    import datetime
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid date-time: {value!r}")
    return datetime.datetime.fromisoformat(
        value.strip().replace("Z", "+00:00")).timestamp()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


# ====================================================================== #
# 审批来源抽象（飞书审批流留接口——超哥授权默认案：本地签发为主）
# ====================================================================== #

class ApprovalSource(abc.ABC):
    """审批送达来源抽象：签发端在落审计前经 ``submit`` 送达。"""

    name = "abstract"

    @abc.abstractmethod
    def submit(self, approval: Mapping[str, Any],
               co_signature: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """把已签发的审批（+联签记录）送达到审批系统，返回送达回执。"""

    @abc.abstractmethod
    def callback(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """接收审批系统的回调（审批状态变更），返回处置结果。"""


class LocalApprovalSource(ApprovalSource):
    """本地签发（默认案）：审批 JSON 直接落 --out 文件，无外部系统。"""

    name = "local"

    def submit(self, approval: Mapping[str, Any],
               co_signature: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        return {
            "delivered": True,
            "mode": "local",
            "approval_id": approval.get("approval_id"),
            "co_signed": co_signature is not None,
        }

    def callback(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        # 本地来源没有回调通道——送达即生效，回调语义只属于外部审批流。
        raise NotImplementedError(
            "LocalApprovalSource 无回调通道（送达即生效）；"
            "回调语义属于外部审批流（feishu）")


class FeishuApprovalSource(ApprovalSource):
    """飞书审批流（占位接口——后续接线时替换实现，签发语义不变）。

    submit/callback 均为 NotImplemented 占位：当前架构裁定为本地 keyring +
    CLI 签发，飞书只留接口。接线前置条件：飞书开放平台应用凭据、审批
    definition code、回调事件验签密钥（均不得入库）。
    """

    name = "feishu"

    def submit(self, approval: Mapping[str, Any],
               co_signature: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        raise NotImplementedError(
            "飞书审批流未接线（架构裁定：本地 keyring + CLI 签发为默认案，"
            "飞书留接口）——FeishuApprovalSource.submit 为占位实现")

    def callback(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError(
            "飞书审批流未接线——FeishuApprovalSource.callback 为占位实现")


#: 来源注册表（CLI --source 名 → 实例）
APPROVAL_SOURCES: Dict[str, type] = {
    "local": LocalApprovalSource,
    "feishu": FeishuApprovalSource,
}


# ====================================================================== #
# 签发审计账本（append-only jsonl + 哈希链）
# ====================================================================== #

class IssuanceAudit:
    """append-only 签发审计账本（jsonl，0600，逐条哈希链防篡改）。

    链规则：每条记录 ``chain_prev`` = 前一条整行 canonical JSON 的
    sha256（首条为全零 GENESIS）；本条摘要 = sha256(本行 canonical JSON)。
    ``verify_chain`` 重放全链——任何篡改/插入/删除都断链。
    """

    def __init__(self, path: str) -> None:
        if not path or not path.strip():
            raise ValueError("audit path must be non-empty")
        self.path = path

    # ------------------------------------------------------------------ #
    def append(self, record: Mapping[str, Any]) -> Dict[str, Any]:
        """追加一条审计记录（补 ts/schema_version/chain_prev），返回落账记录。"""
        body = dict(record)
        body.setdefault("ts", _utc_now_iso())
        body.setdefault("schema_version", APPROVAL_ISSUANCE_SCHEMA_VERSION)
        prev = self.tail_digest()
        body["chain_prev"] = prev
        line = _canonical_json(body)
        digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
        fd = os.open(self.path,
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                     _AUDIT_FILE_MODE)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(self.path, _AUDIT_FILE_MODE)
        out = dict(body)
        out["chain_digest"] = digest
        return out

    def tail_digest(self) -> str:
        """当前链尾摘要（空账本=GENESIS）。"""
        tail = self.tail_line()
        if tail is None:
            return _GENESIS
        return hashlib.sha256(tail.encode("utf-8")).hexdigest()

    def tail_line(self) -> Optional[str]:
        if not os.path.exists(self.path):
            return None
        tail = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    tail = line.rstrip("\n")
        return tail

    # ------------------------------------------------------------------ #
    @staticmethod
    def read_records(path: str) -> List[Dict[str, Any]]:
        """读取全部审计记录（坏行抛 ValueError——审计账本不允许静默跳行）。"""
        records: List[Dict[str, Any]] = []
        if not os.path.exists(path):
            return records
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"audit line {lineno} is not JSON: {exc}") from None
                if not isinstance(rec, dict):
                    raise ValueError(f"audit line {lineno} is not an object")
                records.append(rec)
        return records

    @classmethod
    def verify_chain(cls, path: str) -> Dict[str, Any]:
        """重放校验审计哈希链；返回 {ok, length, break_at, tail}。"""
        records = cls.read_records(path)
        expected_prev = _GENESIS
        for idx, rec in enumerate(records, 1):
            stored_prev = rec.get("chain_prev")
            if stored_prev != expected_prev:
                return {"ok": False, "length": len(records),
                        "break_at": idx, "tail": None,
                        "reason": f"record {idx}: chain_prev mismatch"}
            digest = hashlib.sha256(
                _canonical_json(rec).encode("utf-8")).hexdigest()
            expected_prev = digest
        return {"ok": True, "length": len(records), "break_at": None,
                "tail": expected_prev if records else _GENESIS}


# ====================================================================== #
# payload 构造助手
# ====================================================================== #

def issue_from_preconditions_payload(
        stop_event_id: str, stop_type: str,
        preconditions: Mapping[str, Any]) -> Dict[str, Any]:
    """由客观前置条件构造 resume 类 payload（含其哈希——消费端精确绑定）。

    前置条件的规格校验（必要且充分）由消费端 validate_preconditions 终审；
    此处只做哈希（canonical）——签发人拿到什么就绑定什么，不夹带裁量。
    """
    ph = SevenStageStateMachine.objective_precondition_hash(
        dict(preconditions))
    return {
        "stop_event_id": stop_event_id,
        "stop_type": stop_type,
        "objective_precondition_hash": ph,
    }


# ====================================================================== #
# 签发器
# ====================================================================== #

class ApprovalIssuer:
    """approval-v2 审批签发器（本地 keyring + HMAC + 审计账本）。

    用法（CLI 见 wenquctl approve）::

        issuer = ApprovalIssuer(keyring, audit_path)
        result = issuer.issue(actor="chaoge", approval_type="resume",
                              run_id=..., ..., payload={...})
        # result = {"approval": <envelope>, "co_signature": {...}|None,
        #           "audit_record": {...}}

    校验链（任一失败即 IssuanceError/TwoPersonRuleError，不落审计）：
        1. approval_type/decision/stop_type/stage 合法（消费端同款枚举）；
        2. payload 判别封闭（键集=该类型专属字段全集，非空；
           risk.finding_fingerprints 允许空列表）；
        3. TTL 边界（1s ~ 30 天）；
        4. 签发 key 资格：显式 key_id 或唯一 active key（歧义=拒）；
        5. 高危类型双人规则：--confirm-two-persons + 第二 key（≠主 key，
           且可签发）+ 第二签发人标识；非高危带双人参数=拒（防错觉）；
        6. 信封构造 → 主签名 → （高危）联签 → **双签名自验**；
        7. ApprovalBroker.validate_structure 预检（结构层全量）；
        8. source.submit 送达 → 审计落账（APPROVAL_ISSUED）。
    """

    def __init__(self, keyring: ApprovalKeyring, audit_path: str, *,
                 source: Optional[ApprovalSource] = None) -> None:
        if not isinstance(keyring, ApprovalKeyring):
            raise TypeError("keyring must be an ApprovalKeyring")
        self._keyring = keyring
        self._audit = IssuanceAudit(audit_path)
        self._source = source if source is not None else LocalApprovalSource()

    # ------------------------------------------------------------------ #
    @property
    def audit_path(self) -> str:
        return self._audit.path

    def _validate_payload(self, approval_type: str,
                          payload: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise IssuanceError("payload must be a JSON object")
        allowed = frozenset(PAYLOAD_FIELDS_FOR_TYPE[approval_type])
        required = tuple(PAYLOAD_FIELDS_FOR_TYPE[approval_type])
        stray = sorted(set(payload) - allowed)
        if stray:
            raise IssuanceError(
                f"payload not closed for approval_type={approval_type!r}: "
                f"foreign/unknown fields {stray}（判别联合互斥封闭）")
        missing = [k for k in required if k not in payload]
        if missing:
            raise IssuanceError(
                f"payload discriminator mismatch for "
                f"approval_type={approval_type!r}: missing {missing}")
        # 非空校验与消费端一致：risk.finding_fingerprints 允许空列表
        for key in required:
            if key == "finding_fingerprints":
                continue
            value = payload[key]
            empty = (value is None or value is False or value == ""
                     or (isinstance(value, (list, tuple, dict, set))
                         and len(value) == 0))
            if empty:
                raise IssuanceError(
                    f"payload field {key!r} must be non-empty")
        return dict(payload)

    def _pick_signing_key(self, key_id: Optional[str]) -> str:
        if key_id is not None:
            try:
                self._keyring.get_for_signing(key_id)
            except (KeyNotFoundError, KeyStateError) as exc:
                raise IssuanceError(
                    f"签发 key 资格不满足: {exc}") from None
            return key_id
        active = self._keyring.active_key_ids()
        if not active:
            raise IssuanceError(
                "keyring 无可签发 key（active 且未过期为空）——"
                "先 wenquctl keys create")
        if len(active) > 1:
            raise IssuanceError(
                f"keyring 有多个 active key {active}——必须显式 --key-id")
        return active[0]

    def _check_two_person(self, approval_type: str, *,
                          confirm_two_persons: bool,
                          second_key_id: Optional[str],
                          second_actor: Optional[str]) -> None:
        high_risk = approval_type in HIGH_RISK_APPROVAL_TYPES
        given = (confirm_two_persons or second_key_id is not None
                 or second_actor is not None)
        if not high_risk and given:
            raise TwoPersonRuleError(
                f"approval_type={approval_type!r} 非高危类型"
                f"（高危={sorted(HIGH_RISK_APPROVAL_TYPES)}），"
                "不接受双人联签参数（防「已联签」错觉）")
        if high_risk and not confirm_two_persons:
            raise TwoPersonRuleError(
                f"高危类型 {approval_type!r} 必须 --confirm-two-persons"
                "（双人确认+第二签发人 key 联签）")
        if high_risk:
            if not (isinstance(second_key_id, str) and second_key_id.strip()):
                raise TwoPersonRuleError(
                    "高危类型必须 --second-key-id（第二签发人 key 联签）")
            if not (isinstance(second_actor, str) and second_actor.strip()):
                raise TwoPersonRuleError(
                    "高危类型必须 --second-actor（第二签发人标识）")

    def _check_principal(self, key_id: str, actor: str) -> None:
        """R8-SIGNER-PRINCIPAL-004 签发端预检：actor ∈ key 的 actors 登记
        面（登记面 opt-in——未登记 actors 的存量 key 不受限；消费端
        ``ApprovalBroker._verify_signature`` 为权威门，此处早失败只为止
        「签出来消费端一定不收」的浪费签发）。"""
        actors = self._keyring.key_actors(key_id)
        if actors is not None and actor not in actors:
            raise IssuanceError(
                f"actor {actor!r} 不在 key {key_id!r} 的 actors 登记面 "
                f"{list(actors)}（R8-SIGNER-PRINCIPAL-004：actor 冒用他人 "
                "key 签发——消费端同样会拒，签发端先拒止浪费）")

    # ------------------------------------------------------------------ #
    def issue(self,  # noqa: C901 —— 校验链显式展开（可读性优先）
              *,
              actor: str,
              approval_type: str,
              run_id: str,
              task_id: str,
              stage: str,
              environment: str,
              authorized_scope: str,
              policy_hash: str,
              ruleset_hash: str,
              input_watermark: str,
              expected_state_version: int,
              payload: Mapping[str, Any],
              stop_type: Optional[str] = None,
              stop_event_id: Optional[str] = None,
              decision: str = "approve",
              key_id: Optional[str] = None,
              ttl_seconds: int = _DEFAULT_TTL_SECONDS,
              issued_at: Optional[str] = None,
              now_epoch: Optional[float] = None,
              confirm_two_persons: bool = False,
              second_key_id: Optional[str] = None,
              second_actor: Optional[str] = None,
              source: Optional[ApprovalSource] = None,
              ) -> Dict[str, Any]:
        """签发一份 approval-v2 审批（见类 docstring 校验链）。"""
        # 1. 枚举与形状（与消费端同款封闭集合）
        if not (isinstance(actor, str) and actor.strip()):
            raise IssuanceError("actor must be a non-empty string")
        if approval_type not in _APPROVAL_TYPES:
            raise IssuanceError(
                f"invalid approval_type {approval_type!r}; "
                f"valid: {sorted(_APPROVAL_TYPES)}")
        if decision not in _APPROVAL_DECISIONS:
            raise IssuanceError(
                f"invalid decision {decision!r}; "
                f"valid: {sorted(_APPROVAL_DECISIONS)}")
        if stop_type is None:
            if approval_type == "resume":
                raise IssuanceError(
                    "resume 审批必须显式 stop_type（锚定真实停等类型）")
            stop_type = DEFAULT_STOP_TYPE[approval_type]
        if stop_type not in STOP_PRECONDITION_SPECS:
            raise IssuanceError(
                f"invalid stop_type {stop_type!r}; "
                f"valid: {sorted(STOP_PRECONDITION_SPECS)}")
        if stage not in STAGES:
            raise IssuanceError(f"invalid stage {stage!r}; valid: {list(STAGES)}")
        if stop_event_id is None:
            if approval_type == "resume":
                raise IssuanceError(
                    "resume 审批必须显式 stop_event_id（锚定停等事件）")
            stop_event_id = f"n/a-{approval_type}"
        if not (isinstance(expected_state_version, int)
                and not isinstance(expected_state_version, bool)
                and expected_state_version >= 1):
            raise IssuanceError("expected_state_version must be integer >= 1")

        # 2. payload 判别封闭
        payload = self._validate_payload(approval_type, payload)

        # 3. TTL 边界
        if not (isinstance(ttl_seconds, int)
                and not isinstance(ttl_seconds, bool)
                and 1 <= ttl_seconds <= _MAX_TTL_SECONDS):
            raise IssuanceError(
                f"ttl_seconds must be integer in [1, {_MAX_TTL_SECONDS}]")

        # 4. 签发 key 资格
        chosen_key_id = self._pick_signing_key(key_id)
        secret = self._keyring.get_for_signing(chosen_key_id)
        # R8-SIGNER-PRINCIPAL-004：actor ∈ 主签 key 的 actors 登记面（预检）
        self._check_principal(chosen_key_id, actor)

        # 5. 高危双人规则
        self._check_two_person(
            approval_type, confirm_two_persons=confirm_two_persons,
            second_key_id=second_key_id, second_actor=second_actor)
        co_secret: Optional[str] = None
        if confirm_two_persons and approval_type in HIGH_RISK_APPROVAL_TYPES:
            assert second_key_id is not None  # _check_two_person 已保证
            assert second_actor is not None
            if second_key_id == chosen_key_id:
                raise TwoPersonRuleError(
                    "第二签发人 key 不得与主签发 key 相同（真双人，"
                    "同一把 key 签两遍不是联签）")
            if second_actor == actor:
                raise TwoPersonRuleError(
                    "第二签发人标识不得与主签发人相同（真双人——"
                    "R8-SIGNER-PRINCIPAL-004：同一 actor 不能用两把 "
                    "key 凑联签，消费端对信封联签条目 actor 互异硬门）")
            try:
                co_secret = self._keyring.get_for_signing(second_key_id)
            except (KeyNotFoundError, KeyStateError) as exc:
                # 与主 key 同一契约：联签 key 资格失败也收敛为 IssuanceError
                # （fail-closed，不落审计）——不向调用方泄漏底层 KeyError 族。
                raise IssuanceError(
                    f"第二签发人 key 资格不满足: {exc}") from None
            # R8-SIGNER-PRINCIPAL-004：second_actor ∈ 第二 key 的 actors（预检）
            self._check_principal(second_key_id, second_actor)

        # 6. 信封构造 + 主签名 +（高危）联签
        issued_at = issued_at or _utc_now_iso(now_epoch)
        expires_at = _utc_now_iso(
            _parse_iso_epoch(issued_at) + ttl_seconds)
        envelope: Dict[str, Any] = {
            "schema_version": _APPROVAL_SCHEMA_VERSION,
            "approval_id": f"apr_{uuid.uuid4().hex}",
            "approval_type": approval_type,
            "key_id": chosen_key_id,
            "run_id": run_id,
            "task_id": task_id,
            "stop_event_id": stop_event_id,
            "stop_type": stop_type,
            "stage": stage,
            "environment": environment,
            "authorized_scope": authorized_scope,
            "policy_hash": policy_hash,
            "ruleset_hash": ruleset_hash,
            "input_watermark": input_watermark,
            "expected_state_version": expected_state_version,
            "actor": actor,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "nonce": secrets.token_hex(16),
            "decision": decision,
            "signature": "",
            "payload": payload,
        }
        envelope.pop("signature", None)
        envelope["signature"] = sign_envelope(secret, envelope)

        # R7-AUTH-DUAL-CONSUME-005：高危联签嵌入信封（消费端契约要求
        # envelope 携带 cosignatures——主签 + 第二签发人签，两名不同 key
        # 对同一「信封体」的独立 HMAC；sign_envelope 排除 signature/
        # cosignatures 两键，故主签名对联签数组不敏感、联签各自可验）。
        # 兼容保留：联签记录同时以外置 dict 形态返回（result["co_signature"]，
        # 审计/对账既有消费面零变化）。
        co_signature: Optional[Dict[str, Any]] = None
        if co_secret is not None:
            co_hex = sign_envelope(co_secret, envelope)
            envelope["cosignatures"] = [
                {"key_id": chosen_key_id, "actor": actor,
                 "signature": envelope["signature"]},
                {"key_id": second_key_id, "actor": second_actor,
                 "signature": co_hex},
            ]
            co_signature = {
                "schema_version": APPROVAL_ISSUANCE_SCHEMA_VERSION,
                "approval_id": envelope["approval_id"],
                "primary_key_id": chosen_key_id,
                "primary_signature": envelope["signature"],
                "second_key_id": second_key_id,
                "second_actor": second_actor,
                "co_signature": co_hex,
                "ts": _utc_now_iso(now_epoch),
                "embedded_in_envelope": True,
            }

        # 7. 双签名自验（先于任何落账——签出来就必须两个签名都真）
        if not verify_envelope(secret, envelope, envelope["signature"]):
            raise IssuanceError(
                "主签名自验失败（不应发生——HMAC 实现或 key 状态异常）")
        if co_signature is not None and not verify_envelope(
                co_secret, envelope, co_signature["co_signature"]):
            raise IssuanceError(
                "联签自验失败（不应发生——第二 key HMAC 实现异常）")
        try:
            ApprovalBroker.validate_structure(envelope)
        except ApprovalRejected as exc:
            raise IssuanceError(
                f"签发预检失败（ApprovalBroker.validate_structure 拒绝——"
                f"该审批消费端不会收）: {exc}") from None

        # 8. 送达（feishu 未接线 → NotImplementedError 向上抛，不落审计）
        used_source = source if source is not None else self._source
        delivery = used_source.submit(envelope, co_signature)

        audit_record = self._audit.append({
            "record_type": "APPROVAL_ISSUED",
            "actor": actor,
            "approval_id": envelope["approval_id"],
            "approval_type": approval_type,
            "run_id": run_id,
            "task_id": task_id,
            "stop_type": stop_type,
            "stop_event_id": stop_event_id,
            "decision": decision,
            "key_id": chosen_key_id,
            "nonce_digest": hashlib.sha256(
                envelope["nonce"].encode("utf-8")).hexdigest(),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "ttl_seconds": ttl_seconds,
            "high_risk": approval_type in HIGH_RISK_APPROVAL_TYPES,
            "two_person": co_signature is not None,
            "second_key_id": second_key_id,
            "second_actor": second_actor,
            "co_signature": (co_signature or {}).get("co_signature"),
            "payload_fields": sorted(payload),
            "payload_digest": approval_payload_digest(payload),
            "cosign_key_ids": [e.get("key_id") for e in
                               envelope.get("cosignatures") or []],
            "source": used_source.name,
            "delivery": delivery,
        })
        return {"approval": envelope,
                "co_signature": co_signature,
                "audit_record": audit_record}


# ====================================================================== #
# 对账：签发审计（批了）× EventStore APPROVAL_CONSUMED（用了）
# ====================================================================== #

def _load_consumed_from_eventstore(
        db_path: str) -> List[Dict[str, Any]]:
    """只读扫描 pipeline_events，抽取 APPROVAL_CONSUMED 事件面。"""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"event store not found: {db_path!r}")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT seq, payload FROM pipeline_events ORDER BY seq ASC"
        ).fetchall()
    finally:
        conn.close()
    consumed: List[Dict[str, Any]] = []
    for seq, payload_text in rows:
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError:
            continue  # 非事件行（不应出现）；对账只认可解析事件
        if isinstance(payload, dict) and payload.get(
                "event_type") == "APPROVAL_CONSUMED":
            consumed.append({
                "seq": seq,
                "approval_id": payload.get("approval_id"),
                "approval_type": payload.get("approval_type"),
                "nonce_digest": payload.get("nonce_digest"),
                "run_id": payload.get("run_id"),
                "ts": payload.get("ts"),
            })
    return consumed


def reconcile_issuance(audit_path: str, db_path: str, *,
                       now_epoch: Optional[float] = None
                       ) -> Dict[str, Any]:
    """双向对账：批了（签发审计）vs 用了（APPROVAL_CONSUMED）vs 未用过期。

    分类：
    - ``used_ok``                     签发记录 × 消费事件 双匹配
                                       （approval_id + nonce 摘要均一致）；
    - ``consumed_without_issuance``   消费事件无对应签发记录（旁路签发/
                                       审计账本损坏——审计链同查）；
    - ``digest_mismatch``             approval_id 匹配但 nonce 摘要不一致
                                       （重造信封/账本被改）；
    - ``issued_unused_active``        批了未用，TTL 内（在期未消费）；
    - ``issued_unused_expired``       批了未用，已过期（未用过期）；
    - ``duplicate_approval_ids``      同一 approval_id 签发多次（签发端异常）；
    - ``chain_ok``                    审计哈希链完整性。

    ``ok`` = 账本一致性（chain_ok 且无 consumed_without_issuance、无
    digest_mismatch、无 duplicate_approval_ids）——未用过期是业务状态，
    不是账本错误，只报告不判红。
    """
    now = now_epoch if now_epoch is not None else time.time()
    chain = IssuanceAudit.verify_chain(audit_path)
    records = IssuanceAudit.read_records(audit_path)

    issued: Dict[str, Dict[str, Any]] = {}
    duplicates: List[str] = []
    for rec in records:
        if rec.get("record_type") != "APPROVAL_ISSUED":
            continue
        approval_id = rec.get("approval_id")
        if approval_id in issued:
            duplicates.append(approval_id)
            continue
        issued[approval_id] = rec

    consumed = _load_consumed_from_eventstore(db_path)
    used_ok: List[str] = []
    consumed_without_issuance: List[Dict[str, Any]] = []
    digest_mismatch: List[Dict[str, Any]] = []
    consumed_ids = set()
    for c in consumed:
        approval_id = c.get("approval_id")
        consumed_ids.add(approval_id)
        rec = issued.get(approval_id)
        if rec is None:
            consumed_without_issuance.append(c)
        elif rec.get("nonce_digest") != c.get("nonce_digest"):
            digest_mismatch.append(
                {"approval_id": approval_id,
                 "issued_nonce_digest": rec.get("nonce_digest"),
                 "consumed_nonce_digest": c.get("nonce_digest")})
        else:
            used_ok.append(approval_id)

    unused_active: List[Dict[str, Any]] = []
    unused_expired: List[Dict[str, Any]] = []
    bad_expiry: List[str] = []
    for approval_id, rec in issued.items():
        if approval_id in consumed_ids:
            continue
        try:
            expires = _parse_iso_epoch(rec.get("expires_at"))
        except ValueError:
            bad_expiry.append(approval_id)
            continue
        entry = {"approval_id": approval_id,
                 "approval_type": rec.get("approval_type"),
                 "run_id": rec.get("run_id"),
                 "expires_at": rec.get("expires_at")}
        if expires > now:
            unused_active.append(entry)
        else:
            unused_expired.append(entry)

    ok = (chain["ok"] and not consumed_without_issuance
          and not digest_mismatch and not duplicates and not bad_expiry)
    return {
        "generated_at": _utc_now_iso(now),
        "audit_path": audit_path,
        "event_store": db_path,
        "ok": ok,
        "chain_ok": chain["ok"],
        "chain_break_at": chain.get("break_at"),
        "audit_records": len(records),
        "issued_total": len(issued),
        "consumed_total": len(consumed),
        "used_ok": used_ok,
        "consumed_without_issuance": consumed_without_issuance,
        "digest_mismatch": digest_mismatch,
        "issued_unused_active": unused_active,
        "issued_unused_expired": unused_expired,
        "duplicate_approval_ids": sorted(set(duplicates)),
        "issued_bad_expiry": bad_expiry,
    }

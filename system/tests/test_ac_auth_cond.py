#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——AUTH/STOP/RISK/COND 四族（test_ac_auth_cond）。

覆盖 Codex 方案 §20.1/§20.5 中 AUTH-01~06、STOP-01~03、RISK-01、COND-01~06
共 16 条：每条按方案表格「注入/期望」逐字对齐，真实注入（真实 SQLite 临时
事件库 + approval-v2 全信封 + fixtures/approval-keys.json 测试密钥的真实
HMAC-SHA256 签发）与真实断言（消费/拒绝/事件流/终态），绝不 xfail 硬凑。

被测正源（不改动任何产品码）：
- system/wenqu_core/wenqu_pipeline.py   ApprovalBroker（结构封闭+HMAC 验签
  +envelope 全字段 exact 绑定+TTL+state_version CAS+nonce 事件正源一次性
  消费）、NineStopTypes 九类停等、RunManager（resume_waiting/authorize_risk/
  complete_run/register_finding/reserve_action/start_action/commit_action/
  fail_action/reconcile_receipt）、ActionSaga（授权消费链+receipt 分级）
- system/wenqu_core/approval_keys.py    ApprovalKeyring/sign_envelope
  （key 撤销=移出 keyring 即未知 key 拒绝）
- system/wenqu_core/gate_aggregator.py  technical_eligible 语义（CONDITIONAL
  永不上绿；COND-01/03/04 的聚合层半边）
- system/schemas/finding-event-v2.schema.json
  RISK_REVOKED/RISK_INVALIDATED 转移表（RISK-01 的 REVOKED/INVALIDATED +
  立即重开 + 修复链入口半边；经 jsonschema Draft7 真实校验冻结 schema）

语义映射边界（诚实声明，非硬凑）：
- AUTH-06「无 user-presence」：approval-v2 无独立 user-presence 位（如硬件
  token UV），产品最接近语义是 decision!=approve（非明确用户批准决定，
  conditional/deny 不足以消费）→ 一律拒。
- COND-01「技术 context failure」/COND-03「success/AUTHORIZED_CONDITIONAL」：
  产品落地面为 gate_aggregator（technical_eligible=False + GitHub failure；
  CONDITIONAL 绝不上绿）+ wenqu_pipeline complete_run（无 risk 授权 fail-closed
  拒绝 / 有精确授权才 COMPLETED_CONDITIONAL 且 verdict 仍 CONDITIONAL）。
- RISK-01「追加 REVOKED/INVALIDATED」：RunManager 层无主动撤销 API；撤销/
  失效转移表冻结于 finding-event-v2.schema.json（RISK_REVOKED←ACCEPTED_RISK、
  RISK_INVALIDATED←ACCEPTED_RISK→OPEN 立即重开、FIX_STARTED←OPEN 修复链），
  以 jsonschema 对冻结 schema 的真实校验断言；管线半边（finding 面改变 →
  已消费授权在 complete_run 判定点失效、run 保持可修复）同步实证。
- 方案 §20 STOP 行注（L330）：STOP-01~03 须逐类型验证九类全覆盖「错误类型/
  旧版本/重放审批仍拒」「有授权但客观条件未恢复仍拒」「客观条件已恢复但无
  授权仍拒」——本文件逐字执行。

独立运行：python3 system/tests/test_ac_auth_cond.py [--json OUT.json]
exit 0 = 全部用例绿；--json 额外输出逐 ID 结果数组 {id, test, passed}。
"""
from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

SYSTEM_DIR = Path(__file__).resolve().parent.parent  # system/
if str(SYSTEM_DIR) not in sys.path:
    sys.path.insert(0, str(SYSTEM_DIR))

from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope  # noqa: E402
from wenqu_core.gate_aggregator import CONDITIONAL, GateAggregator  # noqa: E402
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ACTION_FAILED_UNKNOWN,
    NineStopTypes,
)
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ActionError,
    ApprovalPreconditionError,
    ApprovalRejected,
    ApprovalReuseError,
    PipelineError,
    RECEIPT_RECONCILED,
    RunManager,
    SevenStageStateMachine as SM,
)

# ── 测试密钥（fixtures 登记密钥；与生产物理隔离，仅自测签发） ──────────────
_KEYRING_PATH = SYSTEM_DIR / "tests" / "fixtures" / "approval-keys.json"
KEYRING = ApprovalKeyring.from_path(str(_KEYRING_PATH))
KEY_A = "key_test_1"
KEY_B = "key_test_2"
SECRET_A = KEYRING.get(KEY_A)
SECRET_B = KEYRING.get(KEY_B)

# ── run 身份模板（approval-v2 envelope 绑定值与之一致才可消费） ─────────────
ID_STAGING = {
    "commit_sha": "a" * 40,
    "environment": "staging",
    "scope_hash": "scope-ac-001",
    "policy_hash": "policy-ac-77",
    "ruleset_hash": "rules-ac-07",
}
NINE_STOP_TYPES: Tuple[str, ...] = tuple(t.value for t in NineStopTypes)

# 九类停等的合法客观前置条件（STOP-01 重放腿/STOP-02 对照腿需要一次成功消费）
VALID_PRECONDITIONS: Dict[str, Dict[str, Any]] = {
    "ambiguity": {"requirement_four_elements": "四要素-v3 冻结", "scope_hash": "scope-ac-001"},
    "prod-write": {"gate_reference": "gate-pw-77", "rollback_level": "R2"},
    "ddl": {
        "ddl_statement_digest": "d" * 64, "environment": "staging",
        "verification_fresh": True, "verification_legacy": True,
        "verification_minimal": True, "rollback_verified": True,
    },
    "release": {
        "release_id": "rel-ac-9", "commit_sha": "a" * 40, "environment": "staging",
        "gate_reference": "gate-rel-9", "manifest_sha256": "m" * 64,
        "rollback_plan": "rp-rel-9",
    },
    "scope": {
        "new_scope_hash": "scope-ac-002", "risk_refrozen": True,
        "required_set_refrozen": True, "evidence_refrozen": True,
    },
    "fund-auth": {
        "fund_subject_role": "ops-admin", "positive_test_ref": "pos-ac-1",
        "negative_test_ref": "neg-ac-1", "conservation_check": True,
        "audit_target": "audit://wenqu/ac-77",
    },
    "exm-fuse": {"adjudication_ref": "exm-adj-ac-9", "fuse_lifted_evidence": "evidence://fuse-9"},
    "resource": {
        "resource_probe_ref": "probe://disk/free", "probe_recovered": True,
        "safety_margin_met": True,
    },
    "ext-unavail": {
        "dependency_probe_ref": "probe://ext/api", "probe_recovered": True,
        "evidence_freshness_reverified": True,
    },
}

# prod_write 类 action 审批 payload（approval-v2 判别封闭键集）
PROD_WRITE_PAYLOAD = {
    "operation_digest": "4" * 64, "data_scope_digest": "5" * 64,
    "idempotency_key": "idem-ac-77", "conservation_hash": "6" * 64,
}


# ---------------------------------------------------------------------------
# 通用小工具（独立撰写）
# ---------------------------------------------------------------------------
def _ok(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)


def _raises(exc_type: type, fn: Callable[[], Any], *,
            contains: Optional[str] = None) -> Exception:
    """执行 fn 并断言抛出 exc_type（可选断言错误文本包含 contains）。"""
    try:
        fn()
    except exc_type as exc:  # type: ignore[misc]
        if contains is not None and contains not in str(exc):
            raise AssertionError(
                f"期望 {exc_type.__name__} 含 {contains!r}，实得: {exc}") from exc
        return exc
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"期望 {exc_type.__name__}，实得 {type(exc).__name__}: {exc}") from exc
    raise AssertionError(f"期望 {exc_type.__name__}，但调用未抛错")


@contextlib.contextmanager
def _sandbox(tag: str):
    """每用例独立临时目录（真实 SQLite 文件库，拒绝 :memory:）。"""
    td = tempfile.mkdtemp(prefix=f"ac-auth-cond-{tag}-")
    try:
        yield Path(td)
    finally:
        shutil.rmtree(td, ignore_errors=True)


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _mgr(td: Path, name: str = "events.db", *, keyring: ApprovalKeyring = KEYRING,
         store: Optional[EventStore] = None) -> Tuple[EventStore, RunManager]:
    st = store if store is not None else EventStore(str(td / name))
    return st, RunManager(st, keyring=keyring)


def _sign(approval: Dict[str, Any], *, secret: str = SECRET_A,
          key_id: str = KEY_A) -> Dict[str, Any]:
    """对 envelope 重算 HMAC 签名（覆盖旧 signature；返回深拷贝）。"""
    ap = copy.deepcopy(approval)
    ap["key_id"] = key_id
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(secret, ap)
    return ap


def _base_envelope(*, approval_type: str, run_id: str, task_id: str,
                   stop_type: str, stage: str, version: int,
                   environment: str = ID_STAGING["environment"],
                   scope: str = ID_STAGING["scope_hash"],
                   policy: str = ID_STAGING["policy_hash"],
                   ruleset: str = ID_STAGING["ruleset_hash"],
                   watermark: str = ID_STAGING["commit_sha"],
                   stop_event_id: str = "n/a-not-a-waiting-anchor",
                   actor: str = "ac-auth-cond-signer",
                   issued_at: str = "2026-01-01T00:00:00Z",
                   expires_at: str = "2099-01-01T00:00:00Z",
                   nonce: Optional[str] = None,
                   decision: str = "approve",
                   key_id: str = KEY_A,
                   payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """approval-v2 全信封（_APPROVAL_REQUIRED_TOP 逐字段；未签名的基底）。"""
    return {
        "schema_version": "2.0",
        "approval_id": f"apr_ac_{approval_type}_{os.urandom(4).hex()}",
        "approval_type": approval_type,
        "key_id": key_id,
        "run_id": run_id,
        "task_id": task_id,
        "stop_event_id": stop_event_id,
        "stop_type": stop_type,
        "stage": stage,
        "environment": environment,
        "authorized_scope": scope,
        "policy_hash": policy,
        "ruleset_hash": ruleset,
        "input_watermark": watermark,
        "expected_state_version": version,
        "actor": actor,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce or f"nonce-ac-{approval_type}-{os.urandom(8).hex()}",
        "decision": decision,
        "signature": "",
        "payload": payload if payload is not None else {},
    }


def _resume_approval(run_id: str, task_id: str, *, stop_event_id: str,
                     stop_type: str, version: int,
                     preconditions: Dict[str, Any],
                     stage: str = "S1_REQUIREMENT", **over: Any) -> Dict[str, Any]:
    """resume 类审批：payload 绑定客观前置条件内容哈希。"""
    ap = _base_envelope(
        approval_type="resume", run_id=run_id, task_id=task_id,
        stop_type=stop_type, stage=stage, version=version,
        stop_event_id=stop_event_id,
        payload={
            "stop_event_id": stop_event_id,
            "stop_type": stop_type,
            "objective_precondition_hash":
                SM.objective_precondition_hash(preconditions),
        })
    for k, v in over.items():
        ap[k] = v
    return _sign(ap)


def _risk_approval(run_id: str, task_id: str, *, version: int,
                   fingerprints: List[str], severity: str = "MEDIUM",
                   stage: str = "S7_GATE", **over: Any) -> Dict[str, Any]:
    """risk 类审批（COND 族/AUTH 族共用基底；over 覆盖任意信封字段）。"""
    ap = _base_envelope(
        approval_type="risk", run_id=run_id, task_id=task_id,
        stop_type="scope", stage=stage, version=version,
        payload={
            "finding_fingerprints": list(fingerprints),
            "severity": severity,
            "reason": "ac-auth-cond 风险接受理由-低风险可接受项",
            "compensating_controls": ["ctrl-ac-1", "ctrl-ac-2"],
            "expiry": "2099-12-31T00:00:00Z",
        })
    for k, v in over.items():
        ap[k] = v
    return _sign(ap)


def _action_approval(run_id: str, task_id: str, *, version: int,
                     stage: str = "S1_REQUIREMENT",
                     **over: Any) -> Dict[str, Any]:
    """prod_write 类 action 审批（reserve_action 必传的授权）。"""
    ap = _base_envelope(
        approval_type="prod_write", run_id=run_id, task_id=task_id,
        stop_type="prod-write", stage=stage, version=version,
        payload=dict(PROD_WRITE_PAYLOAD))
    for k, v in over.items():
        ap[k] = v
    return _sign(ap)


def _cosign_ap(ap: Dict[str, Any], *, second_key_id: str = KEY_B,
               second_actor: str = "erge",
               primary_actor: str = "chaoge") -> Dict[str, Any]:
    """R7-AUTH-DUAL-CONSUME-005：给已主签的高危（prod_write）审批补嵌入
    联签数组——主签人 + 第二签发人（fixtures 双 active key）对同一信封体
    的独立 HMAC。既有断言不动（只增不减），成功路径按新消费契约补联签。"""
    body = {k: v for k, v in ap.items()
            if k not in ("signature", "cosignatures")}
    out = dict(ap)
    out["cosignatures"] = [
        {"key_id": ap["key_id"], "actor": primary_actor,
         "signature": ap["signature"]},
        {"key_id": second_key_id, "actor": second_actor,
         "signature": sign_envelope(KEYRING.get(second_key_id), body)},
    ]
    return out


def _descriptor(ap: Dict[str, Any]) -> Dict[str, Any]:
    """exact action descriptor（reserve_action 实参声明的动作描述=payload 副本）。"""
    return dict(ap["payload"])


def _external_receipt(reserved: Dict[str, Any], run_id: str,
                      *, watermark: str = ID_STAGING["commit_sha"],
                      outcome: str = "COMMITTED",
                      external_ref: str = "ext-ac-action-77",
                      **over: Any) -> Dict[str, Any]:
    """action-execution-receipt v1.0 外部正源回执（测试密钥 HMAC 签发）。"""
    rc: Dict[str, Any] = {
        "schema_version": "1.0",
        "receipt_type": "action-execution-receipt",
        "action_id": reserved["action_id"],
        "run_id": run_id,
        "action_type": reserved["action_type"],
        "action_target": reserved["action_target"],
        "watermark": watermark,
        "outcome": outcome,
        "external_ref": external_ref,
        "ts": "2026-10-08T00:00:00Z",
        "key_id": KEY_A,
        "signature": "",
    }
    for k, v in over.items():
        rc[k] = v
    rc.pop("signature", None)
    rc["signature"] = sign_envelope(SECRET_A, rc)
    return rc


def _waiting_run(mgr: RunManager, task_id: str, stop_type: str,
                 ident: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """创建 run → 启动 S1 → 触发指定类型停等（返回 run_id 与停等锚点）。"""
    run_id = mgr.create_run(task_id, ident)["run_id"]
    mgr.advance_stage(run_id)
    w = mgr.raise_waiting(run_id, stop_type, f"ac-auth-cond 停等注入-{stop_type}")
    return run_id, w


def _soft_terminal_run(mgr: RunManager, task_id: str,
                       ident: Dict[str, Any]) -> str:
    """S1..S6 PASS、S7 CONDITIONAL（软终态）——COND 族的『CONDITIONAL run』。"""
    run_id = mgr.create_run(task_id, ident)["run_id"]
    for _ in range(6):
        mgr.advance_stage(run_id, execution_status="COMPLETED",
                          policy_verdict="PASS")
    mgr.advance_stage(run_id, execution_status="COMPLETED",
                      policy_verdict="CONDITIONAL")
    return run_id


def _count_events(store: EventStore, run_id: str, event_type: str) -> int:
    n = 0
    for (_seq, _h, payload) in store._conn.execute(  # noqa: SLF001
            "SELECT seq, event_hash, payload FROM pipeline_events ORDER BY seq ASC"):
        ev = json.loads(payload)
        if ev.get("run_id") == run_id and ev.get("event_type") == event_type:
            n += 1
    return n


# ---------------------------------------------------------------------------
# AUTH 族（§20.1 AUTH-01~03 + §20.5 AUTH-04~06）
# ---------------------------------------------------------------------------
def test_AUTH_01_resume_without_authorization_rejected(root: Path) -> None:
    """AUTH-01｜注入：无授权 resume｜期望：拒绝。"""
    with _sandbox("auth01") as td:
        store, mgr = _mgr(td)
        run_id, w = _waiting_run(mgr, "task_auth01", "prod-write", ID_STAGING)
        # 腿一：WAITING 中绕过授权直接推进 —— advance_stage 必拒并指向 resume
        exc = _raises(PipelineError, lambda: mgr.advance_stage(run_id),
                      contains="resume_waiting")
        _ok("WAITING" in str(exc), "拒绝理由须点名 WAITING 态")
        # 腿二：无任何审批（approval=None）调 resume —— 结构层即拒
        _raises(ApprovalRejected,
                lambda: mgr.resume_waiting(run_id, None, VALID_PRECONDITIONS["prod-write"]),
                contains="not a JSON object")
        # 腿三：攻击者自造信封（无登记密钥的伪签发）—— 未知 key 拒
        rogue = _base_envelope(
            approval_type="resume", run_id=run_id, task_id="task_auth01",
            stop_type="prod-write", stage="S1_REQUIREMENT",
            version=mgr.get_run(run_id).state_version,
            stop_event_id=w["stop_event_id"], key_id="key_ai_forged_1",
            payload={"stop_event_id": w["stop_event_id"], "stop_type": "prod-write",
                     "objective_precondition_hash":
                         SM.objective_precondition_hash(VALID_PRECONDITIONS["prod-write"])})
        forged = _sign(rogue, secret=os.urandom(32).hex(), key_id="key_ai_forged_1")
        _raises(ApprovalRejected,
                lambda: mgr.resume_waiting(run_id, forged, VALID_PRECONDITIONS["prod-write"]),
                contains="key_id")
        # 期望核对：三路注入全部拒绝后 run 仍 WAITING、停等锚点未变、零消费
        st = mgr.get_run(run_id)
        _ok(st.state == "WAITING" and st.waiting is not None, "无授权不得离开 WAITING")
        _ok(st.waiting.stop_event_id == w["stop_event_id"], "停等锚点不可被扰动")
        _ok(mgr.broker.consumed_approvals(run_id=run_id) == [], "零授权消费")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


def test_AUTH_02_expired_replay_scope_widening_stale_version_rejected(root: Path) -> None:
    """AUTH-02｜注入：过期/重放/扩范围/旧 state_version｜期望：拒绝。"""
    with _sandbox("auth02") as td:
        store, mgr = _mgr(td)
        now = time.time()

        # 腿一：过期（issued/expires 均已过去，结构合法）→ TTL 窗口外拒
        run1, w1 = _waiting_run(mgr, "task_auth02a", "prod-write", ID_STAGING)
        v1 = mgr.get_run(run1).state_version
        expired = _resume_approval(
            run1, "task_auth02a", stop_event_id=w1["stop_event_id"],
            stop_type="prod-write", version=v1,
            preconditions=VALID_PRECONDITIONS["prod-write"],
            issued_at="2026-01-01T00:00:00Z", expires_at="2026-01-02T00:00:00Z")
        _raises(ApprovalRejected, lambda: mgr.resume_waiting(
            run1, expired, VALID_PRECONDITIONS["prod-write"]),
            contains="TTL")
        _ok(mgr.get_run(run1).state == "WAITING", "过期审批不得恢复 run")

        # 腿二：重放（合法消费一次后同 nonce 再消费）→ 一次性消费拒
        ok = _resume_approval(
            run1, "task_auth02a", stop_event_id=w1["stop_event_id"],
            stop_type="prod-write", version=v1,
            preconditions=VALID_PRECONDITIONS["prod-write"],
            issued_at=_iso(now - 60))
        _ok(mgr.resume_waiting(run1, ok, VALID_PRECONDITIONS["prod-write"])["resumed"],
            "对照组：合法授权恢复成功（fail-closed 非 fail-everything）")
        _raises(ApprovalReuseError, lambda: mgr.resume_waiting(
            run1, ok, VALID_PRECONDITIONS["prod-write"]), contains="nonce")

        # 腿三：扩范围（authorized_scope 超出 run scope_hash，重签有效）→ 拒
        run2, w2 = _waiting_run(mgr, "task_auth02b", "prod-write", ID_STAGING)
        v2 = mgr.get_run(run2).state_version
        widened = _resume_approval(
            run2, "task_auth02b", stop_event_id=w2["stop_event_id"],
            stop_type="prod-write", version=v2,
            preconditions=VALID_PRECONDITIONS["prod-write"],
            authorized_scope="scope-ac-001-plus-extra")
        _raises(ApprovalRejected, lambda: mgr.resume_waiting(
            run2, widened, VALID_PRECONDITIONS["prod-write"]),
            contains="authorized_scope")

        # 腿四：旧 state_version（v-1 与 v+1 各一，重签有效）→ CAS 拒
        for stale in (v2 - 1, v2 + 1):
            ap = _resume_approval(
                run2, "task_auth02b", stop_event_id=w2["stop_event_id"],
                stop_type="prod-write", version=stale,
                preconditions=VALID_PRECONDITIONS["prod-write"])
            _raises(ApprovalRejected, lambda a=ap: mgr.resume_waiting(
                run2, a, VALID_PRECONDITIONS["prod-write"]),
                contains="state_version")
        _ok(mgr.get_run(run2).state == "WAITING", "扩范围/旧版本注入后仍 WAITING")
        _ok(len(mgr.broker.consumed_approvals(run_id=run2)) == 0, "腿三/四零消费")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


def test_AUTH_03_ai_self_issued_high_risk_approval_rejected(root: Path) -> None:
    """AUTH-03｜注入：AI/runner 尝试自行签发高风险批准｜期望：拒绝。"""
    with _sandbox("auth03") as td:
        # 腿一：AI 自建密钥自签（结构/HMAC 全合法但 key 未登记）→ 未知 key 拒
        store1, mgr1 = _mgr(td, "a.db")
        run_id = _soft_terminal_run(mgr1, "task_auth03a", ID_STAGING)
        mgr1.register_finding(run_id, "fnd_auth03_1", "fp-auth03", "HIGH", "P1")
        v = mgr1.get_run(run_id).state_version
        self_key = ApprovalKeyring.generate("key_ai_selfsign_1")
        ap_self = _risk_approval(
            run_id, "task_auth03a", version=v, fingerprints=["fp-auth03"],
            severity="HIGH", actor="ai-runner-selfissued")
        ap_self = _sign(ap_self, secret=self_key.get("key_ai_selfsign_1"),
                        key_id="key_ai_selfsign_1")
        _raises(ApprovalRejected, lambda: mgr1.authorize_risk(run_id, ap_self),
                contains="key_id")
        _ok(mgr1.broker.consumed_approvals(run_id=run_id) == [], "自签审批零消费")
        store1.close()

        # 腿二：即便拿到登记密钥，HIGH/CRITICAL 高风险内容仍机器拒绝（无人工豁免）
        store2, mgr2 = _mgr(td, "b.db")
        run2 = _soft_terminal_run(mgr2, "task_auth03b", ID_STAGING)
        mgr2.register_finding(run2, "fnd_auth03_2", "fp-high-2", "HIGH", "P1")
        v2 = mgr2.get_run(run2).state_version
        for sev in ("HIGH", "CRITICAL"):
            ap = _risk_approval(run2, "task_auth03b", version=v2,
                                fingerprints=["fp-high-2"], severity=sev,
                                actor="ai-runner-with-leaked-key")
            _raises(ApprovalRejected, lambda a=ap: mgr2.authorize_risk(run2, a),
                    contains="不可风险接受")
        _ok(mgr2.broker.consumed_approvals(run_id=run2) == [], "高风险内容零消费")
        store2.close()

        # 腿三：AI/runner 无审批直接预留高风险动作（prod-write）→ 必拒
        store3, mgr3 = _mgr(td, "c.db")
        run3 = mgr3.create_run("task_auth03c", ID_STAGING)["run_id"]
        mgr3.advance_stage(run3)
        _raises(ActionError,
                lambda: mgr3.reserve_action(run3, "prod-write", "db://prod/erp#ai"),
                contains="requires")
        _ok(not mgr3.get_run(run3).actions, "零动作预留")
        store3.close()

        # 对照组：同一登记密钥签发的合法低风险授权可消费（证明拒的是内容/身份而非密钥存在性）
        store4, mgr4 = _mgr(td, "d.db")
        run4 = _soft_terminal_run(mgr4, "task_auth03d", ID_STAGING)
        mgr4.register_finding(run4, "fnd_auth03_4", "fp-low-4", "LOW", "P3")
        v4 = mgr4.get_run(run4).state_version
        legal = _risk_approval(run4, "task_auth03d", version=v4,
                               fingerprints=["fp-low-4"], severity="LOW")
        _ok(mgr4.authorize_risk(run4, legal)["consumed"] is True, "对照组消费成功")
        store4.close()


def test_AUTH_04_canonical_payload_unicode_audience_byte_change_fails(root: Path) -> None:
    """AUTH-04｜注入：canonical payload/Unicode/audience 任一字节改变｜期望：验签失败。"""
    with _sandbox("auth04") as td:
        store, mgr = _mgr(td)
        run_id, w = _waiting_run(mgr, "task_auth04", "prod-write", ID_STAGING)
        v = mgr.get_run(run_id).state_version
        pre = VALID_PRECONDITIONS["prod-write"]
        # 带 Unicode 的信封（actor/payload 均含 CJK）——canonical JSON 以
        # ensure_ascii=False 原样签名，任何一字节改动都必须验签失败
        base = _resume_approval(
            run_id, "task_auth04", stop_event_id=w["stop_event_id"],
            stop_type="prod-write", version=v, preconditions=pre,
            actor="授权人-超哥①")
        _ok(len(base["actor"]) > 4 and any(ord(c) > 0x2E80 for c in base["actor"]),
            "对照组信封须真实携带 Unicode")

        def tampered(**over: Any) -> Dict[str, Any]:
            bad = copy.deepcopy(base)
            for k, val in over.items():
                bad[k] = val
            return bad  # 不重签 —— 签名仍是对原 canonical 字节的 HMAC

        # Unicode 一字符翻转（超→趫）：canonical 字节改变 → 验签失败
        _raises(ApprovalRejected, lambda: mgr.resume_waiting(
            run_id, tampered(actor="授权人-趫哥①"), pre), contains="signature verification failed")
        # audience 半边一：environment（受众环境）staging→production → 验签失败
        _raises(ApprovalRejected, lambda: mgr.resume_waiting(
            run_id, tampered(environment="production"), pre), contains="signature verification failed")
        # audience 半边二：authorized_scope 尾部加一字节 → 验签失败
        _raises(ApprovalRejected, lambda: mgr.resume_waiting(
            run_id, tampered(authorized_scope=ID_STAGING["scope_hash"] + "X"), pre),
            contains="signature verification failed")
        # canonical 载荷字节：expires_at 一位数字改动（仍合法 date-time）→ 验签失败
        _raises(ApprovalRejected, lambda: mgr.resume_waiting(
            run_id, tampered(expires_at="2098-01-01T00:00:00Z"), pre),
            contains="signature verification failed")
        # 键序/规范化漂移面：整信封重序列化不改值（canonical 化等价）→ 不属于字节改变，应仍可消费
        _ok(mgr.resume_waiting(run_id, copy.deepcopy(base), pre)["resumed"] is True,
            "对照组：未篡改的 Unicode 信封原样消费成功")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


def test_AUTH_05_concurrent_double_consume_exactly_one_wins(root: Path) -> None:
    """AUTH-05｜注入：并发双消费 approval｜期望：恰一成功。"""
    with _sandbox("auth05") as td:
        db = str(td / "events.db")
        store = EventStore(db)
        mgr_a = RunManager(store, keyring=KEYRING)
        mgr_b = RunManager(EventStore(db), keyring=KEYRING)  # 独立连接的第二个消费者
        run_id, w = _waiting_run(mgr_a, "task_auth05", "prod-write", ID_STAGING)
        v = mgr_a.get_run(run_id).state_version
        ap = _resume_approval(
            run_id, "task_auth05", stop_event_id=w["stop_event_id"],
            stop_type="prod-write", version=v,
            preconditions=VALID_PRECONDITIONS["prod-write"])
        pre = VALID_PRECONDITIONS["prod-write"]

        results: List[Tuple[str, Any]] = []
        barrier = threading.Barrier(2)

        def _consume(tag: str, mgr: RunManager) -> None:
            barrier.wait()
            try:
                rec = mgr.resume_waiting(run_id, copy.deepcopy(ap), dict(pre))
                results.append((tag, rec))
            except Exception as exc:  # noqa: BLE001
                results.append((tag, exc))

        t1 = threading.Thread(target=_consume, args=("A", mgr_a))
        t2 = threading.Thread(target=_consume, args=("B", mgr_b))
        for t in (t1, t2):
            t.start()
        for t in (t1, t2):
            t.join(timeout=60)
        _ok(not t1.is_alive() and not t2.is_alive(), "并发消费不得死锁/挂起")

        wins = [r for r in results if isinstance(r[1], dict)]
        losses = [r for r in results if isinstance(r[1], ApprovalReuseError)]
        _ok(len(wins) == 1, f"恰一成功（实得 {len(wins)}）: {results!r}")
        _ok(len(losses) == 1, f"另一路必为复用拒绝（实得 {len(losses)}）: {results!r}")
        _ok(wins[0][1]["resumed"] is True, "成功方真实完成 resume")
        # 事件面：WAITING_RESUMED 恰一条、nonce 消费恰一条（全有或全无）
        _ok(_count_events(store, run_id, "WAITING_RESUMED") == 1,
            "WAITING_RESUMED 事件恰一条（不产生双恢复）")
        _ok(len(mgr_a.broker.consumed_approvals(run_id=run_id)) == 1, "旁表恰一条消费")
        st = RunManager(EventStore(db), keyring=KEYRING).get_run(run_id)
        _ok(st.state == "RUNNING" and st.waiting is None, "重放终态=已恢复且无停等残留")
        _ok(store.verify_chain()["ok"], "并发写后事件链完整性保持")
        mgr_a.close()
        mgr_b.close()
        store.close()


def test_AUTH_06_key_revoked_clock_rollback_no_user_presence_rejected(root: Path) -> None:
    """AUTH-06｜注入：key revoked/clock rollback/无 user-presence｜期望：拒绝。"""
    with _sandbox("auth06") as td:
        now = time.time()
        # 腿一：key revoked —— keyring 移除 key_test_1（仅登记 key_test_2），
        # 用 key_test_1 签发的审批变成未知 key → 拒
        ring_without_a = ApprovalKeyring({"key_test_2": SECRET_B})
        store, mgr = _mgr(td, "a.db", keyring=ring_without_a)
        run_id, w = _waiting_run(mgr, "task_auth06a", "prod-write", ID_STAGING)
        v = mgr.get_run(run_id).state_version
        pre = VALID_PRECONDITIONS["prod-write"]
        revoked_key_ap = _resume_approval(
            run_id, "task_auth06a", stop_event_id=w["stop_event_id"],
            stop_type="prod-write", version=v, preconditions=pre)
        _raises(ApprovalRejected, lambda: mgr.resume_waiting(run_id, revoked_key_ap, pre),
                contains="key_id")
        # 对照：仍在册的 key_test_2 签发 → 可消费（撤销语义=移出即失效，非全锁死）
        still_valid = _resume_approval(
            run_id, "task_auth06a", stop_event_id=w["stop_event_id"],
            stop_type="prod-write", version=v, preconditions=pre)
        still_valid = _sign(still_valid, secret=SECRET_B, key_id=KEY_B)
        _ok(mgr.resume_waiting(run_id, still_valid, pre)["resumed"] is True,
            "对照组：在册密钥签发可消费")
        store.close()

        # 腿二：clock rollback —— 消费侧时钟落后于签发时刻（now < issued_at）
        store2, mgr2 = _mgr(td, "b.db")
        run2, w2 = _waiting_run(mgr2, "task_auth06b", "prod-write", ID_STAGING)
        v2 = mgr2.get_run(run2).state_version
        future_issued = _resume_approval(
            run2, "task_auth06b", stop_event_id=w2["stop_event_id"],
            stop_type="prod-write", version=v2, preconditions=pre,
            issued_at=_iso(now + 3600), expires_at=_iso(now + 7200))
        _raises(ApprovalRejected, lambda: mgr2.resume_waiting(
            run2, future_issued, pre), contains="TTL")
        _ok(mgr2.get_run(run2).state == "WAITING", "时钟回拨注入后仍 WAITING")
        store2.close()

        # 腿三：无 user-presence —— 产品映射为 decision 非明确『approve』
        # （conditional=未定的条件意见，deny=拒绝意见）均不足以消费
        store3, mgr3 = _mgr(td, "c.db")
        run3, w3 = _waiting_run(mgr3, "task_auth06c", "prod-write", ID_STAGING)
        v3 = mgr3.get_run(run3).state_version
        for decision in ("conditional", "deny"):
            ap = _resume_approval(
                run3, "task_auth06c", stop_event_id=w3["stop_event_id"],
                stop_type="prod-write", version=v3, preconditions=pre,
                decision=decision)
            _raises(ApprovalRejected, lambda a=ap: mgr3.resume_waiting(run3, a, pre),
                    contains="approve")
        _ok(mgr3.get_run(run3).state == "WAITING", "非明确批准不得恢复")
        store3.close()


# ---------------------------------------------------------------------------
# STOP 族（§20.5；方案 L330 要求九类逐类型全覆盖三态矩阵）
# ---------------------------------------------------------------------------
def test_STOP_01_nine_types_wrong_type_stale_version_replay_all_rejected(root: Path) -> None:
    """STOP-01｜注入：九种 stop type 使用错误类型审批（错误类型/旧版本/重放）｜期望：全拒绝。"""
    with _sandbox("stop01") as td:
        store, mgr = _mgr(td)
        for idx, stop_type in enumerate(NINE_STOP_TYPES):
            task = f"task_stop01_{idx}"
            run_id, w = _waiting_run(mgr, task, stop_type, ID_STAGING)
            v = mgr.get_run(run_id).state_version
            other_type = NINE_STOP_TYPES[(idx + 1) % len(NINE_STOP_TYPES)]
            other_pre = VALID_PRECONDITIONS[other_type]

            # (a) 错误类型（半边一）：risk 类审批喂 resume API → 路由判别拒
            risk_like = _risk_approval(
                run_id, task, version=v, fingerprints=[], stage="S1_REQUIREMENT",
                stop_event_id=w["stop_event_id"])
            _raises(ApprovalRejected, lambda: mgr.resume_waiting(
                run_id, risk_like, other_pre), contains="resume")

            # (b) 错误类型（半边二）：resume 审批锚定他类停等（自洽但错型）→ 绑定拒
            wrong_stop = _resume_approval(
                run_id, task, stop_event_id=w["stop_event_id"],
                stop_type=other_type, version=v, preconditions=other_pre)
            _raises(ApprovalRejected, lambda: mgr.resume_waiting(
                run_id, wrong_stop, other_pre), contains="stop_type")

            # (c) 旧版本：expected_state_version=v-1（重签有效）→ CAS 拒
            stale = _resume_approval(
                run_id, task, stop_event_id=w["stop_event_id"],
                stop_type=stop_type, version=v - 1,
                preconditions=VALID_PRECONDITIONS[stop_type])
            _raises(ApprovalRejected, lambda: mgr.resume_waiting(
                run_id, stale, VALID_PRECONDITIONS[stop_type]),
                contains="state_version")

            # (d) 重放：合法消费一次 → 同 nonce 重放 → 一次性拒
            good = _resume_approval(
                run_id, task, stop_event_id=w["stop_event_id"],
                stop_type=stop_type, version=v,
                preconditions=VALID_PRECONDITIONS[stop_type])
            _ok(mgr.resume_waiting(run_id, good, VALID_PRECONDITIONS[stop_type])["resumed"],
                f"{stop_type}: 合法授权应恢复（对照）")
            _raises(ApprovalReuseError, lambda: mgr.resume_waiting(
                run_id, good, VALID_PRECONDITIONS[stop_type]), contains="nonce")
            st = mgr.get_run(run_id)
            _ok(st.state == "RUNNING" and st.waiting is None,
                f"{stop_type}: 恢复后无停等残留")
        _ok(len(mgr.broker.consumed_approvals()) == len(NINE_STOP_TYPES),
            "九类各恰一次消费")
        _ok(store.verify_chain()["ok"], "九类矩阵后事件链完整性保持")
        store.close()


def test_STOP_02_resource_ext_unavail_not_recovered_but_approved_still_blocked(root: Path) -> None:
    """STOP-02｜注入：resource/ext-unavail 未恢复但已批准｜期望：仍不可 resume。"""
    with _sandbox("stop02") as td:
        store, mgr = _mgr(td)
        for stop_type in ("resource", "ext-unavail"):
            task = f"task_stop02_{stop_type.replace('-', '_')}"
            run_id, w = _waiting_run(mgr, task, stop_type, ID_STAGING)
            v = mgr.get_run(run_id).state_version
            # 授权按『已恢复世界』签发（客观条件内容哈希绑定到恢复后事实）
            recovered_pre = dict(VALID_PRECONDITIONS[stop_type])
            ap = _resume_approval(
                run_id, task, stop_event_id=w["stop_event_id"],
                stop_type=stop_type, version=v, preconditions=recovered_pre)

            # 注入一：探针未恢复（probe_recovered=False，真 bool）→ 客观条件不满足
            not_recovered = dict(recovered_pre, probe_recovered=False)
            _raises(ApprovalPreconditionError, lambda: mgr.resume_waiting(
                run_id, ap, not_recovered), contains="not satisfied")
            # 注入二：自报字符串 "false"（伪装恢复）→ 非真 bool 拒
            self_reported = dict(recovered_pre, probe_recovered="false")
            _raises(ApprovalPreconditionError, lambda: mgr.resume_waiting(
                run_id, ap, self_reported), contains="boolean")
            _ok(mgr.get_run(run_id).state == "WAITING",
                f"{stop_type}: 已批准但未恢复 → 仍 WAITING")
            _ok(len(mgr.broker.consumed_approvals(run_id=run_id)) == 0,
                f"{stop_type}: 拒绝路径零消费（授权未被烧掉）")

            # 对照：客观条件真恢复（真 bool True 且与授权哈希一致）→ 放行
            _ok(mgr.resume_waiting(run_id, ap, recovered_pre)["resumed"],
                f"{stop_type}: 恢复+授权齐备 → 放行（必要且充分）")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


def test_STOP_03_nine_types_preconditions_met_but_no_authorization_rejected(root: Path) -> None:
    """STOP-03｜注入：九种 stop type 客观条件已满足但缺一次性授权｜期望：九类全部拒绝 resume。"""
    with _sandbox("stop03") as td:
        store, mgr = _mgr(td)
        for idx, stop_type in enumerate(NINE_STOP_TYPES):
            task = f"task_stop03_{idx}"
            run_id, w = _waiting_run(mgr, task, stop_type, ID_STAGING)
            pre = VALID_PRECONDITIONS[stop_type]  # 客观条件已齐备

            # (a) 客观条件满足也不得绕过授权直接推进
            _raises(PipelineError, lambda: mgr.advance_stage(run_id),
                    contains="resume_waiting")
            # (b) 无授权（approval=None）——客观条件再齐备也拒
            _raises(ApprovalRejected, lambda: mgr.resume_waiting(run_id, None, pre),
                    contains="not a JSON object")
            # (c) 伪签名授权（形状合法 64-hex 但 HMAC 不对）→ 验签拒
            v = mgr.get_run(run_id).state_version
            forged = _resume_approval(
                run_id, task, stop_event_id=w["stop_event_id"],
                stop_type=stop_type, version=v, preconditions=pre)
            forged["signature"] = "0" * 64
            _raises(ApprovalRejected, lambda: mgr.resume_waiting(run_id, forged, pre),
                    contains="signature verification failed")

            st = mgr.get_run(run_id)
            _ok(st.state == "WAITING" and st.waiting is not None,
                f"{stop_type}: 缺一次性授权 → 九类全部拒绝 resume")
            _ok(st.waiting.stop_type == stop_type, f"{stop_type}: 停等类型不可漂移")
            _ok(len(mgr.broker.consumed_approvals(run_id=run_id)) == 0,
                f"{stop_type}: 零授权消费")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


# ---------------------------------------------------------------------------
# RISK 族（§20.5 RISK-01）
# ---------------------------------------------------------------------------
def _finding_schema_validator():
    """载入冻结 finding-event-v2.schema.json（jsonschema 缺失时返回 None）。"""
    try:
        import jsonschema
    except ImportError:
        return None
    schema = json.loads(
        (SYSTEM_DIR / "schemas" / "finding-event-v2.schema.json").read_text(
            encoding="utf-8"))
    return jsonschema.Draft7Validator(schema)


def _finding_event(event_type: str, *, state_from: Optional[str],
                   state_to: Optional[str] = None, **over: Any) -> Dict[str, Any]:
    doc: Dict[str, Any] = {
        "schema_version": "2.0",
        "event_type": event_type,
        "finding_id": "fnd_risk01",
        "fingerprint": "fp-risk01",
        "severity": "MEDIUM",
        "priority": "P2",
        "ts": "2026-10-08T00:00:00Z",
    }
    if state_from is not None:
        doc["state_from"] = state_from
    if state_to is not None:
        doc["state_to"] = state_to
    doc.update(over)
    return doc


def test_RISK_01_revoke_or_invalidate_appends_event_reopens_repairs(root: Path) -> None:
    """RISK-01｜注入：主动撤销或 fingerprint/severity/policy/control 改变｜
    期望：追加 REVOKED/INVALIDATED，立即重开并可进入修复链。"""
    # ── 半边一：冻结 schema 转移表（产品正源资产）真实验证 ──
    validator = _finding_schema_validator()
    if validator is not None:
        # 合法风险接受（对照组：ACCEPTED_RISK←OPEN，MEDIUM/P2+补偿措施）
        validator.validate(_finding_event(
            "ACCEPTED_RISK", state_from="OPEN",
            risk_acceptance={
                "approver": "授权人-超哥", "reason": "ac-auth-cond 低风险接受理由",
                "scope": "scope-ac-001", "compensating_controls": ["ctrl-1"],
                "expiry": "2099-12-31T00:00:00Z"}))
        # 主动撤销：RISK_REVOKED←ACCEPTED_RISK → 追加 REVOKED 合法
        validator.validate(_finding_event("RISK_REVOKED", state_from="ACCEPTED_RISK"))
        # fingerprint/severity/policy/control 改变 → RISK_INVALIDATED 追加且立即重开
        validator.validate(_finding_event(
            "RISK_INVALIDATED", state_from="ACCEPTED_RISK", state_to="OPEN"))
        # 立即重开后可进入修复链：FIX_STARTED←OPEN 合法
        validator.validate(_finding_event("FIX_STARTED", state_from="OPEN"))
        # 负例：非 ACCEPTED_RISK 起点的撤销/失效（未接受先撤销）→ schema 拒
        for bad in (
            _finding_event("RISK_REVOKED", state_from="OPEN"),
            _finding_event("RISK_INVALIDATED", state_from="OPEN", state_to="OPEN"),
            _finding_event("RISK_INVALIDATED", state_from="ACCEPTED_RISK",
                           state_to="CLOSED"),   # 失效必须立即重开为 OPEN，不得关死
            {"schema_version": "2.0", "event_type": "RISK_INVALIDATED",
             "finding_id": "fnd_risk01", "fingerprint": "fp", "severity": "MEDIUM",
             "priority": "P2", "ts": "2026-10-08T00:00:00Z"},  # 缺 state_from/state_to
        ):
            errors = list(validator.iter_errors(bad))
            _ok(errors, f"schema 必须拒绝非法撤销/失效转移: {bad.get('event_type')}"
                        f"/state_from={bad.get('state_from')!r}")
    else:
        print("    (note) jsonschema 未安装，schema 转移表断言降级为管线半边")

    # ── 半边二：管线侧 —— finding 面改变使已消费授权在判定点立即失效，
    #    run 保持可修复（新 attempt 修复链入口可用） ──
    with _sandbox("risk01") as td:
        store, mgr = _mgr(td)
        run_id = _soft_terminal_run(mgr, "task_risk01", ID_STAGING)
        mgr.register_finding(run_id, "fnd_risk01_a", "fp-risk01-a", "MEDIUM", "P2")
        v = mgr.get_run(run_id).state_version
        auth = _risk_approval(run_id, "task_risk01", version=v,
                              fingerprints=["fp-risk01-a"])
        _ok(mgr.authorize_risk(run_id, auth)["consumed"] is True, "授权先合法消费")

        # 注入：授权后 finding 面改变（新增 fingerprint）→ 授权覆盖面失配
        mgr.register_finding(run_id, "fnd_risk01_b", "fp-risk01-b", "MEDIUM", "P2")
        _raises(PipelineError, lambda: mgr.complete_run(run_id),
                contains="未过期且指纹精确匹配")
        _ok(mgr.get_run(run_id).state == "RUNNING",
            "授权失效后不得完成 CONDITIONAL（立即重开=保持可变）")
        # 可进入修复链：软终态段可开新 attempt（修复链入口）
        out = mgr.advance_stage(run_id)
        st = mgr.get_run(run_id)
        _ok(out.get("started_attempt_id", "").startswith("att_"),
            "修复链入口：软终态段可追加新 attempt")
        _ok(st.stages["S7_GATE"].current_attempt.status == "RUNNING",
            "S7 修复 attempt 处于 RUNNING")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


# ---------------------------------------------------------------------------
# COND 族（§20.5 COND-01~06）
# ---------------------------------------------------------------------------
def test_COND_01_conditional_without_risk_authorization_not_eligible(root: Path) -> None:
    """COND-01｜注入：CONDITIONAL 无 risk authorization｜期望：technical eligibility=false，技术 context failure。"""
    # 聚合半边：CONDITIONAL 站 → technical_eligible=False + 技术上下文 failure
    agg = GateAggregator({"1", "2"}, target_sha=ID_STAGING["commit_sha"],
                         environment="staging")
    agg.add({"station": "1", "outcome": "PASS", "sha": ID_STAGING["commit_sha"],
             "environment": "staging"})
    agg.add({"station": "2", "outcome": "CONDITIONAL", "sha": ID_STAGING["commit_sha"],
             "environment": "staging"})
    verdict = agg.aggregate()
    _ok(verdict["aggregate_outcome"] == CONDITIONAL, "条件站必须保持 CONDITIONAL")
    _ok(verdict["technical_eligible"] is False, "无授权 CONDITIONAL → technical_eligible=false")
    status = agg.to_github_status(verdict)
    _ok(status["state"] == "failure", "技术 context 必须 failure（绝不上绿）")

    # 管线半边：软终态 run 无 risk 授权 → complete_run fail-closed 拒绝
    with _sandbox("cond01") as td:
        store, mgr = _mgr(td)
        run_id = _soft_terminal_run(mgr, "task_cond01", ID_STAGING)
        mgr.register_finding(run_id, "fnd_cond01", "fp-cond01", "MEDIUM", "P2")
        _ok(not mgr.get_run(run_id).risk_authorizations, "未消费任何 risk 授权")
        _ok(mgr.broker.has_unexpired_risk_authorization(run_id) is None,
            "授权查询面为空")
        _raises(PipelineError, lambda: mgr.complete_run(run_id), contains="risk 授权")
        st = mgr.get_run(run_id)
        _ok(st.state == "RUNNING" and not st.terminal,
            "无授权 CONDITIONAL 不得完成——保持未完成（fail-closed）")
        _ok(st.stage_statuses()["S7_GATE"] == "COMPLETED_CONDITIONAL",
            "内部判定保持 CONDITIONAL（不洗白为 PASS）")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


def test_COND_02_authorization_cross_sha_env_widened_set_replay_rejected(root: Path) -> None:
    """COND-02｜注入：授权跨 SHA/env/扩 finding 集/重放｜期望：拒绝。"""
    with _sandbox("cond02") as td:
        # 三个软终态 run：A=staging/X；B=staging/Y（异 SHA）；C=production/X（异 env）
        id_b = dict(ID_STAGING, commit_sha="b" * 40)
        id_c = dict(ID_STAGING, environment="production")
        store, mgr = _mgr(td)
        run_a = _soft_terminal_run(mgr, "task_cond02a", ID_STAGING)
        run_b = _soft_terminal_run(mgr, "task_cond02b", id_b)
        run_c = _soft_terminal_run(mgr, "task_cond02c", id_c)
        for r in (run_a, run_b, run_c):
            mgr.register_finding(r, "fnd_cond02", "fp-cond02", "MEDIUM", "P2")
        va = mgr.get_run(run_a).state_version
        template = _risk_approval(run_a, "task_cond02a", version=va,
                                  fingerprints=["fp-cond02"])

        # 腿一：跨 SHA —— 授权移植到 run B（重签有效，watermark 仍锚 X）→ 拒
        cross_sha = _sign(dict(template, run_id=run_b, task_id="task_cond02b",
                               input_watermark=ID_STAGING["commit_sha"]))
        _raises(ApprovalRejected, lambda: mgr.authorize_risk(run_b, cross_sha),
                contains="commit_sha")
        # 腿二：跨 env —— 授权移植到 run C（重签有效，env 仍 staging）→ 拒
        cross_env = _sign(dict(template, run_id=run_c, task_id="task_cond02c",
                               environment="staging",
                               input_watermark=ID_STAGING["commit_sha"]))
        _raises(ApprovalRejected, lambda: mgr.authorize_risk(run_c, cross_env),
                contains="environment")
        # 腿三：扩 finding 集 —— 指纹面声称超出 run 实际可接受集 → 精确匹配拒
        vb = mgr.get_run(run_b).state_version
        widened = _risk_approval(
            run_b, "task_cond02b", version=vb,
            fingerprints=["fp-cond02", "fp-not-registered"],
            input_watermark=id_b["commit_sha"])
        _raises(ApprovalRejected, lambda: mgr.authorize_risk(run_b, widened),
                contains="精确匹配")
        # 腿四：重放 —— run C 合法消费一次后同 nonce 重放 → 拒
        vc = mgr.get_run(run_c).state_version
        legal_c = _risk_approval(run_c, "task_cond02c", version=vc,
                                 fingerprints=["fp-cond02"],
                                 environment="production",
                                 input_watermark=ID_STAGING["commit_sha"])
        _ok(mgr.authorize_risk(run_c, legal_c)["consumed"] is True, "对照组：合法授权可消费")
        _raises(ApprovalReuseError, lambda: mgr.authorize_risk(run_c, legal_c),
                contains="nonce")
        _ok(len(mgr.broker.consumed_approvals(run_id=run_c)) == 1, "恰一次消费")
        for r in (run_a, run_b):
            _ok(mgr.get_run(r).risk_authorizations == [],
                f"{r}: 移植/扩面授权零落账")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


def test_COND_03_authorized_conditional_action_gate_exactly_once(root: Path) -> None:
    """COND-03｜注入：合法低风险接受、其余全 PASS、risk 与 action 两类精确授权｜
    期望：内部仍 CONDITIONAL；技术 context=success/AUTHORIZED_CONDITIONAL；Action Gate 成功后动作恰一次。"""
    # 聚合半边：其余全 PASS + 单条件站 → 整线仍 CONDITIONAL（绝不上绿）
    agg = GateAggregator({"1"}, target_sha=ID_STAGING["commit_sha"],
                         environment="staging")
    agg.add({"station": "1", "outcome": "CONDITIONAL", "sha": ID_STAGING["commit_sha"],
             "environment": "staging"})
    v_agg = agg.aggregate()
    _ok(v_agg["aggregate_outcome"] == CONDITIONAL and not v_agg["technical_eligible"],
        "其余全 PASS 时条件站仍使整线 CONDITIONAL（内部不洗白）")

    with _sandbox("cond03") as td:
        store, mgr = _mgr(td)
        run_id = _soft_terminal_run(mgr, "task_cond03", ID_STAGING)
        statuses = mgr.get_run(run_id).stage_statuses()
        _ok(all(statuses[s] == "PASSED" for s in list(statuses)[:6])
            and statuses["S7_GATE"] == "COMPLETED_CONDITIONAL",
            "S1..S6 全 PASS + S7 CONDITIONAL（内部仍 CONDITIONAL）")
        mgr.register_finding(run_id, "fnd_cond03", "fp-cond03", "LOW", "P3")

        # risk 类精确授权（指纹精确匹配可接受面）→ 消费成功
        v = mgr.get_run(run_id).state_version
        risk = _risk_approval(run_id, "task_cond03", version=v,
                              fingerprints=["fp-cond03"], severity="LOW")
        _ok(mgr.authorize_risk(run_id, risk)["consumed"] is True, "risk 类精确授权消费")

        # action 类精确授权（prod_write 审批）→ Action Gate 全链恰一次
        # R7：prod_write 高危——补嵌入双联签 + exact descriptor（新消费契约）
        action_ap = _cosign_ap(_action_approval(run_id, "task_cond03",
                                                version=v, stage="S7_GATE"))
        reserved = mgr.reserve_action(run_id, "prod-write",
                                      "db://staging/erp#cond03", action_ap,
                                      action_descriptor=_descriptor(action_ap))
        _ok(reserved["action_state"] == "RESERVED", "action 授权预留成功")
        mgr.start_action(run_id, reserved["action_id"], receipt="cond03 caller self-report")
        receipt = _external_receipt(reserved, run_id)
        _ok(mgr.reconcile_receipt(run_id, reserved["action_id"], receipt)["reconciled"]
            is True, "外部正源回执对账通过（Action Gate 成功）")
        committed = mgr.commit_action(run_id, reserved["action_id"], receipt)
        _ok(committed["action_state"] == "COMMITTED"
            and committed["receipt_status"] == RECEIPT_RECONCILED,
            "动作经对账回执恰一次 COMMITTED")

        # 动作恰一次：终态后不可再动、授权不可复用、旧回执不可移植到新动作
        _raises(ActionError, lambda: mgr.start_action(run_id, reserved["action_id"]))
        _raises(ActionError, lambda: mgr.commit_action(
            run_id, reserved["action_id"], receipt))
        _raises(ApprovalReuseError, lambda: mgr.reserve_action(
            run_id, "prod-write", "db://staging/erp#cond03-2", action_ap))
        fresh_ap = _cosign_ap(_action_approval(run_id, "task_cond03",
                                               version=v, stage="S7_GATE"))
        second = mgr.reserve_action(run_id, "prod-write",
                                    "db://staging/erp#cond03-2", fresh_ap,
                                    action_descriptor=_descriptor(fresh_ap))
        mgr.start_action(run_id, second["action_id"])
        # 旧动作的 attestation 移植到新动作（action_id 不一致）→ Action Gate 拒
        _raises(ActionError, lambda: mgr.commit_action(
            run_id, second["action_id"], receipt), contains="action_id")
        mgr.fail_action(run_id, second["action_id"],
                        "旧 attestation 不可移植——按失败收口")

        # 技术上下文：授权后的 CONDITIONAL 完成可成立（AUTHORIZED_CONDITIONAL 的
        # 产品落地面），且 verdict 仍 CONDITIONAL、不升格 SUCCEEDED
        done = mgr.complete_run(run_id)
        _ok(done["final_state"] == "COMPLETED_CONDITIONAL",
            "risk+action 双授权后 COMPLETED_CONDITIONAL 成立")
        _ok(done["policy_verdict"] == "CONDITIONAL" and done["execution_status"] == "COMPLETED",
            "完成事件双轴仍 COMPLETED/CONDITIONAL（内部 CONDITIONAL 语义保持）")
        _ok("risk authorization" in done["terminal_reason"],
            "终态理由须记录授权在案（AUTHORIZED_CONDITIONAL 语义）")
        st = RunManager(EventStore(str(td / "events.db")),
                        keyring=KEYRING).get_run(run_id)
        _ok(st.actions[reserved["action_id"]]["action_state"] == "COMMITTED",
            "重放面：动作恰一次 COMMITTED 随事件流重建")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


def test_COND_04_p0_p1_risk_acceptance_or_conditional_auth_rejected_stays_blocked(root: Path) -> None:
    """COND-04｜注入：P0/P1 尝试风险接受或条件授权｜期望：拒绝并保持 BLOCKED。"""
    with _sandbox("cond04") as td:
        store, mgr = _mgr(td)
        run_id = _soft_terminal_run(mgr, "task_cond04", ID_STAGING)
        # 登记不可风险接受面：HIGH/P1（severity 轴）与 MEDIUM/P0（priority 轴）
        mgr.register_finding(run_id, "fnd_cond04_sev", "fp-cond04-sev", "HIGH", "P1")
        mgr.register_finding(run_id, "fnd_cond04_pri", "fp-cond04-pri", "MEDIUM", "P0")
        # 一个可接受项作为对照（证明拒的是 P0/P1 面而非整 run 死锁）
        mgr.register_finding(run_id, "fnd_cond04_ok", "fp-cond04-ok", "MEDIUM", "P2")
        v = mgr.get_run(run_id).state_version

        # 腿一：P0/P1 风险接受（HIGH severity 声明）→ 机器拒绝
        ap_high = _risk_approval(run_id, "task_cond04", version=v,
                                 fingerprints=["fp-cond04-sev"], severity="HIGH")
        _raises(ApprovalRejected, lambda: mgr.authorize_risk(run_id, ap_high),
                contains="不可风险接受")
        # 腿二：以 MEDIUM 声明夹带 P0/P1 指纹（伪装条件授权）→ 精确匹配拒
        ap_smuggle = _risk_approval(
            run_id, "task_cond04", version=v,
            fingerprints=["fp-cond04-ok", "fp-cond04-pri"], severity="MEDIUM")
        _raises(ApprovalRejected, lambda: mgr.authorize_risk(run_id, ap_smuggle),
                contains="精确匹配")
        # 腿三：即便先合法接受了可接受项，complete 仍因 P0/P1 在案面拒绝并保持未完成
        legal = _risk_approval(run_id, "task_cond04", version=v,
                               fingerprints=["fp-cond04-ok"], severity="MEDIUM")
        _ok(mgr.authorize_risk(run_id, legal)["consumed"] is True, "对照项授权消费成功")
        _raises(PipelineError, lambda: mgr.complete_run(run_id),
                contains="不得风险接受")
        st = mgr.get_run(run_id)
        _ok(st.state == "RUNNING" and not st.terminal,
            "P0/P1 在案 → CONDITIONAL 完成被阻断（保持 BLOCKED 语义：不得完成）")
        _ok(st.stage_statuses()["S7_GATE"] == "COMPLETED_CONDITIONAL",
            "内部判定保持软终态不漂移")
        # 聚合半边：条件态永不映射绿（保持阻断口径一致）
        agg = GateAggregator({"1"}, target_sha=ID_STAGING["commit_sha"],
                             environment="staging")
        agg.add({"station": "1", "outcome": "CONDITIONAL",
                 "sha": ID_STAGING["commit_sha"], "environment": "staging"})
        _ok(agg.to_github_status(agg.aggregate())["state"] == "failure",
            "CONDITIONAL 技术上下文保持 failure（不上绿=保持阻断）")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


def test_COND_05_post_auth_new_finding_ttl_identity_change_invalidated(root: Path) -> None:
    """COND-05｜注入：授权后新增 finding、TTL 到期、SHA/scope/policy/watermark 变化｜
    期望：authorization、attestation、context 失效；动作前重验拒绝。"""
    with _sandbox("cond05") as td:
        now = time.time()
        store, mgr = _mgr(td)

        # 腿一：授权后新增 finding → 授权覆盖面失配 → complete 拒（authorization 失效）
        run1 = _soft_terminal_run(mgr, "task_cond05a", ID_STAGING)
        mgr.register_finding(run1, "fnd_cond05_a1", "fp-cond05-a1", "MEDIUM", "P2")
        v1 = mgr.get_run(run1).state_version
        auth1 = _risk_approval(run1, "task_cond05a", version=v1,
                               fingerprints=["fp-cond05-a1"])
        _ok(mgr.authorize_risk(run1, auth1)["consumed"] is True, "授权先消费")
        mgr.register_finding(run1, "fnd_cond05_a2", "fp-cond05-a2", "MEDIUM", "P2")
        _raises(PipelineError, lambda: mgr.complete_run(run1),
                contains="未过期且指纹精确匹配")
        _ok(mgr.get_run(run1).state == "RUNNING", "context 失效 → 不得完成")

        # 腿二：TTL 到期（envelope expires_at=now+2s，消费后睡眠过期）→ 失效
        run2 = _soft_terminal_run(mgr, "task_cond05b", ID_STAGING)
        mgr.register_finding(run2, "fnd_cond05_b", "fp-cond05-b", "MEDIUM", "P2")
        v2 = mgr.get_run(run2).state_version
        short_ttl = _risk_approval(run2, "task_cond05b", version=v2,
                                   fingerprints=["fp-cond05-b"],
                                   issued_at=_iso(now - 10), expires_at=_iso(now + 2))
        _ok(mgr.authorize_risk(run2, short_ttl)["consumed"] is True, "短 TTL 授权先消费")
        time.sleep(3)  # 真实等待过期（非 mock）
        _ok(mgr.broker.has_unexpired_risk_authorization(run2) is None,
            "TTL 到期 → authorization 失效（事件正源重判）")
        _raises(PipelineError, lambda: mgr.complete_run(run2), contains="未过期")
        _ok(mgr.get_run(run2).state == "RUNNING", "TTL 失效后 run 保持未完成")

        # 腿三：scope 变化（新 run 异 scope_hash）→ 旧授权不可移植（context 不可带走的 SHA/scope/watermark 面）
        # （换新 nonce 重签——否则重放检查先于绑定拒，遮蔽 scope 拒绝面）
        id_other_scope = dict(ID_STAGING, scope_hash="scope-ac-999")
        run3 = _soft_terminal_run(mgr, "task_cond05c", id_other_scope)
        mgr.register_finding(run3, "fnd_cond05_c", "fp-cond05-c", "MEDIUM", "P2")
        v3 = mgr.get_run(run3).state_version
        transplanted = _sign(dict(
            auth1, run_id=run3, task_id="task_cond05c",
            expected_state_version=v3,
            nonce=f"nonce-ac-transplant-{os.urandom(8).hex()}"))
        _raises(ApprovalRejected, lambda: mgr.authorize_risk(run3, transplanted),
                contains="authorized_scope")
        _ok(mgr.get_run(run3).risk_authorizations == [], "scope 变化 → 授权零移植")

        # 腿四：动作前重验 —— 授权签署时的 state_version 过期后 reserve 必拒（CAS）
        run4 = mgr.create_run("task_cond05d", ID_STAGING)["run_id"]
        mgr.advance_stage(run4)          # v=2，S1 RUNNING
        stale_action = _action_approval(run4, "task_cond05d", version=2,
                                        stage="S1_REQUIREMENT")
        mgr.raise_waiting(run4, "prod-write", "cond05 状态推进使 v=2 → v=3")
        _ok(mgr.get_run(run4).state_version == 3, "前置：状态版本已前进")
        _raises(ApprovalRejected, lambda: mgr.reserve_action(
            run4, "prod-write", "db://staging/erp#cond05", stale_action),
            contains="state_version")
        fresh_action = _cosign_ap(_action_approval(run4, "task_cond05d",
                                                   version=3,
                                                   stage="S1_REQUIREMENT"))
        _ok(mgr.reserve_action(run4, "prod-write", "db://staging/erp#cond05",
                               fresh_action,
                               action_descriptor=_descriptor(
                                   fresh_action))["action_state"] == "RESERVED",
            "对照组：重验通过的新授权可预留")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        store.close()


def test_COND_06_concurrent_consume_or_replay_attestation_after_failure_once(root: Path) -> None:
    """COND-06｜注入：并发双消费或动作失败后重放 attestation｜期望：最多一次消费；失败后须新授权。"""
    with _sandbox("cond06") as td:
        db = str(td / "events.db")
        store = EventStore(db)
        mgr_a = RunManager(store, keyring=KEYRING)
        mgr_b = RunManager(EventStore(db), keyring=KEYRING)
        run_id = _soft_terminal_run(mgr_a, "task_cond06", ID_STAGING)
        mgr_a.register_finding(run_id, "fnd_cond06", "fp-cond06", "MEDIUM", "P2")
        v = mgr_a.get_run(run_id).state_version
        ap = _risk_approval(run_id, "task_cond06", version=v,
                            fingerprints=["fp-cond06"])

        # 腿一：并发双消费 risk 授权 → 最多一次（恰一成功、一复用拒）
        outcomes: List[Any] = []
        barrier = threading.Barrier(2)

        def _consume(mgr: RunManager) -> None:
            barrier.wait()
            try:
                outcomes.append(mgr.authorize_risk(run_id, copy.deepcopy(ap)))
            except Exception as exc:  # noqa: BLE001
                outcomes.append(exc)

        t1 = threading.Thread(target=_consume, args=(mgr_a,))
        t2 = threading.Thread(target=_consume, args=(mgr_b,))
        for t in (t1, t2):
            t.start()
        for t in (t1, t2):
            t.join(timeout=60)
        _ok(sum(isinstance(o, dict) for o in outcomes) == 1,
            f"并发双消费恰一成功: {outcomes!r}")
        _ok(sum(isinstance(o, ApprovalReuseError) for o in outcomes) == 1,
            f"另一路必为复用拒绝: {outcomes!r}")
        _ok(len(mgr_a.broker.consumed_approvals(run_id=run_id)) == 1, "台账恰一次消费")
        mgr_a.close()
        mgr_b.close()

        # 腿二：动作失败后重放 attestation → 终态不再裁决；须新授权才能再动作
        mgr = RunManager(EventStore(db), keyring=KEYRING)
        ap2 = _cosign_ap(_action_approval(run_id, "task_cond06", version=v,
                                          stage="S7_GATE"))
        reserved = mgr.reserve_action(run_id, "prod-write", "db://staging/erp#cond06",
                                      ap2, action_descriptor=_descriptor(ap2))
        aid = reserved["action_id"]
        mgr.start_action(run_id, aid, receipt="cond06 started")
        failed = mgr.fail_action(run_id, aid, "runner crash; outcome unknown")
        _ok(failed["action_state"] == ACTION_FAILED_UNKNOWN, "动作失败收口 FAILED_UNKNOWN")
        receipt = _external_receipt(reserved, run_id)  # 事后到达的合法 attestation
        rec = mgr.reconcile_receipt(run_id, aid, receipt)
        _ok(rec["reconciled"] is None and "FAILED_UNKNOWN" in rec["note"],
            "失败终态后重放 attestation 不再裁决（最多一次消费）")
        _raises(ActionError, lambda: mgr.commit_action(run_id, aid, receipt),
                contains="illegal action transition")
        _raises(ApprovalReuseError, lambda: mgr.reserve_action(
            run_id, "prod-write", "db://staging/erp#cond06-2", ap2),
            contains="nonce")  # 失败后旧授权已消费——须新授权
        ap3 = _cosign_ap(_action_approval(run_id, "task_cond06", version=v,
                                          stage="S7_GATE"))
        renewed = mgr.reserve_action(run_id, "prod-write",
                                     "db://staging/erp#cond06-2", ap3,
                                     action_descriptor=_descriptor(ap3))
        _ok(renewed["action_state"] == "RESERVED", "失败后凭新授权可再动作（修复路径）")
        mgr.start_action(run_id, renewed["action_id"])
        committed = mgr.commit_action(
            run_id, renewed["action_id"], _external_receipt(renewed, run_id))
        _ok(committed["action_state"] == "COMMITTED", "新授权链可完整走通")
        _ok(mgr.get_run(run_id).actions[aid]["action_state"] == ACTION_FAILED_UNKNOWN,
            "失败动作终态不可复活")
        _ok(store.verify_chain()["ok"], "事件链完整性保持")
        mgr.close()
        store.close()


# ---------------------------------------------------------------------------
# 运行器
# ---------------------------------------------------------------------------
_TEST_NAME_RE = re.compile(r"^test_(AUTH|STOP|RISK|COND)_(\d{2})_")

# 不可实现清单：本四族 16 条均有真实产品语义可注入，无整条不可实现项。
NOT_IMPLEMENTABLE: Dict[str, str] = {}

# 诚实映射边界（非整条跳过；语义映射说明见模块 docstring）
MAPPING_NOTES: Dict[str, str] = {
    "AUTH-06": "「无 user-presence」映射为 decision!=approve（approval-v2 无独立 UV 位）",
    "RISK-01": "REVOKED/INVALIDATED/立即重开/修复链半边以冻结 finding-event-v2.schema.json "
               "（jsonschema 真实验证）断言；管线半边验证 finding 面改变使已消费授权失效且 run 可修复",
    "COND-01": "「技术 context failure」= gate_aggregator technical_eligible=False+GitHub failure "
               "＋ complete_run 无 risk 授权 fail-closed",
    "COND-03": "「success/AUTHORIZED_CONDITIONAL」产品落地面 = COMPLETED_CONDITIONAL 终态"
               "（verdict 仍 CONDITIONAL，terminal_reason 记授权在案）",
}


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
    print("§20 AUTH/STOP/RISK/COND 四族专属验收测试（16 条；不可实现 0 条）")
    for tid, note in MAPPING_NOTES.items():
        print(f"  NOTE {tid}: {note}")
    print("-" * 72)
    records: List[Dict[str, Any]] = []
    failed: List[str] = []
    for name, fn in tests:
        match = _TEST_NAME_RE.match(name)
        assert match is not None
        test_id = f"{match.group(1)}-{match.group(2)}"
        with tempfile.TemporaryDirectory(prefix="ac-auth-cond-run-") as td:
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
            json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"逐 ID 结果已写: {out_path}")
    print("=" * 72)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

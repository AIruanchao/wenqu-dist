#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——ACT/RUN 族（test_ac_act_run）。

覆盖 Codex 方案 §20.1/§20.5 中 ACT-01~06、RUN-01~03 共 9 条：每条按
「注入→期望」逐字对齐方案 §20 表格（正源：evidence/00-baseline/
codex-external/方案.md），真实构造场景（真实事件库/tmp fixture、真实调用
产品码、真实子进程）并断言结果，绝不空转。

被测正源（不改动任何产品码；均为第五波加固后最终语义）：
- system/wenqu_core/wenqu_pipeline.py
    ActionSaga/RunManager（reserve_action 必传 action 类 HMAC 审批、
    _ACTION_APPROVAL_TYPE 封闭映射、receipt PROVISIONAL/RECONCILED 分级、
    commit 只收外部验签回执、FAILED_UNKNOWN、重放授权消费链校验）
    —— ACT-01~06 全部六条。
- system/wenqu_core/runner.py
    TrustedRunner（run token 注入 + 超时三层击杀 killpg+进程树+token 全
    系统扫杀、env 白名单剥除、allowlist opt-in）与 EvidenceStore CAS
    —— RUN-01/02/03。
- system/wenqu_core/approval_keys.py + tests/fixtures/approval-keys.json
    测试密钥范式：审批/外部回执均以 fixtures 密钥真 HMAC-SHA256 签发。

本地等价映射说明（§20 条目语义 → 本仓被测体语义）：
- ACT-01「context 可表技术 PASS，controller 不动作」→ RunManager 终判可
  表达技术 PASS（七段全 PASSED → SUCCEEDED），但 ActionSaga 侧零事件：
  无 exact merge/release 授权时 reserve_action 全拒（零审批消费、零
  ACTION_* 事件）；技术 PASS run 终态后 controller 永不动作。
- ACT-02「action、method、head/merge-group、artifact/env 任一不符 →
  Action Authorization Gate failure」→ reserve_action 授权门（F4-AUTH-001）
  的各不符腿：action_type↔approval_type 映射不符 / method-artifact 字节
  篡改破坏 HMAC / head=watermark 不符 / env 不符，全拒且零落账。
- ACT-03「check 发布前/后 crash 或回执丢失 → outbox 幂等恢复；同一
  check_run 更新，不产生伪双绿」→ control_outbox 事件幂等（event_id
  INSERT OR IGNORE）、仅复制事件流的崩溃恢复重放一致、同 nonce/同
  action 的重复推进被拒（绝不双 COMMITTED）、无授权消费链的 RESERVED
  重放即 Corruption。
- ACT-04「merge/release 调用前/后 crash 或回执丢失 → 先查询外部事实；
  COMMITTED 或 FAILED_UNKNOWN；绝不盲重试」→ reconcile_receipt（只读
  查询外部事实）先行，COMMITTED 凭验签回执落账；对账不了/外部声明
  FAILED → fail_action=FAILED_UNKNOWN 终态；终态与一次性 nonce 封死
  一切重试路径。
- ACT-05「外部陈旧绿、dispatcher/App 失联 → direct merge 被角色/ruleset
  拒绝；动作保持 BLOCKED」→ 陈旧水印回执拒绝、伪签名回执拒绝、自报
  回执拒绝——动作停留 STARTED/PROVISIONAL（不可 COMMITTED）；ruleset/
  policy 不符的 direct merge 授权在 reserve 门被拒。
- ACT-06「payload 使用错误 discriminator 或缺专属字段 → schema 拒绝」→
  ApprovalBroker.validate_structure 的 payload 判别封闭（键集=该类专属
  字段全集）经 reserve_action 路径逐类型验证。
- RUN-01「被测程序读取 Keychain/SSH agent/生产配置 → 隔离拒绝」→
  TrustedRunner env 白名单剥除：SSH_AUTH_SOCK/生产配置路径等敏感环境
  通道在子进程环境里不存在（隔离拒绝——已实现的进程环境通道半边）。
- RUN-02「timeout 后子孙进程 → 全部终止，无孤儿写盘」→ 超时三层击杀：
  同组子进程（killpg）、setsid 逃逸孙进程（进程树+token 扫杀）、
  double-fork 后被 PID 1 收养的 daemon（token 全系统扫杀）全部死亡，
  三个延迟 marker 均不落盘。
- RUN-03「fork bomb/输出爆量/网络外连 → 配额/allowlist 阻断」→
  allowlist（opt-in）前置阻断：未列名可执行一律 PermissionError、零
  进程产生（marker 不落盘）。

明确未实现的注入子面（不硬凑、不 xfail，见 BOUNDARIES 登记）：
容器级隔离（Keychain 直读/SSH agent socket 直连/任意路径文件读）、
输出爆量字节配额、网络 egress allowlist、真实 GitHub check_run 发布
outbox、dispatcher/App 失联心跳检测——产品中无对应语义，逐条理由见
模块级 BOUNDARIES。

独立运行：python3 system/tests/test_ac_act_run.py [--json OUT.json]
exit 0 = 全部用例绿；默认把逐 ID 结果数组写入
evidence/04-unit-property-mutation/ac-act-run.json。
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

SYSTEM_DIR = Path(__file__).resolve().parent.parent  # system/
REPO_ROOT = SYSTEM_DIR.parent
if str(SYSTEM_DIR) not in sys.path:
    sys.path.insert(0, str(SYSTEM_DIR))

from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope  # noqa: E402
from wenqu_core.runner import RUN_TOKEN_ENV, TrustedRunner  # noqa: E402
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ActionError,
    ApprovalRejected,
    ApprovalReuseError,
    PipelineCorruptionError,
    PipelineError,
    RECEIPT_PROVISIONAL,
    RECEIPT_RECONCILED,
    RunManager,
)

ARTIFACT_PATH = (
    REPO_ROOT / "evidence" / "04-unit-property-mutation" / "ac-act-run.json")

KEYRING = ApprovalKeyring.from_path(
    SYSTEM_DIR / "tests" / "fixtures" / "approval-keys.json")
KEY_ID = "key_test_1"
SECRET = KEYRING.get(KEY_ID)

# run 身份（本文件独立取值；commit_sha 40-hex、env ∈ {local,staging,production}）
IDENT: Dict[str, str] = {
    "commit_sha": "7f3c9a2b5d81e04f6a9c2b7d5e8f10a3c6d9b4e2",
    "environment": "staging",
    "scope_hash": "scope-act-run-001",
    "repo_id": "erp-main",
    "policy_hash": "policy-act-run-7",
    "ruleset_hash": "rules-act-run-3",
}

# approval-v2 payload 判别（与 _APPROVAL_PAYLOAD_DISCRIMINATOR 键集一致）
_PAYLOADS: Dict[str, Dict[str, str]] = {
    "merge": {
        "repo_id": "erp-main",
        "base_sha": "4444444444444444444444444444444444444444",
        "head_sha": "5555555555555555555555555555555555555555",
        "merge_method": "merge",
    },
    "release": {
        "release_id": "rel-2026-10-08.1",
        "artifact_sha256": "6" * 64,
        "manifest_sha256": "7" * 64,
        "environment": "staging",
        "previous_release_id": "rel-2026-10-07.9",
    },
    "ddl": {
        "database_identity": "db://staging/erp",
        "statement_digest": "8" * 64,
        "before_schema_hash": "9" * 64,
        "after_schema_hash": "a" * 64,
        "backup_id": "bak-2026-10-08",
        "rollback_plan_hash": "b" * 64,
    },
    "prod_write": {
        "operation_digest": "c" * 64,
        "data_scope_digest": "d" * 64,
        "idempotency_key": "idem-act-042",
        "conservation_hash": "e" * 64,
    },
    "fund_auth": {
        "subject_role": "ops-fund",
        "amount_scope_digest": "1" * 64,
        "positive_negative_test_hash": "2" * 64,
        "audit_target": "audit-2026-10-08",
    },
    "rollback": {
        "failed_deployment_id": "dep-2026-10-07.2",
        "exact_previous_release_id": "rel-2026-10-06.0",
        "trigger": "gate-red",
        "schema_compatibility_hash": "3" * 64,
    },
}

# action_type → approval_type（与产品 _ACTION_APPROVAL_TYPE 封闭映射一致）
_ACTION_TO_APPROVAL = {
    "merge": "merge", "release": "release", "ddl": "ddl",
    "prod-write": "prod_write", "prod_write": "prod_write",
    "fund-auth": "fund_auth", "fund_auth": "fund_auth",
    "rollback": "rollback",
}

# 各 approval_type 的信封 stop_type 默认值（九类之一即可，不参与 action 绑定）
_STOP_TYPE_OF = {
    "merge": "scope", "release": "release", "ddl": "ddl",
    "prod_write": "prod-write", "fund_auth": "fund-auth",
    "rollback": "release",
}


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def _ok(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)


def _expect_raise(
    exc_type: type, fn: Callable[..., Any], *args: Any, **kwargs: Any
) -> Exception:
    """调用 fn，期望抛出 exc_type；返回异常对象供断言细节。"""
    try:
        fn(*args, **kwargs)
    except exc_type as exc:  # type: ignore[misc]
        return exc
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(
        f"expected {exc_type.__name__} to be raised, but call returned")


@contextlib.contextmanager
def _tmp(root: Optional[Path] = None):
    if root is not None:
        yield Path(root)
        return
    own = tempfile.mkdtemp(prefix="ac-act-run-")
    try:
        yield Path(own)
    finally:
        shutil.rmtree(own, ignore_errors=True)


def _fresh(root: Path, db_name: str = "events.db") -> Tuple[EventStore, RunManager]:
    store = EventStore(str(root / db_name))
    return store, RunManager(store, keyring=KEYRING)


def _s1_running_run(mgr: RunManager, task: str) -> Tuple[str, int]:
    """create + 启动 S1 → RUNNING，S1 attempt RUNNING，state_version=2。"""
    run_id = mgr.create_run(task, IDENT)["run_id"]
    mgr.advance_stage(run_id)
    state = mgr.get_run(run_id)
    _ok(state.state == "RUNNING" and state.state_version == 2,
        f"fixture run 应为 RUNNING/v2，got {state.state}/v{state.state_version}")
    return run_id, state.state_version


def _all_pass_run(mgr: RunManager, task: str) -> str:
    """七段全 PASSED → complete_run → SUCCEEDED（技术 PASS 的 context 表达）。"""
    run_id = mgr.create_run(task, IDENT)["run_id"]
    for _ in range(7):
        mgr.advance_stage(run_id, execution_status="COMPLETED",
                          policy_verdict="PASS")
    done = mgr.complete_run(run_id)
    _ok(done["final_state"] == "SUCCEEDED", f"应 SUCCEEDED，got {done}")
    return run_id


def _event_payloads(mgr: RunManager) -> List[Dict[str, Any]]:
    rows = mgr._db._conn.execute(  # noqa: SLF001 —— 测试读事件正源
        "SELECT payload FROM pipeline_events ORDER BY seq ASC").fetchall()
    return [json.loads(r[0]) for r in rows]


def _count_events(mgr: RunManager, event_type: str, run_id: str) -> int:
    return sum(1 for ev in _event_payloads(mgr)
               if ev.get("event_type") == event_type
               and ev.get("run_id") == run_id)


def _assert_zero_action_side(mgr: RunManager, run_id: str, where: str) -> None:
    """授权门拒绝后必须零落账：零审批消费、零 ACTION_* 事件、零 action 聚合。"""
    for etype in ("APPROVAL_CONSUMED", "ACTION_AUTH_RESERVED", "ACTION_STARTED",
                  "ACTION_COMMITTED", "ACTION_FAILED_UNKNOWN"):
        n = _count_events(mgr, etype, run_id)
        _ok(n == 0, f"{where}: {etype} 应为 0，got {n}")
    _ok(not mgr.get_run(run_id).actions, f"{where}: actions 聚合应为空")
    _ok(mgr.broker.consumed_approvals(run_id=run_id) == [],
        f"{where}: 审批消费台账应为空")


def _sign_ap(ap: Dict[str, Any]) -> Dict[str, Any]:
    ap = dict(ap)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(SECRET, ap)
    return ap


def _make_approval(
    run_id: str, task: str, state_version: int, approval_type: str, *,
    stage: str = "S1_REQUIREMENT", nonce: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None, **over: Any,
) -> Dict[str, Any]:
    """action 类 approval-v2 审批（全信封 + fixtures 密钥真 HMAC 签名）。

    over 覆盖项在签名前应用（得到"签名有效但内容不符"的变体）；
    签名后再篡改字段由调用方自行 dict(..., field=...) 得到。
    """
    ap: Dict[str, Any] = {
        "schema_version": "2.0",
        "approval_id": f"apr_actrun_{approval_type}_{os.urandom(4).hex()}",
        "approval_type": approval_type,
        "key_id": KEY_ID,
        "run_id": run_id,
        "task_id": task,
        "stop_event_id": "n/a-action-reserve",
        "stop_type": _STOP_TYPE_OF[approval_type],
        "stage": stage,
        "environment": IDENT["environment"],
        "authorized_scope": IDENT["scope_hash"],
        "policy_hash": IDENT["policy_hash"],
        "ruleset_hash": IDENT["ruleset_hash"],
        "input_watermark": IDENT["commit_sha"],
        "expected_state_version": state_version,
        "actor": "approver-human",
        "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "nonce": nonce or f"nonce-actrun-{approval_type}-{os.urandom(8).hex()}",
        "decision": "approve",
        "signature": "",
        "payload": dict(payload if payload is not None
                        else _PAYLOADS[approval_type]),
    }
    ap.update(over)
    return _sign_ap(ap)


def _make_receipt(
    action: Dict[str, Any], run_id: str, *, watermark: Optional[str] = None,
    outcome: str = "COMMITTED", external_ref: str = "ext-fact-001",
    **over: Any,
) -> Dict[str, Any]:
    """外部正源回执（action-execution-receipt v1.0 + fixtures 密钥 HMAC）。

    action 传 reserve_action 的返回 dict（action_id/action_type/
    action_target 一致性绑定）。over 在签名前应用。
    """
    rc: Dict[str, Any] = {
        "schema_version": "1.0",
        "receipt_type": "action-execution-receipt",
        "action_id": action["action_id"],
        "run_id": run_id,
        "action_type": action["action_type"],
        "action_target": action["action_target"],
        "watermark": watermark if watermark is not None else IDENT["commit_sha"],
        "outcome": outcome,
        "external_ref": external_ref,
        "ts": "2026-10-08T00:00:00Z",
        "key_id": KEY_ID,
        "signature": "",
    }
    rc.update(over)
    rc = dict(rc)
    rc.pop("signature", None)
    rc["signature"] = sign_envelope(SECRET, rc)
    return rc


def _copy_events_to_new_store(src_store: EventStore, dst_path: Path) -> EventStore:
    """仅复制 pipeline_events 到新库（模拟 outbox/事件正源的崩溃恢复）。"""
    dst = EventStore(str(dst_path))
    rows = src_store._conn.execute(  # noqa: SLF001
        "SELECT event_id, payload, prev_event_hash, event_hash, created_at "
        "FROM pipeline_events ORDER BY seq ASC").fetchall()
    dst._conn.execute("BEGIN IMMEDIATE")  # noqa: SLF001
    for row in rows:
        dst._conn.execute(  # noqa: SLF001
            "INSERT INTO pipeline_events (event_id, payload, prev_event_hash, "
            "event_hash, created_at) VALUES (?, ?, ?, ?, ?)", row)
    dst._conn.execute("COMMIT")  # noqa: SLF001
    return dst


# ---------------------------------------------------------------------------
# ACT-01｜注入：technical PASS，但无 exact merge/release action authorization
#         期望：context 可表技术 PASS，controller 不动作
# ---------------------------------------------------------------------------
def test_ACT_01_technical_pass_without_exact_authorization_controller_holds(
        root: Optional[Path] = None) -> None:
    with _tmp(root) as td:
        store, mgr = _fresh(td)

        # -- 注入半边：run 达成 technical PASS（context 侧可表达） --
        run_a = _all_pass_run(mgr, "task_act01_pass")
        state_a = mgr.get_run(run_a)
        _ok(state_a.state == "SUCCEEDED" and state_a.terminal,
            "技术 PASS 必须可表达为 SUCCEEDED 终判（context 可表技术 PASS）")
        # controller 半边：无 exact action authorization → 零动作
        _assert_zero_action_side(mgr, run_a, "technical PASS run")
        # 无授权预留 → ActionError；即使带上合法签发的 merge 审批，
        # 技术 PASS run 已终态——controller 依旧不动作（TerminalRunError）
        target = "repo://erp-main/pr-42"
        exc = _expect_raise(ActionError, mgr.reserve_action, run_a, "merge",
                            target)
        _ok("requires" in str(exc) or "审批" in str(exc),
            f"无授权预留必须拒绝：{exc}")
        good_merge = _make_approval(run_a, "task_act01_pass",
                                    state_a.state_version, "merge")
        _expect_raise(PipelineError, mgr.reserve_action, run_a, "merge",
                      target, good_merge)
        _assert_zero_action_side(mgr, run_a, "terminal reserve attempt 后")

        # -- 同一 run 非终态对照组：technical 绿 ≠ 动作授权，仍需 exact 审批 --
        run_b = _all_pass_run(mgr, "task_act01_live")
        # run_b 已终态；另建一个停在 S1 RUNNING 的活 run 验证 controller 门
        run_c, v_c = _s1_running_run(mgr, "task_act01_live2")
        _expect_raise(ActionError, mgr.reserve_action, run_c, "release",
                      "prod://erp/rel-77")
        _assert_zero_action_side(mgr, run_c, "活 run 无授权预留后")

        # exact authorization 到位后 controller 才动作（精确授权半边，非全面禁止）
        rel_ap = _make_approval(run_c, "task_act01_live2", v_c, "release")
        r = mgr.reserve_action(run_c, "release", "prod://erp/rel-77", rel_ap)
        _ok(r["action_state"] == "RESERVED", "exact 授权预留应成功")
        _ok(_count_events(mgr, "APPROVAL_CONSUMED", run_c) == 1,
            "预留成功应恰消费一次授权")
        _ok(_count_events(mgr, "ACTION_AUTH_RESERVED", run_c) == 1,
            "预留成功应恰落一条 RESERVED 事件")
        # run_a/run_b（technical PASS）始终零动作
        for rid in (run_a, run_b):
            _ok(_count_events(mgr, "APPROVAL_CONSUMED", rid) == 0
                and _count_events(mgr, "ACTION_AUTH_RESERVED", rid) == 0,
                f"technical PASS run {rid} controller 不得动作")


# ---------------------------------------------------------------------------
# ACT-02｜注入：action、method、head/merge-group、artifact/env 任一不符
#         期望：Action Authorization Gate failure，拒绝动作
# ---------------------------------------------------------------------------
def test_ACT_02_any_mismatch_fails_action_authorization_gate(
        root: Optional[Path] = None) -> None:
    with _tmp(root) as td:
        store, mgr = _fresh(td)
        run_id, v = _s1_running_run(mgr, "task_act02")
        target = "repo://erp-main/pr-42"

        # 腿 1（action 不符）：ddl 审批喂 prod-write action → 类型映射拒绝
        wrong_type = _make_approval(run_id, "task_act02", v, "ddl")
        exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run_id,
                            "prod-write", "db://prod/erp#batch-1", wrong_type)
        _ok("approval_type" in str(exc), f"类型不符拒绝：{exc}")

        # 腿 2（action 词表外）：未知 action_type 携带合法 release 审批 → 拒
        rel_ap = _make_approval(run_id, "task_act02", v, "release")
        exc = _expect_raise(ActionError, mgr.reserve_action, run_id, "deploy",
                            "prod://erp/deploy-9", rel_ap)
        _ok("unknown action_type" in str(exc), f"未知 action 拒绝：{exc}")

        # 腿 3（method 不符）：merge 审批签名后篡改 merge_method → HMAC 拒
        tampered_method = dict(_make_approval(run_id, "task_act02", v, "merge"))
        tampered_method["payload"] = dict(tampered_method["payload"],
                                          merge_method="squash")
        exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run_id,
                            "merge", target, tampered_method)
        _ok("signature" in str(exc), f"method 篡改必须验签失败：{exc}")

        # 腿 4（head/merge-group 不符）：水印非本 run head → 绑定拒绝
        wrong_head = _make_approval(run_id, "task_act02", v, "merge",
                                    input_watermark="b" * 40)
        exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run_id,
                            "merge", target, wrong_head)
        _ok("commit_sha" in str(exc) or "input_watermark" in str(exc),
            f"head 不符拒绝：{exc}")
        # 非 40-hex 水印（结构层即拒，不存在跳过比较的旁路）
        bad_shape = _make_approval(run_id, "task_act02", v, "merge",
                                   input_watermark="not-a-sha")
        exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run_id,
                            "merge", target, bad_shape)
        _ok("40-hex" in str(exc), f"水印形状拒绝：{exc}")

        # 腿 5（artifact 不符）：release 审批签名后篡改 artifact_sha256 → HMAC 拒
        tampered_artifact = dict(_make_approval(run_id, "task_act02", v,
                                                "release"))
        tampered_artifact["payload"] = dict(
            tampered_artifact["payload"], artifact_sha256="f" * 64)
        exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run_id,
                            "release", "prod://erp/rel-77", tampered_artifact)
        _ok("signature" in str(exc), f"artifact 篡改必须验签失败：{exc}")

        # 腿 6（env 不符）：签名的 release 审批 environment=production（异环境）→ 拒
        wrong_env = _make_approval(run_id, "task_act02", v, "release",
                                   environment="production")
        exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run_id,
                            "release", "prod://erp/rel-77", wrong_env)
        _ok("environment" in str(exc), f"env 不符拒绝：{exc}")

        # 期望半边：Action Authorization Gate failure —— 全部拒绝且零落账
        _assert_zero_action_side(mgr, run_id, "六条不符注入后")
        _ok(store.verify_chain()["ok"], "拒绝路径不得留任何事件（链完好）")


# ---------------------------------------------------------------------------
# ACT-03｜注入：check 发布前/后 crash 或回执丢失
#         期望：outbox 幂等恢复；同一 check_run 更新，不产生伪双绿
# ---------------------------------------------------------------------------
def test_ACT_03_outbox_idempotent_recovery_no_double_green(
        root: Optional[Path] = None) -> None:
    with _tmp(root) as td:
        store, mgr = _fresh(td)
        run_id, v = _s1_running_run(mgr, "task_act03")
        ap = _make_approval(run_id, "task_act03", v, "release")
        reserved = mgr.reserve_action(run_id, "release", "prod://erp/rel-77", ap)
        aid = reserved["action_id"]
        mgr.start_action(run_id, aid, receipt="publish attempt 1")

        # -- 腿 1（发布后 crash → 事件流恢复）：仅复制事件正源重建管理器，
        #    重放必须还原同一动作面（outbox 幂等恢复），同 nonce 不得二次占位
        recovered_store = _copy_events_to_new_store(
            store, td / f"recovered-{uuid.uuid4().hex[:6]}.db")
        mgr_rc = RunManager(recovered_store, keyring=KEYRING)
        st_rc = mgr_rc.get_run(run_id)
        _ok(st_rc.actions[aid]["action_state"] == "STARTED",
            "崩溃恢复重放应还原 STARTED")
        _ok(st_rc.actions[aid]["receipt_status"] == RECEIPT_PROVISIONAL,
            "恢复重放应还原 PROVISIONAL 分级")
        _ok(st_rc.consumed_nonce_types, "恢复重放应还原授权消费链")
        exc = _expect_raise(ApprovalReuseError, mgr_rc.reserve_action, run_id,
                            "release", "prod://erp/rel-77", ap)
        _ok("不可复用" in str(exc), f"恢复后同授权不得再预留：{exc}")

        # -- 腿 2（at-least-once 重投）：同一 sealed outbox 事件二次 append
        #    → event_id 幂等键命中，零新行、重放不变（不产生第二个绿）
        started_payload = next(
            ev for ev in _event_payloads(mgr)
            if ev.get("event_type") == "ACTION_STARTED")
        before_rows = mgr._db._conn.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
        from wenqu_core.wenqu_pipeline import _PipelineDb  # noqa: E402
        _h2, inserted = _PipelineDb.append_event(
            mgr._db._conn, dict(started_payload))  # noqa: SLF001
        after_rows = mgr._db._conn.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
        _ok(inserted is False, "重复投递同一 outbox 事件必须被幂等忽略")
        _ok(before_rows == after_rows, "幂等忽略不得新增事件行")
        _ok(mgr.get_run(run_id).actions[aid]["action_state"] == "STARTED",
            "重复投递后重放状态不变")

        # -- 腿 3（同一 check/action 更新，不产生伪双绿）：先查询外部事实，
        #    COMMITTED 恰一次；重复 commit / 重复 start 全拒
        good = _make_receipt(reserved, run_id)
        first = mgr.reconcile_receipt(run_id, aid, good)
        again = mgr.reconcile_receipt(run_id, aid, good)
        _ok(first["reconciled"] is True and again["reconciled"] is True,
            "同一回执重复对账幂等（同一 check_run 更新）")
        mgr.commit_action(run_id, aid, good)
        _expect_raise(ActionError, mgr.commit_action, run_id, aid, good)
        _expect_raise(ActionError, mgr.start_action, run_id, aid)
        _ok(_count_events(mgr, "ACTION_COMMITTED", run_id) == 1,
            "ACTION_COMMITTED 必须恰一条（无伪双绿）")
        mgr_after = RunManager(store, keyring=KEYRING)
        st_after = mgr_after.get_run(run_id)
        _ok(st_after.actions[aid]["action_state"] == "COMMITTED"
            and st_after.actions[aid]["receipt_status"] == RECEIPT_RECONCILED,
            "最终重放：恰一次 COMMITTED 且为 RECONCILED 分级")
        _ok(store.verify_chain()["ok"], "outbox 事件链完好")

        # -- 腿 4（发布前 crash 的中间态守卫）：授权消费与 RESERVED 必须同事务
        #    原子成对——伪造"无 APPROVAL_CONSUMED 的 RESERVED"直插事件流，
        #    重放即 Corruption（outbox 恢复不接受断链中间态）
        from wenqu_core.wenqu_pipeline import _seal_event  # noqa: E402
        run2, v2 = _s1_running_run(mgr, "task_act03_guard")
        st2 = mgr.get_run(run2)
        forged = mgr._base_event(  # noqa: SLF001
            "ACTION_AUTH_RESERVED", st2, "COMPLETED", "NOT_EVALUATED",
            actor="attacker", state_version=st2.state_version,
            action_id="act_forge_act03", action_type="merge",
            action_target="repo://erp-main/pr-1",
            approval_id="apr_actrun_merge_forged",
            nonce_digest=hashlib.sha256(b"nonce-forged-act03").hexdigest())
        _PipelineDb.append_event(mgr._db._conn,  # noqa: SLF001
                                 _seal_event(run2, forged))
        _expect_raise(PipelineCorruptionError, mgr.get_run, run2)


# ---------------------------------------------------------------------------
# ACT-04｜注入：merge/release 调用前/后 crash 或回执丢失
#         期望：先查询外部事实；COMMITTED 或 FAILED_UNKNOWN；绝不盲重试
# ---------------------------------------------------------------------------
def test_ACT_04_query_external_fact_committed_or_failed_unknown(
        root: Optional[Path] = None) -> None:
    with _tmp(root) as td:
        store, mgr = _fresh(td)
        run_id, v = _s1_running_run(mgr, "task_act04")

        # -- 动作 1（release）：调用发出后回执丢失 → 先查询外部事实（对账不了）
        #    → FAILED_UNKNOWN 终态；绝不盲重试（nonce 已消费、终态封死）
        ap1 = _make_approval(run_id, "task_act04", v, "release")
        a1 = mgr.reserve_action(run_id, "release", "prod://erp/rel-77", ap1)
        mgr.start_action(run_id, a1["action_id"],
                         receipt="call issued; receipt lost in crash")
        lost = _make_receipt(a1, run_id)          # 从未到达的回执形态
        lost["signature"] = "0" * 64              # 不可验签 → 查询外部事实失败
        rec = mgr.reconcile_receipt(run_id, a1["action_id"], lost)
        _ok(rec["reconciled"] is False,
            "回执丢失/不可验签时查询外部事实必须判对账不了")
        _ok(mgr.get_run(run_id).actions[a1["action_id"]]["action_state"]
            == "STARTED", "对账不了不得篡改动作状态")
        f = mgr.fail_action(run_id, a1["action_id"], "receipt lost after call")
        _ok(f["action_state"] == "FAILED_UNKNOWN",
            "对账不了必须收口 FAILED_UNKNOWN（绝不猜 COMMITTED）")
        # 绝不盲重试：终态后任何推进全拒；同一授权不得重新发起调用
        _expect_raise(ActionError, mgr.start_action, run_id, a1["action_id"])
        _expect_raise(ActionError, mgr.commit_action, run_id, a1["action_id"],
                      _make_receipt(a1, run_id))
        _expect_raise(ActionError, mgr.fail_action, run_id, a1["action_id"])
        exc = _expect_raise(ApprovalReuseError, mgr.reserve_action, run_id,
                            "release", "prod://erp/rel-77", ap1)
        _ok("不可复用" in str(exc), f"同授权重发调用必须拒绝：{exc}")

        # -- 动作 2（merge）：外部事实声明 COMMITTED → 查询通过后恰一次落账
        v_now = mgr.get_run(run_id).state_version
        ap2 = _make_approval(run_id, "task_act04", v_now, "merge")
        a2 = mgr.reserve_action(run_id, "merge", "repo://erp-main/pr-42", ap2)
        mgr.start_action(run_id, a2["action_id"], receipt="merge issued")
        fact2 = _make_receipt(a2, run_id, outcome="COMMITTED",
                              external_ref="gh-merge-42")
        rec2 = mgr.reconcile_receipt(run_id, a2["action_id"], fact2)
        _ok(rec2["reconciled"] is True and rec2["outcome"] == "COMMITTED",
            "外部正源声明 COMMITTED → 先查询后落账")
        c2 = mgr.commit_action(run_id, a2["action_id"], fact2)
        _ok(c2["action_state"] == "COMMITTED"
            and c2["receipt_status"] == RECEIPT_RECONCILED,
            "凭外部事实落 COMMITTED（RECONCILED 分级）")

        # -- 动作 3（ddl）：外部事实声明 FAILED → 不得 COMMITTED，
        #    走 fail_action → FAILED_UNKNOWN
        v_now = mgr.get_run(run_id).state_version
        ap3 = _make_approval(run_id, "task_act04", v_now, "ddl")
        a3 = mgr.reserve_action(run_id, "ddl", "db://staging/erp", ap3)
        mgr.start_action(run_id, a3["action_id"])
        fact3 = _make_receipt(a3, run_id, outcome="FAILED",
                              external_ref="ddl-exec-9")
        exc = _expect_raise(ActionError, mgr.commit_action, run_id,
                            a3["action_id"], fact3)
        _ok("FAILED_UNKNOWN" in str(exc),
            f"外部声明 FAILED 不得 COMMITTED：{exc}")
        _ok(mgr.fail_action(run_id, a3["action_id"])[
                "action_state"] == "FAILED_UNKNOWN", "FAILED → FAILED_UNKNOWN")

        # -- 重放终态面：三动作全部闭口于 {FAILED_UNKNOWN, COMMITTED}，
        #    无悬挂 STARTED/RESERVED（调用后必收口，绝不悬置盲等）
        st = RunManager(store, keyring=KEYRING).get_run(run_id)
        states = {aid_: act["action_state"] for aid_, act in st.actions.items()}
        _ok(states[a1["action_id"]] == "FAILED_UNKNOWN"
            and states[a2["action_id"]] == "COMMITTED"
            and states[a3["action_id"]] == "FAILED_UNKNOWN",
            f"saga 终态面不符：{states}")
        _ok(all(s in ("COMMITTED", "FAILED_UNKNOWN")
                for s in states.values()), f"不得残留非终态动作：{states}")


# ---------------------------------------------------------------------------
# ACT-05｜注入：外部陈旧绿、dispatcher/App 失联
#         期望：direct merge 被角色/ruleset 拒绝；动作保持 BLOCKED
# ---------------------------------------------------------------------------
def test_ACT_05_stale_green_or_dispatcher_loss_keeps_action_blocked(
        root: Optional[Path] = None) -> None:
    with _tmp(root) as td:
        store, mgr = _fresh(td)
        run_id, v = _s1_running_run(mgr, "task_act05")
        ap = _make_approval(run_id, "task_act05", v, "merge")
        reserved = mgr.reserve_action(run_id, "merge",
                                      "repo://erp-main/pr-42", ap)
        aid = reserved["action_id"]
        mgr.start_action(run_id, aid, receipt="merge started; awaiting receipt")

        # -- 腿 1（外部陈旧绿）：旧 SHA 的验签回执 → 拒绝；动作保持 BLOCKED
        stale = _make_receipt(reserved, run_id, watermark="b" * 40,
                              external_ref="gh-merge-OLD")
        exc = _expect_raise(ActionError, mgr.commit_action, run_id, aid, stale)
        _ok("watermark" in str(exc), f"陈旧水印回执必须拒绝：{exc}")
        # 跨 run 移花接木回执 → 同样拒绝
        other_run, _ = _s1_running_run(mgr, "task_act05_other")
        cross = _make_receipt(reserved, other_run)
        exc = _expect_raise(ActionError, mgr.commit_action, run_id, aid, cross)
        _ok("run" in str(exc), f"跨 run 回执必须拒绝：{exc}")

        # -- 腿 2（dispatcher/App 失联，回执不可得）：自报字符串/伪签名回执
        #    全拒——动作停留 STARTED+PROVISIONAL（BLOCKED，不可 COMMITTED）
        _expect_raise(ActionError, mgr.commit_action, run_id, aid,
                      "receipt:self-reported:ok")
        forged = _make_receipt(reserved, run_id)
        forged["signature"] = "0" * 64
        exc = _expect_raise(ActionError, mgr.commit_action, run_id, aid,
                            forged)
        _ok("signature" in str(exc) or "验签" in str(exc),
            f"伪签名回执必须拒绝：{exc}")
        st = mgr.get_run(run_id)
        _ok(st.actions[aid]["action_state"] == "STARTED",
            "失联/陈旧绿下动作必须保持 BLOCKED（STARTED 非终态）")
        _ok(st.actions[aid]["receipt_status"] == RECEIPT_PROVISIONAL,
            "回执分级必须停留 PROVISIONAL，不得自宣 RECONCILED")
        _ok(_count_events(mgr, "ACTION_COMMITTED", run_id) == 0,
            "不得产生任何 COMMITTED 事件（伪绿为零）")

        # -- 腿 3（direct merge 被角色/ruleset 拒绝）：ruleset/policy 不符的
        #    授权在 reserve 门即拒（零动作、零消费）
        run2, v2 = _s1_running_run(mgr, "task_act05_rules")
        bad_ruleset = _make_approval(run2, "task_act05_rules", v2, "merge",
                                     ruleset_hash="rules-EVIL-unapproved")
        exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run2,
                            "merge", "repo://erp-main/pr-43", bad_ruleset)
        _ok("ruleset" in str(exc), f"ruleset 不符必须拒绝：{exc}")
        bad_policy = _make_approval(run2, "task_act05_rules", v2, "merge",
                                    policy_hash="policy-EVIL-unapproved")
        exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run2,
                            "merge", "repo://erp-main/pr-43", bad_policy)
        _ok("policy" in str(exc), f"policy（角色面）不符必须拒绝：{exc}")
        _assert_zero_action_side(mgr, run2, "direct merge 被拒后")
        _ok(store.verify_chain()["ok"], "拒绝路径链完好")


# ---------------------------------------------------------------------------
# ACT-06｜注入：merge/release/DDL/prod-write payload 使用错误 discriminator
#         或缺专属字段
#         期望：schema 拒绝
# ---------------------------------------------------------------------------
def test_ACT_06_wrong_discriminator_or_missing_fields_schema_rejected(
        root: Optional[Path] = None) -> None:
    with _tmp(root) as td:
        store, mgr = _fresh(td)
        run_id, v = _s1_running_run(mgr, "task_act06")

        # (类型, 缺失专属字段, 错误 discriminator 的来源类型)
        matrix = [
            ("merge", "merge_method", "release"),
            ("release", "artifact_sha256", "ddl"),
            ("ddl", "backup_id", "prod_write"),
            ("prod_write", "idempotency_key", "merge"),
        ]
        for approval_type, missing_field, wrong_src in matrix:
            action_type = next(
                at for at, ap_ in _ACTION_TO_APPROVAL.items()
                if ap_ == approval_type and "-" not in at)
            target = f"tgt://{approval_type}/1"

            # 注入 a（缺专属字段）：payload 少一个判别键（签名有效）→ schema 拒
            short_payload = {k: val for k, val in
                             _PAYLOADS[approval_type].items()
                             if k != missing_field}
            ap_missing = _make_approval(run_id, "task_act06", v,
                                        approval_type, payload=short_payload)
            exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run_id,
                                action_type, target, ap_missing)
            _ok("discriminator" in str(exc) and "missing" in str(exc),
                f"{approval_type} 缺 {missing_field} 必须 schema 拒绝：{exc}")

            # 注入 b（错误 discriminator）：把他类 payload 塞进本类型信封
            # （签名有效）→ 键集封闭拒绝
            foreign_payload = dict(_PAYLOADS[wrong_src])
            ap_foreign = _make_approval(run_id, "task_act06", v,
                                        approval_type, payload=foreign_payload)
            exc = _expect_raise(ApprovalRejected, mgr.reserve_action, run_id,
                                action_type, target, ap_foreign)
            _ok("not closed" in str(exc) or "foreign" in str(exc),
                f"{approval_type} 载 {wrong_src} payload 必须键集封闭拒绝：{exc}")

        # 期望半边：四类型 × 两形态共 8 次注入全部 schema 拒绝，零落账
        _assert_zero_action_side(mgr, run_id, "ACT-06 全部注入后")
        _ok(store.verify_chain()["ok"], "schema 拒绝不得产生事件")


# ---------------------------------------------------------------------------
# RUN-01｜注入：被测程序读取 Keychain/SSH agent/生产配置
#         期望：隔离拒绝
# ---------------------------------------------------------------------------
def test_RUN_01_secret_env_channels_isolation_denied(
        root: Optional[Path] = None) -> None:
    with _tmp(root) as td:
        # 伪造敏感通道：SSH agent socket 文件 + 生产配置文件（含哨兵内容）
        agent_sock = td / "agent.sock"
        agent_sock.write_text("FAKE-AGENT-ENDPOINT", encoding="utf-8")
        prod_cfg = td / "prod-secrets.yml"
        prod_cfg.write_text("DB_PASSWORD: sentinel-prod-secret\n",
                            encoding="utf-8")
        out = td / "env-report.json"
        probe_code = (
            "import os, json\n"
            f"report = {{\n"
            f"  'env_keys': sorted(os.environ.keys()),\n"
            f"  'ssh_agent_sock': os.environ.get('SSH_AUTH_SOCK'),\n"
            f"  'prod_config_path': os.environ.get('WQ_PROD_CONFIG'),\n"
            f"  'prod_config_content': (lambda p: open(p).read()\n"
            f"      if p and os.path.exists(p) else 'NOT-REACHABLE')(\n"
            f"          os.environ.get('WQ_PROD_CONFIG')),\n"
            f"}}\n"
            f"open({str(out)!r}, 'w').write(json.dumps(report))\n"
        )
        old_ssh = os.environ.get("SSH_AUTH_SOCK")
        old_cfg = os.environ.get("WQ_PROD_CONFIG")
        os.environ["SSH_AUTH_SOCK"] = str(agent_sock)
        os.environ["WQ_PROD_CONFIG"] = str(prod_cfg)
        try:
            ev = TrustedRunner().run([sys.executable, "-c", probe_code])
            _ok(ev.actual_exit_code == 0 and not ev.timed_out,
                f"探针应正常执行：exit={ev.actual_exit_code}")
            report = json.loads(out.read_text(encoding="utf-8"))
            keys = set(report["env_keys"])
            # 期望：隔离拒绝——敏感环境通道在子进程中不存在，配置不可达
            _ok("SSH_AUTH_SOCK" not in keys,
                "SSH agent 通道变量必须被白名单剥除（隔离拒绝）")
            _ok("WQ_PROD_CONFIG" not in keys,
                "生产配置路径变量必须被白名单剥除（隔离拒绝）")
            _ok(report["ssh_agent_sock"] is None,
                "子进程不得看到 SSH agent socket 路径")
            _ok(report["prod_config_path"] is None,
                "子进程不得看到生产配置路径")
            _ok(report["prod_config_content"] == "NOT-REACHABLE",
                "生产配置内容必须不可达（哨兵内容零泄露）")
            _ok("sentinel-prod-secret" not in json.dumps(report),
                "哨兵秘密不得经任何路径进入子进程观测面")
            # 控制腿：白名单基础变量仍在（隔离≠破坏正常执行）
            _ok({"PATH", "HOME"} <= keys, f"白名单基础变量应保留：{keys}")
            _ok(RUN_TOKEN_ENV in keys, "内部 run token 哨兵应在位（扫杀锚点）")
        finally:
            if old_ssh is None:
                os.environ.pop("SSH_AUTH_SOCK", None)
            else:
                os.environ["SSH_AUTH_SOCK"] = old_ssh
            if old_cfg is None:
                os.environ.pop("WQ_PROD_CONFIG", None)
            else:
                os.environ["WQ_PROD_CONFIG"] = old_cfg


# ---------------------------------------------------------------------------
# RUN-02｜注入：timeout 后子孙进程
#         期望：全部终止，无孤儿写盘
# ---------------------------------------------------------------------------
_RUN02_ATTACK = """import os, time
DIR = {dir!r}
def delayed(path):
    time.sleep(3)
    with open(path, 'w') as fh:
        fh.write('orphan survived')

# 形态1：同进程组子进程（killpg 目标面）
p1 = os.fork()
if p1 == 0:
    delayed(DIR + '/M_GROUP_CHILD'); os._exit(0)
# 形态2：setsid 逃逸进程组 + 中间父退出 → 孙进程被收养（进程树快照漏）
p2 = os.fork()
if p2 == 0:
    os.setsid()
    g = os.fork()
    if g == 0:
        delayed(DIR + '/M_SETSID_GRANDCHILD'); os._exit(0)
    os._exit(0)
# 形态3：setsid + double-fork daemon → 被 PID 1 收养（token 扫杀目标面）
p3 = os.fork()
if p3 == 0:
    os.setsid()
    d = os.fork()
    if d == 0:
        delayed(DIR + '/M_DAEMON')
        time.sleep(30); os._exit(0)
    os._exit(0)
time.sleep(60)
"""


def _kill_survivors(script_path: Path) -> None:
    """失败兜底：清掉仍引用攻击脚本的进程，避免污染宿主机。"""
    import signal
    try:
        proc = subprocess.run(["ps", "-axo", "pid=,command="],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return
    for line in proc.stdout.splitlines():
        if str(script_path) in line:
            pid = line.split()[0]
            if pid.isdigit() and int(pid) != os.getpid():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass


def test_RUN_02_timeout_kills_all_descendants_no_orphan_writes(
        root: Optional[Path] = None) -> None:
    with _tmp(root) as td:
        script = td / f"attack_{uuid.uuid4().hex[:8]}.py"
        script.write_text(_RUN02_ATTACK.format(dir=str(td)),
                          encoding="utf-8")
        markers = [td / "M_GROUP_CHILD", td / "M_SETSID_GRANDCHILD",
                   td / "M_DAEMON"]
        try:
            ev = TrustedRunner(timeout=1.0).run([sys.executable, str(script)])
            _ok(ev.timed_out is True, "超时必须被如实记录（证据不丢）")
            _ok(ev.actual_exit_code is None,
                f"超时证据的退出码应为 None：{ev}")
            time.sleep(3.6)  # 覆盖三个孙进程 t+3s 的写盘窗口
            survived = [m.name for m in markers if m.exists()]
            _ok(not survived, f"孤儿写盘被实锤：{survived}")
            # 全部终止：不得残留任何引用攻击脚本的进程
            proc = subprocess.run(["ps", "-axo", "pid=,command="],
                                  capture_output=True, text=True, timeout=10)
            leftovers = [ln.strip() for ln in proc.stdout.splitlines()
                         if str(script) in ln]
            _ok(not leftovers, f"存活的子孙进程：{leftovers}")
        finally:
            _kill_survivors(script)


# ---------------------------------------------------------------------------
# RUN-03｜注入：fork bomb/输出爆量/网络外连
#         期望：配额/allowlist 阻断
# ---------------------------------------------------------------------------
def test_RUN_03_fork_bomb_blast_network_blocked_by_allowlist(
        root: Optional[Path] = None) -> None:
    with _tmp(root) as td:
        runner = TrustedRunner(allowlist=["/bin/echo"])

        def _blocked(name: str, argv: List[str], marker: Path) -> None:
            exc = _expect_raise(PermissionError, runner.run, argv)
            expected_msg = f"executable not in allowlist: {argv[0]!r}"
            _ok(str(exc) == expected_msg,
                f"{name} 阻断消息不符：{exc!r} != {expected_msg!r}")
            _ok(not marker.exists(),
                f"{name} 载荷必须零执行（marker 不得落盘）")

        # 注入 a（fork bomb 形态）：受限 fork 循环载荷——allowlist 未列名
        # python → 前置阻断，零进程产生
        m_bomb = td / "BOMB_RAN"
        bomb_code = (
            f"open({str(m_bomb)!r}, 'w').write('boom')\n"
            "import os, time\n"
            "for _ in range(5):\n"
            "    if os.fork() == 0:\n"
            "        time.sleep(30); os._exit(0)\n"
            "time.sleep(30)\n"
        )
        _blocked("fork bomb", [sys.executable, "-c", bomb_code], m_bomb)

        # 注入 b（输出爆量形态）：stdout 灌爆载荷——同样被 allowlist 阻断
        m_blast = td / "BLAST_RAN"
        blast_code = (
            f"open({str(m_blast)!r}, 'w').write('blast')\n"
            "import sys\n"
            "for _ in range(1024):\n"
            "    sys.stdout.write('A' * 1048576)\n"
        )
        _blocked("输出爆量", [sys.executable, "-c", blast_code], m_blast)

        # 注入 c（网络外连形态）：urllib 外传载荷——allowlist 阻断于执行前
        m_net = td / "NET_RAN"
        net_code = (
            f"open({str(m_net)!r}, 'w').write('dial')\n"
            "import urllib.request\n"
            "urllib.request.urlopen('http://127.0.0.1:1/exfil')\n"
        )
        _blocked("网络外连", [sys.executable, "-c", net_code], m_net)

        # 注入 d（外部二进制形态）：仓外网络工具不在 allowlist → 阻断
        curl = shutil.which("curl")
        if curl is not None:
            m_bin = td / "CURL_RAN"
            _blocked("外部网络二进制", [curl, "http://127.0.0.1:1/"],
                     m_bin)

        # 控制腿：allowlist 内的合法执行不受影响（阻断≠全禁）
        ev = runner.run(["/bin/echo", "allowlist-ok"])
        _ok(ev.actual_exit_code == 0 and not ev.timed_out,
            f"allowlist 内执行应正常：{ev}")


# ---------------------------------------------------------------------------
# 未实现注入子面登记（诚实边界；不硬凑、不 xfail）
# ---------------------------------------------------------------------------
BOUNDARIES: Dict[str, str] = {
    "RUN-01": (
        "容器级隔离未实现：macOS Keychain 直读、SSH agent Unix socket 直连、"
        "任意路径生产配置文件读不在 TrustedRunner 防线内（全仓无 sandboxexec/"
        "seatbelt/文件系统边界语义）；已实现半边=env 白名单剥除——进程环境通道"
        "（SSH_AUTH_SOCK/配置路径变量）在子进程中不存在，隔离拒绝以该腿验证"),
    "RUN-03": (
        "输出爆量字节配额（stdout 上限截断）与网络 egress allowlist 无产品实现"
        "（TrustedRunner 只有可执行 allowlist opt-in 与超时击杀）；三条注入形态"
        "均经验证的事实是：allowlist 未列名可执行一律 PermissionError 前置阻断、"
        "零进程产生——『配额阻断』仅此腿成立"),
    "ACT-03": (
        "真实 GitHub check_run 发布 outbox（CI check 发布通道）不在本仓被测体"
        "（无 GitHub API client）；本地等价=ActionSaga control_outbox 事件幂等"
        "（event_id INSERT OR IGNORE）+ APPROVAL_CONSUMED/ACTION_AUTH_RESERVED "
        "同事务原子 + 重放授权消费链守卫"),
    "ACT-05": (
        "dispatcher/App 失联检测（heartbeat/熔断）无独立实现；本地等价=回执"
        "不可得时动作停留 STARTED/PROVISIONAL 不可 COMMITTED（BLOCKED），"
        "陈旧水印/跨 run/伪签名回执全部拒绝"),
}


# ---------------------------------------------------------------------------
# 运行器
# ---------------------------------------------------------------------------
_TEST_NAME_RE = re.compile(r"^test_(ACT|RUN)_(\d{2})_")


def _collect_tests() -> List[Tuple[str, Callable[..., None]]]:
    return [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
        and _TEST_NAME_RE.match(name) is not None
    ]


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    json_out: Optional[str] = None
    if "--json" in argv:
        json_out = argv[argv.index("--json") + 1]
    tests = _collect_tests()
    print("=" * 72)
    print("§20 ACT/RUN 族专属验收测试（实现 9 条：ACT-01~06 + RUN-01~03）")
    for tid, reason in BOUNDARIES.items():
        print(f"  BOUNDARY {tid}: {reason}")
    print("-" * 72)
    records: List[Dict[str, Any]] = []
    failed: List[str] = []
    for name, fn in tests:
        match = _TEST_NAME_RE.match(name)
        assert match is not None
        test_id = f"{match.group(1)}-{match.group(2)}"
        with tempfile.TemporaryDirectory(prefix="ac-act-run-") as td:
            try:
                fn(Path(td))
                rec = {"id": test_id, "test": name, "passed": True}
                if test_id in BOUNDARIES:
                    rec["boundaries"] = BOUNDARIES[test_id]
                records.append(rec)
                print(f"  PASS {test_id}  {name}")
            except Exception as exc:  # noqa: BLE001
                failed.append(name)
                rec = {"id": test_id, "test": name, "passed": False,
                       "error": f"{type(exc).__name__}: {exc}"}
                if test_id in BOUNDARIES:
                    rec["boundaries"] = BOUNDARIES[test_id]
                records.append(rec)
                print(f"  FAIL {test_id}  {name}: {type(exc).__name__}: {exc}")
    print("-" * 72)
    print(f"结果: {len(records) - len(failed)}/{len(records)} passed"
          f"{'' if not failed else '；失败: ' + ', '.join(failed)}")
    out_path = Path(json_out) if json_out else ARTIFACT_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"逐 ID 结果已写: {out_path}")
    print("=" * 72)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

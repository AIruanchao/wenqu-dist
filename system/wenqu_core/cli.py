#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wenquctl——P0-2 七段管线 CLI（P0-1 残余接线：命令行直通 RunManager/Broker）。

子命令（全部实际调用 wenqu_core.wenqu_pipeline 的 RunManager/ApprovalBroker，
无旁路、无第二实现）：
  create         创建七段 run（身份五要素必填：commit/environment/scope/policy/ruleset）
  advance        推进当前段（不带 outcome=启动 attempt；带双轴 outcome=完成）
  status         只读快照（重放推导）
  raise-waiting  触发九类停等之一
  resume         消费一次性 resume 审批恢复 WAITING（审批 JSON+前置条件 JSON）
  authorize-risk 消费一次性 risk 授权（审批 JSON）
  complete       终态判定（SUCCEEDED/COMPLETED_CONDITIONAL/FAILED）
  register-finding 在 run 登记面登记 finding（CONDITIONAL 完成核验基础）
  gate           聚合 station-result-v2 结果为整线 gate 判定（F4-GATE-001：
                 GateAggregator 的第一个生产消费者；F6-GATE-SCOPE-001：正门
                 须 --manifest <run-manifest.json>（required/分母取冻结值逐站
                 对账），无 manifest 裸调用默认拒绝、仅诊断可显式
                 --allow-self-declared；R7-GATE-MANIFEST-AUTH-001：--manifest
                 正门必须 --verify-key <keyring> 验签（HMAC-SHA256 签名——
                 无签名/验签失败/key 未知或已吊销一律 ERROR），无签名 manifest
                 仅诊断可显式 --allow-unsigned，顶层与 planner 不一致
                 （required/TTL/scope/分母）一律 BLOCKED；退出码
                 PASS=0/FAIL=1/BLOCKED=2/ERROR=3）

审批 JSON 即 approval-v2 信封（含 key_id + HMAC-SHA256 签名）——签发侧用
wenqu_core.approval_keys.sign_envelope 生成；CLI 只消费不签发（权限分离）。
密钥登记经 --keys 或 WENQU_APPROVAL_KEYRING 指向 keyring 目录/JSON 文件。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Set

_SYS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SYS_DIR not in sys.path:
    sys.path.insert(0, _SYS_DIR)

from wenqu_core.approval_keys import ApprovalKeyring  # noqa: E402
from wenqu_core.approval_issue import (  # noqa: E402
    APPROVAL_SOURCES, HIGH_RISK_APPROVAL_TYPES, ApprovalIssuer,
    IssuanceError, TwoPersonRuleError, issue_from_preconditions_payload,
    reconcile_issuance,
)
from wenqu_core.approval_keys import (  # noqa: E402
    KeyNotFoundError, KeyStateError, append_keyring_event,
    ensure_keyring_dir, generate_secret, save_key_meta, write_key_to_dir,
)
from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    ManifestFreezeError, RunManifest, validate_manifest_consistency,
)
from wenqu_core.gate_aggregator import (  # noqa: E402
    BLOCKED, GateAggregator, mirror_validate_station_result_v2,
)
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ENVIRONMENTS, STAGES, STOP_PRECONDITION_SPECS, ApprovalBroker,
    ApprovalError, PipelineError, RunManager, _APPROVAL_TYPES,
)


def _load_keyring(path: Optional[str]) -> Optional[ApprovalKeyring]:
    explicit = path or os.environ.get("WENQU_APPROVAL_KEYRING", "").strip()
    if not explicit:
        return None
    try:
        return ApprovalKeyring.from_path(explicit)
    except (OSError, ValueError) as exc:
        print(f"wenquctl: keyring 加载失败: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


def _open_manager(db_path: str,
                  keyring: Optional[ApprovalKeyring]) -> RunManager:
    store = EventStore(db_path)
    return RunManager(store, keyring=keyring)


def _read_json_file(path: str, what: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"wenquctl: {what} 文件不可读/非 JSON ({path}): {exc}",
              file=sys.stderr)
        raise SystemExit(2) from None


# ---------------------------------------------------------------------- #
def cmd_create(args: argparse.Namespace) -> int:
    keyring = _load_keyring(args.keys)
    mgr = _open_manager(args.db, keyring)
    try:
        result = mgr.create_run(
            args.task,
            {
                "commit_sha": args.commit_sha,
                "environment": args.environment,
                "scope_hash": args.scope_hash,
                "policy_hash": args.policy_hash,
                "ruleset_hash": args.ruleset_hash,
                **({"repo_id": args.repo_id} if args.repo_id else {}),
            },
            actor=args.actor,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        mgr.close()


def cmd_advance(args: argparse.Namespace) -> int:
    if (args.execution_status is None) != (args.policy_verdict is None):
        print("wenquctl: --execution-status 与 --policy-verdict 必须成对提供",
              file=sys.stderr)
        return 2
    keyring = _load_keyring(args.keys)
    mgr = _open_manager(args.db, keyring)
    try:
        findings: List[str] = list(args.finding or [])
        result = mgr.advance_stage(
            args.run,
            execution_status=args.execution_status,
            policy_verdict=args.policy_verdict,
            evidence_refs=list(args.evidence or []),
            findings=findings,
            actor=args.actor,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        mgr.close()


def cmd_status(args: argparse.Namespace) -> int:
    keyring = _load_keyring(args.keys)
    mgr = _open_manager(args.db, keyring)
    try:
        st = mgr.get_run(args.run)
        out: Dict[str, Any] = {
            "run_id": st.run_id, "task_id": st.task_id, "state": st.state,
            "state_version": st.state_version,
            "terminal": st.terminal,
            "stages": st.stage_statuses(),
            "identity": st.identity,
            "findings": {fid: {"severity": f["severity"],
                               "priority": f["priority"],
                               "fingerprint": f["fingerprint"]}
                         for fid, f in st.findings.items()},
            "consumed_nonce_count": len(st.consumed_nonce_digests),
            "risk_authorizations": st.risk_authorizations,
            "actions": st.actions,
        }
        if st.waiting is not None:
            out["waiting"] = {
                "stop_type": st.waiting.stop_type,
                "stop_event_id": st.waiting.stop_event_id,
                "stage": st.waiting.stage, "reason": st.waiting.reason,
                "required_preconditions":
                    list(st.waiting.required_preconditions),
            }
        print(json.dumps(out, ensure_ascii=False))
        return 0
    finally:
        mgr.close()


def cmd_raise_waiting(args: argparse.Namespace) -> int:
    keyring = _load_keyring(args.keys)
    mgr = _open_manager(args.db, keyring)
    try:
        result = mgr.raise_waiting(args.run, args.stop_type, args.reason,
                                   actor=args.actor)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        mgr.close()


def cmd_resume(args: argparse.Namespace) -> int:
    approval = _read_json_file(args.approval, "approval")
    preconditions = _read_json_file(args.preconditions, "preconditions")
    keyring = _load_keyring(args.keys)
    mgr = _open_manager(args.db, keyring)
    try:
        result = mgr.resume_waiting(args.run, approval, preconditions,
                                    actor=args.actor)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        mgr.close()


def cmd_authorize_risk(args: argparse.Namespace) -> int:
    approval = _read_json_file(args.approval, "approval")
    keyring = _load_keyring(args.keys)
    mgr = _open_manager(args.db, keyring)
    try:
        result = mgr.authorize_risk(args.run, approval)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        mgr.close()


def cmd_complete(args: argparse.Namespace) -> int:
    keyring = _load_keyring(args.keys)
    mgr = _open_manager(args.db, keyring)
    try:
        result = mgr.complete_run(args.run, risk_approval_id=args.risk_approval_id,
                                  reason=args.reason, actor=args.actor)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        mgr.close()


def cmd_register_finding(args: argparse.Namespace) -> int:
    keyring = _load_keyring(args.keys)
    mgr = _open_manager(args.db, keyring)
    try:
        result = mgr.register_finding(args.run, args.finding_id,
                                      args.fingerprint, args.severity,
                                      args.priority, detail=args.detail,
                                      actor=args.actor)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        mgr.close()


# ---------------------------------------------------------------------- #
# P0-2 残余（审批签发端）：approve / keys 子命令
# 架构裁定（超哥授权默认案）：本地 keyring + CLI 签发，飞书留接口。
# ---------------------------------------------------------------------- #

def _resolve_keyring_path(args: argparse.Namespace) -> str:
    """approve/keys 共用：--keyring 显式 > WENQU_APPROVAL_KEYRING。"""
    path = (getattr(args, "keyring", None)
            or os.environ.get("WENQU_APPROVAL_KEYRING", "").strip())
    if not path:
        print("wenquctl: 必须 --keyring 或设 WENQU_APPROVAL_KEYRING"
              "（审批签发 keyring 目录/JSON 文件）", file=sys.stderr)
        raise SystemExit(2)
    return path


def _resolve_audit_path(args: argparse.Namespace, keyring_path: str) -> str:
    """签发审计账本路径：--audit > WENQU_APPROVAL_AUDIT > 目录型 keyring 内
    ``issuance-audit.jsonl``；JSON 文件型 keyring 无缺省——必须显式给。"""
    explicit = (getattr(args, "audit", None)
                or os.environ.get("WENQU_APPROVAL_AUDIT", "").strip())
    if explicit:
        return explicit
    if os.path.isdir(keyring_path):
        return os.path.join(keyring_path, "issuance-audit.jsonl")
    if not os.path.exists(keyring_path):
        print(f"wenquctl: keyring 路径不存在: {keyring_path!r}", file=sys.stderr)
        raise SystemExit(2)
    print("wenquctl: JSON 文件型 keyring 无法推导演发审计账本路径——"
          "必须 --audit（或 WENQU_APPROVAL_AUDIT）", file=sys.stderr)
    raise SystemExit(2)


def cmd_approve(args: argparse.Namespace) -> int:
    """approve 子命令——审批签发端（P0-2 残余）。

    两种模式：
    - 签发（默认）：构造 approval-v2 信封 → HMAC 签名（高危类型双人联签）
      → 双签名自验 + 结构预检 → 送达（--source，feishu 为占位接口）
      → 落 append-only 签发审计 → 信封写 --out（0600，含 nonce 凭据）。
    - 对账（--reconcile-db）：签发审计 × EventStore APPROVAL_CONSUMED
      双向对账（批了 vs 用了 vs 未用过期），打印报告；账本不一致 exit 1。
    """
    keyring_path = _resolve_keyring_path(args)

    if args.reconcile_db:
        audit_path = _resolve_audit_path(args, keyring_path)
        try:
            report = reconcile_issuance(audit_path, args.reconcile_db)
        except (OSError, ValueError) as exc:
            print(f"wenquctl: 对账失败: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 1

    if not args.out:
        print("wenquctl: 签发模式必须 --out（审批信封输出文件）",
              file=sys.stderr)
        return 2
    required_issue_args = (
        ("approval_type", "--approval-type"), ("run", "--run"),
        ("task", "--task"), ("stage", "--stage"),
        ("environment", "--environment"), ("scope", "--scope"),
        ("policy_hash", "--policy-hash"), ("ruleset_hash", "--ruleset-hash"),
        ("watermark", "--watermark"), ("state_version", "--state-version"),
        ("actor", "--actor"),
    )
    missing_args = [flag for attr, flag in required_issue_args
                    if getattr(args, attr) is None]
    if missing_args:
        print(f"wenquctl: 签发模式缺少必填参数: {' '.join(missing_args)}",
              file=sys.stderr)
        return 2

    # ---- 签发模式 ----
    try:
        keyring = ApprovalKeyring.from_path(keyring_path)
    except (OSError, ValueError) as exc:
        print(f"wenquctl: keyring 加载失败: {exc}", file=sys.stderr)
        return 2
    audit_path = _resolve_audit_path(args, keyring_path)

    # payload：--payload（全量 JSON，判别封闭由签发器终审）或
    # --preconditions（resume 专用——自动算 objective_precondition_hash）
    if (args.payload is None) == (args.preconditions is None):
        print("wenquctl: --payload 与 --preconditions 必须二选一"
              "（payload 全量 JSON / resume 前置条件 JSON）", file=sys.stderr)
        return 2
    if args.preconditions is not None:
        if args.approval_type != "resume":
            print("wenquctl: --preconditions 仅用于 resume 类型"
                  "（其余类型给 --payload）", file=sys.stderr)
            return 2
        if not args.stop_type or not args.stop_event_id:
            print("wenquctl: resume 类型必须显式 --stop-type 与 "
                  "--stop-event-id（锚定真实停等）", file=sys.stderr)
            return 2
        pre = _read_json_file(args.preconditions, "preconditions")
        payload = issue_from_preconditions_payload(
            args.stop_event_id, args.stop_type, pre)
    else:
        payload = _read_json_file(args.payload, "payload")

    source = APPROVAL_SOURCES[args.source]()
    issuer = ApprovalIssuer(keyring, audit_path, source=source)
    try:
        result = issuer.issue(
            actor=args.actor,
            approval_type=args.approval_type,
            run_id=args.run,
            task_id=args.task,
            stage=args.stage,
            environment=args.environment,
            authorized_scope=args.scope,
            policy_hash=args.policy_hash,
            ruleset_hash=args.ruleset_hash,
            input_watermark=args.watermark,
            expected_state_version=args.state_version,
            payload=payload,
            stop_type=args.stop_type,
            stop_event_id=args.stop_event_id,
            decision=args.decision,
            key_id=args.key_id,
            ttl_seconds=args.ttl,
            confirm_two_persons=args.confirm_two_persons,
            second_key_id=args.second_key_id,
            second_actor=args.second_actor,
        )
    except (IssuanceError, KeyStateError, KeyNotFoundError) as exc:
        print(f"wenquctl: 签发被拒: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 1
    except NotImplementedError as exc:
        # 飞书审批流占位接口（架构裁定：本地签发为默认案）
        print(f"wenquctl: 审批来源 {args.source!r} 未接线: {exc}",
              file=sys.stderr)
        return 2

    envelope = result["approval"]
    # 信封含 nonce（消费凭据）——0600 落盘，不回显到会话
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.chmod(args.out, 0o600)
    receipt = {
        "issued": True,
        "approval_id": envelope["approval_id"],
        "approval_type": envelope["approval_type"],
        "key_id": envelope["key_id"],
        "actor": envelope["actor"],
        "issued_at": envelope["issued_at"],
        "expires_at": envelope["expires_at"],
        "ttl_seconds": args.ttl,
        "high_risk": envelope["approval_type"] in HIGH_RISK_APPROVAL_TYPES,
        "two_person": result["co_signature"] is not None,
        "second_key_id": (result["co_signature"] or {}).get("second_key_id"),
        "source": args.source,
        "approval_file": args.out,
        "audit_path": audit_path,
        "nonce_digest": result["audit_record"]["nonce_digest"],
    }
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    if args.print_envelope:
        print(json.dumps(envelope, ensure_ascii=False, indent=2))
    return 0


def _managed_keyring_dir(args: argparse.Namespace) -> str:
    """keys create/rotate/revoke 的受管 keyring 目录（目录型，0700）。"""
    path = _resolve_keyring_path(args)
    if os.path.exists(path) and not os.path.isdir(path):
        print(f"wenquctl: keys 写操作需要目录型 keyring（{path!r} 是文件——"
              "受管生命周期（rotate/revoke 元数据）只支持目录）",
              file=sys.stderr)
        raise SystemExit(2)
    ensure_keyring_dir(path)
    return path


def _keyring_event(keyring_dir: str, record_type: str,
                   **fields: Any) -> None:
    import time as _time
    append_keyring_event(
        os.path.join(keyring_dir, "keyring-events.jsonl"),
        {"record_type": record_type,
         "ts": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
         **fields})


def cmd_keys(args: argparse.Namespace) -> int:
    """keys 子命令——签发密钥生命周期（create/rotate/revoke/list）。

    红线：任何输出都不回显 secret 明文（create/rotate 生成后只报 key_id
    与元数据）；secret 文件 0600、目录 0700；事件账本 append-only。
    """
    command = args.keys_command
    if command == "list":
        path = _resolve_keyring_path(args)
        try:
            keyring = ApprovalKeyring.from_path(path)
        except (OSError, ValueError) as exc:
            print(f"wenquctl: keyring 加载失败: {exc}", file=sys.stderr)
            return 2
        keys = []
        for key_id in keyring.key_ids():
            meta = keyring.meta(key_id)
            keys.append({
                "key_id": key_id,
                "status": meta.get("status"),
                "can_sign": keyring.can_sign(key_id),
                "created_at": meta.get("created_at"),
                "rotated_at": meta.get("rotated_at"),
                "rotated_to": meta.get("rotated_to"),
                "revoked_at": meta.get("revoked_at"),
                "expiry": meta.get("expiry"),
                "description": meta.get("description"),
            })
        print(json.dumps({"keyring": path, "count": len(keys),
                          "keys": keys}, ensure_ascii=False, indent=2))
        return 0

    keyring_dir = _managed_keyring_dir(args)
    existing = ApprovalKeyring.from_path(keyring_dir)
    import time as _time
    now_iso = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())

    if command == "create":
        key_id = args.key_id or f"key_{uuid.uuid4().hex[:8]}"
        if existing.has(key_id):
            print(f"wenquctl: key_id {key_id!r} 已存在（keyring 不覆盖——"
                  "轮换用 keys rotate）", file=sys.stderr)
            return 1
        meta: Dict[str, Any] = {"status": "active"}
        if args.expiry:
            meta["expiry"] = args.expiry
            try:
                ApprovalKeyring._normalize_meta(key_id, meta)  # noqa: SLF001
            except ValueError as exc:
                print(f"wenquctl: {exc}", file=sys.stderr)
                return 2
        if args.description:
            meta["description"] = args.description
        secret = generate_secret()
        write_key_to_dir(keyring_dir, key_id, secret, meta)
        _keyring_event(keyring_dir, "KEY_CREATED", key_id=key_id,
                       actor=args.actor, expiry=meta.get("expiry"))
        # 绝不打印 secret；只报 key_id 与元数据
        print(json.dumps({"created": True, "key_id": key_id,
                          "status": "active", "expiry": meta.get("expiry"),
                          "keyring": keyring_dir}, ensure_ascii=False))
        return 0

    if command == "rotate":
        old_id = args.key_id
        if not existing.has(old_id):
            print(f"wenquctl: key_id {old_id!r} 不存在", file=sys.stderr)
            return 1
        old_meta = existing.meta(old_id)
        if old_meta.get("status") != "active":
            print(f"wenquctl: key_id {old_id!r} 状态为 "
                  f"{old_meta.get('status')!r}——只有 active key 可轮换",
                  file=sys.stderr)
            return 1
        new_id = args.new_key_id or f"key_{uuid.uuid4().hex[:8]}"
        if existing.has(new_id) or new_id == old_id:
            print(f"wenquctl: 新 key_id {new_id!r} 不可用（已存在/与旧同）",
                  file=sys.stderr)
            return 1
        # 顺序（失败安全向）：先立新 key（active）→ 再把旧 key 标 rotated。
        # 中断只会留下「双 active」（签发面稍宽，可重跑收敛），
        # 绝不出现「无 active key」或「用已轮换 key 签发」。
        write_key_to_dir(keyring_dir, new_id, generate_secret(),
                         {"status": "active",
                          "description": f"rotated from {old_id}"})
        save_key_meta(keyring_dir, old_id, {
            **old_meta, "status": "rotated", "rotated_at": now_iso,
            "rotated_to": new_id})
        _keyring_event(keyring_dir, "KEY_ROTATED", key_id=old_id,
                       rotated_to=new_id, actor=args.actor)
        print(json.dumps({"rotated": True, "old_key_id": old_id,
                          "old_status": "rotated", "rotated_at": now_iso,
                          "new_key_id": new_id, "new_status": "active",
                          "note": "旧 key 可验存量签名；新签发用新 key",
                          "keyring": keyring_dir}, ensure_ascii=False))
        return 0

    if command == "revoke":
        key_id = args.key_id
        if not existing.has(key_id):
            print(f"wenquctl: key_id {key_id!r} 不存在", file=sys.stderr)
            return 1
        meta = existing.meta(key_id)
        if meta.get("status") == "revoked":
            print(f"wenquctl: key_id {key_id!r} 已是 revoked（幂等拒绝）",
                  file=sys.stderr)
            return 1
        save_key_meta(keyring_dir, key_id, {
            **meta, "status": "revoked", "revoked_at": now_iso})
        _keyring_event(keyring_dir, "KEY_REVOKED", key_id=key_id,
                       actor=args.actor)
        print(json.dumps({"revoked": True, "key_id": key_id,
                          "revoked_at": now_iso,
                          "effect": "该 key 验签即拒（fail-closed），"
                                    "拒绝事件记入 keyring-events.jsonl",
                          "keyring": keyring_dir}, ensure_ascii=False))
        return 0

    print(f"wenquctl: 未知 keys 子命令 {command!r}", file=sys.stderr)
    return 2



# ---------------------------------------------------------------------- #
def _gate_exit_code(outcome: str) -> int:
    """aggregate_outcome -> CLI 退出码（F4-GATE-001 契约）。

    PASS=0；CONDITIONAL=1（软条件项绝不上绿、需人工处置，映射 GitHub
    failure/action_required）；BLOCKED=2（证据残缺/分母缩水/绑定失败——
    fail-closed）；其余（不应出现）一律 2 不放水。
    """
    return {"PASS": 0, "CONDITIONAL": 1, "BLOCKED": 2}.get(outcome, 2)


def _gate_error_json(reason: str, **extra: Any) -> int:
    """ERROR(3) 路径：gate 工具自身无法执行（输入不可读/无法绑定身份）。

    仍打印一个 aggregate 形状的 JSON（policy_verdict=ERROR）供脚本消费，
    退出码固定 3——与证据性 BLOCKED(2) 严格区分。
    """
    payload: Dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy_verdict": "ERROR",
        "aggregate_outcome": "ERROR",
        "technical_eligible": False,
        "reason": reason,
        "reasons": [reason],
    }
    payload.update(extra)
    print(f"wenquctl: gate ERROR: {reason}", file=sys.stderr)
    print(json.dumps(payload, ensure_ascii=False))
    return 3


def cmd_gate(args: argparse.Namespace) -> int:
    """gate 子命令——读入 station-result-v2 JSON，聚合为整线 gate 判定。

    正门路径（F6-GATE-SCOPE-001，P0 根修）：--manifest <run-manifest.json>
    （bugscan_orchestrator.freeze_run_manifest 冻结产物，manifest_hash 防篡改
    复核）。required 站集合与 coverage 分母一律取 manifest 冻结值，逐站对账
    station result 的 identity.scope_hash/commit_sha 与 coverage.denominator
    ——缺站/缩水/自报分母一律 BLOCKED（exit 2）。

    可信根（R7-GATE-MANIFEST-AUTH-001，第七轮洞1 根修）：--manifest 正门
    必须 --verify-key <keyring>——manifest 冻结件须携带 release/manifest
    专用 key 的 HMAC-SHA256 签名并验签通过；无签名/验签失败/key 未知或
    已吊销一律 ERROR(3)。无签名 manifest 仅诊断可显式 --allow-unsigned
    降级（默认拒）。顶层与 planner 的 required/TTL/scope/分母任何不一致
    → manifest_consistency_violation 并整线 BLOCKED（一致性校验独立于
    签名——第七轮反例：改顶层 required 重算 hash/删 TTL/内部不一致）。

    无 manifest 裸调用默认拒绝（exit 3）：required/coverage 自报不具上绿
    效力背书，必须显式 --allow-self-declared（仅诊断用途）。

    每份结果逐个过镜像校验器（mirror_validate_station_result_v2——
    station-result-v2.schema.json 的 Draft-07 全量等价镜像；F6-GATE-FORMAT-
    DUP-002：不再使用 bugscan_orchestrator 私有构建器校验，消除对 schema
    合法嵌套——execution/coverage/artifacts 附加键、非 fnd_ 前缀 finding_ids
    等——的误拒）+ GateAggregator 严格登记。结构校验失败的输入强制整线
    BLOCKED（绝不静默跳过——跳过即分母缩水）。退出码映射见 _gate_exit_code /
    _gate_error_json。
    """
    # 0. 模式裁定：--manifest 正门 / --allow-self-declared 诊断豁免 / 默认拒绝。
    manifest: Optional[RunManifest] = None
    manifest_keyring: Optional[ApprovalKeyring] = None
    manifest_unsigned_downgrade = False
    if args.manifest:
        if args.allow_self_declared:
            return _gate_error_json(
                "--manifest 与 --allow-self-declared 互斥：正门路径下 required/"
                "coverage 必须对账冻结 manifest，不存在自报豁免",
                mode="flag_conflict",
                inputs={"paths": 0, "docs": 0, "load_errors": 0,
                        "schema_invalid": 0})
        if args.required is not None:
            return _gate_error_json(
                "--required 与 --manifest 互斥：required 站集合必须来自冻结 "
                "manifest（F6-GATE-SCOPE-001：不接受自报 required 集）",
                mode="flag_conflict",
                inputs={"paths": 0, "docs": 0, "load_errors": 0,
                        "schema_invalid": 0})
        if args.verify_key:
            try:
                manifest_keyring = ApprovalKeyring.from_path(args.verify_key)
            except (OSError, ValueError) as exc:
                return _gate_error_json(
                    f"--verify-key keyring 加载失败 ({args.verify_key}): "
                    f"{str(exc)[:160]}",
                    mode="verify_key_invalid",
                    inputs={"paths": 0, "docs": 0, "load_errors": 0,
                            "schema_invalid": 0})
        elif not args.allow_unsigned:
            return _gate_error_json(
                "--manifest 正门必须 --verify-key <keyring>"
                "（R7-GATE-MANIFEST-AUTH-001：冻结件须以 release/manifest "
                "专用 key 验签——纯 manifest_hash 任何人都能重算，不构成"
                "可信根）。无签名 manifest 仅诊断可显式 --allow-unsigned",
                mode="manifest_key_required",
                inputs={"paths": 0, "docs": 0, "load_errors": 0,
                        "schema_invalid": 0})
        try:
            manifest = RunManifest.load(
                args.manifest, keyring=manifest_keyring,
                allow_unsigned=args.allow_unsigned)
        except (OSError, json.JSONDecodeError, ManifestFreezeError,
                KeyError, TypeError, ValueError) as exc:
            return _gate_error_json(
                f"run-manifest 不可用/验签失败 ({args.manifest}): "
                f"{str(exc)[:200]}（manifest_hash 复核拒绝=冻结件被篡改或损坏；"
                "签名验签拒绝=无密钥伪造/未知或已吊销 key）",
                mode="manifest_invalid",
                inputs={"paths": 0, "docs": 0, "load_errors": 0,
                        "schema_invalid": 0})
        if not manifest.signature:
            # 显式 --allow-unsigned 才能走到这里（load 默认拒无签名件）
            manifest_unsigned_downgrade = True
    else:
        if args.verify_key:
            return _gate_error_json(
                "--verify-key 仅与 --manifest 搭配（无 manifest 即无信任根可验）",
                mode="flag_conflict",
                inputs={"paths": 0, "docs": 0, "load_errors": 0,
                        "schema_invalid": 0})
        if args.allow_unsigned:
            return _gate_error_json(
                "--allow-unsigned 仅与 --manifest 搭配（自报路径本就无 manifest）",
                mode="flag_conflict",
                inputs={"paths": 0, "docs": 0, "load_errors": 0,
                        "schema_invalid": 0})
        if not args.allow_self_declared:
            return _gate_error_json(
                "gate 拒绝自报模式：无 --manifest 的裸调用默认拒绝"
                "（F6-GATE-SCOPE-001：required 站集合与 coverage 分母不得由结果自报）。"
                "正门路径：--manifest <run-manifest.json>（freeze_run_manifest 冻结"
                "产物）+ --verify-key <keyring>；仅诊断用途可显式 "
                "--allow-self-declared",
                mode="self_declared_refused",
                inputs={"paths": 0, "docs": 0, "load_errors": 0,
                        "schema_invalid": 0})

    # 1. 展开 --results：文件直取；目录按名序取 *.json。
    paths: List[str] = []
    for target in args.results:
        if os.path.isdir(target):
            names = sorted(n for n in os.listdir(target) if n.endswith(".json"))
            if not names:
                return _gate_error_json(
                    f"results 目录无 .json 结果文件: {target}",
                    inputs={"paths": 0, "docs": 0, "load_errors": 0,
                            "schema_invalid": 0})
            paths.extend(os.path.join(target, n) for n in names)
        elif os.path.isfile(target):
            paths.append(target)
        else:
            return _gate_error_json(
                f"results 路径不存在: {target}",
                inputs={"paths": 0, "docs": 0, "load_errors": 0,
                        "schema_invalid": 0})

    # 2. 载入 JSON（不可读/非 JSON 记账为输入错误——ERROR 3，操作者给错了文件）。
    docs: List[Any] = []
    load_errors: List[Dict[str, str]] = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            load_errors.append({"source": path, "error": str(exc)})
            continue
        if isinstance(doc, list):  # 单文件多结果（数组信封）
            docs.extend(doc)
        else:
            docs.append(doc)
    if load_errors:
        # 输入面不完整（文件不可读/非 JSON）——绝不带着缺口继续聚合出 PASS。
        return _gate_error_json(
            f"results 输入不可读/非 JSON x{len(load_errors)} "
            f"[first={load_errors[0]['source']}: {load_errors[0]['error'][:120]}]",
            inputs={"paths": len(paths), "docs": len(docs),
                    "load_errors": len(load_errors), "schema_invalid": 0},
            load_errors=load_errors)

    # 3. 身份绑定：manifest 正源优先；诊断模式显式旗标优先、其次首个可绑定结果。
    if manifest is not None:
        sha = manifest.commit_sha
        env = manifest.environment
        explicit_sha = (args.sha or "").strip().lower()
        explicit_env = (args.env or "").strip()
        if explicit_sha and explicit_sha != sha:
            return _gate_error_json(
                f"--sha {explicit_sha} 与冻结 manifest.commit_sha {sha} 不一致"
                "（正门路径身份以 manifest 为正源）",
                mode="manifest_identity_conflict",
                inputs={"paths": len(paths), "docs": len(docs),
                        "load_errors": 0, "schema_invalid": 0})
        if explicit_env and explicit_env != env:
            return _gate_error_json(
                f"--env {explicit_env!r} 与冻结 manifest.environment {env!r} 不一致"
                "（正门路径身份以 manifest 为正源）",
                mode="manifest_identity_conflict",
                inputs={"paths": len(paths), "docs": len(docs),
                        "load_errors": 0, "schema_invalid": 0})
    else:
        sha = (args.sha or "").strip().lower() or None
        env = (args.env or "").strip() or None
        for doc in docs:
            if not isinstance(doc, Mapping):
                continue
            identity = doc.get("identity")
            if not isinstance(identity, Mapping):
                continue
            if sha is None:
                raw = identity.get("commit_sha")
                if isinstance(raw, str) and raw.strip():
                    sha = raw.strip().lower()
            if env is None:
                raw = identity.get("environment")
                if isinstance(raw, str) and raw.strip():
                    env = raw.strip()
            if sha is not None and env is not None:
                break
        if sha is None or env is None:
            missing = "target_sha" if sha is None else "environment"
            return _gate_error_json(
                f"无法绑定 {missing}：--sha/--env 未给且没有任何结果携带可用的 "
                f"identity.{missing}（gate 证据必须绑定 SHA+环境）",
                inputs={"paths": len(paths), "docs": len(docs),
                        "load_errors": len(load_errors), "schema_invalid": 0},
                load_errors=load_errors)

    # 4. required 集：manifest 冻结值（正门）或显式 --required / 自报默认（诊断）。
    if manifest is not None:
        required: Set[str] = {str(i) for i in manifest.required_stations}
        if not required:
            return _gate_error_json(
                "冻结 manifest 的 required_stations 为空——非法冻结件（空 required"
                " 拒绝真空绿）",
                mode="manifest_invalid",
                inputs={"paths": len(paths), "docs": len(docs),
                        "load_errors": 0, "schema_invalid": 0})
    elif args.required is not None:
        required = set()
        for token in args.required.split(","):
            token = token.strip()
            if not token:
                continue
            if not (token.isdigit() and 0 <= int(token) <= 7):
                return _gate_error_json(
                    f"--required 站 id 必须是 0-7 的整数: {token!r}",
                    inputs={"paths": len(paths), "docs": len(docs),
                            "load_errors": len(load_errors),
                            "schema_invalid": 0})
            required.add(token)
        if not required:
            return _gate_error_json(
                "--required 为空：显式必报站不能是空集（真空绿拒绝）",
                inputs={"paths": len(paths), "docs": len(docs),
                        "load_errors": len(load_errors),
                        "schema_invalid": 0})
    else:
        default_required: Set[str] = set()
        for doc in docs:
            if isinstance(doc, Mapping):
                sid = doc.get("station_id")
                if isinstance(sid, int) and not isinstance(sid, bool):
                    default_required.add(str(sid))
                elif isinstance(doc.get("station"), str) and doc.get("station").strip():
                    default_required.add(doc["station"].strip())
        required = default_required

    # 5. 逐个过镜像校验（schema Draft-07 全量等价；非 v2 形态同样计违例——
    #    gate 的正式输入契约是 station-result-v2）。
    strict_violations: List[Dict[str, str]] = []
    for doc in docs:
        errors = mirror_validate_station_result_v2(doc)
        if errors:
            strict_violations.append(
                {"error": errors[0] if isinstance(errors, list) else str(errors)})

    # 5b. manifest 自一致性校验（R7-GATE-MANIFEST-AUTH-001：独立于签名——
    #     顶层与 planner 的 required/TTL/scope/分母任何不一致都 BLOCKED，
    #     即使签名合法或显式 --allow-unsigned 降级也不例外）。
    manifest_violations: List[str] = []
    if manifest is not None:
        try:
            with open(args.manifest, "r", encoding="utf-8") as fh:
                manifest_raw = json.load(fh)
        except (OSError, json.JSONDecodeError):  # 理论不可达（load 已复核过）
            manifest_violations = ["manifest_raw_unreadable"]
        else:
            manifest_violations = validate_manifest_consistency(manifest_raw)

    # 6. 聚合（GateAggregator 宽松读+严格出；C1-C6 全在 aggregate 内裁决）。
    agg_kwargs: Dict[str, Any] = {}
    if manifest is not None:
        agg_kwargs["expected_scope_hash"] = manifest.scope_hash
        agg_kwargs["expected_denominator"] = manifest.denominator
    agg = GateAggregator(required_stations=required, target_sha=sha,
                         environment=env, **agg_kwargs)
    for doc in docs:
        agg.add(doc)
    result = agg.aggregate()

    # 7. 结构校验失败强制 BLOCKED（绝不静默跳过残缺结果——跳过即分母缩水）。
    if strict_violations:
        if result.get("aggregate_outcome") != BLOCKED:
            result["aggregate_outcome"] = BLOCKED
            result["policy_verdict"] = BLOCKED
            result["technical_eligible"] = False
        first = strict_violations[0]["error"]
        reason = (f"station-result-v2 schema violation x{len(strict_violations)} "
                  f"[first={first[:160]}]")
        result["reasons"] = [reason] + list(result.get("reasons", []))
        result["reason"] = reason

    # 7b. manifest 一致性违例强制 BLOCKED（R7-GATE-MANIFEST-AUTH-001：
    #     顶层/planner 的 required/TTL/scope/分母不一致——重算 hash 洗不白）。
    if manifest_violations:
        if result.get("aggregate_outcome") != BLOCKED:
            result["aggregate_outcome"] = BLOCKED
            result["policy_verdict"] = BLOCKED
            result["technical_eligible"] = False
        first_m = manifest_violations[0]
        reason_m = (f"manifest_consistency_violation x{len(manifest_violations)} "
                    f"[first={first_m[:160]}]")
        result["reasons"] = [reason_m] + list(result.get("reasons", []))
        result["reason"] = reason_m

    result["inputs"] = {
        "paths": len(paths),
        "docs": len(docs),
        "load_errors": len(load_errors),
        "schema_invalid": len(strict_violations),
    }
    if load_errors:
        result["input_errors"] = load_errors
    if manifest is not None:
        result["mode"] = "manifest"
        result["manifest"] = {
            "path": args.manifest,
            "run_id": manifest.run_id,
            "manifest_hash": manifest.manifest_hash,
            "scope_hash": manifest.scope_hash,
            "denominator": manifest.denominator,
            "required_stations": sorted(manifest.required_stations),
            "commit_sha": manifest.commit_sha,
            "environment": manifest.environment,
            # R7-GATE-MANIFEST-AUTH-001：信任根证据（签名/验签/降级口径）
            "signature": {
                "signed": bool(manifest.signature),
                "key_id": manifest.key_id,
                "verified": bool(manifest.signature)
                            and manifest_keyring is not None,
                "allow_unsigned_downgrade": bool(manifest_unsigned_downgrade),
            },
            "consistency_violations": len(manifest_violations),
        }
    else:
        result["mode"] = "self_declared_diagnostic"

    print(json.dumps(result, ensure_ascii=False))
    return _gate_exit_code(result["aggregate_outcome"])


# ---------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wenquctl",
        description="wenqu 七段管线控制 CLI（P0-1/P0-2 接线——直通 RunManager）")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser, need_run: bool = True) -> None:
        p.add_argument("--db", required=True, help="pipeline_events SQLite 路径")
        p.add_argument("--keys", default=None,
                       help="审批签发 keyring（目录或 JSON；缺省读 "
                            "WENQU_APPROVAL_KEYRING）")
        p.add_argument("--actor", default="cli", help="操作者标识")
        if need_run:
            p.add_argument("--run", required=True, help="run_id")

    p = sub.add_parser("create", help="创建七段 run")
    common(p, need_run=False)
    p.add_argument("--task", required=True, help="task_id（^[a-zA-Z0-9_-]+$）")
    p.add_argument("--commit-sha", required=True, help="40-hex git sha")
    p.add_argument("--environment", required=True, choices=sorted(ENVIRONMENTS))
    p.add_argument("--scope-hash", required=True)
    p.add_argument("--policy-hash", required=True)
    p.add_argument("--ruleset-hash", required=True)
    p.add_argument("--repo-id", default=None)
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("advance", help="推进当前段（启动/完成 attempt）")
    common(p)
    p.add_argument("--execution-status", default=None,
                   choices=["COMPLETED", "ERROR", "BLOCKED", "TIMEOUT",
                            "CANCELLED"])
    p.add_argument("--policy-verdict", default=None,
                   choices=["PASS", "FAIL", "CONDITIONAL", "NOT_APPLICABLE",
                            "NOT_EVALUATED"])
    p.add_argument("--evidence", action="append", default=None,
                   metavar="SHA256:HEX")
    p.add_argument("--finding", action="append", default=None, metavar="FND_ID")
    p.set_defaults(func=cmd_advance)

    p = sub.add_parser("status", help="run 只读快照")
    common(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("raise-waiting", help="触发停等")
    common(p)
    p.add_argument("--stop-type", required=True,
                   choices=["ambiguity", "prod-write", "ddl", "release",
                            "scope", "fund-auth", "exm-fuse", "resource",
                            "ext-unavail"])
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_raise_waiting)

    p = sub.add_parser("resume", help="消费一次性 resume 审批恢复 WAITING")
    common(p)
    p.add_argument("--approval", required=True, help="approval-v2 JSON 文件")
    p.add_argument("--preconditions", required=True,
                   help="客观前置条件 JSON 文件")
    p.set_defaults(func=cmd_resume)

    p = sub.add_parser("authorize-risk", help="消费一次性 risk 授权")
    common(p)
    p.add_argument("--approval", required=True, help="approval-v2 JSON 文件")
    p.set_defaults(func=cmd_authorize_risk)

    p = sub.add_parser("complete", help="终态判定")
    common(p)
    p.add_argument("--risk-approval-id", default=None)
    p.add_argument("--reason", default="")
    p.set_defaults(func=cmd_complete)

    p = sub.add_parser("register-finding", help="登记面追加 finding")
    common(p)
    p.add_argument("--finding-id", required=True, metavar="FND_ID")
    p.add_argument("--fingerprint", required=True)
    p.add_argument("--severity", required=True,
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    p.add_argument("--priority", required=True,
                   choices=["P0", "P1", "P2", "P3"])
    p.add_argument("--detail", default="")
    p.set_defaults(func=cmd_register_finding)

    p = sub.add_parser(
        "gate",
        help="聚合 station-result-v2 结果为整线 gate 判定（退出码 "
             "PASS=0/FAIL=1/BLOCKED=2/ERROR=3；F6-GATE-SCOPE-001：正门须 "
             "--manifest + --verify-key，裸调用默认拒绝）")
    p.add_argument("--results", nargs="+", required=True, metavar="PATH",
                   help="station-result-v2 JSON 文件或目录（目录按名序取 "
                        "*.json；可给多个）")
    p.add_argument("--manifest", default=None, metavar="PATH",
                   help="冻结 run-manifest.json（freeze_run_manifest 产物）——"
                        "正门路径：required 站集合/coverage 分母/身份一律取 "
                        "manifest 冻结值（manifest_hash 防篡改复核），逐站对账 "
                        "identity.scope_hash+commit_sha 与 coverage.denominator，"
                        "缺站/缩水/自报分母一律 BLOCKED；正门必须搭配 "
                        "--verify-key（R7-GATE-MANIFEST-AUTH-001）")
    p.add_argument("--verify-key", default=None, dest="verify_key",
                   metavar="KEYRING",
                   help="manifest 验签 keyring（目录或 JSON 文件；与 "
                        "--manifest 搭配必填）——manifest 冻结件须携带 "
                        "release/manifest 专用 key 的 HMAC-SHA256 签名；"
                        "无签名/验签失败/key 未知或已吊销一律 ERROR(3)"
                        "（R7-GATE-MANIFEST-AUTH-001：纯 manifest_hash "
                        "可被任何人重算，不构成可信根）")
    p.add_argument("--allow-unsigned", dest="allow_unsigned",
                   action="store_true",
                   help="仅诊断用途：显式接受无签名 manifest（默认拒——"
                        "无信任根的冻结件不具上绿效力背书；生产判定必须 "
                        "--verify-key 验签。一致性校验仍强制：顶层与 planner "
                        "的 required/TTL/scope/分母不一致照样 BLOCKED）")
    p.add_argument("--allow-self-declared", dest="allow_self_declared",
                   action="store_true",
                   help="仅诊断用途：显式承认无 manifest 的自报模式（required "
                        "站集合与 coverage 分母由结果自报，判定不具上绿效力"
                        "背书）；生产判定必须走 --manifest + --verify-key")
    p.add_argument("--required", default=None, metavar="IDS",
                   help="必报站 id 逗号分隔（如 2,7）；缺省=全部已上报站"
                        "（任何站缺报/硬失败都不得 PASS）；与 --manifest 互斥"
                        "——正门 required 集来自冻结 manifest")
    p.add_argument("--sha", default=None,
                   help="目标 commit SHA（缺省从首个可绑定结果的 "
                        "identity.commit_sha 推导；跨 SHA 混报判 BLOCKED；"
                        "--manifest 模式下须与冻结值一致）")
    p.add_argument("--env", default=None,
                   help="目标环境（缺省从首个可绑定结果的 "
                        "identity.environment 推导；跨环境混报判 BLOCKED；"
                        "--manifest 模式下须与冻结值一致）")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser(
        "approve",
        help="审批签发（P0-2 残余：本地 keyring+CLI 签发，飞书留接口；"
             "高危类型 prod_write/ddl/release/fund_auth 强制双人联签）")
    p.add_argument("--keyring", default=None, metavar="PATH",
                   help="签发 keyring（目录或 JSON；缺省读 "
                        "WENQU_APPROVAL_KEYRING）")
    p.add_argument("--audit", default=None, metavar="PATH",
                   help="签发审计账本 jsonl（缺省：--audit > "
                        "WENQU_APPROVAL_AUDIT > 目录型 keyring 内 "
                        "issuance-audit.jsonl）")
    p.add_argument("--approval-type", choices=sorted(_APPROVAL_TYPES),
                   dest="approval_type",
                   help="审批类型（签发模式必填）")
    p.add_argument("--run", default=None, help="锚定 run_id（签发模式必填）")
    p.add_argument("--task", default=None,
                   help="锚定 task_id（签发模式必填）")
    p.add_argument("--stage", default=None, choices=list(STAGES),
                   help="锚定段（签发模式必填）")
    p.add_argument("--environment", default=None,
                   choices=sorted(ENVIRONMENTS),
                   help="环境（签发模式必填）")
    p.add_argument("--scope", default=None, dest="scope",
                   help="authorized_scope（=run scope_hash，不得扩范围；"
                        "签发模式必填）")
    p.add_argument("--policy-hash", default=None, dest="policy_hash",
                   help="签发模式必填")
    p.add_argument("--ruleset-hash", default=None, dest="ruleset_hash",
                   help="签发模式必填")
    p.add_argument("--watermark", default=None,
                   help="input_watermark（40-hex git sha，强制绑定；"
                        "签发模式必填）")
    p.add_argument("--state-version", default=None, type=int,
                   dest="state_version",
                   help="expected_state_version（消费时 CAS 精确匹配；"
                        "签发模式必填）")
    p.add_argument("--actor", default=None, help="签发人标识（签发模式必填）")
    p.add_argument("--stop-type", default=None,
                   choices=sorted(STOP_PRECONDITION_SPECS), dest="stop_type",
                   help="resume 必填（锚定停等类型）；其余类型缺省按类型映射")
    p.add_argument("--stop-event-id", default=None, dest="stop_event_id",
                   help="resume 必填（锚定停等事件）；其余缺省 n/a-<type>")
    p.add_argument("--decision", default="approve",
                   choices=["approve", "deny", "conditional"])
    p.add_argument("--key-id", default=None, dest="key_id",
                   help="签发 key（缺省=唯一 active key；多个 active 必须显式）")
    p.add_argument("--ttl", type=int, default=3600,
                   help="审批有效期秒数（缺省 3600；上限 30 天）")
    p.add_argument("--payload", default=None, metavar="FILE",
                   help="payload 全量 JSON 文件（按类型判别封闭）")
    p.add_argument("--preconditions", default=None, metavar="FILE",
                   help="resume 前置条件 JSON（自动算 "
                        "objective_precondition_hash；与 --payload 二选一）")
    p.add_argument("--confirm-two-persons", action="store_true",
                   dest="confirm_two_persons",
                   help="双人确认（高危类型 prod_write/ddl/release/fund_auth "
                        "必带）")
    p.add_argument("--second-key-id", default=None, dest="second_key_id",
                   help="第二签发人 key（联签；高危必填，不得与主 key 相同）")
    p.add_argument("--second-actor", default=None, dest="second_actor",
                   help="第二签发人标识（高危必填）")
    p.add_argument("--source", default="local",
                   choices=sorted(APPROVAL_SOURCES),
                   help="审批送达来源（local=本地默认案；feishu=占位接口）")
    p.add_argument("--out", default=None, metavar="FILE",
                   help="审批信封输出文件（0600——含 nonce 消费凭据；"
                        "签发模式必填，对账模式不需要）")
    p.add_argument("--print-envelope", action="store_true",
                   dest="print_envelope",
                   help="同时在 stdout 打印完整信封（默认只打印回执）")
    p.add_argument("--reconcile-db", default=None, dest="reconcile_db",
                   metavar="PATH",
                   help="对账模式：与该 EventStore 的 APPROVAL_CONSUMED 事件"
                        "双向对账（批了 vs 用了 vs 未用过期）")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser(
        "keys", help="签发密钥生命周期（create/rotate/revoke/list；"
                     "0600 secret/0700 目录；输出绝不回显 secret 明文）")
    p.add_argument("--keyring", required=True, metavar="PATH",
                   help="受管 keyring 目录（list 也接受 JSON 文件）")
    keys_sub = p.add_subparsers(dest="keys_command", required=True)

    pk = keys_sub.add_parser("create", help="生成新 key（active）")
    pk.add_argument("--key-id", default=None, metavar="KEY_ID",
                    help="缺省自动 key_<8hex>")
    pk.add_argument("--expiry", default=None, metavar="ISO8601",
                    help="key 过期时间（过期后不得签发；存量验证以信封 TTL 为准）")
    pk.add_argument("--description", default=None)
    pk.add_argument("--actor", default="cli", help="操作者标识")
    pk.set_defaults(func=cmd_keys)

    pk = keys_sub.add_parser("rotate", help="轮换：旧 key 标 rotated（可验存量），"
                                            "新 key 签发")
    pk.add_argument("--key-id", required=True, metavar="KEY_ID")
    pk.add_argument("--new-key-id", default=None, metavar="KEY_ID",
                    help="缺省自动 key_<8hex>")
    pk.add_argument("--actor", default="cli", help="操作者标识")
    pk.set_defaults(func=cmd_keys)

    pk = keys_sub.add_parser("revoke", help="吊销：该 key 验签即拒"
                                            "（fail-closed）+记录拒绝事件")
    pk.add_argument("--key-id", required=True, metavar="KEY_ID")
    pk.add_argument("--actor", default="cli", help="操作者标识")
    pk.set_defaults(func=cmd_keys)

    pk = keys_sub.add_parser("list", help="列出 key 与生命周期元数据"
                                          "（不含 secret）")
    pk.set_defaults(func=cmd_keys)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (PipelineError, ApprovalError) as exc:
        print(f"wenquctl: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    sys.exit(main())

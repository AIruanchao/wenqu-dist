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

审批 JSON 即 approval-v2 信封（含 key_id + HMAC-SHA256 签名）——签发侧用
wenqu_core.approval_keys.sign_envelope 生成；CLI 只消费不签发（权限分离）。
密钥登记经 --keys 或 WENQU_APPROVAL_KEYRING 指向 keyring 目录/JSON 文件。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

_SYS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SYS_DIR not in sys.path:
    sys.path.insert(0, _SYS_DIR)

from wenqu_core.approval_keys import ApprovalKeyring  # noqa: E402
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ENVIRONMENTS, STAGES, ApprovalBroker, ApprovalError, PipelineError,
    RunManager,
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

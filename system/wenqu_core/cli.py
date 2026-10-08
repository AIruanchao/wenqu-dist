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
                 GateAggregator 的第一个生产消费者；退出码 PASS=0/FAIL=1/
                 BLOCKED=2/ERROR=3）

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
from typing import Any, Dict, List, Mapping, Optional, Set

_SYS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SYS_DIR not in sys.path:
    sys.path.insert(0, _SYS_DIR)

from wenqu_core.approval_keys import ApprovalKeyring  # noqa: E402
from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    StationResultValidationError, validate_station_result,
)
from wenqu_core.gate_aggregator import BLOCKED, GateAggregator  # noqa: E402
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

    每份结果逐个过内置结构校验器（validate_station_result——schema 的可执行
    等价物）+ GateAggregator 严格登记（宽松读、聚合 fail-closed）；
    target_sha/environment 缺省从首个可绑定结果的 identity 推导（跨 SHA/环境
    混报由聚合器 C2/C5 判 BLOCKED），--required 缺省=全部已上报站（防分母缩水
    真空绿）。结构校验失败的输入强制整线 BLOCKED（绝不静默跳过——跳过即分母
    缩水）。退出码映射见 _gate_exit_code / _gate_error_json。
    """
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

    # 3. 推导 target_sha / environment（显式旗标优先，其次首个可绑定结果）。
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

    # 4. 逐个严格校验（schema 可执行等价物）＋收集默认 required 集。
    strict_violations: List[Dict[str, str]] = []
    default_required: Set[str] = set()
    for doc in docs:
        try:
            validate_station_result(doc)
        except StationResultValidationError as exc:
            strict_violations.append({"error": str(exc)})
        if isinstance(doc, Mapping):
            sid = doc.get("station_id")
            if isinstance(sid, int) and not isinstance(sid, bool):
                default_required.add(str(sid))
            elif isinstance(doc.get("station"), str) and doc.get("station").strip():
                default_required.add(doc["station"].strip())

    if args.required is not None:
        required: Set[str] = set()
        for token in args.required.split(","):
            token = token.strip()
            if not token:
                continue
            if not (token.isdigit() and 0 <= int(token) <= 7):
                return _gate_error_json(
                    f"--required 站 id 必须是 0-7 的整数: {token!r}",
                    inputs={"paths": len(paths), "docs": len(docs),
                            "load_errors": len(load_errors),
                            "schema_invalid": len(strict_violations)})
            required.add(token)
        if not required:
            return _gate_error_json(
                "--required 为空：显式必报站不能是空集（真空绿拒绝）",
                inputs={"paths": len(paths), "docs": len(docs),
                        "load_errors": len(load_errors),
                        "schema_invalid": len(strict_violations)})
    else:
        required = default_required

    # 5. 聚合（GateAggregator 宽松读+严格出；C1-C5 全在 aggregate 内裁决）。
    agg = GateAggregator(required_stations=required, target_sha=sha,
                         environment=env)
    for doc in docs:
        agg.add(doc)
    result = agg.aggregate()

    # 6. 结构校验失败强制 BLOCKED（绝不静默跳过残缺结果——跳过即分母缩水）。
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

    result["inputs"] = {
        "paths": len(paths),
        "docs": len(docs),
        "load_errors": len(load_errors),
        "schema_invalid": len(strict_violations),
    }
    if load_errors:
        result["input_errors"] = load_errors

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
             "PASS=0/FAIL=1/BLOCKED=2/ERROR=3）")
    p.add_argument("--results", nargs="+", required=True, metavar="PATH",
                   help="station-result-v2 JSON 文件或目录（目录按名序取 "
                        "*.json；可给多个）")
    p.add_argument("--required", default=None, metavar="IDS",
                   help="必报站 id 逗号分隔（如 2,7）；缺省=全部已上报站"
                        "（任何站缺报/硬失败都不得 PASS）")
    p.add_argument("--sha", default=None,
                   help="目标 commit SHA（缺省从首个可绑定结果的 "
                        "identity.commit_sha 推导；跨 SHA 混报判 BLOCKED）")
    p.add_argument("--env", default=None,
                   help="目标环境（缺省从首个可绑定结果的 "
                        "identity.environment 推导；跨环境混报判 BLOCKED）")
    p.set_defaults(func=cmd_gate)

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

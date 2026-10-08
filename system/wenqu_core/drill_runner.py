# -*- coding: utf-8 -*-
"""drill_runner.py——备份/DR 演练编排器（checkpoint/restore drill 产品面）。

正源与契约（模块内不写验收 ID 字面量——追踪矩阵归属纪律，
见 test_ac_ops_families.py 专属测试）：
- 真实演练正源是 ``system/sentinels/backup-restore-drill.sh``：快照→篡改
  （实测字节已变，防伪造演练）→恢复→逐文件 cmp+sha256 字节级对账四步
  全部真跑；DR 模式另加 RPO/RTO 实测计时（冻结目标 RPO<=300s、RTO<=60s）。
- 本模块只做编排、报告解析与结构校验：零 mock、零重演——语料的收集、
  篡改、恢复、对账全部发生在演练脚本的真实子进程内；生产语料根全程
  只读（脚本内 cp 一次），篡改/恢复只发生在沙箱副本。

组件：
- ``DrillOutcome``     一次成功演练的结构化结果（报告 dict + jsonl 路径 +
                       DR 模式的 RPO/RTO 实测数字）。
- ``DrillFailure``     演练失败（子进程非零）：fail-closed——携带 FAIL
                       报告与原因抛出，编排层绝不把失败折算成成功。
- ``run_drill``        编排入口：起真实子进程跑演练脚本，解析双工件
                       （drill-<stamp>.json + .jsonl 事件日志）。
- ``validate_report``  报告结构契约校验（时间/文件/结果三要素、逐文件
                       对账布尔、DR 计时块存在且数字有限）。
- ``read_events``      解析 jsonl 事件日志（逐事件 dict；损坏行抛错，
                       fail-closed 不跳行）。

安全构造（by construction）：
- 纯 stdlib；子进程显式 argv（无 shell 拼接注入面）+ 超时保护。
- 退出码契约：0=PASS；非零=FAIL（语料为空/步骤失败/对账不等/DR 指标
  越冻结目标）。非零时报告若存在则必须 result=FAIL——编排层再校验一次，
  「报告自称 PASS 而退出非零」视为结构破坏直接抛错。
- 时间精度：脚本以 python3 time.time() 亚秒计时（python3 不可用时退化
  整秒）；本层只消费实测数字，绝不补造。
"""

from __future__ import annotations

import json
import math
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]        # wenqu-dist/
DRILL_SCRIPT = REPO_ROOT / "system" / "sentinels" / "backup-restore-drill.sh"

DEFAULT_TIMEOUT_S = 300.0

# YYYYmmddTHHMMSSZ（同秒并发防覆写时可带 -N 序号后缀）
_STAMP_RE = re.compile(r"\d{8}T\d{6}Z(?:-\d+)?\Z")


class DrillFailure(RuntimeError):
    """演练失败（子进程退出非零）——fail-closed，携带 FAIL 报告。"""

    def __init__(self, message: str, report: dict, report_path: Path,
                 jsonl_path: Optional[Path], returncode: int):
        super().__init__(message)
        self.report = report
        self.report_path = report_path
        self.jsonl_path = jsonl_path
        self.returncode = returncode


@dataclass
class DrillOutcome:
    """一次成功演练的结构化结果。"""

    report: dict
    report_path: Path
    jsonl_path: Path
    mode: str = "backup"
    rpo_seconds: Optional[float] = None   # DR 模式：最后快照点→故障注入点实测
    rto_seconds: Optional[float] = None   # DR 模式：恢复开始→全部对账通过实测
    extra: dict = field(default_factory=dict)


def _finite(x) -> bool:
    try:
        return math.isfinite(float(x))
    except (TypeError, ValueError):
        return False


def validate_report(report: dict, *, mode: str) -> dict:
    """结构契约校验（时间/文件/结果三要素 + 逐文件对账 + DR 计时块）。

    只验结构不判语义（PASS/RPO 是否达标由调用方按场景断言）；任何结构
    缺失/类型漂移/数字非有限 → ValueError（fail-closed）。
    """
    if not isinstance(report, dict):
        raise ValueError(f"报告必须是 JSON 对象，实得 {type(report).__name__}")
    for key in ("drill", "stamp", "result", "steps", "byte_match_all"):
        if key not in report:
            raise ValueError(f"报告缺必备字段: {key}")
    if report["drill"] != "backup-restore":
        raise ValueError(f"drill 类型漂移: {report['drill']!r}")
    stamp = report["stamp"]
    if not (isinstance(stamp, str) and _STAMP_RE.fullmatch(stamp)):
        raise ValueError(f"stamp 非约定 UTC 时间戳: {stamp!r}")

    steps = report["steps"]
    if not isinstance(steps, dict):
        raise ValueError(f"steps 必须是对象，实得 {type(steps).__name__}")
    for step in ("snapshot", "tamper", "restore", "reconcile"):
        if step not in steps:
            raise ValueError(f"steps 缺四步之一: {step}")
    snap_files = steps["snapshot"].get("files")
    recon_files = steps["reconcile"].get("files")
    if not isinstance(snap_files, list) or not snap_files:
        raise ValueError("snapshot.files 必须为非空数组")
    if not isinstance(recon_files, list):
        raise ValueError("reconcile.files 必须为数组")
    snap_rels = set()
    for f in snap_files:
        if not (isinstance(f, dict) and {"rel", "sha256", "size"} <= set(f)):
            raise ValueError(f"snapshot 条目结构缺失: {f!r}")
        snap_rels.add(f["rel"])
    recon_rels = set()
    for f in recon_files:
        if not (isinstance(f, dict) and {"rel", "cmp", "sha_match"} <= set(f)):
            raise ValueError(f"reconcile 条目结构缺失: {f!r}")
        if not isinstance(f["cmp"], bool) or not isinstance(f["sha_match"], bool):
            raise ValueError(f"reconcile 布尔漂移（非 bool）: {f!r}")
        recon_rels.add(f["rel"])
    if snap_rels != recon_rels:
        raise ValueError(
            f"对账文件集与快照不一致: 仅快照 {sorted(snap_rels - recon_rels)} "
            f"仅对账 {sorted(recon_rels - snap_rels)}")
    n_restored = steps["restore"].get("files_restored")
    if n_restored != len(snap_rels):
        raise ValueError(f"恢复计数 {n_restored} != 快照文件数 {len(snap_rels)}")

    if mode == "dr":
        dr = report.get("dr")
        if not isinstance(dr, dict):
            raise ValueError("DR 模式报告缺 dr 计时块")
        for key in ("rpo_seconds", "rto_seconds", "rpo_target_s",
                    "rto_target_s", "rpo_ok", "rto_ok"):
            if key not in dr:
                raise ValueError(f"dr 计时块缺字段: {key}")
        for key in ("rpo_seconds", "rto_seconds", "rpo_target_s", "rto_target_s"):
            if not _finite(dr[key]):
                raise ValueError(f"dr.{key} 非有限数字: {dr[key]!r}")
        for key in ("t_snapshot_done_epoch", "t_fault_epoch",
                    "t_restore_start_epoch", "t_reconcile_done_epoch"):
            if not _finite(dr.get(key)):
                raise ValueError(f"dr.{key} 非有限数字: {dr.get(key)!r}")
    elif report.get("dr") is not None:
        raise ValueError(f"backup 模式不应有 dr 计时块: {report['dr']!r}")
    return report


def read_events(jsonl_path: Path) -> list:
    """解析 jsonl 事件日志；损坏行抛 ValueError（不跳行静默继续）。"""
    events = []
    for lineno, line in enumerate(
            jsonl_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{jsonl_path}:{lineno} 损坏事件行: {exc}") from exc
        for key in ("ts", "event", "file", "result"):
            if key not in ev:
                raise ValueError(f"{jsonl_path}:{lineno} 事件缺 {key}: {ev!r}")
        events.append(ev)
    return events


def run_drill(*, wenqu_root, report_dir, mode: str = "backup",
              fault_delay_s: float = 1.0,
              timeout_s: float = DEFAULT_TIMEOUT_S) -> DrillOutcome:
    """真实跑一次备份/DR 演练并返回结构化结果。

    wenqu_root/report_dir 接受 str 或 Path；mode 限 backup|dr；dr 模式
    fault_delay_s 为快照完成后注入的已知故障延迟窗口（秒）。
    成功（退出 0 + 报告 result=PASS）→ DrillOutcome；失败 → DrillFailure。
    """
    if mode not in ("backup", "dr"):
        raise ValueError(f"mode 必须是 backup|dr，实得 {mode!r}")
    wenqu_root = Path(wenqu_root)
    report_dir = Path(report_dir)
    argv = ["bash", str(DRILL_SCRIPT),
            "--wenqu-root", str(wenqu_root),
            "--report-dir", str(report_dir),
            "--mode", mode]
    if mode == "dr":
        if not (isinstance(fault_delay_s, (int, float)) and fault_delay_s > 0):
            raise ValueError(f"fault_delay_s 必须为正数: {fault_delay_s!r}")
        argv += ["--fault-delay", str(fault_delay_s)]

    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout_s)
    reports = sorted(report_dir.glob("drill-*.json"))
    if not reports:
        raise DrillFailure(
            f"drill 退出 {proc.returncode} 且无报告工件（stderr 尾部: "
            f"{proc.stderr.strip()[-400:]})",
            report={}, report_path=report_dir, jsonl_path=None,
            returncode=proc.returncode)
    report_path = reports[-1]
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DrillFailure(f"报告不可解析 {report_path}: {exc}", report={},
                           report_path=report_path, jsonl_path=None,
                           returncode=proc.returncode) from exc
    jsonl_path = Path(report.get("jsonl", str(report_path).replace(
        ".json", ".jsonl")))

    if proc.returncode != 0:
        if report.get("result") != "FAIL":  # 退出非零但报告自称 PASS=结构破坏
            raise DrillFailure(
                f"drill 退出 {proc.returncode} 但报告 result="
                f"{report.get('result')!r}（fail-closed 结构破坏）",
                report=report, report_path=report_path, jsonl_path=jsonl_path,
                returncode=proc.returncode)
        reason = report.get("reason", "<无原因>")
        raise DrillFailure(
            f"drill FAIL (exit {proc.returncode}): {reason}",
            report=report, report_path=report_path, jsonl_path=jsonl_path,
            returncode=proc.returncode)

    validate_report(report, mode=mode)
    if report["result"] != "PASS" or report["byte_match_all"] is not True:
        raise DrillFailure(
            f"drill 退出 0 但判定非 PASS/对账非全等: result={report['result']} "
            f"byte_match_all={report['byte_match_all']}",
            report=report, report_path=report_path, jsonl_path=jsonl_path,
            returncode=proc.returncode)

    outcome = DrillOutcome(report=report, report_path=report_path,
                           jsonl_path=jsonl_path, mode=mode)
    if mode == "dr":
        outcome.rpo_seconds = float(report["dr"]["rpo_seconds"])
        outcome.rto_seconds = float(report["dr"]["rto_seconds"])
    return outcome

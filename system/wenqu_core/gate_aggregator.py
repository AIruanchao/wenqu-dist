# -*- coding: utf-8 -*-
"""统一 Gate 聚合器（Codex W3B；P0-3 二次加固：双契约消费 + dashboard 输出对齐；
F4-GATE-001 根修：v2 输入结构必须严格——add() 前置全量镜像校验）。

消费流水线各 station 产出的 station-result JSON，聚合为整线统一的 gate 判定。

## 输入契约一（station-result-v2，正式契约——schemas/station-result-v2.schema.json）

判别为 v2（`schema_version == "2.0"`，或出现 v2 正式字段组合 station_id/
execution_status/policy_verdict）时，**结构必须严格**：add() 先经
:func:`mirror_validate_station_result_v2`（schema 的无外部依赖镜像校验器）
全量校验 required/类型/enum/pattern/const/allOf-if-then 跨字段语义——
任何 schema-invalid 输入一律记 malformed、该站强制 BLOCKED、
technical_eligible=false（Codex 第四轮实锤：残缺 v2 曾被判 PASS）。
字段语义保持双契约：v2 正式字段 + legacy 兼容字段并存消费。

    {
      "schema_version":     "2.0",
      "station_id":         2,             # 必填：站点编号（0-7）；站点键 = str(station_id)
      "execution_status":   "COMPLETED",   # 必填：COMPLETED/ERROR/BLOCKED/TIMEOUT/CANCELLED
      "policy_verdict":     "PASS",        # 必填：PASS/FAIL/CONDITIONAL/NOT_APPLICABLE/NOT_EVALUATED
      "identity": {                        # 必填：证据身份绑定（C2/C5 的数据源）
        "commit_sha":       "<40-hex>",    #   与构造器 target_sha 比对
        "environment":      "staging",     #   与构造器 environment 比对
        ...
      },
    }

v2 verdict 归一（fail-closed）：
    PASS                        -> PASS
    CONDITIONAL / NOT_APPLICABLE-> CONDITIONAL（软——不得上绿，需人工处置）
    FAIL / NOT_EVALUATED        -> BLOCKED（硬失败）
    execution_status != COMPLETED（ERROR/BLOCKED/TIMEOUT/CANCELLED）
                                -> 整站硬失败（铁律 2：执行未完成不得记 PASS）

## 输入契约二（legacy 旧字段，向后兼容——按 entry 的 input_version 区分）::

    {
      "station":     "lint",        # 站点名（required_stations 成员或旁路站点）
      "outcome":     "PASS",        # 见别名表；未知/缺失一律硬失败
      "sha":         "<full-sha>",  # 亦接受 target_sha / commit_sha
      "environment": "staging",     # 须与构造器 environment 一致
    }

outcome 别名表（大小写不敏感）：
    PASS/PASSED/OK/SUCCESS/GREEN                            -> PASS
    CONDITIONAL/WARN/WARNING/SOFT_PASS/PASS_WITH_WARNINGS   -> CONDITIONAL
    FAIL/FAILED/FAILURE/ERROR/BLOCKED/TIMEOUT/未知/缺失     -> 硬失败（整线 BLOCKED）

## 硬约束（不可降级）
    C1 任一 required 站非 PASS -> 整线非 PASS；
    C2 任一站点证据 SHA 与 target_sha 不一致（或缺失、无法绑定目标）-> BLOCKED；
    C3 分母缩水：required 站未全部上报 -> BLOCKED；空 required_stations 同样 BLOCKED；
    C4 CONDITIONAL != PASS：条件通过永不映射为绿判定 / GitHub success；
    C5 环境不一致 / 结构残缺 / 同站冲突证据 -> BLOCKED（宁可阻断，不猜证据）。

## 输出契约（P0-3 修：对齐 dashboard/server.py read_gate_aggregate 强制校验）

aggregate() 输出除原有字段外必须包含：
    generated_at   ISO8601 UTC（含 Z 后缀，dashboard 以 fromisoformat 解析并查 TTL）
    policy_verdict 整线判定（PASS/CONDITIONAL/BLOCKED；dashboard 要求
                   policy_verdict/overall/verdict 三者至少其一）
端到端保证：合法 v2 输入聚合出的 JSON 喂给 dashboard 的 read_gate_aggregate()
必须 ACCEPT（不触发 AGGREGATOR_MALFORMED/AGGREGATOR_STALE）。

technical_eligible 语义：True 仅表示技术硬门（C2/C3/C5 及“无任何站点硬失败”）
全部通过；与 aggregate_outcome == PASS 不等价——CONDITIONAL 时 technical_eligible
可为 True，但放行判断必须且只能以 aggregate_outcome == PASS 为准。

GitHub 状态映射（to_github_status）：
    PASS        -> state=success  / conclusion=success
    CONDITIONAL -> state=failure  / conclusion=action_required  # 条件项须人工处置，绝不上绿
    BLOCKED     -> state=failure  / conclusion=failure
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Set

__all__ = [
    "GateAggregator", "PASS", "CONDITIONAL", "BLOCKED",
    "mirror_validate_station_result_v2",
]

PASS = "PASS"
CONDITIONAL = "CONDITIONAL"
BLOCKED = "BLOCKED"

_PASS_ALIASES = frozenset({"PASS", "PASSED", "OK", "SUCCESS", "GREEN"})
_CONDITIONAL_ALIASES = frozenset(
    {"CONDITIONAL", "WARN", "WARNING", "SOFT_PASS", "PASS_WITH_WARNINGS"}
)
_SHA_FIELDS = ("sha", "target_sha", "commit_sha")

# v2 正式字段（schemas/station-result-v2.schema.json）
_V2_SCHEMA_VERSION = "2.0"
_V2_EXECUTION_STATUS = ("COMPLETED", "ERROR", "BLOCKED", "TIMEOUT", "CANCELLED")
_V2_POLICY_VERDICTS = ("PASS", "FAIL", "CONDITIONAL", "NOT_APPLICABLE", "NOT_EVALUATED")
_V2_EXEC_HARD_FAIL = frozenset({"ERROR", "BLOCKED", "TIMEOUT", "CANCELLED"})
# v2 policy_verdict -> 聚合 outcome（NOT_APPLICABLE 归 CONDITIONAL：不上绿、需人工确认豁免）
_V2_VERDICT_MAP = {
    "PASS": PASS,
    "CONDITIONAL": CONDITIONAL,
    "NOT_APPLICABLE": CONDITIONAL,
    "FAIL": BLOCKED,
    "NOT_EVALUATED": BLOCKED,
}

_GITHUB_STATE = {
    PASS: ("success", "success"),
    CONDITIONAL: ("failure", "action_required"),
    BLOCKED: ("failure", "failure"),
}


# ====================================================================== #
# station-result-v2 镜像校验器（F4-GATE-001 根修，2026-10-08）
# ====================================================================== #
# schemas/station-result-v2.schema.json 的无外部依赖结构镜像——语义必须与
# schema 文件逐条同步（required/类型/enum/pattern/const/additionalProperties/
# allOf-if-then 跨字段）。system/tests/test_gate_schema_hardening.py 内置
# 一致性自测：对正负样例组，本镜像与 jsonschema+FormatChecker（严格
# date-time 检查注册后）结论必须一致。改 schema 文件时必须同步改这里。
#
# 与 jsonschema 的两处刻意差异（均有一致性自测护栏）：
#   1. date-time：镜像无条件做严格 ISO-8601 解析（jsonschema 的 FormatChecker
#      在未安装 rfc3339-validator 时对 date-time 空转——自测按仓内既有惯例
#      注册严格检查后对齐）；
#   2. PASS 的 scanned==denominator：schema 侧以 const 级联（1..64）机器判定
#      （draft-07 无法表达跨字段数值比较），分母>64 时不误拒合法全扫；镜像
#      侧做全量无界等式判定（缩水无论多大必拒）。
_MIRROR_TOP_KEYS = frozenset({
    "schema_version", "run_id", "station_id", "attempt_id",
    "execution_status", "policy_verdict", "identity", "tool", "execution",
    "coverage", "finding_ids", "artifacts",
})
_MIRROR_TOP_REQUIRED = (
    "schema_version", "run_id", "station_id", "attempt_id",
    "execution_status", "policy_verdict", "identity", "tool", "execution",
)
_MIRROR_IDENTITY_REQUIRED = ("commit_sha", "environment", "scope_hash")
_MIRROR_IDENTITY_OPTIONAL = (
    "project_id", "ruleset_hash", "data_config_hash", "lockfile_hash",
)
_MIRROR_EXEC_REQUIRED = (
    "argv_digest", "started_at", "ended_at", "actual_exit_code",
    "expected_exit_set", "assertion_verdict",
)
_MIRROR_RUN_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_MIRROR_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_MIRROR_CAS_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MIRROR_EXEC_STATUS = frozenset(
    {"COMPLETED", "ERROR", "BLOCKED", "TIMEOUT", "CANCELLED"})
_MIRROR_VERDICTS = frozenset(
    {"PASS", "FAIL", "CONDITIONAL", "NOT_APPLICABLE", "NOT_EVALUATED"})
_MIRROR_ASSERTION = frozenset({"PASS", "FAIL", "ERROR"})
_MIRROR_EXEC_HARD = frozenset({"ERROR", "BLOCKED", "TIMEOUT", "CANCELLED"})
# F4-SCHEMA-001 #5（station 侧）：执行非完成态只允许阻断类裁决
_MIRROR_HARD_EXEC_VERDICTS = frozenset({"FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"})


def _mirror_int(value: Any) -> bool:
    """schema "integer"：bool 不是 integer（JSON Schema 语义）。"""
    return isinstance(value, int) and not isinstance(value, bool)


def _mirror_iso_datetime(value: Any) -> bool:
    """format: date-time（严格 ISO-8601；Z/z 后缀按 UTC 接受）。"""
    if not isinstance(value, str):
        return False
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        datetime.fromisoformat(text)
        return True
    except ValueError:
        return False


def mirror_validate_station_result_v2(result: Any) -> List[str]:
    """station-result-v2.schema.json 的镜像校验；返回违例清单（空 == 合法）。

    无外部依赖（纯标准库）；GateAggregator.add() 对每个 v2 条目前置调用，
    schema-invalid 一律记 malformed 并强制该站 BLOCKED（fail-closed）。
    """
    errors: List[str] = []

    def _err(msg: str) -> None:
        errors.append(msg)

    if not isinstance(result, Mapping):
        return ["station result must be a JSON object"]

    # -- 顶层 required / additionalProperties:false ------------------------
    for key in _MIRROR_TOP_REQUIRED:
        if key not in result:
            _err(f"required: {key}")
    extra = sorted(set(result) - _MIRROR_TOP_KEYS)
    if extra:
        _err(f"additionalProperties not allowed: {extra}")

    # -- 顶层标量 -----------------------------------------------------------
    if result.get("schema_version") != "2.0":
        _err("schema_version must be const '2.0'")
    run_id = result.get("run_id")
    if not isinstance(run_id, str) or not _MIRROR_RUN_ID_RE.match(run_id):
        _err("run_id must be a string matching ^[a-zA-Z0-9_-]+$")
    sid = result.get("station_id")
    if not _mirror_int(sid) or not 0 <= sid <= 7:
        _err("station_id must be an integer in [0,7]")
    if not isinstance(result.get("attempt_id"), str):
        _err("attempt_id must be a string")
    if result.get("execution_status") not in _MIRROR_EXEC_STATUS:
        _err("execution_status must be one of "
             f"{sorted(_MIRROR_EXEC_STATUS)}")
    if result.get("policy_verdict") not in _MIRROR_VERDICTS:
        _err("policy_verdict must be one of "
             f"{sorted(_MIRROR_VERDICTS)}")

    # -- identity -----------------------------------------------------------
    identity = result.get("identity")
    if not isinstance(identity, Mapping):
        _err("identity must be an object")
    else:
        for key in _MIRROR_IDENTITY_REQUIRED:
            if key not in identity:
                _err(f"identity.required: {key}")
        sha = identity.get("commit_sha")
        if not isinstance(sha, str) or not _MIRROR_SHA40_RE.match(sha):
            _err("identity.commit_sha must be a string matching "
                 "^[0-9a-f]{40}$")
        if not isinstance(identity.get("environment"), str):
            _err("identity.environment must be a string")
        if not isinstance(identity.get("scope_hash"), str):
            _err("identity.scope_hash must be a string")
        for key in _MIRROR_IDENTITY_OPTIONAL:
            if key in identity and not isinstance(identity[key], str):
                _err(f"identity.{key} must be a string")

    # -- tool ----------------------------------------------------------------
    tool = result.get("tool")
    if not isinstance(tool, Mapping):
        _err("tool must be an object")
    else:
        for key in ("name", "version"):
            if key not in tool:
                _err(f"tool.required: {key}")
            elif not isinstance(tool[key], str):
                _err(f"tool.{key} must be a string")
        if "digest" in tool and not isinstance(tool["digest"], str):
            _err("tool.digest must be a string")

    # -- execution -----------------------------------------------------------
    execution = result.get("execution")
    if not isinstance(execution, Mapping):
        _err("execution must be an object")
    else:
        for key in _MIRROR_EXEC_REQUIRED:
            if key not in execution:
                _err(f"execution.required: {key}")
        if not isinstance(execution.get("argv_digest"), str):
            _err("execution.argv_digest must be a string")
        for key in ("started_at", "ended_at"):
            if key in execution and not _mirror_iso_datetime(execution[key]):
                _err(f"execution.{key} must be an ISO-8601 date-time")
        if "timeout_s" in execution and (
                not _mirror_int(execution["timeout_s"])
                or execution["timeout_s"] < 1):
            _err("execution.timeout_s must be an integer >= 1")
        if not _mirror_int(execution.get("actual_exit_code")):
            _err("execution.actual_exit_code must be an integer")
        expected = execution.get("expected_exit_set")
        if not isinstance(expected, list) or not all(
                _mirror_int(x) for x in expected):
            _err("execution.expected_exit_set must be an array of integers")
        if execution.get("assertion_verdict") not in _MIRROR_ASSERTION:
            _err("execution.assertion_verdict must be one of "
                 f"{sorted(_MIRROR_ASSERTION)}")
        if "cwd_digest" in execution and not isinstance(
                execution["cwd_digest"], str):
            _err("execution.cwd_digest must be a string")

    # -- coverage（可选；PASS 时必填并升级约束）------------------------------
    coverage = result.get("coverage") if "coverage" in result else None
    if "coverage" in result:
        if not isinstance(coverage, Mapping):
            _err("coverage must be an object")
        else:
            for key in ("denominator", "scanned"):
                if key not in coverage:
                    _err(f"coverage.required: {key}")
                elif not _mirror_int(coverage[key]) or coverage[key] < 0:
                    _err(f"coverage.{key} must be an integer >= 0")
            if "exclusions" in coverage and (
                    not isinstance(coverage["exclusions"], list)
                    or not all(isinstance(x, str)
                               for x in coverage["exclusions"])):
                _err("coverage.exclusions must be an array of strings")

    # -- finding_ids / artifacts ---------------------------------------------
    if "finding_ids" in result and (
            not isinstance(result["finding_ids"], list)
            or not all(isinstance(x, str) for x in result["finding_ids"])):
        _err("finding_ids must be an array of strings")
    artifacts = result.get("artifacts") if "artifacts" in result else None
    if "artifacts" in result:
        if not isinstance(artifacts, list):
            _err("artifacts must be an array")
        else:
            for idx, item in enumerate(artifacts):
                if not isinstance(item, Mapping):
                    _err(f"artifacts[{idx}] must be an object")
                    continue
                for key in ("cas_digest", "size"):
                    if key not in item:
                        _err(f"artifacts[{idx}].required: {key}")
                digest = item.get("cas_digest")
                if not isinstance(digest, str) or not _MIRROR_CAS_RE.match(digest):
                    _err(f"artifacts[{idx}].cas_digest must match "
                         "^sha256:[0-9a-f]{64}$")
                if not _mirror_int(item.get("size")) or item["size"] < 1:
                    _err(f"artifacts[{idx}].size must be an integer >= 1")

    # -- allOf 跨字段 #1：PASS 分支（schema PASS if-then 的全量镜像）----------
    if result.get("policy_verdict") == "PASS":
        if "coverage" not in result:
            _err("PASS requires coverage")
        if "artifacts" not in result:
            _err("PASS requires artifacts")
        if isinstance(coverage, Mapping) and _mirror_int(
                coverage.get("denominator")) and _mirror_int(
                coverage.get("scanned")):
            if coverage["denominator"] < 1:
                _err("PASS coverage.denominator must be >= 1")
            if coverage["scanned"] < 1:
                _err("PASS coverage.scanned must be >= 1")
            # F4-SCHEMA-001 #2（分母缩水）：PASS 必须 scanned == denominator
            # （schema 侧 const 级联 1..64 的无界镜像）
            if coverage["scanned"] != coverage["denominator"]:
                _err("PASS coverage.scanned("
                     f"{coverage['scanned']}) != denominator("
                     f"{coverage['denominator']}) — denominator shrinkage")
        if isinstance(artifacts, list) and len(artifacts) < 1:
            _err("PASS requires non-empty artifacts (minItems 1)")
        if isinstance(execution, Mapping):
            if "actual_exit_code" in execution and (
                    execution["actual_exit_code"] != 0):
                _err("PASS requires execution.actual_exit_code == 0")
            if "assertion_verdict" in execution and (
                    execution["assertion_verdict"] != "PASS"):
                _err("PASS requires execution.assertion_verdict == PASS")
        # F4-SCHEMA-001 #5（station 侧）：PASS 必须执行完成
        if result.get("execution_status") != "COMPLETED":
            _err("PASS requires execution_status COMPLETED")

    # -- allOf 跨字段 #2：执行非完成态只允许阻断类裁决 ------------------------
    # （F4-SCHEMA-001 #5：TIMEOUT+CONDITIONAL / TIMEOUT+PASS 等双轴洗白全拒）
    if result.get("execution_status") in _MIRROR_EXEC_HARD and (
            result.get("policy_verdict") is not None
            and result.get("policy_verdict")
            not in _MIRROR_HARD_EXEC_VERDICTS):
        _err(f"execution_status {result['execution_status']} forbids "
             f"policy_verdict {result.get('policy_verdict')} "
             "(only FAIL/NOT_EVALUATED allowed)")

    return errors


class GateAggregator:
    """消费 station-result JSON（v2 正式契约优先、legacy 兼容），输出整线统一 gate 判定。

    用法::

        agg = GateAggregator(required_stations={"2", "7"},   # v2 站点键 = str(station_id)
                             target_sha="abc...", environment="staging")
        agg.add(station_result_v2).add(...)
        verdict = agg.aggregate()          # 含 generated_at/policy_verdict（dashboard 契约）
        status = agg.to_github_status()    # {"state": ..., "conclusion": ..., "description": ...}

    required_stations 兼容 int 站点号（自动归一为字符串键，如 2 -> "2"）。
    """

    def __init__(self, required_stations: Set[str], target_sha: str, environment: str) -> None:
        target_sha = str(target_sha or "").strip().lower()
        if not target_sha:
            raise ValueError("target_sha is required: gate evidence must be bound to a SHA")
        if not isinstance(environment, str) or not environment:
            raise ValueError("environment is required: gate evidence must be bound to an environment")

        self.required_stations: frozenset = frozenset(
            str(s).strip() for s in required_stations
            if isinstance(s, (str, int)) and not isinstance(s, bool) and str(s).strip()
        )
        self.target_sha: str = target_sha
        self.environment: str = environment

        # 内部登记簿
        self._stations: Dict[str, Dict[str, Any]] = {}
        self._duplicates: List[str] = []
        self._conflicts: List[Dict[str, Any]] = []
        self._malformed: List[Dict[str, Any]] = []
        self._sha_violations: List[Dict[str, Any]] = []
        self._env_violations: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 登记阶段
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_outcome(raw: Any) -> str:
        """归一化 legacy outcome；未知/缺失一律按 BLOCKED（硬失败），绝不猜成好结果。"""
        token = str(raw if raw is not None else "").strip().upper()
        if token in _PASS_ALIASES:
            return PASS
        if token in _CONDITIONAL_ALIASES:
            return CONDITIONAL
        return BLOCKED

    @staticmethod
    def _is_v2(station_result: Mapping) -> bool:
        """v2 判别：显式 schema_version=2.0，或出现 v2 正式字段组合。"""
        if str(station_result.get("schema_version", "")).strip() == _V2_SCHEMA_VERSION:
            return True
        return "station_id" in station_result and (
            "policy_verdict" in station_result or "execution_status" in station_result
        )

    def _parse_v2(self, station_result: Mapping) -> Dict[str, Any]:
        """解析 v2 条目为内部登记结构；结构必须严格（F4-GATE-001 根修）。

        先过 mirror_validate_station_result_v2（schema 全量镜像）：schema-invalid
        记一条 consolidated malformed（含违例明细），该站 outcome 强制 BLOCKED；
        identity/sha/environment 仍按现有方式尽力提取，供 C2/C5 证据绑定裁决
        （缺什么补什么违规——绝不因结构残缺而漏记账）。
        """
        schema_errors = mirror_validate_station_result_v2(station_result)
        sid = station_result.get("station_id")
        if not isinstance(sid, int) or isinstance(sid, bool):
            self._malformed.append({
                "reason": "missing_field:station_id",
                "entry_keys": sorted(map(str, station_result.keys())),
            })
            return {}
        station = str(sid)

        if schema_errors:
            self._malformed.append({
                "reason": "schema_invalid: " + schema_errors[0],
                "station": station,
                "schema_violations": schema_errors[:8],
                "schema_violation_count": len(schema_errors),
            })

        execution_status = str(station_result.get("execution_status") or "").strip().upper()
        policy_verdict = str(station_result.get("policy_verdict") or "").strip().upper()

        identity = station_result.get("identity")
        sha = ""
        environment = None
        if isinstance(identity, Mapping):
            raw_sha = identity.get("commit_sha")
            if isinstance(raw_sha, str) and raw_sha.strip():
                sha = raw_sha.strip().lower()
            env_raw = identity.get("environment")
            if isinstance(env_raw, str):
                environment = env_raw
        else:
            # identity 缺失/非对象——schema_invalid 已记账（镜像 required:identity），
            # 这里继续提取其余字段并保持 C5 记账（宽松读不炸，聚合时 BLOCKED）
            if not schema_errors:
                self._malformed.append({
                    "reason": "missing_field:identity" if identity is None
                    else "malformed_field:identity",
                    "station": station,
                })

        # 铁律 2：执行未完成（ERROR/BLOCKED/TIMEOUT/CANCELLED）→ 整站硬失败
        if schema_errors:
            # F4-GATE-001：schema-invalid 输入不具可信形态——该站一律硬失败
            outcome = BLOCKED
            outcome_raw = "SCHEMA_INVALID"
        elif execution_status in _V2_EXEC_HARD_FAIL:
            outcome = BLOCKED
            outcome_raw = f"{execution_status}/{policy_verdict or '-'}"
        elif execution_status == "COMPLETED":
            outcome = _V2_VERDICT_MAP.get(policy_verdict, BLOCKED)
            outcome_raw = f"{execution_status}/{policy_verdict or '-'}"
        else:
            # execution_status 缺失/未知（宽松读不炸）——fail-closed 硬失败
            outcome = BLOCKED
            outcome_raw = f"{execution_status or '-'}/{policy_verdict or '-'}"

        if not schema_errors:
            # 枚举合法性已由镜像覆盖（schema_invalid 时不再重复记账，避免噪声）
            if execution_status and execution_status not in _V2_EXECUTION_STATUS:
                self._malformed.append({
                    "reason": f"invalid_field:execution_status:{execution_status}",
                    "station": station,
                })
            if policy_verdict and policy_verdict not in _V2_POLICY_VERDICTS:
                self._malformed.append({
                    "reason": f"invalid_field:policy_verdict:{policy_verdict}",
                    "station": station,
                })

        return {
            "station": station,
            "outcome": outcome,
            "outcome_raw": outcome_raw,
            "sha": sha,
            "environment": environment,
            "required": station in self.required_stations,
            "input_version": "v2",
            "execution_status": execution_status or None,
            "policy_verdict_raw": policy_verdict or None,
            "schema_valid": not schema_errors,
        }

    def _parse_legacy(self, station_result: Mapping) -> Dict[str, Any]:
        """解析 legacy 条目（station/outcome/sha/environment）为内部登记结构。"""
        station = station_result.get("station")
        if not isinstance(station, str) or not station.strip():
            self._malformed.append({
                "reason": "missing_field:station",
                "entry_keys": sorted(map(str, station_result.keys())),
            })
            return {}
        station = station.strip()

        outcome = station_result.get("outcome")
        sha = ""
        for field in _SHA_FIELDS:
            value = station_result.get(field)
            if isinstance(value, str) and value.strip():
                sha = value.strip().lower()
                break
        environment = station_result.get("environment")

        return {
            "station": station,
            "outcome": self._normalize_outcome(outcome),
            "outcome_raw": str(outcome if outcome is not None else "").strip(),
            "sha": sha,
            "environment": environment,
            "required": station in self.required_stations,
            "input_version": "legacy",
            "execution_status": None,
            "policy_verdict_raw": None,
            "schema_valid": True,
        }

    def add(self, station_result: dict) -> "GateAggregator":
        """登记一条 station-result（v2 或 legacy 自动判别）；返回 self 以便链式调用。

        v2 条目先过镜像校验器（F4-GATE-001）：schema-invalid 一律记 malformed
        并强制该站 BLOCKED——聚合输出必为 BLOCKED、technical_eligible=false。

        重复站点：内容完全一致视为幂等上报（忽略）；不一致视为冲突证据，
        两者都会在 aggregate() 时以 BLOCKED 或备注形式体现，绝不静默择优。
        """
        if not isinstance(station_result, Mapping):
            self._malformed.append(
                {"reason": "not_a_json_object", "entry": repr(station_result)[:200]}
            )
            return self

        if self._is_v2(station_result):
            entry = self._parse_v2(station_result)
        else:
            entry = self._parse_legacy(station_result)
        if not entry:
            return self  # 已记 malformed，aggregate() 时 BLOCKED
        station = entry["station"]

        previous = self._stations.get(station)
        if previous is not None:
            identical = (
                previous["outcome"] == entry["outcome"]
                and previous["sha"] == entry["sha"]
                and previous["environment"] == entry["environment"]
            )
            if identical:
                self._duplicates.append(station)
            else:
                self._conflicts.append({"station": station, "first": previous, "second": entry})
            return self  # 首条为准；冲突已记账，aggregate() 时 BLOCKED

        self._stations[station] = entry

        # C2：SHA 证据绑定（缺失同样无法绑定 -> 违规）
        if entry["sha"] != self.target_sha:
            self._sha_violations.append({
                "station": station,
                "reason": "missing_sha" if not entry["sha"] else "sha_mismatch",
                "sha": entry["sha"] or None,
                "expected": self.target_sha,
            })
        # C5：环境证据绑定（缺失同样无法绑定 -> 违规）
        if entry["environment"] != self.environment:
            self._env_violations.append({
                "station": station,
                "reason": "missing_environment" if entry["environment"] is None else "environment_mismatch",
                "environment": entry["environment"],
                "expected": self.environment,
            })
        return self

    # ------------------------------------------------------------------ #
    # 判定阶段
    # ------------------------------------------------------------------ #
    def aggregate(self) -> Dict[str, Any]:
        """聚合为统一 gate 判定；不修改登记状态（generated_at 为当下时刻）。"""
        reasons: List[str] = []
        hard = False

        def block(reason: str) -> None:
            nonlocal hard
            hard = True
            reasons.append(reason)

        # 1) C2/C5：证据完整性硬门
        if self._sha_violations:
            detail = "; ".join(f"{v['station']}:{v['reason']}" for v in self._sha_violations)
            block(f"sha_evidence_violation [{detail}]")
        if self._env_violations:
            detail = "; ".join(f"{v['reason']}" for v in self._env_violations)
            stations = ",".join(sorted({v["station"] for v in self._env_violations}))
            block(f"environment_evidence_violation [{stations}] ({detail})")
        if self._malformed:
            block(f"malformed_station_result x{len(self._malformed)} "
                  f"[first={self._malformed[0]['reason']}]")
        if self._conflicts:
            names = ",".join(sorted({c["station"] for c in self._conflicts}))
            block(f"duplicate_station_conflict [{names}]")

        # 2) C3：分母缩水（required 站未全部上报）；空 required 同样拒绝（无真空 PASS）
        reported = set(self._stations)
        missing_required = sorted(self.required_stations - reported)
        bypass_reported = sorted(reported - self.required_stations)
        if missing_required or not self.required_stations:
            if not self.required_stations:
                block("denominator_shrinkage: no required stations configured "
                      "(refusing vacuous PASS)")
            else:
                block("denominator_shrinkage: missing required stations [" +
                      ",".join(missing_required) + "]")

        # 3) 站点硬失败（required 或旁路站一视同仁；未知 outcome 已归入硬失败）
        hard_failed = sorted(s for s, e in self._stations.items() if e["outcome"] == BLOCKED)
        if hard_failed:
            block("station_hard_failure [" + ",".join(hard_failed) + "]")

        # 4) C4：条件项（软，不 block 但整线不得为 PASS）
        conditional = sorted(s for s, e in self._stations.items() if e["outcome"] == CONDITIONAL)
        if conditional:
            reasons.append("conditional_stations [" + ",".join(conditional) + "]")

        if hard:
            outcome = BLOCKED
        elif conditional:
            outcome = CONDITIONAL
        else:
            outcome = PASS

        if not self.required_stations:
            reason = "BLOCKED: no required stations configured — refusing vacuous PASS (P0-3 fix)"
        elif outcome == PASS:
            reason = f"all {len(self.required_stations)} required stations PASS"
        else:
            reason = reasons[0] if reasons else outcome

        stations_summary = {
            s: {
                "outcome": e["outcome"],
                "required": e["required"],
                "sha_bound": e["sha"] == self.target_sha,
                "environment_ok": e["environment"] == self.environment,
                "input_version": e["input_version"],
                "schema_valid": e.get("schema_valid", True),
            }
            for s, e in sorted(self._stations.items())
        }

        return {
            # dashboard/server.py read_gate_aggregate() 强制要求的契约字段（P0-3 修）
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "policy_verdict": outcome,
            # 原有字段（保持稳定）
            "aggregate_outcome": outcome,
            "technical_eligible": (not hard) and outcome == PASS,
            "reason": reason,
            "reasons": reasons,
            "counts": {
                "required_total": len(self.required_stations),
                "required_reported": len(self.required_stations & reported),
                "required_missing": len(missing_required),
                "bypass_stations": len(bypass_reported),
                "duplicates_ignored": len(self._duplicates),
                "conflicts": len(self._conflicts),
                "malformed": len(self._malformed),
            },
            "stations": stations_summary,
            "target_sha": self.target_sha,
            "environment": self.environment,
        }

    def to_github_status(self, aggregate_result: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """映射为 GitHub 状态：Commit Status `state` + Checks API `conclusion` 双口径。

        映射表（CONDITIONAL 绝不上绿，见 C4）：
            PASS->success/success；CONDITIONAL->failure/action_required；BLOCKED->failure/failure
        """
        result = aggregate_result if aggregate_result is not None else self.aggregate()
        outcome = result.get("aggregate_outcome", BLOCKED)
        state, conclusion = _GITHUB_STATE.get(outcome, ("failure", "failure"))
        description = f"gate {outcome}: {result.get('reason', '')}".strip()
        return {
            "state": state,                    # Commit Status API: success/failure/pending/error
            "conclusion": conclusion,          # Checks API conclusion
            "description": description[:140],  # GitHub description 上限 140 字符
            "context": f"wenqu-gate/{self.environment}",
            "target_sha": self.target_sha,
        }

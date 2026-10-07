# -*- coding: utf-8 -*-
"""统一 Gate 聚合器（Codex W3B）。

消费流水线各 station 产出的 station-result JSON，聚合为整线统一的 gate 判定。

station-result 输入契约（add() 的每个元素）::

    {
      "station":     "lint",        # 必填：站点名（required_stations 成员或旁路站点）
      "outcome":     "PASS",        # 必填：见下方别名表；未知/缺失一律按硬失败
      "sha":         "<full-sha>",  # 必填（亦接受 target_sha / commit_sha）
      "environment": "staging",     # 必填：须与构造器 environment 完全一致
    }

outcome 别名表（大小写不敏感）：
    PASS/PASSED/OK/SUCCESS/GREEN                            -> PASS
    CONDITIONAL/WARN/WARNING/SOFT_PASS/PASS_WITH_WARNINGS   -> CONDITIONAL
    FAIL/FAILED/FAILURE/ERROR/BLOCKED/TIMEOUT/未知/缺失     -> 硬失败（整线 BLOCKED）

硬约束（不可降级）：
    C1 任一 required 站非 PASS -> 整线非 PASS；
    C2 任一站点证据 SHA 与 target_sha 不一致（或缺失、无法绑定目标）-> BLOCKED；
    C3 分母缩水：required 站未全部上报 -> BLOCKED；
    C4 CONDITIONAL != PASS：条件通过永不映射为绿判定 / GitHub success；
    C5 环境不一致 / 结构残缺 / 同站冲突证据 -> BLOCKED（宁可阻断，不猜证据）。

technical_eligible 语义：True 仅表示技术硬门（C2/C3/C5 及“无任何站点硬失败”）全部
通过；与 aggregate_outcome == PASS 不等价——CONDITIONAL 时 technical_eligible 可为
True，但放行判断必须且只能以 aggregate_outcome == PASS 为准。

GitHub 状态映射（to_github_status）：
    PASS        -> state=success  / conclusion=success
    CONDITIONAL -> state=failure  / conclusion=action_required  # 条件项须人工处置，绝不上绿
    BLOCKED     -> state=failure  / conclusion=failure
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Set

__all__ = ["GateAggregator", "PASS", "CONDITIONAL", "BLOCKED"]

PASS = "PASS"
CONDITIONAL = "CONDITIONAL"
BLOCKED = "BLOCKED"

_PASS_ALIASES = frozenset({"PASS", "PASSED", "OK", "SUCCESS", "GREEN"})
_CONDITIONAL_ALIASES = frozenset(
    {"CONDITIONAL", "WARN", "WARNING", "SOFT_PASS", "PASS_WITH_WARNINGS"}
)
_SHA_FIELDS = ("sha", "target_sha", "commit_sha")

_GITHUB_STATE = {
    PASS: ("success", "success"),
    CONDITIONAL: ("failure", "action_required"),
    BLOCKED: ("failure", "failure"),
}


class GateAggregator:
    """消费 station-result JSON，输出整线统一 gate 判定。

    用法::

        agg = GateAggregator(required_stations={"lint", "test"},
                             target_sha="abc...", environment="staging")
        agg.add(station_result_1).add(station_result_2)
        verdict = agg.aggregate()          # aggregate_outcome / technical_eligible / reason ...
        status = agg.to_github_status()    # {"state": ..., "conclusion": ..., "description": ...}
    """

    def __init__(self, required_stations: Set[str], target_sha: str, environment: str) -> None:
        target_sha = str(target_sha or "").strip().lower()
        if not target_sha:
            raise ValueError("target_sha is required: gate evidence must be bound to a SHA")
        if not isinstance(environment, str) or not environment:
            raise ValueError("environment is required: gate evidence must be bound to an environment")

        self.required_stations: frozenset = frozenset(
            s.strip() for s in required_stations if isinstance(s, str) and s.strip()
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
        """归一化 outcome；未知/缺失一律按 BLOCKED（硬失败）处理，绝不猜成好结果。"""
        token = str(raw if raw is not None else "").strip().upper()
        if token in _PASS_ALIASES:
            return PASS
        if token in _CONDITIONAL_ALIASES:
            return CONDITIONAL
        return BLOCKED

    def add(self, station_result: dict) -> "GateAggregator":
        """登记一条 station-result；返回 self 以便链式调用。

        重复站点：内容完全一致视为幂等上报（忽略）；不一致视为冲突证据，
        两者都会在 aggregate() 时以 BLOCKED 或备注形式体现，绝不静默择优。
        """
        if not isinstance(station_result, Mapping):
            self._malformed.append(
                {"reason": "not_a_json_object", "entry": repr(station_result)[:200]}
            )
            return self

        station = station_result.get("station")
        if not isinstance(station, str) or not station.strip():
            self._malformed.append({
                "reason": "missing_field:station",
                "entry_keys": sorted(map(str, station_result.keys())),
            })
            return self
        station = station.strip()

        outcome = station_result.get("outcome")
        sha = ""
        for field in _SHA_FIELDS:
            value = station_result.get(field)
            if isinstance(value, str) and value.strip():
                sha = value.strip().lower()
                break
        environment = station_result.get("environment")

        entry = {
            "station": station,
            "outcome": self._normalize_outcome(outcome),
            "outcome_raw": str(outcome if outcome is not None else "").strip(),
            "sha": sha,
            "environment": environment,
            "required": station in self.required_stations,
        }

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
        if sha != self.target_sha:
            self._sha_violations.append({
                "station": station,
                "reason": "missing_sha" if not sha else "sha_mismatch",
                "sha": sha or None,
                "expected": self.target_sha,
            })
        # C5：环境证据绑定（缺失同样无法绑定 -> 违规）
        if environment != self.environment:
            self._env_violations.append({
                "station": station,
                "reason": "missing_environment" if environment is None else "environment_mismatch",
                "environment": environment,
                "expected": self.environment,
            })
        return self

    # ------------------------------------------------------------------ #
    # 判定阶段
    # ------------------------------------------------------------------ #
    def aggregate(self) -> Dict[str, Any]:
        """聚合为统一 gate 判定；纯计算，不修改登记状态。"""
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

        # 2) C3：分母缩水（required 站未全部上报）
        reported = set(self._stations)
        missing_required = sorted(self.required_stations - reported)
        bypass_reported = sorted(reported - self.required_stations)
        if missing_required:
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

        if outcome == PASS and self.required_stations:
            reason = f"all {len(self.required_stations)} required stations PASS"
        elif outcome == PASS:
            reason = "vacuous pass: no required stations configured"
        else:
            reason = reasons[0] if reasons else outcome

        stations_summary = {
            s: {
                "outcome": e["outcome"],
                "required": e["required"],
                "sha_bound": e["sha"] == self.target_sha,
                "environment_ok": e["environment"] == self.environment,
            }
            for s, e in sorted(self._stations.items())
        }

        return {
            "aggregate_outcome": outcome,
            "technical_eligible": not hard,
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

# -*- coding: utf-8 -*-
"""station6_adversarial.py——Codex 方案 W6D：Bug 八站·站6 对抗面（最小真实语义）。

血统与契约正源：
- Codex 方案 §7.1 八站表·站6 对抗：「S3/S5、属性、变异、并发、乱序、
  越权」，required 证据=「独立证据源工件」；
- Codex 方案 W6D：站6=属性、变异、并发、乱序、重复提交、S3/S5；
- 《问渠轨道规范（发行版 v2.0）》§1 站6 判据：pass=每轴必问全覆盖+零发现
  结论出自 ≥2 独立上下文（二审定律）；fail=轴覆盖缺失/单上下文零发现声明；
  error=异源端点宕机（降级须登记豁免，恢复后补一次异源审）；
- schemas/station-result-v2.schema.json：结果严格合规。

诚实边界（为何这是「最小真实语义」而非占位）：
- 反方评审本体（S3 对抗/S5 独立审计的推理过程）无法在扫描器内机器化——
  由 ``wenqu charter`` 向异构端点发射、``wenqu ingest`` 回收产物（注册表
  entry）。本扫描器消费回收后的真实产物账本，做机器可判定面：
  (a) 登记完整性——每个上下文的 source_identity/kind/captured_at/逐轴
  回答齐备（结构损坏 fail-closed 拒绝）；
  (b) 每轴必问——对抗轴清单内每一轴必须被每个在场上下文真实问过
  （asked=True；缺失=轴覆盖缺失→FAIL 落账）；
  (c) 二审定律——零发现结论必须出自 ≥2 个 source_identity 互异的独立
  上下文（§15.7「不允许同命令换标签算异源」：同 source_identity 只计一）；
  (d) 日落合规——证据时效按注册表 TTL（站6 evidence_class=
  permission_vulnerability→7 天）执法，过期上下文不采信（铁律 4）；
  (e) 异源端点在场——required_kinds 声明的异源 kind（默认 S3 对抗+S5
  独立审计）缺任一 → BLOCKED（注册表 error 判据：降级须登记豁免）。
  即「登记+状态汇总」扫描器：不伪造对抗推理，只对账本做完整性与合规判定。

上下文（评审产物）契约（结构损坏=AdversarialLedgerMalformed）::

    {
      "context_id": "s3-cc-20261009",       # 非空，账本内唯一
      "kind": "s3_adversarial",             # 评审上下文类型（非空）
      "source_identity": "claude-code/oppo",# 异源身份：同值只计一个独立源
      "captured_at": "2026-10-09T01:00:00Z",# ISO-8601（TTL 时效锚点）
      "answers": {                          # 每轴必问：axis → 回答记录
          "auth-bypass": {"asked": True,
                          "findings": [{"summary": "…", "severity": "HIGH"}]},
      },
    }

覆盖口径（注册表 coverage_denominator=对抗轴问题数（每轴必问））：
- denominator = 对抗轴数；scanned = 完成判定的轴数。账本结构合法时每轴
  都能判定「被问/被漏问」（判得出才算扫到——站7 同一哲学），故
  scanned==denominator；漏问的轴以 FAIL+finding 呈现而非缩水 BLOCKED
  （注册表 fail 判据：轴覆盖缺失）。

判定矩阵（冻结）：
- required kind 缺席 / 全部上下文过期 → BLOCKED + NOT_EVALUATED
  （异源端点宕机——降级须登记豁免，恢复后补一次异源审）；
- 任一轴被任一在场上下文漏问 → COMPLETED + FAIL（轴覆盖缺失）+ 逐轴
  finding；
- 零发现 且 独立上下文（互异 source_identity）<2 → COMPLETED + FAIL
  （单上下文零发现声明——二审定律）；
- 对抗发现 >0 → COMPLETED + FAIL + 逐发现 finding 落账（对齐站2 探测器
  命中语义：发现=待裁定缺陷，站级不得绿；裁定关闭后重跑可恢复）；
- 每轴必问全覆盖 + 零发现 + ≥2 独立上下文 → COMPLETED + PASS
  （coverage 满分 + 非空 artifacts，schema P0-4 硬约束）。

安全构造（by construction）：
- 纯 stdlib；无外部命令、无 shell、无 eval/exec——判定全部进程内完成
  （RunManifest.to_station_result / 站7 进程内腿同一先例，
  actual_exit_code=0 只表示判定逻辑自身正常结束）。
- 身份三源一律取冻结 manifest 正源，绝不采信账本自报身份。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .bugscan_orchestrator import (
    RunManifest,
    default_registry,
    build_station_result,
    validate_station_result,
)
from .runner import TrustedRunner

__all__ = [
    "STATION_ID",
    "COUNTS_TOWARD_CONVERGENCE",
    "BLOCKS_RELEASE",
    "DEFAULT_REQUIRED_KINDS",
    "VALID_SEVERITIES",
    "AdversarialStationError",
    "AdversarialLedgerMalformed",
    "AdversarialSpecError",
    "AdversarialReviewScanner",
    "scan_station6",
]

__version__ = "1.0.0"

STATION_ID = 6

#: 站6 计入收敛轮（INCIDENT 档 required 成员；注册表 LANE_REQUIRED_STATIONS）。
COUNTS_TOWARD_CONVERGENCE: bool = True

#: 站6 可阻断发布：轴覆盖缺失/单上下文零发现/异源缺席时发布门不得放行。
BLOCKS_RELEASE: bool = True

#: 默认必须到场的异源上下文类型（方案 §7.1/W6D：站6=S3/S5）。
DEFAULT_REQUIRED_KINDS: Tuple[str, ...] = ("s3_adversarial", "s5_independent_audit")

#: 对抗发现严重级白名单（与站2/站3 finding 语义对齐）。
VALID_SEVERITIES: Tuple[str, ...] = ("HIGH", "MEDIUM", "LOW")


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class AdversarialStationError(ValueError):
    """站6 适配器基类错误——一律 fail-closed。"""


class AdversarialSpecError(AdversarialStationError):
    """扫描规格非法：轴清单为空/重复、required_kinds 形态非法。"""


class AdversarialLedgerMalformed(AdversarialStationError):
    """评审产物账本结构性损坏：缺字段、context_id 重复、answers 形态非法。"""


# ---------------------------------------------------------------------------
# 基础工具（与 station5/station7 同算法的本地实现，保持模块自包含）
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_obj(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _sha256_hex(canonical.encode("utf-8"))


def _parse_ts(value: Any, what: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise AdversarialLedgerMalformed(f"{what} must be a non-empty ISO-8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as err:
        raise AdversarialLedgerMalformed(f"{what} is not ISO-8601: {value!r}") from err
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _attempt_id(run_id: str, tag: str) -> str:
    seed = _hash_obj({"run_id": run_id, "tag": tag, "ts": _iso_z(_utc_now())})
    return f"att-{tag}-{seed[:12]}"


def _finding_id(prefix: str, seed: str) -> str:
    safe = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in prefix)
    return f"fnd_{safe}_{_sha256_hex(seed.encode('utf-8'))[:12]}"


def _require_manifest(manifest: RunManifest) -> RunManifest:
    if not isinstance(manifest, RunManifest):
        raise AdversarialStationError(
            f"manifest must be RunManifest, got {type(manifest).__name__}"
        )
    return manifest


def _manifest_identity(manifest: RunManifest) -> Dict[str, Any]:
    """身份三源一律取冻结 manifest 正源，绝不采信账本自报身份。"""
    identity: Dict[str, Any] = {
        "project_id": manifest.project_id,
        "commit_sha": manifest.commit_sha,
        "environment": manifest.environment,
        "scope_hash": manifest.scope_hash,
        "ruleset_hash": manifest.ruleset_hash,
        "data_config_hash": manifest.data_config_hash,
    }
    if manifest.lockfile_hash:
        identity["lockfile_hash"] = manifest.lockfile_hash
    return identity


def _cas_artifact(payload: bytes) -> Optional[Dict[str, Any]]:
    """字节载荷 → CAS 工件条目；空载荷（0B）无证据价值，返回 None。"""
    if not payload:
        return None
    return {"cas_digest": f"sha256:{_sha256_hex(payload)}", "size": len(payload)}


# ---------------------------------------------------------------------------
# AdversarialReviewScanner——站6 唯一入口：对抗产物账本登记+状态汇总
# ---------------------------------------------------------------------------


class AdversarialReviewScanner:
    """站6 对抗面扫描器：对回收的评审产物账本做登记完整性与合规判定。

    用法::

        scanner = AdversarialReviewScanner(
            manifest,
            axes=["auth-bypass", "mutation", "concurrency"],
            contexts=[{...上下文契约...}, ...],
        )
        station_result = scanner.scan()   # station-result-v2

    - ``axes``：对抗轴问题清单（每轴必问；空清单/重复轴 → SpecError）；
    - ``contexts``：``wenqu ingest`` 回收的评审产物（结构损坏 →
      AdversarialLedgerMalformed fail-closed，不产出任何结果）；
    - ``required_kinds``：必须到场的异源上下文类型（默认 S3+S5；缺任一
      → BLOCKED——注册表 error 判据）；
    - ``ttl_days``：证据时效（默认取注册表站6 TTL=7 天，铁律 4 正源）。
    """

    STATION_ID = STATION_ID

    def __init__(
        self,
        manifest: RunManifest,
        *,
        axes: Iterable[str],
        contexts: Iterable[Mapping[str, Any]] = (),
        required_kinds: Iterable[str] = DEFAULT_REQUIRED_KINDS,
        ttl_days: Optional[int] = None,
        now: Optional[datetime] = None,
    ) -> None:
        _require_manifest(manifest)
        self._manifest = manifest
        self._now = now or _utc_now()
        self._ttl_days = (
            ttl_days if ttl_days is not None
            else default_registry().get(STATION_ID).ttl_days
        )
        if (isinstance(self._ttl_days, bool) or not isinstance(self._ttl_days, int)
                or self._ttl_days < 1):
            raise AdversarialSpecError(
                f"ttl_days must be a positive int, got {self._ttl_days!r}")

        axis_list = [a for a in axes or ()]
        if not axis_list or any(not isinstance(a, str) or not a.strip()
                                for a in axis_list):
            raise AdversarialSpecError(
                "axes must contain at least one non-empty question axis"
                "（对抗轴问题清单为空=分母真空，禁止 vacuous 判定）")
        if len(set(axis_list)) != len(axis_list):
            raise AdversarialSpecError("axes contains duplicate entries")
        self._axes: Tuple[str, ...] = tuple(a.strip() for a in axis_list)

        kinds = tuple(required_kinds)
        if not kinds or any(not isinstance(k, str) or not k.strip() for k in kinds):
            raise AdversarialSpecError(
                "required_kinds must be non-empty strings")
        if len(set(kinds)) != len(kinds):
            raise AdversarialSpecError("required_kinds contains duplicates")
        self._required_kinds: Tuple[str, ...] = kinds

        self._contexts: List[Dict[str, Any]] = [
            self._validate_context(dict(c), i) for i, c in enumerate(contexts or ())
        ]
        seen_ids = set()
        for ctx in self._contexts:
            if ctx["context_id"] in seen_ids:
                raise AdversarialLedgerMalformed(
                    f"duplicate context_id: {ctx['context_id']!r}")
            seen_ids.add(ctx["context_id"])
        self.last_breakdown: Dict[str, Any] = {}

    # -- 结构校验（fail-closed：损坏即抛，不产出结果） -----------------------

    @classmethod
    def _validate_context(cls, ctx: Mapping[str, Any], index: int) -> Dict[str, Any]:
        if not isinstance(ctx, Mapping):
            raise AdversarialLedgerMalformed(
                f"contexts[{index}] must be a mapping, got {type(ctx).__name__}"
            )
        for field in ("context_id", "kind", "source_identity"):
            value = ctx.get(field)
            if not isinstance(value, str) or not value.strip():
                raise AdversarialLedgerMalformed(
                    f"contexts[{index}].{field} must be a non-empty string"
                )
        captured_at = _parse_ts(ctx.get("captured_at"),
                                f"contexts[{index}].captured_at")
        answers = ctx.get("answers")
        if not isinstance(answers, Mapping) or not answers:
            raise AdversarialLedgerMalformed(
                f"contexts[{index}].answers must be a non-empty mapping "
                "{axis: {\"asked\": bool, \"findings\": [...]}}"
            )
        parsed_answers: Dict[str, Dict[str, Any]] = {}
        for axis, answer in answers.items():
            if not isinstance(axis, str) or not axis.strip():
                raise AdversarialLedgerMalformed(
                    f"contexts[{index}].answers key must be a non-empty axis name"
                )
            if not isinstance(answer, Mapping):
                raise AdversarialLedgerMalformed(
                    f"contexts[{index}].answers[{axis!r}] must be a mapping"
                )
            asked = answer.get("asked")
            if not isinstance(asked, bool):
                raise AdversarialLedgerMalformed(
                    f"contexts[{index}].answers[{axis!r}].asked must be a bool"
                )
            findings_raw = answer.get("findings", [])
            if not isinstance(findings_raw, (list, tuple)):
                raise AdversarialLedgerMalformed(
                    f"contexts[{index}].answers[{axis!r}].findings must be a list"
                )
            findings: List[Dict[str, str]] = []
            for j, f in enumerate(findings_raw):
                if not isinstance(f, Mapping):
                    raise AdversarialLedgerMalformed(
                        f"contexts[{index}].answers[{axis!r}].findings[{j}] "
                        "must be a mapping"
                    )
                summary = f.get("summary")
                severity = f.get("severity", "HIGH")
                if not isinstance(summary, str) or not summary.strip():
                    raise AdversarialLedgerMalformed(
                        f"contexts[{index}].answers[{axis!r}].findings[{j}].summary "
                        "must be a non-empty string"
                    )
                if severity not in VALID_SEVERITIES:
                    raise AdversarialLedgerMalformed(
                        f"contexts[{index}].answers[{axis!r}].findings[{j}].severity "
                        f"must be one of {list(VALID_SEVERITIES)}, got {severity!r}"
                    )
                findings.append({"summary": summary, "severity": severity})
            parsed_answers[axis.strip()] = {"asked": asked, "findings": findings}
        return {
            "context_id": ctx["context_id"].strip(),
            "kind": ctx["kind"].strip(),
            "source_identity": ctx["source_identity"].strip(),
            "captured_at": captured_at,
            "answers": parsed_answers,
        }

    # -- 判定 ----------------------------------------------------------------

    def scan(self) -> Dict[str, Any]:  # noqa: C901——判定矩阵天然分支多
        started = _iso_z(_utc_now())
        now = self._now

        # (d) 日落合规：过期上下文不采信（铁律 4——证据时效按注册表 TTL）。
        live: List[Dict[str, Any]] = []
        stale: List[Dict[str, str]] = []
        for ctx in self._contexts:
            age = (now - ctx["captured_at"]).total_seconds()
            if age > self._ttl_days * 86400 or age < -300:  # ≤300s 时钟超前容忍
                stale.append({"context_id": ctx["context_id"],
                              "captured_at": _iso_z(ctx["captured_at"])})
            else:
                live.append(ctx)

        argv = (["wenqu_core.station6_adversarial", "ledger-adjudicate",
                 self._manifest.run_id] + list(self._axes))

        # (e) 异源端点在场：required kind 缺任一 → BLOCKED（注册表 error 判据）。
        present_kinds = {ctx["kind"] for ctx in live}
        missing_kinds = [k for k in self._required_kinds if k not in present_kinds]
        if missing_kinds or not live:
            reasons = []
            if missing_kinds:
                reasons.append(
                    "heterogeneous_endpoint_missing: 异源上下文缺席 "
                    f"{missing_kinds}（注册表 error 判据：降级须登记豁免，"
                    "恢复后补一次异源审）")
            if not live:
                reasons.append("no_live_contexts: 无时效内的评审产物"
                               "（全部过期或未回收）")
            breakdown = {
                "judged_at": started, "station": "adversarial",
                "axes_total": len(self._axes),
                "contexts_live": len(live),
                "contexts_stale": stale,
                "missing_required_kinds": missing_kinds,
                "blocking_reasons": reasons,
            }
            self.last_breakdown = breakdown
            ended = _iso_z(_utc_now())
            return build_station_result(
                run_id=self._manifest.run_id,
                station_id=self.STATION_ID,
                attempt_id=_attempt_id(self._manifest.run_id, "st6-adversarial"),
                execution_status="BLOCKED",
                policy_verdict="NOT_EVALUATED",
                identity=_manifest_identity(self._manifest),
                tool={"name": "wenqu_core.station6_adversarial."
                              "AdversarialReviewScanner",
                      "version": __version__},
                execution={
                    "argv_digest": TrustedRunner.argv_digest(argv),
                    "started_at": started,
                    "ended_at": ended,
                    "actual_exit_code": 0,  # 判定进程内完成（先例见模块 docstring）
                    "expected_exit_set": [0],
                    "assertion_verdict": "ERROR",
                },
                coverage={"denominator": len(self._axes), "scanned": 0},
                finding_ids=[
                    _finding_id("adv_context_missing",
                                f"{self._manifest.run_id}:{k}")
                    for k in missing_kinds
                ],
                artifacts=[_cas_artifact(
                    json.dumps(breakdown, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8"))],
            )

        # (b) 每轴必问：任一轴被任一在场上下文漏问 → 轴覆盖缺失。
        axis_gaps: List[Dict[str, str]] = []
        for axis in self._axes:
            for ctx in live:
                answer = ctx["answers"].get(axis)
                if answer is None or not answer["asked"]:
                    axis_gaps.append({"axis": axis,
                                      "context_id": ctx["context_id"]})

        # (c) 二审定律：独立上下文=互异 source_identity（同命令换标签只计一）。
        independent_sources = sorted({ctx["source_identity"] for ctx in live})
        findings: List[Dict[str, Any]] = []
        for ctx in live:
            for axis, answer in sorted(ctx["answers"].items()):
                for f in answer["findings"]:
                    findings.append({
                        "context_id": ctx["context_id"],
                        "source_identity": ctx["source_identity"],
                        "axis": axis,
                        "summary": f["summary"],
                        "severity": f["severity"],
                    })

        verdict_failures: List[str] = []
        if axis_gaps:
            verdict_failures.append(
                f"axis_coverage_gap: {len(axis_gaps)} 处每轴必问违例"
                "（注册表 fail 判据：轴覆盖缺失）")
        if not findings and len(independent_sources) < 2:
            verdict_failures.append(
                "single_context_zero_finding: 零发现结论仅由 "
                f"{len(independent_sources)} 个独立上下文支撑（二审定律须 ≥2；"
                "§15.7 同命令换标签不算异源）")

        if findings or verdict_failures:
            execution_status, policy_verdict, assertion = "COMPLETED", "FAIL", "FAIL"
        else:
            execution_status, policy_verdict, assertion = "COMPLETED", "PASS", "PASS"

        finding_ids: List[str] = [
            _finding_id("adv_axis_gap",
                        f"{self._manifest.run_id}:{g['axis']}:{g['context_id']}")
            for g in axis_gaps
        ]
        if not findings and len(independent_sources) < 2:
            finding_ids.append(_finding_id(
                "adv_single_context_zero", self._manifest.run_id))
        finding_ids += [
            _finding_id("adv_finding",
                        f"{self._manifest.run_id}:{f['context_id']}:"
                        f"{f['axis']}:{f['summary']}")
            for f in findings
        ]

        denominator = len(self._axes)
        scanned = denominator  # 账本结构合法→每轴都可判定被问/漏问

        table = {
            "judged_at": started,
            "station": "adversarial",
            "axes": list(self._axes),
            "axes_total": denominator,
            "contexts_live": [
                {"context_id": c["context_id"], "kind": c["kind"],
                 "source_identity": c["source_identity"],
                 "captured_at": _iso_z(c["captured_at"]),
                 "axes_asked": sum(1 for a in c["answers"].values()
                                   if a["asked"])}
                for c in live
            ],
            "contexts_stale": stale,
            "independent_sources": independent_sources,
            "axis_gaps": axis_gaps,
            "adversarial_findings": findings,
            "verdict_failures": verdict_failures,
            "second_review_law": {
                "zero_finding_conclusion": not findings,
                "independent_contexts": len(independent_sources),
                "satisfied": bool(findings) or len(independent_sources) >= 2,
            },
        }
        ended = _iso_z(_utc_now())
        self.last_breakdown = {
            k: table[k] for k in (
                "judged_at", "axes_total", "independent_sources", "axis_gaps",
                "adversarial_findings", "verdict_failures", "second_review_law")
        }
        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st6-adversarial"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=_manifest_identity(self._manifest),
            tool={"name": "wenqu_core.station6_adversarial."
                          "AdversarialReviewScanner",
                  "version": __version__},
            execution={
                "argv_digest": TrustedRunner.argv_digest(argv),
                "started_at": started,
                "ended_at": ended,
                "actual_exit_code": 0,
                "expected_exit_set": [0],
                "assertion_verdict": assertion,
            },
            coverage={"denominator": denominator, "scanned": scanned},
            finding_ids=finding_ids,
            artifacts=[_cas_artifact(
                json.dumps(table, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8"))],
        )


def scan_station6(
    manifest: RunManifest,
    *,
    axes: Iterable[str],
    contexts: Iterable[Mapping[str, Any]] = (),
    required_kinds: Iterable[str] = DEFAULT_REQUIRED_KINDS,
    ttl_days: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """站6 便捷入口（构造 AdversarialReviewScanner 并立即 scan）。"""
    return AdversarialReviewScanner(
        manifest, axes=axes, contexts=contexts, required_kinds=required_kinds,
        ttl_days=ttl_days, now=now,
    ).scan()


# ---------------------------------------------------------------------------
# 端到端自证（python3 -m wenqu_core.station6_adversarial）
# ---------------------------------------------------------------------------


def _self_test() -> int:
    from datetime import timedelta as _td

    from .bugscan_orchestrator import BugscanPlanner

    planner = BugscanPlanner()
    plan = planner.plan("INCIDENT")
    assert 6 in plan.required_stations  # INCIDENT 档 required 语义自证
    manifest = planner.freeze_run_manifest(
        plan,
        run_id="selftest-st6-001",
        project_id="wenqu-selftest",
        commit_sha="2" * 40,
        environment="local",
        scope=["src/**", "db/**"],
        ruleset={"version": "w6d", "rules": ["W6A-ST6"]},
        data_config={"profile": "default"},
    )
    now = _utc_now()
    axes = ("auth-bypass", "mutation", "concurrency", "out-of-order")
    base_answers = {axis: {"asked": True, "findings": []} for axis in axes}

    def _ctx(cid, kind, source, **overrides):
        ctx = {"context_id": cid, "kind": kind, "source_identity": source,
               "captured_at": _iso_z(now), "answers": dict(base_answers)}
        ctx.update(overrides)
        return ctx

    # [1] PASS：S3+S5 双异源在场、每轴必问、零发现（二审定律满足）
    st = AdversarialReviewScanner(
        manifest, axes=axes,
        contexts=[_ctx("s3-cc", "s3_adversarial", "claude-code/oppo"),
                  _ctx("s5-codex", "s5_independent_audit", "codex/audit")],
        now=now,
    ).scan()
    validate_station_result(st)
    assert st["station_id"] == 6 and st["policy_verdict"] == "PASS"
    assert st["coverage"] == {"denominator": 4, "scanned": 4}
    assert st["artifacts"], "PASS 必须携带非空 artifacts（schema P0-4）"
    print(f"[1] adversarial PASS OK: 4/4 轴全覆盖 + 双异源零发现 "
          f"({st['artifacts'][0]['cas_digest'][:19]}…)")

    # [2] 单上下文零发现 → FAIL（二审定律）；同命令换标签不算异源
    scanner = AdversarialReviewScanner(
        manifest, axes=axes,
        contexts=[_ctx("s3-cc", "s3_adversarial", "claude-code/oppo"),
                  _ctx("s3-cc-relabeled", "s5_independent_audit",
                       "claude-code/oppo")],  # 同 source_identity 换标签
        now=now,
    )
    st = scanner.scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL"
    assert scanner.last_breakdown["independent_sources"] == ["claude-code/oppo"]
    assert not scanner.last_breakdown["second_review_law"]["satisfied"]
    assert any(f.startswith("fnd_adv_single_context_zero")
               for f in st["finding_ids"])
    print("[2] adversarial second-review-law OK: 同源换标签→单上下文零发现 FAIL")

    # [3] 轴覆盖缺失 → FAIL + 逐轴 finding
    skip = dict(base_answers)
    skip["mutation"] = {"asked": False, "findings": []}
    scanner = AdversarialReviewScanner(
        manifest, axes=axes,
        contexts=[_ctx("s3-cc", "s3_adversarial", "claude-code/oppo"),
                  _ctx("s5-codex", "s5_independent_audit", "codex/audit",
                       answers=skip)],
        now=now,
    )
    st = scanner.scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL"
    gaps = scanner.last_breakdown["axis_gaps"]
    assert gaps == [{"axis": "mutation", "context_id": "s5-codex"}]
    assert any(f.startswith("fnd_adv_axis_gap") for f in st["finding_ids"])
    print(f"[3] adversarial axis-gap OK: 漏问 {gaps[0]['axis']}/{gaps[0]['context_id']}"
          " → FAIL 落账")

    # [4] 对抗发现 → FAIL 逐发现落账（待裁定缺陷站级不得绿）
    found = dict(base_answers)
    found["auth-bypass"] = {"asked": True, "findings": [
        {"summary": "越权负例在 /api/orders 放行", "severity": "HIGH"}]}
    st = AdversarialReviewScanner(
        manifest, axes=axes,
        contexts=[_ctx("s3-cc", "s3_adversarial", "claude-code/oppo",
                       answers=found),
                  _ctx("s5-codex", "s5_independent_audit", "codex/audit")],
        now=now,
    ).scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL" and st["execution_status"] == "COMPLETED"
    assert any(f.startswith("fnd_adv_finding") for f in st["finding_ids"])
    print("[4] adversarial findings OK: 对抗发现落账 → FAIL")

    # [5] 异源缺席/证据过期 → BLOCKED（error 判据+TTL 日落）
    scanner = AdversarialReviewScanner(
        manifest, axes=axes,
        contexts=[_ctx("s3-cc", "s3_adversarial", "claude-code/oppo")],
        now=now,
    )
    st = scanner.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED" and st["policy_verdict"] == "NOT_EVALUATED"
    assert scanner.last_breakdown["missing_required_kinds"] == ["s5_independent_audit"]

    scanner = AdversarialReviewScanner(
        manifest, axes=axes,
        contexts=[_ctx("s3-cc", "s3_adversarial", "claude-code/oppo",
                       captured_at=_iso_z(now - _td(days=8))),
                  _ctx("s5-codex", "s5_independent_audit", "codex/audit",
                       captured_at=_iso_z(now - _td(days=8)))],
        now=now,
    )
    st = scanner.scan()
    assert st["execution_status"] == "BLOCKED"
    assert len(scanner.last_breakdown["contexts_stale"]) == 2  # 7d TTL 过期
    print("[5] adversarial endpoint-down/stale OK: 异源缺席与证据过期 → BLOCKED")

    # [6] 结构损坏 → fail-closed 异常（不产出任何结果）
    for bad_ctx in (
        {"context_id": "", "kind": "s3_adversarial",
         "source_identity": "x", "captured_at": _iso_z(now), "answers": base_answers},
        dict(_ctx("s3-cc", "s3_adversarial", "x"), answers={"only-one-axis": {}}),
        dict(_ctx("s3-cc", "s3_adversarial", "x"),
             answers={"auth-bypass": {"asked": "yes", "findings": []}}),
        dict(_ctx("s3-cc", "s3_adversarial", "x"),
             answers={"auth-bypass": {"asked": True,
                                      "findings": [{"summary": "s", "severity": "OHNO"}]}}),
    ):
        try:
            AdversarialReviewScanner(manifest, axes=axes, contexts=[bad_ctx],
                                     now=now)
            raise AssertionError("malformed ledger must raise")
        except AdversarialLedgerMalformed:
            pass
    try:
        AdversarialReviewScanner(manifest, axes=(), contexts=[], now=now)
        raise AssertionError("empty axes must raise")
    except AdversarialSpecError:
        pass
    dup = [_ctx("s3-cc", "s3_adversarial", "x"), _ctx("s3-cc", "s3_adversarial", "y")]
    try:
        AdversarialReviewScanner(manifest, axes=axes, contexts=dup, now=now)
        raise AssertionError("duplicate context_id must raise")
    except AdversarialLedgerMalformed:
        pass
    print("[6] adversarial fail-closed OK: 结构损坏/空轴/重复 context_id 一律拒绝")

    assert COUNTS_TOWARD_CONVERGENCE and BLOCKS_RELEASE
    print("SELF-TEST PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

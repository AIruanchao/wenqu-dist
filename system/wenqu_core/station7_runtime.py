# -*- coding: utf-8 -*-
"""station7_runtime.py——Codex 方案 W6D：Bug 八站·站7 运行时适配器（含站5/站6 占位）。

血统与契约正源：
- Codex 方案 W6D（站4-7 批次）·站7 运行时：常驻哨兵/探针/告警链
  （不参与收敛声明，事件回流站6）。
- 《问渠轨道规范（发行版 v2.0）》§1 站7 判据：pass=哨兵活着+真的会叫
  （告警链实测）；fail=哨兵死/告警链断；error=探针不可用。
- schemas/station-result-v2.schema.json：每腿与整站产出严格合规。

三条腿（每腿独立产出一份 station_id=7 的 station-result-v2，可单独留证；
整站由 combine_station7_results 合并为单一条目）：

- SentinelHealthScanner：哨兵活性=业务结果新鲜度。显式不看 PID/mtime——
  进程在而业务死（空转）与进程死而文件新鲜（残留）都判死；活=哨兵
  近期真实产出过业务心跳（heartbeat JSON/日志尾部时间戳）且自报状态
  健康。
- SloMonitorScanner：SLO 指标采集与阈值判定——按 SLO 清单逐项核对
  监控快照值（>=/>/<=/< 目标），缺口指标按未扫计（缩水 BLOCKED）。
- AlertChannelScanner：告警通道端到端可达性——金丝雀令牌往返实测：
  注入不可猜随机令牌 → 经 TrustedRunner 走真实发送命令 → 回执文件
  必须同时含 delivered=true 与该令牌才认「真的会叫」（防只写本地=
  防线假活）。

站7 语义（模块级常量）：
- COUNTS_TOWARD_CONVERGENCE = False：站7 不计收敛轮（规范 §1 站7
  notes：INCIDENT 档 required 但不参与收敛声明，事件回流站6）；
- BLOCKS_RELEASE = True：站7 FAIL/BLOCKED 可阻断发布。

站5/站6 占位接口（本批 W6D 范围声明）：
- Station5LiveFirePlaceholder：实弹面需所有者明确口令（一次性
  exact-scope 生产写授权），本批仅定义接口签名 + NOT_APPLICABLE 输出；
- Station6AdversarialPlaceholder：对抗面需 ≥2 独立上下文（S3 对抗/
  S5 独立审计）与 wenqu charter/ingest 工具链，本批同样仅占位。
- 两者与站7 同属生产/事件域，占位集中放本文件；IMPLEMENTED=False 是
  机器可判的未实现标记。

安全构造（by construction）：
- 纯 stdlib；一切外部命令经 TrustedRunner（argv 列表、shell=False，
  actual_exit_code 只取 waitpid 真值）；无 shell 拼接、无 eval/exec。
- 分母缩水守卫交由 build_station_result 强制：scanned<denominator →
  BLOCKED/NOT_EVALUATED，绝不记 PASS。
- actual_exit_code=-1 是本文件唯一的非进程哨兵值：只用于「进程未起」
  或「超时被杀」，且只能伴随 ERROR/TIMEOUT（或缩水强制的 BLOCKED）
  出现——结构上不可能支撑 PASS。
- 探针文件缺失/不可解析 = 探针不可用 → 按未扫计（缩水 BLOCKED）；
  文件可读但业务过期 = 哨兵死 → FAIL（判得出死活才算扫到）。
- 进程内完成的腿（哨兵/SLO）actual_exit_code=0 采用 RunManifest.
  to_station_result 同一先例；多通道命令腿的整腿退出码=全 0→0、
  否则按序传播首个非零真值（只用真值，不造值）。
"""

from __future__ import annotations

import hashlib
import json
import math
import operator
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .bugscan_orchestrator import (
    RunManifest,
    StationResultValidationError,
    build_station_result,
    validate_station_result,
)
from .runner import TrustedRunner

__all__ = [
    "STATION_ID",
    "COUNTS_TOWARD_CONVERGENCE",
    "BLOCKS_RELEASE",
    "SentinelHealthScanner",
    "SloMonitorScanner",
    "AlertChannelScanner",
    "combine_station7_results",
    "scan_station7",
    "Station5LiveFirePlaceholder",
    "Station6AdversarialPlaceholder",
    "RuntimeStationError",
    "SentinelSpecError",
    "SloSpecError",
    "AlertChannelSpecError",
]

__version__ = "1.0.0"

STATION_ID = 7

#: 站7 不计收敛轮（规范 §1 站7：INCIDENT 档 required 但不参与收敛声明）。
COUNTS_TOWARD_CONVERGENCE: bool = False

#: 站7 可阻断发布：FAIL/BLOCKED 时发布门不得放行。
BLOCKS_RELEASE: bool = True

#: 心跳未来偏移容忍（秒）：哨兵时钟小幅超前按活；大幅超前=时钟异常/伪造，判死。
_MAX_CLOCK_SKEW_S = 300.0

#: 心跳状态字段缺省健康集合（小写比较）。
DEFAULT_HEALTHY_STATES: Tuple[str, ...] = ("healthy", "ok", "pass", "green", "alive")

#: SLO 比较算子白名单。
_OPS = {
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
}

_RE_LOG_TS = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class RuntimeStationError(ValueError):
    """站7 适配器基类错误——一律 fail-closed。"""


class SentinelSpecError(RuntimeStationError):
    """哨兵探针规格非法：缺字段、kind 未知、freshness 非正。"""


class SloSpecError(RuntimeStationError):
    """SLO 清单/快照非法：缺字段、算子未知、目标非数值、快照不可读。"""


class AlertChannelSpecError(RuntimeStationError):
    """告警通道规格非法：argv 模板缺 {token} 占位符、回执路径缺失。"""


# ---------------------------------------------------------------------------
# 基础工具（与 station4_behavior 同算法的本地实现，保持模块自包含）
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


def _attempt_id(run_id: str, tag: str) -> str:
    seed = _hash_obj({"run_id": run_id, "tag": tag, "ts": _iso_z(_utc_now())})
    return f"att-{tag}-{seed[:12]}"


def _finding_id(prefix: str, seed: str) -> str:
    safe = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in prefix)
    return f"fnd_{safe}_{_sha256_hex(seed.encode('utf-8'))[:12]}"


def _require_manifest(manifest: RunManifest) -> RunManifest:
    if not isinstance(manifest, RunManifest):
        raise RuntimeStationError(
            f"manifest must be RunManifest, got {type(manifest).__name__}"
        )
    return manifest


def _manifest_identity(manifest: RunManifest) -> Dict[str, Any]:
    """身份三源一律取冻结 manifest 正源，绝不采信探针/通道自报身份。"""
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


def _parse_flexible_ts(value: str) -> Optional[datetime]:
    """解析 ISO-8601 或 ``YYYY-MM-DD HH:MM:SS``（哨兵日志本地时区）。"""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    return parsed


# -- 多腿合并判定（worst-of 语义，与 station4_behavior 同一优先级约定） ------

_EXEC_SEVERITY = ("BLOCKED", "ERROR", "TIMEOUT", "CANCELLED")


def _worst_execution_status(statuses: Iterable[str]) -> str:
    seen = set(statuses)
    for token in _EXEC_SEVERITY:
        if token in seen:
            return token
    return "COMPLETED"


def _worst_policy(verdicts: Iterable[str]) -> str:
    active = [v for v in verdicts if v != "NOT_APPLICABLE"]
    if not active:
        return "NOT_APPLICABLE"
    for token in ("FAIL", "NOT_EVALUATED", "CONDITIONAL"):
        if token in active:
            return token
    return "PASS" if all(v == "PASS" for v in active) else "NOT_EVALUATED"


def _worst_assertion(verdicts: Iterable[str]) -> str:
    seen = list(verdicts)
    if "FAIL" in seen:
        return "FAIL"
    if seen and all(v == "PASS" for v in seen):
        return "PASS"
    return "ERROR"


def _merge_exit_codes(codes: List[int]) -> int:
    """全 0 → 0；否则按序传播首个非零真实退出码（只用真值，不造值）。"""
    for code in codes:
        if code != 0:
            return code
    return 0


# ---------------------------------------------------------------------------
# SentinelHealthScanner——站7 腿1：哨兵活性（业务结果新鲜度，非 PID/mtime）
# ---------------------------------------------------------------------------


class SentinelHealthScanner:
    """哨兵活性检查：只认业务结果，显式不查进程表与文件 mtime。

    判活口径（冻结）：
    - ``heartbeat_json``：探针文件为 JSON，须含 ``last_beat_at``（ISO-8601）；
      可选 ``state``（在 healthy_states 内才算健康）。活 = 时间戳落在
      freshness 窗口内（允许 ≤300s 时钟超前）且状态健康。
    - ``heartbeat_log``：哨兵业务日志（如 ``2026-10-07 21:30:00 [HIGH] …``），
      取最后一条非空行的前导时间戳判新鲜度（本地时区），同上判活。

    覆盖口径：denominator=哨兵数；scanned=探针文件可读且可解析的哨兵数
    （不可读/不可解析=探针不可用→未扫，缩水 BLOCKED）；文件可读但业务
    过期/状态不健康=哨兵死→FAIL（判得出死活才算扫到）。
    """

    STATION_ID = STATION_ID
    LEG = "sentinel-health"

    def __init__(
        self,
        manifest: RunManifest,
        *,
        sentinels: Iterable[Mapping[str, Any]],
        healthy_states: Iterable[str] = DEFAULT_HEALTHY_STATES,
        now: Optional[datetime] = None,
    ) -> None:
        _require_manifest(manifest)
        self._manifest = manifest
        self._healthy = {str(s).lower() for s in healthy_states}
        self._now = now or _utc_now()
        self._sentinels: List[Dict[str, Any]] = [
            self._validate(dict(s), i) for i, s in enumerate(sentinels)
        ]
        if not self._sentinels:
            raise SentinelSpecError("sentinels must contain at least one entry（空分母禁止）")
        self.last_breakdown: Dict[str, Any] = {}

    @staticmethod
    def _validate(spec: Mapping[str, Any], index: int) -> Dict[str, Any]:
        if not isinstance(spec, Mapping):
            raise SentinelSpecError(f"sentinels[{index}] must be a mapping")
        name = spec.get("name")
        kind = spec.get("kind")
        path = spec.get("path")
        freshness = spec.get("freshness_s")
        if not isinstance(name, str) or not name.strip():
            raise SentinelSpecError(f"sentinels[{index}].name must be a non-empty string")
        if kind not in ("heartbeat_json", "heartbeat_log"):
            raise SentinelSpecError(
                f"sentinels[{index}].kind must be 'heartbeat_json' or 'heartbeat_log', "
                f"got {kind!r}"
            )
        if not isinstance(path, str) or not path.strip():
            raise SentinelSpecError(f"sentinels[{index}].path must be a non-empty string")
        if isinstance(freshness, bool) or not isinstance(freshness, (int, float)) \
                or freshness <= 0:
            raise SentinelSpecError(
                f"sentinels[{index}].freshness_s must be a positive number"
            )
        return {
            "name": name.strip(),
            "kind": kind,
            "path": path,
            "freshness_s": float(freshness),
        }

    def _read_heartbeat(self, spec: Mapping[str, Any]) -> Optional[Tuple[datetime, Optional[str]]]:
        """读心跳 → (last_beat_at, state)；探针不可用返回 None（未扫）。"""
        try:
            raw = Path(spec["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        if spec["kind"] == "heartbeat_json":
            try:
                payload = json.loads(raw)
            except ValueError:
                return None
            if not isinstance(payload, Mapping):
                return None
            beat = _parse_flexible_ts(str(payload.get("last_beat_at", "")))
            if beat is None:
                return None
            state = payload.get("state")
            return beat, str(state) if state is not None else None
        lines = [line for line in raw.splitlines() if line.strip()]
        if not lines:
            return None
        match = _RE_LOG_TS.match(lines[-1].strip())
        if match is None:
            return None
        beat = _parse_flexible_ts(match.group(1))
        if beat is None:
            return None
        return beat, None

    def _judge(self, spec: Mapping[str, Any]) -> Dict[str, Any]:
        heartbeat = self._read_heartbeat(spec)
        if heartbeat is None:
            return {"scanned": False, "alive": False, "reason": "probe_unavailable"}
        beat, state = heartbeat
        now = self._now
        reference = now if beat.tzinfo is not None else now.astimezone().replace(tzinfo=None)
        delta = (reference - beat).total_seconds()
        if delta < -_MAX_CLOCK_SKEW_S:
            return {"scanned": True, "alive": False, "reason": "clock_skew_future",
                    "last_beat_at": beat.isoformat()}
        if delta > spec["freshness_s"]:
            return {"scanned": True, "alive": False, "reason": "stale",
                    "last_beat_at": beat.isoformat(), "age_s": delta}
        if state is not None and state.lower() not in self._healthy:
            return {"scanned": True, "alive": False, "reason": f"unhealthy_state:{state}",
                    "last_beat_at": beat.isoformat()}
        return {"scanned": True, "alive": True, "reason": "ok",
                "last_beat_at": beat.isoformat(), "age_s": max(delta, 0.0)}

    def scan(self) -> Dict[str, Any]:
        started = _iso_z(self._now)
        outcomes = [(spec, self._judge(spec)) for spec in self._sentinels]
        denominator = len(self._sentinels)
        scanned = sum(1 for _, o in outcomes if o["scanned"])
        dead = [s for s, o in outcomes if o["scanned"] and not o["alive"]]
        unavailable = [s for s, o in outcomes if not o["scanned"]]

        if unavailable:
            execution_status = "COMPLETED"
            policy_verdict = "FAIL" if dead else "NOT_EVALUATED"
            assertion = "FAIL" if dead else "ERROR"
        elif dead:
            execution_status, policy_verdict, assertion = "COMPLETED", "FAIL", "FAIL"
        else:
            execution_status, policy_verdict, assertion = "COMPLETED", "PASS", "PASS"

        finding_ids = [_finding_id("sentinel", s["name"]) for s in dead]
        finding_ids += [_finding_id("sentinel_probe", s["name"]) for s in unavailable]

        table_payload = json.dumps(
            {"judged_at": started,
             "sentinels": [{**s, "outcome": o} for s, o in outcomes]},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")

        ended = _iso_z(_utc_now())
        self.last_breakdown = {
            "leg": self.LEG,
            "sentinels_total": denominator,
            "sentinels_scanned": scanned,
            "sentinels_alive": scanned - len(dead),
            "sentinels_dead": [
                {"name": s["name"], "reason": o["reason"],
                 "last_beat_at": o.get("last_beat_at"), "age_s": o.get("age_s")}
                for s, o in outcomes if o["scanned"] and not o["alive"]
            ],
            "probes_unavailable": [s["name"] for s in unavailable],
            "liveness_basis": "business-heartbeat-freshness（非 PID/mtime）",
        }

        argv = ["wenqu_core.station7_runtime", "sentinel-health"] + sorted(
            s["name"] for s in self._sentinels
        )
        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st7-sentinel"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=_manifest_identity(self._manifest),
            tool={"name": "wenqu_core.station7_runtime.SentinelHealthScanner",
                  "version": __version__},
            execution={
                "argv_digest": TrustedRunner.argv_digest(argv),
                "started_at": started,
                "ended_at": ended,
                "actual_exit_code": 0,  # 进程内完成先例（见类 docstring）
                "expected_exit_set": [0],
                "assertion_verdict": assertion,
            },
            coverage={"denominator": denominator, "scanned": scanned},
            finding_ids=finding_ids,
            artifacts=[_cas_artifact(table_payload)],
        )


# ---------------------------------------------------------------------------
# SloMonitorScanner——站7 腿2：SLO 指标采集与阈值判定
# ---------------------------------------------------------------------------


class SloMonitorScanner:
    """SLO 指标采集与阈值判定。

    SLO 清单项契约::

        {"name": "availability", "target": 0.999, "op": ">="}
        # op ∈ {">=", "<=", ">", "<"}，缺省 ">="；target 必须数值。

    监控快照：构造器直给 ``snapshot={"<name>": value}``，或
    ``snapshot_path`` 指向 JSON（裸映射或 ``{"slos": {...}}``）。
    覆盖口径：denominator=SLO 数；scanned=快照中拿到可用数值的 SLO 数
    （缺失/非数值/NaN=采集缺口→未扫，缩水 BLOCKED）；扫到且破线→FAIL。
    """

    STATION_ID = STATION_ID
    LEG = "slo-monitor"

    def __init__(
        self,
        manifest: RunManifest,
        *,
        slos: Iterable[Mapping[str, Any]],
        snapshot: Optional[Mapping[str, Any]] = None,
        snapshot_path: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> None:
        _require_manifest(manifest)
        if snapshot is None and snapshot_path is None:
            raise SloSpecError("either snapshot or snapshot_path is required")
        self._manifest = manifest
        self._slos: List[Dict[str, Any]] = [
            self._validate_slo(dict(s), i) for i, s in enumerate(slos)
        ]
        if not self._slos:
            raise SloSpecError("slos must contain at least one entry（空分母禁止）")
        self._snapshot = self._load_snapshot(snapshot, snapshot_path)
        self._now = now or _utc_now()
        self.last_breakdown: Dict[str, Any] = {}

    @staticmethod
    def _validate_slo(slo: Mapping[str, Any], index: int) -> Dict[str, Any]:
        if not isinstance(slo, Mapping):
            raise SloSpecError(f"slos[{index}] must be a mapping")
        name = slo.get("name")
        target = slo.get("target")
        op = str(slo.get("op", ">="))
        if not isinstance(name, str) or not name.strip():
            raise SloSpecError(f"slos[{index}].name must be a non-empty string")
        if isinstance(target, bool) or not isinstance(target, (int, float)) \
                or not math.isfinite(float(target)):
            raise SloSpecError(
                f"slos[{index}].target must be a finite number, got {target!r}"
            )
        if op not in _OPS:
            raise SloSpecError(f"slos[{index}].op must be one of {sorted(_OPS)}, got {op!r}")
        return {"name": name.strip(), "target": float(target), "op": op}

    @staticmethod
    def _load_snapshot(
        snapshot: Optional[Mapping[str, Any]], snapshot_path: Optional[str]
    ) -> Dict[str, Any]:
        if snapshot is not None:
            if not isinstance(snapshot, Mapping):
                raise SloSpecError("snapshot must be a mapping of {name: value}")
            return dict(snapshot)
        try:
            raw = Path(snapshot_path).read_text(encoding="utf-8")  # type: ignore[arg-type]
            data = json.loads(raw)
        except (OSError, ValueError) as exc:
            raise SloSpecError(
                f"snapshot unreadable at {snapshot_path}: {exc}"
                "（探针不可用，fail-closed 拒绝产出结果）"
            ) from exc
        if isinstance(data, Mapping) and isinstance(data.get("slos"), Mapping):
            data = data["slos"]
        if not isinstance(data, Mapping):
            raise SloSpecError(
                f"snapshot at {snapshot_path} must be a mapping or {{'slos': {{...}}}}"
            )
        return dict(data)

    def scan(self) -> Dict[str, Any]:
        started = _iso_z(self._now)
        denominator = len(self._slos)
        scanned = 0
        breached: List[Dict[str, Any]] = []
        met: List[str] = []
        missing: List[str] = []

        for slo in self._slos:
            value = self._snapshot.get(slo["name"])
            if (
                value is None or isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                missing.append(slo["name"])
                continue
            scanned += 1
            if not _OPS[slo["op"]](float(value), slo["target"]):
                breached.append({"name": slo["name"], "value": float(value),
                                 "op": slo["op"], "target": slo["target"]})
            else:
                met.append(slo["name"])

        if missing:
            execution_status = "COMPLETED"
            policy_verdict = "FAIL" if breached else "NOT_EVALUATED"
            assertion = "FAIL" if breached else "ERROR"
        elif breached:
            execution_status, policy_verdict, assertion = "COMPLETED", "FAIL", "FAIL"
        else:
            execution_status, policy_verdict, assertion = "COMPLETED", "PASS", "PASS"

        finding_ids = [_finding_id("slo", b["name"]) for b in breached]
        finding_ids += [_finding_id("slo_missing", n) for n in missing]

        table_payload = json.dumps(
            {"judged_at": started, "met": met, "breached": breached, "missing": missing},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")

        ended = _iso_z(_utc_now())
        self.last_breakdown = {
            "leg": self.LEG,
            "slos_total": denominator,
            "slos_scanned": scanned,
            "slos_met": len(met),
            "slos_breached": breached,
            "slos_missing": missing,
        }

        argv = ["wenqu_core.station7_runtime", "slo-monitor"] + sorted(
            f'{s["name"]}{s["op"]}{s["target"]}' for s in self._slos
        )
        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st7-slo"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=_manifest_identity(self._manifest),
            tool={"name": "wenqu_core.station7_runtime.SloMonitorScanner",
                  "version": __version__},
            execution={
                "argv_digest": TrustedRunner.argv_digest(argv),
                "started_at": started,
                "ended_at": ended,
                "actual_exit_code": 0,  # 进程内完成先例（见类 docstring）
                "expected_exit_set": [0],
                "assertion_verdict": assertion,
            },
            coverage={"denominator": denominator, "scanned": scanned},
            finding_ids=finding_ids,
            artifacts=[_cas_artifact(table_payload)],
        )


# ---------------------------------------------------------------------------
# AlertChannelScanner——站7 腿3：告警通道端到端可达性（金丝雀令牌往返）
# ---------------------------------------------------------------------------


class AlertChannelScanner:
    """告警通道端到端可达性：金丝雀令牌往返实测（判据 fail=告警链断）。

    通道项契约::

        {"name": "argus-webhook",
         "argv_template": ["bash", "alert-send.sh", "TEST",
                           "station7-canary", "{token}"],   # 必含 {token}
         "receipt_path": "/tmp/canary-receipt.json"}

    往返判定（三步全过才认「真的会叫」）：
    1. 发送命令经 TrustedRunner 真实执行且 actual_exit_code==0；
    2. 回执文件存在且可读；
    3. 回执含 ``{"delivered": true, "canary_token": "<本次令牌>"}``
       （JSON 严格匹配；或文本回执含本次令牌——spool 风格兜底）。
    令牌为每次扫描随机生成（secrets.token_hex），预置/重放回执不可能
    通过——防「只写本地日志=防线假活」。

    覆盖口径：denominator=通道数；scanned=发送命令真实执行过的通道数
    （可执行缺失/超时被杀=探针不可用→未扫，缩水 BLOCKED）；命令执行了
    但回执缺失/令牌不匹配/退出码非零→FAIL（告警链断）。

    整腿 execution.actual_exit_code：全 0→0；否则按通道顺序传播首个
    非零真值（超时通道计 -1 哨兵）——只用真值，不造值。
    """

    STATION_ID = STATION_ID
    LEG = "alert-channel"

    def __init__(
        self,
        manifest: RunManifest,
        *,
        channels: Iterable[Mapping[str, Any]],
        runner: Optional[TrustedRunner] = None,
        timeout_s: int = 60,
        now: Optional[datetime] = None,
    ) -> None:
        _require_manifest(manifest)
        self._manifest = manifest
        self._channels: List[Dict[str, Any]] = [
            self._validate(dict(c), i) for i, c in enumerate(channels)
        ]
        if not self._channels:
            raise AlertChannelSpecError("channels must contain at least one entry（空分母禁止）")
        if runner is not None and not isinstance(runner, TrustedRunner):
            raise AlertChannelSpecError(
                f"runner must be TrustedRunner, got {type(runner).__name__}"
            )
        self._runner = runner or TrustedRunner(timeout=float(timeout_s))
        self._timeout_s = max(1, int(timeout_s))
        self._now = now
        self.last_breakdown: Dict[str, Any] = {}

    @staticmethod
    def _validate(channel: Mapping[str, Any], index: int) -> Dict[str, Any]:
        if not isinstance(channel, Mapping):
            raise AlertChannelSpecError(f"channels[{index}] must be a mapping")
        name = channel.get("name")
        template = channel.get("argv_template")
        receipt = channel.get("receipt_path")
        if not isinstance(name, str) or not name.strip():
            raise AlertChannelSpecError(f"channels[{index}].name must be a non-empty string")
        if (
            not isinstance(template, (list, tuple)) or not template
            or not all(isinstance(a, str) for a in template)
            or not any("{token}" in a for a in template)
        ):
            raise AlertChannelSpecError(
                f"channels[{index}].argv_template must be a non-empty argv list of "
                "strings containing the {token} placeholder"
            )
        if not isinstance(receipt, str) or not receipt.strip():
            raise AlertChannelSpecError(
                f"channels[{index}].receipt_path must be a non-empty string"
            )
        return {"name": name.strip(), "argv_template": list(template), "receipt_path": receipt}

    def _verify_receipt(self, receipt_path: str, token: str) -> Tuple[bool, str]:
        try:
            raw = Path(receipt_path).read_bytes()
        except OSError:
            return False, "receipt_missing"
        try:
            payload = json.loads(raw.decode("utf-8"))
            if isinstance(payload, Mapping):
                if payload.get("delivered") is True and payload.get("canary_token") == token:
                    return True, "json_verified"
        except ValueError:
            pass
        if token in raw.decode("utf-8", "replace"):
            return True, "text_token_verified"
        return False, "token_mismatch"

    def _fire(self, channel: Mapping[str, Any]) -> Dict[str, Any]:
        token = secrets.token_hex(8)
        argv = [a.replace("{token}", token) for a in channel["argv_template"]]
        try:
            evidence = self._runner.run(argv)
        except (FileNotFoundError, PermissionError) as exc:
            return {"executed": False, "ok": False, "exit_code": -1,
                    "reason": f"launch_failed:{type(exc).__name__}"}
        if evidence.timed_out:
            return {"executed": False, "ok": False, "exit_code": -1, "reason": "timed_out"}
        exit_code = int(evidence.actual_exit_code)
        if exit_code != 0:
            return {"executed": True, "ok": False, "exit_code": exit_code,
                    "reason": f"send_exit_{exit_code}"}
        ok, reason = self._verify_receipt(channel["receipt_path"], token)
        return {"executed": True, "ok": ok, "exit_code": exit_code, "reason": reason}

    def scan(self) -> Dict[str, Any]:
        started = _iso_z(self._now or _utc_now())
        outcomes = [(channel, self._fire(channel)) for channel in self._channels]
        denominator = len(self._channels)
        scanned = sum(1 for _, o in outcomes if o["executed"])
        broken = [c for c, o in outcomes if o["executed"] and not o["ok"]]
        unavailable = [c for c, o in outcomes if not o["executed"]]

        if unavailable:
            execution_status = "COMPLETED"
            policy_verdict = "FAIL" if broken else "NOT_EVALUATED"
            assertion = "FAIL" if broken else "ERROR"
        elif broken:
            execution_status, policy_verdict, assertion = "COMPLETED", "FAIL", "FAIL"
        else:
            execution_status, policy_verdict, assertion = "COMPLETED", "PASS", "PASS"

        exit_code = _merge_exit_codes([o["exit_code"] for _, o in outcomes])
        finding_ids = [_finding_id("alert", c["name"]) for c in broken]
        finding_ids += [_finding_id("alert_probe", c["name"]) for c in unavailable]

        table_payload = json.dumps(
            {"fired_at": started,
             "channels": [{**c, "outcome": {k: v for k, v in o.items() if k != "token"}}
                          for c, o in outcomes]},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")

        ended = _iso_z(_utc_now())
        self.last_breakdown = {
            "leg": self.LEG,
            "channels_total": denominator,
            "channels_executed": scanned,
            "channels_verified": scanned - len(broken),
            "channels_broken": [
                {"name": c["name"], "reason": o["reason"], "exit_code": o["exit_code"]}
                for c, o in outcomes if o["executed"] and not o["ok"]
            ],
            "probes_unavailable": [
                {"name": c["name"], "reason": o["reason"]}
                for c, o in outcomes if not o["executed"]
            ],
        }

        argv = ["wenqu_core.station7_runtime", "alert-channel"] + sorted(
            c["name"] for c in self._channels
        )
        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st7-alert"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=_manifest_identity(self._manifest),
            tool={"name": "wenqu_core.station7_runtime.AlertChannelScanner",
                  "version": __version__},
            execution={
                "argv_digest": TrustedRunner.argv_digest(argv),
                "started_at": started,
                "ended_at": ended,
                "timeout_s": self._timeout_s,
                "actual_exit_code": exit_code,
                "expected_exit_set": [0],
                "assertion_verdict": assertion,
            },
            coverage={"denominator": denominator, "scanned": scanned},
            finding_ids=finding_ids,
            artifacts=[_cas_artifact(table_payload)],
        )


# ---------------------------------------------------------------------------
# 整站合并——三条腿 → 单一 station-result-v2
# ---------------------------------------------------------------------------


def combine_station7_results(leg_results: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """把站7 各腿结果合并为单一条目（GateAggregator 同站只接受一条）。

    合并规则与 station4_behavior.combine_station4_results 同一套 worst-of
    语义（coverage 求和 / 状态 BLOCKED>ERROR>TIMEOUT>CANCELLED>COMPLETED /
    策略 FAIL>NOT_EVALUATED>CONDITIONAL>PASS / 退出码只用真值传播）。

    站7 特记：合并结果 COUNTS_TOWARD_CONVERGENCE=False——不计收敛轮，
    但 FAIL/BLOCKED 照样阻断发布（BLOCKS_RELEASE=True）。
    """
    results = [dict(r) for r in leg_results]
    if not results:
        raise RuntimeStationError("combine_station7_results needs at least one leg result")

    for index, result in enumerate(results):
        try:
            validate_station_result(result)
        except StationResultValidationError as exc:
            raise RuntimeStationError(f"leg[{index}] failed validation: {exc}") from exc

    first = results[0]
    if first["station_id"] != STATION_ID:
        raise RuntimeStationError(
            f"combine_station7_results only merges station {STATION_ID} legs, "
            f"got station_id={first['station_id']}"
        )
    run_id = first["run_id"]
    anchor = first["identity"]
    anchor_keys = ("commit_sha", "environment", "scope_hash")
    for index, result in enumerate(results):
        if result["station_id"] != STATION_ID or result["run_id"] != run_id:
            raise RuntimeStationError(
                f"leg[{index}] station/run mismatch: expected station {STATION_ID} "
                f"run {run_id!r}, got station {result['station_id']} run {result['run_id']!r}"
            )
        for key in anchor_keys:
            if result["identity"].get(key) != anchor.get(key):
                raise RuntimeStationError(
                    f"leg[{index}] identity.{key} mismatch: "
                    f"{result['identity'].get(key)!r} != {anchor.get(key)!r}"
                    "（证据身份不一致，拒绝合并）"
                )

    denominator = sum(int(r["coverage"].get("denominator", 0)) for r in results)
    scanned = sum(int(r["coverage"].get("scanned", 0)) for r in results)
    exclusions: List[str] = []
    for result in results:
        for item in result["coverage"].get("exclusions", ()) or ():
            if item not in exclusions:
                exclusions.append(item)

    execution_status = _worst_execution_status(r["execution_status"] for r in results)
    policy_verdict = _worst_policy(r["policy_verdict"] for r in results)
    assertion = _worst_assertion(
        r["execution"].get("assertion_verdict") for r in results
    )
    exit_code = _merge_exit_codes(
        [int(r["execution"].get("actual_exit_code", 0)) for r in results]
    )
    started_at = min(r["execution"]["started_at"] for r in results)
    ended_at = max(r["execution"]["ended_at"] for r in results)
    timeouts = [
        int(r["execution"]["timeout_s"]) for r in results
        if isinstance(r["execution"].get("timeout_s"), int)
        and r["execution"]["timeout_s"] >= 1
    ]

    finding_ids: List[str] = []
    for result in results:
        for finding in result.get("finding_ids", ()):
            if finding not in finding_ids:
                finding_ids.append(finding)
    artifacts: List[Dict[str, Any]] = []
    seen_digests = set()
    for result in results:
        for art in result.get("artifacts", ()):
            digest = art.get("cas_digest")
            if digest not in seen_digests:
                seen_digests.add(digest)
                artifacts.append({"cas_digest": digest, "size": art["size"]})

    leg_digests = sorted(r["execution"]["argv_digest"] for r in results)
    argv = ["wenqu_core.station7_runtime:combine", run_id] + leg_digests

    return build_station_result(
        run_id=run_id,
        station_id=STATION_ID,
        attempt_id=_attempt_id(run_id, "st7-combined"),
        execution_status=execution_status,
        policy_verdict=policy_verdict,
        identity=dict(anchor),
        tool={"name": "wenqu_core.station7_runtime", "version": __version__},
        execution={
            "argv_digest": TrustedRunner.argv_digest(argv),
            "started_at": started_at,
            "ended_at": ended_at,
            **({"timeout_s": max(timeouts)} if timeouts else {}),
            "actual_exit_code": exit_code,
            "expected_exit_set": [0],
            "assertion_verdict": assertion,
        },
        coverage={
            "denominator": denominator,
            "scanned": scanned,
            **({"exclusions": exclusions} if exclusions else {}),
        },
        finding_ids=finding_ids,
        artifacts=artifacts,
    )


def scan_station7(
    *,
    sentinel: Optional[SentinelHealthScanner] = None,
    slo: Optional[SloMonitorScanner] = None,
    alert: Optional[AlertChannelScanner] = None,
) -> Dict[str, Any]:
    """站7 门面：顺序执行给定的腿扫描器并合并为单一 station-result-v2。"""
    legs = []
    for scanner in (sentinel, slo, alert):
        if scanner is not None:
            legs.append(scanner.scan())
    if not legs:
        raise RuntimeStationError("scan_station7 needs at least one leg scanner")
    return combine_station7_results(legs)


# ---------------------------------------------------------------------------
# 站5/站6 占位接口（W6D 本批：仅签名 + NOT_APPLICABLE，不实现扫描逻辑）
# ---------------------------------------------------------------------------


class Station5LiveFirePlaceholder:
    """站5 实弹面占位接口。

    为何占位：实弹=真实业务流全链操作，生产写须所有者明确口令（一次性
    exact-scope 授权），且不在任何自动档 required 集内——本批 W6D 不实现
    扫描逻辑，仅冻结接口签名。

    语义契约：
    - scan(authorization=...) 签名对齐未来实弹扫描器：authorization 为
      生产写授权对象（approver/scope/expiry 等五要素），flows 为业务流
      清单占位；
    - 无论是否携带授权，本批一律产出 execution_status=BLOCKED +
      policy_verdict=NOT_APPLICABLE（对齐注册表判据：error=生产写授权
      缺失（BLOCKED，不算通过））；
    - actual_exit_code=0 语义=占位判定逻辑自身在进程内完成
      （RunManifest.to_station_result 同例），绝不代表发生过任何真实
      业务写；coverage 0/0=占位未定义业务流断言点（非 vacuous pass——
      verdict 已是 NOT_APPLICABLE）。
    """

    STATION_ID = 5
    IMPLEMENTED = False

    def __init__(self, manifest: RunManifest) -> None:
        _require_manifest(manifest)
        self._manifest = manifest

    def scan(
        self,
        *,
        authorization: Optional[Mapping[str, Any]] = None,
        flows: Iterable[Mapping[str, Any]] = (),
    ) -> Dict[str, Any]:
        started = _iso_z(_utc_now())
        argv = ["wenqu_core.station7_runtime", "station5-live-fire-placeholder",
                self._manifest.run_id]
        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st5-placeholder"),
            execution_status="BLOCKED",
            policy_verdict="NOT_APPLICABLE",
            identity=_manifest_identity(self._manifest),
            tool={
                "name": "wenqu_core.station7_runtime.Station5LiveFirePlaceholder",
                "version": __version__,
            },
            execution={
                "argv_digest": TrustedRunner.argv_digest(argv),
                "started_at": started,
                "ended_at": _iso_z(_utc_now()),
                "timeout_s": 1,
                "actual_exit_code": 0,
                "expected_exit_set": [0],
                "assertion_verdict": "ERROR",
            },
            coverage={"denominator": 0, "scanned": 0},
        )


class Station6AdversarialPlaceholder:
    """站6 对抗面占位接口。

    为何占位：对抗面走 ``wenqu charter`` 发射反方评审 + ``wenqu ingest``
    回收产物，零发现结论须出自 ≥2 独立上下文（二审定律）——S3 对抗/
    S5 独立审计上下文未在本批供给，不实现扫描逻辑，仅冻结接口签名。

    语义契约：
    - scan(contexts=..., axes=...) 签名对齐未来对抗扫描器：contexts 为
      异构审上下文（≥2 才可能得出零发现结论），axes 为对抗轴问题清单；
    - 本批一律产出 BLOCKED + NOT_APPLICABLE；actual_exit_code=0 语义同
      Station5LiveFirePlaceholder（占位判定进程内完成）。
    """

    STATION_ID = 6
    IMPLEMENTED = False

    def __init__(self, manifest: RunManifest) -> None:
        _require_manifest(manifest)
        self._manifest = manifest

    def scan(
        self,
        *,
        contexts: Iterable[Mapping[str, Any]] = (),
        axes: Iterable[str] = (),
    ) -> Dict[str, Any]:
        started = _iso_z(_utc_now())
        argv = ["wenqu_core.station7_runtime", "station6-adversarial-placeholder",
                self._manifest.run_id]
        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st6-placeholder"),
            execution_status="BLOCKED",
            policy_verdict="NOT_APPLICABLE",
            identity=_manifest_identity(self._manifest),
            tool={
                "name": "wenqu_core.station7_runtime.Station6AdversarialPlaceholder",
                "version": __version__,
            },
            execution={
                "argv_digest": TrustedRunner.argv_digest(argv),
                "started_at": started,
                "ended_at": _iso_z(_utc_now()),
                "timeout_s": 1,
                "actual_exit_code": 0,
                "expected_exit_set": [0],
                "assertion_verdict": "ERROR",
            },
            coverage={"denominator": 0, "scanned": 0},
        )


# ---------------------------------------------------------------------------
# 端到端自证（python3 -m wenqu_core.station7_runtime）
# ---------------------------------------------------------------------------


def _self_test() -> int:  # noqa: C901——自测允许长函数
    import sys

    from .bugscan_orchestrator import BugscanPlanner, default_registry

    registry = default_registry()
    registry.validate()
    planner = BugscanPlanner(registry)
    plan = planner.plan("INCIDENT")
    assert plan.required_stations == (0, 1, 2, 3, 4, 6, 7), plan.required_stations

    sha = "1" * 40
    manifest = planner.freeze_run_manifest(
        plan,
        run_id="selftest-st7-001",
        project_id="wenqu-selftest",
        commit_sha=sha,
        environment="production",
        scope=["src/**", "daemons/**"],
        ruleset={"version": "w6d", "rules": ["W6A-ST7"]},
        data_config={"profile": "default"},
    )

    import tempfile as _tf

    with _tf.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)

        # [1] 哨兵活性：新鲜/过期/探针缺失 + 日志格式 ------------------------
        fresh_beat = tmpdir / "fresh.json"
        fresh_beat.write_text(json.dumps(
            {"last_beat_at": _iso_z(_utc_now()), "state": "healthy",
             "business": {"events_seen": 12}}), encoding="utf-8")
        stale_beat = tmpdir / "stale.json"
        stale_beat.write_text(json.dumps(
            {"last_beat_at": _iso_z(_utc_now() - timedelta(hours=3)),
             "state": "healthy"}), encoding="utf-8")
        log_beat = tmpdir / "sentinel.log"
        log_beat.write_text(
            f"{_utc_now().astimezone().strftime('%Y-%m-%d %H:%M:%S')} [INFO] round ok\n",
            encoding="utf-8",
        )

        sentinels = SentinelHealthScanner(
            manifest,
            sentinels=[
                {"name": "ci-event", "kind": "heartbeat_json",
                 "path": str(fresh_beat), "freshness_s": 7200},
                {"name": "conservation", "kind": "heartbeat_log",
                 "path": str(log_beat), "freshness_s": 900},
            ],
        )
        st = sentinels.scan()
        validate_station_result(st)
        assert st["policy_verdict"] == "PASS" and st["coverage"] == {"denominator": 2, "scanned": 2}
        print(f"[1a] sentinel PASS OK: 2/2 业务心跳新鲜（非 PID/mtime 判活）")

        dead = SentinelHealthScanner(
            manifest,
            sentinels=[
                {"name": "ci-event", "kind": "heartbeat_json",
                 "path": str(fresh_beat), "freshness_s": 7200},
                {"name": "stale-one", "kind": "heartbeat_json",
                 "path": str(stale_beat), "freshness_s": 7200},
                {"name": "gone", "kind": "heartbeat_json",
                 "path": str(tmpdir / "nope.json"), "freshness_s": 60},
            ],
        )
        st = dead.scan()
        assert st["execution_status"] == "BLOCKED" and st["policy_verdict"] == "NOT_EVALUATED"
        assert st["coverage"]["scanned"] == 2 < st["coverage"]["denominator"]
        assert dead.last_breakdown["sentinels_dead"][0]["reason"] == "stale"
        assert dead.last_breakdown["probes_unavailable"] == ["gone"]
        print("[1b] sentinel dead/unavailable OK: stale→FAIL 记录 + probe 缺失→缩水 BLOCKED")

        only_dead = SentinelHealthScanner(
            manifest,
            sentinels=[{"name": "stale-one", "kind": "heartbeat_json",
                        "path": str(stale_beat), "freshness_s": 7200}],
        )
        st = only_dead.scan()
        assert st["policy_verdict"] == "FAIL" and st["finding_ids"][0].startswith("fnd_sentinel_")
        print(f"[1c] sentinel FAIL OK: 哨兵死 → {st['finding_ids']}")

        # [2] SLO：达标/破线/指标缺失 ----------------------------------------
        slo = SloMonitorScanner(
            manifest,
            slos=[
                {"name": "availability", "target": 0.999, "op": ">="},
                {"name": "p95_latency_ms", "target": 800, "op": "<="},
                {"name": "error_rate", "target": 0.01, "op": "<"},
            ],
            snapshot={"availability": 0.9995, "p95_latency_ms": 640.0,
                      "error_rate": 0.004},
        )
        st = slo.scan()
        validate_station_result(st)
        assert st["policy_verdict"] == "PASS" and st["coverage"] == {"denominator": 3, "scanned": 3}
        print("[2a] slo PASS OK: 3/3 指标达标")

        breached = SloMonitorScanner(
            manifest,
            slos=[{"name": "availability", "target": 0.999, "op": ">="}],
            snapshot={"availability": 0.991},
        )
        st = breached.scan()
        assert st["policy_verdict"] == "FAIL" and len(st["finding_ids"]) == 1
        assert st["finding_ids"][0].startswith("fnd_slo_")
        print(f"[2b] slo FAIL OK: 破线 → {st['finding_ids']}")

        gap = SloMonitorScanner(
            manifest,
            slos=[
                {"name": "availability", "target": 0.999},
                {"name": "not_collected", "target": 1.0},
            ],
            snapshot={"availability": 0.9997},
        )
        st = gap.scan()
        assert st["execution_status"] == "BLOCKED" and st["coverage"]["scanned"] == 1
        print("[2c] slo missing-metric OK: 采集缺口 1/2 → 缩水 BLOCKED")

        # [3] 告警通道：金丝雀往返 -------------------------------------------
        fake_send = tmpdir / "fake_send.py"
        fake_send.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "mode = sys.argv[1]\n"
            "token = sys.argv[2]\n"
            "receipt = sys.argv[3]\n"
            "if mode == 'exit2':\n"
            "    sys.exit(2)\n"
            "if mode == 'nofile':\n"
            "    sys.exit(0)\n"
            "payload = {'delivered': True, 'canary_token': token}\n"
            "if mode == 'badtoken':\n"
            "    payload['canary_token'] = 'preset-forged-token'\n"
            "Path(receipt).write_text(json.dumps(payload))\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )
        receipt_ok = tmpdir / "receipt-ok.json"
        receipt_badtoken = tmpdir / "receipt-badtoken.json"
        receipt_exit2 = tmpdir / "receipt-exit2.json"
        receipt_nofile = tmpdir / "receipt-nofile.json"  # 永不写入 → receipt_missing

        def _channel(name: str, mode: str, receipt: Path) -> Dict[str, Any]:
            return {
                "name": name,
                "argv_template": [sys.executable, str(fake_send), mode,
                                  "{token}", str(receipt)],
                "receipt_path": str(receipt),
            }

        alert = AlertChannelScanner(
            manifest,
            channels=[_channel("chan-ok", "ok", receipt_ok)],
            runner=TrustedRunner(timeout=30.0), timeout_s=30,
        )
        st = alert.scan()
        validate_station_result(st)
        assert st["policy_verdict"] == "PASS" and st["coverage"] == {"denominator": 1, "scanned": 1}
        assert alert.last_breakdown["channels_broken"] == []
        print("[3a] alert PASS OK: 金丝雀令牌往返验证（真的会叫）")

        broken = AlertChannelScanner(
            manifest,
            channels=[
                _channel("chan-badtoken", "badtoken", receipt_badtoken),
                _channel("chan-exit2", "exit2", receipt_exit2),
                _channel("chan-nofile", "nofile", receipt_nofile),
            ],
            runner=TrustedRunner(timeout=30.0), timeout_s=30,
        )
        st = broken.scan()
        assert st["policy_verdict"] == "FAIL" and st["coverage"]["scanned"] == 3
        assert len(st["finding_ids"]) == 3
        assert st["execution"]["actual_exit_code"] == 2  # 首个非零真值传播（exit2）
        reasons = {b["name"]: b["reason"] for b in broken.last_breakdown["channels_broken"]}
        assert reasons == {"chan-badtoken": "token_mismatch", "chan-exit2": "send_exit_2",
                           "chan-nofile": "receipt_missing"}
        print(f"[3b] alert FAIL OK: 伪回执/发送失败/无回执 → {sorted(reasons.values())}")

        gone = AlertChannelScanner(
            manifest,
            channels=[{"name": "chan-missing-cmd",
                       "argv_template": [str(tmpdir / "not-exist-binary"),
                                         "--send", "{token}"],
                       "receipt_path": str(tmpdir / "r.json")}],
            runner=TrustedRunner(timeout=30.0), timeout_s=30,
        )
        st = gone.scan()
        assert st["execution_status"] == "BLOCKED" and st["coverage"]["scanned"] == 0
        assert st["execution"]["actual_exit_code"] == -1
        print("[3c] alert probe-unavailable OK: 可执行缺失 → -1 哨兵 + 缩水 BLOCKED")

        # [4] 整站合并（哨兵活 + SLO 达标 + 告警通） -------------------------
        combined = scan_station7(
            sentinel=SentinelHealthScanner(
                manifest,
                sentinels=[
                    {"name": "ci-event", "kind": "heartbeat_json",
                     "path": str(fresh_beat), "freshness_s": 7200},
                ],
            ),
            slo=SloMonitorScanner(
                manifest,
                slos=[{"name": "availability", "target": 0.99}],
                snapshot={"availability": 0.999},
            ),
            alert=AlertChannelScanner(
                manifest,
                channels=[_channel("chan-ok", "ok", receipt_ok)],
                runner=TrustedRunner(timeout=30.0), timeout_s=30,
            ),
        )
        validate_station_result(combined)
        assert combined["station_id"] == 7 and combined["policy_verdict"] == "PASS"
        assert combined["coverage"]["denominator"] == 3  # 1 哨兵 + 1 SLO + 1 通道
        assert COUNTS_TOWARD_CONVERGENCE is False and BLOCKS_RELEASE is True
        print(f"[4] combine OK: station-7 single result "
              f"{combined['coverage']['scanned']}/{combined['coverage']['denominator']} → "
              f"{combined['policy_verdict']}（不计收敛轮/可阻断发布）")

        # [5] 站5/站6 占位 ---------------------------------------------------
        st5 = Station5LiveFirePlaceholder(manifest).scan(
            authorization={"approver": "owner", "scope": "order-create"})
        validate_station_result(st5)
        assert st5["station_id"] == 5 and st5["policy_verdict"] == "NOT_APPLICABLE"
        assert st5["execution_status"] == "BLOCKED"
        st6 = Station6AdversarialPlaceholder(manifest).scan(
            contexts=[{"endpoint": "cc"}, {"endpoint": "codex"}])
        validate_station_result(st6)
        assert st6["station_id"] == 6 and st6["policy_verdict"] == "NOT_APPLICABLE"
        assert Station5LiveFirePlaceholder.IMPLEMENTED is False
        assert Station6AdversarialPlaceholder.IMPLEMENTED is False
        print("[5] placeholders OK: 站5/站6 占位 → BLOCKED/NOT_APPLICABLE（含授权参数亦然）")

    print("SELF-TEST PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

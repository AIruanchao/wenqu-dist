# -*- coding: utf-8 -*-
"""capacity_monitor.py——容量安全边际监控（REQ-CAP-001 / AC-CAP-SAFE-MARGIN）。

正源与契约（本模块按 §20 验收表的容量行语义实现，模块内不写验收 ID
字面量——追踪矩阵归属纪律，见 test_ac_ops_families.py 专属测试）：
- Codex 方案 §22「容量、留存与隐私」：迁移/发布会同时占用旧账本、CAS、
  SQLite/WAL、备份和两版 release，须计算峰值并设定最小安全余量；不足即
  BLOCKED；禁止自动删除审计证据。峰值公式（冻结）::

      peak = legacy_snapshot + imported_db + WAL_peak + CAS_copy
           + backup + current_release + next_release + rollback_release

- 期望语义：峰值空间超过安全余量或磁盘满 → 容量闸切换 BLOCKED，
  旧证据和 current 均完整（只读快照可证，零删除/零改写）。

组件：
- ``DiskSample``            一次磁盘采样（真实采集或故障注入数字）。
- ``collect_disk_sample``    shutil.disk_usage 真实采集（唯一真实数据源）。
- ``injected_sample``        故障注入接口：只注入 used/free 数字，
                             绝不真塞盘（测试与演练的安全形态）。
- ``SampleLog``              jsonl append-only 采样流水（峰值记录正源）。
- ``CapacitySpec``           阈值（默认 0.90，可配）/最小安全余量/
                             路径配额/趋势窗口。
- ``CapacityMonitor.judge``  安全边际判定：used/(used+free) 超阈值、
                             磁盘满、路径配额超限、峰值预算吃掉安全余量
                             → CRITICAL finding（violations 全量列出）。
- ``CapacityMonitor.trend``  最近 N 样本最小二乘斜率 → 外推到达阈值的
                             时间估算（WARNING 早警，不 BLOCKED）。
- ``enforce_capacity_gate``  CRITICAL → capacity_gate=BLOCKED，附旧证据
                             与 current 的只读完整性清单。

安全构造（by construction）：
- 纯 stdlib；判定只消费采样数字（真实采集或显式注入），不采信任何
  外部自报结论；阈值比较用严格大于（阈值边界本身不算超）。
- ``enforce_capacity_gate`` 对证据面零写零删——完整性清单为只读哈希，
  「旧证据和 current 均完整」由哈希清单机器可证，而非口头声明。
- jsonl 日志 append-only：损坏行读取即抛错（fail-closed），绝不跳行
  静默继续。
"""

from __future__ import annotations

import hashlib
import json
import math
import shutil
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

__all__ = [
    "DEFAULT_USED_RATIO_THRESHOLD",
    "DEFAULT_MIN_HEADROOM_BYTES",
    "PEAK_BUDGET_COMPONENTS",
    "DiskSample",
    "CapacitySpec",
    "SampleLog",
    "CapacityMonitor",
    "collect_disk_sample",
    "injected_sample",
    "peak_budget_bytes",
    "enforce_capacity_gate",
    "integrity_manifest",
    "CapacityMonitorError",
    "CapacitySpecError",
    "SampleLogError",
    "CAP_WITHIN_MARGIN",
    "CAP_DISK_FULL",
    "CAP_USED_RATIO_EXCEEDED",
    "CAP_QUOTA_RATIO_EXCEEDED",
    "CAP_PEAK_BUDGET_EXCEEDS_HEADROOM",
    "CAP_TREND_THRESHOLD_APPROACH",
]

__version__ = "1.0.0"

#: used/(used+free) 安全边际阈值（默认 0.90，§22「设定最小安全余量」的比率形态）。
DEFAULT_USED_RATIO_THRESHOLD: float = 0.90

#: 峰值预算预留后的最小绝对安全余量（字节）。默认 2 GiB。
DEFAULT_MIN_HEADROOM_BYTES: int = 2 * 1024 ** 3

#: §22 冻结的峰值预算八分量（未知分量拒绝——防拼写缩水分母）。
PEAK_BUDGET_COMPONENTS: Tuple[str, ...] = (
    "legacy_snapshot", "imported_db", "wal_peak", "cas_copy",
    "backup", "current_release", "next_release", "rollback_release",
)

# finding 码（前缀 CAP 为容量域，不含验收 ID 字面量）
CAP_WITHIN_MARGIN = "CAP_WITHIN_MARGIN"
CAP_DISK_FULL = "CAP_DISK_FULL"
CAP_USED_RATIO_EXCEEDED = "CAP_USED_RATIO_EXCEEDED"
CAP_QUOTA_RATIO_EXCEEDED = "CAP_QUOTA_RATIO_EXCEEDED"
CAP_PEAK_BUDGET_EXCEEDS_HEADROOM = "CAP_PEAK_BUDGET_EXCEEDS_HEADROOM"
CAP_TREND_THRESHOLD_APPROACH = "CAP_TREND_THRESHOLD_APPROACH"

#: 判定优先级：磁盘满 > 配额超限 > 比率超限 > 峰值预算吃余量。
_VIOLATION_PRECEDENCE: Tuple[str, ...] = (
    CAP_DISK_FULL,
    CAP_QUOTA_RATIO_EXCEEDED,
    CAP_USED_RATIO_EXCEEDED,
    CAP_PEAK_BUDGET_EXCEEDS_HEADROOM,
)


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class CapacityMonitorError(ValueError):
    """容量监控基类错误——一律 fail-closed。"""


class CapacitySpecError(CapacityMonitorError):
    """规格非法：阈值/余量/配额/峰值分量不合规。"""


class SampleLogError(CapacityMonitorError):
    """采样日志非法：路径不可写、行损坏、样本字段缺失。"""


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_ts(value: Union[str, float, int, datetime]) -> datetime:
    """接受 ISO-8601（Z/带偏移）、epoch 秒或 datetime → aware datetime。"""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise CapacityMonitorError(f"timestamp must be finite, got {value!r}")
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise CapacityMonitorError(
                f"unparseable timestamp {value!r} (expect ISO-8601 or epoch seconds)"
            ) from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise CapacityMonitorError(f"unsupported timestamp type: {type(value).__name__}")


# ---------------------------------------------------------------------------
# DiskSample——一次磁盘采样（真实采集或注入数字）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiskSample:
    """磁盘采样值。不变量：total == used + free，三者非负。

    ``basis`` 区分数据来源：``real``=shutil.disk_usage 真实采集；
    ``injected``=故障注入数字（磁盘满/超阈值演练，不真塞盘）。
    """

    path: str
    used_bytes: int
    free_bytes: int
    total_bytes: int
    recorded_at: str
    basis: str = "real"

    def __post_init__(self) -> None:
        for name in ("used_bytes", "free_bytes", "total_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise CapacityMonitorError(
                    f"{name} must be a non-negative int, got {value!r}"
                )
        if self.total_bytes != self.used_bytes + self.free_bytes:
            raise CapacityMonitorError(
                f"total_bytes must equal used+free: "
                f"{self.total_bytes} != {self.used_bytes}+{self.free_bytes}"
            )
        if not isinstance(self.path, str) or not self.path:
            raise CapacityMonitorError("path must be a non-empty string")
        if self.basis not in ("real", "injected"):
            raise CapacityMonitorError(f"basis must be 'real'|'injected', got {self.basis!r}")
        _parse_ts(self.recorded_at)  # 时间戳必须可解析（fail-closed）

    @property
    def used_ratio(self) -> float:
        """used/(used+free)；全零盘（无任何容量）按 1.0 满盘 fail-closed。"""
        if self.total_bytes <= 0:
            return 1.0
        return self.used_bytes / self.total_bytes

    def to_payload(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "used_bytes": self.used_bytes,
            "free_bytes": self.free_bytes,
            "total_bytes": self.total_bytes,
            "recorded_at": self.recorded_at,
            "basis": self.basis,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "DiskSample":
        if not isinstance(payload, Mapping):
            raise SampleLogError(f"sample payload must be a mapping, got {type(payload).__name__}")
        missing = {"path", "used_bytes", "free_bytes", "total_bytes", "recorded_at"} - set(payload)
        if missing:
            raise SampleLogError(f"sample payload missing fields: {sorted(missing)}")
        try:
            return cls(
                path=str(payload["path"]),
                used_bytes=payload["used_bytes"],
                free_bytes=payload["free_bytes"],
                total_bytes=payload["total_bytes"],
                recorded_at=str(payload["recorded_at"]),
                basis=str(payload.get("basis", "real")),
            )
        except CapacityMonitorError as exc:
            raise SampleLogError(f"invalid sample payload: {exc}") from exc


def collect_disk_sample(path: Union[str, Path] = "/") -> DiskSample:
    """真实采集：shutil.disk_usage 是唯一真实数据源（statvfs 真值）。"""
    usage = shutil.disk_usage(str(path))
    return DiskSample(
        path=str(path),
        used_bytes=int(usage.used),
        free_bytes=int(usage.free),
        total_bytes=int(usage.total),
        recorded_at=_iso_z(_utc_now()),
        basis="real",
    )


def injected_sample(
    used_bytes: int,
    free_bytes: int,
    *,
    path: str = "<fault-injection>",
    at: Union[str, float, int, datetime, None] = None,
) -> DiskSample:
    """故障注入接口：模拟 used/free 数字（磁盘满/超阈值/趋势演练）。

    只构造数字样本，绝不向真实磁盘写数据；``basis='injected'`` 使
    判定链可区分演练与真实现势。
    """
    return DiskSample(
        path=path,
        used_bytes=used_bytes,
        free_bytes=free_bytes,
        total_bytes=used_bytes + free_bytes,
        recorded_at=_iso_z(_parse_ts(at) if at is not None else _utc_now()),
        basis="injected",
    )


def peak_budget_bytes(**components: int) -> int:
    """§22 峰值预算求和：只认冻结八分量，未知分量拒绝（防缩水分母）。

    例：peak_budget_bytes(legacy_snapshot=10**9, backup=2*10**9, ...)
    """
    unknown = set(components) - set(PEAK_BUDGET_COMPONENTS)
    if unknown:
        raise CapacitySpecError(
            f"unknown peak budget components {sorted(unknown)}; "
            f"frozen components are {list(PEAK_BUDGET_COMPONENTS)}"
        )
    total = 0
    for name in PEAK_BUDGET_COMPONENTS:
        value = components.get(name, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CapacitySpecError(f"component {name} must be a non-negative int, got {value!r}")
        total += value
    return total


# ---------------------------------------------------------------------------
# CapacitySpec——阈值/余量/配额/趋势参数
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapacitySpec:
    """安全边际规格（全部可配，默认值即产品契约）。"""

    #: used/(used+free) 超过该比率 → CRITICAL（严格大于；等于阈值不算超）。
    used_ratio_threshold: float = DEFAULT_USED_RATIO_THRESHOLD
    #: 峰值预算预留后剩余可用空间的最小值（字节），不足 → CRITICAL。
    min_headroom_bytes: int = DEFAULT_MIN_HEADROOM_BYTES
    #: 可选路径配额：path → quota_bytes（used/quota 超阈值同样 CRITICAL）。
    path_quotas: Mapping[str, int] = field(default_factory=dict)
    #: 趋势外推窗口：最近 N 个样本参与最小二乘斜率（最少 2）。
    trend_window: int = 4
    #: 早警视界：外推到达阈值的时间不超过该秒数 → WARNING。
    trend_horizon_s: float = 7.0 * 86400.0

    def __post_init__(self) -> None:
        threshold = self.used_ratio_threshold
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) \
                or not (0.0 < float(threshold) <= 1.0):
            raise CapacitySpecError(
                f"used_ratio_threshold must be in (0, 1], got {threshold!r}"
            )
        if isinstance(self.min_headroom_bytes, bool) \
                or not isinstance(self.min_headroom_bytes, int) \
                or self.min_headroom_bytes < 0:
            raise CapacitySpecError(
                f"min_headroom_bytes must be a non-negative int, got {self.min_headroom_bytes!r}"
            )
        if not isinstance(self.trend_window, int) or isinstance(self.trend_window, bool) \
                or self.trend_window < 2:
            raise CapacitySpecError(f"trend_window must be an int >= 2, got {self.trend_window!r}")
        if isinstance(self.trend_horizon_s, bool) \
                or not isinstance(self.trend_horizon_s, (int, float)) \
                or not math.isfinite(float(self.trend_horizon_s)) or self.trend_horizon_s <= 0:
            raise CapacitySpecError(
                f"trend_horizon_s must be a positive finite number, got {self.trend_horizon_s!r}"
            )
        for path, quota in self.path_quotas.items():
            if isinstance(quota, bool) or not isinstance(quota, int) or quota <= 0:
                raise CapacitySpecError(
                    f"path_quotas[{path!r}] must be a positive int, got {quota!r}"
                )


# ---------------------------------------------------------------------------
# SampleLog——jsonl append-only 峰值记录
# ---------------------------------------------------------------------------


class SampleLog:
    """采样流水（jsonl append-only）：每行一个样本 + 截至该行的峰值游标。

    读取损坏行即抛错（fail-closed）——峰值记录是容量判定的正源之一，
    不允许静默跳行导致峰值缩水。
    """

    def __init__(self, path: Union[str, Path]) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def _lines(self) -> List[str]:
        if not self._path.exists():
            return []
        text = self._path.read_text(encoding="utf-8")
        return [line for line in text.splitlines() if line.strip()]

    def append(self, sample: DiskSample) -> Dict[str, Any]:
        """追加一条采样记录；返回该行 payload（含截至本行的峰值游标）。"""
        if not isinstance(sample, DiskSample):
            raise SampleLogError(f"append expects DiskSample, got {type(sample).__name__}")
        prior_peak = self.peak_used_bytes()
        row = {
            **sample.to_payload(),
            "peak_used_bytes_so_far": max(prior_peak, sample.used_bytes),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        return row

    def entries(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for number, line in enumerate(self._lines(), start=1):
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise SampleLogError(
                    f"{self._path}:{number} corrupt jsonl line: {exc}"
                ) from exc
            if not isinstance(row, Mapping):
                raise SampleLogError(f"{self._path}:{number} row is not a mapping")
            rows.append(dict(row))
        return rows

    def samples(self) -> List[DiskSample]:
        """全部样本（按记录顺序）；字段非法即抛错。"""
        return [DiskSample.from_payload(row) for row in self.entries()]

    def recent(self, n: int) -> List[DiskSample]:
        """最近 n 个样本（时间正序返回，即最旧在前）。"""
        if n <= 0:
            raise SampleLogError(f"recent expects n >= 1, got {n}")
        return self.samples()[-n:]

    def peak_used_bytes(self) -> int:
        """日志内见过的最大 used_bytes（空日志为 0）。"""
        peak = 0
        for row in self.entries():
            value = row.get("peak_used_bytes_so_far", row.get("used_bytes", 0))
            if isinstance(value, int) and not isinstance(value, bool):
                peak = max(peak, value)
        return peak


# ---------------------------------------------------------------------------
# CapacityMonitor——判定与趋势
# ---------------------------------------------------------------------------


class CapacityMonitor:
    """容量安全边际监控：采样→峰值记录→判定→趋势外推。

    判定口径（judge，全部 CRITICAL 违例按优先级全量列出）：
    1. 磁盘满：free == 0（used_ratio>=1）。
    2. 路径配额超限：used/quota > 阈值（配额比磁盘总量更紧时生效）。
    3. 比率超限：used/(used+free) > 阈值（严格大于）。
    4. 峰值预算吃掉安全余量：free - peak_budget < min_headroom，
       即 used + peak_budget > total - min_headroom（§22 峰值方向）。
    """

    def __init__(
        self,
        spec: Optional[CapacitySpec] = None,
        sample_log: Optional[SampleLog] = None,
    ) -> None:
        self._spec = spec if spec is not None else CapacitySpec()
        if not isinstance(self._spec, CapacitySpec):
            raise CapacitySpecError(
                f"spec must be CapacitySpec, got {type(self._spec).__name__}"
            )
        if sample_log is not None and not isinstance(sample_log, SampleLog):
            raise SampleLogError(
                f"sample_log must be SampleLog, got {type(sample_log).__name__}"
            )
        self._log = sample_log

    @property
    def spec(self) -> CapacitySpec:
        return self._spec

    def sample(self, path: Union[str, Path] = "/") -> DiskSample:
        """真实采集一条样本；构造时给了 SampleLog 则同时落峰值记录。"""
        sample = collect_disk_sample(path)
        if self._log is not None:
            self._log.append(sample)
        return sample

    def judge(
        self,
        sample: DiskSample,
        *,
        peak_budget: int = 0,
    ) -> Dict[str, Any]:
        """安全边际判定 → finding（dict；severity ∈ OK/CRITICAL）。

        ``peak_budget`` 为 §22 八分量之和（可用 peak_budget_bytes() 构造）。
        finding 结构：code/severity/message + violations 全量列表 + 判定输入
        数字（used/free/total/ratio/headroom），机器可审计。
        """
        if not isinstance(sample, DiskSample):
            raise CapacityMonitorError(
                f"judge expects DiskSample, got {type(sample).__name__}"
            )
        if isinstance(peak_budget, bool) or not isinstance(peak_budget, int) \
                or peak_budget < 0:
            raise CapacitySpecError(
                f"peak_budget must be a non-negative int, got {peak_budget!r}"
            )
        threshold = float(self._spec.used_ratio_threshold)
        ratio = sample.used_ratio
        headroom = sample.free_bytes - peak_budget  # 峰值预留后的安全余量

        violations: List[Dict[str, Any]] = []
        if sample.free_bytes == 0 or ratio >= 1.0:
            violations.append({
                "code": CAP_DISK_FULL,
                "detail": f"free=0 磁盘满（used={sample.used_bytes}）",
            })
        quota = self._spec.path_quotas.get(sample.path)
        if quota is not None:
            quota_ratio = sample.used_bytes / quota
            if quota_ratio > threshold:
                violations.append({
                    "code": CAP_QUOTA_RATIO_EXCEEDED,
                    "detail": f"路径配额 {quota}B 下 used/quota={quota_ratio:.6f} "
                              f"> 阈值 {threshold}",
                    "quota_bytes": quota,
                    "quota_ratio": quota_ratio,
                })
        if ratio > threshold:
            violations.append({
                "code": CAP_USED_RATIO_EXCEEDED,
                "detail": f"used/(used+free)={ratio:.6f} > 阈值 {threshold}",
            })
        if headroom < self._spec.min_headroom_bytes:
            violations.append({
                "code": CAP_PEAK_BUDGET_EXCEEDS_HEADROOM,
                "detail": f"峰值预算 {peak_budget}B 预留后余量 {headroom}B "
                          f"< 最小安全余量 {self._spec.min_headroom_bytes}B",
                "headroom_bytes": headroom,
            })

        violations.sort(key=lambda v: _VIOLATION_PRECEDENCE.index(v["code"]))
        severity = "CRITICAL" if violations else "OK"
        code = violations[0]["code"] if violations else CAP_WITHIN_MARGIN
        if violations:
            message = f"容量安全边际被突破：{code}（{len(violations)} 项违例）"
        else:
            message = (f"容量在安全边际内（ratio={ratio:.6f} <= {threshold}，"
                       f"峰值预留后余量 {headroom}B >= {self._spec.min_headroom_bytes}B）")
        return {
            "code": code,
            "severity": severity,
            "message": message,
            "violations": violations,
            "sample": sample.to_payload(),
            "used_ratio": ratio,
            "used_ratio_threshold": threshold,
            "peak_budget_bytes": peak_budget,
            "headroom_bytes": headroom,
            "min_headroom_bytes": self._spec.min_headroom_bytes,
            "judged_at": _iso_z(_utc_now()),
        }

    # -- 趋势外推 -----------------------------------------------------------

    def trend(self, samples: Iterable[DiskSample]) -> Dict[str, Any]:
        """最近 N 样本最小二乘斜率 → 外推到达阈值的秒数估算。

        返回：slope_bytes_per_s / threshold_bytes / projected_seconds_to_threshold
        （不增长、时间跨度为零或样本不足时为 None + reason）/ 参与样本数。
        分母基准 = 最新样本的 used+free（对最新容量态势外推）。
        """
        window = list(samples)[-self._spec.trend_window:]
        if len(window) < 2:
            return {"slope_bytes_per_s": None, "projected_seconds_to_threshold": None,
                    "reason": "insufficient_samples", "samples_used": len(window),
                    "threshold_bytes": None}
        points = []
        for sample in window:
            epoch = _parse_ts(sample.recorded_at).timestamp()
            points.append((epoch, sample.used_bytes))
        t_mean = sum(t for t, _ in points) / len(points)
        u_mean = sum(u for _, u in points) / len(points)
        s_tt = sum((t - t_mean) ** 2 for t, _ in points)
        if s_tt <= 0.0:
            return {"slope_bytes_per_s": None, "projected_seconds_to_threshold": None,
                    "reason": "zero_time_span", "samples_used": len(points),
                    "threshold_bytes": None}
        slope = sum((t - t_mean) * (u - u_mean) for t, u in points) / s_tt
        last = window[-1]
        threshold_bytes = float(self._spec.used_ratio_threshold) * last.total_bytes
        if slope <= 0.0:
            return {"slope_bytes_per_s": slope, "threshold_bytes": threshold_bytes,
                    "projected_seconds_to_threshold": None,
                    "reason": "not_growing", "samples_used": len(points)}
        seconds = max(0.0, (threshold_bytes - last.used_bytes) / slope)
        return {
            "slope_bytes_per_s": slope,
            "threshold_bytes": threshold_bytes,
            "projected_seconds_to_threshold": seconds,
            "reason": "projected",
            "samples_used": len(points),
        }

    def trend_finding(self, projection: Mapping[str, Any]) -> Dict[str, Any]:
        """趋势外推 → WARNING 早警 finding（不 BLOCKED；到达阈值才 CRITICAL）。"""
        seconds = projection.get("projected_seconds_to_threshold")
        horizon = float(self._spec.trend_horizon_s)
        if seconds is None:
            return {
                "code": CAP_TREND_THRESHOLD_APPROACH,
                "severity": "OK",
                "message": f"趋势外推未命中视界（{projection.get('reason')}）",
                "projection": dict(projection),
                "trend_horizon_s": horizon,
            }
        if float(seconds) <= horizon:
            return {
                "code": CAP_TREND_THRESHOLD_APPROACH,
                "severity": "WARNING",
                "message": f"按最近 {projection.get('samples_used')} 样本斜率外推，"
                           f"约 {float(seconds):.0f}s 后到达安全边际阈值",
                "projection": dict(projection),
                "trend_horizon_s": horizon,
            }
        return {
            "code": CAP_TREND_THRESHOLD_APPROACH,
            "severity": "OK",
            "message": f"外推到达阈值需 {float(seconds):.0f}s，超出早警视界 {horizon:.0f}s",
            "projection": dict(projection),
            "trend_horizon_s": horizon,
        }


# ---------------------------------------------------------------------------
# 完整性清单与容量闸切换
# ---------------------------------------------------------------------------


def integrity_manifest(
    evidence_paths: Iterable[Union[str, Path]] = (),
    current_path: Union[str, Path, None] = None,
) -> Dict[str, Any]:
    """只读完整性清单：文件 → sha256+size；symlink → 目标；缺失如实标注。

    只读不写——「旧证据和 current 均完整」由调用前后清单相等机器可证。
    """
    manifest: Dict[str, Any] = {}
    for raw in evidence_paths:
        path = Path(raw)
        key = str(path)
        if path.is_symlink():
            manifest[key] = {"type": "symlink", "target": str(path.readlink())}
            continue
        if not path.exists():
            manifest[key] = {"type": "missing"}
            continue
        if not path.is_file():
            manifest[key] = {"type": "directory"}
            continue
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
                size += len(chunk)
        manifest[key] = {"type": "file", "size": size, "sha256": digest.hexdigest()}
    if current_path is not None:
        path = Path(current_path)
        if path.is_symlink():
            manifest["<current>"] = {"type": "symlink", "target": str(path.readlink())}
        elif path.is_file():
            payload = path.read_bytes()
            manifest["<current>"] = {
                "type": "file",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        else:
            manifest["<current>"] = {"type": "missing"}
    return manifest


def enforce_capacity_gate(
    finding: Mapping[str, Any],
    *,
    evidence_paths: Iterable[Union[str, Path]] = (),
    current_path: Union[str, Path, None] = None,
) -> Dict[str, Any]:
    """容量闸：CRITICAL finding → capacity_gate=BLOCKED。

    §22 铁律「禁止自动删除审计证据」的 by-construction 兑现：本函数对
    证据面与 current 零写零删，只附只读完整性清单；切换记录（本函数
    返回值）由调用方落到独立的决策账本，绝不覆写旧证据。
    """
    severity = str(finding.get("severity", ""))
    blocked = severity == "CRITICAL"
    return {
        "capacity_gate": "BLOCKED" if blocked else "OPEN",
        "triggered": blocked,
        "finding": dict(finding) if blocked else None,
        "integrity": integrity_manifest(evidence_paths, current_path),
        "deleted_or_modified": [],  # by construction 恒空
        "enforced_at": _iso_z(_utc_now()),
        "evidence_policy": "只读完整性清单；禁止自动删除/改写审计证据（§22）",
    }


# ---------------------------------------------------------------------------
# 端到端自证（python3 -m wenqu_core.capacity_monitor）
# ---------------------------------------------------------------------------


def _self_test() -> int:
    import tempfile

    GiB = 1024 ** 3
    with tempfile.TemporaryDirectory(prefix="wq_capmon_") as tmp:
        # [1] 真实采集 + jsonl 峰值记录
        log = SampleLog(Path(tmp) / "capacity-samples.jsonl")
        monitor = CapacityMonitor(spec=CapacitySpec(used_ratio_threshold=0.9999),
                                  sample_log=log)
        real = monitor.sample(path=tmp)
        assert real.basis == "real" and real.total_bytes == real.used_bytes + real.free_bytes
        assert log.samples()[-1] == real and log.peak_used_bytes() == real.used_bytes
        green = monitor.judge(real)
        assert green["severity"] == "OK" and green["code"] == CAP_WITHIN_MARGIN
        print(f"[1] real sample OK: ratio={real.used_ratio:.4f} 判定链绿，jsonl 峰值已落")

        # [2] 注入负例：超阈值 / 磁盘满 / 峰值预算 / 配额（各用显式规格）
        default_mon = CapacityMonitor()  # 0.90 阈值 / 2GiB 最小余量
        over = default_mon.judge(injected_sample(950 * GiB, 50 * GiB))
        assert over["severity"] == "CRITICAL" and over["code"] == CAP_USED_RATIO_EXCEEDED
        full = default_mon.judge(injected_sample(100 * GiB, 0))
        assert full["code"] == CAP_DISK_FULL
        budget = peak_budget_bytes(backup=550 * GiB, next_release=0)
        peak_mon = CapacityMonitor(CapacitySpec(min_headroom_bytes=100 * GiB))
        peak = peak_mon.judge(injected_sample(400 * GiB, 600 * GiB),
                              peak_budget=budget)
        assert peak["code"] == CAP_PEAK_BUDGET_EXCEEDS_HEADROOM
        quota_spec = CapacitySpec(used_ratio_threshold=0.90,
                                  path_quotas={"<fault-injection>": 100 * GiB})
        q = CapacityMonitor(quota_spec).judge(injected_sample(95 * GiB, 10 * 1024 * GiB))
        assert q["code"] == CAP_QUOTA_RATIO_EXCEEDED
        print("[2] injection negatives OK: 超阈值/满盘/峰值预算/配额 四向全红")

        # [3] 边界：等于阈值不算超（严格大于）
        edge = monitor.judge(injected_sample(900 * GiB, 100 * GiB))
        assert edge["severity"] == "OK"  # 0.9999 阈值下 0.90 未超
        edge_default = CapacityMonitor(CapacitySpec()).judge(
            injected_sample(900 * GiB, 100 * GiB))
        assert edge_default["severity"] == "OK", "ratio==threshold 边界不算超"
        print("[3] boundary OK: ratio==threshold 不触发（严格大于语义）")

        # [4] 趋势外推：线性增长 5h 到阈值；平盘不外推
        series = [injected_sample((100 + 100 * k) * GiB, 600 * GiB, at=3600.0 * k)
                  for k in range(4)]
        proj = monitor.trend(series)
        assert proj["projected_seconds_to_threshold"] is not None
        flat = monitor.trend([injected_sample(400 * GiB, 600 * GiB, at=k * 3600.0)
                              for k in range(4)])
        assert flat["projected_seconds_to_threshold"] is None
        print(f"[4] trend OK: 外推 {proj['projected_seconds_to_threshold']:.0f}s；平盘 None")

        # [5] 容量闸：BLOCKED 切换 + 完整性只读
        ev = Path(tmp) / "ledger.jsonl"
        ev.write_text("evidence-v1\n", encoding="utf-8")
        cur = Path(tmp) / "current"
        target = Path(tmp) / "releases" / "r1"
        target.mkdir(parents=True)
        cur.symlink_to(target)
        before = integrity_manifest([ev], current_path=cur)
        decision = enforce_capacity_gate(over, evidence_paths=[ev], current_path=cur)
        assert decision["capacity_gate"] == "BLOCKED"
        assert decision["integrity"] == before and decision["deleted_or_modified"] == []
        assert ev.read_text(encoding="utf-8") == "evidence-v1\n"
        print("[5] gate OK: CRITICAL→BLOCKED，旧证据/current 完整性清单可证零改动")

    print("SELF-TEST PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

"""scheduler.py——Codex 方案 W4（§13）：统一调度 / Watchdog / Outbox。

四个组件（共享一个 SQLite WAL 运行态库，单写者模型，与 store.py 同款事务纪律）：

- ScheduleRegistry     全局调度注册表：job_id/owner/schedule/环境/due_window/
                       catch_up/watchdog；负责到期计算、睡眠/唤醒补跑、
                       时区/DST 处理（zoneinfo 逐日重算墙钟，绝不跨 DST 平移）。
- JobRunner            调用 TrustedRunner 执行 argv，按统一退出码契约
                       （§7）产出结构化结果：execution_status + policy_verdict +
                       actual_exit_code + commit_sha；run+heartbeat+outbox
                       落在**同一事务**（事务性 outbox）。
- NotificationOutbox   事务内落 outbox → 指数退避重试 → 最大尝试 →
                       dead-letter → dead-letter 本身走 CRITICAL 双通道
                       （系统通知递归有环保护）。
- HeartbeatMonitor     只看**业务结果与新鲜度**，不看 PID/mtime——进程活但
                       功能死 = 不健康（FUNCTION_DEAD，CRITICAL）。

心跳刷新铁律（本模块最核心的不可降级约束）：
    只有 COMPLETED + PASS、同 (job, probe, station) 身份、同输入指纹、
    且结果仍在 TTL 内的记录才允许推进 last_success_at；
    - COMPLETED + NOT_APPLICABLE 不刷新成功时间（它只声明"不适用"）；
    - CONDITIONAL ≠ PASS，同样不刷新；
    - 输入指纹变化 = 旧成功对新输入失效（不变量 #3），成功时间按新指纹重置，
      直到新指纹上出现新的 COMPLETED+PASS。

时间纪律（T-09）：内部一律 UTC epoch（REAL），墙钟调度逐日经 zoneinfo 换算，
时钟回拨只影响"迟到程度"不影响单调推进（next_due_at 只前进不后退）。
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from datetime import time as dtime
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .runner import Evidence, EvidenceStore, TrustedRunner
from .store import EventStore

__all__ = [
    "SchedulerError",
    "ScheduleSpec",
    "WatchdogPolicy",
    "JobDefinition",
    "DueOccurrence",
    "RunRecord",
    "HealthReport",
    "SchedulerStore",
    "ScheduleRegistry",
    "JobRunner",
    "NotificationOutbox",
    "HeartbeatMonitor",
    "compute_input_fingerprint",
    "EXIT_CODE_CONTRACT",
    "EXECUTION_STATUSES",
    "POLICY_VERDICTS",
    "CATCH_UP_POLICIES",
    "ENVIRONMENTS",
    "SEVERITIES",
]

log = logging.getLogger("wenqu.scheduler")

# ---------------------------------------------------------------------------
# 契约常量（wenqu-vNext-contract.md §2/§7 冻结值）
# ---------------------------------------------------------------------------

EXECUTION_STATUSES = ("COMPLETED", "ERROR", "BLOCKED", "TIMEOUT", "CANCELLED")
POLICY_VERDICTS = (
    "PASS",
    "FAIL",
    "CONDITIONAL",
    "NOT_APPLICABLE",
    "NOT_EVALUATED",
)

#: 统一退出码契约（§7）：actual_exit_code → (execution_status, policy_verdict)。
#: 未列出的退出码一律按 ERROR + NOT_EVALUATED 处理（不得折算为 PASS）。
EXIT_CODE_CONTRACT: Dict[int, Tuple[str, str]] = {
    0: ("COMPLETED", "PASS"),
    1: ("COMPLETED", "FAIL"),
    2: ("ERROR", "NOT_EVALUATED"),
    3: ("BLOCKED", "NOT_EVALUATED"),
    4: ("COMPLETED", "CONDITIONAL"),
    124: ("TIMEOUT", "NOT_EVALUATED"),
}

CATCH_UP_POLICIES = ("NONE", "COALESCE", "ALL")
ENVIRONMENTS = ("local", "staging", "production")
SEVERITIES = ("INFO", "WARNING", "CRITICAL")

# 到期枚举的硬上限（1s 间隔睡 1024 秒以上只保留最近 PLAN_LIMIT 次做计划；
# 更早的按策略跳过并落审计，绝不无界展开）
_PLAN_LIMIT_INTERVAL = 1024
_PLAN_LIMIT_DAILY = 400

_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_HHMM_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class SchedulerError(RuntimeError):
    """调度器使用/状态错误（注册非法、作业不存在、禁用强跑等）。"""


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_input_fingerprint(
    *,
    argv_digest: Optional[str] = None,
    commit_sha: Optional[str] = None,
    environment: Optional[str] = None,
    scope_hash: Optional[str] = None,
    ruleset_hash: Optional[str] = None,
    data_config_hash: Optional[str] = None,
    lockfile_hash: Optional[str] = None,
) -> str:
    """输入指纹：身份+输入的规范化 sha256（None 统一为空串参与规范化）。

    心跳刷新以"同指纹"为前提——PASS 证明的是**这组输入**合格；
    指纹变了（commit/scope/规则集/argv 任一变化），旧 PASS 对新输入无效。
    """
    payload = {
        "argv_digest": argv_digest or "",
        "commit_sha": commit_sha or "",
        "environment": environment or "",
        "scope_hash": scope_hash or "",
        "ruleset_hash": ruleset_hash or "",
        "data_config_hash": data_config_hash or "",
        "lockfile_hash": lockfile_hash or "",
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _as_epoch(now: Optional[float]) -> float:
    return time.time() if now is None else float(now)


# ---------------------------------------------------------------------------
# 值对象
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScheduleSpec:
    """调度规格：interval（固定间隔，绝对时间）或 daily（墙钟，DST 感知）。

    - interval：anchor + k*interval，DST 无关（绝对时间推进）。
    - daily：每次出现都经 zoneinfo 逐日换算——春令时"不存在的墙钟"按
      PEP 495 fold=0 解析为跳变后的时刻（单调、每天恰一次）；秋令时
      重复墙钟取第一次出现。绝不做"固定 UTC 偏移平移"。
    """

    kind: str  # "interval" | "daily"
    interval_seconds: Optional[float] = None
    daily_time: Optional[str] = None  # "HH:MM"（本地墙钟）
    tz_name: str = "UTC"

    def __post_init__(self) -> None:
        self.validate()

    # -- 校验 -------------------------------------------------------------
    def validate(self) -> None:
        if self.kind == "interval":
            if not self.interval_seconds or self.interval_seconds < 1.0:
                raise SchedulerError(
                    f"interval schedule requires interval_seconds >= 1.0, "
                    f"got {self.interval_seconds!r}"
                )
        elif self.kind == "daily":
            if not self.daily_time or not _HHMM_RE.match(self.daily_time):
                raise SchedulerError(
                    f"daily schedule requires daily_time 'HH:MM', "
                    f"got {self.daily_time!r}"
                )
        else:
            raise SchedulerError(f"unknown schedule kind: {self.kind!r}")
        try:
            ZoneInfo(self.tz_name)
        except (ZoneInfoNotFoundError, ValueError, KeyError) as exc:
            raise SchedulerError(f"unknown timezone {self.tz_name!r}: {exc}") from exc

    # -- 工厂 -------------------------------------------------------------
    @staticmethod
    def every(seconds: float) -> "ScheduleSpec":
        return ScheduleSpec(kind="interval", interval_seconds=float(seconds))

    @staticmethod
    def daily_at(hhmm: str, *, tz: str = "UTC") -> "ScheduleSpec":
        return ScheduleSpec(kind="daily", daily_time=hhmm, tz_name=tz)

    # -- 计算 -------------------------------------------------------------
    def _daily_hhmm(self) -> Tuple[int, int]:
        m = _HHMM_RE.match(self.daily_time or "")
        assert m is not None  # validate() 已保证
        return int(m.group(1)), int(m.group(2))

    def _tzinfo(self) -> ZoneInfo:
        cached = self.__dict__.get("_tz_cache")
        if cached is None:
            cached = ZoneInfo(self.tz_name)
            object.__setattr__(self, "_tz_cache", cached)
        return cached

    def first_due_after(self, after: float) -> float:
        """严格晚于 after 的下一次出现时刻（epoch，单调）。

        interval 锚定在作业自身时间线（注册时刻 + k*interval），
        不做墙钟网格对齐——"every N 秒"即注册后恰好 N 秒首跑。
        """
        if self.kind == "interval":
            return after + float(self.interval_seconds or 0.0)
        hh, mm = self._daily_hhmm()
        tz = self._tzinfo()
        cur = datetime.fromtimestamp(after, tz).date()
        for _ in range(_PLAN_LIMIT_DAILY * 2):
            cand = datetime.combine(cur, dtime(hh, mm), tzinfo=tz).timestamp()
            if cand > after + 1e-6:
                return cand
            cur += timedelta(days=1)
        raise SchedulerError("daily schedule: no occurrence within search horizon")

    def pending_occurrences(
        self, first: float, now: float
    ) -> Tuple[List[float], int, bool]:
        """从首个待办 first 起枚举 <= now 的出现，返回 (保留列表, 总数, 是否截断)。

        保留列表最多 _PLAN_LIMIT_* 条且**保留最近的**（老的对补跑无意义）。
        """
        if self.kind == "interval":
            step = float(self.interval_seconds or 0.0)
            total = int(math.floor((now - first) / step)) + 1
            if total <= 0:
                return [], 0, False
            if total <= _PLAN_LIMIT_INTERVAL:
                return [first + k * step for k in range(total)], total, False
            last = first + (total - 1) * step
            kept = [last - k * step for k in range(_PLAN_LIMIT_INTERVAL - 1, -1, -1)]
            return kept, total, True
        out: List[float] = []
        cursor = first
        while cursor <= now + 1e-9 and len(out) < _PLAN_LIMIT_DAILY:
            out.append(cursor)
            cursor = self.first_due_after(cursor)
        total = len(out)
        overflow = cursor <= now
        if overflow:  # 保留最近 _PLAN_LIMIT_DAILY 个
            out = out[-_PLAN_LIMIT_DAILY:]
        return out, total, overflow


@dataclass(frozen=True)
class WatchdogPolicy:
    """看门狗策略：只信业务结果的新鲜度。"""

    freshness_seconds: float = 900.0  # last_success_at 距今超过此值=不健康
    grace_seconds: float = 0.0  # 注册后多久内无结果不算告警（首跑宽限）

    def __post_init__(self) -> None:
        if self.freshness_seconds <= 0:
            raise SchedulerError("watchdog freshness_seconds must be > 0")
        if self.grace_seconds < 0:
            raise SchedulerError("watchdog grace_seconds must be >= 0")


@dataclass(frozen=True)
class JobDefinition:
    """调度注册表条目（Codex §13 字段全集）。"""

    job_id: str
    owner: str
    argv: Tuple[str, ...]
    schedule: ScheduleSpec
    environment: str
    probe_id: str
    station_id: int
    cwd: Optional[str] = None
    due_window_seconds: float = 300.0  # 迟于此窗口的到期视为"过期"，按 catch_up 处置
    catch_up: str = "COALESCE"  # NONE | COALESCE | ALL
    max_catch_up_runs: int = 8  # ALL 模式最多补跑次数
    watchdog: WatchdogPolicy = field(default_factory=WatchdogPolicy)
    ttl_seconds: float = 300.0  # 结果有效期：超 TTL 的 PASS 不得刷新心跳
    expected_exit_set: Tuple[int, ...] = (0,)  # 允许的退出码（负例探针可含非零）
    commit_sha: Optional[str] = None
    scope_hash: Optional[str] = None
    ruleset_hash: Optional[str] = None
    data_config_hash: Optional[str] = None
    lockfile_hash: Optional[str] = None
    channels: Tuple[str, ...] = ("primary",)  # 常规通知通道
    enabled: bool = True

    def __post_init__(self) -> None:
        if not _JOB_ID_RE.match(self.job_id or ""):
            raise SchedulerError(f"illegal job_id: {self.job_id!r}")
        if not self.owner:
            raise SchedulerError("owner must be non-empty")
        if not isinstance(self.argv, (tuple, list)) or not self.argv:
            raise SchedulerError("argv must be a non-empty tuple of strings")
        if any(not isinstance(a, str) for a in self.argv):
            raise SchedulerError("argv items must be strings")
        if self.environment not in ENVIRONMENTS:
            raise SchedulerError(
                f"environment must be one of {ENVIRONMENTS}, got {self.environment!r}"
            )
        if not self.probe_id:
            raise SchedulerError("probe_id must be non-empty")
        if not (0 <= self.station_id <= 7):
            raise SchedulerError("station_id must be in [0, 7]")
        if self.due_window_seconds < 0:
            raise SchedulerError("due_window_seconds must be >= 0")
        if self.catch_up not in CATCH_UP_POLICIES:
            raise SchedulerError(
                f"catch_up must be one of {CATCH_UP_POLICIES}, got {self.catch_up!r}"
            )
        if self.max_catch_up_runs < 1:
            raise SchedulerError("max_catch_up_runs must be >= 1")
        if self.ttl_seconds <= 0:
            raise SchedulerError("ttl_seconds must be > 0")
        if self.commit_sha is not None and not _SHA_RE.match(self.commit_sha):
            raise SchedulerError("commit_sha must be 40-hex or None")
        if not self.channels:
            raise SchedulerError("channels must be non-empty")
        if not self.expected_exit_set:
            raise SchedulerError("expected_exit_set must be non-empty")


@dataclass(frozen=True)
class DueOccurrence:
    """一次到期决策：run=True 需执行（scheduled_at 传给 run_job），
    run=False 需调用 mark_skipped 落审计并消费。"""

    job_id: str
    scheduled_at: float
    run: bool
    reason: str  # on_time | coalesced | catch_up_all | stale | missed | overrun
    missed_count: int  # 本次唤醒累计错过的出现次数
    stale: bool  # 是否已超出 due_window


@dataclass(frozen=True)
class RunRecord:
    """结构化执行结果（JobRunner 的唯一产出形态）。"""

    run_id: str
    job_id: str
    probe_id: str
    station_id: int
    environment: str
    scheduled_at: Optional[float]
    started_at: float
    finished_at: float
    execution_status: str
    policy_verdict: str
    actual_exit_code: Optional[int]
    commit_sha: Optional[str]
    argv_digest: str
    input_fingerprint: str
    evidence_digest: Optional[str]
    timed_out: bool
    refreshed_heartbeat: bool
    notifications_enqueued: int
    replayed: bool = False
    warnings: Tuple[str, ...] = ()

    def fresh_until(self, ttl_seconds: float) -> float:
        return self.finished_at + ttl_seconds


@dataclass(frozen=True)
class HealthReport:
    """心跳健康报告。state ∈ FRESH | GRACE | STALE_NO_RESULT |
    STALE_NO_SUCCESS | FUNCTION_DEAD。"""

    job_id: str
    probe_id: str
    station_id: int
    state: str
    healthy: bool
    severity: Optional[str]  # None | INFO | WARNING | CRITICAL
    detail: str
    freshness_seconds: float
    last_success_at: Optional[float]
    last_result_at: Optional[float]
    last_execution_status: Optional[str]
    last_policy_verdict: Optional[str]
    consecutive_failures: int
    success_age: Optional[float] = None


# ---------------------------------------------------------------------------
# 运行态存储（调度器自有 SQLite；事件正源仍是 EventStore，审计另行追加）
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduler_jobs (
    job_id                      TEXT PRIMARY KEY,
    owner                       TEXT NOT NULL,
    argv_json                   TEXT NOT NULL,
    cwd                         TEXT,
    environment                 TEXT NOT NULL,
    probe_id                    TEXT NOT NULL,
    station_id                  INTEGER NOT NULL,
    expected_exit_set_json      TEXT NOT NULL,
    schedule_kind               TEXT NOT NULL,
    interval_seconds            REAL,
    daily_time                  TEXT,
    daily_tz                    TEXT NOT NULL,
    due_window_seconds          REAL NOT NULL,
    catch_up                    TEXT NOT NULL,
    max_catch_up_runs           INTEGER NOT NULL,
    watchdog_freshness_seconds  REAL NOT NULL,
    watchdog_grace_seconds      REAL NOT NULL,
    ttl_seconds                 REAL NOT NULL,
    commit_sha                  TEXT,
    scope_hash                  TEXT,
    ruleset_hash                TEXT,
    data_config_hash            TEXT,
    lockfile_hash               TEXT,
    channels_json               TEXT NOT NULL,
    enabled                     INTEGER NOT NULL DEFAULT 1,
    created_at                  REAL NOT NULL,
    next_due_at                 REAL,
    last_consumed_at            REAL
);

CREATE TABLE IF NOT EXISTS scheduler_runs (
    run_id              TEXT PRIMARY KEY,
    job_id              TEXT NOT NULL,
    probe_id            TEXT NOT NULL,
    station_id          INTEGER NOT NULL,
    environment         TEXT NOT NULL,
    scheduled_at        REAL,
    started_at          REAL NOT NULL,
    finished_at         REAL NOT NULL,
    execution_status    TEXT NOT NULL,
    policy_verdict      TEXT NOT NULL,
    actual_exit_code    INTEGER,
    commit_sha          TEXT,
    argv_digest         TEXT NOT NULL,
    input_fingerprint   TEXT NOT NULL,
    evidence_digest     TEXT,
    timed_out           INTEGER NOT NULL DEFAULT 0,
    refreshed_heartbeat INTEGER NOT NULL DEFAULT 0,
    notifications_enqueued INTEGER NOT NULL DEFAULT 0,
    warnings_json       TEXT NOT NULL DEFAULT '[]',
    UNIQUE (job_id, scheduled_at)
);
CREATE INDEX IF NOT EXISTS idx_scheduler_runs_job
    ON scheduler_runs (job_id, started_at);

CREATE TABLE IF NOT EXISTS scheduler_heartbeats (
    job_id                 TEXT NOT NULL,
    probe_id               TEXT NOT NULL,
    station_id             INTEGER NOT NULL,
    input_fingerprint      TEXT NOT NULL,
    last_success_at        REAL,
    last_result_at         REAL,
    last_execution_status  TEXT,
    last_policy_verdict    TEXT,
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    updated_at             REAL NOT NULL,
    PRIMARY KEY (job_id, probe_id, station_id)
);

CREATE TABLE IF NOT EXISTS scheduler_outbox (
    message_id       TEXT PRIMARY KEY,
    dedup_key        TEXT UNIQUE,
    channel          TEXT NOT NULL,
    severity         TEXT NOT NULL,
    subject          TEXT NOT NULL,
    body             TEXT NOT NULL,
    meta_json        TEXT,
    status           TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING|SENT|DEAD_LETTER
    attempts         INTEGER NOT NULL DEFAULT 0,
    max_attempts     INTEGER NOT NULL,
    next_attempt_at  REAL NOT NULL,
    created_at       REAL NOT NULL,
    sent_at          REAL,
    dead_lettered_at REAL,
    last_error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbox_dispatch
    ON scheduler_outbox (status, next_attempt_at);

CREATE TABLE IF NOT EXISTS scheduler_skips (
    job_id       TEXT NOT NULL,
    scheduled_at REAL NOT NULL,
    skipped_at   REAL NOT NULL,
    reason       TEXT NOT NULL,
    PRIMARY KEY (job_id, scheduled_at)
);
"""


class SchedulerStore:
    """调度器运行态库（WAL；写事务一律 BEGIN IMMEDIATE，单写者 + RLock）。"""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(_SCHEMA)
        self._lock = threading.RLock()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @contextmanager
    def transaction(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def query(self, sql: str, params: Sequence[Any] = ()) -> List[tuple]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SchedulerStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _coerce_store(store: "SchedulerStore | str") -> SchedulerStore:
    if isinstance(store, SchedulerStore):
        return store
    return SchedulerStore(str(store))


# ---------------------------------------------------------------------------
# ScheduleRegistry
# ---------------------------------------------------------------------------


class ScheduleRegistry:
    """全局调度注册表 + 到期计算（纯函数式：due_jobs 不改状态）。

    补跑/过期语义（due_window 与 catch_up 的组合，逐出现判定）：
    - 过期判定：now - scheduled_at > due_window 的出现为 stale。
    - NONE：从不补跑错过的批量——只执行"队首且仍新鲜"的那一次；
      队首已过期则全部跳过；其余批量跳过（missed）。
    - COALESCE：把所有仍新鲜的出现折叠为**最新一次**执行；更早的新鲜
      出现记 coalesced 跳过；全部过期则全部跳过（stale）。
    - ALL：按时间正序补跑最近 max_catch_up_runs 次（不管是否过期——
      显式回填模式）；更老的记 overrun 跳过。

    消费协议（调用方）：对 run=True 的项调用 JobRunner.run_job(job_id,
    scheduled_at=...)；对 run=False 的项调用 mark_skipped(...)。两者都会
    在各自事务里把 next_due_at 推进到被消费出现的下一次（只前进不后退），
    并以 (job_id, scheduled_at) 唯一键保证重放幂等。崩溃在"计划已出、
    尚未执行"之间：状态未变，下次唤醒重新计算（计划是纯函数）。
    """

    def __init__(self, store: "SchedulerStore | str") -> None:
        self._store = _coerce_store(store)

    # -- 注册表维护 -------------------------------------------------------
    def register(self, job: JobDefinition, *, replace: bool = False,
                 now: Optional[float] = None) -> None:
        now = _as_epoch(now)
        if not replace and self.get(job.job_id) is not None:
            raise SchedulerError(f"job already registered: {job.job_id}")
        schedule = job.schedule
        with self._store.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scheduler_jobs ("
                " job_id, owner, argv_json, cwd, environment, probe_id, station_id,"
                " expected_exit_set_json, schedule_kind, interval_seconds, daily_time,"
                " daily_tz, due_window_seconds, catch_up, max_catch_up_runs,"
                " watchdog_freshness_seconds, watchdog_grace_seconds, ttl_seconds,"
                " commit_sha, scope_hash, ruleset_hash, data_config_hash,"
                " lockfile_hash, channels_json, enabled, created_at, next_due_at,"
                " last_consumed_at"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    job.job_id, job.owner, _canonical_json(list(job.argv)), job.cwd,
                    job.environment, job.probe_id, job.station_id,
                    _canonical_json(list(job.expected_exit_set)),
                    schedule.kind, schedule.interval_seconds, schedule.daily_time,
                    schedule.tz_name, job.due_window_seconds, job.catch_up,
                    job.max_catch_up_runs, job.watchdog.freshness_seconds,
                    job.watchdog.grace_seconds, job.ttl_seconds, job.commit_sha,
                    job.scope_hash, job.ruleset_hash, job.data_config_hash,
                    job.lockfile_hash, _canonical_json(list(job.channels)),
                    1 if job.enabled else 0, now,
                    schedule.first_due_after(now), None,
                ),
            )

    def unregister(self, job_id: str) -> bool:
        with self._store.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM scheduler_jobs WHERE job_id = ?", (job_id,)
            )
            return cur.rowcount == 1

    def set_enabled(self, job_id: str, enabled: bool) -> None:
        with self._store.transaction() as conn:
            cur = conn.execute(
                "UPDATE scheduler_jobs SET enabled = ? WHERE job_id = ?",
                (1 if enabled else 0, job_id),
            )
            if cur.rowcount != 1:
                raise SchedulerError(f"unknown job: {job_id}")

    def get(self, job_id: str) -> Optional[JobDefinition]:
        rows = self._store.query(
            "SELECT * FROM scheduler_jobs WHERE job_id = ?", (job_id,)
        )
        return self._row_to_job(rows[0]) if rows else None

    def list_jobs(self, *, enabled: Optional[bool] = None) -> List[JobDefinition]:
        if enabled is None:
            rows = self._store.query("SELECT * FROM scheduler_jobs ORDER BY job_id")
        else:
            rows = self._store.query(
                "SELECT * FROM scheduler_jobs WHERE enabled = ? ORDER BY job_id",
                (1 if enabled else 0,),
            )
        return [self._row_to_job(r) for r in rows]

    def job_state(self, job_id: str) -> Dict[str, Any]:
        rows = self._store.query(
            "SELECT enabled, created_at, next_due_at, last_consumed_at "
            "FROM scheduler_jobs WHERE job_id = ?",
            (job_id,),
        )
        if not rows:
            raise SchedulerError(f"unknown job: {job_id}")
        enabled, created_at, next_due_at, last_consumed_at = rows[0]
        return {
            "enabled": bool(enabled),
            "registered_at": created_at,
            "next_due_at": next_due_at,
            "last_consumed_at": last_consumed_at,
        }

    # -- 到期计算（纯读） ---------------------------------------------------
    def due_jobs(self, now: Optional[float] = None) -> List[DueOccurrence]:
        now = _as_epoch(now)
        out: List[DueOccurrence] = []
        for row in self._store.query(
            "SELECT job_id, schedule_kind, interval_seconds, daily_time, daily_tz,"
            " due_window_seconds, catch_up, max_catch_up_runs, next_due_at"
            " FROM scheduler_jobs WHERE enabled = 1 ORDER BY job_id"
        ):
            (
                job_id, kind, interval_s, daily_time, daily_tz,
                due_window, catch_up, max_runs, next_due,
            ) = row
            if next_due is None or next_due > now:
                continue
            schedule = (
                ScheduleSpec(kind="interval", interval_seconds=interval_s)
                if kind == "interval"
                else ScheduleSpec(kind="daily", daily_time=daily_time,
                                  tz_name=daily_tz)
            )
            pendings, total, overflow = schedule.pending_occurrences(float(next_due), now)
            if not pendings:
                continue
            fresh = [o for o in pendings if now - o <= due_window]
            out.extend(self._plan(job_id, pendings, fresh, total, overflow,
                                  catch_up, int(max_runs), due_window, now))
        return out

    # -- 内部 ---------------------------------------------------------------
    @staticmethod
    def _plan(job_id: str, pendings: List[float], fresh: List[float],
              total: int, overflow: bool, catch_up: str, max_runs: int,
              due_window: float, now: float) -> List[DueOccurrence]:
        def occ(t: float, run: bool, reason: str) -> DueOccurrence:
            return DueOccurrence(job_id=job_id, scheduled_at=t, run=run,
                                 reason=reason, missed_count=total,
                                 stale=(now - t) > due_window)

        plan: List[DueOccurrence] = []
        if catch_up == "ALL":
            keep = pendings[-max_runs:]
            dropped = pendings[:-max_runs] if len(pendings) > max_runs else []
            for t in dropped:
                plan.append(occ(t, False, "overrun"))
            for t in keep:
                plan.append(occ(t, True, "catch_up_all"))
        elif catch_up == "COALESCE":
            if fresh:
                target = fresh[-1]
                for t in pendings:
                    if t == target:
                        plan.append(occ(t, True, "coalesced"))
                    elif t in fresh:
                        plan.append(occ(t, False, "coalesced"))
                    else:
                        plan.append(occ(t, False, "stale"))
            else:
                for t in pendings:
                    plan.append(occ(t, False, "stale"))
        else:  # NONE
            head = pendings[0]
            if fresh and head in fresh:
                plan.append(occ(head, True, "on_time"))
            else:
                plan.append(occ(head, False, "stale"))
            for t in pendings[1:]:
                plan.append(occ(t, False, "missed"))
        if overflow:
            log.warning(
                "job %s: %d occurrences pending (capped at %d in plan)",
                job_id, total, len(pendings),
            )
        return plan

    @staticmethod
    def _row_to_job(row: tuple) -> JobDefinition:
        (
            job_id, owner, argv_json, cwd, environment, probe_id, station_id,
            expected_json, kind, interval_s, daily_time, daily_tz,
            due_window, catch_up, max_runs, wd_fresh, wd_grace, ttl,
            commit_sha, scope_hash, ruleset_hash, data_config_hash,
            lockfile_hash, channels_json, enabled, _created, _next, _last,
        ) = row
        schedule = (
            ScheduleSpec(kind="interval", interval_seconds=interval_s)
            if kind == "interval"
            else ScheduleSpec(kind="daily", daily_time=daily_time, tz_name=daily_tz)
        )
        return JobDefinition(
            job_id=job_id, owner=owner, argv=tuple(json.loads(argv_json)),
            schedule=schedule, environment=environment, probe_id=probe_id,
            station_id=int(station_id), cwd=cwd,
            due_window_seconds=float(due_window), catch_up=catch_up,
            max_catch_up_runs=int(max_runs),
            watchdog=WatchdogPolicy(freshness_seconds=float(wd_fresh),
                                    grace_seconds=float(wd_grace)),
            ttl_seconds=float(ttl),
            expected_exit_set=tuple(json.loads(expected_json)),
            commit_sha=commit_sha, scope_hash=scope_hash,
            ruleset_hash=ruleset_hash, data_config_hash=data_config_hash,
            lockfile_hash=lockfile_hash,
            channels=tuple(json.loads(channels_json)), enabled=bool(enabled),
        )

    # -- 消费推进（写，供 JobRunner/mark_skipped 在各自事务内调用） ---------
    @staticmethod
    def _advance_next_due_tx(conn: sqlite3.Connection, job: JobDefinition,
                             consumed_at: float) -> None:
        """next_due_at ← max(现值, 消费出现的下一次)；只前进不后退。"""
        row = conn.execute(
            "SELECT next_due_at FROM scheduler_jobs WHERE job_id = ?",
            (job.job_id,),
        ).fetchone()
        if row is None:
            raise SchedulerError(f"unknown job: {job.job_id}")
        current = row[0] if row[0] is not None else 0.0
        nxt = max(float(current), job.schedule.first_due_after(consumed_at))
        conn.execute(
            "UPDATE scheduler_jobs SET next_due_at = ?, last_consumed_at = ? "
            "WHERE job_id = ?",
            (nxt, consumed_at, job.job_id),
        )

    def mark_skipped(self, job_id: str, scheduled_at: float, reason: str,
                     now: Optional[float] = None) -> None:
        """消费一个被跳过的出现：落审计 + 推进 next_due（同一事务）。"""
        now = _as_epoch(now)
        job = self.get(job_id)
        if job is None:
            raise SchedulerError(f"unknown job: {job_id}")
        with self._store.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scheduler_skips"
                " (job_id, scheduled_at, skipped_at, reason) VALUES (?,?,?,?)",
                (job_id, scheduled_at, now, reason),
            )
            self._advance_next_due_tx(conn, job, float(scheduled_at))


# ---------------------------------------------------------------------------
# NotificationOutbox
# ---------------------------------------------------------------------------

ChannelSender = Callable[[Dict[str, Any]], None]


class NotificationOutbox:
    """事务性发件箱：指数退避 → 最大尝试 → dead-letter → CRITICAL 双通道。

    - enqueue 与业务状态变更同事务（JobRunner 内部直连同一连接）。
    - CRITICAL 消息强制双通道（critical_channels，缺省 primary+fallback），
      每通道独立重试、独立死信。
    - 任一消息死信后，自动经双通道发一条 CRITICAL "通知管线断裂"告警；
      该系统告警自身死信时不再递归（环保护）。
    - dedup_key 唯一：重复告警（同窗口）自动合并。
    """

    def __init__(
        self,
        store: "SchedulerStore | str",
        *,
        critical_channels: Tuple[str, ...] = ("primary", "fallback"),
        backoff_base_seconds: float = 60.0,
        backoff_cap_seconds: float = 3600.0,
        max_attempts: int = 5,
    ) -> None:
        if len(critical_channels) < 2:
            raise SchedulerError("critical_channels requires at least 2 channels")
        if backoff_base_seconds <= 0 or backoff_cap_seconds < backoff_base_seconds:
            raise SchedulerError("illegal backoff configuration")
        if max_attempts < 1:
            raise SchedulerError("max_attempts must be >= 1")
        self._store = _coerce_store(store)
        self._critical_channels = tuple(critical_channels)
        self._backoff_base = float(backoff_base_seconds)
        self._backoff_cap = float(backoff_cap_seconds)
        self._max_attempts = int(max_attempts)
        self._channels: Dict[str, ChannelSender] = {}

    # -- 通道注册 -----------------------------------------------------------
    def register_channel(self, name: str, sender: ChannelSender) -> None:
        self._channels[name] = sender

    @property
    def critical_channels(self) -> Tuple[str, ...]:
        return self._critical_channels

    # -- 入队 ---------------------------------------------------------------
    def notify(
        self,
        severity: str,
        subject: str,
        body: str,
        *,
        channels: Optional[Sequence[str]] = None,
        meta: Optional[Dict[str, Any]] = None,
        dedup_key: Optional[str] = None,
        now: Optional[float] = None,
    ) -> List[Optional[str]]:
        """按严重度选通道并入队（CRITICAL 强制双通道）；返回各通道 message_id。"""
        if severity not in SEVERITIES:
            raise SchedulerError(f"unknown severity: {severity!r}")
        targets = (
            self._critical_channels
            if severity == "CRITICAL"
            else tuple(channels or ("primary",))
        )
        now = _as_epoch(now)
        ids: List[Optional[str]] = []
        with self._store.transaction() as conn:
            for ch in targets:
                # dedup_key 必须按通道区分：否则双通道的第二条会被全局
                # UNIQUE 去重掉，CRITICAL 冗余通道静默失效。
                ch_key = f"{dedup_key}:{ch}" if dedup_key else None
                ids.append(
                    self._enqueue_tx(conn, ch, severity, subject, body,
                                     meta=meta, dedup_key=ch_key, now=now)
                )
        return ids

    @staticmethod
    def _enqueue_tx(
        conn: sqlite3.Connection,
        channel: str,
        severity: str,
        subject: str,
        body: str,
        *,
        meta: Optional[Dict[str, Any]] = None,
        dedup_key: Optional[str] = None,
        max_attempts: int = 5,
        now: float = 0.0,
    ) -> Optional[str]:
        """事务内落一行 outbox（dedup 命中返回 None）。"""
        message_id = uuid.uuid4().hex
        cur = conn.execute(
            "INSERT OR IGNORE INTO scheduler_outbox ("
            " message_id, dedup_key, channel, severity, subject, body, meta_json,"
            " status, attempts, max_attempts, next_attempt_at, created_at"
            ") VALUES (?,?,?,?,?,?,?,?,0,?,?,?)",
            (
                message_id, dedup_key, channel, severity, subject, body,
                _canonical_json(meta) if meta else None,
                "PENDING", max_attempts, now, now,
            ),
        )
        return message_id if cur.rowcount == 1 else None

    # -- 投递 ---------------------------------------------------------------
    def dispatch_due(self, now: Optional[float] = None, *,
                     batch: int = 64) -> Dict[str, Any]:
        now = _as_epoch(now)
        rows = self._store.query(
            "SELECT message_id, channel, severity, subject, body, meta_json,"
            " attempts, max_attempts FROM scheduler_outbox"
            " WHERE status = 'PENDING' AND next_attempt_at <= ?"
            " ORDER BY created_at LIMIT ?",
            (now, batch),
        )
        sent = dead = failed = 0
        errors: List[str] = []
        for (message_id, channel, severity, subject, body, meta_json,
             attempts, max_attempts) in rows:
            sender = self._channels.get(channel)
            payload = {
                "message_id": message_id, "channel": channel,
                "severity": severity, "subject": subject, "body": body,
                "meta": json.loads(meta_json) if meta_json else {},
                "attempts": attempts,
            }
            err = ""
            if sender is None:
                err = f"channel {channel!r} not registered"
            else:
                try:
                    sender(payload)
                except Exception as exc:  # 通道实现任意异常=投递失败
                    err = f"{type(exc).__name__}: {exc}"
            dead_lettered = False
            with self._store.transaction() as conn:
                if not err:
                    conn.execute(
                        "UPDATE scheduler_outbox SET status='SENT', sent_at=?,"
                        " attempts=attempts+1, last_error=NULL"
                        " WHERE message_id=? AND status='PENDING'",
                        (now, message_id),
                    )
                    sent += 1
                else:
                    attempts_new = attempts + 1
                    if attempts_new >= max_attempts:
                        conn.execute(
                            "UPDATE scheduler_outbox SET status='DEAD_LETTER',"
                            " attempts=?, dead_lettered_at=?, last_error=?"
                            " WHERE message_id=? AND status='PENDING'",
                            (attempts_new, now, err, message_id),
                        )
                        dead_lettered = True
                        dead += 1
                    else:
                        backoff = min(
                            self._backoff_base * (2 ** (attempts_new - 1)),
                            self._backoff_cap,
                        )
                        conn.execute(
                            "UPDATE scheduler_outbox SET attempts=?,"
                            " next_attempt_at=?, last_error=?"
                            " WHERE message_id=? AND status='PENDING'",
                            (attempts_new, now + backoff, err, message_id),
                        )
                        failed += 1
            if err:
                errors.append(f"{channel}/{message_id}: {err}")
            if dead_lettered:
                self._on_dead_letter(
                    message_id=message_id, channel=channel, subject=subject,
                    severity=severity, meta_json=meta_json, attempts=max_attempts,
                    last_error=err, now=now,
                )
        return {"sent": sent, "failed": failed, "dead_lettered": dead,
                "errors": errors}

    def _on_dead_letter(self, *, message_id: str, channel: str, subject: str,
                        severity: str, meta_json: Optional[str], attempts: int,
                        last_error: str, now: float) -> None:
        """死信处置：非系统告警本身 → 经双通道发 CRITICAL 管线断裂告警。"""
        try:
            meta = json.loads(meta_json) if meta_json else {}
        except (TypeError, ValueError):
            meta = {}
        if meta.get("system_dead_letter_notice"):
            log.critical(
                "dead-letter notice %s itself dead-lettered on %s; "
                "halting recursion (notification pipeline fully broken)",
                message_id, channel,
            )
            return
        self.notify(
            "CRITICAL",
            f"[wenqu] 通知死信：通道 {channel} 投递 {attempts} 次全部失败",
            f"死信消息 {message_id}（{severity}）：{subject}\n"
            f"最后错误：{last_error}\n"
            f"通知管线已断裂——人工介入。",
            meta={
                "system_dead_letter_notice": True,
                "dead_message_id": message_id,
                "dead_channel": channel,
            },
            dedup_key=f"deadletter:{message_id}",
            now=now,
        )

    # -- 观测 ---------------------------------------------------------------
    def stats(self) -> Dict[str, int]:
        rows = self._store.query(
            "SELECT status, COUNT(*) FROM scheduler_outbox GROUP BY status"
        )
        return {status: int(n) for status, n in rows}

    def dead_letters(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self._store.query(
            "SELECT message_id, channel, severity, subject, body, meta_json,"
            " attempts, max_attempts, created_at, dead_lettered_at, last_error"
            " FROM scheduler_outbox WHERE status='DEAD_LETTER'"
            " ORDER BY dead_lettered_at DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "message_id": r[0], "channel": r[1], "severity": r[2],
                "subject": r[3], "body": r[4], "meta": r[5],
                "attempts": r[6], "max_attempts": r[7], "created_at": r[8],
                "dead_lettered_at": r[9], "last_error": r[10],
            }
            for r in rows
        ]


# ---------------------------------------------------------------------------
# HeartbeatMonitor
# ---------------------------------------------------------------------------


class HeartbeatMonitor:
    """业务结果心跳监视：健康 = 「最近有 COMPLETED+PASS 且未超 freshness」。

    明确不看进程 PID/文件 mtime——进程活着只产生结果，不产生健康：
    - FUNCTION_DEAD：持续有结果但没有新鲜 PASS（进程活、功能死）→ CRITICAL。
    - STALE_NO_RESULT：既无新鲜成功也无近期结果（调度器/宿主死了）。
    - GRACE：刚注册还没到首跑宽限终点。
    """

    _HEARTBEAT_SQL = (
        "SELECT input_fingerprint, last_success_at, last_result_at,"
        " last_execution_status, last_policy_verdict, consecutive_failures"
        " FROM scheduler_heartbeats"
        " WHERE job_id=? AND probe_id=? AND station_id=?"
    )

    def __init__(self, store: "SchedulerStore | str",
                 outbox: Optional[NotificationOutbox] = None) -> None:
        self._store = _coerce_store(store)
        self._outbox = outbox

    # -- 记录结果（含刷新铁律） ---------------------------------------------
    @staticmethod
    def _classify_refresh(execution_status: str, policy_verdict: str,
                          finished_at: Optional[float], ttl_seconds: float,
                          now: float) -> bool:
        """刷新铁律：COMPLETED+PASS ∧ 结果仍在 TTL 内，其余一律不刷新。

        显式排除：
        - NOT_APPLICABLE（只声明"不适用"，不证明健康）；
        - CONDITIONAL（≠PASS，无独立风险授权不视为合格）；
        - 一切非 COMPLETED 执行态（ERROR/BLOCKED/TIMEOUT/CANCELLED）；
        - finished_at 距 now 超过 TTL 的过期结果。
        """
        if execution_status != "COMPLETED" or policy_verdict != "PASS":
            return False
        if finished_at is None:
            return False
        return (now - finished_at) <= ttl_seconds

    def _upsert_tx(self, conn: sqlite3.Connection, *, job_id: str,
                   probe_id: str, station_id: int, input_fingerprint: str,
                   execution_status: str, policy_verdict: str,
                   finished_at: Optional[float], ttl_seconds: float,
                   now: float) -> bool:
        """事务内 upsert；返回本次是否（为当前跟踪指纹）确立/推进了成功时间。"""
        eligible = self._classify_refresh(
            execution_status, policy_verdict, finished_at, ttl_seconds, now
        )
        row = conn.execute(
            self._HEARTBEAT_SQL, (job_id, probe_id, station_id)
        ).fetchone()
        succeeded = execution_status == "COMPLETED" and policy_verdict == "PASS"
        if row is None:
            conn.execute(
                "INSERT INTO scheduler_heartbeats ("
                " job_id, probe_id, station_id, input_fingerprint,"
                " last_success_at, last_result_at, last_execution_status,"
                " last_policy_verdict, consecutive_failures, updated_at"
                ") VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    job_id, probe_id, station_id, input_fingerprint,
                    now if eligible else None, now, execution_status,
                    policy_verdict, 0 if succeeded else 1, now,
                ),
            )
            return eligible
        (cur_fp, cur_success, _cur_result_at, _cur_status, _cur_verdict,
         cur_failures) = row
        if cur_fp != input_fingerprint:
            # 指纹变化：旧成功对新输入无效（不变量 #3）——按新指纹重置。
            new_success = now if eligible else None
        else:
            # 同指纹：只在合格时前进，绝不后退（此前从未成功则直接确立）。
            if eligible:
                new_success = (
                    now if cur_success is None else max(cur_success, now)
                )
            else:
                new_success = cur_success
        conn.execute(
            "UPDATE scheduler_heartbeats SET input_fingerprint=?,"
            " last_success_at=?, last_result_at=?, last_execution_status=?,"
            " last_policy_verdict=?, consecutive_failures=?, updated_at=?"
            " WHERE job_id=? AND probe_id=? AND station_id=?",
            (
                input_fingerprint, new_success, now, execution_status,
                policy_verdict, 0 if succeeded else cur_failures + 1, now,
                job_id, probe_id, station_id,
            ),
        )
        return eligible

    def record_result(self, *, job_id: str, probe_id: str, station_id: int,
                      input_fingerprint: str, execution_status: str,
                      policy_verdict: str, finished_at: Optional[float],
                      ttl_seconds: float, now: Optional[float] = None) -> bool:
        """外部结果的公共入口（JobRunner 走事务内路径，不经过这里）。"""
        now = _as_epoch(now)
        with self._store.transaction() as conn:
            return self._upsert_tx(
                conn, job_id=job_id, probe_id=probe_id, station_id=station_id,
                input_fingerprint=input_fingerprint,
                execution_status=execution_status, policy_verdict=policy_verdict,
                finished_at=finished_at, ttl_seconds=ttl_seconds, now=now,
            )

    # -- 健康检查 -------------------------------------------------------------
    def check_health(self, now: Optional[float] = None, *,
                     notify: bool = False) -> List[HealthReport]:
        now = _as_epoch(now)
        reports: List[HealthReport] = []
        rows = self._store.query(
            "SELECT j.job_id, j.probe_id, j.station_id,"
            " j.watchdog_freshness_seconds, j.watchdog_grace_seconds,"
            " j.ttl_seconds, j.channels_json, j.created_at, j.enabled,"
            " h.input_fingerprint, h.last_success_at, h.last_result_at,"
            " h.last_execution_status, h.last_policy_verdict,"
            " h.consecutive_failures"
            " FROM scheduler_jobs j LEFT JOIN scheduler_heartbeats h"
            " ON h.job_id = j.job_id AND h.probe_id = j.probe_id"
            " AND h.station_id = j.station_id"
            " ORDER BY j.job_id"
        )
        for r in rows:
            (job_id, probe_id, station_id, freshness, grace, _ttl,
             channels_json, created_at, enabled, _fp, last_success,
             last_result, last_status, last_verdict, failures) = r
            if not enabled:
                continue
            freshness = float(freshness)
            grace = float(grace)
            success_age = (now - last_success) if last_success is not None else None
            result_age = (now - last_result) if last_result is not None else None

            if success_age is not None and success_age <= freshness:
                state, healthy, severity = "FRESH", True, None
                detail = f"成功时间距今 {success_age:.0f}s（新鲜）"
            elif result_age is not None and result_age <= freshness:
                state, healthy, severity = "FUNCTION_DEAD", False, "CRITICAL"
                if success_age is None:
                    detail = (
                        f"持续有结果但从未 PASS（连续失败 {failures}）"
                        "——进程活、功能死"
                    )
                else:
                    detail = (
                        f"持续有结果但最近成功已 {success_age:.0f}s（>新鲜度"
                        f" {freshness:.0f}s，连续失败 {failures}）"
                        "——进程活、功能死"
                    )
            elif last_success is None and last_result is None:
                if now - float(created_at) <= max(grace, freshness):
                    state, healthy, severity = "GRACE", False, "INFO"
                    detail = "注册后尚未出结果（宽限期内）"
                else:
                    state, healthy, severity = "STALE_NO_SUCCESS", False, "CRITICAL"
                    detail = "从未产出任何结果——调度/作业停摆"
            elif last_result is not None and result_age > freshness:
                if success_age is not None and success_age <= 2 * freshness:
                    state, healthy, severity = (
                        "STALE_NO_RESULT", False, "WARNING"
                    )
                    detail = f"成功已 {success_age:.0f}s 且无近期执行"
                else:
                    state, healthy, severity = (
                        "STALE_NO_RESULT", False, "CRITICAL"
                    )
                    detail = (
                        f"成功已 {success_age if success_age is not None else -1:.0f}s"
                        " 且无近期执行——宿主/调度器疑已停摆"
                    )
            else:
                state, healthy, severity = "STALE_NO_SUCCESS", False, "CRITICAL"
                detail = "无新鲜成功（超出新鲜度窗口）"

            report = HealthReport(
                job_id=job_id, probe_id=probe_id, station_id=int(station_id),
                state=state, healthy=healthy, severity=severity, detail=detail,
                freshness_seconds=freshness, last_success_at=last_success,
                last_result_at=last_result, last_execution_status=last_status,
                last_policy_verdict=last_verdict,
                consecutive_failures=int(failures or 0),
                success_age=success_age,
            )
            reports.append(report)
            if notify and self._outbox is not None and severity in (
                "WARNING", "CRITICAL"
            ):
                self._outbox.notify(
                    severity,
                    f"[wenqu] 心跳不健康 {job_id}：{state}",
                    f"{detail}\nprobe={probe_id} station={station_id} "
                    f"freshness={freshness:.0f}s "
                    f"last_success={last_success} last_result={last_result}",
                    channels=tuple(json.loads(channels_json)),
                    dedup_key=(
                        f"heartbeat:{job_id}:{probe_id}:{station_id}:"
                        f"{state}:{int(now // freshness) if freshness > 0 else int(now)}"
                    ),
                    meta={"kind": "heartbeat", "state": state,
                          "job_id": job_id},
                    now=now,
                )
        return reports


# ---------------------------------------------------------------------------
# JobRunner
# ---------------------------------------------------------------------------


class JobRunner:
    """执行作业并把结构化结果、心跳、通知写入同一事务。

    退出码定性：先按统一退出码契约（§7），再用作业的 expected_exit_set
    修正（负例探针命中期望非零码 = PASS；rc=0 但 0 不在期望集 = FAIL）。
    TIMEOUT（无 returncode）不可折算为 PASS（不变量 #1）。
    """

    _NOTIFY_MAP = {
        ("COMPLETED", "FAIL"): "CRITICAL",
        ("COMPLETED", "CONDITIONAL"): "WARNING",
        ("ERROR", "NOT_EVALUATED"): "WARNING",
        ("BLOCKED", "NOT_EVALUATED"): "WARNING",
        ("TIMEOUT", "NOT_EVALUATED"): "WARNING",
    }

    def __init__(
        self,
        store: "SchedulerStore | str",
        runner: TrustedRunner,
        *,
        registry: Optional[ScheduleRegistry] = None,
        outbox: Optional[NotificationOutbox] = None,
        heartbeat: Optional[HeartbeatMonitor] = None,
        evidence_store: Optional[EvidenceStore] = None,
        event_store: Optional[EventStore] = None,
        commit_sha_provider: Optional[Callable[[], Optional[str]]] = None,
        notify_dedup_seconds: float = 3600.0,
    ) -> None:
        self._store = _coerce_store(store)
        self._runner = runner
        self._registry = registry or ScheduleRegistry(self._store)
        self._outbox = outbox or NotificationOutbox(self._store)
        self._heartbeat = heartbeat or HeartbeatMonitor(self._store, self._outbox)
        self._evidence_store = evidence_store
        self._event_store = event_store
        self._commit_sha_provider = commit_sha_provider
        self._notify_dedup = float(notify_dedup_seconds)

    # -- 退出码定性 -----------------------------------------------------------
    @staticmethod
    def classify_exit(rc: Optional[int], timed_out: bool,
                      expected_exit_set: Sequence[int]) -> Tuple[str, str]:
        if timed_out or rc is None:
            return "TIMEOUT", "NOT_EVALUATED"
        status, verdict = EXIT_CODE_CONTRACT.get(rc, ("ERROR", "NOT_EVALUATED"))
        if rc in expected_exit_set:
            if rc in (0, 1):
                verdict = "PASS"  # 期望内命中（含负例探针）
        elif verdict == "PASS":
            status, verdict = "COMPLETED", "FAIL"  # rc=0 但 0 不被期望
        return status, verdict

    # -- 执行 ---------------------------------------------------------------
    def run_job(self, job_id: str, *, scheduled_at: Optional[float] = None,
                now: Optional[float] = None, force: bool = False
                ) -> Optional[RunRecord]:
        """执行一个作业。scheduled_at 来自 DueOccurrence（幂等键）。

        返回 RunRecord（replayed=True 表示命中 (job_id, scheduled_at)
        幂等键、未重复执行）。manual（scheduled_at=None）不参与幂等去重，
        也不推进 next_due_at。
        """
        now = _as_epoch(now)
        job = self._registry.get(job_id)
        if job is None:
            raise SchedulerError(f"unknown job: {job_id}")
        if not job.enabled and not force:
            raise SchedulerError(f"job disabled: {job_id}")

        if scheduled_at is not None:
            existing = self._run_for(job_id, scheduled_at)
            if existing is not None:
                with self._store.transaction() as conn:
                    ScheduleRegistry._advance_next_due_tx(
                        conn, job, float(scheduled_at)
                    )
                return RunRecord(**{**existing, "replayed": True})

        started = time.time()
        warnings: List[str] = []

        commit_sha = job.commit_sha
        if commit_sha is None and self._commit_sha_provider is not None:
            try:
                commit_sha = self._commit_sha_provider() or None
            except Exception as exc:  # provider 故障不阻断执行
                warnings.append(f"commit_sha_provider failed: {exc}")

        argv_digest = TrustedRunner.argv_digest(list(job.argv))
        fingerprint = compute_input_fingerprint(
            argv_digest=argv_digest, commit_sha=commit_sha,
            environment=job.environment, scope_hash=job.scope_hash,
            ruleset_hash=job.ruleset_hash,
            data_config_hash=job.data_config_hash,
            lockfile_hash=job.lockfile_hash,
        )

        evidence: Optional[Evidence] = None
        spawn_error: Optional[str] = None
        try:
            evidence = self._runner.run(list(job.argv), cwd=job.cwd)
        except Exception as exc:
            # 启动/校验失败（可执行文件缺失、allowlist 拒绝、OSError）：
            # 如实记 ERROR——不是 TIMEOUT，也不是凭空消失。
            spawn_error = f"{type(exc).__name__}: {exc}"

        if spawn_error is not None:
            rc: Optional[int] = None
            timed_out = False
            status, verdict = "ERROR", "NOT_EVALUATED"
            warnings.append(f"spawn failed: {spawn_error}")
        else:
            assert evidence is not None
            rc = evidence.actual_exit_code
            timed_out = evidence.timed_out
            status, verdict = self.classify_exit(rc, timed_out,
                                                 job.expected_exit_set)
        finished = time.time()

        evidence_digest: Optional[str] = None
        if evidence is not None and self._evidence_store is not None:
            try:
                evidence_digest = self._evidence_store.put(evidence)
            except Exception as exc:
                warnings.append(f"evidence store write failed: {exc}")

        if scheduled_at is not None:
            run_id = f"job-{job_id}-{int(round(float(scheduled_at) * 1000))}"
        else:
            run_id = f"job-{job_id}-manual-{uuid.uuid4().hex[:12]}"

        # ---- 事务：run + heartbeat + outbox 原子落库（事务性 outbox） ----
        refreshed = False
        notified = 0
        with self._store.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scheduler_runs ("
                " run_id, job_id, probe_id, station_id, environment,"
                " scheduled_at, started_at, finished_at, execution_status,"
                " policy_verdict, actual_exit_code, commit_sha, argv_digest,"
                " input_fingerprint, evidence_digest, timed_out,"
                " refreshed_heartbeat, notifications_enqueued, warnings_json"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run_id, job_id, job.probe_id, job.station_id,
                    job.environment, scheduled_at, started, finished, status,
                    verdict, rc, commit_sha, argv_digest, fingerprint,
                    evidence_digest, 1 if timed_out else 0, 0, 0,
                    _canonical_json(warnings),
                ),
            )
            refreshed = self._heartbeat._upsert_tx(
                conn, job_id=job_id, probe_id=job.probe_id,
                station_id=job.station_id, input_fingerprint=fingerprint,
                execution_status=status, policy_verdict=verdict,
                finished_at=finished, ttl_seconds=job.ttl_seconds, now=now,
            )
            severity = self._NOTIFY_MAP.get((status, verdict))
            if severity is not None:
                notified = self._enqueue_result_notify_tx(
                    conn, job=job, status=status, verdict=verdict, rc=rc,
                    run_id=run_id, severity=severity, now=now,
                )
            conn.execute(
                "UPDATE scheduler_runs SET refreshed_heartbeat=?,"
                " notifications_enqueued=? WHERE run_id=?",
                (1 if refreshed else 0, notified, run_id),
            )
            if scheduled_at is not None:
                ScheduleRegistry._advance_next_due_tx(conn, job,
                                                      float(scheduled_at))

        record = RunRecord(
            run_id=run_id, job_id=job_id, probe_id=job.probe_id,
            station_id=job.station_id, environment=job.environment,
            scheduled_at=scheduled_at, started_at=started, finished_at=finished,
            execution_status=status, policy_verdict=verdict, actual_exit_code=rc,
            commit_sha=commit_sha, argv_digest=argv_digest,
            input_fingerprint=fingerprint, evidence_digest=evidence_digest,
            timed_out=timed_out, refreshed_heartbeat=refreshed,
            notifications_enqueued=notified, replayed=False,
            warnings=tuple(warnings),
        )

        # ---- 提交后：审计事件正源（尽力而为，失败告警不静默） ----
        if self._event_store is not None:
            try:
                self._event_store.append(self._audit_event(record))
            except Exception as exc:
                self._warn_post_commit(
                    f"event-store append failed for {run_id}: {exc}", record
                )
        for w in warnings:
            self._warn_post_commit(w, record)
        return record

    # -- 内部 ---------------------------------------------------------------
    def _run_for(self, job_id: str, scheduled_at: float
                 ) -> Optional[Dict[str, Any]]:
        rows = self._store.query(
            "SELECT * FROM scheduler_runs WHERE job_id=? AND scheduled_at=?",
            (job_id, scheduled_at),
        )
        return self._row_to_record_dict(rows[0]) if rows else None

    @staticmethod
    def _row_to_record_dict(row: tuple) -> Dict[str, Any]:
        return {
            "run_id": row[0], "job_id": row[1], "probe_id": row[2],
            "station_id": row[3], "environment": row[4], "scheduled_at": row[5],
            "started_at": row[6], "finished_at": row[7],
            "execution_status": row[8], "policy_verdict": row[9],
            "actual_exit_code": row[10], "commit_sha": row[11],
            "argv_digest": row[12], "input_fingerprint": row[13],
            "evidence_digest": row[14], "timed_out": bool(row[15]),
            "refreshed_heartbeat": bool(row[16]),
            "notifications_enqueued": row[17],
            "warnings": tuple(json.loads(row[18] or "[]")),
        }

    def _enqueue_result_notify_tx(self, conn: sqlite3.Connection, *,
                                  job: JobDefinition, status: str,
                                  verdict: str, rc: Optional[int], run_id: str,
                                  severity: str, now: float) -> int:
        targets = (
            self._outbox.critical_channels
            if severity == "CRITICAL"
            else job.channels
        )
        bucket = int(now // self._notify_dedup) if self._notify_dedup > 0 else 0
        dedup = (f"jobstatus:{job.job_id}:{status}:{verdict}:{bucket}")
        subject = f"[wenqu] 作业 {job.job_id} {status}/{verdict}"
        body = (
            f"run_id={run_id} exit={rc} probe={job.probe_id} "
            f"station={job.station_id} env={job.environment}"
        )
        n = 0
        for ch in targets:
            mid = NotificationOutbox._enqueue_tx(
                conn, ch, severity, subject, body,
                meta={"kind": "job_result", "job_id": job.job_id,
                      "run_id": run_id},
                dedup_key=f"{dedup}:{ch}",
                max_attempts=self._outbox._max_attempts,
                now=now,
            )
            if mid is not None:
                n += 1
        return n

    @staticmethod
    def _audit_event(record: RunRecord) -> Dict[str, Any]:
        payload = {
            "schema_version": "2.0",
            "event_type": "JOB_RESULT",
            "run_id": record.run_id,
            "job_id": record.job_id,
            "probe_id": record.probe_id,
            "station_id": record.station_id,
            "environment": record.environment,
            "scheduled_at": record.scheduled_at,
            "started_at": record.started_at,
            "finished_at": record.finished_at,
            "execution_status": record.execution_status,
            "policy_verdict": record.policy_verdict,
            "actual_exit_code": record.actual_exit_code,
            "commit_sha": record.commit_sha,
            "argv_digest": record.argv_digest,
            "input_fingerprint": record.input_fingerprint,
            "evidence_digest": record.evidence_digest,
            "timed_out": record.timed_out,
            "actor": "wenqu-scheduler",
        }
        return payload

    def _warn_post_commit(self, message: str, record: RunRecord) -> None:
        log.warning("%s (job=%s run=%s)", message, record.job_id,
                    record.run_id)
        try:
            self._outbox.notify(
                "WARNING",
                f"[wenqu] 调度器降级告警：{record.job_id}",
                message,
                channels=("primary",),
                dedup_key=(
                    f"runnerwarn:{record.job_id}:{message[:64]}:"
                    f"{int(time.time() // self._notify_dedup)}"
                ),
                meta={"kind": "runner_warning", "run_id": record.run_id},
            )
        except Exception:  # 告警失败绝不反向影响已提交的执行结果
            log.exception("post-commit warning notification failed")


# ===========================================================================
# W4 生产接线（launchd com.wenqu.scheduler）——纯追加节，不改动上方任何
# 既有类/函数语义（SCH/ALT/HLT/DOC 既有用例零回退约束）。
#
# 每 5 分钟一个 tick，闭环四件事：
#   1. 观察窗采样：以 TrustedRunner 真跑 tools/observation_daily.py
#      （复用其全部探针语义，非复刻）；run+heartbeat+outbox 同一事务。
#   2. gate 聚合刷新：把采样作业结果铸成 station-result-v2 落
#      ~/.wenqu/state/station-results/<station>.json（同站覆盖=只取最新），
#      调真 wenquctl gate 聚合，原子写 ~/.wenqu/state/gate-aggregate.json
#      （dashboard shadow 只读快照数据源由此激活）；无数据时如实写 BLOCKED。
#   3. 通知闭环：NotificationOutbox 双通道投递——macOS 通知（osascript
#      display notification）+ 文本投递箱 ~/.wenqu/observation/alerts/
#      （attempt/receipt/dead-letter 全审计；通知失败→投递箱必成功，
#      投递箱写入带 3 次重试，成功即 receipt 落 receipts.jsonl）。
#   4. 心跳与日志：~/.wenqu/observation/heartbeat.json（tick 级心跳）+
#      ~/.wenqu/observation/logs/scheduler-YYYY-MM-DD.jsonl（每 tick 一行）。
#
# 可测性：ProductionPaths 可整体注入（测试用临时 WENQU_HOME，绝不写真实
# ~/.wenqu）；now= 时钟接缝贯穿（模块文档时间纪律的正源）。
# ===========================================================================

import os as _os
import shutil as _shutil
import subprocess as _subprocess  # noqa: S404——仅 argv 列表调用，shell=False
from datetime import timezone as _timezone


PROD_JOB_ID = "w4.observation-sample"
PROD_PROBE_ID = "w4-observation-sampler"
PROD_STATION_ID = 0  # W4 生产观察站（station-result-v2 站位）
PROD_LABEL = "com.wenqu.scheduler"
PROD_TICK_INTERVAL = 300  # launchd StartInterval（秒）
PROD_CHANNEL_MACOS = "macos"
PROD_CHANNEL_ALERTBOX = "alertbox"


class ProductionPaths:
    """W4 生产运行的全部路径（env 可覆盖；测试整体注入）。"""

    __slots__ = (
        "repo_root", "wenqu_home", "state_dir", "scheduler_db",
        "gate_aggregate", "station_results_dir", "observation_root",
        "samples_dir", "shadow_dir", "alerts_dir", "drills_dir", "logs_dir",
        "heartbeat", "observation_daily", "cli_py",
    )

    def __init__(self, *, repo_root: str, wenqu_home: str) -> None:
        self.repo_root = repo_root
        self.wenqu_home = wenqu_home
        self.state_dir = _os.path.join(wenqu_home, "state")
        self.scheduler_db = _os.path.join(self.state_dir, "scheduler.db")
        self.gate_aggregate = _os.path.join(self.state_dir,
                                            "gate-aggregate.json")
        self.station_results_dir = _os.path.join(self.state_dir,
                                                 "station-results")
        self.observation_root = _os.path.join(wenqu_home, "observation")
        self.samples_dir = _os.path.join(self.observation_root, "samples")
        self.shadow_dir = _os.path.join(self.observation_root, "shadow")
        self.alerts_dir = _os.path.join(self.observation_root, "alerts")
        self.drills_dir = _os.path.join(self.observation_root, "drills")
        self.logs_dir = _os.path.join(self.observation_root, "logs")
        self.heartbeat = _os.path.join(self.observation_root, "heartbeat.json")
        self.observation_daily = _os.path.join(repo_root, "tools",
                                               "observation_daily.py")
        self.cli_py = _os.path.join(repo_root, "system", "wenqu_core",
                                    "cli.py")

    @staticmethod
    def from_env() -> "ProductionPaths":
        repo_root = _os.path.dirname(_os.path.dirname(_os.path.dirname(
            _os.path.abspath(__file__))))  # system/wenqu_core/ → 仓根
        wenqu_home = _os.environ.get("WENQU_HOME") or _os.path.expanduser(
            "~/.wenqu")
        return ProductionPaths(repo_root=repo_root, wenqu_home=wenqu_home)

    def ensure_dirs(self) -> None:
        for d in (self.state_dir, self.station_results_dir, self.samples_dir,
                  self.shadow_dir, self.alerts_dir, self.drills_dir,
                  self.logs_dir):
            _os.makedirs(d, exist_ok=True)


def _atomic_write_text(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    _os.replace(tmp, path)


def _atomic_write_json(path: str, payload: Any) -> None:
    _atomic_write_text(path, json.dumps(payload, ensure_ascii=False,
                                        indent=2, sort_keys=False) + "\n")


def _iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=_timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _git_head(repo_root: str) -> Optional[str]:
    git = _shutil.which("git") or "/usr/bin/git"
    try:
        p = _subprocess.run([git, "rev-parse", "HEAD"], capture_output=True,
                            text=True, timeout=15, cwd=repo_root)
    except (OSError, _subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    head = (p.stdout or "").strip().lower()
    return head if _SHA_RE.match(head) else None


def capacity_preflight(paths: "ProductionPaths", *,
                       now: Optional[float] = None) -> Dict[str, Any]:
    """B5 容量闸前置检查（tick 级，2026-10-09 接线；语义登记于
    evidence/11-shadow-canary/README.md）。

    - 判定：collect_disk_sample 真实采集 wenqu_home 挂载点 →
      CapacityMonitor.judge()（默认规格 0.90 阈值/2GiB 最小余量；观察
      tick 无 §22 峰值预算，peak_budget=0）；severity=CRITICAL →
      capacity_gate=BLOCKED。
    - 处置边界（刻意不阻断观察采样）：§22「不足即 BLOCKED」的处置对象
      是迁移/发布峰值操作（legacy_snapshot+...+rollback_release 八分量）；
      观察 tick 是 KB 级 JSON 追加写——容量压力下停观测等于自毁唯一
      告警通道，且 tick 的契约是「活着并如实上报」（tick_rc=0 语义
      不变）。BLOCKED 时经 outbox 发 CRITICAL 告警（调用方 dedup），
      移交人类决策。判定链异常 → 如实记 error、gate=UNKNOWN，不猜。
    """
    try:
        from .capacity_monitor import (  # 延迟导入：纯追加节不动模块顶 import 面
            CapacityMonitor,
            collect_disk_sample,
        )
        sample = collect_disk_sample(paths.wenqu_home)
        finding = CapacityMonitor().judge(sample)
        return {
            "capacity_gate": "BLOCKED" if finding["severity"] == "CRITICAL"
                             else "OPEN",
            "code": finding["code"],
            "severity": finding["severity"],
            "message": finding["message"],
            "violations": finding["violations"],
            "used_ratio": finding["used_ratio"],
            "used_ratio_threshold": finding["used_ratio_threshold"],
            "headroom_bytes": finding["headroom_bytes"],
            "min_headroom_bytes": finding["min_headroom_bytes"],
            "judged_at": finding["judged_at"],
            "sample": finding["sample"],
            "source": "wenqu_core.capacity_monitor.judge(collect_disk_sample"
                      "(wenqu_home), peak_budget=0)",
        }
    except Exception as exc:  # 判定链任何故障如实降级为 UNKNOWN（不猜 OPEN）
        log.exception("capacity preflight failed")
        return {
            "capacity_gate": "UNKNOWN",
            "error": f"{type(exc).__name__}: {exc}",
            "judged_at_epoch": _as_epoch(now),
        }


# ---------------------------------------------------------------------------
# G9-01/G9-02 唯一 writer 审计（观察采样只有一个调度入口=com.wenqu.scheduler）
# ---------------------------------------------------------------------------

#: 已退役的观察独立作业 label——install/scheduler 装配不得注册；
#: 运行面一经发现即第二 writer（audit rc1）。
FORBIDDEN_OBSERVATION_LABELS = (
    "com.wenqu.observation",
    "com.wenqu.observation-window",
)


def audit_launchd_observation_writers(
    launch_agents_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """扫描 LaunchAgents plist，找出 com.wenqu.scheduler 之外任何触及
    观察采样面的作业（旧独立观察作业/第二 writer）。只读，不猜。

    判据（Program 或 ProgramArguments 文本）：引用 observation_daily.py、
    ~/.wenqu/observation 路径或观察窗日志（legacy 作业特征）。
    唯一合法入口 PROD_LABEL 豁免。返回 findings（空=收敛）。"""
    import plistlib

    lad = launch_agents_dir or _os.path.expanduser(
        "~/Library/LaunchAgents")
    findings: List[Dict[str, Any]] = []
    try:
        names = sorted(_os.listdir(lad))
    except OSError:
        return findings
    for n in names:
        if not n.endswith(".plist"):
            continue
        p = _os.path.join(lad, n)
        try:
            with open(p, "rb") as fh:
                pl = plistlib.load(fh)
        except Exception:  # noqa: BLE001——plistlib/expat 对畸形 plist 抛多种异常
            # 无法解析 = 无法证明它不是观察 writer → fail-visible 记 finding
            # （launchd 自身若也拒载则该作业不会运行，但审计不猜）
            findings.append({"kind": "unparsable_plist", "label": n,
                             "plist": p})
            continue
        if not isinstance(pl, dict):
            continue
        label = str(pl.get("Label", "") or "")
        prog = str(pl.get("Program", "") or "")
        argv = " ".join(str(a) for a in (pl.get("ProgramArguments") or []))
        text = prog + " " + argv
        touches_observation = (
            "observation_daily.py" in text
            or "/.wenqu/observation" in text
            or "观察窗" in text
        )
        if not touches_observation:
            continue
        if label == PROD_LABEL:
            continue  # 唯一合法调度入口
        kind = ("forbidden_label" if label in FORBIDDEN_OBSERVATION_LABELS
                else "second_observation_writer")
        findings.append({"kind": kind, "label": label, "plist": p})
    return findings


def find_observation_writers(store: "SchedulerStore") -> List[str]:
    """scheduler 注册表内任何 argv/cwd 触及观察采样面的 enabled 作业。

    唯一合法 = PROD_JOB_ID（w4.observation-sample）；>1 或出现其它 job_id
    即第二 writer（G9-01/G9-02：发现第二 writer 时 rc1）。"""
    rows = store.query(
        "SELECT job_id, argv_json, cwd FROM scheduler_jobs WHERE enabled = 1"
    )
    out: List[str] = []
    for job_id, argv_json, cwd in rows:
        blob = str(argv_json) + " " + str(cwd or "")
        if ("observation_daily" in blob
                or "/observation/samples" in blob
                or "/observation/shadow" in blob):
            out.append(str(job_id))
    return sorted(out)


# ---------------------------------------------------------------------------
# 通知通道（W4 双通道）
# ---------------------------------------------------------------------------


def _applescript_escape(text: str) -> str:
    """AppleScript 字符串字面量转义 + 控制字符清洗（通知单行化）。"""
    cleaned = "".join(
        ch if ch >= " " and ch != "\x7f" else " " for ch in text)
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def make_macos_sender(*, osascript: Optional[str] = None) -> ChannelSender:
    """macOS 通知通道：osascript display notification（argv 列表，无 shell）。

    失败语义：osascript 不存在/超时/非零退出 → raise（由 outbox 记
    attempt 并按退避重试→dead-letter；alertbox 通道独立兜底）。
    """
    bin_path = osascript or _shutil.which("osascript") or "/usr/bin/osascript"

    def sender(payload: Dict[str, Any]) -> None:
        title = _applescript_escape(
            f"[wenqu:{payload.get('severity', 'INFO')}] "
            f"{str(payload.get('subject', ''))[:120]}")
        body = _applescript_escape(str(payload.get("body", ""))[:220])
        argv = [bin_path, "-e",
                f'display notification "{body}" with title "{title}"']
        try:
            p = _subprocess.run(argv, capture_output=True, text=True,
                                timeout=15)
        except (OSError, _subprocess.SubprocessError) as exc:
            raise RuntimeError(f"osascript spawn failed: {exc}") from exc
        if p.returncode != 0:
            raise RuntimeError(
                f"osascript rc={p.returncode}: "
                f"{(p.stderr or '').strip()[:200]}")

    return sender


def make_alertbox_sender(alerts_dir: str, *, retries: int = 3) -> ChannelSender:
    """文本投递箱通道：必成功通道（本地原子写 + N 次重试）。

    每条消息一个 txt（文件名含 message_id → 重试幂等覆盖）+ 回执追加
    receipts.jsonl（每行一个成功投递 attempt，含 message_id/时间/通道）。
    重试后仍失败 → raise → outbox 记 attempt（审计正源在库表）。
    """

    def sender(payload: Dict[str, Any]) -> None:
        mid = str(payload.get("message_id", "unknown"))
        ts = time.strftime("%Y%m%d-%H%M%S")
        name = f"{ts}-{payload.get('severity', 'INFO')}-{mid[:12]}.txt"
        path = _os.path.join(alerts_dir, name)
        text = (
            f"message_id: {mid}\n"
            f"channel: {PROD_CHANNEL_ALERTBOX}\n"
            f"severity: {payload.get('severity')}\n"
            f"sent_at: {_iso_utc(time.time())}\n"
            f"subject: {payload.get('subject', '')}\n"
            f"attempts_so_far: {payload.get('attempts', 0) + 1}\n"
            f"---\n{payload.get('body', '')}\n"
        )
        last_exc: Optional[BaseException] = None
        for attempt in range(max(1, retries)):
            try:
                _os.makedirs(alerts_dir, exist_ok=True)
                _atomic_write_text(path, text)
                with open(_os.path.join(alerts_dir, "receipts.jsonl"), "a",
                          encoding="utf-8") as fh:
                    fh.write(json.dumps({
                        "message_id": mid,
                        "channel": PROD_CHANNEL_ALERTBOX,
                        "file": name,
                        "severity": payload.get("severity"),
                        "subject": payload.get("subject"),
                        "receipt_at": _iso_utc(time.time()),
                        "attempt": payload.get("attempts", 0) + 1,
                    }, ensure_ascii=False) + "\n")
                return
            except OSError as exc:
                last_exc = exc
                time.sleep(0.5 * (attempt + 1))
        raise RuntimeError(f"alertbox write failed after {retries} tries: "
                           f"{last_exc}")

    return sender


# ---------------------------------------------------------------------------
# station-result-v2 铸造 + gate 聚合刷新
# ---------------------------------------------------------------------------


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(262144), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _latest_sample_artifact(paths: "ProductionPaths",
                            finished_after: Optional[float] = None
                            ) -> Tuple[Optional[str], Optional[int]]:
    """取最新观察样本文件作 station 工件（需可读且非空）。

    finished_after 给出时要求 mtime 晚于该时刻（防止把上一轮陈旧样本
    记成本轮工件——诚实分母）。"""
    best: Optional[Tuple[float, str, int]] = None
    try:
        names = _os.listdir(paths.samples_dir)
    except OSError:
        return None, None
    for name in sorted(names):
        if not name.endswith(".json"):
            continue
        path = _os.path.join(paths.samples_dir, name)
        try:
            st = _os.stat(path)
        except OSError:
            continue
        if st.st_size <= 0:
            continue
        if finished_after is not None and st.st_mtime < finished_after:
            continue
        if best is None or st.st_mtime > best[0]:
            best = (st.st_mtime, path, st.st_size)
    if best is None:
        return None, None
    return best[1], best[2]


def build_station_result(paths: "ProductionPaths", run: Dict[str, Any],
                         *, now: float) -> Dict[str, Any]:
    """把采样作业的最近 run 铸成 station-result-v2（gate CLI 严格校验）。"""
    verdict = run.get("policy_verdict")
    status = run.get("execution_status")
    art_path, art_size = _latest_sample_artifact(
        paths, finished_after=run.get("started_at"))
    scanned = 1 if (art_path is not None) else 0
    # 采样器完成且样本工件在位 → PASS 证据齐全；否则如实降级：
    #   执行完成但工件缺失 = CONDITIONAL（软，不上绿）；
    #   执行未完成（ERROR/TIMEOUT/BLOCKED）或 FAIL = 对应阻断裁决。
    if status == "COMPLETED" and verdict == "PASS" and scanned == 1:
        sr_verdict, assertion = "PASS", "PASS"
    elif status == "COMPLETED" and verdict in ("FAIL", "CONDITIONAL"):
        sr_verdict, assertion = verdict, "FAIL"
    elif status == "COMPLETED":
        sr_verdict, assertion = "CONDITIONAL", "ERROR"
    else:
        sr_verdict, assertion = "NOT_EVALUATED", "ERROR"
    rc = run.get("actual_exit_code")
    doc: Dict[str, Any] = {
        "schema_version": "2.0",
        "run_id": str(run.get("run_id", "w4-unknown"))
                  .replace("job-", "w4-").replace(".", "-"),
        "station_id": PROD_STATION_ID,
        "attempt_id": str(run.get("run_id", "w4-attempt")),
        "execution_status": status or "ERROR",
        "policy_verdict": sr_verdict,
        "identity": {
            "commit_sha": run.get("commit_sha") or ("0" * 40),
            "environment": run.get("environment") or "production",
            "scope_hash": "wenqu-dist:w4-production-observation",
            "project_id": "wenqu-dist",
        },
        "tool": {"name": "observation_daily", "version": "w4-1.0"},
        "execution": {
            "argv_digest": run.get("argv_digest") or "",
            "started_at": _iso_utc(float(run.get("started_at") or now)),
            "ended_at": _iso_utc(float(run.get("finished_at") or now)),
            "actual_exit_code": rc if isinstance(rc, int) else 1,
            "expected_exit_set": [0],
            "assertion_verdict": assertion,
        },
        "coverage": {"denominator": 1, "scanned": scanned,
                     "exclusions": []},
        "artifacts": [],
    }
    if art_path is not None and art_size is not None:
        digest = _sha256_file(art_path)
        if digest:
            doc["artifacts"].append({
                "cas_digest": f"sha256:{digest}", "size": art_size})
        else:
            doc["coverage"]["scanned"] = 0
    return doc


def _blocked_snapshot(reason: str, *, now: float, **extra: Any
                      ) -> Dict[str, Any]:
    snap: Dict[str, Any] = {
        "generated_at": _iso_utc(now),
        "policy_verdict": "BLOCKED",
        "aggregate_outcome": "BLOCKED",
        "technical_eligible": False,
        "reason": reason,
        "reasons": [reason],
        "counts": {"required_total": 0, "required_reported": 0,
                   "required_missing": 0, "bypass_stations": 0,
                   "duplicates_ignored": 0, "conflicts": 0, "malformed": 0},
        "source": "w4-scheduler",
    }
    snap.update(extra)
    return snap


def refresh_gate_aggregate(paths: "ProductionPaths", *,
                           now: Optional[float] = None) -> Dict[str, Any]:
    """真跑 wenquctl gate 聚合并原子落 gate-aggregate.json。

    无结果数据 / CLI 不可执行 → 如实写 BLOCKED 快照（绝不写真空 PASS）。
    返回写入的快照（含 _written 标记与 CLI 退出码审计字段）。
    """
    now = _as_epoch(now)
    results_dir = paths.station_results_dir
    try:
        names = [n for n in _os.listdir(results_dir) if n.endswith(".json")]
    except OSError:
        names = []
    if not names:
        snap = _blocked_snapshot(
            "no station results under %s（采样器尚未产出任何结果——"
            "拒绝真空 PASS，如实 BLOCKED）" % results_dir,
            now=now, inputs={"paths": 0, "docs": 0, "load_errors": 0,
                             "schema_invalid": 0},
            cli_exit=None)
    else:
        # F6-GATE-SCOPE-001（共享树 2026-10-08 17:25 并行任务入契约）：裸
        # gate 调用默认拒绝。本刷新是 dashboard shadow 的观测快照数据源，
        # 不是发布门判定——不冒充 freeze_run_manifest 正门（采样器非
        # pipeline run，伪造 run-manifest 反而是契约滥用），显式走
        # --allow-self-declared 诊断模式；快照如实携带
        # mode=self_declared_diagnostic / scope_binding.mode=self_declared，
        # 消费方可据此识别其不具上绿效力背书。
        # W8/T-5 正门优先：环境给出冻结 manifest+验签 keyring（+可选 registry）
        # 时走 gate 正门（--manifest --verify-key [--registry]）——现役快照
        # 携带真实身份（target_sha 非零、非 self_declared）；任一 env 缺失
        # 才回退 --allow-self-declared 诊断模式（快照如实自标不具上绿效力）。
        # T-7：正门 results 可指向独立目录（八站 freeze run 产物位）——避免
        # 生产采样器逐班重写的自报站 0 结果与 manifest 冻结身份冲突污染聚合。
        gate_results = _os.environ.get("WENQU_GATE_RESULTS", "").strip()
        gate_manifest = _os.environ.get("WENQU_GATE_MANIFEST", "").strip()
        gate_key = _os.environ.get("WENQU_GATE_VERIFY_KEY", "").strip()
        gate_registry = _os.environ.get("WENQU_GATE_REGISTRY", "").strip()
        if gate_manifest and gate_key and _os.path.isfile(gate_manifest) \
                and _os.path.isfile(gate_key):
            argv = [_os.environ.get("WENQU_PYTHON") or _shutil.which("python3")
                    or "python3", paths.cli_py, "gate", "--results",
                    (gate_results if gate_results and _os.path.isdir(gate_results)
                     else results_dir),
                    "--manifest", gate_manifest, "--verify-key", gate_key]
            if gate_registry and _os.path.isfile(gate_registry):
                argv += ["--registry", gate_registry]
        else:
            argv = [_os.environ.get("WENQU_PYTHON") or _shutil.which("python3")
                    or "python3", paths.cli_py, "gate", "--results", results_dir,
                    "--allow-self-declared"]
        try:
            p = _subprocess.run(argv, capture_output=True, text=True,
                                timeout=60, cwd=paths.repo_root)
            out, rc = p.stdout, p.returncode
        except (OSError, _subprocess.SubprocessError) as exc:
            out, rc = "", -1
            snap = _blocked_snapshot(f"wenquctl gate spawn failed: {exc}",
                                     now=now, cli_exit=-1)
            _atomic_write_json(paths.gate_aggregate, snap)
            return snap
        parsed = None
        for line in reversed((out or "").strip().splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict):
                    break
        if not isinstance(parsed, dict):
            snap = _blocked_snapshot(
                "wenquctl gate 输出不可解析（rc=%s out=%.160s err=%.160s）"
                % (rc, out or "", (p.stderr or "")),
                now=now, cli_exit=rc)
        else:
            snap = dict(parsed)
            snap.setdefault("generated_at", _iso_utc(now))
            snap["source"] = "wenquctl-gate"
            snap["cli_exit"] = rc
    _atomic_write_json(paths.gate_aggregate, snap)
    return snap


# ---------------------------------------------------------------------------
# 生产 tick（唯一入口；launchd 每 5 分钟调一次）
# ---------------------------------------------------------------------------


def _prod_job_definition(paths: "ProductionPaths",
                         argv: Optional[Tuple[str, ...]] = None
                         ) -> JobDefinition:
    return JobDefinition(
        job_id=PROD_JOB_ID,
        owner="w4-production",
        argv=argv or (
            _os.environ.get("WENQU_PYTHON") or _shutil.which("python3")
            or "python3", paths.observation_daily),
        schedule=ScheduleSpec.every(PROD_TICK_INTERVAL),
        environment="production",
        probe_id=PROD_PROBE_ID,
        station_id=PROD_STATION_ID,
        cwd=paths.repo_root,
        due_window_seconds=600.0,
        catch_up="COALESCE",
        max_catch_up_runs=2,
        watchdog=WatchdogPolicy(freshness_seconds=1200.0,
                                grace_seconds=1200.0),
        ttl_seconds=900.0,
        expected_exit_set=(0,),
        channels=(PROD_CHANNEL_MACOS, PROD_CHANNEL_ALERTBOX),
    )


def production_tick(*, paths: Optional["ProductionPaths"] = None,
                    now: Optional[float] = None,
                    runner: Optional[TrustedRunner] = None,
                    macos_sender: Optional[ChannelSender] = None,
                    job_argv: Optional[Tuple[str, ...]] = None,
                    ) -> Dict[str, Any]:
    """W4 生产 tick：采样 → 铸站结果 → gate 刷新 → 心跳 → 通知投递。

    返回 tick 摘要（同时写 heartbeat.json + 当日 tick 日志一行）。
    tick 进程自身的成败与作业 verdict 分离：作业 FAIL 会体现在
    gate/心跳/通知里，但 tick 仍 rc=0（调度器活着就是它的职责）。
    首跑 bootstrap：该作业从未有过任何 run 时，本 tick 立即手动跑一次
    （launchd RunAtLoad 首挂载即出首跑证据；此后走到期机制）。
    job_argv/macdos_sender 为测试注入接缝（生产路径缺省用真采样器与
    真 osascript 通道）。
    """
    paths = paths or ProductionPaths.from_env()
    paths.ensure_dirs()
    now = _as_epoch(now)

    store = SchedulerStore(paths.scheduler_db)
    try:
        registry = ScheduleRegistry(store)
        outbox = NotificationOutbox(
            store,
            critical_channels=(PROD_CHANNEL_MACOS, PROD_CHANNEL_ALERTBOX),
        )
        outbox.register_channel(
            PROD_CHANNEL_MACOS, macos_sender or make_macos_sender())
        outbox.register_channel(
            PROD_CHANNEL_ALERTBOX, make_alertbox_sender(paths.alerts_dir))
        heartbeat_mon = HeartbeatMonitor(store, outbox)
        runner_impl = runner or TrustedRunner(timeout=240.0)
        jrunner = JobRunner(
            store, runner_impl, registry=registry, outbox=outbox,
            heartbeat=heartbeat_mon,
            commit_sha_provider=lambda: _git_head(paths.repo_root),
        )
        # ---- B5 容量闸前置检查（2026-10-09 接线）：判定+记录+CRITICAL 告警；
        # 刻意不阻断观察采样（§22 BLOCKED 处置属迁移/发布峰值操作，观察
        # tick 是 KB 级写——容量压力下停观测=自毁唯一告警通道）。语义登记
        # evidence/11-shadow-canary/README.md。 ----
        cap = capacity_preflight(paths, now=now)
        if cap.get("capacity_gate") == "BLOCKED":
            try:
                outbox.notify(
                    "CRITICAL",
                    f"[wenqu] 容量闸 BLOCKED：{cap.get('code')}",
                    f"{cap.get('message', '')}\n"
                    f"used_ratio={cap.get('used_ratio')} "
                    f"threshold={cap.get('used_ratio_threshold')} "
                    f"headroom={cap.get('headroom_bytes')}B\n"
                    f"观察采样继续（job={PROD_JOB_ID}）；§22 BLOCKED 处置属"
                    f"迁移/发布峰值操作，本告警移交人工决策。",
                    meta={"kind": "capacity_gate", "job_id": PROD_JOB_ID,
                          "code": cap.get("code"),
                          "used_ratio": cap.get("used_ratio")},
                    dedup_key=f"capacitygate:{int(now // 3600)}",
                    now=now,
                )
            except Exception:
                log.exception("capacity gate CRITICAL notify enqueue failed")
        # 先取既有调度状态：register(replace=True) 会把 next_due_at 重置为
        # now+interval——若不保留，每个 tick 先注册再算到期，到期被永远
        # 推到未来 = 采样作业只在首跑 bootstrap 手动跑一次，此后每 tick 仅
        # 拿陈旧 run 刷新 gate（假 PASS）+ 心跳误告警（2026-10-08 生产二跳
        # 实锄：tick2 due=[]、runs 表零增长）。定义可升级（argv/指纹变更
        # 照常生效），但调度状态（next_due_at / last_consumed_at /
        # created_at=宽限锚点）必须跨 tick 保留。
        prev_state: Optional[Dict[str, Any]] = None
        try:
            prev_state = registry.job_state(PROD_JOB_ID)
        except SchedulerError:
            prev_state = None
        registry.register(
            _prod_job_definition(paths, argv=job_argv), replace=True, now=now)
        if prev_state is not None and prev_state["next_due_at"] is not None:
            with store.transaction() as conn:
                conn.execute(
                    "UPDATE scheduler_jobs SET next_due_at=?,"
                    " last_consumed_at=?, created_at=? WHERE job_id=?",
                    (prev_state["next_due_at"],
                     prev_state["last_consumed_at"],
                     prev_state["registered_at"], PROD_JOB_ID),
                )

        due = registry.due_jobs(now=now)
        # ---- G9-02/D 唯一 writer 收敛审计：注册表内观察采样作业必须唯一
        # （PROD_JOB_ID）；发现第二 writer → CRITICAL 告警（fail-visible，
        # 不静默）。launchd 面审计由 tools/window_harvest.py --audit-writers
        # 承担（装配/巡检入口，tick 不扫真实 LaunchAgents 保持可测性）。----
        obs_writers = find_observation_writers(store)
        if len(obs_writers) > 1:
            try:
                outbox.notify(
                    "CRITICAL",
                    "[wenqu] 观察采样出现多 writer（注册表）",
                    "scheduler 注册表内出现 %d 个观察采样作业：%s——"
                    "观察样本面必须唯一 writer（%s）。"
                    % (len(obs_writers), obs_writers, PROD_JOB_ID),
                    meta={"kind": "unique_writer", "job_ids": obs_writers},
                    dedup_key="uniquewriter:%s:%d"
                              % (",".join(obs_writers), int(now // 3600)),
                    now=now,
                )
            except Exception:
                log.exception("unique-writer CRITICAL notify failed")
        runs: List[Dict[str, Any]] = []
        bootstrapped = False
        ever_ran = store.query(
            "SELECT COUNT(*) FROM scheduler_runs WHERE job_id=?",
            (PROD_JOB_ID,))[0][0]
        if ever_ran == 0:
            # 首跑 bootstrap：手动 run（无 scheduled_at 幂等键，不推进 next_due）
            rec = jrunner.run_job(PROD_JOB_ID, now=now)
            runs.append(rec.__dict__)
            bootstrapped = True
        for occ in due:
            if occ.run:
                rec = jrunner.run_job(occ.job_id,
                                      scheduled_at=occ.scheduled_at,
                                      now=now)
                runs.append(rec.__dict__)
            else:
                registry.mark_skipped(occ.job_id, occ.scheduled_at,
                                      occ.reason, now=now)

        # 最近一次真实 run（含本 tick 未到期时的历史 run）铸站结果。
        rows = store.query(
            "SELECT * FROM scheduler_runs WHERE job_id=? "
            "ORDER BY started_at DESC LIMIT 1", (PROD_JOB_ID,))
        station_doc = None
        if rows:
            run_dict = JobRunner._row_to_record_dict(rows[0])
            station_doc = build_station_result(paths, run_dict, now=now)
            station_path = _os.path.join(
                paths.station_results_dir,
                f"{PROD_STATION_ID}.json")  # 同站覆盖=gate 只见最新
            _atomic_write_json(station_path, station_doc)

        gate = refresh_gate_aggregate(paths, now=now)
        health = heartbeat_mon.check_health(now=now, notify=True)
        dispatch = outbox.dispatch_due(now=now)
        stats = outbox.stats()

        payload = {
            "label": PROD_LABEL,
            "tick_at": _iso_utc(now),
            "tick_epoch": now,
            "job_id": PROD_JOB_ID,
            "bootstrapped": bootstrapped,
            "due": [{"scheduled_at": o.scheduled_at, "run": o.run,
                     "reason": o.reason} for o in due],
            "runs": [{"run_id": r["run_id"],
                      "execution_status": r["execution_status"],
                      "policy_verdict": r["policy_verdict"],
                      "actual_exit_code": r["actual_exit_code"],
                      "refreshed_heartbeat": r["refreshed_heartbeat"],
                      "notifications_enqueued": r["notifications_enqueued"]}
                     for r in runs],
            "station_result": (None if station_doc is None else {
                "policy_verdict": station_doc["policy_verdict"],
                "coverage": station_doc["coverage"],
                "execution_status": station_doc["execution_status"]}),
            "gate": {"aggregate_outcome": gate.get("aggregate_outcome"),
                     "policy_verdict": gate.get("policy_verdict"),
                     "reason": gate.get("reason"),
                     "cli_exit": gate.get("cli_exit")},
            "capacity_gate": {
                "gate": cap.get("capacity_gate"),
                "code": cap.get("code"),
                "severity": cap.get("severity"),
                "used_ratio": cap.get("used_ratio"),
                "used_ratio_threshold": cap.get("used_ratio_threshold"),
                "headroom_bytes": cap.get("headroom_bytes"),
                "violations": [v.get("code") for v in cap.get("violations", [])
                               if isinstance(v, dict)],
                "judged_at": cap.get("judged_at"),
                "error": cap.get("error"),
            },
            "health": [{"job_id": h.job_id, "state": h.state,
                        "healthy": h.healthy, "severity": h.severity}
                       for h in health],
            "observation_writers": {"count": len(obs_writers),
                                    "job_ids": obs_writers,
                                    "unique": len(obs_writers) <= 1},
            "notifications": {"dispatch": dispatch, "outbox_stats": stats},
            "paths": {"scheduler_db": paths.scheduler_db,
                      "gate_aggregate": paths.gate_aggregate,
                      "heartbeat": paths.heartbeat,
                      "alerts_dir": paths.alerts_dir},
            "tick_rc": 0,
        }
        _atomic_write_json(paths.heartbeat, payload)
        log_path = _os.path.join(
            paths.logs_dir,
            "scheduler-" + datetime.fromtimestamp(now).strftime(
                "%Y-%m-%d") + ".jsonl")
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return payload
    finally:
        store.close()


def _prod_main(argv: Optional[List[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="wenqu-scheduler",
        description="W4 生产调度 tick（launchd com.wenqu.scheduler 入口）")
    parser.add_argument("command", nargs="?", default="tick",
                        choices=["tick"],
                        help="tick=执行一个生产周期（默认）")
    args = parser.parse_args(argv)
    try:
        payload = production_tick()
    except Exception as exc:  # tick 进程级失败：写错误心跳（可观测）后 rc=2
        log.exception("production tick crashed")
        try:
            paths = ProductionPaths.from_env()
            paths.ensure_dirs()
            _atomic_write_json(paths.heartbeat, {
                "label": PROD_LABEL,
                "tick_at": _iso_utc(time.time()),
                "tick_rc": 2,
                "error": f"{type(exc).__name__}: {exc}",
            })
        except Exception:
            log.exception("failed to write crash heartbeat")
        return 2
    print(json.dumps({
        "tick_rc": payload["tick_rc"],
        "tick_at": payload["tick_at"],
        "gate": payload["gate"]["aggregate_outcome"],
        "health": payload["health"],
        "notifications": payload["notifications"]["dispatch"],
    }, ensure_ascii=False))
    return int(payload["tick_rc"])


if __name__ == "__main__":  # python3 -m wenqu_core.scheduler tick
    import sys as _sys
    _sys.exit(_prod_main())

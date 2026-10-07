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

"""store.py——SQLite WAL append-only 事件正源（ADR-003）。

安全构造（by construction，非依赖扫描器豁免）：
- 所有 SQL 一律参数化（? 占位符），任何值都不拼接进 SQL 文本。
- events 表由 ABORT 触发器强制 append-only：UPDATE / DELETE 直接报错。
- 哈希链：event_hash = sha256(prev_event_hash || canonical_payload)，
  首条 prev 为全零 GENESIS；篡改任意行都会破坏 verify_chain()。
- 写入用 BEGIN IMMEDIATE 单事务完成「读头 + 插入」，避免并发分叉。

P0-6 第六轮（统一事件正源）：``pipeline_events`` 是全系统唯一的事件表，
``EventStore.append``/RunManager._emit 是仅有的写入口——旧 JSONL 账本
迁移器（ledger_migrator）的导入行也经公共 append 写入本表同一哈希链
（不再自建第二张 events 表）；历史库中的旧 ``events`` 表冻结为只读兼容，
残留行由 ledger_migrator.migrate_legacy_events 一次性收编。控制事件
守卫语义（下方 P0-4）对本轮改写零改动。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, Optional, Tuple

__all__ = ["EventStore", "ChainIntegrityError", "GENESIS_HASH",
           "CONTROL_EVENT_TYPE_PREFIXES", "CONTROL_EVENT_TYPE_EXACT",
           "is_control_event"]

GENESIS_HASH = "0" * 64

# ---------------------------------------------------------------------- #
# P0-4 加固（Codex 实锤 #7）：管线控制事件写入口守卫。
# wenqu_pipeline 的控制事件（RUN_*/STAGE_*/ATTEMPT_*/WAITING_*/APPROVAL_*/
# ACTION_*/FINDING_*/SUPERSEDED）只允许经 RunManager._emit 注入——事件
# 携带内部 HMAC seal，重放时逐条验封。公共 EventStore.append 对控制类型
# 一律 ValueError：裸 append 注入 RUN_COMPLETED/PASS 伪造终态的路径就此关闭。
# 外部普通事件（无控制 event_type）保持完全可用。
# ---------------------------------------------------------------------- #

#: 控制事件类型前缀（与 wenqu_pipeline 事件词表对齐）
CONTROL_EVENT_TYPE_PREFIXES: Tuple[str, ...] = (
    "RUN_", "STAGE_", "ATTEMPT_", "WAITING_", "APPROVAL_",
    "ACTION_", "FINDING_",
)
#: 不带前缀的控制事件类型（精确枚举）
CONTROL_EVENT_TYPE_EXACT: Tuple[str, ...] = ("SUPERSEDED",)


def is_control_event(event: Any) -> bool:
    """判定事件是否为 wenqu_pipeline 控制事件（按 event_type 前缀/枚举）。"""
    if not isinstance(event, dict):
        return False
    etype = event.get("event_type")
    if not isinstance(etype, str):
        return False
    return (etype in CONTROL_EVENT_TYPE_EXACT
            or etype.startswith(CONTROL_EVENT_TYPE_PREFIXES))


class ChainIntegrityError(RuntimeError):
    """verify_chain() 检出哈希链断裂或被篡改。"""


_SCHEMA = """
-- P0-6 修：表名改为 pipeline_events 避免与 LedgerMigrator 的 events 表冲突
CREATE TABLE IF NOT EXISTS pipeline_events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE,
    payload         TEXT NOT NULL,
    prev_event_hash TEXT NOT NULL,
    event_hash      TEXT NOT NULL UNIQUE,
    created_at      REAL NOT NULL
);

CREATE TRIGGER IF NOT EXISTS pipeline_events_append_only_no_update
BEFORE UPDATE ON pipeline_events
BEGIN
    SELECT RAISE(ABORT, 'pipeline_events is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS pipeline_events_append_only_no_delete
BEFORE DELETE ON pipeline_events
BEGIN
    SELECT RAISE(ABORT, 'pipeline_events is append-only: DELETE is forbidden');
END;
"""


class EventStore:
    """WAL 模式的 append-only 哈希链事件存储。"""

    def __init__(self, db_path: str) -> None:
        # isolation_level=None：事务由本类显式控制（BEGIN IMMEDIATE/COMMIT）
        self._conn = sqlite3.connect(db_path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        # 并发写排队：WAL 下 BEGIN IMMEDIATE 争锁时等待而非即抛 SQLITE_BUSY
        # （Linux 慢盘上 100 并发写实测无此 pragma 会丢 3% 写面；darwin 时序掩盖）
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    @staticmethod
    def _canonical_payload(event: Dict[str, Any]) -> str:
        return json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

    @staticmethod
    def _compute_hash(prev_event_hash: str, canonical_payload: str) -> str:
        h = hashlib.sha256()
        h.update(prev_event_hash.encode("ascii"))
        h.update(canonical_payload.encode("utf-8"))
        return h.hexdigest()

    # ------------------------------------------------------------------
    def append(self, event: Dict[str, Any]) -> Tuple[str, bool]:
        """追加一条事件，返回 (event_hash, inserted)。

        P0-4 加固：控制事件类型（is_control_event）一律 ValueError——它们
        只能经 RunManager._emit 注入（带内部 seal），公共 append 拒绝裸注入。

        P0-6 修：幂等键基于稳定内容（canonical payload），不含 prev_event_hash。
        重试同一事件 → event_id 相同 → INSERT OR IGNORE 忽略 → inserted=False。
        P0-6 二次修（duplicate 分支）：命中幂等键时返回 DB 中已存行的真实
        event_hash（SELECT 查出，绝不按当前 head 重算——重算值在 DB 中不存在，
        会造成调用方持有悬空 hash）。
        """
        if is_control_event(event):
            raise ValueError(
                "pipeline control events (RUN_*/STAGE_*/ATTEMPT_*/WAITING_*/"
                "APPROVAL_*/ACTION_*/FINDING_*/SUPERSEDED) must be injected "
                "via RunManager._emit with an internal seal; bare "
                "EventStore.append of control event_type is forbidden "
                f"(got event_type={event.get('event_type')!r})")
        payload = self._canonical_payload(event)
        # P0-6: event_id = sha256(canonical_payload)——稳定幂等键
        event_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT event_hash FROM pipeline_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev = row[0] if row else GENESIS_HASH
            computed_hash = self._compute_hash(prev, payload)
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO pipeline_events "
                "(event_id, payload, prev_event_hash, event_hash, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (event_id, payload, prev, computed_hash, time.time()),
            )
            inserted = cur.rowcount == 1
            if inserted:
                event_hash = computed_hash
            else:
                # duplicate：返回 DB 中已存行的真实 event_hash（事务内读出）
                stored = self._conn.execute(
                    "SELECT event_hash FROM pipeline_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if stored is None or not stored[0]:
                    raise ChainIntegrityError(
                        f"duplicate event_id {event_id} not found in store "
                        "(INSERT OR IGNORE ignored but row missing)"
                    )
                event_hash = stored[0]
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return event_hash, inserted

    # ------------------------------------------------------------------
    def head(self) -> Tuple[Optional[str], int]:
        """返回 (链头 event_hash, 总条数)。

        P0-6 二次修：链头 = 按 seq 排序的最后一条（此前单条聚合查询在
        SQLite 下取到首行 hash，head 与 verify_chain 的链尾不一致）。
        """
        row = self._conn.execute(
            "SELECT event_hash FROM pipeline_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None or row[0] is None:
            return None, 0
        total = self._conn.execute(
            "SELECT COUNT(*) FROM pipeline_events"
        ).fetchone()[0]
        return row[0], total

    def verify_chain(self) -> Dict[str, Any]:
        """重算并校验整条哈希链；任何断裂/篡改抛 ChainIntegrityError。"""
        expected_prev = GENESIS_HASH
        scanned = 0
        for seq, event_id, payload, prev_event_hash, event_hash in self._conn.execute(
            "SELECT seq, event_id, payload, prev_event_hash, event_hash "
            "FROM pipeline_events ORDER BY seq ASC"
        ):
            scanned += 1
            if prev_event_hash != expected_prev:
                raise ChainIntegrityError(
                    f"seq {seq}: prev_event_hash {prev_event_hash} != "
                    f"expected {expected_prev}"
                )
            recomputed = self._compute_hash(prev_event_hash, payload)
            if recomputed != event_hash:
                raise ChainIntegrityError(
                    f"seq {seq}: event_hash {event_hash} != recomputed {recomputed}"
                )
            # P0-6: event_id 是内容哈希（幂等键），不再要求等于链哈希 event_hash
            # 仅校验 event_id 是有效的 sha256 hex
            if len(event_id) != 64 or not all(c in "0123456789abcdef" for c in event_id):
                raise ChainIntegrityError(
                    f"seq {seq}: event_id {event_id} is not a valid sha256 hex"
                )
            expected_prev = event_hash
        head_hash, total = self.head()
        if total != scanned:
            raise ChainIntegrityError(
                f"row count mismatch: scanned {scanned}, table holds {total}"
            )
        return {"ok": True, "length": scanned, "head": head_hash}

    # ------------------------------------------------------------------
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

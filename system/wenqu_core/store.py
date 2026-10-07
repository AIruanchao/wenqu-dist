"""store.py——SQLite WAL append-only 事件正源（ADR-003）。

安全构造（by construction，非依赖扫描器豁免）：
- 所有 SQL 一律参数化（? 占位符），任何值都不拼接进 SQL 文本。
- events 表由 ABORT 触发器强制 append-only：UPDATE / DELETE 直接报错。
- 哈希链：event_hash = sha256(prev_event_hash || canonical_payload)，
  首条 prev 为全零 GENESIS；篡改任意行都会破坏 verify_chain()。
- 写入用 BEGIN IMMEDIATE 单事务完成「读头 + 插入」，避免并发分叉。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, Optional, Tuple

__all__ = ["EventStore", "ChainIntegrityError", "GENESIS_HASH"]

GENESIS_HASH = "0" * 64


class ChainIntegrityError(RuntimeError):
    """verify_chain() 检出哈希链断裂或被篡改。"""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE,
    payload         TEXT NOT NULL,
    prev_event_hash TEXT NOT NULL,
    event_hash      TEXT NOT NULL UNIQUE,
    created_at      REAL NOT NULL
);

CREATE TRIGGER IF NOT EXISTS events_append_only_no_update
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS events_append_only_no_delete
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only: DELETE is forbidden');
END;
"""


class EventStore:
    """WAL 模式的 append-only 哈希链事件存储。"""

    def __init__(self, db_path: str) -> None:
        # isolation_level=None：事务由本类显式控制（BEGIN IMMEDIATE/COMMIT）
        self._conn = sqlite3.connect(db_path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
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

        INSERT OR IGNORE 保证重试幂等：完全相同的 (prev, payload) 二次
        插入会被忽略而不是复制行（rowcount == 0 → inserted == False）。
        """
        payload = self._canonical_payload(event)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev = row[0] if row else GENESIS_HASH
            event_hash = self._compute_hash(prev, payload)
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO events "
                "(event_id, payload, prev_event_hash, event_hash, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (event_hash, payload, prev, event_hash, time.time()),
            )
            inserted = cur.rowcount == 1
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return event_hash, inserted

    # ------------------------------------------------------------------
    def head(self) -> Tuple[Optional[str], int]:
        row = self._conn.execute(
            "SELECT event_hash, COUNT(*) FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None or row[0] is None:
            return None, 0
        return row[0], row[1]

    def verify_chain(self) -> Dict[str, Any]:
        """重算并校验整条哈希链；任何断裂/篡改抛 ChainIntegrityError。"""
        expected_prev = GENESIS_HASH
        scanned = 0
        for seq, event_id, payload, prev_event_hash, event_hash in self._conn.execute(
            "SELECT seq, event_id, payload, prev_event_hash, event_hash "
            "FROM events ORDER BY seq ASC"
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
            if event_id != event_hash:
                raise ChainIntegrityError(
                    f"seq {seq}: event_id {event_id} does not match event_hash"
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

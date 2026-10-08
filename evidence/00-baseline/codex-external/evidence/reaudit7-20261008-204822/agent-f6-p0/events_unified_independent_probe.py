#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第七轮 P0-6 独立探针：验证旧 events 收编后是否真正被冻结为只读。"""
import hashlib
import json
import os
import sqlite3
import sys
import tempfile

REPO = "/tmp/wenqu-reaudit7-f6p0-22971"
sys.path.insert(0, os.path.join(REPO, "system"))
from wenqu_core.ledger_migrator import migrate_legacy_events  # noqa:E402
from wenqu_core.store import EventStore  # noqa:E402

LEGACY_SCHEMA = """
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    line_sha TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    source_file TEXT NOT NULL,
    source_line INTEGER NOT NULL,
    payload TEXT NOT NULL,
    migrated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

def sha(s): return hashlib.sha256(s.encode()).hexdigest()

def counts(db):
    c = sqlite3.connect(db)
    try:
        return {
            "legacy_events": c.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "pipeline_events": c.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0],
        }
    finally: c.close()

def main():
    out = {"probe": "events-unified-independent-v1"}
    with tempfile.TemporaryDirectory(prefix="reaudit7-eventstore-") as td:
        db = os.path.join(td, "events.db")
        raw1 = '{"status":"PASS","id":1}'
        c = sqlite3.connect(db)
        c.executescript(LEGACY_SCHEMA)
        c.execute("INSERT INTO events(line_sha,status,source_file,source_line,payload) VALUES(?,?,?,?,?)",
                  (sha(raw1), "PASS", "/legacy/a.jsonl", 1, raw1))
        c.commit(); c.close()

        first = migrate_legacy_events(db)
        out["first_migration"] = {
            "rows_seen": first["rows_seen"], "imported": first["imported"],
            "duplicates": first["duplicates"], "write_api": first["write_api"],
            "counts": counts(db),
        }

        c = sqlite3.connect(db)
        triggers = c.execute(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
        ).fetchall()
        out["triggers"] = [
            {"name": n, "table": t, "guards_legacy_events": t == "events"}
            for n, t, _sql in triggers
        ]

        # 收编完成后直接向声称“冻结只读”的旧表追加：若真 fail-closed 应被拒。
        raw2 = '{"status":"FAIL","id":2}'
        insert = {"succeeded": False, "error": None}
        try:
            c.execute("INSERT INTO events(line_sha,status,source_file,source_line,payload) VALUES(?,?,?,?,?)",
                      (sha(raw2), "FAIL", "/legacy/late.jsonl", 2, raw2))
            c.commit(); insert["succeeded"] = True
        except Exception as exc:
            c.rollback(); insert["error"] = f"{type(exc).__name__}: {exc}"
        out["post_migration_insert"] = insert
        out["after_insert_counts"] = counts(db)

        # 旧表 UPDATE/DELETE 也没有技术性只读约束；均在隔离临时库操作。
        update = {"succeeded": False, "error": None}
        try:
            c.execute("UPDATE events SET status='MUTATED_AFTER_MIGRATION' WHERE source_line=2")
            c.commit(); update["succeeded"] = True
        except Exception as exc:
            c.rollback(); update["error"] = f"{type(exc).__name__}: {exc}"
        delete = {"succeeded": False, "error": None}
        try:
            c.execute("DELETE FROM events WHERE source_line=1")
            c.commit(); delete["succeeded"] = True
        except Exception as exc:
            c.rollback(); delete["error"] = f"{type(exc).__name__}: {exc}"
        out["post_migration_update"] = update
        out["post_migration_delete"] = delete
        out["after_mutations_counts"] = counts(db)
        legacy_rows = c.execute(
            "SELECT id,status,source_file,source_line FROM events ORDER BY id"
        ).fetchall()
        out["legacy_rows_after_mutation"] = [list(x) for x in legacy_rows]
        c.close()

        second = migrate_legacy_events(db)
        out["second_migration_after_late_write"] = {
            "rows_seen": second["rows_seen"], "imported": second["imported"],
            "duplicates": second["duplicates"], "counts": counts(db),
        }
        store = EventStore(db)
        out["chain_after_second"] = store.verify_chain()
        store.close()

        c = sqlite3.connect(db)
        payloads = [json.loads(x[0]) for x in c.execute(
            "SELECT payload FROM pipeline_events ORDER BY seq")]
        c.close()
        out["pipeline_statuses"] = [p.get("status") for p in payloads]
        out["legacy_readonly_enforced"] = not (
            insert["succeeded"] or update["succeeded"] or delete["succeeded"])
    print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

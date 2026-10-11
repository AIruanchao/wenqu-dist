#!/usr/bin/env python3
"""第九轮独立负向探针：同一 SQLite 写主体能否回填/改写行版本账本。
仅操作 /tmp 临时库；探针成功复现旁路时本脚本 exit 0，但 system_verdict=FAIL。
"""
from __future__ import annotations
import hashlib, json, os, sqlite3, stat, sys, tempfile
from pathlib import Path

SNAP = Path('/private/tmp/codex-test/reaudit9-infra-snapshot-20261011-091321')
sys.path.insert(0, str(SNAP / 'system'))
from wenqu_core.ledger_migrator import (  # noqa: E402
    migrate_legacy_events, LEGACY_FREEZE_TRIGGER_NAMES,
    LEGACY_ROW_DIGESTS_TABLE,
)

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
DIGEST_SCHEMA = """
CREATE TABLE legacy_row_digests (
 legacy_id INTEGER PRIMARY KEY,
 row_sha TEXT NOT NULL,
 recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""
EARLY = '2026-01-01 00:00:00'

def content_sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def row_sha(row: tuple) -> str:
    # 独立重算被测契约的规范串，不调用产品私有 helper。
    material = json.dumps(list(row), ensure_ascii=False, sort_keys=True,
                          separators=(',', ':'))
    return hashlib.sha256(material.encode()).hexdigest()

def insert_event(c, rid: int, payload: str, source_line: int | None = None):
    c.execute("INSERT INTO events(id,line_sha,status,source_file,source_line,payload,migrated_at) VALUES(?,?,?,?,?,?,?)",
              (rid, content_sha(payload), 'PASS', '/synthetic/independent.jsonl',
               source_line if source_line is not None else rid, payload, EARLY))

def read_event(c, rid: int) -> tuple:
    return c.execute("SELECT id,line_sha,status,source_file,source_line,payload,migrated_at FROM events WHERE id=?", (rid,)).fetchone()

def drop_table_triggers(c, table: str):
    names = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,))]
    for n in names:
        c.execute(f'DROP TRIGGER "{n}"')
    return names

def chain_payloads(db: str):
    c = sqlite3.connect(db)
    try:
        return [json.loads(r[0]) for r in c.execute('SELECT payload FROM pipeline_events ORDER BY seq')]
    finally:
        c.close()

def scenario_gap_digest_insert(td: str):
    """已有可信 digest ledger 时，在 gap 行后补一个 digest；应被拒但实际被收编。"""
    db = os.path.join(td, 'gap-digest-insert.db')
    c = sqlite3.connect(db)
    c.executescript(LEGACY_SCHEMA)
    insert_event(c, 1, '{"status":"PASS","ts":"2026-01-01T00:00:00Z","seed":1}')
    insert_event(c, 3, '{"status":"FAIL","ts":"2026-01-01T00:02:00Z","seed":3}')
    c.commit(); c.close()
    first = migrate_legacy_events(db)
    c = sqlite3.connect(db)
    dropped = drop_table_triggers(c, 'events')
    evil = '{"status":"PASS","ts":"2026-01-01T00:01:00Z","unauthorized_gap":"accepted"}'
    insert_event(c, 2, evil, 2)
    digest = row_sha(read_event(c, 2))
    # 关键：digest 表所谓 append-only 守卫只拦 UPDATE/DELETE；同一 DB writer 可直接 INSERT 回填历史 gap。
    c.execute(f'INSERT INTO {LEGACY_ROW_DIGESTS_TABLE}(legacy_id,row_sha) VALUES (?,?)', (2, digest))
    c.commit()
    digest_count = c.execute(f'SELECT COUNT(*) FROM {LEGACY_ROW_DIGESTS_TABLE}').fetchone()[0]
    c.close()
    second = migrate_legacy_events(db)
    payloads = chain_payloads(db)
    bypass = (second['imported'] == 1 and second['quarantined'] == 0 and
              any('unauthorized_gap' in o.get('raw','') for o in payloads))
    return {
      'db_mode': oct(stat.S_IMODE(os.stat(db).st_mode)),
      'first': {k:first[k] for k in ('imported','duplicates','quarantined','row_digests_on_record','cutover_max_legacy_id')},
      'attacker_same_sqlite_connection': True,
      'dropped_legacy_triggers': dropped,
      'unauthorized_digest_insert_succeeded': True,
      'digest_rows_after_backfill': digest_count,
      'second': {k:second[k] for k in ('imported','duplicates','quarantined','legacy_untrusted','row_digests_on_record')},
      'malicious_payload_in_unified_chain': any('unauthorized_gap' in o.get('raw','') for o in payloads),
      'bypass_reproduced': bypass,
    }

def scenario_forged_upgrade_baseline(td: str):
    """cutover 有、digest 缺的升级库：攻击者回填 digest 基线后绕过 legacy_untrusted。"""
    db = os.path.join(td, 'forged-upgrade-baseline.db')
    c = sqlite3.connect(db); c.executescript(LEGACY_SCHEMA)
    insert_event(c, 1, '{"status":"PASS","ts":"2026-01-01T00:00:00Z","seed":1}')
    insert_event(c, 3, '{"status":"FAIL","ts":"2026-01-01T00:02:00Z","seed":3}')
    c.commit(); c.close()
    first = migrate_legacy_events(db)
    c = sqlite3.connect(db)
    # 合成旧版升级形状并实施 cutover 后篡改。
    c.execute(f'DROP TABLE {LEGACY_ROW_DIGESTS_TABLE}')
    drop_table_triggers(c, 'events')
    evil_gap = '{"status":"PASS","ts":"2025-12-31T23:59:00Z","forged_upgrade_gap":true}'
    insert_event(c, 2, evil_gap, 2)
    evil_update = '{"status":"PASS","ts":"2025-12-31T23:58:00Z","forged_upgrade_update":true}'
    c.execute('UPDATE events SET line_sha=?,payload=?,migrated_at=? WHERE id=1',
              (content_sha(evil_update), evil_update, '2025-12-31 23:58:00'))
    # 关键：同一 writer 自建并回填“看似完整”的 digest 账本；产品不校验来源/签名/外部锚。
    c.executescript(DIGEST_SCHEMA)
    for rid in (1,2,3):
        c.execute(f'INSERT INTO {LEGACY_ROW_DIGESTS_TABLE}(legacy_id,row_sha) VALUES (?,?)',
                  (rid, row_sha(read_event(c, rid))))
    c.commit(); c.close()
    second = migrate_legacy_events(db)
    payloads = chain_payloads(db)
    bypass = (second['legacy_untrusted'] is False and second['imported'] == 2 and
              second['quarantined'] == 0 and
              any('forged_upgrade_gap' in o.get('raw','') for o in payloads) and
              any('forged_upgrade_update' in o.get('raw','') for o in payloads))
    return {
      'first': {k:first[k] for k in ('imported','quarantined','row_digests_on_record')},
      'forged_digest_ledger_rows': 3,
      'second': {k:second[k] for k in ('imported','duplicates','quarantined','legacy_untrusted','row_digests_on_record')},
      'forged_gap_in_unified_chain': any('forged_upgrade_gap' in o.get('raw','') for o in payloads),
      'forged_update_in_unified_chain': any('forged_upgrade_update' in o.get('raw','') for o in payloads),
      'bypass_reproduced': bypass,
    }

def main():
    with tempfile.TemporaryDirectory(prefix='reaudit9-migration-') as td:
        a = scenario_gap_digest_insert(td)
        b = scenario_forged_upgrade_baseline(td)
        ok = a['bypass_reproduced'] and b['bypass_reproduced']
        out = {
          'probe': 'independent legacy row-version/write-authority adversarial probe',
          'isolation_root': td,
          'scenario_A_gap_digest_backfill': a,
          'scenario_B_forged_upgrade_baseline': b,
          'probe_assertion_verdict': 'PASS' if ok else 'FAIL',
          'system_verdict': 'FAIL' if ok else 'INCONCLUSIVE',
          'finding_family': 'round8 P0-3 existing root: row-version ledger and legacy table share same SQLite write authority; trigger-only guards are removable/backfillable',
        }
        print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if ok else 1

if __name__ == '__main__':
    raise SystemExit(main())

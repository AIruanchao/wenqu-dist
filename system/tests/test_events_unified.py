#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统一事件正源专属测试（Codex P0-6 第六轮：pipeline_events 与迁移器 events
两表两正源根修）。

被测契约（「单一事件表 + 单一写入 API」）：
    system/wenqu_core/ledger_migrator.py —— LedgerMigrator 导入行经公共
    EventStore.append 写入 store.py 的 pipeline_events 哈希链表，不再自建
    第二张 events 表；旧 events 表残留由 migrate_legacy_events 一次性收编
    （幂等），旧表本身冻结只读兼容。

用例族（UE-01~UE-06，全部真实注入、零 mock）：
    UE-01 单一事件表+单一写入 API：迁移产物只落 pipeline_events；event_id
         与 EventStore 同一幂等键（canonical payload SHA256）；同一事件经
         公共 append 重放 = duplicate（同 API 同键收敛）；
    UE-02 内容寻址幂等+逐行 sidecar 映射：同输入两次迁移零重复、行集/
         链头零变化；跨文件同内容行同样计 duplicate（旧 line_sha 语义
         保留）；sidecar 逐行映射与 scan 清单一一对应、只追加；源只读；
    UE-03 坏行隔离语义不回退：坏 JSON/未知状态绝不入统一表；ERROR→BLOCKED、
         FIXED→FIXED_PENDING_VERIFY 的 fail-closed 归一在统一表上成立；
    UE-04 混合流单链：迁移行+EventStore 直写行交错同链，verify_chain
         贯穿、链头精确、重迁移零扰动；
    UE-05 旧 events 表残留一次性收编：合成旧表 fixture → migrate_legacy_
         events 幂等收编入链、旧表只读原样保留；形状异常 fail-closed；
         缺表不报错；与 JSONL 迁移混合同链；
    UE-06 控制事件守卫不回退：迁移事件类型均非控制类型；统一表上裸
         append 伪造 RUN_*/SUPERSEDED 仍一律 ValueError。

独立运行：python3 system/tests/test_events_unified.py → exit 0 全绿。
"""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SYSTEM_DIR = os.path.dirname(HERE)
sys.path.insert(0, SYSTEM_DIR)

from wenqu_core.store import (                             # noqa: E402
    EventStore, is_control_event,
    CONTROL_EVENT_TYPE_PREFIXES, CONTROL_EVENT_TYPE_EXACT)
from wenqu_core.ledger_migrator import (                   # noqa: E402
    LedgerMigrator, migrate_legacy_events, migration_event,
    MIGRATION_EVENT_TYPE, LEGACY_EVENTS_TABLE, LEGACY_RESIDUE_EVENT_TYPE)

PASS_N, FAIL_N = 0, 0
RESULTS = []


class TmpDir:
    def __init__(self, prefix):
        self.prefix = prefix
        self.path = None

    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix=self.prefix)
        return self.path

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)


def expect(exc, fn):
    try:
        fn()
    except exc:
        return
    except Exception as e:                                 # noqa: BLE001
        raise AssertionError(
            f"expected {exc.__name__}, got {type(e).__name__}: {e}")
    raise AssertionError(f"expected {exc.__name__}, nothing raised")


def canonical(obj):
    """与 store.EventStore._canonical_payload 相同的规范化序列化。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def content_sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tables_of(db):
    conn = sqlite3.connect(db)
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


def unified_rows(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT seq, event_id, payload, prev_event_hash, event_hash "
            "FROM pipeline_events ORDER BY seq ASC").fetchall()
    finally:
        conn.close()


def unified_payloads(db, event_type=None):
    out = []
    for row in unified_rows(db):
        obj = json.loads(row[2])
        if event_type is None or obj.get("event_type") == event_type:
            out.append(obj)
    return out


def sidecar_records(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


def write_lines(dirpath, name, lines):
    path = os.path.join(dirpath, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def make_ledger(td, lines, name="legacy.jsonl"):
    src = os.path.join(td, "legacy")
    os.makedirs(src, exist_ok=True)
    write_lines(src, name, lines)
    return src


VALID_LINES = [
    '{"status": "PASS", "ts": "2026-10-01T00:00:00Z", "id": 1}',
    '{"status": "ERROR", "ts": "2026-10-01T00:01:00Z", "id": 2}',
    '{"status": "FIXED", "ts": "2026-10-01T00:02:00Z", "id": 3}',
]

# 旧版 ledger_migrator._SCHEMA 的 events 部分（合成历史库 fixture 用；
# 逐字复刻 v3.7.1 之前的两正源表形状，非生产库）
LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    line_sha     TEXT NOT NULL UNIQUE,
    status       TEXT NOT NULL,
    source_file  TEXT NOT NULL,
    source_line  INTEGER NOT NULL,
    payload      TEXT NOT NULL,
    migrated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_file, source_line);
"""


# ---------------------------------------------------------------------- #
# UE-01：单一事件表 + 单一写入 API
# ---------------------------------------------------------------------- #
def test_UE_01_single_table_single_write_api():
    with TmpDir("ue1-") as td:
        src = make_ledger(td, VALID_LINES + ['{"status": "GHOST", "ts": "t"}'])
        db = os.path.join(td, "ev.db")
        report = LedgerMigrator(src, db).migrate()

        assert report["event_table"] == "pipeline_events"
        assert report["write_api"] == "EventStore.append"
        assert report["conservation"]["imported"] == 3

        # 唯一事件表：pipeline_events 在，旧 events 表绝不被创建
        tables = tables_of(db)
        assert "pipeline_events" in tables
        assert LEGACY_EVENTS_TABLE not in tables, "两表两正源复发"

        # 全部导入行都是 LEDGER_MIGRATED；event_id 与 EventStore 同一
        # 幂等键（canonical payload 的 SHA256）；链逐行可验证
        rows = unified_rows(db)
        assert len(rows) == 3
        prev = "0" * 64
        for seq, event_id, payload, prev_hash, event_hash in rows:
            obj = json.loads(payload)
            assert obj["event_type"] == MIGRATION_EVENT_TYPE
            assert event_id == content_sha(canonical(obj)), \
                "event_id 不是 canonical payload 哈希（幂等键分叉）"
            assert prev_hash == prev
            h = hashlib.sha256()
            h.update(prev.encode("ascii"))
            h.update(payload.encode("utf-8"))
            assert event_hash == h.hexdigest(), "迁移行不在哈希链上"
            prev = event_hash

        # 同 API 同键收敛：用公共 EventStore.append 重放同一迁移事件
        # → duplicate（inserted=False）且返回已存行真实 hash
        verdict = LedgerMigrator.classify(VALID_LINES[0])
        assert verdict["decision"] == "import"
        ev = migration_event(verdict["line_sha"], verdict["status"],
                             VALID_LINES[0])
        store = EventStore(db)
        try:
            h, ins = store.append(ev)
            assert ins is False, "公共 append 重放迁移事件竟再入账（双记账）"
            stored = unified_rows(db)[0]
            assert (stored[1], stored[4]) == (
                content_sha(canonical(ev)), h), "重放 hash 与库内行不一致"
            head, total = store.head()
            assert total == 3 and head == unified_rows(db)[-1][4]
            assert store.verify_chain() == {"ok": True, "length": 3,
                                            "head": head}
        finally:
            store.close()
    return {"event_table": "pipeline_events",
            "write_api": "EventStore.append",
            "legacy_events_table_created": False,
            "event_id_key": "sha256(canonical payload)",
            "same_api_replay": "duplicate (inserted=False)"}


# ---------------------------------------------------------------------- #
# UE-02：内容寻址幂等 + 逐行 sidecar 映射
# ---------------------------------------------------------------------- #
def test_UE_02_idempotent_content_addressed_sidecar_mapping():
    with TmpDir("ue2-") as td:
        # 跨文件同内容行：文件 a 第 2 行与文件 b 第 1 行字节相同
        src = make_ledger(td, [
            '{"status": "PASS", "ts": "2026-10-01T00:00:00Z", "id": 1}',
            '{"status": "FAIL", "ts": "2026-10-01T00:01:00Z", "id": 2}',
        ], name="a.jsonl")
        write_lines(src, "b.jsonl", [
            '{"status": "FAIL", "ts": "2026-10-01T00:01:00Z", "id": 2}',
            '{"status": "WARN", "ts": "2026-10-01T00:02:00Z", "id": 3}',
        ])
        src_bytes = {f: open(os.path.join(src, f), "rb").read()
                     for f in ("a.jsonl", "b.jsonl")}

        db = os.path.join(td, "ev.db")
        sc = db + ".migration-sidecar.jsonl"
        mig1 = LedgerMigrator(src, db)
        inventory = mig1.scan()
        r1 = mig1.migrate()
        assert r1["conservation"]["imported"] == 3
        assert r1["conservation"]["duplicates"] == 1, "跨文件同内容行未计 duplicate"
        rows1 = unified_rows(db)
        sc1 = open(sc, "rb").read()

        # 逐行 sidecar 映射：run1 的每条审计记录与 scan 清单一一对应
        recs1 = sidecar_records(sc)
        assert len(recs1) == len(inventory)
        by_pos = {(r["file"], r["line_no"]): r["line_sha"] for r in recs1}
        assert by_pos == {(e["file"], e["line_no"]): e["line_sha"]
                          for e in inventory}
        dup_recs = [r for r in recs1 if r["decision"] == "duplicate"]
        assert len(dup_recs) == 1 and dup_recs[0]["file"].endswith("b.jsonl")

        # 同输入第二次迁移（独立实例）：零新导入、行集/链头零变化
        store = EventStore(db)
        try:
            head1, total1 = store.head()
        finally:
            store.close()
        r2 = LedgerMigrator(src, db).migrate()
        assert r2["conservation"]["imported"] == 0
        assert r2["conservation"]["duplicates"] == 4
        assert unified_rows(db) == rows1, "二次迁移改动已入链行集（不幂等）"
        store = EventStore(db)
        try:
            head2, total2 = store.head()
            assert (head2, total2) == (head1, total1)
        finally:
            store.close()

        # sidecar 只追加；源 JSONL 只读（前后字节一致）
        sc2 = open(sc, "rb").read()
        assert sc2.startswith(sc1) and len(sc2) > len(sc1)
        for f, b in src_bytes.items():
            assert open(os.path.join(src, f), "rb").read() == b, "源账本被改动"

        # run2 的审计同样与清单一一对应（每行都有去向，零失联）
        recs2 = sidecar_records(sc)[-len(inventory):]
        assert {(r["file"], r["line_no"]) for r in recs2} == {
            (e["file"], e["line_no"]) for e in inventory}
        assert all(r["decision"] in ("imported", "duplicate", "quarantined")
                   for r in recs2)
    return {"run1": {"imported": 3, "duplicates": 1},
            "run2": {"imported": 0, "duplicates": 4},
            "cross_file_duplicate": "counted (line-content addressed)",
            "rows_and_head_stable": True,
            "sidecar_per_line_mapping": "1:1 vs scan inventory",
            "sidecar_append_only": True}


# ---------------------------------------------------------------------- #
# UE-03：坏行隔离语义在统一表上不回退
# ---------------------------------------------------------------------- #
def test_UE_03_quarantine_semantics_on_unified_table():
    bad_lines = [
        '{broken json',
        '["not", "an", "object"]',
        '"just a string"',
        '{"status": "PASS"}',
        '{"ts": "2026-10-01T00:05:00Z"}',
        '{"status": "WEIRD_STATE", "ts": "t"}',
        '{"status": "ACCEPTED", "ts": "t", "approval": {"approved_by": "u"}}',
    ]
    with TmpDir("ue3-") as td:
        src = make_ledger(td, VALID_LINES + bad_lines + ["", "   "])
        db = os.path.join(td, "ev.db")
        report = LedgerMigrator(src, db).migrate()

        c = report["conservation"]
        assert c["lines_total"] == len(VALID_LINES) + len(bad_lines)
        assert c["imported"] == 3 and c["quarantined"] == len(bad_lines)
        assert c["duplicates"] == 0 and report["conserved"] is True

        mig_rows = unified_payloads(db, MIGRATION_EVENT_TYPE)
        assert len(mig_rows) == len(unified_rows(db)) == 3
        imported_raws = {o["raw"] for o in mig_rows}
        for bad in bad_lines:
            assert bad not in imported_raws, f"坏行入链: {bad}"
        # fail-closed 归一在统一表上成立：ERROR→BLOCKED、FIXED→FPV
        statuses = sorted(o["status"] for o in mig_rows)
        assert statuses == ["BLOCKED", "FIXED_PENDING_VERIFY", "PASS"]
        store = EventStore(db)
        try:
            assert store.verify_chain()["ok"] is True
        finally:
            store.close()
        assert LEGACY_EVENTS_TABLE not in tables_of(db)
    return {"bad_lines": len(bad_lines), "quarantined": len(bad_lines),
            "imported_statuses": ["BLOCKED", "FIXED_PENDING_VERIFY", "PASS"],
            "bad_lines_in_unified_table": 0}


# ---------------------------------------------------------------------- #
# UE-04：混合流单链（迁移行 + EventStore 直写行交错）
# ---------------------------------------------------------------------- #
def test_UE_04_mixed_stream_single_chain():
    with TmpDir("ue4-") as td:
        src = make_ledger(td, VALID_LINES)
        db = os.path.join(td, "ev.db")
        LedgerMigrator(src, db).migrate()          # 3 行迁移入链

        store = EventStore(db)
        try:
            h1, i1 = store.append({"probe": "external", "n": 1})
            assert i1 is True
            # 迁移重跑：零新行、链头不动（混合流中幂等保持）
            r2 = LedgerMigrator(src, db).migrate()
            assert r2["conservation"]["imported"] == 0
            head_mid, total_mid = store.head()
            assert total_mid == 4 and head_mid == h1
            h2, i2 = store.append({"probe": "external", "n": 2})
            assert i2 is True
            # 再混合一轮：迁移行/外部行交替追加
            write_lines(src, "more.jsonl",
                        ['{"status": "BLOCKED", "ts": "t2", "id": 9}'])
            r3 = LedgerMigrator(src, db).migrate()
            assert r3["conservation"]["imported"] == 1
            h3, i3 = store.append({"probe": "external", "n": 3})
            assert i3 is True

            verify = store.verify_chain()
            assert verify["ok"] is True and verify["length"] == 7
            head, total = store.head()
            assert (head, total) == (h3, 7)
            # 链序精确：迁移行与外部行按写入顺序交错、prev 逐行咬合
            rows = unified_rows(db)
            expect_prev = "0" * 64
            kinds = []
            for _seq, _eid, payload, prev_h, ehash in rows:
                obj = json.loads(payload)
                kinds.append(obj.get("event_type") or obj.get("probe"))
                assert prev_h == expect_prev
                h = hashlib.sha256()
                h.update(prev_h.encode("ascii"))
                h.update(payload.encode("utf-8"))
                assert ehash == h.hexdigest()
                expect_prev = ehash
            assert kinds == [MIGRATION_EVENT_TYPE] * 3 + \
                ["external", "external", MIGRATION_EVENT_TYPE, "external"]
        finally:
            store.close()
    return {"mixed_chain_length": 7,
            "order": ["LEDGER_MIGRATED"] * 3 + ["external", "LEDGER_MIGRATED",
                                                "external"],
            "rerun_in_mixed_stream": {"imported": 0},
            "verify_chain": "ok"}


# ---------------------------------------------------------------------- #
# UE-05：旧 events 表残留一次性收编（合成旧表 fixture）
# ---------------------------------------------------------------------- #
def _build_legacy_db(db, rows):
    """合成历史库：按旧版 schema 建 events 表并插行（非生产数据）。"""
    conn = sqlite3.connect(db)
    try:
        conn.executescript(LEGACY_SCHEMA)
        for line_sha, status, source_file, source_line, payload in rows:
            conn.execute(
                "INSERT INTO events (line_sha, status, source_file, "
                "source_line, payload) VALUES (?, ?, ?, ?, ?)",
                (line_sha, status, source_file, source_line, payload))
        conn.commit()
    finally:
        conn.close()


def test_UE_05_legacy_events_residue_one_time_migration():
    legacy_rows = [
        (content_sha('{"status": "PASS", "ts": "2026-09-01T00:00:00Z"}'),
         "PASS", "/synthetic/legacy-a.jsonl", 1,
         '{"status": "PASS", "ts": "2026-09-01T00:00:00Z"}'),
        (content_sha('{"status": "FAIL", "ts": "2026-09-01T00:01:00Z"}'),
         "FAIL", "/synthetic/legacy-a.jsonl", 2,
         '{"status": "FAIL", "ts": "2026-09-01T00:01:00Z"}'),
        (content_sha('{"status": "BLOCKED", "ts": "2026-09-01T00:02:00Z"}'),
         "BLOCKED", "/synthetic/legacy-b.jsonl", 7,
         '{"status": "BLOCKED", "ts": "2026-09-01T00:02:00Z"}'),
        # 旧制度下已落账的非常规状态：收编按历史记录原样搬运、不重判
        (content_sha('{"status": "WEIRD_OLD", "ts": "2026-09-01T00:03:00Z"}'),
         "WEIRD_OLD", "/synthetic/legacy-b.jsonl", 9,
         '{"status": "WEIRD_OLD", "ts": "2026-09-01T00:03:00Z"}'),
    ]
    with TmpDir("ue5-") as td:
        db = os.path.join(td, "ev.db")
        _build_legacy_db(db, legacy_rows)
        conn = sqlite3.connect(db)
        try:
            legacy_before = conn.execute(
                "SELECT id, line_sha, status, source_file, source_line, "
                "payload FROM events ORDER BY id").fetchall()
        finally:
            conn.close()

        # 一次性收编：4 行全部经公共 append 入统一链
        r1 = migrate_legacy_events(db)
        assert r1["legacy_table_present"] is True
        assert r1["rows_seen"] == 4 and r1["imported"] == 4 \
            and r1["duplicates"] == 0
        assert r1["event_table"] == "pipeline_events"
        rows = unified_rows(db)
        assert len(rows) == 4
        objs = [json.loads(r[2]) for r in rows]
        assert all(o["event_type"] == LEGACY_RESIDUE_EVENT_TYPE for o in objs)
        # 旧行已记内容逐字段原样搬运（line_sha/status/raw）
        assert [(o["line_sha"], o["status"], o["raw"]) for o in objs] == \
            [(r[0], r[1], r[4]) for r in legacy_rows]
        store = EventStore(db)
        try:
            assert store.verify_chain()["ok"] is True
        finally:
            store.close()

        # 旧表只读兼容：行集逐字节原样保留、仍可查询，且不再是唯一事件源
        conn = sqlite3.connect(db)
        try:
            legacy_after = conn.execute(
                "SELECT id, line_sha, status, source_file, source_line, "
                "payload FROM events ORDER BY id").fetchall()
        finally:
            conn.close()
        assert legacy_after == legacy_before, "旧 events 表被改动（只读兼容破坏）"
        assert {LEGACY_EVENTS_TABLE, "pipeline_events"} <= tables_of(db)
        # 旧表上的 append-only 语义不受影响：收编绝不写旧表（快照已证），
        # 对统一表的篡改路径仍由触发器关死
        conn = sqlite3.connect(db)
        try:
            expect(sqlite3.IntegrityError, lambda: conn.execute(
                "DELETE FROM pipeline_events"))
        finally:
            conn.close()

        # 重跑收编：全 duplicate、行集零变化（一次性幂等）
        rows_before = unified_rows(db)
        r2 = migrate_legacy_events(db)
        assert r2["imported"] == 0 and r2["duplicates"] == 4
        assert unified_rows(db) == rows_before
        # sidecar 携带旧表位置溯源（legacy_id/source_file/source_line）
        recs = sidecar_records(db + ".legacy-events-sidecar.jsonl")
        assert len(recs) == 8          # 两次收编 × 4 行
        assert {(r["source_file"], r["source_line"]) for r in recs} == {
            (r[2], r[3]) for r in legacy_rows}
        assert [r["legacy_id"] for r in recs] == [1, 2, 3, 4, 1, 2, 3, 4]

        # 与 JSONL 迁移混合：同一库同一条链
        src = make_ledger(td, VALID_LINES)
        r3 = LedgerMigrator(src, db).migrate()
        assert r3["conservation"]["imported"] == 3
        store = EventStore(db)
        try:
            verify = store.verify_chain()
            assert verify["ok"] is True and verify["length"] == 7
            types = {o["event_type"] for o in unified_payloads(db)}
            assert types == {LEGACY_RESIDUE_EVENT_TYPE, MIGRATION_EVENT_TYPE}
        finally:
            store.close()

        # 缺表（新库）：不是错误，零行收编
        fresh_db = os.path.join(td, "fresh.db")
        EventStore(fresh_db).close()
        r4 = migrate_legacy_events(fresh_db)
        assert r4["legacy_table_present"] is False and r4["rows_seen"] == 0

        # 形状异常的同名表：fail-closed 拒收，绝不猜搬
        weird_db = os.path.join(td, "weird.db")
        conn = sqlite3.connect(weird_db)
        try:
            conn.execute(
                "CREATE TABLE events (id INTEGER PRIMARY KEY, note TEXT)")
            conn.commit()
        finally:
            conn.close()
        expect(RuntimeError, lambda: migrate_legacy_events(weird_db))
    return {"legacy_rows": 4, "first_run": {"imported": 4, "duplicates": 0},
            "rerun": {"imported": 0, "duplicates": 4},
            "legacy_table": "kept read-only, bytewise unchanged",
            "mixed_with_jsonl_migration": "single chain len=7",
            "missing_table": "ok (rows_seen=0)",
            "wrong_shape_table": "RuntimeError (fail-closed)"}


# ---------------------------------------------------------------------- #
# UE-06：控制事件守卫不回退（统一表上的伪造路径仍关死）
# ---------------------------------------------------------------------- #
def test_UE_06_control_event_guard_not_regressed():
    # 迁移器使用的两个事件类型都不是控制类型（可经公共 append 写入）
    for etype in (MIGRATION_EVENT_TYPE, LEGACY_RESIDUE_EVENT_TYPE):
        assert is_control_event({"event_type": etype}) is False, etype
    # 控制类型判定面完整（前缀 + 精确枚举）
    for etype in CONTROL_EVENT_TYPE_PREFIXES:
        assert is_control_event({"event_type": etype + "_X"}) is True
    for etype in CONTROL_EVENT_TYPE_EXACT:
        assert is_control_event({"event_type": etype}) is True

    with TmpDir("ue6-") as td:
        src = make_ledger(td, VALID_LINES)
        db = os.path.join(td, "ev.db")
        LedgerMigrator(src, db).migrate()
        store = EventStore(db)
        try:
            head_before, total_before = store.head()
            # 统一表上裸 append 伪造控制事件（含伪造 seal）全拒
            forged = [
                {"event_type": "RUN_COMPLETED", "seal": "f" * 64},
                {"event_type": "STAGE_PASSED", "stage": "S7_GATE"},
                {"event_type": "ATTEMPT_STATUS", "status": "RUNNING"},
                {"event_type": "WAITING_RESUMED"},
                {"event_type": "APPROVAL_GRANTED", "nonce": "n"},
                {"event_type": "ACTION_APPROVED"},
                {"event_type": "FINDING_REGISTERED"},
                {"event_type": "SUPERSEDED", "seal": "0" * 64},
            ]
            for ev in forged:
                expect(ValueError, lambda ev=ev: store.append(ev))
            # 拒绝面零副作用：链头/行数不变、链仍可验证
            head_after, total_after = store.head()
            assert (head_after, total_after) == (head_before, total_before)
            assert store.verify_chain()["ok"] is True
            # 对照组：普通外部事件仍可写（守卫拒绝面精确）
            _h, ins = store.append({"event_type": "OBSERVATION", "n": 1})
            assert ins is True
            assert store.verify_chain()["ok"] is True
        finally:
            store.close()
    return {"migration_event_types": "non-control (public append path)",
            "forged_control_events_rejected": len(forged),
            "guard_side_effects": "none (head/total unchanged)",
            "ordinary_events": "still appendable"}


TESTS = [
    ("UE-01", "单一事件表+单一写入 API（同表同幂等键）",
     test_UE_01_single_table_single_write_api),
    ("UE-02", "内容寻址幂等+逐行 sidecar 映射（跨文件同内容=duplicate）",
     test_UE_02_idempotent_content_addressed_sidecar_mapping),
    ("UE-03", "坏行隔离语义在统一表上不回退（ERROR→BLOCKED fail-closed）",
     test_UE_03_quarantine_semantics_on_unified_table),
    ("UE-04", "混合流单链：迁移行+EventStore 直写行交错 verify_chain 贯穿",
     test_UE_04_mixed_stream_single_chain),
    ("UE-05", "旧 events 表残留一次性收编（合成旧表 fixture，幂等+只读兼容）",
     test_UE_05_legacy_events_residue_one_time_migration),
    ("UE-06", "控制事件守卫不回退（统一表上伪造 RUN_*/SUPERSEDED 全拒）",
     test_UE_06_control_event_guard_not_regressed),
]


def main():
    global PASS_N, FAIL_N
    print("统一事件正源专属测试（P0-6 第六轮：单一事件表+单一写入 API）")
    print(f"被测体: {os.path.join('system', 'wenqu_core', 'ledger_migrator.py')}"
          f" + {os.path.join('system', 'wenqu_core', 'store.py')}\n")
    for tid, name, fn in TESTS:
        try:
            detail = fn() or {}
            ok = True
            PASS_N += 1
            print(f"  ok   {tid}  {name}")
            RESULTS.append((tid, name, True, detail))
        except Exception as e:                              # noqa: BLE001
            FAIL_N += 1
            import traceback
            print(f"  FAIL {tid}  {name}")
            print("       " + traceback.format_exc(limit=8).replace(
                "\n", "\n       "))
            RESULTS.append((tid, name, False,
                            {"error": f"{type(e).__name__}: {e}"}))
    exit_code = 0 if FAIL_N == 0 else 1
    print(f"\n结果: {PASS_N} PASS / {FAIL_N} FAIL；exit={exit_code}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

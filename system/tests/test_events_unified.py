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
         append 伪造 RUN_*/SUPERSEDED 仍一律 ValueError；
    UE-07（R7-EVENT-LEGACY-WRITABLE-007 P0 根修 + 第八轮 P0-6 残余根修）
         旧表冻结只读+迟到写拒收+行内容快照账本：收编完成后旧 events 表
         INSERT/UPDATE/DELETE 被冻结触发器全拒；绕过触发器（新库模拟：
         无触发器的旧表）塞入的迟到行在第二次迁移走 quarantine
         （late_write_after_cutover）绝不入链，且 id 通道（id>
         cutover.max_legacy_id，ts 伪装早也能抓）与 ts 通道（行内 ts/
         元数据晚于 cutover，id 塞进历史空位也能抓）独立成立；触发器
         治愈重装、cutover 永不推进、重复收编幂等不重复装触发器。
         第八轮扩展（id/ts 双通道都是 writer 可回填字段）：收编时行内容
         sha256 记入统一库侧受保护账本 legacy_row_digests（AFTER UPDATE/
         DELETE 拒绝触发器，append-only 与事件链同库）；二次迁移逐行
         比对——UPDATE+backdate 的失配行 quarantine
         （row_mutated_after_cutover）绝不入链且不重基线快照；gap 空位
         全回填 INSERT（id/ts 双通道全漏）按账本缺席拒收；账本自身
         UPDATE/DELETE 被触发器关死；合法未动行仍正常 duplicate。
    UE-08（G9-05 R8-EVENT-BACKDATE-008 升级路径根修）legacy 升级
         fail-closed：旧版代码跑过的库（cutover 已记账、无 digest
         ledger——合成法：正常收编后 DROP TABLE legacy_row_digests 抹掉
         行版本账本，库形状与旧版存量库逐表一致）升级时绝不按「当前
         现状」补可信基线：删除 trigger 后的 gap 空位 INSERT+UPDATE+
         backdate（id/ts 双通道全漏的篡改）在升级收编中全部 quarantine
         （legacy_untrusted_no_baseline）、imported=0、主链长度不增、
         digest 账本保持缺席（永不重基线）、报告显式 legacy_untrusted
         标记+人工处置说明；重跑稳定不可收编。不误伤对照：有完整
         digest ledger 的库升级照常（全 duplicate、不标 untrusted）；
         从未 cutover 的全新库照常首跑收编入链。

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
    MIGRATION_EVENT_TYPE, LEGACY_EVENTS_TABLE, LEGACY_RESIDUE_EVENT_TYPE,
    LATE_WRITE_REASON, LEGACY_FREEZE_TRIGGER_NAMES, LEGACY_CUTOVER_TABLE,
    ROW_MUTATED_REASON, LEGACY_ROW_DIGESTS_TABLE,
    LEGACY_DIGEST_FREEZE_TRIGGER_NAMES,
    LEGACY_UNTRUSTED_REASON, LEGACY_UNTRUSTED_ACTION_REQUIRED)

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


# ---------------------------------------------------------------------- #
# UE-07：旧表冻结只读 + 迟到写拒收（R7-EVENT-LEGACY-WRITABLE-007 P0 根修）
# ---------------------------------------------------------------------- #
UE7_ROWS = [
    (content_sha('{"status": "PASS", "ts": "2026-09-01T00:00:00Z"}'),
     "PASS", "/synthetic/ue7.jsonl", 1,
     '{"status": "PASS", "ts": "2026-09-01T00:00:00Z"}'),
    (content_sha('{"status": "FAIL", "ts": "2026-09-01T00:01:00Z"}'),
     "FAIL", "/synthetic/ue7.jsonl", 2,
     '{"status": "FAIL", "ts": "2026-09-01T00:01:00Z"}'),
    (content_sha('{"status": "BLOCKED", "ts": "2026-09-01T00:02:00Z"}'),
     "BLOCKED", "/synthetic/ue7.jsonl", 3,
     '{"status": "BLOCKED", "ts": "2026-09-01T00:02:00Z"}'),
]
#: id 通道专用迟到行：id 必然 > cutover.max_legacy_id，但行内 ts 与
#: migrated_at 全部伪装成 cutover 前的早时间——只有 id 通道能抓到
UE7_LATE_RAW_ID = ('{"status": "PASS", "ts": "2026-09-01T00:03:00Z", '
                   '"id": "late-id-channel"}')
#: ts 通道专用迟到行：塞进历史 id 空位（id ≤ max），migrated_at 伪装早
#: 时间、行内 ts 晚于 cutover——只有 ts 通道能抓到
UE7_LATE_RAW_TS = ('{"status": "FAIL", "ts": "2099-01-01T00:00:00Z", '
                   '"id": "late-ts-channel"}')
UE7_EARLY_META = "2026-09-01 00:00:00"
#: 第八轮（UPDATE+backdate 拒收）专用载荷：收编后 UPDATE 旧行改写的
#: 内容——ts 回填到比原行（2026-09-01）更早的 2026-08-01，id 不变、
#: ts/migrated_at 全部伪装早时间，id/ts 双通道全漏，只有行内容快照
#: 账本（第三通道）能抓到
UE7_MUTATED_RAW = ('{"status": "PASS", "ts": "2026-08-01T00:00:00Z", '
                   '"mutated": "backdated"}')
#: 第八轮（gap 空位全回填拒收）专用载荷：塞进历史空位（id 在
#: max_legacy_id 区间内、该 rowid 在 cutover 时不存在）的行——行内 ts
#: 与 migrated_at 全部回填早时间，id/ts 双通道全漏，只有账本缺席
#: （no row digest on record）能抓到
UE7_GAP_RAW = ('{"status": "PASS", "ts": "2026-09-01T00:05:00Z", '
               '"gap": "backfilled"}')


def _drop_freeze_triggers(conn):
    """模拟触发器被绕过/删除（合成库内的对抗前置；真实库中 DROP 需 schema
    写权限，正是 R7 要防的「绕过触发器」场景）。"""
    for name in LEGACY_FREEZE_TRIGGER_NAMES:
        conn.execute(f"DROP TRIGGER IF EXISTS {name}")
    conn.commit()


def _legacy_insert(conn, line_sha, payload, legacy_id=None,
                   migrated_at=UE7_EARLY_META):
    """手工向旧表塞一行（绕过触发器场景的迟到写注入）。"""
    conn.execute(
        f"INSERT INTO {LEGACY_EVENTS_TABLE} "
        f"(id, line_sha, status, source_file, source_line, payload, migrated_at) "
        f"VALUES (?, ?, ?, ?, ?, ?, ?)",
        (legacy_id, line_sha, "PASS", "/synthetic/late.jsonl", 99, payload,
         migrated_at))
    conn.commit()


def test_UE_07_legacy_frozen_readonly_late_write_quarantined():
    with TmpDir("ue7-") as td:
        db = os.path.join(td, "ev.db")
        _build_legacy_db(db, UE7_ROWS)

        # ---- 首次收编：入链 + 表冻结只读 + cutover 记账 ----
        r1 = migrate_legacy_events(db)
        assert r1["legacy_table_present"] is True
        assert (r1["imported"], r1["duplicates"], r1["quarantined"]) == (3, 0, 0)
        assert r1["legacy_frozen"] is True, "收编完成后旧表未冻结只读"
        assert sorted(r1["frozen_triggers"]) == sorted(LEGACY_FREEZE_TRIGGER_NAMES)
        cutover_ts = r1["cutover_ts"]
        assert cutover_ts and r1["cutover_max_legacy_id"] == 3
        conn = sqlite3.connect(db)
        try:
            trig = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name=?", (LEGACY_EVENTS_TABLE,))}
            assert set(LEGACY_FREEZE_TRIGGER_NAMES) <= trig
            # cutover bookkeeping 单行记账（一经记录永不推进）
            assert conn.execute(
                f"SELECT COUNT(*) FROM {LEGACY_CUTOVER_TABLE}").fetchone()[0] == 1
        finally:
            conn.close()
        rows_after_r1 = unified_rows(db)
        assert len(rows_after_r1) == 3

        # ---- (1) 收编后旧表 INSERT/UPDATE/DELETE → 全部被触发器拒绝 ----
        conn = sqlite3.connect(db)
        try:
            expect(sqlite3.IntegrityError, lambda: _legacy_insert(
                conn, content_sha(UE7_LATE_RAW_ID), UE7_LATE_RAW_ID))
            expect(sqlite3.IntegrityError, lambda: conn.execute(
                f"UPDATE {LEGACY_EVENTS_TABLE} SET status='MUTATED' WHERE id=1"))
            expect(sqlite3.IntegrityError, lambda: conn.execute(
                f"DELETE FROM {LEGACY_EVENTS_TABLE} WHERE id=1"))
            conn.rollback()
            assert conn.execute(
                f"SELECT COUNT(*) FROM {LEGACY_EVENTS_TABLE}").fetchone()[0] == 3
        finally:
            conn.close()
        assert unified_rows(db) == rows_after_r1, "拒收后统一链被扰动"

        # ---- (2) 绕过触发器场景（新库模拟）+ id 通道：无触发器旧表 + 迟到行 ----
        #    真实库中触发器已把 INSERT 关死；DROP TRIGGER 模拟「触发器被
        #    绕过/未安装」。塞入 id=4（>max 3）但行内 ts/migrated_at 全部
        #    伪装早时间——只有 id 通道能抓到
        conn = sqlite3.connect(db)
        try:
            _drop_freeze_triggers(conn)
            _legacy_insert(conn, content_sha(UE7_LATE_RAW_ID), UE7_LATE_RAW_ID)
            assert conn.execute(
                f"SELECT COUNT(*) FROM {LEGACY_EVENTS_TABLE}").fetchone()[0] == 4
        finally:
            conn.close()

        r2 = migrate_legacy_events(db)
        assert (r2["imported"], r2["duplicates"], r2["quarantined"]) == (0, 3, 1)
        assert r2["quarantine_reasons"] == {LATE_WRITE_REASON: 1}
        assert r2["late_write_alert"] is True, "迟到写未告警"
        assert r2["late_write_rows"] == [
            {"legacy_id": 4, "evidence": "id=4 > cutover_max_id=3"}]
        # 迟到行绝不入链：行集零变化、其 line_sha 不在任何链上负载里
        assert unified_rows(db) == rows_after_r1, "迟到行被导入统一链"
        assert all(content_sha(UE7_LATE_RAW_ID) not in r[2]
                   for r in unified_rows(db))
        # 触发器治愈重装；cutover 永不推进
        assert r2["legacy_frozen"] is True
        assert (r2["cutover_ts"], r2["cutover_max_legacy_id"]) == (cutover_ts, 3)
        # 治愈后迟到写再次被关死
        conn = sqlite3.connect(db)
        try:
            expect(sqlite3.IntegrityError, lambda: _legacy_insert(
                conn, content_sha('{"status": "PASS", "ts": "z"}'),
                '{"status": "PASS", "ts": "z"}'))
            conn.rollback()
        finally:
            conn.close()

        # ---- (3) ts 通道独立命中：id 塞进历史空位（≤max）但行内 ts 晚于 cutover ----
        db2 = os.path.join(td, "ev2.db")
        _build_legacy_db(db2, UE7_ROWS[:2])               # ids 1,2
        conn = sqlite3.connect(db2)
        try:
            conn.execute(
                f"INSERT INTO {LEGACY_EVENTS_TABLE} (line_sha, status, "
                f"source_file, source_line, payload) VALUES (?, ?, ?, ?, ?)",
                (UE7_ROWS[2][0], UE7_ROWS[2][1], UE7_ROWS[2][2],
                 UE7_ROWS[2][3], UE7_ROWS[2][4]))          # id=3
            conn.commit()
            conn.execute(
                f"DELETE FROM {LEGACY_EVENTS_TABLE} WHERE id=2")   # 留空位
            conn.commit()
        finally:
            conn.close()
        s1 = migrate_legacy_events(db2)
        assert (s1["imported"], s1["duplicates"], s1["quarantined"]) == (2, 0, 0)
        assert s1["cutover_max_legacy_id"] == 3
        conn = sqlite3.connect(db2)
        try:
            _drop_freeze_triggers(conn)
            _legacy_insert(conn, content_sha(UE7_LATE_RAW_TS), UE7_LATE_RAW_TS,
                           legacy_id=2)                    # id=2 ≤ max=3
        finally:
            conn.close()
        s2 = migrate_legacy_events(db2)
        assert (s2["imported"], s2["duplicates"], s2["quarantined"]) == (0, 2, 1)
        assert s2["quarantine_reasons"] == {LATE_WRITE_REASON: 1}
        assert s2["late_write_alert"] is True
        assert s2["late_write_rows"][0]["legacy_id"] == 2
        assert s2["late_write_rows"][0]["evidence"].startswith("row_ts="), \
            "ts 通道未独立命中（迟到行靠 id 通道漏过）"
        assert "2099-01-01" not in json.dumps(unified_payloads(db2))
        assert s2["legacy_frozen"] is True

        # ---- (4) 幂等：第三次迁移全 duplicate + 迟到行稳定隔离，触发器不重复 ----
        r3 = migrate_legacy_events(db)
        assert (r3["imported"], r3["duplicates"], r3["quarantined"]) == (0, 3, 1)
        assert (r3["cutover_ts"], r3["cutover_max_legacy_id"]) == (cutover_ts, 3)
        assert r3["legacy_frozen"] is True
        conn = sqlite3.connect(db)
        try:
            n_trig = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name=?", (LEGACY_EVENTS_TABLE,)).fetchone()[0]
            assert n_trig == len(LEGACY_FREEZE_TRIGGER_NAMES), \
                "冻结触发器重复安装或缺失"
            # cutover 记账仍单行（重跑绝不推进/绝不双记）
            assert conn.execute(
                f"SELECT COUNT(*) FROM {LEGACY_CUTOVER_TABLE}").fetchone()[0] == 1
        finally:
            conn.close()
        store = EventStore(db)
        try:
            verify = store.verify_chain()
            assert verify["ok"] is True and verify["length"] == 3
        finally:
            store.close()
        # sidecar quarantine 记录携带 reason 与迟到证据（人工裁定线索）
        recs = sidecar_records(db + ".legacy-events-sidecar.jsonl")
        q = [r for r in recs if r["decision"] == "quarantined"]
        assert len(q) == 2                       # r2/r3 各隔离该迟到行一次
        assert all(r["reason"] == LATE_WRITE_REASON and r.get("late_evidence")
                   for r in q)
        assert all(r["legacy_id"] == 4 for r in q)

        # ---- (5) 行内容快照账本（第八轮）：UPDATE+backdate 失配行 quarantine ----
        #    id 不变、ts/migrated_at 全部回填比原行更早——id/ts 双通道全漏，
        #    只有第三通道（内容快照比对）能抓到
        db3 = os.path.join(td, "ev3.db")
        _build_legacy_db(db3, UE7_ROWS)
        t1 = migrate_legacy_events(db3)
        assert (t1["imported"], t1["duplicates"], t1["quarantined"]) == (3, 0, 0)
        assert t1["row_digest_ledger"] == LEGACY_ROW_DIGESTS_TABLE
        assert t1["row_digests_on_record"] == 3, "首跑未记行内容快照账本"
        assert t1["row_mutation_alert"] is False
        rows_t1 = unified_rows(db3)
        conn = sqlite3.connect(db3)
        try:
            # 账本自身 append-only：UPDATE/DELETE 一律触发器关死（与事件链
            # 同库同级的保护——绕过旧表触发器改不到这里）
            expect(sqlite3.IntegrityError, lambda: conn.execute(
                f"UPDATE {LEGACY_ROW_DIGESTS_TABLE} SET row_sha = ? "
                f"WHERE legacy_id = 1", ("f" * 64,)))
            expect(sqlite3.IntegrityError, lambda: conn.execute(
                f"DELETE FROM {LEGACY_ROW_DIGESTS_TABLE} WHERE legacy_id = 1"))
            conn.rollback()
            trig_digest = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name=?", (LEGACY_ROW_DIGESTS_TABLE,))}
            assert set(LEGACY_DIGEST_FREEZE_TRIGGER_NAMES) <= trig_digest, \
                "快照账本 append-only 触发器缺失"
            # 绕过旧表冻结触发器（DROP 模拟）：UPDATE 旧行内容并回填早时间
            _drop_freeze_triggers(conn)
            conn.execute(
                f"UPDATE {LEGACY_EVENTS_TABLE} SET line_sha = ?, "
                f"status = 'PASS', payload = ?, "
                f"migrated_at = '2026-08-01 00:00:00' WHERE id = 2",
                (content_sha(UE7_MUTATED_RAW), UE7_MUTATED_RAW))
            conn.commit()
        finally:
            conn.close()
        t2 = migrate_legacy_events(db3)
        assert (t2["imported"], t2["duplicates"], t2["quarantined"]) == (0, 2, 1)
        assert t2["quarantine_reasons"] == {ROW_MUTATED_REASON: 1}
        assert t2["row_mutation_alert"] is True, "内容失配未告警"
        assert t2["row_mutation_rows"][0]["legacy_id"] == 2
        assert t2["row_mutation_rows"][0]["evidence"].startswith("row_sha="), \
            "失配证据不是内容摘要比对（第三通道未独立命中）"
        # 失配行绝不入链：行集零变化、篡改内容不在任何链上负载里；
        # 未动的合法行（1,3）正常 duplicate（duplicates=2）
        assert unified_rows(db3) == rows_t1, "UPDATE+backdate 行被导入统一链"
        assert all("backdated" not in r[2] for r in unified_rows(db3))
        assert t2["legacy_frozen"] is True            # 触发器治愈重装
        assert (t2["cutover_ts"], t2["cutover_max_legacy_id"]) == \
            (t1["cutover_ts"], 3)                     # cutover 永不推进
        # 稳定性：第三次迁移仍失配拒收；快照绝不重基线（不吸收篡改内容）
        t3 = migrate_legacy_events(db3)
        assert (t3["imported"], t3["duplicates"], t3["quarantined"]) == (0, 2, 1)
        assert t3["quarantine_reasons"] == {ROW_MUTATED_REASON: 1}
        assert t3["row_digests_on_record"] == 3, "快照账本被重基线（白名单篡改）"
        assert unified_rows(db3) == rows_t1
        store = EventStore(db3)
        try:
            assert store.verify_chain() == {"ok": True, "length": 3,
                                            "head": rows_t1[-1][4]}
        finally:
            store.close()
        # sidecar quarantine 记录携带 reason 与失配证据（人工裁定线索）
        recs3 = sidecar_records(db3 + ".legacy-events-sidecar.jsonl")
        q3 = [r for r in recs3 if r["decision"] == "quarantined"]
        assert len(q3) == 2                          # t2/t3 各隔离一次
        assert all(r["reason"] == ROW_MUTATED_REASON and r.get("mutation_evidence")
                   for r in q3)
        assert all(r["legacy_id"] == 2 for r in q3)

        # ---- (6) gap 空位全回填 INSERT（第八轮）：id/ts 双通道全漏 ----
        #    cutover 时 id=2 空位（首跑前已删除）→ 账本缺席即「cutover 后
        #    才出现」的铁证，按迟到写拒收
        db4 = os.path.join(td, "ev4.db")
        _build_legacy_db(db4, UE7_ROWS)
        conn = sqlite3.connect(db4)
        try:
            conn.execute(f"DELETE FROM {LEGACY_EVENTS_TABLE} WHERE id = 2")
            conn.commit()
        finally:
            conn.close()
        u1 = migrate_legacy_events(db4)
        assert (u1["imported"], u1["duplicates"], u1["quarantined"]) == (2, 0, 0)
        assert u1["cutover_max_legacy_id"] == 3
        assert u1["row_digests_on_record"] == 2       # 只记 cutover 时存在过的行
        rows_u1 = unified_rows(db4)
        conn = sqlite3.connect(db4)
        try:
            _drop_freeze_triggers(conn)
            _legacy_insert(conn, content_sha(UE7_GAP_RAW), UE7_GAP_RAW,
                           legacy_id=2)               # id=2 ≤ max，时间全早
        finally:
            conn.close()
        u2 = migrate_legacy_events(db4)
        assert (u2["imported"], u2["duplicates"], u2["quarantined"]) == (0, 2, 1)
        assert u2["quarantine_reasons"] == {LATE_WRITE_REASON: 1}
        assert u2["late_write_alert"] is True
        assert u2["late_write_rows"][0]["legacy_id"] == 2
        assert "no row digest on record" in u2["late_write_rows"][0]["evidence"], \
            "gap 空位全回填行未被账本缺席通道抓到（id/ts 双通道漏过）"
        assert u2["row_digests_on_record"] == 2       # quarantine 不重基线快照
        assert unified_rows(db4) == rows_u1, "gap 回填行被导入统一链"
        assert all("backfilled" not in r[2] for r in unified_rows(db4))
        assert u2["legacy_frozen"] is True
        store = EventStore(db4)
        try:
            assert store.verify_chain()["ok"] is True and \
                store.head()[1] == 2
        finally:
            store.close()
    return {"post_cutover_insert_update_delete": "all rejected (freeze trigger)",
            "bypass_late_row_id_channel": "quarantined, never in chain",
            "bypass_late_row_ts_channel": "quarantined (id in range, ts late)",
            "trigger_healing": "re-installed on next run",
            "cutover_never_advanced": True,
            "freeze_triggers_count": len(LEGACY_FREEZE_TRIGGER_NAMES),
            "rerun_idempotent": {"imported": 0, "duplicates": 3,
                                 "quarantined": 1},
            "update_backdate_row": "quarantined (row_mutated_after_cutover)",
            "gap_backfilled_row": "quarantined (no row digest on record)",
            "row_digest_ledger": "append-only (UPDATE/DELETE trigger-blocked)",
            "snapshot_never_rebaselined": True,
            "legal_untouched_rows": "duplicate"}


# ---------------------------------------------------------------------- #
# UE-08：legacy 升级 fail-closed（G9-05 R8-EVENT-BACKDATE-008 升级路径）
# ---------------------------------------------------------------------- #
#: gap 空位篡改行（id=2 ≤ max，行内 ts 与 migrated_at 全部回填 cutover 前
#: 早时间——id/ts 双通道全漏；旧版库无 digest ledger，第三通道缺席）
UE8_GAP_RAW = ('{"status": "PASS", "ts": "2026-09-01T00:05:00Z", '
               '"gap": "backfilled"}')
#: UPDATE+backdate 篡改载荷（id=1 不变，payload ts 与 migrated_at 回填到
#: 比原行 2026-09-01 更早的 2026-08-01——id/ts 双通道全漏）
UE8_MUTATED_RAW = ('{"status": "PASS", "ts": "2026-08-01T00:00:00Z", '
                   '"mutated": "backdated"}')


def _drop_all_event_triggers(conn):
    """DROP events 表上的全部触发器（模拟冻结触发器被绕过/删除）。"""
    names = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' "
        f"AND tbl_name='{LEGACY_EVENTS_TABLE}'")]
    for name in names:
        conn.execute(f"DROP TRIGGER {name}")
    conn.commit()


def test_UE_08_legacy_upgrade_untrusted_fail_closed():
    with TmpDir("ue8-") as td:
        # ---- (1) 旧版存量库合成：正常收编（记 cutover+装触发器+入链），
        #      再抹掉行版本账本 → 与旧版代码跑过的库逐表逐触发器一致 ----
        db = os.path.join(td, "legacy-upgrade.db")
        _build_legacy_db(db, UE7_ROWS)                   # ids 1,2,3
        conn = sqlite3.connect(db)
        try:
            conn.execute(f"DELETE FROM {LEGACY_EVENTS_TABLE} WHERE id = 2")
            conn.commit()                               # 历史空位：id=2
        finally:
            conn.close()
        old = migrate_legacy_events(db)
        assert (old["imported"], old["quarantined"]) == (2, 0)
        cutover_ts = old["cutover_ts"]
        rows_before = unified_rows(db)                  # 旧版已入链的 2 行
        assert len(rows_before) == 2
        conn = sqlite3.connect(db)
        try:
            assert LEGACY_ROW_DIGESTS_TABLE in tables_of(db)
            conn.execute(f"DROP TABLE {LEGACY_ROW_DIGESTS_TABLE}")
            conn.commit()
            # 库形状对账：旧版存量库（cutover 记账在、无 digest ledger）
            assert LEGACY_ROW_DIGESTS_TABLE not in tables_of(db)
            assert conn.execute(
                f"SELECT COUNT(*) FROM {LEGACY_CUTOVER_TABLE}").fetchone()[0] == 1
        finally:
            conn.close()

        # ---- (2) 升级前篡改：DROP 三触发器 → gap INSERT + UPDATE+backdate ----
        conn = sqlite3.connect(db)
        try:
            _drop_all_event_triggers(conn)
            # gap 空位全回填（id=2 ≤ max_legacy_id=3，时间全早）
            conn.execute(
                f"INSERT INTO {LEGACY_EVENTS_TABLE} "
                f"(id, line_sha, status, source_file, source_line, payload, "
                f"migrated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (2, content_sha(UE8_GAP_RAW), "PASS", "/synthetic/late.jsonl",
                 99, UE8_GAP_RAW, "2026-09-01 00:00:00"))
            # UPDATE 既有行 + backdate（id=1 不变，时间回填更早）
            conn.execute(
                f"UPDATE {LEGACY_EVENTS_TABLE} SET line_sha = ?, "
                f"payload = ?, migrated_at = ? WHERE id = 1",
                (content_sha(UE8_MUTATED_RAW), UE8_MUTATED_RAW,
                 "2026-08-01 00:00:00"))
            conn.commit()
            assert conn.execute(
                f"SELECT COUNT(*) FROM {LEGACY_EVENTS_TABLE}").fetchone()[0] == 3
        finally:
            conn.close()

        # ---- (3) 新版升级收编：legacy_untrusted fail-closed ----
        up = migrate_legacy_events(db)
        # 全部行 quarantine（含本可 duplicate 的已入链合法行——库级不可
        # 验证时逐行区分没有可信前提）；imported=0、主链长度不增
        assert (up["imported"], up["duplicates"], up["quarantined"]) == (0, 0, 3)
        assert up["quarantine_reasons"] == {LEGACY_UNTRUSTED_REASON: 3}
        assert up["legacy_untrusted"] is True, "存量库升级未标 legacy_untrusted"
        assert up["legacy_untrusted_reason"] == LEGACY_UNTRUSTED_REASON
        assert [r["legacy_id"] for r in up["legacy_untrusted_rows"]] == [1, 2, 3]
        assert all(r["evidence"] for r in up["legacy_untrusted_rows"])
        # 显式人工处置说明（重建基线或接受隔离；禁止按现状补基线）
        assert up["legacy_untrusted_action_required"] == \
            LEGACY_UNTRUSTED_ACTION_REQUIRED
        assert ("rebuild" in LEGACY_UNTRUSTED_ACTION_REQUIRED
                and "quarantine" in LEGACY_UNTRUSTED_ACTION_REQUIRED)
        # 篡改内容绝不入链：行集零变化、链上负载无 backfilled/backdated
        assert unified_rows(db) == rows_before, "legacy_untrusted 行被导入统一链"
        assert all("backfilled" not in r[2] and "backdated" not in r[2]
                   for r in unified_rows(db))
        # digest 账本保持缺席：绝不按「升级时现状」补可信基线（补记即把
        # 升级前篡改洗白）；cutover 永不推进；触发器治愈重装
        assert up["row_digests_on_record"] == 0
        assert LEGACY_ROW_DIGESTS_TABLE not in tables_of(db)
        assert (up["cutover_ts"], up["cutover_max_legacy_id"]) == (cutover_ts, 3)
        assert up["legacy_frozen"] is True
        store = EventStore(db)
        try:
            verify = store.verify_chain()
            assert verify["ok"] is True and verify["length"] == 2
        finally:
            store.close()
        # sidecar 隔离记录携带 reason 与不可验证证据（人工裁定线索）
        recs = sidecar_records(db + ".legacy-events-sidecar.jsonl")
        q = [r for r in recs if r["decision"] == "quarantined"]
        assert len(q) == 3
        assert all(r["reason"] == LEGACY_UNTRUSTED_REASON
                   and r.get("untrusted_evidence") for r in q)

        # ---- (4) 稳定性：重跑同样不可收编、绝不重基线（无静默洗白窗口）----
        up2 = migrate_legacy_events(db)
        assert (up2["imported"], up2["quarantined"]) == (0, 3)
        assert up2["quarantine_reasons"] == {LEGACY_UNTRUSTED_REASON: 3}
        assert up2["legacy_untrusted"] is True
        assert up2["row_digests_on_record"] == 0
        assert LEGACY_ROW_DIGESTS_TABLE not in tables_of(db)
        assert unified_rows(db) == rows_before
        assert (up2["cutover_ts"], up2["cutover_max_legacy_id"]) == (cutover_ts, 3)

        # ---- (5) 不误伤 I：有完整 digest ledger 的库升级照常 ----
        #      （fresh cutover 已建账本 → 二次收编全 duplicate、不标 untrusted）
        db2 = os.path.join(td, "trusted-upgrade.db")
        _build_legacy_db(db2, UE7_ROWS)
        t1 = migrate_legacy_events(db2)
        assert (t1["imported"], t1["quarantined"]) == (3, 0)
        assert t1["row_digests_on_record"] == 3
        assert t1["legacy_untrusted"] is False
        rows_t1 = unified_rows(db2)
        t2 = migrate_legacy_events(db2)
        assert (t2["imported"], t2["duplicates"], t2["quarantined"]) == (0, 3, 0)
        assert t2["legacy_untrusted"] is False, "完整账本库被误标 untrusted"
        assert unified_rows(db2) == rows_t1
        assert t2["row_digests_on_record"] == 3

        # ---- (6) 不误伤 II：从未 cutover 的全新库照常首跑收编 ----
        db3 = os.path.join(td, "fresh.db")
        _build_legacy_db(db3, UE7_ROWS[:2])
        f1 = migrate_legacy_events(db3)
        assert (f1["imported"], f1["quarantined"]) == (2, 0)
        assert f1["legacy_untrusted"] is False, "全新库被误标 untrusted"
        assert f1["cutover_ts"] is not None
        assert f1["row_digests_on_record"] == 2       # 首跑即建可信基线
        store = EventStore(db3)
        try:
            assert store.verify_chain()["ok"] is True
        finally:
            store.close()
    return {"legacy_upgrade_tamper": "all quarantined (legacy_untrusted_no_baseline)",
            "imported": 0, "chain_length": "unchanged (2)",
            "digest_ledger": "never re-baselined (stays absent)",
            "report": "legacy_untrusted + manual action required",
            "rerun": "stable (still untrusted, still quarantined)",
            "trusted_ledger_upgrade": "as usual (all duplicates, not flagged)",
            "fresh_db_first_run": "as usual (imports, builds baseline)"}


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
    ("UE-07", "旧表冻结只读+迟到写拒收+行内容快照账本（R7 P0+第八轮：三通道 quarantine/幂等）",
     test_UE_07_legacy_frozen_readonly_late_write_quarantined),
    ("UE-08", "legacy 升级 fail-closed（G9-05 R8-EVENT-BACKDATE-008：无 digest ledger 存量库全隔离/不补基线/不误伤）",
     test_UE_08_legacy_upgrade_untrusted_fail_closed),
]


def main():
    global PASS_N, FAIL_N
    print("统一事件正源专属测试（P0-6 第六轮 + R7 旧表冻结/迟到写拒收根修）")
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

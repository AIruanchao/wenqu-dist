# -*- coding: utf-8 -*-
"""旧 JSONL 账本 -> SQLite EventStore(pipeline_events) 迁移器（Codex W5）。

P0-6 第六轮（统一事件正源）改写——「单一事件表 + 单一写入 API」：
    旧版迁移器自建独立 ``events`` 表，与 ``store.EventStore`` 的
    ``pipeline_events`` 哈希链表形成两表两正源。本轮起迁移器不再含
    ``events`` 建表 DDL、绝不写入任何第二事件表：全部导入行经公共
    :meth:`EventStore.append` 写入与管线控制事件/外部事件同一张
    ``pipeline_events`` 表——迁移产物与 EventStore.append 产物同表、
    同哈希链，混合流 ``verify_chain()`` 单链贯穿。

旧 ``events`` 表（仅存在于历史库）冻结为只读兼容：
    - 新代码绝不创建、绝不写入该表；
    - 历史残留行由一次性函数 :func:`migrate_legacy_events` 收编进
      ``pipeline_events``（内容寻址幂等：重跑全部计 duplicate、零重复入账）；
    - 收编后旧表原样保留在库中，仅供只读对账，不再是事件正源。

约束（不可降级）：
    M1 append-only sidecar：迁移审计只追加写入 sidecar JSONL；绝不重写、
       绝不触碰源 JSONL 内容（源文件只读打开）；
    M2 未知状态 / 缺字段 -> quarantine 隔离，绝不猜填字段、绝不猜归一化；
    M3 状态归一化仅限已知别名表；FIXED 一律记为 FIXED_PENDING_VERIFY
       （未经独立验证不承认修复完成）；
    M4 数量守恒：源非空行数 == 有效导入 + 重复 + quarantine；不守恒即抛
       ConservationError，绝不静默少账。
    M5（§20.2 MIG-05）project key 冲突 -> 显式冲突 quarantine，绝不静默
       选边、绝不拆成假项目：同一行携带多个 project 身份字段且值不一致时，
       以 ``project_key_conflict:...`` reason 隔离待人工裁定，导入行绝不
       归入任一冲突方；一致时按 ``PROJECT_FIELDS`` 优先级取 project_id
       贯通进事件负载（§14.3 canonical repo_id 映射的最小实现）。

每行账本契约：JSON 对象，至少含 ``status`` 与 ``ts`` 两个字段；``status``
归一化后必须落在已知状态集合内。空行不计入守恒分母。

重复判定（与旧版 line_sha 唯一约束语义等价）：导入事件的负载是行内容的
纯函数——``event_type``/``line_sha``/``status``/``raw`` 全部由该行字节
内容决定，不含 source_file/source_line 等位置信息（位置溯源只在 sidecar
审计里逐行映射）。因此 ``event_id``（= canonical payload 的 SHA256，
由 EventStore.append 计算）相等当且仅当行内容相同：同输入两次迁移零
重复；跨文件出现的同内容行同样计为 duplicate（与旧版「按行内容 SHA256
判重」一致）。

提交粒度：导入行逐条经 EventStore.append 入链（每行一个 BEGIN
IMMEDIATE 事务，与管线事件同一写入纪律）；中途崩溃后重跑幂等续账
（已入链行计 duplicate），不会双记账。
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

from .store import EventStore

__all__ = [
    "LedgerMigrator", "ConservationError", "STATUS_ALIASES", "KNOWN_STATUSES",
    "MIGRATION_EVENT_TYPE", "LEGACY_EVENTS_TABLE",
    "LEGACY_RESIDUE_EVENT_TYPE", "migration_event", "migrate_legacy_events",
    "PROJECT_FIELDS", "extract_project_ids",
]

# 已知状态别名归一表（键为全大写形式）
STATUS_ALIASES = {
    "PASS": "PASS",
    "PASSED": "PASS",
    "OK": "PASS",
    "SUCCESS": "PASS",
    "GREEN": "PASS",
    "FAIL": "FAIL",
    "FAILED": "FAIL",
    "FAILURE": "FAIL",
    "RED": "FAIL",
    "CONDITIONAL": "CONDITIONAL",
    "WARN": "CONDITIONAL",
    "WARNING": "CONDITIONAL",
    "BLOCKED": "BLOCKED",
    "ERROR": "BLOCKED",
    "FIXED": "FIXED_PENDING_VERIFY",          # M3：FIXED 未验证不承认
    "FIXED_PENDING_VERIFY": "FIXED_PENDING_VERIFY",
}
KNOWN_STATUSES = frozenset({"PASS", "FAIL", "CONDITIONAL", "BLOCKED", "FIXED_PENDING_VERIFY"})
REQUIRED_FIELDS = ("status", "ts")

#: project 身份字段（MIG-05 §14.3 canonical repo_id 映射的最小实现）：
#: 按序取第一个非空值作为该行 project_id；多字段同时存在且值不一致
#: 即 project key 冲突 -> 显式 quarantine（绝不静默选边/拆成假项目）
PROJECT_FIELDS = ("project_id", "project", "repo_id", "repo", "task")

#: MIG-05 quarantine reason 前缀（报告/对账工具按此前缀聚合冲突清单）
PROJECT_KEY_CONFLICT_PREFIX = "project_key_conflict:"

#: 导入行的统一事件类型（非控制类型——控制事件前缀/枚举之外，可经公共
#: EventStore.append 写入；见 store.CONTROL_EVENT_TYPE_*）
MIGRATION_EVENT_TYPE = "LEDGER_MIGRATED"

#: 旧版两正源残留表名（冻结只读；新代码绝不创建、绝不写入）
LEGACY_EVENTS_TABLE = "events"

#: 旧表残留行收编进 pipeline_events 时的事件类型（同样非控制类型）
LEGACY_RESIDUE_EVENT_TYPE = "LEGACY_EVENTS_ROW_MIGRATED"

#: run 级迁移记账表（bookkeeping，非事件正源；与事件表分离）
_RUNS_SCHEMA = """
CREATE TABLE IF NOT EXISTS migration_runs (
    run_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    finished_at   TEXT NOT NULL DEFAULT (datetime('now')),
    files_scanned INTEGER NOT NULL,
    lines_total   INTEGER NOT NULL,
    imported      INTEGER NOT NULL,
    duplicates    INTEGER NOT NULL,
    quarantined   INTEGER NOT NULL,
    conserved     INTEGER NOT NULL
);
"""

#: 旧 ``events`` 表收编时必须存在的列（缺失即形状异常，fail-closed 拒收）
_LEGACY_REQUIRED_COLUMNS = frozenset({
    "id", "line_sha", "status", "source_file", "source_line", "payload"})


class ConservationError(RuntimeError):
    """数量守恒被破坏：源非空行数 != 有效导入 + 重复 + quarantine。"""


def _line_sha(line: str) -> str:
    """行内容 SHA256（剥离行尾换行，保证跨平台一致）。"""
    return hashlib.sha256(line.rstrip("\r\n").encode("utf-8")).hexdigest()


def extract_project_ids(obj: Dict[str, Any]) -> Dict[str, str]:
    """按 ``PROJECT_FIELDS`` 顺序提取行内的 project 身份字段。

    只取标量（str/int/float）非空值；dict/list 或空串视为该字段缺席
    （绝不把复杂值 stringify 成假 project key）。返回 ``{字段名: 规格化值}``
    （保留字段名大小写与顺序，值做 strip）。
    """
    out: Dict[str, str] = {}
    for field in PROJECT_FIELDS:
        val = obj.get(field)
        if val is None or isinstance(val, (dict, list, bool)):
            continue
        text = str(val).strip()
        if text:
            out[field] = text
    return out


def migration_event(line_sha: str, status: str, raw: str,
                    project_id: Optional[str] = None) -> Dict[str, Any]:
    """构造一条导入行的统一事件（行内容的纯函数，保证内容寻址幂等）。

    负载只含由该行字节内容决定的字段（event_type/line_sha/status/raw，
    以及可选 project_id——同样由该行内容决定）；source_file/source_line
    等位置溯源不进负载（进 sidecar 审计），否则同内容行在不同位置会绕过
    判重、破坏 MIG 幂等语义。project_id 为 None（行内无 project 字段）时
    不写入该键，负载形状与既有无 project 行逐字节一致。
    """
    event: Dict[str, Any] = {
        "event_type": MIGRATION_EVENT_TYPE,
        "line_sha": line_sha,
        "status": status,
        "raw": raw,
    }
    if project_id is not None:
        event["project_id"] = project_id
    return event


class LedgerMigrator:
    """旧 JSONL 账本 -> SQLite EventStore(pipeline_events) 迁移器。

    用法::

        mig = LedgerMigrator(source_dir=".../ledgers", sqlite_path=".../events.db")
        mig.scan()          # 可选：显式建立逐文件逐行 SHA 清单
        report = mig.migrate()
        assert report["conserved"] is True

    sqlite_path 指向的库即统一事件正源库：EventStore 在该库上维护
    ``pipeline_events`` 哈希链表；迁移行与管线事件同表同链。
    """

    def __init__(self, source_dir: str, sqlite_path: str,
                 sidecar_path: Optional[str] = None) -> None:
        self.source_dir = os.path.abspath(source_dir)
        self.sqlite_path = os.path.abspath(sqlite_path)
        self.sidecar_path = (
            os.path.abspath(sidecar_path) if sidecar_path
            else self.sqlite_path + ".migration-sidecar.jsonl"
        )
        self._inventory: List[Dict[str, Any]] = []
        self._last_report: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------ #
    # 扫描：逐文件逐行 SHA 清单
    # ------------------------------------------------------------------ #
    def scan(self, source_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """扫描 *.jsonl（按文件名排序），对每个非空行建立 SHA 清单。

        只读操作，绝不写源文件（M1）。空行跳过、不计入分母。
        """
        root = os.path.abspath(source_dir) if source_dir else self.source_dir
        if not os.path.isdir(root):
            raise FileNotFoundError(f"source_dir not found: {root}")

        inventory: List[Dict[str, Any]] = []
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            if not name.endswith(".jsonl") or not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, start=1):
                    if not line.strip():
                        continue  # 空行不计入守恒分母
                    inventory.append({
                        "file": path,
                        "file_name": name,
                        "line_no": line_no,
                        "line_sha": _line_sha(line),
                        "raw": line.rstrip("\r\n"),
                    })
        self._inventory = inventory
        return inventory

    # ------------------------------------------------------------------ #
    # 分类：已知别名归一化 / 未知或残缺 -> quarantine
    # ------------------------------------------------------------------ #
    @staticmethod
    def classify(line: str) -> Dict[str, Any]:
        """判定单行账本。

        返回 ``{"decision": "import"|"quarantine", "status": ..., "reason": ...,
        "line_sha": ..., "project_id": ...}``；import 时 status 为归一化后的
        已知状态、project_id 为行内一致提取的 project 身份（无则 None）；
        MIG-05：多个 project 身份字段值不一致 -> quarantine，reason 形如
        ``project_key_conflict:<fA>=<vA>!=<fB>=<vB>``（值截断 40 字符），
        绝不静默选边导入任一冲突方。
        """
        sha = _line_sha(line)
        base = {"line_sha": sha, "status": None, "reason": None, "project_id": None}

        try:
            obj = json.loads(line)
        except ValueError:
            return {**base, "decision": "quarantine", "reason": "invalid_json"}
        if not isinstance(obj, dict):
            return {**base, "decision": "quarantine", "reason": "not_a_json_object"}
        for field in REQUIRED_FIELDS:
            if obj.get(field) in (None, ""):
                return {**base, "decision": "quarantine", "reason": f"missing_field:{field}"}

        raw_status = str(obj["status"]).strip().upper()
        normalized = STATUS_ALIASES.get(raw_status)
        if normalized is None:
            # M2：未知状态绝不猜映射
            return {**base, "decision": "quarantine", "reason": f"unknown_status:{raw_status}"}

        # M5（MIG-05）：project 身份字段一致性——冲突即显式隔离
        projects = extract_project_ids(obj)
        values = sorted(set(projects.values()))
        if len(values) > 1:
            # 按字段优先级取前两个不一致字段作冲突证据（值截断防长文本）
            it = iter(projects.items())
            fA, vA = next(it)
            fB, vB = next(
                (f, v) for f, v in it if v != projects[fA])
            reason = (f"{PROJECT_KEY_CONFLICT_PREFIX}"
                      f"{fA}={vA[:40]}!={fB}={vB[:40]}")
            return {**base, "decision": "quarantine", "reason": reason}
        project_id = values[0] if values else None
        return {**base, "decision": "import", "status": normalized,
                "project_id": project_id}

    # ------------------------------------------------------------------ #
    # 迁移：经 EventStore.append 写入统一事件表 + 数量守恒校验
    # ------------------------------------------------------------------ #
    def migrate(self) -> Dict[str, Any]:
        """执行迁移并做数量守恒校验（M4）。

        每行去向恰为三者之一：imported / duplicate / quarantined；
        导入行经公共 ``EventStore.append`` 写入 ``pipeline_events``（单一
        事件表+单一写入 API）；``inserted=False`` 即内容寻址 duplicate
        （等价于旧版 line_sha 唯一冲突）。汇总不守恒 -> 抛
        ConservationError（migration_runs 表同时记账 conserved=0）。
        """
        if not self._inventory:
            self.scan()

        tally = {
            "files_scanned": len({e["file"] for e in self._inventory}),
            "lines_total": len(self._inventory),
            "imported": 0,
            "duplicates": 0,
            "quarantined": 0,
        }
        quarantine_reasons: Dict[str, int] = {}
        status_counts: Dict[str, int] = {}
        per_file: Dict[str, Dict[str, Any]] = {}

        db_dir = os.path.dirname(self.sqlite_path) or "."
        os.makedirs(db_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.sidecar_path) or ".", exist_ok=True)

        # 单一写入 API：EventStore 负责建表（pipeline_events）、BEGIN
        # IMMEDIATE 事务与哈希链维护；本类不再持有任何第二事件表 DDL。
        store = EventStore(self.sqlite_path)
        try:
            # M1：sidecar 只追加（"a"），源 JSONL 全程只读；
            # sidecar 打不开则整体失败（此时零行导入——先开审计再入账）
            with open(self.sidecar_path, "a", encoding="utf-8") as sidecar:

                def audit(entry: Dict[str, Any], decision: str, **extra: Any) -> None:
                    record = {
                        "decision": decision,
                        "file": entry["file"],
                        "line_no": entry["line_no"],
                        "line_sha": entry["line_sha"],
                    }
                    record.update(extra)
                    sidecar.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

                for entry in self._inventory:
                    verdict = self.classify(entry["raw"])
                    stats = per_file.setdefault(entry["file"], {
                        "lines": 0, "imported": 0, "duplicates": 0, "quarantined": 0})
                    stats["lines"] += 1

                    if verdict["decision"] == "quarantine":
                        tally["quarantined"] += 1
                        stats["quarantined"] += 1
                        key = verdict["reason"]
                        quarantine_reasons[key] = quarantine_reasons.get(key, 0) + 1
                        audit(entry, "quarantined", reason=key, preview=entry["raw"][:200])
                        continue

                    # 单一写入 API：与管线控制事件/外部事件同表同链；
                    # inserted=False = 内容寻址 duplicate（本次或既往已入账）；
                    # project_id（若有）随行内容贯通进负载（MIG-05 最小实现）
                    event = migration_event(verdict["line_sha"], verdict["status"],
                                            entry["raw"],
                                            project_id=verdict.get("project_id"))
                    _event_hash, inserted = store.append(event)
                    if not inserted:
                        tally["duplicates"] += 1
                        stats["duplicates"] += 1
                        audit(entry, "duplicate")
                        continue

                    tally["imported"] += 1
                    stats["imported"] += 1
                    status = verdict["status"]
                    status_counts[status] = status_counts.get(status, 0) + 1
                    audit(entry, "imported", status=status)

            # 产物链自检：迁移行与库中既有事件（管线控制事件/外部事件）
            # 必须是同一条可验证哈希链——这是「唯一正源」的运行时证明
            store.verify_chain()

            conserved = (
                tally["lines_total"]
                == tally["imported"] + tally["duplicates"] + tally["quarantined"]
            )
            # run 级记账（bookkeeping 表；非事件正源，不参与哈希链）
            conn = sqlite3.connect(self.sqlite_path)
            try:
                conn.execute("PRAGMA busy_timeout=10000;")
                conn.executescript(_RUNS_SCHEMA)
                conn.execute(
                    "INSERT INTO migration_runs (files_scanned, lines_total, imported, duplicates,"
                    " quarantined, conserved) VALUES (?, ?, ?, ?, ?, ?)",
                    (tally["files_scanned"], tally["lines_total"], tally["imported"],
                     tally["duplicates"], tally["quarantined"], int(conserved)),
                )
                conn.commit()
            finally:
                conn.close()
        finally:
            store.close()

        if not conserved:
            raise ConservationError(
                f"conservation violated: lines_total={tally['lines_total']} != "
                f"imported({tally['imported']}) + duplicates({tally['duplicates']}) + "
                f"quarantined({tally['quarantined']})"
            )

        self._last_report = self._build_report(tally, quarantine_reasons, status_counts,
                                               per_file, conserved)
        return self._last_report

    # ------------------------------------------------------------------ #
    # 报告
    # ------------------------------------------------------------------ #
    def report(self) -> Dict[str, Any]:
        """返回最近一次迁移的守恒报告；尚未迁移时显式报错（不编造空账）。"""
        if self._last_report is None:
            raise RuntimeError("no migration report yet: run migrate() first")
        return self._last_report

    def _build_report(self, tally: Dict[str, int], quarantine_reasons: Dict[str, int],
                      status_counts: Dict[str, int], per_file: Dict[str, Dict[str, Any]],
                      conserved: bool) -> Dict[str, Any]:
        return {
            "source_dir": self.source_dir,
            "sqlite_path": self.sqlite_path,
            "sidecar_path": self.sidecar_path,
            # P0-6 第六轮：统一事件正源的显式锚点
            "event_table": "pipeline_events",
            "write_api": "EventStore.append",
            "conserved": conserved,
            "conservation": {
                "equation": "lines_total == imported + duplicates + quarantined",
                "lines_total": tally["lines_total"],
                "imported": tally["imported"],
                "duplicates": tally["duplicates"],
                "quarantined": tally["quarantined"],
            },
            "files_scanned": tally["files_scanned"],
            "quarantine_reasons": dict(sorted(quarantine_reasons.items())),
            # MIG-05：project key 冲突单独聚合（仍是 quarantine 的子集，
            # 不改变守恒等式；对账工具据此出显式冲突清单）
            "project_key_conflicts": {
                k: v for k, v in sorted(quarantine_reasons.items())
                if k.startswith(PROJECT_KEY_CONFLICT_PREFIX)},
            "imported_status_counts": dict(sorted(status_counts.items())),
            "per_file": [
                {"file": f, **stats} for f, stats in sorted(per_file.items())
            ],
        }


# ---------------------------------------------------------------------- #
# 旧 events 表残留：一次性收编（P0-6 第六轮）
# ---------------------------------------------------------------------- #
def migrate_legacy_events(sqlite_path: str,
                          sidecar_path: Optional[str] = None) -> Dict[str, Any]:
    """把旧版迁移器 ``events`` 表的历史残留行一次性收编进 pipeline_events。

    契约：
    - 只读旧表：本函数绝不 CREATE/INSERT/UPDATE/DELETE 旧 ``events`` 表
      （保留只读兼容；收编后旧表原样留在库中，仅供对账，不再是正源）；
    - 单一写入 API：每行经 ``EventStore.append`` 以
      ``LEGACY_EVENTS_ROW_MIGRATED`` 事件入 ``pipeline_events`` 哈希链；
      事件负载是旧行已记内容（line_sha/status/payload）的纯函数——重跑
      全部计 duplicate，零重复入账（一次性、幂等）；
    - 旧行按已入账历史记录原样收编（status 等字段原封不动）：旧表行是
      旧制度下已落账的数据，收编时重新判定/归一会改写历史账目，故只做
      搬运、绝不再判；JSONL 源行的 quarantine 语义在 :meth:`LedgerMigrator.migrate`；
    - 守恒：rows_seen == imported + duplicates，否则 ConservationError；
    - 逐行 sidecar 审计（append-only），携带旧表 id/source_file/source_line
      位置溯源。

    旧表不存在（新库/已收编库）不是错误：报告 ``legacy_table_present=False``。
    """
    sqlite_path = os.path.abspath(sqlite_path)
    sidecar_path = (os.path.abspath(sidecar_path) if sidecar_path
                    else sqlite_path + ".legacy-events-sidecar.jsonl")
    os.makedirs(os.path.dirname(sidecar_path) or ".", exist_ok=True)

    store = EventStore(sqlite_path)
    try:
        # 表名是模块常量（不可信输入不进 SQL 文本）；存在性用参数化查询
        present = store._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (LEGACY_EVENTS_TABLE,),
        ).fetchone() is not None

        legacy_rows: List[Dict[str, Any]] = []
        if present:
            cols = {r[1] for r in store._conn.execute(
                f"PRAGMA table_info({LEGACY_EVENTS_TABLE})")}
            missing = _LEGACY_REQUIRED_COLUMNS - cols
            if missing:
                # 形状异常 fail-closed：同名表不是旧迁移器产物，绝不猜搬
                raise RuntimeError(
                    f"legacy table {LEGACY_EVENTS_TABLE!r} has unexpected shape; "
                    f"missing columns: {sorted(missing)}; refusing to migrate")
            # 只读 SELECT——旧表全程零写入
            for rid, line_sha, status, source_file, source_line, payload in store._conn.execute(
                f"SELECT id, line_sha, status, source_file, source_line, payload "
                f"FROM {LEGACY_EVENTS_TABLE} ORDER BY id"
            ):
                legacy_rows.append({
                    "id": rid, "line_sha": line_sha, "status": status,
                    "source_file": source_file, "source_line": source_line,
                    "payload": payload,
                })

        imported = duplicates = 0
        with open(sidecar_path, "a", encoding="utf-8") as sidecar:
            for row in legacy_rows:
                event = {
                    "event_type": LEGACY_RESIDUE_EVENT_TYPE,
                    "line_sha": row["line_sha"],
                    "status": row["status"],
                    "raw": row["payload"],
                }
                _event_hash, inserted = store.append(event)
                if inserted:
                    imported += 1
                    decision = "imported"
                else:
                    duplicates += 1
                    decision = "duplicate"
                sidecar.write(json.dumps({
                    "decision": decision,
                    "legacy_table": LEGACY_EVENTS_TABLE,
                    "legacy_id": row["id"],
                    "line_sha": row["line_sha"],
                    "source_file": row["source_file"],
                    "source_line": row["source_line"],
                }, ensure_ascii=False, sort_keys=True) + "\n")

        store.verify_chain()
        if len(legacy_rows) != imported + duplicates:
            raise ConservationError(
                f"legacy residue conservation violated: rows_seen={len(legacy_rows)} != "
                f"imported({imported}) + duplicates({duplicates})")

        return {
            "sqlite_path": sqlite_path,
            "legacy_table": LEGACY_EVENTS_TABLE,
            "legacy_table_present": present,
            "rows_seen": len(legacy_rows),
            "imported": imported,
            "duplicates": duplicates,
            "event_table": "pipeline_events",
            "write_api": "EventStore.append",
            "sidecar_path": sidecar_path,
            "chain_verified": True,
        }
    finally:
        store.close()

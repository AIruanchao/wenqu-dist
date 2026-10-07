# -*- coding: utf-8 -*-
"""旧 JSONL 账本 -> SQLite EventStore 迁移器（Codex W5）。

约束（不可降级）：
    M1 append-only sidecar：迁移审计只追加写入 sidecar JSONL；绝不重写、
       绝不触碰源 JSONL 内容（源文件只读打开）；
    M2 未知状态 / 缺字段 -> quarantine 隔离，绝不猜填字段、绝不猜归一化；
    M3 状态归一化仅限已知别名表；FIXED 一律记为 FIXED_PENDING_VERIFY
       （未经独立验证不承认修复完成）；
    M4 数量守恒：源非空行数 == 有效导入 + 重复 + quarantine；不守恒即抛
       ConservationError，绝不静默少账。

每行账本契约：JSON 对象，至少含 ``status`` 与 ``ts`` 两个字段；``status``
归一化后必须落在已知状态集合内。空行不计入守恒分母。

重复判定：按行内容 SHA256（去行尾换行）判重；跨运行重跑时，已入库行
（line_sha 唯一约束）同样计为 duplicate，保证重跑幂等且账目守恒。
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

__all__ = ["LedgerMigrator", "ConservationError", "STATUS_ALIASES", "KNOWN_STATUSES"]

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

_SCHEMA = """
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


class ConservationError(RuntimeError):
    """数量守恒被破坏：源非空行数 != 有效导入 + 重复 + quarantine。"""


def _line_sha(line: str) -> str:
    """行内容 SHA256（剥离行尾换行，保证跨平台一致）。"""
    return hashlib.sha256(line.rstrip("\r\n").encode("utf-8")).hexdigest()


class LedgerMigrator:
    """旧 JSONL 账本 -> SQLite EventStore 迁移器。

    用法::

        mig = LedgerMigrator(source_dir=".../ledgers", sqlite_path=".../events.db")
        mig.scan()          # 可选：显式建立逐文件逐行 SHA 清单
        report = mig.migrate()
        assert report["conserved"] is True
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
        "line_sha": ...}``；import 时 status 为归一化后的已知状态。
        """
        sha = _line_sha(line)
        base = {"line_sha": sha, "status": None, "reason": None}

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
        return {**base, "decision": "import", "status": normalized}

    # ------------------------------------------------------------------ #
    # 迁移：导入 + 数量守恒校验
    # ------------------------------------------------------------------ #
    def migrate(self) -> Dict[str, Any]:
        """执行迁移并做数量守恒校验（M4）。

        每行去向恰为三者之一：imported / duplicate / quarantined；
        汇总不守恒 -> 抛 ConservationError（migration_runs 表同时记账 conserved=0）。
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

        conn = sqlite3.connect(self.sqlite_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.executescript(_SCHEMA)
            # M1：sidecar 只追加（"a"），源 JSONL 全程只读
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

                    try:
                        conn.execute(
                            "INSERT INTO events (line_sha, status, source_file, source_line, payload)"
                            " VALUES (?, ?, ?, ?, ?)",
                            (verdict["line_sha"], verdict["status"], entry["file"],
                             entry["line_no"], entry["raw"]),
                        )
                    except sqlite3.IntegrityError:
                        # line_sha 唯一冲突 = 重复行（本次运行或既往运行已导入）
                        tally["duplicates"] += 1
                        stats["duplicates"] += 1
                        audit(entry, "duplicate")
                        continue

                    tally["imported"] += 1
                    stats["imported"] += 1
                    status = verdict["status"]
                    status_counts[status] = status_counts.get(status, 0) + 1
                    audit(entry, "imported", status=status)

            conserved = (
                tally["lines_total"]
                == tally["imported"] + tally["duplicates"] + tally["quarantined"]
            )
            conn.execute(
                "INSERT INTO migration_runs (files_scanned, lines_total, imported, duplicates,"
                " quarantined, conserved) VALUES (?, ?, ?, ?, ?, ?)",
                (tally["files_scanned"], tally["lines_total"], tally["imported"],
                 tally["duplicates"], tally["quarantined"], int(conserved)),
            )
            conn.commit()
        finally:
            conn.close()

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
            "imported_status_counts": dict(sorted(status_counts.items())),
            "per_file": [
                {"file": f, **stats} for f, stats in sorted(per_file.items())
            ],
        }

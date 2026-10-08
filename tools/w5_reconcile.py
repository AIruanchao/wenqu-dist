#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w5_reconcile.py —— W5 旧账 reconciliation（方案 §14 / §20.2 MIG-01~05 证据面）。

流程（正源契约，P0-6 第六轮「直连 EventStore API 统一正源」）：
    legacy *.jsonl（只读）
      → 逐行规范化（本工具；确定性规则，绝不猜填）
      → staging JSONL（workdir 下派生产物；源文件零写入）
      → LedgerMigrator.migrate()（导入行经公共 EventStore.append 写入
        pipeline_events 哈希链——单一事件表+单一写入 API）
      → 逐行对账报告 {row_id, 状态, reason, event_id}
      → 四态汇总（mapped / quarantined / 待人工 / 不一致）
        + ACCEPTED 裁定单独清单（MIG-02：ACCEPTED 是未知状态，一律不自动
          导入、不猜映射为 PASS；quarantine+sidecar 留痕即待人工 reopen 通道）

规范化规则（确定性，可审计）：
    ts    别名链（按序取第一个非空字符串）：ts / ts_utc / utc / timestamp / time
          （方案 §14.2 步骤 3 alias 族的最小实现，含本源实测的 utc/ts_utc）
    status 候选链（按序取第一个命中已知别名表的字段）：
          status / verdict / state / result
          - 命中 wenqu_core.ledger_migrator.STATUS_ALIASES（冻结正源）→ 映射；
            本工具绝不自造别名（ALL-GREEN/MERGED/DONE/PARTIAL/master=… 长文本
            等不在冻结表内的值一律不猜，quarantine 记因）
          - 候选值含 "ACCEPTED"（如 ACCEPTED-CLOSED）→ 按原值入 staging，由
            迁移器按 MIG-02 语义 quarantine（unknown_status:ACCEPTED*），本工具
            归类「待人工」并出 ACCEPTED 裁定清单
    坏 JSON / 非对象 / 无可映射 status / 缺 ts（全别名链空）→ quarantine（记因）

row_id = legacy_event_id = sha256(source_file 绝对路径 \\n line_no \\n 去换行原始行)
    （方案 §14.2 步骤 2 的逐行身份；位置溯源只进本报告与 sidecar 审计，
     不进事件负载——保持 event_id 内容寻址幂等）

两次运行幂等（MIG-03/§14.4）：单次调用内对同一库连续跑两遍迁移：
    run1 快照 == run2 快照（逐字节行集 + 链头 + 逻辑快照 SHA），run2 零新导入、
    全计 duplicate；同一 workdir 重复调用本工具亦幂等（append-only 语义，
    db_logical_snapshot_sha 跨调用可比对）。

源文件只读铁律（M1/§14.1）：源目录全程零写入；每次运行前后对每个 *.jsonl
做 SHA256 逐字节比对，变化即 fail-closed（exit 1，绝不带病收尾）。

不写生产库：sqlite 产物只落 workdir（演练=/tmp，正式=evidence/
07-migration-reconcile/migrated-events.db），与任何运行态库无关。

用法：
    演练：python3 tools/w5_reconcile.py --workdir /tmp/w5-drill
    正式：python3 tools/w5_reconcile.py --formal
          （产物：reconcile-report.json + summary.md + migrated-events.db
            [+ .migration-sidecar.jsonl 审计]）

退出码：0 = 守恒 + 幂等 + 链验证 + 源字节不变全部通过 且 不一致=0 且无孤儿事件；
        1 = 任一失败。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "system"))

from wenqu_core.ledger_migrator import (            # noqa: E402
    LedgerMigrator, STATUS_ALIASES, MIGRATION_EVENT_TYPE,
    PROJECT_KEY_CONFLICT_PREFIX, KNOWN_STATUSES)
from wenqu_core.store import EventStore             # noqa: E402

DEFAULT_SOURCE_DIR = "/Users/maccc/Documents/ERP）Zcode/持续修复引擎"
FORMAL_EVIDENCE_DIR = os.path.join(REPO_ROOT, "evidence", "07-migration-reconcile")

#: ts 别名链（§14.2 步骤 3「ts/timestamp/time」+ 本源实测的 ts_utc/utc）
TS_ALIAS_FIELDS = ("ts", "ts_utc", "utc", "timestamp", "time")
#: status 候选链（本源四类承载字段的确定性优先级）
STATUS_CANDIDATE_FIELDS = ("status", "verdict", "state", "result")
ACCEPTED_MARKER = "ACCEPTED"

ST_STAGED_MAP = "_staged_map"          # 内部暂态：已入 staging、待迁移器裁定
ST_STAGED_ACCEPTED = "_staged_accepted"  # 内部暂态：ACCEPTED 味、已入 staging
STATE_MAPPED = "mapped"
STATE_QUARANTINED = "quarantined"
STATE_MANUAL = "待人工(ACCEPTED裁定)"
STATE_INCONSISTENT = "不一致"

#: 口径登记（§14.2 步骤 7：481 仅是旧 dashboard 启发式折叠数，不能充当原始
#: 迁移分母；43 ACCEPTED 属 quality-system findings 口径，与本源不同源）
EXPECTED_CALIBER = {
    "expected_rows": "~481",
    "expected_accepted": 43,
    "caliber_breakdown_from_plan_14_3": (
        "24 OPEN + 4 FIXING + 172 FIXED + 67 VERIFIED + 158 CLOSED "
        "+ 43 ACCEPTED + 13 OTHER = 481（quality-system findings ledger 口径）"),
    "note": (
        "本工具正源是 持续修复引擎/engine-rounds.jsonl（引擎轮次工作日志），"
        "与方案 §14.3 的 481-finding 口径不同源；实际行数与 ACCEPTED 计数以"
        "逐行实扫为准，差异如实记录，不强行对齐、不用 481 充当分母。"),
}


# ---------------------------------------------------------------------- #
# 基础工具
# ---------------------------------------------------------------------- #
def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def legacy_event_id(source_file: str, line_no: int, raw: str) -> str:
    """方案 §14.2 步骤 2：sha256(source_file, line_no, raw_line)。"""
    return hashlib.sha256(
        "\n".join([source_file, str(line_no), raw]).encode("utf-8")).hexdigest()


def _git_head() -> Optional[str]:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:                                       # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------------- #
# 逐行规范化（确定性；绝不猜填）
# ---------------------------------------------------------------------- #
def normalize_row(obj: Dict[str, Any]) -> Dict[str, Any]:
    """判定单行旧账的可迁移性。

    返回 {"staged": bool, "reason": None|str, "mapped_from": None|字段名,
          "status_value": 原始候选值, "ts_value": str, "ts_from": 字段名,
          "accepted_flavor": bool}
    - staged=True 且 accepted_flavor=False：已知别名命中 → 迁移器导入；
    - staged=True 且 accepted_flavor=True：ACCEPTED 味 → 按原值入 staging，
      迁移器按 MIG-02 quarantine（unknown_status:ACCEPTED*）→ 待人工；
    - staged=False：reason 为工具级 quarantine 原因。
    """
    out: Dict[str, Any] = {
        "staged": False, "reason": None, "mapped_from": None,
        "status_value": None, "ts_value": None, "ts_from": None,
        "accepted_flavor": False}

    ts_value: Optional[str] = None
    for field in TS_ALIAS_FIELDS:
        v = obj.get(field)
        if isinstance(v, str) and v.strip():
            ts_value, out["ts_from"] = v.strip(), field
            break
    if ts_value is None:
        out["reason"] = "missing_field:ts"
        return out
    out["ts_value"] = ts_value

    accepted_field, accepted_value = None, None
    for field in STATUS_CANDIDATE_FIELDS:
        v = obj.get(field)
        if not isinstance(v, str) or not v.strip():
            continue
        if v.strip().upper() in STATUS_ALIASES:
            out.update(staged=True, mapped_from=field, status_value=v.strip())
            return out
        if ACCEPTED_MARKER in v.strip().upper() and accepted_field is None:
            accepted_field, accepted_value = field, v.strip()
    if accepted_field is not None:
        out.update(staged=True, mapped_from=accepted_field,
                   status_value=accepted_value, accepted_flavor=True)
        return out

    tried = [f for f in STATUS_CANDIDATE_FIELDS if obj.get(f) is not None]
    out["reason"] = "no_mappable_status(candidates=%s)" % (
        ",".join(tried) if tried else "none")
    return out


def build_staging_object(obj: Dict[str, Any], norm: Dict[str, Any]) -> Dict[str, Any]:
    """staging 行 = 原对象全量字段 + 规范化补写的 status/ts 两个键。

    保留原字段（含 project 候选字段 project_id/project/repo_id/repo/task——
    MIG-05 的 project_id 贯通/冲突隔离因此在真实数据上同样生效）；不删不改
    原键。序列化固定 sort_keys，保证 event_id 内容寻址幂等。
    """
    staged = dict(obj)
    staged["status"] = norm["status_value"]
    staged["ts"] = norm["ts_value"]
    return staged


# ---------------------------------------------------------------------- #
# 源扫描（只读）
# ---------------------------------------------------------------------- #
def scan_source(source_dir: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """*.jsonl 逐行清单 + 文件元数据 + 跳过文件登记。"""
    if not os.path.isdir(source_dir):
        raise FileNotFoundError(f"source_dir not found: {source_dir}")
    rows: List[Dict[str, Any]] = []
    files_meta: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for name in sorted(os.listdir(source_dir)):
        path = os.path.join(source_dir, name)
        if not os.path.isfile(path):
            skipped.append({"file": path, "reason": "not a regular file"})
            continue
        if not name.endswith(".jsonl"):
            skipped.append({"file": path, "reason": "suffix not .jsonl (frozen scan rule)"})
            continue
        with open(path, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-8", errors="replace")
        nonblank = 0
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            nonblank += 1
            raw = line.rstrip("\r\n")
            row = {
                "file": path, "file_name": name, "line_no": line_no,
                "raw": raw, "row_id": legacy_event_id(path, line_no, raw),
                "obj": None, "parse_error": None,
            }
            try:
                parsed = json.loads(raw)
                if not isinstance(parsed, dict):
                    row["parse_error"] = "not_a_json_object"
                else:
                    row["obj"] = parsed
            except ValueError as e:
                row["parse_error"] = f"invalid_json:{type(e).__name__}"
            rows.append(row)
        files_meta.append({
            "file": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "nonblank_lines": nonblank,
            "blank_lines": len(text.splitlines()) - nonblank,
        })
    return rows, files_meta, skipped


# ---------------------------------------------------------------------- #
# 库读取
# ---------------------------------------------------------------------- #
def db_snapshot(db_path: str) -> Tuple[List[Tuple], str]:
    """统一事件表全行快照 + 逻辑快照 SHA（幂等跨调用可比）。"""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT seq, event_id, payload, prev_event_hash, event_hash "
            "FROM pipeline_events ORDER BY seq ASC").fetchall()
    finally:
        conn.close()
    canon = json.dumps([list(r) for r in rows],
                       ensure_ascii=False, separators=(",", ":"))
    return rows, hashlib.sha256(canon.encode("utf-8")).hexdigest()


def read_store_index(db_path: str) -> Dict[str, Dict[str, Any]]:
    """LEDGER_MIGRATED 事件按 line_sha 索引：{line_sha: {event_id, status, raw}}。"""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        pairs = conn.execute(
            "SELECT event_id, payload FROM pipeline_events").fetchall()
    finally:
        conn.close()
    index: Dict[str, Dict[str, Any]] = {}
    for event_id, payload in pairs:
        obj = json.loads(payload)
        if obj.get("event_type") == MIGRATION_EVENT_TYPE:
            index[obj["line_sha"]] = {
                "event_id": event_id, "status": obj.get("status"),
                "raw": obj.get("raw"),
                "project_id": obj.get("project_id"),
            }
    return index


def sidecar_records(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


# ---------------------------------------------------------------------- #
# 主流程
# ---------------------------------------------------------------------- #
def run_reconcile(source_dir: str, workdir: str, formal: bool) -> Tuple[Dict[str, Any], int]:
    started = datetime.now(timezone.utc).isoformat()
    os.makedirs(workdir, exist_ok=True)
    staging_dir = os.path.join(workdir, "staging-normalized")
    db_path = os.path.join(workdir, "migrated-events.db")
    sidecar_path = db_path + ".migration-sidecar.jsonl"
    prior_db_existed = os.path.exists(db_path)

    # ---- 1. 源扫描（只读）+ 字节指纹（前） -----------------------------
    rows, files_meta, skipped = scan_source(source_dir)
    sha_before = {m["file"]: m["sha256"] for m in files_meta}
    total_nonblank = len(rows)

    # ---- 2. 逐行规范化 + staging 写出 ----------------------------------
    os.makedirs(staging_dir, exist_ok=True)
    report_rows: List[Dict[str, Any]] = []
    accepted_list: List[Dict[str, Any]] = []
    quarantine_reasons: Dict[str, int] = {}
    staged_line_shas: set = set()

    staging_handles: Dict[str, Any] = {}
    staging_counters: Dict[str, int] = {}
    try:
        for row in rows:
            entry: Dict[str, Any] = {
                "row_id": row["row_id"], "source_file": row["file"],
                "line_no": row["line_no"], "state": None, "reason": None,
                "event_id": None, "mapped_from": None,
                "status_normalized": None, "duplicate_in_run": False,
                "preview": row["raw"][:200],
                "_raw": row["raw"],
            }
            report_rows.append(entry)

            if row["parse_error"]:
                reason = row["parse_error"]
                entry.update(state=STATE_QUARANTINED, reason=reason)
                quarantine_reasons[reason] = quarantine_reasons.get(reason, 0) + 1
                continue

            norm = normalize_row(row["obj"])
            entry["mapped_from"] = norm["mapped_from"]
            if not norm["staged"]:
                key = norm["reason"].split("(")[0]
                entry.update(state=STATE_QUARANTINED, reason=norm["reason"])
                quarantine_reasons[key] = quarantine_reasons.get(key, 0) + 1
                continue

            staged_obj = build_staging_object(row["obj"], norm)
            line = json.dumps(staged_obj, sort_keys=True, ensure_ascii=False)
            if row["file_name"] not in staging_handles:
                staging_handles[row["file_name"]] = open(
                    os.path.join(staging_dir, row["file_name"]),
                    "w", encoding="utf-8", newline="\n")
                staging_counters[row["file_name"]] = 0
            staging_handles[row["file_name"]].write(line + "\n")
            staging_counters[row["file_name"]] += 1

            entry["_staging_file"] = row["file_name"]
            entry["_staging_line_no"] = staging_counters[row["file_name"]]
            entry["_staging_line"] = line
            entry["_expected_status"] = STATUS_ALIASES.get(
                str(staged_obj["status"]).strip().upper())
            staged_line_shas.add(hashlib.sha256(line.encode("utf-8")).hexdigest())

            if norm["accepted_flavor"]:
                entry["state"] = ST_STAGED_ACCEPTED
                accepted_list.append({
                    "row_id": row["row_id"], "source_file": row["file"],
                    "line_no": row["line_no"], "field": norm["mapped_from"],
                    "raw_value": norm["status_value"],
                    "project_context": {
                        f: row["obj"][f]
                        for f in ("project_id", "project", "repo_id", "repo", "task")
                        if isinstance(row["obj"].get(f), (str, int, float))
                        and not isinstance(row["obj"].get(f), bool)},
                    "preview": row["raw"][:300],
                    "disposition": (
                        "迁移器 quarantine（unknown_status:ACCEPTED*，MIG-02 不猜映射）；"
                        "人工裁定补齐审批要素后另行再录（reopen 通道）"),
                })
            else:
                entry["state"] = ST_STAGED_MAP
    finally:
        for fh in staging_handles.values():
            fh.close()

    # ---- 3. 两次迁移（同一库；幂等证明） -------------------------------
    sidecar_pre = len(sidecar_records(sidecar_path))
    run1_report = LedgerMigrator(staging_dir, db_path).migrate()
    snap1, snap1_sha = db_snapshot(db_path)
    run1_sidecar = sidecar_records(sidecar_path)[sidecar_pre:]

    run2_report = LedgerMigrator(staging_dir, db_path).migrate()
    snap2, snap2_sha = db_snapshot(db_path)
    # run2 的 sidecar 记录 = run1 之后的增量（同键以 run2 为终态；逐行裁定读 run1）
    sidecar_after_run2 = sidecar_records(sidecar_path)
    run2_sidecar = sidecar_after_run2[sidecar_pre + len(run1_sidecar):]

    def pos_map(records: List[Dict[str, Any]]) -> Dict[Tuple[str, int], Dict[str, Any]]:
        return {(os.path.basename(r["file"]), r["line_no"]): r for r in records}

    sidecar_run1_by_pos = pos_map(run1_sidecar)
    sidecar_run2_by_pos = pos_map(run2_sidecar)

    # ---- 4. 逐行对账 ----------------------------------------------------
    store_index = read_store_index(db_path)
    event_raws = {ev["raw"] for ev in store_index.values()}
    counts = {STATE_MAPPED: 0, STATE_QUARANTINED: 0, STATE_MANUAL: 0,
              STATE_INCONSISTENT: 0}

    for entry in report_rows:
        state = entry["state"]
        if state in (ST_STAGED_MAP, ST_STAGED_ACCEPTED):
            pos = (entry["_staging_file"], entry["_staging_line_no"])
            rec1 = sidecar_run1_by_pos.get(pos)
            rec2 = sidecar_run2_by_pos.get(pos)
            line_sha = hashlib.sha256(
                entry["_staging_line"].encode("utf-8")).hexdigest()
            ev = store_index.get(line_sha)

            if state == ST_STAGED_ACCEPTED:
                # MIG-02：ACCEPTED 必须被迁移器 quarantine（unknown_status:ACCEPTED*）
                r = (rec1 or {}).get("reason", "")
                if (rec1 or {}).get("decision") != "quarantined" or \
                        not str(r).startswith("unknown_status:"):
                    entry.update(
                        state=STATE_INCONSISTENT,
                        reason=f"ACCEPTED 行未按 MIG-02 quarantine（run1 sidecar={rec1}）")
                    counts[STATE_INCONSISTENT] += 1
                    continue
                if ev is not None:
                    entry.update(state=STATE_INCONSISTENT,
                                 reason="ACCEPTED 行出现在事件库（不允许）")
                    counts[STATE_INCONSISTENT] += 1
                    continue
                entry.update(state=STATE_MANUAL,
                             reason=f"迁移器判定 {r}（MIG-02：不猜映射，待人工 reopen）")
                counts[STATE_MANUAL] += 1
                continue

            if rec1 is None:
                entry.update(state=STATE_INCONSISTENT,
                             reason="staged 行在 run1 sidecar 无审计记录")
                counts[STATE_INCONSISTENT] += 1
                continue
            if rec1["decision"] == "quarantined":
                reason = str(rec1.get("reason", "quarantined"))
                entry.update(state=STATE_QUARANTINED, reason=reason)
                key = (reason.split(":")[0]
                       if reason.startswith(PROJECT_KEY_CONFLICT_PREFIX) else reason)
                quarantine_reasons[key] = quarantine_reasons.get(key, 0) + 1
                if ev is not None:
                    entry.update(state=STATE_INCONSISTENT,
                                 reason="quarantine 行出现在事件库（隔离泄漏）")
                    counts[STATE_QUARANTINED] -= 1
                    counts[STATE_INCONSISTENT] += 1
                else:
                    counts[STATE_QUARANTINED] += 1
                continue
            if rec1["decision"] in ("imported", "duplicate"):
                problems = []
                if ev is None:
                    problems.append("库内无对应 LEDGER_MIGRATED 事件")
                else:
                    if ev["status"] != entry["_expected_status"]:
                        problems.append(
                            f"库内状态 {ev['status']} != 期望 {entry['_expected_status']}")
                    entry["event_id"] = ev["event_id"]
                rec2 = rec2 or {}
                if rec2.get("decision") != "duplicate":
                    problems.append(f"run2 未计 duplicate（{rec2.get('decision')}）——幂等破坏")
                if problems:
                    entry.update(state=STATE_INCONSISTENT,
                                 reason="；".join(problems))
                    counts[STATE_INCONSISTENT] += 1
                    continue
                entry.update(state=STATE_MAPPED,
                             status_normalized=entry["_expected_status"],
                             duplicate_in_run=rec1["decision"] == "duplicate")
                counts[STATE_MAPPED] += 1
                continue
            entry.update(state=STATE_INCONSISTENT,
                         reason=f"未知 sidecar 决策 {rec1.get('decision')}")
            counts[STATE_INCONSISTENT] += 1
            continue

        # 工具级 quarantine 行：绝不在库（原文不得等于任何事件 raw=staging 行）
        if state == STATE_QUARANTINED:
            if entry["_raw"] in event_raws:
                entry.update(state=STATE_INCONSISTENT,
                             reason="工具级 quarantine 原文出现在事件库（隔离泄漏）")
                counts[STATE_QUARANTINED] -= 1
                counts[STATE_INCONSISTENT] += 1
            else:
                counts[STATE_QUARANTINED] += 1
            continue
        counts[state] = counts.get(state, 0) + 1

    mapped_n = counts[STATE_MAPPED]
    quarantined_n = counts[STATE_QUARANTINED]
    manual_n = counts[STATE_MANUAL]
    inconsistent_n = counts[STATE_INCONSISTENT]

    # 工具级守恒（§14.4：数量守恒 100%、零静默丢行）
    conserved = total_nonblank == mapped_n + quarantined_n + manual_n + inconsistent_n

    # 孤儿事件：库内 LEDGER_MIGRATED 事件必须全部来自本次 staging
    orphan_events = [sha for sha in store_index if sha not in staged_line_shas]

    # ---- 5. 幂等/链/源字节不变验证 -------------------------------------
    store = EventStore(db_path)
    try:
        head, total_events = store.head()
        chain = store.verify_chain()
        chain_ok = bool(chain.get("ok"))
    finally:
        store.close()

    idempotent = {
        "run1_imported": run1_report["conservation"]["imported"],
        "run1_duplicates": run1_report["conservation"]["duplicates"],
        "run1_quarantined": run1_report["conservation"]["quarantined"],
        "run2_imported": run2_report["conservation"]["imported"],
        "run2_duplicates": run2_report["conservation"]["duplicates"],
        "run2_quarantined": run2_report["conservation"]["quarantined"],
        "rowset_identical": snap1 == snap2,
        "snapshot_sha_identical": snap1_sha == snap2_sha,
        "run2_imported_zero": run2_report["conservation"]["imported"] == 0,
        "prior_db_existed": prior_db_existed,
    }
    idempotent_ok = (idempotent["rowset_identical"]
                     and idempotent["snapshot_sha_identical"]
                     and idempotent["run2_imported_zero"])

    sha_after = {m["file"]: file_sha256(m["file"]) for m in files_meta}
    source_unchanged = all(sha_before[f] == sha_after[f] for f in sha_before)

    all_ok = (conserved and idempotent_ok and chain_ok and source_unchanged
              and inconsistent_n == 0 and not orphan_events)

    # ---- 6. 报告 --------------------------------------------------------
    def clean_rows() -> List[Dict[str, Any]]:
        return [{k: v for k, v in r.items() if not k.startswith("_")}
                for r in report_rows]

    report = {
        "artifact": "w5-migration-reconcile",
        "description": (
            "W5 旧账 reconciliation：legacy jsonl 逐行规范化→LedgerMigrator"
            "（EventStore.append 统一正源 pipeline_events）→逐行对账+四态汇总"
            "+ACCEPTED 裁定清单（方案 §14/§20.2 MIG-01~05）"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "started_at": started,
        "git_head": _git_head(),
        "tool": "tools/w5_reconcile.py",
        "mode": "formal" if formal else "drill",
        "source": {
            "dir": source_dir,
            "files": [{**m,
                       "sha256_after": sha_after[m["file"]],
                       "bytewise_unchanged": sha_before[m["file"]] == sha_after[m["file"]]}
                      for m in files_meta],
            "skipped_files": skipped,
            "total_nonblank_lines": total_nonblank,
            "caliber": {
                "expected": EXPECTED_CALIBER,
                "actual_rows": total_nonblank,
                "actual_accepted_flavor": len(accepted_list),
                "verdict": (f"实际 {total_nonblank} 行 / ACCEPTED 味 "
                            f"{len(accepted_list)} 条，与方案 ~481/43 口径不一致"
                            "（不同源），如实记录"),
            },
        },
        "normalization": {
            "ts_alias_fields": list(TS_ALIAS_FIELDS),
            "status_candidate_fields": list(STATUS_CANDIDATE_FIELDS),
            "alias_table": "wenqu_core.ledger_migrator.STATUS_ALIASES"
                           "（冻结正源，本工具零自造别名）",
            "known_statuses": sorted(KNOWN_STATUSES),
            "row_id_formula": "sha256(source_file_abs + '\\n' + line_no + '\\n' + raw_line)",
        },
        "event_store": {
            "table": "pipeline_events",
            "write_api": "EventStore.append",
            "db_path": db_path,
            "db_logical_snapshot_sha": snap2_sha,
            "chain_verified": chain_ok,
            "chain_head": head,
            "event_count_total": total_events,
            "ledger_migrated_events": len(store_index),
            "orphan_events": orphan_events,
        },
        "runs": {"run1": run1_report, "run2": run2_report},
        "verification": {
            "conservation": {
                "equation": "source_nonblank == mapped + quarantined + 待人工 + 不一致",
                "source_nonblank": total_nonblank,
                "mapped": mapped_n, "quarantined": quarantined_n,
                "待人工": manual_n, "不一致": inconsistent_n,
                "conserved": conserved},
            "idempotent": idempotent,
            "source_bytewise_unchanged": source_unchanged,
            "chain_verified": chain_ok,
            "all_checks_passed": all_ok,
        },
        "four_state_summary": {
            "mapped": mapped_n, "quarantined": quarantined_n,
            "待人工": manual_n, "不一致": inconsistent_n,
            "total": total_nonblank},
        "quarantine_reasons": dict(sorted(quarantine_reasons.items())),
        "accepted_adjudication": accepted_list,
        "rows": clean_rows(),
    }
    return report, (0 if all_ok else 1)


# ---------------------------------------------------------------------- #
# summary.md（正式模式）
# ---------------------------------------------------------------------- #
def write_summary(report: Dict[str, Any], summary_path: str) -> None:
    s = report["four_state_summary"]
    v = report["verification"]
    src = report["source"]
    lines: List[str] = []
    a = lines.append
    a("# W5 旧账迁移对账报告（reconciliation summary）")
    a("")
    a(f"- 生成：{report['generated_at']}（mode={report['mode']}，"
      f"tool={report['tool']}，git_head={report.get('git_head')}）")
    a(f"- 源：`{src['dir']}`（{src['total_nonblank_lines']} 非空行；"
      "全程只读，SHA256 前后逐字节一致）")
    a(f"- 事件正源：pipeline_events（写入 API=EventStore.append；"
      f"db=`{report['event_store']['db_path']}`）")
    a("")
    a("## 口径差异（如实记录）")
    a("")
    a(f"- 预期口径：{src['caliber']['expected']['expected_rows']} 条 / "
      f"{src['caliber']['expected']['expected_accepted']} ACCEPTED —— "
      f"{src['caliber']['expected']['caliber_breakdown_from_plan_14_3']}")
    a(f"- 实际口径：{src['caliber']['actual_rows']} 行 / "
      f"ACCEPTED 味 {src['caliber']['actual_accepted_flavor']} 条")
    a(f"- 裁定：{src['caliber']['verdict']}。方案 §14.2.7 明示 481 仅是旧 "
      "dashboard 折叠数，不能充当迁移分母；本报告以逐行实扫为分母。")
    a("")
    a("## 四态汇总")
    a("")
    a("| 状态 | 行数 |")
    a("|---|---|")
    a(f"| mapped（已入统一事件库） | {s['mapped']} |")
    a(f"| quarantined（确定性隔离） | {s['quarantined']} |")
    a(f"| 待人工（ACCEPTED 裁定） | {s['待人工']} |")
    a(f"| 不一致（对账失配，必须=0） | {s['不一致']} |")
    a(f"| **合计（=源非空行数）** | **{s['total']}** |")
    a("")
    a(f"- 守恒等式 `{v['conservation']['equation']}` → "
      f"conserved={v['conservation']['conserved']}")
    a(f"- quarantine 原因分布："
      f"`{json.dumps(report['quarantine_reasons'], ensure_ascii=False)}`")
    a("")
    a("## 幂等与完整性验证")
    a("")
    idem = v["idempotent"]
    a(f"- 两次迁移：run1 imported={idem['run1_imported']}/"
      f"dup={idem['run1_duplicates']}/quarantine={idem['run1_quarantined']}；"
      f"run2 imported={idem['run2_imported']}/"
      f"dup={idem['run2_duplicates']}/quarantine={idem['run2_quarantined']}")
    a(f"- 行集逐字节一致（run1 快照==run2 快照）：{idem['rowset_identical']}")
    a(f"- 库逻辑快照 SHA（跨运行可比）："
      f"`{report['event_store']['db_logical_snapshot_sha']}`")
    a(f"- 哈希链 verify_chain：{v['chain_verified']}"
      f"（head={str(report['event_store']['chain_head'])[:16]}…，"
      f"共 {report['event_store']['event_count_total']} 事件，其中 "
      f"LEDGER_MIGRATED {report['event_store']['ledger_migrated_events']} 条）")
    a(f"- 源文件字节不变：{v['source_bytewise_unchanged']}")
    a(f"- 孤儿事件（库内有、staging 无）："
      f"{len(report['event_store']['orphan_events'])}")
    a(f"- 全部检查通过：**{v['all_checks_passed']}**")
    a("")
    a("## ACCEPTED 裁定清单（单独）")
    a("")
    if not report["accepted_adjudication"]:
        a("（本源无 ACCEPTED 味行）")
    for i, item in enumerate(report["accepted_adjudication"], start=1):
        a(f"{i}. `{item['source_file']}` 行 {item['line_no']}："
          f"{item['field']}=`{item['raw_value']}`")
        if item.get("project_context"):
            a(f"   - 项目上下文：`{json.dumps(item['project_context'], ensure_ascii=False)}`")
        a(f"   - row_id=`{item['row_id']}`；处置：{item['disposition']}")
        a(f"   - 原文预览：{item['preview'][:160]}")
    a("")
    a("## 规范化规则（确定性）")
    a("")
    a(f"- ts 别名链：{report['normalization']['ts_alias_fields']}")
    a(f"- status 候选链：{report['normalization']['status_candidate_fields']}")
    a(f"- 别名正源：{report['normalization']['alias_table']}")
    a("- 不猜填：候选值不在冻结别名表（DONE/PARTIAL/MERGED/ALL-GREEN/"
      "master=… 长文本等）一律 quarantine 记因；FIXED→FIXED_PENDING_VERIFY "
      "由迁移器执行（M3）。")
    a("")
    a("## 诚实边界")
    a("")
    a("- 本源为引擎轮次工作日志（action 叙事行占绝大多数），非状态账本——"
      "quarantine 主因 `no_mappable_status` 属源数据本性，非工具缺陷；")
    a("- 未写任何生产库；legacy 源目录零写入（SHA 前后一致已证）；")
    a("- project key 冲突（MIG-05）在本真实源上计 "
      f"{report['quarantine_reasons'].get(PROJECT_KEY_CONFLICT_PREFIX.rstrip(':'), 0)} 例"
      "（可映射行均无 project 字段；MIG-05 行为面由 system/tests/"
      "test_ac_state_mig.py 合成旧账 fixture 逐字覆盖）。")
    with open(summary_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="W5 旧账 reconciliation（MIG-01~05 证据面）")
    ap.add_argument("--source", default=DEFAULT_SOURCE_DIR,
                    help=f"旧账源目录（默认 {DEFAULT_SOURCE_DIR}；只读）")
    ap.add_argument("--workdir", default=None,
                    help="工作目录（默认 /tmp/w5-reconcile-drill-<tmp>）")
    ap.add_argument("--formal", action="store_true",
                    help="正式模式：产物落 evidence/07-migration-reconcile/")
    args = ap.parse_args()

    workdir = FORMAL_EVIDENCE_DIR if args.formal else (
        args.workdir or tempfile.mkdtemp(prefix="w5-reconcile-drill-"))

    report, exit_code = run_reconcile(os.path.abspath(args.source), workdir, args.formal)

    report_name = "reconcile-report.json" if args.formal else "drill-report.json"
    report_path = os.path.join(workdir, report_name)
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2, sort_keys=True)
    if args.formal:
        write_summary(report, os.path.join(workdir, "summary.md"))

    s = report["four_state_summary"]
    v = report["verification"]
    idem = v["idempotent"]
    print(f"[w5_reconcile] mode={report['mode']} workdir={workdir}")
    print(f"  源非空行 {s['total']} | mapped {s['mapped']} | "
          f"quarantined {s['quarantined']} | 待人工 {s['待人工']} | "
          f"不一致 {s['不一致']}")
    print(f"  run1: imported={idem['run1_imported']} dup={idem['run1_duplicates']} "
          f"quarantine={idem['run1_quarantined']} | run2: "
          f"imported={idem['run2_imported']} dup={idem['run2_duplicates']} "
          f"quarantine={idem['run2_quarantined']}")
    print(f"  守恒={v['conservation']['conserved']} "
          f"幂等={idem['rowset_identical'] and idem['run2_imported_zero']} "
          f"链验证={v['chain_verified']} "
          f"源字节不变={v['source_bytewise_unchanged']}")
    print(f"  ACCEPTED 裁定清单：{len(report['accepted_adjudication'])} 条")
    print(f"  报告：{report_path}")
    print(f"  结果：{'ALL CHECKS PASSED' if exit_code == 0 else 'FAILED (fail-closed)'}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

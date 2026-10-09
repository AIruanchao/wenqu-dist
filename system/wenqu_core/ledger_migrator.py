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
    - 收编后旧表原样保留在库中，仅供只读对账，不再是事件正源；
    - R7-EVENT-LEGACY-WRITABLE-007（P0）根修：收编完成后对旧表安装冻结
      触发器（INSERT/UPDATE/DELETE 一律 RAISE(ABORT)），cutover（冻结）
      时刻记入库内 bookkeeping 表 ``legacy_events_cutover``；晚于 cutover
      才出现/才落账的迟到行绝不导入——一律 quarantine
      （reason=late_write_after_cutover）并在报告告警，迁移器绝不静默
      吸收收编后的写入（详见 :func:`migrate_legacy_events` 契约）。

第八轮 P0-6 残余根修（backdated gap/UPDATE 仍可入链）：cutover 的
    id/ts 双通道都是 writer 可回填的字段——旧表冻结触发器被 DROP 后，
    UPDATE 旧行并回填早 ts（或向历史 gap 空位 INSERT 全回填行）可骗过
    双通道二次入链。根修为「不可伪造的行版本账本」：首次收编把旧表
    每行已读内容的 sha256 记入统一库侧 bookkeeping 表
    ``legacy_row_digests``（rowid→快照；装 AFTER UPDATE/DELETE 拒绝
    触发器，与事件链同库受 append-only 保护）；二次收编逐行比对——
    内容失配即 quarantine（reason=row_mutated_after_cutover）、账本
    缺席（gap 空位后塞入且双通道未命中）按迟到写拒收。旧表侧无论
    怎么改（含 DROP 三触发器）都改不到统一库侧账本，比对必然失配。

G9-05 第九轮根修（legacy 升级洞，R8-EVENT-BACKDATE-008 升级路径）：
    上述行版本账本只保护「fresh cutover 后」的库——旧版代码跑过的库
    只有 cutover 记账、没有 digest ledger。若升级时按「当前现状」补记
    基线，则升级前已发生的 gap/UPDATE+backdate 篡改会被当成可信基线
    收编入链。根修为 ``legacy_untrusted`` fail-closed：升级路径检测到
    「cutover 已记账而 digest ledger 缺失/为空」时，绝不按现状补基线
    ——本次发现的行全部 quarantine（reason=legacy_untrusted_no_baseline，
    imported=0、主链长度不增），报告显式声明该库 legacy 历史不可验证，
    需人工从可信正源重建基线或接受永久隔离（见
    :func:`migrate_legacy_events` 契约）。

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
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .store import EventStore

__all__ = [
    "LedgerMigrator", "ConservationError", "STATUS_ALIASES", "KNOWN_STATUSES",
    "MIGRATION_EVENT_TYPE", "LEGACY_EVENTS_TABLE",
    "LEGACY_RESIDUE_EVENT_TYPE", "migration_event", "migrate_legacy_events",
    "PROJECT_FIELDS", "extract_project_ids",
    "LATE_WRITE_REASON", "LEGACY_FREEZE_TRIGGER_NAMES", "LEGACY_CUTOVER_TABLE",
    "ROW_MUTATED_REASON", "LEGACY_ROW_DIGESTS_TABLE",
    "LEGACY_DIGEST_FREEZE_TRIGGER_NAMES",
    "LEGACY_UNTRUSTED_REASON", "LEGACY_UNTRUSTED_ACTION_REQUIRED",
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

# ---------------------------------------------------------------------- #
# R7-EVENT-LEGACY-WRITABLE-007（P0）：旧表冻结只读 + cutover 记账 + 迟到写拒收
# ---------------------------------------------------------------------- #
#: 收编完成后对旧表安装的冻结触发器（INSERT/UPDATE/DELETE 一律 RAISE(ABORT)）。
#: CREATE TRIGGER IF NOT EXISTS 幂等安装：重跑不报错、不重复；触发器曾被
#: 绕过删除时，下一次收编运行治愈重装。
_LEGACY_FREEZE_ACTIONS = ("insert", "update", "delete")
LEGACY_FREEZE_TRIGGER_NAMES = tuple(
    f"{LEGACY_EVENTS_TABLE}_legacy_frozen_no_{action}"
    for action in _LEGACY_FREEZE_ACTIONS)
_LEGACY_FREEZE_TRIGGER_DDL = tuple(
    f"CREATE TRIGGER IF NOT EXISTS {name} "
    f"BEFORE {action.upper()} ON {LEGACY_EVENTS_TABLE} "
    "BEGIN "
    f"SELECT RAISE(ABORT, 'legacy {LEGACY_EVENTS_TABLE} frozen read-only "
    f"after cutover: {action.upper()} is forbidden'); "
    "END;"
    for action, name in zip(_LEGACY_FREEZE_ACTIONS, LEGACY_FREEZE_TRIGGER_NAMES))

#: 迟到写（cutover 之后才出现/才落账的旧行）的统一 quarantine reason
LATE_WRITE_REASON = "late_write_after_cutover"

#: cutover（冻结时刻）记账表：bookkeeping，非事件正源（与 migration_runs
#: 同类）。为何记在库内 bookkeeping 而不是事件链/sidecar：
#: - 迟到写判定必须与库同生命周期可读（sidecar 是旁路审计文件，可被独立
#:   删除/移动，不能承担执法凭证）；
#: - 往事件链追加 bookkeeping 事件会扰动「收编行数=链增量」的链长不变量，
#:   并混淆「事件负载=旧行内容纯函数」的幂等契约；
#: - sidecar 保持逐行 1:1 审计形状。cutover 时刻经迁移报告显式回带。
LEGACY_CUTOVER_TABLE = "legacy_events_cutover"
_CUTOVER_SCHEMA = (
    f"CREATE TABLE IF NOT EXISTS {LEGACY_CUTOVER_TABLE} ("
    " id            INTEGER PRIMARY KEY CHECK (id = 1),"
    " cutover_ts    TEXT NOT NULL,"
    " cutover_epoch REAL NOT NULL,"
    " max_legacy_id INTEGER NOT NULL,"
    " trigger_names TEXT NOT NULL)"
)

#: 旧 ``events`` 表收编时必须存在的列（缺失即形状异常，fail-closed 拒收）
_LEGACY_REQUIRED_COLUMNS = frozenset({
    "id", "line_sha", "status", "source_file", "source_line", "payload"})

# ---------------------------------------------------------------------- #
# 第八轮 P0-6 残余根修：行内容快照账本（不可伪造的行版本记录）
# ---------------------------------------------------------------------- #
#: 行内容快照账本（bookkeeping，非事件正源）：首跑收编把旧表每行「已读
#: 内容」的 sha256 记入该表（rowid -> 快照）。记在统一库侧而非旧表侧是
#: 刻意的——旧表 writer（含 DROP 掉旧表冻结触发器的绕过者）对统一库无
#: 写权限，改不到账本；账本自身装 AFTER UPDATE/DELETE 拒绝触发器，
#: append-only 保护与 ``pipeline_events`` 同库同级。
LEGACY_ROW_DIGESTS_TABLE = "legacy_row_digests"

#: 快照账本自身的 append-only 守卫触发器（AFTER UPDATE/DELETE 一律 ABORT）
LEGACY_DIGEST_FREEZE_TRIGGER_NAMES = (
    f"{LEGACY_ROW_DIGESTS_TABLE}_append_only_no_update",
    f"{LEGACY_ROW_DIGESTS_TABLE}_append_only_no_delete",
)
_DIGESTS_SCHEMA = (
    f"CREATE TABLE IF NOT EXISTS {LEGACY_ROW_DIGESTS_TABLE} ("
    " legacy_id   INTEGER PRIMARY KEY,"
    " row_sha     TEXT NOT NULL,"
    " recorded_at TEXT NOT NULL DEFAULT (datetime('now')))"
)
_LEGACY_DIGEST_TRIGGER_DDL = tuple(
    f"CREATE TRIGGER IF NOT EXISTS {name} "
    f"AFTER {action} ON {LEGACY_ROW_DIGESTS_TABLE} "
    "BEGIN "
    f"SELECT RAISE(ABORT, '{LEGACY_ROW_DIGESTS_TABLE} is append-only: "
    f"{action} is forbidden'); "
    "END;"
    for action, name in zip(("update", "delete"),
                            LEGACY_DIGEST_FREEZE_TRIGGER_NAMES))

#: 行内容被 UPDATE 过（cutover 后当前内容与账本快照不符）的统一
#: quarantine reason——含仅改 migrated_at 元数据的伪装性改动
ROW_MUTATED_REASON = "row_mutated_after_cutover"

# ---------------------------------------------------------------------- #
# G9-05 第九轮根修（legacy 升级洞，R8-EVENT-BACKDATE-008 升级路径）
# ---------------------------------------------------------------------- #
#: legacy 升级 fail-closed 的统一 quarantine reason：cutover 已记账而
#: digest ledger 缺失/为空（旧版代码跑过的库从来没有行版本账本），升级
#: 时旧表内容不可验证——本次发现的行一律隔离，绝不按「升级时现状」补
#: 可信基线（那会把升级前已发生的 gap/UPDATE+backdate 篡改收编入链）
LEGACY_UNTRUSTED_REASON = "legacy_untrusted_no_baseline"

#: ``legacy_untrusted`` 库的显式处置说明（进迁移报告，人工裁定正门）
LEGACY_UNTRUSTED_ACTION_REQUIRED = (
    "manual intervention required: rebuild the "
    f"{LEGACY_ROW_DIGESTS_TABLE} baseline from an authoritative "
    "pre-cutover source (人工从可信正源重建基线), or accept permanent "
    "quarantine of all legacy rows (或接受全部旧行永久隔离). "
    "Baselining from the current legacy table state is forbidden: "
    "cutover was recorded without a digest ledger, so tampering that "
    "happened before the upgrade (gap inserts / UPDATE+backdate) "
    "cannot be distinguished from untampered rows."
)


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
# R7-EVENT-LEGACY-WRITABLE-007：收编后冻结只读 + 迟到写拒收（第七轮 P0 修）
# 第八轮 P0-6 残余：行内容快照账本（UPDATE+backdate / gap 空位回填拒收）
# ---------------------------------------------------------------------- #
def _parse_ts_to_epoch(value: Any) -> Optional[float]:
    """把行内 ts / migrated_at 等时间值解析为 UTC epoch 秒；不可解析返回 None。

    支持 ISO 8601（含 Z 后缀/无时区按 UTC）、SQLite ``datetime('now')``
    形状、数值 epoch（秒；≥1e12 视为毫秒归一）。不可解析/空值返回
    None——该时间通道缺席，绝不猜时间（M2 精神：缺证据不猜填）。
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) / 1000.0 if value >= 1e12 else float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        num = float(text)
    except ValueError:
        num = None
    if num is not None:
        return num / 1000.0 if num >= 1e12 else num
    iso = (text[:-1] + "+00:00") if text.endswith(("Z", "z")) else text
    parsed: Optional[datetime] = None
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _row_effective_epoch(payload_text: Optional[str],
                         migrated_at: Any = None) -> Optional[float]:
    """旧行「落账时刻」的保守估计：行内 ts（payload JSON 的 ``ts`` 字段）与
    表元数据 ``migrated_at``（rowid 侧元数据通道）两路取可解析的最大值。

    取最大是 fail-closed 方向：任一通道声称该行晚于 cutover，即按迟到
    写处理。全部不可解析返回 None（时间证据缺席，由 id 通道兜底）。
    """
    candidates: List[float] = []
    meta = _parse_ts_to_epoch(migrated_at)
    if meta is not None:
        candidates.append(meta)
    if payload_text:
        try:
            obj = json.loads(payload_text)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            inner = _parse_ts_to_epoch(obj.get("ts"))
            if inner is not None:
                candidates.append(inner)
    return max(candidates) if candidates else None


def _read_cutover(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    """读该库已记录的 cutover；无记账/记账行为空返回 None。"""
    hit = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (LEGACY_CUTOVER_TABLE,)).fetchone()
    if hit is None:
        return None
    row = conn.execute(
        f"SELECT cutover_ts, cutover_epoch, max_legacy_id, trigger_names "
        f"FROM {LEGACY_CUTOVER_TABLE} WHERE id = 1").fetchone()
    if row is None:
        return None
    try:
        names = json.loads(row[3])
    except ValueError:
        names = []
    return {"cutover_ts": row[0], "cutover_epoch": row[1],
            "max_legacy_id": row[2], "trigger_names": names}


def _record_cutover(conn: sqlite3.Connection, max_legacy_id: int,
                    trigger_names: List[str]) -> None:
    """首次冻结记账（bookkeeping，非事件正源）。

    INSERT OR IGNORE + ``id = 1`` CHECK：单行记账，一经记录永不推进——
    迟到判定永远以该库首次 cutover 为准，绝不因后续运行（哪怕吸收过迟到
    行）而把门槛后移。
    """
    now = datetime.now(timezone.utc)
    conn.execute(_CUTOVER_SCHEMA)
    conn.execute(
        f"INSERT OR IGNORE INTO {LEGACY_CUTOVER_TABLE} "
        f"(id, cutover_ts, cutover_epoch, max_legacy_id, trigger_names) "
        f"VALUES (1, ?, ?, ?, ?)",
        (now.strftime("%Y-%m-%dT%H:%M:%SZ"), now.timestamp(),
         int(max_legacy_id), json.dumps(sorted(trigger_names))))


def _install_freeze_triggers(conn: sqlite3.Connection) -> List[str]:
    """对旧 events 表幂等安装冻结只读触发器；返回安装后实际在库的触发器名。

    CREATE TRIGGER IF NOT EXISTS：已安装（含重跑/治愈场景）不报错、不
    重复；返回值以 sqlite_master 实查为准（不信任 IF NOT EXISTS 的静默）。
    """
    for ddl in _LEGACY_FREEZE_TRIGGER_DDL:
        conn.execute(ddl)
    present = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?",
        (LEGACY_EVENTS_TABLE,))}
    return [name for name in LEGACY_FREEZE_TRIGGER_NAMES if name in present]


def _legacy_row_sha(row: Dict[str, Any]) -> str:
    """旧行「已读内容」的规范化 SHA256（行版本账本的记账单位）。

    覆盖 :func:`migrate_legacy_events` 实际读出并决定入链/迟判的全部列
    （id/line_sha/status/source_file/source_line/payload/migrated_at）——
    收编后对这些列的任何 UPDATE（含仅改 migrated_at 元数据的伪装、含
    回填早 ts）都会使摘要失配。migrated_at 通道缺席（形状变体无该列）
    时按 None 记账：列集后来发生变化本身就会造成失配（fail-closed）。
    """
    material = json.dumps(
        [row["id"], row["line_sha"], row["status"], row["source_file"],
         row["source_line"], row["payload"], row["migrated_at"]],
        ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _read_row_digests(conn: sqlite3.Connection) -> Dict[int, str]:
    """读已记录的行内容快照账本；表不存在/为空返回空 dict。"""
    hit = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (LEGACY_ROW_DIGESTS_TABLE,)).fetchone()
    if hit is None:
        return {}
    return {int(r[0]): r[1] for r in conn.execute(
        f"SELECT legacy_id, row_sha FROM {LEGACY_ROW_DIGESTS_TABLE}")}


def _record_row_digests(conn: sqlite3.Connection,
                        legacy_rows: List[Dict[str, Any]]) -> int:
    """把首跑读到的旧行内容快照写入受保护账本；返回账本当前行数。

    摘要按「本轮实际读入并导入的内容」计算（不是写账时刻的重读）——
    运行中途旧行被并发改动时，账本锚定的正是已入链内容，下一轮比对
    必然失配而拒收。INSERT OR IGNORE：既有 rowid 的快照永不改写（该表
    UPDATE/DELETE 已被 AFTER 触发器关死，不存在静默重基线路径）。本函数
    同时补建表与 append-only 触发器（幂等）。

    存量库边界（G9-05 fail-closed 收口）：旧版代码只记了 cutover、没有
    快照账本的库，升级后绝不在本函数按「当下内容」补记基线——当下内容
    无法与 cutover 时刻内容对账，补记等于把升级前篡改洗白成可信基线。
    该场景由调用方检测（cutover 已记账而账本为空）并整体标记
    ``legacy_untrusted``：行全部隔离、基线不补记，需人工从可信正源重建。
    本函数只在「首次 cutover（prior_cutover is None）」这一条路径上被
    调用。
    """
    conn.execute(_DIGESTS_SCHEMA)
    for ddl in _LEGACY_DIGEST_TRIGGER_DDL:
        conn.execute(ddl)
    for row in legacy_rows:
        conn.execute(
            f"INSERT OR IGNORE INTO {LEGACY_ROW_DIGESTS_TABLE} "
            f"(legacy_id, row_sha) VALUES (?, ?)",
            (int(row["id"]), _legacy_row_sha(row)))
    return conn.execute(
        f"SELECT COUNT(*) FROM {LEGACY_ROW_DIGESTS_TABLE}").fetchone()[0]


def migrate_legacy_events(sqlite_path: str,
                          sidecar_path: Optional[str] = None) -> Dict[str, Any]:
    """把旧版迁移器 ``events`` 表的历史残留行一次性收编进 pipeline_events。

    契约：
    - 只读旧行数据：本函数绝不 INSERT/UPDATE/DELETE 旧 ``events`` 表的
      行，收编后旧表行原样留在库中，仅供对账，不再是正源；
    - 冻结只读（R7-EVENT-LEGACY-WRITABLE-007）：收编完成后对旧表安装
      三个拒绝触发器（INSERT/UPDATE/DELETE 一律 RAISE(ABORT)）——
      ``CREATE TRIGGER IF NOT EXISTS`` 幂等安装，重跑不报错、不重复；
      触发器被绕过删除时，下一次收编运行治愈重装；
    - cutover（冻结时刻）记账：首次冻结把 cutover_ts/cutover_epoch/
      max_legacy_id 写入库内 bookkeeping 表 ``legacy_events_cutover``
      （INSERT OR IGNORE——一经记录永不推进，迟到判定永远以首次 cutover
      为准）。cutover 不写入事件链（链长不变量与「负载=旧行内容纯函数」
      幂等契约零扰动）、不额外追加 sidecar 行（sidecar 保持逐行 1:1 审计
      形状），时刻经返回报告显式回带（cutover_ts/cutover_max_legacy_id）；
    - 迟到写拒收（绝不静默吸收收编后的写入）：迁移入口对每行校验时间
      戳——行内 ts（payload JSON 的 ``ts`` 字段）或 rowid 对应元数据
      （``migrated_at`` 列 / id 序）晚于该库已记录 cutover 的行不导入，
      单独 quarantine（reason=late_write_after_cutover）并在报告告警
      （late_write_alert/late_write_rows）。两个独立拒收通道：
      (a) id > cutover.max_legacy_id——cutover 后新出现的行，无论 ts
          伪装多早；(b) 行有效时间戳 > cutover.cutover_epoch——含
          UPDATE 渠道篡改出的迟到内容；
    - 行内容快照账本（第八轮 P0-6 残余根修）：id/ts 双通道都是 writer
      可回填的字段，挡不住「旧表触发器被 DROP 后 UPDATE 旧行并回填早
      ts」与「向历史 gap 空位 INSERT 全回填行」。首跑收编把每行已读
      内容的 sha256 记入统一库侧受保护 bookkeeping 表
      ``legacy_row_digests``（append-only：AFTER UPDATE/DELETE 拒绝
      触发器与事件链同库同级保护）；重跑逐行比对当前内容摘要 vs 账本
      快照——(c) 内容失配（被 UPDATE 过，含仅改 migrated_at 元数据）->
      quarantine（reason=row_mutated_after_cutover，报告告警
      row_mutation_alert/row_mutation_rows）；(d) 账本缺席且 id/ts 双
      通道未命中（gap 空位后塞入的行）-> 按迟到写拒收（evidence 标注
      no row digest on record）。旧表三触发器被 DROP 也绕不开本通道：
      行版本账本在统一库侧，绕过旧表触发器改不掉账本，比对必然失配；
      快照一经记账永不改写、永不重基线（INSERT OR IGNORE + 拒绝触发
      器），quarantine 不会推进 cutover 也不会重写快照；
    - legacy 升级 fail-closed（G9-05 第九轮根修，R8-EVENT-BACKDATE-008
      升级路径）：检测到「cutover 已记账而 digest ledger 缺失/为空」
      （旧版代码跑过的存量库从来没有行版本账本）时，该库标
      ``legacy_untrusted``——绝不按升级时现状补记基线（当下内容无法与
      cutover 时刻对账，补记会把升级前已发生的 gap/UPDATE+backdate
      篡改收编成可信基线）；本次发现的旧行全部 quarantine
      （reason=legacy_untrusted_no_baseline，imported=0、主链长度不增、
      账本保持缺席），报告显式给出 legacy_untrusted 标记与处置说明
      （legacy_untrusted_action_required：人工从可信正源重建基线或接受
      永久隔离）；冻结触发器照常治愈重装（表仍冻结只读），cutover
      照常永不推进。有完整 digest ledger 的库（fresh cutover 或新版
      升级）不受影响，走既有三通道判定；
    - 单一写入 API：每行经 ``EventStore.append`` 以
      ``LEGACY_EVENTS_ROW_MIGRATED`` 事件入 ``pipeline_events`` 哈希链；
      事件负载是旧行已记内容（line_sha/status/payload）的纯函数——重跑
      全部计 duplicate，零重复入账（一次性、幂等）；
    - 旧行按已入账历史记录原样收编（status 等字段原封不动）：旧表行是
      旧制度下已落账的数据，收编时重新判定/归一会改写历史账目，故只做
      搬运、绝不再判（迟到写拒收是「是否搬运」的守门，不是重判状态）；
      JSONL 源行的 quarantine 语义在 :meth:`LedgerMigrator.migrate`；
    - 守恒：rows_seen == imported + duplicates + quarantined，否则
      ConservationError；
    - 逐行 sidecar 审计（append-only），携带旧表 id/source_file/source_line
      位置溯源；quarantine 行额外携带 reason 与迟到证据（late_evidence）。

    旧表不存在（新库/已收编库）不是错误：报告 ``legacy_table_present=False``
    （不装触发器、不记 cutover；但若该库历史上记录过 cutover 而旧表被
    整表删除，cutover 记账仍在——旧表重建后迟到判定继续生效）。
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
        has_migrated_at = False
        if present:
            cols = {r[1] for r in store._conn.execute(
                f"PRAGMA table_info({LEGACY_EVENTS_TABLE})")}
            missing = _LEGACY_REQUIRED_COLUMNS - cols
            if missing:
                # 形状异常 fail-closed：同名表不是旧迁移器产物，绝不猜搬
                raise RuntimeError(
                    f"legacy table {LEGACY_EVENTS_TABLE!r} has unexpected shape; "
                    f"missing columns: {sorted(missing)}; refusing to migrate")
            # migrated_at 是迟到写判定的 rowid 侧元数据通道（旧 schema 自带
            # DEFAULT datetime('now')；形状变体缺列时该通道缺席，由 id 通道
            # 兜底）——存在则一并只读取出
            has_migrated_at = "migrated_at" in cols
            select_cols = ("id, line_sha, status, source_file, source_line, payload"
                           + (", migrated_at" if has_migrated_at else ""))
            # 只读 SELECT——旧表行数据全程零写入
            for row in store._conn.execute(
                f"SELECT {select_cols} FROM {LEGACY_EVENTS_TABLE} ORDER BY id"
            ):
                legacy_rows.append({
                    "id": row[0], "line_sha": row[1], "status": row[2],
                    "source_file": row[3], "source_line": row[4],
                    "payload": row[5],
                    "migrated_at": row[6] if has_migrated_at else None,
                })

        # 该库已记录的 cutover（无论旧表当前是否存在都读：旧表被整表删除
        # 后重建的场景，迟到判定必须继续以首次 cutover 为准）
        prior_cutover = _read_cutover(store._conn)
        # 行内容快照账本（第八轮根修）：与 cutover 同生命周期读取——账本
        # 非空即进入逐行比对模式；为空表示首跑或存量库待补记基线
        prior_digests = _read_row_digests(store._conn)
        # G9-05 legacy 升级 fail-closed（R8-EVENT-BACKDATE-008 升级路径）：
        # cutover 已记账而 digest ledger 缺失/为空 == 旧版代码（只有
        # cutover 通道、无行版本账本）跑过的存量库。此刻旧表内容无法与
        # cutover 时刻内容对账——升级前已发生的 gap/UPDATE+backdate 篡改
        # 与合法行不可区分。绝不按「升级时现状」补基线（那是把篡改收编
        # 成可信基线）：本次发现的行全部隔离、账本保持缺席、人工处置。
        legacy_untrusted = prior_cutover is not None and not prior_digests

        imported = duplicates = quarantined = 0
        quarantine_reasons: Dict[str, int] = {}
        late_rows: List[Dict[str, Any]] = []      # 告警明细（legacy_id+证据）
        mutated_rows: List[Dict[str, Any]] = []   # 内容失配告警明细
        untrusted_rows: List[Dict[str, Any]] = [] # legacy_untrusted 隔离明细
        with open(sidecar_path, "a", encoding="utf-8") as sidecar:
            for row in legacy_rows:
                # legacy_untrusted 优先短路一切通道：库级不可验证时逐行
                # 判定（id/ts/摘要比对）都建立在「有可信基线」的前提上，
                # 前提不成立即整体隔离——包括本可 duplicate 的已入链行
                # （区分对待会泄露「哪些行可收编」的信号，且无法自证）
                if legacy_untrusted:
                    quarantined += 1
                    quarantine_reasons[LEGACY_UNTRUSTED_REASON] = \
                        quarantine_reasons.get(LEGACY_UNTRUSTED_REASON, 0) + 1
                    untrusted_evidence = (
                        f"cutover recorded at "
                        f"{prior_cutover['cutover_ts']} but no "
                        f"{LEGACY_ROW_DIGESTS_TABLE} rows on record; "
                        f"table content at upgrade time is unverifiable")
                    untrusted_rows.append({"legacy_id": row["id"],
                                           "evidence": untrusted_evidence})
                    sidecar.write(json.dumps({
                        "decision": "quarantined",
                        "reason": LEGACY_UNTRUSTED_REASON,
                        "legacy_table": LEGACY_EVENTS_TABLE,
                        "legacy_id": row["id"],
                        "line_sha": row["line_sha"],
                        "source_file": row["source_file"],
                        "source_line": row["source_line"],
                        "untrusted_evidence": untrusted_evidence,
                    }, ensure_ascii=False, sort_keys=True) + "\n")
                    continue
                # 迟到写拒收：cutover 之后才出现/才落账的行绝不入链（两个
                # 独立通道任一命中即拒——id 通道抓新出现的行、ts 通道抓
                # 篡改出的迟到内容；证据原样进 sidecar 与报告）
                late_evidence = None
                mutation_evidence = None
                if prior_cutover is not None:
                    if row["id"] > prior_cutover["max_legacy_id"]:
                        late_evidence = (f"id={row['id']} > "
                                         f"cutover_max_id="
                                         f"{prior_cutover['max_legacy_id']}")
                    else:
                        eff = _row_effective_epoch(row["payload"],
                                                   row["migrated_at"])
                        if (eff is not None
                                and eff > prior_cutover["cutover_epoch"]):
                            late_evidence = (
                                f"row_ts={eff:.3f} > cutover_epoch="
                                f"{prior_cutover['cutover_epoch']:.3f}")
                # 第三通道（行内容快照比对，第八轮根修）：id/ts 都是 writer
                # 可回填的字段，内容快照锚定在统一库侧受保护账本——旧表
                # 触发器被 DROP、行被 UPDATE+backdate 也改不掉账本，比对
                # 必然失配而拒收；账本缺席（gap 空位后塞入）同样拒收
                if (late_evidence is None and prior_cutover is not None
                        and prior_digests):
                    snapshot_sha = prior_digests.get(row["id"])
                    current_sha = _legacy_row_sha(row)
                    if snapshot_sha is None:
                        late_evidence = (
                            f"id={row['id']} not present at cutover "
                            f"(no row digest on record)")
                    elif current_sha != snapshot_sha:
                        mutation_evidence = (
                            f"row_sha={current_sha[:16]} != "
                            f"cutover_snapshot={snapshot_sha[:16]}")
                if late_evidence is not None:
                    quarantined += 1
                    quarantine_reasons[LATE_WRITE_REASON] = \
                        quarantine_reasons.get(LATE_WRITE_REASON, 0) + 1
                    late_rows.append({"legacy_id": row["id"],
                                      "evidence": late_evidence})
                    sidecar.write(json.dumps({
                        "decision": "quarantined",
                        "reason": LATE_WRITE_REASON,
                        "legacy_table": LEGACY_EVENTS_TABLE,
                        "legacy_id": row["id"],
                        "line_sha": row["line_sha"],
                        "source_file": row["source_file"],
                        "source_line": row["source_line"],
                        "late_evidence": late_evidence,
                    }, ensure_ascii=False, sort_keys=True) + "\n")
                    continue
                if mutation_evidence is not None:
                    # 内容被 UPDATE 过（cutover 后与快照失配）→ 绝不入链；
                    # 快照不重写、cutover 不推进——下一次运行同样失配拒收
                    quarantined += 1
                    quarantine_reasons[ROW_MUTATED_REASON] = \
                        quarantine_reasons.get(ROW_MUTATED_REASON, 0) + 1
                    mutated_rows.append({"legacy_id": row["id"],
                                         "evidence": mutation_evidence})
                    sidecar.write(json.dumps({
                        "decision": "quarantined",
                        "reason": ROW_MUTATED_REASON,
                        "legacy_table": LEGACY_EVENTS_TABLE,
                        "legacy_id": row["id"],
                        "line_sha": row["line_sha"],
                        "source_file": row["source_file"],
                        "source_line": row["source_line"],
                        "mutation_evidence": mutation_evidence,
                    }, ensure_ascii=False, sort_keys=True) + "\n")
                    continue

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

        # 收编完成 → 冻结只读：幂等安装拒绝触发器（重跑不报错；触发器曾被
        # 绕过删除时在此治愈重装）；首次冻结即记 cutover（永不推进）
        frozen_triggers: List[str] = []
        if present:
            frozen_triggers = _install_freeze_triggers(store._conn)
            if prior_cutover is None:
                _record_cutover(
                    store._conn,
                    max_legacy_id=max((r["id"] for r in legacy_rows), default=0),
                    trigger_names=frozen_triggers)
            # 行内容快照记账（第八轮根修）：只在首次 cutover（本运行记账）
            # 时建立基线；此后账本 append-only——永不改写、永不重基线，
            # quarantine 不推进快照。G9-05：旧版存量库（cutover 已记账、
            # 账本为空）绝不在此补记基线——当下内容不可验证，补记即把
            # 升级前篡改洗白成可信基线（legacy_untrusted 路径已全部隔离）
            if prior_cutover is None:
                _record_row_digests(store._conn, legacy_rows)

        store.verify_chain()
        if len(legacy_rows) != imported + duplicates + quarantined:
            raise ConservationError(
                f"legacy residue conservation violated: rows_seen={len(legacy_rows)} != "
                f"imported({imported}) + duplicates({duplicates}) + "
                f"quarantined({quarantined})")

        cutover = _read_cutover(store._conn)
        digests_on_record = len(_read_row_digests(store._conn))
        return {
            "sqlite_path": sqlite_path,
            "legacy_table": LEGACY_EVENTS_TABLE,
            "legacy_table_present": present,
            "rows_seen": len(legacy_rows),
            "imported": imported,
            "duplicates": duplicates,
            "quarantined": quarantined,
            "quarantine_reasons": dict(sorted(quarantine_reasons.items())),
            "late_write_alert": bool(late_rows),
            "late_write_rows": late_rows,
            "row_digest_ledger": LEGACY_ROW_DIGESTS_TABLE,
            "row_digests_on_record": digests_on_record,
            "row_mutation_alert": bool(mutated_rows),
            "row_mutation_rows": mutated_rows,
            # G9-05 legacy 升级 fail-closed：显式标记 + 人工处置说明
            "legacy_untrusted": legacy_untrusted,
            "legacy_untrusted_reason": (
                LEGACY_UNTRUSTED_REASON if legacy_untrusted else None),
            "legacy_untrusted_rows": untrusted_rows,
            "legacy_untrusted_action_required": (
                LEGACY_UNTRUSTED_ACTION_REQUIRED if legacy_untrusted else None),
            "cutover_ts": cutover["cutover_ts"] if cutover else None,
            "cutover_max_legacy_id": (cutover["max_legacy_id"]
                                      if cutover else None),
            "legacy_frozen": present and len(frozen_triggers)
            == len(LEGACY_FREEZE_TRIGGER_NAMES),
            "frozen_triggers": frozen_triggers,
            "event_table": "pipeline_events",
            "write_api": "EventStore.append",
            "sidecar_path": sidecar_path,
            "chain_verified": True,
        }
    finally:
        store.close()

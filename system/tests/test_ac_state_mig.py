#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——STATE-01~11 / MIG-01~05（状态、账本、迁移）。

正源（逐字对齐）：
    evidence/00-baseline/codex-external/方案.md §20.2（STATE-01~06、MIG-01~05）
    与 §20.5（STATE-07~11）表格的「注入/期望」列。

被测体（wave6/P1F 工单后为两组，A 组断言不依赖 wenqu_pipeline 行为）：
    A. system/wenqu_core/store.py          —— EventStore（pipeline_events
       哈希链事件正源：append-only 触发器、控制事件守卫、BEGIN IMMEDIATE
       事务、WAL 并发、verify_chain、幂等 head）
       + system/wenqu_core/ledger_migrator.py —— LedgerMigrator（旧 JSONL
       账本迁移：quarantine/守恒/幂等/sidecar 审计；P0-6 第六轮统一正源
       ——导入行经公共 EventStore.append 写入同一张 pipeline_events）
       ——承载 STATE-01/03/04/06/07/08/10、MIG-01~05；
    B. system/wenqu_core/wenqu_pipeline.py —— 七段状态机 RunManager/
       ApprovalBroker（wave6 工单补齐产品面语义：STATE-02 ID/路径校验、
       STATE-05 writer epoch fencing、STATE-09 重放侧 identity 不变量、
       STATE-11 S7 缺授权终判）——承载 STATE-02/05/09/11。

可实现性裁定（诚实优先，不硬凑、不 xfail）：
    本文件对全部 16 个 ID 给出专属真实测试：
        STATE-01~11、MIG-01~05
    修正记录（2026-10-08 W5 对账轮）：MIG-05 曾登记为不可实现（当时
    ledger_migrator 无 project 概念）；并行改写后的迁移器已落地最小实现
    （PROJECT_FIELDS 一致性提取 + project_key_conflict 显式隔离 + project_id
    贯通进事件负载），本文件随即以真实专属测试替换该过期登记——断言只增不减。
    修正记录（2026-10-08 wave6/P1F 工单）：STATE-02/05/09/11 曾登记为
    不可实现（彼时语义在 store/ledger_migrator 中不存在且本文件被禁止
    import wenqu_pipeline）；wave6 工单在 wenqu_pipeline.py 落地对应最小
    真实语义（run_id/finding_id 结构校验、writer epoch fencing、重放侧
    identity 漂移拒绝、adjudicate_gate_conditional 终判口）后，四条过期
    登记转为真实专属测试（负例必拒、断言只增不减）。

覆盖边界（同样显式登记，不冒充完整验收面）：
    STATE-06/07/08/10 的完整语义 = store 层不可变/不可伪造保证 +
    RunManager（wenqu_pipeline）层状态机。本文件只测 store 层已实现的那一半
    （另一 agent 正在并行改 wenqu_pipeline，本文件禁止 import 它）；
    MIG-01 期望中的「+BLOCKED」在迁移器内的对应语义是 ERROR/BLOCKED 别名
    归一化为 BLOCKED 状态导入 + 坏行 quarantine 绝不导入为绿；
    整次迁移的 run 级 BLOCKED 聚合在编排层，不在本文件被测体范围内。

旧账数据说明：MIG 族全部使用小型「合成旧账」fixture（本文件内
build_*_ledger 系列函数在临时目录生成），不是生产账本；
文件名/时间戳/字段名均为合成值。

独立运行：python3 system/tests/test_ac_state_mig.py  → exit 0 全绿；
逐 ID 结果默认写临时目录（G9-07 测试零污染）；设 WENQU_EVIDENCE_OUT_DIR
可显式指定输出目录（有意更新 tracked evidence 快照时的正门）。
"""
import hashlib
import json
import os
import random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SYSTEM_DIR = os.path.dirname(HERE)                      # system/
REPO_ROOT = os.path.dirname(SYSTEM_DIR)                 # 仓根
sys.path.insert(0, SYSTEM_DIR)

# A 组用例只依赖 store / ledger_migrator（对 wenqu_pipeline 零依赖）；
# B 组（wave6/P1F）按新工单依赖 wenqu_pipeline——STATE-02/05/09/11 的
# 产品语义按工单落在该模块（本会话独占其修改权）。
from wenqu_core.store import (                          # noqa: E402
    EventStore, ChainIntegrityError, GENESIS_HASH, is_control_event)
from wenqu_core.ledger_migrator import (                # noqa: E402
    LedgerMigrator, ConservationError, KNOWN_STATUSES,
    MIGRATION_EVENT_TYPE, PROJECT_FIELDS, extract_project_ids,
    PROJECT_KEY_CONFLICT_PREFIX)
import wenqu_core.wenqu_pipeline as _wp                 # noqa: E402  (B 组被测体)
from wenqu_core.wenqu_pipeline import (                 # noqa: E402
    RunManager, PipelineError, PipelineCorruptionError, TerminalRunError,
    ApprovalRejected, InvalidRunIdError, FencedWriterError,
    SevenStageStateMachine as _SM, STAGES as _PIPE_STAGES)
from wenqu_core.approval_keys import (                  # noqa: E402
    ApprovalKeyring, sign_envelope)

def _artifact_out_dir() -> str:
    """证据工件输出目录（G9-07 测试零污染，R8-PYTEST-HISTORICAL-COLLECT-014）：

    - 显式设 ``WENQU_EVIDENCE_OUT_DIR`` → 写该目录（需有意更新 tracked
      evidence 快照时的正门——人工跑、复核后另行入册）；
    - 缺省 → 独立临时目录（mkdtemp）——测试输出零污染，绝不改写仓内
      tracked evidence（git_head/时间戳不再被每次运行覆写）。
    """
    env_dir = os.environ.get("WENQU_EVIDENCE_OUT_DIR")
    if env_dir:
        os.makedirs(env_dir, exist_ok=True)
        return env_dir
    return tempfile.mkdtemp(prefix="wenqu-artifact-ac-state-mig-")


ARTIFACT_PATH = os.path.join(_artifact_out_dir(), "ac-state-mig.json")

# ---------------------------------------------------------------------- #
# 不可实现登记表（模块级；语义在被测体中不存在，非测试跳过）
# wave6/P1F 后为空：STATE-02/05/09/11 已在 wenqu_pipeline 落地最小真实
# 语义并转为专属真实测试（见下方 B 组用例）；MIG-05 已在 W5 对账轮由
# 并行迁移器实现面承接。登记表保留机制本身——未来再出现被测体确无语义
# 的 ID 时按同一格式登记，不以 skip/xfail 冒充。
# ---------------------------------------------------------------------- #
NOT_IMPLEMENTABLE_IN_SCOPE: dict = {}

# STATE-06/07/08/10 与 MIG-01 的覆盖边界（测的是被测体已实现的那一半）
COVERAGE_BOUNDARY = {
    "STATE-01": "测 store 层 schema 边界：携带任意 stage/status 的管线控制事件（RUN_*/STAGE_*/ATTEMPT_* 等 event_type）经公共 EventStore.append 一律 ValueError；attempt 状态枚举校验在 wenqu_pipeline（禁 import，不越界）",
    "STATE-06": "测 store 层：SUPERSEDED 属控制事件不可裸 append 伪造；WAITING 残留事件行不可 UPDATE/DELETE 静默消除，唯一出路是追加新事件。残留清扫与 SUPERSEDED 控制事件的实际签发在 RunManager（wenqu_pipeline，禁 import）",
    "STATE-07": "测 store 层：已落账的 PASSED 证据不可 UPDATE/DELETE 回改成 RUNNING；RUNNING 类状态转移事件是控制类型，普通（裸）事件无法伪造。转移表级拒绝（InvalidTransitionError）在 wenqu_pipeline（禁 import）",
    "STATE-08": "测 store 层：FAILED attempt 的旧证据行不可覆盖（UPDATE 拒绝），重试只能追加新事件（新 attempt 记录），旧证据逐字节不变且链可验证。attempt_id 分配与不可变（AttemptImmutabilityError）在 wenqu_pipeline（禁 import）",
    "STATE-10": "测 store 层前半句：WAITING/FAILED attempt 直接改回 RUNNING 的两条路（UPDATE 行 / 伪造控制事件）全拒；追加新 attempt 事件成功且旧行保留。后半句 stage projection 指向新 attempt 在 RunManager（禁 import）",
    "MIG-01": "测迁移器已实现面：坏 JSON/未知状态 → quarantine 绝不导入；ERROR/BLOCKED 别名按已知状态 BLOCKED 导入（fail-closed 归一）。『+BLOCKED』的整次迁移 run 级 BLOCKED 聚合在编排层（不在被测体）",
    "MIG-02": "测迁移器已实现面：ACCEPTED 是未知状态——无论缺不缺审批信息一律 quarantine（不猜映射为 PASS），进 quarantine=待人工 reopen 的账，sidecar 全程留痕。『invalid 后写 reopen 事件』属 risk acceptance 子系统（FND-016，不在被测体）",
    "MIG-04": "ConservationError 是防御性守卫：tally 与处理循环遍历同一 list，经公共 API 构造不出账目不平（已实证 + 代码通读）。本用例测同秩语义的运行时面：逐行独立对账零失联 + 统一 append-only 事件表上删行攻击被触发器直接拒绝（旧版独立 events 表删后补账的少账向量就此关闭）+ 重迁移幂等零变化 + 审计侧不可写则迁移整体失败、零部分导入、零假守恒记账",
    "MIG-05": "测迁移器最小实现面（P0-6 第六轮 MIG-05 落地）：PROJECT_FIELDS 一致性提取 + 多 project 身份字段值不一致 → project_key_conflict 显式 quarantine（绝不静默选边/拆成假项目）+ 一致时 project_id 贯通进事件负载。§21.1 canonical repo_id（forge_host+owner/repo）冻结映射表与 fingerprint collision 表不在被测体（编排层职责），本文件不越界",
    # ---- wave6/P1F（B 组，被测体 = wenqu_pipeline.py）---- #
    "STATE-02": "测 wenqu_pipeline 三个调用方可控 ID 面：create_run task_id（^字母数字/-/_ 且 ≤64，既有）、register_finding finding_id（^fnd_ 且 ≤64，wave6 补长度面）、全部公开 API 的 run_id（^run_[A-Za-z0-9_-]+$ 且 ≤64，wave6 新增 _validate_run_id 闸口）。../、绝对路径、NUL、超长一律结构层拒绝。store 层 event_id 是 canonical payload 内容哈希（STATE-03/04 已实证无调用方输入面），故注入面落在管线 ID 校验；审批信封内 stop_event_id 等绑定字段属 AUTH 族（AUTH-01/COND-02 已覆盖），不在本 ID 范围",
    "STATE-05": "fenced 写者（RunManager(writer_epoch=N)）的控制事件带 writer_epoch 扩展字段——超出冻结 run-event-v2 词表（默认/未启用模式零盖章、零比较、字节级兼容，P0-4 对抗 #9 的 schema 全绿面不受影响）——schema 升版登记为后续工作包；fencing 作用域=单 run 事件流（被接管流对旧 epoch writer 全写入拒绝，含 broker 消费路径 loader 栅栏；新流/新 run 不受旧租约牵连，本用例显式验证该边界）；epoch 唯一性由租约发放方保证（同 epoch=同租约不区分实例）",
    "STATE-09": "测重放侧 identity 不变量：RUN_CREATED 冻结身份后，流内任何事件携带漂移 identity（SHA/scope/policy 任一变化）或缺 identity 即 PipelineCorruptionError；『强制新 run』正道（supersede 旧 run + 新 identity 新建 run，不变量 #3）以正例激活。写入侧 identity 结构校验（_validate_identity：40-hex/枚举/必填）为既有语义由正常流隐式覆盖；审批跨 SHA/scope/policy 的绑定拒绝属 COND-02/AUTH-02 面（已覆盖）",
    "STATE-11": "complete_run 对『软终态缺可用授权』的 fail-closed 拒绝保持不变（P0-2 既有测试断言不回退）；终判 FAILED 由 wave6 专属裁决口 adjudicate_gate_conditional 承接（S7 软终态 + 无已消费/未过期/指纹匹配授权 → RUN_COMPLETED/COMPLETED/FAIL）。S7 attempt 证据保持不可变（COMPLETED_CONDITIONAL 留档），终判落在 run 层；gate_aggregator 的 technical eligibility/context failure 属 COND-01 面（已覆盖）",
}

# ---------------------------------------------------------------------- #
# 基础设施
# ---------------------------------------------------------------------- #
PASS_N, FAIL_N = 0, 0
RESULTS = []          # [(test_id, name, ok, detail_dict)]


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
    except Exception as e:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc.__name__}, got {type(e).__name__}: {e}")
    raise AssertionError(f"expected {exc.__name__}, nothing raised")


def raw_conn(db_path):
    """打开裸 sqlite 连接做对抗性 SQL（绕过 EventStore 侧 API）。"""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def rows_of(conn, sql, args=()):
    return conn.execute(sql, args).fetchall()


# ---------------------------------------------------------------------- #
# P0-6 第六轮（统一事件正源）查询辅助：MIG 族断言全部落在唯一事件表
# pipeline_events 上（负载为 canonical JSON；位置溯源在 sidecar）
# ---------------------------------------------------------------------- #
def unified_rows(conn):
    """统一事件表全行快照（seq/event_id/payload/prev_event_hash/event_hash）。"""
    return rows_of(conn, "SELECT seq, event_id, payload, prev_event_hash, "
                         "event_hash FROM pipeline_events ORDER BY seq ASC")


def unified_payloads(conn, event_type=None):
    """统一事件表 payload 对象列表（可按 event_type 过滤）。"""
    out = []
    for (p,) in rows_of(conn, "SELECT payload FROM pipeline_events ORDER BY seq ASC"):
        obj = json.loads(p)
        if event_type is None or obj.get("event_type") == event_type:
            out.append(obj)
    return out


def assert_single_event_table(conn):
    """唯一正源断言：库里只有 pipeline_events 这一张事件表（旧 events 表
    不得被新代码创建/复活——两表两正源复发即红）。"""
    tables = {r[0] for r in rows_of(
        conn, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "pipeline_events" in tables, "统一事件表 pipeline_events 缺失"
    assert "events" not in tables, "旧 events 表被创建（两表两正源复发）"


def count_rows(conn, table):
    """表行数；表不存在（失败路径未建 bookkeeping 表）按 0 计（诚实计数，
    不把『表不存在』误报为非零或让查询异常逃逸）。"""
    hit = rows_of(conn, "SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name = ?", (table,))
    if not hit:
        return 0
    return rows_of(conn, f"SELECT COUNT(*) FROM {table}")[0][0]  # 表名为字面量


def assert_migration_chain(db, expected_len):
    """迁移产物与 EventStore 同表同链：verify_chain 通过、长度精确。"""
    store = EventStore(db)
    try:
        head, total = store.head()
        verify = store.verify_chain()
        assert verify["ok"] is True and verify["length"] == expected_len, verify
        assert total == expected_len and head == verify["head"]
        return head
    finally:
        store.close()


# ---------------------------------------------------------------------- #
# STATE-01：任意 stage/status → schema 拒绝
# ---------------------------------------------------------------------- #
def test_STATE_01_arbitrary_stage_status_schema_rejected():
    """注入：任意 stage/status 组合（合法名/未知名/空/超长/含换行与穿越串）。

    期望（被测体已实现面）：这些值要进事件账本只能走管线控制事件
    （RUN_*/STAGE_*/ATTEMPT_*/WAITING_*/APPROVAL_*/ACTION_*/FINDING_* /
    SUPERSEDED），而公共 EventStore.append 对控制类型一律 ValueError——
    即 store 的 schema 边界对「任意 stage/status 的状态写入」整体拒绝；
    连伪造 seal 字段也绕不过（守卫按 event_type 判定）。
    """
    stages = ["S1", "S7", "nonexistent-stage", "", "x" * 5000,
              "../secrets", "/etc/passwd", "a\nb", "站七"]
    statuses = ["PASS", "FAIL", "RUNNING", "PASSED", "WAITING", "", "WEIRD",
                "x" * 5000, "PASSED\nRUNNING"]
    control_types = ["STAGE_ATTEMPT_RECORDED", "STAGE_STATUS", "RUN_STATUS",
                     "ATTEMPT_STATUS", "RUN_RUNNING"]
    checked = 0
    with TmpDir("ac-s1-") as td:
        store = EventStore(os.path.join(td, "ev.db"))
        try:
            for etype in control_types:
                for stage in stages:
                    for status in statuses:
                        ev = {"event_type": etype, "stage": stage,
                              "status": status, "attempt": "a-1"}
                        expect(ValueError, lambda ev=ev: store.append(ev))
                        checked += 1
            # 伪造 seal 字段也绕不过守卫（守卫只看 event_type）
            for forged in ({"event_type": "STAGE_PASSED", "seal": "f" * 64},
                           {"event_type": "SUPERSEDED", "seal": "0" * 64},
                           {"event_type": "RUN_RUNNING", "seal": "ab"}):
                expect(ValueError, lambda ev=forged: store.append(ev))
                checked += 1
            # 对照组：普通（非控制）事件不受影响——拒绝面精确针对状态写入路径
            h, ins = store.append({"event_type": "OBSERVATION",
                                   "stage": "S1", "status": "PASS",
                                   "note": "ordinary event is fine"})
            assert ins is True
            # 任意 stage/status 没有经任何路径落库（对照组仅 1 行）
            assert store.head() == (h, 1)
            assert store.verify_chain()["ok"] is True
        finally:
            store.close()
    assert checked == len(control_types) * len(stages) * len(statuses) + 3
    return {"rejected_combinations": checked,
            "control_types": control_types,
            "boundary": "attempt 状态枚举校验在 wenqu_pipeline（本文件禁 import）"}


# ---------------------------------------------------------------------- #
# STATE-03：100×100 并发写 → 零丢失/重复
# ---------------------------------------------------------------------- #
def test_STATE_03_concurrent_100x100_no_loss_no_dup():
    """注入：100 个并发 writer × 各 100 条不同事件（真实多连接 WAL 并发）。

    期望：零丢失（10000 行全在）、零重复（10000 个唯一 event_id，
    每条恰好 inserted=True 一次）、链仍单一线性且 verify_chain 通过。
    附加子场景：20 个 writer 并发追加同一内容 → 恰好 1 行（幂等不双入账）。
    """
    WRITERS, PER_WRITER = 100, 100
    with TmpDir("ac-s3-") as td:
        db = os.path.join(td, "ev.db")
        EventStore(db).close()          # 预建 schema，再放开并发
        inserted = [0] * WRITERS
        errors = []

        def writer(w):
            try:
                s = EventStore(db)
                try:
                    for i in range(PER_WRITER):
                        _, ins = s.append({"kind": "load", "writer": w, "i": i})
                        if ins:
                            inserted[w] += 1
                finally:
                    s.close()
            except Exception as e:      # noqa: BLE001
                errors.append(f"writer{w}:{type(e).__name__}:{e}")

        threads = [threading.Thread(target=writer, args=(w,))
                   for w in range(WRITERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"并发写抛错（即丢失面）: {errors[:3]}"

        store = EventStore(db)
        try:
            head, total = store.head()
            assert total == WRITERS * PER_WRITER, f"丢失/缺行: {total}"
            assert sum(inserted) == WRITERS * PER_WRITER, \
                f"inserted 计数不符: {sum(inserted)}"
            uniq_ids = rows_of(
                store._conn,
                "SELECT COUNT(DISTINCT event_id) FROM pipeline_events")[0][0]
            assert uniq_ids == WRITERS * PER_WRITER, f"重复行: {uniq_ids}"
            verify = store.verify_chain()
            assert verify["ok"] and verify["length"] == WRITERS * PER_WRITER
            assert verify["head"] == head
        finally:
            store.close()

        # 子场景：同内容并发重放 → 恰好 1 行、1 个 inserted=True、hash 全同
        db2 = os.path.join(td, "idem.db")
        EventStore(db2).close()
        results, ierr = [], []

        def idem_writer():
            try:
                s = EventStore(db2)
                try:
                    results.append(s.append({"same": "retry-payload", "n": 1}))
                finally:
                    s.close()
            except Exception as e:      # noqa: BLE001
                ierr.append(type(e).__name__)

        threads = [threading.Thread(target=idem_writer) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not ierr, f"幂等并发抛错: {ierr}"
        assert sum(1 for _, ins in results if ins) == 1
        assert len({h for h, _ in results}) == 1
        s2 = EventStore(db2)
        try:
            assert s2.head()[1] == 1
        finally:
            s2.close()
    return {"writers": WRITERS, "per_writer": PER_WRITER,
            "total_rows": WRITERS * PER_WRITER,
            "distinct_event_ids": WRITERS * PER_WRITER,
            "chain_verified": True,
            "same_content_concurrent_rows": 1}


# ---------------------------------------------------------------------- #
# STATE-04：事务各点 kill -9 → 全有或全无
# ---------------------------------------------------------------------- #
# 子进程脚本：包装 sqlite3.connect 拦截 execute，在事务的确定性点位对自身发
# SIGKILL（真 kill -9，不是异常模拟）；timer 模式在随机延时后自杀。
_KILL_CHILD_SRC = r'''
import os, signal, sys, threading
import sqlite3
import wenqu_core.store as st

db, mode, pre, delay = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])

class WrapConn:
    def __init__(self, real):
        self._real = real
        self._begins = 0
    def execute(self, sql, *a):
        cur = self._real.execute(sql, *a)
        up = sql.upper()
        if up.startswith("BEGIN"):
            self._begins += 1
            if self._begins > pre and mode == "after_begin":
                os.kill(os.getpid(), signal.SIGKILL)
        elif mode == "after_insert" and up.startswith("INSERT") and self._begins > pre:
            os.kill(os.getpid(), signal.SIGKILL)
        elif mode == "after_commit" and up.startswith("COMMIT") and self._begins > pre:
            os.kill(os.getpid(), signal.SIGKILL)
        return cur
    def __getattr__(self, name):
        return getattr(self._real, name)

_orig = sqlite3.connect
sqlite3.connect = lambda *a, **kw: WrapConn(_orig(*a, **kw))

if mode == "timer":
    threading.Timer(delay, lambda: os.kill(os.getpid(), signal.SIGKILL)).start()

s = st.EventStore(db)
for i in range(pre):
    s.append({"pre": i})
if mode == "timer":
    for i in range(50):
        s.append({"batch": i})
else:
    s.append({"doomed": True})
print("survived")
'''


def _run_kill_child(db, mode, pre, delay=0.0):
    env = dict(os.environ)
    env["PYTHONPATH"] = SYSTEM_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", _KILL_CHILD_SRC, db, mode, str(pre), str(delay)],
        capture_output=True, text=True, timeout=60, env=env)


def test_STATE_04_kill9_all_or_nothing():
    """注入：事务各点 kill -9（SIGKILL，真崩溃，非异常模拟）。

    确定性点位（对第 pre+1 条 doomed append）：
      after_begin  —— BEGIN IMMEDIATE 刚执行完
      after_insert —— INSERT 已执行、未 COMMIT
      after_commit —— COMMIT 已执行、未返回调用方
    随机点位：timer 模式在 50 条批量写入中随机自杀，重复 8 轮。
    期望（全有或全无）：重开库后哈希链始终可验证；行数只会是
    pre（事务未提交，WAL 回收丢弃）或 pre+1（已提交），绝无撕裂半行；
    批量场景行数落在 [0,50] 且链完好。
    """
    points = {}
    for mode in ("after_begin", "after_insert", "after_commit"):
        with TmpDir("ac-s4-") as td:
            db = os.path.join(td, "ev.db")
            pre = 3
            p = _run_kill_child(db, mode, pre)
            assert p.returncode == -9, \
                f"{mode}: 子进程未死于 SIGKILL (rc={p.returncode})"
            store = EventStore(db)
            try:
                total = store.head()[1]
                verify = store.verify_chain()
                doomed = rows_of(
                    store._conn,
                    "SELECT COUNT(*) FROM pipeline_events "
                    "WHERE payload LIKE '%doomed%'")[0][0]
            finally:
                store.close()
            if mode == "after_commit":
                assert total == pre + 1 and doomed == 1, \
                    f"{mode}: 已提交事务丢失 total={total} doomed={doomed}"
            else:
                assert total == pre and doomed == 0, \
                    f"{mode}: 未提交事务泄漏 total={total} doomed={doomed}"
            assert verify["ok"] is True, f"{mode}: 崩溃后链断裂"
            points[mode] = {"rows": total, "chain_ok": True,
                            "committed": mode == "after_commit"}

    rng = random.Random(20261008)      # 固定种子，证据可复现
    timer_observed = []
    for round_no in range(8):
        with TmpDir("ac-s4t-") as td:
            db = os.path.join(td, "ev.db")
            delay = rng.uniform(0.005, 0.25)
            p = _run_kill_child(db, "timer", 0, delay)
            assert p.returncode == -9, f"timer r{round_no}: rc={p.returncode}"
            store = EventStore(db)
            try:
                total = store.head()[1]
                verify = store.verify_chain()
            finally:
                store.close()
            assert 0 <= total <= 50, f"timer r{round_no}: 行数越界 {total}"
            assert verify["ok"] is True, f"timer r{round_no}: 链断裂 @ {total} 行"
            timer_observed.append({"round": round_no, "delay_s": round(delay, 3),
                                   "rows": total, "chain_ok": True})
    return {"deterministic_points": points,
            "timer_rounds": timer_observed,
            "verdict": "每次崩溃后：链完好，行数=已提交事务数（全有或全无）"}


# ---------------------------------------------------------------------- #
# STATE-06：WAITING 终态残留 → SUPERSEDED 事件，不静默删
# ---------------------------------------------------------------------- #
def test_STATE_06_waiting_residue_superseded_not_silently_deleted():
    """注入：账本里留有 WAITING 终态残留事件行；尝试静默消除它。

    期望（被测体已实现面）：
      1) 残留行不可 DELETE/UPDATE（静默删除路径被 append-only 触发器关死）；
      2) SUPERSEDED 是控制事件类型——裸 append 伪造『已被接管』被拒；
      3) 唯一出路是追加新事件（账本延长，残留行逐字节保留、链可验证）。
    """
    with TmpDir("ac-s6-") as td:
        db = os.path.join(td, "ev.db")
        store = EventStore(db)
        try:
            store.append({"event_type": "NOTE", "stage": "S5",
                          "residue": "attempt waiting since kill -9"})
            residue_snapshot = rows_of(
                store._conn, "SELECT seq, payload, event_hash FROM pipeline_events")
            # 1) 静默删/改两条路全拒
            expect(sqlite3.IntegrityError, lambda: store._conn.execute(
                "DELETE FROM pipeline_events WHERE payload LIKE '%waiting%'"))
            expect(sqlite3.IntegrityError, lambda: store._conn.execute(
                "UPDATE pipeline_events SET payload = '{}' "
                "WHERE payload LIKE '%waiting%'"))
            # 裸连接同样拒（触发器在 schema 层，不依赖 EventStore API）
            conn = raw_conn(db)
            try:
                expect(sqlite3.IntegrityError, lambda: conn.execute(
                    "DELETE FROM pipeline_events"))
            finally:
                conn.close()
            # 2) 伪造 SUPERSEDED 控制事件被拒（覆盖旧残留必须走带 seal 的内部口）
            expect(ValueError, lambda: store.append(
                {"event_type": "SUPERSEDED", "residue_ref": "S5"}))
            expect(ValueError, lambda: store.append(
                {"event_type": "WAITING_SUPERSEDED", "residue_ref": "S5"}))
            # 3) 正道：追加接管事件；残留行原样保留
            h2, ins = store.append({"event_type": "NOTE", "stage": "S5",
                                    "superseded_by": "run-2"})
            assert ins is True
            after = rows_of(
                store._conn, "SELECT seq, payload, event_hash FROM pipeline_events")
            assert after[:len(residue_snapshot)] == residue_snapshot, \
                "残留行被改动（不允许）"
            assert store.head() == (h2, 2)
            assert store.verify_chain()["ok"] is True
        finally:
            store.close()
    return {"silent_delete": "rejected (append-only trigger)",
            "silent_update": "rejected (append-only trigger)",
            "forged_superseded_events": "rejected (control-event guard)",
            "residue_rows_preserved": 1,
            "boundary": "SUPERSEDED 控制事件的实际签发在 RunManager（禁 import）"}


# ---------------------------------------------------------------------- #
# STATE-07：普通事件把 PASSED 改回 RUNNING → 拒绝
# ---------------------------------------------------------------------- #
def test_STATE_07_normal_event_cannot_flip_passed_to_running():
    """注入：已落账的 PASSED 证据；三种『改回 RUNNING』的尝试。

    期望（被测体已实现面）：
      1) UPDATE 旧行把 PASSED 换成 RUNNING → 触发器拒绝；
      2) DELETE 旧行再补一条 RUNNING 版本 → DELETE 拒绝；
      3) 普通调用方伪造状态转移事件（event_type 为 RUNNING/ATTEMPT_*/…）
        → 控制事件守卫拒绝（状态转移只能走带 seal 的内部口）；
      4) 事后账本完好：PASSED 行原样、链可验证。
    """
    with TmpDir("ac-s7-") as td:
        db = os.path.join(td, "ev.db")
        store = EventStore(db)
        try:
            store.append({"event_type": "NOTE", "stage": "S3",
                          "status": "PASSED", "evidence": "att-1"})
            before = rows_of(store._conn, "SELECT payload FROM pipeline_events")
            # 1) UPDATE 改状态
            expect(sqlite3.IntegrityError, lambda: store._conn.execute(
                "UPDATE pipeline_events SET payload = replace(payload, "
                "'PASSED', 'RUNNING')"))
            # 2) DELETE 后重写
            expect(sqlite3.IntegrityError, lambda: store._conn.execute(
                "DELETE FROM pipeline_events WHERE payload LIKE '%PASSED%'"))
            # 3) 伪造 RUNNING 状态转移控制事件（普通事件无转移语义，只能冒充控制类型）
            for forged in ({"event_type": "RUN_RUNNING"},
                           {"event_type": "ATTEMPT_RESUMED", "status": "RUNNING"},
                           {"event_type": "STAGE_STATUS", "stage": "S3",
                            "status": "RUNNING"}):
                expect(ValueError, lambda ev=forged: store.append(ev))
            after = rows_of(store._conn, "SELECT payload FROM pipeline_events")
            assert after == before, "PASSED 证据被改动"
            assert store.head()[1] == 1
            assert store.verify_chain()["ok"] is True
            # 仍是 PASSED
            assert rows_of(store._conn, "SELECT COUNT(*) FROM pipeline_events "
                          "WHERE payload LIKE '%PASSED%'")[0][0] == 1
            assert rows_of(store._conn, "SELECT COUNT(*) FROM pipeline_events "
                          "WHERE payload LIKE '%RUNNING%'")[0][0] == 0
        finally:
            store.close()
    return {"update_path": "rejected", "delete_rewrite_path": "rejected",
            "forged_transition_events": "rejected",
            "passed_evidence_intact": True,
            "boundary": "转移表级拒绝（InvalidTransitionError）在 wenqu_pipeline"}


# ---------------------------------------------------------------------- #
# STATE-08：FAILED 重试 → 新 attempt，旧证据不覆盖
# ---------------------------------------------------------------------- #
def test_STATE_08_failed_retry_new_attempt_old_evidence_intact():
    """注入：一次 FAILED attempt 的证据事件；随后发起『重试』。

    期望（被测体已实现面）：
      1) 用新 attempt 数据覆盖旧证据行 → UPDATE 拒绝；
      2) 正当重试路径 = 追加一条新 attempt 事件（新内容、新 event_id/hash）；
      3) 旧 FAILED 证据逐字节不变（payload+event_hash 快照对比），
         新旧 attempt 同时在账、链可验证——旧证据不覆盖。
    """
    with TmpDir("ac-s8-") as td:
        db = os.path.join(td, "ev.db")
        store = EventStore(db)
        try:
            store.append({"event_type": "NOTE", "attempt": "att-1",
                          "result": "FAILED", "log": "exit 1 at S2",
                          "ts": "2026-10-08T00:00:00Z"})
            old = rows_of(store._conn,
                          "SELECT seq, payload, prev_event_hash, event_hash "
                          "FROM pipeline_events")
            # 1) 覆盖旧证据 → 拒绝
            expect(sqlite3.IntegrityError, lambda: store._conn.execute(
                "UPDATE pipeline_events SET payload = ? WHERE payload LIKE ?",
                (json.dumps({"event_type": "NOTE", "attempt": "att-2",
                             "result": "RUNNING"}, sort_keys=True), "%att-1%")))
            # 2) 正当路径：追加新 attempt
            h2, ins = store.append({"event_type": "NOTE", "attempt": "att-2",
                                    "result": "RUNNING", "retry_of": "att-1",
                                    "ts": "2026-10-08T01:00:00Z"})
            assert ins is True
            # 3) 旧证据不变；新 attempt 落账；链完好
            rows = rows_of(store._conn,
                           "SELECT seq, payload, prev_event_hash, event_hash "
                           "FROM pipeline_events ORDER BY seq")
            assert rows[0] == old[0], "旧 FAILED 证据被覆盖/改动"
            assert rows[1][1] != old[0][1] and rows[1][3] == h2
            assert store.head() == (h2, 2)
            assert store.verify_chain()["ok"] is True
            both = rows_of(store._conn,
                           "SELECT COUNT(*) FROM pipeline_events "
                           "WHERE payload LIKE '%att-%'")[0][0]
            assert both == 2
        finally:
            store.close()
    return {"overwrite_attempt": "rejected",
            "old_evidence_byte_identical": True,
            "attempts_in_ledger": ["att-1 (FAILED)", "att-2 (new, RUNNING)"],
            "chain_verified": True,
            "boundary": "attempt_id 分配/AttemptImmutabilityError 在 wenqu_pipeline"}


# ---------------------------------------------------------------------- #
# STATE-10：WAITING/FAILED attempt 直接改回 RUNNING → 拒绝；
#           追加新 attempt 后（projection 由管道层指向它）
# ---------------------------------------------------------------------- #
def test_STATE_10_terminal_attempt_no_direct_running_new_attempt_ok():
    """注入：WAITING 残留 attempt 与 FAILED attempt 各一条证据行；
    尝试把它们『直接改回 RUNNING』。

    期望（被测体已实现面·前半句）：
      1) UPDATE 行改 RUNNING → 拒绝（两行都拒）；
      2) 伪造 ATTEMPT_/RUNNING 控制事件 → 拒绝；
      （后半句）追加新 attempt 事件是允许的出路：新事件落账、
      旧 WAITING/FAILED 行原样保留（projection 读账决定指向——该读侧
      逻辑在 RunManager，本文件不越界重造）。
    """
    with TmpDir("ac-s10-") as td:
        db = os.path.join(td, "ev.db")
        store = EventStore(db)
        try:
            store.append({"event_type": "NOTE", "attempt": "att-1",
                          "status": "WAITING", "why": "manual-gate"})
            store.append({"event_type": "NOTE", "attempt": "att-2",
                          "status": "FAILED", "why": "timeout"})
            snap = rows_of(store._conn,
                           "SELECT seq, payload, event_hash FROM pipeline_events "
                           "ORDER BY seq")
            # 1) 两行直接 UPDATE 改 RUNNING → 全拒
            for marker in ("WAITING", "FAILED"):
                expect(sqlite3.IntegrityError, lambda m=marker: store._conn.execute(
                    "UPDATE pipeline_events SET payload = replace(payload, ?, "
                    "'RUNNING')", (m,)))
            # 2) 伪造控制事件改状态 → 拒绝
            for forged in ({"event_type": "ATTEMPT_RESUMED", "attempt": "att-1",
                            "status": "RUNNING"},
                           {"event_type": "RUN_RUNNING", "attempt": "att-2"},
                           {"event_type": "WAITING_RESUMED", "attempt": "att-1"}):
                expect(ValueError, lambda ev=forged: store.append(ev))
            # 3) 正道：追加新 attempt；旧行原样保留
            h3, ins = store.append({"event_type": "NOTE", "attempt": "att-3",
                                    "status": "RUNNING",
                                    "continues_from": ["att-1", "att-2"]})
            assert ins is True
            rows = rows_of(store._conn,
                           "SELECT seq, payload, event_hash FROM pipeline_events "
                           "ORDER BY seq")
            assert rows[0] == snap[0] and rows[1] == snap[1], \
                "WAITING/FAILED 旧行被改动或被删"
            assert store.head() == (h3, 3)
            assert store.verify_chain()["ok"] is True
            still = rows_of(store._conn, "SELECT COUNT(*) FROM pipeline_events "
                            "WHERE payload LIKE '%WAITING%'")[0][0]
            assert still == 1
        finally:
            store.close()
    return {"direct_update_to_running": "rejected (WAITING & FAILED rows)",
            "forged_control_transitions": "rejected",
            "new_attempt_appended": "att-3",
            "old_rows_preserved": ["att-1 WAITING", "att-2 FAILED"],
            "boundary": "stage projection 指向新 attempt 在 RunManager（禁 import）"}


# ---------------------------------------------------------------------- #
# 合成旧账 fixture 构造器（MIG 族共用；均为合成数据，非生产账本）
# ---------------------------------------------------------------------- #
def _write_lines(dirpath, name, lines):
    path = os.path.join(dirpath, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def _sidecar_records(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                out.append(json.loads(ln))
    return out


# ---------------------------------------------------------------------- #
# MIG-01：坏 JSON/未知状态 → quarantine+BLOCKED
# ---------------------------------------------------------------------- #
def test_MIG_01_bad_json_unknown_status_quarantine():
    """注入（合成旧账）：坏 JSON、非对象 JSON、缺 status/ts、未知状态；
    对照组：已知别名（含 ERROR→BLOCKED 的 fail-closed 归一）。

    期望（被测体已实现面·P0-6 第六轮统一正源契约）：坏行一律 quarantine
    （reason 精确），绝不进入唯一事件表 pipeline_events；导入行经公共
    EventStore.append 落同一哈希链（单一事件表+单一写入 API），migration_runs
    记 quarantined 计数；sidecar 逐行留痕；ERROR/BLOCKED 行按已知状态
    BLOCKED 入链——绝不把坏行洗成绿。
    """
    with TmpDir("ac-m1-") as td:
        src = os.path.join(td, "legacy"); os.makedirs(src)
        lines = [
            '{"status": "PASS", "ts": "2026-10-01T00:00:00Z", "id": 1}',
            '{"status": "ERROR", "ts": "2026-10-01T00:01:00Z", "id": 2}',
            '{"status": "BLOCKED", "ts": "2026-10-01T00:02:00Z", "id": 3}',
            '{"status": "OK", "ts": "2026-10-01T00:03:00Z", "id": 4}',
            '{"status": "FIXED", "ts": "2026-10-01T00:04:00Z", "id": 5}',
            '{broken json',
            '["not", "an", "object"]',
            '"just a string"',
            '{"status": "PASS"}',
            '{"ts": "2026-10-01T00:05:00Z"}',
            '{"status": "", "ts": "2026-10-01T00:06:00Z"}',
            '{"status": "WEIRD_STATE", "ts": "2026-10-01T00:07:00Z"}',
            '',
            '   ',
        ]
        _write_lines(src, "legacy-a.jsonl", lines)
        db = os.path.join(td, "mig.db")
        mig = LedgerMigrator(src, db)
        report = mig.migrate()

        c = report["conservation"]
        assert c["lines_total"] == 12, c          # 空白行不计分母
        assert c["imported"] == 5 and c["quarantined"] == 7 and c["duplicates"] == 0
        assert report["conserved"] is True
        assert report["imported_status_counts"] == {
            "BLOCKED": 2, "FIXED_PENDING_VERIFY": 1, "PASS": 2}
        assert report["quarantine_reasons"] == {
            "invalid_json": 1, "missing_field:status": 2, "missing_field:ts": 1,
            "not_a_json_object": 2, "unknown_status:WEIRD_STATE": 1}
        # P0-6 第六轮：统一正源锚点字段
        assert report["event_table"] == "pipeline_events"
        assert report["write_api"] == "EventStore.append"

        conn = sqlite3.connect(db)
        try:
            assert_single_event_table(conn)      # 唯一事件表（无第二 events 表）
            mig_rows = unified_payloads(conn, MIGRATION_EVENT_TYPE)
            statuses = {}
            for o in mig_rows:
                statuses[o["status"]] = statuses.get(o["status"], 0) + 1
            assert len(mig_rows) == 5
            assert statuses == {"BLOCKED": 2, "FIXED_PENDING_VERIFY": 1,
                                "PASS": 2}
            # 坏行绝不在唯一事件表里（按导入行 raw 逐条比对，不信 LIKE）
            imported_raws = {o["raw"] for o in mig_rows}
            for bad in ('{broken json', '["not", "an", "object"]',
                        '"just a string"', '{"status": "PASS"}',
                        '{"ts": "2026-10-01T00:05:00Z"}',
                        '{"status": "", "ts": "2026-10-01T00:06:00Z"}',
                        '{"status": "WEIRD_STATE", "ts": "2026-10-01T00:07:00Z"}'):
                assert bad not in imported_raws, f"坏行被导入: {bad}"
            # 事件负载是行内容的纯函数：line_sha 与 raw 逐条对应，
            # event_id = sha256(canonical payload)（与 EventStore 同一幂等键）
            for o, row in zip(mig_rows, unified_rows(conn)):
                assert o["line_sha"] == hashlib.sha256(
                    o["raw"].encode("utf-8")).hexdigest()
                assert o["event_type"] == MIGRATION_EVENT_TYPE
                canon = json.dumps(o, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False)
                assert row[1] == hashlib.sha256(
                    canon.encode("utf-8")).hexdigest()
            run = rows_of(conn, "SELECT files_scanned, lines_total, imported, "
                              "duplicates, quarantined, conserved FROM "
                              "migration_runs")
            assert run == [(1, 12, 5, 0, 7, 1)]
        finally:
            conn.close()
        # 迁移产物与 EventStore 同表同链（唯一正源运行时证明）
        assert_migration_chain(db, 5)
        recs = _sidecar_records(mig.sidecar_path)
        quarantined = [r for r in recs if r["decision"] == "quarantined"]
        imported = [r for r in recs if r["decision"] == "imported"]
        assert len(quarantined) == 7 and len(imported) == 5
        assert {r["reason"] for r in quarantined} == {
            "invalid_json", "missing_field:status", "missing_field:ts",
            "not_a_json_object", "unknown_status:WEIRD_STATE"}
        # 导入行按已知状态入账：ERROR/BLOCKED 两行均以 BLOCKED 状态落库
        assert sorted(r["status"] for r in imported) == [
            "BLOCKED", "BLOCKED", "FIXED_PENDING_VERIFY", "PASS", "PASS"]
        # 单元面：classify 的 quarantine 判定矩阵
        for bad in ('{nope', '[1]', 'null', '"s"', '{"status":"X","ts":"t"}',
                    '{"status":"PASS"}', '{"ts":"t"}'):
            v = LedgerMigrator.classify(bad)
            assert v["decision"] == "quarantine", bad
        assert LedgerMigrator.classify(
            '{"status": "ERROR", "ts": "t"}')["status"] == "BLOCKED"
    return {"quarantined": 7, "imported": 5,
            "imported_status_counts": {"BLOCKED": 2, "PASS": 2,
                                       "FIXED_PENDING_VERIFY": 1},
            "bad_lines_in_pipeline_events": 0,
            "single_event_table": "pipeline_events",
            "write_api": "EventStore.append",
            "chain_verified_len": 5,
            "boundary": "run 级 BLOCKED 聚合在编排层（不在被测体）"}


# ---------------------------------------------------------------------- #
# MIG-02：缺审批信息的 ACCEPTED → invalid/reopen
# ---------------------------------------------------------------------- #
def test_MIG_02_accepted_missing_approval_invalid_reopen():
    """注入（合成旧账）：四类 ACCEPTED 行——缺 ts、缺审批要素、带看似完整的
    审批信息、以及一个对照组合法 PASS 行。

    期望（被测体已实现面·P0-6 第六轮统一正源契约）：ACCEPTED 对迁移器是
    未知状态——无论审批信息缺不缺，一律 invalid 进 quarantine（绝不猜映射
    成 PASS），零导入（唯一事件表 pipeline_events 中零 ACCEPTED 行）；
    quarantine + sidecar 留痕即待人工 reopen 的账（重进正源必须人工再录），
    绝不静默放行、绝不静默丢弃。
    """
    with TmpDir("ac-m2-") as td:
        src = os.path.join(td, "legacy"); os.makedirs(src)
        lines = [
            '{"status": "ACCEPTED", "ts": "2026-10-01T00:00:00Z", "id": 1}',
            '{"status": "ACCEPTED", "ts": "2026-10-01T00:01:00Z", "id": 2, '
            '"approval": {"approved_by": "u1", "risk": "P3", '
            '"fingerprint": "abc", "expires": "2026-12-01"}}',
            '{"status": "ACCEPTED"}',
            '{"status": "accepted", "ts": "2026-10-01T00:02:00Z", "id": 3}',
            '{"status": "PASS", "ts": "2026-10-01T00:03:00Z", "id": 4}',
        ]
        _write_lines(src, "accepted-ledger.jsonl", lines)
        db = os.path.join(td, "mig.db")
        mig = LedgerMigrator(src, db)
        report = mig.migrate()

        c = report["conservation"]
        assert c["lines_total"] == 5
        assert c["imported"] == 1 and c["quarantined"] == 4, c
        assert report["quarantine_reasons"] == {
            "missing_field:ts": 1, "unknown_status:ACCEPTED": 3}
        assert report["event_table"] == "pipeline_events"
        conn = sqlite3.connect(db)
        try:
            assert_single_event_table(conn)
            mig_rows = unified_payloads(conn, MIGRATION_EVENT_TYPE)
            assert len(mig_rows) == 1 and mig_rows[0]["status"] == "PASS"
            accepted_in_db = sum(
                1 for o in unified_payloads(conn)
                if "ACCEPTED" in o["raw"] or "accepted" in o["raw"])
            assert accepted_in_db == 0, "ACCEPTED 行被导入（不允许）"
        finally:
            conn.close()
        assert_migration_chain(db, 1)
        recs = _sidecar_records(mig.sidecar_path)
        q = [r for r in recs if r["decision"] == "quarantined"]
        assert len(q) == 4
        assert all("preview" in r for r in q), "quarantine 必须带原文预览（reopen 线索）"
    return {"accepted_lines": 4, "quarantined": 4, "accepted_imported": 0,
            "imported_total": 1,
            "accepted_in_pipeline_events": 0,
            "reopen_channel": "quarantine + sidecar 预览（人工再录）",
            "boundary": "risk acceptance/reopen 事件子系统（FND-016）不在被测体"}


# ---------------------------------------------------------------------- #
# MIG-03：两次迁移 → 结果幂等一致
# ---------------------------------------------------------------------- #
def test_MIG_03_double_migration_idempotent():
    """注入（合成旧账）：同一账本连续两次完整迁移（两个独立迁移器实例）。

    期望（被测体已实现面·P0-6 第六轮统一正源契约）：结果幂等一致——
    唯一事件表 pipeline_events 行集逐字节相同（快照对比），第二次
    imported=0、原导入行全部计为 duplicate（内容寻址幂等键）；链头
    hash/总行数在第二次迁移后零变化；两次守恒均成立；源 JSONL 全程
    只读（前后字节一致）；sidecar 只追加。
    """
    with TmpDir("ac-m3-") as td:
        src = os.path.join(td, "legacy"); os.makedirs(src)
        lines = [
            '{"status": "PASS", "ts": "2026-10-01T00:00:00Z", "id": 1}',
            '{"status": "FAILED", "ts": "2026-10-01T00:01:00Z", "id": 2}',
            '{"status": "WARN", "ts": "2026-10-01T00:02:00Z", "id": 3}',
            '{"status": "PASS", "ts": "2026-10-01T00:00:00Z", "id": 1}',
            '{"status": "MYSTERY", "ts": "2026-10-01T00:03:00Z"}',
            'oops',
        ]
        src_file = _write_lines(src, "dup-ledger.jsonl", lines)
        before_bytes = open(src_file, "rb").read()

        db = os.path.join(td, "mig.db")
        r1 = LedgerMigrator(src, db).migrate()
        conn = sqlite3.connect(db)
        try:
            snap1 = unified_rows(conn)
            assert_single_event_table(conn)
        finally:
            conn.close()
        head1 = assert_migration_chain(db, 3)
        sc1 = open(os.path.join(td, "mig.db.migration-sidecar.jsonl"),
                   "rb").read()

        r2 = LedgerMigrator(src, db).migrate()     # 第二个实例、同一库
        conn = sqlite3.connect(db)
        try:
            snap2 = unified_rows(conn)
        finally:
            conn.close()
        head2 = assert_migration_chain(db, 3)
        sc2 = open(os.path.join(td, "mig.db.migration-sidecar.jsonl"),
                   "rb").read()

        assert snap1 == snap2, "二次迁移改动了已导入行集（不幂等）"
        assert head1 == head2, "二次迁移后链头变化（幂等破坏）"
        assert sc2.startswith(sc1) and len(sc2) > len(sc1), "sidecar 必须只追加"
        assert open(src_file, "rb").read() == before_bytes, "源账本被改动（M1 违规）"
        c1, c2 = r1["conservation"], r2["conservation"]
        assert c1["imported"] == 3 and c1["duplicates"] == 1 \
            and c1["quarantined"] == 2 and c1["lines_total"] == 6
        assert c2["imported"] == 0 and c2["duplicates"] == 4 \
            and c2["quarantined"] == 2 and c2["lines_total"] == 6
        assert r1["conserved"] is True and r2["conserved"] is True
        assert r1["imported_status_counts"] == {
            "CONDITIONAL": 1, "FAIL": 1, "PASS": 1}
        # r2 无新导入，status 计数为空是正确表现（幂等：不再重复入账）
        assert r2["imported_status_counts"] == {}
        assert r1["event_table"] == r2["event_table"] == "pipeline_events"
        conn = sqlite3.connect(db)
        try:
            assert rows_of(conn, "SELECT COUNT(*) FROM migration_runs")[0][0] == 2
        finally:
            conn.close()
    return {"run1": {"imported": 3, "duplicates": 1, "quarantined": 2},
            "run2": {"imported": 0, "duplicates": 4, "quarantined": 2},
            "pipeline_events_rows_identical": True,
            "head_hash_stable": True,
            "source_bytewise_unchanged": True,
            "sidecar_append_only": True}


# ---------------------------------------------------------------------- #
# MIG-04：源行数不守恒 → 迁移失败
# ---------------------------------------------------------------------- #
def test_MIG_04_source_conservation_enforced():
    """注入（合成旧账 + 三类真实破坏）：
      (a) 迁移后对统一事件表直接删行（账本少行=不守恒态的旧攻击面）；
      (b) 审计 sidecar 落在一个目录路径上（任何 OS/用户都写不开）；
      (c) sqlite 目标落在一个目录路径上（根本开不了库）。

    期望（被测体已实现面·P0-6 第六轮统一正源契约）：
      (a) pipeline_events 由 append-only 触发器守卫：定向删行与全表删行
          全部被拒——旧版独立 events 表「删行造成少账、再靠重迁移补账」
          的向量在统一表上关闭（比补账更强的不变量：行根本删不掉）；
          随后重迁移幂等：imported=0、全部计 duplicate、行集/链头零变化，
          守恒等式 lines==imported+duplicates+quarantined 在
          DB/sidecar 独立对账下成立，绝不静默少账；
      (b) 审计不可写 → 迁移整体失败（异常抛出），统一表零导入行、
          migration_runs 零行——没有部分导入、没有假守恒记账；
      (c) 开不了库 → 迁移失败（异常抛出）。
    诚实边界：ConservationError 守卫本身是防御性的——migrate 的计数与
    处理循环遍历同一 list，公共 API 构造不出账目不平（已代码通读+注入
    尝试实证），故此处以同秩语义的运行时面做真实验证；旧版「删行后重
    迁移精确补账」子场景在 append-only 统一表上不可构造（删行被触发器
    拒绝），其保证由更强的「删不掉」不变量承接。
    """
    with TmpDir("ac-m4-") as td:
        src = os.path.join(td, "legacy"); os.makedirs(src)
        n_valid = 9
        lines = ['{"status": "PASS", "ts": "2026-10-01T00:00:00Z", "id": %d}' % i
                 for i in range(n_valid)]
        lines += ['{"status": "GHOST", "ts": "t"}', '{bad']
        _write_lines(src, "conserved.jsonl", lines)
        db = os.path.join(td, "mig.db")

        r1 = LedgerMigrator(src, db).migrate()
        assert r1["conserved"] and r1["conservation"]["imported"] == n_valid

        # 独立对账（不信 report，直接从源文件/统一表/sidecar 重数）
        src_nonblank = sum(1 for ln in open(os.path.join(src, "conserved.jsonl"),
                                            encoding="utf-8") if ln.strip())
        conn = sqlite3.connect(db)
        try:
            db_rows = len(unified_payloads(conn, MIGRATION_EVENT_TYPE))
            quarantined_shas = {r["line_sha"] for r in
                                _sidecar_records(db + ".migration-sidecar.jsonl")
                                if r["decision"] == "quarantined"}
            assert_single_event_table(conn)
        finally:
            conn.close()
        src_shas = {r["line_sha"] for r in LedgerMigrator(src, db).scan()}
        assert src_nonblank == db_rows + len(quarantined_shas)
        assert quarantined_shas <= src_shas and db_rows == n_valid

        # (a) 删行攻击 → append-only 触发器拒绝（统一表上少账向量关闭）
        conn = sqlite3.connect(db)
        try:
            expect(sqlite3.IntegrityError, lambda: conn.execute(
                "DELETE FROM pipeline_events WHERE seq IN (2, 3, 4)"))
            expect(sqlite3.IntegrityError, lambda: conn.execute(
                "DELETE FROM pipeline_events"))
            snap_before = unified_rows(conn)
        finally:
            conn.close()
        head_before = assert_migration_chain(db, n_valid)

        # 重迁移幂等：零新导入、行集/链头零变化、守恒成立（绝不静默少账）
        r2 = LedgerMigrator(src, db).migrate()
        assert r2["conservation"]["imported"] == 0
        assert r2["conservation"]["duplicates"] == n_valid
        assert r2["conserved"] is True
        conn = sqlite3.connect(db)
        try:
            assert unified_rows(conn) == snap_before, "重迁移改动已入链行集"
            assert len(unified_payloads(conn, MIGRATION_EVENT_TYPE)) == n_valid
        finally:
            conn.close()
        head_after = assert_migration_chain(db, n_valid)
        assert head_before == head_after

        # (b) sidecar 写不开（目录路径；对 root 也成立）→ 整体失败、零部分账
        side_dir = os.path.join(td, "sidecar-is-dir"); os.makedirs(side_dir)
        db_b = os.path.join(td, "fail-sidecar.db")
        try:
            LedgerMigrator(src, db_b, sidecar_path=side_dir).migrate()
            raise AssertionError("sidecar 不可写时迁移竟成功（假绿）")
        except (IsADirectoryError, PermissionError, OSError):
            pass
        conn = sqlite3.connect(db_b)
        try:
            assert count_rows(conn, "pipeline_events") == 0
            assert count_rows(conn, "migration_runs") == 0
        finally:
            conn.close()

        # (c) 目标库开不了（目录路径）→ 迁移失败
        try:
            LedgerMigrator(src, side_dir).migrate()
            raise AssertionError("开不了库时迁移竟成功（假绿）")
        except sqlite3.Error:
            pass
    return {"independent_recount": {"source_nonblank": src_nonblank,
                                    "db_rows": n_valid, "quarantined": 2},
            "delete_attacks": "rejected (append-only trigger，定向+全表)",
            "remigration_after_delete_attempt": {"imported": 0,
                                                 "duplicates": n_valid,
                                                 "rows_unchanged": True},
            "unwritable_sidecar": "迁移失败，pipeline_events=0、migration_runs=0",
            "unopenable_db": "迁移失败（异常）",
            "boundary": "ConservationError 为防御性守卫（公共 API 构造不出不平，"
                        "已实证）；此处验证同秩运行时语义；旧版删后补账"
                        "子场景由 append-only「删不掉」不变量承接"}


# ---------------------------------------------------------------------- #
# MIG-05：project key 冲突 → 明确冲突，不拆成假项目
# ---------------------------------------------------------------------- #
def test_MIG_05_project_key_conflict_explicit_no_fake_split():
    """注入（合成旧账）：多 project 身份字段（project_id/project/repo_id/
    repo/task）值不一致的行；对照组：一致多字段行、单字段行、无 project
    行、复杂值（dict）字段行、超长冲突值。

    期望（被测体已实现面·P0-6 第六轮 MIG-05 最小实现）：
      1) 冲突行 → 显式 quarantine，reason 形如
         ``project_key_conflict:<fA>=<vA>!=<fB>=<vB>``（值截断 40 字符），
         绝不静默选边导入任一冲突方——「不拆成假项目」：冲突双方任何
         project 值都不得出现在事件库；
      2) 一致行 → project_id 贯通进事件负载（§14.3 canonical repo_id
         映射的最小实现）；无 project 字段的行负载形状与既往完全一致
         （无 project_id 键）；复杂值字段视为缺席（绝不 stringify 成假
         project key）；
      3) report 单独聚合 project_key_conflicts；二次迁移幂等
         （imported=0、导入行全计 duplicate、冲突行重复 quarantine）。
    """
    # 单元面：extract_project_ids 只取标量非空值，按 PROJECT_FIELDS 顺序
    assert PROJECT_FIELDS == ("project_id", "project", "repo_id", "repo", "task")
    ids = extract_project_ids({
        "task": "t-x", "project": "p-x", "repo": "p-x", "flag": True,
        "zero": 0, "nil": None, "empty": "  ", "lst": [1], "dct": {"k": 1}})
    assert ids == {"project": "p-x", "repo": "p-x", "task": "t-x"}, ids
    assert extract_project_ids({"n": 5}) == {}       # n 不在 PROJECT_FIELDS 表内
    assert extract_project_ids({"repo_id": 42}) == {"repo_id": "42"}

    with TmpDir("ac-m5-") as td:
        src = os.path.join(td, "legacy"); os.makedirs(src)
        long_a, long_b = "a" * 45, "b" * 45
        conflict_a = ('{"status": "PASS", "ts": "t1", "id": 1, '
                      '"project_id": "repo-a", "repo": "repo-b"}')
        conflict_b = ('{"status": "PASS", "ts": "t2", "id": 2, '
                      '"project": "wenqu", "task": "erp-main"}')
        consistent = ('{"status": "FAIL", "ts": "t3", "id": 3, '
                      '"project_id": "wenqu", "repo": "wenqu", "task": "wenqu"}')
        single = '{"status": "WARN", "ts": "t4", "id": 4, "repo_id": "R1"}'
        no_project = '{"status": "PASS", "ts": "t5", "id": 5}'
        dict_ignored = ('{"status": "BLOCKED", "ts": "t6", "id": 6, '
                        '"project_id": {"evil": "dict"}, "task": "T6"}')
        conflict_long = json.dumps(
            {"status": "PASS", "ts": "t7", "id": 7,
             "project_id": long_a, "repo": long_b})
        _write_lines(src, "project-ledger.jsonl", [
            conflict_a, conflict_b, consistent, single, no_project,
            dict_ignored, conflict_long])

        # classify 单元面：冲突判定与 reason 形态
        v = LedgerMigrator.classify(conflict_a)
        assert v["decision"] == "quarantine"
        assert v["reason"] == "project_key_conflict:project_id=repo-a!=repo=repo-b"
        v2 = LedgerMigrator.classify(conflict_long)
        assert v2["decision"] == "quarantine" and v2["reason"] == (
            f"project_key_conflict:project_id={long_a[:40]}!=repo={long_b[:40]}")
        assert LedgerMigrator.classify(consistent) == {
            "decision": "import", "status": "FAIL", "project_id": "wenqu",
            "reason": None,
            "line_sha": LedgerMigrator.classify(consistent)["line_sha"]}

        db = os.path.join(td, "mig.db")
        r1 = LedgerMigrator(src, db).migrate()
        c = r1["conservation"]
        assert c["lines_total"] == 7
        assert c["imported"] == 4 and c["duplicates"] == 0 \
            and c["quarantined"] == 3, c
        assert r1["conserved"] is True
        # 冲突显式聚合（report["project_key_conflicts"] 单独成清单）
        assert set(r1["project_key_conflicts"]) == {
            "project_key_conflict:project_id=repo-a!=repo=repo-b",
            "project_key_conflict:project=wenqu!=task=erp-main",
            f"project_key_conflict:project_id={long_a[:40]}!=repo={long_b[:40]}"}
        assert sum(r1["project_key_conflicts"].values()) == 3
        assert r1["imported_status_counts"] == {
            "BLOCKED": 1, "CONDITIONAL": 1, "FAIL": 1, "PASS": 1}

        conn = sqlite3.connect(db)
        try:
            assert_single_event_table(conn)
            mig_rows = unified_payloads(conn, MIGRATION_EVENT_TYPE)
            assert len(mig_rows) == 4
            by_raw = {o["raw"]: o for o in mig_rows}
            # 「不拆成假项目」：冲突双方 project 值绝不进库（零选边、零拆分）
            all_payload_text = "\n".join(
                p for (p,) in rows_of(conn, "SELECT payload FROM pipeline_events"))
            for banned in ("repo-a", "repo-b", "erp-main", long_a, long_b):
                assert banned not in all_payload_text, f"冲突方 {banned} 泄入库"
            # 冲突行整行绝不导入
            for bad_raw in (conflict_a, conflict_b, conflict_long):
                assert bad_raw not in by_raw
            # project_id 贯通：一致行/单字段行/复杂值忽略行
            assert by_raw[consistent]["project_id"] == "wenqu"
            assert by_raw[single]["project_id"] == "R1"
            assert by_raw[dict_ignored]["project_id"] == "T6"
            # 无 project 行：负载无 project_id 键（形状与既往逐字节一致）
            assert "project_id" not in by_raw[no_project]
            # project_id 进负载即参与内容寻址幂等键（event_id 纯函数性）
            for o, row in zip(mig_rows, unified_rows(conn)):
                canon = json.dumps(o, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False)
                assert row[1] == hashlib.sha256(
                    canon.encode("utf-8")).hexdigest()
        finally:
            conn.close()
        assert_migration_chain(db, 4)

        # 幂等：二次迁移 imported=0、导入行全 duplicate、冲突行重复 quarantine
        r2 = LedgerMigrator(src, db).migrate()
        c2 = r2["conservation"]
        assert c2["imported"] == 0 and c2["duplicates"] == 4 \
            and c2["quarantined"] == 3 and r2["conserved"] is True
        assert r2["project_key_conflicts"] == r1["project_key_conflicts"]
        assert_migration_chain(db, 4)

        # sidecar 逐行留痕：冲突行 quarantine 记录带原文预览
        recs = _sidecar_records(db + ".migration-sidecar.jsonl")
        q = [r for r in recs if r["decision"] == "quarantined"]
        assert len(q) == 6                       # 3 冲突 × 两次运行
        assert all(r.get("reason", "").startswith(PROJECT_KEY_CONFLICT_PREFIX)
                   for r in q)
        assert all("preview" in r for r in q)
    return {"conflict_rows_quarantined": 3, "imported_with_project": 3,
            "imported_without_project_key": 1,
            "conflict_values_in_db": 0,
            "project_key_conflict_reasons": sorted(
                r1["project_key_conflicts"]),
            "idempotent_rerun": {"imported": 0, "duplicates": 4,
                                 "quarantined": 3},
            "boundary": "§21.1 canonical repo_id 冻结映射/fingerprint "
                        "collision 表在编排层（不在被测体）"}


# ====================================================================== #
# wave6/P1F B 组：STATE-02/05/09/11（被测体 = wenqu_core/wenqu_pipeline.py）
# 方案 §20.2/§20.5 注入/期望逐字对齐；负例必拒，断言只增不减。
# ====================================================================== #
W6_IDENT = {
    "commit_sha": "a" * 40,
    "environment": "staging",
    "scope_hash": "scope-w6-001",
    "repo_id": "wenqu-dist",
    "ruleset_hash": "rules-w6",
    "policy_hash": "policy-w6-001",
}

_W6_KEYRING = ApprovalKeyring.from_path(
    os.path.join(HERE, "fixtures", "approval-keys.json"))
_W6_KEY_ID = "key_test_1"
_W6_SECRET = _W6_KEYRING.get(_W6_KEY_ID)


def _w6_manager(db_path, epoch=None):
    """构造 B 组 RunManager（共享测试 keyring；epoch 传入即启用 fencing）。"""
    return RunManager(EventStore(db_path), keyring=_W6_KEYRING,
                      writer_epoch=epoch)


def _w6_sign(ap):
    ap = dict(ap)
    ap.pop("signature", None)
    ap["signature"] = sign_envelope(_W6_SECRET, ap)
    return ap


def _w6_resume_approval(run_id, stop_event_id, stop_type, state_version,
                        task_id, stage="S1_REQUIREMENT", preconditions=None,
                        nonce="nonce-w6-reserve-0001", **over):
    """approval-v2 resume 全信封 + HMAC 签名（B 组停等恢复负例用）。"""
    pre = dict(preconditions if preconditions is not None
               else {"gate_reference": "gate-w6", "rollback_level": "R2"})
    ap = {
        "schema_version": "2.0", "approval_id": "apr_w6_resume",
        "approval_type": "resume", "key_id": _W6_KEY_ID,
        "run_id": run_id, "task_id": task_id,
        "stop_event_id": stop_event_id, "stop_type": stop_type,
        "stage": stage, "environment": W6_IDENT["environment"],
        "authorized_scope": W6_IDENT["scope_hash"],
        "policy_hash": W6_IDENT["policy_hash"],
        "ruleset_hash": W6_IDENT["ruleset_hash"],
        "input_watermark": W6_IDENT["commit_sha"],
        "actor": "w6-test", "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_state_version": state_version,
        "nonce": nonce, "decision": "approve",
        "payload": {"stop_event_id": stop_event_id, "stop_type": stop_type,
                    "objective_precondition_hash":
                        _SM.objective_precondition_hash(pre)},
    }
    ap.update(over)
    return _w6_sign(ap), pre


def _w6_risk_approval(run_id, task_id, state_version, fingerprints=("fp-w6",),
                     stage="S7_GATE", nonce="nonce-w6-risk-0001", **over):
    """approval-v2 risk 全信封 + HMAC 签名（B 组授权负例/正例用）。"""
    ap = {
        "schema_version": "2.0", "approval_id": "apr_w6_risk",
        "approval_type": "risk", "key_id": _W6_KEY_ID,
        "run_id": run_id, "task_id": task_id,
        "stop_event_id": "n/a-soft-terminal", "stop_type": "scope",
        "stage": stage, "environment": W6_IDENT["environment"],
        "authorized_scope": W6_IDENT["scope_hash"],
        "policy_hash": W6_IDENT["policy_hash"],
        "ruleset_hash": W6_IDENT["ruleset_hash"],
        "input_watermark": W6_IDENT["commit_sha"],
        "actor": "w6-test", "issued_at": "2026-10-08T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "expected_state_version": state_version,
        "nonce": nonce, "decision": "approve",
        "payload": {"finding_fingerprints": list(fingerprints),
                    "severity": "MEDIUM", "reason": "w6 conditional residual",
                    "compensating_controls": ["ctrl-w6"],
                    "expiry": "2099-12-31T00:00:00Z"},
    }
    ap.update(over)
    return _w6_sign(ap)


# ---------------------------------------------------------------------- #
# STATE-02：`../`、绝对路径、NUL、超长 ID → 拒绝
# ---------------------------------------------------------------------- #
def test_STATE_02_traversal_absolute_nul_overlong_ids_rejected():
    """注入：`../`、绝对路径、NUL、超长 ID——wenqu_pipeline 三个调用方可控
    ID 面（create_run task_id / 公开 API run_id / register_finding
    finding_id）逐一命中。

    期望：全部结构层拒绝（InvalidRunIdError/PipelineError），坏 ID 零事件
    落账；对照组（合法 ID / 格式合法但未知的 run_id）正常放行或走
    RunNotFoundError——证明拒绝面精确针对 ID 结构，不是 fail-everything。
    """
    bad_ids = [
        "../evil",                    # 相对路径穿越
        "../../etc/passwd",           # 深层穿越
        "/etc/passwd",                # 绝对路径
        "run_nul\x00id",              # NUL 字节
        "x" * 65,                     # 超长（>64）
        "a/b",                        # POSIX 路径分隔符
        "a\\b",                       # Windows 路径分隔符
        "..",                         # 纯穿越段
    ]
    with TmpDir("ac-s2w6-") as td:
        db = os.path.join(td, "events.db")
        mgr = _w6_manager(db)
        # 面 1：create_run 的 task_id（../、绝对路径、NUL、超长全拒）
        for bad in bad_ids:
            expect(PipelineError, lambda b=bad: mgr.create_run(b, W6_IDENT))
        # 面 2：全部公开 API 的 run_id（_validate_run_id 单闸口；get_run 与
        # 变更类各验一个代表 + 其余经同一 _load_state 闸口）
        for bad in bad_ids:
            expect(InvalidRunIdError, lambda b=bad: mgr.get_run(b))
            expect(InvalidRunIdError, lambda b=bad: mgr.advance_stage(b))
            expect(InvalidRunIdError, lambda b=bad: mgr.cancel_run(b))
            expect(InvalidRunIdError, lambda b=bad: mgr.complete_run(b))
            expect(InvalidRunIdError,
                   lambda b=bad: mgr.adjudicate_gate_conditional(b))
        # 面 3：register_finding 的 finding_id（fnd_ 前缀 + 注入载荷）
        run_id = mgr.create_run("task_w6_ids", W6_IDENT)["run_id"]
        mgr.advance_stage(run_id)
        for bad in bad_ids:
            fid = "fnd_" + bad
            expect(PipelineError,
                   lambda f=fid: mgr.register_finding(
                       run_id, f, "fp-w6", "MEDIUM", "P2"))
        # 坏 ID 零落账：事件流只含正道三事件（RUN_CREATED/STAGE_STARTED/对照 finding）
        rows = rows_of(mgr._db._conn, "SELECT payload FROM pipeline_events")
        assert len(rows) == 2, f"坏 ID 路径产生了额外事件: {len(rows)}"
        mgr.register_finding(run_id, "fnd_w6_ok", "fp-w6", "MEDIUM", "P2")
        # 对照组合法面：合法 task_id/run_id/finding_id 正常放行；格式合法但
        # 未知的 run_id 走 RunNotFoundError（结构校验通过，非结构拒绝）
        ok_run = mgr.create_run("task_w6_ok-1", W6_IDENT)["run_id"]
        assert ok_run.startswith("run_") and len(ok_run) <= 64
        expect(_wp.RunNotFoundError, lambda: mgr.get_run("run_ghost_valid"))
        assert mgr._store.verify_chain()["ok"]
    return {"rejected_id_kinds": len(bad_ids),
            "surfaces": ["create_run.task_id", "public API run_id "
                         "(get/advance/cancel/complete/adjudicate)",
                         "register_finding.finding_id"],
            "bad_id_events_written": 0,
            "valid_ids_pass": True,
            "wellformed_unknown_run": "RunNotFoundError（结构校验通过）"}


# ---------------------------------------------------------------------- #
# STATE-05：双 writer epoch → 所有写入拒绝
# ---------------------------------------------------------------------- #
def test_STATE_05_dual_writer_epoch_all_writes_rejected():
    """注入：双 writer epoch——epoch 1 的写者建流写入后，epoch 2 的新写者
    接管同一 run 事件流；旧写者尝试一切写入路径。

    期望（§20.2 逐字）：旧 epoch writer 的**所有写入**拒绝——
      1) 全部变更 API（advance/raise/finding/complete/cancel/supersede）
         一律 FencedWriterError；
      2) broker 消费路径（resume_waiting/authorize_risk）持有完全合法的
         HMAC 审批也消费不了（loader 内栅栏核验）；
      3) 未启用 epoch 的 writer（视为 epoch 0）同样被拒；
      4) 旧 epoch 重放被拒：注入一条 otherwise-valid（seal/state_version/
         转换全对）但 writer_epoch 落后的事件 → 重放即 PipelineCorruptionError；
      5) 被拒写入零副作用（状态/版本零变化、链完好）。
    边界（显式验证）：fencing 作用域=单 run 事件流——旧写者对未被接管的
    新流（新建 run）仍可写（双 writer 争用的是同一条正源流）。
    """
    with TmpDir("ac-s5w6-") as td:
        db = os.path.join(td, "events.db")
        store = EventStore(db)
        w1 = _w6_manager(db, epoch=1)
        run_id = w1.create_run("task_w6_fence", W6_IDENT)["run_id"]
        w1.advance_stage(run_id)                        # S1 RUNNING（epoch 1 盖章）
        assert w1.get_run(run_id).writer_epoch == 1     # 流内 epoch 折叠可见
        # 双 writer：epoch 2 接管（更高 epoch 写入放行，流内 epoch 前移）
        w2 = _w6_manager(db, epoch=2)
        out = w2.advance_stage(run_id, execution_status="COMPLETED",
                               policy_verdict="PASS")
        assert out["attempt_status"] == "PASSED" and out.get("next_stage")
        assert w2.get_run(run_id).writer_epoch == 2
        # 1) 旧 writer 的全部变更 API 拒绝
        for fn in (
            lambda: w1.advance_stage(run_id),
            lambda: w1.advance_stage(run_id, execution_status="ERROR",
                                     policy_verdict="FAIL"),
            lambda: w1.raise_waiting(run_id, "resource", "旧 writer 试图停等"),
            lambda: w1.register_finding(run_id, "fnd_w6_stale", "fp-stale",
                                        "MEDIUM", "P2"),
            lambda: w1.complete_run(run_id),
            lambda: w1.cancel_run(run_id, "stale writer"),
            lambda: w1.supersede_run(run_id, "stale writer"),
            lambda: w1.adjudicate_gate_conditional(run_id),
        ):
            expect(FencedWriterError, fn)
        # 3) 未启用 epoch 的 writer（epoch 0）同样被拒
        w0 = _w6_manager(db)
        expect(FencedWriterError, lambda: w0.advance_stage(run_id))
        # 2) broker 消费路径：w2 停等后，旧 writer 持完全合法审批消费不了
        w2.raise_waiting(run_id, "resource", "等待探针恢复")
        st_w = w2.get_run(run_id)
        v = st_w.state_version
        pre = {"resource_probe_ref": "probe-w6", "probe_recovered": True,
               "safety_margin_met": True}
        ap_resume, _ = _w6_resume_approval(
            run_id, st_w.waiting.stop_event_id, "resource", v,
            "task_w6_fence", stage="S2_SOLUTION", preconditions=pre)
        expect(FencedWriterError,
               lambda: w1.resume_waiting(run_id, ap_resume, pre))
        ap_risk = _w6_risk_approval(run_id, "task_w6_fence", v,
                                    stage="S2_SOLUTION")
        expect(FencedWriterError, lambda: w1.authorize_risk(run_id, ap_risk))
        # 5) 被拒写入零副作用
        st_w = w2.get_run(run_id)
        assert st_w.state == "WAITING" and st_w.state_version == v
        assert st_w.writer_epoch == 2 and not st_w.findings
        assert w2.broker.consumed_approvals(run_id=run_id) == []
        # 4) 旧 epoch 重放被拒：注入 otherwise-valid 但 epoch=1 的事件
        forged = w2._base_event(
            "WAITING_RESUMED", st_w, "COMPLETED", "NOT_EVALUATED",
            stage="S2_SOLUTION", attempt_id="att_w6_epoch_probe",
            state_version=st_w.state_version + 1,
            stop_type="resource", stop_event_id=st_w.waiting.stop_event_id)
        forged["writer_epoch"] = 1
        _wp._PipelineDb.append_event(
            w2._db._conn, _wp._seal_event(run_id, forged))
        expect(PipelineCorruptionError, lambda: w2.get_run(run_id))
        assert store.verify_chain()["ok"]        # 拒绝是逻辑层，链完好
        # 边界：fencing 作用域=单流——旧 writer 对未被接管的新流仍可写
        run_b = w1.create_run("task_w6_fence_b", W6_IDENT)["run_id"]
        assert w1.advance_stage(run_b)["started_attempt_id"]
        assert w1.get_run(run_b).writer_epoch == 1
    return {"stale_writer_apis_rejected": 8,
            "broker_paths_fenced": ["resume_waiting", "authorize_risk"],
            "unfenced_writer_rejected": True,
            "old_epoch_replay": "PipelineCorruptionError（链完好）",
            "side_effects_after_rejections": "zero（版本/状态/消费面不变）",
            "boundary": "fencing 作用域=单 run 事件流；fenced 事件带 "
                        "writer_epoch 扩展字段（超出冻结 run-event-v2 词表，"
                        "默认模式零变化）"}


# ---------------------------------------------------------------------- #
# STATE-09：SHA/scope/policy 变化 → 强制新 run
# ---------------------------------------------------------------------- #
def test_STATE_09_sha_scope_policy_change_forces_new_run():
    """注入：SHA/scope/policy 变化——把携带漂移 identity 的（otherwise-valid：
    seal 合法、state_version 连续、转换合法）事件塞进既有 run 的流。

    期望（§20.5 逐字）：强制新 run——
      1) 重放侧：流内 identity 必须全程一致，commit_sha/scope_hash/
         policy_hash 任一漂移（或缺 identity）即 PipelineCorruptionError
         ——旧 run 流上不存在"原地换身份"路径；
      2) 正道（不变量 #3）：变化 → 旧 run SUPERSEDED 终态 + 新 identity
         新建 run；旧 run 终态后不可再写，证据面由新 run 承接；
      3) 对照：identity 一致的正常事件折叠不受影响。
    """
    mutations = {
        "commit_sha": lambda ident: dict(ident, commit_sha="b" * 40),
        "scope_hash": lambda ident: dict(ident, scope_hash="scope-EVIL-9"),
        "policy_hash": lambda ident: dict(ident, policy_hash="policy-EVIL-9"),
    }
    with TmpDir("ac-s9w6-") as td:
        db = os.path.join(td, "events.db")
        store = EventStore(db)
        mgr = _w6_manager(db)
        # 1) 三类漂移各用独立 run 注入（注入后该 run 重放即被拒）
        for field, mutate in mutations.items():
            run_id = mgr.create_run(f"task_w6_drift_{field}", W6_IDENT)["run_id"]
            mgr.advance_stage(run_id)
            st = mgr.get_run(run_id)
            forged = mgr._base_event(
                "STAGE_COMPLETED", st, "COMPLETED", "PASS",
                stage="S1_REQUIREMENT",
                attempt_id=st.stages["S1_REQUIREMENT"].current_attempt.attempt_id,
                state_version=st.state_version + 1,
                evidence_refs=[], findings=[])
            forged["identity"] = mutate(st.identity)    # 注入身份漂移
            _wp._PipelineDb.append_event(
                mgr._db._conn, _wp._seal_event(run_id, forged))
            expect(PipelineCorruptionError,
                   lambda r=run_id: mgr.get_run(r))
        # 缺 identity 的 run 事件同样拒绝
        run_id = mgr.create_run("task_w6_drift_none", W6_IDENT)["run_id"]
        mgr.advance_stage(run_id)
        st = mgr.get_run(run_id)
        forged = mgr._base_event(
            "STAGE_COMPLETED", st, "COMPLETED", "PASS",
            stage="S1_REQUIREMENT",
            attempt_id=st.stages["S1_REQUIREMENT"].current_attempt.attempt_id,
            state_version=st.state_version + 1, evidence_refs=[], findings=[])
        del forged["identity"]
        _wp._PipelineDb.append_event(
            mgr._db._conn, _wp._seal_event(run_id, forged))
        expect(PipelineCorruptionError, lambda: mgr.get_run(run_id))
        # 3) 对照：identity 一致的正常折叠不受影响
        ok_run = mgr.create_run("task_w6_ident_ok", W6_IDENT)["run_id"]
        out = mgr.advance_stage(ok_run, execution_status="COMPLETED",
                                policy_verdict="PASS")
        assert out["attempt_status"] == "PASSED"
        # 2) 强制新 run 正道（不变量 #3）
        out = mgr.supersede_run(ok_run, "commit_sha 变更，旧证据失效（不变量 #3）")
        assert out["final_state"] == "SUPERSEDED"
        expect(TerminalRunError, lambda: mgr.advance_stage(
            ok_run, execution_status="COMPLETED", policy_verdict="PASS"))
        new_ident = dict(W6_IDENT, commit_sha="c" * 40,
                         scope_hash="scope-w6-002",
                         policy_hash="policy-w6-002")
        run2 = mgr.create_run("task_w6_new_ident", new_ident)["run_id"]
        assert mgr.advance_stage(run2)["started_attempt_id"]
        assert mgr.get_run(run2).identity == new_ident
        assert store.verify_chain()["ok"]
    return {"drift_fields_rejected": sorted(mutations) + ["(missing identity)"],
            "drift_events_replay": "PipelineCorruptionError（旧流无换身份路径）",
            "identity_consistent_events": "正常折叠（对照正例）",
            "forced_new_run": "supersede SUPERSEDED + 新 identity 新 run，"
                              "旧 run 终态后 TerminalRunError",
            "chain_verified": True}


# ---------------------------------------------------------------------- #
# STATE-11：S7 CONDITIONAL 缺 risk authorization → 终判 FAILED；
#           后续批准只能创建新 run，不得写 WAITING
# ---------------------------------------------------------------------- #
def _w6_soft_s7(mgr, task_id):
    """S1..S6 PASS + S7 CONDITIONAL 软终态 + 登记 MEDIUM/P2 finding。"""
    run_id = mgr.create_run(task_id, W6_IDENT)["run_id"]
    for _ in range(6):
        mgr.advance_stage(run_id, execution_status="COMPLETED",
                          policy_verdict="PASS")
    mgr.advance_stage(run_id, execution_status="COMPLETED",
                      policy_verdict="CONDITIONAL")
    mgr.register_finding(run_id, "fnd_w6_s7", "fp-w6", "MEDIUM", "P2")
    return run_id


def test_STATE_11_s7_conditional_missing_risk_authorization_failed():
    """注入：S7 CONDITIONAL 且 run 无任何已消费/未过期/指纹匹配的 risk
    authorization（登记面有一条可接受的 MEDIUM/P2 finding——缺的是授权）。

    期望（§20.5 逐字）：S7/run 终判 FAILED；后续批准只能创建新 run，
    不得写 WAITING——
      1) 终判：adjudicate_gate_conditional → run 终态 FAILED
         （RUN_COMPLETED/COMPLETED/FAIL）；S7 attempt 证据不可变留档；
      2) 不得写 WAITING：终态 run 的一切变更拒绝（raise_waiting/advance/
         complete/register_finding/adjudicate 均 TerminalRunError）；伪造
         带 seal 的 WAITING_RAISED 直插 → 重放 PipelineCorruptionError；
      3) 后续批准：authorize_risk（新签的合法审批）对该 run 无目标
         （ApprovalRejected）；resume 类审批同样拒绝；
      4) 只能创建新 run：新 run 上重走 CONDITIONAL + 新批准（新 run_id/新
         state_version CAS 绑定）→ COMPLETED_CONDITIONAL 成立；旧 run 绑定
         的批准喂新 run 被 run_id mismatch 拒绝；
      5) 既有语义不回退：complete_run 对缺授权软终态的 fail-closed 拒绝保持；
         存在可用授权时终判口拒绝（误用防护）。
    """
    with TmpDir("ac-s11w6-") as td:
        db = os.path.join(td, "events.db")
        store = EventStore(db)
        mgr = _w6_manager(db)
        task = "task_w6_s11"
        run_id = _w6_soft_s7(mgr, task)
        # 5) 既有语义不回退：complete_run 缺授权 fail-closed（run 仍非终态）
        expect(PipelineError, lambda: mgr.complete_run(run_id))
        st = mgr.get_run(run_id)
        assert st.state == "RUNNING" and not st.terminal
        # 1) 终判：S7 CONDITIONAL 缺 risk authorization → run 终态 FAILED
        done = mgr.adjudicate_gate_conditional(run_id)
        assert done["final_state"] == "FAILED"
        assert done["policy_verdict"] == "FAIL"
        assert done["execution_status"] == "COMPLETED"
        st = mgr.get_run(run_id)
        assert st.terminal and st.state == "FAILED"
        assert st.stages["S7_GATE"].current_attempt.status \
            == "COMPLETED_CONDITIONAL"      # attempt 证据不可变，终判在 run 层
        assert "risk" in st.terminal_reason
        # 2) 不得写 WAITING：终态 run 的一切变更拒绝
        for fn in (
            lambda: mgr.raise_waiting(run_id, "resource", "迟到批准想停等"),
            lambda: mgr.advance_stage(run_id),
            lambda: mgr.complete_run(run_id),
            lambda: mgr.register_finding(run_id, "fnd_w6_late", "fp2",
                                         "LOW", "P3"),
            lambda: mgr.adjudicate_gate_conditional(run_id),
            lambda: mgr.supersede_run(run_id, "late"),
        ):
            expect(TerminalRunError, fn)
        # 3) 迟到的批准对该 run 无目标
        v = st.state_version
        risk_late = _w6_risk_approval(run_id, task, v, fingerprints=["fp-w6"])
        expect(ApprovalRejected, lambda: mgr.authorize_risk(run_id, risk_late))
        resume_late, pre_late = _w6_resume_approval(
            run_id, "f" * 64, "resource", v, task, stage="S7_GATE")
        expect(ApprovalRejected,
               lambda: mgr.resume_waiting(run_id, resume_late, pre_late))
        # 2b) 重放侧：伪造带 seal 的 WAITING_RAISED 直插终态 run → Corruption
        forged = mgr._base_event(
            "WAITING_RAISED", st, "BLOCKED", "NOT_EVALUATED",
            stage="S7_GATE",
            attempt_id=st.stages["S7_GATE"].current_attempt.attempt_id,
            state_version=st.state_version + 1,
            stop_type="resource", stop_reason="late authorization",
            required_preconditions=["resource_probe_ref", "probe_recovered",
                                    "safety_margin_met"])
        _wp._PipelineDb.append_event(
            mgr._db._conn, _wp._seal_event(run_id, forged))
        expect(PipelineCorruptionError, lambda: mgr.get_run(run_id))
        # 4) 后续批准只能创建新 run：旧 run 绑定的批准喂新 run → run_id 拒
        run2 = _w6_soft_s7(mgr, task + "_v2")
        v2 = mgr.get_run(run2).state_version
        ap_old = _w6_risk_approval(run_id, task, v, fingerprints=["fp-w6"],
                                   nonce="nonce-w6-risk-old")
        expect(ApprovalRejected, lambda: mgr.authorize_risk(run2, ap_old))
        # 新 run 的新批准（新 run_id/新 state_version CAS）正常成立
        ap_new = _w6_risk_approval(run2, task + "_v2", v2,
                                   fingerprints=["fp-w6"],
                                   nonce="nonce-w6-risk-new")
        assert mgr.authorize_risk(run2, ap_new)["consumed"] is True
        # 5b) 误用防护：存在可用授权时终判口拒绝；正道 complete_run 成立
        expect(PipelineError, lambda: mgr.adjudicate_gate_conditional(run2))
        done2 = mgr.complete_run(run2)
        assert done2["final_state"] == "COMPLETED_CONDITIONAL"
        # 误用防护：S7 非软终态的 run 终判口拒绝
        run3 = mgr.create_run(task + "_v3", W6_IDENT)["run_id"]
        expect(PipelineError, lambda: mgr.adjudicate_gate_conditional(run3))
        assert store.verify_chain()["ok"]
    return {"final_verdict": {"run": "FAILED", "S7_attempt":
                              "COMPLETED_CONDITIONAL（证据不可变留档）"},
            "post_terminal_writes": "全拒（TerminalRunError×6 + 重放侧 "
                                    "WAITING_RAISED Corruption）",
            "late_authorizations": "authorize_risk/resume_waiting 均 "
                                   "ApprovalRejected（run 终态无目标）",
            "new_run_path": "新 run + 新批准（新 run_id/CAS）→ "
                            "COMPLETED_CONDITIONAL；旧批准跨 run 拒",
            "complete_run_semantics": "fail-closed 拒绝保持不变（不回退）"}


# ---------------------------------------------------------------------- #
# 运行器 + 证据工件
# ---------------------------------------------------------------------- #
TESTS = [
    ("STATE-01", "任意 stage/status → schema 拒绝",
     test_STATE_01_arbitrary_stage_status_schema_rejected),
    ("STATE-02", "../、绝对路径、NUL、超长 ID → 拒绝（wenqu_pipeline ID 面）",
     test_STATE_02_traversal_absolute_nul_overlong_ids_rejected),
    ("STATE-03", "100×100 并发写 → 零丢失/重复",
     test_STATE_03_concurrent_100x100_no_loss_no_dup),
    ("STATE-04", "事务各点 kill -9 → 全有或全无",
     test_STATE_04_kill9_all_or_nothing),
    ("STATE-05", "双 writer epoch → 所有写入拒绝（wenqu_pipeline fencing）",
     test_STATE_05_dual_writer_epoch_all_writes_rejected),
    ("STATE-06", "WAITING 终态残留 → SUPERSEDED 事件，不静默删",
     test_STATE_06_waiting_residue_superseded_not_silently_deleted),
    ("STATE-07", "普通事件把 PASSED 改回 RUNNING → 拒绝",
     test_STATE_07_normal_event_cannot_flip_passed_to_running),
    ("STATE-08", "FAILED 重试 → 新 attempt，旧证据不覆盖",
     test_STATE_08_failed_retry_new_attempt_old_evidence_intact),
    ("STATE-09", "SHA/scope/policy 变化 → 强制新 run（重放侧 identity 不变量）",
     test_STATE_09_sha_scope_policy_change_forces_new_run),
    ("STATE-10", "WAITING/FAILED attempt 直接改回 RUNNING → 拒绝；"
                 "追加新 attempt 后由 stage projection 指向它",
     test_STATE_10_terminal_attempt_no_direct_running_new_attempt_ok),
    ("STATE-11", "S7 CONDITIONAL 缺 risk authorization → 终判 FAILED；"
                 "后续批准只能创建新 run，不得写 WAITING",
     test_STATE_11_s7_conditional_missing_risk_authorization_failed),
    ("MIG-01", "坏 JSON/未知状态 → quarantine+BLOCKED",
     test_MIG_01_bad_json_unknown_status_quarantine),
    ("MIG-02", "缺审批信息的 ACCEPTED → invalid/reopen",
     test_MIG_02_accepted_missing_approval_invalid_reopen),
    ("MIG-03", "两次迁移 → 结果幂等一致",
     test_MIG_03_double_migration_idempotent),
    ("MIG-04", "源行数不守恒 → 迁移失败",
     test_MIG_04_source_conservation_enforced),
    ("MIG-05", "project key 冲突 → 明确冲突，不拆成假项目",
     test_MIG_05_project_key_conflict_explicit_no_fake_split),
]


def _git_head():
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:                                   # noqa: BLE001
        pass
    return None


def write_artifact(started_at, finished_at, exit_code):
    results = {}
    for tid, name, ok, detail in RESULTS:
        results[tid] = {
            "name": name,
            "verdict": "PASS" if ok else "FAIL",
            "passed": ok,
            "detail": detail,
            **({"coverage_boundary": COVERAGE_BOUNDARY[tid]}
               if tid in COVERAGE_BOUNDARY else {}),
        }
    for tid, info in NOT_IMPLEMENTABLE_IN_SCOPE.items():
        results[tid] = {
            "name": f"{info['injection']} → {info['expectation']}",
            "verdict": "NOT_IMPLEMENTABLE_IN_SCOPE",
            "reason": info["reason"],
        }
    n_pass = sum(1 for *_, ok, _d in
                 [(r[0], r[1], r[2], r[3]) for r in RESULTS] if ok)
    artifact = {
        "artifact": "ac-state-mig",
        "description": "§20.2/§20.5 STATE-01~11、MIG-01~05 验收 ID 专属测试"
                       "逐 ID 结果（A 组被测体：wenqu_core/store.py + "
                       "wenqu_core/ledger_migrator.py，不依赖 wenqu_pipeline；"
                       "B 组（STATE-02/05/09/11，wave6/P1F）被测体："
                       "wenqu_core/wenqu_pipeline.py）",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_head": _git_head(),
        "test_file": "system/tests/test_ac_state_mig.py",
        "run_command": "python3 system/tests/test_ac_state_mig.py",
        "exit_code": exit_code,
        "started_at": started_at,
        "finished_at": finished_at,
        "fixture_note": "MIG 族旧账均为本测试内构造的小型合成旧账（临时目录），"
                        "非生产账本；STATE-04 崩溃注入为真实 SIGKILL 子进程。",
        "results": dict(sorted(results.items())),
        "summary": {
            "ids_total": 16,
            "implemented_and_passed": n_pass,
            "not_implementable_in_scope": len(NOT_IMPLEMENTABLE_IN_SCOPE),
            "failed": len(RESULTS) - n_pass,
        },
    }
    try:
        os.makedirs(os.path.dirname(ARTIFACT_PATH), exist_ok=True)
        with open(ARTIFACT_PATH, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, ensure_ascii=False, indent=2, sort_keys=True)
        return ARTIFACT_PATH
    except OSError as e:
        print(f"  WARNING: 证据工件写入失败: {e}")
        return None


def main():
    global PASS_N, FAIL_N
    started_at = datetime.now(timezone.utc).isoformat()
    print("§20 验收 ID 专属测试：STATE-01~11 / MIG-01~05")
    print("被测体 A 组: system/wenqu_core/store.py + "
          "system/wenqu_core/ledger_migrator.py（不依赖 wenqu_pipeline）")
    print("被测体 B 组: system/wenqu_core/wenqu_pipeline.py"
          "（wave6/P1F：STATE-02/05/09/11）\n")
    for tid, name, fn in TESTS:
        try:
            detail = fn() or {}
            ok = True
            PASS_N += 1
            print(f"  ok   {tid}  {name}")
            RESULTS.append((tid, name, ok, detail))
        except Exception as e:                          # noqa: BLE001
            FAIL_N += 1
            import traceback
            print(f"  FAIL {tid}  {name}")
            print("       " + traceback.format_exc(limit=8).replace(
                "\n", "\n       "))
            RESULTS.append((tid, name, False, {"error": f"{type(e).__name__}: {e}"}))
    if NOT_IMPLEMENTABLE_IN_SCOPE:
        print("\n不可实现登记（被测体无对应产品语义；不硬凑、不 xfail）：")
        for tid, info in NOT_IMPLEMENTABLE_IN_SCOPE.items():
            print(f"  --   {tid}  {info['injection']} → {info['expectation']}"
                  f"（详见证据工件 reason）")
    else:
        print("\n不可实现登记：无（16/16 ID 均有专属真实测试）")
    exit_code = 0 if FAIL_N == 0 else 1
    finished_at = datetime.now(timezone.utc).isoformat()
    path = write_artifact(started_at, finished_at, exit_code)
    print(f"\n结果: {PASS_N} PASS / {FAIL_N} FAIL；"
          f"范围内不可实现 {len(NOT_IMPLEMENTABLE_IN_SCOPE)} 条；exit={exit_code}")
    if path:
        print(f"证据工件: {path}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

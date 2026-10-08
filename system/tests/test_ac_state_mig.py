#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——STATE-01~11 / MIG-01~05（状态、账本、迁移）。

正源（逐字对齐）：
    evidence/00-baseline/codex-external/方案.md §20.2（STATE-01~06、MIG-01~05）
    与 §20.5（STATE-07~11）表格的「注入/期望」列。

被测体（按工单约束，本文件只依赖这两个模块，绝不 import wenqu_pipeline）：
    system/wenqu_core/store.py          —— EventStore（pipeline_events 哈希链
                                            事件正源：append-only 触发器、控制
                                            事件守卫、BEGIN IMMEDIATE 事务、
                                            WAL 并发、verify_chain、幂等 head）
    system/wenqu_core/ledger_migrator.py —— LedgerMigrator（旧 JSONL 账本迁移：
                                            quarantine/守恒/幂等/sidecar 审计）

可实现性裁定（诚实优先，不硬凑、不 xfail）：
    本文件对 16 个 ID 中的 11 个给出专属真实测试：
        STATE-01/03/04/06/07/08/10、MIG-01/02/03/04
    其余 5 个（STATE-02/05/09/11、MIG-05）在被测体（store.py +
    ledger_migrator.py）中没有任何对应产品语义——详见模块级登记表
    NOT_IMPLEMENTABLE_IN_SCOPE（含逐条证据：语义所在模块或全仓无实现），
    测试运行时与证据工件中均显式输出，不以 skip/xfail 冒充。

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
运行后把逐 ID 结果写入 evidence/04-unit-property-mutation/ac-state-mig.json。
"""
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

# 工单约束：只准依赖 store / ledger_migrator（绝不 import wenqu_pipeline）
from wenqu_core.store import (                          # noqa: E402
    EventStore, ChainIntegrityError, GENESIS_HASH, is_control_event)
from wenqu_core.ledger_migrator import (                # noqa: E402
    LedgerMigrator, ConservationError, KNOWN_STATUSES)

ARTIFACT_PATH = os.path.join(
    REPO_ROOT, "evidence", "04-unit-property-mutation", "ac-state-mig.json")

# ---------------------------------------------------------------------- #
# 不可实现登记表（模块级；语义在被测体中不存在，非测试跳过）
# ---------------------------------------------------------------------- #
NOT_IMPLEMENTABLE_IN_SCOPE = {
    "STATE-02": {
        "injection": "`../`、绝对路径、NUL、超长 ID",
        "expectation": "拒绝",
        "reason": (
            "store.py 的 EventStore 没有任何调用方可控 ID/路径参数——event_id 由 "
            "canonical payload 哈希自动生成（store.py append），db_path 是构造器"
            "参数且不做校验（属运维输入，非不可信输入面）；ledger_migrator.py 同样"
            "没有 ID 概念。『拒绝 ../、绝对路径、NUL、超长 ID』的 ID 校验语义在"
            "被测体中不存在（wenqu_pipeline 的 _validate_identity 只校验非空/"
            "40-hex/environment 枚举，亦无路径/NUL/长度面，且该模块本文件禁 import）"),
    },
    "STATE-05": {
        "injection": "双 writer epoch",
        "expectation": "所有写入拒绝",
        "reason": (
            "全仓 grep 无 writer epoch/fencing 实现：store.py 无 epoch 字段/比较，"
            "wenqu_pipeline 亦无（grep 'epoch' 仅命中 scheduler 时间换算与审批"
            " issued/expires）。『旧 epoch writer 的所有写入被拒』这一产品语义未"
            "实现，无法对 store/ledger_migrator 做真实注入"),
    },
    "STATE-09": {
        "injection": "SHA/scope/policy 变化",
        "expectation": "强制新 run",
        "reason": (
            "run 身份绑定（identity.commit_sha/scope_hash/policy_hash 校验、"
            "InvalidIdentityError、变化即拒绝复用 run）全部实现在 wenqu_pipeline "
            "RunManager/_validate_identity；store.py 事件负载对身份字段完全透明。"
            "该模块被工单禁止 import，且并行 agent 正在改它，本文件不越界测它"),
    },
    "STATE-11": {
        "injection": "S7 CONDITIONAL 缺 risk authorization",
        "expectation": "S7/run 终判 FAILED；后续批准只能创建新 run，不得写 WAITING",
        "reason": (
            "S7 终判聚合与 risk authorization 消费（consume_authorization/"
            "has_unexpired_risk_authorization）全部实现在 wenqu_pipeline "
            "ApprovalBroker/RunManager；store.py 只有控制事件类型守卫这一个相邻"
            "机制（已由本文件其他用例覆盖）。仅凭守卫硬凑 S7 语义即冒充，不凑"),
    },
    "MIG-05": {
        "injection": "project key 冲突",
        "expectation": "明确冲突，不拆成假项目",
        "reason": (
            "ledger_migrator.py 全文无 project 概念（grep 'project' 零命中）："
            "迁移按行 SHA256 判重导入 events 表，不存在 project key 的映射/冲突"
            "检测/报错路径。该语义未实现，无法真实注入"),
    },
}

# STATE-06/07/08/10 与 MIG-01 的覆盖边界（测的是被测体已实现的那一半）
COVERAGE_BOUNDARY = {
    "STATE-01": "测 store 层 schema 边界：携带任意 stage/status 的管线控制事件（RUN_*/STAGE_*/ATTEMPT_* 等 event_type）经公共 EventStore.append 一律 ValueError；attempt 状态枚举校验在 wenqu_pipeline（禁 import，不越界）",
    "STATE-06": "测 store 层：SUPERSEDED 属控制事件不可裸 append 伪造；WAITING 残留事件行不可 UPDATE/DELETE 静默消除，唯一出路是追加新事件。残留清扫与 SUPERSEDED 控制事件的实际签发在 RunManager（wenqu_pipeline，禁 import）",
    "STATE-07": "测 store 层：已落账的 PASSED 证据不可 UPDATE/DELETE 回改成 RUNNING；RUNNING 类状态转移事件是控制类型，普通（裸）事件无法伪造。转移表级拒绝（InvalidTransitionError）在 wenqu_pipeline（禁 import）",
    "STATE-08": "测 store 层：FAILED attempt 的旧证据行不可覆盖（UPDATE 拒绝），重试只能追加新事件（新 attempt 记录），旧证据逐字节不变且链可验证。attempt_id 分配与不可变（AttemptImmutabilityError）在 wenqu_pipeline（禁 import）",
    "STATE-10": "测 store 层前半句：WAITING/FAILED attempt 直接改回 RUNNING 的两条路（UPDATE 行 / 伪造控制事件）全拒；追加新 attempt 事件成功且旧行保留。后半句 stage projection 指向新 attempt 在 RunManager（禁 import）",
    "MIG-01": "测迁移器已实现面：坏 JSON/未知状态 → quarantine 绝不导入；ERROR/BLOCKED 别名按已知状态 BLOCKED 导入（fail-closed 归一）。『+BLOCKED』的整次迁移 run 级 BLOCKED 聚合在编排层（不在被测体）",
    "MIG-02": "测迁移器已实现面：ACCEPTED 是未知状态——无论缺不缺审批信息一律 quarantine（不猜映射为 PASS），进 quarantine=待人工 reopen 的账，sidecar 全程留痕。『invalid 后写 reopen 事件』属 risk acceptance 子系统（FND-016，不在被测体）",
    "MIG-04": "ConservationError 是防御性守卫：tally 与处理循环遍历同一 list，经公共 API 构造不出账目不平（已实证 + 代码通读）。本用例测同秩语义的运行时面：逐行独立对账零失联 + 删行后重迁移精确补账 + 审计侧不可写则迁移整体失败、零部分导入、零假守恒记账",
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

    期望（被测体已实现面）：坏行一律 quarantine（reason 精确），绝不导入
    events 表；migration_runs 记 quarantined 计数；sidecar 逐行留痕；
    ERROR/BLOCKED 行按已知状态 BLOCKED 导入——绝不把坏行洗成绿。
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

        conn = sqlite3.connect(db)
        try:
            statuses = dict(rows_of(conn, "SELECT status, COUNT(*) FROM events "
                                          "GROUP BY status"))
            assert statuses == {"BLOCKED": 2, "FIXED_PENDING_VERIFY": 1,
                                "PASS": 2}
            bad_in_db = rows_of(conn, "SELECT COUNT(*) FROM events WHERE "
                                "payload LIKE '%WEIRD%' OR payload LIKE "
                                "'%broken%' OR payload LIKE '%not%object%'")[0][0]
            assert bad_in_db == 0, "坏行被导入（不允许）"
            run = rows_of(conn, "SELECT files_scanned, lines_total, imported, "
                              "duplicates, quarantined, conserved FROM "
                              "migration_runs")
            assert run == [(1, 12, 5, 0, 7, 1)]
        finally:
            conn.close()
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
            "bad_lines_in_events_table": 0,
            "boundary": "run 级 BLOCKED 聚合在编排层（不在被测体）"}


# ---------------------------------------------------------------------- #
# MIG-02：缺审批信息的 ACCEPTED → invalid/reopen
# ---------------------------------------------------------------------- #
def test_MIG_02_accepted_missing_approval_invalid_reopen():
    """注入（合成旧账）：四类 ACCEPTED 行——缺 ts、缺审批要素、带看似完整的
    审批信息、以及一个对照组合法 PASS 行。

    期望（被测体已实现面）：ACCEPTED 对迁移器是未知状态——无论审批信息
    缺不缺，一律 invalid 进 quarantine（绝不猜映射成 PASS），零导入；
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
        conn = sqlite3.connect(db)
        try:
            db_rows = rows_of(conn, "SELECT status, payload FROM events")
            assert len(db_rows) == 1 and db_rows[0][0] == "PASS"
            accepted_in_db = rows_of(conn, "SELECT COUNT(*) FROM events WHERE "
                                     "payload LIKE '%ACCEPTED%' OR payload "
                                     "LIKE '%accepted%'")[0][0]
            assert accepted_in_db == 0, "ACCEPTED 行被导入（不允许）"
        finally:
            conn.close()
        recs = _sidecar_records(mig.sidecar_path)
        q = [r for r in recs if r["decision"] == "quarantined"]
        assert len(q) == 4
        assert all("preview" in r for r in q), "quarantine 必须带原文预览（reopen 线索）"
    return {"accepted_lines": 4, "quarantined": 4, "imported": 0,
            "reopen_channel": "quarantine + sidecar 预览（人工再录）",
            "boundary": "risk acceptance/reopen 事件子系统（FND-016）不在被测体"}


# ---------------------------------------------------------------------- #
# MIG-03：两次迁移 → 结果幂等一致
# ---------------------------------------------------------------------- #
def test_MIG_03_double_migration_idempotent():
    """注入（合成旧账）：同一账本连续两次完整迁移（两个独立迁移器实例）。

    期望：结果幂等一致——events 表行集逐字节相同（快照对比）；第二次
    imported=0、原导入行全部计为 duplicate；两次守恒均成立；
    源 JSONL 全程只读（前后字节一致）；sidecar 只追加。
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
            snap1 = rows_of(conn, "SELECT line_sha, status, source_file, "
                                  "source_line, payload FROM events ORDER BY id")
        finally:
            conn.close()
        sc1 = open(os.path.join(td, "mig.db.migration-sidecar.jsonl"),
                   "rb").read()

        r2 = LedgerMigrator(src, db).migrate()     # 第二个实例、同一库
        conn = sqlite3.connect(db)
        try:
            snap2 = rows_of(conn, "SELECT line_sha, status, source_file, "
                                  "source_line, payload FROM events ORDER BY id")
        finally:
            conn.close()
        sc2 = open(os.path.join(td, "mig.db.migration-sidecar.jsonl"),
                   "rb").read()

        assert snap1 == snap2, "二次迁移改动了已导入行集（不幂等）"
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
        conn = sqlite3.connect(db)
        try:
            assert rows_of(conn, "SELECT COUNT(*) FROM migration_runs")[0][0] == 2
        finally:
            conn.close()
    return {"run1": {"imported": 3, "duplicates": 1, "quarantined": 2},
            "run2": {"imported": 0, "duplicates": 4, "quarantined": 2},
            "events_table_identical": True, "source_bytewise_unchanged": True,
            "sidecar_append_only": True}


# ---------------------------------------------------------------------- #
# MIG-04：源行数不守恒 → 迁移失败
# ---------------------------------------------------------------------- #
def test_MIG_04_source_conservation_enforced():
    """注入（合成旧账 + 三类真实破坏）：
      (a) 迁移后从 events 表直接删 3 行（账本少行=不守恒态）；
      (b) 审计 sidecar 落在一个目录路径上（任何 OS/用户都写不开）；
      (c) sqlite 目标落在一个目录路径上（根本开不了库）。

    期望（被测体已实现面）：
      (a) 重迁移精确补齐缺失行（imported=3、其余 duplicate），守恒恢复，
          绝不静默少账——守恒等式 lines==imported+duplicates+quarantined
          在 DB/sidecar 独立对账下成立；
      (b) 审计不可写 → 迁移整体失败（异常抛出），events 零行、
          migration_runs 零行——没有部分导入、没有假守恒记账；
      (c) 开不了库 → 迁移失败（异常抛出）。
    诚实边界：ConservationError 守卫本身是防御性的——migrate 的计数与
    处理循环遍历同一 list，公共 API 构造不出账目不平（已代码通读+注入
    尝试实证），故此处以同秩语义的运行时面做真实验证。
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

        # 独立对账（不信 report，直接从源文件/DB/sidecar 重数）
        src_nonblank = sum(1 for ln in open(os.path.join(src, "conserved.jsonl"),
                                            encoding="utf-8") if ln.strip())
        conn = sqlite3.connect(db)
        try:
            db_rows = rows_of(conn, "SELECT COUNT(*) FROM events")[0][0]
            quarantined_shas = {r["line_sha"] for r in
                                _sidecar_records(db + ".migration-sidecar.jsonl")
                                if r["decision"] == "quarantined"}
        finally:
            conn.close()
        src_shas = {r["line_sha"] for r in LedgerMigrator(src, db).scan()}
        assert src_nonblank == db_rows + len(quarantined_shas)
        assert quarantined_shas <= src_shas and db_rows == n_valid

        # (a) 删行 → 不守恒态 → 重迁移必须补齐，不许静默少账
        conn = sqlite3.connect(db)
        try:
            conn.execute("DELETE FROM events WHERE source_line IN (2, 3, 4)")
            conn.commit()
        finally:
            conn.close()
        r2 = LedgerMigrator(src, db).migrate()
        assert r2["conservation"]["imported"] == 3
        assert r2["conservation"]["duplicates"] == n_valid - 3
        assert r2["conserved"] is True
        conn = sqlite3.connect(db)
        try:
            assert rows_of(conn, "SELECT COUNT(*) FROM events")[0][0] == n_valid
        finally:
            conn.close()

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
            assert rows_of(conn, "SELECT COUNT(*) FROM events")[0][0] == 0
            assert rows_of(conn, "SELECT COUNT(*) FROM migration_runs")[0][0] == 0
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
            "deleted_rows_reimported": 3,
            "unwritable_sidecar": "迁移失败，events=0、migration_runs=0",
            "unopenable_db": "迁移失败（异常）",
            "boundary": "ConservationError 为防御性守卫（公共 API 构造不出不平，"
                        "已实证）；此处验证同秩运行时语义"}


# ---------------------------------------------------------------------- #
# 运行器 + 证据工件
# ---------------------------------------------------------------------- #
TESTS = [
    ("STATE-01", "任意 stage/status → schema 拒绝",
     test_STATE_01_arbitrary_stage_status_schema_rejected),
    ("STATE-03", "100×100 并发写 → 零丢失/重复",
     test_STATE_03_concurrent_100x100_no_loss_no_dup),
    ("STATE-04", "事务各点 kill -9 → 全有或全无",
     test_STATE_04_kill9_all_or_nothing),
    ("STATE-06", "WAITING 终态残留 → SUPERSEDED 事件，不静默删",
     test_STATE_06_waiting_residue_superseded_not_silently_deleted),
    ("STATE-07", "普通事件把 PASSED 改回 RUNNING → 拒绝",
     test_STATE_07_normal_event_cannot_flip_passed_to_running),
    ("STATE-08", "FAILED 重试 → 新 attempt，旧证据不覆盖",
     test_STATE_08_failed_retry_new_attempt_old_evidence_intact),
    ("STATE-10", "WAITING/FAILED attempt 直接改回 RUNNING → 拒绝；"
                 "追加新 attempt 后由 stage projection 指向它",
     test_STATE_10_terminal_attempt_no_direct_running_new_attempt_ok),
    ("MIG-01", "坏 JSON/未知状态 → quarantine+BLOCKED",
     test_MIG_01_bad_json_unknown_status_quarantine),
    ("MIG-02", "缺审批信息的 ACCEPTED → invalid/reopen",
     test_MIG_02_accepted_missing_approval_invalid_reopen),
    ("MIG-03", "两次迁移 → 结果幂等一致",
     test_MIG_03_double_migration_idempotent),
    ("MIG-04", "源行数不守恒 → 迁移失败",
     test_MIG_04_source_conservation_enforced),
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
                       "逐 ID 结果（被测体：wenqu_core/store.py + "
                       "wenqu_core/ledger_migrator.py；不依赖 wenqu_pipeline）",
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
    print("§20 验收 ID 专属测试：STATE-01~11 / MIG-01~05（store + ledger_migrator）")
    print(f"被测体: {os.path.join('system', 'wenqu_core', 'store.py')} + "
          f"{os.path.join('system', 'wenqu_core', 'ledger_migrator.py')}"
          f"（不 import wenqu_pipeline）\n")
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
    print("\n不可实现登记（被测体无对应产品语义；不硬凑、不 xfail）：")
    for tid, info in NOT_IMPLEMENTABLE_IN_SCOPE.items():
        print(f"  --   {tid}  {info['injection']} → {info['expectation']}"
              f"（详见证据工件 reason）")
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

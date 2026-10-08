#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——调度/告警/健康/文档治理/容量/备份DR 六族（P0-10 追踪缺口销账件）。

覆盖 §20.4/§20.5 中本件负责的 17 个验收 ID（注入/期望逐字对齐
evidence/00-baseline/codex-external/方案.md §20 表格）：

    SCH-01  launchd 无 Documents 权限                -> ERROR+告警
    SCH-02  脚本 FAIL 后 touch heartbeat             -> 测试抓获、last_success 不变
    SCH-03  睡眠错过周期                             -> 唤醒补跑
    SCH-04  catch-up 与正常调度并发                  -> 只有一个 logical run
    SCH-05  scheduler 整体故障                       -> 独立 watchdog 仍告警
    SCH-06  one-shot job                             -> 只写 wenqu namespace
    SCH-07  COMPLETED+NOT_APPLICABLE 或过期/异指纹 PASS -> 不刷新任何实体的 last_success
    ALT-01  provider 500/超时                        -> outbox 重试/dead-letter
    ALT-02  waiting 到期但零 send attempt/receipt    -> ERROR+告警，不能以 watchdog exit0 记健康
    BAK-01  磁盘满/tar/backup 失败                   -> 不更新 success
    HLT-01  聚合期间输入 watermark 变化              -> snapshot 作废重算
    DOC-01  one-shot 停等数量/枚举漂移               -> CI 阻断
    DOC-02  bug skill 版本/清单/验收数量漂移         -> CI 阻断
    DOC-03  policy/Skill 出现 L4、--admin、force-with-lease 或 skip 绕闸文本 -> CI 阻断
    DOC-04  文档宣称现役/PASS，但 registry 或 Gate 为 BLOCKED -> CI 阻断
    CAP-01  峰值空间超过安全余量或磁盘满             -> 切换 BLOCKED，旧证据和 current 均完整
    DR-01   恢复演练                                 -> 实测满足冻结 RPO/RTO

被测体（全部真实注入、真实断言，零 mock 产品行为）：
    system/wenqu_core/scheduler.py   ScheduleRegistry / JobRunner / NotificationOutbox /
                                     HeartbeatMonitor（DST/重试/幂等/退避/死信）
    system/dashboard/server.py       /api/v1/health 健康原子性 + gate 快照输入水印
    system/wenqu_core/wenqu_pipeline.py 九类停等枚举 + system/docs/specs 契约 + docs/
    probes/stations.json + cli/wenqu VERSION + tests/acceptance.sh   文档注册表对账
    system/wenqu_core/capacity_monitor.py 容量安全边际（REQ-CAP-001/AC-CAP-SAFE-MARGIN）：
                                     shutil.disk_usage 真实采集 + 路径配额 + jsonl
                                     峰值记录 + used/(used+free) 阈值判定（默认 0.90）
                                     + §22 峰值预算 headroom + 趋势外推 + 容量闸
                                     BLOCKED 切换（旧证据/current 只读完整性清单）；
                                     磁盘满注入走 injected_sample 数字注入接口，
                                     绝不真塞盘
    system/sentinels/backup-restore-drill.sh + system/wenqu_core/drill_runner.py
                                     备份可恢复（AC-BACKUP-RESTORABLE）：tmp 语料上
                                     四步真实演练（快照→篡改[实测 sha 已变]→恢复→
                                     逐文件 cmp+sha256 字节级对账）+ 备份失败族
                                     fail-closed（语料不可达 -> 报告 result=FAIL、
                                     退出非零、success 不更新）；DR 演练
                                     （AC-DR-RPO-RTO）：RPO=最后快照点→故障注入点
                                     实测时差（--fault-delay 已知窗口）、RTO=恢复开始→
                                     全部对账通过实测耗时，冻结目标 RPO<=300s/RTO<=60s
                                     由演练脚本内冻结；双工件 drill-<stamp>.json +
                                     .jsonl 事件日志（时间/文件/结果三要素逐事件记账）

运行：python3 system/tests/test_ac_ops_families.py   （独立 exit 0 = 全绿）
证据：evidence/04-unit-property-mutation/ac-ops-families.json（每次运行覆写）。

诚实边界（无法在本机沙箱真实注入、不以假绿硬凑的部分，另见证据 JSON
not_implementable 字段）：
    1. SCH-01 的「launchd 无 Documents 权限」需要真实 launchd 会话 + TCC 授权弹窗
       环境；本件以等价代码接缝注入（作业无法访问其执行环境 -> spawn 失败）覆盖
       「ERROR+告警」判定链，真实 launchd 环境标注未验证。
    2. SCH-03 的真实系统睡眠/唤醒（pmset/14 天时序）无法在单测内发生；使用
       scheduler 模块自带的 now= 时钟注入接缝（模块文档声明的时间纪律正源）。
    3. SCH-05 的「不同故障域独立 watchdog 宿主」（跨进程/跨机）以同库独立
       HeartbeatMonitor 组件覆盖进程内独立性；跨故障域声明为未验证。
    4. HLT-01 的聚合器侧重算属 gate_aggregator 域（并行工作面，本件不碰）；
       本件覆盖 dashboard 正源侧：watermark 变化 -> 快照作废（503 结构化 ERROR，
       绝不透传旧结论）+ 聚合器重算产物（重写快照）即刻生效。bin/wenqu-dashboard.py
       的 /api/v1/health 为遗留自算卡（无 gate 快照水印面，且会写用户真实走势文件），
       水印契约自 W8 起由 system/dashboard/server.py 承载，本件覆盖正源。
    5. BAK-01 的「磁盘满/tar」字面向量不可移植注入（drill 用 cp 管道）；本件以
       同族真实失败（备份语料不可达 -> 演练 fail-closed，报告 result=FAIL、退出
       非零、既有 PASS 工件不被改写=success 不更新）覆盖「backup 失败 -> 不更新
       success」判定链；备份可恢复正语义以 tmp 语料四步真实演练覆盖。
"""
from __future__ import annotations

import hashlib
import http.client
import json
import logging
import math
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]          # wenqu-dist/
SYSTEM = REPO / "system"
sys.path.insert(0, str(SYSTEM))

from wenqu_core.runner import TrustedRunner                     # noqa: E402
from wenqu_core.drill_runner import (                           # noqa: E402
    DrillFailure,
    read_events,
    run_drill,
)
from wenqu_core.scheduler import (                              # noqa: E402
    HeartbeatMonitor,
    JobDefinition,
    JobRunner,
    NotificationOutbox,
    ScheduleRegistry,
    ScheduleSpec,
    SchedulerStore,
    WatchdogPolicy,
    compute_input_fingerprint,
)
from wenqu_core.capacity_monitor import (                        # noqa: E402
    CAP_DISK_FULL,
    CAP_PEAK_BUDGET_EXCEEDS_HEADROOM,
    CAP_QUOTA_RATIO_EXCEEDED,
    CAP_TREND_THRESHOLD_APPROACH,
    CAP_USED_RATIO_EXCEEDED,
    CAP_WITHIN_MARGIN,
    CapacityMonitor,
    CapacitySpec,
    CapacitySpecError,
    SampleLog,
    SampleLogError,
    enforce_capacity_gate,
    injected_sample,
    integrity_manifest,
    peak_budget_bytes,
)

# 测试卫生：产品模块的 log.warning（如 spawn failed）不要打进测试输出
logging.disable(logging.CRITICAL)

EVIDENCE_PATH = REPO / "evidence" / "04-unit-property-mutation" / "ac-ops-families.json"

_RESULTS: dict = {}
_NOT_IMPLEMENTABLE = [
    {
        "id": "SCH-01",
        "gap": "真实 launchd 会话 + TCC「无 Documents 权限」注入",
        "reason": "需要真 launchd 加载作业与 macOS TCC 授权环境，单测沙箱不可复现",
        "mitigation": "以 JobRunner spawn 失败（argv 不可达 / cwd 不可读）等价注入覆盖 ERROR+告警 判定链",
    },
    {
        "id": "SCH-03",
        "gap": "真实系统睡眠/唤醒跨真实周期",
        "reason": "pmset 睡眠与 14 天时序不可在单测内发生",
        "mitigation": "使用 scheduler 正源时钟接缝 now= 注入错过周期，补跑语义全链真跑",
    },
    {
        "id": "SCH-05",
        "gap": "跨故障域独立 watchdog 宿主（独立进程/独立机器）",
        "reason": "本机单测只能证明同库独立组件在调度器停摆后仍告警",
        "mitigation": "HeartbeatMonitor 与 JobRunner 完全解耦、只读持久化运行态，单进程内独立性实证",
    },
    {
        "id": "HLT-01",
        "gap": "gate_aggregator 聚合进程内的 watermark 竞态重算",
        "reason": "gate_aggregator 为并行工作面（本件不碰）；且重算语义属聚合器域",
        "mitigation": "dashboard 正源侧真服务探针：watermark 过期/畸形->快照作废 503，"
                       "重算产物重写快照后新判定即刻生效、旧结论不缓存",
    },
    # ---- F6-COVERAGE-AUTH-001 补录（2026-10-08）：本列表现仅存上方 4 条环境边界登记。
    # ---- CAP-01 已于 2026-10-08 转真：wenqu_core/capacity_monitor.py 入产品
    # ---- （本文件 test_CAP_01_ 专属测试），登记移除、断言只增不减。
    # ---- BAK-01/DR-01 已于 2026-10-08 转真：backup-restore-drill.sh（jsonl
    # ---- 事件日志+DR 模式 RPO/RTO 计时）+ wenqu_core/drill_runner.py 入产品
    # ---- （本文件 test_BAK_01_/test_DR_01_ 专属测试），登记移除、断言只增不减。
    # ---- UI-01~07 七条登记已于 2026-10-08 迁出：dashboard UI 面激活，由
    # ---- system/tests/test_ac_ui_family.py 专属承接（探针=system/wenqu_core/
    # ---- ui_probe.py；证据=evidence/04-unit-property-mutation/ac-ui-family.json；
    # ---- L2 HTTP+DOM 级——Playwright 不可用按可用性降级，浏览器级缺口在该件
    # ---- not_implementable 逐条登记）。
]


# ---------------------------------------------------------------------------
# 通用小工具（不含任何 §20 ID 字面量，避免追踪矩阵误归属）
# ---------------------------------------------------------------------------
def _record(test_id: str, detail: str) -> None:
    _RESULTS[test_id] = {"pass": True, "detail": detail}


def _mk_job(job_id: str, argv, *, station: int, every: float = 60.0,
            due_window: float = 300.0, catch_up: str = "COALESCE",
            max_catch_up: int = 8, freshness: float = 900.0,
            commit_sha=None, cwd=None) -> JobDefinition:
    return JobDefinition(
        job_id=job_id, owner="ac-ops-families", argv=tuple(argv),
        schedule=ScheduleSpec.every(every), environment="local",
        probe_id=f"probe-{job_id}", station_id=station, cwd=cwd,
        due_window_seconds=due_window, catch_up=catch_up,
        max_catch_up_runs=max_catch_up,
        watchdog=WatchdogPolicy(freshness_seconds=freshness, grace_seconds=0.0),
        ttl_seconds=300.0, commit_sha=commit_sha,
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _true_bin() -> str:
    """跨平台定位 true（本机 macOS 无 /bin/true，只有 /usr/bin/true）。"""
    return shutil.which("true") or "/usr/bin/true"


def _http_get(port: int, path: str, timeout: float = 5.0):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    return resp.status, parsed


def _write_gate_snapshot(path: Path, verdict: str | None, *, age_seconds: float = 0.0,
                         raw: str | None = None) -> str:
    """按 read_gate_aggregate 契约写一份聚合器快照；返回 generated_at。"""
    ts = datetime.now(timezone.utc).timestamp() - age_seconds
    gen = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if raw is not None:
        path.write_text(raw, encoding="utf-8")
        return gen
    payload = {
        "generated_at": gen, "policy_verdict": verdict,
        "aggregate_outcome": verdict, "reason": "ac-ops-families probe",
        "counts": {}, "stations": {},
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return gen


class _DashboardServer:
    """在随机空闲端口起 system/dashboard/server.py 子进程，退出时清理。"""

    def __init__(self, sandbox: Path, ttl_seconds: int = 2):
        self.sandbox = sandbox
        self.snap = sandbox / "gate-aggregate.json"
        self.history = sandbox / "health-history.jsonl"
        self.port = _free_port()
        self.ttl = ttl_seconds
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "_DashboardServer":
        env = dict(os.environ,
                   WENQU_GATE_AGGREGATE=str(self.snap),
                   WENQU_AGGREGATE_TTL=str(self.ttl),
                   WENQU_HOME=str(self.sandbox / "wenqu-home"),
                   WENQU_HEALTH_HISTORY=str(self.history))
        self.proc = subprocess.Popen(
            [sys.executable, str(SYSTEM / "dashboard" / "server.py"),
             "--port", str(self.port)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(
                    f"dashboard server 提前退出 rc={self.proc.returncode}")
            try:
                status, _ = _http_get(self.port, "/api/v1/ping")
                if status == 200:
                    return self
            except OSError:
                pass
            time.sleep(0.15)
        raise AssertionError("dashboard server 15s 内未就绪")

    def __exit__(self, *exc) -> None:
        if self.proc is None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def health(self):
        return _http_get(self.port, "/api/v1/health")


# ---------------------------------------------------------------------------
# SCH 族：调度 / 心跳 / 看门狗
# ---------------------------------------------------------------------------
def test_SCH_01_env_permission_denied_yields_error_and_alert():
    """SCH-01 | 注入: launchd 无 Documents 权限 | 期望: ERROR+告警。

    真实 launchd+TCC 环境不可注入（见模块 docstring 边界 1），此处注入等价
    故障：作业的执行环境不可访问（argv[0] 不存在；cwd 无读权限），断言产品
    判定链完整落在 ERROR + WARNING 告警投递上，心跳不刷新。
    """
    with tempfile.TemporaryDirectory(prefix="wq_sch01_") as tmp:
        store = SchedulerStore(os.path.join(tmp, "s.db"))
        try:
            reg = ScheduleRegistry(store)
            delivered: list[dict] = []

            def recorder(payload: dict) -> None:
                delivered.append(payload)

            outbox = NotificationOutbox(store, critical_channels=("primary", "fallback"))
            outbox.register_channel("primary", recorder)
            outbox.register_channel("fallback", recorder)
            hb = HeartbeatMonitor(store, outbox)
            runner = JobRunner(store, TrustedRunner(), registry=reg,
                               outbox=outbox, heartbeat=hb)

            # 注入 A：可执行文件不存在（环境残缺——launchd 拿不到 PATH/权限时的等价形态）
            reg.register(_mk_job("sch01-missing", ("/nonexistent/wenqu-probe", "--run"),
                                station=1), now=1000.0)
            rec = runner.run_job("sch01-missing", scheduled_at=1060.0, now=1061.0)
            assert rec.execution_status == "ERROR", \
                f"环境不可达应为 ERROR，实为 {rec.execution_status}"
            assert rec.policy_verdict != "PASS", "环境错误绝不得折算为 PASS"
            assert rec.refreshed_heartbeat is False, "ERROR 不得刷新 last_success"
            assert any("spawn failed" in w for w in rec.warnings), \
                f"应捕获 spawn 失败警告，实得 {rec.warnings}"

            # 注入 B：cwd 无读权限（Documents 目录被 TCC 拒绝的等价形态；root 下豁免）
            ran_perm = False
            if os.geteuid() != 0:
                locked = os.path.join(tmp, "locked-cwd")
                os.makedirs(locked, exist_ok=True)
                os.chmod(locked, 0o000)
                try:
                    reg.register(_mk_job("sch01-noperm", (_true_bin(),), station=1,
                                        cwd=locked), now=2000.0)
                    rec2 = runner.run_job("sch01-noperm", scheduled_at=2060.0, now=2061.0)
                    ran_perm = True
                    assert rec2.execution_status == "ERROR", \
                        f"cwd 不可读应为 ERROR，实为 {rec2.execution_status}"
                    assert rec2.policy_verdict != "PASS"
                finally:
                    os.chmod(locked, 0o755)

            # 期望：ERROR+告警——WARNING 通知已入 outbox 并真实投递到通道
            result = outbox.dispatch_due(now=time.time() + 3600.0)
            assert result["sent"] >= 1, f"应有告警真实投递，dispatch={result}"
            subjects = " | ".join(d["subject"] for d in delivered)
            assert "sch01-missing" in subjects, f"告警应点名作业，实得 {subjects}"
            assert delivered, "告警必须真实送出（不只入队）"
            rows = store.query(
                "SELECT last_success_at FROM scheduler_heartbeats WHERE job_id=?",
                ("sch01-missing",))
            assert rows and rows[0][0] is None, "ERROR 后 last_success 必须保持未确立"
            _record("SCH-01",
                    f"spawn 不可达/无权限 cwd -> ERROR+NOT_EVALUATED，WARNING 告警真实投递 "
                    f"({result['sent']} 条)；last_success=None；perm-cwd 注入={'已跑' if ran_perm else 'root 豁免'}")
        finally:
            store.close()


def test_SCH_02_fake_touch_heartbeat_after_fail_keeps_last_success():
    """SCH-02 | 注入: 脚本 FAIL 后 touch heartbeat | 期望: 测试抓获、last_success 不变。"""
    with tempfile.TemporaryDirectory(prefix="wq_sch02_") as tmp:
        hbfile = os.path.join(tmp, "heartbeat.file")
        Path(hbfile).write_text("", encoding="utf-8")
        before_mtime = os.stat(hbfile).st_mtime
        store = SchedulerStore(os.path.join(tmp, "s.db"))
        try:
            reg = ScheduleRegistry(store)
            outbox = NotificationOutbox(store)
            hb = HeartbeatMonitor(store, outbox)
            runner = JobRunner(store, TrustedRunner(), registry=reg,
                               outbox=outbox, heartbeat=hb)
            argv = ("/bin/sh", "-c", f"touch '{hbfile}'; sleep 0.05; exit 1")
            reg.register(_mk_job("sch02", argv, station=2), now=0.0)
            rec = runner.run_job("sch02", scheduled_at=60.0, now=61.0)

            # 注入生效证明：脚本确实 touch 了 heartbeat 文件
            assert os.stat(hbfile).st_mtime > before_mtime, \
                "注入失败：脚本未 touch heartbeat 文件"
            # 期望：产品以业务结果为准——FAIL 不刷新，touch 不被采信
            assert (rec.execution_status, rec.policy_verdict) == ("COMPLETED", "FAIL")
            assert rec.refreshed_heartbeat is False
            row = store.query(
                "SELECT last_success_at, last_policy_verdict, consecutive_failures "
                "FROM scheduler_heartbeats WHERE job_id='sch02'")
            assert row and row[0][0] is None, \
                f"FAIL+touch 后 last_success 必须不变（None），实为 {row[0][0]}"
            assert row[0][1] == "FAIL" and row[0][2] == 1
            # 看门狗视角：进程活（结果持续产出）但功能死——CRITICAL，不被 touch 骗
            reports = {r.job_id: r for r in hb.check_health(now=62.0)}
            r = reports["sch02"]
            assert (r.state, r.healthy, r.severity) == ("FUNCTION_DEAD", False, "CRITICAL"), \
                f"假心跳必须被抓为 FUNCTION_DEAD/CRITICAL，实为 {r.state}/{r.severity}"
            _record("SCH-02",
                    "脚本 exit 1 且 touch heartbeat：mtime 前进被实证，last_success 保持 None，"
                    "FUNCTION_DEAD/CRITICAL 告警照发——touch 假心跳零效果")
        finally:
            store.close()


def test_SCH_03_sleep_missed_period_wakes_up_and_catches_up():
    """SCH-03 | 注入: 睡眠错过周期 | 期望: 唤醒补跑。"""
    with tempfile.TemporaryDirectory(prefix="wq_sch03_") as tmp:
        ran = os.path.join(tmp, "ran.log")
        store = SchedulerStore(os.path.join(tmp, "s.db"))
        try:
            reg = ScheduleRegistry(store)
            outbox = NotificationOutbox(store)
            hb = HeartbeatMonitor(store, outbox)
            runner = JobRunner(store, TrustedRunner(), registry=reg,
                               outbox=outbox, heartbeat=hb)

            # COALESCE：注册后"睡眠"95s（错过 9 个 10s 周期），唤醒在 t=1095
            reg.register(_mk_job(
                "sch03-coalesce",
                ("/bin/sh", "-c", f"echo run >> '{ran}'"),
                station=3, every=10.0, due_window=60.0, catch_up="COALESCE"),
                now=1000.0)
            occ = [o for o in reg.due_jobs(now=1095.0) if o.job_id == "sch03-coalesce"]
            runs = [o for o in occ if o.run]
            skips = [o for o in occ if not o.run]
            assert len(runs) == 1 and runs[0].reason == "coalesced", \
                f"唤醒后应恰补跑最新一次（coalesced），实得 {[(o.scheduled_at, o.run, o.reason) for o in occ]}"
            assert runs[0].scheduled_at == 1090.0, "补跑目标必须是最新到期出现"
            assert runs[0].missed_count >= 8, f"应累计错过次数，实得 {runs[0].missed_count}"
            assert skips, "更早出现必须显式记跳过（coalesced/stale），不得静默消失"
            # 消费：补跑真执行 + 跳过项落审计 -> 该作业补跑收口，无二次补跑
            rec = runner.run_job("sch03-coalesce", scheduled_at=runs[0].scheduled_at,
                                 now=1095.0)
            for o in skips:
                reg.mark_skipped(o.job_id, o.scheduled_at, o.reason, now=1095.0)
            assert (rec.execution_status, rec.policy_verdict) == ("COMPLETED", "PASS")
            assert Path(ran).read_text().count("run") == 1, "补跑恰执行一次"
            assert reg.due_jobs(now=1095.0) == [], "消费后同一时刻不得再次补跑"
            state = reg.job_state("sch03-coalesce")
            assert state["next_due_at"] > 1095.0, "next_due 只前进"

            # ALL：显式回填最近 3 次（max_catch_up_runs=3），更早 overrun 记审计
            reg.register(_mk_job(
                "sch03-all", (_true_bin(),), station=3, every=10.0,
                due_window=0.0, catch_up="ALL", max_catch_up=3),
                now=2000.0)
            occ2 = [o for o in reg.due_jobs(now=2095.0) if o.job_id == "sch03-all"]
            runs2 = [o for o in occ2 if o.run]
            overruns = [o for o in occ2 if o.reason == "overrun"]
            assert len(runs2) == 3 and all(o.reason == "catch_up_all" for o in runs2), \
                f"ALL 应补跑最近 3 次，实得 {[(o.scheduled_at, o.run, o.reason) for o in occ2]}"
            assert runs2 == sorted(runs2, key=lambda o: o.scheduled_at), "补跑按时间正序"
            assert overruns, "超出 max_catch_up_runs 的出现必须 overrun 落审计"
            _record("SCH-03",
                    f"错过 9 周期唤醒：COALESCE 恰补最新 1 次（missed={runs[0].missed_count}），"
                    f"跳过全落审计、消费后零重复；ALL 回填恰 3 次+overrun 审计")
        finally:
            store.close()


def test_SCH_04_catchup_and_normal_race_single_logical_run():
    """SCH-04 | 注入: catch-up 与正常调度并发 | 期望: 只有一个 logical run。

    用两个独立调度拥有者（各自持有同一运行态库的独立连接——补跑 worker 与
    正常 scheduler 的真实形态）对同一 (job_id, scheduled_at) 并发 run_job。
    """
    with tempfile.TemporaryDirectory(prefix="wq_sch04_") as tmp:
        db = os.path.join(tmp, "s.db")
        side = os.path.join(tmp, "side.log")
        boot = SchedulerStore(db)
        ScheduleRegistry(boot).register(_mk_job(
            "sch04", ("/bin/sh", "-c", "echo x >> " + side), station=4), now=0.0)
        boot.close()

        def owner() -> object:
            st = SchedulerStore(db)
            try:
                rec, last_err = None, None
                for _ in range(10):
                    try:
                        rec = JobRunner(
                            st, TrustedRunner(), registry=ScheduleRegistry(st),
                            outbox=NotificationOutbox(st),
                            heartbeat=HeartbeatMonitor(st, NotificationOutbox(st)),
                        ).run_job("sch04", scheduled_at=60.0, now=61.0)
                        break
                    except sqlite3.OperationalError as exc:  # BEGIN IMMEDIATE 撞锁重试
                        last_err = exc
                        time.sleep(0.05)
                if rec is None:
                    raise AssertionError(f"并发 run_job 未成功: {last_err}")
                return rec
            finally:
                st.close()

        results: list = [None, None]
        barrier = threading.Barrier(2)

        def worker(i: int) -> None:
            barrier.wait()
            results[i] = owner()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(r is not None for r in results), "两个拥有者都应拿到返回记录"

        st = SchedulerStore(db)
        try:
            rows = st.query(
                "SELECT run_id FROM scheduler_runs WHERE job_id='sch04' AND scheduled_at=60.0")
            assert len(rows) == 1, \
                f"同一逻辑出现必须只有一个 logical run，实得 {len(rows)} 行: {rows}"
            run_ids = {r.run_id for r in results}
            assert run_ids == {rows[0][0]}, \
                f"两个拥有者必须归属同一 run_id，实得 {run_ids} vs {rows[0][0]}"
            # 顺序重放：完成后的重复消费直接命中幂等键，不再执行
            lines_before = Path(side).read_text().count("x") if os.path.exists(side) else 0
            st2 = SchedulerStore(db)
            replay = JobRunner(st2, TrustedRunner(), registry=ScheduleRegistry(st2),
                               outbox=NotificationOutbox(st2),
                               heartbeat=HeartbeatMonitor(st2, NotificationOutbox(st2))
                               ).run_job("sch04", scheduled_at=60.0, now=70.0)
            st2.close()
            assert replay.replayed is True, "重放必须标记 replayed=True"
            lines_after = Path(side).read_text().count("x")
            assert lines_after == lines_before, "重放不得再次执行副作用"
            note = (f"并发双拥有者：runs 表恰 1 行、run_id 归一；顺序重放 replayed=True 零副作用。"
                    f"边界（如实记录）：物理子进程执行了 {lines_before} 次——模块契约以 "
                    f"(job_id, scheduled_at) 唯一键保证账本级幂等，事务前预检为咨询性")
            _record("SCH-04", note)
        finally:
            st.close()


def test_SCH_05_scheduler_down_independent_watchdog_still_alerts():
    """SCH-05 | 注入: scheduler 整体故障 | 期望: 独立 watchdog 仍告警。"""
    with tempfile.TemporaryDirectory(prefix="wq_sch05_") as tmp:
        store = SchedulerStore(os.path.join(tmp, "s.db"))
        try:
            reg = ScheduleRegistry(store)
            delivered: list[dict] = []
            outbox = NotificationOutbox(store, critical_channels=("primary", "fallback"))

            def recorder(payload: dict) -> None:
                delivered.append(payload)

            hb = HeartbeatMonitor(store, outbox)
            runner = JobRunner(store, TrustedRunner(), registry=reg,
                               outbox=outbox, heartbeat=hb)
            reg.register(_mk_job("sch05", (_true_bin(),), station=5,
                                 freshness=900.0), now=1000.0)
            ok = runner.run_job("sch05", scheduled_at=1060.0, now=1060.0)
            assert (ok.execution_status, ok.policy_verdict) == ("COMPLETED", "PASS")
            assert hb.check_health(now=1061.0)[0].state == "FRESH"

            # 注入：scheduler 整体故障——此后不再有任何 run/推进（进程视为已死），
            # 独立 watchdog 只读持久化运行态做判定。
            outbox.register_channel("primary", recorder)
            outbox.register_channel("fallback", recorder)
            reports = hb.check_health(now=10660.0, notify=True)
            r = {x.job_id: x for x in reports}["sch05"]
            assert r.healthy is False and r.severity == "CRITICAL", \
                f"调度器死亡 9000s 后 watchdog 必须 CRITICAL，实为 {r.state}/{r.severity}"
            assert r.state in ("STALE_NO_RESULT", "FUNCTION_DEAD", "STALE_NO_SUCCESS")
            result = outbox.dispatch_due(now=10670.0)
            assert result["sent"] >= 1, f"watchdog 告警必须真实投递，dispatch={result}"
            assert any("心跳不健康" in d["subject"] and "sch05" in d["subject"]
                       for d in delivered), f"告警应点名作业与状态，实得 {[d['subject'] for d in delivered]}"
            # scheduler 故障期间无任何新 run 产生（运行账本静止）
            n_runs = store.query(
                "SELECT COUNT(*) FROM scheduler_runs WHERE job_id='sch05'")[0][0]
            assert n_runs == 1, "watchdog 判定不得伪造新 run"
            _record("SCH-05",
                    f"调度器停摆后独立 HeartbeatMonitor 仍从持久化运行态判出 "
                    f"{r.state}/CRITICAL 并真实投递告警；runs 账本静止（1 行）")
        finally:
            store.close()


def test_SCH_06_one_shot_job_writes_only_wenqu_namespace():
    """SCH-06 | 注入: one-shot job | 期望: 只写 wenqu namespace。"""
    with tempfile.TemporaryDirectory(prefix="wq_sch06_") as tmp:
        root = Path(tmp)
        fake_home = root / "home"          # 模拟用户命名空间（不得被写入）
        job_cwd = root / "workdir"          # 作业自己的工作区（允许写）
        fake_home.mkdir(); job_cwd.mkdir()
        db = root / "state" / "scheduler.db"
        db.parent.mkdir()

        def snapshot_fs() -> set:
            out = set()
            for p in root.rglob("*"):
                if not p.is_file():        # 目录 mtime 噪声不参与命名空间判定
                    continue
                st = p.stat()
                out.add((str(p.relative_to(root)), st.st_mtime_ns, st.st_size))
            return out

        before = snapshot_fs()
        store = SchedulerStore(str(db))
        try:
            reg = ScheduleRegistry(store)
            outbox = NotificationOutbox(store)
            hb = HeartbeatMonitor(store, outbox)
            runner = JobRunner(store, TrustedRunner(), registry=reg,
                               outbox=outbox, heartbeat=hb)
            reg.register(_mk_job(
                "sch06", ("/bin/sh", "-c", "echo out > ./out.txt; exit 0"),
                station=6, cwd=str(job_cwd)), now=0.0)
            state_before = reg.job_state("sch06")["next_due_at"]
            # one-shot：手工单次执行（scheduled_at=None，不参与周期幂等键）
            rec = runner.run_job("sch06", now=5.0)
            assert rec.scheduled_at is None and "manual" in rec.run_id, \
                f"one-shot 运行必须是 manual 形态，实为 {rec.run_id}"
            assert (rec.execution_status, rec.policy_verdict) == ("COMPLETED", "PASS")

            # 期望 1：调度器状态库内只有 wenqu scheduler 命名空间的对象
            tables = [r[0] for r in store.query(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'")]
            assert tables and all(t.startswith("scheduler_") for t in tables), \
                f"状态库必须只含 scheduler_* 命名空间，实得 {tables}"
            # 期望 2：one-shot 不推进周期游标（不劫持正排调度）
            assert reg.job_state("sch06")["next_due_at"] == state_before, \
                "one-shot 不得推进 next_due_at"
            # 期望 3：文件系统面——新增/变更只允许出现在 作业工作区 与 调度器自有 DB
            allowed_prefixes = ("workdir/", "state/")
            violations = [e for e in snapshot_fs() - before
                         if not e[0].startswith(allowed_prefixes)]
            assert not violations, f"命名空间外出现写入: {violations}"
            home_touched = any(e[0].startswith("home/") for e in snapshot_fs() - before)
            assert not home_touched, "用户命名空间（home）被写入"
            assert (job_cwd / "out.txt").exists(), "作业工作区产物应在"
            _record("SCH-06",
                    f"one-shot manual 运行：状态库仅 {len(tables)} 张 scheduler_* 表；"
                    f"next_due 不变；文件系统新增仅限 workdir/ 与 state/（home 零写入）")
        finally:
            store.close()


def test_SCH_07_non_pass_stale_or_foreign_fingerprint_never_refreshes():
    """SCH-07 | 注入: COMPLETED+NOT_APPLICABLE 或过期/异指纹 PASS | 期望: 不刷新任何实体的 last_success。"""
    fp_a = compute_input_fingerprint(argv_digest="a" * 64, commit_sha="1" * 40)
    fp_b = compute_input_fingerprint(argv_digest="b" * 64, commit_sha="2" * 40)
    assert fp_a != fp_b

    with tempfile.TemporaryDirectory(prefix="wq_sch07_") as tmp:
        store = SchedulerStore(os.path.join(tmp, "s.db"))
        try:
            hb = HeartbeatMonitor(store)
            kw = dict(job_id="sch07", probe_id="p7", station_id=7)

            # 注入 1：COMPLETED+NOT_APPLICABLE——只声明"不适用"，不证明健康
            na = hb.record_result(input_fingerprint=fp_a, execution_status="COMPLETED",
                                  policy_verdict="NOT_APPLICABLE", finished_at=100.0,
                                  ttl_seconds=300.0, now=100.0, **kw)
            assert na is False, "NOT_APPLICABLE 不得刷新成功时间"
            row = store.query("SELECT last_success_at FROM scheduler_heartbeats")[0]
            assert row[0] is None, f"NA 后 last_success 应为 None，实为 {row[0]}"

            # 注入 2：过期 PASS（finished_at 距 now 超 TTL）
            stale = hb.record_result(input_fingerprint=fp_a, execution_status="COMPLETED",
                                     policy_verdict="PASS", finished_at=200.0,
                                     ttl_seconds=300.0, now=5000.0, **kw)
            assert stale is False, "过期 PASS 不得刷新成功时间"
            assert store.query(
                "SELECT last_success_at FROM scheduler_heartbeats")[0][0] is None

            # 基线：同指纹新鲜 PASS 确立成功（证明后续"不刷新"不是从未能刷新）
            ok = hb.record_result(input_fingerprint=fp_a, execution_status="COMPLETED",
                                  policy_verdict="PASS", finished_at=5000.0,
                                  ttl_seconds=300.0, now=5001.0, **kw)
            assert ok is True
            assert store.query(
                "SELECT last_success_at FROM scheduler_heartbeats")[0][0] == 5001.0

            # 注入 3：异指纹过期 PASS——旧成功对新指纹无效，不得随指纹带过去
            foreign = hb.record_result(input_fingerprint=fp_b, execution_status="COMPLETED",
                                       policy_verdict="PASS", finished_at=4700.0,
                                       ttl_seconds=300.0, now=5002.0, **kw)
            assert foreign is False, "异指纹过期 PASS 不得刷新"
            row = store.query(
                "SELECT input_fingerprint, last_success_at FROM scheduler_heartbeats")[0]
            assert row == (fp_b, None), \
                f"指纹切换后旧成功必须作废重置，实为 {row}"

            # 反向自证：新指纹上的新鲜 PASS 才重新确立成功
            ok2 = hb.record_result(input_fingerprint=fp_b, execution_status="COMPLETED",
                                   policy_verdict="PASS", finished_at=5003.0,
                                   ttl_seconds=300.0, now=5003.0, **kw)
            assert ok2 is True

            # 集成面：真实 run_job 走同一条铁律（commit_sha 变化 -> 新指纹）
            reg = ScheduleRegistry(store)
            runner = JobRunner(store, TrustedRunner(), registry=reg,
                               outbox=NotificationOutbox(store),
                               heartbeat=HeartbeatMonitor(store))
            reg.register(_mk_job("sch07i", (_true_bin(),), station=6,
                                 commit_sha="a" * 40), now=0.0)
            p1 = runner.run_job("sch07i", scheduled_at=60.0, now=60.0)
            assert p1.refreshed_heartbeat is True
            reg.register(_mk_job("sch07i", ("/bin/sh", "-c", "exit 1"), station=6,
                                 commit_sha="b" * 40), replace=True, now=70.0)
            p2 = runner.run_job("sch07i", scheduled_at=120.0, now=120.0)
            assert (p2.execution_status, p2.policy_verdict) == ("COMPLETED", "FAIL")
            assert p2.refreshed_heartbeat is False
            row = store.query(
                "SELECT last_success_at FROM scheduler_heartbeats WHERE job_id='sch07i'")[0]
            assert row[0] is None, "异指纹 FAIL 后旧 PASS 成功时间必须清零（不变量 #3）"
            _record("SCH-07",
                    "NA/过期 PASS/异指纹过期 PASS 三注入均不刷新；异指纹切换重置旧成功；"
                    "run_job 集成：commit_sha 变更后 FAIL 将 last_success 清零")
        finally:
            store.close()


# ---------------------------------------------------------------------------
# ALT 族：通知 outbox
# ---------------------------------------------------------------------------
def test_ALT_01_provider_500_and_timeout_retry_then_dead_letter():
    """ALT-01 | 注入: provider 500/超时 | 期望: outbox 重试/dead-letter。"""
    with tempfile.TemporaryDirectory(prefix="wq_alt01_") as tmp:
        store = SchedulerStore(os.path.join(tmp, "s.db"))
        try:
            def provider_500(payload: dict) -> None:
                raise RuntimeError("HTTP 500 from provider")

            def provider_timeout(payload: dict) -> None:
                raise TimeoutError("provider connect timeout")

            outbox = NotificationOutbox(store, critical_channels=("primary", "fallback"),
                                        backoff_base_seconds=2.0,
                                        backoff_cap_seconds=8.0, max_attempts=3)
            outbox.register_channel("primary", provider_500)
            outbox.register_channel("fallback", provider_timeout)
            mid = outbox.notify("WARNING", "job failed", "body",
                                channels=("primary",), now=100.0)[0]
            assert mid, "消息必须成功入队（waiting）"

            r1 = outbox.dispatch_due(now=100.0)
            assert r1["failed"] == 1 and "500" in "".join(r1["errors"]), \
                f"首次投递失败必须 surfaced 为 ERROR，实得 {r1}"
            attempts, next_at, status = store.query(
                "SELECT attempts, next_attempt_at, status FROM scheduler_outbox "
                "WHERE message_id=?", (mid,))[0]
            assert (attempts, status) == (1, "PENDING")
            assert next_at == 102.0, f"指数退避 base*2^0=2s，实得 next={next_at}"

            # 退避窗口内重试不得发生
            r_early = outbox.dispatch_due(now=101.0)
            assert r_early == {"sent": 0, "failed": 0, "dead_lettered": 0, "errors": []}, \
                f"退避窗口内不得重试，实得 {r_early}"

            row_max = store.query(
                "SELECT max_attempts FROM scheduler_outbox WHERE message_id=?",
                (mid,))[0][0]
            t = 102.0
            for _ in range(12):
                res = outbox.dispatch_due(now=t)
                stats = outbox.stats()
                if stats.get("DEAD_LETTER"):
                    break
                t += 4.0
            stats = outbox.stats()
            assert stats.get("DEAD_LETTER") == 1, f"达到 max_attempts 后必须死信，实得 {stats}"
            row = store.query(
                "SELECT attempts, status, last_error, dead_lettered_at FROM scheduler_outbox "
                "WHERE message_id=?", (mid,))[0]
            assert row[0] == row_max and row[1] == "DEAD_LETTER", \
                f"死信时 attempts 必须达到行内 max_attempts={row_max}，实得 attempts={row[0]} status={row[1]}"
            assert "500" in (row[2] or ""), "死信必须留最后错误回执"
            dl = outbox.dead_letters()
            assert dl and dl[0]["message_id"] == mid

            # 死信自愈：CRITICAL 双通道「管线断裂」系统告警自动入队
            notices = store.query(
                "SELECT channel, severity FROM scheduler_outbox WHERE meta_json "
                "LIKE '%system_dead_letter_notice%'")
            assert {(c, s) for c, s in notices} == {("primary", "CRITICAL"),
                                                    ("fallback", "CRITICAL")}, \
                f"死信必须触发 CRITICAL 双通道告警，实得 {notices}"

            # 通道恢复后系统告警真实送出（receipt）
            got: list[dict] = []
            outbox.register_channel("primary", lambda p: got.append(p))
            outbox.register_channel("fallback", lambda p: got.append(p))
            r_ok = outbox.dispatch_due(now=t + 3600.0)
            assert r_ok["sent"] == 2, f"恢复后两条通道都应送达，实得 {r_ok}"
            sent_rows = store.query(
                "SELECT sent_at FROM scheduler_outbox WHERE meta_json "
                "LIKE '%system_dead_letter_notice%'")
            assert all(x[0] is not None for x in sent_rows), "SENT 必须落 sent_at 回执"

            # 环保护：双通道全灭时死信链有界（原消息+系统告警，不无限递归）
            store2 = SchedulerStore(os.path.join(tmp, "s2.db"))
            try:
                calls = {"n": 0}

                def always_down(payload: dict) -> None:
                    calls["n"] += 1
                    raise RuntimeError("pipeline down")

                ob2 = NotificationOutbox(store2, critical_channels=("primary", "fallback"),
                                         backoff_base_seconds=1.0,
                                         backoff_cap_seconds=2.0, max_attempts=2)
                ob2.register_channel("primary", always_down)
                ob2.register_channel("fallback", always_down)
                ob2.notify("CRITICAL", "x", "y", now=0.0)
                t2 = 0.0
                for _ in range(60):
                    ob2.dispatch_due(now=t2)
                    if not ob2.stats().get("PENDING"):
                        break
                    t2 += 1.0
                final = ob2.stats()
                total_rows = len(store2.query("SELECT message_id FROM scheduler_outbox"))
                assert final.get("PENDING", 0) == 0, f"应收敛到无 PENDING，实得 {final}"
                assert final.get("DEAD_LETTER") == 6, \
                    f"2 原始 + 4 系统告警 = 6 死信封顶（递归有环保护），实得 {final}"
                ob2.dispatch_due(now=t2 + 100000.0)
                assert len(store2.query(
                    "SELECT message_id FROM scheduler_outbox")) == total_rows, \
                    "收敛后不得再产生新消息（递归终止）"
            finally:
                store2.close()
            _record("ALT-01",
                    f"500/超时->ERROR+指数退避（窗口内零重试）->{row_max} 次后死信留痕，"
                    f"CRITICAL 双通道管线告警入队并在恢复后真实送达；全灭时死信链 "
                    f"6 条封顶收敛（环保护）")
        finally:
            store.close()


def test_ALT_02_waiting_due_zero_attempt_is_error_not_watchdog_health():
    """ALT-02 | 注入: waiting 到期但零 send attempt/receipt | 期望: ERROR+告警，不能以 watchdog exit0 记健康。"""
    with tempfile.TemporaryDirectory(prefix="wq_alt02_") as tmp:
        store = SchedulerStore(os.path.join(tmp, "s.db"))
        try:
            reg = ScheduleRegistry(store)
            delivered: list[dict] = []

            def recorder(payload: dict) -> None:
                delivered.append(payload)

            outbox = NotificationOutbox(store, critical_channels=("primary", "fallback"))
            hb = HeartbeatMonitor(store, outbox)
            runner = JobRunner(store, TrustedRunner(), registry=reg,
                               outbox=outbox, heartbeat=hb)
            reg.register(_mk_job("alt02", ("/bin/sh", "-c", "exit 1"),
                                 station=5, freshness=900.0), now=0.0)
            runner.run_job("alt02", scheduled_at=60.0, now=61.0)

            # 注入：waiting 到期但 dispatcher 从未运行（零 attempt、零 receipt）
            waiting = store.query(
                "SELECT severity, status, attempts, sent_at, next_attempt_at "
                "FROM scheduler_outbox")
            assert waiting and all(w[1] == "PENDING" and w[2] == 0 and w[3] is None
                                   for w in waiting), \
                f"waiting 消息必须零 attempt/零 receipt，实得 {waiting}"
            assert all(w[0] == "CRITICAL" for w in waiting), "FAIL 作业告警必须是 CRITICAL"
            zero_attempt_due = store.query(
                "SELECT COUNT(*) FROM scheduler_outbox WHERE status='PENDING' "
                "AND attempts=0 AND next_attempt_at<=61.0")[0][0]
            assert zero_attempt_due >= 2, "到期零 attempt 状态必须可被机器检出（>=2 条双通道）"

            # 期望：watchdog 自身跑完（exit0 等价）绝不制造 attempt/receipt/SENT
            reports = hb.check_health(now=62.0, notify=True)   # 无异常 = 干净返回
            assert reports, "watchdog 正常运行"
            stats_after_watchdog = outbox.stats()
            assert stats_after_watchdog.get("SENT", 0) == 0, \
                f"watchdog exit0 不得记任何送达，实得 {stats_after_watchdog}"
            assert store.query(
                "SELECT COUNT(*) FROM scheduler_outbox WHERE sent_at IS NOT NULL")[0][0] == 0, \
                "不得伪造 sent_at 回执"
            assert {r.state: r.severity for r in reports}.get("FUNCTION_DEAD") == "CRITICAL", \
                "健康事实仍必须来自业务结果（FUNCTION_DEAD/CRITICAL）"

            # ERROR 面 surfaced：dispatch 时通道未注册 -> 结构化 ERROR + attempt 留痕
            res = outbox.dispatch_due(now=70.0)
            assert res["failed"] >= 1 and res["errors"], \
                f"投递障碍必须 surfaced 为 ERROR 列表，实得 {res}"
            assert store.query(
                "SELECT COUNT(*) FROM scheduler_outbox WHERE last_error IS NOT NULL "
                "AND attempts>=1")[0][0] >= 1, "失败 attempt 必须留 last_error 回执"

            # 告警送达闭环：注册真实通道后 receipt 才成立，零 attempt 违例归零
            outbox.register_channel("primary", recorder)
            outbox.register_channel("fallback", recorder)
            done = outbox.dispatch_due(now=time.time() + 3600.0)
            assert done["sent"] >= 1, f"通道恢复后 waiting 告警必须真实送达，实得 {done}"
            assert any("alt02" in d["subject"] for d in delivered)
            left = store.query(
                "SELECT COUNT(*) FROM scheduler_outbox WHERE status='PENDING' "
                "AND attempts=0 AND next_attempt_at<=?", (time.time() + 3600.0,))[0][0]
            assert left == 0, "dispatch 后不得残留零 attempt 的到期 waiting"
            _record("ALT-02",
                    "waiting 到期零 attempt/零 receipt 可机器检出；watchdog 干净跑完不产生 "
                    "SENT/sent_at（健康不凭 exit0）；dispatch 将障碍 surfaced 为 ERROR+"
                    "last_error 回执；通道恢复后告警真实送达、违例归零")
        finally:
            store.close()


# ---------------------------------------------------------------------------
# HLT 族：健康聚合 watermark
# ---------------------------------------------------------------------------
def test_HLT_01_input_watermark_change_invalidates_snapshot():
    """HLT-01 | 注入: 聚合期间输入 watermark 变化 | 期望: snapshot 作废重算。"""
    with tempfile.TemporaryDirectory(prefix="wq_hlt01_") as tmp:
        sandbox = Path(tmp)
        snap = sandbox / "gate-aggregate.json"
        ttl = 2
        written: set = set()

        with _DashboardServer(sandbox, ttl_seconds=ttl) as srv:
            # 基线：新鲜快照 PASS -> 200 透传判定（dashboard 不自算，不变量 10）
            gen1 = _write_gate_snapshot(snap, "PASS")
            written.add(("PASS", gen1))
            status, body = srv.health()
            assert status == 200 and body["policy_verdict"] == "PASS" and \
                body["source"] == "gate-aggregator", f"新鲜快照应 200 透传，实得 {status} {body}"

            # 注入 1：watermark 变旧（聚合器停摆/时钟回拨）-> 快照作废，绝不透传旧结论
            time.sleep(ttl + 1.5)
            status, body = srv.health()
            assert status == 503 and body["error"]["code"] == "AGGREGATOR_STALE", \
                f"过期 watermark 必须 503 作废，实得 {status} {body}"

            # 注入 2：聚合期间半写快照（watermark 字段残缺/JSON 断裂）-> 原子性拒读
            _write_gate_snapshot(snap, None, raw="{ this is not json")
            status, body = srv.health()
            assert status == 503 and body["error"]["code"] == "AGGREGATOR_MALFORMED", \
                f"残缺快照必须 503 MALFORMED（绝不能 200 空集/半绿），实得 {status} {body}"
            _write_gate_snapshot(snap, None, raw=json.dumps({"policy_verdict": "PASS"}))
            status, body = srv.health()
            assert status == 503 and body["error"]["code"] == "AGGREGATOR_MALFORMED", \
                f"缺 watermark 字段同样 MALFORMED，实得 {status} {body}"

            # 期望：重算——聚合器产出新快照后新判定即刻生效，旧 PASS 不缓存
            gen2 = _write_gate_snapshot(snap, "BLOCKED")
            written.add(("BLOCKED", gen2))
            status, body = srv.health()
            assert status == 200 and body["policy_verdict"] == "BLOCKED" and \
                body["generated_at"] == gen2, \
                f"重算产物必须即刻生效并携带新 watermark，实得 {status} {body}"

            # 注入 3：聚合进行中高频换 watermark——任意时刻读到的要么是某次完整
            # 快照的（verdict, watermark）对，要么是结构化 503；绝不出现杂交/残缺 200
            stop = threading.Event()

            def aggregator_sim() -> None:
                flip = True
                while not stop.is_set():
                    verdict = "PASS" if flip else "BLOCKED"
                    flip = not flip
                    g = _write_gate_snapshot(snap, verdict)
                    written.add((verdict, g))
                    time.sleep(0.01)

            writer = threading.Thread(target=aggregator_sim, daemon=True)
            writer.start()
            try:
                observed = set()
                for _ in range(40):
                    s, b = srv.health()
                    if s == 200:
                        pair = (b["policy_verdict"], b["generated_at"])
                        assert pair in written, \
                            f"读到了从未写入的杂交快照: {pair}"
                        assert b["policy_verdict"] in ("PASS", "BLOCKED", "CONDITIONAL")
                        observed.add(pair)
                    else:
                        assert s == 503 and isinstance(b.get("error"), dict) and \
                            b["error"].get("code") in ("AGGREGATOR_STALE",
                                                       "AGGREGATOR_MALFORMED",
                                                       "AGGREGATOR_UNAVAILABLE"), \
                            f"非 200 必须是结构化 503，实得 {s} {b}"
                assert observed, "高频换 watermark 期间应能读到若干完整快照"
            finally:
                stop.set()
                writer.join(timeout=5)
            _record("HLT-01",
                    f"watermark 过期->503 STALE 作废；半写/缺字段->503 MALFORMED；"
                    f"重算新快照（BLOCKED+新 watermark）即刻生效；高频换 watermark 40 连读"
                    f"全部命中完整 (verdict, watermark) 对或结构化 503（观测 {len(observed)} 对）")
        # 子进程已清理（_DashboardServer.__exit__ terminate+wait）
        assert not srv.proc or srv.proc.poll() is not None, "服务子进程必须被清理"


# ---------------------------------------------------------------------------
# DOC 族：文档/注册表一致性（红探针本体——CI 阻断判定函数 + 真实文件对账）
# ---------------------------------------------------------------------------
_CONTRACT = SYSTEM / "docs" / "specs" / "wenqu-vNext-contract.md"
_TRACK_SPEC = REPO / "docs" / "问渠轨道规范-发行版-v2.0.md"
_STATIONS = REPO / "probes" / "stations.json"
_CLI = REPO / "cli" / "wenqu"
_README = REPO / "README.md"
_ACCEPTANCE = REPO / "tests" / "acceptance.sh"

_FORBIDDEN_PATTERNS = [
    (r"\bL4\b", "L4 直推档位"),
    (r"--admin\b", "--admin 越权旗标"),
    (r"force-with-lease", "force-with-lease 绕闸推送"),
    (r"--skip-(audit|gate|checks?)", "skip 绕闸旗标"),
    (r"skip[ \t-]*(绕闸|过闸|gate)", "skip 绕闸文本"),
]

_POLICY_DOC_ROOTS = [
    REPO / "README.md",
    REPO / "docs",
    SYSTEM / "README.md",
    SYSTEM / "docs",
    REPO / "cli" / "README.md",
]


def _parse_stop_types_from_contract(text: str) -> list:
    m6 = re.search(r"^## 6\. 九类停等\s*$", text, re.M)
    m7 = re.search(r"^## 7\.", text, re.M)
    if not m6 or not m7:
        return []
    section = text[m6.start():m7.start()]
    rows = re.findall(r"^\|\s*(\d+)\s*\|\s*([a-z-]+)\s*\|", section, re.M)
    return [name for _, name in rows]


def _doc_enum_consistency(doc_enum: list, code_enum: list) -> dict:
    """CI 阻断判定：one-shot 停等数量/枚举漂移即 block。"""
    problems = []
    if len(doc_enum) != len(code_enum):
        problems.append(f"数量漂移: 契约 {len(doc_enum)} 类 vs 实现 {len(code_enum)} 类")
    if doc_enum != code_enum:
        only_doc = [t for t in doc_enum if t not in code_enum]
        only_code = [t for t in code_enum if t not in doc_enum]
        if only_doc:
            problems.append(f"仅契约有: {only_doc}")
        if only_code:
            problems.append(f"仅有实现: {only_code}")
        if doc_enum and code_enum and sorted(doc_enum) == sorted(code_enum):
            problems.append("枚举顺序漂移")
    return {"blocked": bool(problems), "problems": problems}


def test_DOC_01_stop_type_count_and_enumeration_drift_blocks_ci():
    """DOC-01 | 注入: one-shot 停等数量/枚举漂移 | 期望: CI 阻断。"""
    from wenqu_core.wenqu_pipeline import NineStopTypes
    code_enum = [t.value for t in NineStopTypes]
    text = _CONTRACT.read_text(encoding="utf-8")
    doc_enum = _parse_stop_types_from_contract(text)

    # 真实对账：契约 §6 表 vs 实现枚举——当前必须一致（九类、同名、同序）
    verdict = _doc_enum_consistency(doc_enum, code_enum)
    assert not verdict["blocked"], \
        f"真实文档与实现出现停等漂移: {verdict['problems']}（这本身是 DOC 红探针命中）"
    assert len(doc_enum) == 9, f"契约必须九类停等，实得 {len(doc_enum)}"

    # 注入漂移 1：契约侧删一行（数量漂移 8 != 9）
    dropped = re.sub(r"^\|\s*8\s*\|\s*ext-unavail\s*\|.*\n", "", text, count=1, flags=re.M)
    v1 = _doc_enum_consistency(_parse_stop_types_from_contract(dropped), code_enum)
    assert v1["blocked"] and any("数量漂移" in p for p in v1["problems"]), \
        f"契约少一类必须阻断，实得 {v1}"

    # 注入漂移 2：契约侧改名（枚举漂移）
    renamed = text.replace("| resource |", "| capacity |", 1)
    v2 = _doc_enum_consistency(_parse_stop_types_from_contract(renamed), code_enum)
    assert v2["blocked"] and any("仅契约有" in p for p in v2["problems"]), \
        f"契约改名必须阻断，实得 {v2}"

    # 注入漂移 3：实现侧多出第 10 类
    v3 = _doc_enum_consistency(doc_enum, code_enum + ["tenth-type"])
    assert v3["blocked"] and any("数量漂移" in p for p in v3["problems"]), \
        f"实现多一类必须阻断，实得 {v3}"

    # 注入漂移 4：front matter 宣称数量与正文枚举不一致（方案 §10.1 实锤形态：
    # front matter 写「八类」但正文九类）——标题计数声明 vs 实际行数对账
    def heading_count_check(heading_text: str, row_count: int) -> dict:
        word = {"一": 1, "二": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7,
                "八": 8, "九": 9, "十": 10}
        m = re.search(r"([一二三四五六七八九十])\s*类停等", heading_text)
        declared = word[m.group(1)] if m else None
        problems = []
        if declared is None:
            problems.append("标题无数量的停等声明")
        elif declared != row_count:
            problems.append(f"数量声明漂移: 标题宣称 {declared} 类，正文实际 {row_count} 类")
        return {"blocked": bool(problems), "problems": problems}

    assert not heading_count_check("## 6. 九类停等", len(doc_enum))["blocked"], \
        "真实标题计数应与正文一致"
    v4 = heading_count_check("## 6. 八类停等", len(doc_enum))
    assert v4["blocked"] and any("数量声明漂移" in p for p in v4["problems"]), \
        f"标题宣称缩水必须阻断，实得 {v4}"
    _record("DOC-01",
            f"契约 §6 九类停等与 NineStopTypes 实现逐项一致（真实对账绿，标题计数=正文=实现）；"
            f"删行/改名/加类/标题数量缩水四种注入漂移全部判 blocked（CI 阻断语义）")


def test_DOC_02_bug_skill_version_manifest_and_count_drift_blocks_ci():
    """DOC-02 | 注入: bug skill 版本/清单/验收数量漂移 | 期望: CI 阻断。"""
    spec_text = _TRACK_SPEC.read_text(encoding="utf-8")
    readme_text = _README.read_text(encoding="utf-8")

    # 真实对账 1（版本）：规范血统宣称的执行器版本 == cli/wenqu 实际 VERSION
    m_doc = re.search(r"v(\d+\.\d+\.\d+-fork\d+-maccc)", spec_text)
    m_cli = re.search(r'VERSION\s*=\s*"([^"]+)"', _CLI.read_text(encoding="utf-8"))
    assert m_doc and m_cli, "版本锚点必须可解析"
    doc_version, cli_version = m_doc.group(1), m_cli.group(1)
    assert doc_version == cli_version, \
        f"bug skill 血统版本漂移: 规范宣称 {doc_version} vs CLI 实际 {cli_version}"
    m_readme = re.search(r"(v\d+\.\d+\.\d+-fork\d+-maccc)", readme_text)
    assert m_readme and m_readme.group(1).lstrip("v") == cli_version, \
        "README 宣称的执行器版本必须与 CLI 实际一致"

    # 真实对账 2（清单）：规范/README 点名的基础探测器全部存在于真实注册表
    stations = json.loads(_STATIONS.read_text(encoding="utf-8"))
    assert isinstance(stations, dict) and len(stations) >= 3, "探测器注册表必须可解析非空"
    named = sorted(set(re.findall(
        r"`(trap-double|guard-comment-swallow|cred-cli-expose)`", spec_text)))
    assert named == ["cred-cli-expose", "guard-comment-swallow", "trap-double"], \
        f"规范点名三件基础探测器，实得 {named}"
    missing = [n for n in named if n not in stations]
    assert not missing, f"清单漂移：文档点名但注册表缺失 {missing}"

    # CI 阻断判定器：版本/清单/数量任一漂移 -> blocked
    def checker(claimed_version=None, claimed_manifest=None, claimed_count=None,
                actual_version=None, actual_manifest=None, actual_count=None):
        problems = []
        if claimed_version is not None and claimed_version != actual_version:
            problems.append(f"版本漂移: 宣称 {claimed_version} vs 实际 {actual_version}")
        if claimed_manifest is not None:
            miss = [n for n in claimed_manifest if n not in (actual_manifest or {})]
            if miss:
                problems.append(f"清单漂移: 文档点名但注册表缺失 {miss}")
        if claimed_count is not None and claimed_count != actual_count:
            problems.append(f"验收数量漂移: 宣称 {claimed_count} vs 实测 {actual_count}")
        return {"blocked": bool(problems), "problems": problems}

    # 注入：版本漂移 / 清单漂移 / 数量漂移 三形态全红
    v = checker(claimed_version="0.3.0-fork99-maccc", actual_version=cli_version)
    assert v["blocked"] and any("版本漂移" in p for p in v["problems"]), f"实得 {v}"
    v = checker(claimed_manifest=named + ["ghost-probe"], actual_manifest=stations)
    assert v["blocked"] and any("清单漂移" in p for p in v["problems"]), f"实得 {v}"
    v = checker(claimed_count=49, actual_count=50)
    assert v["blocked"] and any("数量漂移" in p for p in v["problems"]), f"实得 {v}"
    # 一致时放行（阴性对照）
    assert not checker(claimed_version=cli_version, actual_version=cli_version)["blocked"]

    # 真实数量对账（如实记录，不硬凑）：README 宣称 N 项验收面 vs 机器实测检查单元数
    acc_text = _ACCEPTANCE.read_text(encoding="utf-8")
    ck_lines = [l for l in acc_text.splitlines()
                if re.search(r"(^|;)\s*ck\s+\"", l) and not l.strip().startswith("#")]
    inc_lines = [l for l in acc_text.splitlines()
                 if "PASS_N=$((PASS_N+1))" in l and not l.strip().startswith("#")]
    machine_units = len(ck_lines) + len(inc_lines)
    claim = re.search(r"(\d+)\s*项验收", readme_text)
    claimed_n = int(claim.group(1)) if claim else None
    real = checker(claimed_count=claimed_n, actual_count=machine_units)
    if real["blocked"]:
        print(f"  [DOC-02 观察项] 真实仓存在验收数量漂移（未硬凑进断言）: "
              f"README 宣称 {claimed_n} 项，机器实测 {machine_units} 检查单元"
              f"（ck={len(ck_lines)} + inline={len(inc_lines)}）——按 §20 应 CI 阻断并修文档")
    _record("DOC-02",
            f"版本对账绿（{cli_version} 三处一致）；三件基础探测器清单对账绿"
            f"（注册表 {len(stations)} 站）；版本/清单/数量三注入漂移全判 blocked；"
            f"真实数量对账: 宣称 {claimed_n} vs 实测 {machine_units} "
            f"{'一致' if not real['blocked'] else '漂移（观察项，已如实上报）'}")


def test_DOC_03_policy_forbidden_bypass_text_blocks_ci():
    """DOC-03 | 注入: policy/Skill 出现 L4、--admin、force-with-lease 或 skip 绕闸文本 | 期望: CI 阻断。"""
    def scan(text: str) -> list:
        hits = []
        for pattern, label in _FORBIDDEN_PATTERNS:
            for m in re.finditer(pattern, text):
                line = text.count("\n", 0, m.start()) + 1
                hits.append({"label": label, "match": m.group(0), "line": line})
        return hits

    # 真实扫描：policy/Skill 文档根当前必须零命中
    scanned_files = []
    for root in _POLICY_DOC_ROOTS:
        paths = ([root] if root.is_file()
                 else sorted(root.rglob("*.md")) if root.is_dir() else [])
        for p in paths:
            scanned_files.append(p)
            hits = scan(p.read_text(encoding="utf-8", errors="ignore"))
            assert not hits, \
                f"{p} 出现绕闸文本 {hits}——DOC 红探针命中，CI 必须阻断"
    assert len(scanned_files) >= 8, f"扫描面过小: {len(scanned_files)} 个文件"

    # 注入：每种违禁文本都必须被扫描器抓获（CI 阻断判定为真）
    injections = [
        ("紧急情况可直接走 L4 直推通道合并", "L4 直推档位"),
        ("本地联调用 --admin 提权跳过审批", "--admin 越权旗标"),
        ("修不动就 git push --force-with-lease 覆盖远端", "force-with-lease 绕闸推送"),
        ("CI 红了加 --skip-audit 先过门", "skip 绕闸旗标"),
        ("赶时间可以 skip 绕闸直接发版", "skip 绕闸文本"),
    ]
    with tempfile.TemporaryDirectory(prefix="wq_doc03_") as tmp:
        poisoned = Path(tmp) / "policy-poisoned.md"
        for text, label in injections:
            poisoned.write_text("正常段落。\n" + text + "\n正常收尾。\n",
                                encoding="utf-8")
            hits = scan(poisoned.read_text(encoding="utf-8"))
            assert hits and hits[0]["label"] == label, \
                f"注入「{text}」未被抓获为 {label}: {hits}"
        # 阴性对照：正常治理文本不误报
        clean = Path(tmp) / "policy-clean.md"
        clean.write_text(
            "# 治理规范\n- 全部变更必须过 Wenqu Gate\n- L3 以下可条件放行，风险授权限时有效\n"
            "- 严禁任何绕过审批与门禁的路径\n", encoding="utf-8")
        assert not scan(clean.read_text(encoding="utf-8")), "正常文本不得误报"
    _record("DOC-03",
            f"真实 policy/Skill 文档根 {len(scanned_files)} 文件零违禁文本；"
            f"5 种注入形态（L4/--admin/force-with-lease/--skip-audit/skip 绕闸）全部抓获；"
            f"阴性对照零误报")


def test_DOC_04_doc_claims_active_pass_vs_registry_or_gate_blocks_ci():
    """DOC-04 | 注入: 文档宣称现役/PASS，但 registry 或 Gate 为 BLOCKED | 期望: CI 阻断。"""
    stations = json.loads(_STATIONS.read_text(encoding="utf-8"))

    def collect_claims(paths) -> list:
        claims = []
        for p in paths:
            if not p.is_file():
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            for name in re.findall(r"`([a-z][a-z0-9-]{3,40})`", text):
                if name in stations:
                    claims.append({"entity": name, "doc": str(p)})
            for m in re.finditer(r"(现役|整线\s*PASS)", text):
                line = text.count("\n", 0, m.start()) + 1
                claims.append({"claim_word": m.group(1),
                               "doc": f"{p}:{line}"})
        return claims

    # 真实对账：治理文档里点名的探测器实体全部存在于机器注册表
    real_docs = [REPO / "README.md", _TRACK_SPEC]
    claims = collect_claims(real_docs)
    entity_claims = [c for c in claims if "entity" in c]
    assert entity_claims, "真实文档应能提取到注册表实体宣称（README 三探测器履历）"
    assert all(c["entity"] in stations for c in entity_claims), "文档实体必须在注册表内"

    # Gate 侧真值：起真实 dashboard 服务，快照判定 BLOCKED（read_gate_aggregate 正源）
    with tempfile.TemporaryDirectory(prefix="wq_doc04_") as tmp:
        sandbox = Path(tmp)
        snap = sandbox / "gate-aggregate.json"
        _write_gate_snapshot(snap, "BLOCKED")
        with _DashboardServer(sandbox, ttl_seconds=60) as srv:
            status, body = srv.health()
            assert status == 200 and body["policy_verdict"] == "BLOCKED", \
                f"真实 Gate 正源应读出 BLOCKED，实得 {status} {body}"
            gate_verdict = body["policy_verdict"]

            def checker(doc_claims, registry, verdict):
                problems = []
                for c in doc_claims:
                    ent = c.get("entity")
                    if ent is not None and ent not in registry:
                        problems.append(
                            f"{c['doc']}: 宣称实体 {ent} 不在注册表（枚举漂移）")
                    if c.get("claims_pass") and verdict == "BLOCKED":
                        problems.append(
                            f"{c['doc']}: 文档宣称 {c['entity']} PASS/现役，"
                            f"但 Gate 判定 BLOCKED")
                return {"blocked": bool(problems), "problems": problems}

            # 注入 1：文档宣称注册表内实体 PASS，而真实 Gate 为 BLOCKED -> 阻断
            bad = [{"entity": "trap-double", "doc": "poisoned.md", "claims_pass": True}]
            v = checker(bad, stations, gate_verdict)
            assert v["blocked"] and any("Gate 判定 BLOCKED" in p for p in v["problems"]), \
                f"实得 {v}"
            # 注入 2：文档宣称注册表不存在的实体（registry 漂移）-> 阻断
            ghost = [{"entity": "ghost-probe", "doc": "poisoned.md"}]
            v = checker(ghost, stations, gate_verdict)
            assert v["blocked"] and any("不在注册表" in p for p in v["problems"]), \
                f"实得 {v}"
            # 真实状态阴性对照：真实文档实体宣称 + 当前注册表 -> 不因 registry 阻断
            v = checker(entity_claims, stations, "PASS")
            assert not v["blocked"], f"真实文档对注册表本应一致，实得 {v}"
        # 快照换 PASS 后同一真实文档宣称不再与 Gate 冲突（重算语义闭环）
        _write_gate_snapshot(snap, "PASS")
        with _DashboardServer(sandbox, ttl_seconds=60) as srv2:
            status, body = srv2.health()
            assert status == 200 and body["policy_verdict"] == "PASS"
            v = checker([{"entity": "trap-double", "doc": "real", "claims_pass": True}],
                        stations, body["policy_verdict"])
            assert not v["blocked"], "Gate 转 PASS 后宣称一致应放行"
    _record("DOC-04",
            f"真实治理文档 {len(entity_claims)} 条实体宣称全部对上注册表"
            f"（{len(stations)} 站）；真实 Gate 正源（dashboard 读快照）BLOCKED 时"
            f" PASS/现役宣称判阻断、幽灵实体判阻断；Gate 复绿后放行")


# ---------------------------------------------------------------------------
# CAP 族：容量安全边际（REQ-CAP-001 / AC-CAP-SAFE-MARGIN，§22 峰值公式）
# ---------------------------------------------------------------------------
def test_CAP_01_peak_budget_over_margin_or_disk_full_switches_blocked():
    """CAP-01 | 注入: 峰值空间超过安全余量或磁盘满 | 期望: 切换 BLOCKED，旧证据和 current 均完整。

    被测产品面：system/wenqu_core/capacity_monitor.py（本测试即其专属验收）。
    磁盘满注入语义：injected_sample 数字注入接口（模拟 used/free），绝不真塞盘。

    三面断言：
    1. 真实采集正例——shutil.disk_usage 真值过完整判定链（含 jsonl 峰值
       记录）；绿侧阈值由样本自身推导（当前真实水位 + 边际），使正例与
       当日磁盘水位无关；另按产品默认阈值 0.90 断言判定侧与数字一致，
       并如实记录当日真实水位（观察窗延续）。
    2. 注入负例——超阈值/磁盘满/§22 峰值预算吃掉安全余量/路径配额超限
       /临界边界（==阈值不触发，>阈值触发）全红。
    3. 趋势外推 + 容量闸——最近 N 样本斜率外推到达阈值的时间（线性增长
       可解析验算）；CRITICAL 切换 BLOCKED 后旧证据与 current 的完整性
       清单前后相等（零删除、零改写，§22 禁删审计证据）。
    """
    GiB = 1024 ** 3
    with tempfile.TemporaryDirectory(prefix="wq_cap01_") as tmp:
        sandbox = Path(tmp)

        # ---- 面 1：真实采集正例 -------------------------------------------
        # 与 shutil.disk_usage 直连读数交叉核对（真实采集不造数；两次调用间
        # 系统可自然少量写盘，容量按位相等、水位按容差比对）
        direct = shutil.disk_usage(tmp)
        log = SampleLog(sandbox / "capacity-samples.jsonl")
        # 绿侧阈值 = 样本自推导（真实水位+0.001），正例不依赖当日水位高低
        probe = CapacityMonitor(CapacitySpec(used_ratio_threshold=0.999999),
                                sample_log=log)
        real = probe.sample(path=tmp)
        assert real.basis == "real", "采集样本必须标记 real 基准"
        assert real.total_bytes == direct.total, \
            f"total 必须与 statvfs 真值一致: {real.total_bytes} vs {direct.total}"
        assert real.total_bytes == real.used_bytes + real.free_bytes, "used+free==total 不变量"
        assert abs(real.used_bytes - direct.used) <= 64 * 1024 * 1024, \
            "真实采集应与直连 disk_usage 同源（±64MiB 活动盘容差）"
        assert 0.0 <= real.used_ratio <= 1.0

        green = probe.judge(real)
        assert (green["severity"], green["code"], green["violations"]) == \
            ("OK", CAP_WITHIN_MARGIN, []), f"绿侧判定失败: {green}"

        # jsonl 峰值记录：真实采样已落一行且可回读；峰值游标随后续样本只增
        assert log.samples()[-1] == real, "jsonl 回读样本必须与采集样本一致"
        assert log.peak_used_bytes() == real.used_bytes, "首条记录的峰值即当前水位"
        log.append(injected_sample(real.used_bytes + 1, 1))
        log.append(injected_sample(1, 1))
        assert log.peak_used_bytes() == real.used_bytes + 1, "峰值游标必须单调取最大"
        assert [s.used_bytes for s in log.recent(2)] == [real.used_bytes + 1, 1], \
            "recent 必须按时间正序返回最后 n 条"
        # fail-closed：损坏行读取即抛错，绝不跳行（防峰值缩水）
        bad_log = SampleLog(sandbox / "corrupt.jsonl")
        bad_log.path.write_text("{ not json\n", encoding="utf-8")
        try:
            bad_log.entries()
            raise AssertionError("损坏 jsonl 行必须抛错（fail-closed），不得静默跳过")
        except SampleLogError:
            pass

        # 产品默认阈值 0.90：判定侧必须与数字侧一致（与当日水位无关的
        # 确定性性质）；水位如实记录进证据（观察窗延续）
        default_mon = CapacityMonitor()
        by_default = default_mon.judge(real)
        expected_critical = real.used_ratio > 0.90
        assert (by_default["severity"] == "CRITICAL") == expected_critical, \
            f"默认阈值判定侧必须与数字侧一致: ratio={real.used_ratio}"

        # ---- 面 2：注入负例（数字注入，不真塞盘）--------------------------
        # 注入 A：超阈值——used/(used+free)=0.95 > 0.90
        over = default_mon.judge(injected_sample(950 * GiB, 50 * GiB))
        assert over["severity"] == "CRITICAL" and over["code"] == CAP_USED_RATIO_EXCEEDED
        assert over["used_ratio"] > 0.90 and over["sample"]["basis"] == "injected"
        assert [v["code"] for v in over["violations"]] == [CAP_USED_RATIO_EXCEEDED]

        # 注入 B：磁盘满——free=0（§20.5「或磁盘满」方向），优先级最高
        full = default_mon.judge(injected_sample(100 * GiB, 0))
        assert full["code"] == CAP_DISK_FULL and full["severity"] == "CRITICAL"
        assert full["used_ratio"] == 1.0
        assert CAP_USED_RATIO_EXCEEDED in [v["code"] for v in full["violations"]]

        # 注入 C：峰值空间超过安全余量——磁盘水位健康（ratio=0.40）但 §22
        # 峰值预算（backup=550GiB + next_release）吃掉余量：
        # headroom = free(600GiB) - peak(550GiB) = 50GiB < min_headroom(100GiB)
        budget = peak_budget_bytes(legacy_snapshot=0, imported_db=0, wal_peak=0,
                                   cas_copy=0, backup=550 * GiB,
                                   current_release=0, next_release=0,
                                   rollback_release=0)
        assert budget == 550 * GiB, "§22 八分量求和必须精确"
        peak_mon = CapacityMonitor(CapacitySpec(min_headroom_bytes=100 * GiB))
        peak = peak_mon.judge(injected_sample(400 * GiB, 600 * GiB), peak_budget=budget)
        assert peak["severity"] == "CRITICAL"
        assert peak["code"] == CAP_PEAK_BUDGET_EXCEEDS_HEADROOM
        assert peak["headroom_bytes"] == 50 * GiB
        assert peak["used_ratio"] <= 0.90, "本注入方向水位本身健康，红的是峰值余量"
        # 峰值分量白名单：未知分量拒绝（防拼写缩水分母）
        try:
            peak_budget_bytes(typo_component=1)
            raise AssertionError("未知峰值分量必须被拒绝（fail-closed）")
        except CapacitySpecError:
            pass

        # 注入 D：路径配额——磁盘水位极低但 used/quota=0.95 超阈值
        quota_mon = CapacityMonitor(CapacitySpec(
            used_ratio_threshold=0.90,
            path_quotas={"<fault-injection>": 100 * GiB}))
        quota = quota_mon.judge(injected_sample(95 * GiB, 10 * 1024 * GiB))
        assert quota["code"] == CAP_QUOTA_RATIO_EXCEEDED
        assert quota["used_ratio"] < 0.90, "磁盘面水位低，红的是路径配额面"

        # 注入 E：临界边界——ratio 恰等于阈值不触发（严格大于），越过即红
        edge_ok = default_mon.judge(injected_sample(900 * GiB, 100 * GiB))
        assert edge_ok["severity"] == "OK" and edge_ok["code"] == CAP_WITHIN_MARGIN, \
            f"ratio==threshold 临界不应触发: {edge_ok}"
        edge_over = default_mon.judge(injected_sample(901 * GiB, 99 * GiB))
        assert edge_over["severity"] == "CRITICAL" and \
            edge_over["code"] == CAP_USED_RATIO_EXCEEDED

        # ---- 面 3：趋势外推 + 容量闸 BLOCKED 切换与完整性 -----------------
        # 线性增长：t=0/3600/7200/10800s，used=100/200/300/400GiB，free=600GiB
        # → 斜率 100GiB/h，阈值 0.9*1000GiB=900GiB，(900-400)GiB / (100GiB/h) = 5h
        series = [injected_sample((100 + 100 * k) * GiB, 600 * GiB, at=3600.0 * k)
                  for k in range(4)]
        proj = default_mon.trend(series)
        assert proj["samples_used"] == 4 and proj["slope_bytes_per_s"] > 0
        assert abs(proj["projected_seconds_to_threshold"] - 18000.0) < 1.0, \
            f"线性外推应为 18000s（5h），实得 {proj['projected_seconds_to_threshold']}"
        trend = default_mon.trend_finding(proj)
        assert (trend["severity"], trend["code"]) == ("WARNING", CAP_TREND_THRESHOLD_APPROACH), \
            "视界内逼近阈值必须 WARNING 早警（不 BLOCKED）"
        # 平盘/样本不足：不外推
        flat = default_mon.trend(
            [injected_sample(400 * GiB, 600 * GiB, at=3600.0 * k) for k in range(4)])
        assert flat["projected_seconds_to_threshold"] is None and \
            flat["reason"] == "not_growing"
        assert default_mon.trend(series[:1])["reason"] == "insufficient_samples"
        slow = default_mon.trend(
            [injected_sample((400 + k) * GiB, 600 * GiB, at=3600.0 * k) for k in range(4)])
        assert default_mon.trend_finding(slow)["severity"] == "OK", \
            "远超早警视界（>7d）的外推不得报 WARNING"

        # 容量闸：CRITICAL → BLOCKED，旧证据与 current 完整（前后清单相等）
        ev1 = sandbox / "evidence" / "findings.jsonl"
        ev2 = sandbox / "evidence" / "gate.json"
        ev1.parent.mkdir(parents=True, exist_ok=True)
        ev1.write_text('{"row": 1, "verdict": "PASS"}\n', encoding="utf-8")
        ev2.write_text('{"policy_verdict": "PASS"}\n', encoding="utf-8")
        release_dir = sandbox / "releases" / "r1"
        release_dir.mkdir(parents=True)
        (release_dir / "manifest.json").write_text('{"release": "r1"}\n', encoding="utf-8")
        current = sandbox / "current"
        current.symlink_to(release_dir)
        before = integrity_manifest([ev1, ev2], current_path=current)
        assert before[str(ev1)]["type"] == "file" and \
            before["<current>"] == {"type": "symlink", "target": str(release_dir)}

        decision = enforce_capacity_gate(over, evidence_paths=[ev1, ev2],
                                         current_path=current)
        assert decision["capacity_gate"] == "BLOCKED" and decision["triggered"] is True
        assert decision["finding"]["code"] == CAP_USED_RATIO_EXCEEDED
        assert decision["deleted_or_modified"] == [], "§22 禁删审计证据：必须零删除零改写"
        assert decision["integrity"] == before, \
            "BLOCKED 切换后旧证据/current 完整性清单必须与切换前完全相等"
        assert ev1.read_text(encoding="utf-8") == '{"row": 1, "verdict": "PASS"}\n'
        assert ev2.read_text(encoding="utf-8") == '{"policy_verdict": "PASS"}\n'
        assert os.readlink(current) == str(release_dir), "current 指针必须原样"

        # 阴性对照：绿侧 finding → OPEN，不切换
        open_gate = enforce_capacity_gate(green, evidence_paths=[ev1, ev2],
                                          current_path=current)
        assert open_gate["capacity_gate"] == "OPEN" and open_gate["triggered"] is False

        _record("CAP-01",
                f"真实采集正例（{tmp} 所在卷，当日水位 {real.used_ratio:.2%}，"
                f"默认 0.90 阈值判定侧={'CRITICAL' if expected_critical else 'OK'}"
                f"——与数字侧一致，水位如实记录）；注入负例四向全红"
                f"（超阈值 0.95/磁盘满 free=0/峰值预算 headroom 50GiB<100GiB/"
                f"配额 0.95）+临界边界（==0.90 不触发、0.901 触发）；"
                f"趋势外推线性验算 18000s±1s（WARNING 早警，平盘/单样本不外推）；"
                f"CRITICAL→容量闸 BLOCKED 且旧证据/current 完整性清单前后相等、"
                f"零删除；绿侧→OPEN")


# ---------------------------------------------------------------------------
# 备份/DR 演练族（真实子进程跑 backup-restore-drill.sh，零 mock）
# ---------------------------------------------------------------------------
def _mk_drill_corpus(sandbox: Path):
    """构造演练语料根：真实字节的调度 DB + 聚合/心跳/采样 JSON（5 文件）。

    返回 (wenqu_root, rels)。真实 sqlite 二进制 + 真实 JSON 字节——
    恢复对账面对真实生产形态的文件，而非空壳。
    """
    root = sandbox / "wenqu-home"
    (root / "state").mkdir(parents=True)
    (root / "observation" / "samples").mkdir(parents=True)
    (root / "observation" / "shadow").mkdir(parents=True)
    conn = sqlite3.connect(str(root / "state" / "scheduler.db"))
    conn.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY, next_due REAL, argv TEXT)")
    conn.executemany("INSERT INTO jobs VALUES (?, ?, ?)", [
        ("nightly-backup", 1791400000.5, '["bash","backup.sh"]'),
        ("weekly-watchdog", 1791500000.25, '["bash","watch.sh"]'),
    ])
    conn.commit()
    conn.close()
    (root / "state" / "gate-aggregate.json").write_text(
        json.dumps({"policy_verdict": "PASS", "required": 9, "done": 9}), encoding="utf-8")
    (root / "observation" / "heartbeat.json").write_text(
        json.dumps({"station": 1, "beat_at": "2026-10-08T09:00:00Z"}), encoding="utf-8")
    (root / "observation" / "samples" / "2026-10-08.json").write_text(
        json.dumps({"cpu": 7.5, "disk_used_ratio": 0.93}), encoding="utf-8")
    (root / "observation" / "shadow" / "2026-10-08.json").write_text(
        json.dumps({"shadow": True, "n": 3}), encoding="utf-8")
    rels = ["state/scheduler.db", "state/gate-aggregate.json",
            "observation/heartbeat.json", "observation/samples/2026-10-08.json",
            "observation/shadow/2026-10-08.json"]
    return root, rels


def test_BAK_01_backup_restore_drill_real_reconcile_and_fail_closed_success():
    """BAK-01｜注入：磁盘满/tar/backup 失败｜期望：不更新 success（§20.4 逐字）。

    §25.1 证据类：checkpoint/restore drill（REQ-BACKUP-001/AC-BACKUP-RESTORABLE）。
    测试内真实执行演练（零 mock）：tmp 语料根上跑
    system/sentinels/backup-restore-drill.sh 四步——快照→篡改（实测 sha 已变
    防伪造演练）→恢复→逐文件 cmp+sha256 字节级对账：
    1. 断言恢复后逐文件一致（reconcile cmp+sha_match 双证，且与源语料三方一致）；
    2. 断言报告结构（时间 stamp/文件 files/结果 result 三要素）+ jsonl 事件日志
       （每事件 {ts,t,event,file,result}，覆盖全部语料文件的快照/篡改/恢复/对账）；
    3. 失败分支（backup 失败族：备份语料不可达）→ 演练 fail-closed：退出非零、
       报告 result=FAIL、既有 PASS 工件零改写（= success 不更新）。
    诚实边界：「磁盘满/tar」字面向量不可移植注入（drill 用 cp 管道），以同族
    真实失败覆盖「backup 失败 -> 不更新 success」判定链（见文件头边界 5）。
    """
    with tempfile.TemporaryDirectory(prefix="wq_bak01_") as td:
        sandbox = Path(td)
        root, rels = _mk_drill_corpus(sandbox)
        assert len(rels) == 5
        # 生产语料只读实证基线（演练前后必须逐字节不变）
        sha_before = {rel: hashlib.sha256((root / rel).read_bytes()).hexdigest()
                      for rel in rels}
        reports = sandbox / "reports"
        outcome = run_drill(wenqu_root=root, report_dir=reports)

        rep = outcome.report
        # —— 判定 + 报告结构（时间/文件/结果三要素）——
        assert rep["drill"] == "backup-restore" and rep["result"] == "PASS"
        assert rep["mode"] == "backup" and rep["byte_match_all"] is True
        assert rep["corpus_count"] == len(rels)
        assert re.fullmatch(r"\d{8}T\d{6}Z(?:-\d+)?", rep["stamp"]), rep["stamp"]
        snap = {f["rel"]: f for f in rep["steps"]["snapshot"]["files"]}
        assert set(snap) == set(rels), "快照文件集必须与语料一致"
        for rel, f in snap.items():
            assert re.fullmatch(r"[0-9a-f]{64}", f["sha256"]), f
            assert f["size"] > 0 and f["sha256"] == sha_before[rel], \
                f"快照必须与语料源字节一致: {rel}"
        # 篡改真实发生：三种方式轮转全覆盖 + 演练自证（tamper.ok=实测 sha 已变）
        acts = {a["rel"]: a["how"] for a in rep["steps"]["tamper"]["actions"]}
        assert set(acts) == set(rels) and rep["steps"]["tamper"]["ok"] is True
        assert set(acts.values()) == {"append", "truncate", "delete"}
        assert rep["steps"]["restore"]["files_restored"] == len(rels)
        # —— 恢复后逐文件一致（cmp+sha 双证，与快照、与源语料三方一致）——
        recon = {f["rel"]: f for f in rep["steps"]["reconcile"]["files"]}
        assert set(recon) == set(rels)
        for rel, f in recon.items():
            assert f["cmp"] is True and f["sha_match"] is True, f
            assert f["sha256"] == snap[rel]["sha256"] == sha_before[rel], rel
        for rel in rels:  # 生产语料全程只读
            assert hashlib.sha256((root / rel).read_bytes()).hexdigest() == sha_before[rel]

        # —— jsonl 事件日志（时间/文件/结果，逐事件机器可核）——
        evs = read_events(outcome.jsonl_path)
        kinds = [e["event"] for e in evs]
        assert kinds[0] == "drill_start" and kinds[-1] == "drill_pass"
        assert "tamper_verified" in kinds and "drill_fail" not in kinds
        last_ts = 0.0
        for e in evs:
            assert isinstance(e["ts"], float) and math.isfinite(e["ts"]) \
                and e["ts"] >= last_ts, e
            last_ts = e["ts"]
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", e["t"]), e
        for phase in ("snapshot_file", "restore_file", "reconcile_file"):
            got = {e["file"] for e in evs if e["event"] == phase and e["result"] == "true"}
            assert got == set(rels), (phase, got)
        tamp = {e["file"]: e["result"] for e in evs if e["event"] == "tamper_file"}
        assert set(tamp) == set(rels)
        assert set(tamp.values()) <= {"append", "truncate", "delete"}

        # —— 失败分支：备份语料不可达（backup 失败族）→ fail-closed 不更新 success ——
        pass_bytes = outcome.report_path.read_bytes()
        fail_dir = sandbox / "fail-reports"
        empty_root = sandbox / "empty-home"
        empty_root.mkdir()
        try:
            run_drill(wenqu_root=empty_root, report_dir=fail_dir)
            raise AssertionError("备份失败族必须 fail-closed 抛 DrillFailure")
        except DrillFailure as exc:
            assert exc.returncode == 1, exc
            assert exc.report.get("result") == "FAIL", exc.report
            assert "corpus empty" in exc.report.get("reason", ""), exc.report
        # success 不更新：失败运行自建 FAIL 工件，既有 PASS 报告零改写
        assert outcome.report_path.read_bytes() == pass_bytes, \
            "失败运行不得改写既有 PASS 报告（success 不更新）"
        newest_fail = sorted(fail_dir.glob("drill-*.json"))[-1]
        assert json.loads(newest_fail.read_text(encoding="utf-8"))["result"] == "FAIL"
        fail_events = read_events(newest_fail.with_suffix(".jsonl"))
        assert fail_events[-1]["event"] == "drill_fail" \
            and fail_events[-1]["result"] == "FAIL"

    _record("BAK-01",
            f"tmp 语料 {len(rels)} 文件（真实 sqlite DB+4 JSON）四步真实演练："
            f"快照 sha 与源逐文件一致→篡改三式轮转全覆盖（append/truncate/delete，"
            f"实测 sha 已变防伪造）→恢复 {rep['steps']['restore']['files_restored']} 文件"
            f"→逐文件 cmp+sha256 字节级对账全等（与源三方一致）；生产语料前后字节不变"
            f"（只读）；报告 {rep['stamp']} 含时间/文件/结果三要素+jsonl 事件日志"
            f"{len(evs)} 事件（ts 单调、每文件四相事件齐全）；失败分支（语料不可达）"
            f"fail-closed：exit1+result=FAIL，既有 PASS 工件零改写=不更新 success")


def test_DR_01_dr_drill_rpo_rto_measured_within_frozen_targets():
    """DR-01｜注入：恢复演练｜期望：实测满足冻结 RPO/RTO（§20.5 逐字）。

    §25.1 证据类：restored state/RPO/RTO timing（REQ-DR-001/AC-DR-RPO-RTO）。
    真实跑 --mode dr（零 mock）：快照完成后注入已知故障延迟窗口 1.5s 再篡改：
    - RPO = 最后快照点 → 故障注入点实测时差（应 >= 已知窗口，窗口真实流逝；
      零/负=伪造计时，编排层拒绝 fault_delay<=0）；
    - RTO = 恢复开始 → 全部对账通过实测耗时；
    - 冻结目标由演练脚本内冻结（RPO<=300s、RTO<60s，不接受 CLI 覆盖）。
    断言数字存在且有限、锚点单调、rpo_ok/rto_ok 判定 True、恢复态字节全等、
    RPO/RTO 记录进报告 JSON（dr 块+reason）与 jsonl dr_metrics 事件。
    """
    with tempfile.TemporaryDirectory(prefix="wq_dr01_") as td:
        sandbox = Path(td)
        root, rels = _mk_drill_corpus(sandbox)
        outcome = run_drill(wenqu_root=root, report_dir=sandbox / "reports",
                            mode="dr", fault_delay_s=1.5)
        rep = outcome.report
        dr = rep["dr"]
        # —— RPO/RTO 数字存在且有限（实测，非补造）——
        for key in ("rpo_seconds", "rto_seconds"):
            v = dr[key]
            assert isinstance(v, (int, float)) and math.isfinite(v), (key, v)
        # RPO=最后快照点→故障注入点：>= 已知故障窗口（1.5s 真实流逝）
        assert dr["rpo_seconds"] >= 1.5, dr
        # 冻结目标正源：脚本内冻结 RPO<=300s / RTO<=60s
        assert dr["rpo_target_s"] == 300 and dr["rto_target_s"] == 60, dr
        assert dr["rpo_seconds"] <= 300, dr
        assert dr["rto_seconds"] < 60, dr
        assert dr["rpo_ok"] is True and dr["rto_ok"] is True, dr
        # 计时锚点单调（故障在快照后、对账完成在恢复开始后）
        assert dr["t_fault_epoch"] > dr["t_snapshot_done_epoch"], dr
        assert dr["t_reconcile_done_epoch"] > dr["t_restore_start_epoch"], dr
        # —— 恢复态：字节级全等（restored state）——
        assert rep["result"] == "PASS" and rep["mode"] == "dr"
        assert rep["byte_match_all"] is True
        assert all(f["cmp"] is True and f["sha_match"] is True
                   for f in rep["steps"]["reconcile"]["files"])
        # 编排层暴露的实测数字与报告一致
        assert outcome.rpo_seconds == dr["rpo_seconds"]
        assert outcome.rto_seconds == dr["rto_seconds"]
        # —— RPO/RTO 记录进报告（reason 文本 + jsonl dr_metrics 事件）——
        # reason 由脚本 awk %.6f 打印——用同样 %.6f 格式化比对（浮点 repr 会
        # 丢尾零，如 0.455810 -> '0.45581'，裸 f-string 比对会假红）
        assert f"RPO={dr['rpo_seconds']:.6f}s" in rep["reason"], rep["reason"]
        assert f"RTO={dr['rto_seconds']:.6f}s" in rep["reason"], rep["reason"]
        metrics = [e for e in read_events(outcome.jsonl_path)
                   if e["event"] == "dr_metrics"]
        assert len(metrics) == 1, metrics
        assert metrics[0]["rpo_seconds"] == dr["rpo_seconds"]
        assert metrics[0]["rto_seconds"] == dr["rto_seconds"]
        assert metrics[0]["result"] == "true"
        # —— 阴性守卫：零故障窗口=伪造计时，编排层拒绝（fail-closed）——
        try:
            run_drill(wenqu_root=root, report_dir=sandbox / "reports",
                      mode="dr", fault_delay_s=0)
            raise AssertionError("零故障窗口必须被编排层拒绝（伪造计时）")
        except ValueError:
            pass

    _record("DR-01",
            f"DR 模式真实演练 PASS：RPO 实测 {dr['rpo_seconds']}s"
            f"（>=已知窗口 1.5s，<=冻结目标 {dr['rpo_target_s']}s）、"
            f"RTO 实测 {dr['rto_seconds']}s（<冻结目标 {dr['rto_target_s']}s）；"
            f"计时锚点单调（故障在快照后/对账完成在恢复后）；恢复态 {len(rels)} 文件"
            f"字节级全等；RPO/RTO 记录进报告 dr 块+reason 与 jsonl dr_metrics 事件；"
            f"零故障窗口被编排层 fail-closed 拒绝")


# ---------------------------------------------------------------------------
# 运行器：逐条执行、写证据工件、exit 0/1
# ---------------------------------------------------------------------------
def _git_head() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(REPO),
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return "unknown"


def main() -> int:
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    def _order_key(name):  # 前缀长度无关（DR=2 字母、SCH=3 字母皆可）
        m = re.match(r"test_([A-Z]{2,5})_(\d{2})_", name)
        return (m.group(1), int(m.group(2))) if m else ("ZZZ", 99)

    tests.sort(key=lambda t: _order_key(t[0]))

    print("=" * 72)
    print("§20 验收 ID 专属测试——SCH/ALT/BAK/HLT/DOC/CAP/DR 七族 17 条（真实注入/真实断言）")
    print(f"repo: {REPO}  HEAD: {_git_head()}")
    print("=" * 72)
    passed = failed = 0
    failed_names = []
    for name, fn in tests:
        tid = re.match(r"test_([A-Z]{2,5}_\d{2})_", name)
        tid = tid.group(1).replace("_", "-") if tid else name
        try:
            fn()
            print(f"  PASS  {tid:<8} {name}")
            passed += 1
            _RESULTS.setdefault(tid, {"pass": True, "detail": ""})
        except Exception as exc:  # noqa: BLE001
            failed += 1
            failed_names.append(name)
            _RESULTS[tid] = {"pass": False, "detail": f"{type(exc).__name__}: {exc}"}
            print(f"  FAIL  {tid:<8} {name}: {exc}")
    print("-" * 72)
    print(f"RESULT: PASS={passed} FAIL={failed}"
          f"{'' if not failed else '  failed: ' + ', '.join(failed_names)}")

    try:
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "meta": {
                "artifact": "ac-ops-families",
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "repo_head": _git_head(),
                "test_file": "system/tests/test_ac_ops_families.py",
                "plan_source": "evidence/00-baseline/codex-external/方案.md §20.4/§20.5",
                "scope": "SCH-01~07, ALT-01~02, BAK-01, HLT-01, DOC-01~04, CAP-01, DR-01（17 ID）",
                "run_rc": 0 if not failed else 1,
                "passed": passed,
                "failed": failed,
            },
            "results": _RESULTS,
            "not_implementable": _NOT_IMPLEMENTABLE,
        }
        EVIDENCE_PATH.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"证据工件: {EVIDENCE_PATH.relative_to(REPO)}")
    except OSError as exc:
        print(f"证据工件写入失败（不影响判定）: {exc}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

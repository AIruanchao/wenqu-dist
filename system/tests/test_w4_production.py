#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_w4_production.py——W4 生产闭环三面真实注入断言（SCH/ALT/BAK）。

三面（全部真实执行，无 mock 对象替身；失败注入只注入"故障本身"）：

1. 心跳新鲜度（SCH 面）：真实 production_tick（stub 采样器 exit 0）
   → 作业 PASS → 真 wenquctl gate 子进程聚合 PASS → heartbeat.json 新鲜；
   再经 now= 时钟接缝注入过期 → HeartbeatMonitor 判不健康并 enqueue
   CRITICAL/WARNING → 真投递箱通道收到回执；刷新铁律负例
   （COMPLETED+NOT_APPLICABLE 不得推进 last_success）。
2. 通知死信（ALT 面）：macos 通道注入真实故障（sender raise），
   alertbox 通道为真实文件投递箱——同一 CRITICAL 消息双通道入队后：
   macos 两连败 → DEAD_LETTER（attempt/last_error 全审计）；
   alertbox SENT（txt 落盘 + receipts.jsonl 回执）——通知失败→投递箱必成功。
3. 恢复演练对账（BAK 面）：真实跑 system/sentinels/backup-restore-drill.sh
   （临时 wenqu root 语料）→ 退出码 0 + 报告 JSON 四步齐 + 篡改实测生效
   + 恢复后逐文件字节级全等。

纯标准库；`python3 system/tests/test_w4_production.py`（exit 0=全绿）。
测试全程使用临时 WENQU_HOME，绝不写真实 ~/.wenqu。
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import date

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core import scheduler as sched  # noqa: E402
from wenqu_core.scheduler import (  # noqa: E402
    HeartbeatMonitor,
    NotificationOutbox,
    SchedulerStore,
)

PASS_N, FAIL_N, FAILURES = 0, 0, []


def _ck(name, cond, detail=""):
    global PASS_N, FAIL_N
    if cond:
        PASS_N += 1
        print(f"  ✓ {name}")
    else:
        FAIL_N += 1
        FAILURES.append(name)
        print(f"  ✗ {name} {detail}")


def _write_stub_sampler(td, *, rc):
    """真实可执行的采样器 stub：写当日样本/影子 JSON 后以 rc 退出。"""
    stub = os.path.join(td, f"sampler_rc{rc}.py")
    with open(stub, "w", encoding="utf-8") as fh:
        fh.write(
            "import json, os, sys\n"
            "from datetime import date, datetime, timezone\n"
            "samples, shadow = sys.argv[1], sys.argv[2]\n"
            "os.makedirs(samples, exist_ok=True); os.makedirs(shadow, exist_ok=True)\n"
            "now = datetime.now(timezone.utc).isoformat()\n"
            "day = date.today().isoformat()\n"
            f"payload = {{'stub': True, 'rc': {rc}, 'collected_at': now}}\n"
            f"if {rc} == 0:\n"
            "    open(os.path.join(samples, day + '.json'), 'w').write(json.dumps(payload))\n"
            "    open(os.path.join(shadow, day + '.json'), 'w').write(json.dumps(payload))\n"
            f"sys.exit({rc})\n"
        )
    return stub


def _make_paths(td):
    return sched.ProductionPaths(
        repo_root=os.path.dirname(REPO),  # 仓根（真 cli.py 供 gate 子进程用）
        wenqu_home=os.path.join(td, "wenqu-home"))


# ══════════════════════════════════════════════════════════════════════
# 面 1：心跳新鲜度（真实 production_tick + now= 注入）
# ══════════════════════════════════════════════════════════════════════
def test_heartbeat_freshness():
    with tempfile.TemporaryDirectory(prefix="wq-w4-hb-") as td:
        paths = _make_paths(td)
        stub_ok = _write_stub_sampler(td, rc=0)
        argv = (sys.executable, stub_ok,
                paths.samples_dir, paths.shadow_dir)
        t0 = time.time()

        tick1 = sched.production_tick(
            paths=paths, now=t0, job_argv=argv,
            macos_sender=lambda p: (_ for _ in ()).throw(
                RuntimeError("injected macos down (face1)")))
        _ck("面1 tick1 bootstrap 真跑出 run",
            tick1["bootstrapped"] is True and len(tick1["runs"]) == 1)
        _ck("面1 采样作业 COMPLETED/PASS（exit=0）",
            tick1["runs"][0]["execution_status"] == "COMPLETED"
            and tick1["runs"][0]["policy_verdict"] == "PASS",
            str(tick1["runs"]))
        _ck("面1 真 wenquctl gate 聚合 PASS（station-result-v2 铸造合法）",
            tick1["gate"]["aggregate_outcome"] == "PASS"
            and tick1["gate"]["cli_exit"] == 0, str(tick1["gate"]))
        gate_snap = json.load(open(paths.gate_aggregate, encoding="utf-8"))
        _ck("面1 gate-aggregate.json 落盘且契约字段齐",
            gate_snap.get("policy_verdict") == "PASS"
            and isinstance(gate_snap.get("generated_at"), str))
        _ck("面1 shadow 刷新走诊断模式不冒充发布门（F6-GATE-SCOPE-001）",
            gate_snap.get("mode") == "self_declared_diagnostic"
            and gate_snap.get("scope_binding", {}).get("mode")
            == "self_declared", str(gate_snap.get("mode")))
        hb = json.load(open(paths.heartbeat, encoding="utf-8"))
        _ck("面1 heartbeat.json 新鲜（tick_epoch==注入 now）",
            hb["tick_epoch"] == t0 and hb["tick_rc"] == 0)
        _ck("面1 心跳健康态 FRESH",
            any(h["state"] == "FRESH" and h["healthy"] for h in tick1["health"]),
            str(tick1["health"]))
        log_path = os.path.join(
            paths.logs_dir, "scheduler-" + date.today().isoformat() + ".jsonl")
        _ck("面1 当日 tick 日志已落一行", os.path.isfile(log_path)
            and sum(1 for _ in open(log_path, encoding="utf-8")) == 1)

        # ---- 二跳回归（2026-10-08 生产实锄缺陷）：第二 tick 必须走到期机制
        # 真跑采样（旧缺陷：register(replace=True) 每 tick 重置 next_due_at
        # 到未来 → due 永空 → 采样只在 bootstrap 跑一次，之后拿陈旧 run 刷
        # gate 假 PASS）。断言：due 非空 + 新 run 带 scheduled_at + run 表
        # 增长 + next_due 推进。
        tick2 = sched.production_tick(
            paths=paths, now=t0 + 310, job_argv=argv,
            macos_sender=lambda p: (_ for _ in ()).throw(
                RuntimeError("injected macos down (face1-t2)")))
        _ck("面1 tick2 走到期机制（due 非空且 run）",
            any(o["run"] for o in tick2["due"]) and len(tick2["runs"]) == 1,
            str(tick2["due"]))
        _ck("面1 tick2 新 run 为调度执行（bootstrapped=False）",
            tick2["bootstrapped"] is False
            and tick2["runs"][0]["execution_status"] == "COMPLETED"
            and tick2["runs"][0]["policy_verdict"] == "PASS",
            str(tick2["runs"]))
        conn = sqlite3.connect(paths.scheduler_db)
        try:
            n_runs, sched_nonnull = conn.execute(
                "SELECT COUNT(*), SUM(scheduled_at IS NOT NULL) "
                "FROM scheduler_runs WHERE job_id=?",
                (sched.PROD_JOB_ID,)).fetchone()
        finally:
            conn.close()
        _ck("面1 两跳后 run 表=2 且调度 run 占位",
            n_runs == 2 and sched_nonnull == 1, f"n={n_runs} sched={sched_nonnull}")

        # ---- now= 注入过期：success_age > freshness(1200s) → 不健康 + 告警入队
        store = SchedulerStore(paths.scheduler_db)
        try:
            outbox = NotificationOutbox(
                store,
                critical_channels=(sched.PROD_CHANNEL_MACOS,
                                   sched.PROD_CHANNEL_ALERTBOX))
            outbox.register_channel(sched.PROD_CHANNEL_MACOS, lambda p: (
                _ for _ in ()).throw(RuntimeError("injected macos down")))
            outbox.register_channel(
                sched.PROD_CHANNEL_ALERTBOX,
                sched.make_alertbox_sender(paths.alerts_dir))
            mon = HeartbeatMonitor(store, outbox)
            # 过期注入锚定库内真实 last_success（二跳回归后成功时间已推进，
            # 固定 t0 偏移不再保证过期——锚点必须取自实态而非假定）。
            conn = sqlite3.connect(paths.scheduler_db)
            last_success_at = conn.execute(
                "SELECT last_success_at FROM scheduler_heartbeats "
                "WHERE job_id=?", (sched.PROD_JOB_ID,)).fetchone()[0]
            conn.close()
            assert last_success_at is not None
            t_far = last_success_at + 1200 + 120
            reports = mon.check_health(now=t_far, notify=True)
            _ck("面1 注入过期后判不健康（非 FRESH）",
                all(h.state != "FRESH" for h in reports)
                and all(not h.healthy for h in reports),
                str([(h.job_id, h.state) for h in reports]))
            _ck("面1 过期（1x~2x 窗口）severity=WARNING",
                any(h.severity == "WARNING" for h in reports),
                str([h.severity for h in reports]))
            # 超过 2x freshness：宿主疑停摆 → CRITICAL（时间注入推进）
            reports2 = mon.check_health(
                now=last_success_at + 2400 + 120, notify=True)
            _ck("面1 过期（>2x 窗口）severity=CRITICAL（宿主疑停摆）",
                any(h.severity == "CRITICAL" for h in reports2),
                str([h.severity for h in reports2]))
            before = json.dumps(outbox.stats())
            # 刷新铁律负例：NOT_APPLICABLE 不推进 last_success（同指纹前提）
            conn = sqlite3.connect(paths.scheduler_db)
            last_before, fp_real = conn.execute(
                "SELECT last_success_at, input_fingerprint "
                "FROM scheduler_heartbeats WHERE job_id=?",
                (sched.PROD_JOB_ID,)).fetchone()
            conn.close()
            mon.record_result(
                job_id=sched.PROD_JOB_ID, probe_id=sched.PROD_PROBE_ID,
                station_id=sched.PROD_STATION_ID,
                input_fingerprint=fp_real, execution_status="COMPLETED",
                policy_verdict="NOT_APPLICABLE", finished_at=t_far,
                ttl_seconds=900.0, now=t_far)
            conn = sqlite3.connect(paths.scheduler_db)
            last_after = conn.execute(
                "SELECT last_success_at FROM scheduler_heartbeats "
                "WHERE job_id=?", (sched.PROD_JOB_ID,)).fetchone()[0]
            conn.close()
            _ck("面1 刷新铁律：NOT_APPLICABLE 不推进 last_success",
                last_before == last_after,
                f"{last_before} -> {last_after}")
            stats0 = outbox.stats()
            _ck("面1 不健康告警已入队（outbox 有 PENDING）",
                stats0.get("PENDING", 0) >= 1, before)
            disp = outbox.dispatch_due(now=t_far + 2500)
            _ck("面1 投递箱通道必送达（sent≥1，macos 注入故障不计成败）",
                disp["sent"] >= 1, str(disp))
            receipts = os.path.join(paths.alerts_dir, "receipts.jsonl")
            _ck("面1 投递箱回执 receipts.jsonl 落盘（含心跳告警主题）",
                os.path.isfile(receipts)
                and sched.PROD_JOB_ID
                in open(receipts, encoding="utf-8").read())
        finally:
            store.close()


# ══════════════════════════════════════════════════════════════════════
# 面 2：通知死信（macos 注入真实故障；alertbox 真实投递）
# ══════════════════════════════════════════════════════════════════════
def test_notification_dead_letter_dual_channel():
    with tempfile.TemporaryDirectory(prefix="wq-w4-dl-") as td:
        db = os.path.join(td, "sched.db")
        alerts = os.path.join(td, "alerts")
        store = SchedulerStore(db)
        try:
            outbox = NotificationOutbox(
                store,
                critical_channels=(sched.PROD_CHANNEL_MACOS,
                                   sched.PROD_CHANNEL_ALERTBOX),
                backoff_base_seconds=1.0, backoff_cap_seconds=2.0,
                max_attempts=2)
            boom = RuntimeError("injected osascript failure (face2)")
            outbox.register_channel(
                sched.PROD_CHANNEL_MACOS,
                lambda p: (_ for _ in ()).throw(boom))
            outbox.register_channel(
                sched.PROD_CHANNEL_ALERTBOX,
                sched.make_alertbox_sender(alerts))
            t0 = time.time()
            ids = outbox.notify(
                "CRITICAL", "[w4-test] 通知死信演练",
                "macos 通道注入故障；alertbox 必须送达",
                dedup_key="w4test-dual", now=t0)
            _ck("面2 CRITICAL 强制双通道入队（2 条消息）",
                len(ids) == 2 and all(ids))
            macos_mid, alert_mid = ids
            rows = store.query(
                "SELECT channel FROM scheduler_outbox WHERE message_id IN (?,?)"
                " ORDER BY message_id", (macos_mid, alert_mid))
            _ck("面2 双通道各占一行（dedup 按通道不互吃）",
                sorted(r[0] for r in rows)
                == [sched.PROD_CHANNEL_ALERTBOX, sched.PROD_CHANNEL_MACOS],
                str(rows))
            d1 = outbox.dispatch_due(now=t0)
            _ck("面2 首轮：alertbox SENT + macos 第 1 次失败留退避",
                d1["sent"] == 1 and d1["failed"] == 1, str(d1))
            # notify() 入队路径 max_attempts 固定 5（既有语义）——驱动完整
            # 退避序列（1s/2s/2s[cap]）直至 macos 五连败死信。
            for i, t in enumerate((t0 + 2, t0 + 4, t0 + 8), 2):
                d = outbox.dispatch_due(now=t)
                _ck(f"面2 第 {i} 轮：macos 继续失败留退避（attempt {i}/5）",
                    d["failed"] == 1 and d["dead_lettered"] == 0, str(d))
            d5 = outbox.dispatch_due(now=t0 + 10)
            _ck("面2 第 5 轮：macos 达 max_attempts=5 → DEAD_LETTER",
                d5["dead_lettered"] == 1, str(d5))
            dead = outbox.dead_letters()
            _ck("面2 死信审计：channel/attempts/last_error 全记",
                dead and dead[0]["channel"] == sched.PROD_CHANNEL_MACOS
                and dead[0]["attempts"] == 5
                and "osascript failure" in (dead[0]["last_error"] or ""),
                str(dead[:1]))
            sent_row = store.query(
                "SELECT status FROM scheduler_outbox WHERE message_id=?",
                (alert_mid,))[0][0]
            dead_row = store.query(
                "SELECT status FROM scheduler_outbox WHERE message_id=?",
                (macos_mid,))[0][0]
            _ck("面2 通知失败→投递箱必成功（同消息对 SENT vs DEAD_LETTER）",
                sent_row == "SENT" and dead_row == "DEAD_LETTER",
                f"alertbox={sent_row} macos={dead_row}")
            # 死信触发系统级 CRITICAL 断链告警（双通道，不递归）
            d3 = outbox.dispatch_due(now=t0 + 12)
            notice = store.query(
                "SELECT COUNT(*) FROM scheduler_outbox WHERE "
                "meta_json LIKE '%system_dead_letter_notice%'")[0][0]
            _ck("面2 死信触发断链 CRITICAL 告警（审计留痕）",
                notice >= 1 and d3["sent"] >= 1,
                f"notice={notice} d3={d3}")
            receipts_path = os.path.join(alerts, "receipts.jsonl")
            receipts = [json.loads(l) for l in
                        open(receipts_path, encoding="utf-8") if l.strip()]
            _ck("面2 回执链完整（receipts.jsonl 含送达 message_id）",
                any(r["message_id"] == alert_mid for r in receipts)
                and any(r.get("subject", "").startswith("[w4-test]")
                        for r in receipts), str(receipts[:2]))
            txts = [n for n in os.listdir(alerts) if n.endswith(".txt")]
            _ck("面2 投递箱 txt 通知文件落盘", len(txts) >= 1, str(txts))
        finally:
            store.close()


# ══════════════════════════════════════════════════════════════════════
# 面 3：恢复演练对账（真实跑 backup-restore-drill.sh）
# ══════════════════════════════════════════════════════════════════════
def test_backup_restore_drill_reconciliation():
    with tempfile.TemporaryDirectory(prefix="wq-w4-drill-") as td:
        root = os.path.join(td, "wenqu")
        os.makedirs(os.path.join(root, "state"))
        os.makedirs(os.path.join(root, "observation", "samples"))
        # 真实语料形态：SQLite 字节 + JSON 快照 + 样本
        conn = sqlite3.connect(os.path.join(root, "state", "scheduler.db"))
        conn.execute("CREATE TABLE t (x)")
        conn.execute("INSERT INTO t VALUES ('drill-corpus')")
        conn.commit()
        conn.close()
        with open(os.path.join(root, "state", "gate-aggregate.json"), "w") as f:
            json.dump({"policy_verdict": "PASS", "generated_at": "now"}, f)
        with open(os.path.join(root, "observation", "heartbeat.json"), "w") as f:
            json.dump({"tick_rc": 0}, f)
        with open(os.path.join(root, "observation", "samples",
                               "2026-10-08.json"), "w") as f:
            f.write('{"sample": "corpus"}\n')
        drill = os.path.join(os.path.dirname(REPO), "system", "sentinels",
                             "backup-restore-drill.sh")
        report_dir = os.path.join(td, "reports")
        p = subprocess.run(["/bin/bash", drill, "--wenqu-root", root,
                            "--report-dir", report_dir],
                           capture_output=True, text=True, timeout=60)
        _ck("面3 drill 真实执行 rc=0", p.returncode == 0,
            p.stdout + p.stderr)
        reports = [n for n in os.listdir(report_dir) if n.endswith(".json")]
        _ck("面3 演练报告落盘", len(reports) == 1, str(reports))
        rep = json.load(open(os.path.join(report_dir, reports[0]),
                             encoding="utf-8"))
        # G9-09 强化：四步 + 归档腿（实存验证+独立解包对账）五步齐
        _ck("面3 五步齐：快照/归档/篡改/恢复/对账",
            set(rep["steps"].keys())
            == {"snapshot", "archive", "tamper", "restore", "reconcile"}
            and rep["result"] == "PASS", str(rep.get("steps", {}).keys()))
        _ck("面3 语料≥3 且快照 sha 清单齐",
            rep["corpus_count"] >= 3
            and all("sha256" in f for f in rep["steps"]["snapshot"]["files"]))
        # G9-09：归档实存合同（非空普通文件 sha + 独立解包 hash + 逐文件清单）
        sha_re = __import__("re").compile(r"^[0-9a-f]{64}$")
        arc = rep.get("archive", {})
        _ck("面3 归档实存：size>0/64hex sha/独立解包 extract_sha/逐文件清单",
            arc.get("materialized") is True
            and arc.get("size", 0) > 0
            and sha_re.match(str(arc.get("sha256", "")))
            and sha_re.match(str(arc.get("extract_sha256", "")))
            and {f["rel"] for f in arc.get("files", [])}
            == {f["rel"] for f in rep["steps"]["snapshot"]["files"]}
            and all(sha_re.match(f["sha256"]) for f in arc.get("files", [])),
            str(arc.get("sha256")))
        # G9-09：作业身份（drill 脚本/scheduler 源 SHA）记录入成功报告
        ident = rep.get("identity", {})
        _ck("面3 作业身份：drill/scheduler 源 SHA 记录",
            sha_re.match(str(ident.get("drill_script_sha256", "")))
            and sha_re.match(str(ident.get("scheduler_sha256", ""))),
            str(ident))
        # G9-09：恢复真实走归档（不是从旁边 backup 目录复制）
        _ck("面3 恢复源=archive",
            rep["steps"]["restore"].get("source") == "archive",
            str(rep["steps"]["restore"]))
        _ck("面3 篡改实测生效（防伪造演练）",
            rep["steps"]["tamper"]["ok"] is True
            and len(rep["steps"]["tamper"]["actions"]) >= 3)
        _ck("面3 恢复后逐文件字节级全等",
            rep["byte_match_all"] == 1
            and all(f["cmp"] is True and f["sha_match"] is True
                    for f in rep["steps"]["reconcile"]["files"]))


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    print(f"== W4 生产闭环三面自测（{len(tests)} 面）==")
    for t in tests:
        print(f"-- {t.__name__}")
        try:
            t()
        except Exception as exc:  # 测试自身崩溃=失败（不静默）
            import traceback
            traceback.print_exc()
            FAIL_N += 1
            FAILURES.append(f"{t.__name__} (CRASH: {exc!r})")
    print("=" * 40)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        for f in FAILURES:
            print(f"  ✗ {f}")
    sys.exit(1 if FAIL_N else 0)

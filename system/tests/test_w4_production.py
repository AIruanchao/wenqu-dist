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
4. Sfinal 字节备份恢复（W11-13 面 + W12-06 调度 locale 回归锁）：
   release/release-dr 模式对
   git archive <commit>（Sfinal 干净树字节）做快照→归档→独立解包→
   篡改→全空隔离根恢复→missing/extra/hash/mode/类型 + release verifier
   （wenqu_core.release_drift.audit_tree）双对账；报告绑定
   run_id/commit/deployment epoch/manifest/tree root/身份 SHA；
   仅完整 PASS+fsync 后原子推进 last-success.json；伪 tar/截断/mode/
   extra/并发/容量不足全红；W12-06 另锁「无 LANG/LC_ALL 调度环境 +
   非 ASCII 文件名」直接腿与调度腿 rc0（bsdtar 清单 locale 转义根因）。
5. 唯一 backup 作业（W11-13 面）：现有 scheduler 内恰一个 enabled
   w4.backup-restore-drill；不新增 launchd/cron 入口；DB/launchd/
   cron/argv 四面审计红绿；作业经调度真实跑通。

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
        wenqu_home=os.path.join(td, "wenqu-home"),
        cas_root=os.path.join(td, "cas"))


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


# ══════════════════════════════════════════════════════════════════════
# 面 4（W11-13）：Sfinal 字节备份恢复正演练——release/release-dr 模式
#   语料 = git archive <commit>（Sfinal 干净树字节，与工作树无关）；
#   恢复到全空隔离根；missing/extra/hash/mode/类型 + release verifier
#   （wenqu_core.release_drift.audit_tree，激活只读不变量）双对账；
#   报告绑定 run_id/commit/deployment epoch/manifest/tree root/身份 SHA；
#   仅完整 PASS + fsync 后原子推进 last-success.json。
# ══════════════════════════════════════════════════════════════════════

REPO_ROOT = os.path.dirname(REPO)                      # wenqu-dist/
DRILL_SH = os.path.join(REPO_ROOT, "system", "sentinels",
                        "backup-restore-drill.sh")
_SHA256_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


def _req(cond, msg, detail=""):
    """硬断言（pytest 与 __main__ 双通道都真实红/绿——_ck 仅计数不阻断）。"""
    if not cond:
        raise AssertionError(f"{msg}: {detail}")


def _fixture_repo(td, cjk_names=False):
    """小体量 Sfinal 模拟仓：嵌套目录/0755 可执行/symlink/二进制字节。

    cjk_names=True（W12-06）：另加非 ASCII 文件名成员（中文名常规文件 +
    中文名 symlink）——真实 Sfinal 树含 26+ 个中文证据/文档文件名，
    tar -tzf 文本清单腿的 locale 渲染只有此类语料才能压住（回归锁）。"""
    repo = os.path.join(td, "fixture-repo")
    os.makedirs(os.path.join(repo, "tools", "deep"))
    os.makedirs(os.path.join(repo, "docs"))
    def _w(rel, data, mode=None):
        p = os.path.join(repo, rel)
        with open(p, "wb") as fh:
            fh.write(data)
        if mode is not None:
            os.chmod(p, mode)
    _w("README.md", b"W11-13 Sfinal fixture corpus\n" * 8)
    _w("tools/run.sh", b"#!/bin/sh\necho final-bytes\n" * 4, 0o755)
    _w("tools/deep/data.bin", bytes(range(256)) * 16)
    _w("docs/note.txt", "最终字节备份演练语料\n".encode("utf-8") * 6)
    _w("docs/more.txt", b"second doc payload\n" * 5)
    os.symlink("README.md", os.path.join(repo, "link-to-readme"))
    os.symlink("docs", os.path.join(repo, "link-to-dir"))  # symlink→目录
    if cjk_names:
        os.makedirs(os.path.join(repo, "evidence", "00"), exist_ok=True)
        _w("docs/条件放行说明-fixture.md",
           "非 ASCII 文件名语料（W12-06 调度 locale 根因回归锁）\n"
           .encode("utf-8") * 4)
        _w("evidence/00/验收报告-第N轮-fixture.md",
           "中文证据文件名语料\n".encode("utf-8") * 4)
        os.symlink("docs/条件放行说明-fixture.md",
                   os.path.join(repo, "链接-to-docs"))
    env = dict(os.environ)
    env.setdefault("GIT_AUTHOR_NAME", "w11-13-drill")
    env.setdefault("GIT_AUTHOR_EMAIL", "drill@wenqu.local")
    env.setdefault("GIT_COMMITTER_NAME", "w11-13-drill")
    env.setdefault("GIT_COMMITTER_EMAIL", "drill@wenqu.local")
    for args in (["git", "init", "-q"], ["git", "add", "-A"],
                 ["git", "commit", "-q", "-m", "Sfinal fixture"]):
        subprocess.run(args, cwd=repo, env=env, check=True,
                       capture_output=True)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, env=env,
                         check=True, capture_output=True, text=True
                         ).stdout.strip()
    return repo, sha


def _epoch_file(td, epoch=7, source="operator-declared:test"):
    p = os.path.join(td, "deployment-epoch.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"schema": "activation-epoch/1", "generation": epoch,
                   "epoch": epoch, "source": source}, fh)
    return p


def _fake_tar_dir(box, variant, real_tar, names_echo):
    """红测假 tar：rc0 谎报/截断/mode 篡改/extra 注入（listing 对产物诚实）。"""
    d = os.path.join(box, f"fake-{variant}")
    os.makedirs(d, exist_ok=True)
    s = f"""#!/bin/sh
real="{real_tar}"
case "$1" in
  -tzf)
    arc="$2"
    if [ -f "$arc" ] && [ ! -L "$arc" ]; then
      "$real" -tzf "$arc" 2>/dev/null && exit 0
    fi
    printf '%s\\n' {names_echo}
    exit 0 ;;
  -czf)
    out="$2"; shift 2
    dir=""
    while [ $# -gt 0 ]; do
      case "$1" in
        -C) dir="$2"; shift 2 ;;
        *) break ;;
      esac
    done
    case "{variant}" in
      lie) exit 0 ;;
      truncate)
        "$real" -czf "$out" -C "$dir" "$@" || exit 1
        sz=$(wc -c < "$out"); keep=$(( sz * 2 / 5 ))
        head -c "$keep" "$out" > "$out.t" && mv "$out.t" "$out"
        exit 0 ;;
      mode)
        mut="$(dirname "$out")/mut-tree"; rm -rf "$mut"
        cp -Rp "$dir" "$mut" || exit 1
        chmod 0600 "$mut/tools/run.sh" 2>/dev/null || exit 1
        "$real" -czf "$out" -C "$mut" "$@" || exit 1
        exit 0 ;;
      extra)
        mut="$(dirname "$out")/mut-tree"; rm -rf "$mut"
        cp -Rp "$dir" "$mut" || exit 1
        echo "DRILL-EXTRA-PAYLOAD" > "$mut/docs/EXTRA-DRILL-FILE.txt"
        "$real" -czf "$out" -C "$mut" "$@" || exit 1
        exit 0 ;;
    esac
    exit 1 ;;
esac
exit 1
"""
    fp = os.path.join(d, "tar")
    with open(fp, "w") as fh:
        fh.write(s)
    os.chmod(fp, 0o755)
    return d


def _run_drill(args, *, path_prepend=None, timeout=180, drop_env=()):
    env = dict(os.environ)
    for k in drop_env:                 # W12-06：剥离 locale 仿真 launchd 调度环境
        env.pop(k, None)
    if path_prepend:
        env["PATH"] = f"{path_prepend}{os.pathsep}{os.environ['PATH']}"
    return subprocess.run(["bash", DRILL_SH] + args,
                          capture_output=True, text=True, timeout=timeout,
                          env=env)


def _latest_report(rdir):
    reps = sorted(p for p in os.listdir(rdir) if
                  p.startswith("drill-") and p.endswith(".json"))
    _req(reps, "面4 演练报告未落盘", rdir)
    # 「最新」判定键=(mtime_ns, 名称)：报告写盘即 mtime 单调推进，不受
    # 同秒时间戳/防覆写序号等命名歧义影响（W11-13 CI 慢机同秒竞态根修：
    # 旧式取 sorted()[-1] 在 p0 PASS 与 p1 BLOCKED 同秒时会选中陈旧 PASS）。
    latest = max(reps, key=lambda p: (
        os.stat(os.path.join(rdir, p)).st_mtime_ns, p))
    with open(os.path.join(rdir, latest), encoding="utf-8") as fh:
        return json.load(fh), os.path.join(rdir, latest)


def test_backup_restore_drill_release_final_bytes():
    """W11-13 正例：release-dr 对 Sfinal 字节（git archive）全链 PASS。"""
    with tempfile.TemporaryDirectory(prefix="wq-w4-rel-") as td:
        repo, commit = _fixture_repo(td)
        root = os.path.join(td, "wenqu")
        os.makedirs(root)
        epoch = _epoch_file(td)
        rdir = os.path.join(td, "reports")
        p = _run_drill(["--mode", "release-dr", "--repo", repo,
                        "--source-commit", commit, "--wenqu-root", root,
                        "--report-dir", rdir, "--epoch-file", epoch,
                        "--fault-delay", "1"])
        _req(p.returncode == 0, "面4 release-dr 真实执行 rc=0",
             p.stdout + p.stderr)
        rep, rpath = _latest_report(rdir)
        _req(rep.get("result") == "PASS", "面4 result=PASS", rep.get("reason"))
        _req(rep.get("mode") == "release-dr", "面4 mode 记录",
             rep.get("mode"))
        rid = rep.get("run_id")
        _req(isinstance(rid, str) and rid.startswith("baddrill-"),
             "面4 run_id 绑定", rid)
        rel = rep.get("release") or {}
        _req(rel.get("source_commit") == commit,
             "面4 报告绑定 Sfinal commit", rel.get("source_commit"))
        _req(rel.get("deployment_epoch") == 7
             and "epoch" in str(rel.get("deployment_epoch_source", "")),
             "面4 报告绑定 deployment epoch", rel.get("deployment_epoch"))
        _req(_SHA256_RE.match(str(rel.get("manifest_sha256", ""))),
             "面4 release manifest sha256 绑定", rel.get("manifest_sha256"))
        _req(rel.get("n_files", 0) >= 6 and rel.get("bytes", 0) > 0,
             "面4 语料规模（含 symlink/0755）", rel.get("n_files"))
        _req(bool(rel.get("tree_root")) and bool(rel.get("restore_root")),
             "面4 tree root/restore root 绑定", rel)
        _req(rel.get("restore_root_empty_before") is True,
             "面4 恢复到全空隔离根", rel.get("restore_root_empty_before"))
        checks = rel.get("checks") or {}
        _req(checks.get("missing") == 0 and checks.get("extra") == 0
             and checks.get("drifted") == 0 and checks.get("mode_drifted") == 0
             and checks.get("type_mismatch") == 0
             and checks.get("hash_ok") is True
             and checks.get("mode_ok") is True
             and checks.get("type_ok") is True,
             "面4 missing/extra/hash/mode/类型 全对账", checks)
        ver = rel.get("verifier") or {}
        _req(ver.get("ok") is True
             and "release_drift" in str(ver.get("tool", ""))
             and _SHA256_RE.match(str(ver.get("tree_digest", "")))
             and ver.get("checked") == rel.get("n_files"),
             "面4 release verifier（release_drift.audit_tree）通过", ver)
        ident = rep.get("identity") or {}
        _req(_SHA256_RE.match(str(ident.get("drill_script_sha256", "")))
             and _SHA256_RE.match(str(ident.get("scheduler_sha256", ""))),
             "面4 身份 SHA（drill/scheduler）", ident)
        arc = rep.get("archive") or {}
        _req(arc.get("materialized") is True and arc.get("size", 0) > 0
             and _SHA256_RE.match(str(arc.get("sha256", "")))
             and _SHA256_RE.match(str(arc.get("extract_sha256", ""))),
             "面4 归档实存合同（release 模式）", arc)
        dr = rep.get("dr") or {}
        _req(1.0 <= dr.get("rpo_seconds", -1) <= 300
             and 0 < dr.get("rto_seconds", -1) <= 60
             and dr.get("rpo_ok") is True and dr.get("rto_ok") is True,
             "面4 RPO/RTO 实测入报告且达冻结目标", dr)
        # last-success：仅 PASS 后原子推进，绑定全身份元组
        ls_path = os.path.join(rdir, "last-success.json")
        _req(os.path.isfile(ls_path), "面4 last-success.json 落盘", ls_path)
        with open(ls_path, encoding="utf-8") as fh:
            ls = json.load(fh)
        _req(ls.get("result") == "PASS" and ls.get("run_id") == rid,
             "面4 last-success 绑定 run_id", ls.get("run_id"))
        _req(ls.get("source_commit") == commit
             and ls.get("deployment_epoch") == 7
             and ls.get("manifest_sha256") == rel.get("manifest_sha256")
             and ls.get("archive_sha256") == arc.get("sha256")
             and ls.get("tree_digest") == ver.get("tree_digest"),
             "面4 last-success 绑定 commit/epoch/manifest/archive/tree", ls)
        _req(isinstance(ls.get("rpo_seconds"), (int, float))
             and isinstance(ls.get("rto_seconds"), (int, float)),
             "面4 last-success 记录 RPO/RTO", ls)
        # jsonl 事件日志存在且含 pass 事件
        jpath = rep.get("jsonl")
        _req(jpath and os.path.isfile(jpath), "面4 jsonl 事件日志", jpath)
        with open(jpath, encoding="utf-8") as fh:
            events = [json.loads(x) for x in fh if x.strip()]
        _req(any(e.get("event") == "drill_pass" for e in events),
             "面4 jsonl 含 drill_pass 事件", len(events))


def test_backup_restore_drill_release_red_faults():
    """W11-13 负例：伪 tar 四变体全 rc1，last-success 字节不变。"""
    real_tar = subprocess.run(["which", "tar"], capture_output=True,
                              text=True).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="wq-w4-rel-red-") as td:
        repo, commit = _fixture_repo(td)
        root = os.path.join(td, "wenqu")
        os.makedirs(root)
        epoch = _epoch_file(td)
        rdir = os.path.join(td, "reports")
        # 先出一次 PASS，固定 last-success 基线字节
        p0 = _run_drill(["--mode", "release", "--repo", repo,
                         "--source-commit", commit, "--wenqu-root", root,
                         "--report-dir", rdir, "--epoch-file", epoch])
        _req(p0.returncode == 0, "面4 红测基线 release PASS",
             p0.stdout + p0.stderr)
        ls_path = os.path.join(rdir, "last-success.json")
        baseline = open(ls_path, "rb").read()
        names_echo = " ".join(
            "'README.md' 'docs' 'link-to-readme' 'tools'")
        markers = {"lie": "not materialized",
                   "truncate": "independent archive extraction failed",
                   "mode": "mode",
                   "extra": "extra"}
        for variant in ("lie", "truncate", "mode", "extra"):
            fdir = _fake_tar_dir(td, variant, real_tar, names_echo)
            rdir_v = os.path.join(td, f"rep-{variant}")
            home_v = os.path.join(td, f"home-{variant}")
            os.makedirs(home_v)
            pv = _run_drill(["--mode", "release", "--repo", repo,
                             "--source-commit", commit,
                             "--wenqu-root", home_v,
                             "--report-dir", rdir_v,
                             "--epoch-file", epoch],
                            path_prepend=fdir)
            _req(pv.returncode == 1,
                 f"面4 fake-tar[{variant}] 产品负例 rc=1", pv.stdout + pv.stderr)
            rep_v, _ = _latest_report(rdir_v)
            _req(rep_v.get("result") == "FAIL",
                 f"面4 fake-tar[{variant}] 报告 FAIL", rep_v.get("reason"))
            _req(markers[variant] in str(rep_v.get("reason", "")),
                 f"面4 fake-tar[{variant}] reason 点名",
                 rep_v.get("reason"))
            # last-success 不被失败运行推进（本根无成功历史则必须不存在）
            _req(not os.path.exists(os.path.join(rdir_v,
                                                 "last-success.json")),
                 f"面4 fake-tar[{variant}] 不产 last-success", rdir_v)
        # 基线根的 last-success 字节全程未变
        _req(open(ls_path, "rb").read() == baseline,
             "面4 失败运行不改写既有 last-success", ls_path)


def test_backup_restore_drill_release_concurrency_and_capacity():
    """W11-13 共用进程锁禁重叠 + 容量不足保持 BLOCKED（rc3，不删证据）。"""
    with tempfile.TemporaryDirectory(prefix="wq-w4-rel-lock-") as td:
        repo, commit = _fixture_repo(td)
        root = os.path.join(td, "wenqu")
        os.makedirs(os.path.join(root, "state"))
        rdir = os.path.join(td, "reports")
        # 后台长故障窗演练持有锁（release-dr --fault-delay 6）
        bg = subprocess.Popen(
            ["bash", DRILL_SH, "--mode", "release-dr", "--repo", repo,
             "--source-commit", commit, "--wenqu-root", root,
             "--report-dir", rdir, "--fault-delay", "6"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            lock = os.path.join(root, "state", "backup-drill.lock")
            deadline = time.time() + 10
            while time.time() < deadline and not os.path.exists(lock):
                time.sleep(0.05)
            _req(os.path.exists(lock), "面4 进程锁文件出现", lock)
            time.sleep(0.4)   # 让前台完成锁获取
            p2 = _run_drill(["--mode", "release", "--repo", repo,
                             "--source-commit", commit, "--wenqu-root", root,
                             "--report-dir", rdir], timeout=60)
            _req(p2.returncode == 1,
                 "面4 并发演练（共用锁）rc=1", p2.stdout + p2.stderr)
            _req("concurrent" in (p2.stdout + p2.stderr).lower(),
                 "面4 并发拒绝 reason 点名 concurrent", p2.stderr)
        finally:
            out, err = bg.communicate(timeout=120)
        _req(bg.returncode == 0, "面4 后台演练 PASS", out + err)
        _req(not os.path.exists(os.path.join(rdir, "last-success.json"))
             or json.load(open(os.path.join(rdir, "last-success.json"),
                               encoding="utf-8"))["result"] == "PASS",
             "面4 last-success 仅由 PASS 推进", rdir)
    with tempfile.TemporaryDirectory(prefix="wq-w4-rel-cap-") as td:
        repo, commit = _fixture_repo(td)
        root = os.path.join(td, "wenqu")
        os.makedirs(root)
        epoch = _epoch_file(td)
        rdir = os.path.join(td, "reports")
        p0 = _run_drill(["--mode", "release", "--repo", repo,
                         "--source-commit", commit, "--wenqu-root", root,
                         "--report-dir", rdir, "--epoch-file", epoch])
        _req(p0.returncode == 0, "面4 容量腿基线 PASS", p0.stdout + p0.stderr)
        before = sorted(os.listdir(rdir))
        ls_baseline = open(os.path.join(rdir, "last-success.json"),
                           "rb").read()
        p1 = _run_drill(["--mode", "release", "--repo", repo,
                         "--source-commit", commit, "--wenqu-root", root,
                         "--report-dir", rdir, "--epoch-file", epoch,
                         "--min-free-bytes", "1099511627777"])
        _req(p1.returncode == 3, "面4 容量不足 rc=3 BLOCKED",
             p1.stdout + p1.stderr)
        rep1, _ = _latest_report(rdir)
        _req(rep1.get("result") == "BLOCKED",
             "面4 BLOCKED 报告（非 FAIL）", rep1.get("result"))
        _req("容量" in str(rep1.get("reason", ""))
             or "capacity" in str(rep1.get("reason", "")).lower(),
             "面4 BLOCKED reason 点名容量", rep1.get("reason"))
        _req(all(f in os.listdir(rdir) for f in before),
             "面4 BLOCKED 不删除既有审计证据", os.listdir(rdir))
        _req(open(os.path.join(rdir, "last-success.json"),
                  "rb").read() == ls_baseline,
             "面4 BLOCKED 不推进 last-success", rdir)
        # 报告目录不可写（权限类）→ rc3
        os.chmod(rdir, 0o500)
        try:
            p2 = _run_drill(["--mode", "release", "--repo", repo,
                             "--source-commit", commit, "--wenqu-root", root,
                             "--report-dir", rdir], timeout=60)
            _req(p2.returncode == 3, "面4 目标不可写 rc=3",
                 p2.stdout + p2.stderr)
        finally:
            os.chmod(rdir, 0o755)


# ---- W12-06（R11 硬阻断⑧）：调度环境 locale 根因回归锁 -------------------
# 根因：launchd 调度进程不设 LANG/LC_ALL（plist 模板与实装机均无），
# TrustedRunner 白名单透传后 drill 子进程即 C locale——bsdtar 的
# tar -tzf 文本清单在 C locale 下把非 ASCII 文件名渲染为 \NNN 八进制转义，
# 与 manifest 路径集永不匹配 → 「清单回读未覆盖全部成员」rc1（2026-10-13/14
# 生产两日调度红；同 commit 同 manifest 的手工 UTF-8 终端跑 PASS——差异
# 仅在进程 locale）。根修=drill 脚本对 tar 文本清单腿统一探测并以 UTF-8
# locale 渲染（backup-restore-drill.sh WQ_TAR_LOCALE/_tar_list）。本测试
# 双腿锁根因：直接腿 + 调度腿，语料必须含非 ASCII 文件名成员。
def test_backup_drill_cjk_names_launchd_locale_env():
    """W12-06 直接腿：无 LANG/LC_ALL 环境 + 非 ASCII 文件名 → 全链 rc0 PASS。"""
    with tempfile.TemporaryDirectory(prefix="wq-w4-cjk-") as td:
        repo, commit = _fixture_repo(td, cjk_names=True)
        root = os.path.join(td, "wenqu")
        os.makedirs(root)
        epoch = _epoch_file(td)
        rdir = os.path.join(td, "reports")
        drop = ("LANG", "LC_ALL", "LC_CTYPE")
        p = _run_drill(["--mode", "release-dr", "--repo", repo,
                        "--source-commit", commit, "--wenqu-root", root,
                        "--report-dir", rdir, "--epoch-file", epoch,
                        "--fault-delay", "1"], drop_env=drop)
        _req(p.returncode == 0,
             "W12-06 直接腿：无 locale 环境 + 中文名语料 rc=0（清单回读"
             "以 UTF-8 渲染）", p.stdout + p.stderr)
        rep, _ = _latest_report(rdir)
        _req(rep.get("result") == "PASS", "W12-06 直接腿 result=PASS",
             rep.get("reason"))
        rel = rep.get("release") or {}
        cjk_members = [f for f in ("docs/条件放行说明-fixture.md",
                                   "evidence/00/验收报告-第N轮-fixture.md",
                                   "链接-to-docs")
                       if f in json.dumps(rep.get("steps", {})
                                          .get("snapshot", {}).get("files", []),
                                          ensure_ascii=False)]
        _req(len(cjk_members) == 3, "W12-06 非 ASCII 成员（含 symlink）入清单",
             cjk_members)
        _req(rel.get("checks", {}).get("missing") == 0
             and rel.get("checks", {}).get("extra") == 0,
             "W12-06 全对账（含非 ASCII 成员）", rel.get("checks"))
        ls_path = os.path.join(rdir, "last-success.json")
        _req(os.path.isfile(ls_path)
             and json.load(open(ls_path, encoding="utf-8"))
             .get("source_commit") == commit,
             "W12-06 直接腿 last-success 推进并绑定 commit", ls_path)


def test_backup_job_scheduler_path_launchd_locale_env_cjk():
    """W12-06 调度腿：launchd 形环境（scheduler 进程无 LANG/LC_ALL）经
    production_tick 调度 backup 作业对非 ASCII 文件名树 release-dr 真跑
    rc0/PASS → last_success_at 推进 → watchdog FRESH（不再 FUNCTION_DEAD）。"""
    saved = {k: os.environ.pop(k) for k in ("LANG", "LC_ALL", "LC_CTYPE")
             if k in os.environ}
    try:
        with tempfile.TemporaryDirectory(prefix="wq-w4-cjk-sched-") as td:
            repo, commit = _fixture_repo(td, cjk_names=True)
            paths = _make_paths(td)
            stub_ok = _write_stub_sampler(td, rc=0)
            sampler_argv = (sys.executable, stub_ok,
                            paths.samples_dir, paths.shadow_dir)
            backup_argv = ("bash", DRILL_SH, "--mode", "release-dr",
                           "--repo", repo, "--source-commit", commit,
                           "--wenqu-root", paths.wenqu_home,
                           "--report-dir", paths.drills_dir)
            t0 = time.time()
            sched.production_tick(paths=paths, now=t0,
                                  job_argv=sampler_argv,
                                  backup_job_argv=backup_argv)
            # 拨 due 到过去 → 下一 tick 经调度器真实执行 backup 作业
            #（TrustedRunner 白名单环境自本进程 os.environ 构造——已剥
            # locale，等价 launchd 实装进程面）。
            store = sched.SchedulerStore(paths.scheduler_db)
            try:
                with store.transaction() as conn:
                    conn.execute(
                        "UPDATE scheduler_jobs SET next_due_at=? WHERE job_id=?",
                        (t0 - 3600, sched.BACKUP_JOB_ID))
            finally:
                store.close()
            tick2 = sched.production_tick(paths=paths, now=t0 + 60,
                                          job_argv=sampler_argv,
                                          backup_job_argv=backup_argv)
            bak_runs = [r for r in tick2.get("runs", [])
                        if "backup-restore-drill" in str(r.get("run_id", ""))]
            _req(len(bak_runs) == 1, "W12-06 调度腿恰一次 backup run",
                 tick2.get("runs"))
            _req(bak_runs[0].get("actual_exit_code") == 0
                 and bak_runs[0].get("policy_verdict") == "PASS",
                 "W12-06 调度腿 rc=0/PASS（无 locale 环境下清单回读以 "
                 "UTF-8 渲染）", bak_runs[0])
            ls_path = os.path.join(paths.drills_dir, "last-success.json")
            _req(os.path.isfile(ls_path), "W12-06 调度腿 last-success 推进",
                 ls_path)
            _req(json.load(open(ls_path, encoding="utf-8"))
                 .get("source_commit") == commit,
                 "W12-06 调度腿 last-success 绑定 Sfinal commit", ls_path)
            bak_health = [h for h in tick2.get("health", [])
                          if h.get("job_id") == sched.BACKUP_JOB_ID]
            _req(bak_health and bak_health[0].get("state") == "FRESH"
                 and bak_health[0].get("healthy") is True,
                 "W12-06 PASS 后 backup 作业 watchdog FRESH（非 "
                 "FUNCTION_DEAD）", bak_health)
    finally:
        os.environ.update(saved)


# ══════════════════════════════════════════════════════════════════════
# 面 5（W11-13）：唯一 backup 作业——scheduler 内注册 + 全系统审计
#   现有 scheduler 内恰一个 enabled w4.backup-restore-drill；不新增
#   launchd/cron 入口；DB/launchd/cron/argv 四面审计；经调度真实跑通。
# ══════════════════════════════════════════════════════════════════════

def test_backup_unique_job_registry_and_scheduler():
    with tempfile.TemporaryDirectory(prefix="wq-w4-job-") as td:
        repo, commit = _fixture_repo(td)
        paths = _make_paths(td)
        stub_ok = _write_stub_sampler(td, rc=0)
        sampler_argv = (sys.executable, stub_ok,
                        paths.samples_dir, paths.shadow_dir)
        backup_argv = ("bash", DRILL_SH, "--mode", "release-dr",
                       "--repo", repo, "--source-commit", commit,
                       "--wenqu-root", paths.wenqu_home,
                       "--report-dir", paths.drills_dir)
        t0 = time.time()
        tick1 = sched.production_tick(
            paths=paths, now=t0, job_argv=sampler_argv,
            backup_job_argv=backup_argv)
        # tick 注册两个作业：观察采样 + backup drill（唯一 backup 作业）
        store = sched.SchedulerStore(paths.scheduler_db)
        try:
            rows = store.query(
                "SELECT job_id, argv_json, enabled FROM scheduler_jobs")
            bak = [(j, a, e) for j, a, _c, e in
                   [(r[0], r[1], None, r[2]) for r in rows]
                   if "backup-restore-drill" in str(a)]
            _req(len(bak) == 1 and bak[0][0] == sched.BACKUP_JOB_ID
                 and bak[0][2] == 1,
                 "面5 DB 恰一个 enabled backup 作业", bak)
            argv_blob = bak[0][1]
            _req("--mode" in argv_blob and "release-dr" in argv_blob
                 and paths.wenqu_home in argv_blob,
                 "面5 注册 argv=drill 脚本 release-dr + wenqu-root 绑定",
                 argv_blob)
            # 唯一性审计：DB+launchd+cron+argv 四面（干净面=ok）
            agents = os.path.join(td, "LaunchAgents")
            os.makedirs(agents)
            audit = sched.audit_unique_backup_job(
                store, launch_agents_dir=agents, crontab_text="")
            _req(audit.get("ok") is True
                 and audit.get("enabled_backup_jobs") == 1
                 and audit.get("db_backup_jobs") == [sched.BACKUP_JOB_ID],
                 "面5 唯一 backup 作业审计 ok（干净面）", audit)
            # 负例①：注册表出现第二 backup 作业 → 审计红 + tick 告警面
            from wenqu_core.scheduler import (  # noqa: E402
                JobDefinition, ScheduleSpec, WatchdogPolicy)
            rogue = JobDefinition(
                job_id="w4.backup-restore-drill-rogue", owner="rogue",
                argv=("bash", DRILL_SH, "--mode", "release",
                      "--wenqu-root", paths.wenqu_home),
                schedule=ScheduleSpec.daily_at("04:00"),
                environment="production", probe_id="rogue-backup",
                station_id=0, watchdog=WatchdogPolicy())
            store_registry = sched.ScheduleRegistry(store)
            store_registry.register(rogue)
            audit2 = sched.audit_unique_backup_job(
                store, launch_agents_dir=agents, crontab_text="")
            _req(audit2.get("ok") is False
                 and audit2.get("enabled_backup_jobs") == 2,
                 "面5 第二 backup 作业 → 审计红", audit2)
            store_registry.unregister("w4.backup-restore-drill-rogue")
        finally:
            store.close()
        _req(tick1.get("backup_writers", {}).get("unique") is True,
             "面5 tick 心跳发布 backup writer 唯一性",
             tick1.get("backup_writers"))
        # 负例②：launchd 出现直跑 drill 的第二入口 → 审计红
        agents2 = os.path.join(td, "LaunchAgents-rogue")
        os.makedirs(agents2)
        with open(os.path.join(agents2, "com.wenqu.rogue-backup.plist"),
                  "w") as fh:
            fh.write('<?xml version="1.0"?>\n<plist version="1.0"><dict>'
                     '<key>Label</key><string>com.wenqu.rogue-backup'
                     '</string><key>ProgramArguments</key><array>'
                     '<string>bash</string><string>' + DRILL_SH +
                     '</string></array></dict></plist>\n')
        store2 = sched.SchedulerStore(paths.scheduler_db)
        try:
            a3 = sched.audit_unique_backup_job(
                store2, launch_agents_dir=agents2, crontab_text="")
            _req(a3.get("ok") is False and a3.get("launchd_findings"),
                 "面5 launchd 第二入口 → 审计红", a3.get("launchd_findings"))
            # 负例③：crontab 出现 drill 条目 → 审计红
            a4 = sched.audit_unique_backup_job(
                store2, launch_agents_dir=agents,
                crontab_text="17 3 * * * bash "
                             f"{DRILL_SH} --mode release\n")
            _req(a4.get("ok") is False and a4.get("cron_findings"),
                 "面5 cron 第二入口 → 审计红", a4.get("cron_findings"))
        finally:
            store2.close()
        # 仓内 launchd 模板不得直接跑 drill（scheduler tick 是唯一调度入口）
        import glob as _glob
        for tpl in _glob.glob(os.path.join(
                REPO_ROOT, "system", "launchd", "*.plist.template")):
            text = open(tpl, encoding="utf-8").read()
            _req("backup-restore-drill" not in text,
                 "面5 launchd 模板不得直跑 drill（无第二入口）", tpl)
        # 调度真实跑通：把 backup 作业 next_due 拨到过去 → tick 真跑 drill
        store3 = sched.SchedulerStore(paths.scheduler_db)
        try:
            past = t0 - 3600
            with store3.transaction() as conn:
                conn.execute(
                    "UPDATE scheduler_jobs SET next_due_at=? WHERE job_id=?",
                    (past, sched.BACKUP_JOB_ID))
        finally:
            store3.close()
        tick2 = sched.production_tick(
            paths=paths, now=t0 + 60, job_argv=sampler_argv,
            backup_job_argv=backup_argv)
        bak_runs = [r for r in tick2.get("runs", [])
                    if "w4.backup-restore-drill" in str(r.get("run_id", ""))]
        _req(any(r.get("actual_exit_code") == 0
                 and r.get("policy_verdict") == "PASS" for r in bak_runs),
             "面5 backup 作业经调度真实执行 PASS", tick2.get("runs"))
        ls_path = os.path.join(paths.drills_dir, "last-success.json")
        _req(os.path.isfile(ls_path), "面5 调度腿产出 last-success", ls_path)
        ls = json.load(open(ls_path, encoding="utf-8"))
        _req(ls.get("source_commit") == commit and ls.get("result") == "PASS",
             "面5 last-success 绑定 Sfinal commit", ls)


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

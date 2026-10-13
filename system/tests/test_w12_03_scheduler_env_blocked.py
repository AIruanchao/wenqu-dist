#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_w12_03_scheduler_env_blocked.py——W12-03 FUNCTION_DEAD 判定收窄、
采样 rc3 告警分级与 scheduler plist 模板受管 env 同步（先红后绿）。

生产根因链（/private/tmp/wq12-plan.md W12-03 节）：
  容量>90% → 新窗开不了（T0 十前置 capacity_gate 必须 OPEN）→ 唯一窗已
  invalidate → 采样器 rc3（无有效窗）→ 旧逻辑把 rc3（BLOCKED）结果当
  FUNCTION_DEAD CRITICAL×2（心跳面 + sampler rc3 面双误报）。

四面验收：

A. scheduler plist 模板同步 W11-07 全部受管 env——模板 EnvironmentVariables
   必须显式配置 WENQU_MANAGED_SAMPLER / WENQU_GIT_REPO / WENQU_GIT_RECEIPT /
   WENQU_GIT_REF / WENQU_WINDOW_PREREQS_FILE / WENQU_SCHEDULER_CONFIG /
   WENQU_OBSERVATION_ROOT / WENQU_RELEASE_SHA（与 PROD_ENV_PASSTHROUGH
   保持同源：第一跳缺键 = 第二跳透传空转）。
B. FUNCTION_DEAD 判定收窄：最近结果为 BLOCKED（rc3 统一退出码契约）= 环境
   前置不满足（无有效窗/容量 BLOCKED/受管前置不可满足）——进程活着、如实
   上报阻断，不是「进程活、功能死」。心跳面报 BLOCKED/WARNING（环境态、
   fail-visible），FUNCTION_DEAD/CRITICAL 保留给 FAIL/ERROR/TIMEOUT 持续
   无 PASS（作业真坏）。
C. production_tick 告警分级：rc3 + 容量闸 BLOCKED（scheduler 自采容量态归
   因）→ sampler.environment_blocked=True、config_error=False、WARNING
   告警（sampler_environment_blocked）；rc3 + 容量 OPEN → 维持既有
   CRITICAL（sampler_config_error：receipt 陈旧/篡改/链断照旧 fail-closed
   可见，不得降级）。
D. 真采样器端到端（tmp 根）：prereqs capacity_gate=BLOCKED → auto-open
   拒绝 → rc3（无窗、零样本）；prereqs capacity_gate=OPEN → 开窗成功 →
   rc0（窗口落盘、样本合格）。

纯标准库；`PYTHONPATH=system python3 -m pytest system/tests/test_w12_03_scheduler_env_blocked.py -q`
或 `python3 system/tests/test_w12_03_scheduler_env_blocked.py`（exit 0=全绿）。
"""
import json
import os
import sqlite3
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
ROOT = os.path.dirname(REPO)                                        # 仓根
TOOLS = os.path.join(ROOT, "tools")
for _p in (REPO, TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import observation_daily as od  # noqa: E402
from wenqu_core import scheduler as sched  # noqa: E402
from wenqu_core.scheduler import HeartbeatMonitor, NotificationOutbox, SchedulerStore  # noqa: E402

GIT = "/usr/bin/git"
UPDATER = os.path.join(TOOLS, "control_clone_updater.py")
OBS_DAILY = os.path.join(TOOLS, "observation_daily.py")
PLIST_TEMPLATE = os.path.join(REPO, "launchd",
                              "com.wenqu.scheduler.plist.template")

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


class _EnvGuard:
    """os.environ 受控注入/还原（scheduler hop-1 模拟）。"""

    def __init__(self, overrides):
        self.overrides = overrides
        self.saved = {}

    def __enter__(self):
        for k, v in self.overrides.items():
            self.saved[k] = os.environ.get(k)
            os.environ[k] = v
        return self

    def __exit__(self, *exc):
        for k, old in self.saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old
        return False


_NO_MACOS = lambda p: (_ for _ in ()).throw(  # noqa: E731
    RuntimeError("test: macos channel disabled"))


def _write_rc_sampler(td, rc):
    """真可执行采样 stub：写当日样本/影子后以 rc 退出（w4 stub 同款）。"""
    from datetime import date
    stub = os.path.join(td, f"sampler_rc{rc}_w12.py")
    with open(stub, "w", encoding="utf-8") as fh:
        fh.write(
            "import json, os, sys\n"
            "from datetime import date\n"
            "samples, shadow = sys.argv[1], sys.argv[2]\n"
            "os.makedirs(samples, exist_ok=True); os.makedirs(shadow, exist_ok=True)\n"
            "payload = {'stub': True, 'rc': %d}\n" % rc
            + "day = date.today().isoformat()\n"
            "open(os.path.join(samples, day + '.json'), 'w').write(json.dumps(payload))\n"
            "open(os.path.join(shadow, day + '.json'), 'w').write(json.dumps(payload))\n"
            "sys.exit(%d)\n" % rc
        )
    return stub


def _injected_blocked_sample():
    """容量 BLOCKED 注入样本（used_ratio≈0.94，不真塞盘）。"""
    from wenqu_core.capacity_monitor import injected_sample
    return injected_sample(used_bytes=94, free_bytes=6, path="<w12-03-inject>")


def _injected_open_sample():
    """容量 OPEN 注入样本（ratio≈0.77 / 余量 30GiB ≥ 2GiB）。"""
    from wenqu_core.capacity_monitor import injected_sample
    gib = 1024 ** 3
    return injected_sample(used_bytes=100 * gib, free_bytes=30 * gib,
                           path="<w12-03-inject-open>")


# ══════════════════════════════════════════════════════════════════════
# A. plist 模板受管 env 同步（第一跳与 PROD_ENV_PASSTHROUGH 同源）
# ══════════════════════════════════════════════════════════════════════

def test_plist_template_managed_env_sync(td):
    import plistlib
    with open(PLIST_TEMPLATE, "rb") as f:
        doc = plistlib.load(f)
    envvars = doc.get("EnvironmentVariables") or {}
    envkeys = set(envvars.keys())
    managed = {
        "WENQU_MANAGED_SAMPLER", "WENQU_GIT_REPO", "WENQU_GIT_RECEIPT",
        "WENQU_GIT_REF", "WENQU_WINDOW_PREREQS_FILE",
        "WENQU_SCHEDULER_CONFIG", "WENQU_OBSERVATION_ROOT",
        "WENQU_RELEASE_SHA",
    }
    _ck("A 模板含全部受管 env 键（含 GIT_REF/RELEASE_SHA）",
        managed <= envkeys, f"缺 {sorted(managed - envkeys)}")
    _ck("A 模板受管键值非空（占位符装配）",
        all(str(envvars.get(k, "")).strip() for k in managed),
        str({k: envvars.get(k) for k in managed}))
    pt = set(getattr(sched, "PROD_ENV_PASSTHROUGH", ()) or ())
    _ck("A 模板受管键 ⊆ PROD_ENV_PASSTHROUGH（两跳同源）",
        managed <= pt, f"passthrough 缺 {sorted(managed - pt)}")
    # 反向：plist 声明的 WENQU_* 键必须在 passthrough 内（不得出现只配
    # 第一跳、第二跳被剥的死键——W12-03 生产实锄根因形态）
    plist_wenqu = {k for k in envkeys if k.startswith("WENQU_")}
    _ck("A plist WENQU_* 键无第二跳死键",
        plist_wenqu <= pt, f"死键 {sorted(plist_wenqu - pt)}")


# ══════════════════════════════════════════════════════════════════════
# B. FUNCTION_DEAD 判定收窄（心跳面）
# ══════════════════════════════════════════════════════════════════════

def test_heartbeat_blocked_result_is_env_state_not_function_dead(td):
    store = SchedulerStore(os.path.join(str(td), "hb-w12.db"))
    try:
        from wenqu_core.scheduler import (JobDefinition, ScheduleRegistry,
                                          ScheduleSpec)
        reg = ScheduleRegistry(store)
        for jid in ("w12.env", "w12.dead", "w12.err"):
            reg.register(JobDefinition(
                job_id=jid, owner="w12", argv=("/usr/bin/true",),
                schedule=ScheduleSpec.every(300), environment="local",
                probe_id="w12-probe", station_id=0,
            ), now=0.0)
        mon = HeartbeatMonitor(store)
        fp = sched.compute_input_fingerprint(argv_digest="d" * 8)
        # 场景：采样器持续 rc3（BLOCKED/NOT_EVALUATED，统一退出码契约）
        # ——无有效窗 + 容量 BLOCKED 下的如实上报。
        mon.record_result(
            job_id="w12.env", probe_id="w12-probe", station_id=0,
            input_fingerprint=fp, execution_status="BLOCKED",
            policy_verdict="NOT_EVALUATED", finished_at=1000.0,
            ttl_seconds=900.0, now=1000.0)
        reports = {r.job_id: r for r in mon.check_health(now=1100.0)}
        r = reports["w12.env"]
        _ck("B rc3(BLOCKED) 心跳判 BLOCKED 环境态（非 FUNCTION_DEAD）",
            r.state == "BLOCKED", f"state={r.state}")
        _ck("B rc3(BLOCKED) severity=WARNING（非 CRITICAL 误报）",
            r.severity == "WARNING", f"severity={r.severity}")
        _ck("B rc3(BLOCKED) healthy=False（fail-visible 不假绿）",
            r.healthy is False)
        # 对照组：FAIL/ERROR 持续无 PASS → FUNCTION_DEAD/CRITICAL 保持
        # （作业真坏不得被收窄放走）。
        mon.record_result(
            job_id="w12.dead", probe_id="w12-probe", station_id=0,
            input_fingerprint=fp, execution_status="COMPLETED",
            policy_verdict="FAIL", finished_at=1000.0,
            ttl_seconds=900.0, now=1000.0)
        mon.record_result(
            job_id="w12.err", probe_id="w12-probe", station_id=0,
            input_fingerprint=fp, execution_status="ERROR",
            policy_verdict="NOT_EVALUATED", finished_at=1000.0,
            ttl_seconds=900.0, now=1000.0)
        reports2 = {r.job_id: r for r in mon.check_health(now=1100.0)}
        _ck("B 对照：FAIL 持续无 PASS 仍 FUNCTION_DEAD/CRITICAL",
            reports2["w12.dead"].state == "FUNCTION_DEAD"
            and reports2["w12.dead"].severity == "CRITICAL",
            f"{reports2['w12.dead'].state}/{reports2['w12.dead'].severity}")
        _ck("B 对照：ERROR 持续无 PASS 仍 FUNCTION_DEAD/CRITICAL",
            reports2["w12.err"].state == "FUNCTION_DEAD"
            and reports2["w12.err"].severity == "CRITICAL",
            f"{reports2['w12.err'].state}/{reports2['w12.err'].severity}")
    finally:
        store.close()


# ══════════════════════════════════════════════════════════════════════
# C. production_tick 告警分级（容量归因：环境态降级 / 配置错保持 CRITICAL）
# ══════════════════════════════════════════════════════════════════════

def _tick_with_capacity(td, *, rc, capacity_sample):
    """真跑 production_tick（stub 采样器 rc + 可选容量注入），返回
    (tick payload, outbox 行, paths)。

    capacity_sample 注入依赖 production_tick 的 capacity_sample 接缝
    （W12-03）；接缝不存在（旧代码）时如实退化为真实采集——本机真实
    容量 BLOCKED（W12-04 现势）也能复现红态。"""
    import inspect
    paths = sched.ProductionPaths(
        repo_root=ROOT, wenqu_home=os.path.join(str(td), f"wh-c{rc}"),
        cas_root=os.path.join(str(td), f"cas-c{rc}"))
    stub = _write_rc_sampler(td, rc)
    argv = (sys.executable, stub, paths.samples_dir, paths.shadow_dir)
    kwargs = {}
    if (capacity_sample is not None
            and "capacity_sample" in inspect.signature(
                sched.production_tick).parameters):
        kwargs["capacity_sample"] = capacity_sample
    tick = sched.production_tick(
        paths=paths, now=time.time(), job_argv=argv,
        macos_sender=_NO_MACOS, **kwargs)
    conn = sqlite3.connect(paths.scheduler_db)
    try:
        rows = conn.execute(
            "SELECT severity, subject, meta_json FROM scheduler_outbox"
            " ORDER BY created_at").fetchall()
    finally:
        conn.close()
    return tick, rows, paths


def test_tick_alert_grading_env_blocked_vs_config_error(td):
    # ---- 场景 1：无有效窗 + 容量 BLOCKED → rc3 环境态（非 CRITICAL）----
    tick, rows, _ = _tick_with_capacity(
        td, rc=3, capacity_sample=_injected_blocked_sample())
    sampler = tick.get("sampler") or {}
    _ck("C 场景1 tick rc0（调度存活）不掩盖 sampler rc3",
        tick["tick_rc"] == 0 and sampler.get("last_run_rc") == 3,
        f"tick_rc={tick['tick_rc']} sampler={sampler}")
    _ck("C 场景1 容量闸注入生效 BLOCKED",
        tick.get("capacity_gate", {}).get("gate") == "BLOCKED",
        str(tick.get("capacity_gate")))
    _ck("C 场景1 sampler.environment_blocked=True（环境归因标记）",
        sampler.get("environment_blocked") is True, str(sampler))
    _ck("C 场景1 sampler.config_error=False（非配置缺失/篡改定性）",
        sampler.get("config_error") is False, str(sampler))
    _ck("C 场景1 心跳面 sampler 作业非 CRITICAL（环境态收窄）",
        any(h.get("job_id") == sched.PROD_JOB_ID
            and h.get("severity") != "CRITICAL"
            and h.get("state") == "BLOCKED"
            for h in tick.get("health", [])),
        str(tick.get("health")))
    _ck("C 场景1 无 sampler_config_error CRITICAL（旧误报消除）",
        not any(sev == "CRITICAL" and "sampler_config_error" in str(meta)
                for sev, _subj, meta in rows), str(rows)[:400])
    _ck("C 场景1 sampler 环境态 WARNING 告警入队（fail-visible 不静默）",
        any(sev == "WARNING" and "sampler_environment_blocked" in str(meta)
            for sev, _subj, meta in rows), str(rows)[:400])

    # ---- 场景 2：容量 OPEN 下 rc3 → 配置错维持 CRITICAL（不降级）----
    tick2, rows2, _ = _tick_with_capacity(
        td, rc=3, capacity_sample=_injected_open_sample())
    sampler2 = tick2.get("sampler") or {}
    _ck("C 场景2 容量 OPEN（注入样本，判定链真实走 judge）",
        tick2.get("capacity_gate", {}).get("gate") == "OPEN",
        str(tick2.get("capacity_gate")))
    _ck("C 场景2 sampler.config_error=True（配置缺失/陈旧/篡改定性保留）",
        sampler2.get("config_error") is True, str(sampler2))
    _ck("C 场景2 sampler.environment_blocked=False",
        sampler2.get("environment_blocked") is False, str(sampler2))
    _ck("C 场景2 rc3+容量OPEN → CRITICAL 照发（fail-closed 不被收窄放走）",
        any(sev == "CRITICAL" and "sampler_config_error" in str(meta)
            for sev, _subj, meta in rows2), str(rows2)[:400])


# ══════════════════════════════════════════════════════════════════════
# D. 真采样器端到端（tmp 根）：无窗+容量 BLOCKED → rc3；有窗正常 → rc0
# ══════════════════════════════════════════════════════════════════════

def _make_origin(td, tag):
    src = os.path.join(td, f"src-{tag}")
    os.makedirs(src, exist_ok=True)
    subprocess.run([GIT, "init", "-q", "-b", "main", src], check=True)
    with open(os.path.join(src, "f.txt"), "w") as f:
        f.write("corpus-" + tag + "\n")
    subprocess.run([GIT, "-C", src, "add", "."], check=True)
    subprocess.run([GIT, "-C", src, "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-q", "-m", "init"],
                   check=True)
    bare = os.path.join(td, f"origin-{tag}.git")
    subprocess.run([GIT, "clone", "-q", "--bare", src, bare], check=True)
    return bare


def _setup_controlled(td, tag, *, capacity_gate):
    """受控 clone 全套 + prereqs（capacity_gate 可控）。"""
    bare = _make_origin(td, tag)
    cdir = os.path.join(td, f"ctl-{tag}")
    os.makedirs(cdir, exist_ok=True)
    prereqs_path = os.path.join(cdir, "window-prereqs.json")
    sfinal = "b" * 40
    with open(prereqs_path, "w") as f:
        json.dump({
            "sfinal": sfinal, "tree": "1" * 64, "roots": "2" * 64,
            "registry": "3" * 64, "branch": "4" * 64,
            "evidence_schema": "5" * 64, "observer": od.observer_sha(),
            "ci_run_id": "37994854937", "health_target_sha": sfinal,
            "health_scope": "manifest", "capacity_gate": capacity_gate,
        }, f)
    config = os.path.join(cdir, "sched-config.plist")
    with open(config, "w") as f:
        f.write("<plist>w12-03 scheduler config</plist>\n")
    clone = os.path.join(cdir, "clone")
    receipt = os.path.join(cdir, "clone-receipt.json")
    p = subprocess.run(
        [sys.executable, UPDATER, "--repo", clone, "--remote", bare,
         "--ref", "main", "--receipt", receipt,
         "--prereqs-file", prereqs_path, "--scheduler-config", config,
         "--ttl-seconds", "900"],
        capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, f"updater failed: {p.stdout} {p.stderr}"
    return {"clone": clone, "receipt": receipt, "prereqs": prereqs_path,
            "config": config, "sfinal": sfinal}


def test_real_sampler_env_blocked_rc3_then_open_rc0(td):
    # ---- 场景 1：无窗 + prereqs capacity_gate=BLOCKED → auto-open 拒绝 rc3
    ctl = _setup_controlled(td, "w12d1", capacity_gate="BLOCKED")
    obs_root = os.path.join(str(td), "obs-blocked")
    env = dict(os.environ)
    env.update({
        "HOME": str(td), "WENQU_MANAGED_SAMPLER": "1",
        "WENQU_GIT_REPO": ctl["clone"],
        "WENQU_GIT_RECEIPT": ctl["receipt"],
        "WENQU_WINDOW_PREREQS_FILE": ctl["prereqs"],
        "WENQU_SCHEDULER_CONFIG": ctl["config"],
        "WENQU_OBSERVATION_ROOT": obs_root,
        "WENQU_OBS_PROBE_MODE": "light",
        "WENQU_RELEASE_SHA": ctl["sfinal"],
    })
    p = subprocess.run([sys.executable, OBS_DAILY],
                       capture_output=True, text=True, env=env, timeout=180)
    _ck("D 真采样器 rc3（容量 BLOCKED → 无有效窗，fail-closed）",
        p.returncode == 3,
        f"rc={p.returncode} out={p.stdout[:300]} err={p.stderr[:200]}")
    out_doc = {}
    try:
        out_doc = json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        pass
    _ck("D rc3 正文如实（auto-open refused / prereqs capacity）",
        "auto-open refused" in str(out_doc.get("error", "")),
        str(out_doc)[:300])
    _ck("D 零样本落盘（无窗绝不采样）",
        not os.listdir(os.path.join(obs_root, "samples")) if os.path.isdir(
            os.path.join(obs_root, "samples")) else True)

    # ---- 场景 2：prereqs capacity_gate=OPEN → 开窗成功 rc0 ----
    # 注入边界（如实登记）：本机真实数据卷 94% used（W12-04 现势）——真实
    # 容量采集下样本必带 capacity_blocked 不合格；7789 现役 health 的
    # target_sha 与本地语料 sfinal 也无咬合。故场景 2 经驱动脚本注入两处
    # 探针输入（容量=capacity_monitor.injected_sample OPEN 样本、health=
    # 合成 200 JSON），其余全真（窗口开立/严格链/资格判定/O_EXCL 落盘/
    # rotation）。这与 DiskSample.basis='injected' 的演练语义一致。
    ctl2 = _setup_controlled(td, "w12d2", capacity_gate="OPEN")
    obs_root2 = os.path.join(str(td), "obs-open")
    driver = os.path.join(str(td), "driver_rc0.py")
    with open(driver, "w", encoding="utf-8") as f:
        f.write(
            "import os, sys\n"
            "sys.path.insert(0, %r)\n"
            "sys.path.insert(0, %r)\n"
            "import observation_daily as od\n"
            "from wenqu_core import capacity_monitor as cm\n"
            "from wenqu_core.capacity_monitor import injected_sample\n"
            "gib = 1024 ** 3\n"
            "cm.collect_disk_sample = lambda p: injected_sample(\n"
            "    100 * gib, 30 * gib, path=str(p))\n"
            "od.http_get_json = lambda url: {'status': 200, 'json': {\n"
            "    'target_sha': os.environ['W12_SFINAL'],\n"
            "    'scope_binding': {'mode': 'manifest'}}}\n"
            "sys.exit(od.main())\n"
            % (TOOLS, REPO))
    env2 = dict(env)
    env2.update({
        "W12_SFINAL": ctl2["sfinal"],
        "WENQU_GIT_REPO": ctl2["clone"],
        "WENQU_GIT_RECEIPT": ctl2["receipt"],
        "WENQU_WINDOW_PREREQS_FILE": ctl2["prereqs"],
        "WENQU_SCHEDULER_CONFIG": ctl2["config"],
        "WENQU_RELEASE_SHA": ctl2["sfinal"],
        "WENQU_OBSERVATION_ROOT": obs_root2,
        # full 模式（light 会 skip legacy_health → health_unverifiable）：
        # health 探针走驱动注入的 200 JSON。
        "WENQU_OBS_PROBE_MODE": "full",
    })
    p2 = subprocess.run([sys.executable, driver],
                        capture_output=True, text=True, env=env2, timeout=180)
    _ck("D 真采样器 rc0（有窗正常）",
        p2.returncode == 0,
        f"rc={p2.returncode} out={p2.stdout[:300]} err={p2.stderr[:200]}")
    if p2.returncode == 0:
        doc2 = json.loads(p2.stdout.strip().splitlines()[-1])
        _ck("D rc0 样本合格（qualified=true）",
            doc2.get("qualified") is True, str(doc2)[:300])
        _ck("D 窗口 manifest 已落盘",
            os.path.isdir(os.path.join(obs_root2, "windows")))


if __name__ == "__main__":
    import tempfile

    class _TdProxy(str):
        """字符串路径 + 上下文管理（test 函数把 td 同时当 path 与 ctx）。"""

        def __new__(cls, path, cm):
            obj = super().__new__(cls, path)
            obj._cm = cm
            return obj

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._cm.__exit__(*exc)
            return False

    _tests = [
        test_plist_template_managed_env_sync,
        test_heartbeat_blocked_result_is_env_state_not_function_dead,
        test_tick_alert_grading_env_blocked_vs_config_error,
        test_real_sampler_env_blocked_rc3_then_open_rc0,
    ]
    print(f"== W12-03 FUNCTION_DEAD 收窄/rc3 分级/plist 同步 自测"
          f"（{len(_tests)} 面）==")
    for fn in _tests:
        print(f"-- {fn.__name__}")
        cm = tempfile.TemporaryDirectory(prefix="wq-w1203-")
        td = _TdProxy(cm.name, cm)
        try:
            fn(td)
        except Exception as exc:  # 测试自身崩溃=失败（不静默）
            import traceback
            traceback.print_exc()
            FAIL_N += 1
            FAILURES.append(f"{fn.__name__} crashed: {exc}")
    print(f"\nPASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        print("FAILURES:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    sys.exit(0)

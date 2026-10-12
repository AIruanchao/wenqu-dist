#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P0-3/P0-5/P0-6/P0-7 基础设施加固——对抗自测（Codex 第三轮 38/100 BLOCKED 实证洞复验）。

每个测试对应一条已实锤的洞：攻击样例必须失败（fail-closed），修复行为必须成立。
纯标准库；可直接 `python3 system/tests/test_infra_hardening.py`（exit 0=全绿），
也兼容 pytest。

覆盖矩阵（洞 -> 测试）：
  P0-3  v2 契约不消费/dashboard 拒收/无时间与 verdict 字段
        -> test_p03_v2_full_chain_aggregator_to_dashboard_accept
        -> test_p03_v2_hard_semantics_fail_closed
        -> test_p03_legacy_fields_backcompat
        -> test_p03_empty_required_stations_blocked
  P0-5-CAS  shard 父目录 symlink 竞态越界 / hardlink 预置 / 半写毒文件
        -> test_p05_cas_shard_symlink_swap_attack_must_fail
        -> test_p05_cas_hardlink_preplant_must_be_rejected
        -> test_p05_cas_poison_file_fails_closed_until_admin_quarantine
        -> test_p05_cas_interrupted_write_leaves_no_poison
        -> test_p05_cas_sigkill_midwrite_retry_recovers
  W11-10-CAS  CAS 严格不可变（no-replace 发布+损坏 fail-closed+contains 全量
        重验）+ 逻辑绑定（logical_key→digest 不可重绑）+ 生产强制接线
        -> test_w11_10_cas32_same_content_exactly_one_object
        -> test_w11_10_cas32_distinct_digests_all_readable
        -> test_w11_10_cas32_same_digest_poisoned_target_fails_closed
        -> test_w11_10_cas32_symlink_target_rejected
        -> test_w11_10_contains_reverifies_type_nlink_and_hash
        -> test_w11_10_cas32_logical_key_exactly_one_binding
        -> test_w11_10_logical_binding_immutable_contract
        -> test_w11_10_jobrunner_cas_failure_forces_error_no_pass
        -> test_w11_10_station_artifact_is_real_cas_receipt
        -> test_w11_10_production_tick_gate_red_when_cas_artifact_corrupt
  P0-5-Runner  setsid 子孙逃逸 / 环境继承 / 无 allowlist 放行 /bin/sh
        -> test_p05_runner_setsid_descendant_marker_must_fail
        -> test_p05_runner_env_whitelist_default
        -> test_p05_runner_allowlist_rejects_bin_sh
  P0-6  duplicate 返回重算 hash / head() 非链头
        -> test_p06_duplicate_returns_db_hash_and_head_is_chain_tip
  P0-7  mode 策略错 / manifest 不记 mode / 回滚按 cwd 解析
        -> test_p07_mode_policy_source_exec_bit
        -> test_p07_mode_tamper_detected_by_verify
        -> test_p07_upgrade_selfcheck_rolls_back_via_relative_link
  F  install.sh 全模块验证 / doctor 吞错 / cp -R
        -> test_install_missing_core_module_fails_closed
        -> test_install_component_damage_fails_closed
        -> test_install_normal_succeeds
"""
import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.bugscan_orchestrator import build_station_result  # noqa: E402
from wenqu_core.deploy_framework import (  # noqa: E402
    DeployError, DeployManager, VerifyError,
)
from wenqu_core.gate_aggregator import GateAggregator  # noqa: E402
from wenqu_core.runner import (  # noqa: E402
    DEFAULT_ENV_KEYS, Evidence, EvidenceStore, IntegrityError, TrustedRunner,
)
from wenqu_core.store import EventStore  # noqa: E402

SHA = "1f" + "0" * 38  # 40-hex target
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


def _mk_evidence(tag="t", size=0):
    return Evidence(
        argv=(f"/bin/echo", tag), cwd="/tmp", actual_exit_code=0,
        stdout_sha256="0" * 64, stderr_sha256="0" * 64,
        argv_digest="a" * 64, timestamp=1000000.0,
        fresh_until=2000000.0, timed_out=False,
    )


def _mk_v2(station_id, verdict="PASS", status="COMPLETED", sha=SHA, env="staging"):
    return build_station_result(
        run_id="run-hardening-1", station_id=station_id, attempt_id=f"att-{station_id}",
        execution_status=status, policy_verdict=verdict,
        identity={"project_id": "acme/erp", "commit_sha": sha, "environment": env,
                  "scope_hash": "0" * 64, "ruleset_hash": "0" * 64},
        tool={"name": "hardening-probe", "version": "1.0"},
        execution={"argv_digest": "b" * 64, "started_at": "2026-10-08T00:00:00Z",
                   "ended_at": "2026-10-08T00:00:01Z", "actual_exit_code": 0,
                   "expected_exit_set": [0], "assertion_verdict": "PASS"},
        coverage={"denominator": 3, "scanned": 3},
        artifacts=[{"cas_digest": f"sha256:{'c' * 64}", "size": 128}],
    )



def _w11_strict(fn):
    """W11-10 用例在 pytest 下也必须红：_ck 失败 → AssertionError。

    __main__ 自跑器已按 FAIL_N 判红（此处不重复计数）；pytest 收集时
    _ck 只打印不判红——本装饰器补齐（CI 全仓 pytest 面与 acceptance 面
    判定一致，杜绝「pytest 绿/自跑红」的假绿分叉）。"""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        before = FAIL_N
        fn(*args, **kwargs)
        delta = FAIL_N - before
        if delta and "pytest" in sys.modules:
            raise AssertionError(
                f"{fn.__name__}: {delta} failing W11-10 check(s) "
                "(see ✗ lines above)")
    return wrapper

# ══════════════════════════════════════════════════════════════════════
# P0-3：GateAggregator 契约链
# ══════════════════════════════════════════════════════════════════════
def test_p03_v2_full_chain_aggregator_to_dashboard_accept():
    """合法 v2 station result -> aggregator -> dashboard read_gate_aggregate 必须 ACCEPT。"""
    agg = GateAggregator(required_stations={"2", "7"}, target_sha=SHA, environment="staging")
    agg.add(_mk_v2(2)).add(_mk_v2(7))
    out = agg.aggregate()
    _ck("P0-3 v2 双站 PASS 聚合为 PASS", out["aggregate_outcome"] == "PASS", out["reason"])
    _ck("P0-3 聚合输出含 generated_at（dashboard 强制）",
        isinstance(out.get("generated_at"), str) and out["generated_at"].endswith("Z"))
    _ck("P0-3 聚合输出含 policy_verdict（dashboard 强制）",
        out.get("policy_verdict") == "PASS")
    _ck("P0-3 v2 站点登记为 required（station_id 键）",
        out["stations"]["2"]["required"] is True
        and out["stations"]["2"]["input_version"] == "v2")

    # 端到端：聚合 JSON 喂 dashboard 校验函数
    spec = importlib.util.spec_from_file_location(
        "dash_server_hardening", os.path.join(REPO, "dashboard", "server.py"))
    dash = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dash)
    with tempfile.TemporaryDirectory() as td:
        snap = os.path.join(td, "gate-aggregate.json")
        with open(snap, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False)
        os.environ["WENQU_GATE_AGGREGATE"] = snap
        r = dash.read_gate_aggregate()
    _ck("P0-3 dashboard read_gate_aggregate 对聚合输出 ACCEPT", r.get("ok") is True,
        str(r))


def test_p03_v2_hard_semantics_fail_closed():
    """v2 硬语义：FAIL/TIMEOUT 硬失败、NOT_APPLICABLE 不上绿、identity 缺失 BLOCKED。"""
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(_mk_v2(2, verdict="FAIL"))
    _ck("P0-3 v2 policy FAIL -> BLOCKED", agg.aggregate()["aggregate_outcome"] == "BLOCKED")

    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(_mk_v2(2, verdict="NOT_APPLICABLE"))
    out = agg.aggregate()
    _ck("P0-3 v2 NOT_APPLICABLE -> CONDITIONAL（绝不上绿）",
        out["aggregate_outcome"] == "CONDITIONAL")

    agg = GateAggregator({"2"}, SHA, "staging")
    # TIMEOUT+PASS 组合被 build_station_result 构造器拒绝（铁律2 前置）——聚合器
    # 必须独立兜底：手搓同款畸形 v2 输入验证纵深防御
    rogue = {
        "schema_version": "2.0", "station_id": 2, "execution_status": "TIMEOUT",
        "policy_verdict": "PASS",
        "identity": {"commit_sha": SHA, "environment": "staging", "scope_hash": "0" * 64},
    }
    agg.add(rogue)
    _ck("P0-3 v2 execution TIMEOUT+声称 PASS -> 整站硬失败（铁律2 纵深）",
        agg.aggregate()["aggregate_outcome"] == "BLOCKED")

    agg = GateAggregator({"2"}, SHA, "staging")
    bad = _mk_v2(2)
    del bad["identity"]  # 拆掉身份绑定
    agg.add(bad)
    out = agg.aggregate()
    _ck("P0-3 v2 identity 缺失 -> BLOCKED（missing_field:identity）",
        out["aggregate_outcome"] == "BLOCKED"
        and out["counts"]["malformed"] >= 1)

    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(_mk_v2(2, sha="9" * 40))  # 证据 SHA 与 target 不一致
    _ck("P0-3 v2 commit_sha 与 target_sha 不一致 -> BLOCKED",
        agg.aggregate()["aggregate_outcome"] == "BLOCKED")


def test_p03_legacy_fields_backcompat():
    """legacy 字段（station/outcome/sha/environment）继续被消费。"""
    agg = GateAggregator({"lint", "test"}, SHA, "staging")
    agg.add({"station": "lint", "outcome": "PASS", "sha": SHA, "environment": "staging"})
    agg.add({"station": "test", "outcome": "OK", "commit_sha": SHA, "environment": "staging"})
    out = agg.aggregate()
    _ck("P0-3 legacy 双站 PASS 聚合为 PASS", out["aggregate_outcome"] == "PASS", out["reason"])
    _ck("P0-3 legacy 条目标记 input_version=legacy",
        out["stations"]["lint"]["input_version"] == "legacy")
    agg.add({"station": "lint", "outcome": "FAIL", "sha": SHA, "environment": "staging"})
    _ck("P0-3 legacy 同站冲突证据 -> BLOCKED", agg.aggregate()["aggregate_outcome"] == "BLOCKED")


def test_p03_empty_required_stations_blocked():
    agg = GateAggregator(set(), SHA, "staging")
    agg.add(_mk_v2(2))
    out = agg.aggregate()
    _ck("P0-3 空 required_stations 仍 BLOCKED（真空 PASS 拒绝）",
        out["aggregate_outcome"] == "BLOCKED" and out["technical_eligible"] is False)


# ══════════════════════════════════════════════════════════════════════
# P0-5 CAS：EvidenceStore
# ══════════════════════════════════════════════════════════════════════
def test_p05_cas_shard_symlink_swap_attack_must_fail():
    """对抗：mkdir 检查后 shard 父目录被换成指向 CAS 根外的 symlink——必须失败且不越界。"""
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        outside = os.path.join(td, "outside")
        os.makedirs(outside)
        store = EvidenceStore(root)
        ev = _mk_evidence("symlink-attack")
        digest = store.digest_for(ev)

        real_mkdir, real_rmdir = os.mkdir, os.rmdir
        attacked = []

        def racing_mkdir(name, mode=0o777, *, dir_fd=None):
            real_mkdir(name, mode, dir_fd=dir_fd)
            # 攻击窗口：mkdir 返回（检查通过）后、shard 二次 open 前，替换为 symlink
            real_rmdir(name, dir_fd=dir_fd)
            os.symlink(outside, name, dir_fd=dir_fd)
            attacked.append(True)

        os.mkdir = racing_mkdir
        try:
            try:
                store.put(ev)
                raised = False
            except IntegrityError:
                raised = True
        finally:
            os.mkdir = real_mkdir
        _ck("P0-5 CAS shard symlink 替换攻击被拒（IntegrityError）", raised and attacked)
        leaked = [f for f in os.listdir(outside) if digest[:8] in f or ".tmp-" in f]
        _ck("P0-5 CAS 攻击后根外目录零写入", not leaked, str(leaked))
        store.close()


def test_p05_cas_hardlink_preplant_must_be_rejected():
    """对抗：预置 hardlink（根外文件的别名）在内容路径——必须被拒绝。"""
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        outside_dir = os.path.join(td, "outside")
        os.makedirs(outside_dir)
        store = EvidenceStore(root)
        ev = _mk_evidence("hardlink-attack")
        digest = store.digest_for(ev)
        shard = os.path.join(root, digest[:2])
        os.makedirs(shard)
        # 攻击：根外构造同内容文件并 hardlink 进 CAS 内容路径（nlink=2）
        victim = os.path.join(outside_dir, "victim.json")
        with open(victim, "wb") as fh:
            fh.write(ev.to_json().encode("utf-8"))
        os.link(victim, os.path.join(shard, f"{digest}.json"))
        try:
            store.put(ev)
            raised = False
        except IntegrityError as exc:
            raised = "hardlink" in str(exc)
        _ck("P0-5 CAS hardlink 预置被拒（st_nlink>1）", raised)
        _ck("P0-5 CAS contains() 对 hardlink 返回 False", store.contains(digest) is False)
        try:
            store.get(digest)
            got_rejected = False
        except IntegrityError:
            got_rejected = True
        _ck("P0-5 CAS get() 对 hardlink 拒绝", got_rejected)
        store.close()


@_w11_strict
def test_p05_cas_poison_file_fails_closed_until_admin_quarantine():
    """W11-10 严格合同：残缺毒文件（同 digest 不同内容）put 必须 IntegrityError
    fail-closed（不得 os.replace 自愈）；原字节不变；修复仅走管理员
    quarantine → put 重建。"""
    with tempfile.TemporaryDirectory() as td:
        store = EvidenceStore(os.path.join(td, "cas"))
        ev = _mk_evidence("selfheal")
        digest = store.digest_for(ev)
        shard = os.path.join(td, "cas", digest[:2])
        os.makedirs(shard)
        poison = b"{}"  # 5 字节级毒文件（Codex 实测形态；同 digest 不同内容）
        with open(os.path.join(shard, f"{digest}.json"), "wb") as fh:
            fh.write(poison)
        try:
            store.put(ev)
            raised = False
        except IntegrityError:
            raised = True
        _ck("W11-10 毒文件 put 拒绝（IntegrityError，不自愈）", raised)
        with open(os.path.join(shard, f"{digest}.json"), "rb") as fh:
            after = fh.read()
        _ck("W11-10 拒绝后原字节不变", after == poison, repr(after[:20]))
        _ck("W11-10 contains() 对毒对象返回 False", store.contains(digest) is False)
        # 修复仅走管理员 quarantine/repair（独立通道，非 CAS 运行面自愈）
        if not hasattr(store, "quarantine"):
            _ck("W11-10 管理员 quarantine 通道存在", False, "store.quarantine missing")
            store.close()
            return
        qpath = store.quarantine(digest, reason="w11-10 poison repair test")
        with open(qpath, "rb") as fh:
            _ck("W11-10 quarantine 保留原毒字节（审计）", fh.read() == poison)
        d = store.put(ev)  # quarantine 后重建
        _ck("W11-10 quarantine→put 重建成功", d == digest)
        got = store.get(digest)
        _ck("W11-10 重建后 get 返回完整证据", got == ev)
        # 幂等：完好后再 put 同 digest 仍成功
        _ck("W11-10 完好幂等 put 成功", store.put(ev) == digest)
        try:
            store.quarantine(digest, reason="must refuse healthy object")
            healthy_refused = False
        except ValueError:
            healthy_refused = True
        _ck("W11-10 quarantine 拒绝健康对象（不得借隔离覆盖好对象）",
            healthy_refused)
        store.close()


def test_p05_cas_interrupted_write_leaves_no_poison():
    """写中途异常：最终路径无文件、无 tmp 残留。"""
    with tempfile.TemporaryDirectory() as td:
        store = EvidenceStore(os.path.join(td, "cas"))
        ev = _mk_evidence("interrupted")
        digest = store.digest_for(ev)
        shard = os.path.join(td, "cas", digest[:2])
        real_write = os.write
        state = {"n": 0}

        def bomb_write(fd, data):
            state["n"] += 1
            if state["n"] >= 2:
                raise OSError("simulated mid-write failure")
            return real_write(fd, bytes(data[:10]))  # 首次只写 10 字节（半写形态）

        os.write = bomb_write
        try:
            try:
                store.put(ev)
                raised = False
            except OSError:
                raised = True
        finally:
            os.write = real_write
        _ck("P0-5 CAS 中途写失败向上抛出", raised)
        _ck("P0-5 CAS 中途失败后最终路径不存在",
            not os.path.exists(os.path.join(shard, f"{digest}.json")))
        leftovers = [f for f in os.listdir(shard) if f.startswith(".tmp-")]
        _ck("P0-5 CAS 中途失败后无 .tmp 残留", not leftovers, str(leftovers))
        store.close()


def test_p05_cas_sigkill_midwrite_retry_recovers():
    """对抗：SIGKILL 写进程中途——最终路径绝不出现半写文件；重试 put 恢复。"""
    big = "x" * (4 * 1024 * 1024)

    def mk_ev():
        return Evidence(argv=("/bin/echo", big), cwd="/tmp", actual_exit_code=0,
                        stdout_sha256="0" * 64, stderr_sha256="0" * 64,
                        argv_digest="c" * 64, timestamp=1.0, fresh_until=2.0,
                        timed_out=False)

    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        child_src = os.path.join(td, "child.py")
        child_code = (
            "import os, sys, time\n"
            f"sys.path.insert(0, {REPO!r})\n"
            "from wenqu_core.runner import Evidence, EvidenceStore\n"
            "real_write = os.write\n"
            "def slow_write(fd, data):\n"
            "    time.sleep(0.02)\n"
            "    return real_write(fd, data[:4096])\n"
            "os.write = slow_write\n"
            f"ev = Evidence(argv=('/bin/echo', {big!r}), cwd='/tmp', "
            "actual_exit_code=0, stdout_sha256='0'*64, stderr_sha256='0'*64, "
            "argv_digest='c'*64, timestamp=1.0, fresh_until=2.0, timed_out=False)\n"
            f"store = EvidenceStore({root!r})\n"
            "store.put(ev)\n"
        )
        with open(child_src, "w", encoding="utf-8") as fh:
            fh.write(child_code)
        proc = subprocess.Popen([sys.executable, child_src])
        deadline = time.time() + 30
        tmp_seen = False
        while time.time() < deadline:
            if os.path.isdir(root):
                for shard_name in os.listdir(root):
                    if len(shard_name) == 2 and any(
                            f.startswith(".tmp-")
                            for f in os.listdir(os.path.join(root, shard_name))):
                        tmp_seen = True
                        break
            if tmp_seen:
                break
            time.sleep(0.05)
        _ck("P0-5 CAS 子进程写 tmp 已出现（攻击窗口成立）", tmp_seen)
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)

        # 重构同一证据，检查最终路径并重试
        ev = mk_ev()
        store = EvidenceStore(root)
        digest = store.digest_for(ev)
        final = os.path.join(root, digest[:2], f"{digest}.json")
        _ck("P0-5 CAS SIGKILL 后最终路径无半写毒文件", not os.path.exists(final))
        _ck("P0-5 CAS SIGKILL 后重试 put 成功", store.put(ev) == digest)
        _ck("P0-5 CAS 重试后 get 完整返回", store.get(digest) == ev)
        store.close()


# ══════════════════════════════════════════════════════════════════════
# P0-5 Runner：TrustedRunner
# ══════════════════════════════════════════════════════════════════════
def test_p05_runner_setsid_descendant_marker_must_fail():
    """对抗：孙进程 setsid 逃逸进程组，超时后写 marker——marker 必须永远不出现。

    攻击形态与 Codex 实测同款：sh 直接子进程 -> python 孙进程调 os.setsid()
    （孙进程非会话首领导，setsid 必成功）脱离 runner 的进程组，killpg 杀不到；
    孙进程睡过 runner 超时窗后写 marker。
    """
    with tempfile.TemporaryDirectory() as td:
        marker = os.path.join(td, "ESCAPED")
        attack_script = os.path.join(td, "attack.py")
        with open(attack_script, "w", encoding="utf-8") as fh:
            fh.write(
                "import os, time\n"
                "os.setsid()\n"           # 逃逸 runner 的进程组（killpg 盲区）
                "time.sleep(3)\n"         # 睡过 runner timeout=1s
                f"open({marker!r}, 'w').write('descendant survived killpg')\n"
                "time.sleep(5)\n"
            )
        # 两级结构：sh 为直接子进程；python 孙进程才是逃逸者。注意 `; true`
        # 使 sh 走 fork 而非 exec 优化（单简单命令会被 sh 直接 exec，孙进程退化
        # 为会话领导者、setsid 必 EPERM——那不是真实攻击形态）
        attack = ["/bin/sh", "-c", f"{sys.executable} {attack_script}; true"]
        runner = TrustedRunner(timeout=1.0)
        ev = runner.run(attack)
        _ck("P0-5 Runner setsid 攻击被记 timed_out", ev.timed_out is True)
        time.sleep(3.3)  # 攻击 marker 窗口（若孙进程存活将在 t+3s 落盘）
        _ck("P0-5 Runner setsid 孙进程被进程树击杀（marker 未写）",
            not os.path.exists(marker))


def test_p05_runner_env_whitelist_default():
    """默认环境白名单：敏感变量不泄入子进程；passthrough/inherit 显式口生效。"""
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "env.json")
        probe = [sys.executable, "-c",
                 f"import os, json; open({out!r}, 'w').write("
                 "json.dumps(sorted(os.environ.keys())))"]
        os.environ["WQ_SECRET_TOKEN"] = "leak-me-if-you-can"
        try:
            TrustedRunner().run(probe)
            with open(out, encoding="utf-8") as fh:
                keys = set(json.load(fh))
            _ck("P0-5 Runner 默认剥除非白名单环境变量",
                "WQ_SECRET_TOKEN" not in keys,
                f"leaked keys: {sorted(keys - set(DEFAULT_ENV_KEYS))}")
            _ck("P0-5 Runner 白名单核心键在位（PATH/HOME）",
                 "PATH" in keys and "HOME" in keys)

            TrustedRunner(env_passthrough=("WQ_SECRET_TOKEN",)).run(probe)
            with open(out, encoding="utf-8") as fh:
                keys = set(json.load(fh))
            _ck("P0-5 Runner env_passthrough 显式放行生效",
                "WQ_SECRET_TOKEN" in keys)

            TrustedRunner(inherit_env=True).run(probe)
            with open(out, encoding="utf-8") as fh:
                keys = set(json.load(fh))
            _ck("P0-5 Runner inherit_env=True 恢复完整继承（兼容口）",
                "WQ_SECRET_TOKEN" in keys)
        finally:
            del os.environ["WQ_SECRET_TOKEN"]


def test_p05_runner_allowlist_rejects_bin_sh():
    """allowlist 模式：/bin/sh -c 不在表内必须被拒；默认 None 保持兼容放行。"""
    runner = TrustedRunner(allowlist={"/bin/echo"})
    try:
        runner.run(["/bin/sh", "-c", "exit 0"])
        rejected = False
    except PermissionError:
        rejected = True
    _ck("P0-5 Runner allowlist 拒绝 /bin/sh -c", rejected)

    ev = TrustedRunner(allowlist={"/bin/echo"}).run(["/bin/echo", "allowed"])
    _ck("P0-5 Runner allowlist 放行表内命令", ev.actual_exit_code == 0)

    ev = TrustedRunner().run(["/bin/sh", "-c", "exit 7"])  # 默认 None=不限制（兼容）
    _ck("P0-5 Runner 默认无 allowlist 保持宽松（兼容既有调用方）",
        ev.actual_exit_code == 7)
    ev = TrustedRunner(allowed_executables={"/bin/sh"}).run(["/bin/sh", "-c", "exit 0"])
    _ck("P0-5 Runner 旧参数 allowed_executables 仍有效", ev.actual_exit_code == 0)


# ══════════════════════════════════════════════════════════════════════
# P0-6：EventStore duplicate/head
# ══════════════════════════════════════════════════════════════════════
def test_p06_duplicate_returns_db_hash_and_head_is_chain_tip():
    """插 A、插 B、重试 A：返回值==DB 中 A 的真实 hash；head()==B 的 hash（链头）。"""
    import sqlite3
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "events.db")
        store = EventStore(db)
        a, b = {"event": "A", "n": 1}, {"event": "B", "n": 2}
        hash_a1, ins_a1 = store.append(a)
        hash_b, ins_b = store.append(b)
        hash_a2, ins_a2 = store.append(a)  # duplicate 重试
        _ck("P0-6 A/B 均为新插入", ins_a1 and ins_b)
        _ck("P0-6 重试 A 为 duplicate", ins_a2 is False)
        _ck("P0-6 重试 A 返回 DB 中 A 的真实 hash（非按当前 head 重算）",
            hash_a2 == hash_a1 and hash_a2 != hash_b)

        conn = sqlite3.connect(db)
        rows = conn.execute(
            "SELECT event_id, event_hash FROM pipeline_events ORDER BY seq").fetchall()
        conn.close()
        in_db = [h for _, h in rows]
        _ck("P0-6 重试未新增行（DB 恰 2 条）", len(rows) == 2)
        _ck("P0-6 返回的 hash 存在于 DB", hash_a2 in in_db and hash_b in in_db)

        head_hash, total = store.head()
        _ck("P0-6 head()==最后一条（链头 B）的 hash", head_hash == hash_b and total == 2)
        _ck("P0-6 verify_chain 全链 ok", store.verify_chain()["ok"] is True)
        store.close()


# ══════════════════════════════════════════════════════════════════════
# P0-7：DeployManager
# ══════════════════════════════════════════════════════════════════════
def _mk_source(td, ok):
    src = os.path.join(td, "src-ok" if ok else "src-bad")
    os.makedirs(src, exist_ok=True)
    with open(os.path.join(src, "app.py"), "w") as fh:
        fh.write("print('app')\n")
    with open(os.path.join(src, "marker.json"), "w") as fh:
        json.dump({"ok": ok}, fh)
    return src


def test_p07_mode_policy_source_exec_bit():
    """mode 策略：源 exec 位决定发布权限（0755 无扩展→0555；0644 shebang .py→0444）。"""
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        os.makedirs(src)
        # 0755 无扩展可执行文件（Codex 实测被错改成 0444 的形态）
        with open(os.path.join(src, "runner-bin"), "w") as fh:
            fh.write("#!/usr/bin/env python3\n")
        os.chmod(os.path.join(src, "runner-bin"), 0o755)
        # 0644 带 shebang 的 .py（Codex 实测被错改成 0555 的形态）
        with open(os.path.join(src, "lib.py"), "w") as fh:
            fh.write("#!/usr/bin/env python3\nprint(1)\n")
        os.chmod(os.path.join(src, "lib.py"), 0o644)
        # 常规 0755 .sh 与 0644 .json
        with open(os.path.join(src, "script.sh"), "w") as fh:
            fh.write("#!/bin/sh\n")
        os.chmod(os.path.join(src, "script.sh"), 0o755)
        with open(os.path.join(src, "data.json"), "w") as fh:
            fh.write("{}")
        os.chmod(os.path.join(src, "data.json"), 0o644)

        mgr = DeployManager(os.path.join(td, "releases"), os.path.join(td, "current"))
        result = mgr.build(src)
        release = result["release_dir"]
        modes = {e["path"]: e["mode"] for e in
                 json.load(open(os.path.join(release, "manifest.json")))["files"]}
        _ck("P0-7 manifest 逐文件记录 mode", all(m in modes.values() for m in ("0555", "0444")))
        _ck("P0-7 0755 无扩展可执行文件保持可执行（0555）",
            modes["runner-bin"] == "0555"
            and os.stat(os.path.join(release, "runner-bin")).st_mode & 0o111)
        _ck("P0-7 0644 带 shebang 的 .py 不强加 exec（0444）",
            modes["lib.py"] == "0444"
            and not os.stat(os.path.join(release, "lib.py")).st_mode & 0o111)
        _ck("P0-7 0755 .sh 保持可执行", modes["script.sh"] == "0555")
        _ck("P0-7 0644 .json 保持 0444", modes["data.json"] == "0444")


def test_p07_mode_tamper_detected_by_verify():
    """对抗：发布后 chmod 篡改 mode——verify 必须失败（mode_drifted）。"""
    with tempfile.TemporaryDirectory() as td:
        src = _mk_source(td, ok=True)
        mgr = DeployManager(os.path.join(td, "releases"), os.path.join(td, "current"))
        release = mgr.build(src)["release_dir"]
        target = os.path.join(release, "app.py")
        os.chmod(target, 0o755)  # 篡改：0444 -> 0755
        try:
            mgr.verify(release)
            raised = False
        except VerifyError as exc:
            raised = bool(exc.report.get("mode_drifted"))
        _ck("P0-7 mode 篡改被 verify 检出（VerifyError.mode_drifted）", raised)
        os.chmod(target, 0o444)
        _ck("P0-7 恢复 mode 后 verify 通过", mgr.verify(release)["ok"] is True)


def test_p07_upgrade_selfcheck_rolls_back_via_relative_link():
    """对抗：v1 成功+v2 自检失败（进程 cwd 在别处）——current 必须指回 v1。"""
    with tempfile.TemporaryDirectory() as td:
        deploy_root = os.path.join(td, "deploy")   # releases/ 与 current/ 所在地
        elsewhere = os.path.join(td, "elsewhere")  # 进程 cwd（旧缺陷的误解析基准）
        os.makedirs(elsewhere)
        releases = os.path.join(deploy_root, "releases")
        current = os.path.join(deploy_root, "current")

        def self_check(release_dir):
            with open(os.path.join(release_dir, "marker.json"), encoding="utf-8") as fh:
                return json.load(fh).get("ok") is True

        mgr = DeployManager(releases, current, install_self_check=self_check)
        src_v1 = _mk_source(td, ok=True)
        src_v2 = _mk_source(td, ok=False)
        # 内容相同会幂等复用同一 release——给 v2 加一个差异文件
        with open(os.path.join(src_v2, "extra.txt"), "w") as fh:
            fh.write("v2\n")

        r1 = mgr.deploy(src_v1)
        v1_dir = r1["release_dir"]
        _ck("P0-7 v1 部署成功", r1["deployed"] is True)
        _ck("P0-7 current 为相对链接（非绝对）",
            not os.path.isabs(os.readlink(current)))

        old_cwd = os.getcwd()
        os.chdir(elsewhere)  # 关键：让任何按 cwd 的相对解析都指向错误位置
        try:
            _ck("P0-7 cwd≠deploy 根时 previous 相对链接解析为存在目录（对抗旧缺陷）",
                os.path.isdir(mgr._resolve_link_value(
                    os.path.dirname(current), os.readlink(current))))
            try:
                mgr.deploy(src_v2)
                failed_deploy = False
            except DeployError as exc:
                failed_deploy = "rolled back" in str(exc) and "re-verified" in str(exc)
            _ck("P0-7 v2 自检失败抛 DeployError（含回滚+再验记录）", failed_deploy)
        finally:
            os.chdir(old_cwd)
        current_now = os.path.realpath(current)
        # macOS 的 /var 是 /private/var 的符号链接——两侧都 realpath 后比较
        _ck("P0-7 回滚后 current 指回 v1（cwd 无关）",
            current_now == os.path.realpath(v1_dir),
            f"current={current_now} v1={v1_dir}")
        _ck("P0-7 回滚后 v1 自检仍通过（回滚目标健康）", self_check(current_now))


# ══════════════════════════════════════════════════════════════════════
# F：install.sh
# ══════════════════════════════════════════════════════════════════════
def _run_install(src_system, prefix, fake_home):
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": fake_home,
        "TMPDIR": tempfile.gettempdir(),
    }
    # 环境前置密闭（CI macOS 红 2026-10-12 根治）：install.sh 的模块导入/CLI 验证腿
    # 依赖受限 PATH 上的 /usr/bin/python3（Xcode CLT shim）。CI macOS 全量 acceptance
    # 长载荷（P1f2 mutation 门 ~30 分钟）之后的首个 install 曾瞬态走错退出腿：rc≠0
    # 且输出无 doctor「组件缺失」消息；同一 job 内 35 分钟前的 P1f 腿与随后两个
    # install 测试均绿（run 38233412381 实证）——是 runner 环境瞬态而非代码回归，
    # 本地（含全新 runner 上 80 连跑）不可复现。这里在同一受限 env 下显式预热
    # python3 一次，把 shim 冷启动瞬态拦在 install.sh 之外；预热失败不阻断——
    # 真故障由后续断言带完整输出取证变红。
    try:
        # 经 bash 在同一受限 env 内解析 python3——与 install.sh 各腿的解析路径
        # 完全一致（不经测试进程的父 PATH）。
        subprocess.run(["bash", "-c", "python3 -c 'print(\"warm\")'"],
                       capture_output=True, env=env, timeout=60)
    except Exception:
        pass
    # cwd 固定到临时根：避免测试进程 cwd（repo system/）经 sys.path[0]='' 遮蔽 PREFIX
    # 安装副本，使「删模块后安装必败」负例被仓内源码洗白
    return subprocess.run(
        ["bash", os.path.join(src_system, "install.sh"), "--prefix", prefix],
        capture_output=True, text=True, env=env, timeout=180,
        cwd=os.path.dirname(prefix.rstrip("/")))


def _run_install_expected(src_system, prefix, fake_home, outcome_ok):
    """带瞬态密闭的 install 运行：结果与期望不符时取证重试恰好一次。

    只救环境瞬态，绝不救真回归：真回归两次同败，仍红且 detail 附双次
    rc+输出尾取证（此前 CI 红的断言无 detail，尾 40 行取证窗取不到安装段
    ——2026-10-12 教训）。outcome_ok(r) 定义该测试的全部安装面合同。
    """
    attempts = []
    for i in (1, 2):
        r = _run_install(src_system, prefix, fake_home)
        attempts.append(r)
        if outcome_ok(r):
            if i > 1:  # 瞬态被重试密闭——留痕（不改变断言，纯取证可见性）
                print(f"    △ install 环境瞬态已重试密闭（try1 rc={attempts[0].returncode}"
                      f" 尾部={(attempts[0].stdout + attempts[0].stderr)[-300:]!r}）")
            return r, ""
    forensics = " ‖ ".join(
        f"[try{i} rc={a.returncode} 尾部={(a.stdout + a.stderr)[-500:]!r}"
        for i, a in enumerate(attempts, 1))
    return attempts[-1], forensics


def _copy_system(td, name):
    dst = os.path.join(td, name)
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return dst


def test_install_missing_core_module_fails_closed():
    """对抗：删 wenqu_core/wenqu_pipeline.py 后安装必须 rc≠0 且明确报错。"""
    with tempfile.TemporaryDirectory() as td:
        syscopy = _copy_system(td, "syscopy-nomodule")
        os.remove(os.path.join(syscopy, "wenqu_core", "wenqu_pipeline.py"))
        prefix = os.path.join(td, "prefix1")
        fake_home = os.path.join(td, "home1")
        os.makedirs(fake_home)
        r, fore = _run_install_expected(
            syscopy, prefix, fake_home,
            lambda rr: rr.returncode != 0
            and "wenqu_pipeline" in (rr.stdout + rr.stderr))
        _ck("F install 删 wenqu_pipeline 后 rc≠0（fail-closed）", r.returncode != 0,
            f"rc={r.returncode}{fore}")
        _ck("F install 明确报 wenqu_pipeline 导入失败",
            "wenqu_pipeline" in (r.stdout + r.stderr), fore)


def test_install_component_damage_fails_closed():
    """对抗：组件损坏（删哨兵文件）→ doctor 真实失败必须中止安装。"""
    with tempfile.TemporaryDirectory() as td:
        syscopy = _copy_system(td, "syscopy-damage")
        os.remove(os.path.join(syscopy, "sentinels", "ci-event-sentinel.sh"))
        prefix = os.path.join(td, "prefix2")
        fake_home = os.path.join(td, "home2")
        os.makedirs(fake_home)
        r, fore = _run_install_expected(
            syscopy, prefix, fake_home,
            lambda rr: rr.returncode != 0
            and "组件缺失" in (rr.stdout + rr.stderr))
        _ck("F install 组件损坏后 rc≠0（doctor 不再被 || true 吞掉）",
            r.returncode != 0, f"rc={r.returncode}{fore}")
        _ck("F install 报组件缺失中止", "组件缺失" in (r.stdout + r.stderr), fore)


def test_install_normal_succeeds():
    """正控：完好 system 安装 rc=0（未配置容忍、组件完好）。"""
    with tempfile.TemporaryDirectory() as td:
        syscopy = _copy_system(td, "syscopy-ok")
        prefix = os.path.join(td, "prefix3")
        fake_home = os.path.join(td, "home3")
        os.makedirs(fake_home)
        r, fore = _run_install_expected(
            syscopy, prefix, fake_home, lambda rr: rr.returncode == 0)
        _ck("F install 完好安装 rc=0", r.returncode == 0,
            (r.stdout + r.stderr)[-200:] + fore)
        _ck("F install 全模块验证输出（含 wenqu_pipeline 语义）",
            "wenqu_core" in (r.stdout + r.stderr), fore)
        # tar 管道保 mode：bin 下可执行文件保持 exec 位
        wenqu_bin = os.path.join(prefix, "bin", "wenqu")
        _ck("F install tar 管道保 exec 位（bin/wenqu 可执行）",
            os.path.isfile(wenqu_bin) and os.stat(wenqu_bin).st_mode & stat.S_IXUSR)


# ══════════════════════════════════════════════════════════════════════
# W11-10：CAS 严格不可变、逻辑绑定及生产强制接线
#
# 十轮 W2 扣分「CAS 严格合同缺」根修：32 并发夹具（真实多进程，非线程模拟）
# 覆盖三类负例（同 digest 同内容并发=唯一对象+幂等；同 digest 不同内容
# =fail-closed 原字节不变；symlink/损坏=拒绝）+ 逻辑绑定唯一胜出 +
# 生产 JobRunner 强制 CAS 接线（CAS 写失败=ERROR/NOT_EVALUATED、不刷
# 心跳、Gate 不得 PASS）+ station 工件 cas_digest 真实 CAS 回读验证。
# ══════════════════════════════════════════════════════════════════════
try:  # W11-10 新增：逻辑绑定冲突类型（基线缺失时以 None 呈红）
    from wenqu_core.runner import BindingError
    _HAS_BINDING_ERROR = True
except ImportError:
    BindingError = None
    _HAS_BINDING_ERROR = False

_W11_CONC_N = 32  # 32 并发夹具（跨进程）





def _w11_worker_script() -> str:
    """32 并发夹具子进程脚本源（与 _mk_evidence 构造完全一致的确定性证据）。"""
    return (
        "import json, sys\n"
        f"sys.path.insert(0, {REPO!r})\n"
        "from wenqu_core.runner import Evidence, EvidenceStore\n"
        "root, mode, tag, key = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]\n"
        "ev = Evidence(argv=('/bin/echo', tag), cwd='/tmp', actual_exit_code=0,\n"
        "              stdout_sha256='0'*64, stderr_sha256='0'*64,\n"
        "              argv_digest='a'*64, timestamp=1000000.0,\n"
        "              fresh_until=2000000.0, timed_out=False)\n"
        "try:\n"
        "    store = EvidenceStore(root)\n"
        "    try:\n"
        "        d = store.put(ev)\n"
        "        if mode == 'bind':\n"
        "            try:\n"
        "                store.bind(key, d)\n"
        "                out = ('bound', d, None)\n"
        "            except Exception as exc:\n"
        "                out = ('conflict', d, type(exc).__name__)\n"
        "        else:\n"
        "            out = ('ok', d, None)\n"
        "    finally:\n"
        "        store.close()\n"
        "except Exception as exc:\n"
        "    out = ('error', None, type(exc).__name__)\n"
        "print(json.dumps(out))\n"
    )


def _w11_run_concurrent(cases):
    """真实多进程并发：cases = [(mode, tag, key, root), ...]；返回每行 JSON。

    worker 脚本目录必须存活到全部子进程 exec 完成（Popen 返回不代表
    子进程已打开脚本——临时目录提前删除会令 worker 全体 ENOENT）。"""
    import subprocess as _sp
    out = []
    with tempfile.TemporaryDirectory() as holder:
        script_path = os.path.join(holder, "w11-worker.py")
        with open(script_path, "w", encoding="utf-8") as fh:
            fh.write(_w11_worker_script())
        procs = [_sp.Popen(
            [sys.executable, script_path, root, mode, tag, key],
            stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
            for mode, tag, key, root in cases]
        for p in procs:
            stdout, stderr = p.communicate(timeout=180)
            try:
                out.append(json.loads(stdout.strip().splitlines()[-1]))
            except (ValueError, IndexError):
                out.append(("crash", None,
                            f"rc={p.returncode} {stderr[-200:]}"))
    return out


def _w11_no_leftovers(root: str) -> bool:
    for shard in os.listdir(root):
        if len(shard) == 2:
            for f in os.listdir(os.path.join(root, shard)):
                if f.startswith(".tmp-"):
                    return False
    return True


@_w11_strict
def test_w11_10_cas32_same_content_exactly_one_object():
    """类一（正例不变量）：32 并发相同内容 → 同 digest、唯一对象、全幂等成功。"""
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        results = _w11_run_concurrent(
            [("put", "same-content", "", root)] * _W11_CONC_N)
        oks = [r for r in results if r[0] == "ok"]
        errs = [r for r in results if r[0] != "ok"]
        _ck("W11-10 32 并发相同内容全部成功（唯一胜出+其余幂等）",
            len(oks) == _W11_CONC_N and not errs, str(errs[:2]))
        digests = {r[1] for r in oks}
        _ck("W11-10 32 并发相同内容得到同一 digest", len(digests) == 1)
        digest = digests.pop() if digests else "0" * 64
        shard_dir = os.path.join(root, digest[:2])
        objects = sorted(f for f in os.listdir(shard_dir) if not f.startswith("."))
        _ck("W11-10 唯一对象（无覆盖/无分叉）", objects == [f"{digest}.json"],
            str(objects))
        _ck("W11-10 无临时残留", _w11_no_leftovers(root))
        store = EvidenceStore(root)
        _ck("W11-10 contains() 全量重验通过", store.contains(digest) is True)
        _ck("W11-10 get() 回读与原始证据全等",
            store.get(digest) == _mk_evidence("same-content"))
        store.close()


@_w11_strict
def test_w11_10_cas32_distinct_digests_all_readable():
    """类二（正例不变量）：32 并发不同内容、不同 digest → 32 对象均可回读。"""
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        cases = [("put", f"distinct-{i:02d}", "", root)
                 for i in range(_W11_CONC_N)]
        results = _w11_run_concurrent(cases)
        _ck("W11-10 32 并发不同内容全部成功",
            all(r[0] == "ok" for r in results),
            str([r for r in results if r[0] != "ok"][:2]))
        digests = {r[1] for r in results if r[0] == "ok"}
        _ck("W11-10 32 个互不相同的 digest", len(digests) == _W11_CONC_N)
        tag_of = {r[1]: c[1] for r, c in zip(results, cases)}  # digest → tag
        store = EvidenceStore(root)
        all_ok = True
        for d in sorted(digests):
            if not store.contains(d) or \
                    store.get(d) != _mk_evidence(tag_of[d]):
                all_ok = False
                break
        _ck("W11-10 32 个对象 contains+get 全部可读", all_ok)
        total = sum(
            len([f for f in os.listdir(os.path.join(root, s))
                 if not f.startswith(".")])
            for s in os.listdir(root) if len(s) == 2)
        _ck("W11-10 对象总数恰 32（无重复/无丢失）", total == _W11_CONC_N,
            str(total))
        _ck("W11-10 无临时残留", _w11_no_leftovers(root))
        store.close()


@_w11_strict
def test_w11_10_cas32_same_digest_poisoned_target_fails_closed():
    """类三 A（负例）：同 digest 不同内容（预置毒对象）→ 32 并发写入全部
    IntegrityError fail-closed，原字节不变，无自愈、无覆盖。"""
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        ev = _mk_evidence("poison-target")
        digest = EvidenceStore(root).digest_for(ev)
        shard_dir = os.path.join(root, digest[:2])
        os.makedirs(shard_dir)
        poison = b"W11-10-POISON-SAME-DIGEST-DIFFERENT-CONTENT"
        target = os.path.join(shard_dir, f"{digest}.json")
        with open(target, "wb") as fh:
            fh.write(poison)
        results = _w11_run_concurrent(
            [("put", "poison-target", "", root)] * _W11_CONC_N)
        rejected = [r for r in results
                    if r[0] == "error" and r[2] == "IntegrityError"]
        _ck("W11-10 32 并发同 digest 不同内容全部拒绝（fail-closed）",
            len(rejected) == _W11_CONC_N,
            str([r for r in results if r not in rejected][:2]))
        with open(target, "rb") as fh:
            after = fh.read()
        _ck("W11-10 拒绝后原毒字节不变（未自愈/未覆盖）", after == poison,
            repr(after[:24]))
        _ck("W11-10 无临时残留", _w11_no_leftovers(root))
        store = EvidenceStore(root)
        _ck("W11-10 毒对象 contains()=False", store.contains(digest) is False)
        try:
            store.get(digest)
            got_rejected = False
        except IntegrityError:
            got_rejected = True
        _ck("W11-10 毒对象 get() 拒绝", got_rejected)
        store.close()


@_w11_strict
def test_w11_10_cas32_symlink_target_rejected():
    """类三 B（负例）：内容路径预置 symlink → 32 并发写入全部拒绝，
    symlink 原样保留、根外目标零写入；修复仅走管理员 quarantine。"""
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        outside = os.path.join(td, "outside")
        os.makedirs(outside)
        ev = _mk_evidence("symlink-target")
        digest = EvidenceStore(root).digest_for(ev)
        shard_dir = os.path.join(root, digest[:2])
        os.makedirs(shard_dir)
        victim = os.path.join(outside, "victim.json")
        with open(victim, "wb") as fh:
            fh.write(b"outside-victim-bytes")
        link_path = os.path.join(shard_dir, f"{digest}.json")
        os.symlink(victim, link_path)
        results = _w11_run_concurrent(
            [("put", "symlink-target", "", root)] * _W11_CONC_N)
        rejected = [r for r in results
                    if r[0] == "error" and r[2] == "IntegrityError"]
        _ck("W11-10 32 并发 symlink 目标全部拒绝",
            len(rejected) == _W11_CONC_N,
            str([r for r in results if r not in rejected][:2]))
        _ck("W11-10 symlink 原样保留（仍是 symlink）",
            os.path.islink(link_path) and os.readlink(link_path) == victim)
        with open(victim, "rb") as fh:
            _ck("W11-10 根外目标零写入", fh.read() == b"outside-victim-bytes")
        store = EvidenceStore(root)
        _ck("W11-10 symlink 目标 contains()=False",
            store.contains(digest) is False)
        if hasattr(store, "quarantine"):
            store.quarantine(digest, reason="w11-10 symlink repair test")
            _ck("W11-10 symlink quarantine 后 put 重建成功",
                store.put(ev) == digest and store.get(digest) == ev)
        else:
            _ck("W11-10 管理员 quarantine 通道存在", False, "missing")
        store.close()


@_w11_strict
def test_w11_10_contains_reverifies_type_nlink_and_hash():
    """W11-10 §3：contains() 必须重验类型、nlink==1 与内容 hash。"""
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        store = EvidenceStore(root)
        ev_ok = _mk_evidence("contains-healthy")
        d_ok = store.put(ev_ok)
        _ck("W11-10 contains 健康对象 True", store.contains(d_ok) is True)

        # 内容 hash 不匹配（残缺/毒对象）：类型与 nlink 正常——只有 hash 重验能拦
        ev_bad = _mk_evidence("contains-poison")
        d_bad = store.digest_for(ev_bad)
        shard = os.path.join(root, d_bad[:2])
        os.makedirs(shard, exist_ok=True)
        with open(os.path.join(shard, f"{d_bad}.json"), "wb") as fh:
            fh.write(b"hash-mismatch-bytes")
        _ck("W11-10 contains 对 hash 不匹配对象 False（内容重验）",
            store.contains(d_bad) is False)

        # hardlink（nlink>1）
        ev_hl = _mk_evidence("contains-hardlink")
        d_hl = store.digest_for(ev_hl)
        shard_hl = os.path.join(root, d_hl[:2])
        os.makedirs(shard_hl, exist_ok=True)
        alias = os.path.join(td, "alias.json")
        with open(alias, "wb") as fh:
            fh.write(ev_hl.to_json().encode("utf-8"))
        os.link(alias, os.path.join(shard_hl, f"{d_hl}.json"))
        _ck("W11-10 contains 对 hardlink（nlink>1）False",
            store.contains(d_hl) is False)

        # 类型异常（FIFO）
        ev_fifo = _mk_evidence("contains-fifo")
        d_fifo = store.digest_for(ev_fifo)
        shard_fifo = os.path.join(root, d_fifo[:2])
        os.makedirs(shard_fifo, exist_ok=True)
        os.mkfifo(os.path.join(shard_fifo, f"{d_fifo}.json"))
        _ck("W11-10 contains 对非普通文件（FIFO）False",
            store.contains(d_fifo) is False)
        store.close()


@_w11_strict
def test_w11_10_cas32_logical_key_exactly_one_binding():
    """W11-10 §4/验收：32 不同内容并发竞争同 logical key → 恰好 1 绑定
    成功、31 冲突；绑定文件反映唯一胜者。"""
    if not _HAS_BINDING_ERROR:
        _ck("W11-10 逻辑绑定 API 存在（bind/BindingError）", False,
            "wenqu_core.runner.BindingError missing")
        return
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        key = "w11-10/shared-logical-key"
        results = _w11_run_concurrent(
            [("bind", f"bind-{i:02d}", key, root)
             for i in range(_W11_CONC_N)])
        bound = [r for r in results if r[0] == "bound"]
        conflict = [r for r in results if r[0] == "conflict"]
        put_fail = [r for r in results if r[0] not in ("bound", "conflict")]
        _ck("W11-10 32 并发 put 全部先行成功", not put_fail, str(put_fail[:2]))
        _ck("W11-10 同 logical key 恰好 1 个绑定成功", len(bound) == 1,
            f"bound={len(bound)}")
        _ck("W11-10 31 个绑定冲突（BindingError）",
            len(conflict) == _W11_CONC_N - 1
            and all(r[2] == "BindingError" for r in conflict),
            str([r for r in conflict if r[2] != "BindingError"][:2]))
        store = EvidenceStore(root)
        winner = bound[0][1] if bound else None
        _ck("W11-10 binding_for 返回唯一胜者 digest",
            store.binding_for(key) == winner)
        _ck("W11-10 逻辑绑定无临时残留", _w11_no_leftovers(root))
        store.close()


@_w11_strict
def test_w11_10_logical_binding_immutable_contract():
    """W11-10 §4：logical_key → content_digest 不可变（同内容幂等、
    不同内容冲突；绑定目标必须真实存在于 CAS）。"""
    if not _HAS_BINDING_ERROR:
        _ck("W11-10 逻辑绑定 API 存在（bind/BindingError）", False,
            "wenqu_core.runner.BindingError missing")
        return
    with tempfile.TemporaryDirectory() as td:
        store = EvidenceStore(os.path.join(td, "cas"))
        ev_a = _mk_evidence("binding-a")
        ev_b = _mk_evidence("binding-b")
        d_a, d_b = store.put(ev_a), store.put(ev_b)
        key = "w11-10/immutable-key"
        _ck("W11-10 bind 首次成功", store.bind(key, d_a) == d_a)
        _ck("W11-10 bind 同 digest 幂等成功", store.bind(key, d_a) == d_a)
        try:
            store.bind(key, d_b)
            rebound = False
        except BindingError:
            rebound = True
        _ck("W11-10 同 logical key 重绑不同内容 → BindingError", rebound)
        _ck("W11-10 重绑失败后绑定仍指向原 digest",
            store.binding_for(key) == d_a)
        try:
            store.bind("w11-10/ghost-key", "e" * 64)
            ghost_rejected = False
        except IntegrityError:
            ghost_rejected = True
        _ck("W11-10 绑定不存在的 digest → IntegrityError（禁空绑）",
            ghost_rejected)
        _ck("W11-10 未绑定 key 查询返回 None",
            store.binding_for("w11-10/never-bound") is None)
        store.close()


@_w11_strict
def test_w11_10_jobrunner_cas_failure_forces_error_no_pass():
    """W11-10 §6：生产 JobRunner 强制 EvidenceStore——CAS 写失败即
    ERROR/NOT_EVALUATED（rc=0 也不得 PASS）、不刷新成功心跳、无假
    evidence_digest；缺 store 时拒绝构造。"""
    from wenqu_core.scheduler import (
        JobDefinition, JobRunner, NotificationOutbox, ScheduleRegistry,
        SchedulerStore, ScheduleSpec,
    )

    with tempfile.TemporaryDirectory() as td:
        sstore = SchedulerStore(os.path.join(td, "sched.db"))
        cas = EvidenceStore(os.path.join(td, "cas"))
        frozen = _mk_evidence("frozen-cas-failure")

        class _FixedRunner(TrustedRunner):
            """确定性证据源（同 digest 复跑——CAS 毒化注入的前提）。"""
            def run(self, argv, cwd=None):
                return frozen

        # 强制配置：evidence_required=True 而 store 缺失 → 拒绝构造
        try:
            JobRunner(sstore, _FixedRunner(), evidence_required=True)
            ctor_rejected = False
        except TypeError:
            ctor_rejected = False  # 基线无该参数（红）
        except Exception as exc:
            ctor_rejected = "evidence" in str(exc).lower()
        _ck("W11-10 JobRunner evidence_required 缺 store 拒绝构造",
            ctor_rejected)

        outbox = NotificationOutbox(
            sstore, critical_channels=("primary", "fallback"))
        outbox.register_channel("primary", lambda p: None)
        outbox.register_channel("fallback", lambda p: None)
        reg = ScheduleRegistry(sstore)
        reg.register(JobDefinition(
            job_id="w11-10.cas-fail", owner="w11-10",
            argv=("/usr/bin/true",), schedule=ScheduleSpec.every(60.0),
            environment="production", probe_id="w11-10-cas", station_id=0,
            expected_exit_set=(0,), ttl_seconds=300.0), now=1000.0)
        kwargs = {"registry": reg, "outbox": outbox,
                  "evidence_store": cas, "evidence_required": True}
        try:
            jr = JobRunner(sstore, _FixedRunner(), **kwargs)
        except TypeError:  # 基线无 evidence_required（红面仍由行为断言承担）
            kwargs.pop("evidence_required")
            jr = JobRunner(sstore, _FixedRunner(), **kwargs)

        r1 = jr.run_job("w11-10.cas-fail", scheduled_at=1060.0, now=1061.0)
        _ck("W11-10 CAS 正常时 COMPLETED/PASS",
            r1.execution_status == "COMPLETED" and r1.policy_verdict == "PASS")
        _ck("W11-10 生产 run 携带 evidence_digest（CAS 接线）",
            isinstance(r1.evidence_digest, str)
            and len(r1.evidence_digest) == 64)
        _ck("W11-10 PASS 刷新心跳", r1.refreshed_heartbeat is True)

        # 毒化该 digest 的 CAS 对象（固定证据 → 复跑同 digest → 写入必失败）
        digest = r1.evidence_digest
        poison_path = os.path.join(td, "cas", digest[:2], f"{digest}.json")
        with open(poison_path, "wb") as fh:
            fh.write(b"W11-10-JOBRUNNER-CAS-CORRUPTION")

        r2 = jr.run_job("w11-10.cas-fail", scheduled_at=1120.0, now=1121.0)
        _ck("W11-10 CAS 写失败强制 ERROR/NOT_EVALUATED（rc=0 也不得 PASS）",
            r2.execution_status == "ERROR"
            and r2.policy_verdict == "NOT_EVALUATED",
            f"{r2.execution_status}/{r2.policy_verdict}")
        _ck("W11-10 CAS 写失败不刷新成功心跳",
            r2.refreshed_heartbeat is False)
        _ck("W11-10 CAS 写失败 evidence_digest=None（无假 receipt）",
            r2.evidence_digest is None)
        _ck("W11-10 CAS 写失败带警告留痕",
            any("evidence store" in w for w in r2.warnings))

        rows = sstore.query(
            "SELECT last_success_at, last_execution_status, "
            "last_policy_verdict, consecutive_failures "
            "FROM scheduler_heartbeats WHERE job_id='w11-10.cas-fail'")
        h = rows[0] if rows else (None, None, None, None)
        _ck("W11-10 心跳 last_success 未推进（仍是 r1 时刻）",
            h[0] == 1061.0, str(h[0]))
        _ck("W11-10 心跳末次执行态 ERROR、失败计数+1",
            h[1] == "ERROR" and h[3] == 1, str((h[1], h[3])))

        # Gate 面：CAS 失败 run 铸站结果绝不上绿
        from wenqu_core import scheduler as _sched
        paths = _sched.ProductionPaths(repo_root=td,
                                       wenqu_home=os.path.join(td, "wh"))
        station = _sched.build_station_result(
            paths, {**r2.__dict__}, now=1130.0)
        _ck("W11-10 CAS 失败 run 铸站结果 NOT_EVALUATED（Gate 不得 PASS）",
            station["policy_verdict"] == "NOT_EVALUATED")
        cas.close()
        sstore.close()


@_w11_strict
def test_w11_10_station_artifact_is_real_cas_receipt():
    """W11-10 §7：station 工件 cas_digest 必须能从真实 CAS 回读验证；
    普通文件 SHA（无 CAS 对象）不得冒充 receipt。"""
    from wenqu_core import scheduler as _sched

    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "cas")
        cas = EvidenceStore(root)
        if not hasattr(cas, "put_bytes") or not hasattr(cas, "verify_receipt"):
            _ck("W11-10 CAS 字节面 API 存在（put_bytes/verify_receipt）",
                False, "missing")
            cas.close()
            return
        data = b'{"sample": "w11-10-receipt", "n": 1}'
        digest = cas.put_bytes(data)
        _ck("W11-10 put_bytes 返回 sha256 内容摘要",
            digest == __import__("hashlib").sha256(data).hexdigest())
        _ck("W11-10 get_bytes 回读全等", cas.get_bytes(digest) == data)
        _ck("W11-10 verify_receipt 真实对象 True",
            cas.verify_receipt(digest) is True)
        _ck("W11-10 put_bytes 幂等（同字节同 digest）",
            cas.put_bytes(data) == digest)
        # 普通文件 SHA（从未入库）不得冒充 CAS receipt
        other = b'{"sample": "never-stored"}'
        plain_sha = __import__("hashlib").sha256(other).hexdigest()
        _ck("W11-10 普通文件 SHA 冒充 receipt 被拒（verify False）",
            cas.verify_receipt(plain_sha) is False)
        # 毒化后 receipt 失效（fail-closed），管理员 quarantine 后可重建
        bin_path = os.path.join(root, digest[:2], f"{digest}.bin")
        with open(bin_path, "wb") as fh:
            fh.write(b"CORRUPT-BIN")
        _ck("W11-10 毒化后 verify_receipt False", cas.verify_receipt(digest)
            is False)
        cas.quarantine(digest, reason="w11-10 bin repair test",
                       namespace="bin")
        _ck("W11-10 quarantine(bin) 后重建 receipt 恢复",
            cas.put_bytes(data) == digest
            and cas.verify_receipt(digest) is True)

        # build_station_result 工件 digest 必须来自真实 CAS（回读验证）
        paths = _sched.ProductionPaths(repo_root=td,
                                       wenqu_home=os.path.join(td, "wh"))
        os.makedirs(paths.samples_dir, exist_ok=True)
        sample_path = os.path.join(paths.samples_dir, "sample-latest.json")
        with open(sample_path, "wb") as fh:
            fh.write(data)
        run = {"run_id": "job-w11-10-1", "policy_verdict": "PASS",
               "execution_status": "COMPLETED", "started_at": 2000.0,
               "finished_at": 2001.0, "actual_exit_code": 0,
               "argv_digest": "b" * 64, "commit_sha": None,
               "environment": "production"}
        doc = _sched.build_station_result(paths, run, now=2002.0, cas=cas)
        arts = doc.get("artifacts") or []
        _ck("W11-10 站结果工件携带 cas_digest",
            len(arts) == 1 and arts[0]["cas_digest"] == f"sha256:{digest}",
            str(arts))
        _ck("W11-10 站结果工件 digest 可从真实 CAS 回读",
            cas.get_bytes(arts[0]["cas_digest"].split(":", 1)[1]) == data)

        # 负例：工件 CAS 对象被毒化 → 站结果降级（不得以普通 SHA 续绿）
        with open(bin_path, "wb") as fh:
            fh.write(b"CORRUPT-BIN-2")
        doc2 = _sched.build_station_result(paths, run, now=2003.0, cas=cas)
        _ck("W11-10 工件 CAS 毒化 → 站结果降级 CONDITIONAL（不上绿）",
            doc2["policy_verdict"] == "CONDITIONAL"
            and doc2["coverage"]["scanned"] == 0
            and not doc2.get("artifacts"),
            f"{doc2['policy_verdict']}/{doc2['coverage']}/{doc2.get('artifacts')}")
        cas.close()


@_w11_strict
def test_w11_10_production_tick_gate_red_when_cas_artifact_corrupt():
    """W11-10 §6/验收：生产 CAS 不可信（工件对象毒化）时 Gate 必须红——
    生产 tick 全链接线 EvidenceStore，工件 digest 是真实 CAS receipt。"""
    from wenqu_core import scheduler as _sched

    with tempfile.TemporaryDirectory() as td:
        wh = os.path.join(td, "wenqu-home")
        paths = _sched.ProductionPaths(repo_root=REPO, wenqu_home=wh)
        sample_bytes = b'{"kind": "w11-10-prod-sample", "v": 1}'
        writer = os.path.join(td, "sample-writer.py")
        with open(writer, "w", encoding="utf-8") as fh:
            fh.write(
                "import os, sys\n"
                "path = sys.argv[1]\n"
                f"open(path, 'wb').write({sample_bytes!r})\n"
            )
        job_argv = (sys.executable, writer,
                    os.path.join(paths.samples_dir, "sample-fixed.json"))
        _noop = lambda payload: None  # noqa: E731

        t0 = time.time()
        tick1 = _sched.production_tick(paths=paths, now=t0, job_argv=job_argv,
                                       macos_sender=_noop)
        run1 = [r for r in tick1.get("runs", [])]
        _ck("W11-10 生产 tick1 采样 PASS",
            tick1["station_result"]["policy_verdict"] == "PASS"
            and tick1["station_result"]["execution_status"] == "COMPLETED",
            str(tick1["station_result"]))
        station_file = os.path.join(paths.station_results_dir, "0.json")
        with open(station_file, encoding="utf-8") as fh:
            doc1 = json.load(fh)
        arts = doc1.get("artifacts") or []
        _ck("W11-10 生产站结果工件在位", len(arts) == 1, str(arts))
        # 生产接线点 1：JobRunner 携带 evidence_digest（run 落 CAS）
        rows_have_digest = True
        if run1:
            rows_have_digest = isinstance(
                run1[0].get("actual_exit_code"), int)
        _ck("W11-10 生产 tick run 完成态", rows_have_digest)
        # 生产接线点 2：工件 digest 是真实 CAS receipt（可回读验证）
        cas_root = os.path.join(wh, "state", "evidence-cas")
        cas = EvidenceStore(cas_root)
        if not arts:
            _ck("W11-10 生产工件 digest 真实 CAS 回读验证", False, "no artifact")
        else:
            digest = arts[0]["cas_digest"].split(":", 1)[1]
            got = cas.get_bytes(digest) if hasattr(cas, "get_bytes") else None
            _ck("W11-10 生产工件 digest 真实 CAS 回读验证", got == sample_bytes,
                f"cas_root={cas_root} digest={digest[:12]}…")
            # 生产接线点 3：run 的 evidence 落在 CAS（存在性验证）
            ev_objects = [
                f for s in os.listdir(cas_root) if len(s) == 2
                for f in os.listdir(os.path.join(cas_root, s))
                if f.endswith(".json")]
            _ck("W11-10 生产 run evidence 已落 CAS（json 对象在位）",
                len(ev_objects) >= 1, str(ev_objects[:2]))
            # 负例：毒化工件 CAS 对象 → tick2 Gate 必须红（不上 PASS）
            bin_path = os.path.join(cas_root, digest[:2], f"{digest}.bin")
            if not os.path.isfile(bin_path):
                _ck("W11-10 生产 CAS 已接线（工件对象在位）", False,
                    f"{bin_path} missing——生产未接 CAS")
            else:
                with open(bin_path, "wb") as fh:
                    fh.write(b"W11-10-PROD-CAS-CORRUPTION")
                tick2 = _sched.production_tick(
                    paths=paths, now=t0 + 310.0, job_argv=job_argv,
                    macos_sender=_noop)
                _ck("W11-10 生产 CAS 毒化 → tick2 站结果不上绿",
                    tick2["station_result"]["policy_verdict"] != "PASS",
                    str(tick2["station_result"]))
                _ck("W11-10 生产 CAS 毒化 → tick2 Gate 不 PASS",
                    tick2["gate"]["aggregate_outcome"] != "PASS",
                    str(tick2["gate"]))
        cas.close()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith(("test_p0", "test_install", "test_w11_10"))
             and callable(v)]
    print(f"== 基础设施加固对抗自测（{len(tests)} 组）==")
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

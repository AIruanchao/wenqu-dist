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
        -> test_p05_cas_poison_file_selfheals
        -> test_p05_cas_interrupted_write_leaves_no_poison
        -> test_p05_cas_sigkill_midwrite_retry_recovers
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


def test_p05_cas_poison_file_selfheals():
    """残缺毒文件（历史 5 字节半写）重试 put 必须自愈而非永久报损坏。"""
    with tempfile.TemporaryDirectory() as td:
        store = EvidenceStore(os.path.join(td, "cas"))
        ev = _mk_evidence("selfheal")
        digest = store.digest_for(ev)
        shard = os.path.join(td, "cas", digest[:2])
        os.makedirs(shard)
        with open(os.path.join(shard, f"{digest}.json"), "wb") as fh:
            fh.write(b"{}")  # 5 字节级毒文件（Codex 实测形态）
        d = store.put(ev)  # 不得抛 IntegrityError
        _ck("P0-5 CAS 毒文件重试 put 自愈成功", d == digest)
        got = store.get(digest)
        _ck("P0-5 CAS 自愈后 get 返回完整证据", got == ev)
        # 幂等：完好后再 put 同 digest 仍成功
        _ck("P0-5 CAS 完好幂等 put 成功", store.put(ev) == digest)
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
    # cwd 固定到临时根：避免测试进程 cwd（repo system/）经 sys.path[0]='' 遮蔽 PREFIX
    # 安装副本，使「删模块后安装必败」负例被仓内源码洗白
    return subprocess.run(
        ["bash", os.path.join(src_system, "install.sh"), "--prefix", prefix],
        capture_output=True, text=True, env=env, timeout=180,
        cwd=os.path.dirname(prefix.rstrip("/")))


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
        r = _run_install(syscopy, prefix, fake_home)
        _ck("F install 删 wenqu_pipeline 后 rc≠0（fail-closed）", r.returncode != 0,
            f"rc={r.returncode}")
        _ck("F install 明确报 wenqu_pipeline 导入失败",
            "wenqu_pipeline" in (r.stdout + r.stderr))


def test_install_component_damage_fails_closed():
    """对抗：组件损坏（删哨兵文件）→ doctor 真实失败必须中止安装。"""
    with tempfile.TemporaryDirectory() as td:
        syscopy = _copy_system(td, "syscopy-damage")
        os.remove(os.path.join(syscopy, "sentinels", "ci-event-sentinel.sh"))
        prefix = os.path.join(td, "prefix2")
        fake_home = os.path.join(td, "home2")
        os.makedirs(fake_home)
        r = _run_install(syscopy, prefix, fake_home)
        _ck("F install 组件损坏后 rc≠0（doctor 不再被 || true 吞掉）",
            r.returncode != 0, f"rc={r.returncode}")
        _ck("F install 报组件缺失中止", "组件缺失" in (r.stdout + r.stderr))


def test_install_normal_succeeds():
    """正控：完好 system 安装 rc=0（未配置容忍、组件完好）。"""
    with tempfile.TemporaryDirectory() as td:
        syscopy = _copy_system(td, "syscopy-ok")
        prefix = os.path.join(td, "prefix3")
        fake_home = os.path.join(td, "home3")
        os.makedirs(fake_home)
        r = _run_install(syscopy, prefix, fake_home)
        _ck("F install 完好安装 rc=0", r.returncode == 0,
            (r.stdout + r.stderr)[-200:])
        _ck("F install 全模块验证输出（含 wenqu_pipeline 语义）",
            "wenqu_core" in (r.stdout + r.stderr))
        # tar 管道保 mode：bin 下可执行文件保持 exec 位
        wenqu_bin = os.path.join(prefix, "bin", "wenqu")
        _ck("F install tar 管道保 exec 位（bin/wenqu 可执行）",
            os.path.isfile(wenqu_bin) and os.stat(wenqu_bin).st_mode & stat.S_IXUSR)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith(("test_p0", "test_install")) and callable(v)]
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

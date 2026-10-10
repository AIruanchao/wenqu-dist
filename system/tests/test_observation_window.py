#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_observation_window.py——G9-02/T2：观察样本 O_EXCL、hash chain、动态窗口。

先红后绿负测面（全部 tmp_path 语料，绝不写真实 ~/.wenqu）：

A. O_EXCL/防覆盖（R8-OBS-COLLISION-016）
   - 32 writer 同秒并发 → 32 个不同普通文件，旧样本 hash 不变，链序完整；
   - 预置 symlink / 预置同名文件 → fail-visible（错误记录落 errors/，绝不
     覆盖、绝不跟随 symlink、绝不静默跳过）。
B. hash chain（G9-02）
   - 每条样本记录 epoch_id/sequence/prev_sha256/sample_sha256/release_sha/
     observer_sha/scheduler_config_sha；首条 prev=GENESIS；
   - window_harvest 从 raw 样本重算：篡改/缺 sequence/链断/同序分叉 → rc1。
C. 动态窗口（删除硬编码 2026-10-10 起点）
   - 源码零硬编码日期；window manifest open→first sample→sealed 生命周期；
   - canary 锚点=T0（首条合格样本时刻），NOT_DUE/IN_WINDOW/CLOSED 动态推进；
   - window_harvest 四态：rc0 完整通过 / rc1 窗口内失败 / rc2 NOT_DUE /
     rc3 证据环境错误。
D. 唯一 writer + rotation
   - rotation 识别新旧两代命名；不删当前窗口（active epoch）证据；
   - launchd 审计：除 com.wenqu.scheduler 外任何触及观察面的作业=第二
     writer（含旧 com.wenqu.observation / com.wenqu.observation-window）；
     仓内受版本管理模板不得定义禁止 label；
   - scheduler 注册表审计：观察采样作业唯一（w4.observation-sample）。
E. identity fail-visible（R8-OBS-NOGIT-015）
   - WENQU_GIT_REPO 指向不存在/非 git 路径 → 拒绝静默回退，样本
     qualified=false + 显式 identity_error + fallback_refused，进程 rc1；
   - 有效本地 origin → identity 40hex 合格。
F. T2 收紧（R9-OBS-T0-QUALIFICATION-002 / 九轮 §1 硬阻断 2 / §9 P0-2）
   - F1 开窗门槛：十项前置（release/sfinal+tree+roots+registry+branch+
     evidence_schema+observer+ci_run_id+health+capacity）缺任一/零值/
     self_declared/BLOCKED → 拒开（CLI rc3），绝不 sfinal=null 起钟；
     十项要素写入 manifest digests 块；旧形态无效窗（sfinal=null/digests={}
     照搬现场 w-20261009T231625506512000）收割 → rc3；
   - F2 资格 fail-closed：health 零 SHA/self_declared/capacity BLOCKED/
     release·observer 与窗口不咬合 → qualified=false + unqualified_reasons，
     收割 rc1 且窗口级 qualification 聚合（全窗合格率+理由直方图）；
   - F3 收割严判：5min/bin 预期分桶 × 最低覆盖阈值（默认 90%）不足 →
     rc1 WINDOW_FAIL（绝不 2 样本 rc0）；legacy 样本不计分母但
     counts.legacy_ignored 显式计数；阈值显式可调（min_coverage=0 → rc0）；
   - F4 invalidate 工单：可审计作废记录（invalidated_at+原因+作废人+原窗
     全量+原文件 sha256），不删文件；作废窗收割 rc3；active 释放后可按新
     窗重开；幂等；空 reason/principal 拒绝。

纯标准库；`PYTHONPATH=system python3 -m pytest system/tests/ -q -k "observ or window"`
或 `python3 system/tests/test_observation_window.py`（exit 0=全绿）。
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
ROOT = os.path.dirname(REPO)                                        # 仓根
TOOLS = os.path.join(ROOT, "tools")
for _p in (REPO, TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import observation_daily as od  # noqa: E402
import window_harvest as wh     # noqa: E402
import window_manifest as wm    # noqa: E402
from wenqu_core import scheduler as sched  # noqa: E402

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


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def _core(identity="a" * 40, tag="t", sfinal="b" * 40,
         health_target=None, health_scope="manifest", capacity="OPEN"):
    """样本 core（T2 后默认携带合格 health/capacity 面，可注入坏值）。"""
    return {
        "host": "test-host",
        "repo": {"path": "/tmp/x", "identity": identity,
                 "identity_error": None if identity else "no origin/main",
                 "worktree_head": identity, "dirty": False},
        "disk": {"used_pct": 33.0},
        "legacy_health": {"status": 200, "json": {
            "target_sha": sfinal if health_target is None else health_target,
            "scope_binding": {"mode": health_scope},
            "mode": health_scope + "_aggregation"}},
        "capacity_gate": {"capacity_gate": capacity,
                          "severity": "CRITICAL" if capacity == "BLOCKED"
                          else "OK"},
        "probe_note": tag,
    }


def _record(root, identity="a" * 40, tag="t", release_sha=None,
            scheduler_config_sha=None, collected_at=None, sfinal="b" * 40,
            **core_over):
    return od.record_sample(
        root, _core(identity, tag, sfinal=sfinal, **core_over),
        identity=identity, release_sha=release_sha or sfinal,
        scheduler_config_sha=scheduler_config_sha,
        collected_at=collected_at)


def _prereqs(sfinal="b" * 40, observer=None, **over):
    """T0 十项前置（F1）：与 release_sha/observer_sha/health 正源咬合。"""
    p = {
        "sfinal": sfinal,
        "tree": "1" * 64,
        "roots": "2" * 64,
        "registry": "3" * 64,
        "branch": "4" * 64,
        "evidence_schema": "5" * 64,
        "observer": observer or od.observer_sha(),
        "ci_run_id": "37994854937",
        "health_target_sha": sfinal,
        "health_scope": "manifest",
        "capacity_gate": "OPEN",
    }
    p.update(over)
    return p


def _open_valid(td, duration_hours=336.0, **over):
    return wm.open_window(td, duration_hours=duration_hours,
                          prerequisites=_prereqs(**over))


def _seal_expired(td, manifest):
    """封口并置 end_at 于过去（收割严判用；从盘上重读防 stale 覆盖 t0）。"""
    man = wm.load_manifest(td, manifest["window_id"])
    man["end_at"] = (datetime.now(timezone.utc)
                     - timedelta(minutes=1)).isoformat()
    man["status"] = "sealed"
    wm._atomic_write_json(wm.manifest_path(td, man["window_id"]), man)
    return man


# ══════════════════════════════════════════════════════════════════════
# A. O_EXCL + 防覆盖
# ══════════════════════════════════════════════════════════════════════

def test_32_writers_same_second_immutable(td):
    _open_valid(td)  # T2：十项前置齐备才可开窗（auto-open 已拒空前置）
    samples = os.path.join(td, "samples")
    os.makedirs(samples)
    # 预置一份「旧样本」：hash 记录后必须始终不变
    old_path = os.path.join(samples, "2026-10-01.json")
    with open(old_path, "w") as f:
        f.write('{"legacy": true}\n')
    old_hash = _sha(old_path)

    results = []
    errors = []
    barrier = threading.Barrier(32)

    def writer(i):
        try:
            barrier.wait()  # 同一时刻齐发（同秒并发）
            r = _record(td, tag=f"w{i}")
            results.append(r)
        except Exception as e:  # noqa: BLE001
            errors.append(f"w{i}:{type(e).__name__}:{e}")

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    _ck("A 32 writer 零异常", not errors, str(errors[:3]))
    _ck("A 32 writer 全部成功落盘", len(results) == 32,
        str([r.get("rc") for r in results][:5]))
    names = [os.path.basename(r["path"]) for r in results if r.get("path")]
    _ck("A 32 个不同文件名", len(set(names)) == 32, str(names[:3]))
    files = [n for n in os.listdir(samples)
             if n.endswith(".json") and n != "2026-10-01.json"]
    _ck("A 目录中恰 32 个新样本文件", len(files) == 32, str(len(files)))
    _ck("A 全部普通文件（无 symlink）",
        all(not os.path.islink(os.path.join(samples, n)) for n in files))
    _ck("A 旧样本 hash 不变", _sha(old_path) == old_hash)
    # 链序：32 条 sequence 恰为 1..32，prev 链逐条咬合
    seqs = sorted(r["doc"]["sequence"] for r in results)
    _ck("A 链序完整 1..32（无覆盖丢样）", seqs == list(range(1, 33)),
        str(seqs[:5]))
    by_seq = {r["doc"]["sequence"]: r["doc"] for r in results}
    ok_chain = by_seq[1]["prev_sha256"] == "0" * 64
    for i in range(2, 33):
        ok_chain = ok_chain and by_seq[i]["prev_sha256"] == by_seq[i - 1]["sample_sha256"]
    _ck("A prev 链逐条咬合", ok_chain)
    # 命名契约：UTC 纳秒紧凑串 + 随机片段
    _ck("A 新命名契约（纳秒+随机）",
        all(re.match(r"^\d{8}T\d{15}-[0-9a-f]{8}\.json$", n) for n in names),
        str(names[:2]))


def test_preset_symlink_and_collision_fail_visible(td):
    samples = os.path.join(td, "samples")
    os.makedirs(samples)
    # 预置 symlink：目标是仓外诱饵文件，内容必须原样
    bait = os.path.join(td, "bait.txt")
    with open(bait, "w") as f:
        f.write("do-not-touch")
    fixed_name = "preset-name.json"
    link = os.path.join(samples, fixed_name)
    os.symlink(bait, link)

    res = od.write_sample_exclusive(samples, {"x": 1}, name=fixed_name)
    _ck("A 预置 symlink → 创建失败（不跟随）", res["path"] is None,
        str(res)[:200])
    _ck("A symlink 仍是 symlink（未被替换）", os.path.islink(link))
    _ck("A 诱饵文件内容原样", open(bait).read() == "do-not-touch")
    _ck("A 失败原因可见（symlink/exists）",
        res["error"] is not None and res["error"].get("error")
        == "exclusive_create_failed"
        and res["error"]["attempts"], str(res.get("error"))[:200])

    # 预置同名普通文件：同样 fail-visible，内容不变
    fixed2 = "preset-regular.json"
    with open(os.path.join(samples, fixed2), "w") as f:
        f.write('{"orig": true}')
    res2 = od.write_sample_exclusive(samples, {"x": 2}, name=fixed2)
    _ck("A 预置同名文件 → 拒绝覆盖", res2["path"] is None)
    doc = json.load(open(os.path.join(samples, fixed2)))
    _ck("A 原文件内容未被改动", doc == {"orig": True})

    # 错误记录落 errors/（fail-visible，不静默）
    err_dir = od.errors_dir(td)
    errs = [n for n in os.listdir(err_dir) if n.endswith(".json")] \
        if os.path.isdir(err_dir) else []
    _ck("A 错误记录可见落盘 errors/", len(errs) >= 2, str(errs))


# ══════════════════════════════════════════════════════════════════════
# B. hash chain 字段 + 收割重算
# ══════════════════════════════════════════════════════════════════════

def test_chain_fields_and_sample_hash(td):
    _open_valid(td)
    rel, scs = "b" * 40, "c" * 64
    r1 = _record(td, release_sha=rel, scheduler_config_sha=scs, tag="s1")
    r2 = _record(td, release_sha=rel, scheduler_config_sha=scs, tag="s2")
    d1, d2 = r1["doc"], r2["doc"]
    for fld in ("epoch_id", "sequence", "prev_sha256", "sample_sha256",
                "release_sha", "observer_sha", "scheduler_config_sha",
                "window_id"):
        _ck(f"B 样本记录 {fld}", fld in d1 and d1[fld] is not None)
    _ck("B 首条 prev=GENESIS(0*64)", d1["prev_sha256"] == "0" * 64)
    _ck("B sequence 1→2", d1["sequence"] == 1 and d2["sequence"] == 2)
    _ck("B prev 咬合", d2["prev_sha256"] == d1["sample_sha256"])
    _ck("B 同 epoch", d1["epoch_id"] == d2["epoch_id"])
    # sample_sha256 可由 doc（除自身外）重算
    recal = od.compute_sample_sha256({k: v for k, v in d1.items()
                                      if k != "sample_sha256"})
    _ck("B sample_sha256 可重算", recal == d1["sample_sha256"])


def test_harvest_recompute_negative(td):
    _open_valid(td, duration_hours=0.05)  # 3min 窗 → 1 个 5min 桶（rc0 可达）
    rel, scs = "b" * 40, "c" * 64
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="h1")
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="h2")
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="h3")

    # 基线：窗口内（未到期）且无失败 → rc2 NOT_DUE
    v = wh.harvest(td)
    _ck("B harvest 基线 NOT_DUE(rc2)", v["rc"] == 2, str(v)[:200])

    samples = od.samples_dir(td)
    files = sorted(n for n in os.listdir(samples)
                   if re.match(od.NEW_SAMPLE_NAME_RE, n))
    # 篡改中间样本（identity 换值）→ 内容变化后 sample_sha256 不匹配 → rc1
    p2 = os.path.join(samples, files[1])
    doc = json.load(open(p2))
    doc["repo"]["identity"] = "f" * 40
    with open(p2, "w") as f:
        json.dump(doc, f)
    v = wh.harvest(td)
    _ck("B 篡改样本 → rc1", v["rc"] == 1 and v["status"] == "WINDOW_FAIL",
        str(v)[:200])
    _ck("B 篡改失败原因=sample_hash_mismatch",
        any(f["code"] == "sample_hash_mismatch" for f in v["failures"]),
        str(v.get("failures"))[:200])

    # 复原 p2 后重新生成干净链，再做缺口负测
    for n in os.listdir(samples):
        if re.match(od.NEW_SAMPLE_NAME_RE, n):
            os.remove(os.path.join(samples, n))
    for m in os.listdir(wm.manifest_dir(td)):
        os.remove(os.path.join(wm.manifest_dir(td), m))
    _open_valid(td, duration_hours=0.05)
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="c1")
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="c2")
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="c3")
    files = sorted(n for n in os.listdir(samples)
                   if re.match(od.NEW_SAMPLE_NAME_RE, n))
    os.remove(os.path.join(samples, files[1]))  # 删 seq2 → 缺口
    v = wh.harvest(td)
    _ck("B 缺 sequence → rc1",
        v["rc"] == 1 and any(f["code"] == "sequence_gap"
                             for f in v["failures"]), str(v)[:200])

    # 同序分叉（多 writer 并发写同 sequence 两份）→ rc1
    fork = json.load(open(os.path.join(samples, files[0])))
    fork["probe_note"] = "fork"
    fork_path = od.write_sample_exclusive(
        samples, fork, name="20260101T000000000000001-deadbeef.json")["path"]
    _ck("B 分叉样本可落盘（收割负责暴露）", fork_path is not None)
    v = wh.harvest(td)
    _ck("B 同序分叉 → rc1",
        v["rc"] == 1 and any(f["code"] == "forked_sequence"
                             for f in v["failures"]), str(v)[:200])
    os.remove(fork_path)

    # 预置 symlink 样本 → rc1（绝不跟随）
    os.symlink(bait := os.path.join(td, "b2"),
               os.path.join(samples, "20260101T000000000000002-cafebabe.json"))
    v = wh.harvest(td)
    _ck("B symlink 样本 → rc1",
        v["rc"] == 1 and any(f["code"] == "symlink_sample"
                             for f in v["failures"]), str(v)[:200])
    os.remove(os.path.join(samples, "20260101T000000000000002-cafebabe.json"))

    # 未篡改的干净窗口：清场重建完整链，手动封口后（end 已过）→ rc0
    for n in os.listdir(samples):
        if re.match(od.NEW_SAMPLE_NAME_RE, n):
            os.remove(os.path.join(samples, n))
    for m in os.listdir(wm.manifest_dir(td)):
        os.remove(os.path.join(wm.manifest_dir(td), m))
    _open_valid(td, duration_hours=0.05)
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="g1")
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="g2")
    man = wm.active_manifest(td)
    man["end_at"] = (datetime.now(timezone.utc)
                     - timedelta(hours=1)).isoformat()
    man["status"] = "sealed"
    wm._atomic_write_json(wm.manifest_path(td, man["window_id"]), man)
    v = wh.harvest(td)
    _ck("B 完整封口窗口 → rc0", v["rc"] == 0 and v["status"] == "PASS",
        str(v)[:300])


# ══════════════════════════════════════════════════════════════════════
# C. 动态窗口：无硬编码起点 + manifest 生命周期 + canary 锚点
# ══════════════════════════════════════════════════════════════════════

def test_no_hardcoded_window_start(td=None):
    src = open(os.path.join(TOOLS, "observation_daily.py"),
               encoding="utf-8").read()
    _ck("C 源码无硬编码 2026-10-10", "2026-10-10" not in src)
    _ck("C 源码无硬编码 datetime(2026", "datetime(2026" not in src)


def test_manifest_lifecycle(td):
    m = _open_valid(td, duration_hours=336.0, sfinal="d" * 40)
    _ck("C open_window 创建 manifest（十项前置封入 digests）",
        m["status"] == "open" and m["sfinal"] == "d" * 40
        and m["duration_hours"] == 336.0
        and len(m["digests"]) == len(wm.PREREQ_DIGEST_KEYS)
        and m["digests"]["ci_run_id"] == "37994854937")
    _ck("C t0 未定（动态起点待首样）", m["t0"] is None
        and m["start_at"] is None and m["end_at"] is None)
    _ck("C window_id/epoch_id 非空且不同",
        m["window_id"] and m["epoch_id"] and m["window_id"] != m["epoch_id"])
    # 重复 open 同 window_id → rc1 冲突
    try:
        wm.open_window(td, window_id=m["window_id"],
                       prerequisites=_prereqs(sfinal="d" * 40))
        dup = False
    except wm.WindowError:
        dup = True
    _ck("C 重复 open 同 window_id 拒绝", dup)
    # active 解析
    _ck("C active_manifest 命中", wm.active_manifest(td)["window_id"]
        == m["window_id"])
    # 首样 → t0/首样 hash/起止回填（合格样本才锚定 T0）
    r = _record(td, release_sha="d" * 40, scheduler_config_sha="c" * 64,
                tag="first", sfinal="d" * 40)
    _ck("C 首样合格（T0 可锚定）", r["doc"]["qualified"] is True,
        str(r["doc"].get("qualify_failures")))
    m2 = wm.load_manifest(td, m["window_id"])
    _ck("C 首样回填 t0/first_sample_sha256",
        m2["t0"] is not None and m2["first_sample_sha256"]
        == r["doc"]["sample_sha256"])
    end = datetime.fromisoformat(m2["end_at"])
    start = datetime.fromisoformat(m2["start_at"])
    _ck("C 起止=duration（end-start==336h）",
        abs((end - start).total_seconds() - 336 * 3600) < 2)
    # 封口 → sealed，重复 seal 幂等
    m3 = wm.seal_window(td, m["window_id"])
    _ck("C seal_window → sealed", m3["status"] == "sealed")
    m4 = wm.seal_window(td, m["window_id"])
    _ck("C seal 幂等", m4["status"] == "sealed"
        and m4["sealed_at"] == m3["sealed_at"])
    # sealed manifest 不可再改（首样回填拒绝）
    try:
        wm.note_first_sample(td, m4, sample_sha256="e" * 64, t0_iso=m4["t0"])
        mutated = True
    except wm.WindowError:
        mutated = False
    _ck("C sealed manifest 拒绝变更", not mutated)
    _ck("C sealed 后 active_manifest=None（窗口已收）",
        wm.active_manifest(td) is None)


def test_canary_dynamic_anchor(td=None):
    now = datetime.now(timezone.utc)
    _ck("C canary 无锚点 → NOT_DUE",
        od.build_canary(None, now_dt=now, anchor_iso=None, root=td)["status"]
        == "NOT_DUE")
    anchor = (now - timedelta(hours=1)).isoformat()
    c = od.build_canary(True, now_dt=now, anchor_iso=anchor, root=td)
    _ck("C canary 锚后 1h → IN_WINDOW", c["status"] == "IN_WINDOW"
        and c["equal_count"] == 1)
    old_anchor = (now - timedelta(hours=49)).isoformat()
    c2 = od.build_canary(False, now_dt=now, anchor_iso=old_anchor, root=td)
    _ck("C canary 锚后 49h（>48h 窗）→ CLOSED", c2["status"] == "CLOSED")


def test_harvest_four_states(td):
    rel, scs = "b" * 40, "c" * 64
    _open_valid(td, duration_hours=0.05)  # 3min 窗 → 1 桶（rc0 可达）
    # rc2：窗口进行中
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="n1")
    _record(td, release_sha=rel, scheduler_config_sha=scs, tag="n2")
    v = wh.harvest(td)
    _ck("C 四态·进行中窗口 rc2", v["rc"] == 2 and v["status"] == "NOT_DUE",
        str(v)[:200])
    # rc0：封口后完整通过（含分桶覆盖达标）
    man = wm.active_manifest(td)
    man["end_at"] = (datetime.now(timezone.utc)
                     - timedelta(minutes=1)).isoformat()
    man["status"] = "sealed"
    wm._atomic_write_json(wm.manifest_path(td, man["window_id"]), man)
    v = wh.harvest(td)
    _ck("C 四态·完整窗口 rc0", v["rc"] == 0, str(v)[:300])
    _ck("C 收割重算样本计数=2（不信累计）",
        v["counts"]["qualified_samples"] == 2, str(v.get("counts")))
    _ck("C 窗口级 qualification 聚合（全窗合格率 1.0）",
        v.get("qualification", {}).get("qualified_ratio") == 1.0,
        str(v.get("qualification")))
    # rc1：窗口内失败（不合格样本：identity 缺失）
    _open_valid(td, duration_hours=24.0)
    r = _record(td, identity=None, tag="bad")
    _ck("C identity 缺失样本 qualified=false",
        r["doc"]["qualified"] is False
        and "repo_identity_missing" in r["doc"]["qualify_failures"])
    v = wh.harvest(td)
    _ck("C 四态·窗口内失败 rc1",
        v["rc"] == 1 and any(f["code"] == "unqualified_sample"
                             for f in v["failures"]), str(v)[:250])
    # rc3：证据环境错误（无 manifest / 根不可读 / manifest 损坏）
    empty = os.path.join(td, "empty-root")
    os.makedirs(empty)
    v = wh.harvest(empty)
    _ck("C 四态·无 manifest rc3", v["rc"] == 3
        and v["status"] == "ENV_ERROR", str(v)[:200])
    bad = os.path.join(td, "bad-root")
    os.makedirs(os.path.join(bad, "windows"))
    os.makedirs(os.path.join(bad, "samples"))
    with open(os.path.join(bad, "windows", "x.json"), "w") as f:
        f.write("{not json")
    v = wh.harvest(bad)
    _ck("C 四态·manifest 损坏 rc3", v["rc"] == 3)


# ══════════════════════════════════════════════════════════════════════
# D. rotation 新命名识别 + 当前窗口保护 + 唯一 writer
# ══════════════════════════════════════════════════════════════════════

def test_rotation_new_names_and_window_protection(td):
    samples = od.samples_dir(td)
    os.makedirs(samples)
    now = time.time()
    old_ns = int((now - 40 * 86400) * 1e9)   # 40 天前（> KEEP_DAYS=30）
    # 旧命名超期样本（应删）
    legacy_old = os.path.join(samples, "2026-08-20.json")
    open(legacy_old, "w").write("{}")
    # 新命名超期样本（应删——必须被识别，而不是永久滞留）
    new_old = od.gen_sample_name(now_ns=old_ns)
    open(os.path.join(samples, new_old), "w").write("{}")
    # 当前窗口样本：命名日期被伪造得很旧 + mtime 很旧，但属于 active epoch
    m = _open_valid(td)
    r = _record(td, release_sha="b" * 40, scheduler_config_sha="c" * 64,
                tag="cur")
    cur_path = r["path"]
    os.utime(cur_path, (now - 40 * 86400, now - 40 * 86400))
    # 非当前窗口、新命名、近期 mtime 但名字超期 → 名字正源删除
    stranger = od.gen_sample_name(now_ns=old_ns)
    open(os.path.join(samples, stranger), "w").write('{"epoch": "other"}')

    removed = od.rotate(samples, protect_epoch=m["epoch_id"])

    _ck("D rotation 删除旧命名超期", "2026-08-20.json" in removed)
    _ck("D rotation 识别并删除新命名超期", new_old in removed)
    _ck("D rotation 不删当前窗口证据（epoch 保护）",
        os.path.exists(cur_path) and cur_path not in removed)
    _ck("D 无关新命名超期样本照删", stranger in removed)
    _ck("D 当前窗口样本仍在盘", os.path.exists(cur_path))


def test_unique_writer_launchd_audit(td):
    lad = os.path.join(td, "LaunchAgents")
    os.makedirs(lad)
    rogue = {
        "Label": "com.wenqu.observation",
        "ProgramArguments": ["/usr/bin/python3",
                             "/Users/x/wenqu-dist/tools/observation_daily.py"],
    }
    with open(os.path.join(lad, "com.wenqu.observation.plist"), "wb") as f:
        import plistlib
        plistlib.dump(rogue, f)
    legacy = {
        "Label": "com.wenqu.observation-window",
        "ProgramArguments": ["python3", "-c",
                             "open('~/Documents/观察窗日志.jsonl','a')"],
    }
    with open(os.path.join(lad, "com.wenqu.observation-window.plist"),
              "wb") as f:
        import plistlib
        plistlib.dump(legacy, f)
    ok = {
        "Label": "com.wenqu.scheduler",
        "ProgramArguments": ["/usr/bin/python3", "-m",
                             "wenqu_core.scheduler", "tick"],
    }
    with open(os.path.join(lad, "com.wenqu.scheduler.plist"), "wb") as f:
        import plistlib
        plistlib.dump(ok, f)

    findings = sched.audit_launchd_observation_writers(lad)
    labels = {f["label"] for f in findings}
    _ck("D launchd 审计发现旧 observation 独立作业",
        "com.wenqu.observation" in labels, str(labels))
    _ck("D launchd 审计发现旧 observation-window 作业",
        "com.wenqu.observation-window" in labels, str(labels))
    _ck("D launchd 审计不误报唯一合法入口",
        "com.wenqu.scheduler" not in labels and len(findings) == 2)

    # 干净目录 → 零发现
    clean = os.path.join(td, "LaunchAgents-clean")
    os.makedirs(clean)
    with open(os.path.join(clean, "com.wenqu.scheduler.plist"), "wb") as f:
        import plistlib
        plistlib.dump(ok, f)
    _ck("D 干净 launchd 目录零发现",
        sched.audit_launchd_observation_writers(clean) == [])

    # 仓内受版本管理模板：不得定义禁止 label；唯一观察入口=scheduler
    tmpl_dir = os.path.join(ROOT, "system", "launchd")
    _ck("D 仓内存在受版本管理 launchd 模板目录", os.path.isdir(tmpl_dir))
    import plistlib as pl
    managed_labels = []
    for n in os.listdir(tmpl_dir):
        if not n.endswith((".plist", ".plist.template")):
            continue
        with open(os.path.join(tmpl_dir, n), "rb") as f:
            doc = pl.load(f)
        managed_labels.append(doc.get("Label", ""))
    _ck("D 模板唯一观察入口=com.wenqu.scheduler",
        managed_labels == ["com.wenqu.scheduler"], str(managed_labels))
    _ck("D 模板无禁止 label",
        not (set(managed_labels)
             & set(sched.FORBIDDEN_OBSERVATION_LABELS)))

    # harvest --audit-writers 模式：rogue 在场 rc1，干净 rc0
    r = subprocess.run(
        [sys.executable, os.path.join(TOOLS, "window_harvest.py"),
         "--root", td, "--audit-writers", "--launchagents", lad],
        capture_output=True, text=True, timeout=30)
    _ck("D harvest --audit-writers 有 rogue → rc1", r.returncode == 1,
        r.stdout[:200] + r.stderr[:200])
    r2 = subprocess.run(
        [sys.executable, os.path.join(TOOLS, "window_harvest.py"),
         "--root", td, "--audit-writers", "--launchagents", clean],
        capture_output=True, text=True, timeout=30)
    _ck("D harvest --audit-writers 干净 → rc0", r2.returncode == 0,
        r2.stdout[:200] + r2.stderr[:200])


def test_scheduler_registry_single_observation_writer(td):
    from wenqu_core.scheduler import JobDefinition, ScheduleSpec, SchedulerStore
    store = SchedulerStore(os.path.join(td, "sched.db"))
    reg = sched.ScheduleRegistry(store)
    paths = sched.ProductionPaths(repo_root=ROOT,
                                  wenqu_home=os.path.join(td, "wh"))
    reg.register(sched.JobDefinition(
        job_id="w4.observation-sample", owner="t",
        argv=("/usr/bin/true", paths.observation_daily),
        schedule=ScheduleSpec.every(300), environment="production",
        probe_id="p", station_id=0))
    writers = sched.find_observation_writers(store)
    _ck("D 注册表审计：唯一观察 writer=w4.observation-sample",
        writers == ["w4.observation-sample"], str(writers))
    reg.register(sched.JobDefinition(
        job_id="rogue.second-sampler", owner="t",
        argv=("/usr/bin/true", paths.observation_daily),
        schedule=ScheduleSpec.every(60), environment="production",
        probe_id="p2", station_id=3))
    writers2 = sched.find_observation_writers(store)
    _ck("D 注册表审计：第二 writer 可见",
        set(writers2) == {"w4.observation-sample", "rogue.second-sampler"},
        str(writers2))
    store.close()


# ══════════════════════════════════════════════════════════════════════
# E. identity fail-visible（WENQU_GIT_REPO 无效 → 显式错误样本，rc1）
# ══════════════════════════════════════════════════════════════════════

def test_invalid_git_repo_fail_visible(td):
    # 1) 进程级：无效 WENQU_GIT_REPO → rc1 + 显式不合格样本（不静默回退）
    env = dict(os.environ)
    env.update({
        "HOME": td,
        "WENQU_OBSERVATION_ROOT": os.path.join(td, "obs"),
        "WENQU_GIT_REPO": os.path.join(td, "no-such-repo"),
        "WENQU_OBS_PROBE_MODE": "light",
        "WENQU_RELEASE_SHA": "b" * 40,
        "WENQU_SCHEDULER_CONFIG": os.path.join(td, "sched.plist"),
        # T2：auto-open 十项前置（缺则 fail-visible rc3，绝不起 sfinal=null 窗）
        "WENQU_WINDOW_PREREQS_JSON": json.dumps(_prereqs(sfinal="b" * 40)),
    })
    with open(env["WENQU_SCHEDULER_CONFIG"], "w") as f:
        f.write("<plist>template</plist>\n")
    p = subprocess.run(
        [sys.executable, os.path.join(TOOLS, "observation_daily.py")],
        capture_output=True, text=True, env=env, timeout=120)
    _ck("E 无效仓 → 进程 rc1（fail-visible）", p.returncode == 1,
        f"rc={p.returncode} out={p.stdout[:200]} err={p.stderr[:200]}")
    samples = od.samples_dir(env["WENQU_OBSERVATION_ROOT"])
    files = [n for n in os.listdir(samples) if n.endswith(".json")]
    _ck("E 显式错误样本已落盘", len(files) == 1, str(files))
    doc = json.load(open(os.path.join(samples, files[0])))
    _ck("E 样本 qualified=false", doc.get("qualified") is False,
        str(doc.get("qualify_failures")))
    _ck("E identity_error 显式非空",
        bool(doc.get("repo", {}).get("identity_error")))
    _ck("E 拒绝静默回退（fallback_refused）",
        doc.get("repo", {}).get("fallback_refused") is True)
    _ck("E identity 为 null", doc.get("repo", {}).get("identity") is None)

    # 收割暴露：该窗口 rc1（不合格样本不进合格分母）
    v = wh.harvest(env["WENQU_OBSERVATION_ROOT"])
    _ck("E 含 identity 缺失样本的窗口 harvest rc1", v["rc"] == 1,
        str(v)[:200])

    # 2) probe_repo 单元面：非 git 目录同样拒绝回退
    notgit = os.path.join(td, "not-a-repo")
    os.makedirs(notgit)
    monkey_env = {"WENQU_GIT_REPO": notgit}
    old = os.environ.get("WENQU_GIT_REPO")
    os.environ["WENQU_GIT_REPO"] = notgit
    try:
        info = od.probe_repo()
    finally:
        if old is None:
            del os.environ["WENQU_GIT_REPO"]
        else:
            os.environ["WENQU_GIT_REPO"] = old
    _ck("E 非 git 目录 → identity null + 拒绝回退",
        info["identity"] is None and info.get("fallback_refused") is True,
        str(info)[:200])


def test_valid_local_origin_qualified(td):
    # 真实本地 git 对（bare origin + clone）：origin/main 可得 → 合格
    git = "/usr/bin/git"
    src = os.path.join(td, "src")
    os.makedirs(src)
    subprocess.run([git, "init", "-q", "-b", "main", src], check=True)
    with open(os.path.join(src, "f.txt"), "w") as f:
        f.write("x")
    subprocess.run([git, "-C", src, "add", "."], check=True)
    subprocess.run([git, "-C", src, "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-q", "-m", "init"],
                   check=True)
    bare = os.path.join(td, "origin.git")
    subprocess.run([git, "clone", "-q", "--bare", src, bare], check=True)
    clone = os.path.join(td, "clone")
    subprocess.run([git, "clone", "-q", bare, clone], check=True)
    old = os.environ.get("WENQU_GIT_REPO")
    os.environ["WENQU_GIT_REPO"] = clone
    try:
        info = od.probe_repo()
    finally:
        if old is None:
            del os.environ["WENQU_GIT_REPO"]
        else:
            os.environ["WENQU_GIT_REPO"] = old
    _ck("E 有效受控 clone → identity 40hex",
        isinstance(info["identity"], str)
        and re.match(r"^[0-9a-f]{40}$", info["identity"]), str(info)[:200])
    _ck("E 有效仓不触发 fallback_refused",
        info.get("fallback_refused") is not True)
    q = od.qualify_identity(info)
    _ck("E qualify_identity=True", q[0] is True and q[1] == [],
        str(q))


# ══════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════
# F. T2 收紧（R9-OBS-T0-QUALIFICATION-002 / 九轮 §1 硬阻断 2 / §9 P0-2）
#    先红后绿三负例：空 sfinal 开窗 / 坏 health 样本 qualified / 2 样本收割 rc0
# ══════════════════════════════════════════════════════════════════════

def test_open_gate_ten_prerequisites(td):
    """F1 开窗门槛：十项前置缺任一/零值/self_declared/BLOCKED → 拒开（rc3），
    绝不 sfinal=null 起钟（红负例1：空前置开窗曾成功）。"""
    # 负例1：什么都不带（现场同款路径）→ 必须 WindowPrereqError
    try:
        wm.open_window(td)
        opened = False
    except wm.WindowPrereqError:
        opened = True
    _ck("F1 空前置 open_window 拒开（WindowPrereqError）", opened)
    mdir = wm.manifest_dir(td)
    _ck("F1 拒开后无 manifest 落盘",
        not os.path.exists(mdir) or not os.listdir(mdir))

    # API 面：单项缺失/零值/失配逐一拒开
    for name, over in [
        ("缺 release/sfinal", {"sfinal": None}),
        ("零占位 sfinal", {"sfinal": "0" * 40, "health_target_sha": "0" * 40}),
        ("缺 roots", {"roots": None}),
        ("缺 branch", {"branch": None}),
        ("缺 exact CI run id", {"ci_run_id": None}),
        ("health target != sfinal", {"health_target_sha": "c" * 40}),
        ("health scope=self_declared", {"health_scope": "self_declared"}),
        ("capacity=BLOCKED", {"capacity_gate": "BLOCKED"}),
        ("capacity=CRITICAL", {"capacity_gate": "CRITICAL"}),
        ("observer 零占位", {"observer": "0" * 64}),
    ]:
        p = _prereqs(**over)
        p = {k: v for k, v in p.items() if v is not None}
        try:
            wm.open_window(td, prerequisites=p)
            refused = False
        except wm.WindowPrereqError:
            refused = True
        _ck(f"F1 拒开·{name}", refused)

    # 齐备十项 → 开窗成功且 digests 块全量封入
    m = _open_valid(td)
    _ck("F1 十项齐备开窗成功",
        m["status"] == "open" and m["sfinal"] == "b" * 40)
    _ck("F1 十项要素写入 digests 块",
        all(m["digests"].get(k) for k in wm.PREREQ_DIGEST_KEYS)
        and m["digests"]["sfinal"] == m["sfinal"]
        and m["digests"]["health_target_sha"] == m["sfinal"]
        and m["digests"]["capacity_gate"] == "OPEN")

    # CLI 面：缺参 rc3 拒开 + 缺项清单；全参 rc0
    cli = os.path.join(TOOLS, "window_manifest.py")
    r = subprocess.run([sys.executable, cli, "open", "--root", str(td),
                        "--window-id", "w-cli-noprereq"],
                       capture_output=True, text=True, timeout=30)
    _ck("F1 CLI 空参 open → rc3", r.returncode == 3, r.stdout[:200])
    out = json.loads(r.stdout or "{}")
    _ck("F1 CLI 拒开带缺项清单",
        out.get("refused") == "open" and out.get("failures"), r.stdout[:200])
    r = subprocess.run([sys.executable, cli, "open", "--root", str(td),
                        "--release", "b" * 40],
                       capture_output=True, text=True, timeout=30)
    _ck("F1 CLI 仅 --release → rc3（其余九项缺）", r.returncode == 3)
    pr = _prereqs()
    full = [sys.executable, cli, "open", "--root", str(td),
            "--window-id", "w-cli-full", "--release", pr["sfinal"],
            "--tree", pr["tree"], "--roots", pr["roots"],
            "--registry", pr["registry"], "--branch", pr["branch"],
            "--evidence-schema", pr["evidence_schema"],
            "--observer", pr["observer"], "--ci-run-id", pr["ci_run_id"],
            "--health-target-sha", pr["health_target_sha"],
            "--health-scope", pr["health_scope"],
            "--capacity-gate", pr["capacity_gate"]]
    r = subprocess.run(full, capture_output=True, text=True, timeout=30)
    _ck("F1 CLI 十项齐备 → rc0", r.returncode == 0,
        r.stdout[:200] + r.stderr[:200])
    _ck("F1 CLI 开窗 digests 封印计数=11",
        json.loads(r.stdout or "{}").get("digests_sealed")
        == len(wm.PREREQ_DIGEST_KEYS), r.stdout[:200])

    # auto-open（采样器路径）无前置环境 → fail-visible（rc3 语义）
    empty = os.path.join(td, "empty-obs")
    os.makedirs(empty)
    rec = od.record_sample(empty, {
        "repo": {"identity": "a" * 40, "identity_error": None},
        "disk": {"used_pct": 1.0}})
    _ck("F1 无前置环境 auto-open 拒绝（采样 fail-visible rc3）",
        rec["rc"] == 3 and rec["qualify_failures"]
        == ["window_manifest_error"], str(rec)[:250])
    _ck("F1 拒绝后未落任何样本/manifest（仅锁工件）",
        not [n for n in os.listdir(od.samples_dir(empty))
             if n.endswith(".json")]
        and not [n for n in os.listdir(wm.manifest_dir(empty))
                 if n.endswith(".json")])

    # 旧形态无效窗（照搬现场 w-20261009T231625506512000：sfinal=null、
    # digests={} 却已起钟）→ 收割必须 rc3（绝不 PASS）
    os.makedirs(os.path.join(td, "legacy-bad", "windows"), exist_ok=True)
    os.makedirs(os.path.join(td, "legacy-bad", "samples"), exist_ok=True)
    bad_man = {
        "schema": wm.SCHEMA, "window_id": "w-legacybad",
        "epoch_id": "e-legacybad", "kind": "w10-observation",
        "status": "sealed", "created_at": "2026-10-09T23:14:54+00:00",
        "duration_hours": 336.0, "sfinal": None, "digests": {},
        "t0": "2026-10-09T23:14:54+00:00", "first_sample_sha256": "f" * 64,
        "start_at": "2026-10-09T23:14:54+00:00", "sealed_at": None,
        "end_at": "2026-10-09T23:15:54+00:00", "canary_hours": 48.0,
        "history": [],
    }
    wm._atomic_write_json(
        os.path.join(td, "legacy-bad", "windows", "w-legacybad.json"), bad_man)
    v = wh.harvest(os.path.join(td, "legacy-bad"))
    _ck("F1 旧形态无效窗（sfinal=null/digests={}）收割 rc3",
        v["rc"] == 3 and v["status"] == "ENV_ERROR"
        and v.get("prerequisite_failures"), str(v)[:250])


def test_bad_health_sample_unqualified(td):
    """F2 资格 fail-closed：health 零SHA/self_declared/BLOCKED/SHA 不咬合
    → qualified=false + unqualified_reasons（红负例2：曾 qualified=true）。
    窗口级 qualification 聚合（全窗合格率+理由直方图）。"""
    _open_valid(td)
    # 红负例2 现场：health 零 SHA + self_declared + capacity BLOCKED
    r = _record(td, tag="bad-health", health_target="0" * 40,
                health_scope="self_declared", capacity="BLOCKED")
    _ck("F2 坏 health 样本 qualified=false（曾 true）",
        r["doc"]["qualified"] is False, str(r["doc"].get("qualify_failures")))
    qf = set(r["doc"]["qualify_failures"])
    _ck("F2 unqualified_reasons 显式（零SHA/self_declared/BLOCKED）",
        {"health_target_sha_invalid", "health_scope_self_declared",
         "capacity_blocked"} <= qf, str(sorted(qf)))
    # 单项坏：target 与 sfinal 不咬合 / release 不咬合 / observer 不咬合
    r2 = _record(td, tag="h-mismatch", health_target="c" * 40)
    _ck("F2 health target != sfinal → 不合格",
        r2["doc"]["qualified"] is False
        and "health_target_sha_mismatch" in r2["doc"]["qualify_failures"])
    r3 = _record(td, tag="rel-mismatch", release_sha="e" * 40)
    _ck("F2 release_sha != 窗口 sfinal → 不合格",
        r3["doc"]["qualified"] is False
        and "release_sha_window_mismatch" in r3["doc"]["qualify_failures"])

    # 收割：窗1 全部不合格 → rc1 + 逐样本 unqualified_reasons + 窗口聚合
    v = wh.harvest(td)
    _ck("F2 收割 rc1（fail-closed，曾 NOT_DUE 放行）",
        v["rc"] == 1 and v["status"] == "WINDOW_FAIL", str(v)[:200])
    _ck("F2 逐样本 unqualified_reasons 落判词",
        all(isinstance(f.get("unqualified_reasons"), list)
            and f["unqualified_reasons"]
            for f in v["failures"]
            if f.get("code") == "unqualified_sample"),
        str(v["failures"])[:250])
    agg = v.get("qualification", {})
    _ck("F2 窗口级聚合：全窗合格率=0 + 理由直方图",
        agg.get("qualified_ratio") == 0.0
        and agg.get("unqualified_samples") == 3
        and agg.get("unqualified_reasons", {}).get("capacity_blocked") == 1,
        str(agg))

    # 窗2（封口窗1 后开，防多活跃歧义）：observer 与脚本不咬合 → 不合格
    wm.seal_window(td, v["window_id"])
    _open_valid(td, observer="9" * 64)
    r4 = _record(td, tag="obs-mismatch")
    _ck("F2 observer_sha != 窗口 digests.observer → 不合格",
        r4["doc"]["qualified"] is False
        and "observer_sha_window_mismatch" in r4["doc"]["qualify_failures"])
    v3 = wh.harvest(td)
    _ck("F2 observer 失配窗收割 rc1 + 直方图",
        v3["rc"] == 1 and v3["qualification"]["unqualified_reasons"]
        .get("observer_sha_window_mismatch") == 1,
        str(v3.get("qualification")))

    # 窗3（混合）：1 坏 + 1 好 → 合格率 0.5，好样本仍计数
    wm.seal_window(td, v3["window_id"])
    _open_valid(td)
    _record(td, tag="bad2", health_target="0" * 40)
    _record(td, tag="good2")
    v2 = wh.harvest(td)
    _ck("F2 混合窗合格率聚合=0.5（1/2）",
        v2["rc"] == 1
        and v2["qualification"]["qualified_ratio"] == 0.5
        and v2["qualification"]["qualified_samples"] == 1,
        str(v2.get("qualification")))


def test_thin_window_harvest_window_fail(td):
    """F3 收割严判：5min/bin 预期分桶 × 最低覆盖阈值不足 → rc1 WINDOW_FAIL
    （红负例3：曾 2 样本 rc0/PASS）；legacy 不计分母但显式计数。"""
    rel, scs = "b" * 40, "c" * 64
    man = _open_valid(td, duration_hours=24.0)  # 24h → 288 桶 × 90% = 259.2
    for t in ("s1", "s2"):
        rr = _record(td, release_sha=rel, scheduler_config_sha=scs, tag=t)
        assert rr["rc"] == 0, rr
    # legacy 样本：不计分母（现状对），但须显式计数
    sdir = od.samples_dir(td)
    for i in range(3):
        with open(os.path.join(sdir, f"2026-10-0{i + 1}.json"), "w") as f:
            f.write('{"legacy": true}')
    _seal_expired(td, man)
    v = wh.harvest(td)
    _ck("F3 2样本/24h 到期收割 rc1 WINDOW_FAIL（曾 rc0 PASS）",
        v["rc"] == 1 and v["status"] == "WINDOW_FAIL", str(v)[:200])
    cov_fail = next((f for f in v["failures"]
                     if f.get("code") == "coverage_below_threshold"), None)
    _ck("F3 失败码=coverage_below_threshold 且分桶数在判词",
        cov_fail is not None and cov_fail["expected_bins"] == 288
        and cov_fail["covered_bins"] <= 2 and cov_fail["threshold"] == 0.9,
        str(cov_fail))
    _ck("F3 verdict.coverage 覆盖明细",
        v.get("coverage", {}).get("expected_bins") == 288
        and v["coverage"]["bin_minutes"] == 5, str(v.get("coverage")))
    _ck("F3 legacy 不计分母但显式计数（legacy_ignored=3）",
        v["counts"]["legacy_ignored"] == 3
        and v["counts"]["epoch_samples"] == 2, str(v.get("counts")))
    _ck("F3 覆盖失败判词携带 legacy_ignored",
        cov_fail is not None and cov_fail.get("legacy_ignored") == 3)
    # 阈值显式可调（0 → 同证据 rc0：证明门是覆盖驱动而非硬编码）
    v0 = wh.harvest(td, min_coverage=0.0)
    _ck("F3 min_coverage=0 → 同证据 rc0（阈值驱动）",
        v0["rc"] == 0 and v0["status"] == "PASS", str(v0)[:200])
    # CLI 面同名开关
    cli = os.path.join(TOOLS, "window_harvest.py")
    r = subprocess.run([sys.executable, cli, "--root", str(td)],
                       capture_output=True, text=True, timeout=30)
    _ck("F3 CLI 默认阈值 rc1", r.returncode == 1, r.stdout[:150])
    r2 = subprocess.run([sys.executable, cli, "--root", str(td),
                         "--min-coverage", "0"],
                        capture_output=True, text=True, timeout=30)
    _ck("F3 CLI --min-coverage 0 → rc0", r2.returncode == 0,
        r2.stdout[:150])


def test_invalidate_auditable(td):
    """F4 invalidate 工单：可审计作废记录（不删文件），作废窗收割 rc3，
    active 释放后可按新窗重开（新 window_id 重新起算）。"""
    _open_valid(td, duration_hours=24.0)
    r = _record(td, tag="witness", scheduler_config_sha="c" * 64)
    assert r["rc"] == 0
    wid = r["manifest"]["window_id"]
    mpath = wm.manifest_path(td, wid)
    orig_sha = _sha(mpath)

    # 空 reason/principal 拒绝（CLI rc1）
    cli = os.path.join(TOOLS, "window_manifest.py")
    r_bad = subprocess.run([sys.executable, cli, "invalidate", "--root",
                            str(td), "--window-id", wid, "--reason", " ",
                            "--principal", "ops"],
                           capture_output=True, text=True, timeout=30)
    _ck("F4 CLI 空 reason → rc1", r_bad.returncode == 1, r_bad.stdout[:150])

    # 正门作废（CLI）
    r_inv = subprocess.run([sys.executable, cli, "invalidate", "--root",
                            str(td), "--window-id", wid,
                            "--reason", "R9-OBS-T0-QUALIFICATION-002: "
                            "window opened before ten prerequisites",
                            "--principal", "t2-remediation"],
                           capture_output=True, text=True, timeout=30)
    _ck("F4 invalidate CLI rc0", r_inv.returncode == 0,
        r_inv.stdout[:200] + r_inv.stderr[:200])
    out = json.loads(r_inv.stdout or "{}")
    _ck("F4 判词含 invalidated_at/原因/作废人/原窗 hash",
        out.get("invalidated_at") and out.get("reason")
        and out.get("principal") == "t2-remediation"
        and re.match(r"^[0-9a-f]{64}$",
                     out.get("original_manifest_sha256", "")),
        r_inv.stdout[:250])

    # 审计记录落盘：原 manifest 全量留档 + 原文件 sha256 + 不删文件
    ipath = wm.invalidation_path(td, wid)
    _ck("F4 作废记录文件存在（不删 manifest 原文件）",
        os.path.exists(ipath) and os.path.exists(mpath))
    rec = json.load(open(ipath))
    _ck("F4 记录 schema/原窗全量/原窗 hash 咬合",
        rec["schema"] == wm.INVALIDATION_SCHEMA
        and rec["original_manifest"].get("status") == "open"
        and rec["original_manifest"].get("window_id") == wid
        and rec["original_manifest_sha256"] == orig_sha, str(rec)[:200])
    man = wm.load_manifest(td, wid)
    _ck("F4 manifest 状态=invalidated + history 追加（principal 在场）",
        man["status"] == "invalidated"
        and any(h.get("action") == "invalidate"
                and h.get("principal") == "t2-remediation"
                and h.get("original_manifest_sha256") == orig_sha
                for h in man["history"]), str(man.get("history"))[:200])

    # 作废窗：active 释放；收割 rc3（绝不 PASS）；load_manifests 不误报
    _ck("F4 作废后 active_manifest=None",
        wm.active_manifest(td) is None)
    v = wh.harvest(td, window_id=wid)
    _ck("F4 作废窗收割 rc3 ENV_ERROR", v["rc"] == 3
        and "invalidated" in str(v.get("error", "")), str(v)[:200])
    _ck("F4 list 不被作废记录污染",
        all(d["window_id"] == wid for d in wm.load_manifests(td)[0]))

    # 幂等：重复作废返回既有记录（同 invalidated_at）
    rec2 = wm.invalidate_window(td, wid, reason="again",
                                principal="someone-else")
    _ck("F4 重复 invalidate 幂等（返回原记录）",
        rec2["invalidated_at"] == rec["invalidated_at"]
        and rec2["principal"] == rec["principal"])

    # 作废后可按新窗重开（新 window_id / 新 epoch 重新起算）
    m2 = _open_valid(td, duration_hours=336.0)
    _ck("F4 作废释放后新窗可开（新 window_id）",
        m2["window_id"] != wid and m2["status"] == "open")
    r2 = _record(td, tag="fresh-start", scheduler_config_sha="c" * 64)
    _ck("F4 新窗样本合格 + T0 从新首样起算",
        r2["doc"]["qualified"] is True
        and r2["doc"]["window_id"] == m2["window_id"]
        and wm.load_manifest(td, m2["window_id"])["t0"] is not None)


def _run_all():
    import inspect
    mod = sys.modules[__name__]
    fns = [(n, f) for n, f in vars(mod).items()
           if n.startswith("test_") and inspect.isfunction(f)]
    for name, fn in fns:
        print(f"== {name} ==")
        import tempfile
        with tempfile.TemporaryDirectory(prefix="wq-g902-") as t:
            fn(t)
    print(f"\n{'='*50}\nPASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        print("失败项:", FAILURES)
    return 1 if FAIL_N else 0


if __name__ == "__main__":
    sys.exit(_run_all())

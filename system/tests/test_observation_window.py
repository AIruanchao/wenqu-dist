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
G. W11-05 首个合格样本的可恢复锚定（R10-OBS-FIRST-QUALIFIED-ANCHOR-002）
   - seq1 不合格、seq2 合格 → 锚定 seq2（first_qualified_sequence=2）；
     seq1 记入 pre_t0_attempts（保留审计、严格验链、不进分母、不使窗口失败）；
   - seq2 落盘后、锚定前崩溃（note_first_sample 失败模拟）→ 下一 tick/repair
     仍锚 seq2（t0=seq2.collected_at，不漂移到 seq3）；
   - 伪造 qualified=true（raw 面坏）不被采信；sampler/repair/harvest 共用
     单一资格判定；
   - 32 并发只产生一个最早锚；
   - 坏 JSON/断链/symlink → sampler rc3（绝不静默跳过、绝不扩链）；
   - repair：0 已锚/补锚/无需修改；1 暂无合格样本；3 坏链或冲突；
   - seq1 坏但锚后全好 → 到期 rc0 PASS；锚后再坏（seq3）→ rc1 FAIL；
     全窗无合格样本到期 → rc1 no_qualified_anchor（T0 死锁收口）。
H. W11-06 invalidate 单一提交点（R10-OBS-INVALIDATE-ATOMICITY-003）
   - <wid>.invalidated.json 为唯一作废提交点：manifest 原字节保持不动，
     reader 计算 effective status；发布=临时文件 O_EXCL|O_NOFOLLOW + fsync
     + 原子 no-overwrite publish + fsync 目录；
   - failpoint 两态收敛：open 且无 event；或 invalidated 且 event 完整；
   - 幂等：同 reason/principal rc0；冲突参数 rc1；预置/篡改/symlink/
     hardlink/event 损坏/hash 不符 → rc3；
   - legacy 兼容：event+已改 manifest、event+open manifest 均识别为
     invalidated，旧窗绝不 resume；撕裂态（manifest 已 invalidated 无
     event）→ rc3；
   - sample/invalidate 竞态由同一 .window.lock 串行。

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


def _craft_sample(sdir, epoch_id, window_id, seq, prev_sha, *,
                  collected_at=None, mutations=None, qualified=False,
                  reasons=None):
    """手工造一条链上样本（B 组分叉/G 组伪造已用）——hash 重算咬合。
    mutations 在 sample_sha256 计算前覆盖任意键（伪造 raw 面）。"""
    doc = {
        "schema": od.SAMPLE_SCHEMA, "window": "W10-observation",
        "window_id": window_id, "epoch_id": epoch_id,
        "collected_at": collected_at or datetime.now(timezone.utc).isoformat(),
        "probe_mode": "full", "host": "crafted",
        "repo": {"path": "/tmp/x", "identity": "a" * 40,
                 "identity_error": None, "worktree_head": "a" * 40,
                 "dirty": False},
        "disk": {"used_pct": 33.0},
        "legacy_health": {"status": 200, "json": {
            "target_sha": "b" * 40, "scope_binding": {"mode": "manifest"},
            "mode": "manifest_aggregation"}},
        "capacity_gate": {"capacity_gate": "OPEN", "severity": "OK"},
        "sequence": seq, "prev_sha256": prev_sha,
        "release_sha": "b" * 40, "observer_sha": od.observer_sha(),
        "scheduler_config_sha": "c" * 64,
        "qualified": qualified, "qualify_failures": reasons or [],
    }
    for k, val in (mutations or {}).items():
        doc[k] = val
    doc["sample_sha256"] = od.compute_sample_sha256(
        {k: v for k, v in doc.items() if k != "sample_sha256"})
    res = od.write_sample_exclusive(sdir, doc)
    assert res["path"], res["error"]
    return doc


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
    # W11-05：32 并发只产生一个最早锚（seq1，t0=seq1 时刻，history 单条）
    m = wm.load_manifest(td, wm.active_manifest(td)["window_id"])
    _ck("A 32 并发恰一个最早锚（锚=seq1）",
        m["first_qualified_sequence"] == 1
        and m["first_qualified_sample_sha256"] == by_seq[1]["sample_sha256"]
        and m["t0"] == by_seq[1]["collected_at"]
        and len([h for h in m["history"]
                 if h.get("action") == "first_sample"]) == 1,
        str((m.get("first_qualified_sequence"), m.get("t0"))))


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
    # rc1：窗口内失败（W11-05：锚后不合格样本才使窗口失败）
    _open_valid(td, duration_hours=24.0)
    r = _record(td, identity=None, tag="bad")
    _ck("C identity 缺失样本 qualified=false",
        r["doc"]["qualified"] is False
        and "repo_identity_missing" in r["doc"]["qualify_failures"])
    v = wh.harvest(td)
    _ck("C 未锚定窗坏样本=pre_t0_attempt（不使正式窗口失败，rc2 等待首合格）",
        v["rc"] == 2 and v["status"] == "NOT_DUE", str(v)[:250])
    _record(td, tag="good", scheduler_config_sha="c" * 64)   # 锚定 T0
    _record(td, identity=None, tag="bad2", scheduler_config_sha="c" * 64)
    v = wh.harvest(td)
    _ck("C 四态·锚后不合格样本 rc1",
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
    _ck("D 模板唯一观察入口=com.wenqu.scheduler（dashboard=W11-08 UI 面，非观察 writer）",
        set(managed_labels) == {"com.wenqu.scheduler", "com.wenqu.dashboard"}
        and "com.wenqu.scheduler" in managed_labels, str(managed_labels))
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

    # 收割暴露（W11-05：未锚定窗的坏样本=pre_t0_attempt，运行期 rc2 等待
    # 首合格样本；名义到期仍无合格锚 → rc1 no_qualified_anchor）
    obs = env["WENQU_OBSERVATION_ROOT"]
    man = wm.active_manifest(obs)
    v = wh.harvest(obs)
    _ck("E 运行期未锚定窗 rc2（坏样本不使窗口失败，等待首合格）",
        v["rc"] == 2 and v["status"] == "NOT_DUE", str(v)[:200])
    mpath = wm.manifest_path(obs, man["window_id"])
    doc = json.load(open(mpath))
    doc["created_at"] = (datetime.now(timezone.utc)
                         - timedelta(hours=400)).isoformat()
    with open(mpath, "w") as f:
        json.dump(doc, f)
    v = wh.harvest(obs)
    _ck("E 名义到期无合格锚 → rc1 no_qualified_anchor（T0 死锁收口）",
        v["rc"] == 1 and any(f.get("code") == "no_qualified_anchor"
                             for f in v["failures"]), str(v)[:250])

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
    窗口级 qualification 聚合（全窗合格率+理由直方图）。W11-05 后：先以合格
    样本锚定，坏样本均为锚后窗口样本（pre_t0_attempt 语义见 G 组）。"""
    _open_valid(td)
    # 先锚定（W11-05：T0=首条合格样本；锚前样本是 pre_t0_attempt）
    r0 = _record(td, tag="anchor-good")
    assert r0["doc"]["qualified"] is True, r0["doc"].get("qualify_failures")
    # 红负例2 现场：health 零 SHA + self_declared + capacity BLOCKED
    r = _record(td, tag="bad-health", health_target="0" * 40,
                health_scope="self_declared", capacity="BLOCKED")
    _ck("F2 坏 health 样本 qualified=false（曾 true）",
        r["doc"]["qualified"] is False, str(r["doc"].get("qualify_failures")))
    qf = set(r["doc"]["qualify_failures"])
    _ck("F2 unqualified_reasons 显式（零SHA/self_declared/BLOCKED）",
        {"health_target_sha_invalid", "health_scope_self_declared",
         "capacity_blocked"} <= qf, str(sorted(qf)))
    # 单项坏：target 与 sfinal 不咬合 / release 不咬合
    r2 = _record(td, tag="h-mismatch", health_target="c" * 40)
    _ck("F2 health target != sfinal → 不合格",
        r2["doc"]["qualified"] is False
        and "health_target_sha_mismatch" in r2["doc"]["qualify_failures"])
    r3 = _record(td, tag="rel-mismatch", release_sha="e" * 40)
    _ck("F2 release_sha != 窗口 sfinal → 不合格",
        r3["doc"]["qualified"] is False
        and "release_sha_window_mismatch" in r3["doc"]["qualify_failures"])

    # 收割：锚后 3 坏 1 好 → rc1 + 逐样本 unqualified_reasons + 窗口聚合
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
    _ck("F2 窗口级聚合：锚后窗 1好3坏（ratio=0.25）+ 理由直方图",
        agg.get("qualified_ratio") == 0.25
        and agg.get("unqualified_samples") == 3
        and agg.get("unqualified_reasons", {}).get("capacity_blocked") == 1,
        str(agg))

    # 窗2（封口窗1 后开，防多活跃歧义）：observer 与脚本不咬合 → 不合格
    # （手工造样锚定：record_sample 只会盖真实 observer_sha）
    wm.seal_window(td, v["window_id"])
    m2 = _open_valid(td, observer="9" * 64)
    sdir = od.samples_dir(td)
    good9 = _craft_sample(sdir, m2["epoch_id"], m2["window_id"], 1,
                          od.GENESIS_SHA,
                          mutations={"observer_sha": "9" * 64},
                          qualified=True, reasons=[])
    rep = wm.repair_anchor(td, m2["window_id"])
    assert rep["rc"] == 0 and rep["status"] in ("anchored", "already_anchored"), rep
    _craft_sample(sdir, m2["epoch_id"], m2["window_id"], 2,
                  good9["sample_sha256"],
                  mutations={"observer_sha": od.observer_sha()},
                  qualified=False,
                  reasons=["observer_sha_window_mismatch"])
    v3 = wh.harvest(td)
    _ck("F2 observer_sha != 窗口 digests.observer → 不合格（收割重判）",
        v3["rc"] == 1 and v3["qualification"]["unqualified_reasons"]
        .get("observer_sha_window_mismatch") == 1,
        str(v3.get("qualification")))

    # 窗3（混合）：锚好 + 1 坏 + 1 好 → 合格率 2/3，好样本仍计数
    wm.seal_window(td, v3["window_id"])
    _open_valid(td)
    _record(td, tag="mix-anchor")
    _record(td, tag="bad2", health_target="0" * 40)
    _record(td, tag="good2")
    v2 = wh.harvest(td)
    _ck("F2 混合窗合格率聚合=2/3",
        v2["rc"] == 1
        and abs(v2["qualification"]["qualified_ratio"] - 2 / 3) < 1e-6
        and v2["qualification"]["qualified_samples"] == 2,
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
    """F4/W11-06 invalidate 单一提交点（R10-OBS-INVALIDATE-ATOMICITY-003）：
    <wid>.invalidated.json 为唯一作废提交点——manifest 原字节保持不动，
    reader 计算 effective status；作废窗收割 rc3；active 释放后可按新窗重开。"""
    _open_valid(td, duration_hours=24.0)
    r = _record(td, tag="witness", scheduler_config_sha="c" * 64)
    assert r["rc"] == 0
    wid = r["manifest"]["window_id"]
    mpath = wm.manifest_path(td, wid)
    ipath = wm.invalidation_path(td, wid)
    orig_sha = _sha(mpath)

    # 空 reason/principal 拒绝（CLI rc1）
    cli = os.path.join(TOOLS, "window_manifest.py")
    r_bad = subprocess.run([sys.executable, cli, "invalidate", "--root",
                            str(td), "--window-id", wid, "--reason", " ",
                            "--principal", "ops"],
                           capture_output=True, text=True, timeout=30)
    _ck("F4 CLI 空 reason → rc1", r_bad.returncode == 1, r_bad.stdout[:150])

    # 正门作废（CLI）
    reason = ("R10-OBS-INVALIDATE-ATOMICITY-003: single commit point")
    r_inv = subprocess.run([sys.executable, cli, "invalidate", "--root",
                            str(td), "--window-id", wid,
                            "--reason", reason,
                            "--principal", "w11-remediation"],
                           capture_output=True, text=True, timeout=30)
    _ck("F4 invalidate CLI rc0", r_inv.returncode == 0,
        r_inv.stdout[:200] + r_inv.stderr[:200])
    out = json.loads(r_inv.stdout or "{}")
    _ck("F4 判词含 invalidated_at/原因/作废人/原窗 hash",
        out.get("invalidated_at") and out.get("reason")
        and out.get("principal") == "w11-remediation"
        and re.match(r"^[0-9a-f]{64}$",
                     out.get("original_manifest_sha256", "")),
        r_inv.stdout[:250])

    # W11-06 核心：manifest 原字节不动（唯一提交点=事件，不再双写权威文件）
    _ck("F4 manifest 原字节保持（sha 不变）", _sha(mpath) == orig_sha)
    man_disk = json.load(open(mpath))
    _ck("F4 manifest 本体 status 未翻转（effective 由 reader 计算）",
        man_disk["status"] == "open", str(man_disk.get("status")))
    rec = json.load(open(ipath))
    _ck("F4 记录 schema/绑定 window+epoch/原窗 hash 咬合",
        rec["schema"] == wm.INVALIDATION_SCHEMA
        and rec["window_id"] == wid
        and rec["epoch_id"] == man_disk["epoch_id"]
        and rec["original_manifest_sha256"] == orig_sha
        and rec["original_manifest"].get("window_id") == wid, str(rec)[:200])

    # effective status 统一消费：active 释放、收割 rc3、seal 拒绝、绝不 resume
    _ck("F4 作废后 active_manifest=None（event+open manifest 形态）",
        wm.active_manifest(td) is None)
    v = wh.harvest(td, window_id=wid)
    _ck("F4 作废窗收割 rc3 ENV_ERROR（fail-closed）", v["rc"] == 3
        and "invalidated" in str(v.get("error", "")), str(v)[:200])
    try:
        wm.seal_window(td, wid)
        sealed = True
    except wm.WindowError:
        sealed = False
    _ck("F4 作废窗拒绝 seal（永不复活）", not sealed)
    rec_ext = od.record_sample(td, _core(), release_sha="b" * 40,
                               scheduler_config_sha="c" * 64)
    _ck("F4 采样器不向作废窗续写（auto-open 无前置 → rc3，绝不 resume 旧窗）",
        rec_ext["rc"] == 3, str(rec_ext)[:200])
    _ck("F4 list 不被作废记录污染",
        all(d["window_id"] == wid for d in wm.load_manifests(td)[0]))

    # 幂等：同参数重复作废 rc0 返回既有记录；不同 reason/principal → rc1 冲突
    rec2 = wm.invalidate_window(td, wid, reason=reason,
                                principal="w11-remediation")
    _ck("F4 同参数重复 invalidate 幂等（返回原记录）",
        rec2["invalidated_at"] == rec["invalidated_at"]
        and rec2["principal"] == rec["principal"])
    try:
        wm.invalidate_window(td, wid, reason="different",
                             principal="other")
        conflicted = False
    except wm.WindowConflictError:
        conflicted = True
    except wm.WindowError:
        conflicted = False  # 其它错误类型不算冲突
    _ck("F4 冲突参数（不同 reason/principal）→ 拒绝", conflicted)
    r_conf = subprocess.run([sys.executable, cli, "invalidate", "--root",
                             str(td), "--window-id", wid, "--reason", "x2",
                             "--principal", "p2"],
                            capture_output=True, text=True, timeout=30)
    _ck("F4 CLI 冲突参数 → rc1", r_conf.returncode == 1, r_conf.stdout[:150])

    # 作废后可按新窗重开（新 window_id / 新 epoch 重新起算）
    m2 = _open_valid(td, duration_hours=336.0)
    _ck("F4 作废释放后新窗可开（新 window_id）",
        m2["window_id"] != wid and m2["status"] == "open")
    r2 = _record(td, tag="fresh-start", scheduler_config_sha="c" * 64)
    _ck("F4 新窗样本合格 + T0 从新首样起算",
        r2["doc"]["qualified"] is True
        and r2["doc"]["window_id"] == m2["window_id"]
        and wm.load_manifest(td, m2["window_id"])["t0"] is not None)


# ══════════════════════════════════════════════════════════════════════
# G. W11-05 首个合格样本的可恢复锚定（R10-OBS-FIRST-QUALIFIED-ANCHOR-002）
# ══════════════════════════════════════════════════════════════════════

def test_w11_05_anchor_selection_and_recovery(td):
    """G1 最早合格样本锚定+双路径崩溃恢复+伪造不采信+并发单一锚。"""
    man = _open_valid(td, duration_hours=336.0)
    wid = man["window_id"]

    # seq1 不合格 → 不锚定；seq2 合格 → 锚定 seq2（T0 死锁收口）
    r1 = _record(td, tag="bad1", health_target="0" * 40)
    _ck("G1 seq1 不合格落盘 rc1（合法但不合格）", r1["rc"] == 1)
    m = wm.load_manifest(td, wid)
    _ck("G1 seq1 不合格不锚定 T0（等下一合格样本）",
        m["t0"] is None and m.get("first_qualified_sequence") is None)
    r2 = _record(td, tag="good2")
    _ck("G1 seq2 合格 rc0", r2["rc"] == 0)
    m = wm.load_manifest(td, wid)
    _ck("G1 锚定最早合格样本=seq2（first_qualified_sequence=2）",
        m["t0"] is not None
        and m["first_qualified_sequence"] == 2
        and m["first_qualified_sample_sha256"] == r2["doc"]["sample_sha256"]
        and m["first_sample_sha256"] == r2["doc"]["sample_sha256"])
    _ck("G1 t0=seq2.collected_at（不漂移到后续样本）",
        m["t0"] == r2["doc"]["collected_at"])
    pre = m.get("pre_t0_attempts")
    _ck("G1 seq1 记入 pre_t0_attempts（审计保留+重判理由）",
        isinstance(pre, list) and len(pre) == 1
        and pre[0]["sequence"] == 1
        and pre[0]["sample_sha256"] == r1["doc"]["sample_sha256"]
        and pre[0]["unqualified_reasons"], str(pre)[:200])

    # 崩溃恢复·tick 路径：锚字段丢失（样本在、锚无）→ 下一 tick 补锚 seq2
    mpath = wm.manifest_path(td, wid)
    doc_m = json.load(open(mpath))
    for k in ("t0", "start_at", "end_at", "first_sample_sha256",
              "first_qualified_sequence", "first_qualified_sample_sha256",
              "pre_t0_attempts"):
        doc_m[k] = None
    with open(mpath, "w") as f:
        json.dump(doc_m, f)
    r3 = _record(td, tag="good3")
    m = wm.load_manifest(td, wid)
    _ck("G1 tick 恢复：补锚 seq2（t0=seq2 时刻，非 seq3）",
        m["first_qualified_sequence"] == 2
        and m["t0"] == r2["doc"]["collected_at"]
        and m["pre_t0_attempts"][0]["sequence"] == 1,
        str((m.get("first_qualified_sequence"), m.get("t0"))))

    # 崩溃恢复·anchor 提交失败 + repair 正门
    wm.seal_window(td, wid)
    man2 = _open_valid(td, duration_hours=336.0)
    wid2 = man2["window_id"]
    orig_nfs = wm.note_first_sample

    def _boom(*a, **k):
        raise wm.WindowError("simulated crash before anchor commit")

    wm.note_first_sample = _boom
    try:
        rw = _record(td, tag="crash-before-anchor")
    finally:
        wm.note_first_sample = orig_nfs
    _ck("G1 锚定提交崩溃：合格样本仍落盘 rc0", rw["rc"] == 0)
    m = wm.load_manifest(td, wid2)
    _ck("G1 崩溃后 manifest 无锚（等待恢复）",
        m.get("first_qualified_sequence") is None)
    cli = os.path.join(TOOLS, "window_manifest.py")
    r_rep = subprocess.run([sys.executable, cli, "repair", "--root", str(td),
                            "--window-id", wid2],
                           capture_output=True, text=True, timeout=30)
    _ck("G1 repair 补锚 rc0（锚到崩溃前合格样本）", r_rep.returncode == 0,
        r_rep.stdout[:200] + r_rep.stderr[:200])
    m = wm.load_manifest(td, wid2)
    _ck("G1 repair 锚=seq1（t0=崩溃样本时刻）",
        m["first_qualified_sequence"] == 1
        and m["t0"] == rw["doc"]["collected_at"])
    r_rep2 = subprocess.run([sys.executable, cli, "repair", "--root", str(td),
                             "--window-id", wid2],
                            capture_output=True, text=True, timeout=30)
    _ck("G1 repair 幂等（已锚 → rc0）", r_rep2.returncode == 0)
    r_after = _record(td, tag="after-repair")
    m = wm.load_manifest(td, wid2)
    _ck("G1 repair 后续采样不漂移锚（仍 seq1）",
        r_after["rc"] == 0 and m["first_qualified_sequence"] == 1
        and m["t0"] == rw["doc"]["collected_at"])

    # repair rc1：暂无合格样本；repair rc3：坏链
    wm.seal_window(td, wid2)
    man3 = _open_valid(td, duration_hours=336.0)
    wid3 = man3["window_id"]
    rbad = _record(td, tag="no-qualified", health_target="0" * 40)
    _ck("G1 坏样本窗 repair 前置（rc1 落盘）", rbad["rc"] == 1)
    r_rep3 = subprocess.run([sys.executable, cli, "repair", "--root", str(td),
                             "--window-id", wid3],
                            capture_output=True, text=True, timeout=30)
    _ck("G1 repair 暂无合格样本 → rc1", r_rep3.returncode == 1,
        r_rep3.stdout[:150])
    p_bad = rbad["path"]
    d_bad = json.load(open(p_bad))
    d_bad["probe_note"] = "tampered"
    with open(p_bad, "w") as f:
        json.dump(d_bad, f)
    r_rep4 = subprocess.run([sys.executable, cli, "repair", "--root", str(td),
                             "--window-id", wid3],
                            capture_output=True, text=True, timeout=30)
    _ck("G1 repair 坏链（篡改样本）→ rc3", r_rep4.returncode == 3,
        r_rep4.stdout[:200])

    # 伪造 qualified=true（raw 面坏）不被采信：锚越过伪造样本
    wm.seal_window(td, wid3)
    man4 = _open_valid(td, duration_hours=336.0)
    forged = _craft_sample(
        od.samples_dir(td), man4["epoch_id"], man4["window_id"], 1,
        od.GENESIS_SHA,
        mutations={"legacy_health": {"status": 200, "json": {
            "target_sha": "0" * 40, "scope_binding": {"mode": "manifest"},
            "mode": "manifest_aggregation"}}},
        qualified=True, reasons=[])
    r_g = _record(td, tag="real-good")
    m = wm.load_manifest(td, man4["window_id"])
    _ck("G1 伪造 qualified=true 不被采信（锚=seq2 真合格样本）",
        m["first_qualified_sequence"] == 2
        and m["first_qualified_sample_sha256"] == r_g["doc"]["sample_sha256"],
        str((m.get("first_qualified_sequence"),
             m.get("first_qualified_sample_sha256"))))
    _ck("G1 伪造样本在 pre_t0_attempts 中被重判不合格（含理由）",
        m["pre_t0_attempts"][0]["sequence"] == 1
        and m["pre_t0_attempts"][0]["qualified"] is False
        and m["pre_t0_attempts"][0]["unqualified_reasons"],
        str(m["pre_t0_attempts"])[:250])

    # 8 并发（好坏混合）→ 恰一个最早锚
    wm.seal_window(td, man4["window_id"])
    man5 = _open_valid(td, duration_hours=336.0)
    wid5 = man5["window_id"]
    results, errors = [], []
    barrier = threading.Barrier(8)

    def writer(i):
        try:
            barrier.wait()
            if i % 2 == 0:
                results.append(_record(td, tag=f"w11-{i}",
                                       health_target="0" * 40))
            else:
                results.append(_record(td, tag=f"w11-{i}"))
        except Exception as e:  # noqa: BLE001
            errors.append(f"w{i}:{type(e).__name__}:{e}")

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    _ck("G1 8 并发零异常", not errors, str(errors[:3]))
    sdir = od.samples_dir(td)
    seq_map = {}
    for n in os.listdir(sdir):
        if not re.match(od.NEW_SAMPLE_NAME_RE, n):
            continue
        d = json.load(open(os.path.join(sdir, n)))
        if d.get("epoch_id") == man5["epoch_id"]:
            seq_map[d["sequence"]] = d
    good_seqs = sorted(s for s, d in seq_map.items() if d["qualified"] is True)
    m = wm.load_manifest(td, wid5)
    earliest = min(good_seqs)
    _ck("G1 并发锚=最早合格 sequence（%d）" % earliest,
        m["first_qualified_sequence"] == earliest
        and m["first_qualified_sample_sha256"]
        == seq_map[earliest]["sample_sha256"]
        and m["t0"] == seq_map[earliest]["collected_at"])
    _ck("G1 并发恰一次锚提交（history 单条 first_sample）",
        len([h for h in m["history"] if h.get("action") == "first_sample"]) == 1)
    _ck("G1 并发 pre_t0_attempts 全部严格早于锚且重判不合格",
        all(a["sequence"] < earliest and a["qualified"] is False
            for a in m["pre_t0_attempts"])
        and len(m["pre_t0_attempts"]) == earliest - 1,
        str(m["pre_t0_attempts"])[:250])


def test_w11_05_window_verdicts_and_chain_fail_visible(td):
    """G2 四态收割 × pre_t0_attempts 兼容 + 坏链 fail-visible（sampler rc3
    不扩链）。"""
    # 窗A：seq1 坏（pre-anchor）→ seq2 好（锚）→ seq3 好；到期 → rc0 PASS
    manA = _open_valid(td, duration_hours=0.05)
    _record(td, tag="a1", health_target="0" * 40)
    r2 = _record(td, tag="a2")
    _record(td, tag="a3")
    m = wm.load_manifest(td, manA["window_id"])
    _ck("G2 窗A 锚=seq2（seq1 为 pre_t0_attempt）",
        m["first_qualified_sequence"] == 2
        and m["t0"] == r2["doc"]["collected_at"])
    _seal_expired(td, manA)
    v = wh.harvest(td, window_id=manA["window_id"])
    _ck("G2 窗A：seq1 坏但锚后全好 → 到期 rc0 PASS",
        v["rc"] == 0 and v["status"] == "PASS", str(v)[:300])
    _ck("G2 窗A counts：pre_t0_attempts=1 不进分母、锚后合格=2",
        v["counts"].get("pre_t0_attempts") == 1
        and v["counts"]["qualified_samples"] == 2
        and v["qualification"]["qualified_ratio"] == 1.0,
        str((v.get("counts"), v.get("qualification"))))

    # 窗B：seq1 坏 → seq2 好（锚）→ seq3 坏；到期 → rc1（锚后失败）
    manB = _open_valid(td, duration_hours=0.05)
    _record(td, tag="b1", health_target="0" * 40)
    _record(td, tag="b2")
    _record(td, tag="b3", health_target="0" * 40)
    _seal_expired(td, manB)
    v = wh.harvest(td, window_id=manB["window_id"])
    _ck("G2 窗B：锚后 seq3 坏 → 到期 rc1（unqualified_sample）",
        v["rc"] == 1 and any(f["code"] == "unqualified_sample"
                             for f in v["failures"])
        and v["counts"].get("pre_t0_attempts") == 1, str(v)[:250])

    # 窗C：全窗无合格样本：运行期 rc2；名义到期 → rc1 no_qualified_anchor
    manC = _open_valid(td, duration_hours=0.05)
    _record(td, tag="c1", health_target="0" * 40)
    v = wh.harvest(td, window_id=manC["window_id"])
    _ck("G2 窗C 运行期 rc2（等待首合格，T0 不再死锁）",
        v["rc"] == 2 and v["status"] == "NOT_DUE", str(v)[:200])
    mpath = wm.manifest_path(td, manC["window_id"])
    dm = json.load(open(mpath))
    dm["created_at"] = (datetime.now(timezone.utc)
                        - timedelta(hours=1)).isoformat()
    with open(mpath, "w") as f:
        json.dump(dm, f)
    v = wh.harvest(td, window_id=manC["window_id"])
    _ck("G2 窗C 名义到期无合格锚 → rc1 no_qualified_anchor",
        v["rc"] == 1 and any(f.get("code") == "no_qualified_anchor"
                             for f in v["failures"]), str(v)[:250])
    wm.seal_window(td, manC["window_id"])

    # 坏链 fail-visible：sampler rc3、不扩链（断链/symlink/坏 JSON）
    manD = _open_valid(td, duration_hours=24.0)
    rd = _record(td, tag="d1")
    assert rd["rc"] == 0
    sdir = od.samples_dir(td)
    p1 = rd["path"]
    orig_bytes = open(p1, "rb").read()

    def _v2_files():
        return [n for n in os.listdir(sdir)
                if re.match(od.NEW_SAMPLE_NAME_RE, n)]

    n0 = len(_v2_files())
    d_t = json.loads(orig_bytes)
    d_t["probe_note"] = "tampered"
    with open(p1, "w") as f:
        json.dump(d_t, f)
    r_t = _record(td, tag="d2")
    _ck("G2 断链（篡改→hash 失配）→ sampler rc3 且不扩链",
        r_t["rc"] == 3 and any(f.get("code") == "sample_hash_mismatch"
                               for f in r_t.get("chain_failures", []))
        and len(_v2_files()) == n0, str(r_t)[:250])
    with open(p1, "wb") as f:
        f.write(orig_bytes)
    os.remove(p1)
    os.symlink(os.path.join(td, "bait-g2"), p1)
    r_s = _record(td, tag="d3")
    _ck("G2 symlink 样本 → sampler rc3（绝不跟随/静默跳过）",
        r_s["rc"] == 3 and any(f.get("code") == "symlink_sample"
                               for f in r_s.get("chain_failures", [])),
        str(r_s)[:250])
    os.remove(p1)
    with open(p1, "wb") as f:
        f.write(orig_bytes)
    bad = os.path.join(sdir, od.gen_sample_name())
    with open(bad, "w") as f:
        f.write("{not json")
    r_j = _record(td, tag="d4")
    _ck("G2 坏 JSON 样本文件 → sampler rc3（不静默跳过）",
        r_j["rc"] == 3 and any(f.get("code") == "unparsable_sample"
                               for f in r_j.get("chain_failures", [])),
        str(r_j)[:250])
    os.remove(bad)
    r_ok = _record(td, tag="d5")
    _ck("G2 链修复后 sampler 恢复 rc0（可恢复路径）",
        r_ok["rc"] == 0, str(r_ok)[:200])


# ══════════════════════════════════════════════════════════════════════
# H. W11-06 invalidate 单一提交点（R10-OBS-INVALIDATE-ATOMICITY-003）
# ══════════════════════════════════════════════════════════════════════

def test_w11_06_invalidate_failpoints_and_legacy(td):
    """H failpoint 两态收敛 + 预置/篡改/symlink/hardlink rc3 + legacy 兼容
    + 撕裂态 rc3 + sample/invalidate 同锁串行。"""
    cli = os.path.join(TOOLS, "window_manifest.py")
    py = sys.executable

    # ① failpoint：发布中途崩溃（临时文件已写、未 publish）→ 仅 open 态
    man1 = _open_valid(td, duration_hours=24.0)
    _record(td, tag="fp1", scheduler_config_sha="c" * 64)
    wid1 = man1["window_id"]
    leftover = os.path.join(wm.manifest_dir(td), ".tmp-inval-crashsim.tmp")
    with open(leftover, "w") as f:
        f.write('{"partial": true}')
    _ck("H 中途崩溃（temp 残留、无 event）→ 窗口仍 open 可用",
        wm.active_manifest(td)["window_id"] == wid1
        and not os.path.exists(wm.invalidation_path(td, wid1)))
    r1 = subprocess.run([py, cli, "invalidate", "--root", str(td),
                         "--window-id", wid1, "--reason", "fp",
                         "--principal", "w11"],
                        capture_output=True, text=True, timeout=30)
    _ck("H 崩溃残留不阻碍正式作废（rc0，两态收敛）", r1.returncode == 0,
        r1.stdout[:150])
    ev1 = json.load(open(wm.invalidation_path(td, wid1)))
    _ck("H event 完整（绑定 window/epoch/reason/principal/原窗 hash）",
        ev1["schema"] == wm.INVALIDATION_SCHEMA
        and ev1["window_id"] == wid1 and ev1["epoch_id"] == man1["epoch_id"]
        and ev1["reason"] == "fp" and ev1["principal"] == "w11"
        and re.match(r"^[0-9a-f]{64}$", ev1["original_manifest_sha256"]))
    _ck("H 作废后 active 释放", wm.active_manifest(td) is None)

    # ② 预置/篡改/symlink/hardlink → 一律 rc3（不留半提交态）
    adversarial = []
    for kind in ("preset-garbage", "preset-symlink", "preset-hardlink",
                 "tampered-hash"):
        mw = _open_valid(td, duration_hours=24.0)
        foreign = os.path.join(td, "foreign-%s.json" % kind)
        with open(foreign, "w") as f:
            json.dump({"hello": "world"}, f)
        ip = wm.invalidation_path(td, mw["window_id"])
        if kind == "preset-garbage":
            with open(ip, "w") as f:
                f.write("{not json")
        elif kind == "preset-symlink":
            os.symlink(foreign, ip)
        elif kind == "preset-hardlink":
            os.link(foreign, ip)
        else:
            forged_ev = {"schema": wm.INVALIDATION_SCHEMA,
                         "window_id": mw["window_id"],
                         "epoch_id": mw["epoch_id"],
                         "invalidated_at": "2026-10-11T00:00:00+00:00",
                         "reason": "legit", "principal": "ops",
                         "original_manifest_sha256": "0" * 64,
                         "original_manifest": {}}
            with open(ip, "w") as f:
                json.dump(forged_ev, f)
        rr = subprocess.run([py, cli, "invalidate", "--root", str(td),
                             "--window-id", mw["window_id"],
                             "--reason", "legit", "--principal", "ops"],
                            capture_output=True, text=True, timeout=30)
        adversarial.append((kind, rr.returncode, mw["window_id"]))
    codes = {k: rc for k, rc, _ in adversarial}
    _ck("H 预置垃圾内容 → rc3", codes["preset-garbage"] == 3)
    _ck("H 预置 symlink → rc3", codes["preset-symlink"] == 3)
    _ck("H 预置 hardlink → rc3", codes["preset-hardlink"] == 3)
    _ck("H 篡改 event（hash 不咬合）→ rc3", codes["tampered-hash"] == 3)
    # 篡改窗收割 fail-closed（binding 校验）
    wid_tam = next(w for k, _rc, w in adversarial if k == "tampered-hash")
    v_tam = wh.harvest(td, window_id=wid_tam)
    _ck("H 篡改 event 的窗收割 rc3（fail-closed）", v_tam["rc"] == 3,
        str(v_tam)[:200])
    # 清理：移除对抗文件后正门作废成功（证明 rc3 未留半提交态）
    for kind, _rc, w in adversarial:
        ip = wm.invalidation_path(td, w)
        if os.path.lexists(ip):
            os.remove(ip)
        rr = subprocess.run([py, cli, "invalidate", "--root", str(td),
                             "--window-id", w, "--reason", "cleanup",
                             "--principal", "w11"],
                            capture_output=True, text=True, timeout=30)
        assert rr.returncode == 0, (kind, rr.stdout[:200])
    _ck("H 对抗面清理后全部可正门作废（无半提交残留）",
        wm.active_manifest(td) is None)

    # ③ legacy 兼容形态一：event + 已改 manifest（旧 writer 完成态）
    manL = _open_valid(td, duration_hours=24.0)
    _record(td, tag="legacy", scheduler_config_sha="c" * 64)
    widL = manL["window_id"]
    mpathL = wm.manifest_path(td, widL)
    rawL = open(mpathL, "rb").read()
    shaL = hashlib.sha256(rawL).hexdigest()
    docL = json.loads(rawL)
    evL = {"schema": wm.INVALIDATION_SCHEMA, "window_id": widL,
           "epoch_id": docL["epoch_id"],
           "invalidated_at": "2026-10-10T00:00:00+00:00",
           "reason": "legacy-migration", "principal": "old-writer",
           "original_manifest_sha256": shaL, "original_manifest": docL}
    with open(wm.invalidation_path(td, widL), "w") as f:
        json.dump(evL, f)
    docL["status"] = "invalidated"
    docL["history"] = docL.get("history", []) + [
        {"action": "invalidate", "at": "2026-10-10T00:00:00+00:00"}]
    with open(mpathL, "w") as f:
        json.dump(docL, f)
    _ck("H legacy event+已改 manifest → effective invalidated（active 释放）",
        wm.active_manifest(td) is None)
    vL = wh.harvest(td, window_id=widL)
    _ck("H legacy 作废窗收割 rc3（绝不 resume 旧窗）",
        vL["rc"] == 3 and "invalidated" in str(vL.get("error", "")),
        str(vL)[:200])
    recL = wm.invalidate_window(td, widL, reason="legacy-migration",
                                principal="old-writer")
    _ck("H legacy 事件同参数 → 幂等返回原记录（rc0 语义）",
        recL["invalidated_at"] == evL["invalidated_at"])

    # ④ 撕裂态：manifest 已 invalidated 但无 event（旧 bug 现场）→ rc3
    manT = _open_valid(td, duration_hours=24.0)
    _record(td, tag="torn", scheduler_config_sha="c" * 64)
    widT = manT["window_id"]
    dT = json.load(open(wm.manifest_path(td, widT)))
    dT["status"] = "invalidated"
    with open(wm.manifest_path(td, widT), "w") as f:
        json.dump(dT, f)
    vT = wh.harvest(td, window_id=widT)
    _ck("H 撕裂态（invalidated 无 event）收割 rc3", vT["rc"] == 3,
        str(vT)[:200])
    rT = subprocess.run([py, cli, "invalidate", "--root", str(td),
                         "--window-id", widT, "--reason", "r",
                         "--principal", "p"],
                        capture_output=True, text=True, timeout=30)
    _ck("H 撕裂态 invalidate → rc3（绝不静默补写）", rT.returncode == 3,
        rT.stdout[:150])

    # ⑤ sample/invalidate 竞态：同一 .window.lock 串行（无撕裂态）
    manR = _open_valid(td, duration_hours=24.0)
    _record(td, tag="race-anchor", scheduler_config_sha="c" * 64)
    widR = manR["window_id"]
    sdir = od.samples_dir(td)
    n_before = len([n for n in os.listdir(sdir)
                    if re.match(od.NEW_SAMPLE_NAME_RE, n)])
    barrier = threading.Barrier(2)
    outcomes = []

    def _inv():
        barrier.wait()
        try:
            wm.invalidate_window(td, widR, reason="race", principal="w11")
            outcomes.append(("invalidate", 0))
        except wm.WindowError as e:
            outcomes.append(("invalidate", type(e).__name__))

    def _samp():
        barrier.wait()
        r = od.record_sample(td, _core(tag="race"), release_sha="b" * 40,
                             scheduler_config_sha="c" * 64)
        outcomes.append(("sample", r["rc"]))

    ts = [threading.Thread(target=_inv), threading.Thread(target=_samp)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=60)
    evR = wm.load_event(td, widR)
    _ck("H 竞态后 event 完整且为唯一提交点",
        evR is not None and evR["reason"] == "race"
        and wm.active_manifest(td) is None)
    n_after = len([n for n in os.listdir(sdir)
                   if re.match(od.NEW_SAMPLE_NAME_RE, n)])
    sample_rc = next(o[1] for o in outcomes if o[0] == "sample")
    if n_after == n_before + 1:
        _ck("H 竞态序A：样本先入旧窗随后作废（sample rc0 + invalidate rc0）",
            sample_rc == 0)
    else:
        _ck("H 竞态序B：作废先落地，采样拒绝复活旧窗（sample rc3 不写样）",
            sample_rc == 3 and n_after == n_before)


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

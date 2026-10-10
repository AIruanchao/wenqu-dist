#!/usr/bin/env python3
"""window_harvest.py——G9-02/T2 观察窗收割器（从 raw 样本重算，不信累计计数）。

四态退出码（plan G9-02）：
  rc0 PASS        窗口完整通过（封口/到期、链完整重算全对、资格全合格、
                  5min 分桶覆盖 ≥ 最低覆盖阈值）；
  rc1 WINDOW_FAIL 窗口内失败（不合格样本〔identity 缺失/health 坏/capacity
                  BLOCKED/SHA 与窗口不咬合等〕/链断/缺 sequence/同序分叉/
                  样本 hash 不匹配/symlink 样本/到期零样本/分桶覆盖不足）；
  rc2 NOT_DUE     窗口未到期（t0 未锚定或 now < end_at）且目前无失败；
  rc3 ENV_ERROR   证据环境错误（根不可读、无 manifest、manifest 损坏、
                  多个活跃 manifest 歧义、目标窗已作废、manifest 缺十项
                  前置〔须先 invalidate 重开〕）。

重算纪律（不信样本内累计计数/自报 qualified 标志）：
  - sample_sha256：pop 后 canonical JSON 重算比对；
  - 链序：sequence 1..N 连续、prev_sha256 逐条咬合、首条 prev=GENESIS；
  - 合格分母：重新判定 identity（repo.identity 40hex）+ provenance 全字段
    （release_sha 40hex / observer_sha、scheduler_config_sha 64hex）+
    T2 窗口资格（od.qualify_against_window：health target_sha==sfinal 非零
    非 self_declared、capacity 非 BLOCKED/CRITICAL、release/observer 与窗口
    digests 咬合）+ qualified 标志一致性——identity=null/health 坏/容量闸
    关闭绝不计入合格分母，且逐样本记录 unqualified_reasons；
  - 窗口级 qualification 聚合：verdict.qualification（全窗合格率+理由直方图）；
  - 收割严判（T2-C）：5min/bin 预期分桶数 × 最低覆盖阈值（默认 90%）；
    覆盖不足 → rc1 WINDOW_FAIL（绝不 2 样本 rc0）；legacy 样本不计分母，
    但 verdict.counts.legacy_ignored 显式计数。

--audit-writers 模式（G9-01/G9-02 唯一 writer 收敛探针）：
  扫描 LaunchAgents plist + scheduler 注册表，发现 com.wenqu.scheduler
  之外任何触及观察采样面的作业（旧 com.wenqu.observation /
  com.wenqu.observation-window 等）→ rc1；唯一 writer → rc0。

纯标准库；只读收割（不改证据）；测试全部 tmp 根注入。
"""
import argparse
import hashlib
import json
import math
import os
import re
import sys
from datetime import datetime, timezone

_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)
import observation_daily as od  # noqa: E402
import window_manifest as wm    # noqa: E402

GENESIS = od.GENESIS_SHA
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
#: T2-C：样本分桶粒度（分钟）与缺省最低覆盖阈值。
SAMPLE_BIN_MINUTES = 5
MIN_COVERAGE = 0.90


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def _scan_samples(root):
    """扫描 samples/：返回 (v2 样本 [(doc, path, name)], legacy 计数,
    symlink 名单, 损坏计数)。symlink 绝不打开。"""
    sdir = od.samples_dir(root)
    v2, symlinks, unparsable, legacy = [], [], 0, 0
    try:
        names = sorted(os.listdir(sdir))
    except OSError:
        return v2, 0, symlinks, 0
    for n in names:
        if not n.endswith(".json"):
            continue
        p = os.path.join(sdir, n)
        if os.path.islink(p):
            symlinks.append(n)
            continue
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            unparsable += 1
            continue
        if isinstance(d, dict) and d.get("schema") == od.SAMPLE_SCHEMA:
            v2.append((d, p, n))
        else:
            legacy += 1
    return v2, legacy, symlinks, unparsable


def _requalify(doc, manifest=None):
    """从 raw 字段重新判定样本合格性（不信 qualified 自报）。

    T2 fail-closed：structural（identity/provenance）之外追加
    od.qualify_against_window（health/capacity/release·observer 咬合窗口）。
    返回 (qualified, failures)；failures 即该样本的 unqualified_reasons。"""
    failures = []
    identity = (doc.get("repo") or {}).get("identity") \
        if isinstance(doc.get("repo"), dict) else None
    if not (isinstance(identity, str) and SHA1_RE.match(identity)):
        failures.append("identity_invalid")
    for fld, pat in (("release_sha", SHA1_RE),
                     ("observer_sha", SHA256_RE),
                     ("scheduler_config_sha", SHA256_RE),
                     ("prev_sha256", SHA256_RE),
                     ("sample_sha256", SHA256_RE)):
        v = doc.get(fld)
        if not (isinstance(v, str) and pat.match(v)):
            failures.append(fld + "_invalid")
    seq = doc.get("sequence")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        failures.append("sequence_invalid")
    if not isinstance(doc.get("epoch_id"), str) or not doc.get("epoch_id"):
        failures.append("epoch_id_invalid")
    w_ok, w_reasons = od.qualify_against_window(doc, manifest)
    if not w_ok:
        failures.extend(w_reasons)
    flagged = doc.get("qualified") is True
    if not failures and not flagged:
        failures.append("qualified_flag_inconsistent")
    if flagged and failures:
        failures.append("qualified_flag_inconsistent")
    return (not failures), failures


def _verify_chain(samples, *, failures):
    """链重算：hash 可重算、sequence 连续、prev 咬合、首条 GENESIS。
    同序分叉在此暴露。samples: [(doc, path, name)]（单 epoch）。"""
    by_seq = {}
    for doc, path, name in samples:
        seq = doc.get("sequence")
        seq = seq if isinstance(seq, int) and not isinstance(seq, bool) else None
        if seq is None:
            failures.append({"code": "missing_sequence", "file": name})
            continue
        if seq in by_seq:
            failures.append({"code": "forked_sequence", "sequence": seq,
                             "files": [by_seq[seq], name]})
        else:
            by_seq[seq] = name
    ordered = []
    for seq in sorted(by_seq):
        ordered.append((seq, by_seq[seq]))
    docs = {doc.get("sequence"): (doc, path, name)
            for doc, path, name in samples
            if isinstance(doc.get("sequence"), int)}
    # sample_sha256 重算
    for doc, path, name in samples:
        stored = doc.get("sample_sha256")
        recomputed = od.compute_sample_sha256(
            {k: v for k, v in doc.items() if k != "sample_sha256"})
        if stored != recomputed:
            failures.append({"code": "sample_hash_mismatch", "file": name})
    # sequence 连续性 1..N
    if by_seq:
        expected = list(range(1, max(by_seq) + 1))
        missing = sorted(set(expected) - set(by_seq))
        if missing:
            failures.append({"code": "sequence_gap",
                             "missing_sequences": missing})
    # prev 咬合
    for seq, name in ordered:
        doc = docs.get(seq, (None, None, None))[0]
        if doc is None:
            continue
        prev = doc.get("prev_sha256")
        if seq == 1:
            if prev != GENESIS:
                failures.append({"code": "genesis_mismatch", "file": name})
        else:
            prev_doc = docs.get(seq - 1, (None,))[0]
            if prev_doc is None:
                continue  # gap 已记
            if prev != prev_doc.get("sample_sha256"):
                failures.append({"code": "chain_break", "sequence": seq,
                                 "file": name})


def _coverage(manifest, epoch_samples, *, now_dt=None,
              bin_minutes=SAMPLE_BIN_MINUTES):
    """T2-C 分桶覆盖重算：5min/bin 预期桶数 vs 实际被【合格】样本覆盖的桶数。

    返回 {"expected_bins", "covered_bins", "ratio", "qualified_in_window",
    "bin_minutes"}；无法计算（无 t0/无时长）时 ratio=None。仅统计
    collected_at 落在 [t0, end) 内的桶。"""
    t0 = wm.parse_iso(manifest.get("t0") or manifest.get("start_at"))
    end = wm.parse_iso(manifest.get("end_at"))
    try:
        duration_h = float(manifest.get("duration_hours") or 0.0)
    except (TypeError, ValueError):
        duration_h = 0.0
    if t0 is None or duration_h <= 0:
        return {"expected_bins": None, "covered_bins": 0, "ratio": None,
                "qualified_in_window": 0, "bin_minutes": bin_minutes}
    span = (end - t0).total_seconds() if end is not None else \
        duration_h * 3600.0
    span = max(span, duration_h * 3600.0)  # 以窗口名义时长为分母下界
    expected = max(1, math.ceil(span / (bin_minutes * 60.0)))
    covered, in_win = set(), 0
    bin_sec = bin_minutes * 60.0
    for doc, _p, _n in epoch_samples:
        if not doc.get("qualified"):
            continue  # 只有合格样本覆盖分桶
        ts = wm.parse_iso(doc.get("collected_at"))
        if ts is None:
            continue
        idx = int((ts - t0).total_seconds() // bin_sec)
        if 0 <= idx < expected:
            covered.add(idx)
            in_win += 1
    ratio = len(covered) / expected if expected else None
    return {"expected_bins": expected, "covered_bins": len(covered),
            "ratio": ratio, "qualified_in_window": in_win,
            "bin_minutes": bin_minutes}


def harvest(root, *, window_id=None, now=None, min_coverage=MIN_COVERAGE):
    """收割一个窗口（默认取最新 manifest）。返回判定 dict（含 rc）。"""
    verdict = {"rc": None, "status": None, "root": root,
               "window_id": window_id, "failures": [], "counts": {},
               "notes": []}
    if not os.path.isdir(root):
        verdict.update(rc=3, status="ENV_ERROR",
                       error="observation root not a dir: %s" % root)
        return verdict
    docs, merrors = wm.load_manifests(root)
    if not docs:
        verdict.update(rc=3, status="ENV_ERROR",
                       error="no valid window manifest under %s"
                       % wm.manifest_dir(root),
                       manifest_errors=merrors)
        return verdict
    if window_id:
        manifest = next((m for m in docs if m.get("window_id") == window_id),
                        None)
        if manifest is None:
            verdict.update(rc=3, status="ENV_ERROR",
                           error="manifest not found: %s" % window_id)
            return verdict
    else:
        manifest = docs[-1]  # 最新（created_at 排序）
    verdict["window_id"] = manifest.get("window_id")
    verdict["epoch_id"] = manifest.get("epoch_id")

    # T2-D：目标窗已作废 → 证据环境错误（绝不收割作废窗）
    if manifest.get("status") == "invalidated":
        verdict.update(rc=3, status="ENV_ERROR",
                       error="window %s invalidated (audit record: %s)"
                             % (manifest.get("window_id"),
                                manifest.get("window_id")
                                + ".invalidated.json"))
        return verdict
    # T2-A 回看：manifest 必须带十项前置（旧无效窗 sfinal=null/digests 空
    # → 不能收割出 PASS；须先 invalidate 再按新窗重开）
    pfail = wm.validate_prerequisites(manifest.get("digests"))
    if pfail:
        verdict.update(rc=3, status="ENV_ERROR",
                       error="manifest %s lacks sealed T0 prerequisites "
                             "(invalidate + reopen): %s"
                             % (manifest.get("window_id"), "; ".join(pfail)),
                       prerequisite_failures=pfail)
        return verdict

    # 多活跃 manifest = 证据环境歧义（双 writer 风险面）
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    actives = [m for m in docs if m.get("status") == "open"
               and not (wm.parse_iso(m.get("end_at"))
                        and now_dt > wm.parse_iso(m.get("end_at")))]
    if len(actives) > 1:
        verdict.update(rc=3, status="ENV_ERROR",
                       error="multiple active windows: %s" % [
                           m.get("window_id") for m in actives])
        return verdict

    samples, legacy, symlinks, unparsable = _scan_samples(root)
    verdict["counts"]["v2_samples_scanned"] = len(samples)
    verdict["counts"]["legacy_ignored"] = legacy  # legacy 不计分母，显式计数
    verdict["counts"]["unparsable_ignored"] = unparsable
    failures = verdict["failures"]
    for n in symlinks:
        failures.append({"code": "symlink_sample", "file": n})

    epoch_samples = [(d, p, n) for d, p, n in samples
                     if d.get("epoch_id") == manifest.get("epoch_id")]
    qualified_n = 0
    qualification = {
        "epoch_samples": len(epoch_samples), "qualified_samples": 0,
        "unqualified_samples": 0, "qualified_ratio": None,
        "unqualified_reasons": {},
    }
    for doc, path, name in epoch_samples:
        ok, qfail = _requalify(doc, manifest)
        if ok:
            qualified_n += 1
        else:
            for r in qfail:
                qualification["unqualified_reasons"][r] = \
                    qualification["unqualified_reasons"].get(r, 0) + 1
            failures.append({"code": "unqualified_sample", "file": name,
                             "unqualified_reasons": qfail})
    _verify_chain(epoch_samples, failures=failures)
    verdict["counts"]["epoch_samples"] = len(epoch_samples)
    verdict["counts"]["qualified_samples"] = qualified_n
    qualification["qualified_samples"] = qualified_n
    qualification["unqualified_samples"] = len(epoch_samples) - qualified_n
    if epoch_samples:
        qualification["qualified_ratio"] = \
            round(qualified_n / len(epoch_samples), 6)
    verdict["qualification"] = qualification

    if failures:
        verdict.update(rc=1, status="WINDOW_FAIL")
        return verdict

    end = wm.parse_iso(manifest.get("end_at"))
    if end is None:
        verdict.update(rc=2, status="NOT_DUE",
                       note="window open, t0 not yet anchored (no first "
                            "qualified sample)")
        return verdict
    if now_dt < end:
        verdict.update(rc=2, status="NOT_DUE",
                       note="window still running (end_at=%s)" % end.isoformat())
        return verdict
    if not epoch_samples:
        verdict.update(rc=1, status="WINDOW_FAIL")
        failures.append({"code": "no_samples",
                         "detail": "window expired with zero samples"})
        return verdict
    first = (manifest.get("first_sample_sha256") or "")
    if first and epoch_samples:
        head = next((d for d, _p, _n in epoch_samples
                     if d.get("sequence") == 1), None)
        if head is not None and head.get("sample_sha256") != first:
            failures.append({"code": "first_sample_mismatch"})
            verdict.update(rc=1, status="WINDOW_FAIL")
            return verdict
    # T2-C 收割严判：5min 分桶覆盖（legacy 不计分母；counts.legacy_ignored
    # 已显式上报）。覆盖 < 阈值 → rc1 WINDOW_FAIL（绝不 2 样本 rc0）。
    cov = _coverage(manifest, epoch_samples)
    verdict["coverage"] = cov
    if cov["ratio"] is None or cov["ratio"] < float(min_coverage):
        failures.append({
            "code": "coverage_below_threshold",
            "detail": ("qualified-sample bin coverage %.4f < threshold %.2f"
                       % (cov["ratio"] if cov["ratio"] is not None else -1.0,
                          float(min_coverage))),
            "expected_bins": cov["expected_bins"],
            "covered_bins": cov["covered_bins"],
            "bin_minutes": cov["bin_minutes"],
            "ratio": cov["ratio"],
            "threshold": float(min_coverage),
            "legacy_ignored": verdict["counts"]["legacy_ignored"],
        })
        verdict.update(rc=1, status="WINDOW_FAIL")
        return verdict
    verdict.update(rc=0, status="PASS",
                   note="window complete: chain verified by recomputation; "
                        "bin coverage %.4f >= %.2f"
                        % (cov["ratio"], float(min_coverage)))
    return verdict


def audit_writers(launchagents_dir=None, scheduler_db=None):
    """唯一 writer 收敛审计（只读）。

    - launchd 面：com.wenqu.scheduler 之外任何触及观察采样面的 plist；
    - scheduler 注册表面：观察采样作业必须恰为 w4.observation-sample 一个。
    返回 findings 列表（空=收敛）。"""
    findings = []
    system_dir = os.path.join(os.path.dirname(_TOOLS_DIR), "system")
    if system_dir not in sys.path:
        sys.path.insert(0, system_dir)
    from wenqu_core import scheduler as sched
    findings.extend(sched.audit_launchd_observation_writers(launchagents_dir))
    # 注册表面：db 路径必须显式给出（不猜、不扫真实 ~/.wenqu）
    db = scheduler_db
    if db and os.path.isfile(db):
        from wenqu_core.scheduler import SchedulerStore
        try:
            store = SchedulerStore(db)
            try:
                writers = sched.find_observation_writers(store)
            finally:
                store.close()
        except Exception as e:  # noqa: BLE001
            findings.append({"kind": "registry_error", "detail": str(e)[:200]})
        else:
            if len(writers) > 1 or (writers and writers[0] != sched.PROD_JOB_ID):
                findings.append({"kind": "registry_multiple_writers",
                                 "job_ids": writers})
    return findings


def _cli(argv=None):
    ap = argparse.ArgumentParser(
        prog="window_harvest",
        description="G9-02 观察窗收割器（四态 rc0/1/2/3；--audit-writers 唯一 writer 审计）")
    ap.add_argument("--root", required=True, help="observation root")
    ap.add_argument("--window-id", help="指定窗口（默认=最新 manifest）")
    ap.add_argument("--now", help="ISO 时刻（默认=当前）")
    ap.add_argument("--min-coverage", type=float, default=MIN_COVERAGE,
                    help="5min 分桶最低覆盖阈值（默认 %.2f；覆盖不足=rc1）"
                         % MIN_COVERAGE)
    ap.add_argument("--audit-writers", action="store_true",
                    help="唯一 writer 审计模式（launchd+注册表）")
    ap.add_argument("--launchagents", help="LaunchAgents 目录（审计模式）")
    ap.add_argument("--scheduler-db", help="scheduler 注册表 db（审计模式）")
    args = ap.parse_args(argv)

    if args.audit_writers:
        findings = audit_writers(launchagents_dir=args.launchagents,
                                 scheduler_db=args.scheduler_db)
        print(json.dumps({"mode": "audit-writers", "rc": 1 if findings else 0,
                          "findings": findings}, ensure_ascii=False, indent=2))
        return 1 if findings else 0

    now = None
    if args.now:
        try:
            now = datetime.fromisoformat(args.now)
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
        except ValueError:
            print(json.dumps({"rc": 3, "error": "bad --now: %s" % args.now}))
            return 3
    verdict = harvest(args.root, window_id=args.window_id, now=now,
                      min_coverage=args.min_coverage)
    print(json.dumps(verdict, ensure_ascii=False, indent=2,
                     default=str))
    return int(verdict["rc"])


if __name__ == "__main__":
    sys.exit(_cli())

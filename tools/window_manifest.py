#!/usr/bin/env python3
"""window_manifest.py——G9-02 动态观察窗 manifest（sealed window manifest）。

替代旧硬编码窗口起点（2026-10-10 一类）：窗口的 T0 不再写死在代码里，
而是「首条合格样本时刻」；起止、时长、Sfinal、tree/roots digests、首样本
hash 全部登记在 `<observation_root>/windows/<window_id>.json`：

  {
    "schema": "obs-window-manifest-v1",
    "window_id":  "w-<utc-ns>-<hex>",     # 唯一，open 时生成/指定
    "epoch_id":   "e-<uuid4>",            # 样本 hash chain 的链属
    "kind":       "w10-observation",
    "status":     "open" | "sealed",      # sealed 后不可再变更
    "created_at": ISO-UTC,
    "duration_hours": 336.0,              # 窗口时长（T0+duration=end）
    "sfinal":     "<40hex | null>",
    "digests":    {"tree": …, "roots": …, "release": …},
    "t0":                 null | ISO,     # 首条合格样本时刻（动态起点）
    "first_sample_sha256": null | hex,
    "start_at":   null | ISO,             # == t0
    "end_at":     null | ISO,             # == t0 + duration
    "sealed_at":  null | ISO,
    "canary_hours": 48,                   # W9 canary 窗（锚点同样是 t0）
    "history":    [ {action, at, detail} … ]
  }

生命周期：
  open_window()      O_EXCL 创建 status=open（存在同 id → 拒绝）；
                     T2 收紧（R9-OBS-T0-QUALIFICATION-002）：开窗必须携带十项
                     前置要素（prerequisites），缺任一/任一非法 →
                     WindowPrereqError（CLI rc3），绝不 sfinal=null 起钟；
  note_first_sample() 首条【合格】样本落盘后回填 t0/首样 hash/起止（仅 open 期
                     可写，幂等；sealed 后拒绝；不合格样本不锚定 T0）；
  seal_window()      封口（幂等；可从样本目录自行定位首样）；
  invalidate_window() 生成可审计作废记录（<wid>.invalidated.json，含原 manifest
                     全量+原文件 sha256+原因+作废人），manifest 状态改
                     invalidated——绝不删除文件；
  active_manifest()  取当前唯一「open 且未过期」的 manifest；多个活跃
                     manifest = 环境错误（WindowAmbiguityError）。

T0 十项前置（T0_PREREQUISITES，开窗 digests 块唯一来源，缺一=拒开）：
  1  sfinal             release 终 SHA（40hex 非零；--release）
  2  tree               commit tree 摘要（64hex 非零）
  3  roots              roots digest（64hex 非零）
  4  registry           registry 语义 digest（64hex 非零）
  5  branch             branch governance digest（64hex 非零）
  6  evidence_schema    evidence active schema digest（64hex 非零）
  7  observer           observer 脚本 digest（64hex 非零；样本 observer_sha 咬合）
  8  ci_run_id          exact CI run id（数字非空）
  9  health             health 面：health_target_sha==sfinal 且非零、
                       health_scope 非 self_declared
  10 capacity           capacity_gate 必须为 OPEN（BLOCKED/CRITICAL=拒开）

纪律：纯标准库；测试全部经 tmp 根注入，不写真实 ~/.wenqu。
CLI rc 契约：0=成功；1=冲突/失败；3=证据环境错误（含十项前置缺失/非法）。
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

SCHEMA = "obs-window-manifest-v1"
INVALIDATION_SCHEMA = "obs-window-invalidation-v1"
DEFAULT_DURATION_HOURS = 336.0  # W10 观察窗缺省 14 天
DEFAULT_CANARY_HOURS = 48.0

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA64_RE = re.compile(r"^[0-9a-f]{64}$")
CI_RUN_RE = re.compile(r"^[0-9]{1,64}$")
ZERO40 = "0" * 40
ZERO64 = "0" * 64

#: T0 十项前置正名表（名称, 语义）——资格判定/收割/作废共用同一正源。
T0_PREREQUISITES = (
    ("sfinal", "release 终 SHA（40hex 非零；--release）"),
    ("tree", "commit tree 摘要（64hex 非零）"),
    ("roots", "roots digest（64hex 非零）"),
    ("registry", "registry 语义 digest（64hex 非零）"),
    ("branch", "branch governance digest（64hex 非零）"),
    ("evidence_schema", "evidence active schema digest（64hex 非零）"),
    ("observer", "observer 脚本 digest（64hex 非零；样本 observer_sha 咬合）"),
    ("ci_run_id", "exact CI run id（数字非空）"),
    ("health", "health_target_sha==sfinal 非零 + health_scope 非 self_declared"),
    ("capacity", "capacity_gate 必须为 OPEN（BLOCKED/CRITICAL=拒开）"),
)

#: digests 块物理键（health 一项展开为 target_sha+scope 两键）。
PREREQ_DIGEST_KEYS = ("sfinal", "tree", "roots", "registry", "branch",
                      "evidence_schema", "observer", "ci_run_id",
                      "health_target_sha", "health_scope", "capacity_gate")

__all__ = [
    "SCHEMA", "INVALIDATION_SCHEMA", "T0_PREREQUISITES", "PREREQ_DIGEST_KEYS",
    "WindowError", "WindowPrereqError", "WindowAmbiguityError", "manifest_dir",
    "manifest_path", "invalidation_path", "load_manifests", "load_manifest",
    "validate_prerequisites", "prerequisites_from_env", "open_window",
    "seal_window", "note_first_sample", "invalidate_window", "active_manifest",
    "parse_iso", "utc_ns_stamp",
]


class WindowError(RuntimeError):
    """manifest 操作失败（已存在 / 状态非法 / 找不到等）。"""


class WindowPrereqError(WindowError):
    """T0 十项前置缺失/非法——fail-closed 拒开（CLI rc3）。"""


class WindowAmbiguityError(WindowError):
    """多个活跃 manifest——证据环境错误（rc3 语义）。"""


def utc_ns_stamp(now_ns=None):
    """UTC 纳秒紧凑串：YYYYMMDDTHHMMSS + 9 位纳秒（定宽，字典序=时间序）。"""
    ns = time.time_ns() if now_ns is None else int(now_ns)
    dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%S") + "%09d" % (ns % 1_000_000_000)


def parse_iso(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def manifest_dir(root):
    return os.path.join(root, "windows")


def manifest_path(root, window_id):
    return os.path.join(manifest_dir(root), window_id + ".json")


def invalidation_path(root, window_id):
    return os.path.join(manifest_dir(root), window_id + ".invalidated.json")


def _atomic_write_json(path, payload):
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def _new_ids(now_ns=None):
    return ("w-" + utc_ns_stamp(now_ns) + "-" + uuid.uuid4().hex[:6],
            "e-" + uuid.uuid4().hex)


def validate_prerequisites(prereqs):
    """T0 十项前置校验（fail-closed）。返回 failures 列表（空=全部通过）。

    每条失败码：``missing:<key>`` / ``invalid:<key>`` / ``zero:<key>`` /
    ``mismatch:health_target_sha!=sfinal`` /
    ``self_declared:health_scope`` / ``capacity_not_open:capacity_gate``。"""
    p = prereqs if isinstance(prereqs, dict) else {}
    failures = []

    def _need(key, checker):
        if key not in p or p.get(key) in (None, ""):
            failures.append("missing:%s" % key)
            return
        bad = checker(p[key])
        if bad:
            failures.append(bad)

    for key in ("sfinal",):
        _need(key, lambda v: None if (isinstance(v, str) and SHA40_RE.match(v))
              else "invalid:%s" % key)
        if isinstance(p.get(key), str) and p[key] == ZERO40:
            failures.append("zero:%s" % key)
    for key in ("tree", "roots", "registry", "branch", "evidence_schema",
                "observer"):
        _need(key, lambda v, k=key: None if (isinstance(v, str)
                                             and SHA64_RE.match(v))
              else "invalid:%s" % k)
        if isinstance(p.get(key), str) and p[key] == ZERO64:
            failures.append("zero:%s" % key)
    _need("ci_run_id", lambda v: None if (isinstance(v, str)
                                          and CI_RUN_RE.match(v))
          else "invalid:ci_run_id")
    _need("health_target_sha", lambda v: None if (isinstance(v, str)
                                                  and SHA40_RE.match(v)
                                                  and v != ZERO40)
          else "invalid:health_target_sha")
    if ("health_target_sha" in p and p.get("health_target_sha") not in (None, "")
            and isinstance(p.get("sfinal"), str) and p["sfinal"]
            and p.get("health_target_sha") != p.get("sfinal")):
        failures.append("mismatch:health_target_sha!=sfinal")
    _need("health_scope", lambda v: None if (isinstance(v, str) and v.strip())
          else "invalid:health_scope")
    if isinstance(p.get("health_scope"), str) \
            and "self_declared" in p["health_scope"].lower():
        failures.append("self_declared:health_scope")
    _need("capacity_gate", lambda v: None if v == "OPEN"
          else "capacity_not_open:capacity_gate")
    # 保序去重
    seen, ordered = set(), []
    for f in failures:
        if f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered


def prerequisites_from_env(env=None):
    """从受管环境解析十项前置（供采样器 auto-open 使用，缺/坏 fail-closed）。

    来源（按序）：``WENQU_WINDOW_PREREQS_JSON``（内联 JSON 对象）或
    ``WENQU_WINDOW_PREREQS_FILE``（JSON 文件路径）。
    返回 (prereqs_dict_or_None, failures)；failures 非空时 prereqs=None。"""
    env = os.environ if env is None else env
    raw = env.get("WENQU_WINDOW_PREREQS_JSON")
    path = env.get("WENQU_WINDOW_PREREQS_FILE")
    if raw:
        try:
            doc = json.loads(raw)
        except ValueError as e:
            return None, ["prereqs_json_unparsable:%s" % str(e)[:120]]
    elif path:
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError) as e:
            return None, ["prereqs_file_unreadable:%s" % str(e)[:120]]
    else:
        return None, ["prereqs_absent:"
                      "no WENQU_WINDOW_PREREQS_JSON/WENQU_WINDOW_PREREQS_FILE"]
    if not isinstance(doc, dict):
        return None, ["prereqs_not_object"]
    failures = validate_prerequisites(doc)
    return (None, failures) if failures else (doc, [])


def open_window(root, *, window_id=None, epoch_id=None,
                duration_hours=DEFAULT_DURATION_HOURS,
                kind="w10-observation", canary_hours=DEFAULT_CANARY_HOURS,
                now=None, prerequisites=None):
    """创建一个新窗口 manifest（O_EXCL；同 window_id 已存在 → WindowError）。

    T2 收紧：必须携带十项前置 prerequisites（缺任一/任一非法 →
    WindowPrereqError）；十项要素全量写入 manifest 的 digests 块，
    顶层 sfinal=digests.sfinal——绝不 sfinal=null 起钟。"""
    if not isinstance(prerequisites, dict) or not prerequisites:
        raise WindowPrereqError(
            "window open refused: T0 ten prerequisites required "
            "(sfinal/tree/roots/registry/branch/evidence_schema/observer/"
            "ci_run_id/health/capacity); refusing to start clock with "
            "sfinal=null (R9-OBS-T0-QUALIFICATION-002)")
    failures = validate_prerequisites(prerequisites)
    if failures:
        raise WindowPrereqError(
            "window open refused: T0 prerequisites invalid: %s"
            % "; ".join(failures))
    wid, eid = _new_ids()
    wid = window_id or wid
    eid = epoch_id or eid
    if not re.match(r"^[A-Za-z0-9._:-]{1,128}$", wid):
        raise WindowError("illegal window_id: %r" % wid)
    if not re.match(r"^[A-Za-z0-9._:-]{1,128}$", eid):
        raise WindowError("illegal epoch_id: %r" % eid)
    path = manifest_path(root, wid)
    if os.path.exists(path):
        raise WindowError("window already exists: %s" % wid)
    if duration_hours is not None and float(duration_hours) <= 0:
        raise WindowError("duration_hours must be > 0")
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    digests = {k: prerequisites[k] for k in PREREQ_DIGEST_KEYS}
    doc = {
        "schema": SCHEMA,
        "window_id": wid,
        "epoch_id": eid,
        "kind": kind,
        "status": "open",
        "created_at": now_dt.astimezone(timezone.utc).isoformat(),
        "duration_hours": float(duration_hours),
        "sfinal": digests["sfinal"],
        "digests": digests,
        "t0": None,
        "first_sample_sha256": None,
        "start_at": None,
        "end_at": None,
        "sealed_at": None,
        "canary_hours": float(canary_hours),
        "history": [{"action": "open", "at":
                     now_dt.astimezone(timezone.utc).isoformat(),
                     "detail": "manifest created (O_EXCL); T0 ten "
                               "prerequisites sealed into digests"}],
    }
    try:
        os.makedirs(manifest_dir(root), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
            f.write("\n")
    except FileExistsError:
        raise WindowError("window already exists: %s" % wid) from None
    except OSError as e:
        raise WindowError("cannot create manifest %s: %s" % (path, e)) from e
    return doc


def load_manifests(root):
    """读取全部 manifest。返回 (docs, errors)；errors 为证据环境错误清单。"""
    docs, errors = [], []
    d = manifest_dir(root)
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return docs, errors
    for n in names:
        if not n.endswith(".json") or n.endswith(".harvest.json") \
                or n.endswith(".invalidated.json"):
            continue
        p = os.path.join(d, n)
        try:
            with open(p, encoding="utf-8") as f:
                doc = json.load(f)
            if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
                errors.append({"file": n, "code": "bad_schema"})
                continue
            docs.append(doc)
        except (OSError, ValueError) as e:
            errors.append({"file": n, "code": "unparsable",
                           "error": str(e)[:200]})
    docs.sort(key=lambda m: (m.get("created_at") or "", m.get("window_id")))
    return docs, errors


def load_manifest(root, window_id):
    """单读一个 manifest；缺失/损坏 → WindowError。"""
    p = manifest_path(root, window_id)
    try:
        with open(p, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        raise WindowError("cannot load manifest %s: %s" % (window_id, e)) from e
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise WindowError("manifest %s bad schema" % window_id)
    return doc


def _first_sample_of_epoch(root, epoch_id):
    """从样本目录定位链首样本（sequence==1）。返回 (doc, path) 或 (None, None)。

    注意：只认 v2 样本（schema=obs-sample-v2）；legacy 样本不属于任何链。"""
    import observation_daily as od  # 同目录；链解析单一正源
    return od.find_epoch_head_sample(od.samples_dir(root), epoch_id)


def note_first_sample(root, manifest, *, sample_sha256, t0_iso, now=None):
    """首条合格样本落盘后回填 t0/首样 hash/起止。仅 open 期、仅一次。"""
    if manifest.get("status") != "open":
        raise WindowError("manifest %s not open (refuse mutation)"
                          % manifest.get("window_id"))
    if manifest.get("first_sample_sha256"):
        return manifest  # 幂等
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    t0 = parse_iso(t0_iso)
    if t0 is None:
        raise WindowError("bad t0_iso: %r" % t0_iso)
    t0 = t0.astimezone(timezone.utc)
    end = t0 + timedelta(hours=float(manifest.get("duration_hours")
                                      or DEFAULT_DURATION_HOURS))
    iso = now_dt.astimezone(timezone.utc).isoformat()
    manifest = dict(manifest)
    manifest.update({
        "t0": t0.isoformat(),
        "first_sample_sha256": sample_sha256,
        "start_at": t0.isoformat(),
        "end_at": end.isoformat(),
        "history": manifest.get("history", []) + [{
            "action": "first_sample", "at": iso,
            "detail": "t0 anchored to first qualified sample"}],
    })
    _atomic_write_json(manifest_path(root, manifest["window_id"]), manifest)
    return manifest


def seal_window(root, window_id, *, first_sample=None, now=None):
    """封口窗口（幂等）。t0 未定时可从样本目录自行定位首样回填。"""
    manifest = load_manifest(root, window_id)
    if manifest.get("status") == "sealed":
        return manifest
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    iso = now_dt.astimezone(timezone.utc).isoformat()
    if manifest.get("t0") is None:
        doc, _ = ((first_sample, None) if first_sample else
                  _first_sample_of_epoch(root, manifest.get("epoch_id")))
        # T2：T0 只锚定首条【合格】样本（不合格首样不推进窗口起点）
        if isinstance(doc, dict) and doc.get("collected_at") \
                and doc.get("qualified") is True:
            manifest = note_first_sample(
                root, manifest,
                sample_sha256=doc.get("sample_sha256"),
                t0_iso=doc["collected_at"], now=now_dt)
    manifest = dict(manifest)
    manifest["status"] = "sealed"
    manifest["sealed_at"] = iso
    manifest["history"] = manifest.get("history", []) + [{
        "action": "seal", "at": iso, "detail": "window sealed"}]
    _atomic_write_json(manifest_path(root, manifest["window_id"]), manifest)
    return manifest


def invalidate_window(root, window_id, *, reason, principal, now=None):
    """作废一个窗口——生成可审计作废记录，绝不删除文件（T2 工单 D）。

    - 记录落 ``windows/<window_id>.invalidated.json``（O_EXCL）：含
      invalidated_at / reason / principal / 原 manifest 全量留档 /
      原 manifest 文件字节 sha256（作废前实算）；
    - manifest 本体只改 status="invalidated" 并追加 history（可审计、可回溯）；
    - 幂等：已作废且记录在 → 返回既有记录；已作废但记录缺失 → WindowError
      （状态不一致，须人工修复，绝不静默重写）。
    返回作废记录 dict。"""
    if not isinstance(reason, str) or not reason.strip():
        raise WindowError("invalidate requires non-empty reason")
    if not isinstance(principal, str) or not principal.strip():
        raise WindowError("invalidate requires non-empty principal")
    manifest = load_manifest(root, window_id)
    mpath = manifest_path(root, window_id)
    ipath = invalidation_path(root, window_id)
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    iso = now_dt.astimezone(timezone.utc).isoformat()
    if manifest.get("status") == "invalidated":
        if os.path.exists(ipath):
            try:
                with open(ipath, encoding="utf-8") as f:
                    return json.load(f)  # 幂等
            except (OSError, ValueError) as e:
                raise WindowError("invalidation record unreadable for %s: %s"
                                  % (window_id, e)) from e
        raise WindowError(
            "manifest %s already invalidated but audit record missing "
            "(inconsistent state; manual repair required)" % window_id)
    try:
        with open(mpath, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise WindowError("cannot read manifest %s: %s" % (window_id, e)) from e
    original_sha = hashlib.sha256(raw).hexdigest()
    record = {
        "schema": INVALIDATION_SCHEMA,
        "window_id": window_id,
        "epoch_id": manifest.get("epoch_id"),
        "invalidated_at": iso,
        "reason": reason,
        "principal": principal,
        "original_manifest_sha256": original_sha,
        "original_manifest": manifest,
        "note": "auditable invalidation; original manifest file retained "
                "(never deleted) with status=invalidated",
    }
    try:
        fd = os.open(ipath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
            f.write("\n")
    except FileExistsError:
        raise WindowError("invalidation record already exists: %s" % ipath) from None
    except OSError as e:
        raise WindowError("cannot create invalidation record %s: %s"
                          % (ipath, e)) from e
    manifest = dict(manifest)
    manifest["status"] = "invalidated"
    manifest["history"] = manifest.get("history", []) + [{
        "action": "invalidate", "at": iso, "detail": reason,
        "principal": principal, "original_manifest_sha256": original_sha}]
    _atomic_write_json(mpath, manifest)
    return record


def active_manifest(root, *, now=None):
    """当前唯一「open 且未过期」的 manifest。

    - 无 → None（调用方可 auto-open 新窗口）；
    - 多个 → WindowAmbiguityError（证据环境错误，rc3）；
    - 过期判定：end_at 已定且 now > end_at。
    """
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    docs, _ = load_manifests(root)
    active = []
    for m in docs:
        if m.get("status") != "open":
            continue
        end = parse_iso(m.get("end_at"))
        if end is not None and now_dt > end:
            continue
        active.append(m)
    if len(active) > 1:
        raise WindowAmbiguityError(
            "multiple active windows: %s"
            % ", ".join(m.get("window_id", "?") for m in active))
    return active[0] if active else None


# ---------------------------------------------------------------- CLI

def _cli(argv=None):
    ap = argparse.ArgumentParser(
        prog="window_manifest",
        description="G9-02/T2 动态观察窗 manifest（open 需十项前置/seal/"
                    "invalidate 作废/show/list）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_open = sub.add_parser("open", help="创建新窗口 manifest（十项前置缺一=rc3 拒开）")
    p_open.add_argument("--root", required=True)
    p_open.add_argument("--window-id")
    p_open.add_argument("--duration-hours", type=float,
                        default=DEFAULT_DURATION_HOURS)
    p_open.add_argument("--canary-hours", type=float,
                        default=DEFAULT_CANARY_HOURS)
    p_open.add_argument("--kind", default="w10-observation")
    # T0 十项前置（缺任一 → rc3 拒开；--release 即 sfinal）
    p_open.add_argument("--release", "--sfinal", dest="release",
                        help="T0-1 release 终 SHA（40hex 非零）")
    p_open.add_argument("--tree", help="T0-2 commit tree 摘要（64hex）")
    p_open.add_argument("--roots", help="T0-3 roots digest（64hex）")
    p_open.add_argument("--registry", help="T0-4 registry 语义 digest（64hex）")
    p_open.add_argument("--branch", help="T0-5 branch governance digest（64hex）")
    p_open.add_argument("--evidence-schema", help="T0-6 evidence active "
                        "schema digest（64hex）")
    p_open.add_argument("--observer", help="T0-7 observer 脚本 digest（64hex）")
    p_open.add_argument("--ci-run-id", help="T0-8 exact CI run id（数字）")
    p_open.add_argument("--health-target-sha", help="T0-9 health target SHA "
                        "（40hex 非零且==release）")
    p_open.add_argument("--health-scope", help="T0-9 health scope（非 "
                        "self_declared）")
    p_open.add_argument("--capacity-gate", help="T0-10 容量闸（必须 OPEN）")
    p_inv = sub.add_parser("invalidate",
                           help="作废窗口（可审计记录，不删文件）")
    p_inv.add_argument("--root", required=True)
    p_inv.add_argument("--window-id", required=True)
    p_inv.add_argument("--reason", required=True,
                       help="作废原因（入审计记录）")
    p_inv.add_argument("--principal", required=True,
                       help="作废人（入审计记录）")
    p_seal = sub.add_parser("seal", help="封口窗口（幂等）")
    p_seal.add_argument("--root", required=True)
    p_seal.add_argument("--window-id", required=True)
    p_show = sub.add_parser("show", help="打印 manifest")
    p_show.add_argument("--root", required=True)
    p_show.add_argument("--window-id")
    p_list = sub.add_parser("list", help="列出全部 manifest")
    p_list.add_argument("--root", required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "open":
            prerequisites = {
                "sfinal": args.release,
                "tree": args.tree,
                "roots": args.roots,
                "registry": args.registry,
                "branch": args.branch,
                "evidence_schema": args.evidence_schema,
                "observer": args.observer,
                "ci_run_id": args.ci_run_id,
                "health_target_sha": args.health_target_sha,
                "health_scope": args.health_scope,
                "capacity_gate": args.capacity_gate,
            }
            failures = validate_prerequisites(prerequisites)
            if failures:
                print(json.dumps({"rc": 3, "refused": "open",
                                  "error": "T0 ten prerequisites invalid: %s"
                                           % "; ".join(failures),
                                  "failures": failures}, ensure_ascii=False))
                return 3
            doc = open_window(args.root, window_id=args.window_id,
                              duration_hours=args.duration_hours,
                              canary_hours=args.canary_hours,
                              prerequisites=prerequisites, kind=args.kind)
            print(json.dumps({"rc": 0, "window_id": doc["window_id"],
                              "epoch_id": doc["epoch_id"],
                              "sfinal": doc["sfinal"],
                              "digests_sealed": len(doc["digests"])},
                             ensure_ascii=False))
            return 0
        if args.cmd == "invalidate":
            record = invalidate_window(args.root, args.window_id,
                                       reason=args.reason,
                                       principal=args.principal)
            print(json.dumps({"rc": 0,
                              "window_id": record["window_id"],
                              "status": "invalidated",
                              "invalidated_at": record["invalidated_at"],
                              "reason": record["reason"],
                              "principal": record["principal"],
                              "original_manifest_sha256":
                                  record["original_manifest_sha256"],
                              "record_file":
                                  os.path.basename(
                                      invalidation_path(args.root,
                                                        args.window_id))},
                             ensure_ascii=False))
            return 0
        if args.cmd == "seal":
            doc = seal_window(args.root, args.window_id)
            print(json.dumps({"rc": 0, "status": doc["status"],
                              "window_id": doc["window_id"]}))
            return 0
        if args.cmd == "show":
            doc = (load_manifest(args.root, args.window_id)
                   if args.window_id else active_manifest(args.root))
            if doc is None:
                print(json.dumps({"error": "no active manifest"}))
                return 3
            print(json.dumps(doc, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "list":
            docs, errors = load_manifests(args.root)
            print(json.dumps({"windows": [
                {"window_id": m["window_id"], "status": m["status"],
                 "epoch_id": m["epoch_id"],
                 "sfinal": m.get("sfinal")} for m in docs],
                "errors": errors}, ensure_ascii=False))
            return 0
    except WindowPrereqError as e:
        print(json.dumps({"rc": 3, "refused": "open", "error": str(e)}))
        return 3
    except WindowAmbiguityError as e:
        print(json.dumps({"rc": 3, "error": str(e)}))
        return 3
    except WindowError as e:
        print(json.dumps({"rc": 1, "error": str(e)}))
        return 1
    except OSError as e:
        print(json.dumps({"rc": 3, "error": str(e)}))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(_cli())

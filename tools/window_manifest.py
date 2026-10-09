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
  note_first_sample() 首条样本落盘后回填 t0/首样 hash/起止（仅 open 期可写，
                     幂等；sealed 后拒绝）；
  seal_window()      封口（幂等；可从样本目录自行定位首样）；
  active_manifest()  取当前唯一「open 且未过期」的 manifest；多个活跃
                     manifest = 环境错误（WindowAmbiguityError）。

纪律：纯标准库；测试全部经 tmp 根注入，不写真实 ~/.wenqu。
CLI rc 契约：0=成功；1=冲突/失败；3=证据环境错误。
"""
import argparse
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

SCHEMA = "obs-window-manifest-v1"
DEFAULT_DURATION_HOURS = 336.0  # W10 观察窗缺省 14 天
DEFAULT_CANARY_HOURS = 48.0

__all__ = [
    "SCHEMA", "WindowError", "WindowAmbiguityError", "manifest_dir",
    "manifest_path", "load_manifests", "load_manifest", "open_window",
    "seal_window", "note_first_sample", "active_manifest",
    "parse_iso", "utc_ns_stamp",
]


class WindowError(RuntimeError):
    """manifest 操作失败（已存在 / 状态非法 / 找不到等）。"""


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


def open_window(root, *, window_id=None, epoch_id=None,
                duration_hours=DEFAULT_DURATION_HOURS, sfinal=None,
                kind="w10-observation", canary_hours=DEFAULT_CANARY_HOURS,
                now=None, digests=None):
    """创建一个新窗口 manifest（O_EXCL；同 window_id 已存在 → WindowError）。"""
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
    doc = {
        "schema": SCHEMA,
        "window_id": wid,
        "epoch_id": eid,
        "kind": kind,
        "status": "open",
        "created_at": now_dt.astimezone(timezone.utc).isoformat(),
        "duration_hours": float(duration_hours),
        "sfinal": sfinal,
        "digests": dict(digests or {}),
        "t0": None,
        "first_sample_sha256": None,
        "start_at": None,
        "end_at": None,
        "sealed_at": None,
        "canary_hours": float(canary_hours),
        "history": [{"action": "open", "at":
                     now_dt.astimezone(timezone.utc).isoformat(),
                     "detail": "manifest created (O_EXCL)"}],
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
        if not n.endswith(".json") or n.endswith(".harvest.json"):
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
        if isinstance(doc, dict) and doc.get("collected_at"):
            manifest = note_first_sample(
                root, manifest,
                sample_sha256=doc.get("sample_sha256"),
                t0_iso=doc["collected_at"], now=now_dt)
    manifest = dict(manifest)
    manifest["status"] = "sealed"
    manifest["sealed_at"] = iso
    manifest["history"] = manifest.get("history", []) + [{
        "action": "seal", "at": iso, "detail": "window sealed"}]
    _atomic_write_json(manifest_path(root, window_id), manifest)
    return manifest


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
        description="G9-02 动态观察窗 manifest（open/seal/show/list）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_open = sub.add_parser("open", help="创建新窗口 manifest")
    p_open.add_argument("--root", required=True)
    p_open.add_argument("--window-id")
    p_open.add_argument("--duration-hours", type=float,
                        default=DEFAULT_DURATION_HOURS)
    p_open.add_argument("--canary-hours", type=float,
                        default=DEFAULT_CANARY_HOURS)
    p_open.add_argument("--sfinal")
    p_open.add_argument("--kind", default="w10-observation")
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
            if args.sfinal is not None and not re.match(
                    r"^[0-9a-f]{40}$", args.sfinal):
                print(json.dumps({"error": "sfinal must be 40-hex"}))
                return 1
            doc = open_window(args.root, window_id=args.window_id,
                              duration_hours=args.duration_hours,
                              canary_hours=args.canary_hours,
                              sfinal=args.sfinal, kind=args.kind)
            print(json.dumps({"rc": 0, "window_id": doc["window_id"],
                              "epoch_id": doc["epoch_id"]}))
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
                 "epoch_id": m["epoch_id"]} for m in docs],
                "errors": errors}, ensure_ascii=False))
            return 0
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

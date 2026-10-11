#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""release_state.py——双 pin 激活事务 journal（activation-state-v2）。

W11-03（R10-REL-ROLLBACK-DUAL-PIN-005 根修；正源 /private/tmp/wq11-plan.md
「W11-03｜双 pin 激活事务与真实回滚状态机」）：

背景（十轮实证）：plain ``.last-current`` 只记一个裸路径——
  1. 记录的回滚目标树也可能漂移（7eeb8a1 树实测漂移），回滚时第 4 段
     逐文件对账才失败 = 回滚闭环不成立（坏目标到用的时候才知道）；
  2. 激活无事务性：current 切换前后无 journal/断点，kill -9 后既不能
     断言收敛到 old/new，也无法检测指针被顶替。

本模块把激活/回滚升级为四阶段事务（install-release.sh 主载体调用）：

    PREPARED → SYMLINK_SWITCHED → SMOKE_OK → COMMITTED
    （任一非终态可 → ABORTED）

journal 文件 ``$INSTALL_ROOT/activation-state-v2.json``（0600 owner-only）：

    schema, kind(install|rollback|recover_drift),
    generation（事务代号，begin 单调 +1）, epoch（已提交激活数）,
    state, target{sha,tree_path,manifest_path,manifest_sha256,tree_digest,
    version}, previous{…}（双 pin 另一端）, roots_sha256,
    health.previous_target{status: healthy|rollback_unavailable|unknown,
    drifted/missing/extra files, checked_at}, events[], integrity

纪律：
  - 每次写盘 = tmp 文件 + fsync(file) + atomic rename + fsync(dir)；
  - integrity = sha256(canonical JSON 去 integrity 字段)——截断/篡改必断；
  - journal 为 symlink / 权限含组或其他位 / 坏 JSON / integrity 不符 /
    generation 回退 → FuseError（rc3 熔断 BLOCKED，绝不静默继续）；
  - watermark ``.activation-epoch.json`` 记录最近提交的 generation/epoch：
    journal 被删除而 watermark 在 → status/recover 熔断 rc3；
  - 「目标树全量 verify 通过」在 current 切换**前**落 journal（PREPARED
    内含目标 sha/manifest digest/全树实算 digest——begin 时即审计）；
  - 回滚目标健康管理（check-rollback）：对 previous pin 全树对账 +
    .last-current 一致性对账，漂移/顶替 → rollback_unavailable + ALARM；
  - recover：在途事务只许收敛 old 或 new（第三态熔断 rc3）。

退出码：0=正常（含健康判定为 unavailable 的监控语义）；1=语义拒绝；
3=journal/指针/generation 不可调和（熔断 BLOCKED）。

密钥纪律：无密钥；HMAC 签名面在 release_attest.py（本模块只做状态机与
对账，不重复签名信任链）。独立运行：
    python3 system/wenqu_core/release_state.py <subcommand> --help
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

JOURNAL_FILENAME = "activation-state-v2.json"
WATERMARK_FILENAME = ".activation-epoch.json"
LAST_CURRENT_FILENAME = ".last-current"
JOURNAL_SCHEMA = "activation-state-v2"
WATERMARK_SCHEMA = "activation-epoch/1"

STATE_ORDER = ("PREPARED", "SYMLINK_SWITCHED", "SMOKE_OK")
TERMINAL_STATES = ("COMMITTED", "ABORTED")
ALL_STATES = STATE_ORDER + TERMINAL_STATES
KINDS = ("install", "rollback", "recover_drift")

RC_OK, RC_REFUSE, RC_FUSE = 0, 1, 3


class RefuseError(Exception):
    """语义拒绝（rc1）：结构/授权/漂移/TOCTOU 不符。"""


class FuseError(Exception):
    """不可调和（rc3）：journal 损坏/截断/篡改/链接/越根/指针第三态。"""


# ------------------------------------------------------------------ #
# 基础小工具
# ------------------------------------------------------------------ #
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _real(path: str) -> str:
    return os.path.realpath(path)


def _canonical(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _journal_path(install_root: str) -> str:
    return os.path.join(install_root, JOURNAL_FILENAME)


def _watermark_path(install_root: str) -> str:
    return os.path.join(install_root, WATERMARK_FILENAME)


def _releases_root(install_root: str) -> str:
    return _real(os.path.join(install_root, "releases"))


def _atomic_write_json(path: str, data: Dict[str, Any], *, mode: int = 0o600,
                       fsync_dir: bool = True) -> None:
    """write + fsync(file) + atomic rename + fsync(dir)。"""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, indent=1,
                         sort_keys=True) + "\n"
    fd, tmp_path = tempfile.mkstemp(
        prefix="." + os.path.basename(path) + ".", dir=directory)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    if fsync_dir:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _with_integrity(data: Dict[str, Any]) -> Dict[str, Any]:
    body = {k: v for k, v in data.items() if k != "integrity"}
    out = dict(data)
    out["integrity"] = _sha256_bytes(_canonical(body).encode("utf-8"))
    return out


def _load_watermark(install_root: str) -> Optional[Dict[str, Any]]:
    path = _watermark_path(install_root)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            wm = json.load(fh)
    except (OSError, ValueError):
        raise FuseError(f"watermark 不可读/坏 JSON: {path}")
    if wm.get("schema") != WATERMARK_SCHEMA:
        raise FuseError(f"watermark schema 不符: {path}")
    return wm


def load_journal(install_root: str) -> Optional[Dict[str, Any]]:
    """读 journal；缺失返回 None；损坏/截断/篡改/链接 → FuseError。"""
    path = _journal_path(install_root)
    if os.path.islink(path):
        raise FuseError(f"activation journal 是 symlink（顶替攻击面）: {path}")
    if not os.path.exists(path):
        wm = _load_watermark(install_root)  # 坏 watermark 同样熔断
        if wm is not None:
            raise FuseError(
                f"activation journal 缺失而 watermark 证明曾提交事务"
                f"（generation={wm.get('generation')} epoch={wm.get('epoch')}）"
                f"——journal 被删除，双 pin 不可核验: {path}")
        return None
    mode = os.stat(path).st_mode & 0o7777
    if mode & 0o077:
        raise FuseError(
            f"activation journal 权限过宽: mode={oct(mode)}"
            f"（组/其他任何位即拒，须 0600 owner-only）")
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise FuseError(
            f"activation journal 损坏/截断/非 JSON（BLOCKED）: {path}: {exc}")
    if not isinstance(data, dict) or data.get("schema") != JOURNAL_SCHEMA:
        raise FuseError(f"activation journal schema 不符: {path}")
    body = {k: v for k, v in data.items() if k != "integrity"}
    expect = _sha256_bytes(_canonical(body).encode("utf-8"))
    if data.get("integrity") != expect:
        raise FuseError(
            f"activation journal integrity 不符（截断/篡改，BLOCKED）: {path}")
    if data.get("state") not in ALL_STATES:
        raise FuseError(f"activation journal state 非法: {data.get('state')!r}")
    for field in ("generation", "epoch"):
        val = data.get(field)
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise FuseError(
                f"activation journal.{field} 非法（须非负整数）: {val!r}")
    return data


def save_journal(install_root: str, data: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(data)
    data["updated_at"] = _utc_now_iso()
    data["schema"] = JOURNAL_SCHEMA
    _atomic_write_json(_journal_path(install_root), _with_integrity(data))
    return data


def _save_watermark(install_root: str, generation: int, epoch: int) -> None:
    _atomic_write_json(_watermark_path(install_root), {
        "schema": WATERMARK_SCHEMA,
        "generation": generation,
        "epoch": epoch,
        "updated_at": _utc_now_iso(),
    })


# ------------------------------------------------------------------ #
# 树审计（manifest 逐文件 sha256 对账 + 全树 digest 实算）
# ------------------------------------------------------------------ #
def audit_tree(manifest_path: str, tree_root: str) -> Dict[str, Any]:
    """对账解出树 ↔ manifest（缺件/漂移/多件/符号链接全查）。

    tree_digest = sha256(canonical [[path, sha256], …])（按 path 排序、
    仅 manifest 声明的 file 成员、取**实算**哈希）——verify 通过时刻的
    全树指纹，回滚健康管理据此判定漂移。
    """
    report: Dict[str, Any] = {
        "ok": False, "missing": [], "drifted": [], "extra": [],
        "symlinks": [], "tree_digest": None, "n_files": 0,
        "manifest_path": manifest_path, "tree_root": _real(tree_root),
    }
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        report["error"] = f"manifest 不可读/坏 JSON: {exc}"
        return report
    records = manifest.get("files")
    if not isinstance(records, list):
        report["error"] = "manifest.files 非列表"
        return report
    expected: Dict[str, str] = {}
    for rec in records:
        if isinstance(rec, dict) and rec.get("type") == "file" \
                and isinstance(rec.get("path"), str):
            expected[rec["path"]] = str(rec.get("sha256", ""))
    report["n_files"] = len(expected)
    actual: Dict[str, str] = {}
    tree_real = _real(tree_root)
    for dirpath, dirnames, filenames in os.walk(tree_real):
        for fname in filenames:
            p = os.path.join(dirpath, fname)
            rel = os.path.relpath(p, tree_real)
            if os.path.islink(p):
                report["symlinks"].append(rel)
                continue
            try:
                actual[rel] = _sha256_file(p)
            except OSError:
                report["missing"].append(rel)
    for path in sorted(expected):
        if path not in actual and path not in report["missing"]:
            report["missing"].append(path)
        elif path in actual and actual[path] != expected[path]:
            report["drifted"].append(path)
    report["extra"] = sorted(set(actual) - set(expected))
    if not (report["missing"] or report["drifted"] or report["extra"]
            or report["symlinks"]):
        report["ok"] = True
        pairs = [[p, actual[p]] for p in sorted(expected)]
        report["tree_digest"] = _sha256_bytes(
            _canonical({"files": pairs}).encode("utf-8"))
    return report


def pin_snapshot(install_root: str, tree: str) -> Dict[str, Any]:
    """从部署树实况导出 pin 快照（sha/manifest/全树 digest/version）。

    越根（不在 $INSTALL_ROOT/releases/<40hex>/tree 下）→ RefuseError。
    """
    tree_real = _real(tree)
    relroot = _releases_root(install_root)
    try:
        inside = os.path.commonpath([relroot, tree_real]) == relroot
    except ValueError:
        inside = False
    if not inside:
        raise RefuseError(
            f"目标树越根（不在受管 releases 根内）: {tree_real} ⊄ {relroot}")
    if os.path.basename(tree_real) != "tree":
        raise RefuseError(f"目标树末段不是 tree/: {tree_real}")
    parent = os.path.dirname(tree_real)
    sha = os.path.basename(parent)
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RefuseError(f"目标树目录名非 40hex commit: {sha!r}")
    import glob as _glob
    manifests = [m for m in _glob.glob(os.path.join(parent, "*.manifest.json"))
                 if not m.endswith(".verify-report.json")]
    if len(manifests) != 1:
        raise RefuseError(
            f"目标 release manifest 缺失/不唯一: {parent}（四件套不完整）")
    manifest_path = manifests[0]
    version = "UNKNOWN"
    vfile = os.path.join(tree_real, "system", "VERSION")
    if os.path.isfile(vfile):
        try:
            version = open(vfile, encoding="utf-8").read(4096).strip() \
                or "UNKNOWN"
        except OSError:
            version = "UNKNOWN"
    return {
        "sha": sha,
        "tree_path": tree_real,
        "manifest_path": os.path.basename(manifest_path),
        "manifest_sha256": _sha256_file(manifest_path),
        "tree_digest": None,   # 由调用方按审计结果填充
        "version": version,
    }


def _audit_pin(install_root: str, tree: str, *, role: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """pin 快照 + 全树审计；审计不过 → RefuseError（带文件清单）。"""
    pin = pin_snapshot(install_root, tree)
    manifest_path = os.path.join(os.path.dirname(pin["tree_path"]),
                                 pin["manifest_path"])
    rep = audit_tree(manifest_path, pin["tree_path"])
    if not rep["ok"]:
        detail = (f"missing={rep['missing'][:5]} drifted={rep['drifted'][:5]} "
                  f"extra={rep['extra'][:5]} symlinks={rep['symlinks'][:3]}")
        raise RefuseError(
            f"{role}树不完整/漂移（{pin['tree_path']}）: {detail}"
            f"——漂移的现役树不得继续正向安装或冒充正常 rollback"
            f"（recover-drift 通道：--recover-drift 保全现场+新 epoch）")
    pin["tree_digest"] = rep["tree_digest"]
    return pin, rep


def _current_real(install_root: str) -> str:
    link = os.path.join(install_root, "current")
    if not os.path.lexists(link):
        return ""
    return _real(link)


# ------------------------------------------------------------------ #
# 子命令
# ------------------------------------------------------------------ #
def cmd_begin(args: argparse.Namespace) -> int:
    install_root = os.path.abspath(args.install_root)
    j = load_journal(install_root)  # FuseError → rc3
    if j is not None and j["state"] not in TERMINAL_STATES:
        raise RefuseError(
            f"在途事务未收敛（state={j['state']} generation={j['generation']}）"
            f"——先运行 install-release.sh（入口自动 recover）或"
            f" release_state.py recover")
    base_gen = j["generation"] if j is not None else 0
    base_epoch = j["epoch"] if j is not None else 0
    if args.kind not in KINDS:
        raise RefuseError(f"kind 非法: {args.kind!r}")

    target, _ = _audit_pin(install_root, args.target_tree, role="目标(target)")

    previous: Optional[Dict[str, Any]] = None
    prev_tree = args.previous_tree or _current_real(install_root)
    if args.previous_tree == "":
        prev_tree = ""
    if prev_tree:
        if args.allow_drifted_previous:
            pin = pin_snapshot(install_root, prev_tree)
            manifest_path = os.path.join(os.path.dirname(pin["tree_path"]),
                                         pin["manifest_path"])
            rep = audit_tree(manifest_path, pin["tree_path"])
            pin["tree_digest"] = rep["tree_digest"]  # 漂移也如实记录
            previous = pin
        else:
            previous, _ = _audit_pin(install_root, prev_tree,
                                     role="previous/现役(current)")

    data: Dict[str, Any] = {
        "kind": args.kind,
        "generation": base_gen + 1,
        "epoch": base_epoch,
        "state": "PREPARED",
        "target": target,
        "previous": previous,
        "roots_sha256": (_sha256_file(args.roots)
                         if args.roots and os.path.isfile(args.roots) else None),
        "health": {"previous_target": {"status": "unknown"}},
        "events": [],
        "phase_ts": {"PREPARED": _utc_now_iso()},
        "created_at": _utc_now_iso(),
    }
    save_journal(install_root, data)
    print(json.dumps({
        "generation": data["generation"], "kind": data["kind"],
        "state": data["state"],
        "target_tree": target["tree_path"],
        "target_tree_digest": target["tree_digest"],
        "previous_tree": (previous or {}).get("tree_path", ""),
        "message": "PREPARED：目标树全量 verify 通过已落 journal"
                   "（current 切换前）",
    }, ensure_ascii=False))
    return RC_OK


def _load_for_transition(install_root: str, expect_generation: int) -> Dict[str, Any]:
    j = load_journal(install_root)
    if j is None:
        raise RefuseError("无 activation journal——没有在途事务可推进")
    if expect_generation is not None and j["generation"] != expect_generation:
        raise RefuseError(
            f"TOCTOU：generation 不符（期望 {expect_generation}，实为"
            f" {j['generation']}）——journal 被并发替换，拒绝")
    return j


def cmd_advance(args: argparse.Namespace) -> int:
    install_root = os.path.abspath(args.install_root)
    j = _load_for_transition(install_root, args.expect_generation)
    legal = {"PREPARED": "SYMLINK_SWITCHED",
             "SYMLINK_SWITCHED": "SMOKE_OK"}
    nxt = legal.get(j["state"])
    if nxt != args.state:
        raise RefuseError(
            f"journal 阶段跃迁非法: {j['state']} → {args.state}"
            f"（合法: {j['state']} → {nxt}）")
    j["state"] = args.state
    j.setdefault("phase_ts", {})[args.state] = _utc_now_iso()
    save_journal(install_root, j)
    print(json.dumps({"generation": j["generation"], "state": j["state"]},
                     ensure_ascii=False))
    return RC_OK


def cmd_commit(args: argparse.Namespace) -> int:
    install_root = os.path.abspath(args.install_root)
    j = _load_for_transition(install_root, args.expect_generation)
    if j["state"] != "SMOKE_OK":
        raise RefuseError(
            f"COMMIT 只允许来自 SMOKE_OK（实为 {j['state']}）——阶段未完成")
    if args.current_link_expected:
        expect_real = _real(args.current_link_expected)
        cur_real = _current_real(install_root)
        if cur_real != expect_real:
            raise RefuseError(
                f"TOCTOU：current 指针与 journal target 不符"
                f"（current={cur_real} expected={expect_real}）"
                f"——指针被替换，拒绝 COMMIT")
    j["current"] = j["target"]
    j["previous"] = j.get("previous")
    j["epoch"] = int(j["epoch"]) + 1
    j["state"] = "COMMITTED"
    events = list(j.get("events", []))[-31:]
    events.append({"event": "committed", "kind": j.get("kind"),
                   "generation": j["generation"], "epoch": j["epoch"],
                   "at": _utc_now_iso()})
    j["events"] = events
    save_journal(install_root, j)
    # 双 pin 落 .last-current（roll-forward 备援；与 journal previous 一致）
    if j.get("previous"):
        lc = os.path.join(install_root, "releases", LAST_CURRENT_FILENAME)
        prev_tree = j["previous"]["tree_path"]
        tmp = lc + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(prev_tree + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, lc)
    _save_watermark(install_root, j["generation"], j["epoch"])
    print(json.dumps({"generation": j["generation"], "epoch": j["epoch"],
                      "state": j["state"],
                      "current_sha": j["current"]["sha"],
                      "previous_sha": (j.get("previous") or {}).get("sha", ""),
                      "message": "COMMITTED：双 pin 已交换，.last-current 已落"
                                 "（roll-forward 备援）"},
                     ensure_ascii=False))
    return RC_OK


def cmd_abort(args: argparse.Namespace) -> int:
    install_root = os.path.abspath(args.install_root)
    j = _load_for_transition(install_root, args.expect_generation)
    if j["state"] in TERMINAL_STATES:
        raise RefuseError(f"终态事务不可 abort（state={j['state']}）")
    j["state"] = "ABORTED"
    events = list(j.get("events", []))[-31:]
    events.append({"event": "aborted", "reason": args.reason,
                   "generation": j["generation"], "at": _utc_now_iso()})
    j["events"] = events
    save_journal(install_root, j)
    print(json.dumps({"generation": j["generation"], "state": "ABORTED"},
                     ensure_ascii=False))
    return RC_OK


def cmd_recover(args: argparse.Namespace) -> int:
    """在途事务收敛判定：只许 old / new；第三态熔断 rc3。"""
    install_root = os.path.abspath(args.install_root)
    j = load_journal(install_root)
    if j is None:
        print(json.dumps({"action": "none", "reason": "无 journal"},
                         ensure_ascii=False))
        return RC_OK
    if j["state"] in TERMINAL_STATES:
        print(json.dumps({"action": "none", "reason":
                          f"终态 {j['state']}"}, ensure_ascii=False))
        return RC_OK
    target_tree = (j.get("target") or {}).get("tree_path", "")
    prev_tree = (j.get("previous") or {}).get("tree_path", "")
    cur = _current_real(install_root)
    if target_tree and cur == _real(target_tree):
        action = "finish_new"
    elif prev_tree and cur == _real(prev_tree):
        action = "converge_old"
    elif not prev_tree and not cur:
        action = "converge_old"   # 首装事务崩溃于切换前：无 old 可归
    else:
        raise FuseError(
            f"journal 在途（state={j['state']}）而 current 指向第三态"
            f"（current={cur!r} target={target_tree!r} previous={prev_tree!r}）"
            f"——不可收敛为 old/new，熔断 BLOCKED")
    print(json.dumps({
        "action": action, "state": j["state"],
        "generation": j["generation"],
        "target_tree": target_tree, "previous_tree": prev_tree,
        "current": cur,
    }, ensure_ascii=False))
    return RC_OK


def cmd_check_rollback(args: argparse.Namespace) -> int:
    """回滚目标健康管理：previous pin 全树对账 + .last-current 一致性。

    退出码：0=已出健康判定（healthy 或 rollback_unavailable——监控语义，
    告警不打断安装）；1=无 journal/未提交/无 previous pin（拒绝语义）。
    """
    install_root = os.path.abspath(args.install_root)
    j = load_journal(install_root)
    if j is None:
        raise RefuseError(
            "无 activation journal（legacy 态）——双 pin 不可核验，"
            "拒绝回滚（重装生成 journal 后方可 --rollback）")
    if j["state"] != "COMMITTED":
        raise RefuseError(
            f"journal 非 COMMITTED（state={j['state']}）——在途/中止态"
            f"无有效双 pin")
    prev = j.get("previous")
    if not prev:
        raise RefuseError("journal 无 previous pin（首装后无回滚目标记录）")
    prev_tree = prev.get("tree_path", "")
    verdict: Dict[str, Any] = {
        "checked_at": _utc_now_iso(), "checked_tree": prev_tree,
        "drifted_files": [], "missing_files": [], "extra_files": [],
        "last_current": "", "reasons": [],
    }
    status = "healthy"
    rep: Dict[str, Any] = {}
    try:
        manifest_path = os.path.join(os.path.dirname(prev_tree),
                                     prev.get("manifest_path", ""))
        rep = audit_tree(manifest_path, prev_tree)
    except (OSError, ValueError) as exc:
        verdict["reasons"].append(f"审计失败: {exc}")
        rep = {"ok": False}
    if not rep.get("ok"):
        status = "rollback_unavailable"
        verdict["drifted_files"] = rep.get("drifted", [])[:20]
        verdict["missing_files"] = rep.get("missing", [])[:20]
        verdict["extra_files"] = rep.get("extra", [])[:20]
        verdict["reasons"].append(
            "回滚目标树与 manifest 逐文件对账失败（漂移/缺件/多件）")
    elif prev.get("tree_digest") and rep.get("tree_digest") \
            and rep["tree_digest"] != prev["tree_digest"]:
        status = "rollback_unavailable"
        verdict["reasons"].append(
            f"全树 digest 漂移（激活时={prev['tree_digest'][:12]}… "
            f"现在={rep['tree_digest'][:12]}…）")
    # .last-current 一致性（伪造/顶替检测）
    lc_path = os.path.join(install_root, "releases", LAST_CURRENT_FILENAME)
    lc_value = ""
    if os.path.isfile(lc_path):
        try:
            lc_value = open(lc_path, encoding="utf-8").read().strip()
        except OSError:
            lc_value = ""
    verdict["last_current"] = lc_value
    if not lc_value:
        status = "rollback_unavailable"
        verdict["reasons"].append(".last-current 缺失——回滚入口无指针")
    elif _real(lc_value) != _real(prev_tree):
        status = "rollback_unavailable"
        verdict["reasons"].append(
            f".last-current 与 journal previous pin 不符（伪造/顶替: "
            f"{lc_value} != {prev_tree}）")
    j.setdefault("health", {})["previous_target"] = {
        "status": status, **verdict}
    save_journal(install_root, j)
    if status == "rollback_unavailable":
        for reason in verdict["reasons"]:
            print(f"ALARM: 回滚目标不可用（rollback_unavailable）: {reason}",
                  file=sys.stderr)
        print(json.dumps({"status": status, "reasons": verdict["reasons"]},
                         ensure_ascii=False))
    else:
        print(json.dumps({"status": status,
                          "tree_digest": rep.get("tree_digest")},
                         ensure_ascii=False))
    return RC_OK


def cmd_status(args: argparse.Namespace) -> int:
    install_root = os.path.abspath(args.install_root)
    j = load_journal(install_root)
    if j is None:
        print(json.dumps({"present": False}, ensure_ascii=False))
        return RC_OK
    print(json.dumps(j, ensure_ascii=False))
    return RC_OK


def cmd_audit_tree(args: argparse.Namespace) -> int:
    rep = audit_tree(os.path.abspath(args.manifest),
                     os.path.abspath(args.tree))
    print(json.dumps(rep, ensure_ascii=False))
    return RC_OK if rep["ok"] else RC_REFUSE


def cmd_note(args: argparse.Namespace) -> int:
    """向 journal 记录白名单元数据（如 recover-drift 隔离路径）。"""
    install_root = os.path.abspath(args.install_root)
    j = load_journal(install_root)
    if j is None:
        raise RefuseError("无 activation journal——无可记录对象")
    allowed_keys = ("quarantined_tree", "recover_note")
    if args.key not in allowed_keys:
        raise RefuseError(f"note key 不在白名单: {args.key!r}")
    j[args.key] = args.value
    save_journal(install_root, j)
    print(json.dumps({"noted": args.key}, ensure_ascii=False))
    return RC_OK


# ------------------------------------------------------------------ #
# CLI
# ------------------------------------------------------------------ #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="release_state.py",
        description="W11-03 双 pin 激活事务 journal（activation-state-v2）")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_root(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--install-root", required=True)

    sp = sub.add_parser("begin", help="开新事务（PREPARED：目标树 verify 已过）")
    add_root(sp)
    sp.add_argument("--kind", required=True, choices=KINDS)
    sp.add_argument("--target-tree", required=True)
    sp.add_argument("--previous-tree", default=None,
                    help="双 pin 另一端（缺省=解析 current symlink）")
    sp.add_argument("--roots", default=None,
                    help="release-roots.json（记 roots digest）")
    sp.add_argument("--allow-drifted-previous", action="store_true",
                    help="仅 recover_drift：previous 允许带漂移记录（保全现场）")
    sp.set_defaults(fn=cmd_begin)

    sp = sub.add_parser("advance", help="推进阶段（PREPARED→SWITCHED→SMOKE_OK）")
    add_root(sp)
    sp.add_argument("--state", required=True,
                    choices=["SYMLINK_SWITCHED", "SMOKE_OK"])
    sp.add_argument("--expect-generation", type=int, default=None)
    sp.set_defaults(fn=cmd_advance)

    sp = sub.add_parser("commit", help="SMOKE_OK→COMMITTED（交换双 pin+新 epoch）")
    add_root(sp)
    sp.add_argument("--expect-generation", type=int, default=None)
    sp.add_argument("--current-link-expected", default=None,
                    help="commit 前 current 指针必须仍指向该树（TOCTOU 守卫）")
    sp.set_defaults(fn=cmd_commit)

    sp = sub.add_parser("abort", help="非终态→ABORTED（留痕）")
    add_root(sp)
    sp.add_argument("--expect-generation", type=int, default=None)
    sp.add_argument("--reason", default="")
    sp.set_defaults(fn=cmd_abort)

    sp = sub.add_parser("recover", help="在途事务收敛判定（old/new；第三态 rc3）")
    add_root(sp)
    sp.set_defaults(fn=cmd_recover)

    sp = sub.add_parser("check-rollback",
                        help="回滚目标健康管理（漂移→rollback_unavailable+ALARM）")
    add_root(sp)
    sp.set_defaults(fn=cmd_check_rollback)

    sp = sub.add_parser("status", help="打印 journal（损坏/篡改 → rc3）")
    add_root(sp)
    sp.set_defaults(fn=cmd_status)

    sp = sub.add_parser("audit-tree", help="manifest 逐文件对账+全树 digest")
    sp.add_argument("--manifest", required=True)
    sp.add_argument("--tree", required=True)
    sp.set_defaults(fn=cmd_audit_tree)

    sp = sub.add_parser("note", help="记录白名单元数据（隔离路径等）")
    add_root(sp)
    sp.add_argument("--key", required=True)
    sp.add_argument("--value", required=True)
    sp.set_defaults(fn=cmd_note)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args))
    except RefuseError as exc:
        print(f"release_state: REFUSE: {exc}", file=sys.stderr)
        return RC_REFUSE
    except FuseError as exc:
        print(f"release_state: FUSE/BLOCKED: {exc}", file=sys.stderr)
        return RC_FUSE


if __name__ == "__main__":
    raise SystemExit(main())

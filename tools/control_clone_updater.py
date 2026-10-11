#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""control_clone_updater.py——受控 clone 唯一 updater（W11-07）。

十轮 W0 扣分「共享开发仓依赖」的根治件：观察器/git identity 不再消费
可变共享开发树（~/Documents/wenqu-dist），也不在采样路径自行 fetch——
本脚本是**唯一**允许 fetch 的受控组件，维护专用受控干净 clone 位并写
freshness receipt：

  1. 受控 clone 位（--repo）：专用干净 clone（updater 所有；每次运行
     reset --hard origin/<ref> + clean -fd，消灭 dirty/换分支残留）；
  2. receipt（--receipt，原子写）：绑定 exact ref sha + prerequisite/
     scheduler-config 文件内容 sha256 + fetched_at + TTL——采样器
     （tools/observation_daily.py）只读 exact ref 与 receipt，绝不 fetch；
  3. rc 契约：0=fresh；2=fetch 或环境失败（clone/fetch/reset/rev-parse
     失败、声明的文件缺失）——失败绝不落新 receipt（旧 receipt 留存，
     由 TTL 自然陈旧 → 采样器 rc3 fail-closed）。

--validate-only：不 fetch，校验既有 receipt ↔ clone ↔ freshness ↔
文件 hash 的一致性（install-release.sh 部署冻结步使用）。

纪律：纯标准库；subprocess 一律参数列表 + shell=False；绝不写仓内
路径（clone/receipt 全部在 ~/.wenqu/control/ 或显式给定位）。
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

SCHEMA = "w11-control-clone-receipt-v1"
DEFAULT_REF = "main"
DEFAULT_TTL = 900.0
GIT = "/usr/bin/git"


def _log(msg):
    sys.stderr.write("[control-clone-updater] " + msg + "\n")
    sys.stderr.flush()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(args, cwd=None, timeout=120):
    """跑一条 git（参数列表）；返回 (rc, stdout, stderr)。永不抛异常。"""
    try:
        p = subprocess.run([GIT] + list(args), capture_output=True,
                           text=True, timeout=timeout, cwd=cwd)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return None, "", str(e)[:300]


def _is_git_worktree(path):
    return bool(path) and os.path.isdir(path) and os.path.exists(
        os.path.join(path, ".git"))


def _atomic_write_json(path, payload):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".",
                exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def _file_sha_or_none(path, *, label, failures):
    if not path:
        return None
    if not os.path.isfile(path):
        failures.append("env_file_missing:%s:%s" % (label, path))
        return None
    return _sha256_file(path)


def _validate_receipt(repo, receipt_path, *, now=None):
    """校验既有 receipt ↔ clone exact ref ↔ freshness ↔ 文件 hash。

    返回 (ok, failures, receipt_doc)。"""
    failures = []
    doc = None
    try:
        with open(receipt_path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        return False, ["receipt_unreadable:%s" % str(e)[:160]], None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return False, ["receipt_schema_invalid"], doc
    repo_declared = doc.get("repo")
    if os.path.realpath(repo_declared or "") != os.path.realpath(repo):
        failures.append("receipt_repo_mismatch")
    if not _is_git_worktree(repo):
        failures.append("control_clone_not_a_worktree:%s" % repo)
    origin_ref = doc.get("origin_ref") or "origin/" + (doc.get("ref")
                                                       or DEFAULT_REF)
    sha = doc.get("sha")
    if not (isinstance(sha, str) and len(sha) == 40):
        failures.append("receipt_sha_invalid")
        sha = None
    if _is_git_worktree(repo) and sha:
        rc, out, _err = _git(["rev-parse", origin_ref], cwd=repo)
        if rc != 0 or out != sha:
            failures.append("receipt_ref_mismatch:%s!=%s" % (out or "none",
                                                             sha))
    fetched = doc.get("fetched_at_epoch")
    ttl = doc.get("ttl_seconds")
    now = time.time() if now is None else now
    if not isinstance(fetched, (int, float)) or not isinstance(ttl,
                                                               (int, float)) \
            or ttl <= 0:
        failures.append("receipt_freshness_fields_invalid")
    elif (now - float(fetched)) > float(ttl):
        failures.append("receipt_stale:age=%.0fs ttl=%.0fs"
                        % (now - float(fetched), float(ttl)))
    # 声明文件 → 内容 hash 绑定（键名与 receipt 写出的物理键一致）
    for file_key, sha_key, label in (
            ("prereqs_file", "prereqs_sha256", "prereqs"),
            ("scheduler_config", "scheduler_config_sha256",
             "scheduler_config")):
        declared, bound = doc.get(file_key), doc.get(sha_key)
        if declared:
            if not os.path.isfile(declared):
                failures.append("%s_tampered:file_missing" % label)
            elif bound != _sha256_file(declared):
                failures.append("%s_tampered:hash_mismatch" % label)
    return (not failures), failures, doc


def _update(repo, remote, ref, receipt, prereqs_file, scheduler_config,
            ttl, timeout):
    """fetch（唯一处）→ 干净化 → rev-parse exact ref → 原子写 receipt。"""
    failures = []
    if not _is_git_worktree(repo):
        parent = os.path.dirname(os.path.abspath(repo))
        os.makedirs(parent, exist_ok=True)
        rc, out, err = _git(["clone", "--branch", ref, remote, repo],
                            timeout=timeout)
        if rc != 0:
            return ["clone_failed:%s" % (err or out)[:200]]
    else:
        rc, out, err = _git(["fetch", "origin", ref], cwd=repo,
                            timeout=timeout)
        if rc != 0:
            return ["fetch_failed:%s" % (err or out)[:200]]
        # 受控干净 clone：消灭 dirty/换分支/未跟踪残留（updater 所有）
        for args in (["reset", "--hard", "-q", "origin/" + ref],
                     ["clean", "-fdq"]):
            rc, out, err = _git(args, cwd=repo, timeout=timeout)
            if rc != 0:
                return ["clean_failed:%s" % " ".join(args[:2]) + ":"
                        + (err or out)[:160]]
    rc, sha, err = _git(["rev-parse", "origin/" + ref], cwd=repo)
    if rc != 0 or not sha:
        return ["rev_parse_failed:%s" % (err or "")[:160]]
    rc, head, _ = _git(["rev-parse", "HEAD"], cwd=repo)
    if rc == 0 and head != sha:
        # reset 后 HEAD 仍偏（异常态）——拒绝冻结
        return ["head_diverged:%s!=%s" % (head, sha)]
    prereqs_sha = _file_sha_or_none(prereqs_file, label="prereqs",
                                    failures=failures)
    config_sha = _file_sha_or_none(scheduler_config,
                                   label="scheduler_config",
                                   failures=failures)
    if failures:
        return failures
    now = time.time()
    payload = {
        "schema": SCHEMA,
        "repo": os.path.abspath(repo),
        "ref": ref,
        "origin_ref": "origin/" + ref,
        "sha": sha,
        "prereqs_file": (os.path.abspath(prereqs_file)
                         if prereqs_file else None),
        "prereqs_sha256": prereqs_sha,
        "scheduler_config": (os.path.abspath(scheduler_config)
                             if scheduler_config else None),
        "scheduler_config_sha256": config_sha,
        "fetched_at_iso": datetime.fromtimestamp(
            now, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "fetched_at_epoch": now,
        "ttl_seconds": float(ttl),
    }
    _atomic_write_json(receipt, payload)
    return []


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="control-clone-updater",
        description="受控 clone 唯一 updater（fetch + 干净化 + receipt 冻结）")
    parser.add_argument("--repo", required=True,
                        help="受控干净 clone 位（updater 所有）")
    parser.add_argument("--remote",
                        help="origin 远端（fetch 模式必填；validate 模式不用）")
    parser.add_argument("--ref", default=DEFAULT_REF)
    parser.add_argument("--receipt", required=True,
                        help="freshness receipt 输出路径（原子写）")
    parser.add_argument("--prereqs-file",
                        help="运行前置 JSON 文件（内容 hash 绑入 receipt）")
    parser.add_argument("--scheduler-config",
                        help="scheduler 配置文件（内容 hash 绑入 receipt）")
    parser.add_argument("--ttl-seconds", type=float, default=DEFAULT_TTL)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--validate-only", action="store_true",
                        help="不 fetch：校验 receipt↔clone↔freshness↔hash")
    args = parser.parse_args(argv)

    if args.validate_only:
        ok, failures, _ = _validate_receipt(args.repo, args.receipt)
        print(json.dumps({"ok": ok, "rc": 0 if ok else 2,
                          "failures": failures}, ensure_ascii=False))
        if not ok:
            _log("validate-only failed: %s" % "; ".join(failures))
        return 0 if ok else 2

    if not args.remote:
        print(json.dumps({"ok": False, "rc": 2,
                          "failures": ["remote_required"]},
                         ensure_ascii=False))
        return 2
    if args.ttl_seconds <= 0:
        print(json.dumps({"ok": False, "rc": 2,
                          "failures": ["ttl_must_be_positive"]},
                         ensure_ascii=False))
        return 2
    failures = _update(args.repo, args.remote, args.ref, args.receipt,
                       args.prereqs_file, args.scheduler_config,
                       args.ttl_seconds, args.timeout)
    ok = not failures
    print(json.dumps({"ok": ok, "rc": 0 if ok else 2,
                      "failures": failures}, ensure_ascii=False))
    if not ok:
        _log("update failed: %s" % "; ".join(failures))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())

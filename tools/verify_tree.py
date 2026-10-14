#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_tree.py——独立严格全树 release verifier（W12-01；R11 硬阻断②）。

设计约束（与 install 链解耦）：
    - 零仓内依赖：单文件 CLI，只用手标准库——不 import wenqu_core、不读
      WENQU_HOME、不依赖四件套之外的任何安装态（root-owned 控制根需要
      sudo 的部分不在本单范围）。
    - 可对**任意** release 目录实跑：输入可以是 release 根（含 tree/ 与
      wenqu-dist-*.manifest.json 四件套布局），也可以是 tree 目录本身
      （manifest 在其父目录），或 --manifest 显式指定。
    - 语义复用 system/wenqu_core/release_drift.audit_tree 正源（内容
      sha256 + 可写位不变量 + missing/extra/type/special/broken），在其
      上加严：manifest schema 结构校验（rc3）、size 维度入账、哈希打开
      O_NOFOLLOW（symlink 竞态免疫）。

对账维度（逐文件五字段）：
    path   —— manifest 清单 vs 实际实体差集（missing / extra；目录蕴含
              不入 manifest，不算 extra——tar 契约同 release_attest）
    type   —— file/symlink/dir 错型（type_mismatch）
    mode   —— 可写位不变量（audit_tree 语义）：manifest 记录的是 tar 内
              归档 mode（0644/0755），部署协议激活时 chmod -R a-w，磁盘
              应为归档位去写位（0444/0555）。故磁盘 mode 含任何写位
              （& 0o222）即 mode 漂移——0444→0644 纯 mode 漂移在内容
              哈希不变时也能抓；与 tar mode 等值比对会把每棵激活树误判
              为漂移，故不做等值比对（manifest.mode 仅入报告作参考）。
    size   —— 常规文件字节长度 vs manifest.size（symlink 为目标串字节长）
    sha256 —— 常规文件内容哈希；symlink 按目标字符串哈希（lstat-only，
              绝不跟随——audit_tree 正源语义）

symlink 拒（严格档，与现役 manifest 声明的 evidence 归档 symlink 自洽）：
    - 遍历绝不跟随 symlink（os.walk followlinks=False + 逐实体 lstat）；
    - 哈希打开用 O_NOFOLLOW——lstat 与 open 之间被换 symlink 的竞态也会
      被拒（ELOOP → type_mismatch）；
    - manifest 声明 file 的位置出现 symlink → type_mismatch（拒冒充）；
    - manifest 外的 symlink → extra（拒清单外实体）；
    - manifest 声明的 symlink 按目标串哈希对账（目标漂移 → drifted）。

退出码（三态）：
    0 = clean（七桶全空）
    1 = drift（extra/missing/drifted/mode_drifted/type_mismatch/special/
              broken 任一非空）
    3 = input 错（参数错、树缺失/非目录/不可遍历、manifest 缺失/不可读/
      schema 无效/条目歧义、对账无法完成——fail-closed，绝不把「没验成」
      当 clean 或 drift）

用法：
    python3 tools/verify_tree.py <release_dir|tree_dir> [--manifest PATH]
                                 [--json PATH] [-q]

    --json PATH  追加机器可读报告（含全部桶 + checked + exit_code）
    -q           只输出结论行

输出示例（人类面）：
    verify_tree: CLEAN checked=3157 tree=/path/to/tree
    verify_tree: DRIFT checked=3156 drifted=1 missing=0 extra=0
                  mode_drifted=0 type_mismatch=0 special=0 broken=0
"""
from __future__ import annotations

import argparse
import errno
import fnmatch
import hashlib
import json
import os
import re
import stat as _stat
import sys
from typing import Any, Dict, List, Optional, Tuple

__version__ = "1.0.0-w12-01"

EXIT_CLEAN = 0
EXIT_DRIFT = 1
EXIT_INPUT = 3

_RC_HELP = "exit: 0=clean 1=drift 3=input error"

_MANIFEST_GLOB = "wenqu-dist-*.manifest.json"
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_TYPES = frozenset({"file", "symlink", "dir"})

_REPORT_BUCKETS = ("missing", "extra", "drifted", "mode_drifted",
                   "type_mismatch", "special", "broken")


class InputError(Exception):
    """rc3：输入/对账前提错误（fail-closed，非漂移判定）。"""


# ---------------------------------------------------------------------- #
# 输入解析：release 根 / tree 目录 / 显式 manifest
# ---------------------------------------------------------------------- #
def _find_manifests(dirpath: str) -> List[str]:
    try:
        names = os.listdir(dirpath)
    except OSError as exc:
        raise InputError(f"manifest_dir_unlistable:{dirpath}:{exc}") from exc
    return sorted(os.path.join(dirpath, n) for n in names
                  if fnmatch.fnmatch(n, _MANIFEST_GLOB))


def resolve_input(target: str, manifest_opt: Optional[str]
                  ) -> Tuple[str, str]:
    """输入 → (tree_dir, manifest_path)。结构歧义/缺失 → InputError。

    顶层输入按操作者实参解析（realpath 一次——支持传 ``~/.wenqu/current``
    这类激活 symlink）；树**内部**的 symlink 绝不跟随（iter_tree_entries
    lstat-only 契约不受影响）。
    """
    tree = os.path.realpath(target)
    try:
        st = os.stat(tree)  # 顶层输入按操作者实参解析（跟随一次）
    except FileNotFoundError:
        raise InputError(f"tree_missing:{tree}") from None
    except OSError as exc:
        raise InputError(f"tree_unstatable:{tree}:{exc}") from None
    if not _stat.S_ISDIR(st.st_mode):
        raise InputError(f"tree_not_dir:{tree}")

    if manifest_opt:
        if not os.path.isfile(manifest_opt):
            raise InputError(f"manifest_missing:{manifest_opt}")
        return tree, os.path.abspath(manifest_opt)

    # 布局一：release 根（含 tree/ 子目录 + 四件套 manifest）
    inner = os.path.join(tree, "tree")
    if os.path.isdir(inner) and not os.path.islink(inner):
        manifests = _find_manifests(tree)
        if len(manifests) != 1:
            raise InputError(
                f"manifest_not_unique:{len(manifests)} in {tree}")
        return inner, manifests[0]

    # 布局二：tree 目录本身（manifest 在父目录——install 链布局）
    parent = os.path.dirname(tree)
    manifests = _find_manifests(parent) if parent else []
    if len(manifests) != 1:
        raise InputError(f"manifest_not_unique:{len(manifests)} in {parent}")
    return tree, manifests[0]


# ---------------------------------------------------------------------- #
# manifest 装载与 schema 校验（加严：结构错=rc3，不是让对账面兜底）
# ---------------------------------------------------------------------- #
def load_manifest(manifest_path: str) -> Dict[str, Dict[str, Any]]:
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except OSError as exc:
        raise InputError(f"manifest_unreadable:{manifest_path}:{exc}") from exc
    except ValueError as exc:
        raise InputError(f"manifest_invalid_json:{exc}") from None
    if not isinstance(manifest, dict):
        raise InputError("manifest_invalid:top_level_not_object")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise InputError("manifest_invalid:files_empty_or_not_list")

    expected: Dict[str, Dict[str, Any]] = {}
    for idx, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise InputError(f"manifest_invalid:entry[{idx}]_not_object")
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            raise InputError(f"manifest_invalid:entry[{idx}]_path_not_str")
        if path.startswith("/") or ".." in path.split(os.sep) \
                or "\\" in path:
            raise InputError(f"manifest_invalid:unsafe_path:{path!r}")
        if path in expected:
            raise InputError(f"manifest_invalid:duplicate_path:{path!r}")
        etype = entry.get("type")
        if etype not in _ALLOWED_TYPES:
            raise InputError(
                f"manifest_invalid:entry[{idx}]_type:{etype!r}")
        if etype in ("file", "symlink"):
            sha = entry.get("sha256")
            if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
                raise InputError(
                    f"manifest_invalid:entry[{idx}]_sha256:{path!r}")
            size = entry.get("size")
            if not isinstance(size, int) or isinstance(size, bool) \
                    or size < 0:
                raise InputError(
                    f"manifest_invalid:entry[{idx}]_size:{path!r}")
        if not isinstance(entry.get("mode"), int) \
                or isinstance(entry.get("mode"), bool):
            raise InputError(
                f"manifest_invalid:entry[{idx}]_mode:{path!r}")
        expected[path] = entry
    return expected


# ---------------------------------------------------------------------- #
# 树遍历（lstat-only，绝不跟随 symlink）
# ---------------------------------------------------------------------- #
def _hash_file_nofollow(full: str) -> Tuple[str, int]:
    """O_NOFOLLOW 打开并流式哈希；被换 symlink → (ELOOP) type 竞态信号。

    返回 (sha256, size)。open 层拒跟 symlink：lstat 是 file、open 时已被
    换成 symlink 的 TOCTOU 在此闭合（ELOOP → 上抛按 type_mismatch 记）。
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
        | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(full, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise _SymlinkRace(full) from None
        raise InputError(f"file_unopenable:{full}:{exc}") from None
    h = hashlib.sha256()
    size = 0
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            raise _SymlinkRace(full)  # 打开瞬间已不是常规文件
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    finally:
        os.close(fd)
    return h.hexdigest(), size


class _SymlinkRace(Exception):
    """lstat→open 窗口内被换成非常规文件（含 symlink）。"""


def iter_tree_entries(tree: str
                      ) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """遍历树 → {relpath: entry}；不可 lstat 的路径收集为 broken。

    遍历本身不可读（目录无 r/x 位）→ InputError（rc3：对账无法完成，
    fail-closed——绝不静默当「树干净」，也绝不误报漂移）。
    """
    entries: Dict[str, Dict[str, Any]] = {}
    broken: List[str] = []
    for dirpath, dirnames, filenames in os.walk(
            tree, followlinks=False,
            onerror=lambda e: (_ for _ in ()).throw(
                InputError(f"tree_unwalkable:{getattr(e, 'filename', '')}"
                           f":{e}"))):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, tree)
            try:
                st = os.lstat(full)
            except OSError:
                broken.append(rel)
                continue
            if _stat.S_ISLNK(st.st_mode):
                # symlink：lstat-only 记录目标串，绝不跟随
                target = os.readlink(full)
                raw = target.encode("utf-8")
                entries[rel] = {
                    "type": "symlink", "link": target,
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            elif _stat.S_ISDIR(st.st_mode):
                entries[rel] = {"type": "dir",
                                "mode": _stat.S_IMODE(st.st_mode)}
            elif _stat.S_ISREG(st.st_mode):
                entries[rel] = {"type": "file",
                                "mode": _stat.S_IMODE(st.st_mode)}
                # sha/size 延迟到对账命中才算（extra 文件不必哈希）
            else:  # FIFO/socket/device——发行树契约外实体
                entries[rel] = {"type": "special",
                                "mode": _stat.S_IMODE(st.st_mode)}
    return entries, broken


# ---------------------------------------------------------------------- #
# 对账（audit_tree 语义 + size 维度 + O_NOFOLLOW 哈希）
# ---------------------------------------------------------------------- #
def verify_tree(tree_dir: str, manifest_path: str) -> Dict[str, Any]:
    tree = os.path.abspath(tree_dir)
    report: Dict[str, Any] = {
        "tool": f"verify_tree-{__version__}",
        "tree_dir": tree, "manifest_path": os.path.abspath(manifest_path),
        "ok": False, "checked": 0,
        **{k: [] for k in _REPORT_BUCKETS},
        "size_drifted": [],
        "reason": None,
    }

    expected = load_manifest(manifest_path)
    actual, broken = iter_tree_entries(tree)
    report["broken"] = sorted(broken)

    for rel in sorted(actual):
        ent = actual[rel]
        if rel not in expected:
            # 目录蕴含（manifest 只记文件/symlink）不算 extra
            if ent["type"] != "dir":
                report["extra"].append(rel)
            continue
        want = expected[rel]
        want_type = want.get("type", "file")
        if want_type != ent["type"]:
            report["type_mismatch"].append(rel)
            continue
        report["checked"] += 1
        if want_type == "file":
            try:
                sha, size = _hash_file_nofollow(os.path.join(tree, rel))
            except _SymlinkRace:
                report["type_mismatch"].append(rel)
                continue
            ent["sha256"], ent["size"] = sha, size
            if want.get("sha256") != sha:
                report["drifted"].append(rel)
            elif want.get("size") != size:  # size 维度（sha 同 size 必同，
                # 独立入账防 manifest 自洽造假/字段漂移）
                report["size_drifted"].append(rel)
        elif want_type == "symlink":
            if want.get("sha256") != ent["sha256"]:
                report["drifted"].append(rel)
            elif want.get("size") != ent["size"]:
                report["size_drifted"].append(rel)
    report["missing"] = sorted(set(expected) - set(actual))

    # 可写位不变量：树内任何常规文件/目录不得含写位（symlink 的 lstat
    # mode 平台不可控——chmod 不作用于 Linux symlink，与 audit_tree 同豁免）
    for rel in sorted(actual):
        mode = actual[rel].get("mode")
        if mode is not None and (mode & 0o222):
            report["mode_drifted"].append(rel)

    report["special"] = sorted(rel for rel, e in actual.items()
                               if e["type"] == "special")
    for k in ("extra", "drifted", "mode_drifted", "type_mismatch"):
        report[k] = sorted(set(report[k]))
    report["ok"] = not any(report[k] for k in _REPORT_BUCKETS) \
        and not report["size_drifted"]
    return report


# ---------------------------------------------------------------------- #
# CLI
# ---------------------------------------------------------------------- #
class _ArgParser(argparse.ArgumentParser):
    def error(self, message: str):  # 参数错也归三态 rc3
        self.print_usage(sys.stderr)
        sys.stderr.write(f"verify_tree: error: {message}\n{_RC_HELP}\n")
        raise SystemExit(EXIT_INPUT)


def _emit(report: Dict[str, Any], *, quiet: bool, json_path: Optional[str],
          exit_code: int) -> None:
    counts = {k: len(report[k]) for k in _REPORT_BUCKETS}
    counts["size_drifted"] = len(report["size_drifted"])
    if json_path:
        out = dict(report)
        out["exit_code"] = exit_code
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
    if quiet:
        return
    if report["ok"]:
        print(f"verify_tree: CLEAN checked={report['checked']} "
              f"tree={report['tree_dir']}")
        return
    drift_part = " ".join(f"{k}={v}" for k, v in counts.items() if v)
    print(f"verify_tree: DRIFT checked={report['checked']} {drift_part}")
    shown: Dict[str, int] = {k: v for k, v in counts.items() if v}
    for k, v in shown.items():
        paths = report[k if k in report else "size_drifted"][:5]
        more = f" (+{v - 5} more)" if v > 5 else ""
        print(f"  {k}: {paths}{more}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = _ArgParser(
        prog="verify_tree.py",
        description="独立严格全树 release verifier（W12-01）：逐文件 "
                    "path/type/mode/size/sha256 对账 manifest；"
                    "symlink 绝不跟随（lstat-only + O_NOFOLLOW）。")
    parser.add_argument("target", help="release 根或 tree 目录")
    parser.add_argument("--manifest", help="显式 manifest 路径（默认："
                        "release 根/tree 父目录唯一 wenqu-dist-*.manifest.json）")
    parser.add_argument("--json", help="机器可读报告输出路径")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="只输出结论行")
    args = parser.parse_args(argv)

    try:
        tree, manifest = resolve_input(args.target, args.manifest)
        report = verify_tree(tree, manifest)
    except InputError as exc:
        print(f"verify_tree: INPUT-ERROR {exc}", file=sys.stderr)
        print(_RC_HELP, file=sys.stderr)
        return EXIT_INPUT
    except Exception as exc:  # noqa: BLE001 - fail-visible，绝不假绿
        print(f"verify_tree: INPUT-ERROR internal:{type(exc).__name__}: {exc}",
              file=sys.stderr)
        return EXIT_INPUT

    exit_code = EXIT_CLEAN if report["ok"] else EXIT_DRIFT
    try:
        _emit(report, quiet=args.quiet, json_path=args.json,
              exit_code=exit_code)
    except OSError as exc:
        print(f"verify_tree: INPUT-ERROR json_write_failed:{exc}",
              file=sys.stderr)
        return EXIT_INPUT
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

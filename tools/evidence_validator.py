#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence 索引严格 validator——G9-07（R8-EVID-FIELDS-013 根修）。

缺陷形态：active evidence 索引允许 ``commit/run_id/real_rc = null + note``
冒充严格字段（"23 条 hash 全实算，但 commit/字段合同未满足"）——
宽松合同使 evidence 分母里混入不可复核条目。

本 validator 是 evidence-index-active-v2 / evidence-index-legacy-v1 两个
schema 的可执行等价物（零第三方依赖；不 import jsonschema——CI 无网/无
依赖也要能跑）：

active 表逐条强制：
  - commit：exact 40 位小写 hex（短 SHA/null/note 替代一律非法）；
  - run_id / cwd / verified_by / environment：非空字符串；
  - argv：非空字符串数组（≥1 条、逐条非空）；
  - real_rc：真实整数退出码（bool 冒充非法；允许非 0——诚实优先）；
  - time：ISO 8601 带时区精确时刻（区间/口语化非法）；
  - fresh_until：非空且合法 ISO 日期/时刻（"长期" 非法——长效证据给显式复审日）；
  - 禁止任何 ``*_note`` 键（null+note 冒充正是缺陷形态）；
  - evidence_path：仓内相对路径（拒绝对路径/..逃逸）、存在、普通文件、
    非 symlink、非空；
  - artifact_sha256：64hex 且等于 evidence_path 内容实算 sha256。

legacy/non_scoring 表：不进 active 分母；逐条要求 migrated_reason 非空
（登记降级缺口）+ entry_id/title + hash/文件存在性复核。

rc：0=全过；1=任何违规（CI/acceptance 红腿）；2=索引结构损坏。

用法：
  python3 tools/evidence_validator.py --root <repo根> \
      [--index evidence/evidence-index.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ACTIVE_SCHEMA_ID = "evidence-index-active-v2"
LEGACY_SCHEMA_ID = "evidence-index-legacy-v1"
SCHEMA_FILES = {
    ACTIVE_SCHEMA_ID: "system/schemas/evidence-index-active-v2.schema.json",
    LEGACY_SCHEMA_ID: "system/schemas/evidence-index-legacy-v1.schema.json",
}

_RE_ENTRY_ID = re.compile(r"^EV-[A-Z0-9][A-Z0-9-]*$")
_RE_COMMIT40 = re.compile(r"^[0-9a-f]{40}$")
_RE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RE_TIME = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(\.[0-9]+)?(Z|[+-][0-9]{2}:?[0-9]{2})$")
_RE_TTL = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}"
    r"(T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:?[0-9]{2}))?$")

ACTIVE_REQUIRED = ("entry_id", "category", "title", "what", "commit", "run_id",
                   "environment", "argv", "cwd", "real_rc", "time",
                   "artifact_sha256", "evidence_path", "fresh_until",
                   "verified_by")

# 允许的完整字段集（additionalProperties: false 的等价物）
ACTIVE_ALLOWED = set(ACTIVE_REQUIRED) | {"scope", "ruleset", "caveat"}
LEGACY_REQUIRED = ("entry_id", "category", "title", "migrated_reason")
LEGACY_ALLOWED = LEGACY_REQUIRED + tuple(
    "what run_id commit environment scope ruleset time argv real_rc "
    "artifact_sha256 evidence_path fresh_until verified_by caveat "
    "commit_note".split())


class IndexStructError(RuntimeError):
    """索引结构损坏（rc2）。"""


def _is_int_not_bool(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_path(root: Path, rel: Any) -> Tuple[Optional[str], Optional[str]]:
    """返回 (错误, 实算 sha256)。检查：字符串/相对/无 ..、存在、普通文件、
    非 symlink、非空；通过则顺带实算内容哈希。"""
    if not isinstance(rel, str) or not rel:
        return "evidence_path 缺失/非字符串", None
    if rel.startswith("/") or rel.startswith("\\") or os.path.isabs(rel):
        return f"evidence_path 不得为绝对路径: {rel!r}", None
    parts = PurePosixParts(rel)
    if any(p == ".." for p in parts):
        return f"evidence_path 不得含 ..: {rel!r}", None
    target = root / Path(*parts)
    try:
        lst = os.lstat(target)
    except OSError:
        return f"evidence_path 不存在: {rel!r}", None
    if stat.S_ISLNK(lst.st_mode):
        return f"evidence_path 是 symlink（不变量 #11）: {rel!r}", None
    if not stat.S_ISREG(lst.st_mode):
        return f"evidence_path 不是普通文件: {rel!r}", None
    if lst.st_size == 0:
        return f"evidence_path 是空文件: {rel!r}", None
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return None, digest


def PurePosixParts(rel: str) -> List[str]:
    return [p for p in rel.replace("\\", "/").split("/") if p]


def validate_active_entry(root: Path, entry: Dict[str, Any],
                          idx: int) -> List[str]:
    errs: List[str] = []
    tag = f"active[{idx}] {entry.get('entry_id', '<无 entry_id>')}"
    for field in ACTIVE_REQUIRED:
        if field not in entry or entry[field] is None:
            errs.append(f"{tag}: 必填字段 {field} 缺失/为 null（null+note 冒充严格字段被禁止）")
    extra = set(entry) - ACTIVE_ALLOWED
    if extra:
        errs.append(f"{tag}: 未知字段 {sorted(extra)}（additionalProperties false）")
    note_keys = sorted(k for k in entry if k.endswith("_note"))
    if note_keys:
        errs.append(f"{tag}: 禁止 *_note 冒充键 {note_keys}（R8-EVID-FIELDS-013 缺陷形态）")
    if not _RE_ENTRY_ID.match(str(entry.get("entry_id", ""))):
        errs.append(f"{tag}: entry_id 形态非法")
    commit = entry.get("commit")
    if isinstance(commit, str) and not _RE_COMMIT40.match(commit):
        errs.append(f"{tag}: commit 非 exact 40 位小写 hex: {commit!r}")
    run_id = entry.get("run_id")
    if run_id is not None and (not isinstance(run_id, str) or not run_id.strip()):
        errs.append(f"{tag}: run_id 非空字符串违规")
    cwd_v = entry.get("cwd")
    if cwd_v is not None and (not isinstance(cwd_v, str) or not cwd_v.strip()):
        errs.append(f"{tag}: cwd 非空字符串违规")
    argv = entry.get("argv")
    if argv is not None:
        if not isinstance(argv, list) or not argv:
            errs.append(f"{tag}: argv 须为非空数组")
        elif any(not isinstance(a, str) or not a.strip() for a in argv):
            errs.append(f"{tag}: argv 含空串/非字符串项")
    real_rc = entry.get("real_rc")
    if real_rc is not None and not _is_int_not_bool(real_rc):
        errs.append(f"{tag}: real_rc 须为整数退出码（bool/字符串冒充非法）: {real_rc!r}")
    time_v = entry.get("time")
    if isinstance(time_v, str) and not _RE_TIME.match(time_v):
        errs.append(f"{tag}: time 非合法 ISO 8601 带时区时刻: {time_v!r}")
    ttl = entry.get("fresh_until")
    if isinstance(ttl, str) and not _RE_TTL.match(ttl):
        errs.append(f"{tag}: fresh_until(TTL) 非空合法 ISO 日期/时刻违规: {ttl!r}")
    for str_field in ("category", "title", "what", "environment", "verified_by"):
        v = entry.get(str_field)
        if v is not None and (not isinstance(v, str) or not v.strip()):
            errs.append(f"{tag}: {str_field} 非空字符串违规")
    sha = entry.get("artifact_sha256")
    if isinstance(sha, str) and not _RE_SHA256.match(sha):
        errs.append(f"{tag}: artifact_sha256 非 64hex: {sha!r}")
    perr, actual = _check_path(root, entry.get("evidence_path"))
    if perr:
        errs.append(f"{tag}: {perr}")
    elif actual is not None and sha != actual:
        errs.append(f"{tag}: artifact_sha256 与实算不符（登记 {sha!r} ≠ 实算 {actual!r}）")
    return errs


def validate_legacy_entry(root: Path, entry: Dict[str, Any],
                          idx: int) -> List[str]:
    errs: List[str] = []
    tag = f"legacy[{idx}] {entry.get('entry_id', '<无 entry_id>')}"
    for field in LEGACY_REQUIRED:
        v = entry.get(field)
        if not isinstance(v, str) or not v.strip():
            errs.append(f"{tag}: 必填 {field} 缺失/空（legacy 也要登记降级缺口）")
    extra = set(entry) - set(LEGACY_ALLOWED)
    if extra:
        errs.append(f"{tag}: 未知字段 {sorted(extra)}")
    sha = entry.get("artifact_sha256")
    if isinstance(sha, str) and not _RE_SHA256.match(sha):
        errs.append(f"{tag}: artifact_sha256 非 64hex: {sha!r}")
    perr, actual = _check_path(root, entry.get("evidence_path"))
    if perr:
        errs.append(f"{tag}: {perr}")
    elif actual is not None and sha != actual:
        errs.append(f"{tag}: artifact_sha256 与实算不符（历史文件损坏也要红）")
    return errs


def run(root: Path, index_rel: str) -> int:
    index_path = root / index_rel
    try:
        doc = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"❌ 索引不可读: {index_path}: {exc}")
        return 2
    if not isinstance(doc, dict):
        raise IndexStructError("索引顶层须为对象")
    # v1 单表兼容腿：旧索引（无 active/legacy_non_scoring 分表但有 entries）
    # 一律按 active 严格合同整表校验——旧宽松条目（null+note/口语化 TTL）
    # 必须以「违规清单」形式红（rc1），而不是结构错误蒙混。
    if "active" not in doc and "legacy_non_scoring" not in doc \
            and isinstance(doc.get("entries"), list):
        print("⚠ 检测到 v1 单表索引——全部条目按 active 严格合同校验"
              "（G9-07 迁移前状态必须红）")
        errs: List[str] = []
        for i, entry in enumerate(doc["entries"]):
            if not isinstance(entry, dict):
                raise IndexStructError(f"entries[{i}] 非对象")
            errs.extend(validate_active_entry(root, entry, i))
        if errs:
            print(f"❌ evidence validator 失败——{len(errs)} 处违规（v1 宽松条目不满足严格合同）:")
            for e in errs:
                print(f"   - {e}")
            return 1
        print("✅ v1 索引条目全部满足严格合同（无需迁移）")
        return 0
    for key in ("index_version", "active", "legacy_non_scoring"):
        if key not in doc:
            raise IndexStructError(f"索引缺顶层键 {key!r}（v2 分表结构）")
    active_tbl, legacy_tbl = doc["active"], doc["legacy_non_scoring"]
    for name, tbl, want in (("active", active_tbl, ACTIVE_SCHEMA_ID),
                            ("legacy_non_scoring", legacy_tbl, LEGACY_SCHEMA_ID)):
        if not isinstance(tbl, dict) or tbl.get("schema") != want:
            raise IndexStructError(f"{name} 表缺 schema={want!r} 标识")
        if not isinstance(tbl.get("entries"), list):
            raise IndexStructError(f"{name} 表缺 entries 数组")
        schema_file = root / SCHEMA_FILES[want]
        try:
            json.loads(schema_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise IndexStructError(f"schema 文件不可读/损坏: {schema_file}: {exc}")

    errs: List[str] = []
    seen_ids: set = set()
    for i, entry in enumerate(active_tbl["entries"]):
        if not isinstance(entry, dict):
            raise IndexStructError(f"active[{i}] 非对象")
        eid = entry.get("entry_id")
        if eid in seen_ids:
            errs.append(f"active[{i}]: entry_id 重复 {eid!r}")
        seen_ids.add(eid)
        errs.extend(validate_active_entry(root, entry, i))
    for i, entry in enumerate(legacy_tbl["entries"]):
        if not isinstance(entry, dict):
            raise IndexStructError(f"legacy[{i}] 非对象")
        eid = entry.get("entry_id")
        if eid in seen_ids:
            errs.append(f"legacy[{i}]: entry_id 重复 {eid!r}")
        seen_ids.add(eid)
        errs.extend(validate_legacy_entry(root, entry, i))

    n_active = len(active_tbl["entries"])
    n_legacy = len(legacy_tbl["entries"])
    print(f"evidence 索引校验：active={n_active}（严格分母） "
          f"legacy/non_scoring={n_legacy}（不计分）")
    if errs:
        print(f"❌ evidence validator 失败——{len(errs)} 处违规:")
        for e in errs:
            print(f"   - {e}")
        return 1
    print("✅ evidence validator 通过（active 全严格字段+实算 hash+普通文件+合法 TTL）")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Evidence 索引严格 validator（R8-EVID-FIELDS-013）")
    ap.add_argument("--root", required=True, help="repo 根目录（wenqu-dist）")
    ap.add_argument("--index", default="evidence/evidence-index.json",
                    help="索引文件相对路径（默认 evidence/evidence-index.json）")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"❌ --root 不存在: {root}")
        return 2
    try:
        return run(root, args.index)
    except IndexStructError as exc:
        print(f"❌ 索引结构损坏: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())

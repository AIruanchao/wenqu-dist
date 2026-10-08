#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""codeowners-ruleset-doctor——CI-06 诊断件（§20.5：CODEOWNERS/ruleset 一致性）。

语义（逐字对齐 Codex 方案 §20.5 CI-06）：
  注入：CODEOWNERS 文件存在但 ruleset 未强制（review）；
  期望：doctor ERROR。

判定规则（fail-closed——「没有强制证据」即「未强制」，不猜、不放行）：
  1. 仓内任一 GitHub 约定位置存在 CODEOWNERS（仓根/.github//docs/），
     且不存在「对默认分支生效的 active review 强制」→ ERROR。
     「未强制」覆盖：零 ruleset；enforcement=disabled/evaluate（evaluate 是
     干跑不拦）；ruleset 无 pull_request 规则；pull_request 规则
     required_approving_review_count=0 且 require_code_owner_review=false；
     ruleset 分支目标不含默认分支（含排除默认分支）。
  2. 无 CODEOWNERS → PASS（本检查不适用；绝不 ERROR——注入前提不存在）。
  3. 强制证据二选一（先 rulesets 后老式 branch protection）：
     a. active ruleset 目标含默认分支且 pull_request 规则
        required_approving_review_count>=1 或 require_code_owner_review=true；
     b. /branches/{b}/protection 的 required_pull_request_reviews.
        required_approving_review_count>=1（老式分支保护等价强制）。

证据输入（--ruleset-file，缺省再读 --repo/.github/rulesets/*.json）：
  GitHub REST /repos/{o}/{r}/rulesets 返回的数组（或单对象/{"rulesets":[…]}），
  或 /branches/{b}/protection 对象——与 evidence/08-ci-and-branch-rules/
  回读件同构；本地 fixture 用同一形状模拟「未强制/已强制」两种状态。

用法：
  python3 system/bin/codeowners-ruleset-doctor.py --repo . \
      [--ruleset-file rulesets.json] [--default-branch main] [--json OUT.json]
exit 0=PASS；1=ERROR（对齐 hardening-doctor：任一红 exit 1，可接值班巡检）。
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

__version__ = "1.0.0"

CHECK_ID = "CI-06"

#: GitHub 官方 CODEOWNERS 约定位置（相对仓根）。
CODEOWNERS_LOCATIONS: Tuple[str, ...] = (
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
    ".github/docs/CODEOWNERS",
)

#: 仓内声明式 ruleset fixture 目录（缺省证据源之一）。
RULESET_FIXTURE_DIR = Path(".github") / "rulesets"


def find_codeowners(repo: Path) -> List[Path]:
    """返回仓内实际存在的 CODEOWNERS 文件（约定位置，按序）。"""
    return [repo / rel for rel in CODEOWNERS_LOCATIONS
            if (repo / rel).is_file()]


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pattern_matches_branch(pattern: str, branch: str) -> bool:
    """ruleset ref_name 模式对分支的命中（glob，支持 ~DEFAULT_BRANCH 专属token）。

    GitHub 语义：include/exclude 用完整 ref glob（refs/heads/<branch>）；
    `~DEFAULT_BRANCH` 是默认分支专属 token。宽松兼容裸分支名/前缀 glob。
    """
    if not isinstance(pattern, str) or not pattern:
        return False
    full_ref = f"refs/heads/{branch}"
    if pattern == "~DEFAULT_BRANCH":
        return True
    return fnmatch.fnmatch(full_ref, pattern) or fnmatch.fnmatch(branch, pattern)


def _ruleset_targets_branch(ruleset: Mapping[str, Any], branch: str) -> bool:
    """active ruleset 的 ref_name 条件是否覆盖默认分支（exclude 优先）。"""
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, Mapping):
        return True  # 无条件 = 对全部分支生效
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, Mapping):
        return True
    for pattern in ref_name.get("exclude") or ():
        if _pattern_matches_branch(pattern, branch):
            return False  # 显式排除默认分支 = 未覆盖
    include = ref_name.get("include") or []
    if not include:
        return True  # 空 include = 全分支
    return any(_pattern_matches_branch(p, branch) for p in include)


def _pull_request_rule_enforces_review(rule: Mapping[str, Any]) -> bool:
    """pull_request 规则是否强制 review（批准数>=1 或要求 code owner 审阅）。"""
    params = rule.get("parameters")
    if not isinstance(params, Mapping):
        return False
    count = params.get("required_approving_review_count", 0)
    if _is_int(count) and count >= 1:
        return True
    if params.get("require_code_owner_review") is True:
        return True  # 与 CODEOWNERS 语义最紧的强制
    return False


def is_review_enforced(
    rulesets: Optional[Sequence[Any]], default_branch: str = "main"
) -> Optional[Dict[str, Any]]:
    """在 rulesets 证据里找「对默认分支生效的 active review 强制」。

    返回强制证据（dict）；找不到返回 None（=未强制，fail-closed）。
    非对象条目跳过不采信（畸形证据不折算为强制）。
    """
    for ruleset in rulesets or ():
        if not isinstance(ruleset, Mapping):
            continue
        if str(ruleset.get("enforcement", "")).strip().lower() != "active":
            continue  # disabled / evaluate（干跑）/ 缺失 = 未强制
        if not _ruleset_targets_branch(ruleset, default_branch):
            continue
        rules = ruleset.get("rules")
        if not isinstance(rules, Sequence):
            continue
        for rule in rules:
            if not isinstance(rule, Mapping):
                continue
            if rule.get("type") == "pull_request" and _pull_request_rule_enforces_review(rule):
                return {
                    "kind": "ruleset",
                    "ruleset_name": ruleset.get("name"),
                    "ruleset_id": ruleset.get("id"),
                    "rule": "pull_request",
                }
    return None


def is_review_enforced_by_branch_protection(
    protection: Optional[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    """老式分支保护等价强制：required_pull_request_reviews 批准数>=1。"""
    if not isinstance(protection, Mapping):
        return None
    rpr = protection.get("required_pull_request_reviews")
    if isinstance(rpr, Mapping):
        count = rpr.get("required_approving_review_count", 0)
        if _is_int(count) and count >= 1:
            return {
                "kind": "branch_protection",
                "rule": "required_pull_request_reviews",
                "required_approving_review_count": count,
            }
    return None


def check(
    repo_path: str | Path,
    *,
    rulesets: Optional[Sequence[Any]] = None,
    branch_protection: Optional[Mapping[str, Any]] = None,
    default_branch: str = "main",
) -> Dict[str, Any]:
    """CI-06 主判定：CODEOWNERS 存在但 ruleset 未强制 review → ERROR。

    返回 doctor 报告 dict：{check, repo, default_branch, codeowners_found,
    review_enforced_by, findings, status}；status 只有 PASS/ERROR 两态。
    """
    repo = Path(repo_path)
    owners = find_codeowners(repo)
    enforced = (
        is_review_enforced(rulesets, default_branch)
        or is_review_enforced_by_branch_protection(branch_protection)
    )
    findings: List[str] = []
    if not owners:
        status = "PASS"
        findings.append(
            "no CODEOWNERS under convention locations "
            f"({', '.join(CODEOWNERS_LOCATIONS)}) — CI-06 not applicable"
        )
    elif enforced:
        status = "PASS"
        findings.append(
            f"CODEOWNERS ({owners[0].relative_to(repo) if repo in owners[0].parents else owners[0]}) "
            f"backed by enforced review via {enforced['kind']}"
        )
    else:
        status = "ERROR"
        findings.append(
            "CODEOWNERS exists but NO active ruleset enforces review on "
            f"default branch {default_branch!r} (zero/disabled/evaluate ruleset, "
            "no pull_request rule, review count 0, or branch not covered) — "
            "CODEOWNERS without enforcement is decoration, not protection (CI-06)"
        )
    return {
        "check": CHECK_ID,
        "doctor": "codeowners-ruleset-doctor",
        "version": __version__,
        "repo": str(repo),
        "default_branch": default_branch,
        "codeowners_found": [str(p) for p in owners],
        "review_enforced_by": enforced,
        "rulesets_examined": len(list(rulesets)) if rulesets is not None else 0,
        "findings": findings,
        "status": status,
    }


def load_ruleset_evidence(
    path: str | Path,
) -> Tuple[List[Any], Optional[Mapping[str, Any]]]:
    """读 ruleset 证据文件（--ruleset-file）。

    接受形状：rulesets 数组 / 单 ruleset 对象 / {"rulesets": [...]} /
    {"branch_protection": {...}} / 老式 branch protection 对象（凭
    required_pull_request_reviews 或 url 特征识别）。
    返回 (rulesets, branch_protection)。
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rulesets: List[Any] = []
    protection: Optional[Mapping[str, Any]] = None
    if isinstance(data, Mapping):
        if isinstance(data.get("rulesets"), list):
            rulesets = list(data["rulesets"])
            if isinstance(data.get("branch_protection"), Mapping):
                protection = data["branch_protection"]
        elif "required_pull_request_reviews" in data or "required_status_checks" in data \
                or str(data.get("url", "")).endswith("/protection"):
            protection = data  # 老式分支保护对象
        else:
            rulesets = [data]  # 单个 ruleset 对象
    elif isinstance(data, list):
        rulesets = data
    else:
        raise ValueError(
            f"ruleset evidence must be a JSON array/object, got {type(data).__name__}"
        )
    return rulesets, protection


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="CI-06 doctor: CODEOWNERS present but ruleset not enforced → ERROR"
    )
    parser.add_argument("--repo", default=".", help="仓库根目录（缺省当前目录）")
    parser.add_argument(
        "--ruleset-file", default=None,
        help="ruleset 证据 JSON（GitHub /rulesets 数组或 /branches/*/protection 对象）；"
             "缺省时读 <repo>/.github/rulesets/*.json fixture",
    )
    parser.add_argument("--default-branch", default="main")
    parser.add_argument("--json", default=None, help="报告 JSON 输出路径")
    args = parser.parse_args(argv)

    rulesets: List[Any] = []
    protection: Optional[Mapping[str, Any]] = None
    source_note = "none (fail-closed: no evidence = not enforced)"
    if args.ruleset_file:
        rulesets, protection = load_ruleset_evidence(args.ruleset_file)
        source_note = f"--ruleset-file {args.ruleset_file}"
    else:
        fixture_dir = Path(args.repo) / RULESET_FIXTURE_DIR
        if fixture_dir.is_dir():
            for fixture in sorted(fixture_dir.glob("*.json")):
                try:
                    r, p = load_ruleset_evidence(fixture)
                except (ValueError, json.JSONDecodeError):
                    continue  # 畸形 fixture 不采信（fail-closed 方向）
                rulesets.extend(r)
                protection = protection or p
            source_note = f"{RULESET_FIXTURE_DIR}/*.json fixture"

    report = check(
        args.repo,
        rulesets=rulesets,
        branch_protection=protection,
        default_branch=args.default_branch,
    )
    report["evidence_source"] = source_note

    print(f"== {CHECK_ID} codeowners-ruleset-doctor v{__version__} ==")
    for finding in report["findings"]:
        marker = "✓" if report["status"] == "PASS" else "✗"
        print(f"  {marker} {finding}")
    if report["status"] == "PASS":
        print(f"== PASS：{CHECK_ID} 一致 ==")
    else:
        print(f"== FAIL：{CHECK_ID} doctor ERROR（上方 ✗ 项处置）==")
    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

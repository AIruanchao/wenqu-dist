#!/usr/bin/env bash
# merge-ci-evidence.sh —— 精确 merge SHA 的 main CI 证据采集（R8-P0-7 残余根修）。
#
# 背景（Codex 第八轮 P0-7/P0-10）：「merge commit 缺精确 main CI」——此前 CI
# 结论用分支/时间窗推断（run 列表≠该 merge SHA 本身的 push run），无法证明
# 合流点在 main 上双平台真跑真绿。本脚本对**指定 SHA** 做精确取证：
#
#   1. git rev-parse 解析完整 SHA（须在本地对象库；merge 身份用 %P 双亲核验）
#   2. `gh run list --branch main --commit <full-sha>` 实查（exact-SHA 匹配，
#      GitHub 只返回 headSha 严格相等的 run——无子串/时间窗推断）
#   3. 只认 event=push 的 run：merge commit 由 push 事件落到 main；PR 事件
#      run 的 head SHA 是分支头（≠ merge SHA），不算 main 精确 CI，但如实
#      记录在 pr_head_runs_excluded 供审计
#   4. `gh run view <id> --json jobs`：逐 job 核验双平台
#      matrix (ubuntu-latest) / matrix (macos-latest)（与 main 分支保护
#      required contexts 同集合）均 status=completed + conclusion=success
#   5. 结论 JSON（含 gh 原始输出）落
#      evidence/08-ci-and-branch-rules/merge-ci-<shortsha>.json
#   6. merge 身份门（R9-INFRA-CI-MERGEKIND-001 根修，九轮基建域新 P1）：
#      父数 >= 2 的 merge commit 才可 PASS；单父/零父 push commit 的语义
#      =「非合并证据目标」→ verdict=NOT_MERGE_COMMIT、rc1（JSON 与判定
#      一致；gh 实查到的 run 原始数据仍如实落档供审计）
#
# 用法：
#   bash tools/merge-ci-evidence.sh <SHA> [--repo DIR] [--branch main]
#        [--out-dir DIR] [--slug OWNER/REPO]
#     <SHA>          目标 commit（merge SHA；短 SHA/分支名可解析即须完整唯一）
#     --repo DIR     源 git 仓（默认脚本所在仓根）
#     --branch BR    目标分支（默认 main）
#     --out-dir DIR  证据目录（默认 <repo>/evidence/08-ci-and-branch-rules）
#     --slug O/R     gh 仓 slug（默认解析 origin remote）
#
# exit：0=verdict PASS（该 SHA 是父数>=2 的 merge commit，且在 main 有
#         push run 且双平台 success）；
#       1=证据不足或非合并目标（NOT_MERGE_COMMIT：父数<2——即使 run 全绿；
#         或无 push run / 非双平台 / 非 success——如实落档）；
#       2=环境/用法错（git/gh 缺失、SHA 解析失败等）。
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEFAULT_REPO=$(cd "$SCRIPT_DIR/.." && pwd)

SHA=""
REPO="$DEFAULT_REPO"
BRANCH="main"
OUT_DIR=""
SLUG=""

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="${2:?--repo 缺参数}"; shift 2;;
    --branch) BRANCH="${2:?--branch 缺参数}"; shift 2;;
    --out-dir) OUT_DIR="${2:?--out-dir 缺参数}"; shift 2;;
    --slug) SLUG="${2:?--slug 缺参数}"; shift 2;;
    -h|--help) sed -n '2,32p' "$0"; exit 0;;
    *) if [ -z "$SHA" ]; then SHA="$1"; shift;
       else echo "merge-ci-evidence: 未知参数 $1" >&2; exit 2; fi;;
  esac
done

[ -n "$SHA" ] || { echo "usage: bash tools/merge-ci-evidence.sh <SHA> [选项]" >&2; exit 2; }
[ -d "$REPO/.git" ] || { echo "merge-ci-evidence: 不是 git 仓: $REPO" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "merge-ci-evidence: git 不可用" >&2; exit 2; }
command -v gh >/dev/null 2>&1 || { echo "merge-ci-evidence: gh 不可用" >&2; exit 2; }

FULL_SHA=$(git -C "$REPO" rev-parse --verify "${SHA}^{commit}" 2>/dev/null) \
  || { echo "merge-ci-evidence: SHA 解析失败: $SHA" >&2; exit 2; }
FULL_SHA=${FULL_SHA%%[[:space:]]*}
SHORT_SHA=$(git -C "$REPO" rev-parse --short=7 "$FULL_SHA")
PARENTS=$(git -C "$REPO" show -s --format=%P "$FULL_SHA")
SUBJECT=$(git -C "$REPO" show -s --format=%s "$FULL_SHA")
IS_MERGE=0
[ "$(printf '%s\n' "$PARENTS" | wc -w | tr -d ' ')" -ge 2 ] && IS_MERGE=1

if [ -z "$SLUG" ]; then
  REMOTE_URL=$(git -C "$REPO" remote get-url origin 2>/dev/null) \
    || { echo "merge-ci-evidence: origin remote 缺失（或用 --slug 指定）" >&2; exit 2; }
  SLUG=$(printf '%s\n' "$REMOTE_URL" \
    | sed -e 's|^git@github.com:||' -e 's|^https://github.com/||' \
          -e 's|^http://github.com/||' -e 's|\.git$||' \
          -e 's|/$||')
  case "$SLUG" in
    */*) : ;;
    *) echo "merge-ci-evidence: 无法从 remote 解析 slug: $REMOTE_URL" >&2; exit 2;;
  esac
fi
[ -n "$OUT_DIR" ] || OUT_DIR="$REPO/evidence/08-ci-and-branch-rules"
mkdir -p "$OUT_DIR"
OUT_JSON="$OUT_DIR/merge-ci-$SHORT_SHA.json"

TD=$(mktemp -d) || exit 2
trap 'rm -rf "$TD"' EXIT

# 1) exact-SHA run 列表（gh --commit 过滤 = headSha 严格相等）
gh run list --repo "$SLUG" --branch "$BRANCH" --commit "$FULL_SHA" \
  --limit 50 --json databaseId,event,headSha,status,conclusion,workflowName,createdAt,updatedAt,url \
  > "$TD/runs.json" \
  || { echo "merge-ci-evidence: gh run list 失败（auth/网络?）" >&2; exit 2; }

# 2) push run 逐个取 jobs 明细
python3 - "$TD/runs.json" "$TD" "$SLUG" "$BRANCH" > "$TD/push_runs.json" <<'PYEOF' || exit 2
import json, subprocess, sys
runs_path, td, slug, branch = sys.argv[1:5]
runs = json.load(open(runs_path, encoding="utf-8"))
push, excluded = [], []
for r in runs:
    if r.get("event") == "push":
        rid = str(r["databaseId"])
        proc = subprocess.run(
            ["gh", "run", "view", rid, "--repo", slug,
             "--json", "databaseId,headSha,event,status,conclusion,jobs"],
            capture_output=True, text=True)
        if proc.returncode != 0:
            r["_jobs_error"] = proc.stderr.strip()[:200]
        else:
            r["_jobs"] = json.loads(proc.stdout).get("jobs", [])
        push.append(r)
    else:
        excluded.append(r)
json.dump({"push_runs": push, "pr_head_runs_excluded": excluded},
          open(f"{td}/split.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print(json.dumps(push))
PYEOF

# 3) 判定 + 落档（required 双平台与 main 分支保护 required contexts 同集合）
python3 - "$TD" "$OUT_JSON" "$SLUG" "$BRANCH" "$FULL_SHA" "$SHORT_SHA" \
          "$PARENTS" "$SUBJECT" "$IS_MERGE" <<'PYEOF'
import json, os, sys, datetime
(td, out_json, slug, branch, full_sha, short_sha, parents, subject, is_merge) = \
    sys.argv[1:10]
split = json.load(open(f"{td}/split.json", encoding="utf-8"))
runs_raw = json.load(open(f"{td}/runs.json", encoding="utf-8"))
REQUIRED = ["matrix (ubuntu-latest)", "matrix (macos-latest)"]

push_runs = split["push_runs"]
verdict, reason = "FAIL", ""
primary = None
is_merge_flag = bool(int(is_merge))
if not is_merge_flag:
    # R9-INFRA-CI-MERGEKIND-001：父数<2 的 commit 不是「合并提交精确双平台
    # CI」证据目标——即使 main 上有全绿 push run 也不得 PASS（run 原始数据
    # 仍落档，供审计复核）
    verdict = "NOT_MERGE_COMMIT"
    reason = (f"commit {short_sha} 父数={len(parents.split())}"
              f"（is_merge_commit=false）：非合并证据目标，仅父数>=2 的 "
              f"merge commit 可判 PASS；其 push run 是否全绿不构成本工具证据")
elif not push_runs:
    verdict = "INSUFFICIENT"
    reason = (f"--branch {branch} --commit {full_sha} 无 event=push run："
              f"该 SHA 未以 push 事件落到 {branch}（exact-SHA 实查，非推断）")
else:
    good = []
    for r in push_runs:
        jobs = {(j.get("name"), j.get("status"), j.get("conclusion"))
                for j in r.get("_jobs", [])}
        ok = (r.get("status") == "completed"
              and r.get("conclusion") == "success"
              and all((n, "completed", "success") in jobs for n in REQUIRED))
        r["_verdict"] = "PASS" if ok else "FAIL"
        if ok:
            good.append(r)
    if good:
        primary = max(good, key=lambda r: r.get("createdAt", ""))
        verdict = "PASS"
        reason = (f"run {primary['databaseId']}（event=push，headSha={full_sha}）"
                  f"双平台 {'/'.join(REQUIRED)} 均 completed/success")
    else:
        verdict = "FAIL"
        reason = f"有 push run 但不满足双平台 success：{len(push_runs)} 个 push run 均未全绿"

payload = {
    "schema": "wenqu-merge-ci-evidence/1",
    "collected_at": datetime.datetime.now(datetime.timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%SZ"),
    "tool": "tools/merge-ci-evidence.sh",
    "method": ("gh run list --repo {slug} --branch {branch} --commit <full-sha>"
               "（exact-SHA 严格相等匹配，无子串/时间窗推断）+ event=push 过滤"
               "+ gh run view --json jobs 双平台逐 job 核验").format(
                   slug=slug, branch=branch),
    "repo": slug,
    "branch": branch,
    "commit": full_sha,
    "commit_short": short_sha,
    "commit_subject": subject,
    "commit_parents": parents.split(),
    "is_merge_commit": bool(int(is_merge)),
    "required_matrix_jobs": REQUIRED,
    "gh_run_list_raw": runs_raw,
    "push_runs": push_runs,
    "pr_head_runs_excluded": split["pr_head_runs_excluded"],
    "primary_run": primary,
    "verdict": verdict,
    "verdict_reason": reason,
    "urls": sorted({r.get("url") for r in push_runs if r.get("url")}),
}
with open(out_json, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=1, sort_keys=True)
    fh.write("\n")
print(f"merge-ci-evidence: {verdict}  {short_sha}  →  {out_json}")
print(f"  {reason}")
sys.exit(0 if verdict == "PASS" else 1)
PYEOF

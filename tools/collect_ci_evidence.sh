#!/usr/bin/env bash
# collect_ci_evidence.sh —— exact-SHA CI 与实时分支规则存证采集器（W12-09/S12）。
#
# 背景（W12-09）：merge-ci-evidence.sh 解决「merge SHA 的 main CI 精确结论」，
# 但原始 API 证据（run/jobs/check-runs/branch-rules 四类原始 JSON）散落不齐、
# 且落在仓内（evidence/08）会被后续提交改动——「实时规则存证」要求取证时点
# 的分支保护/ruleset 原文与 CI 原始回包**固化在仓外证据根**。本工具对指定
# SHA 一次采齐四类原始证据并给出机器可判结论：
#
#   1. git rev-parse 解析完整 SHA（须在本地对象库；%P 双亲/%s 主题一并落档）
#   2. `gh api` 直调（不用 gh run list 转述，保原始回包）：
#      a. GET /repos/{slug}/actions/runs?head_sha=<full>        → runs.json
#         （head_sha 过滤 = headSha 严格相等，exact-SHA，无子串/时间窗推断）
#      b. GET /repos/{slug}/actions/runs/{id}/jobs（每个 push run）→ run-<id>-jobs.json
#      c. GET /repos/{slug}/commits/<full>/check-runs           → check-runs.json
#      d. GET /repos/{slug}/rules/branches/<branch>             → branch-rules-rulesets.json
#         GET /repos/{slug}/branches/<branch>/protection        → branch-protection-classic.json
#         （404 容忍：ruleset 化仓库 classic 端点可无保护配置，如实落档）
#   3. 脱敏（redaction）：所有落盘原文先过凭据擦除（ghp_/gho_/ghu_/ghs_/ghr_
#      _token、github_pat_、JWT、authorization/token/password 字段、PEM 私钥块），
#      每文件替换计数落 verdict.json——替换过什么与换了几处可审计；
#      HTTP 响应头不落盘（仅状态行进日志），避免 Set-Cookie 类敏感头入档。
#   4. 结论 verdict.json（含 argv/时间/每工件 sha256/fresh_until 硬约束字段）：
#      PASS = 该 SHA 在 <branch> 有 event=push 的 exact-SHA run，
#             run completed+success，且 required 双平台 job
#             matrix (ubuntu-latest) / matrix (macos-latest)
#             （与 main 分支保护 required contexts 同集合）逐 job
#             completed+success（jobs API 为主证，check-runs 佐证）。
#      分支规则只存证不裁 PASS（rules_crosscheck 记录 required contexts
#      覆盖情况供审计），与 merge-ci-evidence.sh 的「裁 CI 不裁规则」口径一致。
#
# 仓外纪律：--out-root 必须在仓外（解析后落在 <repo> 内即 rc2 拒绝）；
# 单 SHA 证据目录 collect-<short>/ 已存在即拒绝（不覆盖既有原始证据）。
#
# 用法：
#   bash tools/collect_ci_evidence.sh <SHA> [--repo DIR] [--branch main]
#        [--out-root DIR] [--slug OWNER/REPO]
#     <SHA>          目标 commit（短 SHA/分支名可解析即须完整唯一）
#     --repo DIR     源 git 仓（默认脚本所在仓根）
#     --branch BR    目标分支（默认 main）
#     --out-root DIR 仓外证据根（默认 /tmp/wq-ci-evidence；禁止落在仓内）
#     --slug O/R     gh 仓 slug（默认解析 origin remote）
#
# exit：0=verdict PASS（exact-SHA push run 双平台全绿，原始四类证据已落档）；
#       1=证据不足或未绿（INSUFFICIENT/FAIL——远端无该 SHA run / push run
#         缺失 / required job 非双平台 success——原始数据仍如实落档）；
#       2=环境/用法错（git/gh 缺失、SHA 解析失败、out-root 在仓内、
#         目标目录已存在、API 非容错端点非 200 等）。
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEFAULT_REPO=$(cd "$SCRIPT_DIR/.." && pwd)
ARGV_ORIG="$*"

SHA=""
REPO="$DEFAULT_REPO"
BRANCH="main"
OUT_ROOT="/tmp/wq-ci-evidence"
SLUG=""
MAX_JOB_RUNS=20

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="${2:?--repo 缺参数}"; shift 2;;
    --branch) BRANCH="${2:?--branch 缺参数}"; shift 2;;
    --out-root) OUT_ROOT="${2:?--out-root 缺参数}"; shift 2;;
    --slug) SLUG="${2:?--slug 缺参数}"; shift 2;;
    -h|--help) sed -n '2,48p' "$0"; exit 0;;
    *) if [ -z "$SHA" ]; then SHA="$1"; shift;
       else echo "collect-ci-evidence: 未知参数 $1" >&2; exit 2; fi;;
  esac
done

[ -n "$SHA" ] || { echo "usage: bash tools/collect_ci_evidence.sh <SHA> [选项]" >&2; exit 2; }
git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 \
  || { echo "collect-ci-evidence: 不是 git 仓: $REPO" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "collect-ci-evidence: git 不可用" >&2; exit 2; }
command -v gh >/dev/null 2>&1 || { echo "collect-ci-evidence: gh 不可用" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "collect-ci-evidence: python3 不可用" >&2; exit 2; }

FULL_SHA=$(git -C "$REPO" rev-parse --verify "${SHA}^{commit}" 2>/dev/null) \
  || { echo "collect-ci-evidence: SHA 解析失败: $SHA" >&2; exit 2; }
FULL_SHA=${FULL_SHA%%[[:space:]]*}
SHORT_SHA=$(git -C "$REPO" rev-parse --short=7 "$FULL_SHA")
PARENTS=$(git -C "$REPO" show -s --format=%P "$FULL_SHA")
SUBJECT=$(git -C "$REPO" show -s --format=%s "$FULL_SHA")

if [ -z "$SLUG" ]; then
  REMOTE_URL=$(git -C "$REPO" remote get-url origin 2>/dev/null) \
    || { echo "collect-ci-evidence: origin remote 缺失（或用 --slug 指定）" >&2; exit 2; }
  SLUG=$(printf '%s\n' "$REMOTE_URL" \
    | sed -e 's|^git@github.com:||' -e 's|^https://github.com/||' \
          -e 's|^http://github.com/||' -e 's|\.git$||' -e 's|/$||')
  case "$SLUG" in
    */*) : ;;
    *) echo "collect-ci-evidence: 无法从 remote 解析 slug: $REMOTE_URL" >&2; exit 2;;
  esac
fi

# 仓外纪律：out-root 解析后不得落在仓内
mkdir -p "$OUT_ROOT" 2>/dev/null \
  || { echo "collect-ci-evidence: out-root 不可创建: $OUT_ROOT" >&2; exit 2; }
OUT_ROOT_ABS=$(cd "$OUT_ROOT" && pwd)
REPO_ABS=$(cd "$REPO" && pwd)
case "$OUT_ROOT_ABS/" in
  "$REPO_ABS"/*) echo "collect-ci-evidence: out-root 落在仓内（仓外强制）: $OUT_ROOT_ABS" >&2; exit 2;;
esac
OUT_DIR="$OUT_ROOT_ABS/collect-$SHORT_SHA"
[ -e "$OUT_DIR" ] && { echo "collect-ci-evidence: 目标目录已存在，拒绝覆盖既有原始证据: $OUT_DIR" >&2; exit 2; }
mkdir -p "$OUT_DIR"

TD=$(mktemp -d) || exit 2
trap 'rm -rf "$TD"' EXIT
LOG="$OUT_DIR/collect.log"
COLLECTED_AT=$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')
printf '== collect_ci_evidence %s ==\ncollected_at=%s\nslug=%s branch=%s commit=%s\nargv: %s\n\n' \
  "1" "$COLLECTED_AT" "$SLUG" "$BRANCH" "$FULL_SHA" "$ARGV_ORIG" >> "$LOG"

# api_get <rel_path> <accept> <outfile> <tolerate_404:0|1>
# gh api --include 直调；响应头不落盘（仅状态行进日志），body 过脱敏后落档。
# 返回：0=200；1=404（tolerate 时已如实落档）；2=gh/脱敏失败；3=非预期状态。
api_get() {
  local rel="$1" accept="$2" outfile="$3" tol404="$4" status rc redcounts
  printf '\$ gh api -H "Accept: %s" "repos/%s/%s"\n' "$accept" "$SLUG" "$rel" >> "$LOG"
  if ! gh api --include -H "Accept: $accept" "repos/$SLUG/$rel" > "$TD/raw.http" 2>"$TD/raw.err"; then
    # gh 对部分端点以非零退出码表达 HTTP 404（如 branches/<b>/protection 的
    # Branch not found）——tolerate_404 端点如实落占位并按 404 语义返回 1
    if [ "$tol404" = "1" ] && grep -q 'HTTP 404' "$TD/raw.err"; then
      printf '  gh api HTTP 404（容忍：无 body，落占位占档）\n' >> "$LOG"
      printf '{"gh_api_error": "HTTP 404", "stderr": "%s", "note": "gh 以非零退出码表达 404，本文件为占位占档，非 API 回包"}\n' \
        "$(head -c 120 "$TD/raw.err" | tr '\n' ' ' | tr -d '"')" > "$outfile"
      printf '{}' > "$TD/raw.counts"
      return 1
    fi
    printf '  gh api 失败（auth/网络）: %s\n' "$(head -c 200 "$TD/raw.err" | tr '\n' ' ')" >> "$LOG"
    return 2
  fi
  status=$(python3 - "$TD/raw.http" "$outfile" "$TD/raw.counts" <<'PYEOF'
import json, re, sys
raw_path, out_path, counts_path = sys.argv[1], sys.argv[2], sys.argv[3]
data = open(raw_path, "rb").read()
# --include 回包 = 状态行 + 响应头 + 空行 + body（头不落盘，仅返回状态行）。
# 头体分隔可能是 CRLF 空行或 LF 空行（gh 在 HTTP/2 下发 LF 头）；两种都拆。
head, body = b"", data
for sep_pair in (b"\r\n\r\n", b"\n\n"):
    sep = data.find(sep_pair)
    if sep != -1:
        head, body = data[:sep], data[sep + len(sep_pair):]
        break
status_line = head.split(b"\n", 1)[0].decode("ascii", "replace").strip()
# 脱敏：凭据类模式一律替换（过删优于漏删），计数可审计
PATTERNS = [
    (re.compile(r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b'), r'[REDACTED:\1_token]'),
    (re.compile(r'\bgithub_pat_[A-Za-z0-9_]{20,}\b'), '[REDACTED:finegrained_pat]'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'),
     '[REDACTED:private_key]'),
    (re.compile(r'("(?:authorization|token|access_token|refresh_token|password|secret|api_key)"\s*:\s*"(?:Bearer\s+|token\s+)?)[^"]*(")'),
     r'\1[REDACTED]\2'),
    (re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'), '[REDACTED:jwt]'),
]
text = body.decode("utf-8", "replace")
counts = {}
for pat, rep in PATTERNS:
    text, n = pat.subn(rep, text)
    if n:
        counts[rep.replace("\\1", "")] = counts.get(rep.replace("\\1", ""), 0) + n
open(out_path, "w", encoding="utf-8").write(text)
open(counts_path, "w", encoding="utf-8").write(json.dumps(counts, ensure_ascii=False))
print(status_line)
PYEOF
  ) || rc=$?
  rc=${rc:-0}
  if [ $rc -ne 0 ]; then
    printf '  脱敏/拆包失败 rc=%s\n' "$rc" >> "$LOG"
    return 2
  fi
  redcounts=$(cat "$TD/raw.counts" 2>/dev/null || true)
  printf '  %s -> %s (%s bytes)%s\n' "$status" "$(basename "$outfile")" \
    "$(wc -c < "$outfile" | tr -d ' ')" \
    "${redcounts:+ [redacted: $redcounts]}" >> "$LOG"
  case "$status" in
    *200*) return 0;;
    *404*)
      if [ "$tol404" = "1" ]; then
        printf '  （404 容忍：原文如实落档）\n' >> "$LOG"; return 1
      fi
      printf '  非预期 404（该端点不容忍）\n' >> "$LOG"; return 3;;
    *) printf '  非预期 HTTP 状态: %s\n' "$status" >> "$LOG"; return 3;;
  esac
}

STATUS_JSON="$TD/status.json"
: > "$STATUS_JSON"

record() { # record <endpoint> <outfile> <rc> —— 供 verdict 汇总 API 状态
  python3 - "$STATUS_JSON" "$1" "$2" "$3" <<'PYEOF'
import json, sys
path, ep, outfile, rc = sys.argv[1:5]
arr = json.load(open(path)) if open(path).read(1) else []
arr.append({"endpoint": ep, "file": outfile, "rc": int(rc)})
open(path, "w").write(json.dumps(arr))
PYEOF
}

fail2() { echo "collect-ci-evidence: $*" >&2; printf '\n[ABORT rc2] %s\n' "$*" >> "$LOG"; exit 2; }

# ---- 1) exact-SHA runs（非容错端点：非 200 = 环境错） ----
RC1=0
api_get "actions/runs?head_sha=$FULL_SHA&per_page=100" "application/vnd.github+json" \
  "$OUT_DIR/runs.json" 0 || RC1=$?
[ $RC1 -eq 0 ] || fail2 "actions/runs 采集失败（rc=${RC1}，auth/网络/非 200）"
record "actions/runs?head_sha=" "$OUT_DIR/runs.json" 0

# ---- 2) check-runs（404 = 远端无该 SHA → 证据不足 rc1，交 verdict 判） ----
RC2=0
api_get "commits/$FULL_SHA/check-runs" "application/vnd.github+json" \
  "$OUT_DIR/check-runs.json" 1 || RC2=$?
if [ $RC2 -eq 1 ]; then
  echo "collect-ci-evidence: 远端无该 SHA 的 check-runs（404）→ 交 verdict 判 INSUFFICIENT" >> "$LOG"
elif [ $RC2 -ne 0 ]; then
  fail2 "check-runs 采集失败（rc=${RC2}）"
fi
record "commits/<sha>/check-runs" "$OUT_DIR/check-runs.json" $RC2

# ---- 3) 实时分支规则（rulesets + classic，均容忍 404） ----
RC3=0
api_get "rules/branches/$BRANCH" "application/vnd.github+json" \
  "$OUT_DIR/branch-rules-rulesets.json" 1 || RC3=$?
[ $RC3 -le 1 ] || fail2 "rules/branches 采集失败（rc=${RC3}）"
record "rules/branches/$BRANCH" "$OUT_DIR/branch-rules-rulesets.json" $RC3
RC4=0
api_get "branches/$BRANCH/protection" "application/vnd.github+json" \
  "$OUT_DIR/branch-protection-classic.json" 1 || RC4=$?
[ $RC4 -le 1 ] || fail2 "branches/protection 采集失败（rc=${RC4}）"
record "branches/$BRANCH/protection" "$OUT_DIR/branch-protection-classic.json" $RC4

# ---- 4) push runs 的 jobs 明细 ----
python3 - "$OUT_DIR/runs.json" "$TD/push_run_ids.json" <<'PYEOF' || fail2 "runs.json 解析失败（非 JSON?）"
import json, sys
runs = json.load(open(sys.argv[1], encoding="utf-8"))
ids = [r["id"] for r in runs.get("workflow_runs", [])
       if r.get("event") == "push"][:20]  # MAX_JOB_RUNS 防御性上限
json.dump(ids, open(sys.argv[2], "w"))
PYEOF
N_JOBS_OK=0; N_JOBS_FAIL=0
for RID in $(python3 -c 'import json,sys;print(" ".join(map(str,json.load(open(sys.argv[1])))))' "$TD/push_run_ids.json"); do
  if api_get "actions/runs/$RID/jobs?per_page=100" "application/vnd.github+json" \
       "$OUT_DIR/run-$RID-jobs.json" 0; then
    N_JOBS_OK=$((N_JOBS_OK+1)); record "actions/runs/<id>/jobs" "$OUT_DIR/run-$RID-jobs.json" 0
  else
    N_JOBS_FAIL=$((N_JOBS_FAIL+1)); record "actions/runs/<id>/jobs" "(missing run-$RID)" 4
  fi
done
printf '\npush_runs_jobs: ok=%s fail=%s\n' "$N_JOBS_OK" "$N_JOBS_FAIL" >> "$LOG"

# ---- 5) 判定 + verdict.json ----
RC_FINAL=0
python3 - "$OUT_DIR" "$TD" "$STATUS_JSON" "$SLUG" "$BRANCH" "$FULL_SHA" \
  "$SHORT_SHA" "$PARENTS" "$SUBJECT" "$COLLECTED_AT" "$ARGV_ORIG" <<'PYEOF' || RC_FINAL=$?
import datetime, glob, hashlib, json, os, sys
(out_dir, td, status_json, slug, branch, full_sha, short_sha,
 parents, subject, collected_at, argv) = sys.argv[1:12]
REQUIRED = ["matrix (ubuntu-latest)", "matrix (macos-latest)"]

def load(p, default=None):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return default

def sha256_of(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

runs = load(f"{out_dir}/runs.json", {})
check = load(f"{out_dir}/check-runs.json", {})
rulesets = load(f"{out_dir}/branch-rules-rulesets.json", None)
classic = load(f"{out_dir}/branch-protection-classic.json", None)
api_calls = load(status_json, [])

workflow_runs = runs.get("workflow_runs", []) if isinstance(runs, dict) else []
push_runs = [r for r in workflow_runs
             if r.get("event") == "push"
             and r.get("head_branch") == branch
             and r.get("head_sha") == full_sha]

push_detail = []
for r in push_runs:
    rid = r.get("id")
    jobs_doc = load(f"{out_dir}/run-{rid}-jobs.json")
    entry = {
        "run_id": rid,
        "run_url": r.get("html_url"),
        "status": r.get("status"),
        "conclusion": r.get("conclusion"),
        "created_at": r.get("created_at"),
        "updated_at": r.get("updated_at"),
        "jobs_fetched": jobs_doc is not None,
    }
    if jobs_doc is not None:
        jmap = {}
        for j in jobs_doc.get("jobs", []):
            jmap[j.get("name")] = {"status": j.get("status"),
                                   "conclusion": j.get("conclusion")}
        entry["required_jobs"] = {n: jmap.get(n) for n in REQUIRED}
        entry["_all_required_ok"] = all(
            jmap.get(n) == {"status": "completed", "conclusion": "success"}
            for n in REQUIRED)
    else:
        entry["required_jobs"] = None
        entry["_all_required_ok"] = False
    push_detail.append(entry)

check_runs = check.get("check_runs", []) if isinstance(check, dict) else []
cmap = {c.get("name"): {"status": c.get("status"), "conclusion": c.get("conclusion")}
        for c in check_runs}
check_crosscheck = {n: cmap.get(n) for n in REQUIRED}

# 分支规则实时存证（不裁 PASS，覆盖情况供审计）
def ctx_from_rulesets(rs):
    if not isinstance(rs, list):
        return None
    ctxs = []
    for rule in rs:
        if rule.get("type") == "required_status_checks":
            c = (rule.get("parameters") or {}).get("required_status_checks") or {}
            ctxs.extend(c.get("contexts", []) or c.get("checks", []))
    return ctxs or None

def ctx_from_classic(cl):
    if not isinstance(cl, dict):
        return None
    c = (cl.get("required_status_checks") or {}).get("contexts")
    return list(c) if isinstance(c, list) and c else None

rs_ctx = ctx_from_rulesets(rulesets)
cl_ctx = ctx_from_classic(classic)
all_ctx = (rs_ctx or []) + (cl_ctx or [])
rules_crosscheck = {
    "rulesets_required_contexts": rs_ctx,
    "classic_required_contexts": cl_ctx,
    "rules_http": [a.get("rc") for a in api_calls
                   if a.get("endpoint", "").startswith(("rules/branches", "branches/"))],
    "required_covered_by_rules": (all(n in all_ctx for n in REQUIRED)
                                  if all_ctx else None),
    "note": "实时规则原文已落档；required contexts 覆盖为审计字段，不参与 PASS 裁定",
}

# ---- verdict ----
verdict, reason = "FAIL", ""
if not isinstance(check, dict) or not check_runs and check.get("total_count") is None:
    verdict = "INSUFFICIENT"
    reason = (f"commits/{short_sha}/check-runs 404：远端查无该 SHA——"
              f"本地对象库有但未推送，或远端已不可见（exact-SHA 实查，非推断）")
elif not push_runs:
    verdict = "INSUFFICIENT"
    reason = (f"actions/runs?head_sha={full_sha} 无 event=push 且 head_branch={branch} "
              f"的 run：该 SHA 未以 push 事件落到 {branch}（exact-SHA 实查）")
else:
    good = [e for e in push_detail
            if e.get("status") == "completed"
            and e.get("conclusion") == "success"
            and e.get("_all_required_ok")]
    unverifiable = [e for e in push_detail if not e.get("jobs_fetched")]
    if good:
        g = max(good, key=lambda e: str(e.get("created_at")))
        verdict = "PASS"
        reason = (f"run {g['run_id']}（event=push，headSha={full_sha}）双平台 "
                  f"{'/'.join(REQUIRED)} 均 completed/success（jobs API 主证；"
                  f"check-runs 佐证={check_crosscheck}）")
    elif unverifiable and len(unverifiable) == len(push_detail):
        verdict = "INSUFFICIENT"
        reason = f"push run 存在但 jobs 明细采集失败（{len(unverifiable)} 个），无法逐 job 核验"
    else:
        verdict = "FAIL"
        reason = (f"有 exact-SHA push run（{len(push_detail)} 个）但不满足双平台 success："
                  f"逐 run 结论见 push_runs_verified")

for e in push_detail:
    e.pop("_all_required_ok", None)

fresh_until = (datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
artifacts = sorted(glob.glob(f"{out_dir}/*"))
payload = {
    "schema": "wenqu-collect-ci-evidence/1",
    "tool": "tools/collect_ci_evidence.sh",
    "collected_at": collected_at,
    "fresh_until": fresh_until,
    "method": ("gh api 直调原始回包（--include 取状态行，响应头不落盘；body 过"
               "凭据脱敏后落仓外证据根）：actions/runs?head_sha=<full>（exact-SHA "
               "严格相等）+ actions/runs/<id>/jobs + commits/<full>/check-runs + "
               "rules/branches/<branch> + branches/<branch>/protection"),
    "environment": "github-api-live",
    "repo": slug,
    "branch": branch,
    "commit": full_sha,
    "commit_short": short_sha,
    "commit_subject": subject,
    "commit_parents": parents.split(),
    "is_merge_commit": len(parents.split()) >= 2,
    "argv": argv,
    "required_matrix_jobs": REQUIRED,
    "api_calls": [{"endpoint": a.get("endpoint"), "rc": a.get("rc"),
                   "file": os.path.basename(a.get("file") or ""),
                   "file_sha256": (sha256_of(a["file"])
                                   if a.get("file") and os.path.isfile(a["file"])
                                   else None),
                   "file_bytes": (os.path.getsize(a["file"])
                                  if a.get("file") and os.path.isfile(a["file"])
                                  else None)}
                  for a in api_calls],
    "runs_total_count": runs.get("total_count") if isinstance(runs, dict) else None,
    "push_runs_count": len(push_runs),
    "pr_head_runs_excluded_count": len(workflow_runs) - len(push_runs),
    "push_runs_verified": push_detail,
    "check_runs_total_count": check.get("total_count") if isinstance(check, dict) else None,
    "check_runs_required_crosscheck": check_crosscheck,
    "rules_crosscheck": rules_crosscheck,
    "verdict": verdict,
    "verdict_reason": reason,
    "exit_code": 0 if verdict == "PASS" else 1,
}
out_json = f"{out_dir}/verdict.json"
with open(out_json, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=1, sort_keys=True)
    fh.write("\n")
print(f"collect-ci-evidence: {verdict}  {short_sha}  →  {out_json}")
print(f"  {reason}")
print(f"  artifacts: {len(artifacts)} files in {out_dir}")
sys.exit(0 if verdict == "PASS" else 1)
PYEOF
printf '\n[verdict rc=%s]\n' "$RC_FINAL" >> "$LOG"
exit $RC_FINAL

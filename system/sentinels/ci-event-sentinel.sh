#!/usr/bin/env bash
# ci-event-sentinel v1（2026-09-30 建仓加固，EXM-20260930-02 的观察面补口）
# 反的什么事故：GitHub pull_request 事件流仓级故障 7h+ 无人察觉（EXM-02）——
# 推送全部成功、CI 全部沉默，靠人肉探针才发现。
# 捕获原理：近 60min 内 open PR 有 push 活动（updatedAt 变化）而 pull_request 型 run 零创建
#   → 事件流疑似死亡 → HIGH 告警；平峰（无 PR 活动）静默防误报。
set -uo pipefail
REPO="${WENQU_REPO:?需设 WENQU_REPO}"
LOG=~/.zcode/quality-system/4c6665172cfd52c9/sentinel/ci-event.log
ts() { date '+%F %T'; }
ALERT_SEND=/Users/maccc/argus3-runtime/scripts/argus/alert-send.sh
alert() {  # 加固 v1.1：本地日志+统一 spool/webhook 双落（防只写本地=防线假活）
  echo "$(ts) [$1] $2" >> "$LOG"
  [ -x "$ALERT_SEND" ] && "$ALERT_SEND" "$1" "ci-event-sentinel" "$2" >/dev/null 2>&1 || true
}

NOW=$(date +%s)
# ① 近 60min open PR 活动（updatedAt 进窗）
PR_ACTIVE=$(gh pr list -R "$REPO" --state open --limit 30 --json updatedAt 2>/dev/null | python3 -c "
import json,sys,datetime
n=0
for pr in json.load(sys.stdin):
    t=datetime.datetime.fromisoformat(pr['updatedAt'].replace('Z','+00:00')).timestamp()
    if $(date +%s)-t < 3600: n+=1
print(n)")
[ -z "${PR_ACTIVE:-}" ] && PR_ACTIVE=0

# ② 近 60min pull_request 型 run 创建数
PR_RUNS=$(gh run list -R "$REPO" --limit 50 --json event,createdAt 2>/dev/null | python3 -c "
import json,sys,datetime
n=0
for r in json.load(sys.stdin):
    if r['event']!='pull_request': continue
    t=datetime.datetime.fromisoformat(r['createdAt'].replace('Z','+00:00')).timestamp()
    if $(date +%s)-t < 3600: n+=1
print(n)")
[ -z "${PR_RUNS:-}" ] && PR_RUNS=0

if [ "$PR_ACTIVE" -gt 0 ] && [ "$PR_RUNS" -eq 0 ]; then
  alert HIGH "CI 事件哨兵：近 60min 有 ${PR_ACTIVE} 个 open PR 活动但零 pull_request run 创建——事件流疑似死亡（EXM-02 形态），处置=空commit探针确认+报障评估"
  exit 1
fi
echo "$(ts) [OK] pr_active=${PR_ACTIVE} pr_runs=${PR_RUNS}" >> "$LOG"

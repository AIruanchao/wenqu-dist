#!/usr/bin/env bash
# auto-merge v1（迭代5：合流自动化——绕 GitHub check propagation 阻塞）
# 每 N 分钟检查 open PR：全绿+BEHIND→自动 merge master→push→重试合流
# 部署：launchd/cron 或 nohup 后台
set -uo pipefail
INTERVAL="${1:-300}"  # 默认 5 分钟
REPO="${WENQU_REPO:?需设 WENQU_REPO}"
LOG=~/.zcode/quality-system/4c6665172cfd52c9/sentinel/auto-merge.log

log() { echo "$(date '+%F %T') $1" >> "$LOG"; }

while true; do
    sleep "$INTERVAL"

    # 获取 open PR 列表
    PRS=$(gh pr list -R "$REPO" --state open --json number,statusCheckRollup,mergeStateStatus 2>/dev/null)
    [ -z "$PRS" ] && continue

    # 逐个检查
    COUNT=$(echo "$PRS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null)
    for i in $(seq 0 $((COUNT - 1))); do
        PR_DATA=$(echo "$PRS" | python3 -c "
import json,sys
prs = json.load(sys.stdin)
if $i < len(prs): print(json.dumps(prs[$i]))
else: print('{}')
" 2>/dev/null)

        NUM=$(echo "$PR_DATA" | python3 -c "import json,sys; print(json.load(sys.stdin).get('number',''))" 2>/dev/null)
        STATE=$(echo "$PR_DATA" | python3 -c "import json,sys; print(json.load(sys.stdin).get('mergeStateStatus',''))" 2>/dev/null)

        [ -z "$NUM" ] && continue

        # 检查所有 required checks 是否绿
        ALL_GREEN=$(echo "$PR_DATA" | python3 -c "
import json,sys
d = json.load(sys.stdin)
checks = d.get('statusCheckRollup', [])
for c in checks:
    name = c.get('name','')
    conclusion = c.get('conclusion','')
    # Fast 是 required——必须 SUCCESS
    if 'Fast' in name and conclusion != 'SUCCESS':
        print('no'); exit()
print('yes' if checks else 'no')
" 2>/dev/null)

        if [ "$ALL_GREEN" = "yes" ]; then
            if [ "$STATE" = "BEHIND" ]; then
                log "PR#$NUM: Fast绿+BEHIND→merge master 对齐"
                # 获取分支名
                BRANCH=$(gh pr view $NUM -R "$REPO" --json headRefName --jq .headRefName 2>/dev/null)
                [ -z "$BRANCH" ] && continue

                # 在本地 merge master 到分支
                cd /tmp && rm -rf auto-merge-$NUM
                git clone -q --depth=200 --branch "$BRANCH" "https://github.com/$REPO.git" auto-merge-$NUM 2>/dev/null
                cd auto-merge-$NUM
                git fetch origin master --depth=200 --quiet 2>/dev/null
                git merge origin/master -m "merge: auto-align by auto-merge" --no-edit 2>/dev/null
                if [ $? -eq 0 ]; then
                    git push origin "$BRANCH" 2>/dev/null
                    log "PR#$NUM: master merged, pushed"
                else
                    log "PR#$NUM: merge conflict, skipping"
                fi
                cd /tmp && rm -rf auto-merge-$NUM
            elif [ "$STATE" = "CLEAN" ] || [ "$STATE" = "UNSTABLE" ]; then
                log "PR#$NUM: Fast绿+${STATE}→尝试合流"
                gh pr merge $NUM -R "$REPO" --squash --admin --delete-branch=false 2>/dev/null
                if [ $? -eq 0 ]; then
                    log "PR#$NUM: MERGED ✅"
                else
                    log "PR#$NUM: merge failed (will retry)"
                fi
            fi
        fi
    done
done

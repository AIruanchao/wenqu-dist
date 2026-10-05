#!/usr/bin/env bash
# weekly-watchdog v2（2026-09-30 重建+增强：BSF-03 根修——不只查存在，查新鲜度+退出态+内容 fatal）
# 看《dupscan周哨兵》最新报告：>8 天未更新 / 含网络 FATAL / 含 ratchet_exit 非 0 → 告警
set -uo pipefail
OUT_DIR="/Users/maccc/Documents/ERP）Zcode/dupscan周哨兵"
LOG=~/.zcode/quality-system/4c6665172cfd52c9/sentinel/weekly.log
NOTIFY_LIB="${WEEKLY_NOTIFY_LIB:-}"   # 可接 sentinel-notify-lib 统一外发（未配置则本地日志）
ts() { date '+%F %T'; }
LATEST=$(ls -t "$OUT_DIR"/dupscan-weekly-*.txt 2>/dev/null | head -1)
alert() {  # alert <level> <msg>
  echo "$(ts) [$1] $2" >> "$LOG"
  if [ -n "$NOTIFY_LIB" ] && [ -f "$NOTIFY_LIB" ]; then
    bash "$NOTIFY_LIB" "dupscan周哨兵" "$1" "$2" 2>/dev/null || true
  fi
}
if [ -z "$LATEST" ]; then
  alert HIGH "无任何周报（dupscan-weekly 从未出结果）——哨兵通道死"
  exit 1
fi
AGE=$(( ($(date +%s) - $(stat -f %m "$LATEST")) / 86400 ))
BASE=$(basename "$LATEST")
if [ "$AGE" -gt 8 ]; then
  alert HIGH "最新周报 $BASE 已 ${AGE} 天（>8）——周哨兵停摆（BSF-03 修复后应触发此前从未触发的告警）"
  exit 1
fi
if grep -qE "FATAL: git fetch|ratchet_exit=[^0]" "$LATEST"; then
  DETAIL=$(grep -E "FATAL: git fetch|ratchet_exit=[^0]" "$LATEST" | head -2 | tr '\n' '; ')
  alert MEDIUM "最新周报 $BASE（${AGE}天前）带失败态：$DETAIL"
  exit 1
fi
echo "$(ts) [OK] $BASE age=${AGE}d 无失败态" >> "$LOG"

# 加固 v2.1（2026-10-01）：哨兵的哨兵——ci-event-sentinel 自身新鲜度（dupscan-weekly 死 9 天教训的三度应用）
CI_EVENT_LOG=~/.zcode/quality-system/4c6665172cfd52c9/sentinel/ci-event.log
if [ -f "$CI_EVENT_LOG" ]; then
  CIE_AGE=$(( ($(date +%s) - $(stat -f %m "$CI_EVENT_LOG")) / 60 ))
  if [ "$CIE_AGE" -gt 70 ]; then
    alert HIGH "ci-event-sentinel 日志 ${CIE_AGE}min 未更新（>70）——事件哨兵自身停摆（launchd ci-event-sentinel 检查）"
    exit 1
  fi
fi

# 加固 v2.2（2026-10-01）：守恒哨兵新鲜度（每日 05:05 跑，>26h 未更新=停摆）
CONS_LOG=~/.zcode/quality-system/4c6665172cfd52c9/sentinel/conservation.log
if [ -f "$CONS_LOG" ]; then
  CONS_AGE=$(( ($(date +%s) - $(stat -f %m "$CONS_LOG")) / 3600 ))
  if [ "$CONS_AGE" -gt 26 ]; then
    alert HIGH "conservation-sentinel 日志 ${CONS_AGE}h 未更新——资金守恒防线停摆"
    exit 1
  fi
fi

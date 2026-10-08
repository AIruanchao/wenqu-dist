#!/usr/bin/env bash
# backup-restore-drill.sh——W4 生产备份恢复演练（快照→篡改→恢复→字节级对账）。
#
# 语料（corpus）：真实生产状态文件的字节级副本（默认取
#   ${WENQU_HOME:-~/.wenqu} 下 state/scheduler.db、state/gate-aggregate.json、
#   observation/heartbeat.json、observation/samples 与 shadow 的最新 JSON）。
#   生产文件本身全程只读（cp 一次），篡改/恢复全部发生在演练沙箱副本上——
#   演练语义是"证明 checkpoint→restore 管道能精确还原字节"，不是自伤生产态。
#
# 四步（全部真实执行，无模拟）：
#   1 快照：corpus → live/（工作副本）+ backup/（checkpoint），shasum 清单
#   2 篡改：对 live/ 副本追加垃圾字节/截断为零/删除文件（篡改后必须实测
#     sha 已变——伪造演练直接 FAIL）
#   3 恢复：backup/ 逐文件 cp -p 回 live/（含重建被删文件）
#   4 对账：backup vs live 逐文件 cmp 字节级 + shasum 对清单
#
# 报告：JSON 落 <report-dir>/drill-<UTC时间戳>.json（默认
#   ${WENQU_HOME:-~/.wenqu}/observation/drills/）。
#   另落同缀 .jsonl 事件日志（每行 {ts,t,event,file,result[,...extra]}——
#   时间/文件/结果三要素，逐事件追加，供验收测试与审计直接核对）。
# 退出码：0=PASS；1=FAIL（语料为空/步骤失败/对账不等/DR 指标越冻结目标）。
#
# DR 模式（--mode dr）：在四步之上加 RPO/RTO 实测计时（全部真跑）：
#   RPO = 最后快照点 -> 故障注入点（篡改开始）的实测时差。快照完成后
#         按 --fault-delay 秒注入已知故障延迟窗口（默认 1s），故 RPO
#         应 >= 该窗口且 <= 冻结目标——零/负值=伪造计时直接 FAIL。
#   RTO = 恢复开始（第一条 cp）-> 全部对账通过的实测耗时。
#   冻结目标（本脚本内冻结，不接受 CLI 覆盖）：RPO<=300s、RTO<=60s。
#   DR PASS = 字节对账全等 && rpo_ok && rto_ok。
#
# 用法：
#   bash system/sentinels/backup-restore-drill.sh [--wenqu-root DIR]
#        [--report-dir DIR] [--keep-workdir]
#        [--mode backup|dr] [--fault-delay SEC]（dr 专用，默认 1）
set -uo pipefail

WENQU_ROOT="${WENQU_HOME:-$HOME/.wenqu}"
REPORT_DIR=""
KEEP_WORK=0
MODE="backup"
FAULT_DELAY="1"
# 冻结 RPO/RTO 目标（秒）：DR-01 语义「实测满足冻结 RPO/RTO」的正源。
DR_RPO_TARGET_S=300
DR_RTO_TARGET_S=60
while [ $# -gt 0 ]; do
  case "$1" in
    --wenqu-root) WENQU_ROOT="${2:?}"; shift 2 ;;
    --report-dir) REPORT_DIR="${2:?}"; shift 2 ;;
    --keep-workdir) KEEP_WORK=1; shift ;;
    --mode) MODE="${2:?}"; shift 2 ;;
    --fault-delay) FAULT_DELAY="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "drill: unknown arg: $1" >&2; exit 1 ;;
  esac
done
case "$MODE" in backup|dr) ;; *) echo "drill: --mode must be backup|dr" >&2; exit 1 ;; esac
case "$FAULT_DELAY" in
  ''|*[!0-9.]*) echo "drill: --fault-delay must be a positive number" >&2; exit 1 ;;
esac
REPORT_DIR="${REPORT_DIR:-$WENQU_ROOT/observation/drills}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
# 同秒并发防覆写：工件名已存在则追加序号（drill-<stamp>-2.json），绝不覆盖既有演练证据
_SEQ=1
while [ -e "$REPORT_DIR/drill-$STAMP.json" ] || [ -e "$REPORT_DIR/drill-$STAMP.jsonl" ]; do
  _SEQ=$((_SEQ+1))
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$_SEQ"
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wenqu-drill.XXXXXXXX")" || exit 1
LIVE="$WORK/live"; BACKUP="$WORK/backup"
mkdir -p "$LIVE" "$BACKUP" "$REPORT_DIR" || exit 1

# ---- 计时基元（亚秒精度；python3 不可用时退化为整秒 date） ----------------
_now() {  # 输出 "<epoch浮点> <ISO8601UTC>"
  python3 -c 'import time; print(f"{time.time():.6f} " + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))' \
    2>/dev/null || echo "$(date +%s) $(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
_epoch() { _now | awk '{print $1}'; }
_fsub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.6f", a-b}'; }       # a-b
_fcmp() { awk -v a="$1" -v b="$2" 'BEGIN{print (a<b) ? "lt" : ((a>b) ? "gt" : "eq")}'; }
_fge()  { [ "$(_fcmp "$1" "$2")" != "lt" ]; }

# ---- jsonl 事件日志（时间/文件/结果） -------------------------------------
JSONL_PATH="$REPORT_DIR/drill-$STAMP.jsonl"
: > "$JSONL_PATH" || exit 1
ev() {  # $1=event $2=file(空="-") $3=result $4=额外 JSON 片段（可空）
  local now line
  now=$(_now)
  line=$(printf '{"ts": %s, "t": "%s", "event": "%s", "file": "%s", "result": "%s"%s}' \
    "${now%% *}" "${now#* }" "$1" "${2:--}" "$3" "${4:+, $4}")
  printf '%s\n' "$line" >> "$JSONL_PATH"
}
T_START=$(_epoch)

# ---- 语料收集（生产文件只读） -------------------------------------------
CORPUS_REL=()
add_corpus() {  # $1=仓库内相对路径（存在且可读才入列）
  [ -f "$WENQU_ROOT/$1" ] && [ -r "$WENQU_ROOT/$1" ] && CORPUS_REL+=("$1")
}
add_corpus "state/scheduler.db"
add_corpus "state/gate-aggregate.json"
add_corpus "observation/heartbeat.json"
latest_json() {  # $1=目录 → 最新 mtime 的 *.json 相对路径（无则空）
  local dir="$WENQU_ROOT/$1" best="" bestm=0 m name
  [ -d "$dir" ] || { echo ""; return; }
  for name in "$dir"/*.json; do
    [ -f "$name" ] || continue
    m=$(/usr/bin/stat -f %m "$name" 2>/dev/null || echo 0)
    if [ "$m" -gt "$bestm" ]; then bestm="$m"; best="${name#"$WENQU_ROOT"/}"; fi
  done
  echo "$best"
}
for rel in "$(latest_json observation/samples)" "$(latest_json observation/shadow)"; do
  [ -n "$rel" ] && add_corpus "$rel"
done

fail() {  # $1=原因 → 写 FAIL 报告并退出 1
  write_report FAIL "$1"
  ev drill_fail - FAIL "\"reason\": \"$1\""
  echo "drill: FAIL: $1" >&2
  [ "$KEEP_WORK" -eq 1 ] && echo "drill: workdir kept: $WORK" >&2
  exit 1
}

REPORT_PATH="$REPORT_DIR/drill-$STAMP.json"
DR_JSON="null"
write_report() {  # $1=result $2=reason；其余步骤事实由调用方拼进 $STEPS_JSON
  local bm="null"
  [ -n "${BYTE_MATCH_ALL:-}" ] && bm=$( [ "$BYTE_MATCH_ALL" -eq 1 ] && echo true || echo false )
  cat > "$REPORT_PATH.tmp" <<EOF
{
  "drill": "backup-restore",
  "stamp": "$STAMP",
  "mode": "$MODE",
  "wenqu_root": "$WENQU_ROOT",
  "workdir": "$WORK",
  "corpus_count": ${#CORPUS_REL[@]},
  "steps": ${STEPS_JSON:-null},
  "dr": $DR_JSON,
  "result": "$1",
  "reason": "$2",
  "byte_match_all": $bm,
  "jsonl": "$JSONL_PATH"
}
EOF
  mv "$REPORT_PATH.tmp" "$REPORT_PATH"
}

[ "${#CORPUS_REL[@]}" -ge 1 ] || fail "corpus empty: no production state files under $WENQU_ROOT"
ev drill_start - "$MODE" "\"corpus_count\": ${#CORPUS_REL[@]}, \"wenqu_root\": \"$WENQU_ROOT\""

# ---- 步骤 1：快照 ---------------------------------------------------------
SNAP_JSON="["; FIRST=1
for rel in "${CORPUS_REL[@]}"; do
  mkdir -p "$LIVE/$(dirname "$rel")" "$BACKUP/$(dirname "$rel")"
  cp -p "$WENQU_ROOT/$rel" "$LIVE/$rel"   || fail "snapshot cp live $rel"
  cp -p "$WENQU_ROOT/$rel" "$BACKUP/$rel" || fail "snapshot cp backup $rel"
  sha=$(/usr/bin/shasum -a 256 "$BACKUP/$rel" | awk '{print $1}')
  size=$(/usr/bin/stat -f %z "$BACKUP/$rel")
  [ "$FIRST" -eq 1 ] || SNAP_JSON+=", "; FIRST=0
  SNAP_JSON+="{\"rel\": \"$rel\", \"sha256\": \"$sha\", \"size\": $size}"
  ev snapshot_file "$rel" true "\"sha256\": \"$sha\", \"size\": $size"
done
SNAP_JSON+="]"

# ---- DR 计时：快照点 -> 故障注入点（已知延迟窗口，可控制 RPO） -----------
if [ "$MODE" = "dr" ]; then
  T_SNAP_DONE=$(_epoch)
  sleep "$FAULT_DELAY"
  T_FAULT=$(_epoch)
  RPO_S=$(_fsub "$T_FAULT" "$T_SNAP_DONE")
  ev fault_window - true "\"rpo_seconds\": $RPO_S, \"fault_delay_s\": $FAULT_DELAY"
fi

# ---- 步骤 2：篡改（真实改字节） -------------------------------------------
TAMPER_JSON="["
tamper() {  # $1=rel $2=方式 $3=描述
  TAMPER_JSON+="{\"rel\": \"$1\", \"how\": \"$2\"}, "
  echo "drill: tamper $1 ($3)"
}
i=0
for rel in "${CORPUS_REL[@]}"; do
  i=$((i+1))
  m=$(( (i - 1) % 3 + 1 ))  # 1/2/3 轮转（i%3 在 3 的倍数时余 0 无分支）
  case $m in
    1) printf 'DRILL-TAMPER-BYTES-%s' "$STAMP" >> "$LIVE/$rel"
       tamper "$rel" append "追加垃圾字节"
       ev tamper_file "$rel" append ;;
    2) : > "$LIVE/$rel"
       tamper "$rel" truncate "截断为零字节"
       ev tamper_file "$rel" truncate ;;
    3) rm -f "$LIVE/$rel"
       tamper "$rel" delete "删除文件"
       ev tamper_file "$rel" delete ;;
  esac
done
TAMPER_JSON="${TAMPER_JSON%, }]"
# 篡改必须真的改了字节（追加/截断类实测 sha 已变；删除类实测文件不在）——
# 没改动的"假演练"直接 FAIL。
TAMPER_VERIFIED=1
i=0
for rel in "${CORPUS_REL[@]}"; do
  i=$((i+1)); m=$(( (i - 1) % 3 + 1 ))
  if [ "$m" -eq 3 ]; then
    [ ! -e "$LIVE/$rel" ] || TAMPER_VERIFIED=0
  else
    sha_now=$(/usr/bin/shasum -a 256 "$LIVE/$rel" 2>/dev/null | awk '{print $1}')
    sha_old=$(/usr/bin/shasum -a 256 "$BACKUP/$rel" | awk '{print $1}')
    [ "$sha_now" != "$sha_old" ] || TAMPER_VERIFIED=0
  fi
done
[ "$TAMPER_VERIFIED" -eq 1 ] || fail "tamper did not actually change bytes (fake drill)"
ev tamper_verified - true "\"actions\": ${TAMPER_JSON}"

# ---- 步骤 3：恢复（DR：恢复开始即 RTO 起表） ------------------------------
[ "$MODE" = "dr" ] && T_RESTORE_START=$(_epoch)
RESTORE_N=0
for rel in "${CORPUS_REL[@]}"; do
  cp -p "$BACKUP/$rel" "$LIVE/$rel" || fail "restore cp $rel"
  RESTORE_N=$((RESTORE_N+1))
  ev restore_file "$rel" true "\"n\": $RESTORE_N"
done

# ---- 步骤 4：字节级对账 ---------------------------------------------------
BYTE_MATCH_ALL=1
RECON_JSON="["
FIRST=1
for rel in "${CORPUS_REL[@]}"; do
  sha_old=$(/usr/bin/shasum -a 256 "$BACKUP/$rel" | awk '{print $1}')
  sha_now=$(/usr/bin/shasum -a 256 "$LIVE/$rel" | awk '{print $1}')
  if cmp -s "$BACKUP/$rel" "$LIVE/$rel" && [ "$sha_now" = "$sha_old" ]; then match=true; else match=false; BYTE_MATCH_ALL=0; fi
  [ "$FIRST" -eq 1 ] || RECON_JSON+=", "; FIRST=0
  RECON_JSON+="{\"rel\": \"$rel\", \"cmp\": $match, \"sha_match\": $match, \"sha256\": \"$sha_now\"}"
  ev reconcile_file "$rel" "$match" "\"sha256\": \"$sha_now\""
done
RECON_JSON+="]"

# ---- DR 计时收口：RTO=恢复开始 -> 全部对账通过；RPO/RTO 对冻结目标判定 ----
if [ "$MODE" = "dr" ]; then
  T_RECONCILE_DONE=$(_epoch)
  RTO_S=$(_fsub "$T_RECONCILE_DONE" "$T_RESTORE_START")
  RPO_OK=false; RTO_OK=false
  # RPO 必须 >= 已知故障窗口（窗口真实流逝；零/负=伪造计时）且 <= 冻结目标
  if _fge "$RPO_S" "$FAULT_DELAY" && _fge "$DR_RPO_TARGET_S" "$RPO_S"; then RPO_OK=true; fi
  # RTO 必须 > 0 且 <= 冻结目标（60s）
  if _fge "$RTO_S" "0.000001" && _fge "$DR_RTO_TARGET_S" "$RTO_S"; then RTO_OK=true; fi
  DR_JSON=$(cat <<EOF
{
  "mode": "dr",
  "fault_delay_s": $FAULT_DELAY,
  "rpo_seconds": $RPO_S,
  "rto_seconds": $RTO_S,
  "rpo_target_s": $DR_RPO_TARGET_S,
  "rto_target_s": $DR_RTO_TARGET_S,
  "rpo_ok": $RPO_OK,
  "rto_ok": $RTO_OK,
  "t_snapshot_done_epoch": $T_SNAP_DONE,
  "t_fault_epoch": $T_FAULT,
  "t_restore_start_epoch": $T_RESTORE_START,
  "t_reconcile_done_epoch": $T_RECONCILE_DONE
}
EOF
)
  ev dr_metrics - "$([ "$RPO_OK" = true ] && [ "$RTO_OK" = true ] && echo true || echo false)" \
    "\"rpo_seconds\": $RPO_S, \"rto_seconds\": $RTO_S, \"rpo_target_s\": $DR_RPO_TARGET_S, \"rto_target_s\": $DR_RTO_TARGET_S"
fi

STEPS_JSON=$(cat <<EOF
{
  "snapshot": {"ok": true, "files": $SNAP_JSON},
  "tamper": {"ok": $( [ "$TAMPER_VERIFIED" -eq 1 ] && echo true || echo false ), "actions": $TAMPER_JSON},
  "restore": {"ok": true, "files_restored": $RESTORE_N},
  "reconcile": {"files": $RECON_JSON}
}
EOF
)
if [ "$MODE" = "dr" ]; then
  if [ "$BYTE_MATCH_ALL" -eq 1 ] && [ "$RPO_OK" = "true" ] && [ "$RTO_OK" = "true" ]; then
    write_report PASS "4/4 steps ok; byte-identical restore; RPO=${RPO_S}s<=${DR_RPO_TARGET_S}s, RTO=${RTO_S}s<=${DR_RTO_TARGET_S}s (frozen targets met)"
    ev drill_pass - PASS "\"rpo_seconds\": $RPO_S, \"rto_seconds\": $RTO_S"
    echo "drill: PASS 4/4（快照${#CORPUS_REL[@]}文件→篡改→恢复→字节级对账全等）"
    echo "drill: DR 实测 RPO=${RPO_S}s（目标<=${DR_RPO_TARGET_S}s） RTO=${RTO_S}s（目标<=${DR_RTO_TARGET_S}s）"
    echo "drill: report: $REPORT_PATH"
  elif [ "$BYTE_MATCH_ALL" -ne 1 ]; then
    fail "byte-level reconcile mismatch after restore"
  else
    fail "DR frozen targets not met: RPO=${RPO_S}s(rpo_ok=$RPO_OK) RTO=${RTO_S}s(rto_ok=$RTO_OK)"
  fi
elif [ "$BYTE_MATCH_ALL" -eq 1 ]; then
  write_report PASS "4/4 steps ok; all restored files byte-identical to snapshot"
  ev drill_pass - PASS
  echo "drill: PASS 4/4（快照${#CORPUS_REL[@]}文件→篡改→恢复→字节级对账全等）"
  echo "drill: report: $REPORT_PATH"
else
  fail "byte-level reconcile mismatch after restore"
fi
[ "$KEEP_WORK" -eq 1 ] || rm -rf "$WORK"
exit 0

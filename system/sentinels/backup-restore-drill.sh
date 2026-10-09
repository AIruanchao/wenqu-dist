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
#   3 恢复：从 archive（backup.tar.gz 独立解包产物）逐文件 cp -p 回 live/
#     （含重建被删文件）——恢复源是归档，不是旁边 backup/ 目录
#   4 对账：backup vs live 逐文件 cmp 字节级 + shasum 对清单
#
# 归档腿（G9-09/R8-BAK-FAKE-TAR-SUCCESS-019 强化——对 tar 谎报零信任）：
#   1b 归档：backup/ → backup.tar.gz（tar 经 PATH 解析，无豁免）+ tar -tzf
#      清单回读（逐文件精确行匹配）；
#   1c 归档实存验证：archive 必须存在、非空、普通文件（非 symlink/非目录/
#      非 fifo）、size>0；记录 archive SHA256 入报告（伪 tar「创建 rc0 但
#      不产归档」在这里必死——绝不信 tar 退出码自报成功）；
#   1d 独立解包对账：用独立实现（python3 tarfile——与 tar 通道完全无关的
#      另一条解包路径）把 archive 解到全新空目录，全部语料逐字节 cmp 对账
#      （账本 DB/聚合配置/心跳/样本全覆盖，强于抽样）。解包失败（截断/
#      损坏/路径逃逸/链接成员）或任一文件缺失/字节不等 = 演练 FAIL。
#      旧 archive 复用（同文件名、旧字节）在此对账必死。记录解包侧
#      逐文件 sha + 聚合 extract SHA256 入报告。
#
# 报告：JSON 落 <report-dir>/drill-<UTC时间戳>.json（默认
#   ${WENQU_HOME:-~/.wenqu}/observation/drills/）。
#   另落同缀 .jsonl 事件日志（每行 {ts,t,event,file,result[,...extra]}——
#   时间/文件/结果三要素，逐事件追加，供验收测试与审计直接核对）。
#   成功报告另记作业身份（drill 脚本与 wenqu_core/scheduler.py 源 SHA）、
#   archive hash、独立解包 hash、RPO/RTO 实测数值（G9-09 验收判据）。
# 退出码：0=PASS；1=FAIL（语料为空/步骤失败/归档不实存/解包对账不等/
#   对账不等/DR 指标越冻结目标）。失败运行只写自己的 FAIL 报告，绝不
#   改写既有 PASS 工件（= 不更新 last-success/成功 heartbeat）。
#
# DR 模式（--mode dr）：在四步之上加 RPO/RTO 实测计时（全部真跑）：
#   RPO = 最后快照点 -> 故障注入点（篡改开始）的实测时差。快照完成后
#         按 --fault-delay 秒注入已知故障延迟窗口（默认 1s），故 RPO
#         应 >= 该窗口且 <= 冻结目标——零/负值=伪造计时直接 FAIL。
#   RTO = 恢复开始（含 archive 独立解包——真实 DR 必须先解归档）-> 全部
#         对账通过的实测耗时。
#   冻结目标（本脚本内冻结，不接受 CLI 覆盖）：RPO<=300s、RTO<=60s。
#   DR PASS = 字节对账全等 && rpo_ok && rto_ok。
#
# 故障注入模式（--fault，R7-BAK-01 三腿补齐；演练在故障下必须 FAIL 且
# 不更新 success 工件——失败运行只写自己的 FAIL 报告，绝不改写既有 PASS）：
#   --fault enospc     磁盘满腿（等价模拟，诚实登记）：对恢复写路径注入
#         「文件大小上限」——小配额 tmpfs 在 macOS/无 root 不可移植，
#         以 ulimit -f 1（512B 块）子壳包裹恢复 cp，写出超限即写失败
#         （ENOSPC 同族：cp 非零退出/SIGXFSZ）。若注入未生效（语料全在
#         上限之下）也按 FAIL 拒绝——故障模式下绝不允许 PASS。
#   --fault tar-broken tar 腿：归档步骤（快照后 backup/ → backup.tar.gz
#         + tar -tzf 清单回读校验 + 1c 实存验证 + 1d 独立解包对账）经
#         PATH 解析真实 tar；本模式自注入假 tar 二进制（PATH 前置），
#         归档必须失败 → 演练 FAIL。外部 PATH 注入（测试前置假 tar 目录，
#         含「创建/清单双 rc0 谎报」「旧归档复用」「symlink 归档」「截断
#         归档」「伪清单内容缺失」五类）同效——脚本对 tar 无任何豁免：
#         tar 的 rc 与自报清单都不构成成功证据，归档必须实存且可被
#         独立实现逐字节还原。
#
# 用法：
#   bash system/sentinels/backup-restore-drill.sh [--wenqu-root DIR]
#        [--report-dir DIR] [--keep-workdir]
#        [--mode backup|dr] [--fault-delay SEC]（dr 专用，默认 1）
#        [--fault none|enospc|tar-broken]（默认 none）
set -uo pipefail

WENQU_ROOT="${WENQU_HOME:-$HOME/.wenqu}"
REPORT_DIR=""
KEEP_WORK=0
MODE="backup"
FAULT_DELAY="1"
FAULT="none"
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
    --fault) FAULT="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,70p' "$0"; exit 0 ;;
    *) echo "drill: unknown arg: $1" >&2; exit 1 ;;
  esac
done
case "$MODE" in backup|dr) ;; *) echo "drill: --mode must be backup|dr" >&2; exit 1 ;; esac
case "$FAULT" in none|enospc|tar-broken) ;; *) echo "drill: --fault must be none|enospc|tar-broken" >&2; exit 1 ;; esac
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
# 跨平台工具（macOS shasum/stat -f vs GNU sha256sum/stat -c）
_sha256() { if command -v /usr/bin/shasum >/dev/null 2>&1; then /usr/bin/shasum -a 256 "$@"; else sha256sum "$@"; fi; }
_sha256_stdin() { if command -v /usr/bin/shasum >/dev/null 2>&1; then /usr/bin/shasum -a 256; else sha256sum; fi; }
_file_mtime() { local f="$1"; if stat -f %m "$f" >/dev/null 2>&1; then stat -f %m "$f"; else stat -c %Y "$f"; fi; }
_file_size() { local f="$1"; if stat -f %z "$f" >/dev/null 2>&1; then stat -f %z "$f"; else stat -c %s "$f"; fi; }

# ---- 作业身份（G9-09：成功报告必须记录 scheduler/source SHA） -------------
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
_sha_or_null() {  # $1=文件 → 64hex 或 "null"（文件缺失/不可读时诚实记 null）
  local s=""
  [ -f "$1" ] && [ ! -L "$1" ] && s=$(_sha256 "$1" 2>/dev/null | awk '{print $1}')
  case "$s" in
    ''|*[!0-9a-f]*) echo "null" ;;
    *) echo "$s" ;;
  esac
}
DRILL_SCRIPT_SHA=$(_sha_or_null "$SCRIPT_DIR/$(basename -- "$0")")
SCHEDULER_SHA=$(_sha_or_null "$SCRIPT_DIR/../wenqu_core/scheduler.py")

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
    m=$(_file_mtime "$name" 2>/dev/null || echo 0)
    if [ "$m" -gt "$bestm" ]; then bestm="$m"; best="${name#"$WENQU_ROOT"/}"; fi
  done
  echo "$best"
}
for rel in "$(latest_json observation/samples)" "$(latest_json observation/shadow)"; do
  [ -n "$rel" ] && add_corpus "$rel"
done

fail() {  # $1=原因 → 写 FAIL 报告并退出 1（绝不改写既有 PASS 工件）
  write_report FAIL "$1"
  ev drill_fail - FAIL "\"reason\": \"$1\""
  echo "drill: FAIL: $1" >&2
  [ "$KEEP_WORK" -eq 1 ] && echo "drill: workdir kept: $WORK" >&2
  exit 1
}

REPORT_PATH="$REPORT_DIR/drill-$STAMP.json"
DR_JSON="null"
ARCHIVE_JSON="null"
write_report() {  # $1=result $2=reason；其余步骤事实由调用方拼进 $STEPS_JSON
  local bm="null"
  [ -n "${BYTE_MATCH_ALL:-}" ] && bm=$( [ "$BYTE_MATCH_ALL" -eq 1 ] && echo true || echo false )
  cat > "$REPORT_PATH.tmp" <<EOF
{
  "drill": "backup-restore",
  "stamp": "$STAMP",
  "mode": "$MODE",
  "fault": "$FAULT",
  "wenqu_root": "$WENQU_ROOT",
  "workdir": "$WORK",
  "identity": {
    "drill_script_sha256": "$DRILL_SCRIPT_SHA",
    "scheduler_sha256": "$SCHEDULER_SHA"
  },
  "corpus_count": ${#CORPUS_REL[@]},
  "steps": ${STEPS_JSON:-null},
  "archive": $ARCHIVE_JSON,
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
  sha=$(_sha256 "$BACKUP/$rel" | awk '{print $1}')
  size=$(_file_size "$BACKUP/$rel")
  [ "$FIRST" -eq 1 ] || SNAP_JSON+=", "; FIRST=0
  SNAP_JSON+="{\"rel\": \"$rel\", \"sha256\": \"$sha\", \"size\": $size}"
  ev snapshot_file "$rel" true "\"sha256\": \"$sha\", \"size\": $size"
done
SNAP_JSON+="]"

# ---- 步骤 1b：归档腿（tar 真实通道；R7-BAK-01 补齐） ----------------------
# backup/ → backup.tar.gz + tar -tzf 清单回读校验（逐文件精确行匹配）。
# tar 经 PATH 解析（无豁免）：--fault tar-broken 自注入假 tar（PATH 前置），
# 外部 PATH 注入假 tar 同效——归档/清单任一失败 → 演练 FAIL（fail-closed）。
# 注意：tar 的 rc0 与自报清单都只是「第一道闸」，不构成成功证据——归档
# 是否真实存在、能否被独立实现还原，由 1c/1d 决定（G9-09 强化）。
TAR_BIN="tar"
if [ "$FAULT" = "tar-broken" ]; then
  FAULT_BIN="$WORK/fault-bin"
  mkdir -p "$FAULT_BIN" || exit 1
  printf '#!/bin/sh\necho "drill fault: tar broken (injected)" >&2\nexit 1\n' \
    > "$FAULT_BIN/tar" || exit 1
  chmod +x "$FAULT_BIN/tar" || exit 1
  TAR_BIN="$FAULT_BIN/tar"
fi
ARCHIVE="$WORK/backup.tar.gz"
"$TAR_BIN" -czf "$ARCHIVE" -C "$BACKUP" "${CORPUS_REL[@]}" \
  || fail "archive tar leg failed under fault=$FAULT (rc=$?)"
"$TAR_BIN" -tzf "$ARCHIVE" > "$WORK/archive.list" 2>/dev/null \
  || fail "archive listing tar -tzf failed under fault=$FAULT (rc=$?)"
ARCHIVE_LIST_OK=1
for rel in "${CORPUS_REL[@]}"; do
  grep -Fxq "$rel" "$WORK/archive.list" || ARCHIVE_LIST_OK=0
done
[ "$ARCHIVE_LIST_OK" -eq 1 ] \
  || fail "archive listing incomplete: tar -tzf 清单与语料集不一致（tar 腿证据损坏/伪清单）"
ev archive_ok - true "\"files\": ${#CORPUS_REL[@]}, \"bytes\": $(_file_size "$ARCHIVE" 2>/dev/null || echo 0)"

# ---- 步骤 1c：归档实存验证（G9-09 A：不信 tar rc/清单自报） ---------------
# archive 必须是真实落盘的普通文件：存在、非空、非 symlink、非目录、
# 非 fifo（-f 只认普通文件；symlink 单独以 -L 拒绝——即使目标内容正确）。
if [ ! -f "$ARCHIVE" ] || [ -L "$ARCHIVE" ]; then
  fail "archive not materialized as a regular non-symlink file: ${ARCHIVE}（伪 tar 谎报 rc0/伪清单——归档不存在或是 symlink）"
fi
ARCHIVE_SIZE=$(_file_size "$ARCHIVE")
[ "$ARCHIVE_SIZE" -gt 0 ] 2>/dev/null \
  || fail "archive empty (size=$ARCHIVE_SIZE) — tar 归档腿产出为空"
ARCHIVE_SHA=$(_sha256 "$ARCHIVE" | awk '{print $1}')
case "$ARCHIVE_SHA" in
  ''|*[!0-9a-f]*) fail "archive sha256 unavailable（归档不可读）" ;;
esac
ev archive_verified - true "\"size\": $ARCHIVE_SIZE, \"sha256\": \"$ARCHIVE_SHA\""

# ---- 步骤 1d：独立解包对账（G9-09 B：另一条解包路径逐字节对账） -----------
# python3 tarfile（stdlib 独立实现，与 tar 通道零共享代码）解到全新空目录；
# 拒绝路径逃逸/绝对路径/链接成员；解包失败（截断/损坏 gz/坏头）或任一语料
# 缺失/字节不等（旧 archive 复用=同名单旧字节）→ FAIL。逐文件 cmp+sha 双证。
_extract_archive() {  # $1=archive $2=dest（必须为已存在的全新空目录）；rc0=成功
  python3 - "$1" "$2" <<'PYEX'
import sys, tarfile
arc, dest = sys.argv[1], sys.argv[2]
try:
    with tarfile.open(arc, "r:gz") as tf:
        for m in tf.getmembers():
            if m.name.startswith("/") or ".." in m.name.split("/"):
                sys.exit(3)          # 路径逃逸/绝对路径成员
            if m.issym() or m.islnk() or not (m.isfile() or m.isdir()):
                sys.exit(3)          # 链接/非常规成员
        try:
            tf.extractall(dest, filter="data")
        except TypeError:            # py<3.12 无 filter 参数
            tf.extractall(dest)
except SystemExit:
    raise
except Exception as exc:             # ReadError/EOFError(gz 截断)/OSError...
    print(f"independent extract failed: {exc!r}", file=sys.stderr)
    sys.exit(2)
sys.exit(0)
PYEX
}
EXTRACT_DIR="$WORK/extract-verify"
mkdir -p "$EXTRACT_DIR" || exit 1
_extract_archive "$ARCHIVE" "$EXTRACT_DIR" \
  || fail "independent archive extraction failed (rc=$?) — 归档不可解包（截断/损坏/路径逃逸/链接成员）"
EXTRACT_JSON="["; EXTRACT_OK=1; FIRST=1; EXTRACT_MISSING=""
for rel in "${CORPUS_REL[@]}"; do
  if [ -f "$EXTRACT_DIR/$rel" ] && [ ! -L "$EXTRACT_DIR/$rel" ] \
     && cmp -s "$BACKUP/$rel" "$EXTRACT_DIR/$rel" \
     && [ "$(_sha256 "$EXTRACT_DIR/$rel" | awk '{print $1}')" = "$(_sha256 "$BACKUP/$rel" | awk '{print $1}')" ]; then
    esha=$(_sha256 "$EXTRACT_DIR/$rel" | awk '{print $1}')
    esz=$(_file_size "$EXTRACT_DIR/$rel")
    [ "$FIRST" -eq 1 ] || EXTRACT_JSON+=", "; FIRST=0
    EXTRACT_JSON+="{\"rel\": \"$rel\", \"sha256\": \"$esha\", \"size\": $esz}"
    ev extract_file "$rel" true "\"sha256\": \"$esha\""
  else
    EXTRACT_OK=0; EXTRACT_MISSING+="$rel "
    ev extract_file "$rel" false "\"cmp\": false"
  fi
done
EXTRACT_JSON+="]"
[ "$EXTRACT_OK" -eq 1 ] \
  || fail "archive extract reconcile mismatch/missing: 独立解包对账不等或缺失（旧归档复用/内容缺失/字节漂移）: $EXTRACT_MISSING"
EXTRACT_SHA=$(for rel in "${CORPUS_REL[@]}"; do
    printf '%s %s\n' "$rel" "$(_sha256 "$EXTRACT_DIR/$rel" | awk '{print $1}')"
  done | _sha256_stdin | awk '{print $1}')
ARCHIVE_JSON=$(cat <<EOF
{
  "path": "$ARCHIVE",
  "size": $ARCHIVE_SIZE,
  "sha256": "$ARCHIVE_SHA",
  "extract_sha256": "$EXTRACT_SHA",
  "listing_files": ${#CORPUS_REL[@]},
  "materialized": true,
  "files": $EXTRACT_JSON
}
EOF
)
ev extract_reconcile - true "\"files\": ${#CORPUS_REL[@]}, \"extract_sha256\": \"$EXTRACT_SHA\""

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
    sha_now=$(_sha256 "$LIVE/$rel" 2>/dev/null | awk '{print $1}')
    sha_old=$(_sha256 "$BACKUP/$rel" | awk '{print $1}')
    [ "$sha_now" != "$sha_old" ] || TAMPER_VERIFIED=0
  fi
done
[ "$TAMPER_VERIFIED" -eq 1 ] || fail "tamper did not actually change bytes (fake drill)"
ev tamper_verified - true "\"actions\": ${TAMPER_JSON}"

# ---- 步骤 3：恢复（G9-09 C：真正从 archive 恢复，不从 backup/ 复制） -------
# 恢复源 = archive 的第二次独立解包（隔离目录 restore-from-archive/，与 1d
# 的 extract-verify/ 互不共享）；解包后复核 archive hash 未在演练中途被换
# （防 TOCTOU 换归档）。live/ 的每个文件都从该解包产物 cp -p 恢复——
# 「恢复走归档」由对账闭环证明：live == backup 字节全等 ⇔ 归档内容 ==
# 快照内容（1d 已独立证明 归档==backup，此处 live==backup 与 cp 源审计
# 双证恢复真实走的是归档通道）。
# DR：恢复开始即 RTO 起表（真实 DR 必须先解归档——解包计入 RTO）。
# --fault enospc：恢复写路径注入「文件大小上限」（ulimit -f 1 = 512B，子壳
# 包裹——等价模拟磁盘满写出失败；只作用于恢复写，快照/归档/对账不受影响）。
# 故障模式下注入必须生效：若全部语料都在上限之下（注入未咬合）也按 FAIL
# 拒绝——故障注入演练绝不允许 PASS。
[ "$MODE" = "dr" ] && T_RESTORE_START=$(_epoch)
RESTORE_SRC="$WORK/restore-from-archive"
mkdir -p "$RESTORE_SRC" || exit 1
_extract_archive "$ARCHIVE" "$RESTORE_SRC" \
  || fail "restore extraction from archive failed (rc=$?) — 恢复源解包失败（归档在演练中途损坏）"
ARCHIVE_SHA_RESTORE=$(_sha256 "$ARCHIVE" | awk '{print $1}')
[ "$ARCHIVE_SHA_RESTORE" = "$ARCHIVE_SHA" ] \
  || fail "archive mutated during drill (sha256 changed after 1c verification) — TOCTOU 换归档"
for rel in "${CORPUS_REL[@]}"; do
  [ -f "$RESTORE_SRC/$rel" ] && [ ! -L "$RESTORE_SRC/$rel" ] \
    || fail "restore source missing member: ${rel}（归档缺少恢复所需成员）"
done
ev restore_extract - true "\"src\": \"$RESTORE_SRC\", \"sha256\": \"$ARCHIVE_SHA_RESTORE\""
RESTORE_N=0
RESTORE_FAULT_HIT=0
for rel in "${CORPUS_REL[@]}"; do
  if [ "$FAULT" = "enospc" ]; then
    if ( ulimit -f 1 2>/dev/null; exec cp -p "$RESTORE_SRC/$rel" "$LIVE/$rel" ); then
      :
    else
      FRC=$?
      RESTORE_FAULT_HIT=1
      ev restore_file "$rel" false "\"fault\": \"enospc\", \"rc\": $FRC"
      fail "restore cp $rel (enospc fault: write size cap hit, rc=$FRC)"
    fi
  else
    cp -p "$RESTORE_SRC/$rel" "$LIVE/$rel" || fail "restore cp $rel"
  fi
  RESTORE_N=$((RESTORE_N+1))
  ev restore_file "$rel" true "\"n\": $RESTORE_N, \"src\": \"archive\""
done
if [ "$FAULT" = "enospc" ] && [ "$RESTORE_FAULT_HIT" -eq 0 ]; then
  fail "enospc fault did not trigger (all corpus files under the 512B write cap) — injection ineffective, refusing to PASS"
fi

# ---- 步骤 4：字节级对账（live[来自归档] vs backup[快照正本]） ---------------
BYTE_MATCH_ALL=1
RECON_JSON="["
FIRST=1
for rel in "${CORPUS_REL[@]}"; do
  sha_old=$(_sha256 "$BACKUP/$rel" | awk '{print $1}')
  sha_now=$(_sha256 "$LIVE/$rel" | awk '{print $1}')
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
  "archive": {"ok": true, "listing_ok": true, "materialized": true, "size": $ARCHIVE_SIZE, "sha256": "$ARCHIVE_SHA", "extract_sha256": "$EXTRACT_SHA"},
  "tamper": {"ok": $( [ "$TAMPER_VERIFIED" -eq 1 ] && echo true || echo false ), "actions": $TAMPER_JSON},
  "restore": {"ok": true, "source": "archive", "files_restored": $RESTORE_N},
  "reconcile": {"files": $RECON_JSON}
}
EOF
)
if [ "$MODE" = "dr" ]; then
  if [ "$BYTE_MATCH_ALL" -eq 1 ] && [ "$RPO_OK" = "true" ] && [ "$RTO_OK" = "true" ]; then
    write_report PASS "4/4 steps ok; byte-identical restore; RPO=${RPO_S}s<=${DR_RPO_TARGET_S}s, RTO=${RTO_S}s<=${DR_RTO_TARGET_S}s (frozen targets met)"
    ev drill_pass - PASS "\"rpo_seconds\": $RPO_S, \"rto_seconds\": $RTO_S, \"archive_sha256\": \"$ARCHIVE_SHA\", \"extract_sha256\": \"$EXTRACT_SHA\""
    echo "drill: PASS 4/4（快照${#CORPUS_REL[@]}文件→篡改→从归档恢复→字节级对账全等）"
    echo "drill: DR 实测 RPO=${RPO_S}s（目标<=${DR_RPO_TARGET_S}s） RTO=${RTO_S}s（目标<=${DR_RTO_TARGET_S}s）"
    echo "drill: archive sha256=$ARCHIVE_SIZE bytes $ARCHIVE_SHA; 独立解包 extract_sha256=$EXTRACT_SHA"
    echo "drill: report: $REPORT_PATH"
  elif [ "$BYTE_MATCH_ALL" -ne 1 ]; then
    fail "byte-level reconcile mismatch after restore"
  else
    fail "DR frozen targets not met: RPO=${RPO_S}s(rpo_ok=$RPO_OK) RTO=${RTO_S}s(rto_ok=$RTO_OK)"
  fi
elif [ "$BYTE_MATCH_ALL" -eq 1 ]; then
  write_report PASS "4/4 steps ok; all restored files byte-identical to snapshot (restored from archive; archive independently extracted+reconciled)"
  ev drill_pass - PASS "\"archive_sha256\": \"$ARCHIVE_SHA\", \"extract_sha256\": \"$EXTRACT_SHA\""
  echo "drill: PASS 4/4（快照${#CORPUS_REL[@]}文件→篡改→从归档恢复→字节级对账全等）"
  echo "drill: archive sha256=$ARCHIVE_SIZE bytes $ARCHIVE_SHA; 独立解包 extract_sha256=$EXTRACT_SHA"
  echo "drill: report: $REPORT_PATH"
else
  fail "byte-level reconcile mismatch after restore"
fi
[ "$KEEP_WORK" -eq 1 ] || rm -rf "$WORK"
exit 0

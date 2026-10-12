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
# W11-13 release 模式（--mode release|release-dr）——Sfinal 最终字节正演练：
#   语料 = git archive <commit> 导出的 Sfinal 干净树字节（与工作树无关；
#   正源 repo 默认 $WENQU_GIT_REPO（受控 clone）否则脚本所在仓，commit 默认
#   $WENQU_RELEASE_SHA 否则 HEAD——生产部署树无 .git，必须经受控 clone 取
#   最终字节）。链路：
#     R1 快照   git archive → 空目录解出 live/ + 构建逐文件 manifest
#               （path/type/mode/size/sha256，symlink 记 target；canonical
#               JSON 的 sha256 即 manifest_sha256）
#     R2 容量   峰值占用≈5×语料 + 64MiB 余量 vs 实测 free（--min-free-bytes
#               可抬高底线）——不足=BLOCKED rc3，绝不删既有证据换通过
#     R3 归档   tar -czf（PATH 解析无豁免）+ 实存验证（1c 同款）+ 独立解包
#               （python3 tarfile 第二条解包路径）对账 manifest：
#               missing/extra/drifted/mode/type 五面全查
#     R4 篡改   live/ 追加/截断/删除/chmod/extra 五类轮转（实测已变）
#     R5 恢复   全空隔离根 restore-root/（不存在→新建；空根先决记录），
#               归档独立解包恢复 + TOCTOU 复核归档 sha
#     R6 对账   恢复根 vs manifest：missing/extra/hash/mode/类型 全查
#     R7 验证器 release verifier = wenqu_core.release_drift.audit_tree
#               （生产树对账正源：内容+类型+激活只读不变量；恢复根先施加
#               chmod -R a-w 激活协议再验）——ok=false 即 FAIL
#   release-dr 另做 RPO/RTO 实测计时（同 DR 冻结目标 300s/60s）。
#   报告绑定：run_id（baddrill-<stamp>）、Sfinal commit、deployment epoch
#   （--epoch-file 或 $WENQU_ROOT/.activation-epoch.json 探测）、release
#   manifest sha256 + tree root/restore root、身份 SHA（drill/scheduler）。
#   last-success.json：<report-dir>/last-success.json——仅完整 PASS 且报告
#   fsync 后原子推进（tmp+fsync+rename+dir fsync）；FAIL/BLOCKED 绝不触碰。
#   进程锁：$WENQU_ROOT/state/backup-drill.lock（fd 级 flock，进程生存期）
#   ——scheduler 作业与手工演练共用，重叠即 rc1 fail-closed。
#   退出码：0=PASS；1=归档/恢复/完整性/并发重叠失败；3=权限/容量/目标不可用。
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
#        [--mode backup|dr|release|release-dr] [--fault-delay SEC]
#        （dr/release-dr 专用，默认 1）
#        [--fault none|enospc|tar-broken]（backup/dr 专用，默认 none）
#        （release/release-dr 专用：）
#        [--repo DIR]（Sfinal 字节正源仓，默认 $WENQU_GIT_REPO 或脚本仓）
#        [--source-commit SHA]（默认 $WENQU_RELEASE_SHA 或 HEAD）
#        [--epoch-file PATH]（deployment epoch JSON，缺省探测激活水位）
#        [--min-free-bytes N]（容量底线，不足 BLOCKED rc3）
set -uo pipefail

WENQU_ROOT="${WENQU_HOME:-$HOME/.wenqu}"
REPORT_DIR=""
KEEP_WORK=0
MODE="backup"
FAULT_DELAY="1"
FAULT="none"
REPO_ARG=""
SOURCE_COMMIT_ARG=""
EPOCH_FILE=""
MIN_FREE_BYTES=""
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
    --repo) REPO_ARG="${2:?}"; shift 2 ;;
    --source-commit) SOURCE_COMMIT_ARG="${2:?}"; shift 2 ;;
    --epoch-file) EPOCH_FILE="${2:?}"; shift 2 ;;
    --min-free-bytes) MIN_FREE_BYTES="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,110p' "$0"; exit 0 ;;
    *) echo "drill: unknown arg: $1" >&2; exit 1 ;;
  esac
done
case "$MODE" in backup|dr|release|release-dr) ;; *) echo "drill: --mode must be backup|dr|release|release-dr" >&2; exit 1 ;; esac
case "$FAULT" in none|enospc|tar-broken) ;; *) echo "drill: --fault must be none|enospc|tar-broken" >&2; exit 1 ;; esac
case "$FAULT_DELAY" in
  ''|*[!0-9.]*) echo "drill: --fault-delay must be a positive number" >&2; exit 1 ;;
esac
if [ -n "$MIN_FREE_BYTES" ]; then
  case "$MIN_FREE_BYTES" in
    *[!0-9]*) echo "drill: --min-free-bytes must be a non-negative integer" >&2; exit 1 ;;
  esac
fi
case "$MODE" in
  release|release-dr)
    if [ "$FAULT" != "none" ]; then
      echo "drill: --fault 仅适用于 backup/dr 模式" >&2; exit 1
    fi ;;
esac
REPORT_DIR="${REPORT_DIR:-$WENQU_ROOT/observation/drills}"
# macOS bsdtar 默认为带扩展属性的文件追加 ._* AppleDouble 成员——它们不是
# Sfinal 树字节的一部分（manifest 不含），会让归档对账出现 extra。全局关闭
#（含假 tar 子进程与解包侧；GNU tar 忽略此变量，跨平台无副作用）。
export COPYFILE_DISABLE=1
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
# 同秒并发防覆写：工件名已存在则在 Z 后紧贴追加零填充序号
# （drill-<stamp>02.json），绝不覆盖既有演练证据。
# 序号必须紧贴 Z（无 '-' 分隔符）：'0'-'9'(0x30+) > '.'(0x2E)，保证
# 词典序=时间序——同秒后到者排在基名之后、仍先于后秒基名。旧式
# -<seq> 后缀因 '-'(0x2D) < '.' 排在基名之前，「取最新 drill-*.json」
# 的词典序消费方（测试 _latest_report / drill_runner / ops 审计）会取到
# 陈旧报告——CI 慢机 p0 PASS 与 p1 BLOCKED 同秒窗口实测红，W11-13 根修。
_SEQ=1
while [ -e "$REPORT_DIR/drill-$STAMP.json" ] || [ -e "$REPORT_DIR/drill-$STAMP.jsonl" ]; do
  _SEQ=$((_SEQ+1))
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)$(printf '%02d' "$_SEQ")"
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wenqu-drill.XXXXXXXX")" || exit 1
LIVE="$WORK/live"; BACKUP="$WORK/backup"
mkdir -p "$LIVE" "$BACKUP" "$REPORT_DIR" || exit 1
# 报告目标可写性（权限类 rc3 先决——写不了审计证据的目标不可用；必须在
# jsonl/报告任何写动作之前判定）
if [ ! -w "$REPORT_DIR" ]; then
  echo "drill: BLOCKED: report dir not writable (permission): $REPORT_DIR" >&2
  exit 3
fi

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
RELEASE_JSON="null"
LAST_SUCCESS_JSON="null"
RUN_ID="baddrill-$STAMP"
write_report() {  # $1=result $2=reason；其余步骤事实由调用方拼进 $STEPS_JSON
  local bm="null"
  [ -n "${BYTE_MATCH_ALL:-}" ] && bm=$( [ "$BYTE_MATCH_ALL" -eq 1 ] && echo true || echo false )
  cat > "$REPORT_PATH.tmp" <<EOF
{
  "drill": "backup-restore",
  "stamp": "$STAMP",
  "run_id": "$RUN_ID",
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
  "release": $RELEASE_JSON,
  "dr": $DR_JSON,
  "result": "$1",
  "reason": "$2",
  "byte_match_all": $bm,
  "last_success": $LAST_SUCCESS_JSON,
  "jsonl": "$JSONL_PATH"
}
EOF
  mv "$REPORT_PATH.tmp" "$REPORT_PATH"
}

# 报告目标可写性已在 jsonl/报告写动作前判定（见 WORK 建立处）。

# ---- 事件首帧：drill_start（backup/dr 模式；release 模式在解析出
# Sfinal 正源后自记 drill_start）——jsonl 事件序列契约：首=drill_start ----
if [ "$MODE" != "release" ] && [ "$MODE" != "release-dr" ]; then
  [ "${#CORPUS_REL[@]}" -ge 1 ] || fail "corpus empty: no production state files under $WENQU_ROOT"
  ev drill_start - "$MODE" "\"corpus_count\": ${#CORPUS_REL[@]}, \"wenqu_root\": \"$WENQU_ROOT\""
fi

# ---- W11-13 共用进程锁（scheduler/manual 演练禁止重叠；fd 生存期=本进程） --
# fd 9 打开锁文件（继承给 python3 子进程做 flock）；锁随 bash 进程退出释放
# （含 kill：fd 关闭即解锁）——无陈旧锁文件问题。取锁失败=并发重叠=rc1。
LOCK_DIR="$WENQU_ROOT/state"
if ! mkdir -p "$LOCK_DIR" 2>/dev/null; then
  echo "drill: BLOCKED: cannot create lock dir (permission): $LOCK_DIR" >&2
  exit 3
fi
LOCK_FILE="$LOCK_DIR/backup-drill.lock"
if ! exec 9>>"$LOCK_FILE"; then
  echo "drill: BLOCKED: cannot open lock file (permission): $LOCK_FILE" >&2
  exit 3
fi
if ! python3 -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)' 2>/dev/null; then
  LOCK_REASON="concurrent drill refused: shared lock busy ($LOCK_FILE) — scheduler/manual 演练禁止重叠（W11-13 唯一 backup 作业纪律）"
  write_report FAIL "$LOCK_REASON"
  ev drill_fail - FAIL "\"reason\": \"$LOCK_REASON\""
  echo "drill: FAIL: $LOCK_REASON" >&2
  exit 1
fi
ev lock_acquired - true "\"lock\": \"$LOCK_FILE\""

# ═══════════════════════════════════════════════════════════════════════
# W11-13 release 模式：Sfinal 最终字节备份恢复正演练（独立流程，自收敛退出）
# ═══════════════════════════════════════════════════════════════════════
SYSTEM_DIR="$SCRIPT_DIR/.."

fail3() {  # $1=原因 → BLOCKED 报告 + rc3（权限/容量/目标不可用；不删任何证据）
  write_report BLOCKED "$1"
  ev drill_blocked - BLOCKED "\"reason\": \"$1\""
  echo "drill: BLOCKED: $1" >&2
  [ "$KEEP_WORK" -eq 1 ] && echo "drill: workdir kept: $WORK" >&2
  exit 3
}

if [ "$MODE" = "release" ] || [ "$MODE" = "release-dr" ]; then

# ---- R0：正源解析（repo/commit/epoch）------------------------------------
GIT_BIN="$(command -v git || true)"
[ -n "$GIT_BIN" ] || fail3 "git unavailable（Sfinal 字节正源不可达=目标不可用）"
RELEASE_REPO="${REPO_ARG:-${WENQU_GIT_REPO:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}}"
[ -d "$RELEASE_REPO" ] || fail3 "source repo unavailable: $RELEASE_REPO"
RELEASE_COMMIT_SPEC="${SOURCE_COMMIT_ARG:-${WENQU_RELEASE_SHA:-HEAD}}"
RELEASE_COMMIT="$("$GIT_BIN" -C "$RELEASE_REPO" rev-parse --verify \
  "${RELEASE_COMMIT_SPEC}^{commit}" 2>/dev/null | tr 'A-F' 'a-f' || true)"
case "$RELEASE_COMMIT" in
  ''|*[!0-9a-f]*) fail3 "source commit unresolved in $RELEASE_REPO: $RELEASE_COMMIT_SPEC";;
esac
[ "${#RELEASE_COMMIT}" -eq 40 ] \
  || fail3 "source commit not 40-hex: $RELEASE_COMMIT"

# deployment epoch 绑定：--epoch-file 显式（必须可解析）否则探测激活水位，
# 两者皆无 → null+absent（诚实登记，不编造）。
EPOCH_VAL="null"; EPOCH_SRC="absent"
if [ -n "$EPOCH_FILE" ]; then
  [ -f "$EPOCH_FILE" ] || fail3 "epoch file unavailable: $EPOCH_FILE"
  _ev="$(python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get("epoch"); assert isinstance(v,int) and v>=0; print(v)' "$EPOCH_FILE" 2>/dev/null || true)"
  case "$_ev" in ''|*[!0-9]*) fail3 "epoch file invalid (epoch must be non-negative int): $EPOCH_FILE";; esac
  EPOCH_VAL="$_ev"; EPOCH_SRC="epoch-file:$EPOCH_FILE"
elif [ -f "$WENQU_ROOT/.activation-epoch.json" ]; then
  _ev="$(python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get("epoch"); print(v if isinstance(v,int) and v>=0 else "")' "$WENQU_ROOT/.activation-epoch.json" 2>/dev/null || true)"
  if [ -n "$_ev" ]; then EPOCH_VAL="$_ev"; EPOCH_SRC="activation-watermark:$WENQU_ROOT/.activation-epoch.json"; fi
fi
ev drill_start - "$MODE" "\"corpus\": \"git-archive:$RELEASE_COMMIT\", \"repo\": \"$RELEASE_REPO\", \"deployment_epoch\": $EPOCH_VAL"

# ---- R1：快照（git archive Sfinal 干净树 → 空目录 + 逐文件 manifest）------
if ! "$GIT_BIN" -C "$RELEASE_REPO" archive --format=tar "$RELEASE_COMMIT" \
     > "$WORK/source.tar" 2>/dev/null; then
  fail3 "git archive failed（Sfinal 字节不可导出=目标不可用）"
fi
_extract_release() {  # $1=tar(gz) $2=dest；rc0=成功（拒绝逃逸/非常规成员）
  python3 - "$1" "$2" <<'PYRELEX'
import os, sys, tarfile
arc, dest = sys.argv[1], sys.argv[2]
def _safe(name):
    return not name.startswith("/") and ".." not in name.split("/")
try:
    with tarfile.open(arc, "r:*") as tf:
        members = tf.getmembers()
        for m in members:
            if not _safe(m.name) or (m.islnk() and not _safe(m.linkname)):
                sys.exit(3)                       # 路径逃逸/绝对路径
            if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
                sys.exit(3)                       # fifo/char/blk/dev 契约外
        for m in members:
            target = os.path.join(dest, m.name)
            if m.isdir():
                os.makedirs(target, exist_ok=True)
            elif m.issym():
                if os.path.lexists(target):
                    os.unlink(target)
                os.symlink(m.linkname, target)
            elif m.islnk():
                src = os.path.join(dest, m.linkname)
                if not os.path.exists(src):
                    sys.exit(4)                   # 硬链接目标未先落盘
                if os.path.lexists(target):
                    os.unlink(target)
                os.link(src, target)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                fh = tf.extractfile(m)
                if fh is None:
                    sys.exit(3)
                with open(target, "wb") as out:
                    while True:
                        chunk = fh.read(1 << 20)
                        if not chunk:
                            break
                        out.write(chunk)
                os.chmod(target, m.mode & 0o7777)
except SystemExit:
    raise
except Exception as exc:
    print(f"release extract failed: {exc!r}", file=sys.stderr)
    sys.exit(2)
sys.exit(0)
PYRELEX
}
LIVE="$WORK/live"
_extract_release "$WORK/source.tar" "$LIVE" \
  || fail "Sfinal snapshot extraction failed (rc=$?)"
MANIFEST_PATH="$WORK/sfinal.manifest.json"
PATHS_FILE="$WORK/manifest-paths.txt"       # 全部成员（file+symlink）
FILES_FILE="$WORK/manifest-files.txt"       # 可篡改常规文件（file 类型）
export WQ_RELEASE_COMMIT="$RELEASE_COMMIT"
N_FILES="$(python3 - "$LIVE" "$MANIFEST_PATH" "$PATHS_FILE" "$FILES_FILE" <<'PYMAN'
import hashlib, json, os, stat, sys
live, manifest_path, paths_file, files_file = (
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
records, paths, files = [], [], []
for dirpath, dirnames, filenames in os.walk(live):
    dirnames.sort()
    # symlink→目录成员落在 dirnames（followlinks=False 不下钻但必须入清单——
    # 与 release_drift._iter_tree_entries 同形，否则验证器判 extra）
    for name in sorted(dirnames + filenames):
        full = os.path.join(dirpath, name)
        rel = os.path.relpath(full, live)
        st = os.lstat(full)
        if stat.S_ISLNK(st.st_mode):
            tgt = os.readlink(full)
            records.append({"path": rel, "type": "symlink",
                            "sha256": hashlib.sha256(
                                tgt.encode("utf-8")).hexdigest(),
                            "symlink_target": tgt, "size": len(tgt.encode())})
            paths.append(rel)
        elif stat.S_ISDIR(st.st_mode):
            continue          # 真目录由文件路径蕴含，不入清单（tar 契约）
        elif stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(full, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            records.append({"path": rel, "type": "file",
                            "mode": stat.S_IMODE(st.st_mode),
                            "size": st.st_size, "sha256": h.hexdigest()})
            paths.append(rel)
            files.append(rel)
        else:
            sys.stderr.write(f"special member in Sfinal tree: {rel}\n")
            sys.exit(5)
records.sort(key=lambda r: r["path"])
manifest = {"schema": "wenqu-backup-manifest/1",
            "source_commit": os.environ.get("WQ_RELEASE_COMMIT", ""),
            "files": records}
with open(manifest_path, "w", encoding="utf-8") as fh:
    fh.write(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
with open(paths_file, "w", encoding="utf-8") as fh:
    fh.write("\n".join(paths) + ("\n" if paths else ""))
with open(files_file, "w", encoding="utf-8") as fh:
    fh.write("\n".join(sorted(files)) + ("\n" if files else ""))
total_bytes = sum(r["size"] for r in records if r["type"] == "file")
print(f"{len(records)} {total_bytes}")
PYMAN
)"
NFB="$N_FILES"            # 原串 "<n_files> <bytes>"——先留原串再拆两段
N_FILES="${NFB%% *}"
LIVE_BYTES="${NFB#* }"
case "$N_FILES" in ''|*[!0-9]*|0) fail "Sfinal manifest empty（语料为空=完整性失败）";; esac
case "$LIVE_BYTES" in ''|*[!0-9]*) LIVE_BYTES=0 ;; esac
[ "$LIVE_BYTES" -gt 0 ] || fail "Sfinal corpus bytes=0（空树不可作备份语料）"
MANIFEST_SHA=$(_sha256 "$MANIFEST_PATH" | awk '{print $1}')
ev snapshot_file sfinal.manifest.json true "\"n_files\": $N_FILES, \"bytes\": $LIVE_BYTES, \"manifest_sha256\": \"$MANIFEST_SHA\""

# ---- R2：容量前置（不足=BLOCKED rc3；绝不删除审计证据换取通过）------------
CAPACITY_JSON="$(python3 - "$WORK" "$REPORT_DIR" "$LIVE_BYTES" "${MIN_FREE_BYTES:-0}" <<'PYCAP'
import json, shutil, sys
work, rdir, corpus, floor = (sys.argv[1], sys.argv[2], int(sys.argv[3]),
                             int(sys.argv[4]))
free = min(shutil.disk_usage(work).free, shutil.disk_usage(rdir).free)
required = corpus * 5 + 64 * 1024 * 1024   # 峰值≈5×语料 + 64MiB 余量
required = max(required, floor)
print(json.dumps({"free_bytes": free, "required_bytes": required,
                  "corpus_bytes": corpus, "min_free_override": floor,
                  "ok": free >= required}))
PYCAP
)"
CAP_OK="$(printf '%s' "$CAPACITY_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ok"])' 2>/dev/null || echo False)"
if [ "$CAP_OK" != "True" ]; then
  _cap_sum="$(printf '%s' "$CAPACITY_JSON" | python3 -c 'import json,sys
d=json.load(sys.stdin)
print("free_bytes={free_bytes} required_bytes={required_bytes} "
      "corpus_bytes={corpus_bytes} min_free_override={min_free_override}"
      .format(**d))' 2>/dev/null || true)"
  fail3 "容量不足（capacity BLOCKED）：${_cap_sum} —— 保持 BLOCKED，绝不以删除审计证据换取通过"
fi

# ---- R3：归档腿（tar 经 PATH 解析无豁免；实存验证 + 独立解包对账）---------
TAR_BIN="tar"
ARCHIVE="$WORK/backup.tar.gz"
tops=()
for p in "$LIVE"/* "$LIVE"/.[!.]* "$LIVE"/..?*; do
  [ -e "$p" ] || [ -L "$p" ] || continue
  tops+=("${p#"$LIVE"/}")
done
[ "${#tops[@]}" -ge 1 ] || fail "release corpus top-level empty"
"$TAR_BIN" -czf "$ARCHIVE" -C "$LIVE" "${tops[@]}" \
  || fail "release archive tar leg failed (rc=$?)"
# 3a 实存验证（伪 tar 谎报 rc0 在此必死）
if [ ! -f "$ARCHIVE" ] || [ -L "$ARCHIVE" ]; then
  fail "release archive not materialized as a regular non-symlink file: ${ARCHIVE}（伪 tar 谎报 rc0——归档不存在或是 symlink）"
fi
ARCHIVE_SIZE=$(_file_size "$ARCHIVE")
[ "$ARCHIVE_SIZE" -gt 0 ] 2>/dev/null || fail "release archive empty (size=$ARCHIVE_SIZE)"
ARCHIVE_SHA=$(_sha256 "$ARCHIVE" | awk '{print $1}')
case "$ARCHIVE_SHA" in ''|*[!0-9a-f]*) fail "release archive sha256 unavailable";; esac
ev archive_verified - true "\"size\": $ARCHIVE_SIZE, \"sha256\": \"$ARCHIVE_SHA\""
# 3b 独立解包（python3 tarfile 第二路径）→ manifest 五面对账
#     （missing/extra/drifted/mode/type——mode/extra 篡改归档在此必死）
EXTRACT_DIR="$WORK/extract-verify"
mkdir -p "$EXTRACT_DIR" || exit 1
_extract_release "$ARCHIVE" "$EXTRACT_DIR" \
  || fail "release independent archive extraction failed (rc=$?) — 归档不可解包（截断/损坏/路径逃逸/契约外成员）"
RECON_EXTRACT="$(python3 - "$MANIFEST_PATH" "$EXTRACT_DIR" "$WORK/recon-extract.json" <<'PYRECON'
import hashlib, json, os, stat, sys
manifest_path, root, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
manifest = json.load(open(manifest_path, encoding="utf-8"))
exp = {r["path"]: r for r in manifest["files"]}
act = {}
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort()
    for name in sorted(dirnames + filenames):  # symlink→目录在 dirnames
        full = os.path.join(dirpath, name)
        rel = os.path.relpath(full, root)
        st = os.lstat(full)
        if stat.S_ISLNK(st.st_mode):
            act[rel] = {"type": "symlink",
                        "sha256": hashlib.sha256(
                            os.readlink(full).encode("utf-8")).hexdigest()}
        elif stat.S_ISDIR(st.st_mode):
            continue          # 真目录由文件路径蕴含，不入对账（同 manifest）
        elif stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(full, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            act[rel] = {"type": "file", "mode": stat.S_IMODE(st.st_mode),
                        "sha256": h.hexdigest()}
        else:
            act[rel] = {"type": "special"}
rep = {"missing": [], "extra": [], "drifted": [], "mode": [], "type": []}
for p in sorted(exp):
    if p not in act:
        rep["missing"].append(p); continue
    e, a = exp[p], act[p]
    if e["type"] != a["type"]:
        rep["type"].append(p); continue
    if e["sha256"] != a["sha256"]:
        rep["drifted"].append(p); continue
    if e["type"] == "file" and int(e.get("mode", 0)) != int(a["mode"]):
        rep["mode"].append(p)
rep["extra"] = sorted(set(act) - set(exp))
rep["ok"] = not any(rep[k] for k in ("missing", "extra", "drifted", "mode", "type"))
for k in ("missing", "extra", "drifted", "mode", "type"):
    rep[k] = rep[k][:5]
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(json.dumps(rep))
print(rep["ok"])
PYRECON
)"
[ "$RECON_EXTRACT" = "True" ] || {
  _recon_sum="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print(" ".join(f"{k}={d.get(k)}" for k in
      ("missing","extra","drifted","mode","type") if d.get(k)))
' "$WORK/recon-extract.json" 2>/dev/null || true)"
  fail "release archive extract reconcile mismatch（${_recon_sum}）"
}
EXTRACT_SHA="$(python3 - "$MANIFEST_PATH" "$EXTRACT_DIR" <<'PYAGG'
import hashlib, json, os, sys
manifest, root = json.load(open(sys.argv[1], encoding="utf-8")), sys.argv[2]
lines = []
for r in sorted(manifest["files"], key=lambda r: r["path"]):
    full = os.path.join(root, r["path"])
    h = hashlib.sha256()
    if os.path.islink(full):
        h.update(os.readlink(full).encode("utf-8"))
    else:
        with open(full, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    lines.append(f"{r['path']} {h.hexdigest()}")
print(hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest())
PYAGG
)"
ARCHIVE_JSON=$(cat <<EOF
{
  "path": "$ARCHIVE",
  "size": $ARCHIVE_SIZE,
  "sha256": "$ARCHIVE_SHA",
  "extract_sha256": "$EXTRACT_SHA",
  "listing_files": $N_FILES,
  "materialized": true
}
EOF
)
ev extract_reconcile - true "\"files\": $N_FILES, \"extract_sha256\": \"$EXTRACT_SHA\""
# 3c 清单回读（最后道闸：tar -tzf 输出必须覆盖全部 manifest 成员）
"$TAR_BIN" -tzf "$ARCHIVE" > "$WORK/archive.list" 2>/dev/null \
  || fail "release archive listing tar -tzf failed (rc=$?)"
LISTING_OK="$(python3 - "$MANIFEST_PATH" "$WORK/archive.list" <<'PYLIST'
import json, sys
exp = {r["path"] for r in json.load(open(sys.argv[1], encoding="utf-8"))["files"]}
got = set()
with open(sys.argv[2], encoding="utf-8") as fh:
    for ln in fh:
        n = ln.strip()
        if n.startswith("./"):
            n = n[2:]
        if n:
            got.add(n)
print(exp <= got)
PYLIST
)"
[ "$LISTING_OK" = "True" ] || fail "release archive listing incomplete: tar -tzf 清单未覆盖全部 Sfinal 成员（伪清单/内容缺失）"

# ---- R4（release-dr）：故障窗计时（RPO=快照点→故障注入点）----------------
if [ "$MODE" = "release-dr" ]; then
  T_SNAP_DONE=$(_epoch)
  sleep "$FAULT_DELAY"
  T_FAULT=$(_epoch)
  RPO_S=$(_fsub "$T_FAULT" "$T_SNAP_DONE")
  ev fault_window - true "\"rpo_seconds\": $RPO_S, \"fault_delay_s\": $FAULT_DELAY"
fi

# ---- R5：篡改 live/（五类轮转；实测已变，防伪造演练）----------------------
# 单进程 python 执行（Sfinal 全树数千文件逐文件 bash 动作过慢；且路径含
# 引号/控制字符时 bash 字符串拼接必坏 JSON——json.dump 才是正确转义正源）。
# 事件按类汇总；逐文件明细由 tamper-actions.json 完整落盘入 WORK。
TAMPER_SUM="$(python3 - "$LIVE" "$FILES_FILE" "$WORK/tamper-actions.json" "$STAMP" <<'PYTAMPER'
import json, os, stat, sys
live, files_path, actions_path, stamp = (sys.argv[1], sys.argv[2],
                                         sys.argv[3], sys.argv[4])
files = [ln for ln in open(files_path, encoding="utf-8").read().split("\n")
         if ln]
actions = []
for i, rel in enumerate(files):
    kind = i % 5
    target = os.path.join(live, rel)
    if kind == 0:
        with open(target, "ab") as fh:
            fh.write(f"DRILL-TAMPER-{stamp}".encode("utf-8"))
        actions.append({"rel": rel, "how": "append"})
    elif kind == 1:
        if os.path.getsize(target) == 0:
            # 零字节文件截断不动字节（Sfinal 树含大量空 stderr 证据件）——
            # 改为追加，确保篡改实测生效（fail-closed 验证要求记录必须失配）
            with open(target, "ab") as fh:
                fh.write(f"DRILL-TAMPER-{stamp}".encode("utf-8"))
            actions.append({"rel": rel, "how": "append-empty"})
        else:
            with open(target, "wb"):
                pass
            actions.append({"rel": rel, "how": "truncate"})
    elif kind == 2:
        os.unlink(target)
        actions.append({"rel": rel, "how": "delete"})
    elif kind == 3:
        st = os.lstat(target)
        os.chmod(target, stat.S_IMODE(st.st_mode) & ~0o222)
        actions.append({"rel": rel, "how": "chmod-aw"})
    else:
        extra_rel = f"DRILL-EXTRA-{i + 1}.txt"
        with open(os.path.join(live, extra_rel), "wb") as fh:
            fh.write(f"DRILL-EXTRA-{stamp}".encode("utf-8"))
        actions.append({"rel": extra_rel, "how": "extra-file"})
with open(actions_path, "w", encoding="utf-8") as fh:
    json.dump(actions, fh, ensure_ascii=False)
print(len(actions))
PYTAMPER
)" || fail "release tamper leg failed (rc=$?)"
_tamper_n="${TAMPER_SUM%% *}"
case "$_tamper_n" in ''|*[!0-9]*) fail "release tamper corpus empty";; esac
ev tamper_files sfinal-tree true "\"actions\": ${_tamper_n}, \"kinds\": \"append/truncate/delete/chmod-aw/extra-file 轮转\""
# 篡改实测生效：每个被动作路径的 manifest 记录必须已失配（sha/mode/缺失），
# extra 文件必须存在——零变化=伪造演练直接 FAIL。
TAMPER_OK="$(python3 - "$MANIFEST_PATH" "$LIVE" "$WORK/tamper-actions.json" <<'PYTAMP'
import hashlib, json, os, stat, sys
manifest_path, live, actions_path = sys.argv[1], sys.argv[2], sys.argv[3]
actions = json.load(open(actions_path, encoding="utf-8"))
exp = {r["path"]: r for r in json.load(open(manifest_path, encoding="utf-8"))["files"]}
def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
ok = True
for a in actions:
    rel, how = a["rel"], a["how"]
    if how == "extra-file":
        if not os.path.exists(os.path.join(live, rel)):
            ok = False
        continue
    full = os.path.join(live, rel)
    if not os.path.lexists(full):
        continue          # 已删=必失配
    st = os.lstat(full)
    if stat.S_ISREG(st.st_mode):
        e = exp.get(rel, {})
        same = (_sha(full) == e.get("sha256")
                and stat.S_IMODE(st.st_mode) == e.get("mode"))
        if same:
            ok = False    # 记录仍匹配=篡改未生效
print(ok)
PYTAMP
)"
[ "$TAMPER_OK" = "True" ] || fail "release tamper did not actually change bytes/mode (fake drill)"

# ---- R6：恢复到全空隔离根（归档独立解包；TOCTOU 复核归档 sha）------------
[ "$MODE" = "release-dr" ] && T_RESTORE_START=$(_epoch)
RESTORE_ROOT="$WORK/restore-root"
RESTORE_EMPTY_BEFORE=false
if [ ! -e "$RESTORE_ROOT" ]; then RESTORE_EMPTY_BEFORE=true; fi
mkdir -p "$RESTORE_ROOT" || exit 1
ARCHIVE_SHA_RESTORE=$(_sha256 "$ARCHIVE" | awk '{print $1}')
[ "$ARCHIVE_SHA_RESTORE" = "$ARCHIVE_SHA" ] \
  || fail "release archive mutated during drill (TOCTOU 换归档)"
_extract_release "$ARCHIVE" "$RESTORE_ROOT" \
  || fail "release restore extraction from archive failed (rc=$?) — 恢复源解包失败"
ev restore_extract - true "\"src\": \"$RESTORE_ROOT\", \"sha256\": \"$ARCHIVE_SHA_RESTORE\""

# ---- R7：恢复根 vs manifest 全对账（missing/extra/hash/mode/类型）---------
RECON_RESTORE="$(python3 - "$MANIFEST_PATH" "$RESTORE_ROOT" "$WORK/recon-restore.json" <<'PYRECON2'
import hashlib, json, os, stat, sys
manifest_path, root, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
manifest = json.load(open(manifest_path, encoding="utf-8"))
exp = {r["path"]: r for r in manifest["files"]}
act = {}
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort()
    for name in sorted(dirnames + filenames):  # symlink→目录在 dirnames
        full = os.path.join(dirpath, name)
        rel = os.path.relpath(full, root)
        st = os.lstat(full)
        if stat.S_ISLNK(st.st_mode):
            act[rel] = {"type": "symlink",
                        "sha256": hashlib.sha256(
                            os.readlink(full).encode("utf-8")).hexdigest()}
        elif stat.S_ISDIR(st.st_mode):
            continue          # 真目录由文件路径蕴含，不入对账（同 manifest）
        elif stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(full, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            act[rel] = {"type": "file", "mode": stat.S_IMODE(st.st_mode),
                        "sha256": h.hexdigest()}
        else:
            act[rel] = {"type": "special"}
rep = {"missing": [], "extra": [], "drifted": [], "mode": [], "type": [],
       "special": []}
for p in sorted(exp):
    if p not in act:
        rep["missing"].append(p); continue
    e, a = exp[p], act[p]
    if e["type"] != a["type"]:
        rep["type"].append(p); continue
    if e["sha256"] != a["sha256"]:
        rep["drifted"].append(p); continue
    if e["type"] == "file" and int(e.get("mode", 0)) != int(a["mode"]):
        rep["mode"].append(p)
for p, a in act.items():
    if p not in exp and a["type"] != "dir":
        (rep["special"] if a["type"] == "special" else rep["extra"]).append(p)
rep["ok"] = not any(rep[k] for k in ("missing", "extra", "drifted",
                                     "mode", "type", "special"))
for k in ("missing", "extra", "drifted", "mode", "type", "special"):
    rep[k] = sorted(rep[k])[:5]
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(json.dumps(rep))
print(rep["ok"])
PYRECON2
)"
[ "$RECON_RESTORE" = "True" ] || {
  _recon_sum="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print(" ".join(f"{k}={d.get(k)}" for k in
      ("missing","extra","drifted","mode","type","special") if d.get(k)))
' "$WORK/recon-restore.json" 2>/dev/null || true)"
  fail "release restore reconcile mismatch（${_recon_sum}）"
}
ev reconcile_file sfinal-tree true "\"root\": \"$RESTORE_ROOT\""

# ---- R8：release verifier（生产树对账正源 release_drift.audit_tree）--------
# 先施加部署激活协议（chmod -R a-w 只读不变量）再验——与生产 current 树同一
# 验证语义；验证器来自运行树（独立于被备份语料）。验后恢复 u+w 以便清理。
chmod -R a-w "$RESTORE_ROOT" 2>/dev/null || true
VERIFIER_RC=0
VERIFIER_OUT="$(python3 - "$MANIFEST_PATH" "$RESTORE_ROOT" "$SYSTEM_DIR" <<'PYVER'
import json, sys
sys.path.insert(0, sys.argv[3])
try:
    from wenqu_core.release_drift import audit_tree
except Exception as exc:
    print(json.dumps({"ok": False, "reason": f"verifier import failed: {exc!r}"}))
    sys.exit(1)
rep = audit_tree(sys.argv[2], sys.argv[1])
print(json.dumps({"ok": rep.get("ok"), "tool": "wenqu_core.release_drift.audit_tree",
                  "tree_digest_note": "content digest via manifest reconcile",
                  "checked": rep.get("checked"),
                  "missing": rep.get("missing", [])[:5],
                  "extra": rep.get("extra", [])[:5],
                  "drifted": rep.get("drifted", [])[:5],
                  "mode_drifted": rep.get("mode_drifted", [])[:5],
                  "type_mismatch": rep.get("type_mismatch", [])[:5],
                  "special": rep.get("special", [])[:5],
                  "reason": rep.get("reason")}))
sys.exit(0 if rep.get("ok") else 1)
PYVER
)" || VERIFIER_RC=$?
chmod -R u+w "$RESTORE_ROOT" 2>/dev/null || true
[ "$VERIFIER_RC" -eq 0 ] \
  || fail "release verifier (wenqu_core.release_drift.audit_tree) rejected restored tree: $VERIFIER_OUT"
VERIFIER_CHECKED="$(printf '%s' "$VERIFIER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("checked"))' 2>/dev/null || echo null)"
ev verifier - true "\"checked\": $VERIFIER_CHECKED"

# ---- 聚合 digest（tree digest=manifest 规范字节摘要）----------------------
TREE_DIGEST="$(python3 - "$MANIFEST_PATH" <<'PYTD'
import hashlib, sys
with open(sys.argv[1], "rb") as fh:
    print(hashlib.sha256(fh.read()).hexdigest())
PYTD
)"

# ---- DR 收口（RTO=恢复开始→验证器通过）-----------------------------------
if [ "$MODE" = "release-dr" ]; then
  T_RECONCILE_DONE=$(_epoch)
  RTO_S=$(_fsub "$T_RECONCILE_DONE" "$T_RESTORE_START")
  RPO_OK=false; RTO_OK=false
  if _fge "$RPO_S" "$FAULT_DELAY" && _fge "$DR_RPO_TARGET_S" "$RPO_S"; then RPO_OK=true; fi
  if _fge "$RTO_S" "0.000001" && _fge "$DR_RTO_TARGET_S" "$RTO_S"; then RTO_OK=true; fi
  DR_JSON=$(cat <<EOF
{
  "mode": "release-dr",
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
  [ "$RPO_OK" = "true" ] && [ "$RTO_OK" = "true" ] \
    || fail "release DR frozen targets not met: RPO=${RPO_S}s RTO=${RTO_S}s"
fi

# ---- PASS：报告 + fsync + last-success 原子推进（仅此刻）------------------
BYTE_MATCH_ALL=1
RELEASE_JSON=$(cat <<EOF
{
  "source_commit": "$RELEASE_COMMIT",
  "source": "git archive (Sfinal clean-tree bytes)",
  "repo_root": "$RELEASE_REPO",
  "deployment_epoch": $EPOCH_VAL,
  "deployment_epoch_source": "$EPOCH_SRC",
  "manifest_path": "$MANIFEST_PATH",
  "manifest_sha256": "$MANIFEST_SHA",
  "tree_root": "$LIVE",
  "restore_root": "$RESTORE_ROOT",
  "restore_root_empty_before": $RESTORE_EMPTY_BEFORE,
  "n_files": $N_FILES,
  "bytes": $LIVE_BYTES,
  "capacity_preflight": $CAPACITY_JSON,
  "checks": {"missing": 0, "extra": 0, "drifted": 0, "mode_drifted": 0,
             "type_mismatch": 0, "hash_ok": true, "mode_ok": true,
             "type_ok": true},
  "verifier": {"ok": true, "tool": "wenqu_core.release_drift.audit_tree",
               "checked": $VERIFIER_CHECKED,
               "tree_digest": "$TREE_DIGEST"}
}
EOF
)
SNAP_REL_JSON="$(python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
print(json.dumps([{"rel": r["path"], "sha256": r["sha256"],
                   "size": r.get("size", 0)} for r in m["files"]]))
' "$MANIFEST_PATH")"
STEPS_JSON=$(cat <<EOF
{
  "snapshot": {"ok": true, "source": "git-archive", "files": $SNAP_REL_JSON},
  "archive": {"ok": true, "listing_ok": true, "materialized": true,
              "size": $ARCHIVE_SIZE, "sha256": "$ARCHIVE_SHA",
              "extract_sha256": "$EXTRACT_SHA"},
  "tamper": {"ok": true, "actions": $(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1], encoding="utf-8"))))' "$WORK/tamper-actions.json")},
  "restore": {"ok": true, "source": "archive", "files_restored": $N_FILES,
              "restore_root": "$RESTORE_ROOT"},
  "reconcile": {"root": "$RESTORE_ROOT", "manifest_sha256": "$MANIFEST_SHA",
                "files": $(python3 -c 'import json,sys
print(json.dumps([{"rel": r["path"], "cmp": True, "sha_match": True}
                  for r in json.load(open(sys.argv[1]))["files"]]))
' "$MANIFEST_PATH")}
}
EOF
)
if [ "$MODE" = "release-dr" ]; then
  PASS_REASON="release $N_FILES 文件 Sfinal 字节：空根恢复全对账（missing/extra/hash/mode/类型）+ release verifier ok；RPO=${RPO_S}s<=${DR_RPO_TARGET_S}s RTO=${RTO_S}s<=${DR_RTO_TARGET_S}s"
else
  PASS_REASON="release $N_FILES 文件 Sfinal 字节：空根恢复全对账（missing/extra/hash/mode/类型）+ release verifier ok"
fi
LAST_SUCCESS_PATH="$REPORT_DIR/last-success.json"
# fsync 报告与 jsonl（先落盘再加 last-success——证据先于推进）
write_report PASS "$PASS_REASON"
python3 - "$REPORT_PATH" "$JSONL_PATH" <<'PYFS'
import os, sys
for p in sys.argv[1:]:
    fd = os.open(p, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PYFS
# last-success 原子推进：tmp+fsync+rename+dir fsync；绑定全身份元组
cat > "$WORK/last-success.payload.json" <<EOF
{
  "schema": "wenqu-backup-last-success/1",
  "run_id": "$RUN_ID",
  "stamp": "$STAMP",
  "mode": "$MODE",
  "result": "PASS",
  "advanced_at": "$(_now | awk '{print $2}')",
  "source_commit": "$RELEASE_COMMIT",
  "deployment_epoch": $EPOCH_VAL,
  "deployment_epoch_source": "$EPOCH_SRC",
  "manifest_sha256": "$MANIFEST_SHA",
  "tree_digest": "$TREE_DIGEST",
  "archive_sha256": "$ARCHIVE_SHA",
  "extract_sha256": "$EXTRACT_SHA",
  "verifier_ok": true,
  "rpo_seconds": ${RPO_S:-null},
  "rto_seconds": ${RTO_S:-null},
  "identity": {
    "drill_script_sha256": "$DRILL_SCRIPT_SHA",
    "scheduler_sha256": "$SCHEDULER_SHA"
  }
}
EOF
python3 - "$WORK/last-success.payload.json" "$LAST_SUCCESS_PATH" <<'PYLS'
import json, os, sys
payload_path, dest = sys.argv[1], sys.argv[2]
data = json.dumps(json.load(open(payload_path, encoding="utf-8")),
                  ensure_ascii=False, indent=2) + "\n"
tmp = dest + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    fh.write(data)
    fh.flush()
    os.fsync(fh.fileno())
os.replace(tmp, dest)
dirfd = os.open(os.path.dirname(dest) or ".", os.O_DIRECTORY)
try:
    os.fsync(dirfd)
finally:
    os.close(dirfd)
PYLS
# 报告补记 last-success 推进事实（同 run_id 原地刷新 + fsync；推进已先完成）
LAST_SUCCESS_JSON="{\"path\": \"$LAST_SUCCESS_PATH\", \"advanced\": true, \"run_id\": \"$RUN_ID\"}"
write_report PASS "$PASS_REASON"
python3 - "$REPORT_PATH" <<'PYFS2'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PYFS2
ev drill_pass - PASS "\"run_id\": \"$RUN_ID\", \"archive_sha256\": \"$ARCHIVE_SHA\", \"extract_sha256\": \"$EXTRACT_SHA\", \"manifest_sha256\": \"$MANIFEST_SHA\", \"tree_digest\": \"$TREE_DIGEST\""
echo "drill: PASS release（Sfinal $N_FILES 文件 → 归档 → 空根恢复 → 全对账 + release verifier ok）"
echo "drill: run_id=$RUN_ID commit=$RELEASE_COMMIT epoch=$EPOCH_VAL manifest=$MANIFEST_SHA"
[ "$MODE" = "release-dr" ] && echo "drill: DR 实测 RPO=${RPO_S}s（目标<=${DR_RPO_TARGET_S}s） RTO=${RTO_S}s（目标<=${DR_RTO_TARGET_S}s）"
echo "drill: report: $REPORT_PATH"
[ "$KEEP_WORK" -eq 1 ] || rm -rf "$WORK"
exit 0

fi  # ---- release/release-dr 模式流程结束 ----

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

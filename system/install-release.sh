#!/usr/bin/env bash
# install-release.sh —— 终态四件套重产 + 不可变激活链（外部授权根版）。
#
# 演进史：
#   R7-REL-STALE-012  终态四件套 + 不可变激活（git archive → build → sign →
#                     sbom → verify → 部署 → 只读化 → 原子切换）。
#   R8-REL-PIN-ROOT   plan pin（部署树内 plan.pin）+ source commit 树内实算。
#   G9-12（本轮）     Codex 第八轮 R8-REL-FROZEN-ROOT-009 残余两根修：
#                     ① 旧幂等复验两支 `verify … || true` 后 `$?` 恒 0——
#                        篡改既有 release 后重跑安装器仍 rc0（fail-open，
#                        红证 /tmp/g9-12-evidence/red1-tamper-rerun.log）。
#                        现全文件禁除 verify 类吞 rc：一律显式
#                        `if verify; then …; else fail`，verify 失败=安装器
#                        rc1 停止（无 --force 豁免不可继续）。
#                     ② 旧 plan pin 值从候选源码（tools/ac_traceability.py
#                        import）自生成并写回同一 release——side commit 自洽
#                        改方案+常量后，安装器亲手把攻击值铸成「受保护根」
#                        （红证 /tmp/g9-12-evidence/red2-side-commit.log）。
#                        现安装器**只消费**外部预置授权文件 release-roots.json
#                        （allowed_commit+plan_sha256+manifest_sha256，0600，
#                        由部署授权流程仓外预置），绝不从候选源码/dist 自生
#                        成 pin 写回；本脚本亦不调用 roots-template。
#   G9-13（本轮）     九轮 R9-REL-ROLLBACK-ROOT-BYPASS-004 根修：旧 --rollback
#                        仅凭 .last-current 指向目录存在即切 current——绕过
#                        roots/manifest/签名/SBOM/哈希/血统，不冒烟不复验（红证
#                        /tmp/t4-evidence/RED-rollback-tampered-bypass.log：篡改
#                        manifest 一字节后回滚仍 rc0 直切）。现回滚与正向链
#                        **同一信任链**六段 fail-closed：
#                        [1] 结构门（releases/<40hex>/tree + 四件套唯一 +
#                            manifest.source_commit==目录 SHA——防目录顶包）；
#                        [2] 外部授权门（roots allowed_commit 须同时容纳现役
#                            与回滚目标两个 SHA=回滚授权语义；main 血统同正
#                            向门）；
#                        [3] 四件套 verify（tar/manifest/sig/sbom 对账外部
#                            roots 核心 digest，--report 落回滚证据）；
#                        [4] 解出树逐文件 sha256 对账 manifest（部署后篡改抽核）；
#                        [5] 切换前实录 current（补偿锚点）→ rename(2) 原子切换；
#                        [6] 切换后冒烟：可达/身份（readlink+VERSION）+health
#                            （scheduler 导入）+auth（approval_keys 加载
#                            keyring）+可选服务重载；任一失败自动补偿切回原
#                            current 并 rc1（.last-current 保持原值供审计）。
#
# 外部授权门（构建前 fail-closed，任一不过=rc1）：
#   1. roots 文件存在（默认 $WENQU_RELEASE_ROOTS 或
#      $INSTALL_ROOT/release-roots.json；生产位 ~/.wenqu/release-roots.json）；
#   2. 权限 owner-only（mode 无组/其他任何位——>0600 即拒）；
#   3. 目标 commit 在 allowed_commit 清单内（外部授权=side commit 拒绝的
#      正门：授权流程只收录 main push CI 已绿的确切 SHA）；
#   4. main 血统：commit 须 origin/main（回退 main）可达——非受保护 main
#      血统的 side commit 即使四件套自洽签名也拒（与 3 双保险；仓内
#      evidence/08 merge-ci-*.json 仅为辅助审计记录，不作放行正源）。
#
# 构建输出两模式（G9-12 边界，与 tools/release_attest.py 对齐）：
#   生产安装链（本脚本）：一律仓外构建 $BUILD_BASE/<sha>（默认
#     $INSTALL_ROOT/build/<sha>，--build-dir 可改但必须在仓外）——不污染
#     源码树 dist/，已部署/已存证制品零触碰。
#   仓内存证模式：`python3 tools/release_attest.py build --dist-dir dist`
#     （存证 PR 用）——与本安装链互不影响；本脚本不再写仓内 dist/。
#
# 用法：
#   bash system/install-release.sh [COMMIT] [选项]
#     COMMIT              目标 commit（默认 HEAD；分支名/SHA 均可——须在
#                         外部 allowed_commit 且 main 血统）
#     --keyring PATH      签发 keyring（默认 $WENQU_RELEASE_KEYRING 或
#                         ~/.wenqu-dist-release/release-keyring.json）
#     --install-root P    安装根（默认 $WENQU_INSTALL_ROOT 或 ~/.wenqu）
#     --release-roots P   外部授权 roots（默认 $WENQU_RELEASE_ROOTS 或
#                         $INSTALL_ROOT/release-roots.json）
#     --build-dir P       仓外构建基目录（默认 $INSTALL_ROOT/build）
#     --repo PATH         源仓（默认脚本所在仓根）
#     --force             部署位已存在但验签失败时强制删除重部署（默认中止）
#     --reload-scheduler  激活后 launchctl 重载 com.wenqu.scheduler 并 kickstart
#     --reload-dashboard  激活后 launchctl 重载 com.wenqu.dashboard（现役
#                         dashboard 走 current 不可变树，切换后须重启）
#     --no-activate       只产四件套到仓外构建位（+verify 过 roots），不部署
#     --rollback          切回 .last-current 记录的上一个激活目标（G9-13：
#                         与正向链同一信任链——结构门/外部授权门+main 血统/
#                         四件套 verify/树逐文件对账/切换后 health+auth 冒烟，
#                         失败自动补偿切回原 current 并 rc1；详见文件头注）
#
# 密钥纪律：keyring 只传路径给 release_attest（只读 import）；secret 绝不
# 回显/入档。HMAC 对称签名 = tamper-evident，非非否认（§21.4 诚实边界）。
#
# exit：0=激活完成（或幂等复验通过）；1=任一环节 fail-closed 中止
#       （roots 缺失/权限宽/未授权 commit/side commit/verify 真失败/篡改）。
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEFAULT_REPO=$(cd "$SCRIPT_DIR/.." && pwd)

COMMIT="HEAD"
KEYRING="${WENQU_RELEASE_KEYRING:-$HOME/.wenqu-dist-release/release-keyring.json}"
INSTALL_ROOT="${WENQU_INSTALL_ROOT:-$HOME/.wenqu}"
REPO="$DEFAULT_REPO"
ROOTS=""
BUILD_BASE=""
FORCE=0
RELOAD_SCHEDULER=0
RELOAD_DASHBOARD=0
NO_ACTIVATE=0
ROLLBACK=0

while [ $# -gt 0 ]; do
  case "$1" in
    --keyring) KEYRING="${2:?--keyring 缺参数}"; shift 2;;
    --install-root) INSTALL_ROOT="${2:?--install-root 缺参数}"; shift 2;;
    --release-roots) ROOTS="${2:?--release-roots 缺参数}"; shift 2;;
    --build-dir) BUILD_BASE="${2:?--build-dir 缺参数}"; shift 2;;
    --repo) REPO="${2:?--repo 缺参数}"; shift 2;;
    --force) FORCE=1; shift;;
    --reload-scheduler) RELOAD_SCHEDULER=1; shift;;
    --reload-dashboard) RELOAD_DASHBOARD=1; shift;;
    --no-activate) NO_ACTIVATE=1; shift;;
    --rollback) ROLLBACK=1; shift;;
    -h|--help) sed -n '2,60p' "$0"; exit 0;;
    *) if [ "$COMMIT" = "HEAD" ]; then COMMIT="$1"; shift;
       else echo "install-release: 未知参数 $1" >&2; exit 1; fi;;
  esac
done

log() { printf '  %s\n' "$*"; }
die() { echo "install-release: ERROR: $*" >&2; exit 1; }

PY="${WENQU_PYTHON:-python3}"
RELROOT="$INSTALL_ROOT/releases"
CURRENT="$INSTALL_ROOT/current"
LAST_CURRENT="$RELROOT/.last-current"
UID_N=$(id -u)
# roots/构建缺省位依赖 INSTALL_ROOT（可在参数解析中被覆盖）→ 解析后统一取。
ROOTS="${ROOTS:-${WENQU_RELEASE_ROOTS:-$INSTALL_ROOT/release-roots.json}}"
BUILD_BASE="${BUILD_BASE:-$INSTALL_ROOT/build}"
# trap 清理是「失败也无须救」的收尾（rm 临时文件）——但 G9-12 吞 rc 清理
# 的一部分：旧版 `… || true' EXIT 会把脚本异常夭折（unbound/信号等非显式
# exit 的死法）的退出码掩成 0。现显式保存/回传真实 rc——清理永不改判。
trap 'rc=$?; rm -f "$INSTALL_ROOT/.current.new.$$" \
      "$INSTALL_ROOT/.current.rollback.$$" "$INSTALL_ROOT/.chmod-err.$$" \
      2>/dev/null; exit $rc' EXIT

# ---------------------------------------------------------------- 回滚模式
# G9-13（R9-REL-ROLLBACK-ROOT-BYPASS-004 根修）：回滚不再「目录存在即切」，
# 与正向安装链同一信任链六段 fail-closed（详见文件头注）。任一段失败=rc1，
# 未切换即拒；已切换后冒烟失败=自动补偿切回原 current 再 rc1。
if [ "$ROLLBACK" = "1" ]; then
  [ -f "$LAST_CURRENT" ] || die "无 .last-current 记录，无法回滚"
  PREV=$(cat "$LAST_CURRENT")
  [ -n "$PREV" ] || die ".last-current 为空，无法回滚"
  [ -d "$PREV" ] || die "回滚目标不存在: $PREV"
  [ -f "$KEYRING" ] || die "keyring 不存在: ${KEYRING}（回滚验签必需）"
  [ -e "$REPO/.git" ] || die "不是 git 仓: ${REPO}（回滚血统/对象库核验必需）"
  command -v git >/dev/null 2>&1 || die "git 不可用"

  # -------- [1/6] 结构门：受管 releases/<40hex>/tree + 四件套唯一 + 身份钉
  echo "== rollback [1/6] 结构门: $PREV =="
  RELROOT_REAL=$(cd "$RELROOT" 2>/dev/null && pwd -P) \
    || die "releases 根不可达: $RELROOT"
  PREV_REAL=$(cd "$PREV" 2>/dev/null && pwd -P) \
    || die "回滚目标不可解析: $PREV"
  case "$PREV_REAL/" in
    "$RELROOT_REAL/"*) : ;;
    *) die "回滚目标不在受管 releases 根内: ${PREV_REAL}——拒绝任意目录顶替 current" ;;
  esac
  RB_RELDIR=$(dirname "$PREV_REAL")
  RB_SHA=$(basename "$RB_RELDIR")
  [ "$(basename "$PREV_REAL")" = "tree" ] \
    || die "回滚目标末段不是 tree/: $PREV_REAL"
  printf '%s' "$RB_SHA" | grep -qE '^[0-9a-f]{40}$' \
    || die "回滚目标目录名非 40hex commit: $RB_SHA"
  RB_MANIFESTS=("$RB_RELDIR"/wenqu-dist-*.manifest.json)
  if [ "${#RB_MANIFESTS[@]}" -ne 1 ] || [ ! -f "${RB_MANIFESTS[0]}" ]; then
    die "回滚目标 manifest 缺失/不唯一: ${RB_RELDIR}（四件套不完整）"
  fi
  RB_MANIFEST="${RB_MANIFESTS[0]}"
  RB_STEM=${RB_MANIFEST%.manifest.json}
  for ext in tar.gz release.sig sbom.spdx.json; do
    [ -f "$RB_STEM.$ext" ] || die "回滚目标四件套缺件: $RB_STEM.$ext"
  done
  RB_SC=$("$PY" -c 'import json,sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["source_commit"])' \
    "$RB_MANIFEST" 2>/dev/null) \
    || die "回滚目标 manifest 不可解析: $RB_MANIFEST"
  [ "$RB_SC" = "$RB_SHA" ] \
    || die "回滚目标身份断裂: manifest.source_commit=$RB_SC != 目录 SHA=${RB_SHA}（目录顶包/改名，拒绝）"
  log "结构门 OK  commit=${RB_SHA}（$(basename "$RB_STEM") 四件套完整）"

  # -------- [2/6] 外部授权门（与正向门同构；roots 同时容纳现役与回滚目标）
  echo "== rollback [2/6] 外部授权门: roots=$ROOTS =="
  "$PY" - "$ROOTS" "$RB_SHA" "$REPO" <<'PYGATE_RB' || die "回滚外部授权门未过（fail-closed，不切换）"
import json, os, re, subprocess, sys

roots_path, full_sha, repo = sys.argv[1], sys.argv[2], sys.argv[3]
ERR = lambda m: print(f"install-release: ERROR: {m}", file=sys.stderr)

# 1) 存在 + 2) owner-only 权限（组/其他任何位即拒——>0600 语义）
if not os.path.isfile(roots_path):
    ERR(f"release-roots 授权文件缺失: {roots_path}——回滚目标同样须外部授权"
        f"（allowed_commit 同时容纳现役与回滚目标两个 SHA），无豁免路径")
    sys.exit(1)
mode = os.stat(roots_path).st_mode & 0o7777
if mode & 0o077:
    ERR(f"release-roots 权限过宽: {roots_path} mode={oct(mode)}"
        f"（组/其他任何位即拒，须 0600 owner-only）")
    sys.exit(1)
try:
    roots = json.load(open(roots_path, encoding="utf-8"))
except (OSError, ValueError) as exc:
    ERR(f"release-roots 不可读/非 JSON: {exc}")
    sys.exit(1)

# 3) 回滚目标 commit ∈ allowed_commit（回滚授权正门）
allowed = roots.get("allowed_commit")
entries = {}
if isinstance(allowed, list) and allowed:
    for ent in allowed:
        if isinstance(ent, dict):
            entries[ent.get("commit", "")] = ent.get("manifest_sha256", "")
if full_sha not in entries:
    ERR(f"回滚目标 commit 不在 release-roots allowed_commit: {full_sha}"
        f"——未授权回滚目标（授权清单须同时收录现役与回滚 SHA，"
        f"四件套自洽签名也不放行）")
    sys.exit(1)
plan = roots.get("plan_sha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", plan):
    ERR(f"release-roots.plan_sha256 非法（应 64hex）: {plan!r}")
    sys.exit(1)

# 4) main 血统（与正向门同构：非受保护 main 血统的回滚目标即拒）
mainref = ""
for ref in ("origin/main", "main"):
    probe = subprocess.run(["git", "-C", repo, "rev-parse", "--verify",
                            f"refs/remotes/{ref}^{{commit}}"] if ref.startswith("origin/")
                           else ["git", "-C", repo, "rev-parse", "--verify",
                                 f"refs/heads/{ref}^{{commit}}"],
                          capture_output=True, text=True)
    if probe.returncode == 0:
        mainref = probe.stdout.strip()
        break
if not mainref:
    ERR("无法解析 main 权威 ref（origin/main/main 均失败）——回滚血统无法核验")
    sys.exit(1)
anc = subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor",
                      full_sha, mainref], capture_output=True)
if anc.returncode != 0:
    ERR(f"回滚目标非 main 血统: {full_sha} 不可达自 {mainref}——拒绝")
    sys.exit(1)
print(f"  回滚授权门 OK  allowed={len(entries)} commit={full_sha[:12]}… "
      f"main={mainref[:12]}… plan={plan[:12]}…")
PYGATE_RB

  # -------- [3/6] 四件套 verify（manifest/签名/SBOM/哈希 对账外部 roots）
  echo "== rollback [3/6] 四件套 verify（对账外部 roots）=="
  if "$PY" "$REPO/tools/release_attest.py" verify \
    --manifest "$RB_MANIFEST" --keyring "$KEYRING" \
    --release-roots "$ROOTS" --repo "$REPO" \
    --report "$RELROOT/rollback-verify-report.$RB_SHA.json"; then
    :
  else
    die "回滚目标四件套 verify 失败（篡改/未授权/坏件）——拒绝切换（fail-closed）"
  fi

  # -------- [4/6] 解出树逐文件对账（部署后篡改抽核；只读，不删证据）
  echo "== rollback [4/6] 解出树逐文件 sha256 对账 =="
  "$PY" - "$RB_RELDIR" "$(basename "$RB_STEM")" <<'PYRB' \
    || die "回滚目标解出树与 manifest 逐文件对账失败（部署位被篡改?）——拒绝切换"
import hashlib, json, os, sys
reldir, stem = sys.argv[1], sys.argv[2]
m = json.load(open(os.path.join(reldir, stem + ".manifest.json"),
                   encoding="utf-8"))
bad = []
for rec in m["files"]:
    if rec["type"] != "file":
        continue
    p = os.path.join(reldir, "tree", rec["path"])
    try:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != rec["sha256"]:
            bad.append(rec["path"])
    except OSError:
        bad.append(rec["path"])
if bad:
    print("tree drift: %s" % bad[:5], file=sys.stderr)
    sys.exit(1)
print("  回滚树与 manifest 逐文件 sha256 全符（%d files）" % len(m["files"]))
PYRB

  # -------- [5/6] 切换前实录 current（补偿锚点）→ 原子切换
  echo "== rollback [5/6] 记录 current + 原子切换 =="
  CUR_BEFORE=$(readlink "$CURRENT" 2>/dev/null || true)
  [ -n "$CUR_BEFORE" ] || die "current 不存在/不可读——无「切回」语义，人工处置"
  log "切换前实录 current → ${CUR_BEFORE}（失败补偿锚点）"
  if [ -e "$CURRENT" ] && [ ! -L "$CURRENT" ]; then
    die "$CURRENT 已存在且不是 symlink——拒绝覆盖（人工处置）"
  fi
  ln -s "$PREV_REAL" "$INSTALL_ROOT/.current.rollback.$$"
  "$PY" -c 'import os, sys; os.rename(sys.argv[1], sys.argv[2])' \
    "$INSTALL_ROOT/.current.rollback.$$" "$CURRENT"
  log "ROLLBACK SWITCH  current → $PREV_REAL"

  # 补偿函数：冒烟/重载任一失败 → 切回原 current 并 rc1（.last-current
  # 保持原值供审计——失败现场不抹除）。
  rb_compensate() {
    echo "install-release: ERROR: $*——自动补偿：切回原 current" >&2
    ln -s "$CUR_BEFORE" "$INSTALL_ROOT/.current.rollback.$$"
    "$PY" -c 'import os, sys; os.rename(sys.argv[1], sys.argv[2])' \
      "$INSTALL_ROOT/.current.rollback.$$" "$CURRENT" 2>/dev/null || true
    if [ "$(readlink "$CURRENT" 2>/dev/null)" = "$CUR_BEFORE" ]; then
      log "补偿完成  current 已切回 ${CUR_BEFORE}（.last-current 保持原值供审计）"
    else
      echo "install-release: ERROR: 补偿失败——current=$(readlink "$CURRENT" 2>/dev/null) 期望=${CUR_BEFORE}，须人工处置" >&2
    fi
    exit 1
  }

  # -------- [6/6] 切换后冒烟：可达/身份 + health + auth（+可选服务重载）
  echo "== rollback [6/6] 切换后冒烟（可达/身份/health/auth）=="
  [ -f "$CURRENT/system/wenqu_core/scheduler.py" ] \
    || rb_compensate "切换后 current/system/wenqu_core/scheduler.py 不可达"
  [ "$(readlink "$CURRENT" 2>/dev/null)" = "$PREV_REAL" ] \
    || rb_compensate "切换后 current 身份漂移"
  RB_VER=$(cat "$CURRENT/system/VERSION" 2>/dev/null) || RB_VER=UNKNOWN
  log "回滚位身份: VERSION=$RB_VER commit=$RB_SHA"
  if PYTHONPATH="$CURRENT/system" "$PY" -c \
    "import wenqu_core.scheduler as s; import os; \
     print('  rollback health OK  wenqu_core.scheduler from', os.path.dirname(s.__file__))"; then
    :
  else
    rb_compensate "回滚位 wenqu_core.scheduler 导入失败（health 冒烟）"
  fi
  if PYTHONPATH="$CURRENT/system" "$PY" - "$KEYRING" <<'PYAUTH'
import sys
from wenqu_core.approval_keys import ApprovalKeyring
ApprovalKeyring.from_path(sys.argv[1])
print("  rollback auth OK  approval_keys（回滚位）可加载 keyring")
PYAUTH
  then
    :
  else
    rb_compensate "回滚位 approval_keys/keyring 加载失败（auth 冒烟）"
  fi

  # 可选：launchd 服务重载（与正向链同参数；失败走补偿而非裸 die）
  if [ "$RELOAD_SCHEDULER" = "1" ]; then
    echo "== rollback reload com.wenqu.scheduler =="
    PLIST="$HOME/Library/LaunchAgents/com.wenqu.scheduler.plist"
    [ -f "$PLIST" ] || rb_compensate "plist 不存在: $PLIST"
    launchctl bootout "gui/$UID_N/com.wenqu.scheduler" 2>/dev/null || true
    launchctl bootstrap "gui/$UID_N" "$PLIST" \
      || rb_compensate "launchctl bootstrap 失败（scheduler）"
    launchctl kickstart "gui/$UID_N/com.wenqu.scheduler" \
      || rb_compensate "launchctl kickstart 失败（scheduler）"
    log "scheduler 已重载并 kickstart"
  fi
  if [ "$RELOAD_DASHBOARD" = "1" ]; then
    echo "== rollback reload com.wenqu.dashboard =="
    PLIST="$HOME/Library/LaunchAgents/com.wenqu.dashboard.plist"
    [ -f "$PLIST" ] || rb_compensate "plist 不存在: $PLIST"
    launchctl bootout "gui/$UID_N/com.wenqu.dashboard" 2>/dev/null || true
    launchctl bootstrap "gui/$UID_N" "$PLIST" \
      || rb_compensate "launchctl bootstrap 失败（dashboard）"
    DASH_PORT=7789
    READY=0
    for _ in $(seq 1 20); do
      if curl -sS -o /dev/null --noproxy '*' \
          "http://127.0.0.1:$DASH_PORT/api/v1/ping" 2>/dev/null; then
        READY=1; break
      fi
      sleep 0.5
    done
    [ "$READY" = "1" ] || rb_compensate "dashboard 重载后 15s 内未在 $DASH_PORT 就绪（health 冒烟）"
    log "dashboard 已重载（current → $(readlink "$CURRENT")）"
  fi

  # 全部通过：交换 .last-current（下一次 --rollback 即 roll-forward 备援）
  printf '%s\n' "$CUR_BEFORE" > "$LAST_CURRENT"
  log "记录上一激活目标（roll-forward 备援）→ $CUR_BEFORE"
  echo "ROLLBACK OK  current → $PREV_REAL"
  echo "  回滚授权  : ${ROOTS}（0600；allowed_commit 同时容纳现役与回滚目标）"
  echo "  回滚证据  : $RELROOT/rollback-verify-report.$RB_SHA.json"
  exit 0
fi

# ---------------------------------------------------------------- 前置
# .git 目录（正仓）或 .git 文件（git worktree 指针）均为合法源仓。
[ -e "$REPO/.git" ] || die "不是 git 仓: $REPO"
[ -f "$KEYRING" ] || die "keyring 不存在: ${KEYRING}（生产签发 key 仓外隔离）"
command -v git >/dev/null 2>&1 || die "git 不可用"

FULL_SHA=$(git -C "$REPO" rev-parse --verify "$COMMIT^{commit}") \
  || die "commit 解析失败: $COMMIT"
FULL_SHA=${FULL_SHA%%[[:space:]]*}
echo "== install-release: commit $FULL_SHA ($COMMIT) =="

NAME="wenqu-dist-$(git -C "$REPO" rev-parse --short=7 "$FULL_SHA")"
BUILD_DIR="$BUILD_BASE/$FULL_SHA"
RELDIR="$RELROOT/$FULL_SHA"

# ------------------------------------------------- 0) 外部授权门（G9-12）
# 任何授权面失败=rc1，且发生在构建之前——「只有 exact main CI 绿后才允许
# 构建 Sfinal 制品」。全部为只读检查（不生成/不回写 roots）。
echo "== [0/5] 外部授权门: roots=$ROOTS =="
"$PY" - "$ROOTS" "$FULL_SHA" "$REPO" <<'PYGATE' || die "外部授权门未过（fail-closed）"
import json, os, re, subprocess, sys

roots_path, full_sha, repo = sys.argv[1], sys.argv[2], sys.argv[3]
ERR = lambda m: print(f"install-release: ERROR: {m}", file=sys.stderr)

# 1) 存在 + 2) owner-only 权限（组/其他任何位即拒——>0600 语义）
if not os.path.isfile(roots_path):
    ERR(f"release-roots 授权文件缺失: {roots_path}——由部署授权流程仓外"
        f"预置（0600: allowed_commit+plan_sha256+manifest_sha256）；"
        f"安装器不生成授权文件（无豁免路径）")
    sys.exit(1)
mode = os.stat(roots_path).st_mode & 0o7777
if mode & 0o077:
    ERR(f"release-roots 权限过宽: {roots_path} mode={oct(mode)}"
        f"（组/其他任何位即拒，须 0600 owner-only）")
    sys.exit(1)
try:
    roots = json.load(open(roots_path, encoding="utf-8"))
except (OSError, ValueError) as exc:
    ERR(f"release-roots 不可读/非 JSON: {exc}")
    sys.exit(1)

# 3) commit ∈ allowed_commit（外部授权正门）
allowed = roots.get("allowed_commit")
entries = {}
if isinstance(allowed, list) and allowed:
    for ent in allowed:
        if isinstance(ent, dict):
            entries[ent.get("commit", "")] = ent.get("manifest_sha256", "")
if full_sha not in entries:
    ERR(f"目标 commit 不在 release-roots allowed_commit: {full_sha}"
        f"——side commit/未授权 commit（外部授权清单只收录 main push CI"
        f" 已绿的确切 SHA；四件套自洽签名也不放行）")
    sys.exit(1)
plan = roots.get("plan_sha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", plan):
    ERR(f"release-roots.plan_sha256 非法（应 64hex）: {plan!r}")
    sys.exit(1)

# 4) main 血统：origin/main（回退 main）可达（side commit 双保险）
mainref = ""
for ref in ("origin/main", "main"):
    probe = subprocess.run(["git", "-C", repo, "rev-parse", "--verify",
                            f"refs/remotes/{ref}^{{commit}}"] if ref.startswith("origin/")
                           else ["git", "-C", repo, "rev-parse", "--verify",
                                 f"refs/heads/{ref}^{{commit}}"],
                          capture_output=True, text=True)
    if probe.returncode == 0:
        mainref = probe.stdout.strip()
        break
if not mainref:
    ERR("无法解析 main 权威 ref（origin/main/main 均失败）——main 血统无法核验")
    sys.exit(1)
anc = subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor",
                      full_sha, mainref], capture_output=True)
if anc.returncode != 0:
    ERR(f"commit 非 main 血统: {full_sha} 不可达自 {mainref}"
        f"——side commit 拒绝（即使 allowed_commit 误收录也拒）")
    sys.exit(1)
print(f"  授权门 OK  allowed={len(entries)} commit={full_sha[:12]}… "
      f"main={mainref[:12]}… plan={plan[:12]}…")
PYGATE

# ------------------------------------------------- 1) 四件套重产（仓外）
echo "== [1/5] build+sign+sbom+verify → ${BUILD_DIR}（仓外构建）=="
mkdir -p "$BUILD_DIR"
cd "$REPO"
if "$PY" tools/release_attest.py build --commit "$FULL_SHA" \
  --out-dir "$BUILD_DIR" --repo "$REPO"; then :; else
  die "build 失败（含 --out-dir 仓外边界强制）——fail-closed"
fi
if "$PY" tools/release_attest.py sign \
  --manifest "$BUILD_DIR/$NAME.manifest.json" --keyring "$KEYRING"; then :; else
  die "sign 失败——fail-closed"
fi
if "$PY" tools/release_attest.py sbom \
  --manifest "$BUILD_DIR/$NAME.manifest.json"; then :; else
  die "sbom 失败——fail-closed"
fi

# verify 对外部 roots 四重对账（allowed_commit/plan/manifest 核心 digest/
# source commit 树内实算）。显式分支保留真实 rc——失败即 rc1，无吞rc路径。
if "$PY" tools/release_attest.py verify \
  --manifest "$BUILD_DIR/$NAME.manifest.json" --keyring "$KEYRING" \
  --release-roots "$ROOTS" --repo "$REPO" \
  --report "$BUILD_DIR/$NAME.verify-report.json"; then
  :
else
  die "构建位四件套 verify 失败（对账外部 roots）——不出厂（fail-closed）"
fi

if [ "$NO_ACTIVATE" = "1" ]; then
  log "四件套已产出到 ${BUILD_DIR}（--no-activate，未部署）"
  exit 0
fi

# ------------------------------------------------- 2) 部署到不可变位
echo "== [2/5] 部署 $RELDIR =="
FRESH=0
if [ -d "$RELDIR" ]; then
  # 幂等重装：部署位已存在 → 复验既有四件套（对账外部 roots）；通过则
  # 不重写（不可变纪律）。G9-12 根修：verify 直接置于 if 条件位——真实
  # rc 驱动分支，篡改/损坏既有 release 必 rc1（旧版 `|| true` 已删除）。
  if "$PY" tools/release_attest.py verify \
    --manifest "$RELDIR/$NAME.manifest.json" --keyring "$KEYRING" \
    --release-roots "$ROOTS" --repo "$REPO" \
    >/dev/null 2>&1; then
    log "部署位已存在且验签通过（对账外部 roots）——保持不可变，仅重新激活"
  elif [ "$FORCE" = "1" ]; then
    log "部署位验签失败 + --force → 删除重部署: $RELDIR"
    chmod -R u+w "$RELDIR" 2>/dev/null || true   # 清理辅助（非 verify 语义）
    rm -rf "$RELDIR"
  else
    die "部署位已存在但验签失败（不可变位被篡改?）: ${RELDIR}——人工核查或 --force"
  fi
fi

if [ ! -d "$RELDIR" ]; then
  FRESH=1
  mkdir -p "$RELDIR"
  for ext in tar.gz manifest.json release.sig sbom.spdx.json; do
    cp -p "$BUILD_DIR/$NAME.$ext" "$RELDIR/$NAME.$ext"
  done
  mkdir -p "$RELDIR/tree"
  tar -xzf "$RELDIR/$NAME.tar.gz" -C "$RELDIR/tree"
  if [ -f "$RELDIR/tree/system/wenqu_core/scheduler.py" ]; then :; else
    chmod -R u+w "$RELDIR" 2>/dev/null || true   # 清理辅助（非 verify 语义）
    rm -rf "$RELDIR"
    die "解出的树缺 system/wenqu_core/scheduler.py——非本仓制品"
  fi
  # G9-12：不再向部署树写 plan.pin——授权根只有外部 release-roots.json
  # （旧版从候选源码自生成 pin 写回=自证根，已连根移除）。

  # ------------------------------------------------- 3) 部署位复验（仅新装：
  #     防复制/解压损坏；幂等路径上面已复验，不可变位不再写入报告）
  echo "== [3/5] 部署位 verify 复验 + tree 逐文件对账 =="
  if "$PY" tools/release_attest.py verify \
    --manifest "$RELDIR/$NAME.manifest.json" --keyring "$KEYRING" \
    --release-roots "$ROOTS" --repo "$REPO" \
    --report "$RELDIR/verify-report.json"; then
    :
  else
    chmod -R u+w "$RELDIR" 2>/dev/null || true   # 清理辅助（非 verify 语义）
    rm -rf "$RELDIR"
    die "部署位四件套 verify 失败（对账外部 roots）——中止激活（fail-closed）"
  fi
  # 解出树与制品内清单逐文件对账（tree 必须逐字节等于 git archive 树）。
  # `|| { 清理; die }` 分支保留真实 rc（die=rc1），非吞 rc 模式。
  "$PY" - "$RELDIR" "$NAME" <<'PYEOF' || { chmod -R u+w "$RELDIR" 2>/dev/null || true; \
       rm -rf "$RELDIR"; die "解出树与 manifest 逐文件对账失败"; }
import hashlib, json, os, sys
reldir, name = sys.argv[1], sys.argv[2]
m = json.load(open(os.path.join(reldir, name + ".manifest.json"),
                   encoding="utf-8"))
bad = []
for rec in m["files"]:
    if rec["type"] != "file":
        continue
    p = os.path.join(reldir, "tree", rec["path"])
    try:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != rec["sha256"]:
            bad.append(rec["path"])
    except OSError:
        bad.append(rec["path"])
if bad:
    print("tree drift: %s" % bad[:5], file=sys.stderr)
    sys.exit(1)
print("  tree 与 manifest 逐文件 sha256 全符（%d files）" % len(m["files"]))
PYEOF
else
  log "== [3/5] 幂等路径：部署位四件套已复验（真实 rc），跳过重写"
fi

# ------------------------------------------------- 4) 不可变化 + 原子切换
echo "== [4/5] 不可变化 + 原子激活 =="
if [ "$FRESH" = "1" ]; then
  # G9-12：只读化 fail-closed——chmod 失败（而非仅告警）即中止：半只读的
  # 「不可变位」名不副实，宁可中止也不带病激活。
  if ! chmod -R a-w "$RELDIR" 2>"$INSTALL_ROOT/.chmod-err.$$"; then
    chmod -R u+w "$RELDIR" 2>/dev/null || true   # 清理辅助（非 verify 语义）
    rm -rf "$RELDIR"
    die "chmod a-w 只读化失败（不可变纪律破坏）: $(cat "$INSTALL_ROOT/.chmod-err.$$" 2>/dev/null | head -1)"
  fi
fi
if [ -e "$CURRENT" ] && [ ! -L "$CURRENT" ]; then
  die "$CURRENT 已存在且不是 symlink——拒绝覆盖（人工处置）"
fi
if [ -L "$CURRENT" ] || [ -e "$CURRENT" ]; then
  readlink "$CURRENT" > "$LAST_CURRENT" 2>/dev/null \
    && log "记录上一激活目标 → $(cat "$LAST_CURRENT")"
fi
# 原子切换：临时 symlink + rename(2)。不能用 mv——BSD mv 对「目标是
# symlink→目录」会跟随目标把新链接移进目录（实测踩坑）；rename(2) 语义是
# 原子替换 symlink 本身（不跟随目标），python os.rename 即此语义。
ln -s "$RELDIR/tree" "$INSTALL_ROOT/.current.new.$$"
"$PY" -c 'import os, sys; os.rename(sys.argv[1], sys.argv[2])' \
  "$INSTALL_ROOT/.current.new.$$" "$CURRENT"
log "current → $(readlink "$CURRENT")"
[ -f "$CURRENT/system/wenqu_core/scheduler.py" ] \
  || die "激活后 current/system 不可达"

# ------------------------------------------------- 5) 激活位导入冒烟
echo "== [5/5] 激活位导入冒烟 =="
if PYTHONPATH="$CURRENT/system" "$PY" -c \
  "import wenqu_core.scheduler as s; import os; \
   print('  import OK  wenqu_core.scheduler from', os.path.dirname(s.__file__))"; then
  :
else
  die "激活位 wenqu_core.scheduler 导入失败"
fi

# 可选：launchd 重载 + 立即 kickstart 一轮
if [ "$RELOAD_SCHEDULER" = "1" ]; then
  echo "== reload com.wenqu.scheduler =="
  PLIST="$HOME/Library/LaunchAgents/com.wenqu.scheduler.plist"
  [ -f "$PLIST" ] || die "plist 不存在: $PLIST"
  launchctl bootout "gui/$UID_N/com.wenqu.scheduler" 2>/dev/null || true  # 未装载时 bootout 必败=正常前置
  launchctl bootstrap "gui/$UID_N" "$PLIST" \
    || die "launchctl bootstrap 失败"
  launchctl kickstart "gui/$UID_N/com.wenqu.scheduler" \
    || die "launchctl kickstart 失败"
  log "scheduler 已重载并 kickstart（活性: launchctl print gui/$UID_N/com.wenqu.scheduler）"
fi

# P0-9/W8 联动：dashboard 现役 = current 不可变树上的 system/dashboard/
# server.py（plist 直指 current symlink）。current 切换是 rename(2) 原子
# 替换 symlink，常驻进程仍持旧 release 树的 inode——不重载就继续跑旧版。
if [ "$RELOAD_DASHBOARD" = "1" ]; then
  echo "== reload com.wenqu.dashboard =="
  PLIST="$HOME/Library/LaunchAgents/com.wenqu.dashboard.plist"
  [ -f "$PLIST" ] || die "plist 不存在: $PLIST"
  launchctl bootout "gui/$UID_N/com.wenqu.dashboard" 2>/dev/null || true  # 未装载时 bootout 必败=正常前置
  launchctl bootstrap "gui/$UID_N" "$PLIST" \
    || die "launchctl bootstrap 失败"
  # 活性回读：进程必须已在 7789 监听且 argv 解析到新 current 树
  DASH_PORT=7789
  READY=0
  for _ in $(seq 1 20); do
    if curl -sS -o /dev/null --noproxy '*' \
        "http://127.0.0.1:$DASH_PORT/api/v1/ping" 2>/dev/null; then
      READY=1; break
    fi
    sleep 0.5
  done
  [ "$READY" = "1" ] || die "dashboard 重载后 15s 内未在 $DASH_PORT 就绪"
  log "dashboard 已重载（current → $(readlink "$CURRENT")；活性: curl 127.0.0.1:$DASH_PORT/api/v1/ping）"
fi

echo "INSTALL-RELEASE OK  $FULL_SHA"
echo "  外部授权  : ${ROOTS}（0600，部署授权流程预置；安装器只消费）"
echo "  四件套    : $BUILD_DIR/$NAME.{tar.gz,manifest.json,release.sig,sbom.spdx.json}（仓外构建）"
echo "  不可变位  : ${RELDIR}（chmod a-w，fail-closed）"
echo "  激活      : $CURRENT → $RELDIR/tree"
echo "  回滚      : bash system/install-release.sh --rollback"

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
#     --rollback          切回 .last-current 记录的上一个激活目标
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
if [ "$ROLLBACK" = "1" ]; then
  [ -f "$LAST_CURRENT" ] || die "无 .last-current 记录，无法回滚"
  PREV=$(cat "$LAST_CURRENT")
  [ -d "$PREV" ] || die "回滚目标不存在: $PREV"
  ln -s "$PREV" "$INSTALL_ROOT/.current.rollback.$$"
  "$PY" -c 'import os, sys; os.rename(sys.argv[1], sys.argv[2])' \
    "$INSTALL_ROOT/.current.rollback.$$" "$CURRENT"
  log "ROLLBACK OK  current → $PREV"
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

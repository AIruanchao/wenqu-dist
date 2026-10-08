#!/usr/bin/env bash
# install-release.sh —— 终态四件套重产 + 不可变激活链（R7-REL-STALE-012 根修）。
#
# 背景（Codex 第七轮 P0）：dist/ 签名制品绑旧提交 1620c7c 而非终态；且
# com.wenqu.scheduler 直接吃共享可变工作树（Documents/wenqu-dist）——并行
# agent 改工作树 = 生产身份漂移。本脚本把「从哪个 commit 出包、生产跑哪份
# 代码」钉成一条不可变激活链：
#
#   git archive <commit> → build → sign → sbom → verify（dist/ 四件套）
#     → 部署 ~/.wenqu/releases/<full-sha>/{四件套, tree/（解出的完整树）}
#     → verify 在部署位复验 → chmod a-w（不可变）
#     → ~/.wenqu/current 原子切换（临时 symlink + rename(2)，无中间态）
#
# 重复可执行：对同一 commit 重跑 = 幂等（部署位四件套已存在且验签通过 →
# 不重写只重激活）；对不同 commit 重跑 = 追加新 releases/<sha> 并切换。
# 本波最终 SHA 未定（后续合并）——终局由主会话对本脚本跑一次入仓。
#
# 用法：
#   bash system/install-release.sh [COMMIT] [选项]
#     COMMIT            目标 commit（默认 HEAD；分支名/SHA 均可）
#     --keyring PATH    签发 keyring（默认 $WENQU_RELEASE_KEYRING 或
#                       ~/.wenqu-dist-release/release-keyring.json）
#     --install-root P  安装根（默认 $WENQU_INSTALL_ROOT 或 ~/.wenqu）
#     --repo PATH       源仓（默认脚本所在仓根）
#     --force           部署位已存在但验签失败时强制删除重部署（默认中止）
#     --reload-scheduler  激活后 launchctl 重载 com.wenqu.scheduler 并 kickstart
#     --no-activate     只产四件套到 dist/，不部署不切换
#     --rollback        切回 .last-current 记录的上一个激活目标
#
# 密钥纪律：keyring 只传路径给 release_attest（只读 import）；secret 绝不
# 回显/入档。HMAC 对称签名 = tamper-evident，非非否认（§21.4 诚实边界）。
#
# exit：0=激活完成（或幂等复验通过）；1=任一环节 fail-closed 中止。
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEFAULT_REPO=$(cd "$SCRIPT_DIR/.." && pwd)

COMMIT="HEAD"
KEYRING="${WENQU_RELEASE_KEYRING:-$HOME/.wenqu-dist-release/release-keyring.json}"
INSTALL_ROOT="${WENQU_INSTALL_ROOT:-$HOME/.wenqu}"
REPO="$DEFAULT_REPO"
FORCE=0
RELOAD_SCHEDULER=0
NO_ACTIVATE=0
ROLLBACK=0

while [ $# -gt 0 ]; do
  case "$1" in
    --keyring) KEYRING="${2:?--keyring 缺参数}"; shift 2;;
    --install-root) INSTALL_ROOT="${2:?--install-root 缺参数}"; shift 2;;
    --repo) REPO="${2:?--repo 缺参数}"; shift 2;;
    --force) FORCE=1; shift;;
    --reload-scheduler) RELOAD_SCHEDULER=1; shift;;
    --no-activate) NO_ACTIVATE=1; shift;;
    --rollback) ROLLBACK=1; shift;;
    -h|--help) sed -n '2,30p' "$0"; exit 0;;
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
trap 'rm -f "$INSTALL_ROOT/.current.new.$$" \
      "$INSTALL_ROOT/.current.rollback.$$" 2>/dev/null || true' EXIT

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
[ -d "$REPO/.git" ] || die "不是 git 仓: $REPO"
[ -f "$KEYRING" ] || die "keyring 不存在: ${KEYRING}（生产签发 key 仓外隔离）"
command -v git >/dev/null 2>&1 || die "git 不可用"

FULL_SHA=$(git -C "$REPO" rev-parse --verify "$COMMIT^{commit}") \
  || die "commit 解析失败: $COMMIT"
FULL_SHA=${FULL_SHA%%[[:space:]]*}
echo "== install-release: commit $FULL_SHA ($COMMIT) =="

NAME="wenqu-dist-$(git -C "$REPO" rev-parse --short=7 "$FULL_SHA")"
DIST_DIR="$REPO/dist"
RELDIR="$RELROOT/$FULL_SHA"

# ------------------------------------------------- 1) 四件套重产（dist/）
echo "== [1/5] build+sign+sbom+verify → $DIST_DIR =="
cd "$REPO"
"$PY" tools/release_attest.py build --commit "$FULL_SHA" \
  --dist-dir "$DIST_DIR" --repo "$REPO"
"$PY" tools/release_attest.py sign \
  --manifest "$DIST_DIR/$NAME.manifest.json" --keyring "$KEYRING"
"$PY" tools/release_attest.py sbom --manifest "$DIST_DIR/$NAME.manifest.json"
"$PY" tools/release_attest.py verify \
  --manifest "$DIST_DIR/$NAME.manifest.json" --keyring "$KEYRING" \
  --report "$DIST_DIR/$NAME.verify-report.json" \
  || die "dist 四件套 verify 失败——不出厂（fail-closed）"

if [ "$NO_ACTIVATE" = "1" ]; then
  log "四件套已产出到 ${DIST_DIR}（--no-activate，未部署）"
  exit 0
fi

# ------------------------------------------------- 2) 部署到不可变位
echo "== [2/5] 部署 $RELDIR =="
FRESH=0
if [ -d "$RELDIR" ]; then
  # 幂等重装：部署位已存在 → 复验既有四件套；通过则不重写（不可变纪律）
  if "$PY" tools/release_attest.py verify \
      --manifest "$RELDIR/$NAME.manifest.json" --keyring "$KEYRING" \
      >/dev/null 2>&1; then
    log "部署位已存在且验签通过——保持不可变，仅重新激活"
  elif [ "$FORCE" = "1" ]; then
    log "部署位验签失败 + --force → 删除重部署: $RELDIR"
    chmod -R u+w "$RELDIR" 2>/dev/null || true
    rm -rf "$RELDIR"
  else
    die "部署位已存在但验签失败（不可变位被篡改?）: ${RELDIR}——人工核查或 --force"
  fi
fi

if [ ! -d "$RELDIR" ]; then
  FRESH=1
  mkdir -p "$RELDIR"
  for ext in tar.gz manifest.json release.sig sbom.spdx.json; do
    cp -p "$DIST_DIR/$NAME.$ext" "$RELDIR/$NAME.$ext"
  done
  mkdir -p "$RELDIR/tree"
  tar -xzf "$RELDIR/$NAME.tar.gz" -C "$RELDIR/tree"
  [ -f "$RELDIR/tree/system/wenqu_core/scheduler.py" ] \
    || { chmod -R u+w "$RELDIR" 2>/dev/null || true; rm -rf "$RELDIR"; \
         die "解出的树缺 system/wenqu_core/scheduler.py——非本仓制品"; }

  # ------------------------------------------------- 3) 部署位复验（仅新装：
  #     防复制/解压损坏；幂等路径上面已复验，不可变位不再写入报告）
  echo "== [3/5] 部署位 verify 复验 + tree 逐文件对账 =="
  "$PY" tools/release_attest.py verify \
    --manifest "$RELDIR/$NAME.manifest.json" --keyring "$KEYRING" \
    --report "$RELDIR/verify-report.json" \
    || { chmod -R u+w "$RELDIR" 2>/dev/null || true; \
         die "部署位四件套 verify 失败——中止激活（fail-closed）"; }
  # 解出树与制品内清单逐文件对账（tree 必须逐字节等于 git archive 树）
  "$PY" - "$RELDIR" "$NAME" <<'PYEOF' || { chmod -R u+w "$RELDIR" 2>/dev/null || true; \
         die "解出树与 manifest 逐文件对账失败"; }
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
  log "== [3/5] 幂等路径：部署位四件套已复验，跳过重写"
fi

# ------------------------------------------------- 4) 不可变化 + 原子切换
echo "== [4/5] 不可变化 + 原子激活 =="
if [ "$FRESH" = "1" ]; then
  chmod -R a-w "$RELDIR" 2>/dev/null || log "（警告）chmod a-w 未完全生效"
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
PYTHONPATH="$CURRENT/system" "$PY" -c \
  "import wenqu_core.scheduler as s; import os; \
   print('  import OK  wenqu_core.scheduler from', os.path.dirname(s.__file__))" \
  || die "激活位 wenqu_core.scheduler 导入失败"

# 可选：launchd 重载 + 立即 kickstart 一轮
if [ "$RELOAD_SCHEDULER" = "1" ]; then
  echo "== reload com.wenqu.scheduler =="
  PLIST="$HOME/Library/LaunchAgents/com.wenqu.scheduler.plist"
  [ -f "$PLIST" ] || die "plist 不存在: $PLIST"
  launchctl bootout "gui/$UID_N/com.wenqu.scheduler" 2>/dev/null || true
  launchctl bootstrap "gui/$UID_N" "$PLIST" \
    || die "launchctl bootstrap 失败"
  launchctl kickstart "gui/$UID_N/com.wenqu.scheduler" \
    || die "launchctl kickstart 失败"
  log "scheduler 已重载并 kickstart（活性: launchctl print gui/$UID_N/com.wenqu.scheduler）"
fi

echo "INSTALL-RELEASE OK  $FULL_SHA"
echo "  四件套    : $DIST_DIR/$NAME.{tar.gz,manifest.json,release.sig,sbom.spdx.json}"
echo "  不可变位  : ${RELDIR}（chmod a-w）"
echo "  激活      : $CURRENT → $RELDIR/tree"
echo "  回滚      : bash system/install-release.sh --rollback"

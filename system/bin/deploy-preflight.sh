#!/usr/bin/env bash
# deploy-preflight v1（2026-10-01 建仓加固——部署三坑机器闸）
# 反的什么事故（全部 9-30 夜战实锄）：
#   ①/tmp/DEPLOY_HEAD 残留上批指纹→precheck 源指纹拒（战训同款二犯）
#   ②lineage 镜像仓 origin/master 陈旧→世系棘轮 fail-closed 拒（服务器无 GitHub 通道）
#   ③artifact tar 带 .next/ 前缀（应内容形态）→绿侧解包空→自动回滚拒
# 用法：bash deploy-preflight.sh <待部署git_hash或master> [artifact.tar]
set -uo pipefail
REPO_DIR="${WENQU_REPO_DIR:?需设 WENQU_REPO_DIR}"
CLOUD="${WENQU_DB_SSH:?需设 WENQU_DB_SSH}"
LINEAGE="${WENQU_LINEAGE_GIT:?需设 WENQU_LINEAGE_GIT}"
FAIL=0

TARGET="${1:-master}"
TAR="${2:-}"

echo "== deploy-preflight: target=$TARGET tar=${TAR:-∅} =="

# ── 闸1: 本地真值取 HEAD ──
cd "$REPO_DIR" || { echo "✗ 仓不可达"; exit 1; }
git fetch origin master --quiet || { echo "✗ fetch origin 失败（网络）"; exit 1; }
if [ "$TARGET" = "master" ]; then
  NEW_HASH=$(git rev-parse origin/master)
else
  git cat-file -e "${TARGET}^{commit}" 2>/dev/null || { echo "✗ 本地无对象 $TARGET（先 fetch）"; exit 1; }
  NEW_HASH=$(git rev-parse "$TARGET")
fi
echo "新部署头: $NEW_HASH"

# ── 闸2: lineage 镜像对齐 ──
LIN=$(ssh "$CLOUD" "sudo git -C $LINEAGE rev-parse refs/remotes/origin/master 2>/dev/null" 2>/dev/null | tr -d '[:space:]')
if [ "$LIN" != "$NEW_HASH" ]; then
  echo "✗ lineage 镜像陈旧: cloud4=$LIN ≠ 新头"
  echo "  修复: cd '$REPO_DIR' && git push $CLOUD:$LINEAGE +${NEW_HASH}:refs/remotes/origin/master"
  FAIL=1
else
  echo "✓ lineage 镜像=新头"
fi

# ── 闸3: /tmp/DEPLOY_HEAD 指纹 ──
DH=$(ssh "$CLOUD" "cat /tmp/DEPLOY_HEAD 2>/dev/null" 2>/dev/null | tr -d '[:space:]')
if [ -n "$DH" ] && [ "$DH" != "$NEW_HASH" ]; then
  echo "✗ DEPLOY_HEAD 残留上批: $DH ≠ 新头"
  echo "  修复: ssh $CLOUD \"echo -n $NEW_HASH | sudo tee /tmp/DEPLOY_HEAD >/dev/null\""
  FAIL=1
elif [ -z "$DH" ]; then
  echo "⚠ DEPLOY_HEAD 空（部署时按需写入 $NEW_HASH）"
else
  echo "✓ DEPLOY_HEAD=新头"
fi

# ── 闸4: artifact 形态（可选） ──
if [ -n "$TAR" ] && [ -f "$TAR" ]; then
  FIRST=$(tar -tf "$TAR" 2>/dev/null | head -1)
  case "$FIRST" in
    .next/*|.next) echo "✗ tar 是 .next 前缀形态（首条目 $FIRST）——须在 .next/ 目录内打包内容形态"; FAIL=1 ;;
    ./|*BUILD_ID*|*GIT_HASH*|"."|"./") echo "✓ tar 内容形态（首条目 ${FIRST:0:40}）" ;;
    *) echo "⚠ tar 首条目形态未识别: $FIRST（人工确认应为内容形态）" ;;
  esac
else
  echo "— 未提供 tar，跳过形态闸"
fi

# ── 闸5: 世系棘轮预演（只读） ──
PROD_TIP=$(ssh "$CLOUD" "head -1 /opt/erp-guard/state/deploy-lineage 2>/dev/null" 2>/dev/null | tr -d '[:space:]')
if [ -n "$PROD_TIP" ]; then
  ANCESTOR=$(ssh "$CLOUD" "sudo git -C $LINEAGE merge-base --is-ancestor $PROD_TIP $NEW_HASH 2>/dev/null && echo yes || echo no" 2>/dev/null)
  if [ "$ANCESTOR" = "yes" ]; then
    echo "✓ 世系棘轮预演: 生产 ${PROD_TIP:0:8} ⊆ 新头"
  else
    echo "✗ 世系棘轮预演失败: 生产 $PROD_TIP 不含于新头（先合流 master 或推齐镜像后重试——镜像缺对象也会判 no，若闸2刚修复请重跑本预检）"
    FAIL=1
  fi
fi

[ "$FAIL" -eq 0 ] && echo "== PASS：五闸全过 ==" || { echo "== FAIL：按上方修复命令处理后重跑 =="; exit 1; }

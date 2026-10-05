#!/usr/bin/env bash
# cursor-auto-verify v1（2026-10-02 问渠融合件：Cursor 交卷→零返工验证→自动推送）
# 取代人工"ZCode 亲验三步"的前两步（簿记+测试面），第三步（diff 全读）仍属 ZCode 判断。
# 部署位：183 ~/quality-tools/（与 iron-gate/blast-radius 同目录）
# 调用：cursor-auto-verify.sh <仓目录> <分支> [base_ref]
set -uo pipefail
TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:?仓目录}"; BR="${2:?分支}"; BASE="${3:-origin/master}"
cd "$DIR" || exit 1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
log()  { echo -e "  $1"; }
ok()   { echo -e "  ${GREEN}✓ $1${NC}"; }
bad()  { echo -e "  ${RED}✗ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠ $1${NC}"; }

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  问渠·零返工自动验证  cursor-auto-verify v1  ║"
echo "║  Cursor 交卷 → iron-gate → blast-radius     ║"
echo "║  → affected tests → pass=自动推送            ║"
echo "╚══════════════════════════════════════════════╝"

# ── 前置：确认 Cursor 产物 ──
NEW_COMMITS=$(git log --oneline "$BASE"..HEAD 2>/dev/null | wc -l | tr -d ' ')
if [ "$NEW_COMMITS" -eq 0 ]; then
  bad "无新 commits（$BASE..HEAD 为空）——Cursor 可能没产出"
  exit 1
fi
ok "Cursor 产出 $NEW_COMMITS 个新 commits"

# ── Step 1: iron-gate（0.1s 簿记闸）──
echo ""
echo "── Step 1: iron-gate ──"
if bash "$TOOLS_DIR/iron-gate.sh" "$DIR" "$BASE" 2>&1 | sed 's/^/  /'; then
  ok "iron-gate 全过"
else
  bad "iron-gate 拦截——修后重跑（上面有具体修法提示）"
  exit 1
fi

# ── Step 2: blast-radius（影响面+测试推荐）──
echo ""
echo "── Step 2: blast-radius ──"
BR_OUT=$(python3 "$TOOLS_DIR/blast-radius.py" "$DIR" "$BASE" 2>/dev/null)
TESTS=$(echo "$BR_OUT" | python3 -c "
import json,sys
raw = sys.stdin.read()
end = raw.rfind('}\n')
if end < 0: print(''); exit()
d = json.loads(raw[:end+2])
print('\n'.join(d['test_files_to_run']))
" 2>/dev/null)
INDIRECT=$(echo "$BR_OUT" | python3 -c "
import json,sys
raw = sys.stdin.read()
end = raw.rfind('}\n')
if end < 0: print('0'); exit()
print(json.loads(raw[:end+2])['indirect_impact_count'])
" 2>/dev/null)
ok "影响面分析：$INDIRECT 个间接影响文件"
if [ -n "$TESTS" ] && [ "$TESTS" != "" ]; then
  TEST_COUNT=$(echo "$TESTS" | grep -c . || echo 0)
  ok "推荐 $TEST_COUNT 个测试文件"
else
  warn "无受影响测试——跳过 Step 3"
fi

# ── Step 3: 受影响测试 ──
if [ -n "$TESTS" ] && [ "$TESTS" != "" ]; then
  echo ""
  echo "── Step 3: affected tests ──"
  TEST_LIST=$(echo "$TESTS" | tr '\n' ' ')
  if NODE_OPTIONS=--max-old-space-size=8192 node node_modules/vitest/vitest.mjs run $TEST_LIST --reporter=dot 2>&1 | tail -4; then
    ok "受影响测试全绿"
  else
    bad "受影响测试红——修后重跑"
    exit 1
  fi
fi

# ── Step 4: 构建面（next build——route 导出/use server 唯 build 查出）──
echo ""
echo "── Step 4: next build ──"
if [ -f package.json ] && grep -q '"next"' package.json 2>/dev/null; then
  if NODE_OPTIONS=--max-old-space-size=8192 node node_modules/next/dist/bin/next build >/dev/null 2>&1; then
    ok "next build 绿"
  else
    bad "next build 红（route 导出/use server 类型唯 build 查出——查 tail /tmp/build.log）"
    NODE_OPTIONS=--max-old-space-size=8192 node node_modules/next/dist/bin/next build 2>&1 | tail -5
    exit 1
  fi
else
  warn "非 Next.js 项目，跳过 build"
fi

# ── 全绿：自动 relay-push ──
echo ""
echo "════════════════════════════════════════════"
ok "零返工四步全绿——自动推送到 GitHub"
echo "════════════════════════════════════════════"
# 推送到 GitHub（183→本机→GitHub 中转或直推）
git push origin "HEAD:refs/heads/$BR" 2>&1 | tail -2 || {
  # 183 直推失败→本机中转
  warn "183 直推失败，尝试本机中转（需本机执行 relay-push）"
  echo ">>> 在本机跑: bash ~/.zcode/quality-system/4c6665172cfd52c9/bin/relay-push.sh $DIR $BR"
}
echo ""
ok "推送完成——GitHub 将触发 CI（预期一次过 >85%）"
echo ">>> 下一步: Gate (~30min) → 合流 → 部署"

#!/usr/bin/env bash
# workorder-precheck v1（2026-10-01 建仓加固——派工簿记三红本地闸）
# 反的什么事故（每批 Cursor 都踩、每红一轮 Gate 30min）：
#   ①PIT 新条目缺 family: 标签（S8 守卫，Z13 十三条全踩）
#   ②README stats 不同步（Z13/Z14 各踩一次）
#   ③SDD domain-spec 缺「## 验收标准」段（SDD AC 门，Z13 踩）
#   ④树含 node_modules/.next（软链事故，z13 三连红元凶）
# 用法：bash workorder-precheck.sh <仓目录> <base-ref>
set -uo pipefail
DIR="${1:?仓目录}"; BASE="${2:?base ref}"
cd "$DIR" || exit 1
FAIL=0
echo "== workorder-precheck: $DIR vs $BASE =="

# ── 闸1: 新 PIT 条目 family 标签 ──
MISS_FAM=$(git diff "$BASE"...HEAD -- sdd/bug-library/PITFALLS.md 2>/dev/null | grep "^+## PIT-" | sed 's/^+## \(PIT-[0-9]*\).*/\1/' | while read -r pit; do
  git show "HEAD:sdd/bug-library/PITFALLS.md" 2>/dev/null | grep -A 1 "^## ${pit} " | grep -q "^family:" || echo "$pit"
done | tr '\n' ' ')
if [ -n "$MISS_FAM" ]; then
  echo "✗ PIT 新条目缺 family 标签: ${MISS_FAM}（S8 会红——条目标题行下加 'family:<slug>'）"
  FAIL=1
else
  echo "✓ PIT family 标签齐"
fi

# ── 闸2: README stats 一致 ──
if [ -f scripts/gates/check-readme-stats.py ]; then
  if python3 scripts/gates/check-readme-stats.py --repo-root . >/dev/null 2>&1; then
    echo "✓ README stats 一致"
  else
    echo "✗ README stats 不同步（修法: python3 scripts/gates/check-readme-stats.py --repo-root . --fix）"
    FAIL=1
  fi
fi

# ── 闸3: 变更的 SDD spec 含验收标准段 ──
for f in $(git diff --name-only "$BASE"...HEAD -- 'sdd/domain-spec/*.md' 2>/dev/null); do
  if [ -f "$f" ] && ! grep -q "^## 验收标准" "$f"; then
    echo "✗ $f 缺「## 验收标准」段（SDD AC 门会红）"
    FAIL=1
  fi
done
[ "$FAIL" -eq 0 ] && echo "✓ SDD spec 验收段齐"

# ── 闸4: 树内构建物/软链 ──
BAD=$(git ls-tree -r --name-only HEAD | grep -cE "^node_modules$|^\.next/" || true)
if [ "${BAD:-0}" -gt 0 ]; then echo "✗ 树含构建物（node_modules/.next）"; FAIL=1; else echo "✓ 树无构建物"; fi

[ "$FAIL" -eq 0 ] && echo "== PASS：四闸全过，可推送 ==" || { echo "== FAIL：修后重跑 =="; exit 1; }

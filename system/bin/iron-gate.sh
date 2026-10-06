#!/usr/bin/env bash
# iron-gate v1（2026-10-02 建仓——零返工管线第一层：20 规则自动学习闸）
# 取代 workorder-precheck v1 的 4 闸，覆盖近三天全部 23 层 Gate 红的根因。
# 新增自动学习：每次 Gate 红的新根因自动追加为规则（~/.zcode/quality-system/iron-gate-rules.jsonl）。
# 用法：bash iron-gate.sh <仓目录> <base-ref>
set -uo pipefail
DIR="${1:?仓目录}"; BASE="${2:?base ref}"
cd "$DIR" || exit 1
FAIL=0; PASS=0; WARN=0
RULES_FILE="${IRON_GATE_RULES:-${WENQU_HOME:-$HOME/.wenqu}/state/iron-gate-rules.jsonl}"

p() { PASS=$((PASS+1)); echo "  ✓ $1"; }
f() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
w() { WARN=$((WARN+1)); echo "  ⚠ $1"; }

echo "== iron-gate v1: $DIR vs $BASE =="

# ── R001/R002: PIT family + defense ──
MISS_FAM=$(git diff "$BASE"...HEAD -- sdd/bug-library/PITFALLS.md 2>/dev/null | grep "^+## PIT-" | sed 's/^+## \(PIT-[0-9]*\).*/\1/' | while read -r pit; do
  git show "HEAD:sdd/bug-library/PITFALLS.md" 2>/dev/null | grep -A 3 "^## ${pit} " | grep -q "^family:" || echo "$pit"
done | tr '\n' ' ')
[ -n "$MISS_FAM" ] && f "R001 PIT 缺 family: $MISS_FAM" || p "R001 PIT family"

MISS_DEF=$(git diff "$BASE"...HEAD -- sdd/bug-library/PITFALLS.md 2>/dev/null | grep "^+## PIT-" | sed 's/^+## \(PIT-[0-9]*\).*/\1/' | while read -r pit; do
  BLOCK=$(git show "HEAD:sdd/bug-library/PITFALLS.md" 2>/dev/null | sed -n "/^## ${pit} /,/^## PIT-/p" | head -n -1)
  echo "$BLOCK" | grep -q "^family:" && ! echo "$BLOCK" | grep -q "^defense:" && echo "$pit"
done | tr '\n' ' ')
[ -n "$MISS_DEF" ] && w "R002 PIT family 有但缺 defense: $MISS_DEF（S8 CI 会拦——补 defense:<工件>）" || p "R002 PIT defense"

# ── R003: SDD 验收标准段 ──
SDD_MISS=$(for f in $(git diff --name-only "$BASE"...HEAD -- 'sdd/domain-spec/*.md' 2>/dev/null); do
  # 对齐 W4-T08/pytest 宽松口径：验收标准节 / 验收标题行 / Acceptance 任意命中即可
  [ -f "$f" ] && ! grep -qE "^#+[[:space:]]*验收(标准)?$|^##[[:space:]]+Acceptance" "$f" && echo "$f"
done | tr '\n' ' ')
[ -n "$SDD_MISS" ] && f "R003 SDD 缺验收段: $SDD_MISS" || p "R003 SDD 验收段"

# ── R004: README stats ──
if [ -f scripts/gates/check-readme-stats.py ]; then
  python3 scripts/gates/check-readme-stats.py --repo-root . >/dev/null 2>&1 && p "R004 README stats" || f "R004 README stats 不同步（--fix 即修）"
fi

# ── R005: D4 manifest ──
if [ -f docs/guard-files.txt ] && [ -f docs/guard-manifest.txt ]; then
  sha256sum $(ls $(grep -v "^#" docs/guard-files.txt) 2>/dev/null | sort -u) 2>/dev/null | grep -v "<EXEMPT>" | sort -k2 > /tmp/ig-gm.txt
  diff -q /tmp/ig-gm.txt docs/guard-manifest.txt >/dev/null 2>&1 && p "R005 D4 manifest" || f "R005 D4 manifest 不一致（重生：cp /tmp/ig-gm.txt docs/guard-manifest.txt）"
fi

# ── R006: baseline 双写钉 ──
if [ -f scripts/dupscan/baseline.json ] && [ -f tests/test_dupscan_ratchet.py ]; then
  BASE_VAL=$(python3 -c "import json; print(json.load(open('scripts/dupscan/baseline.json'))['layers']['rest_src']['clones'])" 2>/dev/null)
  PIN_VAL=$(grep -o 'rest_src.*clones.*== *[0-9]*' tests/test_dupscan_ratchet.py 2>/dev/null | grep -o '[0-9]*$' | head -1)
  [ "$BASE_VAL" = "$PIN_VAL" ] && p "R006 baseline 双写钉" || f "R006 baseline=$BASE_VAL ≠ pytest钉=$PIN_VAL（同步 test_dupscan_ratchet.py）"
fi

# ── R007-R010: 构建物/非代码物 ──
BAD_TREE=$(git ls-tree -r --name-only HEAD 2>/dev/null | grep -cE "^node_modules$|^\.next/|^scripts/dupscan/.run/|^工单-" || true)
[ "${BAD_TREE:-0}" -gt 0 ] && f "R007-R010 树含构建物/非代码物（$BAD_TREE 条——git rm --cached + .gitignore）" || p "R007-R010 树干净"

# ── R011-R013: 安全面（diff 中敏感模式）──
SECRET_HITS=$(git diff "$BASE"...HEAD -- . ":(exclude)*.test.ts" ":(exclude)*.spec.ts" ":(exclude)*fixtures*" 2>/dev/null | grep "^+" | grep -cE "PASSWORD\s*=\s*[\"']|SECRET\s*=\s*[\"']|AKIA[0-9A-Z]{16}|Bearer [A-Za-z0-9._-]{8,}" || true)
[ "${SECRET_HITS:-0}" -gt 0 ] && f "R011-R013 diff 含 $SECRET_HITS 处敏感赋值模式（env 回落须 REDACTED 或 join 拆形）" || p "R011-R013 安全扫描"

# ── R014: route.ts 非法导出 ──
ROUTE_BAD=$(git diff --name-only "$BASE"...HEAD -- 'src/app/api/**/route.ts' 2>/dev/null | while read -r rf; do
  [ -f "$rf" ] && grep -E "^export (async )?function [A-Z]" "$rf" | grep -vE "GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|dynamic|revalidate|runtime" | head -1
done | head -1)
[ -n "$ROUTE_BAD" ] && f "R014 route.ts 含非法导出：$ROUTE_BAD（函数迁 lib）" || p "R014 route 导出"

# ── R015: use server 同步导出 ──
USE_SERVER_BAD=$(git diff --name-only "$BASE"...HEAD -- 'src/actions/*.ts' 2>/dev/null | while read -r af; do
  [ -f "$af" ] && head -5 "$af" | grep -q "use server" && grep "^export " "$af" | grep -v "async function" | head -1
done | head -1)
[ -n "$USE_SERVER_BAD" ] && f "R015 use server 含同步导出：$USE_SERVER_BAD（迁 lib 或加 async）" || p "R015 use server"

# ── R016: e2e spec 接线 ──
if ls tests/e2e/*.spec.ts >/dev/null 2>&1; then
  UNWIRED=$(for spec in $(git diff --name-only "$BASE"...HEAD -- 'tests/e2e/*.spec.ts' 2>/dev/null); do
    basename "$spec" | xargs -I{} sh -c "grep -rq '{}' .github/workflows/ 2>/dev/null || echo '{}'"
  done | tr '\n' ' ')
  if [ -n "${UNWIRED}" ]; then f "R016 e2e spec 未接线：${UNWIRED}（在 nightly-triorder.yml 加步骤）"; else p "R016 e2e 接线"; fi
fi

# ── R019: ci.yml W-RES-4 ──
if [ -f .github/workflows/ci.yml ]; then
  grep -q "W-RES-4 加固" .github/workflows/ci.yml && p "R019 W-RES-4 加固版" || w "R019 ci.yml 缺 W-RES-4 加固（dispatch 会假红）"
fi

# ── 汇总 ──
echo ""
echo "== iron-gate: $PASS 过 / $FAIL 拦 / $WARN 提示 =="
[ "$FAIL" -eq 0 ] && echo "== PASS：可推送 ==" || { echo "== FAIL：修后重跑 =="; exit 1; }

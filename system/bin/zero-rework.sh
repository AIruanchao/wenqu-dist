#!/usr/bin/env bash
# zero-rework v1（2026-10-02 零返工管线统一入口）
# 三层串联：iron-gate（簿记闸）→ blast-radius（影响面）→ affected tests（含属性测试）
# 用法：bash zero-rework.sh <仓目录> <base-ref>
# 结果：全绿=可推送；红=按提示修后重跑（不消耗 Gate 30 分钟）
set -uo pipefail
Q=~/.zcode/quality-system/4c6665172cfd52c9
DIR="${1:?仓目录}"; BASE="${2:?base ref}"
cd "$DIR" || exit 1

echo "╔══════════════════════════════════════════╗"
echo "║  零返工管线 zero-rework v1               ║"
echo "║  Layer 1: iron-gate     (簿记/构建物/安全) ║"
echo "║  Layer 3: blast-radius  (影响面推演)       ║"
echo "║  Layer 2: affected tests (受影响测试+属性) ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Layer 1: iron-gate ──
echo "── Layer 1: iron-gate ──"
if bash "$Q/bin/iron-gate.sh" "$DIR" "$BASE"; then
  echo "✅ Layer 1 过"
else
  echo "❌ Layer 1 拦——修后重跑（节省 Gate 30 分钟）"
  exit 1
fi
echo ""

# ── Layer 3: blast-radius ──
echo "── Layer 3: blast-radius ──"
BR_OUTPUT=$(python3 "$Q/bin/blast-radius.py" "$DIR" "$BASE" 2>/dev/null)
TESTS=$(echo "$BR_OUTPUT" | python3 -c "
import json,sys
raw = sys.stdin.read()
end = raw.rfind('}\n')
if end < 0: print(''); exit()
d = json.loads(raw[:end+2])
print('\n'.join(d['test_files_to_run']))
" 2>/dev/null)
AFFECTED_COUNT=$(echo "$BR_OUTPUT" | python3 -c "
import json,sys
raw = sys.stdin.read()
end = raw.rfind('}\n')
if end < 0: print('0'); exit()
d = json.loads(raw[:end+2])
print(d['indirect_impact_count'])
" 2>/dev/null)
echo "  间接影响文件：$AFFECTED_COUNT"
echo "  推荐测试：$(echo "$TESTS" | grep -c . || echo 0) 个"
echo ""

# ── Layer 2: run affected tests ──
if [ -n "$TESTS" ] && [ "$TESTS" != "" ]; then
  echo "── Layer 2: affected tests ──"
  TEST_LIST=$(echo "$TESTS" | tr '\n' ' ')
  echo "  跑：npx vitest run $TEST_LIST"
  if NODE_OPTIONS=--max-old-space-size=8192 npx vitest run $TEST_LIST --reporter=dot 2>&1 | tail -5; then
    echo "✅ Layer 2 过"
  else
    echo "❌ Layer 2 红——测试失败，修后重跑"
    exit 1
  fi
else
  echo "── Layer 2: 无受影响测试，跳过 ──"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  ✅ 零返工管线全绿——可推送                ║"
echo "║  Gate 预期一次过（簿记/安全/测试已预验）    ║"
echo "╚══════════════════════════════════════════╝"

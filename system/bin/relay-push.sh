#!/usr/bin/env bash
# relay-push v1（2026-10-01 建仓加固——183→本机→GitHub 标准中转）
# 反的什么事故：夜战多次人肉中转翻车——fetch 未取到对象 push 报 bad object、
#   refspec 简写解析失败、183 树 checkout 在他人分支上直推污染。
# 语义：按引用整体取回（保对象完整）→ 三自检 → 推远端。
# 用法：bash relay-push.sh <183仓路径> <分支> [远端分支名=分支]
set -uo pipefail
HOST="${WENQU_RELAY_HOST:?需设 WENQU_RELAY_HOST}"
SRC="$1"; BR="$2"; DST="${3:-$BR}"
LOCAL=${WENQU_RELAY_LOCAL:?需设 WENQU_RELAY_LOCAL}
TMPREF="relay/$(echo "$BR" | tr '/' '_')"

cd "$LOCAL" || { echo "✗ 本地仓不可达 $LOCAL"; exit 1; }

echo "== relay-push: $SRC:$BR -> origin:$DST =="
# ① 按引用取回（完整对象）
if ! git fetch "ssh://$HOST$SRC" "+refs/heads/$BR:refs/heads/$TMPREF" 2>&1 | tail -1; then
  echo "✗ fetch 183 失败"; exit 1
fi
HEAD=$(git rev-parse "refs/heads/$TMPREF" 2>/dev/null) || { echo "✗ 引用未建立"; exit 1; }
echo "取回: $BR -> $HEAD"

# ② 自检：index 意外软链/构建物（夜战 node_modules 软链事故的机器闸）
BAD=$(git ls-tree -r --name-only "$HEAD" | grep -cE "^node_modules$|^\.next/" || true)
if [ "${BAD:-0}" -gt 0 ]; then
  echo "✗ 树内含构建物/软链（node_modules/.next）——拒绝中转，先在源端剔除"
  exit 1
fi
# ③ 自检：冲突标记零残留（行首形态，排除历史条目文本）
CM=$(git grep -cE "^(<<<<<<<|>>>>>>>)" "$HEAD" -- '*.md' 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}' || true)
[ "${CM:-0}" -gt 0 ] && { echo "✗ md 文件含行首冲突标记 $CM 处——先解冲突"; exit 1; }

echo "自检过（对象完整/无构建物/无冲突标记）→ 推送"
git push origin "refs/heads/$TMPREF:refs/heads/$DST" 2>&1 | tail -2
git branch -qD "$TMPREF" 2>/dev/null || true

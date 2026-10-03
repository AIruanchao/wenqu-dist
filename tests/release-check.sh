#!/usr/bin/env bash
# 打包前置检查（S11 建议固化）：版本号残留机械全查——升版批的同族半改防线
# 用法：bash tests/release-check.sh <新版本号如 v1.0.17> <新fork号如 fork17>
set -u
V="${1:?用法: release-check.sh <v版本> <fork版本>}"; F="${2:?缺 fork 版本}"
FAIL=0
# 正源文件（CHANGELOG 的旧版本号=历史条目合法，排除）
for f in README.md cli/README.md docs/*.md; do
  while IFS=: read -r ln content; do
    echo "  残留: $f:$ln $content"
    FAIL=1
  # fork17-S12 加固：先剥本行的新版本引用再查旧（防同行新旧并存被整行豁免）；
  # forkN/vN.N.N 后加边界类（[^0-9]|$）防 fork170 前瞻豁免
  done < <(grep -nE "v0\.3\.0-fork[0-9]+-maccc|发行版-v1\.0\.[0-9]+\.md" "$f" \
    | sed -E "s/$F[^0-9]/CUR/g; s/${V//./\\.}[^0-9]/CUR/g" \
    | grep -E "v0\.3\.0-fork[0-9]+-maccc|发行版-v1\.0\.[0-9]+\.md" || true)
done
# CLI VERSION 常量对齐
GV=$(python3 cli/wenqu --version | awk '{print $2}')
[ "$GV" = "0.3.0-$F-maccc" ] || { echo "  ❌ cli VERSION=$GV 期望 0.3.0-$F-maccc"; FAIL=1; }
[ $FAIL -eq 0 ] && echo "release-check PASS（零旧版本残留+VERSION 对齐）" || echo "release-check FAIL"
exit $FAIL

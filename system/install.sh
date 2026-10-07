#!/usr/bin/env bash
# wenqu v3.0 一键安装（macOS / Linux 通用）
# 用法：./install.sh [--prefix ~/.wenqu]
set -euo pipefail
PREFIX="${1:---prefix}"; [ "$PREFIX" = "--prefix" ] && PREFIX="${2:-$HOME/.wenqu}"
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════╗
║  问渠 wenqu v3.0 —— 质量工程体系安装  ║
╚══════════════════════════════════════╝"
echo "目标：$PREFIX"

# 1. 目录
mkdir -p "$PREFIX"/{bin,sentinels,daemons,db,ci,templates,specs,config,logs,state}

# 2. 拷贝组件
cp -R "$SRC"/bin/. "$PREFIX/bin/"
cp -R "$SRC"/sentinels/. "$PREFIX/sentinels/" 2>/dev/null || true
cp -R "$SRC"/daemons/. "$PREFIX/daemons/" 2>/dev/null || true
# P0 containment：安装面始终收敛为不可启动的审计 stub。
printf '%s\n' 'printf '\''%s\n'\'' '\''auto-merge permanently disabled per P0 containment'\'' >&2; exit 1' > "$PREFIX/daemons/auto-merge.sh"
cp -R "$SRC"/db/. "$PREFIX/db/" 2>/dev/null || true
cp -R "$SRC"/ci/. "$PREFIX/ci/" 2>/dev/null || true
cp -R "$SRC"/templates/. "$PREFIX/templates/" 2>/dev/null || true
cp -R "$SRC"/specs/. "$PREFIX/specs/" 2>/dev/null || true
[ -f "$SRC/config/wenqu.env.example" ] && cp "$SRC/config/wenqu.env.example" "$PREFIX/env.example"
chmod +x "$PREFIX"/bin/* "$PREFIX"/sentinels/* "$PREFIX"/daemons/* 2>/dev/null || true

# 3. PATH 注入（幂等）
case ":$PATH:" in
  *":$PREFIX/bin:"*) : ;;
  *) SHELL_RC="$HOME/.zshrc"; [ -n "${BASH_VERSION:-}" ] && SHELL_RC="$HOME/.bashrc"
     echo "export PATH=\"$PREFIX/bin:\$PATH\"" >> "$SHELL_RC"
     echo "✓ PATH 已写入 ${SHELL_RC}（新开终端生效）" ;;
esac

# 4. 首个配置（幂等）
if [ ! -f "$PREFIX/env" ] && [ -f "$PREFIX/env.example" ]; then
  cp "$PREFIX/env.example" "$PREFIX/env"
fi
echo "✓ 配置：$PREFIX/env（编辑后 wenqu doctor 校验）"

# 5. 依赖探测（只提示不强装）
echo "── 依赖探测 ──"
for c in git python3 node; do command -v $c >/dev/null && echo "✓ $c $($c --version 2>&1 | head -1)" || echo "✗ 缺 $c（必需）"; done
command -v psql >/dev/null && echo "✓ psql（哨兵/守护需要）" || echo "△ 缺 psql（仅影响 DB 类组件）"
python3 -c "import psycopg2" 2>/dev/null && echo "✓ psycopg2（守护进程需要）" || echo "△ 缺 psycopg2：pip3 install psycopg2-binary"
[ -f "$PREFIX/bin/tla2tools.jar" ] && echo "✓ TLA+ 工具链" || echo "△ 无 tla2tools.jar（仅影响形式化验证组件）"
command -v z3 >/dev/null && echo "✓ Z3 定理证明器" || echo "△ 缺 z3（brew install z3，仅影响 SMT 组件）"

# 6. 自检
echo "── 自检 ──"
WENQU_HOME="$PREFIX" bash "$SRC/bin/wenqu" doctor || true

echo "
安装完成。三步上手：
  1. 编辑 $PREFIX/env —— 填你的仓库/DB/告警参数
  2. cd 你的项目 && wenqu init      —— 初始化项目级质量体系
  3. wenqu status                   —— 查看全组件状态
"

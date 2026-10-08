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
# P0-1 修：安装 wenqu_core（新核心）+ schemas + dashboard
mkdir -p "$PREFIX/lib/wenqu_core" "$PREFIX/schemas" "$PREFIX/dashboard"
for f in "$SRC"/wenqu_core/*.py; do
  [ -f "$f" ] && cp "$f" "$PREFIX/lib/wenqu_core/"
done
# 确保包可导入
touch "$PREFIX/lib/wenqu_core/__init__.py"
[ -f "$SRC/wenqu_core/__init__.py" ] && cp "$SRC/wenqu_core/__init__.py" "$PREFIX/lib/wenqu_core/"

for f in "$SRC"/schemas/*.json; do
  [ -f "$f" ] && cp "$f" "$PREFIX/schemas/"
done

for ext in html css js py; do
  [ -f "$SRC/dashboard/index.$ext" ] && cp "$SRC/dashboard/index.$ext" "$PREFIX/dashboard/"
done
for f in "$SRC"/dashboard/*.html "$SRC"/dashboard/*.css "$SRC"/dashboard/*.js "$SRC"/dashboard/*.py; do
  [ -f "$f" ] && cp "$f" "$PREFIX/dashboard/"
done

# P0-7/F 修：wenqu_core 全模块导入验证（不是只验 TrustedRunner）。
# 必装清单为硬编码（删 wenqu_pipeline.py 后源目录枚举不再覆盖它——硬编码兜底），
# 叠加源目录现存模块；任一导入失败即 rc=1 明确报错（fail-closed）。
if ! PYTHONPATH="$PREFIX/lib" python3 - "$SRC/wenqu_core" <<'PYEOF'
import importlib, os, sys
# cwd 遮蔽防御：剥除 ''/cwd，确保验证的是 PREFIX 安装副本而非调用目录下的源码
sys.path = [p for p in sys.path if p not in ("", ".", os.getcwd())]
src = sys.argv[1]
required = {
    "runner", "store", "source_gate", "bugscan_orchestrator", "scheduler",
    "gate_aggregator", "ledger_migrator", "deploy_framework",
    "wenqu_pipeline", "station2_static", "station3_contract",
    "station4_behavior", "station7_runtime",
}
discovered = {
    f[:-3] for f in os.listdir(src)
    if f.endswith(".py") and f != "__init__.py"
} if os.path.isdir(src) else set()
mods = sorted(required | discovered)
failed = []
for m in mods:
    try:
        importlib.import_module("wenqu_core." + m)
    except Exception as e:
        failed.append(f"{m} ({type(e).__name__}: {e})")
if failed:
    print("wenqu_core 模块导入失败: " + "; ".join(failed), file=sys.stderr)
    sys.exit(1)
print(f"wenqu_core 全模块导入验证通过（{len(mods)} 模块）", file=sys.stderr)
PYEOF
then
  echo "✗ 安装自检失败：wenqu_core 存在缺失/不可导入模块——安装中止" >&2
  exit 1
fi
echo "✓ wenqu_core 安装验证通过（全模块可导入，含 wenqu_pipeline）"

# P0-7/F 修：cp -R 改 tar 管道（保 mode/symlink；cp -R 会拍平权限与链接语义）
tar_copy() { # tar_copy <源目录> <目标目录>
  mkdir -p "$2"
  tar -C "$1" -cf - . | tar -C "$2" -xf -
}
tar_copy "$SRC/bin" "$PREFIX/bin"
tar_copy "$SRC/sentinels" "$PREFIX/sentinels"
tar_copy "$SRC/daemons" "$PREFIX/daemons"
# P0 containment：安装面始终收敛为不可启动的审计 stub。
printf '%s\n' 'printf '\''%s\n'\'' '\''auto-merge permanently disabled per P0 containment'\'' >&2; exit 1' > "$PREFIX/daemons/auto-merge.sh"
tar_copy "$SRC/db" "$PREFIX/db"
tar_copy "$SRC/ci" "$PREFIX/ci"
tar_copy "$SRC/templates" "$PREFIX/templates"
tar_copy "$SRC/specs" "$PREFIX/specs"
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
# 注：${c} 必须加花括号——macOS bash 3.2 + UTF-8 locale 下 `$c（` 会被解析成
# 单个超长变量名（unbound variable 崩溃，node 缺失时才触发——P0-7/F 顺带根治）。
for c in git python3 node; do command -v ${c} >/dev/null && echo "✓ ${c} $(${c} --version 2>&1 | head -1)" || echo "✗ 缺 ${c}（必需）"; done
command -v psql >/dev/null && echo "✓ psql（哨兵/守护需要）" || echo "△ 缺 psql（仅影响 DB 类组件）"
python3 -c "import psycopg2" 2>/dev/null && echo "✓ psycopg2（守护进程需要）" || echo "△ 缺 psycopg2：pip3 install psycopg2-binary"
[ -f "$PREFIX/bin/tla2tools.jar" ] && echo "✓ TLA+ 工具链" || echo "△ 无 tla2tools.jar（仅影响形式化验证组件）"
command -v z3 >/dev/null && echo "✓ Z3 定理证明器" || echo "△ 缺 z3（brew install z3，仅影响 SMT 组件）"

# 6. 自检（P0-7/F 修：doctor 真实执行、不吞退出码；组件损坏中止，全新未配置容忍）
#    区分口径：doctor 输出「缺 <组件>」= 安装面损坏（中止，rc=1）；
#    仅「配置」类失败（无配置/占位符未填）= 全新安装未配置（容忍——配置后 wenqu doctor 复检）。
echo "── 自检 ──"
DOC_RC=0
DOC_OUT=$(WENQU_HOME="$PREFIX" bash "$SRC/bin/wenqu" doctor 2>&1) || DOC_RC=$?
if echo "$DOC_OUT" | grep -q "缺"; then
  echo "✗ 安装自检失败——组件缺失/损坏，安装中止（doctor rc=${DOC_RC}）" >&2
  echo "$DOC_OUT" | grep "缺" | tail -3 >&2
  exit 1
elif [ "$DOC_RC" -ne 0 ]; then
  echo "△ doctor rc=${DOC_RC}：全新安装未配置（容忍）——编辑 $PREFIX/env 后 wenqu doctor 复检"
else
  echo "✓ 安装自检通过（wenqu doctor rc=0）"
fi

echo "
安装完成。三步上手：
  1. 编辑 $PREFIX/env —— 填你的仓库/DB/告警参数
  2. cd 你的项目 && wenqu init      —— 初始化项目级质量体系
  3. wenqu status                   —— 查看全组件状态
"

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P1f2 AST 行为门——八轮 Codex P1f2 残余修复（文本 assert 计数可被绕过 → AST 行为门）。

背景：旧 P1f2 用文本 grep 数 `assert`/`_ck`/`expect` 出现次数，三类绕过均不红：
  a) 常量真值断言（assert True / assert 1）——计数照涨、行为恒过；
  b) 删掉被测调用只留断言壳——计数不缩；
  c) 删掉失败路径（负例/异常腿）——计数不缩。

本工具对 F6-TRC-GATE-001 的八个专属测试文件做纯 ast 静态分析（零第三方依赖、
不导入不执行任何被测体，只读源码），逐顶层 test 函数产出三指标：

  trivial_asserts       assert 的测试表达式为常量真值（ast.Constant 真值 /
                        Name 'True'）→ 计劣（恒真化绕过面）
  has_call_into_module  函数体内在被测面上真实交互 → 良。被测面静态识别：
                        - wenqu_core.* 导入名/别名（文件内任意层 import 收集）
                          上的调用/取属性/下标/迭代（枚举迭代=执行产品 __iter__）；
                        - 轻量数据流传播的实例（gate = SourceGate(...) 之后
                          gate.execute_gate() / result["exit_code"]）；
                        - 产品构造器/装载器助手的产物（store, mgr = _mgr(td)
                          之后 mgr.get_run(...)；doctor = _load_doctor() 之后
                          doctor.check(...)）——助手=体内真实触碰产品码的
                          同文件模块级函数/类（构造 wenqu_core 对象、
                          spec_from_file_location 装载、或 subprocess 启动
                          产品路径常量指向的脚本）；
                        - 产品路径常量（模块级 __file__ 派生、不含 tests/
                          fixtures 字段的 Path 常量，如 _CONTRACT/_STATIONS）
                          上的读（.read_text()）与 subprocess 引用
                          （[sys.executable, str(DOCTOR), ...]）。
  has_failure_path      存在可失败的断言通道 → 良：
                        - expect/raises 族异常助手调用（expect/_expect_raise/
                          _raises/pytest.raises…）；
                        - try-except（含 except 子句）；
                        - 断言助手（_ok/_ck 式：体内含条件 raise）且首参非
                          常量真值（条件可判假=负例通道）；
                        - 函数内内联条件 raise（if ...: raise ...）；
                        - 非常量真值的 assert（可判假的真实检查）。

合格函数 = trivial_asserts == 0 且 has_call_into_module 且 has_failure_path。
汇总每文件合格函数数，与冻结基线 tests/p1f-behavior-baseline.txt 比对：
合格数缩水、专属文件缺失、源码不可解析、基线缺项/格式非法 → exit 1（CI 红）。

用法：
  python3 system/tests/p1f_ast_gate.py --root <repo根> --baseline <基线文件> [--verbose]
  python3 system/tests/p1f_ast_gate.py --root <repo根> --emit-baseline
  python3 system/tests/p1f_ast_gate.py --root <repo根> --file test_ac_gate_family
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# 与 acceptance.sh P1f 节的 P1F_FILES 同源（F6-TRC-GATE-001 八专属文件）
P1F_FILES: List[str] = [
    "test_ac_gate_family",
    "test_ac_state_mig",
    "test_ac_deploy_release",
    "test_ac_station_families",
    "test_ac_ops_families",
    "test_ac_auth_cond",
    "test_ac_act_run",
    "test_ac_ui_family",
]

# importlib 动态装载产品码的标志调用名（装载器助手判定）
_LOADER_MARKS = {"spec_from_file_location", "module_from_spec", "exec_module"}

# expect/raises 族异常助手名（调用即失败通道）
_EXPECT_NAME_MARKS = ("expect", "raises")

# subprocess 家族方法名（启动子进程=可能驱动产品脚本）
_SUBPROCESS_FUNCS = {"run", "popen", "call", "check_call", "check_output"}

# 产品路径常量的排除字段（夹具路径不算被测面）
_NON_PRODUCT_SEGMENTS = {"tests", "test", "fixtures", "fixture", "__pycache__"}


# ---------------------------------------------------------------------------
# 基础判定
# ---------------------------------------------------------------------------
def _is_truthy_const(node: ast.expr) -> bool:
    """常量真值：ast.Constant 真值 / Name 'True'（恒真化断言的静态形态）。"""
    if isinstance(node, ast.Constant):
        try:
            return bool(node.value)
        except Exception:  # 无布尔语义的常量对象按非真值处理
            return False
    if isinstance(node, ast.Name) and node.id == "True":
        return True
    return False


def _call_func_name(call: ast.Call) -> Optional[str]:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _is_expect_like(name: Optional[str]) -> bool:
    if not name:
        return False
    return any(mark in name.lower() for mark in _EXPECT_NAME_MARKS)


def _is_subprocess_call(call: ast.Call) -> bool:
    f = call.func
    return isinstance(f, ast.Attribute) and f.attr.lower() in _SUBPROCESS_FUNCS


def _expr_mentions(node: ast.expr, names: Set[str]) -> bool:
    """表达式子树是否引用了 names 中任一名字。"""
    return any(
        isinstance(n, ast.Name) and n.id in names for n in ast.walk(node)
    )


# ---------------------------------------------------------------------------
# 文件级上下文（被测面收集）
# ---------------------------------------------------------------------------
class FileContext:
    def __init__(self, tree: ast.Module) -> None:
        self.tested_names: Set[str] = set()        # wenqu_core.* 导入名/别名
        self.product_paths: Set[str] = set()       # 产品路径常量名（模块级）
        self.loader_helpers: Set[str] = set()      # importlib 装载器助手
        self.assert_helpers: Set[str] = set()      # _ok/_ck 式断言助手
        self.product_helpers: Set[str] = set()     # 产品构造器/驱动器助手（函数）
        self.product_classes: Set[str] = set()     # 产品驱动器类
        self._collect(tree)

    # —— 收集 ——
    def _collect(self, tree: ast.Module) -> None:
        # 1) wenqu_core 被测面：模块级+函数级 import 全收（同名只可能来自被测面）
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and (
                node.module == "wenqu_core" or node.module.startswith("wenqu_core.")
            ):
                for alias in node.names:
                    self.tested_names.add(alias.asname or alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "wenqu_core" or alias.name.startswith("wenqu_core."):
                        self.tested_names.add(alias.asname or alias.name)
        # 2) 模块级产品路径常量：__file__ 派生链（fixpoint 追链），排除夹具字段
        self._collect_product_paths(tree)
        # 3) 模块级函数/类分类
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._touches_product(stmt):
                    self.product_helpers.add(stmt.name)
                body_nodes = ast.walk(stmt)
                if any(
                    isinstance(n, ast.Call) and _call_func_name(n) in _LOADER_MARKS
                    for n in body_nodes
                ):
                    self.loader_helpers.add(stmt.name)
                if self._has_conditional_raise(stmt):
                    self.assert_helpers.add(stmt.name)
            elif isinstance(stmt, ast.ClassDef):
                if any(
                    self._touches_product(sub) for sub in stmt.body
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))
                ):
                    self.product_classes.add(stmt.name)

    def _collect_product_paths(self, tree: ast.Module) -> None:
        """__file__ 派生的模块级 Path 常量（REPO/SYSTEM/DASH/_CONTRACT…）。

        fixpoint：常量值子树含 __file__ 或已判定常量名 → 产品路径常量；
        但链上出现 tests/fixtures 等夹具字段的除外（夹具不是被测面）。
        """
        for _ in range(8):  # 链深有限，几轮收敛
            grew = False
            for stmt in tree.body:
                if not isinstance(stmt, ast.Assign):
                    continue
                value = stmt.value
                if not _expr_mentions(value, self.product_paths) and not any(
                    isinstance(n, ast.Name) and n.id == "__file__"
                    for n in ast.walk(value)
                ):
                    continue
                if any(
                    isinstance(n, ast.Constant) and isinstance(n.value, str)
                    and n.value.strip("./").strip("/") in _NON_PRODUCT_SEGMENTS
                    for n in ast.walk(value)
                ):
                    continue  # 夹具路径：tests/fixtures 下不算被测面
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and t.id not in self.product_paths:
                        self.product_paths.add(t.id)
                        grew = True
            if not grew:
                break

    def _touches_product(self, fn: ast.FunctionDef) -> bool:
        """体内真实触碰产品码：wenqu_core 根调用/产品路径常量引用/装载器标志。

        注意：模块级分析环境为空（参数不预信任）——夹具助手（_git/_make_repo
        只碰参数与字面量）不会被判为产品面。
        """
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                fname = node.func.id if isinstance(node.func, ast.Name) else None
                if fname in self.tested_names:
                    return True
                if _call_func_name(node) in _LOADER_MARKS:
                    return True
                if _is_subprocess_call(node) and _expr_mentions(
                    node, self.product_paths
                ):
                    return True
            elif isinstance(node, ast.Name):
                if node.id in self.product_paths:
                    return True
        return False

    @staticmethod
    def _has_conditional_raise(fn: ast.FunctionDef) -> bool:
        """_ok/_ck 式助手：if <cond>: raise ...（断言助手=条件抛错）。"""
        for node in ast.walk(fn):
            if isinstance(node, ast.If):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Raise):
                        return True
        return False


# ---------------------------------------------------------------------------
# 函数级行为分析（按语句顺序做轻量信任数据流）
# ---------------------------------------------------------------------------
class FunctionMetrics:
    __slots__ = ("name", "trivial_asserts", "has_call", "has_failure")

    def __init__(self, name: str) -> None:
        self.name = name
        self.trivial_asserts = 0
        self.has_call = False
        self.has_failure = False

    @property
    def qualified(self) -> bool:
        return self.trivial_asserts == 0 and self.has_call and self.has_failure

    def hint(self) -> str:
        why = []
        if self.trivial_asserts:
            why.append(f"trivial_asserts={self.trivial_asserts}")
        if not self.has_call:
            why.append("无被测调用")
        if not self.has_failure:
            why.append("无失败路径")
        return ",".join(why) if why else "合格"


class _Env:
    """函数内轻量信任环境：产品对象局部名 + 产品路径局部名。"""

    __slots__ = ("trusted", "path_locals")

    def __init__(self, trusted: Set[str], path_locals: Set[str]) -> None:
        self.trusted = trusted      # 产品对象（可在其上调用/读属性/下标/迭代）
        self.path_locals = path_locals  # 产品路径派生局部（subprocess 引用算被测）

    def copy(self) -> "_Env":
        return _Env(set(self.trusted), set(self.path_locals))

    def merge(self, other: "_Env") -> None:
        self.trusted |= other.trusted
        self.path_locals |= other.path_locals


class FunctionAnalyzer:
    def __init__(self, ctx: FileContext) -> None:
        self.ctx = ctx

    # —— 信任根判定 ——
    def _trusted_root(self, node: ast.expr, env: _Env) -> bool:
        if isinstance(node, ast.Name):
            return (
                node.id in self.ctx.tested_names
                or node.id in self.ctx.product_paths
                or node.id in env.trusted
            )
        if isinstance(node, ast.Attribute):
            return self._trusted_root(node.value, env)
        if isinstance(node, ast.Subscript):  # f = rep.findings[0] 仍是被测产物
            return self._trusted_root(node.value, env)
        if isinstance(node, ast.Call):
            return self._trusted_root(node.func, env)
        if isinstance(node, ast.Await):
            return self._trusted_root(node.value, env)
        return False

    def _producing_helper_call(self, value: ast.expr) -> bool:
        """值是产品构造器/装载器/驱动器助手或产品类的调用 → 产物可信。"""
        if not isinstance(value, ast.Call):
            return False
        f = value.func
        if isinstance(f, ast.Name) and (
            f.id in self.ctx.loader_helpers
            or f.id in self.ctx.product_helpers
            or f.id in self.ctx.product_classes
        ):
            return True
        return False

    def _assign_trusted(self, value: ast.expr, env: _Env) -> bool:
        if self._trusted_root(value, env):
            return True
        return self._producing_helper_call(value)

    # —— 表达式扫描（ Calls 全子树） ——
    def _scan_expr(self, node: ast.expr, env: _Env, m: FunctionMetrics) -> None:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                self._check_call(sub, env, m)
            elif isinstance(sub, (ast.Attribute, ast.Subscript)):
                # 被测态读取信号：可信根上的属性读/下标（消费产品输出）
                if self._trusted_root(sub.value, env):
                    m.has_call = True
            elif isinstance(sub, ast.NamedExpr):  # walrus：(x := trusted())
                if isinstance(sub.target, ast.Name) and self._assign_trusted(
                    sub.value, env
                ):
                    env.trusted.add(sub.target.id)

    def _check_call(self, call: ast.Call, env: _Env, m: FunctionMetrics) -> None:
        # 指标二：被测面上的真实调用
        if self._trusted_root(call.func, env):
            m.has_call = True
        # 泛化腿：subprocess 启动产品路径（脚本/常量）= 驱动产品码
        if _is_subprocess_call(call) and _expr_mentions(
            call, self.ctx.product_paths | env.path_locals
        ):
            m.has_call = True
        # 指标三：失败通道（expect/raises 族 + 断言助手带可判假首参）
        fname = call.func.id if isinstance(call.func, ast.Name) else None
        if _is_expect_like(fname):
            m.has_failure = True
        if fname in self.ctx.assert_helpers:
            first = call.args[0] if call.args else None
            if first is not None and not _is_truthy_const(first):
                m.has_failure = True

    # —— 语句遍历（顺序数据流） ——
    def _visit_body(self, stmts: List[ast.stmt], env: _Env, m: FunctionMetrics) -> None:
        for st in stmts:
            self._visit_stmt(st, env, m)

    def _visit_stmt(self, st: ast.stmt, env: _Env, m: FunctionMetrics) -> None:
        if isinstance(st, ast.Assert):
            if _is_truthy_const(st.test):
                m.trivial_asserts += 1  # 常量真值断言——恒真化，计劣
            else:
                m.has_failure = True    # 可判假的真实检查=失败通道
            self._scan_expr(st.test, env, m)
            if st.msg is not None:
                self._scan_expr(st.msg, env, m)
            return
        if isinstance(st, ast.Assign):
            self._scan_expr(st.value, env, m)
            self._propagate_targets(st.targets, st.value, env)
            return
        if isinstance(st, ast.AnnAssign):
            if st.value is not None:
                self._scan_expr(st.value, env, m)
                if isinstance(st.target, ast.Name):
                    self._propagate_targets([st.target], st.value, env)
            return
        if isinstance(st, ast.AugAssign):
            self._scan_expr(st.value, env, m)
            return
        if isinstance(st, (ast.Expr, ast.Return, ast.Delete)):
            expr = getattr(st, "value", None)
            if expr is not None:
                self._scan_expr(expr, env, m)
            return
        if isinstance(st, ast.If):
            self._scan_expr(st.test, env, m)
            # 内联条件 raise：if <cond>: raise ...（失败通道）
            if any(isinstance(n, ast.Raise) for n in ast.walk(st)):
                m.has_failure = True
            env_body, env_else = env.copy(), env.copy()
            self._visit_body(st.body, env_body, m)
            self._visit_body(st.orelse, env_else, m)
            env.merge(env_body)
            env.merge(env_else)
            return
        if isinstance(st, ast.While):
            self._scan_expr(st.test, env, m)
            env_body = env.copy()
            self._visit_body(st.body, env_body, m)
            self._visit_body(st.orelse, env.copy(), m)
            env.merge(env_body)
            return
        if isinstance(st, (ast.For, ast.AsyncFor)):
            self._scan_expr(st.iter, env, m)
            env_body = env.copy()
            if self._trusted_root(st.iter, env):
                m.has_call = True  # 迭代被测对象=执行产品 __iter__
                self._add_targets(st.target, env_body.trusted)
            self._visit_body(st.body, env_body, m)
            self._visit_body(st.orelse, env.copy(), m)
            env.merge(env_body)
            return
        if isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                self._scan_expr(item.context_expr, env, m)
                if item.optional_vars is not None:
                    if self._assign_trusted(item.context_expr, env):
                        self._add_targets(item.optional_vars, env.trusted)
                    if _expr_mentions(
                        item.context_expr, self.ctx.product_paths | env.path_locals
                    ):
                        self._add_targets(item.optional_vars, env.path_locals)
            self._visit_body(st.body, env, m)
            return
        if isinstance(st, ast.Try):
            if st.handlers:  # except 子句存在=异常失败通道
                m.has_failure = True
            branches: List[_Env] = []
            for block in (st.body, st.orelse, st.finalbody):
                b = env.copy()
                self._visit_body(block, b, m)
                branches.append(b)
            for h in st.handlers:
                hb = env.copy()
                self._visit_body(h.body, hb, m)
                branches.append(hb)
            for b in branches:
                env.merge(b)
            return
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # 嵌套函数（回调/闭包）：以当前 env 副本分析，指标并入父函数
            self._visit_body(st.body, env.copy(), m)
            return
        if isinstance(st, ast.ClassDef):
            for d in st.decorator_list:
                self._scan_expr(d, env, m)
            self._visit_body(st.body, env.copy(), m)
            return
        if isinstance(st, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
                           ast.Pass, ast.Break, ast.Continue)):
            return
        if isinstance(st, ast.Raise):
            if st.exc is not None:
                self._scan_expr(st.exc, env, m)
            if st.cause is not None:
                self._scan_expr(st.cause, env, m)
            return
        # 其余罕见语句（match 等）：保守全子树扫 Calls，不做数据流
        for sub in ast.walk(st):
            if isinstance(sub, ast.Call):
                self._check_call(sub, env, m)
            elif isinstance(sub, ast.Assert):
                if _is_truthy_const(sub.test):
                    m.trivial_asserts += 1
                else:
                    m.has_failure = True
        return

    def _propagate_targets(self, targets: List[ast.expr], value: ast.expr,
                           env: _Env) -> None:
        if self._assign_trusted(value, env):
            for t in targets:
                self._add_targets(t, env.trusted)
        if _expr_mentions(value, self.ctx.product_paths | env.path_locals):
            for t in targets:
                self._add_targets(t, env.path_locals)

    def _add_targets(self, target: ast.expr, names: Set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for el in target.elts:
                self._add_targets(el, names)
        elif isinstance(target, ast.Starred):
            self._add_targets(target.value, names)


# ---------------------------------------------------------------------------
# 文件分析
# ---------------------------------------------------------------------------
def analyze_file(path: Path) -> Dict[str, Any]:
    """返回 {file, total, qualified, metrics[], error}。源码不可解析=error。"""
    result: Dict[str, Any] = {
        "file": path.stem, "total": 0, "qualified": 0, "metrics": [], "error": None,
    }
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, ValueError) as exc:
        result["error"] = f"源码不可读/不可解析: {exc}"
        return result
    ctx = FileContext(tree)
    analyzer = FunctionAnalyzer(ctx)
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith("test_"):
            m = FunctionMetrics(stmt.name)
            analyzer._visit_body(stmt.body, _Env(set(), set()), m)
            result["metrics"].append(m)
            result["total"] += 1
            if m.qualified:
                result["qualified"] += 1
    return result


# ---------------------------------------------------------------------------
# 基线
# ---------------------------------------------------------------------------
def parse_baseline(path: Path) -> Dict[str, int]:
    """解析基线：# 注释行跳过；<文件名> <合格数>；非法行/重复条目抛错。"""
    baseline: Dict[str, int] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or not parts[1].isdigit():
            raise ValueError(f"基线第 {lineno} 行格式非法: {raw!r}（应为 '<文件名> <合格数>'）")
        if parts[0] in baseline:
            raise ValueError(f"基线第 {lineno} 行重复条目: {parts[0]}")
        baseline[parts[0]] = int(parts[1])
    return baseline


def emit_baseline(root: Path) -> int:
    lines = [
        "# P1f2 AST 行为门基线（八轮 Codex P1f2 残余修复：文本 assert 计数可被",
        "# 「常量真值断言/删被测调用/删失败路径」绕过 → 主门升级为 AST 行为门）。",
        "# 合格函数 = 非常量真值断言 且 有被测模块交互 且 有失败路径。",
        "# 只允许增长，缩水即 CI 红。再生成：",
        "#   python3 system/tests/p1f_ast_gate.py --root <repo根> --emit-baseline",
        "#     > tests/p1f-behavior-baseline.txt（增长后须人工复核再冻结）",
    ]
    for name in P1F_FILES:
        r = analyze_file(root / "system" / "tests" / f"{name}.py")
        if r["error"]:
            print(f"!! {name}: {r['error']}", file=sys.stderr)
            return 2
        lines.append(f"{name} {r['qualified']}")
    print("\n".join(lines))
    return 0


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def run_gate(root: Path, baseline_path: Path, verbose: bool = False,
             single_file: Optional[str] = None) -> int:
    tests_dir = root / "system" / "tests"
    names = [single_file] if single_file else P1F_FILES
    baseline: Optional[Dict[str, int]] = None
    if not single_file:
        try:
            baseline = parse_baseline(baseline_path)
        except (OSError, ValueError) as exc:
            print(f"❌ 基线不可用（{baseline_path}）: {exc}")
            return 1

    fail = False
    rows: List[str] = []
    total_q = 0
    for name in names:
        path = tests_dir / f"{name}.py"
        r = analyze_file(path)
        if r["error"]:
            print(f"❌ {name}: {r['error']}")
            fail = True
            continue
        total_q += r["qualified"]
        bad = sum(1 for m in r["metrics"] if not m.qualified)
        rows.append(f"  {name}: 合格 {r['qualified']}/{r['total']}"
                    f"（未达标 {bad} 个）")
        if verbose or single_file:
            for m in r["metrics"]:
                flag = "✅" if m.qualified else "⚠️ "
                rows.append(f"    {flag} {m.name}: {m.hint()}")
        if baseline is not None:
            if name not in baseline:
                print(f"❌ {name}: 基线缺项——行为门未冻结该文件")
                fail = True
            elif r["qualified"] < baseline[name]:
                print(f"❌ {name}: 合格函数 {r['qualified']} < 基线 {baseline[name]}"
                      "（空壳化/恒真化/删被测调用/删失败路径）")
                fail = True
    if baseline is not None:
        extra = set(baseline) - set(P1F_FILES)
        if extra:
            print(f"❌ 基线含未知条目: {sorted(extra)}")
            fail = True

    if rows:
        print("\n".join(rows))
    if baseline is not None and not fail:
        print(f"✅ AST 行为门通过（八文件合格函数共 {total_q} ≥ 冻结基线）")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="P1f2 AST 行为门（八专属文件断言行为质量棘轮）")
    ap.add_argument("--root", required=True, help="repo 根目录（wenqu-dist）")
    ap.add_argument("--baseline", help="冻结基线 tests/p1f-behavior-baseline.txt")
    ap.add_argument("--emit-baseline", action="store_true", help="输出当前合格数基线（再冻结用）")
    ap.add_argument("--file", help="单文件调试（输出逐函数三指标）")
    ap.add_argument("--verbose", action="store_true", help="check 模式附逐函数明细")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"❌ --root 不存在: {root}")
        return 2
    if args.emit_baseline:
        return emit_baseline(root)
    if args.file:
        if args.file not in P1F_FILES:
            print(f"❌ --file 须为八专属文件之一: {P1F_FILES}")
            return 2
        return run_gate(root, root / "tests" / "p1f-behavior-baseline.txt",
                        verbose=True, single_file=args.file)
    if not args.baseline:
        print("❌ check 模式需要 --baseline（或改用 --emit-baseline）")
        return 2
    return run_gate(root, Path(args.baseline), verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())

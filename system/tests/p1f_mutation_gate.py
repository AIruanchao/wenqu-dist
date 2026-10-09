#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P1f2 mutation 门——G9-07（R8-TRC-TRUTHY-ASSERT-012 根修：AST 形态门→真 mutation gate）。

背景：八轮后的 AST 形态门（p1f_ast_gate.py）能抓「字面恒真/无被测调用/
无失败路径」三类字面空壳，但两类非字面绕过仍计入合格函数数：
  a) 非字面恒真：assert len(str(product_call())) >= 0——非常量、有调用、
     有失败路径形态，AST 三指标全绿，但断言永不可能失败；
  b) 与产品行为无数据流关系的等量假测试替换：_ok(1 + 1 == 2) 形假腿。
形态计数无法区分「断言可失败」与「断言确实对产品行为敏感」。

本工具把完成标准从「形态」换成「行为」：对产品函数做机械变异（三类：
返回值取反 negate_return / 比较符翻转 flip_compare / 删关键守卫行
drop_raise），逐 mutation 在沙箱副本树上运行其映射的专属测试文件——
每个 mutation 必须至少杀死一个测试（对应文件 exit != 0），mutation
score 必须 100%（于 tests/p1f-mutations.json 所选集）。空壳化/恒真化/
假测试替换的专属测试文件将杀不死任何 mutation → 本门 rc1。

与两道既有闸的关系（G9-07 定版：三道闸并存，棘轮只增不减）：
  第一道（主）：本 mutation gate——行为敏感度；
  第二道：tests/p1f-behavior-baseline.txt AST 形态基线（p1f_ast_gate.py）；
  第三道：tests/p1f-assert-baseline.txt 文本计数旧棘轮。

沙箱纪律：每 mutation 复制仓树到临时目录（忽略 .git/evidence/dist 等
重目录），AST 变异只写沙箱内副本，绝不动工作树；测试产物经
WENQU_EVIDENCE_OUT_DIR 重定向进沙箱临时目录。控制腿（未变异沙箱）先跑：
映射文件不全绿则本门 rc2（防「测试本来就红→假 kill」空转计分）。

用法：
  python3 system/tests/p1f_mutation_gate.py --root <repo根> \
      --mutations tests/p1f-mutations.json [--json OUT.json] [--verbose]
"""
from __future__ import annotations

import argparse
import ast
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# 与 acceptance.sh P1f 节 / p1f_ast_gate.py 的 P1F_FILES 同源（F6-TRC-GATE-001 八专属文件）
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

VALID_OPS = ("negate_return", "flip_compare", "drop_raise")

# 沙箱复制忽略（重目录/环境残留；测试面不需要它们）
_SANDBOX_IGNORE = shutil.ignore_patterns(
    ".git", "evidence", "dist", ".pytest_cache", "__pycache__",
    ".github", ".DS_Store", "._*", "*.pyc",
)

# 比较符翻转映射（机械、成对可逆）
_FLIP = {
    ast.Lt: ast.GtE, ast.GtE: ast.Lt,
    ast.Gt: ast.LtE, ast.LtE: ast.Gt,
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
    ast.In: ast.NotIn, ast.NotIn: ast.In,
    ast.Is: ast.IsNot, ast.IsNot: ast.Is,
}


class MutationSpecError(RuntimeError):
    """mutation 集结构/定位失败（集本身损坏——rc2，与 kill 失败区分）。"""


# ---------------------------------------------------------------------------
# AST 机械变异
# ---------------------------------------------------------------------------
class _OpCounter(ast.NodeVisitor):
    """统计目标函数体内各 op 的可作用点数（0=mutation 无法落地）。"""

    def __init__(self) -> None:
        self.returns_with_value = 0
        self.flippable_compares = 0
        self.raises = 0

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.returns_with_value += 1

    def visit_Compare(self, node: ast.Compare) -> None:
        if node.ops and all(type(op) in _FLIP for op in node.ops):
            self.flippable_compares += 1

    def visit_Raise(self, node: ast.Raise) -> None:
        self.raises += 1


class _NegateReturn(ast.NodeTransformer):
    """return V → return not (V)——返回值取反（布尔语义翻转）。"""

    def visit_Return(self, node: ast.Return) -> ast.Return:
        if node.value is None:
            return node
        return ast.copy_location(
            ast.Return(value=ast.UnaryOp(op=ast.Not(), operand=copy.deepcopy(node.value))),
            node)


class _FlipCompare(ast.NodeTransformer):
    """比较符翻转：<↔>=、>↔<=、==↔!=、in↔not in、is↔is not。"""

    def visit_Compare(self, node: ast.Compare) -> ast.Compare:
        new_ops = [_FLIP[type(op)]() for op in node.ops]
        return ast.copy_location(
            ast.Compare(left=node.left, ops=new_ops, comparators=node.comparators),
            node)


class _DropRaise(ast.NodeTransformer):
    """删除函数体内第一个 Raise 语句（关键守卫行删除；后续 raise 保留）。"""

    def __init__(self) -> None:
        self.dropped = False

    def visit_Raise(self, node: ast.Raise) -> ast.stmt:
        if not self.dropped:
            self.dropped = True
            return ast.copy_location(ast.Pass(), node)
        return node


def _make_scoped(function: str, inner: ast.NodeTransformer) -> ast.NodeTransformer:
    """构造只作用于同名函数体的变换器（其余源码不动）。"""

    class _Scoped(ast.NodeTransformer):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
            self.generic_visit(node)  # 先递归（嵌套/方法同名同治）
            if node.name == function:
                return ast.copy_location(inner.visit(node), node)
            return node

    return _Scoped()


def apply_mutation(src: str, module_path: str, function: str,
                   op: str) -> Tuple[str, int]:
    """对 module 源码中指定函数应用机械变异，返回 (变异后源码, 作用点数)。

    函数不存在 / op 无处落地 / 变异后源码无变化 → MutationSpecError。
    """
    try:
        tree = ast.parse(src, filename=module_path)
    except SyntaxError as exc:
        raise MutationSpecError(f"{module_path}: 源码不可解析: {exc}") from exc

    counter = _OpCounter()
    matched = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function:
            matched += 1
            counter.visit(node)
    if matched == 0:
        raise MutationSpecError(
            f"{module_path}: 未找到目标函数 {function!r}——mutation 集与产品码脱锚")
    points = {
        "negate_return": counter.returns_with_value,
        "flip_compare": counter.flippable_compares,
        "drop_raise": counter.raises,
    }[op]
    if points == 0:
        raise MutationSpecError(
            f"{module_path}#{function}: op={op} 无处落地（产品码已变？mutation 集需同步）")

    inner = {"negate_return": _NegateReturn, "flip_compare": _FlipCompare,
             "drop_raise": _DropRaise}[op]()
    scoped = _make_scoped(function, inner)
    baseline_unparsed = ast.unparse(tree)  # 先快照（NodeTransformer 原地改树）
    mutated = ast.fix_missing_locations(scoped.visit(tree))
    out = ast.unparse(mutated)
    if out == baseline_unparsed:
        raise MutationSpecError(
            f"{module_path}#{function}: op={op} 变异后源码无变化（无效 mutation）")
    return out, points


# ---------------------------------------------------------------------------
# mutation 集装载与校验
# ---------------------------------------------------------------------------
def load_mutations(path: Path) -> List[Dict[str, Any]]:
    """装载并结构校验 mutation 集（tests/p1f-mutations.json）。"""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MutationSpecError(f"mutation 集不可读: {path}: {exc}") from exc
    if not isinstance(raw, dict) or "mutations" not in raw:
        raise MutationSpecError("mutation 集顶层须为 {schema_version, mutations:[...]}")
    seen_ids: set = set()
    seen_killer: Dict[str, set] = {name: set() for name in P1F_FILES}
    for i, m in enumerate(raw["mutations"]):
        for field in ("id", "module", "function", "op", "test_files", "description"):
            if field not in m or not m[field]:
                raise MutationSpecError(f"mutation[{i}] 缺必填字段 {field!r}")
        if m["id"] in seen_ids:
            raise MutationSpecError(f"mutation id 重复: {m['id']}")
        seen_ids.add(m["id"])
        if m["op"] not in VALID_OPS:
            raise MutationSpecError(f"{m['id']}: 未知 op {m['op']!r}（合法: {VALID_OPS}）")
        if not m["module"].startswith("wenqu_core/") or not m["module"].endswith(".py"):
            raise MutationSpecError(f"{m['id']}: module 须为 wenqu_core/*.py 相对路径")
        mod_name = m["module"][len("wenqu_core/"):]
        if "/" in mod_name or not mod_name[:-3].isidentifier():
            raise MutationSpecError(f"{m['id']}: module 不支持子目录/非法名: {m['module']}")
        files = m["test_files"]
        if not isinstance(files, list) or not files:
            raise MutationSpecError(f"{m['id']}: test_files 须为非空数组")
        for tf in files:
            if tf not in P1F_FILES:
                raise MutationSpecError(f"{m['id']}: test_files 含未知专属文件 {tf!r}")
            seen_killer[tf].add(m["id"])
    # 覆盖门：每个专属文件至少杀一个 mutation（防某文件完全脱离行为锚）
    uncovered = [tf for tf, ids in seen_killer.items() if not ids]
    if uncovered:
        raise MutationSpecError(f"mutation 集未覆盖专属文件: {uncovered}")
    return raw["mutations"]


# ---------------------------------------------------------------------------
# 沙箱执行
# ---------------------------------------------------------------------------
def _run_test_file(sandbox: Path, test_file: str,
                   artifacts_dir: Path) -> Tuple[int, float]:
    """在沙箱根运行一个专属测试文件，返回 (exit_code, 秒)。"""
    env = dict(os.environ)
    env["WENQU_EVIDENCE_OUT_DIR"] = str(artifacts_dir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(sandbox / "system" / "tests" / f"{test_file}.py")],
        cwd=str(sandbox), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=900,
    )
    return proc.returncode, time.monotonic() - started


def run_gate(root: Path, mutations_path: Path, json_out: Optional[Path],
             verbose: bool = False) -> int:
    mutations = load_mutations(mutations_path)
    needed_files = sorted({tf for m in mutations for tf in m["test_files"]})

    rows: List[Dict[str, Any]] = []
    killed = 0
    vacuous: List[str] = []
    t0 = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="p1f-mutation-gate-") as tmp:
        tmpd = Path(tmp)
        # —— 控制腿：未变异沙箱上全部映射文件必须绿（防假 kill 空转计分）——
        control = _sandbox_copy(root, tmpd / "control")
        control_art = tmpd / "control-artifacts"
        control_rc: Dict[str, int] = {}
        for tf in needed_files:
            rc, _dt = _run_test_file(control, tf, control_art)
            control_rc[tf] = rc
            if rc != 0:
                vacuous.append(tf)
        if vacuous:
            print("❌ 控制腿失败（未变异沙箱即红，kill 不可信——防空转计分）:")
            for tf in vacuous:
                print(f"   {tf}: exit={control_rc[tf]}")
            shutil.rmtree(control, ignore_errors=True)
            return 2
        shutil.rmtree(control, ignore_errors=True)

        # —— 变异腿：逐 mutation 沙箱执行 ——
        for idx, m in enumerate(mutations, 1):
            module_rel = m["module"]  # wenqu_core/xxx.py
            sandbox = _sandbox_copy(root, tmpd / f"mut-{idx:02d}")
            target = sandbox / "system" / module_rel
            try:
                src = target.read_text(encoding="utf-8")
                mutated, points = apply_mutation(src, str(target), m["function"], m["op"])
                target.write_text(mutated + "\n", encoding="utf-8")
            except MutationSpecError as exc:
                print(f"❌ {m['id']}: mutation 集失效——{exc}")
                shutil.rmtree(sandbox, ignore_errors=True)
                return 2
            kill_rc: Optional[int] = None
            killer: Optional[str] = None
            for tf in m["test_files"]:
                rc, _dt = _run_test_file(sandbox, tf, tmpd / f"art-{idx:02d}")
                if rc != 0:
                    kill_rc, killer = rc, tf
                    break  # 至少一个转红即杀死
            is_killed = kill_rc is not None
            killed += 1 if is_killed else 0
            rows.append({
                "id": m["id"], "module": module_rel, "function": m["function"],
                "op": m["op"], "points": points,
                "killed": is_killed, "killer": killer,
                "kill_rc": kill_rc, "test_files": m["test_files"],
            })
            mark = "✅ KILLED" if is_killed else "❌ SURVIVED"
            line = (f"  [{idx}/{len(mutations)}] {mark} {m['id']} "
                    f"{module_rel}#{m['function']} op={m['op']}"
                    + (f" killer={killer}(exit={kill_rc})" if is_killed else ""))
            print(line)
            if verbose:
                print(f"      {m['description']}")
            shutil.rmtree(sandbox, ignore_errors=True)

    total = len(mutations)
    score = (100.0 * killed / total) if total else 0.0
    elapsed = time.monotonic() - t0
    print("-" * 72)
    print(f"mutation score: {killed}/{total} = {score:.1f}%（{elapsed:.1f}s，沙箱全临时）")
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps({
            "tool": "p1f_mutation_gate", "killed": killed, "total": total,
            "score": round(score, 2), "control_green": {tf: 0 for tf in needed_files},
            "rows": rows,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"报告已写: {json_out}")
    if killed != total:
        survivors = [r["id"] for r in rows if not r["killed"]]
        print(f"❌ mutation gate 失败——存活 {len(survivors)}: {survivors}")
        print("   （专属测试空壳化/恒真化/假测试替换会杀不死 mutation——行为覆盖被掏空）")
        return 1
    print("✅ mutation gate 通过（所选集 mutation score 100%，每个变异至少杀一个专属测试）")
    return 0


def _sandbox_copy(root: Path, dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(root, dest, ignore=_SANDBOX_IGNORE, symlinks=False)
    return dest


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="P1f2 mutation 门（八专属文件行为敏感度棘轮）")
    ap.add_argument("--root", required=True, help="repo 根目录（wenqu-dist）")
    ap.add_argument("--mutations", required=True, help="mutation 集文件（tests/p1f-mutations.json）")
    ap.add_argument("--json", help="结构化报告输出路径（临时目录，勿指向 tracked evidence）")
    ap.add_argument("--verbose", action="store_true", help="附 mutation 描述")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"❌ --root 不存在: {root}")
        return 2
    try:
        return run_gate(root, Path(args.mutations), Path(args.json) if args.json else None,
                        verbose=args.verbose)
    except MutationSpecError as exc:
        print(f"❌ mutation 集失效: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())

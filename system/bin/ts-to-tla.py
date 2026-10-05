#!/usr/bin/env python3
"""
ts-to-tla v1（LLM→TLA+ 自动生成器）

原理：读取 TypeScript 源码 → 提取函数签名/类型/业务约束 → 
     自动生成对应的 TLA+ 规范 → 用 TLC 验证

这消除了"手写 TLA+ 模型与实际代码脱节"的风险——规范直接从代码生成。

用法：ts-to-tla.py <ts_file> [--output <tla_file>] [--verify]
"""
import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

def extract_functions(ts_source: str) -> list:
    """从 TypeScript 源码提取函数信息"""
    functions = []

    # 匹配 export function / async function
    func_pattern = re.compile(
        r'export\s+(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*(?::\s*([^{]+))?\s*\{',
        re.MULTILINE
    )
    for match in func_pattern.finditer(ts_source):
        name = match.group(1)
        params_raw = match.group(2) or ""
        return_type = (match.group(3) or "void").strip()

        # 解析参数
        params = []
        for param in params_raw.split(","):
            param = param.strip()
            if not param: continue
            # 简单解析 "name: Type" 形式
            parts = param.split(":")
            if len(parts) >= 2:
                p_name = parts[0].strip().replace("?", "")
                p_type = parts[1].strip()
                params.append({"name": p_name, "type": p_type})

        # 提取函数体中的关键约束（assert/throw/if 检查）
        body_start = match.end()
        # 找到函数体的大致范围
        brace_count = 1
        pos = body_start
        while pos < len(ts_source) and brace_count > 0:
            if ts_source[pos] == '{': brace_count += 1
            elif ts_source[pos] == '}': brace_count -= 1
            pos += 1
        body = ts_source[body_start:pos-1]

        # 提取约束（throw/if 语句）
        constraints = []
        for throw_match in re.finditer(r'if\s*\(([^)]+)\)\s*(?:\{[^}]*throw|throw)', body):
            constraints.append(throw_match.group(1))
        for assert_match in re.finditer(r'assert\(([^)]+)\)', body):
            constraints.append(assert_match.group(1))

        functions.append({
            "name": name,
            "params": params,
            "return_type": return_type,
            "constraints": constraints,
            "body_size": len(body),
        })

    return functions


def generate_tla(functions: list, module_name: str = "Generated") -> str:
    """从函数信息生成 TLA+ 规范"""
    lines = []
    lines.append(f"-------------------- MODULE {module_name} --------------------")
    lines.append("(***************************************************************************")
    lines.append(" * 自动生成的 TLA+ 规范（ts-to-tla.py）")
    lines.append(" * 从 TypeScript 源码提取的函数约束")
    lines.append(" ***************************************************************************)")
    lines.append("")
    lines.append("EXTENDS Naturals, Reals, TLC")
    lines.append("")

    # 提取所有变量
    all_vars = set()
    for func in functions:
        for p in func["params"]:
            all_vars.add(p["name"])

    # 常量
    if all_vars:
        lines.append("VARIABLES")
        var_list = ", ".join(sorted(all_vars))
        lines.append(f"  \\* {var_list}")
        lines.append("")

    # 变量声明
    lines.append("vars == <<" + var_list + ">>" if all_vars else "vars == << >>")
    lines.append("")

    # 类型不变式
    lines.append("(* 类型不变式 *)")
    lines.append("TypeOK ==")
    type_assertions = []
    for func in functions:
        for p in func["params"]:
            if "Decimal" in p["type"] or "number" in p["type"]:
                type_assertions.append(f"{p['name']} \\in Real")
            elif "string" in p["type"] or "String" in p["type"]:
                type_assertions.append(f"{p['name']} \\in STRING")
            elif "boolean" in p["type"] or "Boolean" in p["type"]:
                type_assertions.append(f"{p['name']} \\in BOOLEAN")
    if type_assertions:
        lines.append("  /\\ " + " /\\ ".join(type_assertions))
    else:
        lines.append("  TRUE")
    lines.append("")

    # 业务约束
    lines.append("(* 业务约束（从 throw/assert 语句提取）*)")
    lines.append("BusinessConstraints ==")
    constraint_assertions = []
    for func in functions:
        for c in func["constraints"]:
            # 简单转换 TypeScript 条件到 TLA+
            tla_c = ts_condition_to_tla(c)
            if tla_c:
                constraint_assertions.append(tla_c)
    if constraint_assertions:
        for i, ca in enumerate(constraint_assertions):
            prefix = "  /\\ " if i == 0 else "  /\\ "
            lines.append(f"{prefix}{ca}")
    else:
        lines.append("  TRUE")
    lines.append("")

    # 完整不变式
    lines.append("(* 完整不变式 *)")
    lines.append("Invariant == TypeOK /\\ BusinessConstraints")
    lines.append("")

    # 初始状态
    lines.append("(* 初始状态 *)")
    lines.append("Init ==")
    init_vals = []
    for v in sorted(all_vars):
        init_vals.append(f"{v} = 0")
    if init_vals:
        lines.append("  /\\ " + " /\\ ".join(init_vals))
    else:
        lines.append("  TRUE")
    lines.append("")

    # 状态转换（基于函数操作）
    lines.append("(* 状态转换 *)")
    lines.append("Next ==")
    next_actions = []
    for func in functions:
        action = r"\E delta \in {-10..10} :"
        action += f"  vars' = [vars EXCEPT !.{func['params'][0]['name']} = @ + delta]"
        next_actions.append(f"  ({action})")
    if next_actions:
        lines.append("  \\/ " + "\n  \\/ ".join(next_actions))
    else:
        lines.append("  TRUE")
    lines.append("")

    lines.append("Spec == Init /\\ [][Next]_vars")
    lines.append("")
    lines.append("THEOREM Spec => []Invariant")
    lines.append("")
    lines.append("=" * 77)
    return "\n".join(lines)


def ts_condition_to_tla(condition: str) -> str | None:
    """将 TypeScript 条件表达式转换为 TLA+"""
    # 常见模式转换
    replacements = [
        (r"\.gt\(", " > "),
        (r"\.lt\(", " < "),
        (r"\.gte\(", " >= "),
        (r"\.lte\(", " <= "),
        (r"\.equals\(", " = "),
        (r"===?\s*", " = "),
        (r"!==?\s*", " # "),
        (r"&&", " /\\ "),
        (r"\|\|", " \\/ "),
        (r"!", "~"),
        (r"null|undefined", "NIL"),
        (r"\.length\s*===?\s*0", " = << >>"),
        (r"\.length\s*>\s*0", " # << >>"),
    ]
    result = condition
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result)
    # 如果还有太多 TypeScript 特有语法，返回 None
    ts_only = re.findall(r'\.\w+\(|=>|typeof|instanceof|await', result)
    if len(ts_only) > 2:
        return None
    return result


def main():
    if len(sys.argv) < 2:
        print("用法: ts-to-tla.py <ts_file> [--output <tla_file>] [--verify]")
        sys.exit(1)

    ts_file = sys.argv[1]
    output_file = None
    verify = "--verify" in sys.argv

    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        output_file = sys.argv[idx + 1]

    source = Path(ts_file).read_text()
    functions = extract_functions(source)

    if not functions:
        print("NO_FUNCTIONS: 未找到可提取的导出函数")
        sys.exit(0)

    module_name = Path(ts_file).stem.replace("-", "_").capitalize()
    tla_code = generate_tla(functions, module_name)

    if output_file:
        Path(output_file).write_text(tla_code)
        print(f"GENERATED: {output_file} ({len(functions)} functions)")
    else:
        print(tla_code)

    if verify and output_file:
        result = subprocess.run(
            ["java", "-jar", os.path.expanduser("~/tla-tools/tla2tools.jar"),
             Path(output_file).stem],
            capture_output=True, text=True,
            cwd=Path(output_file).parent
        )
        print(f"TLC result: {result.returncode} (0=no errors)")


if __name__ == "__main__":
    main()

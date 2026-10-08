#!/usr/bin/env python3
"""提取指定 §20 专属测试函数的完整源码，供逐 ID 人工语义审计。"""
import ast
import json
from pathlib import Path

ROOT = Path.cwd()
SELECT = [
    "GATE-09", "GATE-10", "GATE-11", "CI-06",
    "STATE-02", "STATE-05", "STATE-09", "STATE-11",
    "DEP-01", "DEP-02", "DEP-04", "DEP-06", "DEP-08", "DEP-09",
    "SC-03", "SC-05", "TEN-04", "PERF-03", "PERF-04",
    "CAP-01", "BAK-01", "DR-01",
    "UI-01", "UI-03", "UI-04", "UI-06", "UI-07",
]
targets = {x.replace("-", "_"): x for x in SELECT}
found = {}
for path in sorted((ROOT / "system" / "tests").glob("test_ac_*.py")):
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    lines = text.splitlines()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for key, tid in targets.items():
            if node.name.startswith("test_" + key + "_"):
                src = "\n".join(lines[node.lineno - 1: node.end_lineno])
                found[tid] = {
                    "id": tid,
                    "file": str(path.relative_to(ROOT)),
                    "function": node.name,
                    "line_start": node.lineno,
                    "line_end": node.end_lineno,
                    "docstring": ast.get_docstring(node) or "",
                    "source": src,
                }

missing = sorted(set(SELECT) - set(found))
assert not missing, missing
print(json.dumps({"selected": SELECT, "count": len(found), "tests": found},
                 ensure_ascii=False, indent=2))

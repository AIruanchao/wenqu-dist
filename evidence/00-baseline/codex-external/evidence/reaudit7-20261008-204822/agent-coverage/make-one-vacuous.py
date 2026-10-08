#!/usr/bin/env python3
"""Isolated mutation helper: replace one test function body with assert True."""
import ast, pathlib, sys
p=pathlib.Path(sys.argv[1]); target=sys.argv[2]
s=p.read_text(encoding='utf-8'); tree=ast.parse(s)
node=next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==target)
# Preserve function signature/decorators; replace body from first stmt through function end.
lines=s.splitlines(keepends=True)
start=node.body[0].lineno-1; end=node.end_lineno
indent=' '*(node.col_offset+4)
replacement=[indent+'"""第七轮隔离对抗：专属 ID 名称保留，但真实断言全部删除。"""\n',indent+'assert True\n']
lines[start:end]=replacement
p.write_text(''.join(lines),encoding='utf-8')
print(f'mutated={p} function={target} old_body_lines={end-start} new_assertions=1(vacuous)')

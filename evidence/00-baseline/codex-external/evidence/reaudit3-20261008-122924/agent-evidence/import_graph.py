import ast, pathlib
for p in pathlib.Path('.').rglob('*.py'):
    if '.git' in p.parts or 'evidence' in p.parts:
        continue
    try:
        t=ast.parse(p.read_text(errors='ignore'))
    except Exception:
        continue
    for n in ast.walk(t):
        if isinstance(n,(ast.Import,ast.ImportFrom)):
            s=ast.unparse(n)
            if 'gate_aggregator' in s or 'GateAggregator' in s:
                print(f'{p}:{getattr(n,"lineno",0)}:{s}')

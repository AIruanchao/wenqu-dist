import ast,re,json
from pathlib import Path
root=Path('/Users/maccc/Documents/wenqu-dist')
selected={
'system/tests/test_ac_gate_family.py':['GATE-01','MRG-03','CI-09'],
'system/tests/test_ac_auth_cond.py':['AUTH-04','COND-03','STOP-02'],
'system/tests/test_ac_act_run.py':['ACT-01','ACT-04','RUN-02'],
'system/tests/test_ac_state_mig.py':['STATE-03','MIG-04'],
'system/tests/test_ac_station_families.py':['DB-02','TEN-06','PERF-01','STA-01'],
'system/tests/test_ac_ops_families.py':['SCH-04','ALT-02','DOC-03'],
'system/tests/test_ac_deploy_release.py':['REL-02','DEP-03','RB-01'],
}
matrix=json.loads((root/'evidence/traceability-matrix.json').read_text())['matrix']
for rel,ids in selected.items():
 p=root/rel; src=p.read_text(); lines=src.splitlines(); tree=ast.parse(src)
 funcs={n.name:n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
 print('\n'+'='*100); print(rel)
 for tid in ids:
  e=matrix[tid]; fn=e['test_function']; n=funcs.get(fn)
  print('\n'+'-'*100)
  print(f"ID={tid} plan_injection={e['injection']!r} plan_expectation={e['expectation']!r}")
  print(f"matrix_fn={fn} line={e.get('line')} ast={n.lineno if n else None}-{n.end_lineno if n else None}")
  if n:
   for i in range(n.lineno,n.end_lineno+1): print(f'{i:5}: {lines[i-1]}')

#!/usr/bin/env python3
import ast,json,re,sys
from pathlib import Path
root=Path(sys.argv[1])
readme=(root/'README.md').read_text()
acc=(root/'tests/acceptance.sh').read_text()
src=(root/'system/tests/test_ac_ops_families.py').read_text()
claim=int(re.search(r'(\d+)\s*项验收',readme).group(1))
workflow_claim=int(re.search(r'双矩阵×release-check\+(\d+)\s*项',readme).group(1))
ck=[l for l in acc.splitlines() if re.search(r'(^|;)\s*ck\s+"',l) and not l.strip().startswith('#')]
inc=[l for l in acc.splitlines() if 'PASS_N=$((PASS_N+1))' in l and not l.strip().startswith('#')]
units=len(ck)+len(inc)
tree=ast.parse(src)
fn=next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=='test_DOC_02_bug_skill_version_manifest_and_count_drift_blocks_ci')
# Collect asserts whose source segment references `real` (the actual-repo result).
real_asserts=[]
for n in ast.walk(fn):
    if isinstance(n,ast.Assert):
        seg=ast.get_source_segment(src,n) or ''
        if re.search(r'\breal\b',seg): real_asserts.append(seg)
real_print_branch=('if real["blocked"]:' in ast.get_source_segment(src,fn) and 'print(' in ast.get_source_segment(src,fn))
result={
 'probe':'real documentation drift nonblocking assertion probe',
 'readme_acceptance_claim':claim,
 'readme_ci_claim':workflow_claim,
 'machine_acceptance_units':units,
 'ck_units':len(ck),'inline_units':len(inc),
 'real_drift': claim!=units or workflow_claim!=units,
 'assertions_binding_real_result':real_asserts,
 'real_drift_only_printed':real_print_branch,
 'script_runtime_rc_from_independent_log':0,
 'script_runtime_result':'PASS=18 FAIL=0; emitted DOC-02 observation that §20 should block',
}
reproduced=result['real_drift'] and not real_asserts and real_print_branch
result['probe_assertion_verdict']='PASS' if reproduced else 'FAIL'
result['system_verdict']='FAIL' if reproduced else 'NOT_REPRODUCED'
print(json.dumps(result,ensure_ascii=False,indent=2))
sys.exit(0 if reproduced else 1)

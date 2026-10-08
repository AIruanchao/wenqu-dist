#!/usr/bin/env python3
from pathlib import Path
import subprocess, json, hashlib, sys, shutil
iso=Path(sys.argv[1]); outroot=Path(sys.argv[2]); outroot.mkdir(parents=True,exist_ok=True)
orig=(iso/'evidence/00-baseline/codex-external/方案.md').read_text(encoding='utf-8')
row='| GATE-01 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |'
range_row='| GATE-01～12 | REQ-EVID-001 / AC-EVID-FAIL-CLOSED | W2/W3A/W3B | raw rc、CAS、before/after |'
assert orig.count(row)==1, orig.count(row)
assert orig.count(range_row)==1, orig.count(range_row)

def rep(old,new):
    assert orig.count(old)==1,(old,orig.count(old))
    return orig.replace(old,new,1)
cases={
 '00-baseline': orig,
 '01-id-text': rep(row,'| GATE-99 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |'),
 '02-injection-text': rep(row,'| GATE-01 | base ref 不存在/fetch 成功 | ERROR/BLOCKED |'),
 '03-expectation-text': rep(row,'| GATE-01 | base ref 不存在/fetch 失败 | PASS |'),
 '04-zero-width-unicode': rep(row,'| GATE-01 | base ref 不存在/fetch 失败 | ERROR/\u200bBLOCKED |'),
 '05-unicode-homoglyph': rep('| AUTH-04 | canonical payload/Unicode/audience 任一字节改变 | 验签失败 |',
                                  '| AUTH-04 | canonical payload/Unicοde/audience 任一字节改变 | 验签失败 |'),
 '06-whitespace-inside-token': rep(row,'| GATE-01 | base ref 不存在/fetch 失败 | ERROR / BLOCKED |'),
 '07-benign-format-control': rep(row,'|   GATE-01   |   `base ref 不存在/fetch 失败`   |   `ERROR/BLOCKED`   |'),
 '08-columns-swapped': rep(row,'| GATE-01 | ERROR/BLOCKED | base ref 不存在/fetch 失败 |'),
 '09-extra-table-column': rep(row,'| GATE-01 | base ref 不存在/fetch 失败 | EXTRA | ERROR/BLOCKED |'),
 '10-range-endpoint': rep(range_row,'| GATE-01～11 | REQ-EVID-001 / AC-EVID-FAIL-CLOSED | W2/W3A/W3B | raw rc、CAS、before/after |'),
 '11-251-req-meta': rep(range_row,'| GATE-01～12 | REQ-EVID-999 / AC-EVID-FAIL-CLOSED | W2/W3A/W3B | raw rc、CAS、before/after |'),
 '12-251-columns-swapped': rep(range_row,'| GATE-01～12 | REQ-EVID-001 / AC-EVID-FAIL-CLOSED | raw rc、CAS、before/after | W2/W3A/W3B |'),
 '13-row-format-id-narrative': rep(row,'GATE-01 — base ref 不存在/fetch 失败 — ERROR/BLOCKED'),
 '14-duplicate-exact-row': rep(row,row+'\n'+row),
 '15-duplicate-poison-first': rep(row,'| GATE-01 | POISON-INJECTION | POISON-EXPECTATION |\n'+row),
 '16-fullwidth-id-digits': rep(row,'| GATE-０１ | base ref 不存在/fetch 失败 | ERROR/BLOCKED |'),
 '17-frozen-sha-drift-outside': orig+'\n<!-- harmless but frozen SHA drift -->\n',
}
summary=[]
for name,text in cases.items():
    p=outroot/f'{name}.md'; p.write_text(text,encoding='utf-8')
    jp=outroot/f'{name}.json'; lp=outroot/f'{name}.log'
    cmd=[sys.executable,str(iso/'tools/ac_traceability.py'),'--check','--plan',str(p),'--json',str(jp)]
    cp=subprocess.run(cmd,cwd=iso,text=True,capture_output=True,env={**__import__('os').environ,'PYTHONDONTWRITEBYTECODE':'1'})
    lp.write_text('$ '+' '.join(cmd)+'\n'+cp.stdout+'\n--- STDERR ---\n'+cp.stderr+f'\nexit_code={cp.returncode}\n',encoding='utf-8')
    report=json.loads(jp.read_text())
    pc=report['meta'].get('plan_cross_check')
    summary.append({
      'case':name,'rc':cp.returncode,'plan_sha256':hashlib.sha256(text.encode()).hexdigest(),
      'catalog_integrity_field':report['meta'].get('catalog_integrity'),
      'catalog_problem_count':len(report['meta'].get('catalog_problems') or []),
      'plan_ok':None if pc is None else pc.get('ok'),
      'semantic_ok':None if pc is None else pc.get('semantic_ok'),
      'semantic_rows_parsed':None if pc is None else pc.get('semantic_rows_parsed'),
      'plan_only':None if pc is None else pc.get('plan_only'),
      'frozen_only':None if pc is None else pc.get('frozen_only'),
      'problems':report['meta'].get('catalog_problems'),
    })
# nonexistent plan case
name='18-nonexistent-plan'
p=outroot/'DOES-NOT-EXIST.md'; jp=outroot/f'{name}.json'; lp=outroot/f'{name}.log'
cmd=[sys.executable,str(iso/'tools/ac_traceability.py'),'--check','--plan',str(p),'--json',str(jp)]
cp=subprocess.run(cmd,cwd=iso,text=True,capture_output=True,env={**__import__('os').environ,'PYTHONDONTWRITEBYTECODE':'1'})
lp.write_text('$ '+' '.join(cmd)+'\n'+cp.stdout+'\n--- STDERR ---\n'+cp.stderr+f'\nexit_code={cp.returncode}\n',encoding='utf-8')
report=json.loads(jp.read_text())
summary.append({'case':name,'rc':cp.returncode,'plan_sha256':None,
 'catalog_integrity_field':report['meta'].get('catalog_integrity'),
 'catalog_problem_count':len(report['meta'].get('catalog_problems') or []),
 'plan_ok':None,'semantic_ok':None,'semantic_rows_parsed':None,
 'plan_only':None,'frozen_only':None,'problems':report['meta'].get('catalog_problems')})
(outroot/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
with (outroot/'summary.tsv').open('w',encoding='utf-8') as f:
 f.write('case\trc\tcatalog_field\tproblem_count\tplan_ok\tsemantic_ok\trows\tsha\n')
 for x in summary:
  f.write(f"{x['case']}\t{x['rc']}\t{x['catalog_integrity_field']}\t{x['catalog_problem_count']}\t{x['plan_ok']}\t{x['semantic_ok']}\t{x['semantic_rows_parsed']}\t{x['plan_sha256']}\n")
print((outroot/'summary.tsv').read_text())

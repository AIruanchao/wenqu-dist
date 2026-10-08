#!/usr/bin/env python3
import json,re,sys,hashlib
from pathlib import Path
plan=Path('/private/tmp/codex-test/方案.md')
out=Path('/private/tmp/codex-test/evidence/reaudit3-20261008-122924/agent-evidence/traceability-live.json')
text=plan.read_text(encoding='utf-8')
sha=hashlib.sha256(plan.read_bytes()).hexdigest()
sec20=text[text.index('# 20.'):text.index('# 21.')]
sec251=text[text.index('## 25.1'):text.index('# 26.')]
ids20=set(re.findall(r'\b([A-Z]{2,5}-\d{2})\b',sec20))
rows=[]; ids251=set(); meta={}
for line in sec251.splitlines():
    if not line.startswith('|') or '测试 ID 范围' in line or re.match(r'^\|[-: ]+\|',line): continue
    cells=[c.strip() for c in line.strip().strip('|').split('|')]
    if len(cells)!=4: continue
    m=re.fullmatch(r'([A-Z]{2,5})-(\d{2})(?:～(\d{2}))?',cells[0])
    if not m: continue
    p,lo,hi=m.group(1),int(m.group(2)),int(m.group(3) or m.group(2))
    expanded={f'{p}-{i:02d}' for i in range(lo,hi+1)}
    ids251 |= expanded
    rows.append({'range':cells[0],'count':len(expanded),'req_ac':cells[1],'work_packages':cells[2],'evidence_class':cells[3]})
    req,ac=[x.strip() for x in cells[1].split('/',1)]
    for tid in expanded: meta[tid]=(req,ac,cells[2],cells[3])
d=json.loads(out.read_text())
ids_tool=set(d['matrix'])
def norm(s): return re.sub(r'\s+','',s.replace('～','~'))
meta_mismatch=[]
for tid in sorted(ids251 & ids_tool):
    e=d['matrix'][tid]; actual=(e['req'],e['ac'],e['work_packages'],e['evidence_class'])
    exp=meta[tid]
    if tuple(map(norm,actual)) != tuple(map(norm,exp)):
        meta_mismatch.append({'id':tid,'expected':exp,'actual':actual})
res={
 'plan_sha256':sha,
 'sec20_count':len(ids20),'sec251_expanded_count':len(ids251),'tool_count':len(ids_tool),
 'sec20_equals_sec251':ids20==ids251,
 'sec20_equals_tool':ids20==ids_tool,
 'sec251_equals_tool':ids251==ids_tool,
 'sec20_only_vs_251':sorted(ids20-ids251),'sec251_only_vs_20':sorted(ids251-ids20),
 'tool_only_vs_251':sorted(ids_tool-ids251),'sec251_only_vs_tool':sorted(ids251-ids_tool),
 'mapping_rows':rows,'metadata_mismatch_count':len(meta_mismatch),'metadata_mismatches':meta_mismatch,
 'tool_stats':d['stats'],
 'observation':'工具自身 cross_check_plan 仅解析 §20 并与内置冻结 catalog 比较，不解析 §25.1；本独立检查补做 §25.1 范围展开与四列元数据逐 ID 对账。'
}
print(json.dumps(res,ensure_ascii=False,indent=2))
sys.exit(0 if sha=='96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306' and ids20==ids251==ids_tool and not meta_mismatch else 1)

import re,json,pathlib,sys,os
plan=pathlib.Path('/private/tmp/codex-test/方案.md').read_text()
s20=plan.split('# 20. 强制红探针与验收矩阵',1)[1].split('# 21.',1)[0]
s251=plan.split('## 25.1 全部验收 ID 的反向需求/AC 映射',1)[1].split('# 26.',1)[0]
ids20=[]
for line in s20.splitlines():
 m=re.match(r'^\|\s*([A-Z]+-\d+)\s*\|',line)
 if m: ids20.append(m.group(1))
ids251=[]
for line in s251.splitlines():
 m=re.match(r'^\|\s*([A-Z]+)-(\d+)(?:～(\d+))?\s*\|',line)
 if not m: continue
 pre,a,b=m.group(1),int(m.group(2)),m.group(3)
 width=len(m.group(2)); b=int(b) if b else a
 ids251 += [f'{pre}-{i:0{width}d}' for i in range(a,b+1)]
live=json.load(open(os.path.join(open('/private/tmp/codex-test/.reaudit3-current').read().strip(),'04-evidence','traceability-live.json')))
ids_tool=list(live['matrix'])
sets=[set(ids20),set(ids251),set(ids_tool)]
print('COUNTS_WITH_DUPLICATES',len(ids20),len(ids251),len(ids_tool))
print('UNIQUE_COUNTS',*(len(x) for x in sets))
print('DUP20',sorted(x for x in set(ids20) if ids20.count(x)>1))
print('DUP251',sorted(x for x in set(ids251) if ids251.count(x)>1))
print('20_ONLY_VS_251',sorted(sets[0]-sets[1]))
print('251_ONLY_VS_20',sorted(sets[1]-sets[0]))
print('20_ONLY_VS_TOOL',sorted(sets[0]-sets[2]))
print('TOOL_ONLY_VS_20',sorted(sets[2]-sets[0]))
print('SET_EQUAL',sets[0]==sets[1]==sets[2])
print('DEDICATED',live['stats']['dedicated_implemented'],'PROXY',live['stats']['proxy_partial'],'MISSING',live['stats']['missing'])
sys.exit(0 if sets[0]==sets[1]==sets[2] and len(sets[0])==131 else 1)

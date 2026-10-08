#!/usr/bin/env python3
"""第四轮独立追踪对账；不导入被验工具，不调用其函数。"""
import ast, hashlib, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

repo=Path(sys.argv[1]).resolve()
live_path=Path(sys.argv[2]).resolve()
out_path=Path(sys.argv[3]).resolve()
plan_path=repo/'evidence/00-baseline/codex-external/方案.md'
tool_path=repo/'tools/ac_traceability.py'
plan=plan_path.read_text(encoding='utf-8')
tool_src=tool_path.read_text(encoding='utf-8')

def norm(s):
    return re.sub(r'\s+',' ',s.replace('`','').replace('～','~')).strip()

def table_cells(line):
    if not line.startswith('|') or not line.rstrip().endswith('|'): return None
    return [x.strip() for x in line.strip().strip('|').split('|')]

# §20：逐行、逐语义、逐小节独立解析。
m20=re.search(r'^# 20\.',plan,re.M); m21=re.search(r'^# 21\.',plan,re.M)
assert m20 and m21 and m20.start()<m21.start()
sec20=plan[m20.start():m21.start()]
rows20=[]; current=None
for line in sec20.splitlines():
    mh=re.match(r'^## (20\.\d+)\b',line)
    if mh: current=mh.group(1)
    c=table_cells(line)
    if not c or len(c)!=3: continue
    mm=re.fullmatch(r'([A-Z]{2,5})-(\d{2})',c[0])
    if mm:
        rows20.append({'id':f'{mm.group(1)}-{mm.group(2)}','section':current,
                       'injection':c[1],'expectation':c[2]})
ids20_list=[r['id'] for r in rows20]
dup20=sorted(k for k,v in Counter(ids20_list).items() if v>1)
map20={r['id']:r for r in rows20}

# §25.1：范围展开，逐前缀四列映射。
m251=re.search(r'^## 25\.1\b',plan,re.M); m26=re.search(r'^# 26\.',plan,re.M)
assert m251 and m26 and m251.start()<m26.start()
sec251=plan[m251.start():m26.start()]
expanded=[]; map251={}; prefix_rows=[]; range_errors=[]
for line in sec251.splitlines():
    c=table_cells(line)
    if not c or len(c)!=4: continue
    mm=re.fullmatch(r'([A-Z]{2,5})-(\d{2})(?:[～~](\d{2}))?',c[0])
    if not mm: continue
    pfx,lo=mm.group(1),int(mm.group(2)); hi=int(mm.group(3) or mm.group(2))
    if hi<lo: range_errors.append(f'{c[0]} reverse range'); continue
    ra=[x.strip() for x in c[1].split('/',1)]
    if len(ra)!=2: range_errors.append(f'{c[0]} bad req/ac'); continue
    meta={'req':ra[0],'ac':ra[1],'work_packages':c[2],'evidence_class':c[3]}
    prefix_rows.append({'prefix':pfx,'lo':lo,'hi':hi,**meta})
    for n in range(lo,hi+1):
        tid=f'{pfx}-{n:02d}'; expanded.append(tid); map251[tid]=meta
ids251_list=expanded
dup251=sorted(k for k,v in Counter(ids251_list).items() if v>1)

# 只用 AST literal 读取冻结目录；不执行被验工具。
tree=ast.parse(tool_src)
nodes={}
for node in tree.body:
    if isinstance(node,ast.Assign):
        for t in node.targets:
            if isinstance(t,ast.Name): nodes[t.id]=node.value
need=['EXPECTED_TOTAL','PREFIX_META','ID_DEFS','PROXY_ALIASES','SCAN_ROOTS']
missing_ast=[n for n in need if n not in nodes]
assert not missing_ast,missing_ast
expected_total=ast.literal_eval(nodes['EXPECTED_TOTAL'])
prefix_meta=ast.literal_eval(nodes['PREFIX_META'])
id_defs=ast.literal_eval(nodes['ID_DEFS'])
proxy_aliases=ast.literal_eval(nodes['PROXY_ALIASES'])
scan_roots=ast.literal_eval(nodes['SCAN_ROOTS'])
# AST 原始 dict 键重复（literal_eval 会折叠，所以另算）。
id_key_list=[]
for k in nodes['ID_DEFS'].keys:
    p,n=ast.literal_eval(k); id_key_list.append(f'{p}-{n:02d}')
dup_tool=sorted(k for k,v in Counter(id_key_list).items() if v>1)
ids_tool={f'{p}-{n:02d}' for p,n in id_defs}

# 三集合 + §20 语义 + §25.1 四列元数据。
semantic_errors=[]
for (p,n),(inj,exp) in id_defs.items():
    tid=f'{p}-{n:02d}'; row=map20.get(tid)
    if not row: continue
    if norm(inj)!=norm(row['injection']): semantic_errors.append(f'{tid}: injection')
    if norm(exp)!=norm(row['expectation']): semantic_errors.append(f'{tid}: expectation')
meta_errors=[]
for tid,meta in map251.items():
    pfx=tid.split('-')[0]
    if pfx not in prefix_meta:
        meta_errors.append(f'{tid}: prefix absent in tool'); continue
    req,ac,wp,ev=prefix_meta[pfx]
    checks={'req':req,'ac':ac,'work_packages':wp,'evidence_class':ev}
    for k,v in checks.items():
        if norm(v)!=norm(meta[k]): meta_errors.append(f'{tid}: {k}')

# 独立扫描测试资产：精确 ID/下划线形态即使出现在注释也记 raw；0 raw 是最强反证。
forms={tid:[tid,tid.replace('-','_'),'test_'+tid.replace('-','_')] for tid in ids_tool}
raw_hits=defaultdict(list); test_context_hits=defaultdict(list); scanned=[]
for root_rel in ['tests','system/tests','cli','system/wenqu_core','probes']:
    root=repo/root_rel
    if not root.is_dir(): continue
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix not in ('.py','.sh'): continue
        if any(x in path.parts for x in ('__pycache__','.pytest_cache','.git','node_modules')): continue
        rel=str(path.relative_to(repo)); scanned.append(rel)
        src=path.read_text(encoding='utf-8',errors='ignore')
        for tid,fs in forms.items():
            present=[f for f in fs if f in src]
            if present: raw_hits[tid].append({'file':rel,'forms':present})
        if path.suffix=='.py':
            try: pt=ast.parse(src)
            except SyntaxError: continue
            lines=src.splitlines()
            for fn in ast.walk(pt):
                if not isinstance(fn,(ast.FunctionDef,ast.AsyncFunctionDef)): continue
                if not re.search(r'(^test_|selftest|self_test|_self_test$)',fn.name,re.I): continue
                body='\n'.join(lines[fn.lineno-1:(fn.end_lineno or fn.lineno)])
                for tid,fs in forms.items():
                    if any(f in fn.name or f in body for f in fs):
                        test_context_hits[tid].append({'file':rel,'function':fn.name})
        else:
            for no,line in enumerate(src.splitlines(),1):
                if line.lstrip().startswith('#'): continue
                for tid,fs in forms.items():
                    if any(f in line for f in fs): test_context_hits[tid].append({'file':rel,'line':no})

# live matrix 与独立解析逐字段对账。
live=json.loads(live_path.read_text(encoding='utf-8'))
matrix=live.get('matrix',{})
live_mapping_errors=[]
for tid in sorted(ids_tool):
    if tid not in matrix:
        live_mapping_errors.append(f'{tid}: missing matrix row'); continue
    ent=matrix[tid]; r20=map20.get(tid); r251=map251.get(tid)
    if not r20 or not r251: continue
    expected={'section':r20['section'],'injection':r20['injection'],'expectation':r20['expectation'],
              'req':r251['req'],'ac':r251['ac'],'work_packages':r251['work_packages'],
              'evidence_class':r251['evidence_class']}
    for k,v in expected.items():
        if norm(str(ent.get(k,'')))!=norm(str(v)): live_mapping_errors.append(f'{tid}: {k}')

stats=live.get('stats',{})
implemented={tid for tid,e in matrix.items() if e.get('implemented') is True}
proxy={tid for tid,e in matrix.items() if e.get('match_type')=='proxy_partial'}
proxy_ref_checks={}
for tid,pa in proxy_aliases.items():
    p=repo/pa['test_file']; proxy_ref_checks[tid]={'file_exists':p.is_file(),
      'reference_text_present': p.is_file() and (pa['test_function'] in p.read_text(encoding='utf-8',errors='ignore') or
        all(part in p.read_text(encoding='utf-8',errors='ignore') for part in re.findall(r'[A-Za-z_][A-Za-z0-9_]*',pa['test_function'])[:1]))}

tracked=json.loads((repo/'evidence/traceability-matrix.json').read_text(encoding='utf-8'))
repo_head=(repo/'.git/HEAD').read_text().strip() if (repo/'.git/HEAD').is_file() else None
import subprocess
actual_head=subprocess.run(['git','rev-parse','HEAD'],cwd=repo,text=True,capture_output=True).stdout.strip()

set_diffs={
 '20_only_vs_tool':sorted(set(ids20_list)-ids_tool),'tool_only_vs_20':sorted(ids_tool-set(ids20_list)),
 '251_only_vs_tool':sorted(set(ids251_list)-ids_tool),'tool_only_vs_251':sorted(ids_tool-set(ids251_list)),
 '20_only_vs_251':sorted(set(ids20_list)-set(ids251_list)),'251_only_vs_20':sorted(set(ids251_list)-set(ids20_list)),
 'matrix_only_vs_tool':sorted(set(matrix)-ids_tool),'tool_only_vs_matrix':sorted(ids_tool-set(matrix)),
}
failures=[]
if hashlib.sha256(plan.encode()).hexdigest()!='96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306': failures.append('plan sha mismatch')
if expected_total!=131 or len(ids20_list)!=131 or len(ids251_list)!=131 or len(ids_tool)!=131: failures.append('count mismatch')
if dup20 or dup251 or dup_tool: failures.append('duplicates')
if any(set_diffs.values()): failures.append('set mismatch')
if semantic_errors: failures.append('§20 semantic mapping mismatch')
if meta_errors or range_errors: failures.append('§25.1 metadata mapping mismatch')
if live_mapping_errors: failures.append('live matrix mapping mismatch')
if raw_hits or test_context_hits: failures.append('dedicated exact ID hits are nonzero; review classification')
if implemented: failures.append('live implemented contradicts independent zero-hit scan')
if proxy!=set(proxy_aliases): failures.append('proxy registry/live mismatch')
if stats.get('total_ids')!=131 or stats.get('dedicated_implemented')!=0 or stats.get('proxy_partial')!=3 or stats.get('missing')!=128: failures.append('live stats mismatch')

result={
 'plan_sha256':hashlib.sha256(plan.encode()).hexdigest(),'repo_head':actual_head,
 'counts':{'section20_rows':len(ids20_list),'section20_unique':len(set(ids20_list)),
           'section251_expanded':len(ids251_list),'section251_unique':len(set(ids251_list)),
           'tool_catalog_unique':len(ids_tool),'live_matrix_rows':len(matrix)},
 'duplicates':{'section20':dup20,'section251':dup251,'tool_catalog_ast':dup_tool},
 'set_differences':set_diffs,'section20_semantic_errors':semantic_errors,
 'section251_metadata_errors':meta_errors,'range_errors':range_errors,
 'live_mapping_errors':live_mapping_errors,
 'coverage_independent':{'scanned_files':len(scanned),'raw_exact_id_hits':dict(raw_hits),
                         'test_context_exact_id_hits':dict(test_context_hits),
                         'dedicated_count':len(implemented),'proxy_ids':sorted(proxy),
                         'missing_count':131-len(implemented)-len(proxy),
                         'proxy_reference_checks':proxy_ref_checks},
 'live_stats':stats,'tracked_matrix_meta':tracked.get('meta',{}),
 'tracked_matrix_head_matches_current':tracked.get('meta',{}).get('repo_head')==actual_head,
 'failures':failures,'ok':not failures,
}
out_path.write_text(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8')
print(f"方案SHA={result['plan_sha256']}")
print(f"集合计数: §20={len(ids20_list)}/{len(set(ids20_list))} §25.1={len(ids251_list)}/{len(set(ids251_list))} 工具={len(ids_tool)} matrix={len(matrix)}")
print(f"重复: §20={len(dup20)} §25.1={len(dup251)} 工具AST={len(dup_tool)}")
print(f"集合差异项总数={sum(len(x) for x in set_diffs.values())}")
print(f"§20逐行注入/期望差异={len(semantic_errors)}；§25.1四列映射差异={len(meta_errors)}；live逐字段差异={len(live_mapping_errors)}")
print(f"专属精确ID原始命中={len(raw_hits)}，测试上下文命中={len(test_context_hits)}，live dedicated={len(implemented)}，proxy={len(proxy)}，missing={131-len(implemented)-len(proxy)}")
print(f"tracked matrix HEAD={tracked.get('meta',{}).get('repo_head')} current={actual_head} match={result['tracked_matrix_head_matches_current']}")
print('RESULT='+('PASS' if not failures else 'FAIL')+' failures='+json.dumps(failures,ensure_ascii=False))
raise SystemExit(0 if not failures else 1)

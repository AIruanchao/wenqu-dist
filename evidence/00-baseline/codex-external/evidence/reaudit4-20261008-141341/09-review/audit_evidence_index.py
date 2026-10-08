#!/usr/bin/env python3
from __future__ import annotations
import json, hashlib, re, subprocess
from pathlib import Path
from collections import Counter
repo=Path('/Users/maccc/Documents/wenqu-dist')
idxp=repo/'evidence/evidence-index.json'
d=json.loads(idxp.read_text())
req=['run_id','commit','environment','scope','ruleset','time','argv','real_rc','artifact_sha256','fresh_until']
hex40=re.compile(r'^[0-9a-f]{40}$')
hex64=re.compile(r'^[0-9a-f]{64}$')
def sha(p):
 h=hashlib.sha256();
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def blank(v): return v is None or v=='' or v==[] or v=={}
def git_full(commit):
 if not isinstance(commit,str): return None
 m=re.fullmatch(r'[0-9a-f]{7,40}',commit)
 if not m:return None
 p=subprocess.run(['git','rev-parse','--verify',commit+'^{commit}'],cwd=repo,text=True,capture_output=True)
 return p.stdout.strip() if p.returncode==0 else None
print(f'index_sha256={sha(idxp)}')
print(f'index_version={d.get("index_version")} entries={len(d.get("entries",[]))}')
print(f'repo_head_at_filing={d.get("repo_head_at_filing",{}).get("commit")}')
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
print(f'live_HEAD={head}')
print(f'head_match={d.get("repo_head_at_filing",{}).get("commit")==head}')
print('\nENTRY_AUDIT')
strict_ok=[]
for e in d['entries']:
 miss=[k for k in req if k not in e or blank(e.get(k))]
 p=repo/e.get('evidence_path','')
 kind='missing'
 if p.is_file():kind='file'
 elif p.is_dir():kind='dir'
 art=e.get('artifact_sha256')
 art_exact=isinstance(art,str) and bool(hex64.fullmatch(art))
 c=e.get('commit')
 c_exact=isinstance(c,str) and bool(hex40.fullmatch(c))
 c_resolved=git_full(c)
 argv_ok=isinstance(e.get('argv'),list) and len(e['argv'])>0 and all(isinstance(x,str) and x.strip() for x in e['argv'])
 path_ok=(kind=='file')
 ok=(not miss and path_ok and art_exact and c_exact and argv_ok)
 if ok:strict_ok.append(e['entry_id'])
 print(json.dumps({
  'entry_id':e.get('entry_id'),'path':e.get('evidence_path'),'path_type':kind,
  'path_sha256':sha(p) if p.is_file() else None,
  'missing_or_blank_required':miss,'artifact_sha256_exact64':art_exact,
  'commit_exact40':c_exact,'commit_resolved':c_resolved,'argv_nonempty':argv_ok,
  'strict_24_2_usable':ok
 },ensure_ascii=False,sort_keys=True))
print('\nSUMMARY')
print('strict_24_2_usable_count=',len(strict_ok),'ids=',strict_ok)
print('path_types=',dict(Counter('file' if (repo/e.get('evidence_path','')).is_file() else 'dir' if (repo/e.get('evidence_path','')).is_dir() else 'missing' for e in d['entries'])))
print('artifact_sha256_exact64_count=',sum(isinstance(e.get('artifact_sha256'),str) and bool(hex64.fullmatch(e['artifact_sha256'])) for e in d['entries']))
print('commit_exact40_count=',sum(isinstance(e.get('commit'),str) and bool(hex40.fullmatch(e['commit'])) for e in d['entries']))
print('entries_with_any_blank_required=',sum(any(k not in e or blank(e.get(k)) for k in req) for e in d['entries']))
print('known_gaps:')
for x in d.get('known_gaps',[]):print('-',x)
print('\nCURRENT_ARTIFACT_INDEXING')
paths={e.get('evidence_path','').rstrip('/') for e in d['entries']}
for rel in [
 'evidence/08-ci-and-branch-rules/branch-protection-readback-20261008.json',
 'evidence/08-ci-and-branch-rules/rulesets-count-20261008.txt',
 'evidence/10-ui-launchd-alert-backup/dashboard-7789-deploy-20261008.json']:
 p=repo/rel
 print(json.dumps({'path':rel,'exists':p.exists(),'sha256':sha(p) if p.is_file() else None,'exactly_indexed':rel in paths},ensure_ascii=False))
print('current_run_37733159993_indexed=',any(str(e.get('run_id','')).startswith('37733159993') for e in d['entries']))
print('current_head_e4aba84_indexed=',any(head in str(e.get('commit','')) for e in d['entries']))

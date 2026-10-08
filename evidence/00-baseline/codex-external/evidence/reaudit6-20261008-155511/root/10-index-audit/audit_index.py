#!/usr/bin/env python3
import json,re,hashlib,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve(); idx=root/'evidence/evidence-index.json'
d=json.loads(idx.read_text())
required=['run_id','commit','environment','scope','ruleset','time','argv','real_rc','artifact_sha256','fresh_until','evidence_path']
hex64=re.compile(r'^[0-9a-f]{64}$')
sha40=re.compile(r'^[0-9a-f]{40}$')
rows=[]
for e in d.get('entries',[]):
    issues=[]
    for k in required:
        if k not in e: issues.append('missing_key:'+k)
        elif e[k] is None or e[k]=='' or e[k]==[]: issues.append('empty:'+k)
    c=e.get('commit')
    if not isinstance(c,str) or not (sha40.fullmatch(c) or re.fullmatch(r'[0-9a-f]{7,39}',c)):
        issues.append('commit_not_exact_sha')
    a=e.get('artifact_sha256')
    if not isinstance(a,str) or not hex64.fullmatch(a): issues.append('artifact_sha256_not_exact64')
    p=e.get('evidence_path')
    target=root/p if isinstance(p,str) else None
    if not target or not target.exists(): issues.append('evidence_path_missing')
    elif target.is_dir(): issues.append('evidence_path_is_directory_not_artifact')
    elif isinstance(a,str) and hex64.fullmatch(a):
        h=hashlib.sha256(target.read_bytes()).hexdigest()
        if h!=a: issues.append('artifact_hash_mismatch:'+h)
    rows.append({'entry_id':e.get('entry_id'),'issues':issues,'strict_pass':not issues})
print(json.dumps({'entry_count':len(rows),'strict_pass':sum(x['strict_pass'] for x in rows),'strict_fail':sum(not x['strict_pass'] for x in rows),'rows':rows},ensure_ascii=False,indent=2))
sys.exit(0 if rows and all(x['strict_pass'] for x in rows) else 1)

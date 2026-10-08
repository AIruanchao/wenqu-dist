#!/usr/bin/env python3
from pathlib import Path
import json,hashlib,re,sys,datetime
root=Path(sys.argv[1]); idx=root/'evidence/evidence-index.json'; d=json.loads(idx.read_text())
required=['run_id','commit','environment','scope','ruleset','time','argv','real_rc','artifact_sha256','evidence_path','fresh_until']
rows=[]
for e in d['entries']:
 p=root/e.get('evidence_path','') if e.get('evidence_path') else None
 kind='missing'
 actual_hash=None; size=None
 if p and p.exists():
  if p.is_file():
   kind='file'; b=p.read_bytes(); actual_hash=hashlib.sha256(b).hexdigest(); size=len(b)
  elif p.is_dir(): kind='directory'
 ah=e.get('artifact_sha256')
 exact=bool(isinstance(ah,str) and re.fullmatch(r'[0-9a-f]{64}',ah))
 extracted=re.findall(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])',ah or '') if isinstance(ah,str) else []
 match=(exact and kind=='file' and ah==actual_hash)
 missing=[k for k in required if e.get(k) is None or e.get(k)=='' or (k=='argv' and not e.get(k))]
 commit=e.get('commit')
 commit_full=bool(isinstance(commit,str) and re.fullmatch(r'[0-9a-f]{40}',commit))
 rows.append({
   'entry_id':e.get('entry_id'),'path':e.get('evidence_path'),'path_kind':kind,
   'size':size,'actual_sha256':actual_hash,'declared':ah,'declared_exact64':exact,
   'declared_matches_path':match,'hashes_embedded':extracted,'missing_or_empty':missing,
   'commit_full40':commit_full,'run_id':e.get('run_id'),'commit':commit,
   'environment':e.get('environment')
 })
summary={
 'entries':len(rows),
 'all_required_keys_present':sum(not r['missing_or_empty'] for r in rows),
 'paths_exist':sum(r['path_kind']!='missing' for r in rows),
 'paths_are_files':sum(r['path_kind']=='file' for r in rows),
 'artifact_sha_exact64':sum(r['declared_exact64'] for r in rows),
 'artifact_sha_exact64_matches_evidence_path':sum(r['declared_matches_path'] for r in rows),
 'commit_full40':sum(r['commit_full40'] for r in rows),
 'size_field_present':sum('artifact_size' in e or 'size' in e for e in d['entries']),
}
out={'index_sha256':hashlib.sha256(idx.read_bytes()).hexdigest(),'summary':summary,'rows':rows}
print(json.dumps(out,ensure_ascii=False,indent=2))

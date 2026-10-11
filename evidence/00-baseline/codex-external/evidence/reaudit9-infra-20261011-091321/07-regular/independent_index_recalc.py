#!/usr/bin/env python3
import datetime, hashlib, json, os, re, stat, sys
from pathlib import Path
root=Path(sys.argv[1]).resolve(); idx=root/'evidence/evidence-index.json'
doc=json.loads(idx.read_text(encoding='utf-8'))
now=datetime.datetime.now(datetime.timezone.utc)
commit_re=re.compile(r'^[0-9a-f]{40}$'); sha_re=re.compile(r'^[0-9a-f]{64}$')
errors=[]; rows=[]; ids=set()
for table in ('active','legacy_non_scoring'):
    for i,e in enumerate(doc[table]['entries']):
        eid=e.get('entry_id'); duplicate=eid in ids; ids.add(eid)
        rel=e.get('evidence_path'); declared=e.get('artifact_sha256'); path=root/str(rel)
        kind='missing'; size=None; actual=None
        try:
            st=os.lstat(path)
            kind='symlink' if stat.S_ISLNK(st.st_mode) else ('regular' if stat.S_ISREG(st.st_mode) else 'other')
            size=st.st_size
            if kind=='regular': actual=hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError: pass
        row={'table':table,'n':i,'entry_id':eid,'path':rel,'kind':kind,'size':size,'declared_sha256':declared,'actual_sha256':actual,'hash_equal':actual==declared}
        if table=='active':
            missing=[k for k in ('entry_id','category','title','what','commit','run_id','environment','argv','cwd','real_rc','time','artifact_sha256','evidence_path','fresh_until','verified_by') if k not in e or e[k] is None]
            row.update(commit_40=bool(commit_re.fullmatch(str(e.get('commit','')))),argv_nonempty=isinstance(e.get('argv'),list) and bool(e['argv']) and all(isinstance(x,str) and x.strip() for x in e['argv']),real_rc_integer=isinstance(e.get('real_rc'),int) and not isinstance(e.get('real_rc'),bool),required_missing=missing)
            try:
                ttl=datetime.datetime.fromisoformat(str(e['fresh_until']).replace('Z','+00:00'))
                if ttl.tzinfo is None: ttl=ttl.replace(tzinfo=datetime.timezone.utc)
                row['fresh_at_audit']=ttl >= now
            except Exception: row['fresh_at_audit']=False
        else:
            row['migrated_reason_nonempty']=isinstance(e.get('migrated_reason'),str) and bool(e['migrated_reason'].strip())
        bad=[]
        if duplicate: bad.append('duplicate_id')
        if not isinstance(rel,str) or not rel or os.path.isabs(str(rel)) or '..' in Path(str(rel)).parts: bad.append('unsafe_path')
        if kind!='regular' or not size: bad.append('not_nonempty_regular')
        if not sha_re.fullmatch(str(declared or '')) or actual!=declared: bad.append('hash')
        if table=='active':
            if row['required_missing']: bad.append('missing_required')
            if not row['commit_40']: bad.append('commit')
            if not row['argv_nonempty']: bad.append('argv')
            if not row['real_rc_integer']: bad.append('real_rc')
            if not row['fresh_at_audit']: bad.append('ttl')
        else:
            if not row['migrated_reason_nonempty']: bad.append('migrated_reason')
        row['problems']=bad; errors.extend(f'{table}[{i}] {eid}: {x}' for x in bad); rows.append(row)
print(json.dumps({'audited_at':now.isoformat(),'index':str(idx),'active_count':len(doc['active']['entries']),'legacy_count':len(doc['legacy_non_scoring']['entries']),'rows':rows,'problem_count':len(errors),'problems':errors,'verdict':'PASS' if not errors else 'FAIL'},ensure_ascii=False,indent=2))
sys.exit(0 if not errors else 1)

#!/usr/bin/env python3
import json,hashlib,os,re
from pathlib import Path
R=Path('/Users/maccc/Documents/wenqu-dist'); idx=json.loads((R/'evidence/evidence-index.json').read_text())
required=['run_id','commit','environment','scope','ruleset','time','argv','real_rc','artifact_sha256','fresh_until']
entries=[]
for e in idx['entries']:
    missing=[k for k in required if k not in e or e[k] in (None,'',[],{})]
    ep=e.get('evidence_path','')
    if ep.startswith('外部：'): p=Path(ep.split('：',1)[1])
    else: p=R/ep
    entries.append({'entry_id':e['entry_id'],'commit':e.get('commit'),'evidence_path':ep,'path_exists':p.exists(),
                    'path_kind':'dir' if p.is_dir() else ('file' if p.is_file() else 'missing'),
                    'missing_hard_fields':missing,'artifact_sha256':e.get('artifact_sha256'),
                    'artifact_sha256_is_hex64':bool(re.fullmatch(r'[0-9a-f]{64}',str(e.get('artifact_sha256') or ''))),
                    'commit_contains_full_sha40':bool(re.search(r'\b[0-9a-f]{40}\b',str(e.get('commit') or '')))})
sections={}
for d in sorted((R/'evidence').glob('[0-9][0-9]-*')):
    files=[p for p in d.rglob('*') if p.is_file()]
    substantive=[p for p in files if p.name!='README.md']
    direct_substantive=[p for p in d.iterdir() if p.is_file() and p.name!='README.md']
    sections[d.name]={'all_files_recursive':len(files),'substantive_recursive':len(substantive),
                      'substantive_direct':len(direct_substantive),'direct_files':[str(p.relative_to(R)) for p in direct_substantive],
                      'note':'00-baseline 的递归工件主要是旧轮外部证据快照；其他目录只有 README' if d.name=='00-baseline' else ''}
# Validate .sha256 files actually match target when format recognisable
sha_checks=[]
for sf in (R/'evidence').rglob('*.sha256'):
    raw=sf.read_text(errors='replace').strip(); m=re.match(r'^([0-9a-f]{64})\s+\*?(.+)$',raw)
    if not m:
        sha_checks.append({'sha_file':str(sf.relative_to(R)),'parse':False,'raw':raw}); continue
    expected,name=m.groups(); target=sf.parent/name
    if not target.exists():
        # some lines record absolute/basename weirdness, fall back basename without path prefix
        target=sf.with_suffix('')
    actual=hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None
    sha_checks.append({'sha_file':str(sf.relative_to(R)),'target':str(target),'exists':target.exists(),'expected':expected,'actual':actual,'ok':actual==expected})
head=os.popen(f"git -C '{R}' rev-parse HEAD").read().strip()
res={'current_head':head,'index_repo_head_at_filing':idx.get('repo_head_at_filing'),
     'entry_count':len(entries),'entries':entries,'entries_missing_any_hard_field':sum(bool(e['missing_hard_fields']) for e in entries),
     'entries_pointing_to_directory_not_artifact':sum(e['path_kind']=='dir' for e in entries),
     'entries_with_strict_hex_artifact_hash':sum(e['artifact_sha256_is_hex64'] for e in entries),
     'entries_with_file_path_and_strict_hash':sum(e['path_kind']=='file' and e['artifact_sha256_is_hex64'] for e in entries),
     'section_inventory':sections,'sha_checks':sha_checks,
     'index_known_gaps':idx.get('known_gaps'),
     'staleness_observations':[
       '索引 repo_head_at_filing=e00de14，不是本轮 ff050bb；索引无 ff050bb CI run 37727549548 条目',
       'known_gaps 仍称外部证据未快照，但 ff050bb 已把旧轮 evidence 快照嵌入 00-baseline/codex-external/evidence，索引未同步',
       '01~13 各工作包目录均只有 README，无 §24.2 所需原始证据工件',
       '目录路径不能替代逐工件 artifact sha256；9 个 index entries 中 7 个有空硬字段，另 2 个虽字段非空但路径/哈希不可逐工件核验'
     ]}
print(json.dumps(res,ensure_ascii=False,indent=2))

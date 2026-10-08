#!/usr/bin/env python3
from pathlib import Path
import json,re,sys
root=Path(sys.argv[1])
def load(name):
 s=(root/name).read_text()
 # discard command line, strip appended exit_code= line/suffix
 s=s.split('\n',1)[1]
 s=re.sub(r'exit_code=\d+\s*$', '', s)
 return json.loads(s)
run=load('01-run-view.json.txt'); api=load('02-run-api.json.txt'); jobs=load('03-run-jobs.json.txt')
checks=load('04-commit-check-runs.json.txt'); prot=load('05-main-protection.json.txt')
repo=load('07-repo-settings.json.txt'); rules=load('08-rulesets.json.txt')
pr4=load('09-pr4.json.txt'); pr5=load('10-pr5.json.txt')
workflow=Path('/tmp/reaudit6-trace.dxHErV/.github/workflows/acceptance.yml').read_text()
summary={
 'run':{k:run.get(k) for k in ['databaseId','headSha','headBranch','event','status','conclusion','workflowName','createdAt','startedAt','updatedAt','url']},
 'run_actor':api.get('actor',{}).get('login'),'run_path':api.get('path'),'run_attempt':api.get('run_attempt'),
 'jobs':[{'id':j['databaseId'],'name':j['name'],'status':j['status'],'conclusion':j['conclusion'],'startedAt':j['startedAt'],'completedAt':j['completedAt'], 'step_names':[s['name'] for s in j['steps']]} for j in run['jobs']],
 'check_runs':[{'name':c['name'],'app':c.get('app',{}).get('slug'),'sha':c.get('head_sha'),'status':c['status'],'conclusion':c['conclusion'],'details_url':c['details_url']} for c in checks.get('check_runs',[])],
 'branch_protection':{
  'strict':prot.get('required_status_checks',{}).get('strict'),
  'contexts':prot.get('required_status_checks',{}).get('contexts'),
  'checks':prot.get('required_status_checks',{}).get('checks'),
  'enforce_admins':prot.get('enforce_admins',{}).get('enabled'),
  'required_signatures':prot.get('required_signatures',{}).get('enabled'),
  'allow_force_pushes':prot.get('allow_force_pushes',{}).get('enabled'),
  'allow_deletions':prot.get('allow_deletions',{}).get('enabled'),
  'required_reviews_present':'required_pull_request_reviews' in prot,
  'conversation_resolution':prot.get('required_conversation_resolution',{}).get('enabled')},
 'repo':{'default_branch':repo.get('default_branch'),'allow_auto_merge':repo.get('allow_auto_merge'),'pushed_at':repo.get('pushed_at')},
 'rulesets_count':len(rules),
 'workflow':{
   'uses':re.findall(r'uses:\s*([^\s]+)',workflow),
   'sha_pinned':all(bool(re.fullmatch(r'[^@]+@[0-9a-f]{40}',x)) for x in re.findall(r'uses:\s*([^\s]+)',workflow)),
   'has_merge_group': 'merge_group' in workflow,
   'runs_seven_ac_files': any('test_ac_' in l for l in workflow.splitlines()),
 },
 'prs':[]
}
for p in (pr4,pr5):
 checks2=[c for c in p['statusCheckRollup'] if c.get('__typename')=='CheckRun']
 summary['prs'].append({
  'number':p['number'],'state':p['state'],'createdAt':p['createdAt'],'mergedAt':p['mergedAt'],
  'headRefOid':p['headRefOid'],'mergeCommit':p.get('mergeCommit',{}).get('oid'),
  'reviewDecision':p.get('reviewDecision'),'autoMergeRequest':p.get('autoMergeRequest'),
  'checks':[{'name':c['name'],'conclusion':c['conclusion'],'completedAt':c['completedAt'],'detailsUrl':c['detailsUrl']} for c in checks2],
  'all_checks_success':bool(checks2) and all(c['conclusion']=='SUCCESS' for c in checks2),
  'latest_check_completed':max((c['completedAt'] for c in checks2),default=None),
 })
print(json.dumps(summary,ensure_ascii=False,indent=2))

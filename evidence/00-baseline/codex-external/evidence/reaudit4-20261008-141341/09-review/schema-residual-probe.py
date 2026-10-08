import json, os, sys
from pathlib import Path
from jsonschema import Draft7Validator, FormatChecker
root=Path(sys.argv[1])
S=root/'system/schemas'
def valid(name,obj):
 v=Draft7Validator(json.load(open(S/name)),format_checker=FormatChecker())
 es=sorted(v.iter_errors(obj),key=lambda e:list(e.path))
 return not es, [e.message for e in es]
ident={'commit_sha':'a'*40,'environment':'local','scope_hash':'scope'}
base_ev={
 'schema_version':'2.0','evidence_id':'ev_x','run_id':'run_x','identity':ident,
 'tool':{'name':'t','version':'1'},'runner':{'runner_id':'r','version':'1'},
 'execution':{'argv_digest':'d','started_at':'2026-10-08T00:00:00Z','finished_at':'2026-10-08T00:00:01Z','actual_exit_code':9},
 'verdict':'PASS','artifact':{'artifact_sha256':'b'*64,'artifact_size':1},'fresh_until':'2026-10-09T00:00:00Z'}
base_st={
 'schema_version':'2.0','run_id':'run_x','station_id':2,'attempt_id':'a1','execution_status':'COMPLETED','policy_verdict':'PASS','identity':ident,
 'tool':{'name':'t','version':'1'},
 'execution':{'argv_digest':'d','started_at':'2026-10-08T00:00:00Z','ended_at':'2026-10-08T00:00:01Z','actual_exit_code':0,'expected_exit_set':[0],'assertion_verdict':'PASS'},
 'coverage':{'denominator':9,'scanned':1},'artifacts':[{'cas_digest':'sha256:'+'c'*64,'size':1}]}
base_find={'schema_version':'2.0','event_type':'CLOSED','finding_id':'fnd_x','fingerprint':'fp','severity':'LOW','priority':'P3','ts':'2026-10-08T00:00:00Z','state_from':'VERIFIED','state_to':'OPEN'}
risk_inv={'schema_version':'2.0','event_type':'RISK_INVALIDATED','finding_id':'fnd_x','fingerprint':'fp','severity':'LOW','priority':'P3','ts':'2026-10-08T00:00:00Z'}
run={'schema_version':'2.0','event_type':'RUN_COMPLETED','run_id':'run_x','execution_status':'TIMEOUT','policy_verdict':'CONDITIONAL','identity':ident}
cases=[('evidence_PASS_exit9','evidence-v2.schema.json',base_ev),('station_PASS_shrunk_1_of_9','station-result-v2.schema.json',base_st),('finding_CLOSED_state_to_OPEN','finding-event-v2.schema.json',base_find),('finding_RISK_INVALIDATED_no_from','finding-event-v2.schema.json',risk_inv),('run_TIMEOUT_CONDITIONAL','run-event-v2.schema.json',run)]
accepted=[]
for label,schema,obj in cases:
 ok,errs=valid(schema,obj); print(label, 'ACCEPTED' if ok else 'REJECTED', errs[:2]);
 if ok: accepted.append(label)
print('accepted_residuals=',accepted)
raise SystemExit(1 if accepted else 0)

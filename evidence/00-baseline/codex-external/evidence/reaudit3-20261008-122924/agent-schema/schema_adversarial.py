#!/usr/bin/env python3
import copy, json, os, sys
from pathlib import Path
import jsonschema
from jsonschema import Draft7Validator, FormatChecker

repo = Path(sys.argv[1] if len(sys.argv)>1 else '/Users/maccc/Documents/wenqu-dist')
sd = repo/'system'/'schemas'
for p in sorted(sd.glob('*.json')):
    schema=json.loads(p.read_text())
    try:
        Draft7Validator.check_schema(schema)
        print(f'CHECK_SCHEMA {p.name}: PASS')
    except Exception as e:
        print(f'CHECK_SCHEMA {p.name}: FAIL {type(e).__name__}: {e}')

def result(label, schema_name, obj, expect='REJECT', format_check=False):
    schema=json.loads((sd/schema_name).read_text())
    v=Draft7Validator(schema, format_checker=FormatChecker() if format_check else None)
    errs=list(v.iter_errors(obj))
    actual='REJECT' if errs else 'ACCEPT'
    verdict='EXPECTED' if actual==expect else 'UNEXPECTED'
    print(f'{label}: actual={actual} expected={expect} => {verdict}')
    if errs:
        print('  first_error='+errs[0].message)

approval={
 'schema_version':'2.0','approval_id':'apr_probe','approval_type':'merge',
 'run_id':'run_probe','stop_event_id':'stop_probe','stop_type':'release',
 'actor':'auditor','issued_at':'2026-10-08T00:00:00Z','expires_at':'2026-10-09T00:00:00Z',
 'nonce':'1234567890abcdef','decision':'approve','signature':'s'*32,
 'payload':{'repo_id':'o/r','base_sha':'a'*40,'head_sha':'b'*40,'merge_method':'squash'}
}
result('APP_missing_payload_fixed','approval-v2.schema.json',{k:v for k,v in approval.items() if k!='payload'},'REJECT')
wrong=copy.deepcopy(approval); wrong['payload']={'finding_fingerprints':['f'],'severity':'LOW','reason':'long enough reason','compensating_controls':['x'],'expiry':'2026-10-09T00:00:00Z'}
result('APP_merge_with_only_risk_payload_fixed','approval-v2.schema.json',wrong,'REJECT')
cross=copy.deepcopy(approval); cross['payload'].update({'finding_fingerprints':['f'],'severity':'LOW','reason':'long enough reason','compensating_controls':['x'],'expiry':'2026-10-09T00:00:00Z'})
result('APP_merge_plus_risk_cross_type_extra','approval-v2.schema.json',cross,'REJECT')
extra=copy.deepcopy(approval); extra['payload']['arbitrary_untrusted_field']={'x':1}
result('APP_payload_arbitrary_extra','approval-v2.schema.json',extra,'REJECT')
types=copy.deepcopy(approval); types['payload']['repo_id']=['not','string']; types['payload']['base_sha']={'x':1}
result('APP_payload_wrong_types','approval-v2.schema.json',types,'REJECT')
minimal=copy.deepcopy(approval)
# These common-envelope bindings are absent already: task_id/stage/environment/authorized_scope/policy/ruleset/input/state_version
result('APP_missing_exact_binding_envelope','approval-v2.schema.json',minimal,'REJECT')
badtime=copy.deepcopy(approval); badtime['issued_at']='not-a-date'; badtime['expires_at']='also-not-date'
result('APP_bad_dates_default_Draft7','approval-v2.schema.json',badtime,'REJECT',False)
result('APP_bad_dates_with_FormatChecker','approval-v2.schema.json',badtime,'REJECT',True)

finding={
 'schema_version':'2.0','event_type':'ACCEPTED_RISK','finding_id':'fnd_probe','fingerprint':'fp',
 'severity':'LOW','priority':'P3','ts':'2026-10-08T00:00:00Z',
 'risk_acceptance':{'approver':'a','reason':'0123456789','scope':'s','expiry':'2026-10-09T00:00:00Z'}
}
result('FINDING_p0_accepted_fixed','finding-event-v2.schema.json',{**finding,'severity':'CRITICAL','priority':'P0'},'REJECT')
closed=copy.deepcopy(finding); closed['event_type']='CLOSED'; closed.pop('risk_acceptance'); closed['state_from']='OPEN'
result('FINDING_closed_from_open_fixed','finding-event-v2.schema.json',closed,'REJECT')
result('FINDING_accepted_missing_compensating_controls','finding-event-v2.schema.json',finding,'REJECT')
fromclosed=copy.deepcopy(finding); fromclosed['state_from']='CLOSED'; fromclosed['state_to']='ACCEPTED_RISK'
result('FINDING_accepted_from_closed_illegal_transition','finding-event-v2.schema.json',fromclosed,'REJECT')
weird={**finding,'event_type':'FIX_COMPLETED','state_from':'CLOSED','state_to':'OPEN'}; weird.pop('risk_acceptance')
result('FINDING_fix_completed_closed_to_open','finding-event-v2.schema.json',weird,'REJECT')
inv={**finding,'event_type':'RISK_INVALIDATED'}; inv.pop('risk_acceptance')
result('FINDING_risk_invalidated_without_transition','finding-event-v2.schema.json',inv,'REJECT')

evidence={
 'evidence_id':'ev_probe','run_id':'run','identity':{'commit_sha':'a'*40,'environment':'local','scope_hash':'scope'},
 'tool':{'name':'t','version':'1'},'runner':{'runner_id':'r','version':'1'},
 'execution':{'argv_digest':'d','started_at':'2026-10-08T00:00:00Z','finished_at':'2026-10-08T00:00:01Z','actual_exit_code':0},
 'fresh_until':'2026-10-08T01:00:00Z'
}
result('EVIDENCE_missing_schema_verdict_artifact','evidence-v2.schema.json',evidence,'REJECT')
ev2=copy.deepcopy(evidence); ev2.update(schema_version='2.0',verdict='PASS',artifact={})
result('EVIDENCE_empty_artifact','evidence-v2.schema.json',ev2,'REJECT')
ev3=copy.deepcopy(ev2); ev3['execution']['started_at']='invalid'; ev3['execution']['finished_at']='invalid'; ev3['fresh_until']='invalid'
result('EVIDENCE_bad_dates_default_Draft7','evidence-v2.schema.json',ev3,'REJECT',False)

station={
 'schema_version':'2.0','run_id':'run','station_id':1,'attempt_id':'a','execution_status':'COMPLETED','policy_verdict':'PASS',
 'identity':{'commit_sha':'a'*40,'environment':'local','scope_hash':'scope'},
 'tool':{'name':'t','version':'1'},
 'execution':{'argv_digest':'d','started_at':'2026-10-08T00:00:00Z','ended_at':'2026-10-08T00:00:01Z','actual_exit_code':0,'expected_exit_set':[0],'assertion_verdict':'PASS'}
}
result('STATION_pass_without_coverage_artifacts','station-result-v2.schema.json',station,'REJECT')
st0=copy.deepcopy(station); st0['coverage']={'denominator':0,'scanned':0}; st0['artifacts']=[]
result('STATION_vacuous_zero_denominator_pass','station-result-v2.schema.json',st0,'REJECT')
shrink=copy.deepcopy(station); shrink['coverage']={'denominator':10,'scanned':1}; shrink['artifacts']=[]
result('STATION_shrunk_coverage_pass','station-result-v2.schema.json',shrink,'REJECT')
badrc=copy.deepcopy(station); badrc['execution']['actual_exit_code']=99
result('STATION_nonzero_rc_policy_pass','station-result-v2.schema.json',badrc,'REJECT')

run={
 'schema_version':'2.0','event_type':'RUN_COMPLETED','run_id':'run','execution_status':'ERROR','policy_verdict':'PASS',
 'identity':{'commit_sha':'a'*40,'environment':'local','scope_hash':'scope'}
}
result('RUN_error_plus_pass','run-event-v2.schema.json',run,'REJECT')
run2=copy.deepcopy(run); run2['execution_status']='COMPLETED'; run2['findings']=['fnd_x']
result('RUN_completed_pass_with_findings','run-event-v2.schema.json',run2,'REJECT')

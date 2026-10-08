#!/usr/bin/env python3
import json, os, sys, tempfile
sys.path.insert(0, '/Users/maccc/Documents/wenqu-dist/system')
from wenqu_core.store import EventStore
from wenqu_core.wenqu_pipeline import RunManager, ApprovalBroker
IDENT={'commit_sha':'a'*40,'environment':'staging','scope_hash':'scope-real','repo_id':'repo','ruleset_hash':'rules-real'}

def risk(run_id, nonce):
 return {
  'schema_version':'2.0','approval_id':'apr_probe','approval_type':'risk','run_id':run_id,
  'stop_event_id':'forged-no-stop','stop_type':'scope','actor':'attacker-string',
  'issued_at':'2026-10-08T00:00:00Z','expires_at':'2099-01-01T00:00:00Z',
  'nonce':nonce,'decision':'approve','signature':'x'*32,
  'payload':{'finding_fingerprints':['critical-fp'],'severity':'HIGH','reason':'forged acceptance','compensating_controls':['none'],'expiry':'2099-01-01T00:00:00Z'}
 }

def case(name, mutate):
 td=tempfile.mkdtemp(prefix='reaudit3-ap-')
 mgr=RunManager(EventStore(os.path.join(td,'events.db')))
 rid=mgr.create_run('task_'+name, IDENT)['run_id']
 ap=risk(rid, ('nonce-'+name+'-abcdefghijklmnop')[:40])
 mutate(ap)
 try:
  st=ApprovalBroker.validate_structure(ap)
  print(name+': validate_structure=ACCEPT')
 except Exception as e:
  print(name+': validate_structure=REJECT '+type(e).__name__+': '+str(e))
  return
 try:
  rec=mgr.authorize_risk(rid, ap)
  print(name+': consume_authorization=ACCEPT '+json.dumps(rec,sort_keys=True))
 except Exception as e:
  print(name+': consume_authorization=REJECT '+type(e).__name__+': '+str(e))

case('missing_all_exact_bindings', lambda a: None)
case('invalid_watermark_bypasses_sha_check', lambda a: a.update({'input_watermark':'not-a-sha','environment':'staging','authorized_scope':'scope-real'}))
case('mismatched_policy_ruleset_ignored', lambda a: a.update({'environment':'staging','authorized_scope':'scope-real','input_watermark':'a'*40,'policy_hash':'wrong-policy','ruleset_hash':'wrong-rules'}))
case('cross_type_payload_extras', lambda a: a['payload'].update({'repo_id':'o/r','base_sha':'b'*40,'head_sha':'c'*40,'merge_method':'squash','arbitrary':{'cmd':'evil'}}))
case('high_severity_risk_accepted', lambda a: a.update({'environment':'staging','authorized_scope':'scope-real','input_watermark':'a'*40}))

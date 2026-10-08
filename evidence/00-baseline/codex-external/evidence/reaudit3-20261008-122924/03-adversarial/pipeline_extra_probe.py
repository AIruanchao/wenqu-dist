import sys, tempfile, os, json
sys.path.insert(0,'/Users/maccc/Documents/wenqu-dist/system')
sys.path.insert(0,'/Users/maccc/Documents/wenqu-dist/system/tests')
from wenqu_core.store import EventStore
from wenqu_core.wenqu_pipeline import RunManager, SevenStageStateMachine as SM, ApprovalReuseError, ApprovalRejected, PipelineCorruptionError
from test_wenqu_pipeline import IDENT, make_resume_approval, make_risk_approval

def new():
  td=tempfile.TemporaryDirectory(prefix='reaudit3-pipe-'); s=EventStore(os.path.join(td.name,'x.db')); return td,s,RunManager(s)

def prep_wait(mgr, task, typ='resource'):
  r=mgr.create_run(task,IDENT)['run_id']; mgr.advance_stage(r); w=mgr.raise_waiting(r,typ,'probe'); return r,w
# 1 cross-run same nonce must reject globally
td,s,m=new(); r1,w1=prep_wait(m,'cross1'); r2,w2=prep_wait(m,'cross2')
pre={'resource_probe_ref':'p','probe_recovered':'yes','safety_margin_met':'yes'}
a1,_=make_resume_approval(r1,w1['stop_event_id'],'resource',m.get_run(r1).state_version,preconditions=pre,nonce='same-global-nonce-0001',approval_id='apr_cross_1'); a1['payload']['objective_precondition_hash']=SM.objective_precondition_hash(pre)
a2,_=make_resume_approval(r2,w2['stop_event_id'],'resource',m.get_run(r2).state_version,preconditions=pre,nonce='same-global-nonce-0001',approval_id='apr_cross_2'); a2['payload']['objective_precondition_hash']=SM.objective_precondition_hash(pre)
print('CROSS_RUN_FIRST',m.resume_waiting(r1,a1,pre)['resumed'])
try: m.resume_waiting(r2,a2,pre); print('CROSS_RUN_REUSE','ACCEPTED_BAD')
except Exception as e: print('CROSS_RUN_REUSE','REJECTED',type(e).__name__)
# 2 approval prepared then run cancelled
td2,s2,m2=new(); r,w=prep_wait(m2,'cancelafter'); ap,_=make_resume_approval(r,w['stop_event_id'],'resource',m2.get_run(r).state_version,preconditions=pre,nonce='cancelled-run-nonce-01',approval_id='apr_cancelled'); ap['payload']['objective_precondition_hash']=SM.objective_precondition_hash(pre); m2.cancel_run(r)
try: m2.resume_waiting(r,ap,pre); print('APPROVAL_AFTER_CANCEL','ACCEPTED_BAD')
except Exception as e: print('APPROVAL_AFTER_CANCEL','REJECTED',type(e).__name__)
# 3 raw state_version rewind remains hash-chain-valid but replay must reject
td3,s3,m3=new(); r=m3.create_run('rewind',IDENT)['run_id']; m3.advance_stage(r); st=m3.get_run(r)
s3.append({'schema_version':'2.0','event_type':'STAGE_COMPLETED','run_id':r,'task_id':st.task_id,'execution_status':'COMPLETED','policy_verdict':'PASS','identity':IDENT,'state_version':1,'ts':'2026-10-08T00:00:00Z','actor':'probe','stage':'S1_REQUIREMENT','attempt_id':st.stages['S1_REQUIREMENT'].current_attempt.attempt_id})
print('REWIND_CHAIN_VALID',s3.verify_chain()['ok'])
try: m3.get_run(r); print('STATE_VERSION_REWIND','ACCEPTED_BAD')
except Exception as e: print('STATE_VERSION_REWIND','REJECTED',type(e).__name__)
# 4 cancellation must not leave a RUNNING attempt in terminal run
td4,s4,m4=new(); r=m4.create_run('cancelattempt',IDENT)['run_id']; m4.advance_stage(r); m4.cancel_run(r); st=m4.get_run(r)
print('CANCELLED_RUN_STATE',st.state,'ATTEMPT_STATUS',st.stages['S1_REQUIREMENT'].status,'EXPECTED_ATTEMPT','CANCELLED')
# 5 ERROR+CONDITIONAL must never become completed-conditional; probe actual behavior
td5,s5,m5=new(); r=m5.create_run('errorconditional',IDENT)['run_id']
for _ in range(6): m5.advance_stage(r,execution_status='COMPLETED',policy_verdict='PASS')
out=m5.advance_stage(r,execution_status='ERROR',policy_verdict='CONDITIONAL')
ap=make_risk_approval(r,nonce='error-cond-risk-00001',approval_id='apr_error_cond')
print('ERROR_CONDITIONAL_ATTEMPT',out['attempt_status'])
print('ERROR_CONDITIONAL_RISK_CONSUMED',m5.authorize_risk(r,ap)['consumed'])
print('ERROR_CONDITIONAL_FINAL',m5.complete_run(r)['final_state'])

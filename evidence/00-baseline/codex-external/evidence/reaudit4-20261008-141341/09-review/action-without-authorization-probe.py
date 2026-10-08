import os, sys, tempfile
sys.path.insert(0, os.path.join(sys.argv[1], 'system'))
from wenqu_core.store import EventStore
from wenqu_core.wenqu_pipeline import RunManager
p=tempfile.mktemp(prefix='reaudit4-action-', suffix='.db')
store=EventStore(p); mgr=RunManager(store)
ident={'commit_sha':'a'*40,'environment':'production','scope_hash':'scope1','policy_hash':'policy1','ruleset_hash':'rules1'}
r=mgr.create_run('task-action-no-auth', ident)
rid=r['run_id']
# No keyring, approval, risk/action authorization, or approval consumption.
reserved=mgr.reserve_action(rid, 'release', 'production')
started=mgr.start_action(rid, reserved['action_id'])
committed=mgr.commit_action(rid, reserved['action_id'], 'caller-self-asserted-receipt')
state=mgr.get_run(rid)
consumed=mgr.broker.consumed_approvals(run_id=rid)
print({'run_id':rid,'approval_consumptions':len(consumed),'reserved':reserved['action_state'],'started':started['action_state'],'committed':committed['action_state'],'replayed_action':state.actions[reserved['action_id']]})
# Defense should reject before RESERVED. Reaching COMMITTED without approval is FAIL.
raise SystemExit(1 if committed['action_state']=='COMMITTED' and len(consumed)==0 else 0)

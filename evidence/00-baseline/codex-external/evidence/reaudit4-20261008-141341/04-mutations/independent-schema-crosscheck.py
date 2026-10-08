#!/usr/bin/env python3
"""独立交叉探针：JSON Schema 与内建 Broker 对 1 字节 nonce 必须同拒，否则非零。"""
import json, os, sys
from pathlib import Path
repo=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(repo/'system'))
import jsonschema
from wenqu_core.wenqu_pipeline import ApprovalBroker, ApprovalRejected
schema=json.loads((repo/'system/schemas/approval-v2.schema.json').read_text())
ap={
 'schema_version':'2.0','approval_id':'apr_independent_nonce','approval_type':'resume',
 'key_id':'key_independent','run_id':'run_independent','task_id':'task_independent',
 'stop_event_id':'stop_independent','stop_type':'prod-write','stage':'S4_IMPLEMENT',
 'environment':'local','authorized_scope':'scope:independent','policy_hash':'p',
 'ruleset_hash':'r','input_watermark':'0'*40,'expected_state_version':1,
 'actor':'human-independent','issued_at':'2026-10-08T00:00:00Z',
 'expires_at':'2026-10-09T00:00:00Z','nonce':'x','decision':'approve',
 'signature':'0'*64,
 'payload':{'stop_event_id':'stop_independent','stop_type':'prod-write',
            'objective_precondition_hash':'0'*64},
}
schema_rejects=False
try: jsonschema.validate(ap,schema)
except jsonschema.ValidationError: schema_rejects=True
broker_rejects=False
try: ApprovalBroker.validate_structure(ap)
except ApprovalRejected: broker_rejects=True
print(json.dumps({'case':'one-byte-nonce','schema_rejects':schema_rejects,
                  'broker_rejects':broker_rejects},ensure_ascii=False,sort_keys=True))
if schema_rejects != broker_rejects:
    print('CROSSCHECK_DIVERGENCE: schema 与 Broker 判定不一致',file=sys.stderr)
    raise SystemExit(7)
if not schema_rejects:
    print('CROSSCHECK_WEAK: 两侧均接受恶意样例',file=sys.stderr)
    raise SystemExit(8)
raise SystemExit(0)

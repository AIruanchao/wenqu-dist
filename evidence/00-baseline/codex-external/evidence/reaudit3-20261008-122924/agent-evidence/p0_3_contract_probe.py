#!/usr/bin/env python3
import json,os,sys,tempfile,importlib.util
from pathlib import Path
ROOT=Path('/Users/maccc/Documents/wenqu-dist')
sys.path.insert(0,str(ROOT/'system'))
from wenqu_core.gate_aggregator import GateAggregator
import jsonschema
schema=json.loads((ROOT/'system/schemas/station-result-v2.schema.json').read_text())
sha='a'*40
v2={
 'schema_version':'2.0','run_id':'run1','station_id':0,'attempt_id':'att1',
 'execution_status':'COMPLETED','policy_verdict':'PASS',
 'identity':{'commit_sha':sha,'environment':'test','scope_hash':'scope'},
 'tool':{'name':'probe','version':'1'},
 'execution':{'argv_digest':'sha256:x','started_at':'2026-10-08T00:00:00Z','ended_at':'2026-10-08T00:00:01Z','actual_exit_code':0,'expected_exit_set':[0],'assertion_verdict':'PASS'},
 'coverage':{'denominator':1,'scanned':1},'finding_ids':[],'artifacts':[]
}
jsonschema.Draft7Validator(schema).validate(v2)
a=GateAggregator({'station0'},sha,'test'); a.add(v2); v2agg=a.aggregate()
old={'station':'station0','outcome':'PASS','sha':sha,'environment':'test'}
b=GateAggregator({'station0'},sha,'test'); b.add(old); oldagg=b.aggregate()
zero=GateAggregator(set(),sha,'test').aggregate()
fd,path=tempfile.mkstemp(prefix='reaudit3-gate-',suffix='.json'); os.close(fd)
Path(path).write_text(json.dumps(oldagg),encoding='utf-8')
os.environ['WENQU_GATE_AGGREGATE']=path
spec=importlib.util.spec_from_file_location('dashserver',ROOT/'system/dashboard/server.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
dash=mod.read_gate_aggregate()
Path(path).unlink()
res={
 'station_v2_schema_valid':True,
 'station_v2_keys':sorted(v2),
 'aggregator_input_documented_keys':['station','outcome','sha','environment'],
 'v2_to_aggregator':v2agg,
 'old_shape_to_aggregator':oldagg,
 'aggregator_output_to_dashboard':dash,
 'zero_denominator':zero,
 'conclusions':[
  '合法 station-result-v2 因无 station/outcome 顶层旧字段被 GateAggregator 记 malformed 并 BLOCKED',
  'GateAggregator 对旧私有结构可 PASS，但输出缺 generated_at/ts 与 policy_verdict/overall/verdict，Dashboard 拒绝',
  '零 required_stations 已改为 BLOCKED，但只修了真空 PASS，未打通正式契约链'
 ]
}
print(json.dumps(res,ensure_ascii=False,indent=2))
# 探针判定：期望暴露断链，满足时 rc=0（发现被成功复现）
assert v2agg['aggregate_outcome']=='BLOCKED' and v2agg['counts']['malformed']==1
assert oldagg['aggregate_outcome']=='PASS'
assert dash['ok'] is False and dash['code']=='AGGREGATOR_MALFORMED'
assert zero['aggregate_outcome']=='BLOCKED' and zero['technical_eligible'] is False

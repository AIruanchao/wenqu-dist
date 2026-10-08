import sys,os,tempfile,json,pathlib,datetime
sys.path.insert(0,'/Users/maccc/Documents/wenqu-dist/system')
from wenqu_core.bugscan_orchestrator import build_station_result
from wenqu_core.gate_aggregator import GateAggregator
valid=build_station_result(
 run_id='run_x',station_id=1,attempt_id='att1',execution_status='COMPLETED',policy_verdict='PASS',
 identity={'commit_sha':'a'*40,'environment':'staging','scope_hash':'scope'},
 tool={'name':'x','version':'1'},
 execution={'argv_digest':'x','started_at':'2026-10-08T00:00:00Z','ended_at':'2026-10-08T00:00:01Z','actual_exit_code':0,'expected_exit_set':[0],'assertion_verdict':'PASS'},
 coverage={'denominator':1,'scanned':1},artifacts=[{'cas_digest':'sha256:'+'b'*64,'size':1}])
agg=GateAggregator({'1'},'a'*40,'staging'); agg.add(valid); out=agg.aggregate()
print('VALID_STATION_V2_KEYS',sorted(valid))
print('AGGREGATOR_ON_VALID_V2',json.dumps(out,ensure_ascii=False,sort_keys=True))
# Add only a fresh timestamp to demonstrate dashboard still rejects aggregator's actual verdict vocabulary
with tempfile.TemporaryDirectory(prefix='reaudit3-contract-') as td:
 p=pathlib.Path(td)/'gate.json'; out['generated_at']=datetime.datetime.now(datetime.timezone.utc).isoformat(); p.write_text(json.dumps(out))
 os.environ['WENQU_GATE_AGGREGATE']=str(p)
 import importlib.util
 spec=importlib.util.spec_from_file_location('dash','/Users/maccc/Documents/wenqu-dist/system/dashboard/server.py')
 m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
 print('DASHBOARD_READ_AGGREGATOR_OUTPUT',m.read_gate_aggregate())

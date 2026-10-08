import json, os, sys, tempfile
from pathlib import Path
sys.path.insert(0, os.path.join(sys.argv[1], 'system'))
from jsonschema import Draft7Validator
from wenqu_core.gate_aggregator import GateAggregator
sha='a'*40
invalid={'schema_version':'2.0','station_id':2,'execution_status':'COMPLETED','policy_verdict':'PASS','identity':{'commit_sha':sha,'environment':'local'}}
schema=json.load(open(Path(sys.argv[1])/'system/schemas/station-result-v2.schema.json'))
schema_ok=Draft7Validator(schema).is_valid(invalid)
agg=GateAggregator({2},sha,'local').add(invalid).aggregate()
td=Path(tempfile.mkdtemp(prefix='reaudit4-agg-')); p=td/'gate.json'; p.write_text(json.dumps(agg))
os.environ['WENQU_GATE_AGGREGATE']=str(p)
# Load dashboard server only after env binding.
import importlib.util
spec=importlib.util.spec_from_file_location('dashserver',Path(sys.argv[1])/'system/dashboard/server.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
dash=m.read_gate_aggregate()
print({'formal_schema_accepts_input':schema_ok,'aggregator_outcome':agg['aggregate_outcome'],'technical_eligible':agg['technical_eligible'],'dashboard_ok':dash['ok'],'counts':agg['counts']})
# Defense should not turn schema-invalid input into technical PASS accepted by dashboard.
raise SystemExit(1 if (not schema_ok and agg['technical_eligible'] and dash['ok']) else 0)

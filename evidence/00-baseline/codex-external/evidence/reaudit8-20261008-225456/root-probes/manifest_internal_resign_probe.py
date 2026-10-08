#!/usr/bin/env python3
import json, os, sys, tempfile, subprocess, hashlib
from pathlib import Path
ROOT=Path('/private/tmp/wenqu-reaudit8-20261008-225456')
sys.path.insert(0,str(ROOT/'system'))
from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope
from wenqu_core.bugscan_orchestrator import BugscanPlanner, default_registry, RunManifest, validate_manifest_consistency

def canon(o): return json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def h(o): return hashlib.sha256(canon(o).encode()).hexdigest()
secret='R8-known-active-manifest-key-0123456789abcdef'
kr=ApprovalKeyring({'key_r8_manifest':secret})
planner=BugscanPlanner(default_registry())
plan=planner.plan('FAST')
with tempfile.TemporaryDirectory(prefix='r8-known-resign-') as td:
    td=Path(td)
    keypath=td/'keyring.json'
    kr.save_json(str(keypath)); os.chmod(keypath,0o600)
    honest=planner.freeze_run_manifest(plan,run_id='r8-honest',project_id='internal/wenqu',commit_sha='67f9aa7370430d2be689c2d217513107c642b4a6',environment='staging',scope=['src/**','tests/**','tools/**'],ruleset={'v':'r8'},data_config={'v':'r8'},signing_keyring=kr,signing_key_id='key_r8_manifest')
    doc=honest.to_dict()
    # 已知 active key 持有者把 FAST 必跑 {0,1} 同步缩成 {0}，保持全部已实现内部一致性。
    doc['required_stations']=[0]
    doc['planner']['required_stations']=[0]
    doc['station_ttls']={'0':doc['station_ttls']['0']}
    # 保持 lane_effective=FAST，不提供任何合法 downgrade；现有一致性校验未与 lane 表/registry 对账。
    doc.pop('manifest_hash',None); doc.pop('signature',None)
    doc['signature']=sign_envelope(secret,doc)
    doc['manifest_hash']=h({k:v for k,v in doc.items() if k!='manifest_hash'})
    mpath=td/'forged-internally-consistent.json'
    mpath.write_text(canon(doc),encoding='utf-8')
    loaded=RunManifest.load(mpath,keyring=ApprovalKeyring.from_path(str(keypath)))
    result=loaded.to_station_result(attempt_id='attempt-r8-forged')
    rpath=td/'station0.json'; rpath.write_text(json.dumps(result,ensure_ascii=False),encoding='utf-8')
    cmd=['bash',str(ROOT/'system/bin/wenquctl'),'gate','--results',str(rpath),'--manifest',str(mpath),'--verify-key',str(keypath)]
    cp=subprocess.run(cmd,text=True,capture_output=True)
    print('HONEST_REQUIRED',list(honest.required_stations))
    print('FORGED_TOP_REQUIRED',doc['required_stations'])
    print('FORGED_PLANNER_REQUIRED',doc['planner']['required_stations'])
    print('FORGED_LANE',doc['planner']['lane_effective'])
    print('FORGED_DROPPED',doc['planner'].get('dropped_stations'))
    print('CONSISTENCY_ISSUES',validate_manifest_consistency(doc))
    print('LOAD_VERIFIED_REQUIRED',list(loaded.required_stations))
    print('CMD',json.dumps(cmd,ensure_ascii=False))
    print('RC',cp.returncode)
    print('STDOUT',cp.stdout.strip())
    print('STDERR',cp.stderr.strip())
    try: out=json.loads(cp.stdout)
    except Exception: out={}
    vulnerable=(cp.returncode==0 and out.get('aggregate_outcome')=='PASS' and out.get('manifest',{}).get('signature',{}).get('verified') is True and out.get('manifest',{}).get('required_stations')==[0])
    print('VULNERABLE',vulnerable)
    raise SystemExit(0 if vulnerable else 1)

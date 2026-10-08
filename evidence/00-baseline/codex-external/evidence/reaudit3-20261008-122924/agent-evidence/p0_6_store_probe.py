#!/usr/bin/env python3
import json,sqlite3,sys,tempfile
from pathlib import Path
ROOT=Path('/Users/maccc/Documents/wenqu-dist'); sys.path.insert(0,str(ROOT/'system'))
from wenqu_core.store import EventStore
from wenqu_core.ledger_migrator import LedgerMigrator
res={}
with tempfile.TemporaryDirectory(prefix='reaudit3-p06-') as td:
 p=Path(td)/'retry.db'
 with EventStore(str(p)) as s:
  h1,i1=s.append({'kind':'A','value':1})
  h2,i2=s.append({'kind':'A','value':1})
  res['consecutive_retry']={'first':[h1,i1],'second':[h2,i2],'verify':s.verify_chain()}
 p2=Path(td)/'intervening.db'
 with EventStore(str(p2)) as s:
  ha,ia=s.append({'kind':'A','value':1})
  hb,ib=s.append({'kind':'B','value':2})
  hr,ir=s.append({'kind':'A','value':1})
  rows=s._conn.execute('select seq,event_id,event_hash,payload from pipeline_events order by seq').fetchall()
  head=s.head(); ver=s.verify_chain()
  res['retry_after_intervening']={'A':[ha,ia],'B':[hb,ib],'retry_A_return':[hr,ir],
    'retry_hash_equals_original':hr==ha,'retry_hash_exists_in_db':any(r[2]==hr for r in rows),
    'rows':rows,'head_method':head,'actual_last_hash':rows[-1][2],'head_is_actual_last':head[0]==rows[-1][2],
    'verify_chain_report':ver}
 # Order 1: EventStore then migrator
 src1=Path(td)/'src1'; src1.mkdir(); (src1/'f.jsonl').write_text('{"status":"PASS","ts":"2026-10-08T00:00:00Z"}\n')
 db1=Path(td)/'order1.db'; EventStore(str(db1)).close(); r1=LedgerMigrator(str(src1),str(db1)).migrate()
 tables1=[r[0] for r in sqlite3.connect(db1).execute("select name from sqlite_master where type='table' order by name")]
 # Order 2: migrator then EventStore
 src2=Path(td)/'src2'; src2.mkdir(); (src2/'f.jsonl').write_text('{"status":"PASS","ts":"2026-10-08T00:00:00Z"}\n')
 db2=Path(td)/'order2.db'; r2=LedgerMigrator(str(src2),str(db2)).migrate(); EventStore(str(db2)).close()
 tables2=[r[0] for r in sqlite3.connect(db2).execute("select name from sqlite_master where type='table' order by name")]
 res['coexistence']={'eventstore_then_migrator':{'report':r1,'tables':tables1},'migrator_then_eventstore':{'report':r2,'tables':tables2}}
res['assessment']={
 'specific_second_round_duplicate_insert_fixed':res['consecutive_retry']['second'][1] is False and res['consecutive_retry']['verify']['length']==1,
 'specific_table_schema_collision_fixed':all({'events','pipeline_events'}.issubset(set(x['tables'])) for x in res['coexistence'].values()),
 'residual_duplicate_return_hash_is_nonexistent':not res['retry_after_intervening']['retry_hash_exists_in_db'],
 'residual_head_is_wrong':not res['retry_after_intervening']['head_is_actual_last'],
 'residual_two_event_tables_not_one_source':True,
}
print(json.dumps(res,ensure_ascii=False,indent=2,default=str))
# Probe passes if both claimed fixes and both residuals are reproduced.
a=res['assessment']; assert all(a.values())

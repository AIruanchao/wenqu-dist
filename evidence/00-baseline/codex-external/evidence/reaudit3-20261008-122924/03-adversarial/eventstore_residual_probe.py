import os,sys,tempfile,sqlite3,json,pathlib
sys.path.insert(0,'/Users/maccc/Documents/wenqu-dist/system')
from wenqu_core.store import EventStore
from wenqu_core.ledger_migrator import LedgerMigrator
with tempfile.TemporaryDirectory(prefix='reaudit3-store-') as td:
  db=os.path.join(td,'events.db'); led=os.path.join(td,'led'); os.mkdir(led)
  open(os.path.join(led,'a.jsonl'),'w').write('{"status":"OPEN","ts":"2026-01-01T00:00:00Z"}\n')
  s=EventStore(db)
  h1,i1=s.append({'kind':'A','value':1})
  hb,ib=s.append({'kind':'B','value':2})
  h1retry,i1retry=s.append({'kind':'A','value':1})
  rows=s._conn.execute('select seq,event_id,event_hash,prev_event_hash,payload from pipeline_events order by seq').fetchall()
  print('INSERT_FLAGS',i1,ib,i1retry,'ROW_COUNT',len(rows))
  print('ORIGINAL_HASH',h1)
  print('RETRY_RETURN_HASH',h1retry)
  print('RETRY_HASH_EXISTS',any(r[2]==h1retry for r in rows))
  print('HEAD_API',s.head(),'ACTUAL_LAST',rows[-1][2], 'COUNT',len(rows))
  print('CHAIN',s.verify_chain())
  s.close()
  m=LedgerMigrator(led,db); print('MIGRATE',m.migrate()['conservation'])
  c=sqlite3.connect(db)
  print('TABLES',[r[0] for r in c.execute("select name from sqlite_master where type='table' order by name")])
  print('EVENT_COUNTS',c.execute('select count(*) from pipeline_events').fetchone()[0], c.execute('select count(*) from events').fetchone()[0])

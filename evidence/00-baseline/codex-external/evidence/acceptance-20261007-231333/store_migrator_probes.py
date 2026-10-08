import json, tempfile
from pathlib import Path
from wenqu_core.store import EventStore
from wenqu_core.ledger_migrator import LedgerMigrator

out={}
with tempfile.TemporaryDirectory() as td:
    db=str(Path(td)/"e.db")
    with EventStore(db) as s:
        h1,_=s.append({"n":1}); h2,_=s.append({"n":2})
        hh,n=s.head()
        out["head_after_two"]={"count":n,"head_equals_latest":hh==h2,"head_equals_first":hh==h1}
with tempfile.TemporaryDirectory() as td:
    td=Path(td); src=td/"src"; src.mkdir()
    (src/"l.jsonl").write_text('{"status":"PASS","ts":"2026-10-07T00:00:00Z"}\n')
    db=str(td/"same.db")
    err=None
    with EventStore(db) as s:
        s.append({"n":1})
    try: LedgerMigrator(str(src),db).migrate()
    except Exception as e: err=f"{type(e).__name__}: {e}"
    out["store_then_migrator"]={"error":err}
with tempfile.TemporaryDirectory() as td:
    td=Path(td); src=td/"src"; src.mkdir()
    (src/"l.jsonl").write_text('{"status":"PASS","ts":"2026-10-07T00:00:00Z"}\n')
    db=str(td/"same.db"); LedgerMigrator(str(src),db).migrate()
    err=None
    try:
        with EventStore(db) as s: s.append({"n":1})
    except Exception as e: err=f"{type(e).__name__}: {e}"
    out["migrator_then_store"]={"error":err}
print(json.dumps(out,ensure_ascii=False,indent=2,sort_keys=True))

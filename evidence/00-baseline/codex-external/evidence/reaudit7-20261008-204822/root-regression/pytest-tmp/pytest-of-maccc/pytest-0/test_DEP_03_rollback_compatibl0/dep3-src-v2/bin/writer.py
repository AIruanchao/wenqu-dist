#!/usr/bin/env python3
import sys
sys.path.insert(0, '/private/tmp/wenqu-reaudit7-20261008-204822/system')
from wenqu_core.store import EventStore
store = EventStore(sys.argv[1])
event_hash, inserted = store.append({
    "kind": "business-event", "era": sys.argv[2], "n": int(sys.argv[3])})
store.close()
sys.stdout.write(event_hash)

#!/usr/bin/env python3
# 冻结在 release 内的兼容读取器：只依赖 pipeline_events 稳定 schema
import json, sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
rows = conn.execute(
    "SELECT seq, payload FROM pipeline_events ORDER BY seq").fetchall()
conn.close()
print(json.dumps({"count": len(rows), "events": [json.loads(p) for _, p in rows]}))

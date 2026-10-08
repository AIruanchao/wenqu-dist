#!/usr/bin/env python3
import os
import subprocess

needle = "auto" + "-merge.sh"
me = os.getpid()
parent = os.getppid()
out = subprocess.check_output(["ps", "-axo", "pid=,ppid=,command="], text=True)
hits = []
for line in out.splitlines():
    parts = line.strip().split(None, 2)
    if len(parts) != 3:
        continue
    pid, ppid, cmd = int(parts[0]), int(parts[1]), parts[2]
    if pid in {me, parent}:
        continue
    if needle in cmd:
        hits.append({"pid": pid, "ppid": ppid, "command": cmd})
print({"needle": needle, "hits": hits, "count": len(hits)})
raise SystemExit(1 if hits else 0)

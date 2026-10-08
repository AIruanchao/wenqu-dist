#!/usr/bin/env python3
"""独立反证 UI-07 超大日志的字节上界（tail -n 对病态单行无界）。"""
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path.cwd()
SERVER = ROOT / "system" / "dashboard" / "server.py"
SOURCE_BYTES = 6 * 1024 * 1024

with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]

with tempfile.TemporaryDirectory(prefix="reaudit7-ui07-") as td:
    home = Path(td)
    (home / "logs").mkdir(parents=True)
    pth = home / "logs" / "one-huge-line.log"
    pth.write_bytes(b"X" * SOURCE_BYTES + b"\n")
    env = dict(os.environ, WENQU_HOME=str(home))
    p = subprocess.Popen([sys.executable, str(SERVER), "--port", str(port)],
                         cwd=ROOT, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                c.request("GET", "/api/v1/ping",
                          headers={"Host": f"127.0.0.1:{port}"})
                if c.getresponse().status == 200:
                    break
            except OSError:
                time.sleep(0.05)
        t0 = time.monotonic()
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        c.request("GET", "/api/v1/logs",
                  headers={"Host": f"127.0.0.1:{port}"})
        r = c.getresponse()
        body = r.read()
        elapsed = time.monotonic() - t0
        out = {
            "source_bytes": pth.stat().st_size,
            "source_lines": 1,
            "status": r.status,
            "response_bytes": len(body),
            "content_length": int(r.getheader("Content-Length") or -1),
            "elapsed_seconds": round(elapsed, 6),
            "response_over_1MiB": len(body) > 1024 * 1024,
        }
        print(json.dumps(out, ensure_ascii=False, indent=2))
        if r.status == 200 and len(body) > 1024 * 1024:
            print("UI07_SINGLE_LINE_RESULT=GAP_UNBOUNDED_BYTES")
        else:
            print("UI07_SINGLE_LINE_RESULT=BOUNDED")
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(timeout=5)

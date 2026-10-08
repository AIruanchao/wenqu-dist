#!/usr/bin/env python3
"""独立反证 UI-06“未认证日志读取→拒绝”是否存在真实认证门。"""
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
MARKER = "REAUDIT7-UI06-NOAUTH-SENSITIVE-7d31"

with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]

with tempfile.TemporaryDirectory(prefix="reaudit7-ui06-") as td:
    home = Path(td)
    (home / "logs").mkdir(parents=True)
    (home / "logs" / "sensitive.log").write_text(MARKER + "\n", encoding="utf-8")
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
        # 故意不发送 Authorization/Cookie/API key，仅合法 Host。
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/api/v1/logs",
                  headers={"Host": f"127.0.0.1:{port}"})
        r = c.getresponse()
        body = r.read()
        out = {
            "request_authorization_header": None,
            "request_cookie_header": None,
            "status": r.status,
            "sensitive_marker_returned": MARKER.encode() in body,
            "body_head": body[:300].decode("utf-8", "replace"),
        }
        print(json.dumps(out, ensure_ascii=False, indent=2))
        if r.status == 200 and MARKER.encode() in body:
            print("UI06_UNAUTH_LOG_RESULT=GAP_FALSE_GREEN")
        else:
            print("UI06_UNAUTH_LOG_RESULT=EXPECTED_REJECT")
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(timeout=5)

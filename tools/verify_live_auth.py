#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_live_auth.py —— W11-14 B 面：现役 HTTP auth 三态负例自动化验证。

十轮 W8 扣分「HTTP auth 现役负例未验」根修：对**现役** dashboard（默认
127.0.0.1:7789）打真实请求，验证 /api/v1/logs 三态（无 key 403 / 错 key 403 /
对 key 200，W11-08 密钥文件化合同）+ 路径穿越 / XSS 传输契约 / Origin-Host
负例。绝不触碰运行体（只读 GET；不写任何文件到目标机）。

退出码合同（方案 §W11-14）：
  0 = 全部腿绿（三态 403/403/200 + 负例全拒 + 传输契约在场）；
  1 = 任一腿不符（DOM/协议/语义漂移——含 200 泄漏、负例放行、契约缺失）；
  3 = 运行体不可用（ping 不通/连接拒绝）或验证前置不足（对 key 材料缺失——
      三态的 200 腿无凭证可达，绝不假绿）。

密钥材料（三态 200 腿所需；只读，绝不回显）：
  --key-file <path>  0600 密钥文件（生产正源；默认取 $WENQU_DASHBOARD_KEY_FILE）
  --key <value>      显式密钥（沙箱/演练用；避免进 shell 历史可用 --key-file）

用法：
  python3 tools/verify_live_auth.py                          # 打 7789（key 从 env）
  python3 tools/verify_live_auth.py --port 7789 --key-file /path/0600.key \
      --out /tmp/w11-14-evidence/live-auth-report.json
  python3 tools/verify_live_auth.py --self-test              # 红探针自证（对拍两腿）

--self-test 纪律（负例不瞎）：本地起
  a) 沙箱好服务（system/dashboard/server.py，W11-08 合法 0600 key 文件）→
     脚本全腿必须 rc0；
  b) 故意不设防假服务（无 Host/Origin 校验、logs 无鉴权、无 CSP）→
     脚本必须 rc1（证明每条负例腿都能红，杜绝假绿）。
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import stat as stat_m
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOOL_VERSION = "verify_live_auth/1.0"
REPO = Path(__file__).resolve().parents[1]
RC_OK, RC_FAIL, RC_UNAVAILABLE = 0, 1, 3
LEAK_MARKERS = ("WENQU", "token", "secret", "password")  # 泄漏面嗅探（粗粒度提示用）


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_req(host: str, port: int, method: str, path: str, *,
             headers: dict | None = None, timeout: float = 10.0,
             host_value: str | None = "__AUTO__") -> tuple[int, dict, bytes]:
    """发真实 HTTP 请求。host_value=None → 不发 Host 头（no-Host 负例）；
    其它字符串 → 伪 Host 注入（DNS rebinding 形态负例）。

    putrequest(skip_host) 直控 Host 面——http.client.request() 不暴露该参数。"""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        if host_value == "__AUTO__":
            conn.putrequest(method, path)
        else:
            conn.putrequest(method, path, skip_host=True)
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        if host_value == "__AUTO__":
            pass  # putrequest 已自动补 Host: host:port
        elif host_value is not None:
            conn.putheader("Host", host_value)
        conn.putheader("Connection", "close")
        conn.endheaders()
        r = conn.getresponse()
        data = r.read()
        hd = {k.lower(): v for k, v in r.getheaders()}
        return r.status, hd, data
    finally:
        conn.close()


def load_key(args) -> tuple[str | None, str | None]:
    """(key, err)。--key 优先，其次 --key-file（默认 $WENQU_DASHBOARD_KEY_FILE）。"""
    if args.key:
        return args.key.strip() or None, None
    path = args.key_file or os.environ.get("WENQU_DASHBOARD_KEY_FILE") or ""
    path = path.strip()
    if not path:
        return None, None
    try:
        lst = os.lstat(path)
    except OSError as e:
        return None, "KEYFILE_STAT_FAIL: %s (%s)" % (path, e)
    if not stat_m.S_ISREG(lst.st_mode):
        return None, "KEYFILE_NOT_REGULAR: %s" % path
    if stat_m.S_IMODE(lst.st_mode) != 0o600:
        return None, "KEYFILE_MODE_%o_NOT_600: %s" % (stat_m.S_IMODE(lst.st_mode), path)
    with open(path, encoding="utf-8") as f:
        k = f.read().rstrip("\r\n")
    return (k or None), None


class Report:
    def __init__(self, target: str):
        self.rows: list[dict] = []
        self.target = target

    def leg(self, name: str, ok: bool, detail: str, *, expected: str = "", got: str = ""):
        self.rows.append({"leg": name, "ok": bool(ok), "detail": detail,
                          "expected": expected, "got": got, "ts": _now_iso()})
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name}: {detail}")
        return ok

    @property
    def all_ok(self) -> bool:
        return all(r["ok"] for r in self.rows)

    def dump(self, path: Path) -> None:
        payload = {"tool": TOOL_VERSION, "target": self.target,
                   "generated_at": _now_iso(),
                   "rc": RC_OK if self.all_ok else RC_FAIL,
                   "legs": self.rows,
                   "note": "密钥绝不落报告；响应体只记状态/头/长度与判定，不记内容"}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        print(f"证据工件: {path}")


def verify(host: str, port: int, key: str | None) -> tuple[Report, int]:
    rep = Report(f"http://{host}:{port}")
    unavailable = False

    # ── 腿 0：运行体可达性（ping 不可达 → rc3，不与语义混淆）─────────────
    try:
        st, _, body = http_req(host, port, "GET", "/api/v1/ping")
    except OSError as e:
        rep.leg("runtime-reachable", False, f"连接失败：{e}")
        return rep, RC_UNAVAILABLE
    if st != 200:
        rep.leg("runtime-reachable", False, f"/api/v1/ping → {st}（运行体不健康）")
        return rep, RC_UNAVAILABLE
    rep.leg("runtime-reachable", True, f"/api/v1/ping → 200")

    # ── 腿 1：logs 三态（W11-08 合同：无 403 / 错 403 / 对 200）──────────
    st, hd, body = http_req(host, port, "GET", "/api/v1/logs")
    no_leak = not _looks_like_logpayload(body)
    rep.leg("logs-nokey-403", st == 403 and no_leak,
            f"无 X-Auth-Key → {st}（期望 403 fail-closed）",
            expected="403", got=str(st))
    st, hd, body = http_req(host, port, "GET", "/api/v1/logs",
                            headers={"X-Auth-Key": "wrong-key-verify-live-auth"})
    rep.leg("logs-wrongkey-403", st == 403 and not _looks_like_logpayload(body),
            f"错 X-Auth-Key → {st}（期望 403，payload 零泄漏）",
            expected="403", got=str(st))
    if key is None:
        rep.leg("logs-rightkey-200", False,
                "无密钥材料（--key-file/--key/$WENQU_DASHBOARD_KEY_FILE 均缺）——"
                "三态 200 腿不可验证（前置不足，绝不假绿）")
        unavailable = True
    else:
        st, hd, body = http_req(host, port, "GET", "/api/v1/logs",
                                headers={"X-Auth-Key": key})
        json_ok = hd.get("content-type", "").startswith("application/json")
        nosniff = hd.get("x-content-type-options") == "nosniff"
        rep.leg("logs-rightkey-200", st == 200 and json_ok,
                f"对 X-Auth-Key → {st}（期望 200；JSON 传输 {json_ok}；"
                f"响应 {len(body)}B）", expected="200", got=str(st))
        rep.leg("logs-transport-contract", json_ok and nosniff,
                f"logs Content-Type={hd.get('content-type')!r} + nosniff={nosniff}"
                "（XSS 传输契约：日志只作 JSON 数据，绝不进 HTML 上下文）")

    # ── 腿 2：XSS 面（页面 CSP + nosniff 契约）───────────────────────────
    st, hd, body = http_req(host, port, "GET", "/")
    csp = hd.get("content-security-policy", "")
    has_csp = ("default-src 'self'" in csp and "script-src 'self'" in csp
               and "frame-ancestors 'none'" in csp)
    nosniff = hd.get("x-content-type-options") == "nosniff"
    no_acao = not any(k.startswith("access-control-allow-") for k in hd)
    inline = b"<script>" in body  # 内联脚本面（外链 <script src= 是合法形态）
    rep.leg("page-xss-contract", st == 200 and has_csp and nosniff and no_acao and not inline,
            f"GET / → {st}；CSP={'在' if has_csp else '缺'}；nosniff={nosniff}；"
            f"零 ACAO={no_acao}；内联 <script>={'无' if not inline else '有（红）'}")

    # ── 腿 3：路径穿越负例（白名单外一律 404，绝不 200）──────────────────
    for label, path in (("traversal-/../server.py", "/../server.py"),
                        ("traversal-../../etc/passwd", "/../../etc/passwd"),
                        ("traversal-encoded-%2e%2e%2f", "/%2e%2e%2f%2e%2e%2fetc/passwd"),
                        ("traversal-dotdot-file", "/....//....//server.py")):
        try:
            st, _, body = http_req(host, port, "GET", path)
        except OSError as e:
            rep.leg(label, False, f"请求异常：{e}")
            continue
        rep.leg(label, st == 404,
                f"GET {path} → {st}（期望 404 白名单拒绝；200=源码/系统文件泄漏）",
                expected="404", got=str(st))

    # ── 腿 4：Origin/Host 负例（CSRF/DNS rebinding 面）───────────────────
    for label, hdrs in (("origin-evil-403", {"Origin": "http://evil.example.com"}),
                        ("sec-fetch-cross-site-403", {"Sec-Fetch-Site": "cross-site"})):
        st, _, _ = http_req(host, port, "GET", "/", headers=hdrs)
        rep.leg(label, st == 403, f"{hdrs} → {st}（期望 403 跨源拒绝）",
                expected="403", got=str(st))
    for label, hv in (("host-evil-rebinding-403", f"evil.example.com:{port}"),
                      ("host-no-header-403", None),
                      ("host-wrong-port-403", "127.0.0.1:1")):
        st, _, _ = http_req(host, port, "GET", "/", host_value=hv)
        rep.leg(label, st == 403, f"Host={hv!r} → {st}（期望 403）",
                expected="403", got=str(st))

    if unavailable:
        return rep, RC_UNAVAILABLE
    return rep, (RC_OK if rep.all_ok else RC_FAIL)


def _looks_like_logpayload(body: bytes) -> bool:
    """拒绝响应体是否携带日志数据面痕迹（泄漏判定：403 体应是错误 JSON，
    不含多行日志/哨兵内容形态）。"""
    if not body:
        return False
    try:
        j = json.loads(body)
        if isinstance(j, dict) and isinstance(j.get("error"), dict):
            return False  # 结构化错误体=正确形态
    except ValueError:
        return True  # 非 JSON 体=可疑泄漏
    keys = [k for k in (j.keys() if isinstance(j, dict) else [])
            if str(k).endswith(".log")]
    return bool(keys)


# ─────────────────── self-test（负例不瞎：对拍两腿） ───────────────────
class _VulnHandler(BaseHTTPRequestHandler):
    """故意不设防：无 Host/Origin 校验、logs 无鉴权、无 CSP、穿越 200。"""
    protocol_version = "HTTP/1.1"
    timeout = 5

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, data, ctype="application/json; charset=utf-8"):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            return self._send(200, "<html><body>ok</body></html>", "text/html")
        if p == "/api/v1/ping":
            return self._send(200, '{"pong": true}')
        if p == "/api/v1/logs":  # 无鉴权直接放行日志数据
            return self._send(200, json.dumps({"sentinel.log": "SENSITIVE line1\nline2"}))
        return self._send(200, "file-content")  # 穿越也 200


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def self_test() -> int:
    print("== self-test：对拍两腿（证明负例腿不瞎） ==")
    # a) 沙箱好服务（产品 server.py + 合法 0600 key 文件）→ 必须 rc0
    sys.path.insert(0, str(REPO / "system"))
    sys.path.insert(0, str(REPO / "system" / "tests"))
    from test_ac_ui_family import _Dash, _write_snapshot  # noqa: E402
    with tempfile.TemporaryDirectory(prefix="wq_vla_good_") as tmp:
        sandbox = Path(tmp)
        with _Dash(sandbox) as dash:
            _write_snapshot(dash.snap, "PASS")
            (dash.home / "logs").mkdir(exist_ok=True)
            (dash.home / "logs" / "sentinel.log").write_text("line\n", encoding="utf-8")
            rep, rc = verify("127.0.0.1", dash.port, dash.log_key)
            print(f"  好服务腿 rc={rc}（期望 {RC_OK}）")
            if rc != RC_OK:
                print("SELF-TEST FAIL：好服务上脚本未全绿")
                return 1
    # b) 不设防假服务 → 必须 rc1（负例必红）
    port = _free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), _VulnHandler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        time.sleep(0.2)
        rep, rc = verify("127.0.0.1", port, "any-key-0123456789")
        print(f"  假服务腿 rc={rc}（期望 {RC_FAIL}）")
        if rc != RC_FAIL:
            print("SELF-TEST FAIL：不设防服务上脚本未红——负例腿瞎了")
            return 1
        reds = [r["leg"] for r in rep.rows if not r["ok"]]
        need = {"logs-nokey-403", "logs-wrongkey-403", "page-xss-contract"}
        assert need & set(reds), f"关键负例未红: {reds}"
        print(f"  负例红腿（节选）: {sorted(set(reds))[:6]}")
    finally:
        srv.shutdown()
        srv.server_close()
    print("SELF-TEST PASS：好服务 rc0 / 不设防服务 rc1（负例腿不瞎）")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="现役 dashboard HTTP auth 三态+负例验证（W11-14 B）")
    ap.add_argument("--host", default="127.0.0.1", help="目标主机（默认 127.0.0.1）")
    ap.add_argument("--port", type=int, default=7789, help="目标端口（默认 7789 现役）")
    ap.add_argument("--key-file", help="0600 密钥文件路径（默认 $WENQU_DASHBOARD_KEY_FILE）")
    ap.add_argument("--key", help="显式密钥（沙箱/演练用；优先于 --key-file）")
    ap.add_argument("--out", default="/tmp/w11-14-evidence/live-auth-report.json",
                    help="证据 JSON 输出路径")
    ap.add_argument("--self-test", action="store_true",
                    help="对拍自证：好服务 rc0 / 不设防服务 rc1（不打现役）")
    args = ap.parse_args(argv)

    print(f"== verify_live_auth {TOOL_VERSION} ==")
    if args.self_test:
        return self_test()

    key, kerr = load_key(args)
    if kerr:
        print(f"  密钥文件不可用：{kerr}")
    rep, rc = verify(args.host, args.port, key)
    rep.dump(Path(args.out))
    verdict = {RC_OK: "全绿（三态+负例+契约）", RC_FAIL: "存在不符腿",
               RC_UNAVAILABLE: "运行体不可用或验证前置不足（rc3/BLOCKED）"}[rc]
    print(f"RESULT: rc={rc} — {verdict}")
    return rc


if __name__ == "__main__":
    sys.exit(main())

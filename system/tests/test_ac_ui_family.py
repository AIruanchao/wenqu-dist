#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——UI 族七条（P1f 接入件；W8 UI 面激活）。

覆盖 §20.4/§20.5 中 UI 前缀全部 7 个验收 ID（注入/期望逐字对齐
evidence/00-baseline/codex-external/方案.md §20 表格）：

    UI-01  少一个闭合标签                          -> 构建/启动门失败
    UI-02  XSS 日志/账本文本                       -> 不执行
    UI-03  CSRF/伪 Origin/text/plain 写入           -> 拒绝
    UI-04  Gate 红、其他项高分                      -> 总体 BLOCKED
    UI-05  ACCEPTED/OTHER/quarantine               -> 均可钻取
    UI-06  DNS rebinding/伪 Host/未认证日志读取      -> 拒绝
    UI-07  慢请求/高并发/超大日志                    -> 不耗尽资源

方法级别（按可用性降级，如实记录）：Playwright 探测失败（python3 -c "import
playwright" ModuleNotFoundError）→ 全族降级为 **L2：HTTP+DOM 解析级**：
  - 被测体 = 真实产品面：system/dashboard/server.py（子进程、临时随机端口、
    沙箱化 WENQU_* 环境；绝不触碰 7789 运行时）+ index.html/app.js 静态契约 +
    产品自带 --self-check 启动自检门。
  - 探测面 = system/wenqu_core/ui_probe.py（构建门/协议面探针/同水位探针/
    钻取探针/限速探针；零第三方依赖）。
  - 负例纪律（红探针）：对每个激活面，另起「故意脆弱的假服务」注入对应缺陷，
    断言探针必报——证明探测面不瞎，杜绝假绿。
浏览器级（真实渲染执行/点击链/目视读数）在本机不可得，逐条登记
not_implementable（见证据 JSON 与模块 docstring 诚实边界）。

运行：python3 system/tests/test_ac_ui_family.py   （独立 exit 0 = 全绿）
证据：evidence/04-unit-property-mutation/ac-ui-family.json（每次运行覆写）。

诚实边界（不以假绿硬凑）：
  1. UI-02「不执行」的终极证明是真实浏览器渲染执行环境；本件以传输契约
     （application/json + nosniff，payload 作为数据无损往返）+ CSP 契约
     （响应头与 meta 双写、script-src 'self' 禁内联）+ 前端源码契约
     （零 innerHTML/insertAdjacentHTML/document.write/eval 注入 API +
     textContent 渲染）三层等价收窄；浏览器执行未验证。
  2. UI-04 的浏览器侧同水位目视读数（总览页人眼看到的判定）未验证；
     已证 API 同水位（verdict/score/watermark 逐字透传）+ 前端判定优先级
     源码契约（policy_verdict 优先、失败渲染 errBox 绝不伪绿）。
  3. UI-05「quarantine 钻取」：dashboard 状态机无 quarantine 表面（账本 fold
     静默跳过非法行，无隔离区 UI）；ACCEPTED/OTHER 的 DOM 节点在当前 app.js
     中无 click 接线（仅五链状态可点）。已激活 API 钻取（?items=STATE 计数与
     明细一致性）+ 静态契约；浏览器点击链与 quarantine 表面登记未验证。
  4. UI-06「DNS rebinding」需真实 DNS 解析+浏览器宿主；本件在协议级验证其
     产品防御（Host 白名单：伪 Host/无 Host/错端口 Host 全 403，数据面不可达）。
  5. UI-07 慢请求防御实测为 15s 连接读超时（REQUEST_TIMEOUT）；「超大日志」
     的产品界是行数界（tail -n 20/文件）而非字节界——病态单行超长文件可产生
     大响应，登记为观察项（本任务不改产品面）。
  6. UI-01「构建/启动门」以产品 --self-check 自检门 + ui_probe 构建门承载并
     实证红/绿；server 常驻启动路径未强制每次 serve 前自动跑门（登记观察项）。
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]          # wenqu-dist/
SYSTEM = REPO / "system"
sys.path.insert(0, str(SYSTEM))

from wenqu_core.ui_probe import (                     # noqa: E402
    UIFinding,
    build_gate,
    html_structural_gate,
    probe_health_watermark,
    probe_http_surface,
    probe_ledger_drill,
    probe_rate_guard,
    raw_request,
    static_dom_contract,
)

EVIDENCE_PATH = REPO / "evidence" / "04-unit-property-mutation" / "ac-ui-family.json"
DASH = SYSTEM / "dashboard"

_RESULTS: dict = {}
_METHOD_LEVEL = "L2-HTTP-DOM"

_NOT_IMPLEMENTABLE = [
    {
        "id": "UI-02",
        "gap": "真实浏览器渲染执行环境（chromium headless）内 XSS payload 不执行的终证",
        "reason": "Playwright 不可用（import playwright ModuleNotFoundError）；"
                  "本机无浏览器自动化通道",
        "mitigation": "三层等价链已证：JSON+nosniff 传输契约 / CSP 响应头+meta 双写禁内联 / "
                      "前端零注入 API+textContent 源码契约；负例假服务上的内联脚本/注入 API "
                      "面被探针必报",
    },
    {
        "id": "UI-04",
        "gap": "浏览器侧同水位目视读数（总览页渲染出的判定与权威一致）",
        "reason": "无浏览器渲染通道；API 同水位与前端源码判定优先级契约已证",
        "mitigation": "verdict/score/watermark 逐字透传断言 + app.js 判定优先级"
                      "（policy_verdict||overall||verdict）与 errBox 失败路径源码契约",
    },
    {
        "id": "UI-05",
        "gap": "quarantine 状态的 UI 钻取表面；ACCEPTED/OTHER 节点的浏览器点击链",
        "reason": "产品语义缺失：dashboard 状态机无 quarantine 表面（fold 静默跳过非法行，"
                  "无隔离区查询端点）；app.js 中 ACCEPTED/OTHER 计数节点无 click 接线"
                  "（仅 OPEN/FIXING/FIXED/VERIFIED/CLOSED 五链状态可点）",
        "mitigation": "API 钻取已真激活（?items=ACCEPTED/OTHER 计数与明细一致、非法行不炸"
                      "不计数）；静态契约证明钻取通道与两状态节点存在；浏览器点击链待 UI "
                      "交互面产品化后补",
    },
    {
        "id": "UI-06",
        "gap": "真实 DNS rebinding 攻击链（攻击者域名解析到回环+浏览器宿主）",
        "reason": "需真实 DNS 栈与浏览器；单测沙箱不可复现",
        "mitigation": "协议级验证其唯一产品防御点：Host 白名单（伪 Host/无 Host/错端口 "
                      "Host 全 403 且日志数据面不可达）+ Origin/Sec-Fetch-Site 拒绝；"
                      "负例假服务无 Host 校验被探针必报",
    },
]


# ---------------------------------------------------------------------------
# 通用小工具（不含任何 §20 ID 字面量，避免追踪矩阵误归属）
# ---------------------------------------------------------------------------
def _record(test_id: str, detail: str) -> None:
    _RESULTS[test_id] = {"pass": True, "detail": detail, "method": _METHOD_LEVEL}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_snapshot(path: Path, verdict: str, *, score=87, age_seconds: float = 0.0) -> str:
    ts = datetime.now(timezone.utc).timestamp() - age_seconds
    gen = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "generated_at": gen, "policy_verdict": verdict,
        "aggregate_outcome": verdict, "score": score, "reason": "ui-family probe",
        "counts": {"total": 131, "passed": 130},
        "stations": {f"S{i}": {"verdict": "PASS", "score": 95 + i % 5} for i in range(1, 8)},
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return gen


class _Dash:
    """在随机空闲端口起 system/dashboard/server.py 子进程（沙箱化环境，退出清理）。"""

    def __init__(self, sandbox: Path, *, ttl_seconds: int = 1800):
        self.sandbox = sandbox
        self.snap = sandbox / "gate-aggregate.json"
        self.home = sandbox / "wenqu-home"
        self.ledger_root = sandbox / "bugscan-ledger"
        self.port = _free_port()
        self.ttl = ttl_seconds
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "_Dash":
        self.home.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ,
                   WENQU_HOME=str(self.home),
                   WENQU_GATE_AGGREGATE=str(self.snap),
                   WENQU_AGGREGATE_TTL=str(self.ttl),
                   WENQU_BUGSCAN_LEDGER=str(self.ledger_root),
                   WENQU_HEALTH_HISTORY=str(self.sandbox / "history.jsonl"),
                   WENQU_DECISIONS=str(self.sandbox / "decisions.jsonl"),
                   WENQU_LEDGER=str(self.sandbox / "rounds.jsonl"),
                   WENQU_REPO_DIR=str(self.sandbox))
        self.proc = subprocess.Popen(
            [sys.executable, str(DASH / "server.py"), "--port", str(self.port)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(self.sandbox))
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(f"dashboard server 提前退出 rc={self.proc.returncode}")
            try:
                st, _, _ = raw_request("127.0.0.1", self.port, "GET", "/api/v1/ping")
                if st == 200:
                    return self
            except OSError:
                pass
            time.sleep(0.15)
        raise AssertionError("dashboard server 15s 内未就绪")

    def __exit__(self, *exc) -> None:
        if self.proc is None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


def _selfcheck_in(dirpath: Path) -> subprocess.CompletedProcess:
    """在给定目录（dashboard 副本）上跑产品自带 --self-check 启动自检门。"""
    port = _free_port()
    env = dict(os.environ,
               WENQU_HOME=str(dirpath / "wh"),
               WENQU_GATE_AGGREGATE=str(dirpath / "no-snapshot.json"),
               WENQU_DECISIONS=str(dirpath / "dec.jsonl"),
               WENQU_LEDGER=str(dirpath / "rounds.jsonl"),
               WENQU_REPO_DIR=str(dirpath))
    return subprocess.run(
        [sys.executable, str(dirpath / "server.py"), "--self-check", "--port", str(port)],
        capture_output=True, text=True, timeout=180, cwd=str(dirpath), env=env)


def _copy_dashboard(dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for f in ("index.html", "app.css", "app.js", "server.py"):
        shutil.copy2(DASH / f, dst / f)


# ---------------------------------------------------------------------------
# 负例脚手架：故意脆弱的假服务（红探针——探针必须报出每一个注入缺陷）
# ---------------------------------------------------------------------------
_VULN_HTML = (
    '<!DOCTYPE html>\n<html><head><meta charset="utf-8"><title>vuln</title>\n'
    '<script>alert("inline-xss")</script>\n'
    '<style>body { background: #fff }</style>\n'
    '</head>\n<body onload="boot()">\n'
    '<div id="ov"><p>overview</p>\n'
    '<div onclick="steal()">click me</div>\n'
    '</body></html>\n')

_VULN_JS = (
    'document.getElementById("out").innerHTML = window.__payload;\n'
    'eval(window.__payload);\n')


class _VulnHandler(BaseHTTPRequestHandler):
    """无 Host/Origin 校验、无安全头、内联脚本、写接口全开、自算健康度、无限制速。"""
    protocol_version = "HTTP/1.1"
    timeout = 2  # 防 Content-Length 注入探针挂死

    def log_message(self, fmt, *args):  # 静音
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
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(200, _VULN_HTML, "text/html; charset=utf-8")
        if path == "/app.js":
            return self._send(200, _VULN_JS, "application/javascript")
        if path == "/app.css":
            return self._send(200, "body{color:red}", "text/css; charset=utf-8")
        if path == "/api/v1/ping":
            return self._send(200, '{"pong": true}')
        if path == "/api/v1/logs":
            return self._send(200, '{"vuln.log": "SENSITIVE-LOG-PAYLOAD token=secret"}')
        if path == "/api/v1/health":  # 自算洗绿：无视权威快照永远 PASS
            return self._send(200, json.dumps(
                {"policy_verdict": "PASS", "score": 99,
                 "generated_at": "2026-01-01T00:00:00Z", "source": "self-computed"}))
        if path == "/api/v1/bugscan-ledger":
            if "items=" in self.path:  # 钻取语义破坏：任意状态都回 OPEN 明细+假计数
                return self._send(200, json.dumps({
                    "items_state": "OPEN", "items_total": 7,
                    "items": [{"st": "OPEN", "id": "V-1", "sev": "HIGH", "title": "x",
                               "proj": "p", "stale": False, "ts": "2026-10-01"}]}))
            return self._send(200, json.dumps({
                "available": True,
                "projects": [{"key": "p", "findings": 5,
                              "by_status": {"OPEN": 3, "ACCEPTED": 1, "OTHER": 1},
                              "by_sev": {}, "last_ts": ""}],
                "total": {"findings": 5, "by_status": {"OPEN": 3, "ACCEPTED": 1, "OTHER": 1},
                          "by_sev": {}, "last_ts": ""},
                "open_total": 3, "open_items": [], "stale_open": 0}))
        return self._send(200, "ok")  # 任意路径 200：白名单/版本化全失（含 /../server.py）

    def do_OPTIONS(self):  # CORS 预检放行
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):  # 写接口全开：任意 Content-Type 全收 200
        n = int(self.headers.get("Content-Length") or 0)
        if n > 0:
            try:
                self.rfile.read(n)
            except OSError:
                return
        return self._send(200, '{"ok": true}')


class _VulnServer:
    """进程内假服务（随机端口）；用于证明探针对每个注入缺陷必报。"""

    def __init__(self):
        self.port = _free_port()
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), _VulnHandler)
        self.srv.daemon_threads = True
        self.th = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self) -> "_VulnServer":
        self.th.start()
        return self

    def __exit__(self, *exc) -> None:
        self.srv.shutdown()
        self.srv.server_close()


def _codes(findings: list) -> set:
    return {f.code for f in findings}


# ---------------------------------------------------------------------------
# UI 族七条
# ---------------------------------------------------------------------------
def test_UI_01_missing_closing_tag_fails_build_and_startup_gate():
    """UI-01 | 注入: 少一个闭合标签 | 期望: 构建/启动门失败。

    三腿：产品 --self-check 启动自检门（真进程、临时端口）红/绿对照；
    ui_probe 构建门（parser 级标签闭合栈）对四种破损形态必报、对真件零误报；
    parser 门比产品字符串计数门严格（</span> 缺失产品漏报、探针必报）。
    """
    # 腿 1：产品自带启动自检门——完整副本必须绿（基线）
    with tempfile.TemporaryDirectory(prefix="wq_ui01a_") as tmp:
        good = Path(tmp) / "dash"
        _copy_dashboard(good)
        r_good = _selfcheck_in(good)
        assert r_good.returncode == 0, \
            f"完整副本自检应 PASS，实得 rc={r_good.returncode}: {r_good.stdout[-400:]}"

        # 注入：少一个闭合标签（删首个 </div>）→ 启动门必须失败
        bad = Path(tmp) / "dash-broken"
        _copy_dashboard(bad)
        idx = bad / "index.html"
        html = idx.read_text(encoding="utf-8")
        assert "</div>" in html, "注入前置失败：index.html 无 </div>"
        idx.write_text(html.replace("</div>", "", 1), encoding="utf-8")
        r_bad = _selfcheck_in(bad)
        assert r_bad.returncode != 0, "少一个闭合标签后启动自检门仍绿——门失效"
        assert "平衡" in r_bad.stdout or "FAIL" in r_bad.stdout, \
            f"失败应点名结构破损，实得: {r_bad.stdout[-400:]}"

    # 腿 2：探针构建门——破损目录必报，真件零发现
    pristine = build_gate(DASH)
    assert pristine == [], f"真 dashboard 构建门应零发现，实得 {[x.as_dict() for x in pristine]}"
    real_html = (DASH / "index.html").read_text(encoding="utf-8")
    mutations = {
        "missing-</div>": real_html.replace("</div>", "", 1),
        "missing-</span>": real_html.replace("</span>", "", 1),
        "stray-</div>": real_html + "</div>",
        "missing-</html>": real_html.replace("</html>", "", 1),
    }
    caught = {}
    for name, mutated in mutations.items():
        f = html_structural_gate(mutated, f"mut-{name}.html")
        assert f and _codes(f) & {"UNCLOSED_TAG", "STRAY_CLOSE_TAG"}, \
            f"破损形态 {name} 未被探针构建门抓获: {[x.as_dict() for x in f]}"
        caught[name] = sorted(_codes(f))[0]
    # 严格性对照：产品字符串计数门只对 div 计数，</span> 缺失漏报——探针必报
    span_case = mutations["missing-</span>"]
    product_div_gate = span_case.count("<div") == span_case.count("</div>")
    assert product_div_gate is True, "对照前提失败：span 注入不应扰动 div 计数"
    assert "missing-</span>" in caught and caught["missing-</span>"] == "UNCLOSED_TAG", \
        "探针必须抓到产品字符串门漏报的 </span> 缺失"
    _record("UI-01",
            f"产品 --self-check 启动门：完整副本 rc=0，删一个 </div> 后 rc!=0（点名「div 平衡」）；"
            f"探针构建门：真件 0 发现，四种破损形态（</div>/</span>/游离</div>/</html>）全报，"
            f"且抓到产品字符串计数门漏报的 </span> 缺失（parser 严格性 ⊇ 产品门）")


def test_UI_02_xss_log_and_ledger_text_does_not_execute():
    """UI-02 | 注入: XSS 日志/账本文本 | 期望: 不执行。

    L2 三层链：传输契约（application/json+nosniff，payload 作为数据无损往返）；
    CSP 契约（响应头+meta 双写禁内联，served 页面结构门零内联面）；
    前端源码契约（app.js 零注入 API + textContent 渲染）。
    负例：假服务的内联脚本/事件/无 CSP/innerHTML 注入面被探针必报。
    """
    payload_img = '<img src=x onerror="window.__xss1=1">'
    payload_script = "<script>window.__xss2=1</script>"
    payload_svg = "<svg onload=alert(1)>"
    with tempfile.TemporaryDirectory(prefix="wq_ui02_") as tmp:
        sandbox = Path(tmp)
        with _Dash(sandbox) as dash:
            _write_snapshot(dash.snap, "BLOCKED")
            (dash.home / "logs").mkdir(parents=True, exist_ok=True)
            (dash.home / "logs" / "xss.log").write_text(
                payload_img + "\n" + payload_script + "\nnormal line\n", encoding="utf-8")
            proj = dash.ledger_root / "projX"
            proj.mkdir(parents=True, exist_ok=True)
            rows = [
                {"id": "X-1", "sev": "HIGH", "status": "accepted-risk",
                 "title": payload_img + " 已接受项标题", "ts": "2026-10-01T10:00:00"},
                {"id": "X-2", "sev": "MED", "status": "deferred-strange",
                 "title": payload_script + " 未归类项", "ts": "2026-10-02T10:00:00"},
            ]
            with open(proj / "findings.jsonl", "w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")

            # 传输契约：payload 作为 JSON 数据无损往返（不进 HTML 上下文）
            st, hd, body = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/logs")
            assert st == 200, f"logs 应 200，实得 {st}"
            assert hd.get("content-type", "").startswith("application/json"), \
                f"日志必须以 JSON 传输（非 HTML 上下文），实得 {hd.get('content-type')!r}"
            assert hd.get("x-content-type-options") == "nosniff", "缺 nosniff（MIME 嗅探面）"
            logs = json.loads(body)
            assert logs["xss.log"].splitlines()[0] == payload_img, "payload 文本应无损往返"
            assert payload_script in logs["xss.log"], "script payload 应作为数据在场"
            st, _, body2 = raw_request("127.0.0.1", dash.port,
                                       "GET", "/api/v1/bugscan-ledger?items=ACCEPTED")
            items = json.loads(body2)["items"]
            assert any(payload_img in (x.get("title") or "") for x in items), \
                "账本 XSS 标题应作为数据在场（钻取通道）"

            # CSP/结构/源码三层契约：真服务面探针 + 真件静态契约全零发现
            surf = probe_http_surface("127.0.0.1", dash.port)
            assert surf == [], f"真 UI 面探针应零发现，实得 {[x.as_dict() for x in surf]}"
            html_txt = (DASH / "index.html").read_text(encoding="utf-8")
            js_txt = (DASH / "app.js").read_text(encoding="utf-8")
            assert html_structural_gate(html_txt) == [], "index.html 应零内联面"
            contract = static_dom_contract(html_txt, js_txt)
            assert contract == [], f"前端 XSS 面契约应零发现，实得 {[x.as_dict() for x in contract]}"
            for sink in ("innerHTML", "insertAdjacentHTML", "document.write", "eval("):
                assert sink not in js_txt, f"app.js 不得含注入 API {sink}"
            assert "textContent" in js_txt, "app.js 必须走 textContent 渲染"

    # 负例（红探针）：故意脆弱页面——探针必报每一个 XSS 注入面
    with _VulnServer() as vuln:
        f = probe_http_surface("127.0.0.1", vuln.port)
        got = _codes(f)
        for must in ("INLINE_SCRIPT", "INLINE_EVENT_HANDLER", "CSP_META_MISSING",
                     "SECURITY_HEADER_MISSING", "XSS_SINK_IN_JS"):
            assert must in got, f"负例缺陷 {must} 未被探针报出，实得 {sorted(got)}"
    _record("UI-02",
            "XSS 注入三通道（日志/账本标题/钻取明细）payload 无损在场但全程 JSON+nosniff 传输；"
            "CSP 响应头+meta 双写、served 页零内联脚本/事件；app.js 零注入 API（innerHTML/"
            "insertAdjacentHTML/document.write/eval 全无）+textContent 渲染；负例假服务 5 类"
            " XSS 面全被探针必报。浏览器渲染执行未验证（无 Playwright，证据 JSON 已登记）")


def test_UI_03_csrf_fake_origin_and_text_plain_writes_rejected():
    """UI-03 | 注入: CSRF/伪 Origin/text/plain 写入 | 期望: 拒绝。

    真服务面：跨源 Origin/Sec-Fetch-Site 403；OPTIONS 预检 405 且零 ACAO；
    decide 写接口（json/text/plain）双路径 405；其他端点 text/plain 415；
    chunked 传输拒收。负例：写接口全开+预检放行的假服务被探针必报。
    """
    with tempfile.TemporaryDirectory(prefix="wq_ui03_") as tmp:
        with _Dash(Path(tmp)) as dash:
            _write_snapshot(dash.snap, "PASS")
            # CSRF 面：伪 Origin / 跨站 Sec-Fetch-Site / 预检
            st, _, _ = raw_request("127.0.0.1", dash.port, "GET", "/",
                                   headers={"Origin": "http://evil.example.com"})
            assert st == 403, f"跨源 Origin 应 403，实得 {st}"
            st, _, _ = raw_request("127.0.0.1", dash.port, "GET", "/",
                                   headers={"Sec-Fetch-Site": "cross-site"})
            assert st == 403, f"Sec-Fetch-Site: cross-site 应 403，实得 {st}"
            st, hd, _ = raw_request("127.0.0.1", dash.port, "OPTIONS", "/api/v1/ping")
            assert st == 405, f"CORS 预检应 405，实得 {st}"
            assert not any(k.startswith("access-control-allow-") for k in hd), \
                f"预检不得回 ACAO 头，实得 {dict(hd)}"

            # 写接口关闭：decide 双路径（json 与 text/plain CSRF 型）都拒
            for path in ("/api/decide", "/api/v1/decide"):
                st, _, body = raw_request("127.0.0.1", dash.port, "POST", path,
                                          headers={"Content-Type": "application/json"},
                                          body='{"id":"x","action":"take"}')
                j = json.loads(body)
                assert st == 405 and j["error"]["code"] == "WRITE_DISABLED", \
                    f"POST {path}(json) 应 405 WRITE_DISABLED，实得 {st} {j}"
                st, _, body = raw_request("127.0.0.1", dash.port, "POST", path,
                                          headers={"Content-Type": "text/plain"},
                                          body="id=1&action=take")
                j = json.loads(body)
                assert st == 405 and j["error"]["code"] == "WRITE_DISABLED", \
                    f"POST {path}(text/plain CSRF 型) 应 405，实得 {st} {j}"
            # 其他端点：text/plain 明确 415；chunked 明确 411——类型与传输面双拒
            st, _, body = raw_request("127.0.0.1", dash.port, "POST", "/api/v1/x",
                                      headers={"Content-Type": "text/plain"}, body="hello")
            assert st == 415 and json.loads(body)["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE", \
                f"text/plain 写入应 415，实得 {st}"
            st, _, body = raw_request("127.0.0.1", dash.port, "POST", "/api/v1/x",
                                      headers={"Transfer-Encoding": "chunked"})
            assert st == 411, f"chunked 请求应 411，实得 {st}"
            # 同源合法读不受影响（防误伤对照）
            st, _, _ = raw_request("127.0.0.1", dash.port, "GET", "/",
                                   headers={"Origin": f"http://127.0.0.1:{dash.port}"})
            assert st == 200, f"同源 Origin 应放行，实得 {st}"
            surf = probe_http_surface("127.0.0.1", dash.port)
            assert surf == [], f"真 UI 面探针应零发现，实得 {[x.as_dict() for x in surf]}"

    # 负例：写接口全开（任意类型 200）+预检放行的假服务——探针必报
    with _VulnServer() as vuln:
        f = probe_http_surface("127.0.0.1", vuln.port)
        got = _codes(f)
        for must in ("WRITE_ENDPOINT_OPEN", "WRITE_WITH_TEXT_PLAIN_ALLOWED",
                     "CROSS_ORIGIN_ALLOWED", "CORS_PREFLIGHT_ALLOWED"):
            assert must in got, f"负例缺陷 {must} 未被探针报出，实得 {sorted(got)}"
    _record("UI-03",
            "跨源 Origin/Sec-Fetch-Site→403；OPTIONS 预检→405 零 ACAO；decide 双路径×"
            "（json/text/plain）→405 WRITE_DISABLED；其他端点 text/plain→415、chunked→411；"
            "同源对照 200 不误伤；负例假服务写开放/预检放行/跨源放行全被探针必报")


def test_UI_04_gate_red_with_high_other_scores_is_overall_blocked():
    """UI-04 | 注入: Gate 红、其他项高分 | 期望: 总体 BLOCKED。

    真服务面：快照 policy_verdict=BLOCKED 而各站/计数高分（score 87）→
    /api/v1/health 逐字透传 BLOCKED（score/watermark 同水位、绝不自算洗绿）；
    快照转 PASS 即刻传播；快照过期→503 结构化 ERROR 绝不 200 伪绿。
    前端源码契约：判定优先级 policy_verdict 优先、失败渲染 errBox。
    负例：自算洗绿假服务被同水位探针必报。
    """
    appjs = (DASH / "app.js").read_text(encoding="utf-8")
    assert "h.policy_verdict||h.overall||h.verdict" in appjs, \
        "前端判定必须以权威 verdict 为先（同水位源码契约）"
    assert "errBox(e,'健康度正源" in appjs, "健康数据源失败必须渲染错误框（不得伪绿）"

    with tempfile.TemporaryDirectory(prefix="wq_ui04_") as tmp:
        sandbox = Path(tmp)
        with _Dash(sandbox, ttl_seconds=2) as dash:
            gen = _write_snapshot(dash.snap, "BLOCKED", score=87)
            st, _, body = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/health")
            j = json.loads(body)
            assert st == 200 and j["policy_verdict"] == "BLOCKED", \
                f"Gate 红必须总体 BLOCKED，实得 {st} {j}"
            assert j.get("score") == 87 and j.get("generated_at") == gen, \
                f"score/watermark 必须逐字透传（其他项高分不洗绿），实得 score={j.get('score')} gen={j.get('generated_at')}"
            assert j.get("source") == "gate-aggregator", "必须声明正源"
            f = probe_health_watermark("127.0.0.1", dash.port,
                                       {"policy_verdict": "BLOCKED", "score": 87,
                                        "generated_at": gen})
            assert f == [], f"同水位探针应零发现，实得 {[x.as_dict() for x in f]}"

            # 权威复绿→UI 即刻传播（无缓存旧结论）
            gen2 = _write_snapshot(dash.snap, "PASS", score=95)
            st, _, body = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/health")
            j = json.loads(body)
            assert st == 200 and j["policy_verdict"] == "PASS" and j["generated_at"] == gen2, \
                f"快照翻转后 UI 必须即刻同水位，实得 {j}"

            # 快照过期（聚合器停摆）→ 503 结构化 ERROR，绝不 200 伪绿
            time.sleep(3.5)
            st, _, body = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/health")
            j = json.loads(body)
            assert st == 503 and j["error"]["code"] == "AGGREGATOR_STALE", \
                f"过期快照应 503 STALE，实得 {st} {j}"
            f2 = probe_health_watermark("127.0.0.1", dash.port,
                                        {"policy_verdict": "BLOCKED"}, snapshot_fresh=False)
            assert f2 == [], f"过期面探针应零发现，实得 {[x.as_dict() for x in f2]}"

    # 负例：自算洗绿（权威 BLOCKED 而 UI 报 PASS+99）——同水位探针必报
    with _VulnServer() as vuln:
        f = probe_health_watermark("127.0.0.1", vuln.port,
                                   {"policy_verdict": "BLOCKED", "score": 87,
                                    "generated_at": _now_iso()})
        got = _codes(f)
        assert "UI_VERDICT_DIVERGES_FROM_AUTHORITY" in got and "UI_SCORE_RECOMPUTED" in got, \
            f"洗绿负例未被探针报出，实得 {sorted(got)}"
    _record("UI-04",
            "Gate 红+各站高分（score 87）→health 逐字透传 BLOCKED（score/watermark 同水位，"
            "source=gate-aggregator）；快照转 PASS 即刻传播；过期→503 AGGREGATOR_STALE 绝不"
            "200 伪绿；前端判定优先级+errBox 源码契约在位；负例自算洗绿（PASS+99）被同水位"
            "探针双报（verdict+score）。浏览器目视读数未验证（已登记）")


def test_UI_05_accepted_other_and_quarantine_drilldown():
    """UI-05 | 注入: ACCEPTED/OTHER/quarantine | 期望: 均可钻取。

    真服务面：账本含 OPEN/ACCEPTED/OTHER/FIXED+非法行——聚合计数正确、
    非法行不炸不计数；ACCEPTED/OTHER/OPEN 逐状态钻取（计数与明细一致、
    明细字段真实）；前端钻取通道（?items=）与两状态节点静态契约在位。
    负例：钻取状态错配+假计数被探针必报。quarantine UI 表面缺失如实登记。
    """
    appjs = (DASH / "app.js").read_text(encoding="utf-8")
    assert "'/api/v1/bugscan-ledger?items='+encodeURIComponent(stt)" in appjs, \
        "前端钻取通道（?items= 状态过滤）源码契约缺失"
    assert "'ACCEPTED'" in appjs and "'OTHER'" in appjs, \
        "ACCEPTED/OTHER 状态节点契约缺失"

    with tempfile.TemporaryDirectory(prefix="wq_ui05_") as tmp:
        with _Dash(Path(tmp)) as dash:
            _write_snapshot(dash.snap, "PASS")
            proj = dash.ledger_root / "drill"
            proj.mkdir(parents=True, exist_ok=True)
            rows = [
                {"id": "D-1", "sev": "HIGH", "status": "OPEN", "title": "待修", "ts": "2026-10-05T10:00:00"},
                {"id": "D-2", "sev": "MED", "status": "accepted-risk", "title": "有条件接受项", "ts": "2026-10-04T10:00:00"},
                {"id": "D-3", "sev": "LOW", "status": "deferred-strange", "title": "未归类残差项", "ts": "2026-10-03T10:00:00"},
                {"id": "D-4", "sev": "INFO", "status": "fixed", "title": "已修待验", "ts": "2026-10-02T10:00:00"},
            ]
            with open(proj / "findings.jsonl", "w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                fh.write('{"id": truncated malformed row\n')  # 隔离区形态：非法行

            # 聚合真值：五态计数正确；非法行被隔离（不计数、不炸端点）
            st, _, body = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/bugscan-ledger")
            base = json.loads(body)
            assert st == 200 and base["available"] is True, f"账本端点应可用，实得 {st}"
            assert base["total"]["by_status"] == {"OPEN": 1, "ACCEPTED": 1, "OTHER": 1, "FIXED": 1}, \
                f"状态聚合应恰四项各一（非法行不计数），实得 {base['total']['by_status']}"
            assert base["total"]["findings"] == 4, "非法行不得混入分母"

            # 逐状态钻取：ACCEPTED / OTHER（注入点名）+ OPEN（链首对照）
            for state, want_id in (("ACCEPTED", "D-2"), ("OTHER", "D-3"), ("OPEN", "D-1")):
                f, d = probe_ledger_drill("127.0.0.1", dash.port, state)
                assert f == [], f"{state} 钻取探针应零发现，实得 {[x.as_dict() for x in f]}"
                ids = [x["id"] for x in d.get("items", [])]
                assert ids == [want_id], f"{state} 钻取应恰得 {want_id}，实得 {ids}"
                assert d["items_total"] == 1 and d["items_state"] == state
                item = d["items"][0]
                assert item["st"] == state and item["title"], "钻取明细字段必须真实可读"

    # 负例：任意状态都回 OPEN 明细+假计数——钻取探针必报
    with _VulnServer() as vuln:
        f, _d = probe_ledger_drill("127.0.0.1", vuln.port, "ACCEPTED")
        got = _codes(f)
        assert {"LEDGER_DRILL_STATE_MISMATCH", "LEDGER_DRILL_COUNT_MISMATCH"} <= got, \
            f"钻取负例未被探针报出，实得 {sorted(got)}"
    _record("UI-05",
            "ACCEPTED/OTHER（注入点名）+OPEN 钻取：?items= 计数与明细一致（各恰 1 条、字段真实）；"
            "非法行被 fold 隔离（不计数不炸、分母=4）；前端 ?items= 通道与 ACCEPTED/OTHER 节点"
            "源码契约在位；负例状态错配+假计数被探针双报。quarantine UI 表面缺失+两节点无 "
            "click 接线（浏览器点击链）——如实登记 not_implementable")


def test_UI_06_dns_rebinding_fake_host_unauth_log_read_rejected():
    """UI-06 | 注入: DNS rebinding/伪 Host/未认证日志读取 | 期望: 拒绝。

    真服务面（数据面打 /api/v1/logs）：本机合法读 200（数据在场对照）；
    伪 Host/无 Host/错端口 Host→403 且响应体不含日志 payload（数据不可达）；
    跨源 Origin/Sec-Fetch-Site→403。负例：无 Host 校验假服务被探针必报。
    真实 DNS rebinding 链（DNS+浏览器）不可注入，如实登记。
    """
    marker = "UI06-SENSITIVE-LOG-LINE-9d7f"
    with tempfile.TemporaryDirectory(prefix="wq_ui06_") as tmp:
        with _Dash(Path(tmp)) as dash:
            _write_snapshot(dash.snap, "PASS")
            (dash.home / "logs").mkdir(parents=True, exist_ok=True)
            (dash.home / "logs" / "sentinel6.log").write_text(
                marker + "\nnormal line\n", encoding="utf-8")

            # 对照：本机合法请求（正确 Host、无 Origin）数据可读
            st, _, body = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/logs")
            assert st == 200 and marker.encode() in body, "注入前提：日志数据应在场可读"

            for label, hv in (("伪 Host（rebinding 形态）", "evil.example.com:%d" % dash.port),
                              ("无 Host 头", None),
                              ("错端口 Host", "127.0.0.1:1")):
                st, _, body = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/logs",
                                          host_value=hv)
                assert st == 403, f"{label} 应 403，实得 {st}"
                assert marker.encode() not in body, \
                    f"{label} 拒绝时数据面必须不可达（payload 泄漏）"
            for label, hdrs in (("跨源 Origin 读日志", {"Origin": "http://evil.example.com"}),
                                ("Sec-Fetch-Site 跨站读日志", {"Sec-Fetch-Site": "cross-site"})):
                st, _, body = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/logs",
                                          headers=hdrs)
                assert st == 403 and marker.encode() not in body, \
                    f"{label} 应 403 且数据不可达，实得 {st}"
            surf = probe_http_surface("127.0.0.1", dash.port)
            assert surf == [], f"真 UI 面探针应零发现，实得 {[x.as_dict() for x in surf]}"

    # 负例：无 Host 校验的假服务——日志数据面被任意 Host 放行，探针必报
    with _VulnServer() as vuln:
        f = probe_http_surface("127.0.0.1", vuln.port)
        hits = [x for x in f if x.code == "HOST_VALIDATION_MISSING"]
        assert hits, f"Host 校验缺失未被探针报出，实得 {sorted(_codes(f))}"
        assert any("SENSITIVE" in (x.evidence.get("body_head") or "") or
                   "evil" in x.detail for x in hits), "负例证据应携带数据面泄漏痕迹"
    _record("UI-06",
            "伪 Host/无 Host/错端口 Host→403 且日志 payload 零泄漏（数据面不可达）；跨源 "
            "Origin/Sec-Fetch-Site 读日志→403；本机合法读对照 200 在场；负例无 Host 校验"
            "假服务被探针报 HOST_VALIDATION_MISSING（含泄漏证据）。真实 DNS rebinding 链"
            "（DNS+浏览器）未验证——已登记；协议级防御即产品唯一防线，已实证")


def test_UI_07_slow_concurrent_huge_logs_do_not_exhaust_resources():
    """UI-07 | 注入: 慢请求/高并发/超大日志 | 期望: 不耗尽资源。

    真服务面：超大日志（3 文件×~1.5MB）读取有界（行数界 tail -20）且时延受控；
    慢速半开请求期间并发服务正常、且被 15s 连读超时收割；超大声明体 413 快拒；
    60 并发全 200；窗口限速真实触发 429。负例：无限制速假服务被探针必报。
    """
    with tempfile.TemporaryDirectory(prefix="wq_ui07_") as tmp:
        with _Dash(Path(tmp)) as dash:
            _write_snapshot(dash.snap, "PASS")
            logs_dir = dash.home / "logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            first_line, last_line = "FIRST-LINE-MUST-BE-TAILED-OUT", "LAST-LINE-KEEP-0Z71"
            for i in range(3):
                with open(logs_dir / f"big{i}.log", "w", encoding="utf-8") as fh:
                    fh.write(first_line + "\n")
                    for j in range(998):
                        fh.write(("filler %06d " % j) + "y" * 1500 + "\n")
                    fh.write(last_line + "\n")
            total_bytes = sum((logs_dir / f"big{i}.log").stat().st_size for i in range(3))
            assert total_bytes > 3 * 1024 * 1024, "注入前提：超大日志 ≥3MB"

            # 超大日志：读取有界（行数界）+ 时延受控 + tail 语义正确
            t0 = time.monotonic()
            st, hd, body = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/logs",
                                       timeout=15.0)
            dt = time.monotonic() - t0
            assert st == 200, f"超大日志读取应 200，实得 {st}"
            assert len(body) < 300_000, \
                f"响应应被 tail 行数界约束（<300KB），实得 {len(body)}B（源 {total_bytes}B）"
            assert dt < 5.0, f"超大日志读取时延 {dt:.2f}s 超界"
            logs = json.loads(body)
            assert len(logs) == 3 and all(last_line in v for v in logs.values()), \
                "tail 语义：每文件末行应在"
            assert all(first_line not in v for v in logs.values()), \
                "tail 语义：首行应被截出（不整读超大文件）"

            # 慢速半开请求：期间并发服务正常；被连接读超时收割（实测 15s 档）
            sk = socket.create_connection(("127.0.0.1", dash.port), timeout=30)
            sk.sendall(("GET /api/v1/ping HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                        % dash.port).encode())
            closed: list = []

            def _watch():
                t0 = time.monotonic()
                try:
                    data = sk.recv(64)
                except OSError as exc:  # noqa: BLE001
                    data = repr(exc).encode()
                closed.append((time.monotonic() - t0, data))

            t_stall = time.monotonic()  # 观察锚点（仅用于日志；_watch 内部自计时）
            th = threading.Thread(target=_watch, daemon=True)
            th.start()
            for _ in range(3):
                st2, _, _ = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/ping")
                assert st2 == 200, f"慢请求期间并发服务应正常，实得 {st2}"
                time.sleep(1.0)
            th.join(timeout=25)
            sk.close()
            assert closed, "慢速连接收割观察超时（25s 无关闭）"
            stall_t, _recv = closed[0]
            assert 5.0 < stall_t <= 22.0, \
                f"慢速连接应在读超时档（~15s）被服务器关闭，实得 {stall_t:.1f}s"

            # 超大声明体：413 快拒（先于读体）
            t0 = time.monotonic()
            st3, _, body3 = raw_request("127.0.0.1", dash.port, "POST", "/api/v1/x",
                                        headers={"Content-Length": "1000000"})
            assert st3 == 413 and json.loads(body3)["error"]["code"] == "BODY_TOO_LARGE", \
                f"超大声明体应 413 BODY_TOO_LARGE，实得 {st3}"
            assert time.monotonic() - t0 < 5.0, "413 必须先于读体（快拒）"

            # 高并发：60 并发读全部 200（隔离于慢连接之外）
            results: list = [None] * 60

            def _hit(i):
                try:
                    results[i] = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/ping")[0]
                except OSError as exc:
                    results[i] = repr(exc)

            threads = [threading.Thread(target=_hit, args=(i,)) for i in range(60)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)
            bad = [r for r in results if r != 200]
            assert not bad, f"60 并发应全 200，异常 {bad[:5]}"

            # 过载防护：窗口限速真实触发（此服务器生命周期内首次 429）
            f_rate, first_429 = probe_rate_guard("127.0.0.1", dash.port, burst=220)
            assert f_rate == [], f"限速探针应零发现，实得 {[x.as_dict() for x in f_rate]}"
            assert first_429 is not None and first_429 <= 210, \
                f"429 应在窗口配额内出现，实得第 {first_429} 次"

            # 全部压力后服务仍健康
            st4, _, _ = raw_request("127.0.0.1", dash.port, "GET", "/api/v1/ping")
            assert st4 in (200, 429), f"压力后服务应存活，实得 {st4}"

    # 负例：无限制速假服务——200 连发零 429，探针必报
    with _VulnServer() as vuln:
        f, first_429 = probe_rate_guard("127.0.0.1", vuln.port, burst=200)
        assert first_429 is None and _codes(f) == {"RATE_LIMIT_MISSING"}, \
            f"无限速负例未被探针报出，实得 {sorted(_codes(f))}"
    _record("UI-07",
            f"超大日志（{total_bytes // 1024}KB 源→{len(body) // 1024}KB 响应，tail 行数界、"
            f"{dt * 1000:.0f}ms、首行截出末行保留）；慢速半开请求期间并发 3×200、"
            f"{stall_t:.1f}s 被读超时收割（15s 档）；超大声明体 413 快拒；60 并发全 200；"
            f"限速真实触发（第 {first_429} 发 429）；压力后存活。负例无限速假服务被探针"
            f"必报。观察项：tail 为行数界非字节界（病态单行可放大响应，产品未改）")


# ---------------------------------------------------------------------------
# 运行器：逐条执行、写证据工件、exit 0/1
# ---------------------------------------------------------------------------
def _git_head() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(REPO),
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _playwright_available() -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec("playwright") is not None
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    order = {f"test_UI_{i:02d}_": i for i in range(1, 8)}
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    tests.sort(key=lambda t: order.get(t[0][:11], 99))

    pw = _playwright_available()
    print("=" * 72)
    print("§20 验收 ID 专属测试——UI 族 7 条（真实注入/真实断言/负例红探针）")
    print(f"repo: {REPO}  HEAD: {_git_head()}")
    print(f"方法级别: {'L1 真浏览器（Playwright 可用）' if pw else 'L2 HTTP+DOM（Playwright 不可用，按可用性降级）'}")
    print("=" * 72)
    passed = failed = 0
    failed_names = []
    for name, fn in tests:
        tid = name[len("test_"):].split("_", 2)
        tid = "-".join(tid[:2])
        try:
            fn()
            print(f"  PASS  {tid:<8} {name}")
            passed += 1
            _RESULTS.setdefault(tid, {"pass": True, "detail": "", "method": _METHOD_LEVEL})
        except Exception as exc:  # noqa: BLE001
            failed += 1
            failed_names.append(name)
            _RESULTS[tid] = {"pass": False, "method": _METHOD_LEVEL,
                             "detail": f"{type(exc).__name__}: {exc}"}
            print(f"  FAIL  {tid:<8} {name}: {exc}")
    print("-" * 72)
    print(f"RESULT: PASS={passed} FAIL={failed}"
          f"{'' if not failed else '  failed: ' + ', '.join(failed_names)}")

    try:
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "meta": {
                "artifact": "ac-ui-family",
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "repo_head": _git_head(),
                "test_file": "system/tests/test_ac_ui_family.py",
                "probe_module": "system/wenqu_core/ui_probe.py",
                "plan_source": "evidence/00-baseline/codex-external/方案.md §20.4/§20.5",
                "scope": "UI-01~07（7 ID，UI 前缀全量）",
                "method_level": "L2-HTTP-DOM",
                "method_level_reason": "Playwright 不可用（python3 -c \"import playwright\" "
                                        "ModuleNotFoundError）——按方法可用性降级；"
                                        "被测体=system/dashboard/server.py 真子进程"
                                        "（临时随机端口，沙箱 WENQU_*，不触 7789）",
                "playwright_available": pw,
                "run_rc": 0 if not failed else 1,
                "passed": passed,
                "failed": failed,
                "observations": [
                    "UI-07 超大日志的产品界是行数界（tail -n 20/文件）而非字节界："
                    "病态单行超长日志文件可产生大响应（本任务不改产品面，登记观察）",
                    "UI-01 构建门以产品 --self-check 启动自检门 + ui_probe 构建门承载；"
                    "server 常驻启动路径未强制每次 serve 前自动跑门（登记观察）",
                ],
            },
            "results": _RESULTS,
            "not_implementable": _NOT_IMPLEMENTABLE,
        }
        EVIDENCE_PATH.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"证据工件: {EVIDENCE_PATH.relative_to(REPO)}")
    except OSError as exc:
        print(f"证据工件写入失败（不影响判定）: {exc}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

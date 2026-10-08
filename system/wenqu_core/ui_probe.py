#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wenqu UI 探针与构建门（stdlib-only；W8 UI 验收族的机器探测面）。

定位：dashboard（system/dashboard/server.py + index.html/app.css/app.js）是问渠
发行版的唯一 UI 面。本模块把「UI 可被机器验证」的部分固化为可复用探针：

  1. 构建门（build gate）
     - html_structural_gate(html)   HTML 良构性：标签闭合栈（少一个闭合标签必报）、
                                    内联 <script>/on* 事件/style、CSP meta 契约。
     - static_dom_contract(html, js) 静态 DOM 契约：四页签容器、data-t 导航、
                                    外链 css/js、前端零 HTML 字符串注入 API（XSS 面）。
     - build_gate(dash_dir)          dashboard 目录级构建门（文件齐 + 上述两门全过）。
  2. 协议面探针（起真实服务进程后打真实 HTTP）
     - probe_http_surface(host, port)   安全响应头/CORS 默认拒绝/Host 校验（防 DNS
                                        rebinding）/写接口关闭/text/plain 拒收/体量
                                        上限/路径白名单/API 版本化，一并做页面结构门。
     - probe_health_watermark(...)      UI 与权威聚合器同水位：verdict/score/watermark
                                        逐字透传，UI 不得自算洗绿。
     - probe_ledger_drill(...)          状态钻取：?items=STATE 必须返回该状态明细且
                                        计数与聚合一致。
     - probe_rate_guard(...)            过载防护：窗口限速必须真实触发。

所有探针返回 list[UIFinding]（空列表 = 零发现）。探针对「故意脆弱的假服务」必须
报出对应 finding——这是负例（红探针）纪律：探测面本身可被证明不瞎。

诚实边界：本模块不做真实浏览器渲染/执行验证（无 Playwright 依赖）；
「不执行」「同水位」等浏览器级语义由传输契约（JSON+nosniff）、CSP 契约
（禁内联）、前端源码契约（零注入 API + textContent）在协议/静态层等价收窄，
浏览器级验证留在上层测试件按可用性降级并如实标注。
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

PROBE_VERSION = "wenqu-ui-probe/1.0"

# ─────────────────────────────── 数据结构 ───────────────────────────────
@dataclass(frozen=True)
class UIFinding:
    """一条 UI 探针发现（code 为机器稳定码，detail 为人类可读证据）。"""
    code: str
    detail: str
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail, "evidence": self.evidence}


# ─────────────────────────────── 构建门：HTML 结构 ───────────────────────────────
VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}

_CSP_META_REQUIRED = ("default-src 'self'", "script-src 'self'",
                      "frame-ancestors 'none'")

_XSS_SINK_PATTERNS = (
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write", "document.writeln", "eval(", "new Function",
)

_REQUIRED_CONTAINER_IDS = ("ov", "pipe", "deck", "bugdeck")


class _GateParser(HTMLParser):
    """栈式标签平衡 + 内联危险面收集（html.parser，容错但记账）。"""

    def __init__(self, source: str):
        super().__init__(convert_charrefs=True)
        self.source = source
        self.stack: list[tuple[str, int]] = []
        self.raw: list[tuple[str, str]] = []
        self.csp_meta: str | None = None

    # -- 属性面：内联事件 / 内联样式属性 --
    def _scan_attrs(self, tag: str, attrs) -> None:
        for k, _v in attrs or []:
            kl = (k or "").lower()
            if tag == "script" or kl.startswith("on"):
                pass  # script 由 tag 级判定；on* 在这里判
            if kl.startswith("on") and len(kl) > 2:
                self.raw.append(("INLINE_EVENT_HANDLER",
                                 f"<{tag} {k}=...> 第{self.getpos()[0]}行内联事件属性（CSP script-src 'self' 不兼容）"))
            if kl == "style":
                self.raw.append(("INLINE_STYLE_ATTR",
                                 f"<{tag} style=...> 第{self.getpos()[0]}行内联样式属性"))
        if tag == "meta":
            ad = {k.lower(): (v or "") for k, v in (attrs or [])}
            if ad.get("http-equiv", "").lower() == "content-security-policy":
                self.csp_meta = ad.get("content", "")

    def handle_starttag(self, tag, attrs):
        self._scan_attrs(tag, attrs)
        if tag == "script":
            ad = {k.lower() for k, _ in attrs or []}
            if "src" not in ad:
                self.raw.append(("INLINE_SCRIPT",
                                 f"<script> 第{self.getpos()[0]}行为内联脚本（无 src 外链）——CSP 构建门必拒"))
        if tag == "style":
            self.raw.append(("INLINE_STYLE_BLOCK",
                             f"<style> 第{self.getpos()[0]}行为内联样式块"))
        if tag not in VOID_ELEMENTS:
            self.stack.append((tag, self.getpos()[0]))

    def handle_startendtag(self, tag, attrs):
        # 自闭合写法 <tag/>：视为平衡，不压栈；属性面仍要扫
        self._scan_attrs(tag, attrs)
        if tag == "script":
            ad = {k.lower() for k, _ in attrs or []}
            if "src" not in ad:
                self.raw.append(("INLINE_SCRIPT",
                                 f"<script/> 第{self.getpos()[0]}行为自闭合内联脚本"))

    def handle_endtag(self, tag):
        if tag in VOID_ELEMENTS:
            return
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()
            return
        names = [t for t, _ in self.stack]
        if tag in names:
            # 隐式截断：<div><span></div> —— span 未显式闭合
            while self.stack:
                t, ln = self.stack.pop()
                if t == tag:
                    break
                self.raw.append((
                    "UNCLOSED_TAG",
                    f"<{t}>（{self.source}第{ln}行开标签）被 </{tag}> 隐式截断，未显式闭合"))
        else:
            self.raw.append(("STRAY_CLOSE_TAG",
                             f"</{tag}> 第{self.getpos()[0]}行为无对应开标签的闭合标签"))

    def finish(self) -> list[tuple[str, str]]:
        super().close()
        for t, ln in self.stack:
            self.raw.append(("UNCLOSED_TAG",
                             f"<{t}>（{self.source}第{ln}行开标签）直至文档结束未闭合"))
        return self.raw


def html_structural_gate(html_text: str, source: str = "index.html") -> list[UIFinding]:
    """HTML 构建/启动门：结构良构性 + 内联危险面 + CSP meta 契约。

    破损 HTML（少一个闭合标签/游离闭合标签/隐式截断）必须报 finding；
    良构且零内联面时返回空列表。
    """
    p = _GateParser(source)
    try:
        p.feed(html_text)
        rows = p.finish()
    except Exception as exc:  # noqa: BLE001 —— 解析器异常本身就是门失败
        return [UIFinding("HTML_PARSE_ERROR", f"{source} HTML 解析器异常: {exc!r}")]
    findings = [UIFinding(code, f"{source}: {detail}") for code, detail in rows]
    if p.csp_meta is None:
        findings.append(UIFinding(
            "CSP_META_MISSING",
            f"{source} 缺 Content-Security-Policy meta（script-src 'self' 构建契约缺失）"))
    else:
        missing = [tok for tok in _CSP_META_REQUIRED if tok not in p.csp_meta]
        if missing:
            findings.append(UIFinding(
                "CSP_META_WEAK",
                f"{source} CSP meta 缺指令 {missing}（实为 {p.csp_meta!r}）"))
    return findings


def static_dom_contract(html_text: str, js_text: str,
                        source_html: str = "index.html",
                        source_js: str = "app.js") -> list[UIFinding]:
    """静态 DOM/前端契约：四页签容器、data-t 导航、外链资源、零注入 API。"""
    findings: list[UIFinding] = []
    for cid in _REQUIRED_CONTAINER_IDS:
        if f'id="{cid}"' not in html_text:
            findings.append(UIFinding(
                "DOM_CONTAINER_MISSING",
                f"{source_html} 缺页签容器 id=\"{cid}\"（四页签 ov/pipe/deck/bugdeck 契约）"))
    if html_text.count("data-t=") != 4:
        findings.append(UIFinding(
            "DOM_NAV_TABS_DRIFT",
            f"{source_html} data-t 导航数={html_text.count('data-t=')}，契约 4"))
    if 'href="app.css"' not in html_text:
        findings.append(UIFinding("CSS_NOT_EXTERNAL",
                                  f"{source_html} 未外链 app.css"))
    if 'src="app.js"' not in html_text:
        findings.append(UIFinding("JS_NOT_EXTERNAL",
                                  f"{source_html} 未外链 app.js（应 <script src> 外链）"))
    for sink in _XSS_SINK_PATTERNS:
        if sink in js_text:
            findings.append(UIFinding(
                "XSS_SINK_IN_JS",
                f"{source_js} 含 HTML 字符串注入 API「{sink}」——日志/账本 XSS 注入面"))
    if "textContent" not in js_text:
        findings.append(UIFinding(
            "TEXT_RENDER_CONTRACT_MISSING",
            f"{source_js} 未使用 textContent（动态文本必须走文本节点渲染契约）"))
    return findings


def build_gate(dash_dir) -> list[UIFinding]:
    """dashboard 目录级构建门：三件静态资源在位 + 结构门 + DOM/前端契约。"""
    d = Path(dash_dir)
    findings: list[UIFinding] = []
    texts: dict[str, str] = {}
    for fname in ("index.html", "app.css", "app.js"):
        p = d / fname
        if not p.is_file():
            findings.append(UIFinding("BUILD_ASSET_MISSING",
                                      f"{fname} 不存在（dashboard 构建件缺失）"))
            continue
        try:
            texts[fname] = p.read_text(encoding="utf-8")
        except OSError as exc:
            findings.append(UIFinding("BUILD_ASSET_UNREADABLE", f"{fname}: {exc}"))
    if "index.html" in texts:
        findings += html_structural_gate(texts["index.html"], "index.html")
        js = texts.get("app.js", "")
        findings += static_dom_contract(texts["index.html"], js)
    if "app.css" in texts and len(texts["app.css"].strip()) < 200:
        findings.append(UIFinding("CSS_EMPTY", "app.css 空/过短（构建件残缺）"))
    return findings


# ─────────────────────────────── HTTP 底座（原始套接字，可发畸形请求） ───────────────────────────────
_AUTO = object()  # Host 头哨兵：默认自动填 host:port；None=故意不发 Host


def raw_request(host: str, port: int, method: str, path: str,
                headers: dict | None = None, body: bytes | str = b"",
                timeout: float = 10.0, host_value=_AUTO) -> tuple[int, dict, bytes]:
    """发送原始 HTTP/1.1 请求（Connection: close），读至 EOF。

    host_value: _AUTO → 自动 Host: host:port；str → 伪 Host 注入；None → 不发 Host 头。
    headers 里显式给的 Content-Length 优先（用于体量上限注入：声明大 CL 但不发体）。
    返回 (status, 小写头 dict, body bytes)。
    """
    if isinstance(body, str):
        body = body.encode("utf-8")
    hdrs: dict[str, str] = dict(headers or {})
    req = [f"{method} {path} HTTP/1.1", "Connection: close"]
    if host_value is _AUTO and not any(k.lower() == "host" for k in hdrs):
        req.append(f"Host: {host}:{port}")
    elif isinstance(host_value, str) and not any(k.lower() == "host" for k in hdrs):
        req.append(f"Host: {host_value}")
    has_cl = any(k.lower() == "content-length" for k in hdrs)
    for k, v in hdrs.items():
        req.append(f"{k}: {v}")
    if not has_cl and (body or method in ("POST", "PUT", "PATCH")):
        req.append(f"Content-Length: {len(body)}")
    data = ("\r\n".join(req) + "\r\n\r\n").encode("latin-1", "replace") + body
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(data)
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()
    raw = b"".join(chunks)
    head, _, payload = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        status = 0
    hd: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hd.setdefault(k.strip().lower(), v.strip())
    return status, hd, payload


# ─────────────────────────────── 协议面探针 ───────────────────────────────
REQUIRED_RESPONSE_HEADERS = {
    "content-security-policy": ("default-src 'self'", "frame-ancestors 'none'"),
    "x-frame-options": ("deny",),
    "x-content-type-options": ("nosniff",),
    "cache-control": ("no-store",),
    "referrer-policy": ("no-referrer",),
}


def probe_http_surface(host: str, port: int, *,
                       include_static: bool = True) -> list[UIFinding]:
    """对运行中的 UI 服务做协议级安全/结构探测（空列表=零发现）。

    覆盖：安全响应头、CORS 默认拒绝（无 ACAO/OPTIONS 预检必败）、Host 校验
    （防 DNS rebinding，含伪 Host/无 Host/错端口 Host）、写接口关闭、
    text/plain 写入拒收、请求体上限、路径白名单、API 版本化、页面结构门。
    """
    f: list[UIFinding] = []
    st, hd, body = raw_request(host, port, "GET", "/")
    if st != 200:
        f.append(UIFinding("PAGE_NOT_SERVED", f"GET / → {st}（页面不可服务）"))
    else:
        if not hd.get("content-type", "").startswith("text/html"):
            f.append(UIFinding("PAGE_CTYPE_WRONG",
                               f"GET / Content-Type={hd.get('content-type')!r} 非 text/html"))
        for name, musts in REQUIRED_RESPONSE_HEADERS.items():
            val = hd.get(name)
            if not val:
                f.append(UIFinding("SECURITY_HEADER_MISSING",
                                   f"GET / 缺响应头 {name}",
                                   evidence={"header": name}))
                continue
            missing = [m for m in musts if m not in val.lower()]
            if missing:
                f.append(UIFinding("SECURITY_HEADER_WEAK",
                                   f"响应头 {name}={val!r} 缺 {missing}"))
        leak = [k for k in hd if k.startswith("access-control-allow-")]
        if leak:
            f.append(UIFinding("CORS_HEADER_LEAK",
                               f"响应携带 {leak}（CORS 默认拒绝被破坏）"))
        if include_static:
            html = body.decode("utf-8", "replace")
            f += html_structural_gate(html, f"served:{host}:{port}/")
            jst, jhd, jbody = raw_request(host, port, "GET", "/app.js")
            js = jbody.decode("utf-8", "replace") if jst == 200 else ""
            f += static_dom_contract(html, js, f"served:{host}:{port}/", "served:/app.js")

    for path, ctype_prefix in (("/app.css", "text/css"),
                               ("/app.js", "application/javascript")):
        st2, hd2, _ = raw_request(host, port, "GET", path)
        if st2 != 200:
            f.append(UIFinding("STATIC_ASSET_NOT_SERVED", f"GET {path} → {st2}"))
        elif not hd2.get("content-type", "").startswith(ctype_prefix):
            f.append(UIFinding("STATIC_CTYPE_WRONG",
                               f"GET {path} Content-Type={hd2.get('content-type')!r}"))

    st3, _, b3 = raw_request(host, port, "GET", "/api/v1/ping")
    if st3 != 200 or b"true" not in b3:
        f.append(UIFinding("PING_NOT_OK", f"GET /api/v1/ping → {st3} {b3[:60]!r}"))

    # Host 校验（数据面打 /api/v1/logs：拒绝时数据不可达）
    data_path = "/api/v1/logs"
    for label, hv in (("伪 Host evil.example.com", f"evil.example.com:{port}"),
                      ("无 Host 头", None),
                      ("错端口 Host", "127.0.0.1:1")):
        st4, _, b4 = raw_request(host, port, "GET", data_path, host_value=hv)
        if st4 == 200:
            f.append(UIFinding(
                "HOST_VALIDATION_MISSING",
                f"{label} 仍 200 放行日志数据面（DNS rebinding/伪 Host 防护缺失）",
                evidence={"probe": label, "body_head": b4[:80].decode("latin-1", "replace")}))
        elif st4 != 403:
            f.append(UIFinding("HOST_REJECT_UNEXPECTED",
                               f"{label} → {st4}（非 403 拒绝形态，语义漂移）"))

    # Origin / Sec-Fetch-Site（CSRF 面）
    for label, hdrs in (("跨源 Origin", {"Origin": "http://evil.example.com"}),
                        ("Sec-Fetch-Site: cross-site", {"Sec-Fetch-Site": "cross-site"})):
        st5, _, _ = raw_request(host, port, "GET", "/", headers=hdrs)
        if st5 == 200:
            f.append(UIFinding("CROSS_ORIGIN_ALLOWED",
                               f"{label} 请求被 200 放行（CORS 默认拒绝缺失）"))
    st6, hd6, _ = raw_request(host, port, "OPTIONS", "/api/v1/ping")
    if st6 == 200 or any(k.startswith("access-control-allow-") for k in hd6):
        f.append(UIFinding("CORS_PREFLIGHT_ALLOWED",
                           f"OPTIONS 预检 → {st6} 且头 {dict(hd6)}（预检必败被破坏）"))

    # 写接口与写类型
    st7, _, _ = raw_request(host, port, "POST", "/api/decide",
                            headers={"Content-Type": "application/json"},
                            body='{"id":"x","action":"take"}')
    if 200 <= st7 < 300:
        f.append(UIFinding("WRITE_ENDPOINT_OPEN", f"POST /api/decide → {st7}（写接口未关）"))
    st8, _, _ = raw_request(host, port, "POST", "/api/v1/decide",
                            headers={"Content-Type": "text/plain"}, body="id=1&action=take")
    if 200 <= st8 < 300:
        f.append(UIFinding("WRITE_WITH_TEXT_PLAIN_ALLOWED",
                           f"POST text/plain /api/v1/decide → {st8}（CSRF 型写入被接受）"))
    # 请求体上限：声明 1MB Content-Length 但不发体——拒绝必须先于读取
    st9, _, _ = raw_request(host, port, "POST", "/api/v1/x",
                            headers={"Content-Length": "1000000"})
    if 200 <= st9 < 300:
        f.append(UIFinding("BODY_LIMIT_MISSING", f"超大 Content-Length POST → {st9}（未拒收）"))
    # 路径白名单 / API 版本化
    st10, _, _ = raw_request(host, port, "GET", "/../server.py")
    if st10 == 200:
        f.append(UIFinding("PATH_TRAVERSAL_LEAK", "GET /../server.py → 200（白名单外泄）"))
    st11, _, _ = raw_request(host, port, "GET", "/api/components")
    if st11 != 404:
        f.append(UIFinding("API_VERSIONING_NOT_ENFORCED",
                           f"未版本化 /api/components → {st11}（应为 404 API_VERSION_REQUIRED）"))
    return f


def probe_health_watermark(host: str, port: int, expected: dict,
                           *, snapshot_fresh: bool = True) -> list[UIFinding]:
    """UI 与权威聚合器同水位：/api/v1/health 必须逐字透传快照判定，绝不自算。

    expected: {"policy_verdict": ..., 可选 "score", "generated_at"}。
    snapshot_fresh=False 时 503 结构化 ERROR 是合法形态（快照作废绝不透传旧结论）。
    """
    f: list[UIFinding] = []
    st, _, body = raw_request(host, port, "GET", "/api/v1/health")
    try:
        import json
        data = json.loads(body)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return [UIFinding("HEALTH_MALFORMED", f"/api/v1/health → {st} 非 JSON 对象")]
    if st == 503:
        if snapshot_fresh:
            err = data.get("error") if isinstance(data.get("error"), dict) else {}
            f.append(UIFinding(
                "HEALTH_UNAVAILABLE_ON_FRESH_SNAPSHOT",
                f"新鲜快照下 health 503 {err.get('code', '')}（UI 不可用且非输入所致）"))
        return f
    if st != 200:
        return [UIFinding("HEALTH_NOT_TRANSPARENT", f"/api/v1/health → {st} {data!r}")]
    if not snapshot_fresh:
        f.append(UIFinding("STALE_SNAPSHOT_TRANSPARENT",
                           "过期快照仍 200 透传（应作废为 503 结构化 ERROR）"))
    exp_verdict = expected.get("policy_verdict")
    got_verdict = data.get("policy_verdict") or data.get("overall") or data.get("verdict")
    if exp_verdict is not None and got_verdict != exp_verdict:
        f.append(UIFinding(
            "UI_VERDICT_DIVERGES_FROM_AUTHORITY",
            f"Gate 红（权威 {exp_verdict}）而 UI 判 {got_verdict!r}——UI 自算洗绿",
            evidence={"authority": exp_verdict, "ui": got_verdict}))
    if "score" in expected and data.get("score") != expected["score"]:
        f.append(UIFinding("UI_SCORE_RECOMPUTED",
                           f"score 透传 {data.get('score')!r} != 权威 {expected['score']!r}"))
    if expected.get("generated_at") and data.get("generated_at") != expected["generated_at"]:
        f.append(UIFinding("UI_WATERMARK_DIVERGES",
                           f"watermark {data.get('generated_at')!r} != {expected['generated_at']!r}"))
    return f


def probe_ledger_drill(host: str, port: int, state: str) -> tuple[list[UIFinding], dict]:
    """状态钻取：?items=STATE 必须返回该状态明细，且计数与聚合一致。"""
    import json
    f: list[UIFinding] = []
    st, _, b = raw_request(host, port, "GET", "/api/v1/bugscan-ledger")
    try:
        base = json.loads(b)
    except ValueError:
        return [UIFinding("LEDGER_BASE_MALFORMED", f"/api/v1/bugscan-ledger → {st} 非 JSON")], {}
    by_status = ((base.get("total") or {}).get("by_status")) if isinstance(base, dict) else None
    expected_total = (by_status or {}).get(state, 0) if isinstance(by_status, dict) else None

    st2, _, b2 = raw_request(host, port, "GET", f"/api/v1/bugscan-ledger?items={state}")
    try:
        d = json.loads(b2)
    except ValueError:
        return [UIFinding("LEDGER_DRILL_MALFORMED",
                          f"?items={state} → {st2} 非 JSON")], {}
    if st2 != 200:
        return [UIFinding("LEDGER_DRILL_UNAVAILABLE",
                          f"?items={state} → {st2}（状态不可钻取）")], d
    if d.get("items_state") != state:
        f.append(UIFinding("LEDGER_DRILL_STATE_MISMATCH",
                           f"请求 {state} 实返 items_state={d.get('items_state')!r}"))
    items = d.get("items") or []
    bad = [x.get("id") for x in items if not isinstance(x, dict) or x.get("st") != state]
    if bad:
        f.append(UIFinding("LEDGER_DRILL_STATE_MISMATCH",
                           f"钻取结果混入非 {state} 项: {bad[:5]}"))
    if expected_total is not None and d.get("items_total") != expected_total:
        f.append(UIFinding("LEDGER_DRILL_COUNT_MISMATCH",
                           f"items_total={d.get('items_total')} != 聚合 by_status[{state}]={expected_total}"))
    if expected_total and not items:
        f.append(UIFinding("LEDGER_DRILL_EMPTY",
                           f"聚合计 {state}={expected_total} 但钻取明细为空"))
    return f, d


def probe_rate_guard(host: str, port: int, burst: int = 220) -> tuple[list[UIFinding], int | None]:
    """过载防护：连续请求必须触发限速（429）。返回 (findings, 首个 429 的序号)。"""
    first_429: int | None = None
    for i in range(burst):
        st, _, _ = raw_request(host, port, "GET", "/api/v1/ping")
        if st == 429:
            first_429 = i + 1
            break
    if first_429 is None:
        return [UIFinding("RATE_LIMIT_MISSING",
                          f"{burst} 连发无 429（窗口限速缺失——高并发耗尽面）")], None
    return [], first_429

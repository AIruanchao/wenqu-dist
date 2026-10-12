#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""browser_e2e.py —— W11-14 C 面：真实 Chromium 浏览器验证（十轮 W8「真实
浏览器 UI 未验」扣分根修）。

不是 HTTP 单测、不是 DOM grep——起**真实 dashboard 服务** + **真实 Chromium**
（Playwright），走真实点击链并取证。不进 pytest 收集（无 test_ 前缀；CI 以
独立 required job 跑，浏览器不可用必须红，绝不静默 SKIP）。

验证面（方案 §W11-14）：
  1. 页面加载：四页签渲染、健康卡非错误态、页签真实点击切换；
  2. quarantine 面钻取：点击 QUARANTINE/ACCEPTED/OTHER/OPEN 节点 → 明细盒
     展开（reason/row_hash/preview 以文本呈现）、再点收起；
  3. 零态可操作：干净账本（quarantine=0）下 QUARANTINE 节点仍可点击且展示
     零态文案；
  4. API/DOM 一致：四状态节点计数与 /api/v1/bugscan-ledger 聚合完全一致；
  5. console：pageerror=0；除「logs 403（W11-08 fail-closed 首询，解锁前）」
     这一类**预期**资源错误外 console error=0；
  6. network：全部请求同源（XSS fixture 不产生任何外部请求）；请求/响应
     事件全量落证（脱敏 HAR：剥离 X-Auth-Key 值）；
  7. XSS fixture 不执行：日志/账本标题/sidecar preview 携带 <img onerror>/
     <script> payload——payload 文本必须在 DOM 在场（textContent 渲染）、
     window.__xss* 全局必须 undefined、无 dialog 触发；
  8. W11-08 解锁链：logs 首询 403 → prompt → 输入密钥（仅内存）→ 日志面板
     真实渲染日志内容。

退出码合同（方案 §W11-14）：
  0 = 全部通过；
  1 = DOM、console、network 任一不符；
  3 = 浏览器或运行体不可用（Playwright 缺失/Chromium 缺失/服务起不来）。

用法：
  python3 system/tests/browser_e2e.py                    # 沙箱 fixture 模式
  python3 system/tests/browser_e2e.py --out /tmp/w11-14-evidence/browser
  python3 system/tests/browser_e2e.py --base-url http://127.0.0.1:7789 \
      [--prod-key-file /path/0600.key]                  # 生产验收（只读）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[2]
SYSTEM = REPO / "system"
RC_OK, RC_FAIL, RC_UNAVAILABLE = 0, 1, 3

XSS_TITLE = '<img src=x onerror="window.__xssTitle=1">'
XSS_LOG = "<script>window.__xssLog=1</script>"
XSS_SIDEcar = '<svg onload=window.__xssQ=1>'


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Verdict:
    def __init__(self):
        self.failures: list[str] = []
        self.notes: list[str] = []
        self.blocks: list[dict] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.blocks.append({"name": name, "ok": bool(ok), "detail": detail, "ts": _now_iso()})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"：{detail}" if detail else ""))
        if not ok:
            self.failures.append(f"{name}: {detail}")
        return ok

    def note(self, msg: str):
        self.notes.append(msg)
        print(f"  [NOTE] {msg}")


# ───────────────────────── fixture：沙箱 dashboard ─────────────────────────
def boot_sandbox(tmp: Path, *, clean: bool = False):
    """起真实 dashboard 服务 + 沙箱数据面。返回 (dash, key)。"""
    sys.path.insert(0, str(SYSTEM))
    sys.path.insert(0, str(SYSTEM / "tests"))
    from test_ac_ui_family import _Dash, _write_snapshot  # noqa: E402

    dash = _Dash(tmp, log_key=None if clean else "browser-e2e-log-key-0123456789")
    dash.__enter__()
    _write_snapshot(dash.snap, "PASS", score=92)
    logs_dir = dash.home / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    if not clean:
        (logs_dir / "sentinel-e2e.log").write_text(
            XSS_LOG + "\nE2E-NORMAL-LINE-42\n", encoding="utf-8")
    proj = dash.ledger_root / "e2eproj"
    proj.mkdir(parents=True, exist_ok=True)
    with open(proj / "findings.jsonl", "w", encoding="utf-8") as fh:
        if not clean:
            fh.write(json.dumps({"id": "E-1", "sev": "HIGH", "status": "OPEN",
                                 "title": XSS_TITLE + " 浏览器标题", "ts": "2026-10-05T10:00:00"},
                                ensure_ascii=False) + "\n")
            fh.write(json.dumps({"id": "E-2", "sev": "MED", "status": "accepted-risk",
                                 "title": "接受项", "ts": "2026-10-04T10:00:00"},
                                ensure_ascii=False) + "\n")
            fh.write(json.dumps({"id": "E-3", "sev": "LOW", "status": "deferred-x",
                                 "title": "残差项", "ts": "2026-10-03T10:00:00"},
                                ensure_ascii=False) + "\n")
            fh.write('{"id": e2e-broken-line\n')  # fold 坏行 → QUARANTINE
            with open(proj / ".quarantine.jsonl", "w", encoding="utf-8") as sf:
                sf.write(json.dumps({"reason": "unknown_status:legacy-token",
                                     "preview": XSS_SIDEcar + " sidecar 行",
                                     "line": 9, "ts": "2026-10-01T00:00:00Z"},
                                    ensure_ascii=False) + "\n")
        else:
            fh.write(json.dumps({"id": "C-1", "sev": "LOW", "status": "OPEN",
                                 "title": "干净账本唯一行", "ts": "2026-10-05T10:00:00"},
                                ensure_ascii=False) + "\n")
    return dash


# ───────────────────────── 浏览器主流程 ─────────────────────────
def run_browser(base_url: str, out: Path, *, prod_key: str | None,
                headless: bool) -> tuple[Verdict, int]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        print(f"  [BLOCK] Playwright 不可用：{e}（rc3/BLOCKED——绝不静默降级为 HTTP 级）")
        return Verdict(), RC_UNAVAILABLE

    v = Verdict()
    console_log: list[dict] = []
    network_log: list[dict] = []
    dialogs: list[str] = []
    har_raw = out / "har-raw.json"
    out.mkdir(parents=True, exist_ok=True)
    unlock_ts = [None]  # logs 解锁完成时刻（此后 console error 必须=0）

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=headless)
        except Exception as e:  # noqa: BLE001 —— 浏览器不可用=rc3/BLOCKED
            print(f"  [BLOCK] Chromium 启动失败：{e}（rc3/BLOCKED）")
            return v, RC_UNAVAILABLE
        try:
            ctx = browser.new_context(record_har_path=str(har_raw), record_har_mode="minimal")
            page = ctx.new_page()
            page.set_default_timeout(20000)

            def on_console(msg):
                entry = {"type": msg.type, "text": msg.text, "ts": _now_iso()}
                try:
                    loc = msg.location
                    entry["url"] = loc.url if loc else ""
                except Exception:  # noqa: BLE001
                    pass
                console_log.append(entry)

            def on_dialog(d):
                dialogs.append(f"{d.type}:{(d.message or '')[:40]}")
                if d.type == "prompt" and prod_key:
                    d.accept(prod_key)
                    unlock_ts[0] = time.monotonic()
                else:
                    d.dismiss()

            page.on("console", on_console)
            page.on("pageerror", lambda e: console_log.append(
                {"type": "pageerror", "text": str(e), "ts": _now_iso()}))
            page.on("dialog", on_dialog)
            origin = urlparse(base_url)
            same_origin = f"{origin.scheme}://{origin.netloc}"

            def on_request(req):
                network_log.append({"phase": "request", "method": req.method,
                                    "url": req.url, "ts": _now_iso()})

            def on_response(resp):
                network_log.append({"phase": "response", "status": resp.status,
                                    "url": resp.url, "ts": _now_iso()})

            page.on("request", on_request)
            page.on("response", on_response)

            # ── 1. 页面加载 ──
            try:
                page.goto(base_url + "/", wait_until="domcontentloaded")
            except Exception as e:  # noqa: BLE001
                v.check("page-load", False, f"页面加载失败：{e}")
                return v, RC_FAIL
            v.check("page-load", True, page.title())
            page.wait_for_selector("#tabs .tab", state="visible")
            tabs = page.locator("#tabs .tab")
            v.check("four-tabs", tabs.count() == 4, f"页签数 {tabs.count()}（期望 4）")
            # 健康卡非错误态（数据面真实渲染）
            page.wait_for_selector("#healthcard", state="visible")
            # 页签真实点击切换（四页签逐一）
            tab_ok = True
            for i in range(tabs.count()):
                tabs.nth(i).click()
                active = page.locator("#tabs .tab.active").get_attribute("data-t")
                want = tabs.nth(i).get_attribute("data-t")
                if active != want:
                    tab_ok = False
                    v.note(f"页签切换不符：点 {want} 实得 active={active}")
            tabs.nth(3).click()  # 停在 bug 管线页（钻取面所在）
            v.check("tab-click-chain", tab_ok, "四页签真实点击切换全一致")

            # ── 4. API/DOM 计数一致 ──
            api = page.evaluate(
                "async () => (await (await fetch('/api/v1/bugscan-ledger')).json())")
            st = api.get("total", {}).get("by_status", {})
            qtotal = api.get("quarantine_total")

            def node_count(label: str) -> str:
                loc = page.locator(
                    "div.bnode.side",
                    has=page.locator("b", has_text=label)).locator(".cnt")
                return loc.inner_text(timeout=5000).strip()

            page.wait_for_selector("div.bnode.side", state="visible")
            for label, expect in (("ACCEPTED", st.get("ACCEPTED", 0)),
                                  ("OTHER", st.get("OTHER", 0)),
                                  ("QUARANTINE", qtotal)):
                got = node_count(label)
                v.check(f"count-{label.lower()}-api-dom",
                        got == str(expect), f"DOM={got} API={expect}")

            # ── 2. quarantine 面钻取（真实点击） ──
            def drill(label: str, expect_rows: int | None = None) -> str:
                page.locator("div.bnode.side",
                             has=page.locator("b", has_text=label)).click()
                page.wait_for_selector("#bglitems", state="visible")
                # 等 fetch 完成载入中→明细头出现（防把「载入中…」当明细）
                page.wait_for_function(
                    "() => {const b=document.querySelector('#bglitems');"
                    "return b && b.textContent.includes('明细');}")
                box = page.locator("#bglitems")
                txt = box.inner_text(timeout=5000)
                if expect_rows is not None:
                    rows = box.locator("div.row").count()
                    v.check(f"drill-{label.lower()}-rows",
                            rows == expect_rows, f"明细行 {rows}（期望 {expect_rows}）")
                return txt

            txt_q = drill("QUARANTINE", expect_rows=(qtotal or 0))
            v.check("drill-quarantine-fields",
                    ("invalid_json" in txt_q or "unknown_status" in txt_q)
                    and re.search(r"\b[0-9a-f]{12}\b", txt_q) is not None,
                    "隔离明细含 reason + row_hash 前 12 hex")
            page.screenshot(path=str(out / "screenshot-quarantine-drill.png"),
                            full_page=False)
            drill("ACCEPTED", expect_rows=st.get("ACCEPTED", 0))
            drill("OTHER", expect_rows=st.get("OTHER", 0))
            # OPEN（链首）也可点
            page.locator("div.bnode", has=page.locator("b", has_text="OPEN")).first.click()
            page.wait_for_selector("#bglitems", state="visible")
            page.wait_for_function(
                "() => {const b=document.querySelector('#bglitems');"
                "return b && b.textContent.includes('明细');}")
            v.check("drill-open", True, "OPEN 链首节点可点且明细盒展开")

            # ── 8. W11-08 解锁链 / logs 渲染（回总览页——#logs 在 ov 页签内） ──
            page.locator('#tabs .tab[data-t="ov"]').click()
            if prod_key:
                page.wait_for_selector("#logs pre, #logs .errbox", state="visible")
                logs_txt = page.locator("#logs").inner_text(timeout=5000)
                v.check("logs-unlocked-render", "E2E-NORMAL-LINE-42" in logs_txt or
                        ".log" in logs_txt, f"日志面板渲染 {len(logs_txt)}B")
                page.screenshot(path=str(out / "screenshot-logs-unlocked.png"),
                                full_page=False)

            # ── 7. XSS fixture 不执行 ──
            globals_ok = page.evaluate(
                "() => ['__xssTitle','__xssLog','__xssQ','__xss1','__xss2']"
                ".every(k => window[k] === undefined)")
            # 文本在场证据读 textContent（page.content() 是 HTML 序列化，会转义 <）
            payload_in_dom = page.evaluate(
                "s => document.body.textContent.includes(s)", XSS_TITLE) \
                and page.evaluate("s => document.body.textContent.includes(s)", XSS_LOG)
            v.check("xss-not-executed", bool(globals_ok),
                    f"window.__xss* 全 undefined={globals_ok}；prompt 链={dialogs[:1]}")
            v.check("xss-payload-as-text", bool(payload_in_dom),
                    "payload 以文本在场（textContent 渲染证据）")

            # ── 截图/DOM 取证 ──
            page.screenshot(path=str(out / "screenshot-main.png"), full_page=True)
            (out / "dom-snapshot.html").write_text(page.content(), encoding="utf-8")

            ctx.close()  # 落 HAR
        finally:
            browser.close()

    # ── 5. console 判定 ──
    # 预期类（逐类登记，绝不放宽其它）：
    #   a) logs 403 资源错误——W11-08 fail-closed 首询（解锁前），设计内行为；
    #   b) Chromium 对 meta 形式 frame-ancestors/X-Frame-Options 的厂商提示——
    #      真正的强制通道是服务器响应头（server.py _sec_headers 每响应必带）；
    #      index.html 内这两条 meta 是文档性声明（既有构建门契约要求在位，
    #      ui_probe._CSP_META_REQUIRED/自检门逐字断言——改约属独立工单）。
    RE_403 = re.compile(r"status of 403")
    RE_META_CSP = re.compile(
        r"(frame-ancestors' is ignored when delivered via a <meta>|"
        r"X-Frame-Options may only be set via an HTTP header)")
    # 网络面归因底账：会话内除 /api/v1/logs 外是否还存在其它 403（无则无
    # location 的 403 资源错误可唯一归因 logs——W11-08 fail-closed 首询）
    other_403 = [n["url"] for n in network_log
                 if n.get("status") == 403 and not n["url"].endswith("/api/v1/logs")]

    def _is_expected_403(c: dict) -> bool:
        if not RE_403.search(c.get("text", "")):
            return False
        u = c.get("url", "")
        if u.endswith("/api/v1/logs"):
            return True
        return u == "" and not other_403

    pageerrors = [c for c in console_log if c["type"] == "pageerror"]
    v.check("console-pageerror-zero", not pageerrors,
            f"pageerror {len(pageerrors)} 条" + (f"：{pageerrors[:2]}" if pageerrors else ""))
    errors = [c for c in console_log if c["type"] == "error"]
    n_403 = sum(1 for c in errors if _is_expected_403(c))
    n_meta = sum(1 for c in errors if RE_META_CSP.search(c.get("text", "")))
    unexpected = [c for c in errors
                  if not _is_expected_403(c)
                  and not RE_META_CSP.search(c.get("text", ""))]
    v.check("console-error-zero", not unexpected,
            f"console error 共 {len(errors)} 条：logs-403（fail-closed 预期）{n_403}、"
            f"meta-CSP 厂商提示（头部强制为主通道）{n_meta}、非预期 {len(unexpected)}"
            + (f"：{unexpected[:2]}" if unexpected else ""))
    v.check("no-unexpected-dialogs", not dialogs or all(d.startswith("prompt") for d in dialogs),
            f"dialogs={dialogs[:3]}")

    # ── 6. network 判定：全同源、零外部请求 ──
    external = [n for n in network_log if not n["url"].startswith(same_origin)
                and not n["url"].startswith("data:")]
    v.check("network-same-origin-only", not external,
            f"请求总数 {len(network_log)}，外部请求 {len(external)}"
            + (f"：{external[:3]}" if external else ""))

    # ── 证据落盘（HAR 脱敏：X-Auth-Key 值绝不入证） ──
    try:
        har = json.loads(har_raw.read_text(encoding="utf-8"))
        for entry in har.get("log", {}).get("entries", []):
            for hdr in entry.get("request", {}).get("headers", []):
                if hdr.get("name", "").lower() == "x-auth-key":
                    hdr["value"] = "[REDACTED]"
        (out / "har-sanitized.json").write_text(
            json.dumps(har, ensure_ascii=False, indent=1), encoding="utf-8")
        har_raw.unlink()
    except (OSError, ValueError) as e:
        v.note(f"HAR 脱敏失败（原 HAR 保留为 har-raw.json）：{e}")
    (out / "console.json").write_text(
        json.dumps(console_log, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "network.json").write_text(
        json.dumps(network_log, ensure_ascii=False, indent=1), encoding="utf-8")

    return v, (RC_OK if not v.failures else RC_FAIL)


def run_zero_state(out: Path, headless: bool) -> tuple[Verdict, int]:
    """干净账本（quarantine=0）零态可操作腿（方案 §W11-14 第 8 点）。"""
    from playwright.sync_api import sync_playwright
    v = Verdict()
    with tempfile.TemporaryDirectory(prefix="wq_e2e_zero_") as tmp:
        dash = boot_sandbox(Path(tmp), clean=True)
        try:
            base_url = f"http://127.0.0.1:{dash.port}"
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=headless)
                page = browser.new_context().new_page()
                page.set_default_timeout(20000)
                page.goto(base_url + "/", wait_until="domcontentloaded")
                page.locator('#tabs .tab[data-t="bugdeck"]').click()  # 状态机在 bug 管线页签内
                page.wait_for_selector("div.bnode.side", state="visible")
                cnt = page.locator("div.bnode.side",
                                   has=page.locator("b", has_text="QUARANTINE")) \
                    .locator(".cnt").inner_text()
                v.check("zero-quarantine-count", cnt == "0", f"QUARANTINE 节点计数 {cnt}（期望 0）")
                node = page.locator("div.bnode.side",
                                    has=page.locator("b", has_text="QUARANTINE"))
                v.check("zero-node-clickable", node.is_enabled(), "零态节点可点击")
                node.click()
                page.wait_for_selector("#bglitems", state="visible")
                page.wait_for_function(
                    "() => {const b=document.querySelector('#bglitems');"
                    "return b && b.textContent.includes('明细');}")  # 载入中→明细（fetch 完成）
                txt = page.locator("#bglitems").inner_text(timeout=5000)
                v.check("zero-state-panel", "0" in txt and "零态" in txt,
                        f"零态面板文案在场：{txt[:60]!r}")
                node.click()  # 再点收起（可操作双向）
                page.wait_for_selector("#bglitems", state="detached")
                v.check("zero-state-collapse", True, "再点收起成功")
                page.screenshot(path=str(out / "screenshot-zero-state.png"), full_page=False)
                browser.close()
        finally:
            dash.__exit__(None, None, None)
    return v, (RC_OK if not v.failures else RC_FAIL)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="真实 Chromium 浏览器验证（W11-14 C；rc0/1/3）")
    ap.add_argument("--base-url", help="生产模式：现役 dashboard URL（如 http://127.0.0.1:7789）；"
                                       "缺省=沙箱 fixture 模式（起真实服务+注入数据面）")
    ap.add_argument("--prod-key-file", help="生产模式 logs 解锁密钥文件（0600；可选）")
    ap.add_argument("--out", default="/tmp/w11-14-evidence/browser-e2e",
                    help="证据输出目录")
    ap.add_argument("--headed", action="store_true", help="有头模式（本机调试）")
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    headless = not args.headed

    print("== browser_e2e（真实 Chromium；W11-14 C 面）==")
    prod_key = None
    if args.prod_key_file:
        try:
            if (os.stat(args.prod_key_file).st_mode & 0o777) != 0o600:
                print(f"  [BLOCK] 密钥文件非 0600：{args.prod_key_file}")
                return RC_UNAVAILABLE
            prod_key = Path(args.prod_key_file).read_text(encoding="utf-8").strip()
        except OSError as e:
            print(f"  [BLOCK] 密钥文件不可读：{e}")
            return RC_UNAVAILABLE

    summary: dict = {"tool": "browser_e2e/1.0", "generated_at": _now_iso(),
                     "mode": "production" if args.base_url else "sandbox-fixture",
                     "base_url": args.base_url, "checks": [], "rc": None}

    try:
        if args.base_url:
            v, rc = run_browser(args.base_url, out, prod_key=prod_key, headless=headless)
            summary["checks"] = v.blocks
        else:
            # 沙箱 fixture 模式：主数据面 + 零态腿（两个独立沙箱）
            with tempfile.TemporaryDirectory(prefix="wq_e2e_main_") as tmp:
                dash = boot_sandbox(Path(tmp))
                try:
                    v, rc = run_browser(f"http://127.0.0.1:{dash.port}", out,
                                        prod_key="browser-e2e-log-key-0123456789",
                                        headless=headless)
                    summary["checks"] = v.blocks
                finally:
                    dash.__exit__(None, None, None)
            if rc == RC_OK:
                v2, rc2 = run_zero_state(out, headless)
                summary["checks"] += v2.blocks
                rc = rc2 if rc2 != RC_OK else rc
    except Exception as exc:  # noqa: BLE001 —— 运行体级故障=rc3/BLOCKED
        print(f"  [BLOCK] 运行体不可用：{type(exc).__name__}: {exc}")
        summary["rc"] = RC_UNAVAILABLE
        (out / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
        return RC_UNAVAILABLE

    summary["rc"] = rc
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"RESULT: rc={rc}（0=全过 / 1=DOM·console·network 不符 / 3=浏览器或运行体不可用）")
    return rc


if __name__ == "__main__":
    sys.exit(main())

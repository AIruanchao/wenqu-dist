#!/usr/bin/env python3
"""wenqu dashboard —— 单文件零依赖 Web 仪表盘（v3.1 新增）

用法：wenqu dashboard [端口=7788]
数据源全部现成：组件体检/守护状态/哨兵日志尾/引擎账本尾/棘轮基线。
"""
import json
import os
import signal
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WQ = os.environ.get("WENQU_HOME", os.path.expanduser("~/.wenqu"))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7788

COMPONENTS = {
    "bin": ["wenqu-env.sh", "iron-gate.sh", "blast-radius.py", "cursor-auto-verify.sh",
            "deploy-preflight.sh", "hardening-doctor.sh", "wenqu-dashboard.py"],
    "sentinels": ["ci-event-sentinel.sh", "conservation-sentinel.sh", "ssl-cert-sentinel.sh"],
    "daemons": ["auto-merge.sh", "conservation-daemon.py"],
}

PAGE = """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<title>问渠 wenqu · 仪表盘</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#c9d1d9;--dim:#8b949e;--ok:#3fb950;--bad:#f85149;--acc:#58a6ff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,"PingFang SC",monospace;padding:24px}
h1{font-size:18px;margin-bottom:4px} .sub{color:var(--dim);font-size:12px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px}
.card h2{font-size:13px;color:var(--acc);margin-bottom:10px;font-weight:600}
.row{display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px dashed #21262d;font-size:13px}
.row:last-child{border:none}
.ok{color:var(--ok)} .bad{color:var(--bad)} .dim{color:var(--dim)}
pre{background:#0a0d12;border:1px solid var(--line);border-radius:6px;padding:10px;font-size:11px;overflow:auto;max-height:260px;color:#a8b3bf}
.bar{height:6px;background:#21262d;border-radius:3px;overflow:hidden;margin:6px 0}
.bar>i{display:block;height:100%;background:var(--ok)}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;background:#1f6feb33;color:var(--acc);margin-left:8px}
#ts{color:var(--dim);font-size:11px}
</style></head><body>
<h1>问渠 wenqu <span class="badge" id="ver">…</span></h1>
<div class="sub">本地质量工程体系 · <span id="ts"></span> · 端口 """ + str(PORT) + """</div>
<div class="grid">
  <div class="card"><h2>组件体检</h2><div id="comp">载入中…</div></div>
  <div class="card"><h2>守护进程</h2><div id="daemon">载入中…</div>
    <div style="margin-top:8px" class="dim" id="cronline"></div></div>
  <div class="card"><h2>棘轮基线（若项目接入）</h2><div id="ratchet">—</div></div>
  <div class="card"><h2>引擎账本 · 最近 8 轮</h2><div id="rounds">载入中…</div></div>
  <div class="card" style="grid-column:1/-1"><h2>哨兵日志尾</h2>
    <div id="logs"></div></div>
</div>
<script>
async function j(u){const r=await fetch(u);return r.json()}
function el(h){const d=document.createElement('div');d.innerHTML=h;return d}
async function refresh(){
  const c=await j('/api/components');const box=document.getElementById('comp');box.innerHTML='';
  let ok=0,tot=0;
  for(const[grp,items]of Object.entries(c)){
    if(!Array.isArray(items))continue;
    for(const it of items){tot++;if(it.ok)ok++;
      box.appendChild(el(`<div class="row"><span>${grp}/${it.name}</span><span class="${it.ok?'ok':'bad'}">${it.ok?'✓ 在位':'✗ 缺失'}</span></div>`))}
  }
  const pct=tot?Math.round(ok*100/tot):0;
  box.prepend(el(`<div class="bar"><i style="width:${pct}%"></i></div><div class="row"><span>完整度</span><span class="${pct==100?'ok':'bad'}">${ok}/${tot}</span></div>`));
  document.getElementById('ver').textContent=c.version||'';
  const d=await j('/api/daemons');const db=document.getElementById('daemon');db.innerHTML='';
  const ds=Object.entries(d.daemons);
  if(!ds.length)db.innerHTML='<span class="dim">无运行中守护（wenqu start）</span>';
  for(const[n,s]of ds)db.appendChild(el(`<div class="row"><span>${n}</span><span class="${s=='运行中'?'ok':'bad'}">${s}</span></div>`));
  document.getElementById('cronline').textContent=`cron 哨兵任务：${d.cron} 条`;
  const r=await j('/api/ratchet');const rb=document.getElementById('ratchet');
  rb.innerHTML=r.available?'':'<span class="dim">未接入（项目内 scripts/dupscan/baseline.json）</span>';
  if(r.available){rb.innerHTML='';
    for(const[l,v]of Object.entries(r.layers))rb.appendChild(el(`<div class="row"><span>${l}</span><span>${v.clones} 克隆 / ${v.rate}%</span></div>`))}
  const rd=await j('/api/rounds');const rbox=document.getElementById('rounds');rbox.innerHTML='';
  for(const x of rd.rounds)rbox.appendChild(el(`<div class="row" title="${(x.label||'').replace(/"/g,'&quot;')}"><span class="dim" style="flex:0 0 76px">${x.ts||''}</span><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${x.label}</span></div>`));
  const lg=await j('/api/logs');const lbox=document.getElementById('logs');lbox.innerHTML='';
  for(const[n,t]of Object.entries(lg)){lbox.appendChild(el(`<h2 style="margin-top:8px">${n}</h2>`));const p=document.createElement('pre');p.textContent=t;lbox.appendChild(p)}
  document.getElementById('ts').textContent='更新于 '+new Date().toLocaleTimeString();
}
refresh();setInterval(refresh,15000);
</script></body></html>"""


def components():
    out = {}
    for grp, items in COMPONENTS.items():
        out[grp] = [{"name": n, "ok": os.path.isfile(os.path.join(WQ, grp, n))} for n in items]
    ver = ""
    try:
        with open(os.path.join(WQ, "VERSION")) as f:
            ver = f.read().strip()
    except OSError:
        pass
    return {"components": out, "version": ver}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if self.path == "/api/components":
            c = components()
            flat = {}
            for grp, items in c["components"].items():
                flat[grp] = items
            return self._send(200, json.dumps({"version": c["version"], **flat}, ensure_ascii=False))
        if self.path == "/api/daemons":
            daemons, state = {}, os.path.join(WQ, "state")
            if os.path.isdir(state):
                for f in os.listdir(state):
                    if f.endswith(".pid"):
                        try:
                            pid = int(open(os.path.join(state, f)).read().strip())
                            os.kill(pid, 0)
                            st = "运行中"
                        except OSError:
                            st = "已退出"
                        daemons[f[:-4]] = st
            cron = 0
            try:
                cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout.count("wenqu/sentinels")
            except OSError:
                pass
            return self._send(200, json.dumps({"daemons": daemons, "cron": cron}, ensure_ascii=False))
        if self.path == "/api/ratchet":
            for cand in ("scripts/dupscan/baseline.json", os.path.join(os.environ.get("WENQU_REPO_DIR", ""), "scripts/dupscan/baseline.json")):
                if cand and os.path.isfile(cand):
                    try:
                        d = json.load(open(cand))
                        return self._send(200, json.dumps({"available": True, "layers": {
                            k: {"clones": v.get("clones"), "rate": v.get("duplicate_rate_pct")} for k, v in d.get("layers", {}).items()}}, ensure_ascii=False))
                    except (OSError, ValueError):
                        pass
            return self._send(200, json.dumps({"available": False}, ensure_ascii=False))
        if self.path == "/api/rounds":
            rounds, path = [], os.environ.get("WENQU_LEDGER")
            if not path:
                for cand in ("ERP）Zcode/持续修复引擎/engine-rounds.jsonl", "持续修复引擎/engine-rounds.jsonl"):
                    p = os.path.expanduser(f"~/Documents/{cand}")
                    if os.path.isfile(p):
                        path = p
                        break
            if path and os.path.isfile(path):
                try:
                    lines = [l for l in open(path, errors="ignore") if l.strip()][-8:]
                    for l in lines:
                        try:
                            d = json.loads(l)
                            rnd = d.get("round") or d.get("id") or ""
                            ts = str(d.get("ts", ""))[5:16]
                            st = d.get("state") or d.get("summary") or d.get("title") or ""
                            label = str(st)[:60] or d.get("type", "")
                            rounds.append({"ts": ts, "label": f"r{rnd} {label}" if rnd else label})
                        except ValueError:
                            continue
                except OSError:
                    pass
            return self._send(200, json.dumps({"rounds": rounds}, ensure_ascii=False))
        if self.path == "/api/logs":
            out, logdir = {}, os.path.join(WQ, "logs")
            if os.path.isdir(logdir):
                for f in sorted(os.listdir(logdir)):
                    if f.endswith(".log"):
                        try:
                            tail = subprocess.run(["tail", "-n", "20", os.path.join(logdir, f)], capture_output=True, text=True).stdout
                            out[f] = tail or "(空)"
                        except OSError:
                            pass
            if not out:
                out["(说明)"] = "哨兵经 wenqu cron 安装后，日志将出现在 ~/.wenqu/logs/"
            return self._send(200, json.dumps(out, ensure_ascii=False))
        return self._send(404, '{"error":"not found"}')


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print(f"wenqu dashboard → http://127.0.0.1:{PORT}  (Ctrl-C 停)")
    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))
    srv.serve_forever()


if __name__ == "__main__":
    main()

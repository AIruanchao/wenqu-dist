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
.tab{background:var(--card);border:1px solid var(--line);color:var(--dim);border-radius:6px;padding:6px 18px;cursor:pointer;font-size:13px}
.tab.active{color:var(--acc);border-color:var(--acc)}
.pl{margin-bottom:28px}
.pl h3{font-size:14px;color:var(--fg);margin-bottom:2px}
.pl .src{color:var(--dim);font-size:11px;margin-bottom:10px}
.flow{display:flex;flex-direction:column;align-items:center;gap:2px}
.frow{display:flex;gap:10px;align-items:stretch;justify-content:center;flex-wrap:wrap}
.node{background:var(--card);border:1px solid var(--acc);border-radius:8px;padding:8px 14px;text-align:center;min-width:130px;max-width:230px}
.node b{color:var(--acc);font-size:12px;display:block;margin-bottom:2px}
.node span{color:var(--dim);font-size:11px;line-height:1.45;display:block}
.node.alt{border-color:#3d44db}
.node.fin{border-color:var(--ok)}
.arrow{color:var(--dim);font-size:15px;line-height:1;padding:3px 0}
.lane{border-style:dashed}
.mx{display:grid;grid-template-columns:repeat(5,52px);gap:4px;margin:8px auto;width:max-content}
.mx div{height:40px;border:1px solid var(--line);border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:10px;color:var(--dim);background:var(--card)}
.mx .hd{border-color:var(--acc);color:var(--acc);font-weight:600}
.mx .self{opacity:.25}
.mx .rv{border-color:#3d44db;color:#a5b4fc}
</style></head><body>
<h1>问渠 wenqu <span class="badge" id="ver">…</span></h1>
<div class="sub">本地质量工程体系 · <span id="ts"></span> · 端口 """ + str(PORT) + """</div>
<nav style="margin-bottom:14px;display:flex;gap:8px">
  <button class="tab active" onclick="showTab('ov')">总览</button>
  <button class="tab" onclick="showTab('pipe')">管线流程</button>
</nav>
<div id="pipe" style="display:none"><div class="pl"><h3>四轨出生制 v3.1</h3><div class="src">正源：optimal-quality-process（方案/规格/规则类自动触发；假设任何单轨不可信——任何错误至少被两层独立机制拦截）</div>
<div class="flow">
 <div class="frow"><div class="node"><b>S0 brief 起草</b><span>FACT 编号事实+TERM 术语表+ASSUMPTION 假设</span></div>
 <div class="node"><b>S0.5 brief 复审</b><span>冻结前两轨异源审完备性（brief=全员上界）</span></div></div>
 <div class="arrow">▼</div>
 <div class="frow">
  <div class="node lane"><b>ZCode 轨</b><span>盲写·隔离期禁通信</span></div>
  <div class="node lane"><b>Claude 轨</b><span>盲写·隔离期禁通信</span></div>
  <div class="node lane"><b>M3 轨</b><span>盲写·隔离期禁通信</span></div>
  <div class="node lane"><b>Codex 轨</b><span>盲写·完整性前置检查</span></div></div>
 <div class="arrow">▼ S1 四起草 → S1.5 双格式落地（哈希校验）</div>
 <div class="mx">
  <div></div><div class="hd">ZCode</div><div class="hd">Claude</div><div class="hd">M3</div><div class="hd">Codex</div>
  <div class="hd">ZCode</div><div class="self">自</div><div class="rv">审②</div><div class="rv">审③</div><div class="rv">审④</div>
  <div class="hd">Claude</div><div class="rv">审①</div><div class="self">自</div><div class="rv">审⑤</div><div class="rv">审⑥</div>
  <div class="hd">M3</div><div class="rv">审⑦</div><div class="rv">审⑧</div><div class="self">自</div><div class="rv">审⑨</div>
  <div class="hd">Codex</div><div class="rv">审⑩</div><div class="rv">审⑪</div><div class="rv">审⑫</div><div class="self">自</div></div>
 <div class="arrow">▼ S2 四方交叉盲审 = 4×3 十二份（批次封口/迟到不入批/BLOCKER 即断）</div>
 <div class="frow"><div class="node alt"><b>S2.5 材料打包</b><span>杂交稿+处置矩阵+对质索引+BLOCKER 清单（双写校验）</span></div>
 <div class="node alt"><b>S3 对质大会</b><span>六审齐无条件启动；异议保护：1:2 分歧不得被多数决关闭</span></div></div>
 <div class="arrow">▼</div>
 <div class="frow"><div class="node fin"><b>三源终审</b><span>螺旋熔断停审</span></div><div class="node fin"><b>用户终裁</b><span>发布/打回</span></div></div>
</div></div>

<div class="pl"><h3>EQS 七段开发管线</h3><div class="src">正源：eqs-dev-flow（顺序不可倒；质量关卡放激励正确的一侧——验收域在方案时冻结，实扫在完成时执行）</div>
<div class="flow"><div class="frow">
 <div class="node"><b>① 需求卡</b><span>范围/风险/成功条件</span></div><div class="arrow">▸</div>
 <div class="node"><b>② 双轨方案</b><span>CC 独立写+ZCode 审</span></div><div class="arrow">▸</div>
 <div class="node alt"><b>③ EQS 前置门禁</b><span>冻结「收敛底表」=考卷（过门禁≠完成）</span></div><div class="arrow">▸</div>
 <div class="node"><b>④ 实现</b><span>Cursor 冻结工单+ZCode 亲验三步</span></div><div class="arrow">▸</div>
 <div class="node"><b>⑤ 亲验</b><span>diff 全读/独立复跑/关键断言</span></div><div class="arrow">▸</div>
 <div class="node alt"><b>⑥ 递归清零</b><span>对照底表 N 轮异源实扫</span></div><div class="arrow">▸</div>
 <div class="node fin"><b>⑦ EQS 全量+Gate</b><span>验收契约终判</span></div></div></div></div>

<div class="pl"><h3>问渠八站 · 一环一本账</h3><div class="src">正源：bug-scan-pipeline（站序=成本×确定性递增，便宜的先拦；编排层不造轮子）</div>
<div class="flow">
 <div class="frow">
  <div class="node"><b>站0 范围冻结</b><span>每次开扫首站·五元组指纹</span></div><div class="arrow">▸</div>
  <div class="node"><b>站1 源闸</b><span>PR 阻断·CI Fast+棘轮</span></div><div class="arrow">▸</div>
  <div class="node"><b>站2 静态与供应链</b><span>周·dupscan+引擎五类+CVE</span></div><div class="arrow">▸</div>
  <div class="node"><b>站3 契约与数据</b><span>周·openapi+org-guard+矩阵</span></div></div>
 <div class="arrow">▼</div>
 <div class="frow">
  <div class="node"><b>站4 行为面</b><span>nightly·e2e 全量+抽检</span></div><div class="arrow">▸</div>
  <div class="node"><b>站5 实弹面</b><span>发布前·真单 14 节链+18 发对抗</span></div><div class="arrow">▸</div>
  <div class="node"><b>站6 对抗面</b><span>事件·上产 24h 四轴+反例轮</span></div><div class="arrow">▸</div>
  <div class="node"><b>站7 运行时</b><span>持续·Argus 哨兵（不参与收敛声明）</span></div></div>
 <div class="arrow">▼ 横切 · 收敛环（任何「干净/扫完」声明必过）</div>
 <div class="frow"><div class="node alt" style="max-width:560px"><b>递归清零 v2.2</b><span>N 轮异源实扫：FAST=1 / STANDARD=2 / INCIDENT=3（末轮含 S3 对抗或 S5 独立审计）；上限 N+1 超限转人工；每轮 rounds.jsonl 工件，无工件不计轮；同命令族+同时辰+换模型转述≠异源</span></div></div>
</div></div></div>
<div class="grid" id="ov">
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
function showTab(t){
  document.getElementById('ov').style.display=t=='ov'?'':'none';
  document.getElementById('pipe').style.display=t=='pipe'?'':'none';
  document.querySelectorAll('.tab').forEach((b,i)=>b.classList.toggle('active',(t=='ov')==(i==0)));
}
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

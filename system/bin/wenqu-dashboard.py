#!/usr/bin/env python3
"""wenqu dashboard —— 单文件零依赖 Web 仪表盘（v3.1 新增）

用法：wenqu dashboard [端口=7788]
数据源全部现成：组件体检/守护状态/哨兵日志尾/引擎账本尾/棘轮基线。
"""
import json
from datetime import datetime, timedelta
import os
import re
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WQ = os.environ.get("WENQU_HOME", os.path.expanduser("~/.wenqu"))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7788
_DECIDE_LOCK = threading.Lock()  # /api/decide 读改写整段互斥（ThreadingHTTPServer 并发下防丢账）

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
@keyframes flash{0%{background:#f0883e55}100%{background:transparent}}
.flash{animation:flash 1.6s ease-out}
@keyframes popnum{0%{transform:scale(1.25);color:#f0883e}100%{transform:scale(1)}}
.popnum{animation:popnum .9s ease-out}
.spark{display:flex;align-items:flex-end;gap:2px;height:34px;margin-left:auto}
.spark i{width:7px;border-radius:2px 2px 0 0;background:linear-gradient(180deg,#3fb950,#1f6feb);min-height:2px}
.spark i.hot{background:linear-gradient(180deg,#f0883e,#f85149)}
.up{color:var(--ok);font-size:11px}.down{color:var(--bad);font-size:11px}
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
#deck .tools{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}
.pbtn{background:#1f6feb33;color:var(--acc);border:1px solid var(--acc);border-radius:6px;padding:4px 14px;cursor:pointer;font-size:12px}
.pbar{height:5px;background:#21262d;border-radius:3px;overflow:hidden;flex:1;min-width:120px}
.pbar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,#1f6feb,#3fb950);transition:width .5s}
.tbtn{background:var(--card);border:1px solid var(--line);color:var(--dim);border-radius:14px;padding:3px 12px;cursor:pointer;font-size:12px}
.tbtn.on{color:var(--acc);border-color:var(--acc)}
.deck{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.scard{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;cursor:pointer;transition:transform .18s,border-color .18s,opacity .3s,box-shadow .18s;animation:pop .45s both}
.scard:hover{transform:translateY(-3px);border-color:var(--acc)}
.scard.now{border-color:var(--ok);box-shadow:0 0 0 1px var(--ok),0 0 18px #3fb95033}
.scard.lit{border-color:#2f81f7;opacity:1}
.scard.off{opacity:.32;filter:saturate(.4)}
.scard .sn{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:8px;background:#1f6feb33;color:var(--acc);font-weight:700;margin-right:8px;flex:none}
.scard .tier{font-size:11px;color:#a5b4fc;background:#3d44db22;border:1px solid #3d44db55;border-radius:9px;padding:0 8px;margin-left:8px}
.scard .det{max-height:0;overflow:hidden;transition:max-height .3s}
.scard.open .det{max-height:340px}
.scard .det .lab{color:var(--dim);font-size:10px;margin-top:8px;letter-spacing:.5px}
.scard .det p{font-size:11.5px;color:#a8b3bf;line-height:1.55}
@keyframes pop{from{opacity:0;transform:translateY(14px) scale(.97)}to{opacity:1;transform:none}}
#ringcard{margin-top:12px;display:flex;gap:16px;align-items:center;border-style:dashed;animation:pop .45s .7s both}
#ringcard.now{border-color:var(--ok);border-style:solid;box-shadow:0 0 22px #3fb95033}
.ring{width:54px;height:54px;border-radius:50%;border:3px dashed var(--acc);animation:spin 9s linear infinite;flex:none;display:flex;align-items:center;justify-content:center}
.ring b{font-size:10px;color:var(--acc);animation:spin 9s linear infinite reverse}
@keyframes spin{to{transform:rotate(360deg)}}
.bnode{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 16px;text-align:center;min-width:104px}
.bnode b{color:var(--fg);font-size:12px;display:block}
.bnode .cnt{font-size:22px;font-weight:700;color:var(--acc);display:block;margin:2px 0;line-height:1.1}
.bnode .hint{color:var(--dim);font-size:10px;display:block}
.bnode.hot{border-color:var(--bad)}
.bnode.hot .cnt{color:var(--bad)}
.bnode.side{border-style:dashed}
.chip{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;background:#1f6feb33;color:var(--acc);margin:2px 4px 2px 0}
.chip.h{background:#f8514933;color:#f85149}.chip.m{background:#f0883e33;color:#f0883e}.chip.l{background:#3fb95033;color:#3fb950}
</style></head><body>
<h1>问渠 wenqu <span class="badge" id="ver">…</span></h1>
<div class="sub">本地质量工程体系 · <span id="ts"></span> · 端口 """ + str(PORT) + """</div>
<nav style="margin-bottom:14px;display:flex;gap:8px">
  <button class="tab active" data-t="ov" onclick="showTab('ov')">总览</button>
  <button class="tab" data-t="pipe" onclick="showTab('pipe')">管线流程</button>
  <button class="tab" data-t="deck" onclick="showTab('deck')">问渠全流程</button>
  <button class="tab" data-t="bugdeck" onclick="showTab('bugdeck')">bug 管线</button>
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
<div id="deck" style="display:none">
 <div class="pl"><h3>问渠八站 · 动态卡片</h3><div class="src">正源：bug-scan-pipeline SKILL.md §1（站序=成本×确定性递增，便宜的先拦）——点卡片展开执行件/通过判据；点档位查看该档点亮的站点；▶ 自动巡游全流程</div>
  <div class="tools">
    <button class="pbtn" id="playBtn" onclick="playFlow()">▶ 自动巡游</button>
    <div class="pbar"><i id="pfill"></i></div>
    <span id="playmsg" class="dim" style="font-size:12px">8 站 + 收敛环</span>
  </div>
  <div class="tools" id="tiers"></div>
  <div id="tierinfo" class="src" style="margin:0 0 10px">档位×站点矩阵：选择档位查看该档覆盖的站点与 lane/N（升档站点集=高档∪原档，只增不减）</div>
  <div class="deck" id="stdeck"></div>
  <div class="card" id="ringcard">
    <div class="ring"><b>收敛</b></div>
    <div><b style="color:var(--acc)">收敛环（横切）· 递归清零 v2.2</b>
    <p style="font-size:12px;color:#a8b3bf;line-height:1.6">任何「这站干净/整线扫完」声明 → N 轮异源实扫：FAST=1 / STANDARD=2 / INCIDENT=3（末轮含 S3 对抗或 S5 独立审计）；上限 N+1 超限转人工；S1-S5 证据源实质轮换——同命令族+同时辰+换模型转述同一日志≠异源；每轮 rounds.jsonl 工件，无工件不计轮。证据时效双上限：权限/漏洞情报类 ≤7 天、其余 ≤30 天，跨类从短；指纹五元组（SHA+规则版本集+环境+范围哈希+数据/配置版本）变化即失效重跑。</p></div>
  </div>
  <div class="src" style="margin-top:8px">一本账 = rounds.jsonl / findings.jsonl 账本族（无工件不计轮）；跳站依赖=每档继承证据表显式化，nightly 继承站3 须周档未超时+差集为空</div>
</div>
</div>
<div id="bugdeck" style="display:none">
 <div class="pl"><h3>bug 管线 · 一本账运转视图</h3><div class="src">主源：bug-scan-pipeline SKILL.md（§4/§9/§9b/§6/§7 逐字收敛）；六层落地细节=SKILL §8 v2.0 血统段——与「问渠全流程」页签（§1-§2 八站结构与档位）互补，本页=缺陷从发现到收敛的运转面 · 账本计数实读 ~/.zcode/quality-system/bugscan-ledger/（现态折叠：同 id 末次流转为准）</div>
 <div class="card" style="margin-bottom:10px"><h2>📒 缺陷账本 · 状态机（实数据）</h2>
  <div id="bglstate">载入中…</div>
  <div id="bglproj" style="margin-top:10px"></div>
  <div id="bgltrend" style="margin-top:12px;display:none"><h2>📈 流转趋势 · 近 30 天</h2><div id="trendsvg"></div></div>
  <div class="src" id="bglnote" style="margin-top:8px">状态机正源 §4：OPEN→FIXING→VERIFIED→CLOSED；ACCEPTED 须批准人+理由+到期日，到期哨兵日检、到期未续自动重开 OPEN 并告警。FIXED=历史变体态（已修复待验证）。账本为多源异构历史，计数为归一口径。</div>
 </div>
 <div class="card" style="margin-bottom:12px;border-color:#f0883e"><h2>🔁 §9 post-fix 收敛循环（修复波必跑）</h2>
  <div style="font-size:12px;color:#f0883e;margin-bottom:8px">铁律：修复即新攻击面——任何成批修复后必须开对抗复扫循环</div>
  <div class="tools">
    <button class="pbtn" id="pfBtn" onclick="pfFlow()">▶ 巡游五步</button>
    <div class="pbar"><i id="pffill"></i></div>
    <span id="pfmsg" class="dim" style="font-size:12px">5 步循环 · 曲线递减=健康</span>
  </div>
  <div class="deck" id="pfdeck"></div>
  <div class="tools" style="margin-top:10px">
    <span class="dim" style="font-size:11px">实战递减曲线（§9.3）</span>
    <div class="spark" id="pfspark"></div>
    <span class="dim" style="font-size:11px">20→12→4→1→0 · 不递减=修复方法有系统性问题，停手复盘</span>
  </div>
 </div>
 <div class="pl" style="margin-top:6px"><h3>§9b 加固循环 · 异源审引擎（2026-10-03 固化）</h3><div class="src">wenqu-dist 18 轮实战方法论 skill 化，任何交付物可复用；与 §9 的区别：§9 针对修复波产物，§9b 针对完整交付物的多轮对抗强化</div>
 <div class="deck" id="hardendeck"></div></div>
 <div class="pl" style="margin-top:6px"><h3>§6 扫描器军火库（12 件 + v2.0 六层）</h3><div class="src">新件清单——2026-09-17「全量开干」当日 7 件全建成；Z 系探测器与三域插座后续扩编 · 点击卡片展开详情</div>
 <div class="deck" id="arsdeck"></div>
 <div id="layers6"></div></div>
 <div class="pl" style="margin-top:6px"><h3>§7 盲区诚实声明（16 条）+ §5 收敛声明模板</h3><div class="src">季度复盘一次；命中且成事故→触发缺口决议重审。PASS=已知盲区外收敛，非零 Bug 承诺；最高标准=可证伪、可审计、不把未知说成安全</div>
 <details style="margin-bottom:8px"><summary class="dim" style="cursor:pointer;font-size:12px">展开 16 条盲区清单</summary><div id="blindspots" style="margin-top:8px"></div></details>
 <div class="src">收敛声明两版（禁自由发挥）：清零声明（零豁免时）／条件放行声明（有有效豁免时只能用此版——铁律 3：带有效豁免只能称「条件放行」不能称「清零」）；生产观察窗未跨过=候选收敛；两版均须附盲区清单作为附件</div></div>
</div>
</div>
<div class="grid" id="ov">
  <div class="card" style="grid-column:1/-1;border-color:#3fb950" id="healthcard"><h2>❤️ 系统健康度</h2><div id="health">载入中…</div></div>
  <div class="card" style="border-color:#f0883e" id="deccard"><h2>⏳ 待拍板</h2><div id="dec" style="max-height:340px;overflow:auto">载入中…</div></div>
  <div class="card"><h2>组件体检</h2><div id="comp">载入中…</div></div>
  <div class="card"><h2>守护进程</h2><div id="daemon">载入中…</div>
    <div style="margin-top:8px" class="dim" id="cronline"></div></div>
  <div class="card"><h2>棘轮基线（若项目接入）</h2><div id="ratchet">—</div></div>
  <div class="card"><h2>引擎账本 · 最近 8 轮</h2><div id="rounds">载入中…</div></div>
  <div class="card" style="grid-column:1/-1"><h2>哨兵日志尾</h2>
    <div id="logs"></div></div>
  <div class="card" style="grid-column:1/-1;border-color:#a371f7"><h2>🤖 全流程智能编排</h2><div id="orch">载入中…</div></div>
</div>
<script>
async function j(u){const r=await fetch(u);return r.json()}
function el(h){const d=document.createElement('div');d.innerHTML=h;return d}
function showTab(t){
  for(const id of['ov','pipe','deck','bugdeck'])document.getElementById(id).style.display=t==id?'':'none';
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.t==t));
  if(location.hash.slice(1)!==t) history.replaceState(null,'','#'+t);  // 页签记忆：刷新/分享链接直达
}
window.addEventListener('hashchange',()=>{const h=location.hash.slice(1);if(['ov','pipe','deck','bugdeck'].includes(h))showTab(h)});
(function(){const h=location.hash.slice(1);if(['ov','pipe','deck','bugdeck'].includes(h))showTab(h)})();
const STATIONS=[
 {n:0,name:'范围冻结',tier:'每次开扫首站',exec:'EQS 前置门禁（eqs-dev-flow ③段）；五元组指纹=SHA+规则版本集+环境+范围哈希+数据/配置版本 → rounds.jsonl',pass:'必跑项与覆盖分母齐全；身份一致三查（commit SHA+构建指纹 GIT_HASH+环境标识）；未知影响面不得自动排除；定级理由（档位+触发面+升降档依据）随指纹落账供复核'},
 {n:1,name:'源闸',tier:'PR 阻断',exec:'CI Fast：tsc/eslint/vitest/pytest/守卫棘轮/openapi/org-guard + verify-rebase-integrity（hook）+ typedRoutes 反证探针；涉权限/资金/租户 PR+隔离环境定向真单链',pass:'全绿+棘轮不升+探针真红（写死链探针→tsc 必红 TS2322）'},
 {n:2,name:'静态与供应链全量',tier:'周',exec:'dupscan-fullscan（jscpd 棘轮，周哨兵周日 04:00）+ 持续修复引擎五类（日档常驻）+ route-integrity 静态腿 + dh-audit（仅 correctness）+ supply-chain-audit（周一 08:30）',pass:'克隆率≤基线；dh-audit exit 0；CVE 零 HIGH 及以上；引擎五类 0 open'},
 {n:3,name:'契约与数据',tier:'周',exec:'openapi 对账 + org-guard + db-schema-recon-4track 漂移白名单（周一 08:00）+ api-perm-matrix（静态矩阵 org/session/none/exempt+双面探针）+ 迁移类 DDL 三段式',pass:'无未归属端点；无未解释漂移；矩阵三源一致（仲裁序=运行时＞DB＞静态，不投票）；负例（越权/跨租户）全拦+正例全通'},
 {n:4,name:'行为面',tier:'nightly',exec:'e2e 全量 + route-integrity 动态腿 + web-gui-tester 抽检（~60 核心页轮换；545 遍历页与 565 形态盘点不混分母）',pass:'e2e 全绿+抽样零新发现+每测试点一张已看截图'},
 {n:5,name:'实弹面',tier:'版本/新模块首版/权限资金 PR 发布前',exec:'erp-real-order-test：真单 14 节链+18 发对抗+DB 断言；生产写须超哥明确口令，越界拒跑上报',pass:'DB 断言全 PASS+废单清点+守恒公式对账平'},
 {n:6,name:'对抗面',tier:'事件（上产 24h 内）',exec:'post-delivery-adversarial-audit 四轴+S3 反例轮+fact-verify；simplify 候选不自动重构（工件化留痕）；支付/第三方对接变更=对抗+实弹+沙箱回读三件',pass:'每轴必问全覆盖+新用例含守卫真拦住负断言；不强制每轴必有发现'},
 {n:7,name:'运行时',tier:'持续',exec:'Argus 四班哨兵/probe/self-heal+告警触达链（sentinel-notify-lib 主，Hermes 兜底）',pass:'不参与收敛声明（时态不同）；事件工单回流站6'}
];
const TIERS=[
 {k:'PR 每次合入',s:[0,1],lane:'FAST→INCIDENT（权限资金类+站5 发布前专项）'},
 {k:'日 cron 常驻',s:[2],lane:'FAST/1（引擎五类+路由哨兵·自动监测非开扫，零发现不出声明）'},
 {k:'周 launchd',s:[0,2,3],lane:'STANDARD/2'},
 {k:'nightly',s:[0,4],lane:'STANDARD/2（继承站3 证据须周档未超时+差集为空）'},
 {k:'版本/新模块首版',s:[0,5],lane:'STANDARD/2'},
 {k:'事件 上产24h内',s:[0,6,5],lane:'STANDARD→INCIDENT（支付/第三方对接+站5 实弹）'},
 {k:'季度',s:[0,1,2,3,4,5,6,7],lane:'INCIDENT/3+末轮 S5（全线+尾巴盘点+性能基线+管线失效演练）'}
];
function renderDeck(){
  const dk=document.getElementById('stdeck');dk.innerHTML='';
  STATIONS.forEach((s,i)=>{
    const d=document.createElement('div');d.className='scard';d.style.animationDelay=(i*70)+'ms';
    d.onclick=()=>{document.querySelectorAll('#stdeck .scard').forEach(x=>{if(x!==d)x.classList.remove('open')});d.classList.toggle('open')};
    d.innerHTML=`<div style="display:flex;align-items:center;margin-bottom:6px"><span class="sn">${s.n}</span><b style="font-size:13px;flex:1">${s.name}</b><span class="tier">${s.tier}</span></div>
    <div class="det"><div class="lab">执行件</div><p>${s.exec}</p><div class="lab">通过判据</div><p>${s.pass}</p></div>
    <span class="dim" style="font-size:11px">点击展开执行件 / 通过判据</span>`;
    dk.appendChild(d);
  });
  const tb=document.getElementById('tiers');tb.innerHTML='';
  TIERS.forEach(t=>{
    const b=document.createElement('button');b.className='tbtn';b.textContent=t.k;
    b.onclick=()=>{
      document.querySelectorAll('.tbtn').forEach(x=>x.classList.remove('on'));b.classList.add('on');
      document.querySelectorAll('#stdeck .scard').forEach((c,i)=>{c.classList.toggle('lit',t.s.includes(STATIONS[i].n));c.classList.toggle('off',!t.s.includes(STATIONS[i].n))});
      document.getElementById('tierinfo').innerHTML=`<b style="color:var(--acc)">${t.k}</b> → 站点 {${t.s.join('、')}} · lane/N = ${t.lane}`;
    };
    tb.appendChild(b);
  });
}
let playTimer=null;
function stopPlay(){if(playTimer){clearInterval(playTimer);playTimer=null}}
function playFlow(){
  const cards=[...document.querySelectorAll('#stdeck .scard')];const ring=document.getElementById('ringcard');
  stopPlay();
  const btn=document.getElementById('playBtn');
  if(btn.dataset.run){btn.dataset.run='';btn.textContent='▶ 自动巡游';cards.forEach(c=>c.classList.remove('now'));ring.classList.remove('now');return}
  btn.dataset.run='1';btn.textContent='⏸ 停止巡游';
  cards.forEach(c=>c.classList.remove('now'));ring.classList.remove('now');
  let i=0;const total=cards.length+1;
  playTimer=setInterval(()=>{
    if(i>=cards.length){
      cards.forEach(c=>c.classList.remove('now'));ring.classList.add('now');
      document.getElementById('pfill').style.width='100%';
      document.getElementById('playmsg').innerHTML='走查完成——任何「干净/扫完」声明必过收敛环（递归清零 v2.2）';
      stopPlay();btn.dataset.run='';btn.textContent='▶ 自动巡游';return;
    }
    cards.forEach(c=>c.classList.remove('now'));
    const c=cards[i];c.classList.add('now');c.scrollIntoView({block:'nearest',behavior:'smooth'});
    document.getElementById('pfill').style.width=Math.round((i+1)*100/total)+'%';
    document.getElementById('playmsg').innerHTML=`站${STATIONS[i].n} <b>${STATIONS[i].name}</b> · ${STATIONS[i].tier}`;
    i++;
  },1500);
}
renderDeck();
const POSTFIX=[
 {n:1,name:'圈面',tier:'§9.1',exec:'修复批全部产物文件（git diff <基线>..master -- src 剔测试），双代理并行分片对抗审',pass:'审计六维：CAS 快照真拦竞态 / 幂等键真唯一 / 权限锚点对 / 事务边界 / 孪生口径一致性 / Decimal'},
 {n:2,name:'异源升级',tier:'§9.2',exec:'第三轮起鼓励真库实验（docker PG + 真实 Prisma 版本实证，如 25P02 家族——交互式事务 P2002 后 catch 内重查必炸）',pass:'证据源实质轮换：同命令族+同时辰+换模型转述≠异源'},
 {n:3,name:'修复-复扫循环',tier:'§9.3',exec:'每轮发现→冻结工单→修复→上产→下轮复扫新产物',pass:'曲线应递减（实战 20→12→4→1→0）；不递减=修复方法有系统性问题，停手复盘'},
 {n:4,name:'封环条件',tier:'§9.4 · 三条全满足',exec:'① 末轮零新发现；② 存量数据尾巴生产核查清（历史口径行数=0 或已裁定）；③ 修复语义短路/边界亲审零疑问',pass:'三条全满足才可宣言收敛；缺一=继续循环'},
 {n:5,name:'入账',tier:'§9.5',exec:'每轮发现进 bugscan-ledger；方法论战训入 quality-system candidates',pass:'封环时跑 check-ingestion --last-action 收口'}
];
const PFCURVE=[20,12,4,1,0];
const HARDEN=[
 {n:'A',name:'异源审引擎（核心引擎）',tier:'§9b A',exec:'每轮派零先前上下文子代理：charter=「证明它是错的或不完备的」+攻击面清单+上限条数+零发现合法；实测优先于推演；修复者自验=自审（同批代码自审漏 6 条实证——二审定律）',pass:'曲线判读：递减=健康；平台期≠稳态（「无 HIGH」可能含账面成分）；轮换维度再扫（代码→测试件→文档→故障形态）每换一维常有增量；停机=曲线归零+变异闭环+正门验收全绿→条件放行（非清零——盲区清单+解除条件必附）；无限磨低危=反模式'},
 {n:'B',name:'修复批纪律（四条）',tier:'§9b B',exec:'① 同族半改按 family 收口（同一防线 A 处修 B 处没修——18 轮最高频病灶，六族实证）② 真实执行语义验证（声明的 rc/shell/退出码语义必须实测对齐——PIPESTATUS 赋值陷阱 / xargs 123 混叠 / die-append 顺序三案）③ 故障形态双类注入（内容异常 GBK/BOM/二进制/超长行 + 宿主异常 磁盘满/只读/PATH 残缺）④ 声明与事实对齐（声称改了必须 grep assert 在文 + git diff 非零）',pass:'「修复验证只想到的形态≠全部形态」——S7 模式定谳'},
 {n:'C',name:'验收三法（跨模型审最高优先）',tier:'§9b C',exec:'跨模型审（v2.0 新增）：GLM 收敛到零后必须送至少一个异族模型终审（Codex/K3/M3）——实证 GLM 12 轮收敛到 0，Codex 一轮 8 HIGH + K3 一轮 3 Critical 全漏（同族认知盲区=结构性限制，无法靠更多轮修复）；变异测试=夹具有效性唯一可信法（把修复还原为坏形态→全套测试必须红，绿了=假绿夹具）；文档修复验收=逐变更点 assert + git diff 非零',pass:'工具通道：codex exec --skip-git-repo-check -s read-only ／ mmx text chat --model kimi-k3；机械闸（release-check 类）——首跑即抓漏=防线生效实证'}
];
const ARSENAL=[
 {n:1,name:'api-perm-matrix',st:'站3',badge:'✅现役',one:'787 端点静态矩阵+openapi 对账+双面探针',det:'静态矩阵（org=488/session=176/none=17/exempt=425）+双面探针（dry-run 默认）；PR#527 入仓，首基线已入库'},
 {n:2,name:'supply-chain-audit',st:'站2',badge:'✅现役',one:'npm audit CVE+lockfile 对账+依赖快照 diff+安装脚本面',det:'launchd 周一 08:30；首跑 CLEAN（CVE 0 HIGH+ / lockfile 0 漂移 / 1472 传递依赖基线 / 9 安装脚本包全良性）'},
 {n:3,name:'simplify 工件化',st:'站6',badge:'✅',one:'simplify-evidence-<日期>.md 五要素落盘纪律',det:'候选不自动重构，证据工件五要素（2026-09-17 工件化）'},
 {n:4,name:'DB 漂移周哨兵',st:'站3',badge:'✅现役',one:'db-schema-recon-4track 漂移白名单周扫',det:'launchd 周一 08:00 + erp_readonly 只读账户 + watchdog；首跑 CLEAN（基线 27 还在收敛）'},
 {n:5,name:'dupscan 周哨兵',st:'站2',badge:'✅现役',one:'仓内正源 check-ratchet.sh 周扫（弃自建口径）',det:'launchd 周日 04:00；首跑 PASS 三层全在基线下'},
 {n:6,name:'DH Next.js 适配',st:'站1',badge:'✅',one:'dh-gate 判定函数双分支化',det:'cloud3 判定函数移植双分支（Python + Node/Next），ERP 仓实测 web 判定，md5 对账 0a83919b'},
 {n:7,name:'perf-baseline-runner',st:'季度档',badge:'✅现役',one:'绝对阈值+相对退化双判性能基线',det:'launchd 季度首日 05:00；首基线 CLEAN（登录 p95≈90ms / health p95≈166ms / 单进程 RSS 1623MB / PG 12 连接）'},
 {n:8,name:'Z-A advisory-watch',st:'—',badge:'🆕v1.7',one:'框架安全通告跟踪',det:'GitHub Advisories API 比对 lockfile 实锁版本，命中且实锁<修复版→告警；幂等哈希去重。触发=CVE-2025-29927（middleware bypass CVSS 9.1）曾靠人工核免疫'},
 {n:9,name:'Z-B export-tenant-audit',st:'—',badge:'🆕v1.7',one:'导出/下载端点租户过滤静态扫',det:'全 export/download 路由查询 builder where 缺 organizationId 且模型属 TENANT_MODELS→违例清单；基线=Z17 修后 0 违例（BSF-20261001-06 双例实证）'},
 {n:10,name:'Z-C N+1 基线',st:'—',badge:'候选',one:'Prisma query 事件计数探针',det:'staging top 路由 query/req 阈值——先基线不阻断'},
 {n:11,name:'Z-D DB 守恒约束',st:'—',badge:'候选',one:'LedgerEntry Σ 约束触发器方案',det:'业界最佳实践=CHECK/触发器写时现形；涉生产 DDL 拍板'},
 {n:12,name:'stations.json 三域探测器',st:'跨仓插座',badge:'🆕v1.8',one:'trap-double / guard-comment-swallow / cred-cli-expose',det:'零依赖 bash+awk+grep 可挂任意仓（协议见 §10）；F4 战训固化，部署 ccc 实测三站全中真缺陷'}
];
const LAYERS6=[
 {u:'U1',name:'Sentry DSN',badge:'✅生产已配',det:'cloud4 生产 env SENTRY_DSN 键在位实证（9-14 上产）；SKILL §8 血统段仍标「待授权」=滞后续写'},
 {u:'U2',name:'fast-check 属性测试',badge:'✅入 master',det:'资金域 7 属性（SKILL §8 v2.0）'},
 {u:'U3',name:'Stryker 变异测试',badge:'✅3 文件 0% 发现',det:'首跑基线 69.58 分+3 文件 0% 发现（SKILL §8 v2.0）'},
 {u:'U4',name:'Semgrep',badge:'✅3 自定义规则',det:'3 自定义规则入仓（SKILL §8 v2.0）'},
 {u:'U5',name:'CodeQL',badge:'⚠️边界标注',det:'private 不可用，如实标注（SKILL §8 v2.0）'},
 {u:'U6',name:'Zod 覆盖审计',badge:'✅top 风险 5 处',det:'覆盖审计（0.25%→top 风险 5 处）（SKILL §8 v2.0）'}
];
const BLIND=[
 '业务正确性只到已建模断言（18 发+真单链）——靠实弹+用户报告+季度业务走查日',
 'schema 对账只对当前 schema（迁移类已强制 DDL 三段式+实弹双核验）',
 '第三方 SaaS 行为不在视野（支付类已强制核验，其余靠 SLA+对抗）',
 'AI 生成语义 bug 静态结构性盲（缓解=新模块首版强制站5）',
 '性能深层瓶颈只到基线快照，profiling 人工',
 '无独立渗透测试件（季度人工评审替代）',
 '多模型交叉≠保证独立',
 '「扫干净」=限定范围收敛声明，非零 Bug 承诺；最高标准=可证伪、可审计、不把未知说成安全',
 '框架层安全通告（Next.js middleware bypass 族）依赖人工核版本——缓解=Z-A 通告跟踪哨兵',
 '导出/下载路径为租户泄漏高发面（wanji BSF-11 + catalog 双例实证）——缓解=Z-B 导出租户周扫',
 '查询级性能（N+1/计划退化）无自动化（端点基线只测延迟不测查询数）——缓解=Z-C N+1 基线起步',
 '守恒不变量在 DB 层无硬约束（应用层+人工对账兜底）——缓解=Z-D 评估',
 'Next.js 缓存租户串扰面（深审=IMMUNE：零危险原语+全站动态渲染；重审计触发=引入 unstable_cache/"use cache"/fetch tags 时）',
 '会计错误 13 类模式（SQL 化 4 类检测=0/57 全为业务巧合；重扫触发=财务对账不平时先跑此四查）',
 '跨仓/只读委托时运行态站（4/5/7）常不可达——离线审计≠运行态验证，交付声明必须如实分列（F4 实战定式）',
 '防线「同族半改」结构性盲：同一防线 A 处修 B 处没修（F4 六例）——缓解=对抗审必查族覆盖对称性+修复批按 family 收口勿逐点'
];
function renderBugDeck(){
  const mk=(dkid,arr,fh)=>{
    const dk=document.getElementById(dkid);dk.innerHTML='';
    arr.forEach((s,i)=>{
      const d=document.createElement('div');d.className='scard';d.style.animationDelay=(i*60)+'ms';
      d.onclick=()=>{document.querySelectorAll('#'+dkid+' .scard').forEach(x=>{if(x!==d)x.classList.remove('open')});d.classList.toggle('open')};
      d.innerHTML=fh(s);dk.appendChild(d);
    });
  };
  mk('pfdeck',POSTFIX,s=>`<div style="display:flex;align-items:center;margin-bottom:6px"><span class="sn">${s.n}</span><b style="font-size:13px;flex:1">${s.name}</b><span class="tier">${s.tier}</span></div>
    <div class="det"><div class="lab">执行</div><p>${s.exec}</p><div class="lab">判读</div><p>${s.pass}</p></div>
    <span class="dim" style="font-size:11px">点击展开执行 / 判读</span>`);
  mk('hardendeck',HARDEN,s=>`<div style="display:flex;align-items:center;margin-bottom:6px"><span class="sn">${s.n}</span><b style="font-size:13px;flex:1">${s.name}</b><span class="tier">${s.tier}</span></div>
    <div class="det"><div class="lab">纪律</div><p>${s.exec}</p><div class="lab">要点</div><p>${s.pass}</p></div>
    <span class="dim" style="font-size:11px">点击展开纪律 / 要点</span>`);
  mk('arsdeck',ARSENAL,s=>`<div style="display:flex;align-items:center;margin-bottom:6px"><span class="sn">${s.n}</span><b style="font-size:13px;flex:1">${s.name}</b><span class="tier">${s.st}</span><span class="tier" style="color:#3fb950;border-color:#3fb95055;background:#3fb95022">${s.badge}</span></div>
    <div style="font-size:12px;color:#a8b3bf">${s.one}</div>
    <div class="det"><div class="lab">详情</div><p>${s.det}</p></div>
    <span class="dim" style="font-size:11px">点击展开详情</span>`);
  const l6=document.getElementById('layers6');
  l6.innerHTML='<div class="lab" style="color:var(--dim);font-size:10px;margin:12px 0 6px;letter-spacing:.5px">v2.0 六层强化（SKILL §8 血统段 2026-10-03「我要最强」）</div>';
  LAYERS6.forEach(x=>{l6.appendChild(el(`<div class="row"><span style="flex:0 0 40px" class="dim">${x.u}</span><span style="flex:0 0 170px">${x.name}</span><span style="color:#3fb950;font-size:12px;flex:0 0 130px">${x.badge}</span><span class="dim" style="font-size:11px;flex:1">${x.det}</span></div>`))});
  const bs=document.getElementById('blindspots');
  BLIND.forEach((t,i)=>{bs.appendChild(el(`<div style="font-size:11.5px;color:#a8b3bf;line-height:1.55;padding:3px 0;border-bottom:1px dashed #21262d"><span class="dim" style="margin-right:8px">${String(i+1).padStart(2,'0')}</span>${t}</div>`))});
  const sp=document.getElementById('pfspark');
  sp.innerHTML=PFCURVE.map(v=>`<i title="${v} 发现" style="height:${Math.max(3,v*2)}px;${v===0?'background:linear-gradient(180deg,#3fb950,#1f6feb)':''}"></i>`).join('');
}
let pfTimer=null;
function pfFlow(){
  const cards=[...document.querySelectorAll('#pfdeck .scard')];
  const btn=document.getElementById('pfBtn');
  if(pfTimer){clearInterval(pfTimer);pfTimer=null;cards.forEach(c=>c.classList.remove('now'));btn.textContent='▶ 巡游五步';return}
  btn.textContent='⏸ 停止巡游';
  cards.forEach(c=>c.classList.remove('now'));
  let i=0;
  pfTimer=setInterval(()=>{
    if(i>=cards.length){
      clearInterval(pfTimer);pfTimer=null;
      cards.forEach(c=>c.classList.remove('now'));
      document.getElementById('pffill').style.width='100%';
      document.getElementById('pfmsg').innerHTML='走查完成——封环条件三条全满足才可宣言收敛';
      btn.textContent='▶ 巡游五步';return;
    }
    cards.forEach(c=>c.classList.remove('now'));
    cards[i].classList.add('now');cards[i].scrollIntoView({block:'nearest',behavior:'smooth'});
    document.getElementById('pffill').style.width=Math.round((i+1)*100/cards.length)+'%';
    document.getElementById('pfmsg').innerHTML=`第${POSTFIX[i].n}步 <b>${POSTFIX[i].name}</b> · ${POSTFIX[i].tier}`;
    i++;
  },1500);
}
async function loadBGL(){
  const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const d=await j('/api/bugscan-ledger');
  const box=document.getElementById('bglstate');
  if(!d.available){box.innerHTML='<span class="dim">未发现 bugscan-ledger 账本目录（~/.zcode/quality-system/bugscan-ledger/）</span>';document.getElementById('bglproj').innerHTML='';return}
  const st=d.total.by_status||{};
  const chain=[['OPEN','发现待修'],['FIXING','修复中'],['FIXED','已修待验·变体'],['VERIFIED','已验证'],['CLOSED','已关闭'],['ACCEPTED','有条件接受'],['OTHER','未归类']];
  let h='<div class="frow">';
  chain.forEach(([k,lab],ix)=>{
    if(ix)h+='<div class="arrow">▸</div>';
    const n=st[k]||0;
    const clickable=n>0?` style="cursor:pointer" onclick="toggleItems('${k}')" title="点击展开该状态明细"`:'';
    const hot=k==='OPEN'&&n>0?' hot':'';
    h+=`<div class="bnode${hot}"${clickable}><b>${k}${n>0?' ▾':''}</b><span class="cnt">${n}</span><span class="hint">${lab}</span></div>`;
  });
  h+='</div>';
  const sv=d.total.by_sev||{};
  h+=`<div style="margin-top:10px"><span class="chip h">HIGH ${sv.HIGH||0}</span><span class="chip m">MED ${sv.MED||0}</span><span class="chip l">LOW ${sv.LOW||0}</span><span class="chip">INFO ${sv.INFO||0}</span><span class="chip">其他 ${sv.OTHER||0}</span>${(d.stale_open||0)>0?`<span class="chip" style="background:#f0883e33;color:#f0883e;border:1px dashed #f0883e" title="OPEN 且 >14 天无活动——多半是修了没销账的陈账，跑 sweep 核销">⏳ 陈账 ${d.stale_open}</span>`:''}<span class="dim" style="font-size:11px;margin-left:6px">严重度归一口径 · findings 共 ${d.total.findings} 条 · ${d.projects.length} 项目 · 最近活动 ${esc(d.total.last_ts||'—')}</span></div>`;
  box.innerHTML=h;
  window._openItems=d.open_items||[];window._openTotal=d.open_total||0;
  const old=document.getElementById('bglitems');if(old)old.remove();
  window._itemsShown=null;
  window.toggleItems=async function(stt){
    let el=document.getElementById('bglitems');
    if(el&&window._itemsShown===stt){el.remove();window._itemsShown=null;return}
    window._itemsShown=stt;
    if(!el){el=document.createElement('div');el.id='bglitems';el.style.cssText='margin-top:10px;max-height:300px;overflow:auto;border:1px dashed #30363d;border-radius:8px;padding:8px';document.getElementById('bglstate').appendChild(el);}
    el.innerHTML='<div class="dim" style="font-size:11px">载入中…</div>';
    let d2;
    if(stt==='OPEN'){d2={items:window._openItems,items_total:window._openTotal};}
    else{try{d2=await j('/api/bugscan-ledger?items='+encodeURIComponent(stt));}catch(e){d2={items:[],items_total:0};}}
    if(window._itemsShown!==stt)return;  // 期间已切换
    const items=d2.items||[];
    el.innerHTML=`<div class="dim" style="font-size:11px;margin-bottom:4px">${stt} 明细 ${d2.items_total||0} 条（严重度序${(d2.items_total||0)>items.length?`，仅列前 ${items.length} 条`:''}）· 再点 ${stt} 收起</div>`+
      items.map(x=>`<div class="row"${x.stale?' style="border-left:2px solid #f0883e;padding-left:6px"':''}><span class="chip ${x.sev==='HIGH'?'h':(x.sev==='MED'?'m':(x.sev==='LOW'?'l':''))}" style="margin:0 6px 0 0">${x.sev}</span>${x.stale?`<span class="dim" style="font-size:10px;color:#f0883e;flex:0 0 44px" title="OPEN 超 14 天无活动=陈账嫌疑">⏳${esc(x.ts||'')}</span>`:''}<span class="dim" style="flex:0 0 110px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.proj)}">${esc(x.proj)}</span><span class="dim" style="flex:0 0 96px">${esc(x.id)}</span><span style="flex:1;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.title)}">${esc(x.title)||'<i style="opacity:.5">（无标题）</i>'}</span></div>`).join('');
  };
  const pb=document.getElementById('bglproj');pb.innerHTML='';
  d.projects.slice(0,8).forEach(p=>{
    pb.appendChild(el(`<div class="row"><span class="dim" style="flex:0 0 132px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.key)}">${esc(p.key)}</span><span style="flex:1;font-size:12px">${p.findings} 条 · OPEN ${p.by_status.OPEN||0} / FIXED ${p.by_status.FIXED||0} / VERIFIED ${p.by_status.VERIFIED||0} / CLOSED ${p.by_status.CLOSED||0}</span><span class="dim" style="font-size:11px;flex:0 0 108px;text-align:right;white-space:nowrap">${esc(p.last_ts)}</span></div>`));
  });
}
renderBugDeck();
loadBGL().catch(()=>{});setInterval(()=>loadBGL().catch(()=>{}),60000);
// 趋势曲线（近 30 天状态流转计数→SVG 面积叠加）
async function loadTrend(){
  try{
    const d=(await j('/api/bugscan-trend')).days;
    if(!d||!d.length)return;
    document.getElementById('bgltrend').style.display='';
    const W=880,H=140,pad=28,mx=Math.max(1,...d.map(x=>x.FIXED+x.CLOSED+x.VERIFIED+x.ACCEPTED+x.OPEN+x.FIXING));
    const series=[['CLOSED','#3fb950'],['VERIFIED','#2f81f7'],['FIXED','#a371f7'],['FIXING','#d29922'],['ACCEPTED','#f0883e'],['OPEN','#f85149']];
    const pts=(k)=>d.map((x,i)=>`${pad+i*(W-2*pad)/Math.max(d.length-1,1)},${H-24-(x[k]||0)*(H-48)/mx}`).join(' ');
    const area=(k)=>pts(k)+` ${W-pad},${H-24} ${pad},${H-24}`;
    let svg=`<svg width="100%" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="max-width:${W}px">`;
    for(let i=series.length-1;i>=0;i--){const[k,c]=series[i];svg+=`<polygon points="${area(k)}" fill="${c}" fill-opacity="0.18" stroke="${c}" stroke-width="1.5"><title>${k} 叠层</title></polygon>`;}
    d.forEach((x,i)=>{if(i%5===0||i===d.length-1)svg+=`<text x="${pad+i*(W-2*pad)/Math.max(d.length-1,1)}" y="${H-8}" fill="#8b949e" font-size="10" text-anchor="middle">${x.d}</text>`});
    svg+=`<text x="${pad}" y="16" fill="#8b949e" font-size="10">峰值 ${mx} 流转/天 · 绿=CLOSED 蓝=VERIFIED 紫=FIXED 橙=ACCEPTED 红=OPEN</text></svg>`;
    document.getElementById('trendsvg').innerHTML=svg;
  }catch(e){}
}
loadTrend();setInterval(()=>loadTrend().catch(()=>{}),120000);
// SSE：账本文件变化实时推送（替代盲轮询首跳延迟；断线 EventSource 自动重连）
try{
  const es=new EventSource('/api/bugscan-sse');
  es.addEventListener('ledger',()=>{loadBGL().catch(()=>{});loadTrend().catch(()=>{})});
}catch(e){}
async function refresh(){
  const escD=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
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
  document.getElementById('cronline').textContent=`定时哨兵：${d.cron} 条`;
  const r=await j('/api/ratchet');const rb=document.getElementById('ratchet');
  rb.innerHTML=r.available?'':'<span class="dim">未接入（项目内 scripts/dupscan/baseline.json）</span>';
  if(r.available){rb.innerHTML='';
    for(const[l,v]of Object.entries(r.layers))rb.appendChild(el(`<div class="row"><span>${l}</span><span>${v.clones} 克隆 / ${v.rate}%</span></div>`))}
  const rd=await j('/api/rounds');const rbox=document.getElementById('rounds');
  {const prevR=window.__lastRounds;const n=rd.rounds.length;
   if(prevR!=null&&n>prevR){rbox.classList.remove('flash');void rbox.offsetWidth;rbox.classList.add('flash');}
   window.__lastRounds=n;}
  rbox.innerHTML='';
  for(const x of rd.rounds)rbox.appendChild(el(`<div class="row" title="${(x.label||'').replace(/"/g,'&quot;')}"><span class="dim" style="flex:0 0 76px">${x.ts||''}</span><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${x.label}</span></div>`));
  const lg=await j('/api/logs');const lbox=document.getElementById('logs');lbox.innerHTML='';
  for(const[n,t]of Object.entries(lg)){const h2=document.createElement('h2');h2.style.marginTop='8px';h2.textContent=n;lbox.appendChild(h2);const p=document.createElement('pre');p.textContent=t;lbox.appendChild(p);}
  const h=await j('/api/health');const hbox=document.getElementById('health');
  window.__hist=window.__hist||[];
  if(h.score!=null){
    const prev=window.__lastScore;
    window.__hist.push(h.score);if(window.__hist.length>24)window.__hist.shift();
  window.__lastScore=h.score;
  }
  if(h.score!=null){const col=h.score>=90?'var(--ok)':(h.score>=75?'#f0883e':'var(--bad)');
    hbox.innerHTML=`<div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">
      <div style="text-align:center;flex:none"><div id="hscore" style="font-size:44px;font-weight:700;color:${col};line-height:1">${h.score}</div>
      <div style="font-size:12px;color:${col}">${h.grade}</div></div>
      <div style="flex:none;text-align:center"><div class="spark" id="hspark"></div><div class="dim" style="font-size:10px">最近走势</div></div>
      <div style="flex:1;min-width:300px">${h.parts.map(p=>`<div class="row"><span>${p['项']}</span><span class="dim">${p['详情']}</span><span style="color:${p['比']==='100%'?'var(--ok)':'#f0883e'}">${p['得分']}/${p['满分']}</span></div>`).join('')}</div>
    </div>`;}
  {const hh=await j('/api/health-history').catch(()=>[]);
   const hc=document.getElementById('health');
   if(hh&&hh.length>1&&hc){const pts=hh.map((p,i)=>`${20+i*(440/Math.max(hh.length-1,1))},${40-p.score*0.36}`).join(' ');
     hc.appendChild(el(`<div style="margin-top:8px;border-top:1px dashed #30363d;padding-top:6px"><svg width="100%" height="44" viewBox="0 0 460 44" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="#3fb950" stroke-width="2"/></svg><div class="dim" style="font-size:10px">历史走势 ${hh.length} 点（${hh[0].ts} 起）</div></div>`));}}
  {const heat=await j('/api/rounds-heat').catch(()=>[]);
   const rwrap=document.getElementById('rounds')?.parentElement;
   if(heat&&heat.length&&rwrap&&!document.getElementById('rheat')){
     const mx=Math.max(...heat.map(x=>x.n),1);
     const cells=heat.map(x=>`<i title="${x.d}：${x.n} 轮" style="width:9px;height:9px;border-radius:2px;background:rgba(63,185,80,${x.n?0.25+0.75*x.n/mx:0.08})"></i>`).join('');
     const bar=document.createElement('div');bar.id='rheat';bar.style.cssText='display:flex;gap:2px;margin-top:8px;flex-wrap:wrap';
     bar.innerHTML=cells+`<span class="dim" style="font-size:10px;margin-left:6px">近 30 天轮次</span>`;
     rwrap.appendChild(bar);}}
  {const sp=document.getElementById('hspark');
   if(sp){sp.innerHTML=window.__hist.map(v=>`<i class="${v<75?'hot':''}" style="height:${Math.max(3,v*0.3)}px" title="${v}"></i>`).join('');}
   const sc=document.getElementById('hscore');
   if(sc&&window.__scorePrev!=null&&window.__scorePrev!==h.score){sc.classList.remove('popnum');void sc.offsetWidth;sc.classList.add('popnum');
     const old=sc.parentElement.querySelector('.up,.down');if(old)old.remove();
     sc.insertAdjacentHTML('afterend',`<span class="${h.score>window.__scorePrev?'up':'down'}">${h.score>window.__scorePrev?'▲':'▼'}</span>`);}
   window.__scorePrev=h.score;}
  window.decide=async function(id,act){
    const item=dec.find(x=>x.id===id);
    if(item&&item.red&&!confirm(`该决策属红旗类（资金/库存/权限）：\n${item.q}\n确认${act==='take'?'采纳':'驳回'}默认建议？`))return;
    const r=await fetch('/api/decide',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,action:act})});
    if(r.ok){refresh();}else{alert('清账失败：'+(await r.text()));}
  };
  const dec=await j('/api/decisions');const dbox=document.getElementById('dec');
  {const pc=document.getElementById('deccard');const prevD=window.__lastDec;
   if(prevD!=null&&prevD!==dec.length){pc.classList.remove('flash');void pc.offsetWidth;pc.classList.add('flash');}
   window.__lastDec=dec.length;}
  if(!dec.length){dbox.innerHTML='<span class="dim">无待拍项——全部清账 ✅</span>';}
  else{dbox.innerHTML='';
    for(const d of dec){
      const days=d.ttl?Math.max(0,d.ttl-Math.floor((Date.now()-new Date(d.ts).getTime())/86400000)):null;
      const overdue=days===0;
      const btn=document.createElement('button');btn.className='pbtn';btn.style.cssText='padding:1px 10px;font-size:11px';btn.textContent='✓ 采纳';
      btn.onclick=()=>decide(d.id,'take');
      const btn2=document.createElement('button');btn2.className='pbtn';btn2.style.cssText='padding:1px 10px;font-size:11px;border-color:var(--bad);color:var(--bad)';btn2.textContent='✗ 驳回';
      btn2.onclick=()=>decide(d.id,'reject');
      const row=el(`<div class="row" style="align-items:flex-start;flex-direction:column;gap:2px;${overdue?'background:#f8514922;padding:4px 6px;border-radius:6px':''}">
        <div style="display:flex;justify-content:space-between;width:100%"><span><span class="badge" style="background:${d.red?'#f8514933;color:#f85149':'#1f6feb33'}">${escD(d.cat)}${d.red?' 🔴':''}</span> ${escD(d.q)}</span>
        <span class="${overdue?'bad':'dim'}" style="font-size:11px;white-space:nowrap">${overdue?'⏰ 已逾期':(days!=null?`TTL ${days}d`:'')}</span></div>
        <div class="dim" style="font-size:12px">💡 ${escD(d.opt||'')}${d.intent?' <span class="ok">［已标记意向］</span>':''}</div>
      </div>`);
      const bar=document.createElement('div');bar.style.cssText='display:flex;gap:6px;margin-top:3px';bar.append(btn,btn2);row.appendChild(bar);
      dbox.appendChild(row);
    }
  }
  {const all=await j('/api/decisions?all=1').catch(()=>null);
   if(all&&all.length){const done=all.filter(x=>x.status!=='待拍').slice(-8).reverse();
     if(done.length){dbox.appendChild(el(`<details style="margin-top:8px"><summary class="dim" style="cursor:pointer;font-size:12px">已拍 ${all.filter(x=>x.status!=='待拍').length} 条（点击展开）</summary>${done.map(x=>`<div class="row" style="opacity:.65"><span class="dim">${escD(x.id)}</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escD(x.q)}</span><span class="${x.status==='已拍'?'ok':'dim'}">${escD(x.status)}</span></div>`).join('')}</details>`));}}}
  document.getElementById('ts').textContent='更新于 '+new Date().toLocaleTimeString();
  // 编排器状态（launchd 任务态+最近日志）
  try{
    const obox=document.getElementById('orch');
    const logLines=(await j('/api/orchestrator'));
    obox.innerHTML=logLines.html||'<span class="dim">编排器日志为空</span>';
    const ol=document.getElementById('orchlog');
    if(ol) ol.textContent=logLines.log||'';  // textContent 防 XSS（日志内容不可信）
  }catch(e){}
}
refresh();setInterval(refresh,5000);
setInterval(()=>{const t=document.getElementById('ts');if(t)t.textContent='更新于 '+new Date().toLocaleTimeString('zh-CN',{hour12:false});},1000);
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


def _norm_status(s):
    """账本状态归一——bugscan-ledger 为多源异构历史（OPEN(运维)/FIXED(...备注)/VERIFIED_CLOSED_PROD 等变体），归一到 §4 正源状态机五态+FIXED 过渡+OTHER 残差。"""
    if s is None:
        return "OTHER"
    t = str(s).strip()
    if not t:
        return "OTHER"
    tl = t.lower()
    if tl.startswith("open"):
        return "OPEN"
    if tl.startswith("partially-fixed") or tl.startswith("partially_fixed"):
        return "FIXING"  # 真实账本 2036aa7ab8c9 存在的变体（部分修复=修复中）
    if tl.startswith("fixing"):
        return "FIXING"
    if tl.startswith("fixed+verified") or t.startswith("VERIFIED_CLOSED") or tl.startswith("partially-verified"):
        return "VERIFIED"
    if tl.startswith("fixed") or tl.startswith("corrected") or tl.startswith("done") or tl.startswith("mitigated") or tl.startswith("documented"):
        return "FIXED"
    if tl.startswith("verified"):
        return "VERIFIED"
    if tl.startswith("closed") or tl.startswith("rejected"):
        return "CLOSED"
    if tl.startswith("accepted"):
        return "ACCEPTED"
    return "OTHER"


def _norm_sev(s):
    if s is None:
        return "OTHER"
    t = str(s).strip().lower()
    if not t:
        return "OTHER"
    # 词级匹配（完整词或连字符复合词边界），防止 highway/below/mediumship 等无关词误收
    toks = [w for w in re.split(r"[^a-z]+", t) if w]
    def hit(*stems):
        return any(w == st or w.startswith(st + "-") for w in toks for st in stems)
    if hit("crit", "critical"):
        return "HIGH"
    if hit("high"):
        return "HIGH"
    if hit("med", "medium"):
        return "MED"  # 复合值（med-high/low-medium/med-low）统一取含 med 档，与取高的 high 对称
    if hit("low"):
        return "LOW"
    if hit("info") or t == "pass":
        return "INFO"
    return "OTHER"


def _fold_project(f, by_day=None):
    """单项目账本折叠：finding 行按 id 去重取末次为初始态；同 id 末次 state_transition 的
    目标态覆盖初始态（与 wenqu CLI 锁内折叠视图同源，防幻影 OPEN）。
    by_day 传入时按天累计状态流转计数（趋势数据）。"""
    cur, trans, sev_of, title_of, ts_of, last = {}, {}, {}, {}, {}, ""
    for l in open(f, errors="ignore"):
        l = l.strip()
        if not l:
            continue
        try:
            d = json.loads(l)
        except ValueError:
            continue
        if not isinstance(d, dict) or not ("id" in d or "finding_id" in d):
            continue  # 审计行（run/charter）不计
        fid = str(d.get("id") or d.get("finding_id"))
        ts = str(d.get("ts") or d.get("time") or "")
        if ts > last:
            last = ts
        if "record_type" in d:
            # 流转审计行：先嗅探源侧——SEVERITY 降档流转只更新严重度不碰状态；
            # 状态流转要求目标态是合法状态词（OPEN->REOPENED 等未知目标保持初始态不误吞）
            tr = str(d.get("transition", ""))
            if "->" in tr:
                src_side, to_state = tr.split("->", 1)[0].strip().upper(), tr.rsplit(">", 1)[1].strip()
                if src_side.startswith("SEVERITY"):
                    sev_to = to_state.split("(")[0].strip()
                    if sev_to and _norm_sev(sev_to) != "OTHER":
                        sev_of[fid] = sev_to
                elif to_state and _norm_status(to_state) != "OTHER":
                    trans[fid] = to_state
                    if by_day is not None:
                        _d = ts[:10]
                        if len(_d) == 10 and _d.startswith("20"):
                            _k = (_d, _norm_status(to_state))
                            by_day[_k] = by_day.get(_k, 0) + 1
            if ts:
                ts_of[fid] = ts  # 流转行也是活动（陈账计时须含流转——否则旧 finding 当日流转后 dashboard 仍报陈旧）
            continue
        cur[fid] = d.get("status") or d.get("state")  # 同 id 重复摄入取末次
        raw_sev = d.get("sev") or d.get("severity")
        # 稀疏更新行（只改 status 无 severity，或带 FIX/FIX-PARTIAL 工作流标签）不抹已有严重度
        if raw_sev is not None and _norm_sev(raw_sev) != "OTHER":
            sev_of[fid] = raw_sev
        t = str(d.get("title") or d.get("desc") or "").strip()
        if t:
            title_of[fid] = t  # 末次出现的非空标题保留
        if ts:
            ts_of[fid] = ts  # 末次活动时间（finding 行/流转行共用取末次）
    return cur, trans, sev_of, title_of, ts_of, last


_LEDGER_CACHE = {"stamp": None, "data": None}
_LEDGER_LOCK = threading.Lock()
_EP_CACHE = {}  # 慢端点 TTL 结果缓存（health 30s/hh 30s/logs 15s；decide 等即时端点不入此表）
_SSE_COUNT = {}  # SSE 连接计数（dict 计数器——方法内免 global 声明）
_SSE_SEM = threading.BoundedSemaphore(4)  # SSE 并发上限（线程安全非阻塞获取）


def _ledger_files(root):
    """采集账本文件集及其 (mtime_ns,size) 签名（basename+realpath 双校验限制在允许目录内）。"""
    files = {}
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return files
    for name in names:
        # 路径防御：仅接受 basename 级子项名（显式拒绝 .. 与分隔符），规范化后必须仍在 root 内
        if name != os.path.basename(name) or ".." in name or name.startswith("."):
            continue
        f = os.path.realpath(os.path.join(root, name, "findings.jsonl"))
        if not (f == root or f.startswith(root + os.sep)) or not os.path.isfile(f):
            continue
        try:
            st = os.stat(f)
        except OSError:
            continue
        files[f] = (st.st_mtime_ns, st.st_size)
    return files


def bugscan_ledger():
    """实读 bugscan-ledger 账本；折叠语义见 _fold_project。

    性能（2026-10-07「优化」）：文件 (mtime,size) 签名不变→直接返回缓存（读侧仅 json 序列化
    不修改 dict，CPython 只读并发安全）；未命中在 _LEDGER_LOCK 内单飞重读（singleflight，
    并发不重复 IO）。任何未预期异常兜底返回稳定错误（fail-soft），不写缓存。"""
    root = os.path.realpath(os.path.expanduser(
        os.environ.get("WENQU_BUGSCAN_LEDGER", "~/.zcode/quality-system/bugscan-ledger")))
    if not os.path.isdir(root):
        return {"available": False}
    files = _ledger_files(root)
    stamp = frozenset(files.items())
    with _LEDGER_LOCK:
        if _LEDGER_CACHE["stamp"] == stamp:
            return _LEDGER_CACHE["data"]
        try:
            data = _bugscan_ledger_impl(files)
        except Exception as e:  # RecursionError/PermissionError/编码等边缘全兜底，不炸端点
            return {"available": False, "error": f"{type(e).__name__}: {e}"}
        _LEDGER_CACHE["stamp"] = stamp
        _LEDGER_CACHE["data"] = data
        return data


def _bugscan_ledger_impl(files):
    """files={已校验 findings.jsonl 路径: (mtime,size)}；折叠语义见 _fold_project。"""
    projects = []
    tot_status, tot_sev = {}, {}
    tot_findings, tot_last = 0, ""
    all_items = []
    stale_open = 0
    by_day = {}  # {(day, state): count} 从 transition 行提取
    STALE_DAYS = 14  # 陈账线：OPEN 且末次活动 >14 天=已修未销嫌疑（时效协议其余项 ≤30 天的一半先行黄线）
    now = datetime.now()
    for f in files:
        cur, trans, sev_of, title_of, ts_of, last = _fold_project(f, by_day)
        if not cur:
            continue
        key = os.path.basename(os.path.dirname(f))
        by_status, by_sev = {}, {}
        for fid, init_status in cur.items():
            stt = _norm_status(trans.get(fid) or init_status)  # 流转现态优先
            by_status[stt] = by_status.get(stt, 0) + 1
            sv = _norm_sev(sev_of.get(fid))
            by_sev[sv] = by_sev.get(sv, 0) + 1
            stale = False
            if stt == "OPEN":
                t = str(ts_of.get(fid, ""))
                # 剥时区后缀再截 19 位（+08:00/Z 尾随会让 fromisoformat 出 aware→naive 混算 TypeError，或截出非法串漏检）
                for suf in ("+08:00", "+00:00", "Z"):
                    if t.endswith(suf):
                        t = t[: -len(suf)]
                        break
                t = t[:19]
                try:
                    if t:
                        dt = datetime.fromisoformat(t)
                        if (now - dt).days > STALE_DAYS:
                            stale = True
                            stale_open += 1
                except ValueError:
                    pass
            all_items.append({"st": stt, "id": fid, "sev": sv, "title": title_of.get(fid, "")[:90], "proj": key,
                              "stale": stale, "ts": str(ts_of.get(fid, ""))[:10]})
        n_find = len(cur)
        projects.append({"key": key, "findings": n_find, "by_status": by_status, "by_sev": by_sev, "last_ts": last[:16]})
        tot_findings += n_find
        for k, v in by_status.items():
            tot_status[k] = tot_status.get(k, 0) + v
        for k, v in by_sev.items():
            tot_sev[k] = tot_sev.get(k, 0) + v
        if last > tot_last:
            tot_last = last
    projects.sort(key=lambda p: -p["findings"])
    sev_rank = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3, "OTHER": 4}
    all_items.sort(key=lambda x: (sev_rank.get(x["sev"], 9), x["proj"]))
    return {"available": True, "projects": projects,
            "total": {"findings": tot_findings, "by_status": tot_status, "by_sev": tot_sev, "last_ts": tot_last[:16]},
            "open_total": sum(1 for x in all_items if x["st"] == "OPEN"),
            "open_items": [x for x in all_items if x["st"] == "OPEN"][:60],  # 兼容：OPEN 明细（前 60）
            "stale_open": stale_open,  # 陈账积压：OPEN 且 >14 天无活动（已修未销嫌疑）
            "_all_items": all_items,  # 内部全集（端点按 ?items=STATE 过滤；不下发无参请求）
            "_by_day": by_day}  # 趋势：按天状态流转计数（transition 行日期 → 目标态）


def ledger_trend():
    """趋势数据：近 30 天每日各状态流转计数（从 transition 行提取，无 transition 则跳过）。"""
    root = os.path.realpath(os.path.expanduser(
        os.environ.get("WENQU_BUGSCAN_LEDGER", "~/.zcode/quality-system/bugscan-ledger")))
    if not os.path.isdir(root):
        return {"days": []}
    day_st = {}  # {(day, state): count}
    for f in _ledger_files(root):  # 复用安全入口（realpath 根边界+basename 校验——勿自行 join 绕过）
        for l in open(f, errors="ignore"):
            l = l.strip()
            if "record_type" not in l or "transition" not in l:
                continue
            try:
                d = json.loads(l)
            except ValueError:
                continue
            if not isinstance(d, dict) or d.get("record_type") != "state_transition":
                continue
            tr = str(d.get("transition", ""))
            if "->" not in tr:
                continue
            src, to = tr.split("->", 1)[0].strip().upper(), tr.rsplit(">", 1)[1].strip()
            if src.startswith("SEVERITY"):
                continue
            st = _norm_status(to)
            if st == "OTHER":
                continue
            t = str(d.get("time") or d.get("ts") or "")[:10]
            if len(t) == 10 and t.startswith("20"):
                day_st[(t, st)] = day_st.get((t, st), 0) + 1
    out_days = []
    today = datetime.now().strftime("%Y-%m-%d")
    for i in range(29, -1, -1):
        d = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        counts = {st: day_st.get((d, st), 0) for st in ("OPEN", "FIXING", "FIXED", "VERIFIED", "CLOSED", "ACCEPTED")}
        out_days.append({"d": d[5:], **counts})
    return {"days": out_days}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    @staticmethod
    def _decide_write(out_lines):
        """写回决策台账（原子：先写 tmp 再 replace）。"""
        p = os.path.expanduser(os.environ.get("WENQU_DECISIONS", "~/Documents/ERP）Zcode/决策台账.jsonl"))
        tmp = p + ".tmp-decide"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(out_lines) + "\n")
        os.replace(tmp, p)

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path == "/api/decide":
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._send(400, '{"error":"bad length"}')
            if n > 1048576:
                return self._send(413, '{"error":"body too large"}')
            try:
                body = json.loads(self.rfile.read(n).decode()) if n else {}
            except ValueError:
                return self._send(400, '{"error":"bad json"}')
            if not isinstance(body, dict):
                return self._send(400, '{"error":"body must be object"}')
            dec_id, action = body.get("id"), body.get("action")
            if not dec_id or action not in ("take", "reject"):
                return self._send(400, '{"error":"需要 id 与 action=take|reject"}')
            path = os.path.expanduser(os.environ.get("WENQU_DECISIONS", "~/Documents/ERP）Zcode/决策台账.jsonl"))
            try:
                _DECIDE_LOCK.acquire()  # 读改写整段互斥（finally 统一释放——行级异常不再泄漏锁）
                try:
                    lines = [l for l in open(path, encoding="utf-8", errors="ignore") if l.strip()]
                    out, hit = [], False
                    for l in lines:
                        try:
                            d = json.loads(l)
                        except ValueError:
                            out.append(l); continue
                        if not isinstance(d, dict):  # 合法 JSON 非对象（数组/null/数字）原样保留，防 AttributeError 泄漏锁
                            out.append(l); continue
                        if d.get("id") == dec_id and d.get("status") == "待拍":
                            d["status"] = "已拍"
                            d["verdict"] = ("采纳默认建议" if action == "take" else "驳回默认建议") + "（dashboard 一键·超哥点击）"
                            d["executed"] = "点击时间 " + datetime.now().strftime("%m-%d %H:%M")
                            hit = True
                        out.append(json.dumps(d, ensure_ascii=False))
                    if not hit:
                        return self._send(404, '{"error":"id 不存在或非待拍"}')
                    self._decide_write(out)
                    return self._send(200, '{"ok":true}')
                finally:
                    _DECIDE_LOCK.release()
            except OSError as e:
                return self._send(500, json.dumps({"error": str(e)}))
        return self._send(404, '{"error":"not found"}')

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
        if self.path == "/api/health":
            b = _EP_CACHE.setdefault("health", {"ts": 0.0, "data": None})
            if b["data"] is not None and time.time() - b["ts"] < 30:  # TTL 30s：走势本身 10min 粒度
                return self._send(200, b["data"])
            def sub(name, got, full, weight, detail=""):
                return {"项": name, "得分": round(got * weight, 1), "满分": weight,
                        "比": f"{got*100:.0f}%", "详情": detail}
            parts, total, full = [], 0.0, 0.0
            c = components()
            items = [it for grp in c["components"].values() if isinstance(grp, list) for it in grp]
            okc = sum(1 for it in items if it["ok"])
            r1 = okc / len(items) if items else 0
            parts.append(sub("组件完整", r1, 100, 30, f"{okc}/{len(items)} 在位")); total += r1*30; full += 30
            daemons_live = 0
            state = os.path.join(WQ, "state")
            if os.path.isdir(state):
                for f in os.listdir(state):
                    if f.endswith(".pid"):
                        try:
                            os.kill(int(open(os.path.join(state, f)).read().strip()), 0)
                            daemons_live += 1
                        except (OSError, ValueError):
                            pass
            cron = 0
            try:
                cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout.count("wenqu/sentinels")
            except OSError:
                pass
            r2 = 1.0 if daemons_live > 0 else (0.5 if cron > 0 else 0.0)
            parts.append(sub("守护与哨兵", r2, 100, 20, f"守护 {daemons_live} 活 / cron {cron} 条")); total += r2*20; full += 20
            import shutil
            du = shutil.disk_usage(os.path.expanduser("~"))
            disk_pct = du.used / du.total * 100
            # 远程盘（cloud4 /opt）——5 分钟缓存防每查必 ssh
            cache_p = "/tmp/wenqu-cloud4-disk.json"
            remote_pct = None
            try:
                if os.path.isfile(cache_p) and datetime.now().timestamp() - os.path.getmtime(cache_p) < 300:
                    remote_pct = json.load(open(cache_p)).get("pct")
            except Exception:
                remote_pct = None
            if remote_pct is None:
                try:
                    out_ = subprocess.run(["ssh", "-o", "ConnectTimeout=4", "-o", "BatchMode=yes", "root@cloud4",
                                           "python3 -c \"import os;s=os.statvfs('/opt');print(round((s.f_blocks-s.f_bavail)*100/s.f_blocks))\""],
                                          capture_output=True, text=True, timeout=6).stdout.strip()
                    remote_pct = float(out_) if out_.replace(".", "").isdigit() else None
                    if remote_pct is not None:
                        json.dump({"pct": remote_pct}, open(cache_p, "w"))
                except Exception:
                    remote_pct = None
            r3 = (1.0 if disk_pct < 80 else (0.7 if disk_pct < 88 else 0.3)) * 0.5
            detail3 = f"本机 {disk_pct:.0f}%"
            if remote_pct is not None:
                r3 += (1.0 if remote_pct < 80 else (0.7 if remote_pct < 88 else 0.3)) * 0.5
                detail3 += f" / 服务器 {remote_pct:.0f}%"
            else:
                r3 += 0.5
                detail3 += " / 服务器未知"
            parts.append(sub("磁盘（本机/服务器）", r3, 100, 10, detail3)); total += r3*10; full += 10
            ratcheted = 0
            for cand in ("scripts/dupscan/baseline.json", os.path.join(os.environ.get("WENQU_REPO_DIR", ""), "scripts/dupscan/baseline.json")):
                if cand and os.path.isfile(cand):
                    try:
                        d = json.load(open(cand))
                        ratcheted = sum(1 for v in d.get("layers", {}).values())
                    except (OSError, ValueError):
                        pass
            r4 = 1.0 if ratcheted >= 3 else (0.5 if ratcheted else 0.0)
            parts.append(sub("棘轮基线", r4, 100, 15, f"{ratcheted}/3 层在位")); total += r4*15; full += 15
            rounds_recent = 0
            for lp in ("~/Documents/ERP）Zcode/持续修复引擎/engine-rounds.jsonl",):
                p = os.path.expanduser(lp)
                if os.path.isfile(p):
                    try:
                        lines = [l for l in open(p, errors="ignore") if l.strip()][-20:]
                        today = datetime.utcnow().strftime("%m-%d")  # 与账本 ts 的 UTC 同口径
                        rounds_recent = 0
                        for l in lines:
                            try:
                                ts = str(json.loads(l).get("ts") or json.loads(l).get("utc") or json.loads(l).get("time") or "")[:16]
                            except ValueError:
                                continue
                            if today in ts:
                                rounds_recent += 1
                    except OSError:
                        pass
            r5 = 1.0 if rounds_recent >= 3 else (0.6 if rounds_recent else 0.2)
            parts.append(sub("账本活性", r5, 100, 15, f"今日 {rounds_recent} 轮")); total += r5*15; full += 15
            try:
                dl = json.load(open(os.path.expanduser("~/Documents/ERP）Zcode/决策台账.jsonl"), errors="ignore")) if False else None
            except Exception:
                dl = None
            pending = 0
            try:
                import io as _io
                with _io.open(os.path.expanduser("~/Documents/ERP）Zcode/决策台账.jsonl"), errors="ignore") as f:
                    pending = sum(1 for l in f if l.strip() and isinstance((json.loads(l) if l.strip().startswith(("{", "[")) else {}), dict) and json.loads(l).get("status") == "待拍")
            except Exception:
                pass
            r6 = 1.0 if pending == 0 else (0.6 if pending <= 3 else 0.2)
            parts.append(sub("决策积压", r6, 100, 10, f"{pending} 条待拍")); total += r6*10; full += 10
            # W0-FND007 修：第 7 维「CI Gate 实际状态」——dashboard 不得比 Gate 更绿
            gate_conclusion = None
            try:
                import subprocess as _sp2
                _r = _sp2.run(["gh", "api", "repos/AIruanchao/qisemi-erp/actions/runs?branch=master&per_page=15",
                              "--jq", '[.workflow_runs[]|select(.name=="CI")][0].conclusion'],
                             capture_output=True, text=True, timeout=10,
                             env={**os.environ, "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"})
                gate_conclusion = _r.stdout.strip() or None
            except Exception:
                gate_conclusion = None
            r7 = 1.0 if gate_conclusion == "success" else (0.0 if gate_conclusion == "failure" else 0.5)
            parts.append(sub("CI Gate（正源）", r7, 100, 20, f"Gate={gate_conclusion or '查询失败'}"))
            total += r7 * 20; full += 20
            score = round(total / full * 100, 0) if full else 0
            # FND-007 硬约束：Gate 红→dashboard 最高只能 40（绝不能比 Gate 更绿）
            if gate_conclusion == "failure" and score > 40:
                score = 40
            grade = "健康" if score >= 90 else ("良好" if score >= 75 else ("关注" if score >= 60 else "告警"))
            if gate_conclusion == "failure":
                grade = "告警"
            hist_p = os.path.expanduser("~/Documents/ERP）Zcode/健康度走势.jsonl")
            try:
                last = ""
                if os.path.isfile(hist_p):
                    for l in open(hist_p, errors="ignore"):
                        if l.strip():
                            last = l
                last_ts = json.loads(last).get("ts", "") if last else ""
                if not last_ts or (datetime.now() - datetime.fromisoformat(last_ts)).total_seconds() > 600:
                    with open(hist_p, "a") as f:
                        f.write(json.dumps({"ts": datetime.now().isoformat(timespec="seconds"), "score": score}, ensure_ascii=False) + "\n")
            except Exception:
                pass
            out = json.dumps({"score": score, "grade": grade, "parts": parts}, ensure_ascii=False)
            b["data"], b["ts"] = out, time.time()
            return self._send(200, out)
        if self.path == "/api/health-history":
            b = _EP_CACHE.setdefault("hh", {"ts": 0.0, "data": None})
            if b["data"] is not None and time.time() - b["ts"] < 30:
                return self._send(200, b["data"])
            out = []
            try:
                for l in open(os.path.expanduser("~/Documents/ERP）Zcode/健康度走势.jsonl"), errors="ignore"):
                    if l.strip():
                        try:
                            d = json.loads(l)
                            out.append({"ts": d.get("ts", "")[5:16], "score": d.get("score")})
                        except ValueError:
                            continue
            except OSError:
                pass
            out = json.dumps(out[-48:], ensure_ascii=False)
            b["data"], b["ts"] = out, time.time()
            return self._send(200, out)
        if self.path == "/api/rounds-heat":
            import collections
            days = collections.Counter()
            for lp in ("~/Documents/ERP）Zcode/持续修复引擎/engine-rounds.jsonl",):
                p = os.path.expanduser(lp)
                if os.path.isfile(p):
                    try:
                        for l in open(p, errors="ignore"):
                            if not l.strip():
                                continue
                            try:
                                d = json.loads(l)
                            except ValueError:
                                continue
                            ts = str(d.get("ts") or d.get("time") or "")[:10]
                            if ts:
                                days[ts] += 1
                    except OSError:
                        pass
            out = []
            for i in range(29, -1, -1):
                day = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
                out.append({"d": day[5:], "n": days.get(day, 0)})
            return self._send(200, json.dumps(out, ensure_ascii=False))
        if self.path.split("?")[0] == "/api/bugscan-ledger":
            d = bugscan_ledger()
            if "_all_items" in d:  # 无参请求不下发内部全集；?items=STATE 按状态过滤钻取
                want = None
                if "?" in self.path:
                    want = dict(p.split("=", 1) for p in self.path.split("?", 1)[1].split("&") if "=" in p).get("items", "")
                d = dict(d)
                full = d.pop("_all_items")
                d.pop("_by_day", None)  # 趋势数据走独立端点（TTL 缓存）
                if want:
                    d["items_state"] = want
                    d["items_total"] = sum(1 for x in full if x["st"] == want)
                    d["items"] = [x for x in full if x["st"] == want][:60]
            return self._send(200, json.dumps(d, ensure_ascii=False))
        if self.path == "/api/bugscan-trend":
            b = _EP_CACHE.setdefault("trend", {"ts": 0.0, "data": None})
            if b["data"] is not None and time.time() - b["ts"] < 60:
                return self._send(200, b["data"])
            out = json.dumps(ledger_trend(), ensure_ascii=False)
            b["data"], b["ts"] = out, time.time()
            return self._send(200, out)
        if self.path == "/api/bugscan-sse":
            # SSE 连接数限制（单用户面 4 路足够；超出 503 防线程放大——dict 计数器免 global）
            if not _SSE_SEM.acquire(blocking=False):  # BoundedSemaphore(4)：线程安全非阻塞获取
                return self._send(503, '{"error":"sse connections full"}')
            # SSE：账本 mtime 签名变化→推事件（前端 EventSource 替代盲轮询；30s 心跳保活）
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                last_stamp = None
                t0 = time.time()
                while time.time() - t0 < 300:  # 5 分钟断开，前端 EventSource 自动重连
                    root = os.path.realpath(os.path.expanduser(
                        os.environ.get("WENQU_BUGSCAN_LEDGER", "~/.zcode/quality-system/bugscan-ledger")))
                    stamp = _ledger_files(root) if os.path.isdir(root) else {}
                    sig = hash(frozenset(stamp.items()))
                    if last_stamp is not None and sig != last_stamp:
                        d = bugscan_ledger()
                        msg = json.dumps({"type": "ledger-changed", "open": d["total"]["by_status"].get("OPEN", 0),
                                          "findings": d["total"]["findings"], "stale": d.get("stale_open", 0)},
                                         ensure_ascii=False)
                        self.wfile.write(f"event: ledger\ndata: {msg}\n\n".encode())
                    else:
                        self.wfile.write(b": hb\n\n")  # 心跳注释行
                    self.wfile.flush()
                    last_stamp = sig
                    time.sleep(10)
            except (BrokenPipeError, ConnectionResetError):
                pass  # 客户端断开
            finally:
                _SSE_SEM.release()
            return
        if self.path.startswith("/api/decisions"):
            want_all = "all=1" in self.path
            out = []
            env = os.environ.get("WENQU_DECISIONS", os.path.expanduser("~/Documents/ERP）Zcode/决策台账.jsonl"))
            try:
                for l in open(env, errors="ignore"):
                    if not l.strip():
                        continue
                    try:
                        d = json.loads(l)
                    except ValueError:
                        continue
                    if not isinstance(d, dict):  # 非对象行防 AttributeError
                        continue
                    if d.get("status") == "待拍" or want_all:
                        row = {k: d.get(k) for k in ("id", "cat", "q", "opt", "ttl", "red", "ts", "intent")}
                        if want_all:
                            row["status"] = d.get("status")
                        out.append(row)
            except OSError:
                pass
            return self._send(200, json.dumps(out, ensure_ascii=False))
        if self.path == "/api/logs":
            b = _EP_CACHE.setdefault("logs", {"ts": 0.0, "data": None})
            if b["data"] is not None and time.time() - b["ts"] < 15:  # 日志尾 15s 滞后可接受
                return self._send(200, b["data"])
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
            out = json.dumps(out, ensure_ascii=False)
            b["data"], b["ts"] = out, time.time()
            return self._send(200, out)
        if self.path == "/api/orchestrator":
            b = _EP_CACHE.setdefault("orch", {"ts": 0.0, "data": None, "lock": threading.Lock()})
            if b["data"] is not None and time.time() - b["ts"] < 30:
                return self._send(200, b["data"])
            with b["lock"]:  # singleflight：并发只一路执行子进程
                if b["data"] is not None and time.time() - b["ts"] < 30:
                    return self._send(200, b["data"])
            # launchd 状态
            orch_state = "未加载"
            try:
                r = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/com.wenqu.orchestrator"],
                                   capture_output=True, text=True, timeout=5)
                if "state = running" in r.stdout: orch_state = "运行中"
                elif "state = not running" in r.stdout: orch_state = "已加载（等触发）"
            except Exception: pass
            sweep_state = "未加载"
            try:
                r = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/com.wenqu.sweep"],
                                   capture_output=True, text=True, timeout=5)
                if "state = running" in r.stdout: sweep_state = "运行中"
                elif "state = not" in r.stdout: sweep_state = "已加载（等触发）"
            except Exception: pass
            # 编排日志尾
            orch_log = "(空)"
            try:
                orch_log = subprocess.run(["tail", "-n", "5", os.path.join(WQ, "logs", "orchestrator.log")],
                                          capture_output=True, text=True, timeout=5).stdout or "(空)"
            except Exception: pass
            out = json.dumps({
                "html": f'<div class="row"><span>编排器（orchestrator.sh）</span><span class="ok">{orch_state}</span></div>'
                       f'<div class="row"><span>陈账检测（sweep.py）</span><span class="ok">{sweep_state}</span></div>'
                       f'<div class="row"><span>管线</span><span class="dim">扫描→sweep 检测→Agent 修→Codex 审(≤3轮)→零发现销账→dashboard 归零</span></div>'
                       f'<div class="row"><span>部署</span><span class="dim">永远停等超哥口令</span></div>'
                       f'<pre id="orchlog" style="margin-top:6px"></pre>',
                "log": orch_log
            }, ensure_ascii=False)
            b["data"], b["ts"] = out, time.time()
            return self._send(200, out)


def main():
    # 启动自检：HTML div 平衡+容器层级（fail-fast——2026-10-07 总览空白事故根治）
    lint_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "html-balance-lint.py")
    if os.path.isfile(lint_path):
        import subprocess as _sp
        rc = _sp.run(["python3", lint_path, os.path.abspath(__file__)],
                     capture_output=True, text=True).returncode
        if rc != 0:
            print("::error::dashboard HTML 平衡自检 FAIL——拒绝启动（修复 div 嵌套后重试）", file=sys.stderr)
            sys.exit(2)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print(f"wenqu dashboard → http://127.0.0.1:{PORT}  (Ctrl-C 停)")
    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))
    srv.serve_forever()


if __name__ == "__main__":
    main()

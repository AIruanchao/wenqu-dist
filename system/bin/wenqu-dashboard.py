#!/usr/bin/env python3
"""wenqu dashboard —— 单文件零依赖 Web 仪表盘（v3.1 新增）

用法：wenqu dashboard [端口=7788]
数据源全部现成：组件体检/守护状态/哨兵日志尾/引擎账本尾/棘轮基线。
"""
import json
from datetime import datetime
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
</style></head><body>
<h1>问渠 wenqu <span class="badge" id="ver">…</span></h1>
<div class="sub">本地质量工程体系 · <span id="ts"></span> · 端口 """ + str(PORT) + """</div>
<nav style="margin-bottom:14px;display:flex;gap:8px">
  <button class="tab active" data-t="ov" onclick="showTab('ov')">总览</button>
  <button class="tab" data-t="pipe" onclick="showTab('pipe')">管线流程</button>
  <button class="tab" data-t="deck" onclick="showTab('deck')">问渠全流程</button>
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
</div>
<script>
async function j(u){const r=await fetch(u);return r.json()}
function el(h){const d=document.createElement('div');d.innerHTML=h;return d}
function showTab(t){
  for(const id of['ov','pipe','deck'])document.getElementById(id).style.display=t==id?'':'none';
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.t==t));
}
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
    d.onclick=()=>{document.querySelectorAll('.scard').forEach(x=>{if(x!==d)x.classList.remove('open')});d.classList.toggle('open')};
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
      document.querySelectorAll('.scard').forEach((c,i)=>{c.classList.toggle('lit',t.s.includes(STATIONS[i].n));c.classList.toggle('off',!t.s.includes(STATIONS[i].n))});
      document.getElementById('tierinfo').innerHTML=`<b style="color:var(--acc)">${t.k}</b> → 站点 {${t.s.join('、')}} · lane/N = ${t.lane}`;
    };
    tb.appendChild(b);
  });
}
let playTimer=null;
function stopPlay(){if(playTimer){clearInterval(playTimer);playTimer=null}}
function playFlow(){
  const cards=[...document.querySelectorAll('.scard')];const ring=document.getElementById('ringcard');
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
  for(const[n,t]of Object.entries(lg)){lbox.appendChild(el(`<h2 style="margin-top:8px">${n}</h2>`));const p=document.createElement('pre');p.innerHTML=t.split(String.fromCharCode(10)).map(l=>/ERROR|FAIL/i.test(l)?`<span style="color:#f85149">${l}</span>`:(/WARN/i.test(l)?`<span style="color:#f0883e">${l}</span>`:(/OK|PASS/i.test(l)?`<span style="color:#3fb950">${l}</span>`:l))).join(String.fromCharCode(10));}
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
      dbox.appendChild(el(`<div class="row" style="align-items:flex-start;flex-direction:column;gap:2px;${overdue?'background:#f8514922;padding:4px 6px;border-radius:6px':''}">
        <div style="display:flex;justify-content:space-between;width:100%"><span><span class="badge" style="background:${d.red?'#f8514933;color:#f85149':'#1f6feb33'}">${d.cat}${d.red?' 🔴':''}</span> ${d.q}</span>
        <span class="${overdue?'bad':'dim'}" style="font-size:11px;white-space:nowrap">${overdue?'⏰ 已逾期':(days!=null?`TTL ${days}d`:'')}</span></div>
        <div class="dim" style="font-size:12px">💡 ${d.opt||''}${d.intent?' <span class="ok">［已标记意向］</span>':''}</div>
        <div style="display:flex;gap:6px;margin-top:3px"><button class="pbtn" style="padding:1px 10px;font-size:11px" onclick="decide('${d.id}','take')">✓ 采纳</button><button class="pbtn" style="padding:1px 10px;font-size:11px;border-color:var(--bad);color:var(--bad)" onclick="decide('${d.id}','reject')">✗ 驳回</button></div>
      </div>`));
    }
  }
  document.getElementById('ts').textContent='更新于 '+new Date().toLocaleTimeString();
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

    def do_POST(self):
        import datetime
        if self.path == "/api/decide":
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n).decode()) if n else {}
            except ValueError:
                return self._send(400, '{"error":"bad json"}')
            did, act = body.get("id"), body.get("action")
            if did not in ("take", "reject") and act not in ("take", "reject"):
                pass
            dec_id, action = body.get("id"), body.get("action")
            if not dec_id or action not in ("take", "reject"):
                return self._send(400, '{"error":"需要 id 与 action=take|reject"}')
            path = os.path.expanduser(os.environ.get("WENQU_DECISIONS", "~/Documents/ERP）Zcode/决策台账.jsonl"))
            try:
                lines = [l for l in open(path, errors="ignore") if l.strip()]
                out, hit = [], False
                for l in lines:
                    try:
                        d = json.loads(l)
                    except ValueError:
                        out.append(l); continue
                    if d.get("id") == dec_id and d.get("status") == "待拍":
                        d["status"] = "已拍"
                        d["verdict"] = ("采纳默认建议" if action == "take" else "驳回默认建议") + "（dashboard 一键·超哥点击）"
                        d["executed"] = "点击时间 " + datetime.datetime.now().strftime("%m-%d %H:%M")
                        hit = True
                    out.append(json.dumps(d, ensure_ascii=False))
                if not hit:
                    return self._send(404, '{"error":"id 不存在或非待拍"}')
                open(path, "w").write("\n".join(out) + "\n")
                return self._send(200, '{"ok":true}')
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
            r3 = 1.0 if disk_pct < 80 else (0.7 if disk_pct < 88 else 0.3)
            parts.append(sub("本机磁盘", r3, 100, 10, f"已用 {disk_pct:.0f}%")); total += r3*10; full += 10
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
                        today = datetime.now().strftime("%m-%d")
                        rounds_recent = sum(1 for l in lines if today in l[:16])
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
                    pending = sum(1 for l in f if l.strip() and json.loads(l).get("status") == "待拍")
            except Exception:
                pass
            r6 = 1.0 if pending == 0 else (0.6 if pending <= 3 else 0.2)
            parts.append(sub("决策积压", r6, 100, 10, f"{pending} 条待拍")); total += r6*10; full += 10
            score = round(total / full * 100, 0) if full else 0
            grade = "健康" if score >= 90 else ("良好" if score >= 75 else ("关注" if score >= 60 else "告警"))
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
            return self._send(200, json.dumps({"score": score, "grade": grade, "parts": parts}, ensure_ascii=False))
        if self.path == "/api/decisions":
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
                    if d.get("status") == "待拍":
                        out.append({k: d.get(k) for k in ("id", "cat", "q", "opt", "ttl", "red", "ts", "intent")})
            except OSError:
                pass
            return self._send(200, json.dumps(out, ensure_ascii=False))
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

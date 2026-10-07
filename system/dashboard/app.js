'use strict';
/* wenqu dashboard W8 前端（自单文件版 wenqu-dashboard.py v3.1 提取改造）
 * 安全改造（威胁模型 T-04/T-05）：
 *  - 全部动态文本走 textContent / DOM 构造，零 HTML 字符串注入 API（日志/账本 XSS 注入面消除）
 *  - 页签切换 showTab 读 data-t 属性；事件全部 addEventListener（无内联 onclick，CSP script-src 'self' 兼容）
 *  - api() 封装 fetch：数据源缺失时服务端返回非 200 + 结构化 {"error":{code,detail}}，前端渲染错误框，
 *    绝不把缺失静默折算成空集/零分（健康度不自算加权分，只读 gate aggregator 快照）
 */
const $=id=>document.getElementById(id);
function el(t,c,txt){const d=document.createElement(t);if(c)d.className=c;if(txt!=null)d.textContent=String(txt);return d}
async function api(path){
  const r=await fetch(path);
  let body=null;
  try{body=await r.json()}catch(_e){/* 非 JSON 体 */}
  if(!r.ok||(body&&body.error)){
    const err=(body&&body.error)?body.error:{code:'HTTP_'+r.status,detail:r.statusText||''};
    const ex=new Error(String(err.code||'ERROR')+': '+String(err.detail||''));
    ex.code=String(err.code||'ERROR');ex.detail=String(err.detail||'');throw ex;
  }
  return body;
}
function errBox(e,extra){
  const d=el('div','errbox');
  d.textContent='⚠ 数据源错误 ['+((e&&e.code)||'NETWORK')+'] '+((e&&e.detail)||e.message||'')+(extra?(' —— '+extra):'');
  return d;
}

/* ── 页签（data-t） ── */
const TAB_IDS=['ov','pipe','deck','bugdeck'];
function showTab(t){
  if(!TAB_IDS.includes(t))t='ov';
  for(const id of TAB_IDS){const n=$(id);if(n)n.classList.toggle('hidden',id!==t)}
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.t===t));
  if(location.hash.slice(1)!==t)history.replaceState(null,'','#'+t);  // 页签记忆：刷新/分享链接直达
}
(function initTabs(){
  const nav=$('tabs');
  if(nav)nav.addEventListener('click',e=>{
    const b=e.target.closest('.tab');
    if(b&&b.dataset.t)showTab(b.dataset.t);
  });
  window.addEventListener('hashchange',()=>{const h=location.hash.slice(1);if(TAB_IDS.includes(h))showTab(h)});
  const h=location.hash.slice(1);if(TAB_IDS.includes(h))showTab(h);
  const p=$('port');if(p)p.textContent='端口 '+(location.port||'80');
})();

/* ── 问渠全流程：八站动态卡片 ── */
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
function scardBase(s,head,afterHead){
  const d=el('div','scard');
  d.addEventListener('click',()=>{document.querySelectorAll('.scard').forEach(x=>{if(x!==d)x.classList.remove('open')});d.classList.toggle('open')});
  const hd=el('div','scard-head');
  hd.appendChild(el('span','sn',s.n));
  hd.appendChild(el('b','scard-title',s.name));
  for(const extra of head)hd.appendChild(extra);
  d.appendChild(hd);
  if(afterHead)afterHead(d);
  return d;
}
function renderDeck(){
  const dk=$('stdeck');if(!dk)return;
  dk.replaceChildren();
  STATIONS.forEach((s,i)=>{
    const d=scardBase(s,[el('span','tier',s.tier)],null);
    d.style.animationDelay=(i*70)+'ms';
    const det=el('div','det');
    det.appendChild(el('div','lab','执行件'));det.appendChild(el('p',null,s.exec));
    det.appendChild(el('div','lab','通过判据'));det.appendChild(el('p',null,s.pass));
    d.appendChild(det);
    d.appendChild(el('span','dim fs11','点击展开执行件 / 通过判据'));
    dk.appendChild(d);
  });
  const tb=$('tiers');if(!tb)return;
  tb.replaceChildren();
  TIERS.forEach(t=>{
    const b=el('button','tbtn',t.k);
    b.addEventListener('click',()=>{
      document.querySelectorAll('.tbtn').forEach(x=>x.classList.remove('on'));b.classList.add('on');
      document.querySelectorAll('#stdeck .scard').forEach((c,i)=>{c.classList.toggle('lit',t.s.includes(STATIONS[i].n));c.classList.toggle('off',!t.s.includes(STATIONS[i].n))});
      const info=$('tierinfo');
      if(info)info.replaceChildren(el('b','t-acc',t.k),document.createTextNode(' → 站点 {'+t.s.join('、')+'} · lane/N = '+t.lane));
    });
    tb.appendChild(b);
  });
}
let playTimer=null;
function stopPlay(){if(playTimer){clearInterval(playTimer);playTimer=null}}
function playFlow(){
  const cards=[...document.querySelectorAll('#stdeck .scard')];const ring=$('ringcard');
  stopPlay();
  const btn=$('playBtn');if(!btn)return;
  if(btn.dataset.run){btn.dataset.run='';btn.textContent='▶ 自动巡游';cards.forEach(c=>c.classList.remove('now'));if(ring)ring.classList.remove('now');return}
  btn.dataset.run='1';btn.textContent='⏸ 停止巡游';
  cards.forEach(c=>c.classList.remove('now'));if(ring)ring.classList.remove('now');
  let i=0;const total=cards.length+1;
  const msg=$('playmsg');
  playTimer=setInterval(()=>{
    if(i>=cards.length){
      cards.forEach(c=>c.classList.remove('now'));if(ring)ring.classList.add('now');
      const f=$('pfill');if(f)f.style.width='100%';
      if(msg)msg.textContent='走查完成——任何「干净/扫完」声明必过收敛环（递归清零 v2.2）';
      stopPlay();btn.dataset.run='';btn.textContent='▶ 自动巡游';return;
    }
    cards.forEach(c=>c.classList.remove('now'));
    const c=cards[i];c.classList.add('now');c.scrollIntoView({block:'nearest',behavior:'smooth'});
    const f=$('pfill');if(f)f.style.width=Math.round((i+1)*100/total)+'%';
    if(msg)msg.replaceChildren(el('b',null,'站'+STATIONS[i].n+' '+STATIONS[i].name),document.createTextNode(' · '+STATIONS[i].tier));
    i++;
  },1500);
}
renderDeck();

/* ── bug 管线静态数据 ── */
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
  const mk=(dkid,arr,build)=>{
    const dk=$(dkid);if(!dk)return;
    dk.replaceChildren();
    arr.forEach((s,i)=>{
      const d=build(s);
      d.style.animationDelay=(i*60)+'ms';
      dk.appendChild(d);
    });
  };
  mk('pfdeck',POSTFIX,s=>{const d=scardBase(s,[el('span','tier',s.tier)],null);
    const det=el('div','det');
    det.appendChild(el('div','lab','执行'));det.appendChild(el('p',null,s.exec));
    det.appendChild(el('div','lab','判读'));det.appendChild(el('p',null,s.pass));
    d.appendChild(det);d.appendChild(el('span','dim fs11','点击展开执行 / 判读'));return d});
  mk('hardendeck',HARDEN,s=>{const d=scardBase(s,[el('span','tier',s.tier)],null);
    const det=el('div','det');
    det.appendChild(el('div','lab','纪律'));det.appendChild(el('p',null,s.exec));
    det.appendChild(el('div','lab','要点'));det.appendChild(el('p',null,s.pass));
    d.appendChild(det);d.appendChild(el('span','dim fs11','点击展开纪律 / 要点'));return d});
  mk('arsdeck',ARSENAL,s=>{const d=scardBase(s,[el('span','tier',s.st),el('span','tier tier-ok',s.badge)],dd=>{
    dd.appendChild(el('div','one',s.one));
  });
    const det=el('div','det');
    det.appendChild(el('div','lab','详情'));det.appendChild(el('p',null,s.det));
    d.appendChild(det);d.appendChild(el('span','dim fs11','点击展开详情'));return d});
  const l6=$('layers6');
  if(l6){l6.replaceChildren(el('div','l6head','v2.0 六层强化（SKILL §8 血统段 2026-10-03「我要最强」）'));
    LAYERS6.forEach(x=>{const r=el('div','row');
      r.appendChild(el('span','dim w40',x.u));
      r.appendChild(el('span','w170',x.name));
      r.appendChild(el('span','ok fs12 w130',x.badge));
      r.appendChild(el('span','dim fs11 flex1',x.det));
      l6.appendChild(r)})}
  const bs=$('blindspots');
  if(bs){bs.replaceChildren();
    BLIND.forEach((t,i)=>{const d=el('div','blind-item');
      d.appendChild(el('span','dim blind-idx',String(i+1).padStart(2,'0')));
      d.appendChild(document.createTextNode(t));
      bs.appendChild(d)})}
  const sp=$('pfspark');
  if(sp){sp.replaceChildren();
    PFCURVE.forEach(v=>{const i=el('i');i.title=v+' 发现';i.style.height=Math.max(3,v*2)+'px';if(v===0)i.className='zero';sp.appendChild(i)})}
}
let pfTimer=null;
function pfFlow(){
  const cards=[...document.querySelectorAll('#pfdeck .scard')];
  const btn=$('pfBtn');if(!btn)return;
  const msg=$('pfmsg');
  if(pfTimer){clearInterval(pfTimer);pfTimer=null;cards.forEach(c=>c.classList.remove('now'));btn.textContent='▶ 巡游五步';return}
  btn.textContent='⏸ 停止巡游';
  cards.forEach(c=>c.classList.remove('now'));
  let i=0;
  pfTimer=setInterval(()=>{
    if(i>=cards.length){
      clearInterval(pfTimer);pfTimer=null;
      cards.forEach(c=>c.classList.remove('now'));
      const f=$('pffill');if(f)f.style.width='100%';
      if(msg)msg.textContent='走查完成——封环条件三条全满足才可宣言收敛';
      btn.textContent='▶ 巡游五步';return;
    }
    cards.forEach(c=>c.classList.remove('now'));
    cards[i].classList.add('now');cards[i].scrollIntoView({block:'nearest',behavior:'smooth'});
    const f=$('pffill');if(f)f.style.width=Math.round((i+1)*100/cards.length)+'%';
    if(msg)msg.replaceChildren(el('b',null,'第'+POSTFIX[i].n+'步 '+POSTFIX[i].name),document.createTextNode(' · '+POSTFIX[i].tier));
    i++;
  },1500);
}
renderBugDeck();

/* ── bugscan-ledger 实数据（状态机） ── */
let bglItemsShown=null;
function bglItemRow(x){
  const r=el('div','row'+(x.stale?' stale-row':''));
  const sevCls=x.sev==='HIGH'?'h':(x.sev==='MED'?'m':(x.sev==='LOW'?'l':''));
  r.appendChild(el('span','chip '+sevCls,x.sev));
  if(x.stale){const s2=el('span','dim stale-note','⏳'+(x.ts||''));s2.title='OPEN 超 14 天无活动=陈账嫌疑';r.appendChild(s2)}
  const pj=el('span','dim ell w110');pj.title=x.proj||'';pj.textContent=x.proj||'';r.appendChild(pj);
  r.appendChild(el('span','dim w96',x.id));
  const ti=el('span','ell flex1');
  if(x.title){ti.title=x.title;ti.textContent=x.title}else{ti.appendChild(el('i','faded','（无标题）'))}
  r.appendChild(ti);
  return r;
}
async function toggleItems(stt,openItems,openTotal){
  let box=$('bglitems');
  if(box&&bglItemsShown===stt){box.remove();bglItemsShown=null;return}
  bglItemsShown=stt;
  if(!box){box=el('div');box.id='bglitems';box.className='bglitems';$('bglstate').appendChild(box)}
  box.replaceChildren(el('div','dim fs11 mb4','载入中…'));
  let d2;
  if(stt==='OPEN'){d2={items:openItems||[],items_total:openTotal||0}}
  else{
    try{d2=await api('/api/v1/bugscan-ledger?items='+encodeURIComponent(stt))}
    catch(e){if(bglItemsShown!==stt)return;box.replaceChildren(errBox(e));return}
  }
  if(bglItemsShown!==stt)return;  // 期间已切换
  const items=d2.items||[];
  const only=(d2.items_total||0)>items.length?('，仅列前 '+items.length+' 条'):'';
  box.replaceChildren(el('div','dim fs11 mb4',stt+' 明细 '+(d2.items_total||0)+' 条（严重度序'+only+'）· 再点 '+stt+' 收起'));
  for(const x of items)box.appendChild(bglItemRow(x));
}
async function loadBGL(){
  let d;
  try{d=await api('/api/v1/bugscan-ledger')}
  catch(e){const b=$('bglstate');if(b)b.replaceChildren(errBox(e,'bugscan-ledger 数据源'));return}
  const box=$('bglstate');if(!box)return;
  if(!d.available){
    box.replaceChildren(el('span','dim',(d.error?('账本读取错误：'+d.error):'未发现 bugscan-ledger 账本目录（~/.zcode/quality-system/bugscan-ledger/）')));
    const pb=$('bglproj');if(pb)pb.replaceChildren();return;
  }
  bglItemsShown=null;const old=$('bglitems');if(old)old.remove();
  const st=d.total.by_status||{};
  const frow=el('div','frow');
  const chain=[['OPEN','发现待修'],['FIXING','修复中'],['FIXED','已修待验·变体'],['VERIFIED','已验证'],['CLOSED','已关闭']];
  const openItems=d.open_items||[],openTotal=d.open_total||0;
  chain.forEach(([k,lab],ix)=>{
    if(ix)frow.appendChild(el('div','arrow','▸'));
    const n=st[k]||0;
    const node=el('div','bnode'+((k==='OPEN'&&n>0)?' hot':''));
    if(n>0){node.title='点击展开该状态明细';node.addEventListener('click',()=>{toggleItems(k,openItems,openTotal)})}
    node.appendChild(el('b',null,k+(n>0?' ▾':'')));
    node.appendChild(el('span','cnt',n));
    node.appendChild(el('span','hint',lab));
    frow.appendChild(node);
  });
  const frow2=el('div','frow mt8');
  frow2.appendChild(el('div','arrow','↳'));
  const acc=el('div','bnode side');
  acc.appendChild(el('b',null,'ACCEPTED'));acc.appendChild(el('span','cnt',st['ACCEPTED']||0));
  acc.appendChild(el('span','hint','有条件接受（批准人+理由+到期日；到期未续自动重开）'));
  const oth=el('div','bnode side');
  oth.appendChild(el('b',null,'OTHER'));oth.appendChild(el('span','cnt',st['OTHER']||0));
  oth.appendChild(el('span','hint','无状态字段/变体未归类'));
  frow2.appendChild(acc);frow2.appendChild(oth);
  const sv=d.total.by_sev||{};
  const chiprow=el('div','mt10');
  chiprow.appendChild(el('span','chip h','HIGH '+(sv.HIGH||0)));
  chiprow.appendChild(el('span','chip m','MED '+(sv.MED||0)));
  chiprow.appendChild(el('span','chip l','LOW '+(sv.LOW||0)));
  chiprow.appendChild(el('span','chip','INFO '+(sv.INFO||0)));
  chiprow.appendChild(el('span','chip','其他 '+(sv.OTHER||0)));
  if((d.stale_open||0)>0){
    const csp=el('span','chip chip-stale','⏳ 陈账 '+d.stale_open);
    csp.title='OPEN 且 >14 天无活动——多半是修了没销账的陈账，跑 sweep 核销';
    chiprow.appendChild(csp);
  }
  const note=el('span','dim fs11','严重度归一口径 · findings 共 '+d.total.findings+' 条 · '+d.projects.length+' 项目 · 最近活动 '+(d.total.last_ts||'—'));
  note.style.marginLeft='6px';
  chiprow.appendChild(note);
  box.replaceChildren(frow,frow2,chiprow);
  const pb=$('bglproj');
  if(pb){pb.replaceChildren();
    d.projects.slice(0,8).forEach(p=>{
      const r=el('div','row');
      const k=el('span','dim ell w132');k.title=p.key||'';k.textContent=p.key||'';
      r.appendChild(k);
      r.appendChild(el('span','flex1 fs12',p.findings+' 条 · OPEN '+(p.by_status.OPEN||0)+' / FIXED '+(p.by_status.FIXED||0)+' / VERIFIED '+(p.by_status.VERIFIED||0)+' / CLOSED '+(p.by_status.CLOSED||0)));
      r.appendChild(el('span','dim fs11 w108',p.last_ts));
      pb.appendChild(r);
    })}
}

/* ── 总览各卡 ── */
async function loadComponents(){
  const c=await api('/api/v1/components');
  const box=$('comp');if(!box)return;
  box.replaceChildren();
  let ok=0,tot=0;
  for(const[grp,items]of Object.entries(c)){
    if(!Array.isArray(items))continue;
    for(const it of items){tot++;if(it.ok)ok++;
      const r=el('div','row');
      r.appendChild(el('span',null,grp+'/'+it.name));
      r.appendChild(el('span',it.ok?'ok':'bad',it.ok?'✓ 在位':'✗ 缺失'));
      box.appendChild(r);
    }
  }
  const pct=tot?Math.round(ok*100/tot):0;
  const bar=el('div','bar');const bi=el('i');bi.style.width=pct+'%';bar.appendChild(bi);
  const sum=el('div','row');
  sum.appendChild(el('span',null,'完整度'));
  sum.appendChild(el('span',pct===100?'ok':'bad',ok+'/'+tot));
  box.prepend(sum);box.prepend(bar);
  const v=$('ver');if(v)v.textContent=c.version||'—';
}
async function loadDaemons(){
  const d=await api('/api/v1/daemons');
  const db=$('daemon');if(!db)return;
  db.replaceChildren();
  const ds=Object.entries(d.daemons||{});
  if(!ds.length)db.appendChild(el('span','dim','无运行中守护（wenqu start）'));
  for(const[n,s]of ds){const r=el('div','row');
    r.appendChild(el('span',null,n));
    r.appendChild(el('span',s==='运行中'?'ok':'bad',s));
    db.appendChild(r)}
  const cl=$('cronline');if(cl)cl.textContent='定时哨兵：'+(d.cron!=null?d.cron:'?')+' 条';
}
async function loadRatchet(){
  const r=await api('/api/v1/ratchet');
  const rb=$('ratchet');if(!rb)return;
  if(!r.available){rb.replaceChildren(el('span','dim','未接入（项目内 scripts/dupscan/baseline.json）'));return}
  rb.replaceChildren();
  for(const[l,v]of Object.entries(r.layers||{})){const row=el('div','row');
    row.appendChild(el('span',null,l));
    row.appendChild(el('span',null,v.clones+' 克隆 / '+v.rate+'%'));
    rb.appendChild(row)}
}
async function loadRounds(){
  const rd=await api('/api/v1/rounds');
  const rbox=$('rounds');if(!rbox)return;
  const prevR=window.__lastRounds;const n=(rd.rounds||[]).length;
  if(prevR!=null&&n>prevR){rbox.classList.remove('flash');void rbox.offsetWidth;rbox.classList.add('flash')}
  window.__lastRounds=n;
  rbox.replaceChildren();
  for(const x of (rd.rounds||[])){
    const r=el('div','row');r.title=x.label||'';
    r.appendChild(el('span','dim w76',x.ts||''));
    const lb=el('span','ell');lb.textContent=x.label;
    r.appendChild(lb);
    rbox.appendChild(r);
  }
  let heat=null;try{heat=await api('/api/v1/rounds-heat')}catch(_e){heat=null}
  const rwrap=rbox.parentElement;
  if(Array.isArray(heat)&&heat.length&&rwrap&&!$('rheat')){
    const mx=Math.max(...heat.map(x=>x.n||0),1);
    const bar=el('div');bar.id='rheat';bar.className='heatwrap';
    for(const x of heat){const i=el('i','heat');i.title=(x.d||'')+': '+(x.n||0)+' 轮';i.style.opacity=x.n?(0.25+0.75*x.n/mx):0.08;bar.appendChild(i)}
    bar.appendChild(el('span','dim heatnote','近 30 天轮次'));
    rwrap.appendChild(bar);
  }
}
async function loadLogs(){
  const lg=await api('/api/v1/logs');
  const lbox=$('logs');if(!lbox)return;
  lbox.replaceChildren();
  for(const[n,t]of Object.entries(lg)){
    lbox.appendChild(el('h2','mt8',n));
    const p=document.createElement('pre');
    for(const line of String(t).split('\n')){
      if(line){
        const cls=/ERROR|FAIL/i.test(line)?'lg-err':(/WARN/i.test(line)?'lg-warn':(/OK|PASS/i.test(line)?'lg-ok':null));
        if(cls)p.appendChild(el('span',cls,line));else p.appendChild(document.createTextNode(line));
      }
      p.appendChild(document.createTextNode('\n'));
    }
    lbox.appendChild(p);
  }
}
async function loadHealth(){
  const hbox=$('health');if(!hbox)return;
  let h;
  try{h=await api('/api/v1/health')}
  catch(e){hbox.replaceChildren(errBox(e,'健康度正源=gate aggregator 快照（本端不自算加权分）'));return}
  const verdict=String(h.policy_verdict||h.overall||h.verdict||'NOT_EVALUATED');
  const score=Number.isFinite(h.score)?Math.round(h.score):null;
  const hist=window.__hist||(window.__hist=[]);
  if(score!=null){hist.push(score);if(hist.length>24)hist.shift()}
  const col=score==null?(verdict==='PASS'?'var(--ok)':(verdict==='FAIL'?'var(--bad)':'#f0883e'))
    :(score>=90?'var(--ok)':(score>=75?'#f0883e':'var(--bad)'));
  const wrap=el('div','hbox');
  const left=el('div','htxt');
  const sc=el('div','hscore');sc.id='hscore';sc.style.color=col;
  if(score!=null){sc.textContent=score}else{sc.textContent=verdict;sc.style.fontSize='20px'}
  const gr=el('div','hgrade');gr.style.color=col;
  gr.textContent=score!=null?(h.grade?(h.grade+' · '+verdict):verdict):('verdict '+verdict);
  left.appendChild(sc);left.appendChild(gr);
  const mid=el('div','hsparkwrap');
  const sp=el('div','spark');sp.id='hspark';
  for(const v of hist){const i=el('i');if(v<75)i.className='hot';i.style.height=Math.max(3,v*0.3)+'px';i.title=String(v);sp.appendChild(i)}
  mid.appendChild(sp);mid.appendChild(el('div','dim hnote','最近走势'));
  const right=el('div','hparts');
  for(const p of (Array.isArray(h.parts)?h.parts:[])){
    if(!p||typeof p!=='object')continue;
    const name=p['项']!=null?String(p['项']):(p.name!=null?String(p.name):'');
    const det=p['详情']!=null?String(p['详情']):(p.detail!=null?String(p.detail):'');
    const got=p['得分'],full=p['满分'];
    const ratio=(Number.isFinite(got)&&Number.isFinite(full)&&full>0)?(Number(got)/Number(full)):null;
    const row=el('div','row');
    row.appendChild(el('span',null,name));
    row.appendChild(el('span','dim',det));
    const cell=el('span',null,(Number.isFinite(got)?got:'—')+'/'+(Number.isFinite(full)?full:'—'));
    cell.style.color=ratio===1?'var(--ok)':'#f0883e';
    row.appendChild(cell);
    right.appendChild(row);
  }
  wrap.appendChild(left);wrap.appendChild(mid);wrap.appendChild(right);
  const meta=el('div','dim fs11 mt8','快照源 '+(h.source||'gate-aggregator')+' · 时间 '+(h.generated_at||h.ts||'—'));
  hbox.replaceChildren(wrap,meta);
  const scEl=$('hscore');
  if(scEl&&window.__scorePrev!=null&&score!=null&&window.__scorePrev!==score){
    scEl.classList.remove('popnum');void scEl.offsetWidth;scEl.classList.add('popnum');
    const updown=el('span',score>window.__scorePrev?'up':'down',score>window.__scorePrev?'▲':'▼');
    if(scEl.parentElement)scEl.after(updown);
  }
  window.__scorePrev=score;
  let hh=null;try{hh=await api('/api/v1/health-history')}catch(_e){hh=null}
  if(Array.isArray(hh)&&hh.length>1){
    const pts=hh.map((p,i)=>(20+i*(440/Math.max(hh.length-1,1)))+','+(40-(Number(p.score)||0)*0.36)).join(' ');
    const chart=el('div','hh-chart');
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('width','100%');svg.setAttribute('height','44');
    svg.setAttribute('viewBox','0 0 460 44');svg.setAttribute('preserveAspectRatio','none');
    const pl=document.createElementNS('http://www.w3.org/2000/svg','polyline');
    pl.setAttribute('points',pts);pl.setAttribute('fill','none');
    pl.setAttribute('stroke','#3fb950');pl.setAttribute('stroke-width','2');
    svg.appendChild(pl);chart.appendChild(svg);
    chart.appendChild(el('div','dim hnote','历史走势 '+hh.length+' 点（'+(hh[0].ts||'—')+' 起）'));
    hbox.appendChild(chart);
  }
}
async function loadDecisions(){
  const dec=await api('/api/v1/decisions');
  const dbox=$('dec');if(!dbox)return;
  const pc=$('deccard');
  const prevD=window.__lastDec;
  if(pc&&prevD!=null&&prevD!==dec.length){pc.classList.remove('flash');void pc.offsetWidth;pc.classList.add('flash')}
  window.__lastDec=dec.length;
  if(!dec.length){dbox.replaceChildren(el('span','dim','无待拍项——全部清账 ✅'));return}
  dbox.replaceChildren();
  for(const d of dec){
    const days=d.ttl?Math.max(0,d.ttl-Math.floor((Date.now()-new Date(d.ts).getTime())/86400000)):null;
    const overdue=days===0;
    const row=el('div','row dec-row'+(overdue?' dec-overdue':''));
    const top=el('div','dec-top');
    const left=el('span');
    left.appendChild(el('span','badge'+(d.red?' badge-red':''),(d.cat||'')+(d.red?' 🔴':'')));
    left.appendChild(document.createTextNode(' '+(d.q||'')));
    top.appendChild(left);
    top.appendChild(el('span',(overdue?'bad':'dim')+' dec-ttl',overdue?'⏰ 已逾期':(days!=null?('TTL '+days+'d'):'')));
    const opt=el('div','dim dec-opt','💡 '+(d.opt||''));
    if(d.intent)opt.appendChild(el('span','intent-ok',' ［已标记意向］'));
    const btns=el('div','dec-btns');
    const hint='第一阶段写接口已关闭（POST /api/decide → 405）';
    const bt=el('button','pbtn pbtn-sm','✓ 采纳');bt.disabled=true;bt.title=hint;
    const br=el('button','pbtn pbtn-sm dec-reject','✗ 驳回');br.disabled=true;br.title=hint;
    btns.appendChild(bt);btns.appendChild(br);
    row.appendChild(top);row.appendChild(opt);row.appendChild(btns);
    dbox.appendChild(row);
  }
  let all=null;try{all=await api('/api/v1/decisions?all=1')}catch(_e){all=null}
  if(Array.isArray(all)&&all.length){
    const doneAll=all.filter(x=>x.status!=='待拍');
    const done=doneAll.slice(-8).reverse();
    if(done.length){
      const det=el('details');det.className='mt8';
      det.appendChild(el('summary','dim sum-dim','已拍 '+doneAll.length+' 条（点击展开）'));
      for(const x of done){
        const r=el('div','row dec-done');
        r.appendChild(el('span','dim',x.id));
        const q=el('span','flex1 ell');q.title=x.q||'';q.textContent=x.q||'';
        r.appendChild(q);
        r.appendChild(el('span',x.status==='已拍'?'ok':'dim',x.status));
        det.appendChild(r);
      }
      dbox.appendChild(det);
    }
  }
}

/* ── 刷新循环（分区容错：任一数据源失败只染红自己的卡） ── */
const SECTIONS=[
  ['comp',loadComponents],
  ['daemon',loadDaemons],
  ['ratchet',loadRatchet],
  ['rounds',loadRounds],
  ['logs',loadLogs],
  ['health',loadHealth],
  ['dec',loadDecisions],
];
async function refresh(){
  await Promise.all(SECTIONS.map(async([box,fn])=>{
    try{await fn()}catch(e){const b=$(box);if(b)b.replaceChildren(errBox(e))}
  }));
}
refresh().catch(()=>{});
setInterval(()=>refresh().catch(()=>{}),5000);
loadBGL().catch(()=>{});
setInterval(()=>loadBGL().catch(()=>{}),60000);
setInterval(()=>{const t=$('ts');if(t)t.textContent='更新于 '+new Date().toLocaleTimeString('zh-CN',{hour12:false})},1000);

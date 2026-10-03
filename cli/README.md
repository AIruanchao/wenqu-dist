# wenqu — 缺陷工程轨道 CLI（F7 v0.3.0，血统件上轨）

**轨道，不是大脑**：确定性站位原生执行；AI 站位只做 发 charter→收产物→跑收口门；智能永远在会话侧。
底座三件套：sha256 范围冻结 + jsonl append-only 账本 + exit-code 收口门。**stdlib-only（Python≥3.9），零供应链。**

## 快速开始

```bash
python wenqu init --path <仓库>            # 站0：范围冻结（scope_hash）
python wenqu run tests --path <仓库>       # 确定站：fail 自动落账 OPEN（exit 1）
python wenqu ingest <发现.jsonl>           # AI 站产物入账（schema 严格，方言自动归一）
python wenqu findings --sev HIGH --status OPEN   # 现态查询（有 OPEN 时 exit 1——CI 可挂）
python wenqu close <id> --note "理由"      # 状态转移（append-only，不改写历史）
python wenqu verify --allow-open 0         # 收口门：schema 净 + OPEN≤限额 → exit 0/1
python wenqu repair                        # 账本自愈（坏行/重复/孤儿→隔离区，v0.2#7）
python wenqu selftest                      # 端到端自证（零依赖环境 30 秒体检）
python -m pytest test_wenqu.py -q          # 契约测试套件（20 用例）
```

## 加固点

append-only 账本（转移审计链可见）/ schema 双口校验/ 原子 ingest（默认全有或全无，--partial 逐行）+**方言归一**（severity→sev、高/中/低→HIGH/MEDIUM/LOW）/ 幂等 init / 全链 UTF-8 / 退出码契约（0/1/2）经 selftest+pytest 双层锁定 / SKIP_DIRS 防扫描污染。

## 纪律

- **预算帽（自带 C-3）**：本目录代码+测试 ≤1200 非空行（当前 ~570，余 51%）。
- 站位注册表 STATIONS 为内置最小集；扩展=加表项，不加代码层（未来若加载外部配置，须列表型 cmd+PATH 白名单——评审#10 前置约束）。close 走状态机（--allow-any 逃生门）；init 范围漂移且账本非空须 --force；时间戳统一 UTC。
- AI 站位 charter 模板见 `../plane/docs/反方评审章程-v1.0.md` 附录 B。

## 血统与闸门

问渠八站一环一本账 v1.6（maccc 正源）｜ F7 设计稿 ｜ 启动指令=超哥 2026-09-30"启动问渠 作为CLI形态 加固"。三闸中②③按指令越期（风险：问渠线后续接管正源评审；本工具零接触生产）。


## fork 行为增补（maccc fork1-4，2026-10-02；详见 ../CHANGELOG.md）

- **自定义站位**（fork1/BSF-37）：`run <名>` 不再被 argparse 锁死——stations.json 里的域探测器可直接 run；未知站位仍 exit 2 兜底且报错列出全部可用站位（含自定义）。
- **超时**（fork2/3）：每站可配 `"timeout": 秒`（默认 300；须 ≥1 整数）；超时=exit 2 不落账不计通过。
- **轮次**（fork2/3）：`run <站> --round N`（N≥1）——run 审计行与 AUTO 发现携带轮次，参与 `verify --convergence` 判定。
- **convergence 三前置**（fork2/BSF-38）：Converged 须 已标轮次 ≥N 且轮号连续 且近 N 轮零新发现；任一不满足即拒绝（证据不足/不连续/未收敛）。
- **repair 行类安全**（fork4/BSF-39）：run/charter 审计行不再被误隔离（原一次 repair 清空审计链+废掉 sweep）；重写账本走与 append 相同的锁协议；quarantine 追加式（不覆盖前次隔离历史）。

## fork5-15 行为增补（v1.0.15 补录——此前停在 fork4）
- fork5 sweep 站名精确匹配（provenance.station）；fork6 并发安全四写者全程锁+ingest 折叠视图+charter 铸轮拒绝；fork7 GBK 写路径；fork8 U+2028 行分割+close 锁+kind 白名单；fork9 flock 锁+缺 id+--path 守卫；fork10 rc 契约（1=命中/≥2=环境错误）+B 段双断言；fork11 rc≥2 不落账+UTC 绝对断言；fork12 PIPESTATUS 直管+die 前置；fork13 LC_ALL=C 三站+finding 先于日志；fork14 日志降级统一；fork15 provenance 降级标记+! -type l。详见 ../CHANGELOG.md。

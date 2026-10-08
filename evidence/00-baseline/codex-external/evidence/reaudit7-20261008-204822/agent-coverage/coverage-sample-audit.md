# §20 专属覆盖真实性抽查（第七轮，冻结 d32c859）

## 口径

- 方案正源 SHA256：`96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306`。
- 候选：`d32c859f9043798d9e8a4984e8f57aa64567e33c`；全部破坏性验证在 `/tmp` 私有副本。
- 不是按函数名判真：逐项对照冻结 `injection`、`expectation` 与函数体真实断言，并对可疑项另造负例。
- 抽取 27 条，覆盖 GATE/CI/STATE/DEP/SC/TEN/PERF/CAP/BAK/DR/UI 11 族。27 个 pytest node 独立执行 `27 passed`（rc=0）；源代码与行号见 `selected-tests-source.json`。

## 逐项对照

| ID | 冻结注入 → 期望 | 实际断言语义（非名称） | 判定 |
|---|---|---|---|
| GATE-09 | `N=-1/0/超上限` → 参数错误 | `-1/0/4/99/bool/str/float/None`、低于 lane 契约、伪造 `N=0` plan 均抛错；1/2/3 正控通过。 | 符合 |
| GATE-10 | 超过 `N+1` → BLOCKED 等人工 | 跑满轮次未收敛即 BLOCKED，写入人工裁定证据；自动续轮拒绝；仅 STOP/CONTINUE 裁定，CONTINUE 只加一轮。 | 符合 |
| GATE-11 | 同命令换 S 标签 → 不计异源轮 | 同 argv 换标签/解释器路径/空白扰动只增 duplicate；真 argv 变化才增异源轮，重复不推进收敛窗口。 | 符合 |
| CI-06 | CODEOWNERS 存在但 ruleset 未强制 → doctor ERROR | 临时 repo + ruleset fixture 覆盖零规则、evaluate/disabled/错分支/批准数0等，均 ERROR；真 CLI rc1/rc0 正反对照。 | 符合（协议级 fixture，不代替线上回读） |
| STATE-02 | traversal/绝对路径/NUL/超长 ID → 拒绝 | 对 create_run/run API/finding 三入口注入坏 ID，断言结构异常及零落账；合法与格式合法未知 ID 作精确性正控。 | 符合 |
| STATE-05 | 双 writer epoch → 所有旧写拒绝 | advance/wait/finding/complete/cancel/supersede/adjudicate、broker 消费、epoch0、旧 epoch 重放全部拒绝且零副作用。 | 符合 |
| STATE-09 | SHA/scope/policy 变化 → 强制新 run | 三种 identity 漂移/缺失的 otherwise-valid 事件重放报 corruption；正道旧 run SUPERSEDED、新身份新 run；同 identity 正控。 | 符合 |
| STATE-11 | S7 CONDITIONAL 缺 risk auth → FAILED；后批只能新 run | 终判 FAILED，终态全部写 API 拒绝；迟到审批不能复活，授权后另建新 run，原流无 WAITING。 | 符合 |
| DEP-01 | 两部署者争 lease → 最多一成功 | 两真实子进程并发 16MiB 源，恰一 WIN/一 LeaseError；显式持锁拒绝；SIGKILL 后内核释放锁。 | 符合 |
| DEP-02 | smoke 访问生产 DB/state → 隔离拒绝 | 临时 sandbox 中对生产路径 open/sqlite/symlink 逃逸均拒，失败版本不激活、旧 current 与生产字节不变。 | 符合（本机 audit-hook 隔离） |
| DEP-04 | 自签/替换/revoked release key → 拒绝 | unknown 自签 key、替换 pinned key、签名体/manifest 篡改、revoked key 的 verify/rollback/sign 均拒；current 不变。 | 符合（HMAC 非否认性为已知边界） |
| DEP-06 | 无迁移锁/未验证备份/expand 越权 → 激活前 BLOCKED | 缺三要素汇总拒绝；伪锁、漂移备份、错类型/坏签名/不绑定 digest 授权拒绝；三项真凭证齐备才激活。 | 符合 |
| DEP-08 | ROLLBACK_FAILED → writer/merge/release 熔断 | 投毒 previous 使自动回滚失败，持久 FUSE_OPEN；新 manager 的 deploy/rollback 均拒；只准人工修复+resume。 | 符合 |
| DEP-09 | 观察窗内 contract/down → 拒绝、独立授权 | 窗内 contract/down 无独立 `ddl_contract` 授权拒绝；expand、独立授权及窗后正控通过。 | 符合 |
| SC-03 | install script/resolved/integrity 变化 → FAIL/人工审 | lockfile 新增、resolved、integrity、install script 分别落 HIGH/P1 finding；新增依赖进入分母；相同锁正控 PASS。 | 符合 |
| SC-05 | 快照签名错误/过期/**分页不全** → BLOCKED | 签名错、过期、载荷篡改、裸 JSON 均 BLOCKED；但专属函数把分页委托给 ADV-02，产品验签不检查分页。独立构造合法签名 `complete:false,pages_total:2` 被 `COMPLETED/PASS 12/12`。 | **部分；分页腿假绿** |
| TEN-04 | `$queryRaw` 跨租户 → 阻断 | `$queryRaw/$executeRaw`、裸 SQL、SELECT 列表诱饵、间接 SQL、否定谓词均报 finding；WHERE 租户等值/ANY 正控通过。 | 符合 |
| PERF-03 | 尾部极慢样本 → 正确进 p95/p99 | 1..100 线性插值验算；90×10ms+10×1000ms 得 p95/p99=1000；阈值只报对应 finding；全快正控。 | 符合 |
| PERF-04 | 输入 1→100、query count 线性 → FAIL | 1→2、100→101 的最小二乘斜率约1，线性+超限均报；批处理、常数超限、单点边界分开验证。 | 符合 |
| CAP-01 | 峰值超余量或磁盘满 → BLOCKED，旧证据/current 完整 | 真实 disk_usage 正控；数字注入 95%、free=0、峰值预算不足、quota 超阈值均红；BLOCKED 前后证据 hash/current 等值。 | 符合（安全数字注入，不真塞盘） |
| BAK-01 | **磁盘满/tar/backup 失败** → 不更新 success | 真实 `cp` 演练、恢复逐字节对账及“空语料”generic backup failure；函数 docstring 明示未注入磁盘满/tar，产品脚本也无 tar 通路。 | **部分；冻结三腿只覆盖一类** |
| DR-01 | 恢复演练 → 实测满足冻结 RPO/RTO | 真 subprocess/cp 临时语料，故障窗口1.5s；RPO/RTO 有限且锚点单调，目标固定300/60，恢复字节全等、JSON/jsonl 同值。 | 符合（临时语料，不是生产灾备） |
| UI-01 | 少一个闭合标签 → 构建/启动门失败 | 启动自检对缺 `</div>` 红；parser 构建门对 div/span/html/游离闭合均红。但产品 `--self-check` 仅数 div，独立删 `</span>` 后仍 rc0/PASS。 | **部分；构建门可挡，产品启动门漏 span** |
| UI-03 | CSRF/伪 Origin/text/plain 写 → 拒绝 | 真服务跨源403、预检405无 ACAO、写口405、其他 text/plain 415、chunked 411；脆弱假服务被探针命中。 | 符合 |
| UI-04 | Gate 红且他项高分 → 总体 BLOCKED | 真服务逐字透传 BLOCKED/score/watermark；转 PASS 即时传播；过期503；自算洗绿假服务被探针双报。 | 符合 |
| UI-06 | DNS rebinding/伪 Host/**未认证日志读取** → 拒绝 | 伪/空/错 Host 与跨源均403，但正确 Host、无 Authorization/Cookie 的匿名 `/api/v1/logs` 被专属测试当正控。独立注入敏感标记实得 HTTP200 并泄漏。 | **部分；未认证腿假绿** |
| UI-07 | 慢请求/高并发/**超大日志** → 不耗尽 | 慢连接、60并发、体积声明、速率守卫有断言；普通多行大日志因 `tail -20` 受控。但独立 6MiB 单行日志返回约6.29MB，产品无字节上限。 | **部分；病态单行无界** |

## 汇总

- 抽样：27/131（20.6%），11 族；**22 条完整对应，5 条部分对应**。
- 这不是 131 全体的统计推断；它足以反证“131/131 均具备冻结语义”的绝对声明。
- 4 个明确可复现产品/协议假绿：SC-05 分页、UI-06 匿名日志、UI-07 单行巨日志、UI-01 启动自检 span；BAK-01 是冻结注入未按字面执行。
- 更根本的 Gate 问题：将 SC-05 函数体清空为唯一 `assert True` 后，专属套件仍 29/29，trace 仍 131/131、rc0；另一独立探针将整份 gate family 替换为 24 个 `pass` 后完整 acceptance 仍 66/66。函数名/计数不等于语义覆盖。

## 核心证据

- `04-trace-baseline.log`、`trace-baseline.json`：冻结 131 集合/映射基线。
- `05-dedicated-baseline.log`：八专属文件 131 函数全跑基线。
- `16-selected-source-extract.log`、`selected-tests-source.json`：27 条函数体/行号/文档字符串。
- `25-selected-27-pytest.log`：27 node 实跑，rc0、27 passed。
- `18-independent-sc05-pagination-rerun.log`：分页不全假绿。
- `21-ui01-span-product-selfcheck-rerun.log`：缺 span 的产品启动自检假绿。
- `22-independent-ui06-noauth.log`：匿名日志泄漏。
- `23-independent-ui07-single-line.log`：6MiB 单行响应无字节界。
- `33-vacuous-single-id-direct.log`：单 ID 空语义仍被 suite+trace 计绿。
- `38-bak01-product-static-rerun.log`：备份产品通路为 cp、无 tar。

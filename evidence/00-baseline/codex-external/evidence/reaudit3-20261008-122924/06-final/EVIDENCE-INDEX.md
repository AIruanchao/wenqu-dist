# 第三轮复审证据索引

- 复审对象：`/Users/maccc/Documents/wenqu-dist`
- 冻结提交：`ff050bbb9c95c04ecb975900f5440f9bfcd1a447`
- 方案 SHA256：`96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306`
- 证据根：`/private/tmp/codex-test/evidence/reaudit3-20261008-122924`

所有 `00-baseline`～`06-final` 的命令记录均带命令、输出和退出码；三个子审计目录保存探针源码和原始输出。

## 关键证据

| 范围 | 文件 | 结论 |
|---|---|---|
| 基线与身份 | `00-baseline/git-status-head.txt`、`source-hashes.txt`、`capacity-and-identity.txt` | HEAD、clean、方案/二轮报告哈希 |
| acceptance | `01-regression/acceptance-full.txt` | 本地 62/62，rc=0 |
| acceptance 副作用 | `00-baseline/acceptance-mutated-worktree.txt`、`post-restore-status.txt` | 会改写受版本控制矩阵；验收后已恢复 |
| 核心自测 | `01-regression/test-wenqu-pipeline.txt`、`test-core-wiring.txt` | 10/10、8/8 |
| 模块移除 | `03-adversarial/removal-module.txt`、`agent-core/09-removal-wenqu_pipeline.log` | 两个指定测试均非零 |
| Schema 移除/篡改 | `03-adversarial/removal-schema.txt`、`schema-tamper-crosscheck.txt` | Schema 删除双红；approval-v2 篡改交叉验证红 |
| 工具移除 | `03-adversarial/removal-tool.txt` | acceptance 61/1，rc=1 |
| P0-1/P0-2 全审 | `agent-core/findings.md`、`agent-core/11-adversarial-pipeline.log` | 测试锚点成立但生产接线、审批与重放不变量失败 |
| 安装漏接线 | `agent-core/16-removal-installer-still-green.log` | 删除核心模块后安装仍 rc=0 |
| 非 resume CAS | `agent-core/17-nonresume-cas-bypass.log` | 旧 state_version 风险授权仍被消费 |
| P0-3 契约链 | `03-adversarial/p0-3-contract-chain.txt`、`agent-evidence/15-p0-3-contract-probe.log` | v2 station→aggregator→dashboard 断链 |
| Schema 对抗 | `agent-schema/15-schema-adversarial-results.txt` | approval/finding/evidence/station/run 多项反例被接受 |
| Approval Broker | `agent-schema/16-approval-broker-adversarial-results.txt` | 缺绑定、错 policy、跨类型、HIGH 风险均可消费 |
| CAS/Runner | `agent-schema/17-cas-runner-adversarial-results.txt` | 父目录 TOCTOU、hardlink、部分写、setsid 逃逸 |
| EventStore | `03-adversarial/eventstore-residual.txt`、`agent-evidence/16-p0-6-store-probe.log` | duplicate 伪 hash、错误 head、双表双正源 |
| Deploy | `03-adversarial/deploy-residual.txt`、`agent-evidence/18-p0-7-deploy-probe.log` | mode 与升级回滚仍失败 |
| auto-merge | `02-runtime/auto-merge-readonly.txt` | 源码为拒绝 stub，安装体/进程/cron 均未发现 |
| Dashboard 运行身份 | `02-runtime/dashboard-identity-readonly.txt`、`dashboard-installed-source-diff.txt` | 7789 运行旧安装体，未部署安全修复 |
| 观察窗 | `02-runtime/observation-window-readonly.txt` | 仅 1 次样本，40/告警/Gate failure |
| 131 追踪矩阵 | `04-evidence/ac-traceability-live.txt`、`independent-id-set-check.txt` | 三集合 131 等式成立；专属 0、代理 3、缺失 128 |
| 追踪假绿 | `agent-evidence/22-trace-plan20-tamper-default.log`～`25-acceptance-plan20-tamper.log` | §20 篡改下 acceptance 仍全绿；§25.1 元数据未被 check |
| 仓内 evidence 对账 | `agent-evidence/19b-evidence-index-reconcile.log` | 索引 stale；01～13 只有 README；严格可核验条目为 0 |
| CI 真实性 | `05-ci/gh-run-view.json.txt`、`gh-run-log.txt` | run 37727549548 对 ff050bb 双平台 success |
| 分支保护 | `05-ci/branch-protection.txt` | main 未保护、rulesets=[] |
| 制品/工作包目录 | `06-final/release-and-workpack-inventory.txt` | 无 tar/zip 最终制品；01～13 无直接实质工件 |
| 子审计汇总 | `agent-core/findings.md`、`agent-evidence/findings.md` | 独立分域复核结果 |

## 完整性

- 子目录清单：`agent-core/MANIFEST.sha256`、`agent-evidence/MANIFEST.sha256`
- 全证据根清单：`MANIFEST.sha256`
- 总报告：`/private/tmp/codex-test/验收报告-第三轮.md`
- 总报告摘要：`/private/tmp/codex-test/验收报告-第三轮.md.sha256`

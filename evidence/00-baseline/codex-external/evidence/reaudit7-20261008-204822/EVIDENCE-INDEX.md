# 第七轮复审证据导航

- 审计时间：2026-10-08 20:48–21:12（Asia/Shanghai）
- 冻结验收对象：`d32c859f9043798d9e8a4984e8f57aa64567e33c`
- 冻结副本：`/private/tmp/wenqu-reaudit7-20261008-204822`
- 原则：源仓只读；所有破坏性变异均位于 `/tmp` 私有副本。

## 顶层环境与基线

| 文件 | 内容 |
|---|---|
| `00-context.txt` | 起始身份、源仓状态、方案与第六轮报告摘要 |
| `01-copy-freeze.txt` | d32 冻结副本构造与对象身份 |
| `02-source-ref-drift.txt` | 本地分支、main、远端 ref 差异 |
| `09-live-source-drift-2051.txt` | 审计中外部并行源树漂移 |
| `11-final-source-runtime-status.txt` | 终点源仓、remote main、launchd、7789 health/405 快照 |
| `12-submanifest-verification.txt` | 三个子证据清单校验 rc0 |

## F6 与 P0

| 文件 | 内容 |
|---|---|
| `agent-f6-p0/FINDINGS.md` | F6 六项、P0 十项汇总 |
| `agent-f6-p0/10-gate-independent-probe.log` | manifest 缩 required、自算摘要、重复语义漂移、schema 边界 |
| `agent-f6-p0/11-trace-parser-independent.log` | 缺 plan、重复行、全文件 SHA 漂移应红 |
| `agent-f6-p0/14-evidence-index-strict-audit.log` | 20 条证据索引逐条实算与严格字段统计 |
| `agent-f6-p0/15-p1f-noop-semantic-bypass.log` | 专属测试空壳但 acceptance 66/66 |
| `agent-f6-p0/30-approval-independent-probe.log` | target 未绑定、联签未消费、权限未强制 |
| `agent-f6-p0/40-events-unified-independent-probe.log` | legacy events 仍可增删改及二次导入 |

## 131 覆盖与篡改

| 文件 | 内容 |
|---|---|
| `agent-coverage/SUMMARY.md` | 131 基线、27 条抽查与 Gate 破坏性结论 |
| `agent-coverage/coverage-sample-audit.md` | 27 条跨族 ID→注入→期望→断言逐项表 |
| `agent-coverage/25-selected-27-pytest.log` | 27 条节点实跑，27 passed |
| `agent-coverage/42-independent-gate-full-adversarial.log` | manifest/重复件/schema 综合独立探针 |
| `agent-coverage/34-section20-id-full-acceptance.log` | §20 ID 篡改完整 acceptance 必红 |
| `agent-coverage/35-section20-semantic-full-acceptance.log` | §20 语义篡改完整 acceptance 必红 |
| `agent-coverage/36-section251-full-acceptance.log` | §25.1 映射篡改完整 acceptance 必红 |
| `agent-coverage/43a-p1f-delete-full-acceptance.log` | P1f 删件必红 |
| `agent-coverage/43b-p1f-gatefamily-stub-full-acceptance.log` | 保留函数名但语义空壳仍全绿 |
| `agent-coverage/18-independent-sc05-pagination-rerun.log` | SC-05 不完整分页仍 PASS |
| `agent-coverage/22-independent-ui06-noauth.log` | 匿名日志读取 200 |
| `agent-coverage/23-independent-ui07-single-line.log` | 6MiB 单行日志无字节上限 |

## 运行面、CI、W4/W5、TLA、release

| 文件 | 内容 |
|---|---|
| `agent-runtime/SUMMARY.md` | 运行面与外部事实总览 |
| `agent-runtime/02-gh-run-json.txt`、`03-gh-run-human.txt` | GitHub run 37778240376 双平台 success |
| `agent-runtime/05-branch-protection.txt`、`06-rulesets.txt` | 分支保护/ruleset 回读 |
| `agent-runtime/10b-live-7789-process.txt`、`12c-live-http-7789.txt`、`13-runtime-candidate-hash.txt` | 7789 进程、API、运行文件 hash |
| `agent-runtime/36-w4-tests-d32.txt` | W4 候选 36/36 |
| `agent-runtime/47-scheduler-final-2101.txt` | launchd 自然 tick 与现役 aggregate BLOCKED |
| `agent-runtime/39-w4-alert-dr-independent.txt`、`46b-dr-independent-math.txt` | 通知、DR 字节/RPO/RTO 独立对账 |
| `agent-runtime/32-w5-artifact-inspect.txt`–`35-w5-live-drill-d32.txt` | 1967 历史快照与 1974 live 幂等重跑 |
| `agent-runtime/29-tla-pytest-tlc.txt`、`31c-tla-independent-mutations.txt` | TLC 真跑与两类应红变异 |
| `agent-runtime/43b-release-stale-policy-binding.txt`、`45-release-independent-rebuild-tamper.txt` | 旧 commit 制品、错误 policy hash、重建与篡改 |
| `agent-runtime/44-observation-sample-binding.txt` | W10 样本存在性和 SHA/dirty 绑定 |

## 全量回归与独立补证

| 文件 | 内容 |
|---|---|
| `root-regression/05-acceptance-explicit.log`、`.rc` | acceptance 66/66，rc0 |
| `root-regression/individual/summary.tsv` | 21 个 system test 脚本及 CLI 文件逐个 rc0 |
| `root-regression/04-pytest-all.log`、`.rc` | 统一 pytest：236 passed、16 fixture errors、rc1 |
| `root-independent/01-release-plan-binding.txt` | 真方案 SHA 与 61 字符 release 常量不等 |
| `root-independent/02-release-verify.log`、`.rc` | 错 policy hash 仍 VERIFY OK/rc0 |
| `root-independent/04-cua-ui-attempt.txt` | 三种真实浏览器通道均不可用；未冒充 UI 通过 |
| `root-independent/06-station56-placeholder-search.txt` | 站5/6 明示 placeholder / NOT_APPLICABLE |

## 完整性

- `agent-f6-p0/MANIFEST.sha256`、`agent-coverage/MANIFEST.sha256`、`agent-runtime/MANIFEST.sha256` 已分别 `shasum -a 256 -c`，均 rc0。
- 顶层 `MANIFEST.sha256` 覆盖本目录全部普通文件（排除自身）。

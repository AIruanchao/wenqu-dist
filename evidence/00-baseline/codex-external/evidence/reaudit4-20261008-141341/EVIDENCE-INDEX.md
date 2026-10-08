# 第四轮复审证据索引

- 证据根：`/private/tmp/codex-test/evidence/reaudit4-20261008-141341`
- 被验 HEAD：`e4aba84c1dabe1342ea234321eea3d300bea24a5`
- 最终判定：`49/100 BLOCKED`
- 报告：`/private/tmp/codex-test/验收报告-第四轮.md`
- 报告 SHA256：`5d86b3f0b86d17635377eeaff2827ffb5fa63805935ccfb042a5e28fb814e8a3`

| 路径 | 证据主题 | 入口 |
|---|---|---|
| `00-baseline/` | 身份、方案、第三轮报告、提交范围 | `environment.txt` |
| `01-probes/` | 第三轮 12 项失败探针异源复核 | `findings.md`、`01-results-rollup.txt` |
| `03-workpackages/` | 工作包与制品库存 | `inventory.txt` |
| `04-mutations/` | 模块/schema/工具移除和 Schema 变异 | `findings.md` |
| `05-trace/` | 131 集合、§20/§25.1 篡改、专属覆盖 | `findings.md` |
| `06-ci-branch/` | CI run、check、branch protection、PR 时间线 | `18-pr-merge-required-check-timeline.txt` |
| `07-runtime/` | 7789 PID/listener/hash/health/部署边界 | `03-runtime-hash.log`、`07-plan-vs-active-dashboard.log` |
| `08-acceptance/` | 62/62 全跑与 P1c 只读 | `findings.md` |
| `09-review/` | P0 新反例、回归、索引与时序审计 | `findings.md` |
| `10-final/` | 收尾完整性、报告副本与哈希 | `final-source-integrity.txt` |

关键硬阻断原始证据：

- Runner double-fork：`01-probes/logs/probe-11-runner-escape*.log`
- Action 无审批：`09-review/action-without-authorization-probe.txt`
- Schema-invalid v2 假 PASS：`09-review/aggregator-invalid-v2-probe.txt`
- Schema 残余：`09-review/schema-residual-probe.txt`
- §20 语义假绿：`05-trace/08-section20-semantic-check.log`、`09-section20-semantic-acceptance.log`
- required CI 覆盖缺口：`09-review/ci-critical-tests-removed-acceptance.txt`
- 安装体 CLI 断链：`09-review/installed-wenquctl-help.txt`
- evidence-index 0/14：`09-review/06-evidence-index-audit.log`

所有逐命令日志均包含命令、stdout/stderr 和退出码；分目录及证据根清单分别见各 `MANIFEST.sha256`。

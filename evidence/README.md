# evidence/ — P0-10 证据包基础设施

依据 Codex 重构方案 §24.2（方案正源 `/private/tmp/codex-test/方案.md`，SHA256
`96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306`）建立的证据包目录。
2026-10-08 由 P0-10 建档（初始状态：多数目录 EMPTY/PARTIAL，逐目录状态见各自 README）。

## 目录总览

| 目录 | 证据域 | 工作包 | 建档时状态 |
|---|---|---|---|
| 00-baseline | W0 基线快照 | W0 | EMPTY |
| 01-threat-model-and-contracts | 威胁模型/冻结契约 | W1 | PARTIAL |
| 02-schemas-and-tla | Schema 与形式化 | W1/W2 | PARTIAL |
| 03-red-probes-before | 红探针 BEFORE（假绿复现） | §20 全局 | EMPTY |
| 04-unit-property-mutation | 单元/属性/变异 | W2/W3/W6 | PARTIAL |
| 05-concurrency-crash-chaos | 并发/崩溃/混沌 | W2/W4/W7 | PARTIAL |
| 06-scanner-goldens | 扫描器金样夹具 | W6A~D | PARTIAL |
| 07-migration-reconcile | 481 条旧账对账 | W5 | NOT STARTED |
| 08-ci-and-branch-rules | CI 与分支规则 | W3 | PARTIAL |
| 09-release-manifest-attestation | 发布清单/签名 | W7A/W7B | PARTIAL |
| 10-ui-launchd-alert-backup | UI/launchd/告警/备份 | W4/W8 | PARTIAL |
| 11-shadow-canary | Shadow/Canary | W9 | EMPTY |
| 12-rollback-drill | 回滚演练 | W7B/W10 | EMPTY |
| 13-observation-window | 14 天观察窗 | W10 | NOT STARTED |

## 硬约束（§24.2 原文）

每项证据必须绑定：`run_id`、`commit`、`environment`、`scope`、`ruleset`、`时间`、`argv`、
`真实 rc`、`artifact SHA256`、`fresh_until`。缺任一字段的「证据」不得用于任何放行判定。

## 索引

- 总索引：`evidence/evidence-index.json`
- 131 个验收 ID（§20）追踪矩阵：`evidence/traceability-matrix.json`
  （由 `tools/ac_traceability.py` 生成，重跑命令：`python3 tools/ac_traceability.py`）

## 诚实边界

本目录建档本身**不构成任何验收完成**：Codex 验收报告（2026-10-07）总判定仍为
**BLOCKED（29/100）**；本结构只是让后续证据有唯一归位处，防止「测试通过=完成」的口径漂移。

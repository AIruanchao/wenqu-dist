# 07-migration-reconcile — W5 旧账迁移对账证据

## 证据类型

481 条遗留 finding 记录 → 新事件正源的逐项迁移 reconciliation：

- `legacy_record_id → canonical_finding_id → migration_decision_id → evidence` 全量索引（481 条，
  若 W0 快照后分母变化须以新快照为准并解释差异）；
- 坏 JSON/未知状态 → quarantine 清单；
- 缺审批要素的 43 条 ACCEPTED → invalid/reopen 决策记录；
- 两次迁移幂等性、源行数守恒校验输出。

对应 §14（W5 迁移）。

## 关联测试 ID

MIG-01～05、STATE-06、RISK-01。

## 当前状态（2026-10-08 建档时点）

**NOT STARTED（证据面）——迁移器代码存在但 W5 对账证据为 0**：

| 工件 | 状态 |
|---|---|
| `system/wenqu_core/ledger_migrator.py` | 存在（未纳入 5 模块 selftest 复核清单，无独立执行证据） |
| 481 条逐项 reconciliation 索引 | **无** |
| 43 条 ACCEPTED 缺要素处置记录 | **无** |
| Codex 验收 W5 评分 | 1/8 FAIL（2026-10-07） |

诚实边界：外部探针 `/private/tmp/codex-test/evidence/acceptance-20261007-231333/store-migrator-probes.json`
含 Codex 方向的迁移器对抗探针结果，未固化入本仓。

## 填写规则

1. reconciliation 索引必须机器生成且可重跑；行数守恒校验失败即迁移失败，不得带病收尾。
2. quarantine/invalid/reopen 每条决策须可追溯到源记录原文（脱敏后）。

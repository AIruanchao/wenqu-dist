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

## 当前状态（2026-10-08 W5 对账产出后更新）

**进行中（证据面已产出，待人工裁定项在案）**：

| 工件 | 状态 |
|---|---|
| `system/wenqu_core/ledger_migrator.py` | 存在（P0-6 第六轮统一正源契约；导入行经公共 EventStore.append 入 pipeline_events） |
| 逐项 reconciliation 索引 | **已产出**：`reconcile-report.json`（tools/w5_reconcile.py 机器生成，可重跑；逐行 {row_id, 状态, reason, event_id}） |
| 四态汇总 + 两次迁移幂等 + 源行数守恒 | **已产出**：`summary.md` + `migrated-events.db`（16 mapped / 1950 quarantined / 1 待人工 / 0 不一致 = 1967 非空行，守恒成立） |
| ACCEPTED 缺要素处置记录 | **已产出**：`reconcile-report.json` 的 `accepted_adjudication` 清单（1 条 ACCEPTED-CLOSED，MIG-02 quarantine 待人工 reopen） |
| Codex 验收 W5 评分 | 1/8 FAIL（2026-10-07，产出前口径） |

口径裁定（如实记录）：方案 §14.2.7 明示「481 仅是旧 dashboard 启发式折叠数，不能充当
原始迁移分母」；本目录正源为 持续修复引擎/engine-rounds.jsonl（1967 非空行），与
481/43 的 quality-system findings 口径不同源，差异已写入报告 `source.caliber`。

诚实边界：外部探针 `/private/tmp/codex-test/evidence/acceptance-20261007-231333/store-migrator-probes.json`
含 Codex 方向的迁移器对抗探针结果，未固化入本仓。

## 填写规则

1. reconciliation 索引必须机器生成且可重跑；行数守恒校验失败即迁移失败，不得带病收尾。
2. quarantine/invalid/reopen 每条决策须可追溯到源记录原文（脱敏后）。

## 重跑方式

```bash
python3 tools/w5_reconcile.py            # /tmp 演练（fail-closed，exit 0 才可正式）
python3 tools/w5_reconcile.py --formal   # 重产本目录三件套（append-only 幂等）
```

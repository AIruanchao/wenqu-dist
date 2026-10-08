# W5 旧账迁移对账报告（reconciliation summary）

- 生成：2026-10-08T09:29:58.137411+00:00（mode=formal，tool=tools/w5_reconcile.py，git_head=1620c7c030bd1ea5eb096e0509b7f864c4e90a6d）
- 源：`/Users/maccc/Documents/ERP）Zcode/持续修复引擎`（1967 非空行；全程只读，SHA256 前后逐字节一致）
- 事件正源：pipeline_events（写入 API=EventStore.append；db=`/Users/maccc/Documents/wenqu-dist/evidence/07-migration-reconcile/migrated-events.db`）

## 口径差异（如实记录）

- 预期口径：~481 条 / 43 ACCEPTED —— 24 OPEN + 4 FIXING + 172 FIXED + 67 VERIFIED + 158 CLOSED + 43 ACCEPTED + 13 OTHER = 481（quality-system findings ledger 口径）
- 实际口径：1967 行 / ACCEPTED 味 1 条
- 裁定：实际 1967 行 / ACCEPTED 味 1 条，与方案 ~481/43 口径不一致（不同源），如实记录。方案 §14.2.7 明示 481 仅是旧 dashboard 折叠数，不能充当迁移分母；本报告以逐行实扫为分母。

## 四态汇总

| 状态 | 行数 |
|---|---|
| mapped（已入统一事件库） | 16 |
| quarantined（确定性隔离） | 1950 |
| 待人工（ACCEPTED 裁定） | 1 |
| 不一致（对账失配，必须=0） | 0 |
| **合计（=源非空行数）** | **1967** |

- 守恒等式 `source_nonblank == mapped + quarantined + 待人工 + 不一致` → conserved=True
- quarantine 原因分布：`{"missing_field:ts": 40, "no_mappable_status": 1910}`

## 幂等与完整性验证

- 两次迁移：run1 imported=0/dup=16/quarantine=1；run2 imported=0/dup=16/quarantine=1
- 行集逐字节一致（run1 快照==run2 快照）：True
- 库逻辑快照 SHA（跨运行可比）：`f5bbaebe90b54888c2c12f2c23bb0ab3d1bb5d7ff97ff419e996fee41d2f5860`
- 哈希链 verify_chain：True（head=fe929c37e3416f31…，共 16 事件，其中 LEDGER_MIGRATED 16 条）
- 源文件字节不变：True
- 孤儿事件（库内有、staging 无）：0
- 全部检查通过：**True**

## ACCEPTED 裁定清单（单独）

1. `/Users/maccc/Documents/ERP）Zcode/持续修复引擎/engine-rounds.jsonl` 行 1873：verdict=`ACCEPTED-CLOSED`
   - 项目上下文：`{"task": "wenqu-v3.5.1-bugdeck"}`
   - row_id=`b622d1e3824cb37ce5f62505c2b73b833ea37f60f10e5aa8151a53d080e1d9ca`；处置：迁移器 quarantine（unknown_status:ACCEPTED*，MIG-02 不猜映射）；人工裁定补齐审批要素后另行再录（reopen 通道）
   - 原文预览：{"round": "r1630", "utc": "2026-10-06T19:14Z", "task": "wenqu-v3.5.1-bugdeck", "verdict": "ACCEPTED-CLOSED", "summary": "bug管线动态页第四页签（账本状态机实数据481/OPEN31+post-fi

## 规范化规则（确定性）

- ts 别名链：['ts', 'ts_utc', 'utc', 'timestamp', 'time']
- status 候选链：['status', 'verdict', 'state', 'result']
- 别名正源：wenqu_core.ledger_migrator.STATUS_ALIASES（冻结正源，本工具零自造别名）
- 不猜填：候选值不在冻结别名表（DONE/PARTIAL/MERGED/ALL-GREEN/master=… 长文本等）一律 quarantine 记因；FIXED→FIXED_PENDING_VERIFY 由迁移器执行（M3）。

## 诚实边界

- 本源为引擎轮次工作日志（action 叙事行占绝大多数），非状态账本——quarantine 主因 `no_mappable_status` 属源数据本性，非工具缺陷；
- 未写任何生产库；legacy 源目录零写入（SHA 前后一致已证）；
- project key 冲突（MIG-05）在本真实源上计 0 例（可映射行均无 project 字段；MIG-05 行为面由 system/tests/test_ac_state_mig.py 合成旧账 fixture 逐字覆盖）。

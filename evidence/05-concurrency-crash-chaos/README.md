# 05-concurrency-crash-chaos — 并发/崩溃/混沌证据

## 证据类型

- 并发写压测（如 100×100 并发）零丢失/零重复的原始日志；
- 事务各点 kill -9 / 断电模拟（WAL 恢复）的恢复记录；
- 双 writer epoch / lease 争抢的 fencing 证据；
- 混沌注入（scheduler 整体故障、外部 provider 500/超时）下的系统行为记录。

对应 §6.4（SQLite 事件正源）、§12、§16.3（原子部署）、§13（调度）。

## 关联测试 ID

STATE-03/04/05、AUTH-05、COND-06、DEP-01/02、SCH-04/05、ALT-01、ACT-03/04、REL-02、BAK-01、CAP-01。

## 当前状态（2026-10-08 建档时点）

**PARTIAL——遗留 CLI 账本有并发回归；wenqu_core EventStore/部署面的并发与崩溃证据为 0**：

| 已有资产 | 覆盖对象 | 证据 |
|---|---|---|
| `tests/acceptance.sh` I 节（8 进程撞锁写账本零损坏） | 遗留 cli findings.jsonl 账本 | acceptance.sh 53 PASS 内（2026-10-07） |
| `tests/acceptance.sh` L 节（并发 ingest 后账本可用、同 id 不双入账） | 遗留账本 | 同上 |
| wenqu_core EventStore（STATE-03/04/05） | 新核心 | **无任何并发/崩溃证据** |
| deploy_framework（REL-02 kill -9、DEP-01 lease） | 部署面 | **无证据** |

注：P0-6+7（commit be50cb8）给 EventStore 加了幂等（内容哈希 event_id）并过 CI，但无独立
kill -9/双 writer 证据落档。

## 填写规则

1. 崩溃注入必须记录注入时点（事务哪个点）、恢复后状态校验命令与输出。
2. 并发压测必须记录并发度矩阵、种子、是否出现孤儿写盘。
3. 混沌类证据必须区分「注入成功」与「系统正确反应」两个独立证明。

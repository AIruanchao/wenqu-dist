# ADR-001：SQLite WAL 事件正源替代 JSONL

## 状态
已接受（2026-10-07，Codex 方案 §6.4 冻结）

## 背景
当前 JSONL 账本存在：不可事务、不可并发、不可恢复、无状态约束、无幂等键、无事件链、无 CAS。

## 决策
采用 SQLite WAL 作为唯一事件正源，替代 JSONL。

## 理由
1. WAL 提供事务原子性（BEGIN IMMEDIATE + COMMIT）
2. 并发安全（WAL 模式 + busy_timeout）
3. 崩溃恢复（WAL 日志自动重放）
4. 事件链（prev_event_hash → event_hash）
5. 触发器禁 UPDATE/DELETE（append-only 强制）
6. 状态与 outbox 同事务提交
7. JSONL 仅作为 DB 的只读兼容投影

## 实现要点
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
-- 每表 unique idempotency key
-- events 表 trigger 禁止 UPDATE/DELETE
-- 状态事件与 notification_outbox 同事务
```

## 后果
- 正：事务/并发/恢复/审计链/幂等全达成
- 负：增加 SQLite 依赖（Python stdlib 自带，零额外安装）；JSONL 消费者需迁移至 DB 投影

## 迁移策略
- 观察期 expand/contract：新字段先 additive
- 旧 JSONL 只读快照、逐行哈希、旁路迁移（W5）
- JSONL 由 v2 exporter 从 DB 生成只读投影

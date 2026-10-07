# 问渠 one-shot 七段管线契约 v2.0

> 冻结版本：1.0 | 冻结日期：2026-10-07 | 血统：Codex 方案 §6.2 逐字收敛
> 此文件是机器可判定契约的唯一正源——任何实现必须与此文件一致，不一致=实现缺陷

## 1. 七段枚举（唯一）

```text
S1_REQUIREMENT → S2_SOLUTION → S3_EQS_PRE → S4_IMPLEMENT
→ S5_CONVERGENCE → S6_EQS_FULL → S7_GATE
```

顺序不可倒。前段非 PASSED 不得启动后段。

## 2. 统一结果双轴

```text
execution_status = COMPLETED | ERROR | BLOCKED | TIMEOUT | CANCELLED
policy_verdict   = PASS | FAIL | CONDITIONAL | NOT_APPLICABLE | NOT_EVALUATED
```

- `COMPLETED+NOT_APPLICABLE` 只能由受保护 policy 的 applicability rule 生成
- `CONDITIONAL ≠ PASS`：无独立有效 risk authorization 时 technical_eligible=false
- `UNKNOWN/MISSING/STALE/MALFORMED/EMPTY/TIMEOUT` 均是阻断态，不得折算为 PASS

## 3. Run 总状态

```text
CREATED | RUNNING | WAITING | FAILED | SUCCEEDED
| COMPLETED_CONDITIONAL | CANCELLED | SUPERSEDED
```

## 4. 段状态

```text
PENDING | RUNNING | PASSED | COMPLETED_CONDITIONAL
| FAILED | WAITING | CANCELLED
```

## 5. 允许转换（唯一）

Run：
```text
CREATED → RUNNING | CANCELLED
RUNNING → WAITING | FAILED | SUCCEEDED | COMPLETED_CONDITIONAL | CANCELLED | SUPERSEDED
WAITING → RUNNING | FAILED | CANCELLED | SUPERSEDED
```

段 attempt：
```text
PENDING → RUNNING | CANCELLED
RUNNING → PASSED | COMPLETED_CONDITIONAL | FAILED | WAITING | CANCELLED
```

## 6. 九类停等

| # | stop_type | 恢复必要且充分条件 |
|---:|---|---|
| 0 | ambiguity | 一次性授权 + 新需求四要素与 scope hash 冻结 |
| 1 | prod-write | 一次性 exact-scope 授权 + 对应前置 Gate + 回滚级别 |
| 2 | ddl | 一次性 exact DDL/环境授权 + fresh/legacy/minimal/回滚验证 |
| 3 | release | 一次性 exact release/SHA/env 授权 + Gate/manifest/回滚预案 |
| 4 | scope | 一次性新 scope 授权 + 风险、required 集和证据重新冻结 |
| 5 | fund-auth | 一次性资金/权限授权 + 正负测试 + 守恒/审计 |
| 6 | exm-fuse | 一次性裁定授权 + 实际解除熔断或完成独立治理裁定 |
| 7 | resource | 一次性恢复授权 + 资源探针恢复并满足安全余量 |
| 8 | ext-unavail | 一次性恢复授权 + 外部依赖健康探针恢复并重验证据新鲜度 |

## 7. 统一退出码

| 码 | 含义 |
|---:|---|
| 0 | 执行完成且策略 PASS |
| 1 | 执行完成但有 FINDINGS/FAIL |
| 2 | 工具、输入、网络、格式或证据 ERROR |
| 3 | 权限、审批或依赖 BLOCKED |
| 4 | CONDITIONAL，必须存在合法限时风险接受 |
| 124 | TIMEOUT |

## 8. 不可变安全不变量

1. 任一 required probe 非 PASS 时整线不得 PASS
2. PASS 必须绑定：run_id + commit_sha + environment + scope_hash + ruleset_hash + data_config_hash + artifact hashes + TTL
3. run 起跑后 commit、环境、规则集或范围变化，旧证据立即失效并新建 run
4. WAITING 只能由规定停等事件产生；无有效一次性授权不得 resume
5. 审批不能复用、扩范围、跨 SHA、跨环境或跨状态版本
6. 所有控制事件只追加；纠错使用 supersede/reopen 事件
7. evidence 不得是 symlink、外部路径、空文件或无哈希文件
8. findings 数量从解析后的 finding list 计算，不信任自报数字
9. 只有 trusted runner 实际捕获的退出码有效
10. dashboard 只能等于或比权威聚合器更保守，绝不能更绿

## 9. 架构正源

| 域 | 位置 |
|---|---|
| 可执行核心 | wenqu-dist（唯一实现，manifest 校验，不得热改） |
| ERP 域插件 | qisemi-erp 正源（scanners、探针、CI adapter） |
| 可变状态 | SQLite WAL（事件正源，append-only） |
| 证据 | content-addressed store（sha256 寻址） |
| 配置/秘密 | ~/.config/wenqu 或 Keychain（不入 argv/日志/Git） |

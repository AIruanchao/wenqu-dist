# 02-schemas-and-tla — Schema 与 TLA+ 形式化证据

## 证据类型

- JSON Schema（Draft-07）正本及其校验记录（正例/反例执行日志）；
- TLA+ / 形式化规格（状态机不变量、死锁/活性检查输出，TLC 模型检查日志）；
- schema 演进与迁移的兼容性证据。

对应 Codex 方案 §10（W1 契约冻结）、§11.3 验收矩阵。

## 关联测试 ID

- STATE-01（任意 stage/status → schema 拒绝）、STATE-11、ACT-06、COND-04（schema 层硬化的直接验收面）
- MIG-01（坏 JSON/未知状态 → quarantine）

## 当前状态（2026-10-08 建档时点）

**PARTIAL——5 个 Schema 在仓内存在并通过 CI 接线测试；TLA+ 只有 ERP 支付域历史件，问渠状态机
未建 TLA+ 模型**：

| 工件 | 路径 | 状态 |
|---|---|---|
| run-event-v2.schema.json | `system/schemas/` | 存在；P0-4 批加固（commit e00de14） |
| station-result-v2.schema.json | `system/schemas/` | 存在 |
| evidence-v2.schema.json | `system/schemas/` | 存在 |
| finding-event-v2.schema.json | `system/schemas/` | 存在；P0/P1 拒 ACCEPTED 硬化 |
| approval-v2.schema.json | `system/schemas/` | 存在；顶层 if/then 判别式硬化 |
| PaymentConservation.tla | `system/specs/` | ERP 支付守恒域历史件，**非**问渠七段状态机 |
| ts-to-tla.py | `system/bin/` | 转换工具存在，未产出问渠模型 |

注意（诚实边界）：`system/tests/test_core_wiring.py` 只验证 schema 存在且可解析 + 2 个业务不变量
负例（CRITICAL 拒 ACCEPTED_RISK），**不等于** §20 全部 schema 面验收通过。

## 2026-10-08 更新：W1 缺口（无 Wenqu TLA/TLC）已闭环

问渠七段状态机 + 审批消费 TLA+ 规约建立并通过 TLC 真实模型检查
（TLC 2.15 / Temurin 17 / 仓内 `system/bin/tla2tools.jar`）：

| 工件 | 路径 | 状态 |
|---|---|---|
| wenqu_pipeline.tla | `specs/tla/` | 规约正本：常量表 + Next + 7 不变量（TypeOK/NoSkipStages/PriorPassedGate/AttemptImmutable/NonceOnceConsumed/TerminalFinal/DoubleAxisNoWash），逐定义注明代码行号映射 |
| wenqu_pipeline.cfg | `specs/tla/` | 小模型 2 段 × 2 attempt 界；TLC `Model checking completed. No error has been found.`（2442 states / 834 distinct / depth 12） |
| TLC 原始输出 + 覆盖统计 | `tlc-wenqu-pipeline-2026-10-08.log` | 10 个动作全部真实发生（非空转） |
| 变异探针（6 个全红） | `tlc-wenqu-pipeline-mutation-probes-2026-10-08.log` | nonce/双轴门/段序/终态分支/映射锁/attempt 不可变逐一破坏 → 对应不变量当场 violated（检查可证伪） |
| 运行记录 | `tla-wenqu-pipeline-run-2026-10-08.md` | 环境探测、命令、exit code、映射表、诚实边界 |
| 规约漂移对照测试 | `system/tests/test_tla_spec.py` | 10 用例：TLA 常量表与 Python 正源逐项比对（25 对双轴全积映射）；单 token 漂移注入实证必红 |

边界：TLC 穷举为有界实例（非 7 段满配）；审批结构/签名/TTL/绑定抽象为
预审原子，保留 nonce/CAS/路由三轴；不主张活性。详见运行记录第 5 节。

## 填写规则

1. 每次Schema 变更须附 before/after 正反例执行记录（jsonschema 校验日志，真实 rc）。
2. TLA+ 模型检查须保存 TLC 原始输出与配置（何常量、何不变量、状态空间规模）。

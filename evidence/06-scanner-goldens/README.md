# 06-scanner-goldens — 扫描器金样与夹具证据

## 证据类型

Bug 八站扫描器（W6A～W6D）的金样（golden）测试证据：

- DB 漂移识别金样：`[+]`/`[-]`/`[*]` 各形态、catalog 顺序/默认表达式/extension 的规范化输出对照；
- 供应链/advisory 夹具：离线快照（含签名/分页）、registry 超时、多页多 range 遍历记录；
- 租户扫描分母探针：Prisma DMMF/AST/runtime 三源对账（193 模型全量，非 27 硬编码）；
- 性能基线：raw 样本、p95/p99 计算、baseline 晋升与 policy hash 绑定记录。

对应 §15.2～§15.6。

## 关联测试 ID

DB-01～06、SC-01～05、ADV-01～02、TEN-01～08、PERF-01～06、STA-01～02。

## 当前状态（2026-10-08 建档时点）

**PARTIAL——W6B/C/D 站点实现与内嵌 selftest 在仓（rc=0×5，2026-10-07 Codex 复核），但金样/
夹具文件为 0，分母漏洞（FND-013，漏 172 模型）与 DB 漂移误判（FND-010）尚未根治**：

| 工件 | 状态 |
|---|---|
| `system/wenqu_core/station2_static.py`（+selftest） | 存在，rc=0 |
| `system/wenqu_core/station3_contract.py`（+selftest） | 存在，rc=0 |
| `system/wenqu_core/station4_behavior.py`（+selftest） | 存在，rc=0 |
| `system/wenqu_core/station7_runtime.py`（+selftest） | 存在，rc=0 |
| `system/wenqu_core/bugscan_orchestrator.py`（+selftest） | 存在，rc=0 |
| DB 漂移金样（DB-01～06） | **无** |
| 供应链离线快照夹具（SC-05） | **无** |
| 租户 DMMF 分母对账（TEN-01～08） | **无**（旧 export-tenant-audit.mjs 仍在 argus-assemble 侧） |
| 性能基线 raw 样本（PERF-01～06） | **无** |

## 填写规则

1. 每个金样必须同时存输入夹具与期望输出（ golden 文件），变更需双 PR 对照。
2. 站点 selftest 升级为 §20 ID 标注后，执行输出直接引用到本目录。
3. 分母类证据必须给出「全量对象清单来源」（DMMF/AST/runtime 哪个源、何时快照）。

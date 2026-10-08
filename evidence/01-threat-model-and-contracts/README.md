# 01-threat-model-and-contracts — W1 威胁模型与冻结契约证据

## 证据类型

W1（契约、Schema、威胁模型、红探针定义）的产物：

- 威胁模型（STRIDE/攻击面/TCB）及其与测试 ID 的映射表；
- 冻结的契约文档（七段状态机、Bug 八站统一结果、审批/授权语义）；
- 契约与实现的一致性核验记录（DOC-01～04 的生成式 consistency report 底稿）。

## 关联测试 ID

- DOC-01～04（文档/契约漂移 → CI 阻断）
- 威胁模型条目 T-01～T-13 已在册（`system/docs/security/threat-model.md`），映射到 MRG-03/05、
  STATE-04/05、GATE-04～06、AUTH-02 等。

## 当前状态（2026-10-08 建档时点）

**PARTIAL——契约工件在仓内存在，但均未按 §24.2 绑定 run_id/SHA/fresh_until 落档为证据**：

| 工件 | 路径 | 状态 |
|---|---|---|
| 威胁模型 v1 | `system/docs/security/threat-model.md` | 存在，含 T-01～T-13 与测试 ID 映射 |
| vNext 契约 | `system/docs/specs/wenqu-vNext-contract.md` | 存在，未冻结版本号 |
| ADR-001/002/003 | `system/docs/adr/` | 存在（事件正源/审批安全/可信 runner） |
| 宪法/工单模板 | `system/templates/` | 存在 |

缺口：threat model 尚未覆盖 §20 全部注入面（如 COND/DEP/STOP 族）；契约未做机器校验版本冻结。

## 填写规则

1. 契约文档冻结时须附 SHA256 并登记入 `evidence-index.json`。
2. consistency report 必须是生成器输出（可重跑复现），不接受手工编辑结论。

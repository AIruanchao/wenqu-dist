# 04-unit-property-mutation — 单元/属性/变异测试证据

## 证据类型

- 单元测试执行记录（pytest/junit 原始输出）；
- 属性测试（property-based，如 hypothesis）对状态机转换、CAS、幂等的性质检查记录；
- 变异测试（mutation）得分报告——证明测试真的能杀变异体，不是恒真断言；
- AFTER 侧红探针（修复后正确阻断）也按测试族归档到本目录对应子项。

对应 §12.3（收敛验证器 v3）、§15（W6 各站）。

## 关联测试 ID

GATE-04/09/10/11、STATE-01/02、AUTH-01～06、COND-01～06、MIG-02～05、SC-04、TEN-01～03、
DOC-01～04 等以断言为核心的族。

## 当前状态（2026-10-08 建档时点）

**PARTIAL——接线级与遗留回归在绿，但 §20 ID 专属测试为 0，属性/变异测试为 0**：

| 已有资产 | 规模 | 最近绿证据 |
|---|---|---|
| `system/tests/test_core_wiring.py`（P0-1 接线） | 8 用例 | CI run 37660552501 @ 1858a75，2026-10-07 |
| `tests/acceptance.sh`（发行版回归） | 53 检查全过 | Codex 复核 2026-10-07 23:13–23:21（外部证据） |
| `cli/test_wenqu.py`（CLI 契约） | 20 pytest 用例 | 同上 CI acceptance 工作流 |
| `wenqu_core` 5 模块内嵌 selftest | rc=0 ×5 | Codex 复核 2026-10-07（外部证据） |

诚实边界：以上均**不含** §20 的 131 个 ID 专属用例（详见 `evidence/traceability-matrix.json`，
初始覆盖率见运行 `tools/ac_traceability.py` 输出）；无 property-based、无 mutation 报告。

## 填写规则

1. 归档 junit/pytest `-v` 原始输出 + rc + 用例清单哈希；跳过条件（skip）必须显式列出。
2. property/mutation 工具的种子（seed）必须记录以便复现。

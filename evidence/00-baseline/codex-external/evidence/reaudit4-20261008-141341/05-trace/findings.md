# 第四轮复审：追踪矩阵、篡改闸与专属覆盖

## 基线对账

- 冻结方案 SHA256：`96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306`。
- 独立脚本不导入、不调用被验工具函数，而是直接解析方案 Markdown、工具 AST 字面量与 live matrix：
  - §20：131 行 / 131 唯一；
  - §25.1：展开 131 / 131 唯一；
  - 工具冻结目录：131；live matrix：131；
  - 三集合差异 0，重复 0；
  - §20 每行 `注入/期望` 与冻结目录差异 0；
  - §25.1 的 REQ、AC、工作包、证据类与冻结映射差异 0；
  - live matrix 逐 ID 七字段映射差异 0。
- 专属覆盖呈现属实：扫描 23 个 `.py/.sh` 资产，对 131 ID 的连字符、下划线、`test_` 三种精确形态，原始命中 0、测试上下文命中 0；live 显示 dedicated=0、proxy=3（`GATE-02/COND-04/STATE-03`）、missing=128，与独立结果一致。
- 仓内受控 `evidence/traceability-matrix.json` 的 `repo_head=e00de14...`，仍旧于当前 `e4aba84...`；本轮 live 临时矩阵已绑定当前 HEAD，但受控快照本身未刷新。

## 篡改对抗

| 变异 | `ac_traceability.py --check` | 完整 acceptance | 判定 |
|---|---:|---:|---|
| §20 `GATE-01→GATE-99`（集合变异） | rc=2 | rc=1，61/1 | PASS：ID 集合漂移已 fail-closed |
| §25.1 GATE 的 REQ 元数据改写 | rc=2 | rc=1，61/1 | PASS：范围展开/四列映射漂移已 fail-closed |
| §20 保留 `GATE-01`，只改“注入”语义文本 | **rc=0** | **rc=0，62/0 ALL GREEN** | **FAIL：§20 语义内容篡改仍假绿** |

## 新发现 F4-TRC-001（高风险）

`cross_check_plan()` 只提取 §20 ID 集合，并未把 §20 每行的 `注入/期望` 与工具内 `ID_DEFS` 做运行时对账。因此只要攻击者保留 ID，就能任意漂移验收语义而 `--check` 与 P1c 全绿。基线当前内容虽与冻结目录一致，但防篡改 Gate 不完整；“§20 内容篡改必非零”只能在 ID 集合口径下成立，按真实语义内容口径不成立。

## 证据

- 基线 live：`11-live-tool-check.log`、`traceability-live-source.json`。
- 独立对账：`independent-trace-audit.py`、`12-independent-trace-audit-source-live.log`、`independent-trace-results.json`。
- §20 ID 变异：`01-section20-id-mutation.log`、`02-section20-id-check.log`、`03-section20-id-acceptance.log`。
- §25.1 元数据变异：`04-section251-meta-mutation.log`、`05-section251-meta-check.log`、`06-section251-meta-acceptance.log`。
- §20 语义假绿：`07-section20-semantic-mutation.log`、`08-section20-semantic-check.log`、`09-section20-semantic-acceptance.log`。

# 03-red-probes-before — 红探针 BEFORE（旧实现假绿/漏拦复现）证据

## 证据类型

Codex 方案 §20 的硬前提：**所有用例必须保存 before/after**。本目录存放 BEFORE 侧——
在旧实现上证明注入确实能产生假绿/漏拦（攻击先成功），作为修复后正确阻断（AFTER，落
`04`～`07` 对应目录）的对照组。

重放边界（§20 强制）：旧版 before 复现只能在副本、mock API、测试仓、fixture 或隔离环境进行；
自动合流、生产写、DDL、真实外部告警和回滚类缺陷禁止在真实系统重放——此类只能用已有生产日志/
审计证据作 before。

## 关联测试 ID

§20 全部 131 个 ID 的 before 侧；特别是 FND-001～017 对应的 MRG/GATE/STATE/SC/DB/TEN/PERF 族。

## 当前状态（2026-10-08 建档时点）

**EMPTY / NOT STARTED**：

- `system/tests/red_probes/` 目录已建但为空（0 文件）；
- Codex 验收报告（2026-10-07）明确判定「active CI 中的独立红探针与完整验收矩阵」缺失（BLOCKED 项 7）；
- 外部相邻：`/private/tmp/codex-test/evidence/acceptance-20261007-231333/` 含
  `adversarial-probes.json`、`runner-cas-probes.json`、`store-migrator-probes.json`（Codex 方向的
  独立对抗探针，rc/输出在档），同样未固化入本仓。

## 填写规则

1. 每个探针一个工件组：注入脚本 + 原始输出 + 真实 rc + SHA256 + 环境说明（副本/隔离）。
2. 必须能证明「旧实现确实拦不住」——只有注入没有漏拦证据的不算 before。
3. 生产日志类 before 须注明来源时间与脱敏处理，禁止回显凭据原文。

# 08-ci-and-branch-rules — CI 与分支规则证据

## 证据类型

- CI 工作流定义（acceptance / ci-fast / nightly）及其在真实远端的运行记录（check run ID、SHA、
  结论、时长）；
- 分支保护/required checks/ruleset 配置回读（API 原始 JSON）；
- Gate 触发条件、required check 集合与 DAG 校验（CI-05～09）证据；
- auto-merge 改造后（exact-SHA、无子串匹配、无 --admin）的合流审计记录。

对应 §12（Gate/CI/合流）。

## 关联测试 ID

CI-05～09、GATE-01～03、MRG-01～07、DOC-01～04（CI 阻断类）。

## 当前状态（2026-10-08 建档时点）

**PARTIAL——CI 在真实远端在跑且最近两推全绿；但 required-check 硬门与 ruleset 证据缺失，
FND-001/003（auto-merge 子串/假绿）未根治**：

| 项 | 状态 |
|---|---|
| `.github/workflows/acceptance.yml`（push/PR 触发，4 步） | 在役；SHA256 df6d6ef1…（2026-10-08 计算） |
| `system/ci/ci-fast.yml`、`nightly.yml` | 仓内存在，未证实已在远端启用 |
| CI 通过记录 | run 37660552501 @ 1858a75 success（2026-10-07T17:37:51Z，27s）；run 37660144865 @ be50cb8 success（2026-10-07T17:34:41Z）——`gh run list` 实查 |
| required checks / branch ruleset 回读 | **无**（外部 `/private/tmp/codex-test/evidence/reaudit-20261007/branch-required-checks.json` 有 2026-10-07 15:15 时点回读，未固化） |
| 当前 HEAD e00de14 的 CI 结论 | 建档时**未查得**（外部 writer 刚推，观察窗未过） |

## 填写规则

1. CI 记录须含 run id、head SHA、结论、原始 API 输出（`gh run view --json`），不接受截图转述。
2. ruleset 回读须注明 API 版本与时间；ruleset 变更前后各留一份对照。
3. 合流审计记录须含 exact-SHA 匹配证据与拒绝案例。

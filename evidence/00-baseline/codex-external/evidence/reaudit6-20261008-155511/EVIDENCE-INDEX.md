# 第六轮复审证据入口

- 目标快照：`b259dac4248b14af6ec05e1b3fc7f61401aba6b6`
- 起点：2026-10-08 15:55:11 +08，clean main
- 结论：`52/100 BLOCKED`
- 正式报告：`/private/tmp/codex-test/验收报告-第六轮.md`

## 身份与漂移

- `root/00-baseline.txt`：b259 clean 起点、冻结方案 hash。
- `root/05-source-drift.txt`：15:58 外部 writer 切换/提交证据。
- `root/06-ci-branch/post-drift-state.txt`：PR#6 后 main 状态。
- `root/12-final-source-state.txt`：最终 `main/origin=07a94945...`，b259 仍可寻址。

## 12 项旧探针与 F4 六项

- `agents/runner-auth/logs/probe-{01..07,09,10}.log`：旧探针独立变体。
- `root/11-independent-probes/auth_chain_probe.{py,log}`：F4-AUTH 独立全链与事务故障注入。
- `root/11-independent-probes/auth_exact_target_bypass_probe.{py,log}`：签名 release payload 可用于任意 action target，探针 rc=1。
- `root/11-independent-probes/runner_reparent_probe.{py,log}`：旧探针 11 新后台重挂接变体，3/3。
- `agents/gate-schema-cli/03-independent-gate-schema-probe.log`：旧探针 08、F4-GATE/F4-SCHEMA 与新反例。
- `agents/gate-schema-cli/04-independent-rollback-probe.log`：旧探针 12。
- `agents/gate-schema-cli/05-*`、`06-*`：安装体 CLI 与缺件变异。
- `agents/gate-schema-cli/07-*`～`10-*`：acceptance、关键文件删除、三移除锚点。

## 追踪与 99/131

- `agents/trace-ci-runtime/16-trace-mutation-run.txt`、`mutations/summary.tsv`：§20/§25.1 变异与 fail-open。
- `agents/trace-ci-runtime/18-seven-dedicated-runtime.log`：七文件 99/99 实跑。
- `agents/trace-ci-runtime/25-id-sample-audit.md`：21 条跨七文件逐 ID 审计。
- `agents/trace-ci-runtime/19-hollow-*`：DOC-03 恒真后仍绿。
- `agents/trace-ci-runtime/20-delete7-*`：删七文件后 trace/acceptance 双绿。
- `agents/trace-ci-runtime/26-not-implementable-audit.json`：32 missing 的模块登记对账。

## CI / branch / runtime / observation

- `root/06-ci-branch/`、`agents/trace-ci-runtime/github/`：run 37745638008、两 jobs、日志、保护门、PR#4/#5。
- `root/06-ci-branch/ci-log-key-evidence.txt`：Ubuntu `mktemp` 错误、63 PASS、独立 pytest 20 passed。
- `root/08-runtime/runtime-snapshot.txt`、`agents/trace-ci-runtime/runtime/17-runtime-vs-remote-branch.json`：7789 active SHA 与 PR#6 对账。
- `root/09-observation/observation-snapshot.txt`、`agents/trace-ci-runtime/runtime/13-observation-semantic-verdict.json`：首样本错 SHA/dirty、shadow 503/null。
- `root/13-auto-merge-correct-path.txt`、`13-auto-merge-process-refined.txt`：正确 daemon 路径与 active writer 精确复核。

## Evidence index / candidate / regression

- `root/10-index-audit/index-audit.json`：20 条严格 0/20。
- `agents/trace-ci-runtime/evidence-index/strict-audit.json`：逐路径/字段/hash 复核。
- `agents/trace-ci-runtime/24-candidate-artifact-audit.txt`：tar/hash/451 项、签名/SBOM 边界。
- `root/regression/`：14 套测试、五模块自测、acceptance、station4 重复。

## 完整性

- `agents/runner-auth/MANIFEST.sha256`
- `agents/gate-schema-cli/MANIFEST.sha256`
- `agents/trace-ci-runtime/MANIFEST.sha256`
- `MANIFEST.sha256`：本证据根总清单，排除自身。

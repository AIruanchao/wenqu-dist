# 00-baseline — W0 基线快照证据

## 证据类型

W0（快照与危险面隔离）产出的时点基线：仓库 HEAD/SHA、现役运行体身份对账（runtime vs source hash）、
磁盘容量水位、auto-merge/launchd/crontab 现役状态、dashboard 健康分时点投影、branch ruleset 现状。
对应 Codex 方案 §9（W0）与 FND-008（runtime/source 热补漂移）、FND-021（磁盘 90%）。

每项证据必须绑定（§24.2 硬约束）：`run_id`、`commit`、`environment`、`scope`、`ruleset`、`时间`、
`argv`（采集命令原文）、`真实 rc`、`artifact SHA256`、`fresh_until`（时效边界，过期即不得用于放行）。

## 关联测试 ID

- CAP-01（峰值空间/磁盘满 → 切换 BLOCKED）——容量基线是它的 before 输入。

## 当前状态（2026-10-08 建档时点）

**EMPTY（仓内零工件）**——W0 尚未在本仓内执行落档。

外部相邻证据（临时目录，随时可能消失，须尽快快照入本目录）：

- `/private/tmp/codex-test/evidence/reaudit-20261007/`（Codex 复审基线，captured_at=2026-10-07 15:15 CST）：
  `branch-required-checks.json`、`dashboard-health.json`、`dashboard-runtime-diff.patch`、
  `runtime-source-hashes.txt`、`skill-hashes.txt`、`launchctl-selected.txt`、`waiting-states.json`、`manifest.sha256`。
- 该目录已验证存在且含 manifest，但其内容**尚未复制入本目录**，不计为已固化证据。

## 填写规则

1. 只接受只读采集命令的原始输出 + manifest 哈希清单，不接受转述。
2. 每次 W0 重跑生成独立 `run_id` 子目录或文件前缀，禁止覆盖旧基线。
3. `fresh_until` 默认 ≤7 天；过期基线只能作历史对照，不得作放行依据。

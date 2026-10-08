# 第三轮复审子任务 C 发现

> 范围：P0-3 / P0-6 / P0-7 / P0-10、W0-W10 证据评分建议、CI、追踪矩阵、证据索引对账、工具移除锚点。  
> 验收基线：`ff050bbb9c95c04ecb975900f5440f9bfcd1a447`。  
> 方案 SHA256：`96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306`，仓内快照一致。  
> 产物仓在本子任务开始与结束均 clean；所有破坏性探针均在 `/private/tmp` 隔离 clone/临时目录执行。

## 一、总判定（本子任务范围）

**BLOCKED。** 四个负责复核的 P0 均未达到关闭条件：

| P0 | 状态 | 结论 |
|---|---|---|
| P0-3 | **FAIL / 未关闭** | 零分母真空 PASS 已修，但正式 `station-result-v2` → `GateAggregator` → `Dashboard` 仍断链，且聚合器无生产调用方/快照生产者。 |
| P0-6 | **PARTIAL，但仍 FAIL** | “相同事件二次插入”和两种建表顺序冲突的窄问题已修；但 duplicate 返回不存在于 DB 的 event hash、`head()` 返回首条而非链头、迁移器与核心仍是两个事件表/两个正源。 |
| P0-7 | **PARTIAL，但仍 FAIL** | `.sh` 执行位与首次失败 current 删除的窄问题已修；但升级失败不会回滚相对 previous 链接，失败 release 留在 current；mode 不入 manifest/不可校验，安装器仍 `cp -R` 且 `doctor ... || true`，框架未接线。 |
| P0-10 | **PARTIAL，但仍 FAIL** | 14 目录、生成器和 131-ID 矩阵已入仓，且 0% 专属覆盖如实呈现；但 01～13 目录只有 README、专属用例仍 0/131、索引无可逐工件核验的完整条目，追踪 gate 可假绿。 |

## 二、P0-3：station / Schema / Aggregator / Dashboard 契约

### 已确认修复

- `required_stations=set()` 现在得到 `aggregate_outcome=BLOCKED`、`technical_eligible=false`，不再真空 PASS。
- `system/tests/test_core_wiring.py` 对这一窄断言有接线。

### 仍然阻断

1. `station-result-v2.schema.json` 的正式字段是 `station_id/execution_status/policy_verdict/identity...`；`GateAggregator.add()` 仍消费旧私有结构 `station/outcome/sha/environment`。
2. 独立探针构造并经 Draft-07 验证通过的合法 v2 station result；传给聚合器后被记为 `missing_field:station`，整线 BLOCKED。
3. 聚合器对旧结构可以 PASS，但其输出只有 `aggregate_outcome/target_sha/environment...`，缺 Dashboard 强制要求的 `generated_at|ts` 与 `policy_verdict|overall|verdict`，`read_gate_aggregate()` 返回 `AGGREGATOR_MALFORMED`。
4. AST/调用图仅发现 `system/tests/test_core_wiring.py` 导入 `GateAggregator`；没有生产 orchestrator 调用，也没有仓内 `gate-aggregate.json` 生产者。

证据：`13-p0-3-source-review.log`、`14c-p0-3-import-callgraph.log`、`15-p0-3-contract-probe.log`。

## 三、P0-6：EventStore

### 已确认修复

- 同一 payload 连续 append：第一次 `inserted=true`，第二次 `inserted=false`，链长度为 1。
- EventStore → LedgerMigrator、LedgerMigrator → EventStore 两种顺序均不再抛列冲突；DB 同时出现 `events` 与 `pipeline_events`。

### 新实锤残余

1. **duplicate 返回伪 hash：** 即使 `inserted=false`，`append()` 返回的是按当前链头新算出的 hash，而不是已存在行的 hash；该返回值不在 DB 中，连续立即重试也不同于首插 hash。
2. **链头计算错误：** 两条事件后，`head()` 返回第一条 hash；实际最后一条 hash 不同。`verify_chain()` 仍报 `ok=true`，并把错误 head 返回给调用方。根因是 `SELECT event_hash, COUNT(*) ... ORDER BY seq DESC` 混用聚合列和非聚合列。
3. **仍有两个正源：** 只是把冲突表改名为 `pipeline_events`；迁移器继续写 `events`。这避免 DDL 撞表，但不满足方案 §6.4 的单一事件正源及 W5 向统一正源迁移要求。

证据：`16-p0-6-store-probe.log`、`system/wenqu_core/store.py` 源码记录于相关日志。

## 四、P0-7：制品 / 原子部署

### 已确认修复

- 源 `.sh` 0755 构建后为 0555，可执行。
- 首次部署 self-check 失败时，`current` symlink 被删除。

### 新实锤残余

1. **升级失败回滚失效：** 成功首版后，`current` 是相对链接 `releases/<id>`；失败升级读取 `_prev_target=os.readlink()` 后用进程 cwd 做 `os.path.isdir(_prev_target)`，判断为不存在，跳过 rollback，错误信息为 `no previous release to roll back to`，`current` 留在失败新版。
2. **mode 规则错误且不可验证：** 0755 的无扩展名可执行文件被改成 0444；0644 但带 shebang 的 `.py` 被改成 0555。manifest 文件项只有 `path/sha256/size`，把 0555 篡成 0444 后 `verify()` 仍 `ok=true`。
3. **manifest 缺字段：** 缺 `version/source_commit/quality_policy_commit/build_id/builder/schema_version/policy_hash/artifact_sha256/runtime/SBOM/schema compatibility/signature` 等方案 §16.2 字段。
4. **真实安装路径未接框架：** `system/install.sh` 仍有 `cp -R`，仍以 `doctor 2>&1 || true` 吞真实 rc 后 grep 文本判定，也未导入/调用 `DeployManager`。

证据：`17-p0-7-source-review.log`、`18-p0-7-deploy-probe.log`。

## 五、P0-10：证据包 / 追踪矩阵 / 工具锚点

### 131 ID 与 §25.1

- live 运行：131 个冻结 ID；方案 §20 侧 131；工具矩阵 131；exit 0。
- 独立解析（不复用工具硬编码）展开 §25.1 范围后也是 131；三集合完全相等，四列 `REQ/AC、工作包、证据类` 逐 ID 与当前工具输出一致，0 mismatch。
- 专属覆盖诚实输出：**0/131（0.0%）**；代理部分覆盖 3（GATE-02、STATE-03、COND-04）；缺失 128。该 0% 表述属实，不能解释为验收覆盖完成。
- 仓内已提交的 `evidence/traceability-matrix.json` 仍绑定 `repo_head=e00de14`；本轮 live 外置生成结果绑定 ff050bb，统计相同。

### 工具移除锚点

- 隔离 clone 全量 `tests/acceptance.sh`：62 PASS / 0 FAIL，rc=0。
- 删除 `tools/ac_traceability.py` 后：61 PASS / 1 FAIL，P1c 明确红，rc=1。**存在性移除锚点有效。**

### 追踪 gate 假绿

- 在隔离 clone 篡改 §20：`GATE-01 → GATX-01`。生成器默认模式打印集合 FAIL，但 exit **0**；只有手工加 `--check` 才 exit 2。
- `tests/acceptance.sh` P1c 调用默认模式，不加 `--check`；同一 §20 篡改下全量 acceptance 仍 **62 PASS / 0 FAIL / ALL GREEN / rc=0**。
- 在隔离 clone 只篡改 §25.1 映射 `REQ-EVID-001 → REQ-EVID-TAMPER`；即使执行生成器 `--check` 仍 exit **0**。原因是 `cross_check_plan()` 只解析 §20 的显式 ID，并未解析 §25.1 范围或元数据，却把输出标签写成“§25.1 集合等式”。

### evidence 索引与实际文件

- `evidence/evidence-index.json` 只有 9 条，建档 HEAD=e00de14，无 ff050bb/CI run 37727549548 条目。
- 9 条中 7 条有空的 §24.2 硬字段；4 条 `evidence_path` 只是目录；严格要求“路径为文件且 artifact_sha256 为 64 hex”时为 **0 条**。
- `01`～`13` 每个目录都只有 README，直接 substantive artifact=0；`00-baseline` 的递归工件主要是第二轮/方案复审旧快照，不是 ff050bb 的 W0/W1…W10 新证据。
- index 的 known_gaps 仍称外部证据未快照、HEAD=e00de14 无 CI，已与 ff050bb 仓实态漂移。
- 方案与二轮报告快照的 SHA256 核验通过。

证据：`06-evidence-content.log`、`09-traceability-live.log`、`10-independent-trace-check.log`、`11-acceptance-isolated.log`、`12-tool-removal-anchor.log`、`19b-evidence-index-reconcile.log`、`22-*`～`25-*`。

## 六、CI 真实性

- `gh run view 37727549548 --repo AIruanchao/wenqu-dist` rc=0：
  - `headSha=ff050bbb9c95c04ecb975900f5440f9bfcd1a447`
  - branch=`main`、event=`push`、status=`completed`、conclusion=`success`
  - macOS 与 Ubuntu 两个 matrix job 均 success；P1/P1b/P1c 在日志中实际执行；各 CI acceptance 为 61 PASS / 0 FAIL（pytest 在 acceptance 内跳过，后续独立步骤安装 pytest 并跑 20 个旧 CLI 用例）。
- 因此“该 run 对该 SHA success”属实。
- 但它**不是准入硬门**：GitHub API 返回 main `Branch not protected`（HTTP 404），repository rulesets=`[]`。CI success 不能等价为 Required Gate 或防绕过合流。
- CI P1c 只验证工具存在/可运行，且受上述默认不 `--check` 假绿影响；不能证明 131 专属 AC 已实现。

证据：`20-ci-run-json.log`、`21-ci-run-log.log`、`26-branch-protection.log`、`27-repo-rulesets.log`。

## 七、W0-W10 建议评分（供总报告合并）

> 这是按第二轮同权重、仅凭当前可复核证据的保守建议；W2 的最终分数应与状态机专审结果合并。

| 工作包 | 权重 | 二轮 | 三轮建议 | 依据 / 不升分缺口 |
|---|---:|---:|---:|---|
| W0 快照与危险面隔离 | 8 | 2 | **2** | 仓当前 clean、方案/旧报告快照验真；但无 ff050bb 全量 baseline bundle、writer inventory、maintenance authorization、runtime/source 当前对账；00-baseline 无直接新工件。 |
| W1 契约、Schema、威胁模型、红探针 | 10 | 4 | **6** | Schema 业务约束与 131 映射有实质新增；但问渠 TLA 缺、BEFORE 红探针目录空、0/131 专属测试，CI schema 行为测试可因无 jsonschema 直接 return。 |
| W2 Trusted Runner、事件账本、授权、CAS | 15 | 3 | **8** | 新 1792 行状态/审批/重放核心与 10 项行为自测、Runner/CAS 修复可加分；但 EventStore 有伪 hash/错 head/双正源，统一全表/outbox/runner 完整隔离与 100×100/kill-9 证据缺失。 |
| W3 Gate、CI、合流控制 | 15 | 2 | **3** | ff050bb 双平台 CI success、核心/工具存在性锚点接入；但 main 无保护/ruleset，Aggregator 正式契约断链且无调用方，追踪 gate 可假绿，0 专属 AC。 |
| W4 调度、Outbox、通知、备份 | 10 | 3 | **3** | 本轮无对应实现/证据增量；10 类目录只有 README，无 outbox receipt、真 launchd、新鲜度、备份恢复。 |
| W5 旧账迁移 | 8 | 1 | **1** | 07 目录只有 README，481 条 reconciliation 与 43 条 ACCEPTED 裁定均无；改名避冲突反而保留两个事件表。 |
| W6 Bug 八站 | 15 | 8 | **8** | 既有站点模块/selftest 保留；本轮无 scanner golden、分母/DB/租户/供应链专属验收增量，统一聚合仍断链。 |
| W7 制品、安装、部署、回滚 | 8 | 2 | **3** | `.sh` mode 与首败链接删除为真实窄修；但升级回滚新实锤失败、manifest/mode/签名/lease/授权/installer 接线仍缺。 |
| W8 Dashboard 与控制面安全 | 7 | 3 | **4** | `/api/decide` 源码四检查并有 CI；但无本轮真实运行身份/Playwright/安全 E2E，Dashboard 与 Aggregator 契约仍断。 |
| W9 Shadow/Canary/切换 | 2 | 0 | **0** | 11 目录只有 README，零 shadow/canary/cutover 工件。 |
| W10 观察窗/演练/收官 | 2 | 1 | **1** | 保留二轮“job 存在”的最低分；13/12 目录均只有 README，无 14 天指标、回滚/DR 演练、战训收官。 |
| **总分** | **100** | **29** | **39（建议）** | **硬门优先，仍 BLOCKED。** |

## 八、关键证据文件索引

- 基线/方案/二轮：`00-baseline.log`、`02-prior-report-full.log`、`03-plan-core-workpacks.log`、`04-plan-probes-matrix.log`
- 全量 acceptance / 移除工具：`11-acceptance-isolated.log`、`12-tool-removal-anchor.log`
- P0-3：`13-p0-3-source-review.log`、`14c-p0-3-import-callgraph.log`、`15-p0-3-contract-probe.log`
- P0-6：`16-p0-6-store-probe.log`
- P0-7：`17-p0-7-source-review.log`、`18-p0-7-deploy-probe.log`
- P0-10 / 追踪：`09-traceability-live.log`、`10-independent-trace-check.log`、`19b-evidence-index-reconcile.log`、`22-trace-plan20-tamper-default.log`、`23-trace-plan20-tamper-check.log`、`24-trace-plan251-tamper-check.log`、`25-acceptance-plan20-tamper.log`
- CI/保护：`20-ci-run-json.log`、`21-ci-run-log.log`、`26-branch-protection.log`、`27-repo-rulesets.log`
- 增量与收尾：`28-increment-diff.log`、`29-final-repo-status.log`

# 第四轮复审：外部 CI / 分支规则 / 证据索引 / 7789 运行身份核验

- 复审对象：`/Users/maccc/Documents/wenqu-dist`
- 冻结 HEAD：`e4aba84c1dabe1342ea234321eea3d300bea24a5`
- 时间：2026-10-08（Asia/Shanghai）
- 边界：仓库与运行态均只读；未改 branch protection、未部署/重启、未发 POST、未执行生产写。只在本轮独立证据目录写文件。

## 结论摘要

**外部事实不是全假，但仍不足以放行：建议整体继续 `BLOCKED`。**

1. CI run `37733159993` 属实：`acceptance` / `push` / `main` / `e4aba84...`，状态 `completed/success`；macOS、Ubuntu 两个 job 都成功。
2. `main` 当前确有 branch protection：`strict=true`、required=`matrix (ubuntu-latest)` + `matrix (macos-latest)`、两项均绑定 GitHub Actions app `15368`、`enforce_admins=true`、force push/delete 禁止。仓内 readback 与实时 API JSON 的 SHA256 完全一致。
3. PR#1/#2 的当前 required context 在各自合并前均已有 SUCCESS；因此“这两个 PR 的实际 required check 集合在 merge 前满足”属实。**但当前 Gate 不是冻结方案要求的四个稳定 context，也没有 CODEOWNERS/review、merge_group、workflow pinning。**
4. 新增重大边界：唯一 required workflow 没有执行 `test_wenqu_adversarial.py`（11 项）和 `test_infra_hardening.py`（66 项）；两套本地绿不能冒充受保护 CI 绿。
5. 7789 运行身份对账成功：PID `64211`，active、工作树和 `HEAD` 的 `system/bin/wenqu-dashboard.py` 完整 SHA256 都是 `72ba1db7...73ddf`。但运行体仍是 legacy 单文件写版 `/api/decide`，不是模块化只读 `server.py`（405）；模块化安装目录不存在。
6. `evidence-index.json` 有 14 个语法条目，历史快照/manifest 多数可验真；但按冻结 §24.2 与第三轮同口径的机器可放行标准，**0/14 完整合格**。索引仍绑定 `ff050bb`，未索引当前 CI、当前 HEAD、branch readback，且 `known_gaps` 仍错误声称 main 无保护。
7. W5/W9/W10 指定目录仍只有 README，无索引条目；最终 release archive / SBOM 为 0。时间窗缺口仍成立。

## 1. CI run 37733159993 真实性

### 实时回读

| 字段 | 结果 |
|---|---|
| workflow | `acceptance` |
| event / branch | `push` / `main` |
| head SHA | `e4aba84c1dabe1342ea234321eea3d300bea24a5` |
| run attempt | 1 |
| status / conclusion | `completed` / `success` |
| 创建 / 完成 | `2026-10-08T05:35:40Z` / `05:36:13Z` |
| jobs | macOS success；Ubuntu success |
| GitHub artifacts | `0` |

日志实况：

- 两个平台的 `tests/acceptance.sh` 都报告 `PASS=61 FAIL=0 / ALL GREEN`；
- 两个平台后续独立 pytest 步骤均报告 `20 passed`；
- P1 core wiring 8/8、P1b pipeline 10/10、P1c 追踪 `--check` 均确实执行；
- Ubuntu 出现一次 GNU `mktemp: too few X's`，随后 fallback 成功，job 仍 success；不据此判失败。

### 不能从该 run 推出的结论

唯一 workflow 与 `tests/acceptance.sh` 均未引用：

- `system/tests/test_wenqu_adversarial.py`；
- `system/tests/test_infra_hardening.py`。

所以 required CI 只证明当前 workflow 中的 release-check、acceptance、CLI pytest、自测成功；不能证明开发方声称的 11/11、66/66 已进入不可绕过 Gate。该 run 也没有上传 artifact。

关键证据：

- `06-ci-branch/01-gh-run-view.json`
- `06-ci-branch/02b-run-jobs.json`
- `06-ci-branch/03-check-runs.json`
- `06-ci-branch/04-gh-run.log`
- `06-ci-branch/12-run-api.json`
- `06-ci-branch/14-required-check-coverage.log`
- `06-ci-branch/16-run-artifacts.json`

## 2. Branch protection 与 PR#1/#2 时间线

### 当前规则

实时 API：

- `strict=true`；
- required checks：`matrix (ubuntu-latest)`、`matrix (macos-latest)`；
- 两项 `app_id=15368`；
- `enforce_admins.enabled=true`；
- `allow_force_pushes=false`、`allow_deletions=false`；
- `required_pull_request_reviews=null`、`restrictions=null`；
- repository rulesets 为 `[]`。

仓内 `branch-protection-readback-20261008.json` 与本轮 live response 均为 SHA256 `7b075c8b...4aab6`，字节一致。

### 合并时间线

| PR | head | required checks 完成 | mergedAt | 判定 |
|---|---|---|---|---|
| #1 | `14600f829b...` | push run `37732624290` 最晚 `05:29:50Z`；PR run `37732630449` 最晚 `05:29:53Z`；两 context 均 SUCCESS | `05:30:20Z` | 按当前 required 集合，合并前已满足 |
| #2 | `c345b7bbc0...` | push run `37733093290` 最晚 `05:35:22Z`；PR run `37733100994` 最晚 `05:35:30Z`；两 context 均 SUCCESS | `05:35:37Z` | 按当前 required 集合，合并前已满足 |

边界：当前 API 能证明**现态规则**，PR/check 时间线能证明 required 名称在 merge 前成功；没有组织 audit-log 工件可单独证明保护规则在整个历史窗口从未被短暂修改。

### 与冻结方案的差距

冻结方案要求至少：

- `Fast (lint+tsc)`；
- `Bugscan Required Gate`；
- `Wenqu Required Gate`；
- `Action Authorization Gate`；
- CODEOWNERS review 真启用；
- merge_group 明确终态；
- workflow/action 钉 commit SHA，PR 不能修改自己的 workflow 自证。

现态只有两个 generic matrix contexts；无 CODEOWNERS 文件、无 required review、workflow 无 `merge_group`，actions 仍用 `@v4/@v5` 浮动标签。因此这是“有保护且 PR 实际过了当前门”，不是“冻结方案 W3 Required Gate 已完成”。

关键证据：

- `06-ci-branch/06-branch-protection.json`
- `06-ci-branch/07-required-status-checks.json`
- `06-ci-branch/08-enforce-admins.json`
- `06-ci-branch/10-branch-evidence-reconcile.log`
- `06-ci-branch/18-pr-merge-required-check-timeline.txt`
- `06-ci-branch/19-plan-vs-live-gate.log`

## 3. evidence-index 与实际工件对账

### 正向事实

- JSON 可解析，条目数确为 14；14 条 `evidence_path` 均存在（10 个文件、4 个目录）。
- 方案快照及外部正源 SHA256 均为冻结值 `96b8646...2306`。
- 第二轮、第三轮报告快照与外部文件哈希一致。
- 三组历史证据主 manifest、两个子 manifest 全量 `shasum -c` 成功。
- 索引中以 prose 描述的历史 hash（测试文件、报告、manifest、v3.6.3 SHA 文件）经人工抽取后均可对上。

### 严格不合格点

按 §24.2 的 `run_id + commit + environment + scope + ruleset + time + argv + real rc + artifact SHA256 + fresh_until` 与第三轮“具体文件、完整 40 位 SHA、纯 64hex artifact hash”口径：

- 严格合格：`0/14`；
- 完整 40 位 commit：`0/14`；
- `artifact_sha256` 为纯 64hex：`2/14`；
- 至少一个必填为空：`11/14`；
- 4 条路径只指向目录；
- `repo_head_at_filing=ff050bb...`，不等于 live `e4aba84...`；
- 当前 run `37733159993` 未索引；当前 HEAD 未索引；branch readback / rulesets count 文件未精确索引；
- `known_gaps` 仍写“main 无 branch protection/ruleset/required contexts”，与 live API 冲突；
- 受控 `traceability-matrix.json` 的 meta 仍绑定 `e00de14...`（静态基线可以保留，但不能当当前 HEAD 运行证据）。

因此应表述为：**历史快照可验真，但当前 release 证据索引仍 stale / 非机器可放行。**

关键证据：

- `09-review/06-evidence-index-audit.log`
- `09-review/05-sidecar-manifest-verification.log`
- `09-review/07-declared-hash-reconcile.log`
- `09-review/04-evidence-file-inventory.log`
- `09-review/08-trace-matrix-metadata.log`

## 4. 7789 运行身份与控制面边界

### 身份对账通过

- launchd label：`com.wenqu.dashboard`，state=running，PID=`64211`；
- 命令：Python + `/Users/maccc/.wenqu/bin/wenqu-dashboard.py 7789`；
- listener：`127.0.0.1:7789`；
- active / worktree / `git show HEAD:system/bin/wenqu-dashboard.py` 完整 SHA256 均为：
  `72ba1db7a8e2a292ac0feff836988fc8f064a75bf421996ed2ce0247e1873ddf`；
- deployment JSON 记录 PID 64211 与前缀 `72ba1db7`，现态对得上；旧备份 SHA256 为 `52aba1b5...a331`；
- GET `/api/health`：HTTP 200，body 显示 `score=40 / 告警 / Gate=failure`，没有把 blocker 展示成“良好”。

### 不能判 P0-9 全关闭

运行体仍是 `system/bin/wenqu-dashboard.py` 的 legacy 单文件版：

- 仍实现 `_decide_write()` 和 `/api/decide` 写路径；
- 冻结方案第一阶段要求 `/api/decide` 返回 405；仓内模块化 `system/dashboard/server.py` 符合 405，但未被 launchd 使用，`~/.wenqu/dashboard` 目录也不存在；
- active 服务要求 `WENQU_DASHBOARD_KEY`、`X-Auth-Key`、`X-Requested-With`，但 launchd/plist 未配置 key，页面 JS 的 fetch 也不发送后两项。因此写面当前 fail-closed，却同时不可合法操作；这与“审批签发端未建”的已知缺口一致，不能作为完整控制面交付；
- 没有 read authorization / Playwright / `/api/build` attestation 的新证据。

本轮没有发 POST；以上为 launchctl/plist 与同一 HEAD 源码只读交叉验证。

关键证据：

- `07-runtime/01-launchctl-print.log`（环境敏感值已脱敏）
- `07-runtime/02-listener-process.log`
- `07-runtime/03-runtime-hash.log`
- `07-runtime/04-health.log`
- `07-runtime/05-deploy-evidence-reconcile.log`
- `07-runtime/06-control-path-static-readonly.log`
- `07-runtime/07-plan-vs-active-dashboard.log`

## 5. W7 / W5 / W9 / W10 边界

### W7

这次部署能证明“手工 active 文件与候选 hash 一致、进程重启、备份存在”，不能证明冻结 W7：

- active 是直接普通文件 `~/.wenqu/bin/wenqu-dashboard.py`，不是 release symlink；
- `~/.local/share/wenqu` 目标 release 根不存在；
- 部署 JSON 无 source commit、完整 files/mode/hash manifest、artifact hash、policy/schema、SBOM、签名/attestation；
- 无最终 tar/tgz/zip、SBOM；无正式 rollback/restore drill。

### W5/W9/W10

`07-migration-reconcile`、`11-shadow-canary`、`12-rollback-drill`、`13-observation-window` 各只有 README；索引中对应 category 条目为 0。索引自己也承认 W5/W9/W10 时序证据未补。故第三轮分数不得因本轮代码/CI 绿而提升。

证据：`07-runtime/08-release-deployment-boundary.log`、`09-review/09-timing-evidence-audit.log`。

## 6. P0 十项建议（仅本分工可判部分）

| P0 | 建议 | 外部证据边界 |
|---|---|---|
| P0-1 | 交由动态探针分工判定 | 当前 CI 确跑 core 8/8，但新 adversarial/infra 两套未进入 required workflow。 |
| P0-2 | 交由 12 探针分工判定 | CI 只跑 pipeline 10/10，不足以替代独立反例。 |
| P0-3 | **不得因 CI/保护直接判 PASS** | 当前 GitHub 只有两个 generic matrix context，不是方案的 Bugscan/Wenqu/Action 三 Gate；代码 v2 聚合另由探针判定。 |
| P0-4 | 交由 Schema/篡改探针判定 | 无额外外部结论。 |
| P0-5 | 交由 CAS/Runner 探针判定 | 无额外外部结论。 |
| P0-6 | 交由 EventStore 探针判定 | 无额外外部结论。 |
| P0-7 | 交由部署隔离探针判代码修复；**真实发布层仍未关闭** | 当前只是 direct-file 部署，不是冻结 release/manifest/rollback 流程。 |
| P0-8 | **PASS（维持关闭）** | 源 stub exit 1；installed writer 缺失；launchd/cron/真实进程复核未发现 writer。首次 `pgrep` 自匹配已在校正证据中明确排除。 |
| P0-9 | **FAIL / PARTIAL** | active hash 漂移已关闭；但 active 仍 legacy 写版而非模块化 405，只是因 key/headers 缺失 fail-closed；无完整 read auth/UI 真验。 |
| P0-10 | **FAIL / PARTIAL** | 14 条索引存在但 0 条达严格机器可放行；当前 CI/HEAD/branch readback 未索引；无最终制品与时序证据。 |

## 7. W0–W10 外部证据评分建议

以下只按本分工新增证据调整第三轮，不覆盖代码探针分工的独立加减分：

| 包 | 满分 | 三轮 | 本分工建议 | 理由 |
|---|---:|---:|---:|---|
| W0 | 8 | 3 | **3** | auto-merge 继续关闭；但仍无当前完整 baseline manifest、writer inventory、maintenance/凭据撤销证据。 |
| W1 | 10 | 6 | **6（暂）** | Schema/TLA/红探针由其他分工；外部证据不给额外分。 |
| W2 | 15 | 6 | **6（暂）** | 核心 12 探针由其他分工；CI 10/10 不能替代。 |
| W3 | 15 | 3 | **5** | +2：保护、strict/admin、两 PR 合并前 checks 成功属实；但 context/审查/merge_group/pinning 不符合冻结方案，且 11+66 新套件未接 required workflow。 |
| W4 | 10 | 3 | **3** | 一个 launchd dashboard 不是统一调度/outbox/通知/备份闭环。 |
| W5 | 8 | 1 | **1** | reconciliation 目录仅 README，索引 0 条。 |
| W6 | 15 | 8 | **8（暂）** | 聚合器/站点由其他分工；没有 scanner golden / required Bugscan Gate 的新外部工件。 |
| W7 | 8 | 3 | **4** | +1：运行 hash/PID/备份真实；但 direct-file 部署，无 release layout、manifest/SBOM、正式回滚。 |
| W8 | 7 | 4 | **5** | +1：active hash 一致、回环监听、health 诚实显示 Gate failure；但 legacy write 面仍在、合法写不可用、无 read auth/Playwright。 |
| W9 | 2 | 0 | **0** | shadow/canary 目录仅 README。 |
| W10 | 2 | 1 | **1** | 无 14 天、rollback/DR/restore 独立工件。 |
| **外部证据保守小计** | **100** | **38** | **42** | 不是最终总分；需合并探针分工对 W1/W2/W6/W7 的结论。 |

即使其他代理确认 12 个代码反例全部关闭，以下硬门仍足以维持最终 `BLOCKED`：P0-9 运行面不完整、P0-10 证据索引不合格、W3 未达冻结 Gate、W5/W9/W10 未到期、最终 release 未打包。

## 8. 证据完整性与仓库保护

- 仓库收尾 HEAD 仍为 `e4aba84...`；工作树 clean；本分工没有改源仓。
- GitHub/launchctl 输出中的 token、邮箱、代理/API/SSH 环境值已裁剪或脱敏。
- 分目录 `MANIFEST.sha256` 记录本轮证据哈希。

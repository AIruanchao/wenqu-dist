# 问渠 / Bug 管线整改产物验收报告（第四轮独立复审）

- 验收对象：`/Users/maccc/Documents/wenqu-dist`
- 验收基线：`main@e4aba84c1dabe1342ea234321eea3d300bea24a5`
- 第三轮基线：`main@ff050bbb9c95c04ecb975900f5440f9bfcd1a447`，结论 `38/100 BLOCKED`
- 方案正源 SHA256：`96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306`
- 验收日期：2026-10-08（Asia/Shanghai）
- 证据根：`/private/tmp/codex-test/evidence/reaudit4-20261008-141341/`
- 验收性质：独立、只读优先复审；删除、篡改、竞态、失败部署均在 `/tmp` 隔离副本中执行

---

## 1. 最终判定

# **BLOCKED — 49/100**

| 完成层 | 判定 | 主要原因 |
|---|---|---|
| 候选实现完成 | **不通过** | 12 项旧失败族仍有 Runner 逃逸未闭环；另发现 action 无授权可提交、Schema/聚合器假绿、安装后 CLI 断链、§20 语义篡改假绿。 |
| CI 准入完成 | **不通过** | 当前 CI 与分支保护属实，但 required workflow 未执行新增 11 项对抗和 66 项基础设施测试，也不是冻结方案要求的四个稳定 Gate。 |
| 受控部署完成 | **不通过** | 7789 运行 hash 已对上候选，但仍是 legacy 单文件写版；部署不是不可变 release/manifest/SBOM 流程。 |
| 发布后验证完成 | **不通过** | W5/W9/W10 工件未到期/未形成，最终 release 制品未打包。 |
| production-ready | **禁止声明** | P0 十项仅 P0-8 完整通过；其余九项仍为 FAIL/PARTIAL。 |

本轮相对第三轮有实质进步：第三轮连续 12 项失败探针中 **11 项已由新的异源用例确认闭环**；分支保护、PR 正门合流、当前 HEAD 的双平台 CI、7789 完整 hash 对账也都是真实事实。因此总分由 38 提升到 49。

但这些进步不能覆盖仍可运行的 fail-open/逃逸反例。尤其：

1. `TrustedRunner` 的 `setsid + double-fork` daemon 可在 timeout 后继续写文件，连续 3/3 重现；
2. `RunManager.reserve_action → start_action → commit_action` 在 **0 条审批消费**时仍可对 `release/production` 提交调用方自报回执；
3. 正式 Schema 不接受的残缺 station-v2 可被 `GateAggregator` 判 `PASS` 且 Dashboard 接受；
4. 保留 §20 ID、只改变“注入/期望”语义时，追踪 `--check` 和完整 acceptance 均全绿；
5. required CI 删除 11 项对抗测试和 66 项基础设施测试后仍为 `62/62 ALL GREEN`；
6. 正常安装虽然 rc=0，但安装后的 `wenquctl --help` rc=2，入口路径错误。

以上任一项都足以阻止 P0/生产准入关闭。

---

## 2. 验收边界、身份与完整性

### 2.1 正源身份

- 初始、过程中、收尾 HEAD 均为 `e4aba84c1dabe1342ea234321eea3d300bea24a5`；
- `origin/main` 与本地 HEAD 一致；
- 收尾 `git status --porcelain` 为空，`git diff` 与 `git diff --cached` 均 rc=0；
- 外部与仓内方案快照 SHA256 均等于冻结值；
- 外部与仓内第三轮报告 SHA256 均为 `b87d7613717a88a49ec409de12e8a0f1b51c0858e485ac8c7b1de03980bd03ee`。

证据：`00-baseline/environment.txt`、`10-final/final-source-integrity.txt`。

### 2.2 破坏性验证隔离

- 12 项探针使用 `git archive HEAD` 生成无 `.git` 的 `/tmp` 副本；
- 移除锚点、Schema/方案篡改、CI 缺件、部署失败与 CAS 竞态均在独立 `/tmp` clone/copy 中执行；
- 未改 branch protection，未部署/重启，未发 `/api/decide` POST，未执行生产写或 DDL；
- 逃逸进程 PID 已清理，结束核验均不存在。

### 2.3 一次非预期宿主副作用

正常安装探针发现 `install.sh --prefix /tmp/...` 仍会向宿主 `~/.bashrc` 追加 PATH。本轮立即以精确行匹配删除该次追加行并保存恢复记录；未保留该次宿主改动。此事实同时说明安装器仍未做到完全隔离。证据：`09-review/install-host-side-effect-restored.txt`。

---

## 3. 第三轮 12 项失败探针逐条复核

本轮没有调用修复方测试函数来替代独立验证，而是新写 `01-probes/scripts/reaudit4_probe_suite.py`，每项日志均保存完整命令、stdout/stderr 和退出码。统一命令形态为：

```text
env WENQU_REPO_COPY=<隔离副本> PYTHONDONTWRITEBYTECODE=1 \
  python3 .../reaudit4_probe_suite.py --probe <01..12>
```

| # | 第三轮失败项 | 本轮新场景与实测结果 | 闭环判定 | 原始证据 |
|---:|---|---|---|---|
| 01 | 伪签名、缺 exact binding | 跨信封替换 HMAC 被拒；删除 `policy_hash` 后重签仍被必填校验拒绝；正确正例可恢复；rc=0 | **PASS** | `01-probes/logs/probe-01-forged-signature-missing-bindings.log` |
| 02 | risk 冒充 resume | 纯 risk 投 resume API、resume 混入 risk 键均拒绝；拒绝路径不消费 nonce；rc=0 | **PASS** | `probe-02-risk-masquerade-resume.log` |
| 03 | 字符串假布尔 | `evidence_freshness_reverified=" FALSE "` 即使哈希精确绑定仍拒绝；真 bool 正例通过；rc=0 | **PASS** | `probe-03-false-preconditions.log` |
| 04 | 非 resume 无 CAS | 旧 `expected_state_version` 的 risk 授权被拒且不消费；当前版本正例通过；rc=0 | **PASS** | `probe-04-nonresume-cas.log` |
| 05 | TIMEOUT/P1 洗白 | `TIMEOUT+CONDITIONAL` 最终 FAILED；`LOW/P1` finding 不能被风险包洗白；rc=0 | **PASS** | `probe-05-timeout-p1-launder.log` |
| 06 | 控制事件直写 | 公共入口拒绝；绕过入口插入带偷取 seal 的控制事件后重放报损坏；rc=0 | **PASS** | `probe-06-control-event-direct-write.log` |
| 07 | 仅事件重放丢 nonce | 只复制 `pipeline_events` 到新库、旁表为空时，同 nonce 仍由事件投影拒绝；rc=0 | **PASS** | `probe-07-events-only-replay.log` |
| 08 | station-v2 契约链断 | 手工构造正式 v2 的 0/3/6 三站，Schema→Aggregator→Dashboard 全链通过；rc=0 | **PASS（合法输入路径）** | `probe-08-station-v2-chain.log` |
| 09 | EventStore 重试伪 hash/head 错 | 跨 reopen、多条干扰、不同 JSON 键序重试，返回库内原 hash；head 指链尖；rc=0 | **PASS** | `probe-09-eventstore-retry.log` |
| 10 | CAS 父目录 TOCTOU | `mkdir` 后换 shard 为根外 symlink 被拒；整个 CAS 根路径被替换时持久 dirfd 仍写原对象；rc=0 | **PASS** | `probe-10-cas-parent-race.log` |
| 11 | Runner setsid 逃逸 | attached setsid 对照已能杀；但 setsid+double-fork 提前 reparent 的 daemon timeout 后写出 marker，3/3 次 rc=1 | **FAIL / 仅部分闭环** | `probe-11-runner-escape*.log` |
| 12 | 升级失败回滚 | 含空格、多层相对链接、cwd=`/` 场景中 v2 自检失败后精确回 v1 且重验；rc=0 | **PASS** | `probe-12-upgrade-rollback.log` |

**汇总结论：11/12 完全闭环；第 11 项安全目标仍失败。**

Runner 根因：超时时 `_descendants(root_pid)` 只按当下 PPID 图从原 root 查后代；double-fork 中间进程已退出后，daemon 被 launchd/PID 1 接管，后续扫描仍从已死亡 root 出发，无法重新发现。不能以增加 `ps` 扫描轮数等同于 cgroup/pid namespace 级强隔离。

证据汇总：`01-probes/findings.md`、`01-results-rollup.txt`、`02-code-line-evidence.txt`、子目录 `MANIFEST.sha256`。

---

## 4. P0 十项同口径重判

| P0 | 四轮状态 | 本轮确认的真实修复 | 仍阻断的事实 |
|---|---|---|---|
| P0-1 核心接线 | **FAIL / PARTIAL** | 模块/schema/tool 三移除锚点均红；源树 `wenquctl --help` rc=0；安装器全模块导入 15 个模块成功 | 正常安装 rc=0 后，安装体 `bin/wenquctl --help` rc=2：壳寻找 `$PREFIX/wenqu_core/cli.py`，实体在 `$PREFIX/lib/wenqu_core/cli.py`；两套新增关键测试未进入 required CI |
| P0-2 七段状态机与审批 | **FAIL / PARTIAL** | HMAC-SHA256+keyring、全字段绑定、payload 互斥、严格 bool、CAS、终态双轴、seal/重放、nonce 事件正源等旧反例已关闭 | **无任何 action approval** 仍可 reserve/start/commit `release/production`，审批消费数为 0，receipt 可由调用者自报；审批签发端仍未建 |
| P0-3 契约链/Gate | **FAIL / PARTIAL** | 合法 v2 station→aggregator→dashboard 链已通；branch protection 与当前 CI 属实 | 正式 Schema 判无效的极简 v2 被 aggregator 判 PASS、`technical_eligible=true` 且 Dashboard 接受；仓外未发现正式 aggregator 生产调用链；GitHub 不是冻结的 Bugscan/Wenqu/Action Gate |
| P0-4 Schema 不变量 | **FAIL / PARTIAL** | approval 判别联合与 nonce 约束等明显增强；放宽 nonce 的变异能被交叉门杀死 | Draft-07+FormatChecker 仍接受 `evidence PASS+exit9`、`station PASS 1/9`、`CLOSED→OPEN`、无 `state_from` 的 `RISK_INVALIDATED`、`TIMEOUT+CONDITIONAL` |
| P0-5 Runner/CAS | **FAIL / PARTIAL** | CAS 安全打开、原子写、hardlink 计数与父目录竞态关闭；普通 setsid 后代可杀；环境最小化 | setsid+double-fork reparent 仍逃逸；本地 subprocess 也未达到冻结方案的强容器/低权限/网络与资源隔离 |
| P0-6 EventStore | **FAIL / PARTIAL** | duplicate hash 与 `head()` 两项第三轮语义错误已关闭；控制事件/nonce 重放改善 | 核心仍写 `pipeline_events`，`LedgerMigrator` 仍写独立 `events` 表；迁移/旧账唯一正源未统一，W5 未执行 |
| P0-7 部署/回滚 | **FAIL / PARTIAL** | 深层相对链接升级失败回滚、权限位、原子切换等代码路径通过新探针 | 安装后 CLI 断链；7789 为 direct-file 部署而非 immutable release；无完整 manifest/SBOM/signature/lease/备份恢复/最终制品 |
| P0-8 auto-merge | **PASS / 保持关闭** | 源 stub fail-closed；installed writer 不存在；launchd/cron/进程复核无 writer；两 PR 走当前保护门 | 仅关闭危险旧 writer，不代表 W3/W9 自动合流方案已完成 |
| P0-9 7789 控制面 | **FAIL / PARTIAL** | active/worktree/HEAD 完整 SHA256 一致；仅监听 `127.0.0.1`；health 如实显示 `Gate=failure` | active 仍是 legacy 单文件 `/api/decide` 写版，不是方案要求的模块化 405 只读版；launchd 无 key、前端不发必要 headers，写面 fail-closed 但不可合法操作；无 read auth/Playwright/build attestation |
| P0-10 证据/追踪/制品 | **FAIL / PARTIAL** | 索引由 9 增至 14；§25.1 真解析、ID/元数据篡改会红；P1c 已只读；131 集合诚实 | §20 语义文本篡改仍假绿；受控 matrix 绑定旧 HEAD；索引严格合格 0/14 且漏当前 HEAD/run/branch；0/131 专属覆盖；无最终制品与时序工件 |

### 4.1 新的独立阻断反例

#### F4-AUTH-001：ActionSaga 未绑定 exact action authorization

命令与输出见 `09-review/action-without-authorization-probe.txt`：

```text
approval_consumptions=0
reserved=RESERVED → started=STARTED → committed=COMMITTED
receipt=caller-self-asserted-receipt
exit_code=1（审计探针发现漏洞）
```

`ACTION_AUTH_RESERVED` 只是事件名；`reserve_action()` 未要求并消费 action 类型的签名审批，`commit_action()` 只校验非空 receipt。这违反 `action_eligible := technical_eligible AND valid_exact_action_authorization`。

#### F4-GATE-001：聚合器接受 Schema-invalid v2 为 PASS

`09-review/aggregator-invalid-v2-probe.txt`：正式 Schema 拒绝缺 tool/execution/coverage/artifacts 的输入，但 `GateAggregator` 输出 `PASS`、`technical_eligible=true`，Dashboard `ok=true`，探针 rc=1。

#### F4-SCHEMA-001：跨字段不变量仍可假绿

`09-review/schema-residual-probe.txt`：五个应拒样例全部 `ACCEPTED`，探针 rc=1。Schema 删除/nonce 放宽变异能红只证明指定锚点，不能代替这些跨字段不变量。

#### F4-CLI-001：安装成功但安装体入口不可运行

- `bash system/install.sh --prefix <tmp>` → rc=0，全模块导入成功；
- `<prefix>/bin/wenquctl --help` → rc=2，找不到 `<prefix>/wenqu_core/cli.py`。

证据：`09-review/install-normal.txt`、`installed-wenquctl-help.txt`。

---

## 5. W0–W10 同口径评分

> 只对第三轮以后、本轮有独立新证据的项加分；硬门失败优先于总分。

| 工作包 | 权重 | 三轮 | 四轮 | 变化与证据 |
|---|---:|---:|---:|---|
| W0 快照与危险面隔离 | 8 | 3 | **3** | 不升：auto-merge 继续关闭，但仍无当前完整 baseline manifest、writer inventory、maintenance authorization、凭据撤销和 quality-policy 唯一正源证据。 |
| W1 契约/Schema/威胁/TLA/红探针 | 10 | 6 | **7** | +1：HMAC/判别联合、§25.1 四列真解析与多类变异门属实。仍无 Wenqu TLA/TLC、BEFORE 全量红探针；Schema 残余与 §20 语义假绿仍在。 |
| W2 Runner/事件/授权/CAS | 15 | 6 | **10** | +4：12 旧失败族中授权、CAS、事件重放、EventStore 等大部分真实关闭。Runner daemon 逃逸、action 无授权提交、强隔离/kill-9/备份矩阵仍阻断。 |
| W3 Gate/CI/合流控制 | 15 | 3 | **6** | +3：合法 v2 链已通，main strict/admin 保护上线，两 PR 在合并前满足现行 required checks，当前 HEAD 双平台 success。仍无冻结四 Gate/CODEOWNERS/merge_group/pinning；invalid v2 假 PASS；关键 11+66 未接 required CI。 |
| W4 调度/Outbox/通知/备份 | 10 | 3 | **3** | 不升：一个 dashboard launchd 不是统一 scheduler/outbox/receipt/备份恢复闭环。 |
| W5 旧账迁移 | 8 | 1 | **1** | 不升：`07-migration-reconcile` 只有 README；索引无对应工件；迁移器仍是独立 `events` 表。 |
| W6 Bug 八站 | 15 | 8 | **8** | 不升：五个模块自测通过，但站5/6仍明确是 placeholder；无 scanner goldens、真实浏览器/实弹、统一 required Bugscan Gate 的新证据。 |
| W7 制品/安装/部署/回滚 | 8 | 3 | **5** | +2：权限位、深层相对链接回滚、安装全模块导入等代码框架有实证。安装体 CLI 断链，active 为 direct-file，无 release manifest/SBOM/signature/lease/恢复演练/最终制品。 |
| W8 Dashboard/健康/控制面 | 7 | 4 | **5** | +1：7789 完整 hash、回环监听、Gate failure 显示属实。仍是 legacy 写版；模块化 405 未部署；无 read auth、Playwright、原子健康快照证据。 |
| W9 Shadow/Canary/切换 | 2 | 0 | **0** | 不升：目录只有 README，无 shadow/canary/writer epoch/cutover 工件。 |
| W10 观察窗/演练/收官 | 2 | 1 | **1** | 不升：无 14 天、两次周任务、14 次 nightly、回滚/DR/备份恢复独立工件。 |
| **总分** | **100** | **38** | **49** | **BLOCKED** |

---

## 6. 常规核验结果

### 6.1 开发方声称的本地回归

均在隔离副本实际复跑：

| 命令 | 实际输出 | rc | 判定/证据 |
|---|---|---:|---|
| `python3 system/tests/test_wenqu_pipeline.py` | 10 PASS / 0 FAIL | 0 | 属实；`09-review/regression-test-wenqu-pipeline.txt` |
| `python3 system/tests/test_wenqu_adversarial.py` | 11 PASS / 0 FAIL | 0 | 属实；`regression-test-wenqu-adversarial.txt` |
| `python3 system/tests/test_infra_hardening.py` | 66 PASS / 0 FAIL | 0 | 属实；`regression-test-infra-hardening.txt` |
| `python3 system/tests/test_core_wiring.py` | 8 PASS / 0 FAIL | 0 | 属实；`regression-test-core-wiring.txt` |
| 五个模块 self-test | 各 `SELF-TEST PASS` | 均 0 | 属实；`selftest-*.txt` |
| `bash tests/acceptance.sh` | 62 PASS / 0 FAIL，ALL GREEN | 0 | 属实；`08-acceptance/03-acceptance-full.log` |

边界：这些绿只对当前自测表面成立。独立反例已证明其中存在未覆盖漏洞；且新增 11/66 两套测试不在 required workflow。

### 6.2 三个移除锚点

| 隔离变异 | 直接/子测试 | 完整 acceptance | 判定 |
|---|---|---|---|
| 删除 `wenqu_pipeline.py` | core 7/1 rc=1；pipeline rc=1 | 58/4 rc=1 | **PASS：必红** |
| 删除 `approval-v2.schema.json` | core 7/1 rc=1；pipeline 9/1 rc=1 | 60/2 rc=1 | **PASS：必红** |
| 删除 `tools/ac_traceability.py` | direct rc=2 | 61/1 rc=1 | **PASS：必红** |

证据：`04-mutations/findings.md` 与 `01-*`～`11-*` 日志。

### 6.3 Schema 篡改交叉验证

将 `approval-v2.schema.json` 的 `nonce.minLength` 从 16 放宽为 0：

- 独立一字节 nonce Schema/Broker 分歧探针 rc=7；
- pipeline 9/1，rc=1；
- acceptance 61/1，rc=1。

判定：**指定 Schema 语义变异门有效。** 证据：`04-mutations/12-*`～`15-*`。

### 6.4 追踪工具 §20 / §25.1 篡改

| 变异 | `--check` | acceptance | 判定 |
|---|---:|---:|---|
| §20 `GATE-01→GATE-99`（ID 集合） | rc=2 | 61/1 rc=1 | PASS |
| §25.1 GATE 的 REQ 元数据 | rc=2 | 61/1 rc=1 | PASS |
| §20 保留 ID、仅改“注入/期望”语义 | **rc=0** | **62/0 rc=0** | **FAIL / 假绿** |

因此用户要求的“§20 与 §25.1 内容篡改后都必须非零”只在 §20 ID 集合口径成立，在 §20 语义内容口径 **不成立**。新发现编号：`F4-TRC-001`。证据：`05-trace/findings.md`、`07-*`～`09-*`。

### 6.5 P1c 只读性

未篡改基线下 P1c 使用仓外临时 JSON；运行前后：

- 工作树为空；
- `git diff`/cached diff rc=0；
- 受控 matrix 哈希不变；
- HEAD 不变。

第三轮“acceptance 改写受控 matrix”的副作用已关闭。证据：`08-acceptance/04-after-readonly.log`、`05-p1c-readonly.log`。

---

## 7. CI 与分支保护真实性

### 7.1 CI run 37733159993

实时 `gh`/GitHub API 回读：

| 字段 | 实际值 |
|---|---|
| workflow / event | `acceptance` / `push` |
| branch / SHA | `main` / `e4aba84c1dabe1342ea234321eea3d300bea24a5` |
| status / conclusion | `completed` / `success` |
| jobs | macOS success；Ubuntu success |
| artifacts | 0 |

两平台日志中 acceptance 为 61 PASS / 0 FAIL（pytest 在该步骤不可用），后续独立 pytest 均为 20 passed。结论：“该 run 对该 SHA 成功”属实。

证据：`06-ci-branch/01-gh-run-view.json`、`02b-run-jobs.json`、`03-check-runs.json`、`04-gh-run.log`、`12-run-api.json`。

### 7.2 required CI 覆盖缺口

唯一 required workflow 未引用：

- `system/tests/test_wenqu_adversarial.py`（11 项）；
- `system/tests/test_infra_hardening.py`（66 项）。

在隔离副本同时删除这两个文件，`bash tests/acceptance.sh` 仍 `62/62 ALL GREEN, rc=0`。这是 `F4-CI-001`：本地 11/11、66/66 不能冒充受保护 CI Gate 已覆盖。证据：`09-review/ci-critical-tests-removed-acceptance.txt`。

### 7.3 Branch protection 与 PR 时间线

实时 API：

- `strict=true`；
- required contexts：`matrix (ubuntu-latest)`、`matrix (macos-latest)`，均绑定 app_id 15368；
- `enforce_admins=true`；
- force push/delete 禁止；
- required PR reviews 为 null；rulesets=[]。

PR#1 与 PR#2 的两个 required context 均在各自 `mergedAt` 前 SUCCESS，故“经现行保护正门合流”属实。

但冻结方案要求 `Fast (lint+tsc)`、`Bugscan Required Gate`、`Wenqu Required Gate`、`Action Authorization Gate`，并要求 CODEOWNERS review、merge_group、workflow/action commit pinning。现态均未满足；actions 仍是 `@v4/@v5` 浮动标签。证据：`06-ci-branch/18-pr-merge-required-check-timeline.txt`、`19-plan-vs-live-gate.log`。

---

## 8. 7789 运行身份与部署边界

### 8.1 已通过的身份对账

- launchd：`com.wenqu.dashboard`，running，PID 64211；
- 命令：`/Users/maccc/.wenqu/bin/wenqu-dashboard.py 7789`；
- listener：`127.0.0.1:7789`；
- active / worktree / `git show HEAD:system/bin/wenqu-dashboard.py` 完整 SHA256 均为：
  `72ba1db7a8e2a292ac0feff836988fc8f064a75bf421996ed2ce0247e1873ddf`；
- GET `/api/health`：HTTP 200，正文 `score=40 / 告警 / Gate=failure`。

因此第三轮“active hash 不是候选”的问题已关闭。

### 8.2 仍未关闭的控制面

- active 文件仍实现 `/api/decide` 写路由；
- 方案第一阶段要求 405 的模块化 `system/dashboard/server.py` 未被 launchd 使用；
- launchd/plist 未配置 `WENQU_DASHBOARD_KEY`，页面 fetch 也不发 `X-Auth-Key`/`X-Requested-With`；当前写面因缺配置 fail-closed，但不是可用、经授权的控制面；
- 无 read authorization、真实浏览器、`/api/build`、原子 input watermark 快照证据；
- active 是 `~/.wenqu/bin` 普通文件，不是 `~/.local/share/wenqu/releases/.../current` 不可变 release。

证据：`07-runtime/03-runtime-hash.log`、`04-health.log`、`06-control-path-static-readonly.log`、`07-plan-vs-active-dashboard.log`、`08-release-deployment-boundary.log`。

---

## 9. 追踪矩阵与专属覆盖

独立脚本未导入被验工具函数，直接解析方案 Markdown、工具 AST 字面量与 live matrix：

| 对账面 | 结果 |
|---|---:|
| §20 唯一 ID | 131 |
| §25.1 展开唯一 ID | 131 |
| 工具冻结目录 | 131 |
| live matrix | 131 |
| 重复 ID | 0 |
| 三集合差异 | 0 |
| §20 当前逐行“注入/期望”与目录差异 | 0 |
| §25.1 REQ/AC/工作包/证据类差异 | 0 |
| live 七字段差异 | 0 |
| 专属测试覆盖 | **0/131（0.0%）** |
| 代理覆盖 | 3（`GATE-02/COND-04/STATE-03`） |
| missing | 128 |

所以“131 集合等式成立”和“专属覆盖仍为 0%”必须同时表达。集合完整不等于测试实现。

受控 `evidence/traceability-matrix.json` 的 `repo_head` 仍为 `e00de144...`；本轮仓外 live 临时矩阵才绑定当前 `e4aba84...`。证据：`05-trace/10-independent-trace-audit.log`、`11-live-tool-check.log`、`independent-trace-results.json`。

---

## 10. 证据索引与实际文件对账

### 10.1 正向事实

- `evidence-index.json` 可解析，确有 14 条；14 条路径均存在；
- 历史方案/报告快照哈希与三组历史 manifest 可验真；
- live branch protection readback 与仓内 JSON 字节一致。

### 10.2 不能放行的事实

按冻结 §24.2 与第三轮同口径：

- 严格合格条目：**0/14**；
- 完整 40 位 commit：0/14；
- `artifact_sha256` 为纯 64hex：2/14；
- 11/14 至少一个必填为空；
- 4 条只指向目录；
- `repo_head_at_filing=ff050bb...`，不是当前 `e4aba84...`；
- 当前 run 37733159993、当前 HEAD、branch readback/ruleset count 未被精确索引；
- `known_gaps` 仍写 main 无保护，与 live API 冲突；
- W5/W9/W10 指定目录仍只有 README；
- 最终 release archive、SBOM、signature/attestation 为 0。

因此“更新至 14 条”在数量上属实，但不是可机器放行的当前证据链。证据：`09-review/06-evidence-index-audit.log`、`09-timing-evidence-audit.log`。

---

## 11. 已知缺口（不作为本轮新发现，但继续计分）

| 已知缺口 | 四轮状态 |
|---|---|
| 131 ID 专属测试覆盖 0% | 仍为 0/131；诚实呈现，但阻断 W1/W3/P0-10 |
| W5/W9/W10 时序证据未到期 | 仍只有 README/零索引工件 |
| 重放验封威胁模型边界 | 代码已声明同 UID/root 边界；本轮不重复记新发现 |
| 审批签发端未建 | 仍缺；且本轮另发现 ActionSaga 可在无 action 审批时提交 |
| 最终 release 制品未打包 | 仍无 tar/tgz/zip、SBOM、签名 manifest |

---

## 12. 剩余阻断项（按优先级）

1. **P0：** 用 OS 级可收拢边界修复 Runner daemon 化逃逸，并保留本轮 double-fork 负例；
2. **P0：** `reserve_action` 必须先消费、绑定、CAS 校验独立 exact action authorization；receipt 必须来自可验证外部正源；
3. **P0：** Aggregator 在判定前必须执行正式 station-v2 全 Schema 与跨字段不变量校验，schema-invalid 永不可能 PASS；
4. **P0：** 补齐 evidence/station/finding/run 的跨字段 Schema 不变量；
5. **P0：** 修复安装体 `wenquctl` 路径并将安装后真实 CLI 纳入移除锚点/required CI；
6. **P0：** 追踪 Gate 对 §20 每行语义做冻结 hash/结构化映射校验，不只比较 ID；
7. **CI：** 将 11 项对抗和 66 项基础设施测试接入不可绕过 required workflow；建立冻结命名 Gate、CODEOWNERS/review、merge_group 与 action SHA pinning；
8. **运行面：** 7789 切到模块化 405 只读服务或完成正式授权控制面，不得保持“legacy 写路由存在但 UI 永远不可用”的中间态；
9. **发布：** 修复证据索引，生成绑定当前 SHA/env/policy/ruleset 的逐文件证据与最终不可变制品、SBOM、签名/attestation；
10. **时序：** 完成 W5 reconciliation、W9 shadow/canary、W10 观察窗/回滚/备份恢复/DR。

---

## 13. 第四轮证据索引

| 目录/文件 | 内容 |
|---|---|
| `00-baseline/` | HEAD、方案/第三轮报告快照、git log/diff、隔离路径 |
| `01-probes/` | 12 项异源探针源码、逐项完整命令/输出/rc、3 次 Runner 重现、子 manifest |
| `03-workpackages/inventory.txt` | W0–W10 目录、制品、TLA/工件库存 |
| `04-mutations/` | 三移除锚点、Schema 变异、独立交叉脚本、子 manifest |
| `05-trace/` | §20/§25.1 变异、语义假绿、131 独立对账、子 manifest |
| `06-ci-branch/` | `gh run view`/API、jobs/logs/checks、branch protection、PR 合并时间线、子 manifest |
| `07-runtime/` | launchd/listener/hash/health、控制面静态核验、部署边界、子 manifest |
| `08-acceptance/` | 隔离全量 acceptance、P1c 只读性、子 manifest |
| `09-review/` | P0 新反例、回归/模块自测、证据索引/时序审计、安装/CLI、子 manifest |
| `10-final/` | 收尾源仓完整性、报告副本/哈希与总清单 |
| `EVIDENCE-INDEX.md` | 本轮机器证据入口 |
| `MANIFEST.sha256` | 本轮证据根总 SHA256 清单（排除自身） |

子目录 manifest 已逐一复算通过；总 manifest 在报告冻结后生成。

---

## 14. 最终结论

第四波不是“没有生效”：授权/事件/CAS/回滚/分支保护/运行身份等多项修复已被独立新用例确认，第三轮 12 项中 11 项关闭。

但第四波也不是“生产上线级闭环”：Runner、Action 授权、Schema/Gate、安装体、追踪语义、required CI、现役控制面、证据/制品与观察窗仍有硬阻断。

因此第四轮最终判定固定为：

# **49/100 — BLOCKED**

禁止把本报告解读为 candidate closure、CI release gate、production release 或 post-release validation 已完成。

---
title: 问渠与 Bug 管线生产级重构优化方案
version: 1.0
status: 已复审，供 ZCode 执行
generated_at: 2026-10-07T15:05:00+08:00
execution_lane: INCIDENT
current_release_decision: BLOCKED
scope: 问渠 one-shot 七段管线、Bug 八站管线、证据/账本、CI、调度、发布、7789 控制面
---

# 问渠与 Bug 管线生产级重构优化方案

> 本文件是交给 ZCode 的实施总方案，不是“整改已完成”证明。  
> 当前问渠、Bug 管线和 7789 控制面均不得用于生产放行结论；任何部署、合流、分支保护、LaunchAgent、生产 DB、外部告警或回滚动作，仍须逐项获得用户明确授权。

## 0. ZCode 必读执行约束

1. **先判现态为 `BLOCKED`，再施工。** 不得沿用页面的“87 分/良好”作为准入依据。
2. **不得直接修改现役目录** `/Users/maccc/.wenqu`、`/Users/maccc/.zcode/quality-system/bin` 或 LaunchAgent 正在引用的脚本；所有实现必须在版本化正源的独立干净 worktree 中完成。
3. **不得把本方案视为生产动作授权。** 下列动作必须停等用户逐项批准：停止/启动守护、修改 GitHub ruleset、合并、部署、生产写、DDL、真单、外部告警实发、远端备份、生产回滚。
4. **禁止继续使用自动 `--admin` 合流、L4 直推、`force-with-lease` 回滚、文本 `[skip-audit]` 绕过。** 等待时间、runner 排队、网络抖动都不是降级安全门槛的理由。
5. **先盘点并冻结并发写者。** 当前运行体在复审期间仍被外部过程热改、重启；未取得唯一 writer epoch 前，禁止迁移或切换。
6. **不得覆盖或“清理”历史 JSONL。** 旧账本只读快照、逐行哈希、旁路迁移；未知字段或状态进入 quarantine，不得猜填。
7. **同一实现者不得独自完成实现、验收和完成声明。** 守卫、CI、授权、账本、合流等 INCIDENT 级变更，末轮必须由独立上下文 S5 复核。
8. **UNKNOWN/MISSING/STALE/MALFORMED/EMPTY/TIMEOUT 均是阻断态。** 任何“无法判断”都不得折算为零发现、SKIP 或 PASS。
9. **每个工作包必须交付五件套：** 代码/配置、正反测试、证据索引、迁移或部署说明、已演练回滚报告。未演练只能写“已记录回滚路径”。
10. **不得为让 Gate 变绿而修改 Gate 规则、阈值、基线、豁免数量或证据 TTL。** 规则变更必须独立 PR、独立批准、独立对抗验证。

---

# 1. 复审结论与现场快照

## 1.1 有效评分

| 对象 | 纸面设计 | 机器执行/可信度 | 有效综合分 | 当前状态 |
|---|---:|---:|---:|---|
| 问渠 one-shot 七段管线 | 82/100 | 34/100 | **46/100** | **BLOCKED** |
| Bug 八站管线 | 82/100 | 28–55/100 | **41/100** | **BLOCKED** |
| 7789 控制面 | — | 40/100 | **40/100** | 只可作只读汇总面 |

目标不是把展示分数改成 95，而是让机器执行可信度、证据完整性和故障注入验收均达到生产级，并且消灭已知 P0/P1。

## 1.2 2026-10-07 14:59 现场事实

以下是带时点的复审快照。ZCode 开工前必须先执行 W0 重新采集；任何漂移以新 baseline 为准，不得把 14:59 数字当作永远当前。

1. `/Users/maccc/.zcode/quality-system/bin/pipeline-gatedoctor.sh` 实跑返回 **1**：
   - 活跃 EXM=6，超过熔断阈值 5；
   - `exm-next-id.sh` 预期哈希 `ecf932e8…`，实测 `aa349c5…`。
2. `http://127.0.0.1:7789/api/health` 同时返回 **87 / 良好**，本机磁盘已达 **90%**。
3. 现役自动合流器仍运行，`/Users/maccc/.wenqu/daemons/auto-merge.sh`：
   - 只按名称子串识别 Fast；
   - 忽略其他失败检查；
   - 接受 `UNSTABLE`；
   - 使用 `gh pr merge --admin`；
   - 日志持续出现 `cd: auto-merge-831: No such file or directory`，但无熔断。
4. GitHub `AIruanchao/qisemi-erp` 的 `master` 分支保护实时回读仅要求：
   - `Fast (lint+tsc)`；
   - 完整 Gate 不是 required check。
5. 两条 WAITING 已分别滞留约 21.67 天和 9.28 天，`notify_attempts=0`；`com.erp.pendingwatch` 已运行 82 次且最后退出 0，属于协议断裂后的假活。
6. Bug 账本实时汇总：481 findings、24 OPEN、4 FIXING、172 FIXED、67 VERIFIED、158 CLOSED、43 ACCEPTED、13 OTHER。
7. DB 周报把约 **至少 280 项** Prisma 结构变化判成 `19 行 / CLEAN`；且旧算法仍包含“变化行数不超过阈值即 CLEAN”的错误策略。
8. 供应链 2026-10-05 报告显示 audit 空/解析失败、verdict FINDINGS，但脚本仍刷新成功心跳并退出 0。
9. 租户扫描器硬编码 27 个模型；Schema 中直接含 `organizationId` 的模型约 193 个，遗漏约 172 个。
10. 发布正源 `/Users/maccc/Documents/wenqu-dist`：
    - `HEAD=455fa41e405c9c15b293a763e48365edf109e51a`；
    - 工作树 clean；
    - dashboard SHA256=`d20adef…`。
11. 运行体 `/Users/maccc/.wenqu/bin/wenqu-dashboard.py` 在复审期间再次被外部热改并重启：
    - 当前 SHA256=`4ace329…`；
    - 额外存在 `html-balance-lint.py`；
    - Git 正源仍未吸收该修复，重新部署仍可能回归。
12. `system/install.sh` 使用 `cp -R` 原地覆盖、不会清理幽灵文件，并以 `doctor || true` 吞掉安装自检失败。

## 1.3 本轮复验结果

正向回归：

| 验证 | 结果 |
|---|---|
| `/Users/maccc/Documents/wenqu-dist/tests/acceptance.sh` | 53 PASS / 0 FAIL，exit 0 |
| `pytest cli/test_wenqu.py` | 20 passed，exit 0 |
| `tests/release-check.sh v1.0.18 fork24` | PASS，exit 0 |

这些测试不覆盖自动合流、真实状态机、授权、dashboard DOM、LaunchAgent 真环境和证据伪造，因此不能抵消以下安全负例：

| 当前负例 | 现役结果 | 正确结果 |
|---|---|---|
| artifact `exit_code=7`，自报零发现 | verifier `ok=true` / exit 0 | BLOCKED |
| artifact 是指向目录外的 symlink | verifier `ok=true` / exit 0 | BLOCKED |
| 空 rounds + `--n -1` | verifier `ok=true` / exit 0 | 参数错误 |
| 任意 `NOT_A_STAGE/COMPLETELY_FAKE` | 成功落账 | 拒绝 |
| `task_id=../escaped` | 可写出 waiting 目录 | 拒绝 |
| 无授权 `wait-clear ../victim` | 成功删除外层 JSON | 拒绝 |
| Fast SUCCESS + Security FAILURE | 自动合流判断可为 yes | 禁止合流 |
| 不存在 base ref、零测试 | Gate 可返回“全绿/可推送” | ERROR/BLOCKED |

本轮证据包：`/private/tmp/codex-test/evidence/reaudit-20261007/`，索引为其 `manifest.sha256`。其中包含安全负向红探针、wenqu-dist 回归、health、branch required checks、运行/正源哈希、gatedoctor、waiting 和 launchctl 快照；它仍是本轮复审证据，不等同整改后的完整生产证据包。

## 1.4 结论边界

- 本轮没有停止自动合流、修改分支保护、发布、写库、点击决策、发送外部告警或触发真实生产动作。
- 外部热改和重启不是本轮复审所做。
- 方案验证的是**设计完备性、可执行性和可验收性**，不代表整改已经落地。

---

# 2. 最终目标与完成层级

## 2.1 目标

1. 问渠七段具备真实、可恢复、可审计的状态机和授权闸。
2. Bug 八站由唯一 orchestrator 执行；任一 required 站非 PASS 时整线绝不为 PASS。仅 policy 允许且仍有效的低风险接受可使 aggregate=CONDITIONAL，其余 FAIL/ERROR/BLOCKED/缺失/过期一律 BLOCKED。
3. 证据不可由调用者自报；命令、真实退出码、原始输出和工件哈希由 trusted runner 生成。
4. 合流只接受同一 head SHA 的全部 required checks，并另需 exact action authorization；不存在 admin 自动绕闸。
5. 账本具备事务、并发、崩溃恢复、幂等、状态约束和期限豁免。
6. 运行体可由 manifest 证明来自唯一正源，部署和回滚均为原子操作。
7. dashboard 只读展示权威聚合结果，永远不能比 Gate 更绿。
8. 调度、告警、备份和心跳均表达业务结果，而不是“进程执行过”。

## 2.2 四层完成语义

| 层级 | 必须满足 | 禁止使用的措辞 |
|---|---|---|
| 候选实现完成 | 代码、测试、红探针、源树 clean；未部署 | 已上线、生产完成 |
| CI 准入完成 | Required Gate 已实际配置并用测试 PR 验证 | 生产闭环 |
| 受控部署完成 | 用户授权、manifest 对账、真环境 smoke、回滚演练 | 观察完成、零盲区 |
| 发布后闭环完成 | 14 天观察、周任务两轮、强制季度演练、无假绿/漏告警/丢账 | 无限定范围的“绝对安全” |

“清零声明”还要求零有效未关闭 finding、零有效豁免；存在合法 ACCEPTED 风险时只能称“条件放行”。P0/P1 不允许风险豁免。

---

# 3. 边界、术语与正源

## 3.1 两条管线必须拆开

| 名称 | 真实语义 |
|---|---|
| 问渠 one-shot | 需求→方案→EQS 前置→实现→递归清零→EQS 全量→Gate 的七段任务管线 |
| Bug 管线 | 范围、源闸、静态供应链、契约数据、行为、实弹、对抗、运行时的八站扫描管线 |
| 7789 dashboard | 两条管线的只读控制面，不是管线本身，也不能自行制造 PASS |

UI 不得再用“问渠全流程”展示 Bug 八站动画；七段、八站、九类停等和各自 run 必须分开展示。

## 3.2 四域物理隔离

| 域 | 目标位置/所有权 | 约束 |
|---|---|---|
| 可执行核心/制品 | `wenqu-dist`；`releases/<release-id>` | runner/store/state/gate/dashboard/installer 唯一实现，manifest 校验，不得热改 |
| 策略/Skill | W0/W1 必须确认的正式 quality-policy Git 正源 | 只含受保护 policy/Skill/规则包，不复制 executable core |
| ERP 域插件 | `AIruanchao/qisemi-erp` 正源 | scanners、业务探针、CI adapter |
| 可变状态 | SQLite event store | WAL、事务、CAS、append-only 事件 |
| 证据 | content-addressed store `evidence/sha256/<digest>` | 原始输出、不可用路径名寻址、每次 Gate 重验哈希 |
| 配置/秘密 | `~/.config/wenqu`、Keychain 或 0600 文件 | 不入 argv、日志、Git、证据正文 |

`/Users/maccc/.zcode/quality-system` 目前把代码、账本、证据和实时状态混在一个长期脏工作树中，且尚未确认其正式 source repo。W0 必须冻结 quality-policy 的 `repo_id/default branch/owner/build入口/Skill源位置/安装位置/状态位置`；未确定前禁止在现役目录开发。拆分必须渐进进行，不能大爆炸搬迁。

## 3.3 集成发布身份

新增 `wenqu-release.lock.json`，至少绑定：

```text
wenqu_dist_commit
quality_policy_commit
one_shot_skill_sha256
bugscan_skill_sha256
policy_sha256
schema_version
release_manifest_sha256
```

任何一项未知、缺失或与运行体不一致时，release eligibility 必须是 `BLOCKED`。

---

# 4. 不可变安全不变量

1. `UNKNOWN/MISSING/STALE/MALFORMED/EMPTY/TIMEOUT` 一律不是 PASS。
2. 任一 required probe 的执行或策略结果非 PASS，整线不得 PASS。
3. PASS 必须绑定：`run_id + commit_sha + environment + scope_hash + ruleset_hash + data_config_hash + artifact hashes + TTL`。
4. run 起跑后 commit、环境、规则集或范围变化，旧证据立即失效并新建 run。
5. 问渠七段必须顺序推进；Bug 八站中相互独立的站应继续/并行取证。任一 required 站非 PASS 时整线绝不为 PASS；仅 policy 允许且有效的低风险接受可形成 CONDITIONAL，其余非 PASS 一律 BLOCKED。禁止因早站失败而形成后续扫描盲区。
6. WAITING 只能由规定停等事件产生；无有效一次性授权不得 resume。
7. 审批不能复用、扩范围、跨 SHA、跨环境或跨状态版本。
8. release/merge/prod-write 只能消费 exact-scope 的有效授权事件。
9. 所有控制事件只追加；不得删除历史，纠错使用 supersede/reopen 事件。
10. 相同 idempotency key 重放不得造成第二次副作用。
11. evidence 不得是 symlink、外部路径、空文件或无哈希文件。
12. findings 数量从解析后的 finding list 计算，不信任 `findings/content_findings` 自报数字。
13. 只有 trusted runner 实际捕获的退出码有效。
14. dashboard 只能等于或比权威聚合器更保守，绝不能更绿。
15. 自动合流不拥有 admin/bypass 能力；异常时退化为关闭和人工受保护 PR，而不是绕闸。
16. 只有同一实体身份、同一输入指纹、仍在 TTL 内的 `execution_status=COMPLETED && policy_verdict=PASS` 才能刷新该 probe/station/job 的 `last_success`；N/A、CONDITIONAL、FAIL、ERROR、BLOCKED、TIMEOUT、CANCELLED 均不得刷新。心跳必须包含结果和证据身份。
17. P0/P1 未清、有效 required evidence 过期或 runtime 漂移时禁止生产放行。
18. 历史迁移必须数量守恒：源非空行数 = 有效导入 + 重复说明 + quarantine。

---

# 5. 威胁模型与最小可信基

## 5.1 保护资产

- 合流与发布正确性；
- 人类授权不可伪造、不可重放、不可扩范围；
- 账本/证据完整性和断电耐久；
- 租户隔离、资金/权限业务不变量；
- 健康呈现真实性；
- source/runtime 身份一致；
- 告警端到端可达与可确认；
- 回滚不丢失切换后的新事件。

## 5.2 故障与攻击源

- 恶意 PR 内容、伪造 check 名、旧 SHA 绿灯、PR 自改 workflow；
- localhost 恶意网页、CSRF、日志/账本 XSS 注入；
- 同 UID 并发 agent、人工误操作、运行体热补；
- GitHub/npm/registry/SSH 返回空、部分数据、限流或超时；
- launchd 的 PATH、HOME、TCC 与交互 Shell 不一致；
- 磁盘满、只读目录、kill -9、断电、时钟跳变、PID 复用；
- parser 未识别新格式、扫描范围静默缩小；
- 迁移双写、两个 writer epoch、回滚覆盖新事件。

不声称抵御 root/物理控制权丢失、GitHub 组织 owner 被完全攻陷或硬件级攻击；这些必须在最终风险边界中明示。

## 5.3 最小可信基 TCB

```text
scanner/plugin
  └─只产原始输出
trusted runner
  └─捕获 argv/cwd/真实 rc/timeout/stdout/stderr/hash
schema normalizer
  └─严格验证并生成 typed result
independent gate aggregator
  └─校验身份、TTL、required 集合、状态和证据哈希
merge/release controller
  └─动作前同时重验 technical_eligible 与 exact action authorization；两者缺一均不动作
dashboard
  └─只读展示，不写 Gate、不自算放行
```

禁止“扫描脚本自己写 PASS/心跳，再由同目录脚本统计为健康”的循环自证。Gate aggregator 必须是小型、只读、依赖最少的独立组件，并接受变异测试。

---

# 6. 目标数据与状态模型

## 6.1 统一结果双轴

```text
execution_status = COMPLETED | ERROR | BLOCKED | TIMEOUT | CANCELLED
policy_verdict   = PASS | FAIL | CONDITIONAL | NOT_APPLICABLE | NOT_EVALUATED
aggregate_outcome = PASS | CONDITIONAL | BLOCKED
```

- `COMPLETED+NOT_APPLICABLE` 只能由受保护 policy 的 applicability rule 生成；人工文字不能生成 N/A。
- FINDINGS 表示 `COMPLETED+FAIL`，不是 execution status。
- CONDITIONAL 不等于 PASS：无独立有效 risk authorization 时 technical eligibility=false；即使 risk authorization 有效，无 exact action authorization 也不得执行受保护动作。
- **站级语义：** required station 只有 `COMPLETED+PASS` 才是 station PASS；CONDITIONAL 不得改写成 PASS，也不得计入“全站 PASS”。
- **内部聚合语义：** 存在 policy 允许的低风险 `ACCEPTED_RISK` 时，aggregate 仍为 CONDITIONAL；未授权时 CLI 返回 exit 4，GitHub required context 发布 failure/blocked，自动合流不得消费。
- **机器谓词分层：** `technical_eligible := exact_sha_pass OR (aggregate=CONDITIONAL AND valid_risk_authorization AND valid_conditional_attestation)`；`action_eligible := technical_eligible AND valid_exact_action_authorization`。普通 PASS 只证明技术条件，不授予 merge/release/prod-write/DDL 权；所有受保护动作都必须额外具备 exact action authorization。
- **唯一条件放行路径：** 所有非接受项均 PASS，且 approval broker 签发绑定完整 finding 集合和失效域的 risk authorization 后，aggregator 可铸造 `AUTHORIZED_CONDITIONAL` attestation。内部 aggregate、详情页和 dashboard 仍保持琥珀色 CONDITIONAL，不得显示 PASS；P0/P1 永不适用。risk authorization 与 action authorization 是两个判别类型；可由同一个人类批准包同时签发，但必须分别校验、分别消费。
- **Check 映射：** PASS→`success/PASS`；未获 risk authorization 的 CONDITIONAL→`failure/CONDITIONAL_BLOCKED`；合法条件态→`success/AUTHORIZED_CONDITIONAL`；BLOCKED/ERROR/STALE→failure。任何绿色 context 只表达 technical eligibility，不等于动作授权；另一个 `Action Authorization Gate` 只在 exact action authorization 有效时对对应 SHA/action 成功。
- **控制器消费：** merge/release controller 在动作前重新计算 `action_eligible`。CONDITIONAL 时禁用 native auto-merge；PASS 路径也只能由已经审计的人类精确 enqueue 事件或专用最小权限 App 触发。仓库角色/ruleset 必须禁止其他人或 bot 仅凭绿色 context 直接合流；break-glass 另走一次性审计路径。
- 新 finding、finding 集合变化、证据/接受到期、SHA/scope/environment/policy/ruleset/input watermark/state_version 变化或签名密钥吊销，必须在本地立即将 authorization/attestation 判无效并写入失败更新 outbox。即使 GitHub 暂时失联而保留陈旧绿色 context，专用 App 仍会因动作前重验失败而拒绝，其他主体也无直接合流权限。

跨 SQLite 与 GitHub/发布系统禁止宣称 ACID“同一事务”。必须实现 durable saga/outbox：

1. 本地事务原子写入 `RISK_AUTH_CONSUMED + ATTESTATION_CREATED + CONTROL_OUTBOX`，dispatcher 用幂等键创建/更新 check，并回写外部 `check_run_id/revision`；
2. 动作事务原子写 `ACTION_AUTH_RESERVED + ACTION_STARTED + CONTROL_OUTBOX`，随后用 expected-SHA、merge-group SHA 或 deployment fencing token 调外部动作；
3. 收到可验证回执后写 `ACTION_COMMITTED`；超时、崩溃或回执丢失写 `ACTION_FAILED_UNKNOWN`，恢复器必须先查询 GitHub/部署事实再裁定，绝不盲重试；
4. 若已证明外部未发生，则旧授权作废，必须重新授权；若外部已发生，则补记 COMMITTED，不产生第二次副作用；
5. dispatcher 的 crash-before/after-publish、controller 的 crash-before/after-action 与回执丢失均须故障注入。

统一退出码：

| 退出码 | 含义 |
|---:|---|
| 0 | 执行完成且策略 PASS |
| 1 | 执行完成但有 FINDINGS/FAIL |
| 2 | 工具、输入、网络、格式或证据 ERROR |
| 3 | 权限、审批或依赖 BLOCKED |
| 4 | CONDITIONAL，必须存在合法限时风险接受 |
| 124 | TIMEOUT |

只有 `COMPLETED + PASS` 可计 **station required PASS**；`AUTHORIZED_CONDITIONAL` 是独立的显式授权出口，永远不改名为 PASS。

## 6.2 问渠状态机

七段：

```text
S1_REQUIREMENT → S2_SOLUTION → S3_EQS_PRE → S4_IMPLEMENT
→ S5_CONVERGENCE → S6_EQS_FULL → S7_GATE
```

总状态：

```text
CREATED | RUNNING | WAITING | FAILED | SUCCEEDED
| COMPLETED_CONDITIONAL | CANCELLED | SUPERSEDED
```

段状态：

```text
PENDING | RUNNING | PASSED | COMPLETED_CONDITIONAL
| FAILED | WAITING | CANCELLED
```

整段不得用豁免伪造 PASSED。`COMPLETED_CONDITIONAL` 仅允许用于 S7，且永远不等于 PASSED。S1_REQUIREMENT、S7_GATE 和 required 安全检查永远不可整段豁免；N/A/风险接受只作用于 policy 明确允许的非关键子检查，并令整线进入 CONDITIONAL。

### 6.2.1 九类停等与恢复充分条件

统一前提：**九类 WAITING 的恢复都必须同时具备**（a）绑定当前 `stop_event_id/state_version/scope/SHA/environment` 的一次性人类授权，（b）下表客观前置。只有批准没有客观恢复，或只有客观恢复没有一次性批准，均不得 resume。

| # | stop_type | 恢复的必要且充分条件 |
|---:|---|---|
| 0 | `ambiguity` | 一次性授权 + 新需求四要素与 scope hash 冻结；泛化“批准继续”不够 |
| 1 | `prod-write` | 一次性 exact-scope 授权 + 对应前置 Gate + 回滚级别 |
| 2 | `ddl` | 一次性 exact DDL/环境授权 + fresh/legacy/minimal/回滚验证 |
| 3 | `release` | 一次性 exact release/SHA/env 授权 + Gate/manifest/回滚预案 |
| 4 | `scope` | 一次性新 scope 授权 + 风险、required 集和证据重新冻结 |
| 5 | `fund-auth` | 一次性资金/权限授权 + 正负测试 + 守恒/审计 |
| 6 | `exm-fuse` | 一次性裁定授权 + 实际解除熔断或完成独立治理裁定；批准不能伪造健康 |
| 7 | `resource` | 一次性恢复授权 + 资源探针恢复并满足安全余量；批准不能替代容量/锁恢复 |
| 8 | `ext-unavail` | 一次性恢复授权 + 外部依赖健康探针恢复并重验证据新鲜度 |

STOP-01～03 必须逐类型验证：九类全部覆盖“客观条件已恢复但无授权仍拒绝”“有授权但客观条件未恢复仍拒绝”“错误类型/旧版本/重放审批仍拒绝”。

### 6.2.2 允许转换

Run：

```text
CREATED → RUNNING | CANCELLED
RUNNING → WAITING | FAILED | SUCCEEDED | COMPLETED_CONDITIONAL | CANCELLED | SUPERSEDED
WAITING → RUNNING | FAILED | CANCELLED | SUPERSEDED（恢复须满足 §6.2.1）
FAILED/SUCCEEDED/COMPLETED_CONDITIONAL/CANCELLED/SUPERSEDED 为 run 终态；需继续时必须新建 run_id
```

Stage attempt：

```text
PENDING → RUNNING | CANCELLED
RUNNING → PASSED | COMPLETED_CONDITIONAL | FAILED | WAITING | CANCELLED
PASSED/COMPLETED_CONDITIONAL/FAILED/WAITING/CANCELLED 均是该 attempt 的不可变终态
```

重试或 WAITING 恢复时，不改变旧 attempt；先追加 `ATTEMPT_CREATED(parent_attempt_id=...)`，新 attempt 从 PENDING→RUNNING。stage projection 可由 WAITING/FAILED 投影为 RUNNING，但必须指向新 attempt_id。commit/SHA、scope、environment、policy 或 ruleset 变化强制新 run；任何恢复不得覆盖旧 attempt 或旧证据。

### 6.2.3 七段结果与 run/aggregate 的唯一映射

| 情形 | 当前 stage attempt | run projection/终态 | aggregate/technical | 是否可做外部动作 |
|---|---|---|---|---|
| S1～S6 前一段非 PASSED | 不得启动下一段 | 保持 WAITING/FAILED | BLOCKED / false | 否 |
| S1～S6 当前段 WAITING | WAITING（终止该 attempt） | WAITING | BLOCKED / false | 否 |
| S1～S6 当前段 FAILED，且不再重试 | FAILED | FAILED | BLOCKED / false | 否 |
| S1～S6 当前段 PASSED | PASSED | RUNNING，并创建下一段新 attempt | 尚未终判 | 否 |
| S7 聚合 PASS | PASSED | SUCCEEDED | PASS / true | 仍须 exact action authorization |
| S7 聚合 CONDITIONAL，risk authorization 缺失/失效 | FAILED | FAILED | CONDITIONAL / false | 否；后续风险接受必须创建新 run，不得伪造九类 WAITING |
| S7 聚合 CONDITIONAL，risk authorization 与 attestation 有效 | COMPLETED_CONDITIONAL | COMPLETED_CONDITIONAL | CONDITIONAL / true | 仍须独立 exact action authorization |
| S7 聚合 BLOCKED/ERROR/缺失/过期 | FAILED；仅明确可恢复 stop 可用 WAITING | FAILED 或 WAITING | BLOCKED / false | 否 |

S7 内部只消费 S1～S6 和 Bugscan Gate，外部 `Wenqu Required Gate` 是其输出。`SUCCEEDED` 仅表示七段编排以 exact PASS 完成，不代表已合流、已发布或已部署；`COMPLETED_CONDITIONAL` 更不得投影成 SUCCEEDED。动作结果进入独立 action/deployment saga。

### 6.2.4 部署状态机

```text
BUILT → VERIFIED → STAGED → BACKUP_VERIFIED → EXPANDED → ACTIVATING → ACTIVE
ACTIVATING → ROLLBACK_PENDING（失败且存在匹配的预授权回滚）
ACTIVATING → FAILED_BLOCKED（失败且无匹配预授权；等待人类处置）
ACTIVE → ROLLBACK_PENDING（匹配预授权或新的精确回滚授权）
ROLLBACK_PENDING → ROLLED_BACK | ROLLBACK_FAILED
BUILT/VERIFIED/STAGED/BACKUP_VERIFIED/EXPANDED → FAILED_BLOCKED
```

`BACKUP_VERIFIED` 表示一致性 checkpoint 已完成恢复抽验；`EXPANDED` 只允许已授权、幂等、前后兼容的 additive migration。`ROLLED_BACK` 为成功回切终态；`FAILED_BLOCKED`、`ROLLBACK_FAILED` 都是硬阻断终态，必须保留 current/现场、熔断 writer/合流/后续发布并停等用户，不得继续自动尝试。每次转换绑定 `deployment_id/release_id/previous_release_id/schema_version/writer_epoch/migration_lock_id/backup_id/authorization_id/state_version/evidence`。部署状态独立于任务 run 状态；destructive contract migration 使用独立状态机和独立后续授权，不得夹带在本次激活中。

必须用 TLA+/TLC 穷举：

```text
NoStageAdvanceWithoutPriorStagePass
NoResumeWithoutApproval
NoMergeOrReleaseUnlessActionEligible
ApprovalCannotBeReused
ApprovalCannotWidenScope
SingleActiveWriterEpoch
ReplayIsIdempotent
WaitCannotDisappearSilently
MergeUsesExactHeadSha
EvidenceCannotMutateUndetected
AuthorizedConditionalCannotBeReplayed
```

## 6.3 Finding 状态机

```text
OPEN → FIXING → FIXED_PENDING_VERIFY → VERIFIED → CLOSED
```

风险接受分支：

```text
OPEN/FIXING/FIXED_PENDING_VERIFY/VERIFIED → ACCEPTED_RISK
ACCEPTED_RISK → RISK_REVOKED | RISK_INVALIDATED
RISK_REVOKED/RISK_INVALIDATED → OPEN → FIXING → FIXED_PENDING_VERIFY → VERIFIED → CLOSED
CLOSED 再现 → OPEN
```

- CLOSED 只能来自 VERIFIED；
- 现有 `FIXED` 迁移为 `FIXED_PENDING_VERIFY`，不能视为关闭；
- `OTHER`、自由文本和非法转换全部 quarantine 并阻断；
- ACCEPTED_RISK 必须含批准人、理由、精确范围、补偿控制和到期时间；
- 主动撤销，或 fingerprint、severity、policy/ruleset、scope、补偿控制、证据集合、环境任一变化，均追加 `RISK_REVOKED`/`RISK_INVALIDATED` 事件并立即重开；风险负责人可随时从重开后的 OPEN 进入正常修复链，历史接受事件不得覆盖或删除；
- P0/P1 不允许 ACCEPTED_RISK。

## 6.4 SQLite 事件正源

核心表：

```text
runs
stage_attempts
station_attempts
events
approvals
artifacts
findings
finding_events
risk_acceptances
convergence_rounds
notification_outbox
control_outbox
action_attempts
alert_deliveries
sentinel_runs
release_deployments
legacy_quarantine
```

强制设置：

- WAL、`foreign_keys=ON`、`synchronous=FULL`；
- `BEGIN IMMEDIATE`；
- unique idempotency key；
- optimistic `state_version`/CAS；
- events 表 trigger 禁止 UPDATE/DELETE；
- 状态事件与通知 outbox 同事务提交；
- `prev_event_hash/event_hash` 形成链；
- JSONL 仅从 DB 生成只读兼容投影。

## 6.5 审批事件

审批采用 `action/stop_type` 判别联合，而不是让所有类型携带无意义的 PR 字段。公共 envelope 最少包含：

```text
approval_id, approval_type, run_id, task_id, stop_event_id, stop_type, stage,
environment, authorized_scope, policy_hash, ruleset_hash, input_watermark,
actor, issued_at, expires_at, expected_state_version,
nonce, decision, signature
```

判别 payload 至少为：

```text
resume:     stop_event_id + stop_type + objective_precondition_hash
risk:       finding_fingerprints + severity + reason + compensating_controls + expiry
merge:      repo_id + base_sha + PR + head_sha/merge_group_sha + merge_method
release:    release_id + artifact_sha256 + manifest_sha256 + environment + previous_release_id
ddl:        database_identity + statement_digest + before/after_schema_hash + backup_id + rollback_plan_hash
prod_write: operation_digest + data_scope_digest + idempotency_key + conservation/compensation_hash
fund_auth:  subject/role/amount_scope_digest + positive_negative_test_hash + audit_target
rollback:   failed_deployment_id + exact_previous_release_id + trigger + schema_compatibility_hash
```

resume 与本地审批消费必须同事务；外部动作按 §6.1 durable saga 处理。过期、重复、错误 actor、错误 scope、错误 SHA/环境、旧版本或 payload 与 discriminator 不符全部拒绝。第一阶段关闭 dashboard 写接口，仅允许受控 CLI/broker 写入。

## 6.6 可信证据

每份证据最少绑定：

```text
evidence_id, run_id, task_id, stage/station, attempt_id,
repo_id, commit_sha, base_sha, environment, scope_hash,
ruleset_hash, data_config_hash, lockfile_hash,
runner_id/version, tool_name/version/digest,
argv_digest, cwd_digest, started_at, finished_at,
actual_exit_code, stdout_sha256, stderr_sha256,
artifact_sha256, artifact_size, verdict, fresh_until
```

runner 必须以 argv 数组启动命令，实际 waitpid 捕获退出码；以 `O_NOFOLLOW/lstat/realpath` 拒绝 symlink、非普通文件和根外路径；原始输出复制进 CAS 后 fsync，再写 manifest。调用者不得填写实际退出码或总 findings。

`fresh_until` 由受保护 policy 按 `trusted_finished_at + policy_ttl` 计算，调用者和工件不得自行声明。Aggregator 每次读取都必须动态判断 evidence、ACCEPTED_RISK、EXM 是否过期；reopen/expiry scheduler 仅用于修正投影和通知，不能成为过期失效的唯一防线。

时间证据统一 UTC aware timestamp，并记录 boot ID/clock health。检测到时钟回拨、来源不可信或偏差超策略阈值时，Gate 为 UNKNOWN/BLOCKED。

负向测试必须区分：

```text
actual_exit_code     = 被测命令真实退出码
expected_exit_set    = 该测试允许的内层退出码集合
assertion_verdict    = 测试 harness 对行为是否符合预期的判断
```

不能粗暴规定所有内层命令都必须 exit 0；例如“越权请求应被拒绝”的负例可以有非零内层退出码，但外层断言器必须 PASS。Gate 只消费 harness 的可信判定及其原始证据。

---

# 7. 总体架构

```text
┌────────────────── 唯一版本化正源 ──────────────────┐
│ wenqu-dist：唯一 executable core/安装器/dashboard/gate   │
│ quality-policy 正式仓（W0确认）：Skill/policy/规则包       │
│ qisemi-erp：ERP 域 scanners、CI adapter、业务探针          │
└─────────────────────────┬──────────────────────────┘
                          │ build + manifest + tests
                          ▼
                 releases/<release-id>/
                          │ atomic current switch
                          ▼
┌─────────────── 可信执行与控制平面 ──────────────────┐
│ planner → trusted runner → strict normalizer          │
│                  │                                    │
│                  ├─ CAS evidence                      │
│                  └─ SQLite append-only event store    │
│                             │                         │
│             independent gate aggregator               │
│                    │                    │              │
│          merge/release controller       outbox/watch   │
└────────────────────┼────────────────────┼──────────────┘
                     ▼                    ▼
              protected Git flow       alert provider
                     │
                     ▼
             dashboard read-only API
```

## 7.1 Bug 八站唯一入口

实现统一命令面：

```text
bugscanctl plan
bugscanctl run
bugscanctl resume
bugscanctl status
bugscanctl verify
bugscanctl reconcile
bugscanctl migrate-ledger
bugscanctl doctor
```

PR、人工执行、launchd、dashboard、CI 均只能调用该入口，不允许脚本自行定义退出码、心跳或完成语义。

每轮先冻结 `run-manifest.json`，再运行：

| 站 | 目标内容 | required 证据 |
|---|---|---|
| 0 范围冻结 | 项目、SHA、风险、范围、规则、数据配置、required 站集合 | 五元指纹+定级依据 |
| 1 源闸 | Fast、Full Gate、OpenAPI、org guard、反证、rebase、合并身份 | exact-SHA checks |
| 2 静态/供应链 | SAST、重复、依赖漏洞、lock、SBOM、安装脚本、来源策略 | 原始 JSON/SBOM/规则哈希 |
| 3 契约/数据 | API、权限矩阵、DB 四轨语义对账、迁移 fresh/legacy | canonical catalog diff |
| 4 行为 | E2E、真实浏览器、空态/失败态、业务断言 | trace/截图/DB 断言 |
| 5 实弹 | 授权后的真单或沙箱链、幂等、补偿、清理 | 授权+前后状态 |
| 6 对抗 | S3/S5、属性、变异、并发、乱序、越权 | 独立证据源工件 |
| 7 运行时 | 哨兵、SLO、告警触达 | 不计收敛轮，但可阻断发布 |

风险只允许自动升档。任何降档都必须记录风险负责人、理由、范围和到期时间。

## 7.2 每站统一结果

```json
{
  "schema_version": "2.0",
  "run_id": "...",
  "station_id": 3,
  "attempt_id": "...",
  "execution_status": "COMPLETED",
  "policy_verdict": "PASS",
  "identity": {
    "project_id": "AIruanchao/qisemi-erp",
    "commit_sha": "...",
    "environment": "staging",
    "scope_hash": "...",
    "ruleset_hash": "...",
    "data_config_hash": "...",
    "lockfile_hash": "..."
  },
  "tool": {"name": "db-drift", "version": "...", "digest": "..."},
  "execution": {
    "argv_digest": "...",
    "cwd_digest": "...",
    "started_at": "...",
    "ended_at": "...",
    "timeout_s": 300,
    "actual_exit_code": 0,
    "expected_exit_set": [0],
    "assertion_verdict": "PASS"
  },
  "coverage": {"denominator": 193, "scanned": 193},
  "finding_ids": [],
  "artifacts": [{"cas_digest": "sha256:...", "size": 1234}]
}
```

---

# 8. 实施依赖图

```text
W0 现场快照与危险面隔离
 └─W1 契约/Schema/威胁模型/TLA/红探针
    └─W2 trusted runner + event store + 授权 + CAS
       ├─W3A exact-SHA 源闸基础件
       │   └─W6A 八站 planner/registry/站0/站1适配
       │       ├─W6B 站2 静态与供应链
       │       ├─W6C 站3 契约与数据
       │       └─W6D 站4～7 行为/实弹/对抗/运行时
       ├─W5 旧账本迁移 dry-run/状态裁定
       └─W7A 原子发布框架/运行布局

W3A+W6A+W6B+W6C+W6D ───→ W3B 聚合/convergence/Required contexts/merge
W2+W3A+W6A～W6D+W7A ─────→ W4 scheduler/outbox/watchdog
W2+W3B+W5+W6A～W6D+W7A ──→ W8 dashboard/控制面/最终投影接线
W3B+W4+W5+W6A～W6D+W7A+W8 → W7B 最终集成制品
W7B ──→ W9 shadow/canary/受控切换
       └─W10 14 天观察、回滚演练与战训收官
```

W3A/W4 框架/W7A 可在冻结契约后并行开发；W3B 必须等待 W3A 与 W6A～W6D 的真实结果契约完成。W8 在 W7A 的布局中完成 dashboard 与迁移投影接线，W7B 才把包括 W8 在内的全部组件打成最终候选。最终制品、启用、接线和切换必须满足上述真实数据依赖。W3A 只产生可验证的源闸原语，不发布最终 required context；W3B 才是八站聚合和合流控制器，因此不存在 W3↔W6A 自依赖。

禁止逆序施工：

- dashboard 不得先于权威 aggregator；
- 迁移不得先于 schema；
- 自动合流不得先于 Gate；
- branch protection 不得在聚合检查尚未稳定前错误放宽；
- RLS 属于独立高风险 DDL 增强，不是本次整改暗含的必交项。

---

# 9. 工作包 W0：现场快照与危险面隔离

## 9.1 目标

在不破坏现有状态的前提下，建立可恢复基线并切断继续制造不可信合流、写入和“良好”声明的通道。

## 9.2 依赖与禁止并行项

- 无前置依赖。
- 未完成 writer 盘点和快照前，禁止 W5 迁移、W7 部署、任何生产配置修改。
- 当前 gatedoctor 已红，修管线必须走显式 maintenance lane；不得临时改绿 gatedoctor。

## 9.3 动作

1. 建立只读 baseline bundle：
   - 所有相关 Git HEAD、status、remote；
   - runtime、正源、Skill、policy、plist、crontab、脚本 SHA256；
   - 进程 PID/命令/启动时间/打开文件；
   - branch protection/ruleset JSON；
   - JSONL/SQLite/waiting/EXM/日志逐文件哈希；
   - 磁盘、权限、TCC、launchctl 状态。
2. 为所有写者建立 inventory：写入对象、锁、调度、凭据、owner、是否可停。
3. 保存运行体热补 diff；逐项审查后再进入正源，禁止把整个 runtime 反向覆盖 Git。
4. 建立 maintenance authorization：绑定范围、TTL、允许动作，明确禁止生产合流和生产写。
   - 仅允许方案所列代码仓、路径和离线测试动作；
   - 不得在同一 PR 同时修改 maintenance policy 和受保护实现；
   - 禁止 merge、部署、生产写、规则降级和基线抬升；
   - 需要用户授权、独立 S5、独立事件账本和到期自动关闭。
5. **经用户明确授权后**：
   - 停止并卸载旧 auto-merge 调度；
   - 撤销该进程可用的 admin/bypass 凭据；
   - 暂停 dashboard `/api/decide` 写入；
   - 将“87/良好”标记为算法失效、不得用于准入；
   - 暂停文本 `[skip-audit]` 绕过。
6. 本机磁盘 90%：先做只读空间归因；任何删除、压缩、迁移日志或证据须另行批准并保留校验清单。
7. 确认 quality-policy/quality-system 的正式 `repo_id/default branch/owner/build/安装/状态` 边界；无法确认时 W2 以后保持 BLOCKED。

## 9.4 出口/DoD

- baseline bundle 有 manifest 和总 SHA；
- 已识别所有 code/state/evidence/config/secret writer；
- 运行态和静态扫描均证明旧自动合流无法继续执行；
- 进程不再拥有 admin/bypass token；
- dashboard、CLI、Gate 对外统一显示 BLOCKED；
- 无现有状态、日志或脏改动被覆盖。
- maintenance lane 机器策略已证明不能合流、部署或生产写；quality-policy 唯一正源已确认。

## 9.5 证据

```text
evidence/W0/baseline-manifest.json
evidence/W0/processes.txt
evidence/W0/branch-protection-before.json
evidence/W0/runtime-source-diff.patch
evidence/W0/writer-inventory.json
evidence/W0/containment-verification.json
```

## 9.6 回滚

危险自动化的回滚目标只能是“保持关闭、人工受保护流程”，不得恢复旧 auto-merge、admin bypass 或假绿健康算法。

## 9.7 停等点

停止进程、卸载调度、撤销凭据、改 branch protection、改 live dashboard 均须用户逐项授权。

---

# 10. 工作包 W1：契约、Schema、威胁模型、TLA 与红探针

## 10.1 产物

```text
docs/specs/wenqu-vNext-contract.md
docs/specs/bugscan-v2-contract.md
docs/security/threat-model.md
docs/adr/ADR-001-event-store.md
docs/adr/ADR-002-approval-security.md
docs/adr/ADR-003-trusted-runner.md
schemas/run-event-v2.schema.json
schemas/station-result-v2.schema.json
schemas/finding-event-v2.schema.json
schemas/evidence-v2.schema.json
schemas/approval-v2.schema.json
schemas/health-v2.schema.json
policies/default-policy.yaml
specs/WenquPipeline.tla
specs/WenquPipeline.cfg
docs/traceability/REQ-AC-IMP-TEST-EVID.md
tools/check-governance-consistency.py
tests/red_probes/
```

治理文档必须由同一 machine registry/schema 生成或校验，修复当前漂移：

- one-shot front matter 写“八类”但正文实际九类，以及“正式现役”与当前 BLOCKED 冲突；
- one-shot 的 L4 直推/force-with-lease 绕闸规则；
- bug skill front matter v1.6 与正文 v2.0 不一致；
- “7 项”实际 12 项；
- fork8/36 项验收与现役 fork24/53 不一致。

`DOC-*` 红探针必须在 CI 阻断版本、枚举、数量、状态和实际 registry 不一致。

## 10.2 必须冻结的契约

- 七段、八站、九类停等的唯一枚举；
- 执行状态、策略结果、进程退出码；
- Finding 与 ACCEPTED_RISK 状态转换；
- required 证据字段和 TTL；
- 风险分级、不可豁免级别；
- exact-SHA 合流条件；
- 审批 actor、scope、nonce、有效期和消费规则；
- heartbeat、alert、backup、deployment 结果 envelope；
- 兼容版本和迁移策略。
- `severity` 与 `priority` 分离：默认 `CRITICAL→P0`、`HIGH→P1`；资金、权限、租户、数据损坏、合流绕闸可由版本化 policy 升级；自动流程不得降级；P0/P1 不得风险接受。
- CONDITIONAL 默认 technical eligibility=false。只有独立 risk authorization 精确绑定 finding 集、severity、理由、补偿控制、scope/environment/policy/ruleset/input watermark/state_version/TTL 后，才能铸造 `AUTHORIZED_CONDITIONAL` attestation；任何 merge/release/prod-write/DDL 仍需另一个对应判别 payload 的 exact action authorization。两类授权分别校验、分别消费；required context 必须显式标注条件放行，任一机制未完整落地时不得动作。
- 必需漏洞源、辅助源、离线快照签名者和 TTL，以及单源不可用时的状态。
- 性能 endpoint 分母、并发、预热、最小样本/时长、p95/p99/错误率/吞吐与相对退化阈值、baseline 晋升审批。
- check freshness、evidence TTL、scheduler due window 和 catch-up 规则的具体机器参数。
- RPO/RTO 数值：本机已提交事件与 outbox 默认目标 RPO=0，恢复 RTO 由项目冻结（建议不高于 30 分钟），offsite RPO 由数据敏感度和授权决定；未冻结、未实测不得进入 W9。

## 10.3 验收

- JSON Schema 对所有示例和反例给出确定结果；
- 无自由 status、无未定义转换、无“有字段即可 PASS”的弱约束；
- TLC 在约定状态空间内零 invariant violation；
- 威胁→控制→测试逐项映射，无孤立威胁；
- 需求→AC→实现点→测试→证据全部双向可追踪；
- 所有当前假绿先在旧实现下复现并留证，再锁为新实现回归门。

## 10.4 回滚

Schema 在观察期采用 expand/contract；新字段先 additive，旧 reader 保持兼容。禁止用回滚删除已写事件或缩小验证规则。

---

# 11. 工作包 W2：Trusted Runner、事件账本、授权与 CAS

## 11.1 推荐实现边界

以下路径均为**建议落在 `/Users/maccc/Documents/wenqu-dist` 仓内的相对路径**；W1 ADR 必须先冻结 owner repo、默认分支、owner、build 入口和安装目的地。若 W0 找到已有正式 quality-policy 正源，可将 policy/Skill 移入该仓，但 executable core 只能有一份，禁止两仓复制同名实现。

```text
system/wenqu_core/models.py
system/wenqu_core/store.py
system/wenqu_core/state_machine.py
system/wenqu_core/approvals.py
system/wenqu_core/runner.py
system/wenqu_core/evidence.py
system/wenqu_core/outbox.py
system/bin/wenquctl
```

Shell 只允许作为薄入口，不再承担状态、JSON 拼接、授权和聚合逻辑。

## 11.2 实现要求

1. 命令基于目标 commit 的不可变源快照执行；需要 npm install/build/test 写入时使用独立 ephemeral overlay/scratch 或一次性隔离 worktree，结束后验证源内容未变化，禁止复用共享脏仓。
2. argv 数组、cwd、env allowlist、timeout、资源限额均冻结并入证据。
3. runner 捕获真实退出码和原始 stdout/stderr；normalizer 只消费 runner 记录。
4. CAS 写入使用私有临时文件、fsync、原子 rename；拒绝链接和根外路径。
5. SQLite 写入使用事务、幂等键和 CAS；状态与 outbox 原子提交。
6. `wait-clear` 改为追加 `RESUMED/CLOSED/SUPERSEDED` 事件，永不删除历史。
7. 当前两条 stale WAITING 必须逐条读取最新任务状态，由用户裁定；不得脚本自动关闭。
8. hash chain 只宣称 tamper-evident，不宣称抵御同 UID/root 修改；checkpoint 应锚定到独立只读位置或远端受控存储。
9. SQLite 备份使用 backup API 或 `VACUUM INTO` 一致性快照，禁止直接拷贝 DB/WAL 后声称可恢复。
10. W1 必须冻结 runner 后端：优先专用低权限账号上的 ephemeral VM/container；默认无 Keychain、无 SSH agent、无生产凭据、网络 deny-by-default，repo/state/CAS 按最小权限挂载，并限制 CPU、内存、进程数、输出/文件大小。
11. timeout/cancel 必须终止完整 process group/cgroup，验证无子孙进程、后台写者或 fork bomb 残留。

## 11.3 验收矩阵

- 100 writer × 100 events：零丢失、零重复、唯一序列；
- 事务前/中/后 kill -9：恢复后要么全提交、要么全无；
- 任意非法转换、任意自由 status、路径字符、NUL、超长 ID 均拒绝；
- 无授权、过期授权、重复授权、错误 scope、旧 version、错误 SHA/env 均拒绝；
- approval 消费与 resume 原子一致；
- evidence 改字节、替换 symlink、hardlink、截断、空文件均阻断；
- 磁盘满、只读、时钟回拨、进程重放、outbox provider 失败均不丢事件；
- 从 events 全量重放得到的投影与在线投影完全相同；
- 一致性备份恢复演练通过并校验 hash chain。

## 11.4 出口/DoD

- 旧 `pipeline-state.sh` 只能调用新核心或进入只读兼容模式；
- 不再通过路径拼接 task ID；
- pending-watch 消费 versioned JSONL/API，不解析空格文本；
- malformed 行使本轮 ERROR，不得静默 continue；
- 通知 attempt、delivery、acknowledgement 分开计数。

## 11.5 回滚

观察期内 DB migration 只 additive。切换后如果已有 v2 新事件，只允许回滚到兼容 v2 的二进制或前向修复，禁止恢复旧快照覆盖新事件。

---

# 12. 工作包 W3A/W3B：源闸基础件、聚合、收敛、合流与 CI

依赖边界必须在代码、包和 CI job 上物理拆开：

- **W3A（源闸基础件，依赖 W2）：** 实现 §12.2 的 fresh base 获取、merge-base/diff、affected/full test 执行、真实 rc 捕获、exact-SHA/provenance 校验和规范化 `source-gate-result.json`；它不读取八站汇总、不发布 Required Gate、不执行合流。
- **W3B（最终控制面，依赖 W3A+W6A～W6D）：** 实现 §12.1、§12.3～§12.8 的独立 aggregator、收敛、required contexts 和 merge/release 控制。W3B 只能消费 W3A 结果与八站结果，W6 不得反向消费 W3B。

## 12.1 Gate 聚合规则

Gate 对外聚合只给：

```text
PASS | CONDITIONAL | BLOCKED
```

内部保留统一双轴，不再把执行状态混入 policy verdict：

```text
execution_status = COMPLETED | ERROR | BLOCKED | TIMEOUT | CANCELLED
policy_verdict = PASS | FAIL | CONDITIONAL | NOT_APPLICABLE | NOT_EVALUATED
```

只有 policy 明确允许的 `COMPLETED+NOT_APPLICABLE` 才能不阻断；SKIP、UNKNOWN、空输出、missing、stale 不属于 N/A。CONDITIONAL 的 required-check 行为严格遵循 §6.1，不得擅自当 PASS。

## 12.2 修复 iron-gate / zero-rework / preflight

1. base ref 必须 fresh fetch 后验证存在；浅克隆不完整、fetch 失败即 ERROR。
2. 任一 `git diff/show/merge-base` 失败必须传播；禁止把空 stdout 当“无变化”。
3. 无测试仅在冻结 scope 机器证明为纯非行为变更时才可 N/A，否则执行全量测试或 BLOCKED。
4. 缺 node_modules、测试器、凭据、网络是 ERROR，不是 SKIP。
5. `wenqu-preflight` 去 ERP 硬编码，使用 project adapter。
6. 禁止公共固定 `/tmp` 文件；使用权限 0700 的私有临时目录。
7. warning 是否阻断必须由版本化 policy 静态声明。
8. affected Gate 和 full Gate 分开；影响图未知时升级 full，不得缩小范围。

## 12.3 收敛验证器 v3

必须实现：

- `N` 为正整数且有上限；
- 超过 N+1 为 BLOCKED，转人类裁定；
- evidence SHA 必填；
- actual exit、expected exit 和 assertion verdict 分离；
- findings 从 finding events 计算；
- `content_findings` 不可由调用者覆盖；
- `flips.json` 废止，裁定改为带身份/范围/TTL/签名的 adjudication event；
- source diversity 以 detector/version/input/charter/executor 指纹判定，不信任 S1–S5 标签；
- fingerprint 变化后旧轮失效；
- OPEN、FIXING、FIXED_PENDING_VERIFY、OTHER、过期 ACCEPTED_RISK 均阻断“清零”；
- verifier 必须重验 CAS hash、identity、TTL、required 站集合。

本轮已证明的五个负例必须永久固化：

1. artifact exit 9 自报零发现；
2. findings=9、content_findings=0、自处分洗白；
3. 证据裸文件名实际是目录外 symlink；
4. 空 rounds + `--n -1`；
5. FAST 三轮超过 N+1 仍收敛。

## 12.4 合流策略（默认无本地写控制器）

最优默认是删除本地 auto-merge 写控制器，使用 GitHub 原生 merge queue/auto-merge 加 required ruleset；本机只读观察和告警。以下控制器要求只适用于平台能力确实不足、并经独立 ADR 批准的最小权限 GitHub App fallback，绝不再使用 shell daemon、个人 `gh` 或 admin token。

1. 默认关闭；永久移除 `--admin` 和自动修改 PR 分支能力。
2. PASS 路径首选由已审计的 exact action authorization 触发 GitHub merge queue；CONDITIONAL 禁用 native auto-merge，只允许专用最小权限 App 在动作前重验并 enqueue/merge。
3. 只认 branch protection/ruleset 实时枚举出的 required checks；名称精确匹配，禁止子串匹配。
4. 每个 check 必须：
   - SUCCESS；
   - 对应当前 head SHA/merge-group SHA；
   - 在 freshness 窗口；
   - 来自 policy 钉扎的 GitHub App/integration ID、受保护 workflow/ref 和可信 details URL；仅名称相同不可信。
5. PR 必须非 draft、CLEAN、mergeable、审批/CODEOWNERS 满足、无 change request。
6. merge 前重新读取 head/base/ruleset，防 TOCTOU。
   - 优先只使用 GitHub merge queue；fallback controller 必须调用支持 expected head SHA/等价原子前置条件的 API，无法原子约束时不得直接 merge。
7. PENDING/SKIPPED/NEUTRAL/CANCELLED/UNSTABLE/DIRTY/UNKNOWN/API 错误全部不合流。
8. GitHub 429、超时、空 JSON 后断路和告警，不无限重试。
9. break-glass 只能由人对精确 PR+SHA+动作执行一次性、短 TTL 操作；自动程序既不持有也不能消费 bypass/admin 权限。

## 12.5 CI Required Gate

新增稳定 context：

```text
Bugscan Required Gate
Wenqu Required Gate
Action Authorization Gate
```

`Bugscan Required Gate` 聚合八站。问渠内部 S7 决策只消费 exact-SHA 的 S1～S6、`Bugscan Required Gate` 和其他冻结的 release inputs；`Wenqu Required Gate` 是 S7 的唯一外部输出，绝不能作为 S7 输入或被 S7 递归聚合。`Action Authorization Gate` 独立表达 §6.1 的 exact action authorization，不能由前两个技术 Gate 推导。三者必须由默认分支固定版本或外部受控 App 发布，冻结 GitHub App/integration ID、workflow commit、expected head/merge-group SHA；PR 不能通过修改自己的 workflow/manifest 自证通过。workflow/action 均钉 commit SHA，workflow 目录受 CODEOWNERS 保护。

Ruleset 必须实际启用 CODEOWNERS review，而不是仅存在 CODEOWNERS 文件。聚合检查对普通 PR、fork PR、synchronize、reopened、merge_group、runner 不可用和 station result 缺失都必须产生明确终态；外部 aggregator 超时后发布 FAILURE/BLOCKED，不能永久 Pending 或根本不生成 check。

经用户批准后，分支保护至少 required：

```text
Fast (lint+tsc)
Bugscan Required Gate
Wenqu Required Gate
Action Authorization Gate
```

删除：

- `[skip-audit]`；
- `continue-on-error`；
- 工具失败后 warning+success；
- 依赖“合流后 master 再兜底”的前置漏洞；
- one-shot Skill 中“10 分钟合不上就 L4 直推”和 `force-with-lease` 回滚表述。

## 12.6 验收

| 场景 | 期望 |
|---|---|
| Fast SUCCESS + Security FAILURE | 禁止合流 |
| 无 Fast + Gate FAILURE | 禁止合流 |
| required check 缺失/旧 SHA/同名伪造 | 禁止合流 |
| PR 修改 workflow 试图放行自己 | 外部聚合仍阻断 |
| head 在聚合后变化 | 旧结论失效 |
| 技术 Gate 全绿但 Action Authorization Gate 缺失/旧 SHA | 不合流、不发布 |
| CONDITIONAL 技术 context 绿但 native auto-merge 被开启 | doctor FAILURE，禁止 enqueue |
| base 不存在/fetch 失败/零测试 | ERROR/BLOCKED |
| artifact 非零真实 rc、自报零 finding | BLOCKED |
| unsigned flip、N<=0、N+1 超限 | BLOCKED/参数错误 |

对 Gate、合流、授权核心模块做 targeted mutation：删除校验、改比较符、插入 `|| true`、吞异常均必须被测试杀死；目标安全模块 mutation kill=100%，整体门槛不低于 90%。

## 12.7 回滚

branch protection 保存 before JSON，但任何回滚不得恢复不安全规则。新聚合器故障时保持 required checks、暂停自动合流，改走人工受保护 PR；不得关闭检查换取可合流。

## 12.8 停等点

修改 GitHub ruleset、凭据、merge queue 或正式启用 auto-merge，必须单独取得用户授权。

---

# 13. 工作包 W4：统一调度、Watchdog、Outbox 与备份

## 13.1 唯一调度面

每个逻辑 job 只能有一个 owner scheduler：macOS 本机任务使用 launchd，GitHub CI 使用 Actions，远端任务只使用登记的 systemd timer/cron。全局 schedule registry 记录 owner、环境、时区、due window、catch-up 和 watchdog；watchdog 必须与被监控 scheduler/release 处于不同故障域。

macOS 所有 plist 只调用：

```text
~/.local/share/wenqu/current/bin/wenquctl schedule <profile>   # 七段、pending、系统健康、发布观察
~/.local/share/wenqu/current/bin/bugscanctl schedule <profile> # 八站扫描
```

不再直接引用 `/Users/maccc/argus-assemble`、`~/.zcode/.../sentinel` 或任意工作树脚本。

两类命令可共用 trusted runner、event store 和 outbox，但 run、状态机、policy 和 scheduler namespace 必须隔离，禁止 one-shot 任务写入 bugscan 状态或反之。

## 13.2 结构化任务状态

```json
{
  "job_id": "supply-chain",
  "run_id": "...",
  "scheduled_at": "...",
  "started_at": "...",
  "finished_at": "...",
  "execution_status": "ERROR",
  "policy_verdict": "NOT_EVALUATED",
  "actual_exit_code": 2,
  "commit_sha": "...",
  "environment": "local-launchd",
  "artifact_sha256": "...",
  "last_success_at": "...",
  "next_due_at": "..."
}
```

只有同一 job/probe/station 身份与输入指纹、且证据仍在 TTL 内的 `COMPLETED+PASS` 更新对应实体的 `last_success_at`。`COMPLETED+NOT_APPLICABLE` 只能参与受保护 applicability 聚合，绝不能刷新成功时间。发现问题表达为 `COMPLETED+FAIL`，与 ERROR、BLOCKED、TIMEOUT 分开显示；watchdog 检查业务结果和 freshness，不看 PID 或日志 mtime 冒充健康。

## 13.3 Pending/通知修复

- `wait-list --jsonl` 带 `schema_version`；
- producer/consumer 做契约测试；
- malformed 一行使本轮 ERROR；
- `notify_attempts` 只表示真实发送尝试；
- provider 返回 receipt/message_id 才标 delivered；
- attempts/deliveries/acknowledgements 分开；
- 终态任务残留 wait 追加 SUPERSEDED 事件，不直接删除。

## 13.4 告警 Outbox

- 事务内落 outbox；
- JSON 序列化，禁止 shell 拼接未转义内容；
- alert_id/run_id/station/finding_id/idempotency key；
- 指数退避、最大尝试、dead-letter；
- CRITICAL 有独立第二通道；
- seen 只用于通知去重，不能阻止风险重新评估；
- 定期合成触达演练并保存 provider receipt。

## 13.5 备份

- DB 使用 SQLite backup API/VACUUM INTO；
- CAS/manifest 做只读快照；
- 备份完成后校验 hash、列目录、定期恢复演练；
- 失败不刷新 success；
- 不把秘密或生产敏感数据写入不受控备份；
- 外部/offsite 备份须另行授权。

## 13.6 真环境验收

- `env -i`、最小 PATH/HOME；
- launchd 真 PATH/TCC；
- 缺 `WENQU_REPO/WENQU_DB_SSH`；
- 睡眠/唤醒补跑、时区/DST；
- 网络断、provider 500、registry 部分响应；
- 日志目录只读、磁盘满、时钟偏移；
- 进程活但功能死、PID 复用；
- 强制 weekly/quarterly 缩时模拟；
- 日志轮转与弃用 warning 降噪。

建议增加独立 off-host dead-man 检查本机 dashboard/aggregator/alert heartbeat；若本期不建设，最终风险边界必须明确“本机、launchd 和本机网络同时失效时无法自报”。

## 13.7 回滚

调度升级失败时保持旧任务停用、改为人工执行新 runner；不得重新启用 fail-open 脚本。Outbox 事件必须保留并在恢复后幂等重放。

---

# 14. 工作包 W5：历史账本迁移与裁定

## 14.1 原则

- append-only sidecar 迁移；
- 禁止原地重写 JSONL；
- 不伪造未知 SHA/env/scope；
- 未知和缺字段可以完成技术导入，但以 blocker/quarantine 状态存在，发布和清零持续 BLOCKED，直至逐条裁定。

## 14.2 步骤

1. 对所有旧 JSONL/waiting/审批文件做逐文件和逐行 SHA 清单。
2. 每行生成：
   `legacy_event_id=sha256(source_file,line_no,raw_line)`。
3. dry-run 规范化已知 alias：
   - `ts/timestamp/time`；
   - `env/environment`；
   - `scope_hash/range_hash`；
   - `rule_version/ruleset`。
4. 未知状态、长文本状态、坏 JSON、缺身份字段进入 `legacy_quarantine`。
5. 状态安全映射：
   - `FIXED` → `FIXED_PENDING_VERIFY`；
   - 无验证证据的 CLOSED → blocker，等待复核；
   - 缺 approver/reason/expiry 的 ACCEPTED → finding 回到 `OPEN`，追加 `RISK_ACCEPTANCE_INVALIDATED` 事件并保留 invalid reason；
   - OTHER → quarantine blocker。
6. 单事务导入；重复运行两次结果完全相同。
7. 输出守恒报告：源非空行数、合法 JSON 行数、事件数、候选 logical finding、fingerprint 冲突、有效导入、重复、quarantine、需重开项。481 仅是旧 dashboard 启发式折叠数，不能充当原始迁移分母。
8. 影子 importer 对比 48 小时，要求数量守恒、全部 logical finding 可追溯、**零未解释差异**；有意状态变化必须带 `migration_decision_id`、规则和证据，不得为了零差异复刻旧错误投影。这不等同全线观察窗。
9. 短写冻结→最终 delta import→写入 cutover watermark/writer epoch。
10. 新写只入 v2；旧 JSONL 只读，兼容 JSONL 由 v2 exporter 生成。

## 14.3 重点对账

- 481 finding 的 stable fingerprint 和生命周期；
- 24 OPEN、4 FIXING、172 FIXED、67 VERIFIED、158 CLOSED、43 ACCEPTED、13 OTHER；
- 每项目 rounds、指纹和 evidence；
- 两条 stale WAITING；
- 所有豁免、审批和到期日；
- 每个 run 的 commit/environment/scope/ruleset/data config。

还必须冻结 canonical `repo_id` 映射和 fingerprint collision 表；同 fingerprint 不同项目、同旧 ID 不同内容均不得自动合并。

## 14.4 出口/DoD

- 数量守恒 100%；
- 零静默丢行；
- 任一 legacy 行可由 v2 反查原文件/行号/哈希；
- 两次幂等迁移结果一致；
- 无双主写、writer epoch 唯一；
- invalid ACCEPTED 不再被算作关闭；
- migration reconcile 报告由独立脚本复核。

## 14.5 回滚

切换前可废弃 v2 副本重建；切换后若有 v2 新事件，禁止旧快照覆盖。只能使用兼容 v2 的旧二进制或前向修复；必要时从 v2 生成旧格式只读投影，绝不能恢复旧 writer 造成 split-brain。

---

# 15. 工作包 W6：Bug 八站 Orchestrator 与扫描器重建

## 15.1 通用要求

- 所有 scanner 在 exact commit 的不可变源快照上运行；构建/test 写入独立 ephemeral overlay/scratch，结束后验证源快照 diff=0，禁止复用共享脏仓；
- station registry 版本化并进入 ruleset hash；
- 每站输出严格 `station-result.json`；
- 空/未知格式/依赖缺失先判 ERROR；每个 adapter 版本化定义 `expected_exit_map`，例如 npm audit 的有效 JSON+exit1 可判 `COMPLETED+FAIL`，只有未定义/意外退出码才是 ERROR；
- coverage 必须同时给 denominator 和 scanned；未知分母不得 CLEAN；
- 每个 finding 有 stable fingerprint、位置和 CAS 证据；
- required station 的 ERROR/BLOCKED/SKIP 使整线阻断。

## 15.2 子工作包与逐站契约

每站必须冻结：入口、覆盖分母、工具/规则版本、PASS/FAIL/ERROR 判据、TTL、产物 schema、正负测试、责任仓和回滚方式。

### W6A：Planner、Registry、站0/站1适配

- 站0从 target SHA 生成项目身份、范围、风险、required 站集合和证据失效域；分母缩水默认 BLOCKED。
- 站1只消费 W3A 的 exact-SHA `source-gate-result.json` 并完成站内 applicability/coverage 适配；不得消费 W3B，不得由 W6 自报 CI 通过或发布 required context。
- required 集和 registry 来自受保护 policy commit，PR 不可自改。
- 产物：`run-manifest.json`、station dependency graph、coverage denominator manifest。

最低 lane/applicability 矩阵写入 `default-policy.yaml`：

| lane/profile | 不可移除最低集合 | 说明 |
|---|---|---|
| FAST/普通 PR | 0+1 | 权限/资金/租户/迁移/公共基础层自动升档并追加相应站 |
| STANDARD | 0+1+2+3+4 | 有效、同指纹、未过 TTL 的证据才可复用 |
| INCIDENT | 0+1+2+3+4+6；发布就绪还需7 | 涉生产写/资金/外部交易追加5；未获授权则 BLOCKED |
| weekly | 0+2+3 | 不产出自动生产清零声明 |
| nightly | 0+4，并验证3的证据仍有效 | 站3过期则前置完整3 |
| release/new module | 0+1+2+3+4+5+6+7 的适用集合 | N/A 必须机器证明，风险只能增加深度 |

人工降档只形成 CONDITIONAL，不能生成自动 PASS。

### W6B：站2 静态与供应链

- SAST、dupscan、持续修复五类、route 静态腿、供应链、Advisory、SBOM。
- 每个扫描器有独立 coverage denominator 和 rule digest；任一 required 件缺失/过期即站2非 PASS。
- 当前供应链和 Advisory 的 fail-open 作为 mandatory golden。

### W6C：站3 契约与数据

- OpenAPI 全端点分母、org guard、权限矩阵、正负运行时探针、DB 四轨、迁移 fresh/legacy/minimal。
- 运行时探针必须同时验证合法正例与越权负例。
- DB 连接身份、只读状态、diff 方向和 catalog scope 进入 evidence identity。

### W6D：站4～7

- 站4：页面/路由/E2E 分母、真实浏览器、截图/trace 和业务断言完整度。
- 站5：受控合成租户/实弹授权、幂等、守恒、补偿、清理和前后状态。
- 站6：属性、变异、并发、乱序、重复提交、S3/S5。
- 站7：运行事件生成 finding、告警 receipt、SLO 和 release blocker；不计收敛轮。

W6A～W6D 各自可 shadow 和回退为 BLOCKED，但不得回退为旧 scanner 的 PASS。

## 15.3 DB 漂移

彻底废止“文本行数<=30即 CLEAN”。目标采用四轨 canonical object diff：

1. Git `schema.prisma`；
2. Git migrations 在 fresh DB 应用后的 catalog；
3. 生产 `_prisma_migrations`；
4. 生产只读 `pg_catalog/information_schema`。

规范化对象至少包括 schema、table、column(type/null/default)、PK、FK、unique、index、enum、check、trigger、migration history。

每轮 DB evidence 还必须记录：current database、server/version、schema、role、`transaction_read_only`、Prisma/PostgreSQL 版本、diff 方向、catalog scope、extension-owned object 处理策略、默认值/表达式/顺序规范化规则和 migration checksum。连错数据库、角色非只读、方向反转、未知对象类型均 BLOCKED。

迁移类变更还必须覆盖 fresh DB、代表性 legacy/minimal schema、前向迁移、迁移后审计以及失败后的回滚/恢复；只证明“看见漂移”不等于迁移安全。

过渡期：

- 正确解析 `[+]`、`[-]`、`[*]`；
- 未识别 token、空输出或未匹配该 Prisma 版本 `expected_exit_map` 的退出码直接 ERROR；合法“有差异”退出码映射为 `COMPLETED+FAIL`；
- 任一未被有效 allowlist 覆盖的 drift 都 BLOCKED；
- DROP/ALTER TYPE/删约束为高风险，绝不受“数量少”豁免。

allowlist 必须绑定对象 identity、actual/desired hash、原因、owner、ticket、批准人、到期时间；对象或哈希变化自动失效。

## 15.4 供应链与 Advisory

删除 `npm audit || true`、`continue-on-error`、API 失败后成功退出及文本绕过。

判定：

| 输入 | 结果 |
|---|---|
| 有效 JSON，无阻断漏洞 | PASS |
| 有效 JSON，有 HIGH/CRITICAL | FAIL |
| 网络失败、空 JSON、解析失败、未知生态/范围 | ERROR/BLOCKED |
| 有签名且未过期离线快照 | 可按快照判定并展示 age |
| 快照过期且实时源不可用 | BLOCKED |

最少覆盖：生产/全依赖 audit、W1 policy 冻结的必需异源漏洞源（初始候选 OSV）、lockfile hash、name+version+integrity+resolved、Git/path/file 依赖、install scripts、SBOM、许可证/registry 策略、直接/传递依赖增删。

Advisory 必须完整分页、遍历所有 vulnerability ranges；version check 异常为 UNKNOWN，UNKNOWN 不写 seen 且触发重试/阻断。seen 仅通知去重，不参与后续风险判定。

## 15.5 租户隔离

1. 从 Prisma DMMF/schema 自动生成直接和关系间接租户模型分母，禁止硬编码 27 项。
2. 使用 TS AST/调用图识别 alias、默认/相对/重导出、repository wrapper、transaction、raw SQL、动态 export。
3. 普通业务代码必须通过 scoped client/repository；管理员跨租户模块单独 allowlist。
4. 自动生成 A/B 租户动态探针：读取、写入、聚合、分页、搜索、批量 ID、附件/导出。
5. 正例必须通，Org A 访问或导出 Org B 必须拒绝。

RLS 仅作为独立增强项目：先 staging 五个高风险模型试点，另走 DDL 授权、fresh/legacy/rollback；不得悄悄纳入本管线整改部署。

## 15.6 性能与 N+1

- CI 短预算、nightly 稳态、季度完整基线分层；
- 严格执行 W1 profile-specific 的预热时长、最小请求数/持续时间/并发和分位实现；禁止 5 样本手算 p95；
- 校验 HTTP 状态和业务响应语义，快速 404/500 不能通过；
- SSH/TCC/指标 null 为 ERROR；
- `pg_stat_statements` 未具备时明确盲区，不用 idle query 冒充慢查询；
- 通过 OTel/Prisma instrumentation 记录每请求 query count；
- 输入规模 1/10/100 做增长曲线；
- 失败结果不得覆盖 baseline；baseline 绑定 SHA、环境、数据规模、工具版本。

## 15.7 行为、实弹与对抗

- UI 用干净构建和真实浏览器；绑定候选 SHA、角色、DB、环境；
- 真单/生产写必须单独授权，并预先定义清理、补偿、幂等和守恒；
- 对资金、权限、租户、迁移做正向+负向+并发+重复提交；
- S3/S5 结果独立落账，不允许同命令换标签算异源；
- 站 7 不计收敛轮，但任何运行时 blocker 均阻断 release readiness。

## 15.8 出口/DoD

- 当前 DB 报告的至少 280 项变化不再被判 CLEAN；
- audit 空/解析失败必非零且不更新 success；
- `scanned == target SHA 动态生成的 tenant-model denominator`；分母较基线缩小时默认 BLOCKED；193/约172 仅作为当前回归 fixture；新增 organizationId 模型必须自动进入分母；
- 别名、重导出、raw SQL、注释欺骗、长 builder、非 export 路径下载等反例被捕获；
- HTTP 500、null 指标、SSH/TCC 失败均不可能生成性能 PASS；
- 八站 required 集可由风险定级生成，并由 aggregator 强制。

## 15.9 回滚

scanner 新版可逐站 shadow；失败时该站保持 BLOCKED，不能回退为旧 scanner 的 PASS。规则更新必须保留旧/新双跑对比证据。

---

# 16. 工作包 W7：不可变制品、原子部署与运行身份

W7A 先实现 release layout、manifest、installer、lease 和 smoke 框架；W7B 只有在 W3B、W4、W5、W6A～W6D、W8 完成后，才打包含全部组件与最终迁移投影接线的候选制品。W7A 框架通过不代表最终 release 可用。

## 16.1 目标布局

```text
~/.local/share/wenqu/releases/<release-id>/
~/.local/share/wenqu/current -> releases/<release-id>
~/.config/wenqu/config.toml
~/.local/state/wenqu/
~/Library/Logs/Wenqu/
```

配置、秘密、状态和日志不得进入 release。

## 16.2 Release manifest

```text
version, source_commit, quality_policy_commit, build_id,
built_at, builder, schema_version, policy_hash,
files[path,size,mode,sha256], artifact_sha256,
python/node/runtime identity, dependency lock/SBOM hash,
min_schema_version, max_schema_version,
attestation/signature
```

缺件、多件、模式错误、额外未登记可执行文件或 hash 漂移均使安装失败。

## 16.3 原子部署

1. 源工作树 clean、完整测试和红探针通过；构建不可变制品和 manifest；
2. 解到 `releases/<id>.tmp`，完成全清单、权限、schema、签名校验；
3. 使用独立临时 DB/state/config 做临时端口 smoke，禁止触发或接触生产 migration/DB/state；`/api/build` 对账；
4. 生成精确部署包：release/SHA/env、expand migration、迁移前后 schema、备份/恢复、previous release、停止条件与回滚触发器；分别取得部署与生产 DDL/迁移授权；
5. 获取全局 deployment lease、唯一 writer fencing token 和 migration lock；任一锁不唯一或租约失效即 BLOCKED；
6. 创建一致性 backup/checkpoint，记录 LSN/事务水位或等价游标、schema/data hash，并在隔离环境实际恢复抽验；未验证备份不得继续；
7. 仅执行已授权、可重入、向前向后兼容的 **expand migration**；保存逐语句 rc、前后 catalog diff、migration ledger 和 lock 身份；禁止夹带 destructive contract；
8. 同时用现役二进制和候选二进制验证 expanded schema 兼容性；任一失败保持旧 current，进入 `FAILED_BLOCKED`，不得自动 down migration；
9. 原子 rename 成最终 release，再原子切换 `current` 并 restart；
10. 对账 PID、exe path、release id、commit、manifest、DB schema、writer epoch、health，并跨过 readiness 稳定窗；
11. 若激活失败且部署授权已预授权**精确 previous_release、精确触发条件、schema 兼容范围和观察窗**，进入 `ROLLBACK_PENDING` 并原子切回；否则进入 `FAILED_BLOCKED` 等待用户批准，禁止自行选择历史版本；
12. expand 后的字段/表至少保留完整观察与回滚窗口；只有所有 reader/writer 已迁移、旧版本回滚窗口被明确关闭、备份恢复再验证且另获生产 DDL 授权后，才能在独立变更中执行 contract migration。

并发部署/回滚只能一个成功。staging→release rename 与 current symlink 切换必须位于同一文件系统。restart 后不能用单次 HTTP 200 放行。previous compatible 由 event/policy/CAS/API/schema compatibility range 机器判定。`ROLLBACK_FAILED` 时必须冻结 current 与现场、阻断 writer/merge/release、保持告警并停等人工恢复；禁止循环重试或执行破坏性回滚。

安装器必须删除 `doctor || true`。doctor 非零、manifest 不符、linter 缺失均导致整次部署失败。禁止 `cp -R` 覆盖现役目录和保留幽灵文件。

## 16.4 验收

- manifest 缺/多文件、hash 错、版本错、额外脚本；
- staging 中途 kill -9；
- symlink 切换后启动失败；
- 配置/状态被安装器覆盖；
- DB schema 与二进制不兼容；
- 回滚后 build API/PID/manifest 不一致；
- 正源 dashboard 缺闭合标签或缺必需 linter。

以上均必须拒绝部署或自动恢复。回滚演练后检查新事件未丢失。

## 16.5 停等点

正式部署、生产 expand/contract migration、restart、launchctl 修改和回滚均须用户授权；contract 必须晚于观察与回滚窗并再次独立授权。候选制品、离线 smoke 和回滚脚本可先完成。

---

# 17. 工作包 W8：Dashboard、健康模型与控制面安全

## 17.1 结构重构

将单文件 HTML/JS/Python 拆为：

```text
system/dashboard/index.html
system/dashboard/app.js
system/dashboard/app.css
system/dashboard/server.py
```

API 版本化 `/api/v1/*`。GET 只读，不得顺手写 health history。

## 17.2 健康模型

主状态：

```text
GREEN | DEGRADED | BLOCKED | UNKNOWN
```

总体状态取 required 项中的**最坏值**，不是加权平均。分数仅作趋势，不参与解除硬阻断；任一 P0 时即使展示分数也不得超过红色区间。

以下任一出现必须 BLOCKED/UNKNOWN：

- gatedoctor 非 PASS；
- source/runtime manifest 漂移；
- event store/evidence 校验失败；
- required sentinel ERROR/stale；
- 危险旧 auto-merge 存活；
- WAITING 超 SLA 且通知未 delivered；
- required Gate 缺失、错误 SHA 或过期；
- EXM 超阈值；
- P0/P1 未关闭；
- 唯一正源或环境身份未知；
- 磁盘达到资源停等阈值。

每项显示：verdict、last_attempt、last_success、fresh_until、run_id、commit、environment、evidence link、error reason。

## 17.3 功能要求

- 七段问渠、八站 Bug、九类停等分开展示；
- 所有 finding 状态含 ACCEPTED_RISK、quarantine 均可钻取；
- 日志正文可见并明确来源/时点；
- 自动巡游如保留，必须标注“演示动画，不代表执行”；
- 页面显示当前 build/release/source/runtime attestation；
- 数据源缺失返回结构化 ERROR/503，不得 HTTP 200+空集缩小问题数量。

## 17.4 安全

- 服务继续仅绑定 `127.0.0.1` 或权限受控 UDS，禁止 wildcard；严格 Host 校验防 DNS rebinding，CORS 默认拒绝；
- `/api/build` 等最小非敏感端点可匿名，日志、决策、finding 明细需要本地 session/read authorization；
- 动态文本统一 `textContent`/安全模板；禁止未转义 `innerHTML`；
- CSP、`nosniff`、`frame-ancestors 'none'`、`no-store`、`no-referrer`；
- Host/Origin allowlist、body size limit、Content-Type 精确校验；
- 第一阶段 `/api/decide` 返回 405；
- 恢复写操作前必须有：UDS 0600 控制服务或等效隔离、本地 session bootstrap、HttpOnly/SameSite cookie、CSRF、真实 actor、idempotency key、CAS、append-only event；
- 禁止硬编码“超哥点击”和整文件重写；
- request audit 日志脱敏且可轮转；
- 请求超时、最大并发、速率限制、日志响应行数/字节上限和 secret/PII 二次脱敏必须机器化。

健康聚合由独立 aggregator 原子生成带 input watermark 的一致性快照；采集中任一输入版本变化则整份 snapshot 作废重算。Dashboard 不得串行拼接不同时间点 API 后自行得结论。

## 17.5 Playwright/真实浏览器门

- 总览在 fresh/cache/导航后均可见；
- 七段、八站命名与节点正确；
- ACCEPTED/OTHER/quarantine 均可钻取；
- 六个日志正文实际出现；
- XSS payload 不执行；
- CSRF/伪 Origin/text/plain 写入被拒；
- Cache-Control 生效，版本更新不保留坏页面；
- 键盘/ARIA、reduced-motion、375px 无横溢；
- 任一 required blocker 时页面不可能显示“良好”。

## 17.6 回滚

Dashboard 故障只能回退到兼容新 API 的只读版本；不能恢复无鉴权写接口或独立加权健康分。Dashboard 故障本身不得改写底层 Gate，但若 policy 把可观测性列为发布必需项，release readiness 应为 BLOCKED，而不是默认放行。

---

# 18. 工作包 W9：Shadow、Canary 与受控切换

## 18.1 阶段

1. **离线 fixture：** 所有现有红探针、golden、属性、变异和故障注入全过。
2. **Shadow：** 新旧系统读取同一冻结输入；新系统不合流、不写生产状态，仅比较结果。
3. **迁移投影观察：** 至少 48 小时满足总记录数量守恒、全部 logical finding 可追溯、零未解释差异；`FIXED→FIXED_PENDING_VERIFY`、非法 ACCEPTED 重开、OTHER quarantine 等有意状态变化必须逐项带 `migration_decision_id`、命中规则和证据。不得要求“零状态变化”而复刻旧错误投影；本阶段也不等同现役观察窗。
4. **全线 shadow：** 至少 14 天，覆盖两次周任务、14 次 nightly；季度任务用缩短计划强制模拟。
5. **低风险测试仓 canary：** 先只读 checks，再启用 GitHub 原生 merge queue；生产仓仍人工。
6. **正式切换：** 用户逐项授权后切 writer epoch、CI required、scheduler、dashboard read model。
7. **自动合流最后启用：** 默认直接删除本地写控制器，采用 GitHub 原生 merge queue/auto-merge；只有平台确实不支持时，才另立最小权限 GitHub App，禁止个人 `gh`/admin 凭据。

## 18.2 Shadow 判定

必须为零：

- 新系统 false PASS；
- dashboard 与 aggregator 判定差异；
- 账本丢失、重复和状态非法；
- 未授权状态推进；
- 错 SHA 证据复用；
- ERROR 刷新 last_success；
- 告警 created 但未进入 outbox；
- runtime/source 漂移未报；
- quarantine 被计为关闭。

旧系统如果比新系统更绿，不以旧系统为正确答案；必须逐项裁定差异根因。

## 18.3 Canary 停止条件

任一出现立即停止新任务、发布和自动合流：

1. dashboard 绿但 Gate 红；
2. 两个活跃 writer epoch；
3. run 状态与事件重放结果不同；
4. approval 重复消费或扩范围；
5. evidence hash/signature 不符；
6. check SHA 与 PR head 不一致；
7. merge controller 使用未知 check；
8. runtime manifest 漂移；
9. migration count/hash 不守恒；
10. sentinel ERROR 但 last_success 更新；
11. 回滚包或备份不可恢复；
12. 任一新 P0。

停止后保持 disabled/BLOCKED，不自动回退到旧不安全实现。

## 18.4 切换证据

```text
evidence/W9/shadow-comparison.jsonl
evidence/W9/difference-adjudications.jsonl
evidence/W9/canary-runs/
evidence/W9/writer-epoch-cutover.json
evidence/W9/branch-rules-after.json
evidence/W9/runtime-attestation.json
evidence/W9/rollback-drill.md
```

---

# 19. 工作包 W10：14 天观察、回滚演练与战训收官

## 19.1 观察窗硬指标

至少连续 14 天：

- false PASS=0；
- 未授权状态推进=0；
- 错 SHA 合流=0；
- 账本丢失/重复=0；
- source/runtime 漂移=0；
- required sentinel stale 未告警=0；
- WAITING 超 SLA 未通知=0；
- 自动合流无限重试=0；
- dashboard/CLI/aggregator 判定差异=0；
- 合成告警 delivery receipt 达成率=100%；
- 回滚演练成功率=100%；
- 两次自然周任务均有有效 PASS 或明确非 PASS 证据；
- nightly 14 次均可追溯；
- 强制季度 profile 演练完成。

## 19.2 回滚演练

至少覆盖：

1. current symlink 回到上个兼容 release；
2. 服务 restart 后 build/manifest/DB schema 对账；
3. 切换期间产生的新事件仍存在；
4. outbox 未送消息可继续幂等发送；
5. branch rules 故障时保持 required，人工受保护 PR 可工作；
6. SQLite 一致性备份恢复；
7. CAS 缺块/损坏检测；
8. scheduler 回退后不会产生双写者。

## 19.3 战训回流

- 每个新发现进入 finding ledger；
- 同类二犯必须晋升为代码约束/测试/CI Gate；
- 规则、基线、阈值变更独立审批；
- 更新 Skill 时同步版本、front matter、机器 schema、实际列表和回归；
- 运行 governance consistency checker，确保 one-shot/bug Skill、policy、registry、CLI help、CHANGELOG 和 release manifest 使用同一版本与枚举；
- 最终执行战训四查和独立 S5；
- 没有新增经验时也要写明依据。

## 19.4 最终出口

先严格区分两个出口：

- **条件放行：** 存在合法、未过期且仅限低风险的 `ACCEPTED_RISK` 时，最多按 §6.1 输出 `AUTHORIZED_CONDITIONAL`；不得称“清零”“最终闭环”或“生产闭环”。
- **最终生产闭环：** 活跃 `ACCEPTED_RISK=0`，且下列条件全部满足后才允许声明。

最终生产闭环只有同时满足：

- W0–W9 全部 hard DoD；
- 所有 P0/P1 已关闭；
- 活跃 ACCEPTED_RISK=0；
- EXM 熔断解除且逐条有效；
- invalid ACCEPTED/OTHER/quarantine 已裁定；
- 清零声明所需范围内零 OPEN/FIXING/FIXED_PENDING_VERIFY；
- required 证据同一指纹、未过 TTL；
- INCIDENT 连续三轮异源零新发现，末轮独立 S5；
- 部署、回滚、告警、备份恢复已演练；
- 观察窗全部硬指标达标；
- 明确列出仍未覆盖的威胁边界；

才可对**限定范围、SHA、环境和观察窗**给出最终生产闭环声明。

---

# 20. 强制红探针与验收矩阵

所有用例必须保存 before/after：旧实现先证明能产生假绿/漏拦，新实现证明正确阻断或正确通过。仅写测试、不执行红探针无效。旧版 before 复现只能在副本、mock API、测试仓、fixture 或隔离环境进行；自动合流、生产写、DDL、真实外部告警和回滚类缺陷禁止在真实系统重放，已有生产日志/审计证据可直接作为 before。

## 20.1 Gate、授权、合流

| ID | 注入 | 期望 |
|---|---|---|
| GATE-01 | base ref 不存在/fetch 成功 | ERROR/BLOCKED |
| GATE-02 | 零测试、scope 未证明纯文档 | BLOCKED |
| GATE-03 | test runner/依赖缺失 | ERROR |
| GATE-04 | 内层 exit 7、自报零 finding | assertion FAIL/BLOCKED |
| GATE-05 | artifact symlink/hardlink/根外 | BLOCKED |
| GATE-06 | artifact hash 篡改 | BLOCKED |
| GATE-07 | commit/env/scope/ruleset 不符 | BLOCKED |
| GATE-08 | evidence 过 TTL | BLOCKED |
| GATE-09 | `N=-1/0/超上限` | 参数错误 |
| GATE-10 | 超过 N+1 | BLOCKED 等人工裁定 |
| GATE-11 | 同命令换 S 标签 | 不计异源轮 |
| GATE-12 | unsigned flip/adjudication | BLOCKED |
| AUTH-01 | 无授权 resume | 拒绝 |
| AUTH-02 | 过期/重放/扩范围/旧 state_version | 拒绝 |
| AUTH-03 | AI/runner 尝试自行签发高风险批准 | 拒绝 |
| ACT-01 | technical PASS，但无 exact merge/release action authorization | context 可表技术 PASS，controller 不动作 |
| ACT-02 | action、method、head/merge-group、artifact/env 任一不符 | `Action Authorization Gate` failure，拒绝动作 |
| ACT-03 | check 发布前/后 crash 或回执丢失 | outbox 幂等恢复；同一 check_run 更新，不产生伪双绿 |
| ACT-04 | merge/release 调用前/后 crash 或回执丢失 | 先查询外部事实；COMMITTED 或 FAILED_UNKNOWN；绝不盲重试 |
| ACT-05 | 外部陈旧绿、dispatcher/App 失联 | direct merge 被角色/ruleset 拒绝；动作保持 BLOCKED |
| ACT-06 | merge/release/DDL/prod-write payload 使用错误 discriminator 或缺专属字段 | schema 拒绝 |
| MRG-01 | Fast 绿、Security 红 | 不合流 |
| MRG-02 | 没有 Fast、Gate 红 | 不合流 |
| MRG-03 | check 同名伪造/旧 SHA | 不合流 |
| MRG-04 | pending/skipped/neutral/cancelled | 不合流 |
| MRG-05 | head 在聚合后改变 | 旧结论失效 |
| MRG-06 | GitHub 429/空 JSON/超时 | 断路，不合流 |

## 20.2 状态、账本、迁移

| ID | 注入 | 期望 |
|---|---|---|
| STATE-01 | 任意 stage/status | schema 拒绝 |
| STATE-02 | `../`、绝对路径、NUL、超长 ID | 拒绝 |
| STATE-03 | 100×100 并发写 | 零丢失/重复 |
| STATE-04 | 事务各点 kill -9 | 全有或全无 |
| STATE-05 | 双 writer epoch | 所有写入拒绝 |
| STATE-06 | WAITING 终态残留 | SUPERSEDED 事件，不静默删 |
| MIG-01 | 坏 JSON/未知状态 | quarantine+BLOCKED |
| MIG-02 | 缺审批信息的 ACCEPTED | invalid/reopen |
| MIG-03 | 两次迁移 | 结果幂等一致 |
| MIG-04 | 源行数不守恒 | 迁移失败 |
| MIG-05 | project key 冲突 | 明确冲突，不拆成假项目 |

## 20.3 Bug 扫描器

| ID | 注入 | 期望 |
|---|---|---|
| DB-01 | `[+]`/`[-]`/`[*]` | 全识别 |
| DB-02 | 仅一条 DROP COLUMN/删 FK | FAIL，不因数量少放行 |
| DB-03 | 未知格式/空输出/命令非零 | ERROR |
| DB-04 | allowlist 到期/对象 hash 变化 | FAIL |
| SC-01 | 有效 JSON+HIGH/CRITICAL | FAIL |
| SC-02 | 空 JSON/registry 超时 | ERROR |
| SC-03 | install script/resolved/integrity 变化 | FAIL/人工审 |
| SC-04 | 标题含 `[skip-audit]` | 无绕过效果 |
| ADV-01 | version parser 异常 | UNKNOWN，不写 seen |
| ADV-02 | 多页/多 range | 全遍历 |
| TEN-01 | Prisma alias/re-export/wrapper | 纳入分析 |
| TEN-02 | 注释含 organizationId | 不能欺骗 |
| TEN-03 | builder 超 300 字符 | 纳入分析 |
| TEN-04 | `$queryRaw` 跨租户 | 阻断 |
| TEN-05 | 路径不含 export/download 的下载 | 纳入扫描 |
| TEN-06 | Org A 访问/导出 Org B | 动态拒绝 |
| PERF-01 | HTTP 500 但很快 | FAIL |
| PERF-02 | SSH/TCC/null 指标 | ERROR |
| PERF-03 | 尾部极慢样本 | 正确进入 p95/p99 |
| PERF-04 | 输入 1→100，query count 线性 | FAIL |

## 20.4 调度、发布、UI

| ID | 注入 | 期望 |
|---|---|---|
| SCH-01 | launchd 无 Documents 权限 | ERROR+告警 |
| SCH-02 | 脚本 FAIL 后 touch heartbeat | 测试抓获、last_success 不变 |
| SCH-03 | 睡眠错过周期 | 唤醒补跑 |
| ALT-01 | provider 500/超时 | outbox 重试/dead-letter |
| BAK-01 | 磁盘满/tar/backup 失败 | 不更新 success |
| REL-01 | manifest 缺件/多件/错 hash | 部署失败 |
| REL-02 | 部署中 kill -9 | 保持旧 current 或完整新 current |
| REL-03 | doctor 红 | 部署失败并回退 |
| UI-01 | 少一个闭合标签 | 构建/启动门失败 |
| UI-02 | XSS 日志/账本文本 | 不执行 |
| UI-03 | CSRF/伪 Origin/text/plain 写入 | 拒绝 |
| UI-04 | Gate 红、其他项高分 | 总体 BLOCKED |
| UI-05 | ACCEPTED/OTHER/quarantine | 均可钻取 |

## 20.5 补充契约、隔离与治理探针

| ID | 注入 | 期望 |
|---|---|---|
| STOP-01 | 九种 stop type 使用错误类型审批 | 全拒绝 |
| STOP-02 | resource/ext-unavail 未恢复但已批准 | 仍不可 resume |
| STOP-03 | 九种 stop type 的客观条件已满足但缺一次性授权 | 九类全部拒绝 resume |
| STATE-07 | 普通事件把 PASSED 改回 RUNNING | 拒绝 |
| STATE-08 | FAILED 重试 | 新 attempt，旧证据不覆盖 |
| STATE-09 | SHA/scope/policy 变化 | 强制新 run |
| STATE-10 | WAITING/FAILED attempt 直接改回 RUNNING | 拒绝；追加新 attempt 后由 stage projection 指向它 |
| STATE-11 | S7 CONDITIONAL 缺 risk authorization | S7/run 终判 FAILED；后续批准只能创建新 run，不得写 WAITING |
| AUTH-04 | canonical payload/Unicode/audience 任一字节改变 | 验签失败 |
| AUTH-05 | 并发双消费 approval | 恰一成功 |
| AUTH-06 | key revoked/clock rollback/无 user-presence | 拒绝 |
| RUN-01 | 被测程序读取 Keychain/SSH agent/生产配置 | 隔离拒绝 |
| RUN-02 | timeout 后子孙进程 | 全部终止，无孤儿写盘 |
| RUN-03 | fork bomb/输出爆量/网络外连 | 配额/allowlist 阻断 |
| CI-05 | fork、merge_group、check 不产生 | 明确 FAILURE/BLOCKED |
| CI-06 | CODEOWNERS 文件存在但 ruleset 未强制 | doctor ERROR |
| CI-07 | 未授权 App 发布同名 context/旧 details URL | 不可信、阻断 |
| CI-08 | Wenqu Gate 缺失但 Bugscan 绿 | 不合流 |
| CI-09 | S7 把 `Wenqu Required Gate` 当自身输入、重复发布或递归聚合 | schema/DAG 校验拒绝并发布 FAILURE |
| MRG-07 | 最后校验后 head 变化 | expected-SHA 原子拒绝 |
| COND-01 | CONDITIONAL 无 risk authorization | technical eligibility=false，技术 context failure |
| COND-02 | 授权跨 SHA/env/扩 finding 集/重放 | 拒绝 |
| COND-03 | 合法低风险接受、其余全 PASS、risk 与 action 两类精确授权 | 内部仍 CONDITIONAL；技术 context=`success/AUTHORIZED_CONDITIONAL`；Action Gate 成功后动作恰一次 |
| COND-04 | P0/P1 尝试风险接受或条件授权 | 拒绝并保持 BLOCKED |
| COND-05 | 授权后新增 finding、TTL 到期、SHA/scope/policy/watermark 变化 | authorization、attestation、context 失效；动作前重验拒绝 |
| COND-06 | 并发双消费或动作失败后重放 attestation | 最多一次消费；失败后须新授权 |
| RISK-01 | 主动撤销或 fingerprint/severity/policy/control 改变 | 追加 REVOKED/INVALIDATED，立即重开并可进入修复链 |
| DB-05 | 错 DB/role/`transaction_read_only=off` | BLOCKED |
| DB-06 | catalog 顺序、默认表达式、extension 对象 | golden 规范化正确 |
| SC-05 | 离线快照签名错误/过期/分页不全 | BLOCKED |
| TEN-07 | target SHA 新增 tenant model | 分母自动增加 |
| TEN-08 | 合法管理员跨租户正例/普通角色负例 | 前者通、后者拒 |
| PERF-05 | 修改 baseline/阈值试图洗绿 | policy hash 阻断 |
| PERF-06 | 样本/时长/endpoint 分母缩水 | 不得晋升 baseline |
| STA-01 | 任一站 denominator 缩小 | 整线 BLOCKED |
| STA-02 | 站2/3/4/7逐站故障 | 继续独立取证，aggregate BLOCKED |
| SCH-04 | catch-up 与正常调度并发 | 只有一个 logical run |
| SCH-05 | scheduler 整体故障 | 独立 watchdog 仍告警 |
| SCH-06 | one-shot job | 只写 wenqu namespace |
| SCH-07 | `COMPLETED+NOT_APPLICABLE` 或过期/异指纹 PASS | 不刷新任何实体的 `last_success` |
| DEP-01 | 两个部署者争 lease | 最多一个成功 |
| DEP-02 | smoke 访问生产 DB/state | 隔离拒绝 |
| DEP-03 | 新事件后回滚兼容二进制 | 事件零丢失 |
| DEP-04 | 自签/替换/revoked release key | 拒绝 |
| DEP-05 | previous release 超 schema 范围 | 拒绝回滚 |
| DEP-06 | 无迁移锁/未验证备份/expand 超授权 | 激活前 BLOCKED，旧 current 不变 |
| DEP-07 | ACTIVATING 失败且无预授权 | `FAILED_BLOCKED`；不得自动回滚或继续发布 |
| DEP-08 | ROLLBACK_FAILED | writer/merge/release 熔断并停等人工恢复 |
| DEP-09 | 观察窗内夹带 contract/down migration | 拒绝；要求独立授权变更 |
| RB-01 | 无预授权自动回滚/错误旧版本 | 拒绝 |
| UI-06 | DNS rebinding/伪 Host/未认证日志读取 | 拒绝 |
| UI-07 | 慢请求/高并发/超大日志 | 不耗尽资源 |
| HLT-01 | 聚合期间输入 watermark 变化 | snapshot 作废重算 |
| DOC-01 | one-shot 停等数量/枚举漂移 | CI 阻断 |
| DOC-02 | bug skill 版本/清单/验收数量漂移 | CI 阻断 |
| DOC-03 | policy/Skill 出现 L4、`--admin`、`force-with-lease` 或 skip 绕闸文本 | CI 阻断 |
| DOC-04 | 文档宣称现役/PASS，但 registry 或 Gate 为 BLOCKED | CI 阻断 |
| ALT-02 | waiting 到期但零 send attempt/receipt | ERROR+告警，不能以 watchdog exit0 记健康 |
| CAP-01 | 峰值空间超过安全余量或磁盘满 | 切换 BLOCKED，旧证据和 current 均完整 |
| DR-01 | 恢复演练 | 实测满足冻结 RPO/RTO |

---

# 21. 项目身份、策略来源与执行隔离

## 21.1 Canonical repo_id

冻结：

```text
repo_id = forge_host + normalized_owner/repo
```

无 remote 的仓使用持久 UUID。clone 路径、工作树目录和 remote URL 表达形式仅是 location，不参与业务身份。迁移必须为现有各 ledger 目录生成映射表、检测冲突，禁止继续用不同 URL/path 哈希拆账。

## 21.2 Policy 与被扫代码隔离

- station registry、command allowlist、adapter 和 policy 必须来自受保护 policy commit；
- 未信任 PR 无权修改用于验证自己的规则；
- 默认 argv 直执行，禁 `bash -c`；
- 扫描未信任 PR 时隔离生产凭据、网络和写权限；
- 签名/attestation 服务只签自己实际 spawn+waitpid 捕获的结果，不签调用者上传的 rc/artifact。

## 21.3 人类授权可信边界

同 UID 的 AI/runner 可能访问普通 Keychain 项，因此仅记录 actor 名或 HMAC 不足以证明真人批准。

高风险 stop point 应使用具备 user-presence 的独立 approval broker：Touch ID/系统认证，或外部已认证渠道回执+nonce。签名必须绑定 scope、TTL、state_version、SHA 和环境；AI 只能消费，不能签发。

在该能力落地前，保持手工受保护流程，并诚实标注“无法机器证明人类身份”；不得恢复 dashboard 一键批准。

## 21.4 签名与 Attestation 可信根

W1 必须分别冻结 approval signer、runner attestor、release signer：

```text
算法
canonical serialization/Unicode 规范
key_id
signer 身份与 audience
可信公钥钉扎位置
私钥隔离边界
轮换与吊销清单
有效期和时钟异常策略
构建 provenance
```

高风险 approval 由 user-presence broker 签发；release/runner attestation 优先由被测运行体不可访问的 CI 或独立 broker 签发，verifier 只信钉扎公钥。被测程序、普通同 UID 进程和 runner 子进程不得读取私钥。

如果本期无法建立独立 signer，系统只能宣称 `hash drift detection / tamper-evident`，不得声称签名证明来源；对应 release eligibility 保持 BLOCKED 或人工边界明确的候选态。

---

# 22. 容量、留存与隐私

迁移会同时占用旧账本、CAS、SQLite/WAL、备份和两版 release。本机当前约 90% 已用，W0 必须计算峰值：

```text
peak = legacy_snapshot + imported_db + WAL_peak + CAS_copy
     + backup + current_release + next_release + rollback_release
```

设定最小安全余量；不足即 BLOCKED。禁止自动删除审计证据。留存、压缩、外移均是独立授权动作，操作后必须对账 hash 并做恢复抽验。

证据默认脱敏：不保存 token、Cookie、个人信息、生产秘密或完整业务敏感数据；需要保存时使用加密、最小化和明确 retention policy。

CAS 必须冻结 retention、RPO/RTO 和 GC 规则。GC 前证明目标 digest 没有 event/manifest/backup 引用，并完成恢复抽验；引用图未知或 checkpoint 未锚定时禁止回收。

---

# 23. 发布、回滚与授权边界

## 23.1 必须停等用户授权的动作

1. 停止/启动现役 auto-merge、dashboard、sentinel、LaunchAgent；
2. 修改 GitHub branch protection/ruleset、App 权限和凭据；
3. 合并、部署、restart、切换 current；
4. 首次配置告警通道、合成测试实发或变更通知策略；完成授权后，在绑定 channel/scope/TTL 内的常规告警自动投递，不逐条停等；高风险处置动作仍逐项授权；
5. 生产 DB、RLS、DDL、迁移；
6. 生产真单/真实写入；
7. offsite 备份；
8. 生产回滚和数据恢复。

ZCode 可在停等前完成代码、测试、dry-run、PR、候选制品、回滚脚本和证据包。

## 23.2 回滚原则

- 代码：current 原子切回上个**兼容 v2 schema**的 release；
- 数据：expand/contract，观察期不做 destructive down migration；
- 事件：切换后的新事件永不因回滚被覆盖；
- CI：故障时保持 required checks，转人工受保护 PR；
- 自动合流：故障后保持关闭；
- Dashboard：故障后保持只读/不可用；`underlying_gate_outcome` 保持 aggregator 的真实判定、不被覆盖，`release_readiness` 因必需观测面不可用而 BLOCKED；
- 分支保护：before JSON 只用于审计和安全恢复，不得恢复已知绕过。

一次部署授权可以预授权“本次 ACTIVATING 失败时，在指定观察窗内切回精确 previous_release_id”；除此之外的独立生产回滚仍需新授权。

---

# 24. 完成定义与证据包

## 24.1 硬完成门

不得用总分作为放行门。只有以下硬条件全部达成才算最终闭环：

- W0–W10 全部 DoD；
- traceability 零孤儿；
- 所有旧假绿红探针在新实现中均正确阻断；
- 全部 required checks exact-SHA、未过期、来自可信 provenance；
- P0/P1=0；
- 活跃 ACCEPTED_RISK=0；存在任何合法低风险接受时只能走 `AUTHORIZED_CONDITIONAL`，不得称清零或最终生产闭环；
- 账本无非法状态、无未裁定 quarantine；
- 清零范围内无 OPEN/FIXING/FIXED_PENDING_VERIFY；
- 并发、kill、磁盘满、只读、时钟、网络、TCC 故障注入通过；
- targeted mutation 和全量测试门达成；
- 浏览器、launchd、备份恢复、原子部署、回滚均真实演练；
- shadow/canary/14 天观察窗达标；
- 独立 S5 与战训四查通过；
- 未覆盖威胁和生产边界明确列出。

## 24.2 证据包目录

```text
evidence/<program-run-id>/
  00-baseline/
  01-threat-model-and-contracts/
  02-schemas-and-tla/
  03-red-probes-before/
  04-unit-property-mutation/
  05-concurrency-crash-chaos/
  06-scanner-goldens/
  07-migration-reconcile/
  08-ci-and-branch-rules/
  09-release-manifest-attestation/
  10-ui-launchd-alert-backup/
  11-shadow-canary/
  12-rollback-drill/
  13-observation-window/
  evidence-index.json
```

每项绑定 run_id、commit、environment、scope、ruleset、时间、argv、真实 rc、artifact SHA256 和 fresh_until。

---

# 25. 本轮复审发现族→工作包→测试→证据追踪矩阵

下表只覆盖本轮复审形成的**稳定发现族**，不是把 dashboard 投影的 481 条旧记录假称为已经逐条追踪。W5 必须另产出 `legacy_record_id → canonical_finding_id → migration_decision_id → evidence` 的 481 条逐项 reconciliation 索引；数量若随 W0 快照变化，以新快照分母为准并解释差异。

| FND-ID | 复审发现族 | 工作包 | 精确测试 ID | 主要证据 |
|---|---|---|---|---|
| FND-001 | auto-merge 子串、UNSTABLE、`--admin` | W0/W3B | MRG-01～07 | containment、branch rules、merge dry-run |
| FND-002 | L4 直推/文本绕过 | W1/W3B | DOC-03、MRG-01～04 | policy diff、required API 回读 |
| FND-003 | base 不存在/零测试假绿 | W3A | GATE-01～03 | runner 原始日志 |
| FND-004 | verifier 信任 rc/findings/symlink/N | W2/W3B | GATE-04～12 | red-probes before/after |
| FND-005 | 任意状态、路径穿越、无授权 clear | W1/W2 | STATE-01～05、AUTH-01 | property/concurrency/crash 日志 |
| FND-006 | pending-watch 82 次假活 | W2/W4 | SCH-02、ALT-02 | outbox/send attempt/receipt |
| FND-007 | Gate 红、dashboard 87 绿 | W8 | UI-04、HLT-01 | aggregator/UI 同水位对照 |
| FND-008 | runtime/source 热补漂移 | W0/W7A/W7B | REL-01～03、DEP-04 | manifest/attestation |
| FND-009 | 安装器原地覆盖、doctor 吞错 | W7A/W7B | REL-01～03、DEP-01～03 | deploy/rollback drill |
| FND-010 | DB 至少 280 项仍 CLEAN | W6C | DB-01～06 | canonical diff/golden |
| FND-011 | supply FAIL 仍 exit0/刷新心跳 | W4/W6B | SC-01～05、SCH-02 | station-result/heartbeat |
| FND-012 | advisory UNKNOWN 写 seen | W6B | ADV-01～02 | 分页/版本 fixtures |
| FND-013 | 租户扫描固定分母、当前约漏 172 | W6C | TEN-01～08 | DMMF/AST/runtime probes |
| FND-014 | 性能 null/500/错误 p95 | W6D | PERF-01～06 | load profile/raw metrics |
| FND-015 | 当前 481 项多 schema/非法状态 | W5 | MIG-01～05、STATE-01/03～06 | migration reconciliation |
| FND-016 | 当前 43 ACCEPTED 缺要素 | W5 | MIG-02、RISK-01、COND-01/04/05 | risk acceptance events |
| FND-017 | 调度多正源/TCC/假心跳 | W4/W7B | SCH-01～06、ALT-01～02 | launchd 真环境日志 |
| FND-018 | `/api/decide` 无鉴权/非原子 | W2/W8 | AUTH-01～06、UI-03 | security E2E/audit event |
| FND-019 | 总览空白、日志不显示、状态不可点 | W7B/W8 | UI-01、UI-05～07 | Playwright trace/screenshots |
| FND-020 | Skill/版本/枚举/数量/状态说明漂移 | W1/W10 | DOC-01～04 | consistency report |
| FND-021 | 本机磁盘约 90% | W0/§22/W7A/W10 | CAP-01、BAK-01、DEP-06 | capacity budget/recovery |

脚本必须校验每个 `FND-*` 至少映射一个工作包、一个已定义测试 ID 和一个证据路径；每个高风险测试必须反向映射需求。481 条旧记录的逐项映射属于 W5 交付物，不在本方案验证阶段冒充已完成。

## 25.1 全部验收 ID 的反向需求/AC 映射

为避免用“非高风险”逃避追踪，§20 当前定义的 **全部测试均按高风险处理**。以下范围必须由机器展开到每一个 ID；任何新增测试若未进入本表即 governance check 失败。

| 测试 ID 范围 | 冻结需求 / AC | 工作包 | 必需证据类 |
|---|---|---|---|
| GATE-01～12 | REQ-EVID-001 / AC-EVID-FAIL-CLOSED | W2/W3A/W3B | raw rc、CAS、before/after |
| AUTH-01～06 | REQ-AUTH-001 / AC-AUTH-ONE-TIME | W1/W2 | signed payload、replay log |
| ACT-01～06 | REQ-ACT-001 / AC-ACT-SAGA | W2/W3B/W7B | outbox、external receipt、reconcile |
| MRG-01～07 | REQ-MERGE-001 / AC-MERGE-EXACT-SHA | W3B | ruleset、check、merge audit |
| STATE-01～11 | REQ-STATE-001 / AC-STATE-APPEND-ONLY | W1/W2 | event log、property/crash run |
| MIG-01～05 | REQ-MIG-001 / AC-MIG-RECONCILE | W5 | row mapping、decision、quarantine |
| DB-01～06 | REQ-DB-001 / AC-DB-FOUR-TRACK | W6C | catalog diff、DB identity |
| SC-01～05 | REQ-SC-001 / AC-SC-FAIL-CLOSED | W6B | audit JSON、SBOM、signature |
| ADV-01～02 | REQ-ADV-001 / AC-ADV-COMPLETE | W6B | pages/ranges fixture |
| TEN-01～08 | REQ-TENANT-001 / AC-TENANT-DENOMINATOR | W6C | DMMF/AST/runtime probes |
| PERF-01～06 | REQ-PERF-001 / AC-PERF-VALID | W6D | raw samples/profile/baseline auth |
| SCH-01～07 | REQ-SCHED-001 / AC-SCHED-RESULT | W4 | launchd/job result/freshness |
| ALT-01～02 | REQ-ALERT-001 / AC-ALERT-DELIVERED | W4 | outbox/attempt/receipt/dead-letter |
| BAK-01 | REQ-BACKUP-001 / AC-BACKUP-RESTORABLE | W4/W7A | checkpoint/restore drill |
| REL-01～03 | REQ-RELEASE-001 / AC-RELEASE-MANIFEST | W7A/W7B | manifest/build identity |
| STOP-01～03 | REQ-STOP-001 / AC-STOP-AUTH-AND-FACT | W1/W2 | nine-type matrix/events |
| RUN-01～03 | REQ-RUNNER-001 / AC-RUNNER-ISOLATED | W2 | sandbox/quota/process-tree logs |
| CI-05～09 | REQ-CI-001 / AC-CI-TERMINAL | W3B | check runs/ruleset/DAG validation |
| COND-01～06 | REQ-COND-001 / AC-COND-NOT-PASS | W1/W2/W3B | risk/action auth、attestation、context |
| RISK-01 | REQ-RISK-001 / AC-RISK-INVALIDATE | W2/W5 | revoke/invalidate/reopen events |
| STA-01～02 | REQ-STATION-001 / AC-STATION-COVERAGE | W6A～W6D/W3B | station results/aggregate |
| DEP-01～09 | REQ-DEPLOY-001 / AC-DEPLOY-FENCED | W7A/W7B | lease/migration/activation events |
| RB-01 | REQ-ROLLBACK-001 / AC-ROLLBACK-EXACT | W7B | preauthorization/compatibility/drill |
| UI-01～07 | REQ-UI-001 / AC-UI-TRUTHFUL-SECURE | W8 | Playwright/DOM/security trace |
| HLT-01 | REQ-HEALTH-001 / AC-HEALTH-ATOMIC | W8 | input watermark/snapshot retry |
| DOC-01～04 | REQ-DOC-001 / AC-DOC-REGISTRY-CONSISTENT | W1/W10 | generated consistency report |
| CAP-01 | REQ-CAP-001 / AC-CAP-SAFE-MARGIN | W0/W7A | peak budget/disk-full injection |
| DR-01 | REQ-DR-001 / AC-DR-RPO-RTO | W4/W7B/W10 | restored state/RPO/RTO timing |

机器校验的集合等式必须成立：`defined_test_ids(§20) == expanded_mapped_test_ids(§25.1)`；不得只比较数量，也不得允许重复 ID 掩盖缺失 ID。

---

# 26. ZCode 每个工作包的固定回报格式

```text
工作包：W?
状态：候选完成 / 部分完成 / BLOCKED
正源与 SHA：
变更文件：
需求/AC/测试映射：
正向验证：命令、退出码、工件
负向验证：注入、预期、实际、工件
并发/崩溃/恢复验证：
未覆盖与豁免：
部署状态：未部署 / 候选 / 已授权部署
回滚级别：R1记录 / R2演练 / R3执行
用户停等动作：
独立复核结论：
```

严禁只报“测试通过”“HTTP 200”“页面正常”“脚本存在”或一个总分。

---

# 27. 本方案自身验证要求

在交付 ZCode 前必须完成：

1. 当前路径、SHA、数值和运行状态复核；拟建路径明确标注为建议，不冒充已存在。
2. 发现→工作包→测试→证据追踪矩阵零孤儿。
3. 依赖 DAG 无环，所有高风险动作均能到达用户停等点。
4. 全文扫描越界措辞；不得把方案、候选或未授权动作写成已整改/已生产/零盲区。
5. Markdown UTF-8、标题、代码围栏、表格基本结构校验。
6. 独立红队复核安全架构、迁移、回滚和完成定义。
7. 输出文件 SHA256，确保交接后可验真。

最终强调：**方案已验证，不等于整改已验证；当前生产准入结论仍为 BLOCKED。**

---

# 28. ZCode 首轮落刀靶点（快照锚点）

下列行号已在本轮复核时确认存在，仅用于快速定位；ZCode 开工必须先按 W0 记录新 SHA/hash 并重新定位语义，禁止因行号漂移盲改。现役目录只读取证，修复落在对应版本化正源的干净 worktree；尚无远端的 `/Users/maccc/.zcode/quality-system` 先完成 W0 责任仓裁定。

| 目标 | 本轮语义锚点 | 归属工作包 |
|---|---|---|
| `/Users/maccc/.wenqu/daemons/auto-merge.sh` | 34–46、68–75：Fast 子串/UNSTABLE/重试合流 | W0/W3B |
| `/Users/maccc/.zcode/quality-system/bin/pipeline-state.sh` | 34–93：自由状态、路径拼接、直接 clear | W1/W2/W5 |
| `/Users/maccc/.zcode/quality-system/bin/pending-watch.sh` | 51–68：文本协议、notify bump | W2/W4 |
| `/Users/maccc/.zcode/quality-system/bin/verify-convergence.py` | 55、100–112、121–179、225–263：N/自报结果/证据/超轮 | W2/W3B |
| `/Users/maccc/.wenqu/bin/iron-gate.sh` | 18–85：diff 错误传播和文本式检查 | W3A |
| `/Users/maccc/.wenqu/bin/zero-rework.sh` | 29–65：affected test/无测试分支 | W3A |
| `/Users/maccc/Documents/wenqu-dist/system/install.sh` | 13–25、49–52：原地复制并吞掉 doctor 失败 | W7A |
| `/Users/maccc/Documents/wenqu-dist/system/bin/wenqu-dashboard.py` | 187–213、476–477、750–791、855–958：DOM、XSS、写接口、独立评分 | W2/W8 |
| `/Users/maccc/argus-assemble/scripts/bugscan/judge_drift.py` | 7–8：工具错误 exit 0/文本计数 | W6C |
| `/Users/maccc/argus-assemble/scripts/bugscan/db-drift-weekly.sh` | 39–47、63–88：远端错误/空 diff/恒 exit 0 | W4/W6C |
| `/Users/maccc/argus-assemble/scripts/bugscan/supply-chain-audit.sh` | 40–56、125–131：吞掉 npm audit 失败且恒 exit 0 | W4/W6B |
| `/Users/maccc/argus-assemble/scripts/bugscan/advisory-watch.sh` | 37–62：分页/seen/无 verdict gate | W4/W6B |
| `/Users/maccc/argus-assemble/scripts/bugscan/export-tenant-audit.mjs` | 18–85：固定模型/字符串启发式/心跳 | W6C |
| `/Users/maccc/argus-assemble/scripts/bugscan/perf-baseline-runner.sh` | 32–127：HTTP/SSH/null/p95/恒 exit 0 | W6D |
| `/Users/maccc/Documents/ERP）Zcode/qisemi-master-full/.github/workflows/ci.yml` | 103–109、664–726：Gate 触发条件、audit warning+continue | W3B/W6B |

首轮实施顺序不是逐文件盲修，而是：先 W0 冻结与隔离危险写面，再 W1/W2 建立可信契约和核心，随后按 §8 DAG 迁移 adapter。任何对现役脚本的临时止损都必须单独授权、保留 before hash，并在正源中补齐后才能撤销漂移。

---

# 29. 本方案实际验证结果

已执行只读验证器：`/private/tmp/codex-test/evidence/reaudit-20261007/validate_plan.py`。验证对象为本文件，未执行任何合流、部署、服务启停、生产写、DDL、真实告警或回滚。

| 验证面 | 实际结果 |
|---|---|
| UTF-8 / 控制字符 / front matter | PASS；严格 UTF-8，可解析 front matter，NUL=0 |
| Markdown 结构 | PASS；代码围栏成对，全部表格列数一致，标题/章节编号唯一，全部 § 引用有本地目标 |
| 占位符与越界措辞 | PASS；无未决占位标记；现态与方案边界固定为 BLOCKED/未整改 |
| 工作包引用 | PASS；W0～W10 及 W3A/B、W6A～D、W7A/B 均在允许集合，无未定义引用 |
| 依赖 DAG | PASS；机检拓扑无环，关键链为 W3A→W6A～D→W3B，W8→W7B→W9→W10 |
| 测试追踪 | PASS；§20 定义 131 个唯一测试 ID，§25.1 展开映射 131 个，集合完全相等、零重复、零悬空 |
| 复审发现族 | PASS；FND-001～FND-021 连续唯一，每行均有工作包、已定义测试和证据类 |
| 旧账边界 | PASS；481 仅为时点投影，明确由 W5 逐项 reconciliation，不冒充已完成 |
| 停等与授权不变量 | PASS；九类 stop 全部要求一次性授权+客观条件；technical/action eligibility、两类授权和 saga 关键不变量均存在 |
| 快照靶点 | PASS；§28 的 15 个绝对路径在验证时均存在；行号仍须 W0 重定位 |
| 本轮证据包 | PASS；`manifest.sha256` 所列工件逐项 SHA256 校验一致 |
| 独立复核 | PASS；问渠域、Bug 八站域和对抗红队分轮复核，阻断项已逐项回写后再验 |

机器验证结果：**29/29 PASS，exit 0**。最终正文冻结后，以外置 `/private/tmp/codex-test/方案.md.sha256` 作为交接校验；不把自身 hash 嵌入正文，避免自引用失真。验证记录位于同一 evidence 目录。

再次强调：这里通过的是**方案文件的一致性、追踪性和可执行性检查**，不是代码整改验收，不改变当前生产准入 `BLOCKED` 结论。

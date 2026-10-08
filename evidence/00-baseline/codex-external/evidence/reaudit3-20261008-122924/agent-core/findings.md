# 第三轮独立验收子任务 A：P0-1 / P0-2

- 验收对象：`/Users/maccc/Documents/wenqu-dist`
- 冻结 HEAD：`ff050bbb9c95c04ecb975900f5440f9bfcd1a447`
- 方案 SHA256：`96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306`
- 验收原则：产物仓只读；所有删件、SQLite、安装和攻击探针均在 `/tmp` 隔离目录运行。
- 初始/收尾工作树：均 clean，`main...origin/main`，HEAD 未漂移。

## 1. 结论

| 项目 | 判定 | 摘要 |
|---|---|---|
| P0-1 核心接线 | **FAIL（移除法子门 PASS，但真实接线未闭环）** | 删除 `wenqu_pipeline.py` 后两个指定测试均 rc=1；但同一删件副本的 `install.sh` 仍 rc=0 且安装体确实缺该模块。仓内除测试、注释和证据外无 `RunManager/ApprovalBroker` 生产调用方，也无 `wenquctl/bugscanctl`。 |
| P0-2 七段状态机 + Approval Broker | **FAIL / BLOCKED** | 自带行为测试 10/10、指定三类攻击（跨 run nonce、批准包后取消、resume state_version 回绕）通过；但独立攻击实证至少 10 条安全/契约失败，包括伪签名和缺绑定字段可恢复、risk payload 可冒充 resume、未恢复资源可恢复、非 resume 授权不做 CAS、TIMEOUT+P1 风险被洗成条件完成、直接 append 伪造 SUCCEEDED、nonce 消费依赖第二正源、正式 run schema 不接受实现自产 WAITING 事件，且方案要求的 action saga/outbox 完全不存在。 |
| 子任务总判定 | **BLOCKED** | P0-1/P0-2 都不能关闭；不得用 10/10 自测或移除法的局部成功替代完整业务不变量。 |

## 2. P0-1：核心接线复验

### 2.1 指定移除法：PASS

隔离副本移走 `system/wenqu_core/wenqu_pipeline.py`：

- `python3 system/tests/test_core_wiring.py` → **rc=1**，7 PASS / 1 FAIL，明确报 `No module named 'wenqu_core.wenqu_pipeline'`；
- `python3 system/tests/test_wenqu_pipeline.py` → **rc=1**，导入即失败。

证据：`09-removal-wenqu_pipeline.log`。

这证明 active `acceptance.sh` 的 P1/P1b 测试锚点确实依赖该文件（`tests/acceptance.sh:337-360`），关闭了第二轮“删核心后测试仍全绿”的**窄问题**。

### 2.2 真实安装/CLI/运行接线：FAIL

1. **安装器仍可漏装状态机并成功。** 在同一删件副本执行 `system/install.sh --prefix <tmp>`：rc=0，输出“wenqu_core 安装验证通过”，而安装目标中 `lib/wenqu_core/wenqu_pipeline.py` 不存在。原因是安装自检只导入 `TrustedRunner`（`system/install.sh:38-43`），未导入/运行 `RunManager`。证据：`16-removal-installer-still-green.log`。
2. **没有生产调用方。** 排除模块自身与行为测试后，全仓对 `RunManager/SevenStageStateMachine/ApprovalBroker/wenqu_pipeline` 的命中仅剩 `acceptance.sh`、traceability、`test_core_wiring.py` 和 `__init__.py` 注释；无 CLI、daemon、scheduler、dashboard 控制器实际调用。证据：`10-core-wiring-callsites.log`。
3. **缺方案控制入口。** `system/bin/` 中没有 `wenquctl` 或 `bugscanctl`；现有 `system/bin/wenqu:10-135` 仍是旧 shell 命令面，没有七段 create/advance/wait/resume/complete 命令。
4. **测试接线不等于运行接线。** `.github/workflows/acceptance.yml:19-20` 会间接跑 `acceptance.sh`，所以 CI 存在性锚点已接；但产物被安装后没有任何入口消费新状态机，无法形成方案 §5 TCB 所需的 planner/controller 链。

因此 P0-1 不能标 PASS；准确表述是“**移除法测试锚点已建立，安装与 CI 仅部分接线，业务运行入口仍未接线**”。

## 3. P0-2：静态契约核对

### 3.1 已证实通过的部分

| 子项 | 结论 | 代码/运行证据 |
|---|---|---|
| 七段枚举与顺序 | PASS（局部） | `wenqu_pipeline.py:97-105,530-578`；自测规则/完整 happy path 通过。 |
| Run/attempt 基本转换表 | PASS（局部） | `:107-165,553-564`；非法表内转换测试通过。 |
| 九种 stop type 枚举 | PASS（仅枚举） | `:177-188,582-592`；九种均能走自测。 |
| retry 新 attempt、旧 attempt 保留 | PASS（正常 API 路径） | `:1527-1545,1577-1579`；自测证明 FAILED 重试生成新 ID。 |
| resume nonce 与事件同事务 | PASS（resume 路径） | `:984-1066`；`BEGIN IMMEDIATE` 中先占 nonce 再追加事件；并发双消费自测与跨 run nonce 独立探针均恰一成功。 |
| resume state_version CAS | PASS（仅 resume） | `:971-978`；独立回绕样例 expected=v-1 被拒。 |
| 已取消 run 拒绝 resume | PASS | `:912-919`；独立“审批包形成后 cancel”样例被拒且 nonce 未消费。 |
| 事件驱动的在线 run 投影 | PASS（正常受控 API happy path） | `_load_state()` 每次从 `pipeline_events` 折叠（`:1406-1416`）；第二管理器重放 happy path 一致。 |

自带测试运行：`python3 system/tests/test_wenqu_pipeline.py` → **10 PASS / 0 FAIL，rc=0**。证据：`08-test-wenqu-pipeline.log`。

### 3.2 阻断性失败

#### A. Approval 不是可信的人类授权：伪签名、缺身份绑定仍可恢复

- 方案 §6.5 将 `task_id/stage/environment/authorized_scope/policy_hash/ruleset_hash/input_watermark/expected_state_version` 列为公共 envelope 最小字段；Schema 和内置校验的 required 顶层却都未要求其中大部分（Schema `approval-v2.schema.json:7-33`；实现 `wenqu_pipeline.py:264-272`）。
- 绑定检查全部采用“字段存在才比较”（`:946-970`），因此删除这些字段即可绕过 scope/env/SHA/policy/ruleset/task/stage 绑定。
- `signature` 只检查字符串长度（`:856-857`），没有验签、key_id、audience、user-presence 或可信 actor 校验。
- 实证：删掉全部上述可选绑定字段，`actor=mallory`、`signature='X'*32`，仍成功 `WAITING→RUNNING`。

证据：`11-adversarial-pipeline.log` 的 `missing_identity_bindings_and_fake_signature`。

#### B. approval 判别联合可跨类型混装；risk 可冒充 resume

- `consume()` 没有断言 `approval_type == resume`（`:1003-1015`）。
- payload 只检查“本类型 required 字段存在”，不拒绝其他类型字段（`:866-881`）；Schema 的 payload 也没有 `additionalProperties:false` 或互斥 oneOf。
- 构造 `approval_type=risk`，同时带 risk 和 resume 字段：正式 jsonschema 与 Broker 结构校验均接受，且 `resume_waiting()` 真正恢复 run，消费台账记录的类型还是 `risk`。

证据：`11-adversarial-pipeline.log` 的 `cross_type_risk_payload_resumes_waiting`；`14-approval-schema-cross-type.log`。

#### C. 九停等“客观恢复”只是调用者自报的非空值

- `_truthy()` 将任意非空字符串视为真（`:400-406`）。
- `probe_recovered="false"`、`safety_margin_met="false"` 仍通过 resource 前置条件并恢复，与方案 STOP-02“未恢复即使已批准也必须拒绝”相反。
- 所有 gate/probe/manifest/ref 字段也只验非空，未回读权威证据或验证 CAS digest。

证据：`11-adversarial-pipeline.log` 的 `resource_not_recovered_string_false`。

#### D. SHA 绑定可用畸形 watermark 绕过

- 代码只有在 `input_watermark` 已经是 40 位 SHA 时才做比较（`:964-970`）；`"not-a-sha"` 直接跳过。
- 实证：完整审批仅改 `input_watermark="not-a-sha"`，恢复成功。

证据：`11-adversarial-pipeline.log` 的 `malformed_input_watermark_bypasses_sha_binding`。

#### E. 非 resume 授权没有 state_version CAS；action saga 缺失

- `consume_authorization()` 的绑定逻辑（`:1091-1123`）不要求也不比较 `expected_state_version`。
- 实证：run 实际 `state_version=2`，risk 审批声明 `expected_state_version=1` 仍被消费。
- 全 `system/wenqu_core` 搜索不到 `ACTION_AUTH_RESERVED/ACTION_STARTED/ACTION_COMMITTED/ACTION_FAILED_UNKNOWN/control_outbox/action_eligible/AUTHORIZED_CONDITIONAL`；没有方案 §6.1 的动作 saga、outbox、外部 receipt/reconcile，更谈不上 merge/release/DDL/prod-write 的恰一次动作。

证据：`17-nonresume-cas-bypass.log`、`13-static-security-gaps.log`。

#### F. 双轴可把 TIMEOUT 洗成合法条件完成；P1 风险接受和 finding 脱绑

- `validate_outcome()` 只禁止“非 COMPLETED + PASS”，并未禁止 `TIMEOUT/ERROR/BLOCKED + CONDITIONAL`（`:639-659`）；`verdict_to_attempt_status()` 仅看 verdict，把它映射为 `COMPLETED_CONDITIONAL`（`:662-670`）。
- risk 消费表不保存 payload/finding 集/severity/补偿控制，仅保存 nonce、类型、run 等（`:786-800,1135-1155`）；`has_unexpired_risk_authorization()` 只查类型和顶层 expiry（`:1183-1195`）。
- `complete_run()` 只看 soft stage 和“有任一未过期 risk 行”（`:1720-1731`），不核对实际 finding 集。
- 实证：S7=`TIMEOUT+CONDITIONAL`、实际 finding=`fnd_timeout_actual`，用伪签名 risk 审批接受完全不同 fingerprint，severity=`HIGH`，最终被写成 `execution_status=COMPLETED / COMPLETED_CONDITIONAL`。
- 方案 §10.2 明确 `HIGH→P1` 且 P0/P1 不得风险接受。仓内自测反而在 `test_wenqu_pipeline.py:394-420` 用 `severity=HIGH` 并期望条件完成，说明测试把违约行为固化成“绿”。

证据：`11-adversarial-pipeline.log` 的 `timeout_conditional_p1_unbound_risk_laundered`。

#### G. EventStore 公共 append 可绕过 RunManager 伪造 SUCCEEDED

- `EventStore.append()` 接受任意 dict，仅做内容哈希并落库（`store.py:78-105`）。
- 重放 `RUN_COMPLETED` 时只按 event 双轴选择终态和验证 run 转换，不验证七段均 PASSED（`wenqu_pipeline.py:1380-1394`）。
- 实证：S1 仍 RUNNING、S2～S7 PENDING 时直接 append 一个合法链上 `RUN_COMPLETED/PASS`；`get_run()` 得到 `SUCCEEDED`，`verify_chain()` 仍 `ok=true`。

证据：`11-adversarial-pipeline.log` 的 `direct_event_append_forges_success`。

#### H. run 终态与 attempt 投影不一致

- `cancel_run()` 只追加 `RUN_COMPLETED/CANCELLED`（`:1754-1767`）；重放分支没有把当前 RUNNING attempt 转为 CANCELLED。
- 实证：取消活动 run 后 run=`CANCELLED`，S1 attempt 仍=`RUNNING`，与代码注释“attempt 亦 CANCELLED 由重放推导”及契约转换不一致。

证据：`11-adversarial-pipeline.log` 的 `cancelled_run_leaves_running_attempt`。

#### I. “事件重放无第二正源”不成立

- nonce/risk 权威状态保存在可变 `approval_consumptions` 表（`:786-800`），非 resume 授权明确“不产生管线事件”（`:1078-1084`）。
- 只重放 `pipeline_events` 到新库后，run 投影可恢复，但已消费 nonce 丢失；原库拒绝的同 nonce，在重放库被再次消费并恢复。
- 因而事件流不足以恢复审批一次性语义；`approval_consumptions` 是事实上的第二正源，且没有 append-only trigger/hash chain。

证据：`11-adversarial-pipeline.log` 的 `event_replay_loses_nonce_consumption_second_source`。

#### J. 实现自产 WAITING 事件不符合正式 run-event-v2 Schema

- 模块开头明确承认 WAITING 事件带 Schema 未定义扩展（`:47-52`）。
- 正式 Schema `additionalProperties=false`（`run-event-v2.schema.json:54`），又未声明 `stop_type/stop_reason/required_preconditions/approval_id/nonce_digest`。
- 实证：自产 `WAITING_RAISED` 被正式 jsonschema 拒绝，错误为这些字段均 unexpected。

证据：`11-adversarial-pipeline.log` 的 `emitted_waiting_event_violates_run_schema`。

## 4. 对抗探针总表

| 探针 | 安全期望 | 实际 | 判定 |
|---|---|---|---|
| 跨 run 复用同 nonce | 拒绝 | `ApprovalReuseError`，目标 run 保持 WAITING/v3 | PASS |
| 审批包形成后 run 已 cancel | 拒绝 | terminal 拒绝，nonce 未占用 | PASS |
| resume state_version 回绕 | 拒绝 | CAS failure，状态不变 | PASS |
| 缺 task/stage/env/scope/policy/ruleset/SHA + 伪签名 | 拒绝 | 成功恢复 | **FAIL** |
| risk+resume 跨类型 payload | 拒绝 | Schema、Broker、实际恢复均接受 | **FAIL** |
| resource 未恢复（字符串 false） | 拒绝 | 成功恢复 | **FAIL** |
| 畸形 input_watermark | 拒绝 | 成功恢复 | **FAIL** |
| risk expected_state_version 旧版本 | 拒绝 | 成功消费 | **FAIL** |
| S7 TIMEOUT + HIGH/P1 不匹配风险接受 | 拒绝 | 最终 COMPLETED_CONDITIONAL | **FAIL** |
| 公共 EventStore 直写 RUN_COMPLETED/PASS | 拒绝 | S1 RUNNING 时伪造 SUCCEEDED，链仍有效 | **FAIL** |
| cancel 活动 run | 当前 attempt 应 CANCELLED | attempt 仍 RUNNING | **FAIL** |
| 仅事件重放 | 保留 nonce 已消费语义 | 同 nonce 在重放库再次成功 | **FAIL** |
| 自产 WAITING 事件对正式 Schema | 接受 | jsonschema 拒绝 | **FAIL** |

## 5. 证据索引

- `00-inventory.log`：HEAD、clean 状态、方案/报告 SHA。
- `03-code-outline.log`：类/方法/安全锚点索引。
- `04-wenqu_pipeline-numbered.txt`：1792 行实现全文带行号。
- `05-test_wenqu_pipeline-numbered.txt`：行为测试全文带行号。
- `06-test_core_wiring-numbered.txt`：核心接线测试全文带行号。
- `07-approval-schema-numbered.txt`：审批 Schema 带行号。
- `08-test-wenqu-pipeline.log`：10/10 自测 rc=0。
- `09-removal-wenqu_pipeline.log`：指定两个移除法测试均 rc=1。
- `10-core-wiring-callsites.log`：生产调用点缺失、控制入口缺失、CI 间接接线。
- `11-adversarial-pipeline.log`：12 个独立动态对抗探针、3 个安全通过、9 个失败。
- `12-final-worktree.log`：收尾 clean、HEAD 未漂移、关键文件 SHA。
- `13-static-security-gaps.log`：action saga 关键字零命中、Schema 静态证据。
- `14-approval-schema-cross-type.log`：跨类型 payload 被 jsonschema 与 Broker 双接受。
- `15-contract-source-excerpts.log`：冻结方案、第二轮 P0、仓内契约带行号摘录。
- `16-removal-installer-still-green.log`：模块缺失但安装器 rc=0 的反证。
- `17-nonresume-cas-bypass.log`：非 resume 授权 state_version 回绕仍接受。
- `adversarial_pipeline.py`：动态探针源代码。

## 6. 最短整改要求（供总报告引用）

1. P0-1：让正式 CLI/controller/scheduler 实际调用 `RunManager`；安装器必须导入并执行状态机 smoke，删模块时安装本身非零；新增 `wenquctl/bugscanctl` 或等价唯一入口，而非仅测试导入。
2. Approval：公共 envelope 全字段 required；真实验签、key/audience/user-presence；payload 使用互斥封闭 schema；`consume()` 强制 resume 类型。
3. STOP：客观条件必须是 typed、受信探针/证据回读，布尔必须严格 `true`，禁止非空字符串代替事实。
4. 所有授权统一做 `expected_state_version` CAS；risk/action 绑定完整 finding/SHA/env/scope/policy/ruleset/watermark/TTL；P0/P1 机器拒绝。
5. 双轴矩阵从严：非 `COMPLETED` 不得进入可授权 CONDITIONAL；禁止 TIMEOUT/ERROR 洗成完成。
6. 收敛事件写入口：禁止裸 `EventStore.append` 注入控制事件，重放器自身验证七段终态不变量和 identity 恒定。
7. 把 nonce/risk/action authorization 也事件化，或以可重放的 append-only 同链事件建立唯一正源；不得依赖可变旁表。
8. 实现完整 action saga/outbox/receipt/reconcile；修复 cancel/supersede 的 attempt 终态；使所有自产事件严格通过正式 Schema。

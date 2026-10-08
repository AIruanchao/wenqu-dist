# TLA+ 规约与 TLC 模型检查运行记录（2026-10-08）

任务：对七段状态机 + 审批消费建 TLA+ 规约并做模型检查——闭环 Codex 多轮
指出的 W1 缺口（无 Wenqu TLA/TLC）。

- 分支：`wave6/p1f-gate`（工作区含本波其他未提交变更；本件只新增
  `specs/tla/*`、`system/tests/test_tla_spec.py`、本目录证据）
- 规约正本：`specs/tla/wenqu_pipeline.tla`（含规约-代码映射总表）
- 模型配置：`specs/tla/wenqu_pipeline.cfg`（2 段 × 2 attempt 界）
- 结构对照测试：`system/tests/test_tla_spec.py`（10 用例）

## 1. 环境探测（真实输出，非推断）

| 探测项 | 结果 |
|---|---|
| `java -version` | `openjdk version "17.0.20.1" 2026-08-18`（Temurin-17.0.20.1+1） |
| TLC | `TLC2 Version 2.15 of Day Month 20?? (rev: eb3ff99)`（`java -cp system/bin/tla2tools.jar tlc2.TLC` 探测成功） |
| jar 指纹 | `system/bin/tla2tools.jar` sha256 `8cce75caa1e59d0b0483bb8fb881ba33825edce8b2d98aba59d66ce685dd3d1a` |
| 结论 | **TLC 可用，执行真实模型检查**（无不可用边界需声明） |

## 2. 正主模型检查（全量不变量）

命令（exit 0）：

```bash
cd specs/tla && java -Xmx2g -XX:+UseParallelGC \
  -cp ../../system/bin/tla2tools.jar tlc2.TLC -workers 4 -coverage 1 \
  wenqu_pipeline.tla
```

结果（原始输出：`tlc-wenqu-pipeline-2026-10-08.log`）：

```
Model checking completed. No error has been found.
2442 states generated, 834 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 12.
```

- 检查的不变量（cfg INVARIANT 全列）：TypeOK / NoSkipStages /
  PriorPassedGate / AttemptImmutable / NonceOnceConsumed / TerminalFinal /
  DoubleAxisNoWash——各在 834 个可达状态上逐态检验。
- 覆盖统计证实非空转（动作→不同后继发现数）：StartStage 31、
  CompleteStage 129、RaiseWaiting 43、ConsumeResume 2、ConsumeRisk 14、
  FinishSucceeded 38、FinishConditional 28、FinishFailed 109、
  CancelRun 220、SupersedeRun 220。FinishSucceeded/FinishConditional 非 0
  证第二段确实启动并 PASSED/软终态（PriorPassedGate 对 i=2 非空洞）。

## 3. 变异探针（证明检查可证伪，全部在 /tmp 副本上执行，未动仓内规约）

原始输出：`tlc-wenqu-pipeline-mutation-probes-2026-10-08.log`。

| 变异 | 破坏的守卫/锁（代码对应） | TLC 结果 |
|---|---|---|
| mutA2_nonce_risk | ConsumeRisk 去掉 `nonceUsed[n]=0`（nonce 一次性；risk 消费不 bump ver，CAS 锚不失效，nonce 是唯一锁——真实复用场景） | **NonceOnceConsumed violated**（38 态捕获） |
| mutB_outcome | CompleteStage 去掉 ValidOutcome（validate_outcome :1017 PASS-需-COMPLETED 门） | **DoubleAxisNoWash violated**（P_WASH 金丝雀入历史；单独归因运行见日志尾） |
| mutC_skip | StartStage 去掉 `CurStage=i`（跳段启动） | **NoSkipStages violated**（3 态捕获） |
| mutD_terminal | FinishFailed 去掉分支互斥（complete_run fail-closed） | **TerminalFinal violated**（177 态捕获） |
| mutE_mapper_wash | OutcomeStatus 改为"先看 verdict"（outcome_to_attempt_status :1053 映射锁洗白） | **DoubleAxisNoWash violated**（CC_WASH 金丝雀；单独归因运行见日志尾） |
| mutF_immutable | StartStage 允许在 RUNNING attempt 上叠加新 attempt（:2504） | **AttemptImmutable violated**（5 态捕获） |

注：mutB/mutE 在全不变量 cfg 下先被 AttemptImmutable 报出（金丝雀原子
非合法终态，形状不变量先咬）；用仅含 DoubleAxisNoWash 的 cfg 复跑两者，
归因确认（日志尾 attribution check 节）。

## 4. 规约-代码映射（摘要；全文见 .tla 尾部映射总表）

| TLA | Python 正源 |
|---|---|
| StageOrder / RunStates / TerminalRun / RunTrans | `STAGES` / `RUN_STATES` / `TERMINAL_RUN_STATES` / `RUN_TRANSITIONS`（:176-:216） |
| AttemptStatuses / TerminalAttempt / AttemptTrans | `ATTEMPT_STATES` / `TERMINAL_ATTEMPT_STATES` / `ATTEMPT_TRANSITIONS`（:227-:244） |
| ExecStatuses / PolicyVerdicts / ValidOutcome | `EXECUTION_STATUSES` / `POLICY_VERDICTS` / `validate_outcome`（:247-:252, :1006） |
| VerdictToStatus / OutcomeStatus | `verdict_to_attempt_status` / `outcome_to_attempt_status`（:1029/:1045） |
| StartStage / CompleteStage / RaiseWaiting | `advance_stage`（:2445）/ `raise_waiting`（:2567）+ 折叠 STAGE_STARTED/STAGE_COMPLETED/WAITING_RAISED |
| ConsumeResume / ConsumeRisk | `ApprovalBroker.consume`（:1522）/ `consume_authorization`（:1630）+ `resume_waiting`/`authorize_risk` |
| FinishSucceeded/Conditional/Failed / CancelRun / SupersedeRun | `complete_run`（:2663）/ `cancel_run`（:2822）/ `supersede_run`（:2839） |

结构测试 `test_tla_spec.py` 10 用例全绿（含 25 对双轴全积映射比对、
cfg 完整性）；单 token 漂移注入实证必红（StageOrder 改 1 字节 →
`test_stage_order_matches_stages` 失败，注入后已还原，文件字节一致）。

## 5. 诚实边界

1. **有界实例**：TLC 穷举的是 2 段×2 attempt×4 审批原子×ver≤14
   （834 可达态），非 7 段满配；正典常量表全量收录并由结构测试钉死，
   但未对 7 段满配做穷举（状态空间超本机预算）。
2. **API 级建模**：建模 RunManager 公开 API 可产生的事件序列；
   `_replay_fold` 对 STAGE_STARTED 的接受面更宽（容忍重启已 PASSED 的
   更前段，公开 API 不产生该事件）——折叠层不变量不受影响，但该差异
   存在且已在此声明。
3. **审批抽象**：结构/HMAC/TTL/绑定六元组抽象为预审通过原子；保留
   nonce 一次性、CAS、路由三轴。risk 未过期/指纹匹配抽象为已消费即可用
   （fail-closed 半边保留并被 mutD 证伪性验证）。
4. **findings 恒空**、**不主张活性/无死锁**（NoOp 踏步）、**观察类事件
   （FINDING/ACTION_* saga）未建模**（不推进状态机）。
5. 迭代中修正过三处规约自身缺陷（终态化误用 ReplaceLast、金丝雀键错
   到映射后状态、转换表守卫缺失导致 CREATED→SUPERSEDED 误放开——最后
   一处是真实规约-代码偏差，加表驱动守卫后与代码一致）：均以 TLC 红→
   修正→绿的方式闭环，留痕于本记录。

# specs/tla — 问渠七段状态机 + 审批消费 TLA+ 形式化规约

W1 缺口（Codex 多轮指出：无 Wenqu TLA/TLC）闭环件。规约对象是
`system/wenqu_core/wenqu_pipeline.py` 的：

- **SevenStageStateMachine**——七段枚举 / 8 态 run 转换表 / 7 态 attempt
  转换表 / 前段非 PASSED 不得启动后段 / 双轴结果映射；
- **ApprovalBroker**——nonce 一次性 / state_version CAS / API 路由判别 /
  同事务原子消费；
- **RunManager** 公开 API（事件折叠 `_replay_fold` 的可产生行为）。

## 文件

| 文件 | 内容 |
|---|---|
| `wenqu_pipeline.tla` | 规约正本：正典常量表 + Next 关系 + 7 不变量，每个定义注明代码行号映射 |
| `wenqu_pipeline.cfg` | TLC 小模型配置：`StageIds={1,2}`、`MaxHistLen=4`（2 段 × 2 attempt 界）、审批原子 r1/r2/k1/k2 |

## 运行 TLC（真实命令）

```bash
java -Xmx2g -XX:+UseParallelGC \
  -cp system/bin/tla2tools.jar tlc2.TLC -workers 4 \
  specs/tla/wenqu_pipeline.tla
```

最近结果（2026-10-08，TLC 2.15，Temurin 17.0.20.1，
`system/bin/tla2tools.jar` sha256 `8cce75ca…`，原始输出见
`evidence/02-schemas-and-tla/tlc-wenqu-pipeline-2026-10-08.log`）：

```
Model checking completed. No error has been found.
2442 states generated, 834 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 12.
```

覆盖统计（-coverage 1）证实全部 10 个动作在可达状态中真实发生：
StartStage 31 / CompleteStage 129 / RaiseWaiting 43 / ConsumeResume 2 /
ConsumeRisk 14 / FinishSucceeded 38 / FinishConditional 28 / FinishFailed 109 /
CancelRun 220 / SupersedeRun 220（数字为产生不同后继的发现次数）。

## 不变量（与代码逐条对应，详见 .tla 内映射总表）

| 不变量 | 守的契约 | 代码锚点（wenqu_pipeline.py） |
|---|---|---|
| `TypeOK` | 变量类型域 + 停等一致性 | `:816 RunState` / `:791 StageState.status` |
| `NoSkipStages` | 后段启动 ⟹ 前段全部启动过 | `:176 STAGES`（契约 §1 段序） |
| `PriorPassedGate` | 前段非 PASSED 不得启动后段 | `:922 ensure_prior_stages_passed` |
| `AttemptImmutable` | attempt 终态不可变；历史形状 RUNNING/终态交替 | `:765/:2504`，折叠 `:2138/:2211` |
| `NonceOnceConsumed` | nonce 至多消费一次；risk 先消费后可用 | `:1479/:1557`（事件正源） |
| `TerminalFinal` | 终态与 complete_run 三分支一致（fail-closed） | `:2663 complete_run` + 折叠 `:2220` |
| `DoubleAxisNoWash` | 双轴洗白不可能（PASS/CC 不得出自非 COMPLETED 执行） | `:1017/:1053` 双锁 |

变异探针（6 个守卫/映射破坏全部被 TLC 当场抓住，含 DoubleAxisNoWash
单独归因）证明上述检查非空转；`system/tests/test_tla_spec.py` 把正典
常量表与 Python 正源逐项比对，防规约漂移（任何一侧改动不同步即红）。

## 诚实边界

1. **有界模型**：TLC 检查的是 2 段 × 2 attempt × 4 审批原子 × ver≤14 的
   有界实例（穷举 834 可达状态）；正典常量表（7 段、全部转换表、25 对
   双轴映射）全量收录且由结构测试钉死，但 7 段满配实例未做 TLC 穷举
   （状态空间超本机预算；性质结构对段数参数化）。
2. **API 级语义**：规约建模 RunManager 公开 API 可产生的行为
   （advance_stage 只推进 `current_stage`）。`_replay_fold` 的
   STAGE_STARTED 守卫（`ensure_prior_stages_passed`）比 API 更宽
   （折叠层容忍"重启已 PASSED 的更前段"，公开 API 永不产生该事件）；
   该差异不影响折叠层自身的不变量（折叠仍逐事件校验段序）。
3. **审批抽象**：结构/HMAC 验签/TTL/绑定六元组（consume 校验链 1-6 步）
   抽象为"预审通过的审批原子"；保留可证伪的 nonce 一次性、CAS、
   API 路由三轴。risk 授权的未过期/指纹精确匹配抽象为"已消费即可用"，
   complete_run 的 fail-closed 半边（无授权不得 COMPLETED_CONDITIONAL）
   完整保留并被变异探针 mutD 验证。
4. **findings 维度恒空**："PASS 不得携带 findings"（validate_outcome
   `:1022`）半边在模型中以恒空 findings 抽象，其代码行为由 Python
   测试面覆盖、文本由结构测试对照。
5. **安全性规约**：不主张活性/无死锁（终态以 NoOp 原地踏步）。
6. **观察类事件**（FINDING_REGISTERED / ACTION_* saga）未建模——它们
   不推进状态机（折叠 `:2059-2123` 登记面侧记），留待后续规约扩展。

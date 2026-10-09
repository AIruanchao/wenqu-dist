------------------------------- MODULE wenqu_pipeline -------------------------------
(***************************************************************************
 * 问渠（Wenqu）七段状态机 + 审批消费 —— TLA+ 形式化规约
 *
 * 正源代码：system/wenqu_core/wenqu_pipeline.py（分支 wave6/p1f-gate）
 *   - SevenStageStateMachine（七段枚举 / 8 态 run 转换表 / 7 态 attempt
 *     转换表 / 前段非 PASSED 不得启动后段 / 双轴结果映射）
 *   - ApprovalBroker（nonce 一次性 / state_version CAS / 同事务原子消费）
 *   - RunManager（事件折叠 _replay_fold 的公开 API 语义）
 *
 * 本规约建模的是 **RunManager 公开 API 可产生的事件序列**（advance_stage /
 * raise_waiting / resume_waiting / authorize_risk / complete_run / cancel_run /
 * supersede_run），即真实系统行为；_replay_fold 是事件正源校验器，其
 * ensure_prior_stages_passed 守卫在 STAGE_STARTED 上逐字对应（见下）。
 *
 * 诚实边界（抽象决策，逐条可核）：
 *   A1. 双配置界（G9-03）：TLC 检查两个有界实例，须各自达到完成级——
 *       配置 A wenqu_pipeline_A.cfg：StageIds={1..7}×MaxHistLen=2
 *       （七段全序 × 每段 1 attempt：覆盖完整段序、S1..S7 全部启动/
 *       终态化与五类 run 终态；resume 在此配置下被 MaxHistLen 界封死，
 *       由配置 B 承接）；配置 B wenqu_pipeline_B.cfg：StageIds={1,2}×
 *       MaxHistLen=4（2 段 × 2 attempt：覆盖 retry 新 attempt、
 *       state_version CAS 命中/失配、nonce 重放拒绝路径）。
 *       正典常量表（StageOrder 七段、RunTrans、AttemptTrans、双轴集合）
 *       按代码全文收录，结构由 system/tests/test_tla_spec.py 与 Python
 *       正源逐项比对防漂移。
 *   A2. attempt 历史 = 状态序列（RUNNING, 终态, RUNNING, 终态, …），
 *       不含 attempt_id/时间戳/证据——不可变语义以序列形状不变量表达。
 *   A3. 审批的结构/签名/TTL/绑定校验（ApprovalBroker.validate_structure /
 *       _verify_signature / _validate_resume_binding 的 1-6 步）抽象为
 *       "预审通过的审批原子"：模型只保留可证伪的核心三轴——
 *       nonce 一次性（nonceUsed）、state_version CAS（ExpectedVer）、
 *       API 路由判别（ApprovalKind: resume|risk）。
 *   A4. 九类停等 stop_type 抽象为单一停等维度；finding 登记面/严重度/
 *       TTL 过期/指纹精确匹配抽象为 riskAuths 非空即可用
 *       （complete_run 的 fail-closed 半边保留：无 riskAuths 不得
 *       COMPLETED_CONDITIONAL）。findings 维度恒空（validate_outcome 的
 *       "PASS 不得携带 findings" 半边由结构测试对照文本）。
 *   A5. advance_stage 的"PASS 后同事务自动启动后段"与"重试模式（终态后
 *       新 attempt 承接双轴结果）"都是 StartStage/CompleteStage 的原子
 *       组合；拆成可交错的两步建模，行为空间是原系统的超集（安全侧）。
 *   A6. 终态/界外状态以 NoOp 原地踏步（安全性规约，不主张活性/无死锁）。
 ***************************************************************************)

EXTENDS Naturals, Sequences

CONSTANTS
    StageIds,     \* 参与模型的段序号全集（cfg-A {1..7} 七段全序；cfg-B {1,2}）
    r1, r2,       \* resume 类审批原子（cfg 中以 model value 赋值）
    k1, k2,       \* risk 类审批原子（同上）
    MaxHistLen,   \* 每段 attempt 历史长度上限（1 attempt 界 = 2；2 attempt 界 = 4）
    MaxVer        \* ver 计数封顶（记忆战训：无界计数撞 TLC 65535 深度限；
                  \*   cfg-A=16：7 段×(启动+终态化)=14 事件 + 至多 1 个
                  \*   run 终态事件，ver ≤ 1+15=16；cfg-B=14）

\* API 路由判别集（consume 只收 resume / consume_authorization 只收 risk）
ResumeApprovals == {r1, r2}
RiskApprovals   == {k1, k2}

\* 审批原子全集（A3：结构/签名/TTL/绑定六元组已预审通过；保留可证伪的
\* 三轴——nonce 一次性、state_version CAS、API 路由判别）
Approvals == ResumeApprovals \union RiskApprovals

\* 各审批锁定的 state_version（CAS 锚；小模型取值覆盖命中/失配两分支）
ExpectedVerOf(n) ==
    IF n = r1 THEN 2
    ELSE IF n = r2 THEN 5
    ELSE IF n = k1 THEN 3
    ELSE 6

VARIABLES
    rstate,          \* run 总状态（RUN_STATES 8 态，wenqu_pipeline.py:196）
    ver,             \* state_version（状态转换事件计数，每事件 +1）
    ahist,           \* [StageIds -> attempt 状态序列]（段 attempt 历史）
    wstage,          \* 0=非停等；否则停等段序号（WaitingInfo.stage 抽象）
    consumed,        \* 已消费审批原子集（APPROVAL_CONSUMED 事件流正源抽象）
    nonceUsed,       \* [Approvals -> Nat] 各审批原子的成功消费次数（nonce 一次性证据）
    riskAuths        \* 已消费且可用的 risk 授权集（authorize_risk 台账抽象）

vars == <<rstate, ver, ahist, wstage, consumed, nonceUsed, riskAuths>>

(***************************************************************************
 * §1 正典常量表 —— 与 wenqu_pipeline.py 逐字对应
 *（test_tla_spec.py 从本节文本读出并与 Python 正源逐项比对，防规约漂移）
 ***************************************************************************)

\* 七段枚举 ↔ wenqu_pipeline.py:176 STAGES（SevenStageStateMachine.STAGES）
StageOrder ==
    << "S1_REQUIREMENT",
       "S2_SOLUTION",
       "S3_EQS_PRE",
       "S4_IMPLEMENT",
       "S5_CONVERGENCE",
       "S6_EQS_FULL",
       "S7_GATE" >>

\* Run 总状态 ↔ wenqu_pipeline.py:196 RUN_STATES
RunStates ==
    { "CREATED", "RUNNING", "WAITING", "FAILED",
      "SUCCEEDED", "COMPLETED_CONDITIONAL", "CANCELLED", "SUPERSEDED" }

\* Run 终态 ↔ wenqu_pipeline.py:201 TERMINAL_RUN_STATES
TerminalRun ==
    { "FAILED", "SUCCEEDED", "COMPLETED_CONDITIONAL",
      "CANCELLED", "SUPERSEDED" }

\* Run 允许转换 ↔ wenqu_pipeline.py:207 RUN_TRANSITIONS（契约 §5 唯一表）
\* （记录键用标识符书写；以 RunTrans["RUNNING"] 字符串下标访问同一字段）
RunTrans ==
    [ CREATED  |-> { "RUNNING", "CANCELLED" },
      RUNNING  |-> { "WAITING", "FAILED", "SUCCEEDED",
                     "COMPLETED_CONDITIONAL", "CANCELLED", "SUPERSEDED" },
      WAITING  |-> { "RUNNING", "FAILED", "CANCELLED", "SUPERSEDED" } ]

\* attempt 状态全集（含未启动）↔ wenqu_pipeline.py:227 ATTEMPT_STATES
AttemptStatuses ==
    { "PENDING", "RUNNING", "PASSED", "COMPLETED_CONDITIONAL",
      "FAILED", "WAITING", "CANCELLED" }

\* attempt 终态 ↔ wenqu_pipeline.py:232 TERMINAL_ATTEMPT_STATES
TerminalAttempt ==
    { "PASSED", "COMPLETED_CONDITIONAL", "FAILED", "WAITING", "CANCELLED" }

\* attempt 允许转换 ↔ wenqu_pipeline.py:238 ATTEMPT_TRANSITIONS（契约 §5 唯一表）
AttemptTrans ==
    [ PENDING  |-> { "RUNNING", "CANCELLED" },
      RUNNING  |-> { "PASSED", "COMPLETED_CONDITIONAL", "FAILED",
                     "WAITING", "CANCELLED" } ]

\* 统一结果双轴 ↔ wenqu_pipeline.py:247 EXECUTION_STATUSES / :250 POLICY_VERDICTS
ExecStatuses ==
    { "COMPLETED", "ERROR", "BLOCKED", "TIMEOUT", "CANCELLED" }
PolicyVerdicts ==
    { "PASS", "FAIL", "CONDITIONAL", "NOT_APPLICABLE", "NOT_EVALUATED" }

Outcomes == ExecStatuses \X PolicyVerdicts

(***************************************************************************
 * §2 派生算子（StageState.status / RunState.current_stage 的折叠等价物）
 ***************************************************************************)

\* 段当前状态：无 attempt 即 "PENDING"，否则最近 attempt 状态
\* ↔ wenqu_pipeline.py:791 StageState.status
LastOf(s) == IF Len(ahist[s]) = 0 THEN "PENDING" ELSE ahist[s][Len(ahist[s])]

\* 最早的未 PASSED 段（全 PASSED 时为 0）
\* ↔ wenqu_pipeline.py:853 RunState.current_stage（advance_stage 只推进它）
CurStage ==
    LET uns == {i \in StageIds : LastOf(i) # "PASSED"}
    IN IF uns = {} THEN 0
       ELSE CHOOSE x \in uns : \A y \in uns : x <= y

AllPassedNow == \A s \in StageIds : LastOf(s) = "PASSED"
HasSoftNow    == \E s \in StageIds : LastOf(s) = "COMPLETED_CONDITIONAL"
SoftOnlyNow   == \A s \in StageIds :
                   LastOf(s) \in {"PASSED", "COMPLETED_CONDITIONAL"}

ElemsOf(s) == {ahist[s][k] : k \in 1..Len(ahist[s])}

(***************************************************************************
 * §3 双轴结果合法性与映射 —— SevenStageStateMachine 逐条对应
 ***************************************************************************)

\* ↔ wenqu_pipeline.py:1006 validate_outcome：
\*   契约 §2 "阻断态不得折算为 PASS"——execution 非 COMPLETED 时策略不得 PASS。
\*   （"PASS 不得携带 findings" 半边在本模型中 findings 恒空，抽象 A4；
\*    该半边由 test_tla_spec.py 对照 Python 正源方法文本。）
ValidOutcome(e, v) ==
    \* 域约束由 Outcomes == ExecStatuses \X PolicyVerdicts 构造保证
    ~(v = "PASS" /\ e # "COMPLETED")

\* ↔ wenqu_pipeline.py:1029 verdict_to_attempt_status（从严映射：只有 PASS 是 PASSED）
VerdictToStatus ==
    [ PASS             |-> "PASSED",
      CONDITIONAL      |-> "COMPLETED_CONDITIONAL",
      NOT_APPLICABLE   |-> "COMPLETED_CONDITIONAL",
      FAIL             |-> "FAILED",
      NOT_EVALUATED    |-> "FAILED" ]

\* ↔ wenqu_pipeline.py:1045 outcome_to_attempt_status
\*   （P0-4 Codex 实锤 #6 根修：execution 非 COMPLETED 一律 FAILED）
OutcomeStatus(e, v) == IF e # "COMPLETED" THEN "FAILED" ELSE VerdictToStatus[v]

\* 双轴洗白金丝雀——两道锁各自可证伪：
\*   P_WASH：verdict=PASS 而 execution≠COMPLETED（API 门锁
\*           advance_stage:2472 validate_outcome 半边"PASS 需 COMPLETED"）；
\*   CC_WASH：终态映射出 COMPLETED_CONDITIONAL 而 execution≠COMPLETED
\*           （映射锁 outcome_to_attempt_status :1053 的 e≠COMPLETED→FAILED）。
\* 两锁俱在时两个原子均不可达；任一被破坏即被 DoubleAxisNoWash 捕获。
TermElem(e, v) ==
    LET st == OutcomeStatus(e, v)
    IN IF v = "PASS" /\ e # "COMPLETED"
       THEN "P_WASH"
       ELSE IF st = "COMPLETED_CONDITIONAL" /\ e # "COMPLETED"
            THEN "CC_WASH"
            ELSE st

AttemptElems == AttemptStatuses \union {"P_WASH", "CC_WASH"}

(***************************************************************************
 * §4 Init —— create_run（wenqu_pipeline.py:2407）：CREATED/ver=1/全段 PENDING
 ***************************************************************************)

Init ==
    /\ rstate = "CREATED"
    /\ ver = 1
    /\ ahist = [s \in StageIds |-> << >>]
    /\ wstage = 0
    /\ consumed = {}
    /\ nonceUsed = [n \in Approvals |-> 0]
    /\ riskAuths = {}

(***************************************************************************
 * §5 动作 —— RunManager 公开 API 语义（每个动作注明代码映射与守卫出处）
 ***************************************************************************)

\* 启动段 attempt（首启/重试）↔ advance_stage 不带 outcome
\* （wenqu_pipeline.py:2538-2545）→ _append_started（:2497）
\* 守卫映射：
\*   - rstate ∈ {CREATED, RUNNING}：_require_mutable（非终态，:2368）+
\*     WAITING 拒绝（:2520）+ 折叠 CREATED→RUNNING 校验（:2147-2153）
\*   - CurStage = i：advance_stage 只作用于 current_stage（:2525）
\*   - LastOf(i) ≠ RUNNING：attempt 不可变（:2504 AttemptImmutabilityError）
\*   - CurStage=i 本身蕴含 ∀ j<i: LastOf(j)="PASSED"
\*     = ensure_prior_stages_passed（:922 / 折叠 :2142）
StartStage(i) ==
    /\ rstate \in {"CREATED", "RUNNING"}
    /\ (rstate # "RUNNING" => "RUNNING" \in RunTrans[rstate])
    /\ CurStage = i
    /\ LastOf(i) # "RUNNING"
    /\ Len(ahist[i]) + 2 <= MaxHistLen
    /\ ahist' = [ahist EXCEPT ![i] = Append(@, "RUNNING")]
    /\ rstate' = "RUNNING"
    /\ ver' = ver + 1
    /\ UNCHANGED <<wstage, consumed, nonceUsed, riskAuths>>

\* 完成当前 RUNNING attempt（双轴结果）↔ advance_stage 带 outcome
\* （wenqu_pipeline.py:2533-2537）→ _append_completed（:2475）
\* 守卫映射：rstate=RUNNING（非 WAITING/非终态，:2519-2524）；
\*   LastOf(i)="RUNNING"（折叠 :2158 无 RUNNING attempt 即 Corruption）；
\*   ValidOutcome ↔ validate_outcome（:2472 事前 + 折叠 :2225 双轴自证）；
\*   终态由 OutcomeStatus 映射（折叠 :2165）且必在 AttemptTrans["RUNNING"]
\*   行内（折叠 :2167）。历史编码：attempt = ⟨RUNNING, 终态⟩ 两元素，
\*   代码 attempts[-1] = 终态记录（:2178）对应此处追加终态元素。
CompleteStage(i, e, v) ==
    /\ rstate = "RUNNING"
    /\ CurStage = i
    /\ LastOf(i) = "RUNNING"
    /\ ValidOutcome(e, v)
    /\ OutcomeStatus(e, v) \in AttemptTrans["RUNNING"]
    /\ ahist' = [ahist EXCEPT ![i] = Append(@, TermElem(e, v))]
    /\ ver' = ver + 1
    /\ UNCHANGED <<rstate, wstage, consumed, nonceUsed, riskAuths>>

\* 触发停等 ↔ raise_waiting（wenqu_pipeline.py:2567）/ 折叠 WAITING_RAISED
\* （:2179）：run RUNNING→WAITING、当前段 attempt RUNNING→WAITING
\* （两表转换均查 RunTrans/AttemptTrans，:2192/:2186）。
\* 九类停等 stop_type 抽象为单一维度（A4）。
RaiseWaiting(i) ==
    /\ rstate = "RUNNING"
    /\ "WAITING" \in RunTrans[rstate]
    /\ CurStage = i
    /\ LastOf(i) = "RUNNING"
    /\ ahist' = [ahist EXCEPT ![i] = Append(@, "WAITING")]
    /\ rstate' = "WAITING"
    /\ wstage' = i
    /\ ver' = ver + 1
    /\ UNCHANGED <<consumed, nonceUsed, riskAuths>>

\* 消费 resume 审批并恢复停等 ↔ resume_waiting（:2611）→
\* ApprovalBroker.consume（:1522）+ WAITING_RESUMED 同事务追加（:1173-1177
\* 原子性；折叠 :2202）。守卫映射（consume 校验链 3-7 步）：
\*   - rstate="WAITING"：绑定校验要求停等中（:1402）
\*   - n ∈ ResumeApprovals：API 路由判别（:1547 consume 只收 resume）
\*   - nonceUsed[n]=0：nonce 一次性，事件流正源判定（:1479/:1557）
\*   - ExpectedVerOf[n]=ver：state_version CAS（:1468 expected == 当前版本）
\*   - 旧 attempt 停留 WAITING（终态），恢复创建新 attempt（:2211 折叠
\*     守卫 + :2624 注释"attempt 不可变"）
\* TTL/签名/绑定六元组抽象为"预审通过"（A3）。
ConsumeResume(n) ==
    /\ rstate = "WAITING"
    /\ "RUNNING" \in RunTrans[rstate]
    /\ wstage # 0
    /\ n \in ResumeApprovals
    /\ nonceUsed[n] = 0
    /\ ExpectedVerOf(n) = ver
    /\ Len(ahist[wstage]) + 2 <= MaxHistLen
    /\ ahist' = [ahist EXCEPT ![wstage] = Append(@, "RUNNING")]
    /\ rstate' = "RUNNING"
    /\ wstage' = 0
    /\ consumed' = consumed \union {n}
    /\ nonceUsed' = [nonceUsed EXCEPT ![n] = @ + 1]
    /\ riskAuths' = riskAuths
    /\ ver' = ver + 1

\* 消费 risk 授权 ↔ authorize_risk（:2657）→ consume_authorization（:1630）
\* 守卫映射：API 路由只收 risk（:1649-1655，resume 一律拒）；nonce 一次性
\* （同上）；CAS 同样强制（Codex 实锤 #5，:1643）；run 非 terminal
\* （:1667 绑定半边）。高危机器拒绝/指纹精确匹配/TTL 抽象为"预审通过"（A4）。
ConsumeRisk(n) ==
    /\ rstate \notin TerminalRun
    /\ n \in RiskApprovals
    /\ nonceUsed[n] = 0
    /\ ExpectedVerOf(n) = ver
    /\ consumed' = consumed \union {n}
    /\ nonceUsed' = [nonceUsed EXCEPT ![n] = @ + 1]
    /\ riskAuths' = riskAuths \union {n}
    /\ UNCHANGED <<rstate, ver, ahist, wstage>>
    \* 注：APPROVAL_CONSUMED 为观察类事件，state_version 不 +1（折叠 :2060）

\* run 终态判定三分支 ↔ complete_run（wenqu_pipeline.py:2663）：
\*   七段全 PASSED → SUCCEEDED（:2683）；
\*   末态软终态且无未完成段 + 已消费可用 risk 授权 → COMPLETED_CONDITIONAL
\*   （:2687-2723；fail-closed：无授权即拒绝走 FAILED）；
\*   其余 → FAILED（:2727-2733；CREATED 不得直接 FAILED，:2728）。
\*   WAITING 中的 run 不得直接 complete（:2673）。
FinishSucceeded ==
    /\ rstate = "RUNNING"
    /\ "SUCCEEDED" \in RunTrans[rstate]
    /\ AllPassedNow
    /\ rstate' = "SUCCEEDED"
    /\ ver' = ver + 1
    /\ UNCHANGED <<ahist, wstage, consumed, nonceUsed, riskAuths>>

FinishConditional ==
    /\ rstate = "RUNNING"
    /\ "COMPLETED_CONDITIONAL" \in RunTrans[rstate]
    /\ HasSoftNow
    /\ SoftOnlyNow
    /\ riskAuths # {}
    /\ rstate' = "COMPLETED_CONDITIONAL"
    /\ ver' = ver + 1
    /\ UNCHANGED <<ahist, wstage, consumed, nonceUsed, riskAuths>>

FinishFailed ==
    /\ rstate = "RUNNING"
    /\ "FAILED" \in RunTrans[rstate]
    /\ ~AllPassedNow
    /\ ~ (HasSoftNow /\ SoftOnlyNow /\ riskAuths # {})
    /\ rstate' = "FAILED"
    /\ ver' = ver + 1
    /\ UNCHANGED <<ahist, wstage, consumed, nonceUsed, riskAuths>>

\* 取消 ↔ cancel_run（:2822）/ 折叠 :2230（execution=CANCELLED→CANCELLED，
\* 经 RunTrans 表校验 :2246）。终态不可再变更（_require_mutable :2368）。
CancelRun ==
    /\ rstate \in {"CREATED", "RUNNING", "WAITING"}
    /\ "CANCELLED" \in RunTrans[rstate]
    /\ rstate' = "CANCELLED"
    /\ ver' = ver + 1
    /\ UNCHANGED <<ahist, wstage, consumed, nonceUsed, riskAuths>>
    \* wstage 保留（折叠不清理 waiting；终态后无动作可读它）

\* 作废 ↔ supersede_run（:2839）/ 折叠 :2250（不变量 #3：身份变化强制新 run）
SupersedeRun ==
    /\ rstate \in {"CREATED", "RUNNING", "WAITING"}
    /\ "SUPERSEDED" \in RunTrans[rstate]
    /\ rstate' = "SUPERSEDED"
    /\ ver' = ver + 1
    /\ UNCHANGED <<ahist, wstage, consumed, nonceUsed, riskAuths>>

\* 终态/上限截断后的原地踏步（安全性规约不主张活性，A6）
NoOp == UNCHANGED vars

Next ==
    \/ \E i \in StageIds : StartStage(i)
    \/ \E i \in StageIds, o \in Outcomes : CompleteStage(i, o[1], o[2])
    \/ \E i \in StageIds : RaiseWaiting(i)
    \/ \E n \in Approvals : ConsumeResume(n)
    \/ \E n \in Approvals : ConsumeRisk(n)
    \/ FinishSucceeded
    \/ FinishConditional
    \/ FinishFailed
    \/ CancelRun
    \/ SupersedeRun
    \/ NoOp

Spec == Init /\ [][Next]_vars

(***************************************************************************
 * §6 有界约束（TLC CONSTRAINT：终止状态空间枚举）
 *   ver 封顶按配置注入（cfg-A=16 / cfg-B=14）；历史长度封顶 MaxHistLen。
 ***************************************************************************)

Bounded ==
    /\ ver <= MaxVer
    /\ \A s \in StageIds : Len(ahist[s]) <= MaxHistLen

(***************************************************************************
 * §7 不变量 —— 全部为状态谓词，TLC 全量可达状态逐一检验
 ***************************************************************************)

\* I1 TypeOK ↔ RunState/StageState/WaitingInfo 类型域（:816/:780/:804）
\*   外加停等一致性（rstate=WAITING ⟹ 停等段当前 attempt 恰为 WAITING）。
TypeOK ==
    /\ rstate \in RunStates
    /\ ver >= 1
    /\ wstage \in {0} \union StageIds
    /\ \A s \in StageIds : ahist[s] \in Seq(AttemptElems)
    /\ consumed \in SUBSET Approvals
    /\ nonceUsed \in [Approvals -> Nat]
    /\ riskAuths \in SUBSET Approvals
    /\ (rstate = "WAITING" => wstage # 0 /\ LastOf(wstage) = "WAITING")
    /\ (wstage # 0 => LastOf(wstage) = "WAITING" \/ rstate \in TerminalRun)

\* I2 NoSkipStages ↔ 契约 §1 段序（STAGES :176）：后段有 attempt 历史
\*   ⟹ 前段全部启动过（跳段启动在可达状态中不存在）。
NoSkipStages ==
    \A i \in StageIds :
        Len(ahist[i]) > 0 =>
            \A j \in StageIds : j < i => Len(ahist[j]) > 0

\* I3 PriorPassedGate ↔ ensure_prior_stages_passed（:922，折叠 :2142）
\*   ——"前段非 PASSED 不得启动后段"的状态级形式：后段启动过 ⟹ 前段
\*   当前全部 PASSED（公开 API 下已 PASSED 的前段不可回退，见 :2525
\*   只推进 current_stage）。
PriorPassedGate ==
    \A i \in StageIds :
        Len(ahist[i]) > 0 =>
            \A j \in StageIds : j < i => LastOf(j) = "PASSED"

\* I4 AttemptImmutable ↔ "attempt 终态后不可变，重试/恢复一律新 attempt_id"
\*   （:765 StageAttempt 契约 / :2504 / 折叠 :2138-2141, :2211-2214）。
\*   形状：历史奇数位恒 RUNNING（每次启动追加 RUNNING），偶数位恒终态
\*   （一次且仅一次终态化；非末 attempt 一律终态）。
AttemptImmutable ==
    \A s \in StageIds :
        \A k \in 1..Len(ahist[s]) :
            /\ (k % 2 = 1 => ahist[s][k] = "RUNNING")
            /\ (k % 2 = 0 => ahist[s][k] \in TerminalAttempt)

\* I5 NonceOnceConsumed ↔ 不变量 #5 + 事件流正源判定（:1479, :1557）：
\*   每个审批原子至多成功消费一次；consumed 与 nonceUsed 一一对应
\*   （原子性：占 nonce 与事件追加同一事务，:1173-1177）；
\*   risk 授权必先经合法消费（riskAuths ⊆ consumed）。
NonceOnceConsumed ==
    /\ \A n \in Approvals : nonceUsed[n] <= 1
    /\ \A n \in Approvals : (n \in consumed) <=> (nonceUsed[n] = 1)
    /\ riskAuths \subseteq consumed

\* I6 TerminalFinal ↔ complete_run 三分支（:2663）+ 折叠 RUN_COMPLETED
\*   双轴自证（:2220-2247）的终态一致性：
\*   SUCCEEDED ⟹ 七段全 PASSED；COMPLETED_CONDITIONAL ⟹ 存在软终态段、
\*   无未完成/失败段、且已消费可用 risk 授权（fail-closed）；
\*   FAILED ⟹ 既非全 PASSED、也不满足软终态+授权的充分组。
TerminalFinal ==
    /\ (rstate = "SUCCEEDED" => AllPassedNow)
    /\ (rstate = "COMPLETED_CONDITIONAL" =>
           /\ HasSoftNow
           /\ SoftOnlyNow
           /\ riskAuths # {})
    /\ (rstate = "FAILED" =>
           /\ ~AllPassedNow
           /\ ~ (HasSoftNow /\ SoftOnlyNow /\ riskAuths # {}))

\* I7 DoubleAxisNoWash ↔ 契约 §2 + P0-4 Codex 实锤 #6：
\*   "阻断态不得折算为 PASS"（validate_outcome :1017）与
\*   "execution 非 COMPLETED 一律 FAILED"（outcome_to_attempt_status :1053）
\*   ——双轴洗白（TIMEOUT+CONDITIONAL 之类）在 attempt 层不可能产生
\*   PASSED/COMPLETED_CONDITIONAL，进而 run 层不可能 COMPLETED_CONDITIONAL。
\*   P_WASH/CC_WASH 为金丝雀原子：任一道锁被破坏即出现在可达状态中。
DoubleAxisNoWash ==
    /\ \A s \in StageIds :
           /\ "P_WASH" \notin ElemsOf(s)
           /\ "CC_WASH" \notin ElemsOf(s)
    /\ \A s \in StageIds :
           (LastOf(s) = "FAILED" => rstate # "COMPLETED_CONDITIONAL")

=============================================================================
\* ## 规约-代码映射总表（结构测试 test_tla_spec.py 的比对锚点）
\* | TLA 定义           | Python 正源（wenqu_pipeline.py）                          |
\* |--------------------|-----------------------------------------------------------|
\* | StageOrder         | :176 STAGES / SevenStageStateMachine.STAGES               |
\* | RunStates          | :196 RUN_STATES                                           |
\* | TerminalRun        | :201 TERMINAL_RUN_STATES                                  |
\* | RunTrans           | :207 RUN_TRANSITIONS                                      |
\* | AttemptStatuses    | :227 ATTEMPT_STATES                                       |
\* | TerminalAttempt    | :232 TERMINAL_ATTEMPT_STATES                              |
\* | AttemptTrans       | :238 ATTEMPT_TRANSITIONS                                  |
\* | ExecStatuses       | :247 EXECUTION_STATUSES                                   |
\* | PolicyVerdicts     | :250 POLICY_VERDICTS                                      |
\* | ValidOutcome       | :1006 validate_outcome（PASS 需 COMPLETED 半边）          |
\* | VerdictToStatus    | :1029 verdict_to_attempt_status                           |
\* | OutcomeStatus      | :1045 outcome_to_attempt_status                           |
\* | Init               | :2407 create_run                                          |
\* | StartStage         | :2497 _append_started / 折叠 :2133 STAGE_STARTED          |
\* | CompleteStage      | :2475 _append_completed / 折叠 :2154 STAGE_COMPLETED      |
\* | RaiseWaiting       | :2567 raise_waiting / 折叠 :2179 WAITING_RAISED           |
\* | ConsumeResume      | :1522 consume + :2611 resume_waiting / 折叠 :2202         |
\* | ConsumeRisk        | :1630 consume_authorization / :2657 authorize_risk        |
\* | FinishSucceeded    | :2683 complete_run 全 PASSED 分支                         |
\* | FinishConditional  | :2687 complete_run 软终态+risk 分支                       |
\* | FinishFailed       | :2727 complete_run FAILED 分支                            |
\* | CancelRun          | :2822 cancel_run / 折叠 :2230                             |
\* | SupersedeRun       | :2839 supersede_run / 折叠 :2250                          |
\* | TypeOK             | :816 RunState 类型域                                      |
\* | NoSkipStages       | :176 STAGES 段序（契约 §1）                               |
\* | PriorPassedGate    | :922 ensure_prior_stages_passed                           |
\* | AttemptImmutable   | :765/:2504 attempt 不可变契约                              |
\* | NonceOnceConsumed  | :1479/:1557 nonce 一次性（事件正源）                      |
\* | TerminalFinal      | :2663 complete_run 分支 + 折叠 :2220 双轴自证             |
\* | DoubleAxisNoWash   | :1017/:1053 双轴洗白双锁                                  |
=============================================================================

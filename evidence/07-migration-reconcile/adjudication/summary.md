# Quarantine 裁定提案（辅助建议，非裁定）

- 生成：2026-10-08T18:42:04.918686+00:00（tool=tools/quarantine_adjudicate.py v1.0.0）
- 输入报告：`/Users/maccc/Documents/wenqu-dist/evidence/07-migration-reconcile/reconcile-report.json`（sha256=a4d2721c52ab756f…，报告生成于 2026-10-08T09:29:58.137411+00:00，git_head=1620c7c030bd1ea5eb096e0509b7f864c4e90a6d）
- 范围：quarantine 1950 行；定位=**只建议不替人裁定、不写任何库**

## 聚类统计（13 簇）

| 簇 | 规则 | 值形状 | 建议裁定 | 拟议目标 | 行数 | 依据摘要 |
|---|---|---|---|---|---|---|
| `narrative_worklog:result` | R7 | narrative×1120 | **KEEP_QUARANTINE** | — | 1120 | 叙事文本（action 工作日志/带空格短语）：无状态语义，维持隔离（源数据本性，非工具缺陷） |
| `no_status_field_worklog` | R8 | absent×396 | **KEEP_QUARANTINE** | — | 396 | 四个候选状态字段全缺的工作日志行（summary/note 型）：无状态可映射，维持隔离 |
| `token_longtail:result` | R6 | token×229 | **KEEP_QUARANTINE** | — | 229 | token 长尾/过程态（确认态/in-flight/wait/等CI/观察 one-off 等）：非 finding  |
| `state_structured_snapshot` | R3 | dict×57 | **KEEP_QUARANTINE** | — | 57 | 候选值为 dict（结构化巡检快照）：非状态语义，维持隔离 |
| `missing_ts_no_mappable_status` | R2 | missing_ts_unmappable×40 | **KEEP_QUARANTINE** | — | 40 | 缺 ts 且无可映射状态（双重不满足）：无可恢复入账要素，维持隔离 |
| `nearmiss_token:DONE` | R5 | token×38 | **SUBMIT_HUMAN** | FIXED_PENDING_VERIFY | 38 | [DONE] fix 完成态；M3 先例 FIXED→FIXED_PENDING_VERIFY（完成但无验证证据时上限即 |
| `nearmiss_token:GREEN_FAMILY` | R5 | token×31 | **SUBMIT_HUMAN** | PASS | 31 | [GREEN_FAMILY] 巡检全绿判定族（token 含 GREEN/绿）。口径风险：这是仓库态观测而非 findi |
| `token_longtail:verdict` | R6 | token×20 | **KEEP_QUARANTINE** | — | 20 | token 长尾/过程态（确认态/in-flight/wait/等CI/观察 one-off 等）：非 finding  |
| `token_longtail:state` | R6 | token×6 | **KEEP_QUARANTINE** | — | 6 | token 长尾/过程态（确认态/in-flight/wait/等CI/观察 one-off 等）：非 finding  |
| `nearmiss_token:MERGED` | R5 | token×4 | **SUBMIT_HUMAN** | — | 4 | [MERGED] PR 生命周期态，冻结表无 finding 状态对应；无拟议目标，人工定夺保留隔离或另行处理。 拟议目 |
| `nearmiss_token:PARTIAL` | R5 | token×4 | **SUBMIT_HUMAN** | CONDITIONAL | 4 | [PARTIAL] 语义近似 CONDITIONAL，但这是猜测——冻结别名表无 PARTIAL，须人工签字才可扩表。  |
| `narrative_worklog:verdict` | R7 | narrative×3 | **KEEP_QUARANTINE** | — | 3 | 叙事文本（action 工作日志/带空格短语）：无状态语义，维持隔离（源数据本性，非工具缺陷） |
| `nearmiss_token:FIXED_VERIFIED` | R5 | token×2 | **SUBMIT_HUMAN** | — | 2 | [FIXED_VERIFIED] VERIFIED 不在冻结 KNOWN_STATUSES；上限 FIXED_PENDI |

## 建议分布

| 建议裁定 | 簇数 | 行数 |
|---|---|---|
| KEEP_QUARANTINE | 8 | 1871 |
| RECLASSIFY | 0 | 0 |
| SUBMIT_HUMAN | 5 | 79 |
| **合计** | **13** | **1950** |

## 需真人看的最小集合

**1950 行 → 5 个裁定簇 + 8 个确认簇（簇级签字+抽查，免逐行）**；直接处于人工裁定下的行数：**79 / 1950**。

### A. 裁定簇（须逐簇给决定）

| 簇 | 行数 | 拟议目标 | 裁定问题 |
|---|---|---|---|
| `nearmiss_token:DONE` | 38 | FIXED_PENDING_VERIFY | DONE 族 38 行：是否批准扩别名 DONE→FIXED_PENDING_VERIFY 入账？（拟议仅是选项） |
| `nearmiss_token:GREEN_FAMILY` | 31 | PASS | GREEN_FAMILY 族 31 行：是否批准扩别名 GREEN_FAMILY→PASS 入账？（拟议仅是选项） |
| `nearmiss_token:MERGED` | 4 | — | MERGED 族 4 行：保留隔离还是另行定夺？（无拟议目标） |
| `nearmiss_token:PARTIAL` | 4 | CONDITIONAL | PARTIAL 族 4 行：是否批准扩别名 PARTIAL→CONDITIONAL 入账？（拟议仅是选项） |
| `nearmiss_token:FIXED_VERIFIED` | 2 | — | FIXED_VERIFIED 族 2 行：保留隔离还是另行定夺？（无拟议目标） |

### B. 确认簇（簇级签字+抽查即可，免逐行）

| 簇 | 行数 | 依据 | 抽样（行号） |
|---|---|---|---|
| `narrative_worklog:result` | 1120 | 叙事文本（action 工作日志/带空格短语）：无状态语义，维持隔离（源数据本性，非工具缺陷） | 2, 4, 6 |
| `no_status_field_worklog` | 396 | 四个候选状态字段全缺的工作日志行（summary/note 型）：无状态可映射，维持隔离 | 1308, 1310, 1312 |
| `token_longtail:result` | 229 | token 长尾/过程态（确认态/in-flight/wait/等CI/观察 one-off 等）：非 finding 状态语义，维持隔离； | 3, 5, 9 |
| `state_structured_snapshot` | 57 | 候选值为 dict（结构化巡检快照）：非状态语义，维持隔离 | 1506, 1507, 1543 |
| `missing_ts_no_mappable_status` | 40 | 缺 ts 且无可映射状态（双重不满足）：无可恢复入账要素，维持隔离 | 1860, 1863, 1874 |
| `token_longtail:verdict` | 20 | token 长尾/过程态（确认态/in-flight/wait/等CI/观察 one-off 等）：非 finding 状态语义，维持隔离； | 1595, 1599, 1625 |
| `token_longtail:state` | 6 | token 长尾/过程态（确认态/in-flight/wait/等CI/观察 one-off 等）：非 finding 状态语义，维持隔离； | 1738, 1811, 1839 |
| `narrative_worklog:verdict` | 3 | 叙事文本（action 工作日志/带空格短语）：无状态语义，维持隔离（源数据本性，非工具缺陷） | 1700, 1872, 1963 |

裁定输出契约：人工逐簇给 {cluster_id: {disposition: KEEP_QUARANTINE|RECLASSIFY, target: <KNOWN_STATUS>|null}}；批准后的再录由人工走版本化扩表+迁移器重跑通道，本工具不执行

## 一键预览：按建议重分类后的四态统计（假想值，不写迁移库）

| 状态 | 现状 | 场景A·按建议执行 | 场景B·拟议全批准上限 |
|---|---|---|---|
| mapped（已入账） | 16 | 16 | 89 |
| quarantined（隔离） | 1950 | 1950 | 1877 |
| 待人工 | 1 | 1 | 1 |
| 不一致 | 0 | 0 | 0 |
| 合计 | 1967 | 1967 | 1967 |

场景B 新增事件状态分布：{"FIXED_PENDING_VERIFY": 38, "PASS": 31, "CONDITIONAL": 4}

- 场景A注：RECLASSIFY 0 行入账；SUBMIT_HUMAN 79 行维持隔离待裁；正式四态不变（本数据集 RECLASSIFY=0）
- 场景B注：SUBMIT_HUMAN 中带拟议目标的 73 行按拟议入账（假想上限，须逐簇人工批准+版本化扩表后另行再录）；无拟议目标簇维持隔离
- 假想值：本工具不写迁移库/不写任何库；数字仅为人工决策预览

## 方法与证据边界

- 特征空间：quarantine reason（missing_field:ts / no_mappable_status(candidates=X)）× 内容特征（整行 JSON 的候选字段值形状：dict/token/narrative/absent；token 再按近失族/长尾分）
- 别名正源：system/wenqu_core/ledger_migrator.py STATUS_ALIASES（冻结正源）（keys=16，零自造别名，import_degraded=False）
- 源富化：mode=full_line_per_row_verified；逐行 row_id 重算验证 1950/1950，退回 preview 0 行；源文件在报告生成后有追加（sha 不匹配属预期）；逐行以 row_id 重算为准，验不上的行退回 preview 并入 R9 簇
- RECLASSIFY 仅在候选值命中冻结别名表时给出（本数据集预期 0 行——迁移器已取走全部可映射行）；近失族拟议目标全部 requires_human_approval=true
- 完整规则表与逐簇 token 清单见 adjudication-proposal.json

## 自检（fail-closed）

- partition_row_ids_set_equal: PASS
- partition_no_duplicate: PASS
- sum_cluster_sizes_eq_quarantined: PASS
- no_empty_cluster: PASS
- suggestion_enum_valid: PASS
- targets_within_known_statuses: PASS
- distribution_rows_conserved: PASS
- hypothetical_scenario_A__conserved: PASS
- hypothetical_scenario_B__conserved: PASS
- all_passed: PASS

## 终态裁定（2026-10-09，G9-10）

- 产物：`adjudication-final.json`（sha256=a6420343…；1950 行逐行映射，全部 `KEEP_QUARANTINE`，`PENDING=0`）
- 保守原则：不扩冻结别名表、不引入猜测映射、**零 RECLASSIFY=零生产写**（后续人工升级 DONE 簇→FIXED_PENDING_VERIFY 须另行授权，M3 先例在案）
- 人工 5 簇（79 行）保守裁定理由逐簇记录于 `conservative_note`
- 抽查：13 簇×3 样本=39 行全过（row_id 存在性+preview 语义一致性）

## W12-07｜canonical Ed25519 V3 正本签发（2026-10-13）

- **V2 降级 historical**：`adjudication-final.json`（V2/HMAC）自本日起仅为历史证据，不具验签效力；验签一律走 V3 通道。
- **V3 正本**：`adjudication-final-v3.json`（仓内副本与本目录并存；正本=`~/.wenqu-dist-audit/adjudication/S11/S11-adjudication-final-20261013/adjudication-final-v3.json`，sha256=fe91afec75ca84cff16b6af79994f89a8b5679cf671883bd3aae900d13bc22cd，与仓内副本字节一致）。
- **签名面（根修）**：identity_context（Ed25519 签名，覆盖 schema/contract/algorithm/key-id、source SHA、environment、run_id、generated_at、proposal/report hash、report_git_head、authority/principal/production_write、clusters、conservation）入绑全部 1950 行签名与 corpus 根——任一顶层身份字段或任一行被改，验签非零。
- **固定身份**：`source_sha=b88309e0440ba61ace5290e088ba9acc2ccd6c40`（exact S11 SHA）、`environment=production`、`run_id=S11-adjudication-final-20261013`、`key_id=wenqu-adjudication-ed25519-s11-prod-001`。
- **密钥 custody**：私钥 `~/.wenqu-dist-release/adjudication-ed25519.key`（0600，仓外，不入仓/plist/环境/日志/Seal）；公钥经包外通道交付验收方（`~/.wenqu-dist-trust/adjudication/adjudication-ed25519-s11-prod-001.pub`，pub hex=677f05ebf69fc245571b6029a814c74ea5b5d9e6c377ac11001b0812d658bb21）。
- **registry**：`~/.wenqu-dist-trust/adjudication/canonical-registry.json`；仓内仅保存 digest/registry 引用（`adjudication-final.status.json`）。
- **验签命令**（独立验收方视角，四 pin 强制）：见 `adjudication-final.status.json` 的 `verify_command`；当前实测 rc=0（1950/1950、KEEP=1950、PENDING=0、missing/duplicate/extra=0）。
- **范围声明**：本 V3 证明的是 S11 数据裁定（1950 行 quarantine 裁定内容与身份），**不证明 S12 部署能力**。

# 第七轮独立复审子任务 B：§20 覆盖与破坏性 Gate 探针

## 1. 边界与结论

- 冻结对象：`d32c859f9043798d9e8a4984e8f57aa64567e33c`。
- 方案 SHA256：`96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306`。
- 审计私有副本：`/tmp/wenqu-reaudit7-coverage-b-22841` 及本目录记录的多个 `/tmp/wq7b-*` 破坏性副本。
- 本子任务结论：**BLOCKED**。131 个 ID 的“函数名/登记/可执行”基线属实，但“131/131 冻结语义真实覆盖、不可绕过”不成立；Gate manifest 与重复件仍有 rc0/PASS 绕过，正式 Schema 边界仍未闭合。
- **零源仓写入声明**：本审计者未对 `/Users/maccc/Documents/wenqu-dist` 执行写入、删除、checkout、reset、restore 或部署；全部变异只发生在 `/tmp` 私有副本。源仓验收中出现的 HEAD 漂移及 `wenqu_pipeline.py`/`approval-v2.schema.json` 删除是外部并行会话环境事实，本审计未恢复、也不归责冻结 d32。

## 2. F6 本子域重判

| F6 | 判定 | 独立实证 |
|---|---|---|
| GATE-SCOPE | **FAIL** | 正常 manifest PASS、缺站/自报分母/scope 漂移均红；但把顶层 required `[0,1]→[0]` 后自行重算无密钥 `manifest_hash`，保留冲突的 `planner.required=[0,1]`，只交 station0 仍 **rc0/PASS**。manifest 不是不可伪造冻结根，也无内部一致性校验。见 `42-*`。 |
| GATE-FORMAT-DUP | **PARTIAL** | 纯日期 RFC3339 已红，attempt/artifact 漂移已冲突，正式 schema 合法嵌套扩展也不误拒；但只漂移 ruleset/data_config/tool/execution/finding_ids，仍 `duplicates_ignored=1, conflicts=0, rc0/PASS`，不是“全等等价键”。见 `42-*`。 |
| SCHEMA-BOUND | **PARTIAL/未闭环** | 正式 Draft-07 对 `PASS 10006/10007` 仍 0 error；运行镜像/聚合器会 BLOCKED，属于补偿控制，不满足第六轮“Schema 自身具备不变量”。见 `42-*`。 |
| TRC-GATE | **PARTIAL/未闭环** | 删除 required 专属文件完整 acceptance rc1；但把 SC-05 函数体换成唯一 `assert True`，专属 suite 29/29 + trace 131/131 均 rc0；整份 gate family 24 个 `pass` 时完整 acceptance 仍 66/66。见 `33-*`、`43a/43b-*`。 |
| TRC-PARSER | **PASS（本子域闭环）** | 基线 rc0；ID、injection、expectation、§25.1 四列、重复相同行、先毒后正、§20/§25 外字节、缺 plan 全部 rc2；实际全文件 SHA 参与判断。见 `15-trace-*`。 |
| EVID | **FAIL（引用同轮严格审计）** | 同轮严格复算为路径文件 20/20，但裸64hex并实算相等11/20、exact40hex commit13/20、必填全非空6/20、严格合同5/20；非本子任务重复实现，证据源为 sibling `agent-f6-p0/14-*`。 |

因此不能接受“F6 六项全部闭环”。

## 3. 131/131 专属覆盖真实性

### 基线事实

- `ac_traceability --check`：rc0；方案 ID 131、冻结 131、dedicated 131、重复0、实算 SHA 匹配。
- 八专属文件：131 个 `def test_`，直接运行全部 rc0。
- 抽样 27 条、11 族的 pytest nodes：rc0，`27 passed`（4 个函数返回 dict 的 pytest warning，不影响其内部 assert 已执行）。

### 语义抽查结论

- 抽 27/131（20.6%）：**22 完整、5 部分**。
- 明确缺口：
  1. **SC-05**：合法 HMAC/hash 但 `pagination.complete=false,pages_total=2` 的快照被 `COMPLETED/PASS 12/12`；分页腿假绿。
  2. **UI-06**：正确 Host、无 Authorization/Cookie 的 `/api/v1/logs` 返回 200 并泄漏敏感标记；“未认证日志读取拒绝”未实现。
  3. **UI-07**：6MiB 单行日志经 `tail -20` 原样返回约 6.29MB；只有行数界，无字节界。
  4. **UI-01**：parser 构建门能抓缺 span，但产品 `--self-check` 仅核 div；删一个 `</span>` 后启动自检仍 rc0/PASS。
  5. **BAK-01**：真实 cp 演练和 generic backup failure 有覆盖，但测试明示不注入“磁盘满/tar”，产品也没有 tar 通路，冻结三腿不完整。
- 详尽 ID→注入→期望→真实断言表：`coverage-sample-audit.md`；函数源：`selected-tests-source.json`；实跑：`25-selected-27-pytest.log`。

### 名称计数门的结构性绕过

- 私有副本仅将 `test_SC_05...` 函数体替换为 `assert True`，函数名和 TESTS 列表不变：文件自身打印 29/29，trace 仍打印 dedicated 131/131，双 rc0（`33-*`）。
- 同轮另一独立副本将 `test_ac_gate_family.py` 整体替换为 24 个 `def test_noop(): pass`、assert=0：完整 acceptance 仍 `PASS=66 FAIL=0`（本目录固化副本 `43b-*`）。
- 故 131/131 只能证明**名称/文件接线**，不能证明测试体语义或真实断言；`>=95` 总数阈值还允许函数级缩水空间。

## 4. 常规/破坏性探针矩阵

| 探针 | 预期 | 实际 | 判定/证据 |
|---|---:|---:|---|
| 基线 trace | rc0 | rc0，131/131 | PASS，`04-*` |
| required 缺站 | 红 | rc2/BLOCKED | PASS，`42-*` |
| coverage 自报缩水 | 红 | rc2 | PASS，`42-*` |
| scope_hash 漂移 | 红 | rc2 | PASS，`42-*` |
| manifest 原 hash 不重算篡改 | 红 | rc3 | PASS，但弱攻击；`42-*` |
| manifest required 篡改后自算摘要 | 红 | **rc0/PASS** | **FAIL/bypass**，`42-*` |
| 无 manifest 裸调用 | 红 | rc3 | PASS，`42-*` |
| 完全相同重复件 | 幂等 | rc0，ignored=1 | PASS，`42-*` |
| 重复件 attempt/artifact 漂移 | 冲突红 | rc2 | PASS，`42-*` |
| 重复件其他语义字段漂移 | 冲突红 | **rc0/PASS，ignored=1** | **FAIL/bypass**，`42-*` |
| 纯日期时间 | 红 | rc2 | PASS，`42-*` |
| schema 合法嵌套扩展 | 绿 | rc0/PASS | PASS，`42-*` |
| >64 PASS 分母不等（正式 schema） | 红 | **0 errors** | **FAIL**，`42-*` |
| >64 PASS 分母不等（镜像/聚合器） | 红 | mirror error / BLOCKED | 补偿 PASS，`42-*` |
| schema nonce `minLength 16→0` | 红 | P0-2 suite rc1（9/1） | PASS，`39/40-*` |
| 三移除：pipeline / approval schema / trace tool | acceptance 红 | rc1 / rc1 / rc1；目标 P1/P1b/P1c 命中 | PASS；并发运行有额外共享资源失败，不拿额外项作结论，`27/28/29-*` |
| §20 ID 篡改 | acceptance 红 | rc1，P1c trace rc2，65/1 | PASS，`34-*` |
| §20 injection/expectation 语义篡改 | acceptance 红 | rc1，P1c trace rc2，65/1 | PASS，`35-*` |
| §25.1 四列映射篡改 | acceptance 红 | rc1，P1c trace rc2，65/1 | PASS，`36-*` |
| trace 重复相同行 | 红 | rc2 | PASS，`15-trace-duplicate-*` |
| trace 先毒后正重复 | 红 | rc2 | PASS，`15-trace-poison-*` |
| trace 缺 plan | 红 | rc2 | PASS，`15-trace-missing-*` |
| trace §20/§25 外单字节漂移 | 红 | rc2（实算 SHA） | PASS，`15-trace-outside-*` |
| P1f 删除 UI 专属文件 | acceptance 红 | rc1，65/1 | PASS，`43a-*` |
| P1f 保留名称但清空语义 | 红 | **完整 acceptance rc0，66/0** | **FAIL/bypass**，`43b-*` |

## 5. 证据导航

- 身份/基线：`00-baseline-identity.log`、`04-trace-baseline.log`、`05-dedicated-baseline.log`。
- 27 条抽样：`coverage-sample-audit.md`、`selected-tests-source.json`、`25-selected-27-pytest.log`。
- Gate/Schema 综合独立探针：`independent-gate-probe.py`、`42-independent-gate-full-adversarial.log`。
- trace parser/三重篡改：`14-*`、`15-trace-*`、`34-*`、`35-*`、`36-*`。
- 三移除：`26-*`、`27-*`、`28-*`、`29-*`。
- schema 变异：`39-*`、`40-*`。
- P1f：`33-*`、`43a-*`、`43b-*`。
- 产品语义反例：`18-independent-sc05-pagination-rerun.log`、`21-ui01-span-product-selfcheck-rerun.log`、`22-independent-ui06-noauth.log`、`23-independent-ui07-single-line.log`、`38-bak01-product-static-rerun.log`。
- 命令、cwd、退出码、stdout/stderr：每个编号均有 `.command/.cwd/.exit_code/.stdout/.stderr/.log`（跨代理固化的 `43a/43b` 保留原始统一日志格式）。

## 6. 对总报告的建议

- 不能把 `trace=131/131` 或 acceptance 66/66 写成语义覆盖 100%；应写“名称/接线 131/131，27 条语义抽查 22 完整/5 部分，且存在空壳假绿”。
- F6 推荐：`GATE-SCOPE FAIL`、`GATE-FORMAT-DUP PARTIAL`、`SCHEMA-BOUND PARTIAL`、`TRC-GATE PARTIAL`、`TRC-PARSER PASS`、`EVID FAIL`。
- 至少 manifest 重签缩分母、重复站语义冲突忽略、匿名日志读取三项均是 fail-open 安全断言，最终准入必须保持 **BLOCKED**。

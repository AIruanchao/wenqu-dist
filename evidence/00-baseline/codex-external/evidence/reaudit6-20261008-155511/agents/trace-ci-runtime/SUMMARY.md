# 第六轮子审计 C：追踪 / CI / 证据 / 7789 / W9-W10

- **审计基线**：启动时只读确认 `main@b259dac4248b14af6ec05e1b3fc7f61401aba6b6`、工作树 clean；随即以 `git archive` 冻结到 `/tmp/reaudit6-trace.dxHErV`。本人未写源仓，详见 `SOURCE-WRITE-DECLARATION.txt`。
- **子审最终判定**：**BLOCKED**。F4-TRC-001 的直接“改注入/期望文本仍绿”已修，但 P0-10/required Gate 仍可在删除全部七个专属测试、空断言、缺方案、重复表格行时假绿；证据索引“20 条全量 SHA+当前 run/HEAD”与实物严重不符；验收期间又发生目标 SHA/运行体漂移。
- **边界**：所有破坏性用例在 `/tmp`；未发 POST、未加载/卸载 launchd、未部署/回滚、未改 GitHub 配置。

## 1. F4-TRC-001 与 §20/§25.1 独立变异

基线 `tools/ac_traceability.py --check` rc=0，§20 131 行/131 ID 与 §25.1 展开成立。17 种方案变异及一个缺文件用例见 `mutations/summary.tsv`：

| 类别 | 结果 |
|---|---|
| ID 文本、注入文本、期望文本 | 均 rc=2 |
| 零宽 Unicode、Unicode 同形字、token 内空白 | 均 rc=2 |
| 注入/期望列互换、额外列、行格式错位 | 均 rc=2 |
| §25.1 范围端点、REQ 元数据、列互换 | 均 rc=2 |
| 仅反引号/首尾空白的等价格式控制 | rc=0（符合归一化设计） |
| **重复一条完全相同的 §20 行** | **rc=0，假绿** |
| **先放一条 poisoned 重复行、后放正确同行** | **rc=0，字典后写覆盖假绿** |
| **冻结方案 SHA 漂移（§20/§25 外追加内容）** | **rc=0；`PLAN_SHA256` 常量未实算** |
| **`--plan` 指向不存在文件** | **rc=0；直接 SKIP** |

另外，所有应红变异的输出 JSON 仍把 `meta.catalog_integrity` 写为 `OK`（该字段在 plan problems 加入前计算），虽退出码为 2，但机器消费者若读字段会被误导。

**F4-TRC-001 判定：直接修复有效，但只能记 `PARTIAL/CLOSED-DIRECT`；P0-10 未关闭。**

## 2. 99/131 专属覆盖真实性

### 2.1 实跑与逐 ID 内容审计

七文件在 b259 隔离副本真实运行：`20/20 + 16/16 + 9/9 + 11/11 + 24/24 + 14/14 + 5/5 = 99/99`，均 rc=0（`18-seven-dedicated-runtime.log`）。

但“运行全绿”不等于每个名字完整兑现 §20。独立抽查 **21 条、跨七文件**：

- 完整 11；
- 部分 8；
- 明确不匹配 2：`MIG-04`（删目标行后自动补齐成功，未注入“行数不守恒→迁移失败”）、`DOC-03`（detector 只定义在测试函数内部，未产品化/未接 CI）。

逐 ID 注入、期望、具体断言、行号和判定详见：

> **`25-id-sample-audit.md`**

### 2.2 词法覆盖/required Gate 可绕过

- 把 `DOC-03` 整个测试体替换成 `assert True`：专属文件仍 14/14、追踪仍报 99/131，两个 rc 均 0（`19-hollow-*`）。
- 删除七个专属测试文件：追踪 dedicated 由 99 降至 2，但 `--check` **仍 rc=0**；`tests/acceptance.sh` **仍 64/64 ALL GREEN、rc=0**（`20-delete7-*`）。
- 原因：`--check` 只校验冻结目录/方案一致性，不把 dedicated coverage 设为棘轮；acceptance/workflow 不执行七文件。
- `evidence_path` 扫描还会把含全部 ID 的冻结 `方案.md` 当作每个 ID 的“证据”，不能证明测试执行。

### 2.3 32 条“不可实现登记”

矩阵确有 32 missing，但测试模块中按整 ID 登记的只有 **22**；`BAK-01/CAP-01/DR-01/UI-01~07` 共 **10 条**没有各测试文件模块级逐 ID 登记与理由。明细：`26-not-implementable-audit.json`、`14-missing-registration-audit.txt`。

**结论**：`99/131` 是词法命中数，不是 99 条完整语义实现，也不是 required coverage Gate；“32 条均模块级登记”被证伪。

## 3. 证据索引与候选制品

按方案 §24.2 必填值并逐路径实算（`evidence-index/strict-audit.json`）：

| 检查 | 实得 |
|---|---:|
| entries | 20 |
| evidence_path 存在 | 20/20 |
| evidence_path 是具体文件 | 16/20（4 条只指目录） |
| 必填值均非空（run/commit/env/scope/ruleset/time/argv/rc/hash/fresh） | **4/20** |
| `artifact_sha256` 为裸 64hex | **4/20** |
| 裸 hash 与所指具体文件实际 hash 相等 | **1/20** |
| size 字段 | **0/20** |
| commit 为完整 40hex | 3/20 |

额外错绑：

- `repo_head_at_filing` 仍为 `f2b8fc3`，不是 b259；当前 CI run `37745638008` 未入索引。
- 受控 `traceability-matrix.json` 的 `repo_head` 仍为 `b08fa7a...`，与条目宣称 `f2b8fc3`/目标 b259 不符。
- `EV-W5-001` 的裸 hash 不匹配其 `ac-auth-cond.json`；多条值为 null 或“说明文字+hash”，不可机器等值核验。

候选制品本身可核验：

- `dist/wenqu-vNext-candidate-f2b8fc3.tar.gz` size=3,356,318；SHA256=`0c998a042aedbd7619a4b88b812cb8503e1b3270008d0115dca5c6246600fe00`，与清单一致；tar 可列出 451 项。
- 但索引 hash 指向 tar，`evidence_path` 却指 checksum 文本，严格路径-hash 不同；无签名、SBOM、attestation（已知缺口）。

**“20 条全量 SHA+当前 run/HEAD 达标”判定：FAIL。**

## 4. CI、分支保护、PR 与 auto-merge

`gh` 实时回读（`github/`）：

- run `37745638008`：`push/main`，head=`b259dac...`，completed/success；macOS、Ubuntu 两 job 均 success，check-runs exact SHA 正确。
- 远端日志真实 acceptance 为两端 **63 PASS/0 FAIL**（acceptance 内 pytest 不可用而 skip），随后独立 pytest step 两端 20 passed；不是“远端 acceptance 64/64”。
- P1d/P1e 确实在 required acceptance 内运行，因此 F4-CI-001 原始“12+66 两套未接线”直接缺口已关闭。
- main protection：`strict=true`、`enforce_admins=true`、required=`matrix (ubuntu-latest)`/`matrix (macos-latest)` 且 app_id=GitHub Actions；禁止 force push/delete。
- PR#4、#5 均在最后 required check success 后才 merge；`autoMergeRequest=null`。
- 不足：无 required review/CODEOWNERS 强制、无 conversation resolution、rulesets=0、workflow 无 `merge_group`，`actions/checkout@v4` 与 `setup-python@v5` 未 pin 40hex SHA。
- **关键新缺口**：七个“99 条专属”文件不在 workflow/acceptance；删除七文件仍 required acceptance 绿。
- repo `allow_auto_merge=false`；launchd/ps/crontab 无 auto-merge，`~/.wenqu/bin/auto-merge.sh` 与 b259 archive 均不存在。P0-8 可保持 PASS。

## 5. 7789 运行身份与验收期间漂移

本子审取证时：

- launchd `com.wenqu.dashboard` running，PID 42242，命令 `~/.wenqu/bin/wenqu-dashboard.py 7789`；只监听 `127.0.0.1:7789`。
- health HTTP 200，但正文 `score=40 / Gate=failure`。
- active hash=`675603caca01317029f5cd208c2ebfc62f3c8272caa74491db05426d56dc1b2a`；**不等于** b259 archive hash=`1cdb3a49...`。
- 经 GitHub contents API 独立对账，active 精确等于 `419e778...`，也等于验收期间后来合入的 main `07a94945...`（PR#6）；PID 于 15:58 启动。
- b259 与 active 的差异是 legacy 单文件追加日志 XSS 输出修复/单飞缓存等；active 仍保留 `do_POST` 与 `/api/decide`，不是模块化只读服务。

因此 b259 的“当前运行身份”在验收中被外部 writer 失效。此漂移不是本子审造成；它是 W0/P0-9 的硬阻断，b259 运行结论必须冻结而不能沿用新 SHA 的健康结果。

## 6. W9/W10 时钟与首日样本

- `com.wenqu.observation` 已加载，`StartCalendarInterval=09:05`，runs=2、last exit=0；样本与 shadow 文件存在。
- 首日样本 `collected_at=2026-10-08T06:56:04Z`，却绑定 `b08fa7a...`、`repo_dirty=true`、旧 CI run `37738717793`，不是 f2/b259。
- shadow server ready=200 且 finally=`term`，但模块化 `/api/v1/health`=503，比较 `key_sets_equal=null`、`score_equal=null`，明确“无法比对”。
- LaunchAgent 直接执行可变工作树路径 `/Users/maccc/Documents/wenqu-dist/tools/observation_daily.py`，不是不可变 release；验收期间源树推进进一步破坏样本同一性。
- 14 天本来就未到期（已知缺口）；更严格地说，当前“第 1 天”样本也不能计作 b259 的有效观察样本。

## 7. P0 与 W 项建议判定

| 项 | 建议 | 证据化理由 |
|---|---|---|
| P0-8 auto-merge | **PASS / 保持关闭** | GitHub allow=false；PR autoMerge=null；本机无 writer/launchd/cron/脚本 |
| P0-9 7789 | **FAIL / PARTIAL** | 回环监听和 fail-closed 健康属实；但仍 legacy 写版，且运行体已从 b259 漂移到 07a949 |
| P0-10 证据/追踪/制品 | **FAIL** | coverage 删除/空断言不红，parser 缺方案/重复行假绿；10 条未登记；索引严格 hash 1/20；矩阵 stale；无签名/SBOM |
| W0（8） | **建议 2/8** | 起点有 clean b259+隔离归档，auto-merge 关闭；但共享源码/远端 main/运行体在验收中推进，目标身份失效 |
| W3（15） | **建议 7/15** | strict/admin/双 required 与 PR 时间线真实，12+66 已接；但 99 专属不在 required、无 merge_group/review/pinning |
| W7（8） | **建议 5/8（至多 6）** | 候选 tar+hash 可验；但非当前 b259 制品、索引不严格、无签名/SBOM，运行部署不是不可变 release |
| W8（7） | **建议 4/7** | 仅回环、健康如实 Gate=failure；现役仍 legacy POST，且运行 SHA 漂移 |
| W9（2） | **0/2** | shadow 启动但 modular=503，实际比较两字段均 null；观察期未到 |
| W10（2） | **1/2** | launchd/样本机制存在；但首样本错 SHA+dirty，14 天/演练/收官未完成 |

## 8. 本子审新增发现

1. **F6-TRC-GATE-001（P0）**：99 coverage 不是 Gate；删除七专属文件后追踪与 acceptance 双绿，空断言也保持 99。
2. **F6-TRC-PARSER-002（P1）**：缺 plan、重复行覆盖、冻结 SHA 漂移可 rc=0；失败 JSON 仍称 catalog_integrity=OK。
3. **F6-TRC-AUTHENTICITY-003（P1）**：21 条抽查 8 部分、2 不匹配；32 missing 仅 22 有模块级整 ID 登记。
4. **F6-EVID-001（P0）**：20 条索引仅 1 条严格路径-hash 匹配、0 size、当前 run/HEAD 未绑定，PR#5 提交声明被实物证伪。
5. **F6-BASELINE-DRIFT-001（P0）**：验收期间外部 writer 将 main/7789 推进至 PR#6/07a949；b259 运行身份与时序证据失效。
6. **F6-OBS-001（P1）**：W9/W10 首样本绑定 b08 dirty/旧 CI；shadow 503、比较 null，不能计入 b259 观察窗。

## 9. 主要证据入口

- `01-git-baseline.txt`：b259 clean 起点。
- `16-trace-mutation-run.txt`、`mutations/summary.{tsv,json}`：§20/§25.1 变异退出码。
- `18-seven-dedicated-runtime.log`：七文件 99/99 实跑。
- **`25-id-sample-audit.md`**：21 条跨七文件逐 ID 真伪表。
- `19-hollow-*`、`20-delete7-*`：空断言/删除七文件假绿。
- `26-not-implementable-audit.json`：32 vs 22+10 对账。
- `evidence-index/strict-audit.json`、`24-candidate-artifact-audit.txt`：20 条索引/制品实算。
- `github/14-summary.json`、`github/15-run-log-key-lines.txt`：CI/保护/PR/工作流。
- `runtime/04-*`、`runtime/17-runtime-vs-remote-branch.json`：7789 hash 与漂移。
- `runtime/12-*`、`runtime/13-observation-semantic-verdict.json`：首样本与 shadow。

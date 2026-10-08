# 第六轮子审计 B：Gate / Schema / CLI / CI / 回滚

- 审计对象：`/Users/maccc/Documents/wenqu-dist`
- 冻结验收快照：`b259dac4248b14af6ec05e1b3fc7f61401aba6b6`
- 隔离副本：`/tmp/wenqu-reaudit6-gate-schema-cli-b259dac.6p9i8M`（由当时 clean 的 `git archive HEAD` 生成）
- 证据目录：`/private/tmp/codex-test/evidence/reaudit6-20261008-155511/agents/gate-schema-cli/`
- 方法：不调用修复方 `test_*` 代替独立断言；先用自写生产 API/CLI/Draft-07 对抗探针，再把修复方套件仅作补充回归。

## 0. 源仓只读与漂移边界

本人未执行过 `checkout/switch/commit/reset/merge/push`，未向源仓写文件。开始时源仓为 clean `b259dac`，关键文件与 `/tmp` 隔离副本逐文件 SHA256 相等（`00-repo-inventory.txt`、`02-isolated-copy.txt`）。主审随后通知共享源仓被外部 writer 漂移到 `release/v3.7.1@419e778`；此后本子审停止触碰共享源仓，全部实跑继续使用既有 `b259dac` 隔离副本。因此本报告只认证 `b259dac`，不认证后来漂移的源树。

## 1. 总结判定

**本子域结论：BLOCKED / 部分闭环。**

- 旧探针 08 合法 `station-v2 → Aggregator → Dashboard`：**PASS**。
- 旧探针 12 深层相对 symlink 升级失败回滚：**PASS**。
- `F4-CLI-001`：**PASS**（源树布局、安装布局、安装体真实 `gate` 均 rc=0；删 `cli.py` 安装 rc=1）。
- `F4-CI-001`：**PASS**（acceptance 64/64 rc=0；两关键文件分别删除均 rc=1；workflow 确实执行 acceptance）。
- `F4-GATE-001`：**PARTIAL / 未闭环**。原“残缺 v2 直接 PASS”已关闭，显式缺站、空 required、冲突裁决、四态退出码均正确；但仍有可复现 fail-open：required 集合可由已上报结果自举、coverage/scope 未绑定权威 frozen manifest、RFC3339-invalid date-time 可 PASS、语义不同重复站被弱等价键吞掉。
- `F4-SCHEMA-001`：**PARTIAL / 未闭环**。指定五类反例均已关闭；但正式 schema 在 `scanned>64` 时仍接受 `PASS 65/66`，只靠聚合器镜像补拦，不满足“Schema 自身不变量”口径。

独立探针共 56 个断言：48 PASS、8 FAIL，审计脚本 rc=1（有 finding 即非零）。其中一个 schema 合法扩展被 CLI 额外拒绝属于 fail-closed 兼容性偏差；`FINDING_REOPENED` 的 `state_to` 残差因事件类型是否隐含目标态存在口径歧义，仅列待裁定，不作为本子域主阻断。

## 2. 旧探针终态

### 2.1 旧探针 08：合法 station-v2 全链

独立构造站 0/3/6，逐份通过严格 Draft-07；生产镜像零错误；聚合结果：

- `aggregate_outcome=PASS`
- `technical_eligible=true`
- `required_total=required_reported=3`
- `malformed=0`
- `wenquctl gate --required 0,3,6` rc=0
- Dashboard `read_gate_aggregate()` 返回 `ok=true` 且 `policy_verdict=PASS`

证据：`03-independent-gate-schema-probe.log`。

### 2.2 旧探针 12：深层相对 symlink 回滚

独立变体同时包含：路径空格、current 位于三层深目录、相对链接含三个 `..`、部署时 cwd=`/`、v2 安装自检失败。结果：

- 捕获 `DeployError`；
- current 精确回指 v1；
- v1 manifest 对账 `ok=true`；
- self-check 调用顺序为 bad-v2 → stable-v1；
- 错误正文含 `rollback self-check re-verified`；
- 脚本 rc=0。

证据：`04-independent-rollback-probe.log`。

## 3. F4-GATE-001 独立复核

### 已闭环

1. 缺 `tool/execution/coverage/artifacts` 的 v2：正式 schema 拒绝；聚合 `BLOCKED`、`technical_eligible=false`、`malformed=1`；CLI rc=2。
2. 显式 required `{0,3,6}` 只报 0/3：`BLOCKED`、`required_missing=1`。
3. 直接空 required：`BLOCKED`；CLI 显式空 `--required`：ERROR rc=3。
4. 同站 PASS/CONDITIONAL 冲突：`BLOCKED`、`conflicts=1`。
5. 四态：PASS=0、CONDITIONAL=1、BLOCKED=2、ERROR=3；CONDITIONAL 的 `technical_eligible=false`。
6. `COMPLETED+NOT_APPLICABLE` → CONDITIONAL/rc1；`TIMEOUT+NOT_APPLICABLE` 虽保留站级 schema 语义，但聚合硬 BLOCKED/rc2。

### 未闭环 / 新反例

#### R6-GATE-SCOPE-001（P0）required 分母可由当前上报集合自举

只交一份合法站 0 且省略 `--required`，CLI 把 `{0}` 当完整 required 集合并返回 rc=0/PASS/technical=true。生产调用方未绑定 run manifest 或 planner 的冻结 required 集，无法识别原本应报 `{0,3,6}` 的 scope shrinking。

#### R6-GATE-COVERAGE-001（P0，与上一项同根因）coverage/scope 为调用方自报

提交 `coverage=1/1`、任意 `scope_hash=caller-chosen-scope`，即使权威分母应为 99，显式 `--required 0` 仍 rc=0/PASS。CLI 无 manifest/registry/可信证据签名输入，结构合法不能证明分母真实。

#### R6-GATE-FORMAT-001（P0）所谓“全量镜像”接受 RFC3339-invalid 时间

正式 schema 声明 `format: date-time`。独立严格格式校验拒绝纯日期 `2026-10-08` 和无时区 `2026-10-08T00:00:00`；生产镜像用 `datetime.fromisoformat`，两者均零错误，Aggregator 和 CLI 均 rc=0/PASS/technical=true。宿主 `jsonschema 4.26.0` 未装 `rfc3339-validator`，默认 FormatChecker 没有 `date-time` checker；生产 `_cross_check_with_jsonschema` 又未传 FormatChecker，不能补拦。修复方所谓“严格”测试同样使用 `datetime.fromisoformat`，未覆盖该差异。

#### R6-GATE-DUP-001（P1）语义不同重复站被弱等价键吞没

两份同站 PASS 仅 outcome/SHA/environment 相同，但 `attempt_id`、`scope_hash`、coverage（1/1 与 7/7）和 artifact digest 全不同；代码仍记 `duplicates_ignored=1/conflicts=0` 并 PASS。实现注释声称仅“内容完全一致”才幂等，但实际等价键只比较三个归一字段。

#### R6-GATE-EQUIV-001（P2，fail-closed 兼容性）CLI 与正式 schema 不等价

在 `identity` 增加 schema 默认允许的嵌套扩展字段：正式 Draft-07 合法、镜像合法，但 CLI 另一套 `validate_station_result` 私自施加嵌套 `additionalProperties:false`，最终 rc=2/BLOCKED。不是假绿，但否定“schema 可执行等价物”及前向兼容。

完整命令、输出、退出码：`03-independent-gate-schema-probe.log`；探针源码：`independent_gate_schema_probe.py`。

## 4. F4-SCHEMA-001 独立复核

### 指定反例已闭环

- evidence `PASS+exit7`：拒绝；`PASS+exit0` 合法；`FAIL+exit7` 合法。
- station `PASS 2/3`：拒绝；`PASS 3/3` 合法。
- station `PASS+exit9`、`PASS+assertion FAIL`、`PASS 0/0`：均拒绝。
- `RISK_INVALIDATED` 缺 `state_from/state_to`：拒绝；完整 `ACCEPTED_RISK→OPEN` 合法。
- `SUPERSEDED` 缺 `state_from`：拒绝；从 OPEN 合法；从 CLOSED 拒绝。
- station/run `TIMEOUT+CONDITIONAL`：均拒绝；`COMPLETED+CONDITIONAL` 合法。
- NOT_APPLICABLE 边界符合声明：完成态为 CONDITIONAL 不上绿；TIMEOUT 仍硬 BLOCKED。

### 仍有正式 Schema 缺口

`station-result-v2.schema.json` 只为 scanned=1..64 生成等值级联，且未给 denominator/scanned 上限；因此正式 Draft-07 对 `PASS, scanned=65, denominator=66` 返回合法。聚合镜像会补拦，所以当前 CLI 路径不假绿，但 **P0-4“Schema 本身具备不变量”仍未完全闭环**。证据：`03-independent-gate-schema-probe.log`（`R6-SCHEMA-BOUND-001`）。

待裁定残差：`FINDING_REOPENED(state_from=ACCEPTED_RISK)` 不带 `state_to` 被 schema 接受；冻结方案写“风险撤销/失效后立即重开”和“CLOSED 再现→OPEN”，但其他事件是否由 event_type 隐含 target 尚有解释空间，本轮不升格主阻断。

## 5. F4-CLI-001

- 源树 `system/bin/wenquctl --help` rc=0。
- `install.sh --prefix <tmp>` rc=0。
- 安装体 `<prefix>/bin/wenquctl --help` rc=0。
- 安装体真实 `gate` 对合法 station-v2 rc=0/PASS。
- 安装布局存在 `<prefix>/bin/wenquctl` 与 `<prefix>/lib/wenqu_core/cli.py`，hash 分别与冻结源一致。
- 隔离变异删除 `wenqu_core/cli.py` 后，安装 rc=1，正文明确“安装体 wenquctl 断链”。

判定：**F4-CLI-001 PASS**。证据：`05-install-double-layout.log`、`06-install-missing-cli-mutation.log`。

## 6. F4-CI-001、acceptance 与三移除锚点

### Required workflow 接线

`.github/workflows/acceptance.yml` 的双 OS matrix 明确执行 `bash tests/acceptance.sh`；acceptance P1d/P1e 直接执行两关键套件，缺文件分支递增 FAIL，最终任何 FAIL `exit 1`。静态断言全真，`bash -n` rc=0。证据：`11-ci-wiring-static.txt`。

### 实跑

- 完整 acceptance：`RESULT: PASS=64 FAIL=0 / ALL GREEN / rc=0`。
- 删 `test_wenqu_adversarial.py`：`PASS=63 FAIL=1 / rc=1`，P1d 精确红。
- 删 `test_infra_hardening.py`：`PASS=63 FAIL=1 / rc=1`，P1e 精确红。
- 修复方补充回归（不替代独立探针）：gate/schema 20/20、CLI/install/CI 19/19、adversarial 12/12、infra 66/66，均 rc=0。

三移除锚点分别独立变异，完整 acceptance 均 rc=1：

1. 删 `system/wenqu_core/wenqu_pipeline.py`：58/6；
2. 删 `system/schemas/approval-v2.schema.json`：61/3；
3. 删 `tools/ac_traceability.py`：63/1。

证据：`07-acceptance-full.log`、`08-acceptance-delete-adversarial.log`、`09-acceptance-delete-infra.log`、`10-removal-anchor-*.log`、`12-developer-regression-suites.log`。

判定：**F4-CI-001 PASS（对 b259dac 的本地 required workflow 内容）**。分支保护实时回读和指定 GitHub run 由主审/CI 子审合并，不在本子审重复认证。

## 7. P0 与 W 分项建议（供主报告合并）

| 项 | 本子审建议 | 理由 |
|---|---|---|
| P0-1 核心接线 | **PASS（仅 b259dac 候选面）** | 双布局 CLI、安装体真实 gate、三移除锚点、required acceptance 接线均有实跑；源仓后续漂移须主审另行冻结。 |
| P0-3 契约链/Gate | **FAIL / PARTIAL** | 合法全链与原残缺反例闭环，但 frozen required/scope/coverage 未绑定，format-invalid 可假绿，弱重复冲突被吞。 |
| P0-4 Schema 不变量 | **FAIL / PARTIAL** | 五项指定反例闭环；正式 station schema 的 >64 等值域仍有缺口，生产镜像仅作补偿。 |
| P0-7 部署/回滚 | **PARTIAL** | 双布局安装和深层相对链接失败回滚通过；已知无 SBOM/签名、现役 7789 仍非 immutable release，不可判整体 PASS。 |

建议分项（仍需主审结合其他子域）：

- **W1：7/10（不升）**。五项跨字段修复属实，但 formal schema 边界、format 镜像不等价仍在；冻结方案要求的完整形式化/红探针面也非本轮全部闭合。
- **W3：8/15**。相对第四轮可因真实 `wenquctl gate`、四态退出和 P1d/P1e required 接线加分；但上述 Gate fail-open 使其不能更高或通过硬门。
- **W7：6/8**。安装 CLI 与回滚实证支持 +1；无签名/SBOM及运行体非不可变 release 继续扣分。

## 8. 证据入口

| 文件 | 内容 |
|---|---|
| `00-repo-inventory.txt` | 开始时 b259dac、clean、树清单 |
| `01-source-review.txt` | 冻结快照关键实现逐行审阅 |
| `02-isolated-copy.txt` | git archive 与 11 个关键文件双边 SHA256 |
| `03-independent-gate-schema-probe.log` | 独立 56 断言、完整输出/rc；核心新反例 |
| `independent_gate_schema_probe.py` | 独立探针源码 |
| `04-independent-rollback-probe.log` | 旧探针12独立变体完整输出/rc |
| `independent_rollback_probe.py` | 回滚探针源码 |
| `05-install-double-layout.log` | 源/安装布局、安装体 gate 实跑 |
| `06-install-missing-cli-mutation.log` | 删除 cli.py 后安装必红 |
| `07-acceptance-full.log` | acceptance 64/64 rc0 |
| `08-*`、`09-*` | 两关键测试文件分别删除必红 |
| `10-removal-anchor-*.log` | 三移除锚点逐项完整 acceptance 必红 |
| `11-ci-wiring-static.txt` | workflow→acceptance→P1d/P1e 静态接线 |
| `12-developer-regression-suites.log` | 修复方四套补充回归 |
| `MANIFEST.sha256` | 本目录全量 SHA256 清单（排除自身） |

# 第七轮子任务 C：运行面、外部事实与制品独立复审摘要

- 审计时段：2026-10-08 20:49–21:02（Asia/Shanghai）
- 冻结候选：`d32c859f9043798d9e8a4984e8f57aa64567e33c`
- 取证原则：源仓只读；冻结树由 `git archive d32c859` 导出；需 `.git` 的测试在 `/private/tmp/reaudit7-release-d32c859` 独立 detached clone 执行；所有破坏性变异只在 `/private/tmp`。
- 子任务总判定：**BLOCKED**。这不是否定 d32 的全部代码：CI、模块化 7789、W4 代码测试、W5、TLA 与签名机制均有真实正证；阻断来自最终集成 release 并非 d32、release policy hash 错绑、证据索引不满足其宣称的严格契约、有效观察窗首样本不存在，以及现役调度聚合依赖可变共享工作树且审计时已 fail-closed 为 BLOCKED。

## 一、必须分离的三个身份

| 身份 | 实查事实 | 判定 |
|---|---|---|
| 冻结候选 | Git 对象 `d32c859...`，tree `88d730...`；所有候选测试均从该对象导出的独立副本运行 | 审计正本 |
| 远端 main / CI | 20:57 实查 `refs/heads/main=d32c859...`；run `37778240376` 为 main push、两平台 job 均 `success` | PASS |
| 现役运行体 / 可变工作树 | 7789 实际执行 `~/.wenqu/dashboard/server.py`，四个模块化静态/服务文件与 d32 逐字节相同；但 active VERSION 为 3.8.4，调度器 `WorkingDirectory/PYTHONPATH` 指向共享仓，仓当时为 `wave6/p1f-gate@1495913...` 且持续有并行在途改动 | 不能等同于“d32 已不可变部署” |

审计开始 20:49 的共享树仅有 VERSION、旧 dashboard 与 SHA 文件在途变更；20:51 前后外部并行验证使 `system/wenqu_core/wenqu_pipeline.py` 缺失，20:56 又见 `system/schemas/approval-v2.schema.json` 缺失。未对这些文件做恢复或修改，也不把它们归责于冻结 d32；但自然 launchd tick 证明现役调度会直接消费这棵可变树。

## 二、逐项判定

### 1. GitHub CI 与分支保护

- **CI：PASS。** `gh run view 37778240376`：event=`push`、branch=`main`、headSha=`d32c859...`、conclusion=`success`；Ubuntu job `113314473537` 与 macOS job `113314473846` 全部完成成功。
- **远端 main：PASS。** 20:57 `git ls-remote origin refs/heads/main` 仍为 d32。
- **经典 branch protection：PASS / 治理加固 PARTIAL。** strict required checks 精确为 `matrix (ubuntu-latest)`、`matrix (macos-latest)`，`enforce_admins=true`，禁止 force-push/delete；PR#8/#9 均经两平台绿检查合入。另一方面 required signatures、conversation resolution、linear history 未启用，没有 ruleset，保护响应亦无 required pull-request reviews。不能把两条 required checks 扩大为完整 CODEOWNERS/签名治理。

### 2. 7789 模块化运行身份（P0-9）

- **PASS。** listener 为 `127.0.0.1:7789`、PID 78778、PPID 1，命令为 `...Python ~/.wenqu/dashboard/server.py --port 7789`；dashboard LaunchAgent 指向该模块化文件。
- active `server.py/index.html/app.js/app.css` 与冻结 d32 对应文件逐字节相同，SHA256 分别为 `fb4c6c...`、`caa333...`、`fed9d1...`、`d0e329...`。
- `/api/v1/ping`、`components`、`health` 可读；未版本化 `/api/health` 为 404；`POST /api/decide` 与 `/api/v1/decide` 均 405 `WRITE_DISABLED`，PUT/OPTIONS 亦 405。
- 边界：active VERSION=3.8.4，而冻结 d32 VERSION=3.8.3；health 数据来自共享工作树驱动的 aggregate，不是 d32 的不可变 release identity。

### 3. W4 生产调度、通知、DR

- **候选实现与调度活性：PASS；审计终点现役 aggregate：BLOCKED。** 冻结 d32 的 `test_w4_production.py` 为 36 PASS/0 FAIL。LaunchAgent 每 300 秒运行，run counter 持续增加；20:46 前连续多轮自然 tick 为 PASS。20:51、20:56、21:01 三轮自然 tick 在共享树文件缺失时 gate 均正确 fail-closed 为 BLOCKED，`cli_exit=1`，而调度 job/心跳本身仍 COMPLETED/PASS/rc0。
- **通知：PASS。** 现役 scheduler DB 中 `alertbox` 与 `macos` 各 1 条，均 `SENT`、attempts=1；投递箱 txt 与 `receipts.jsonl` 的 message_id 对账一致。这里的 macOS “送达”证据是 `osascript` 调用成功/DB SENT，不等于用户阅读回执。
- **DR：PASS。** `drill-20261008T095759Z` 含 5 文件 snapshot→tamper→restore→reconcile，逐文件 SHA/byte match；独立重算 RPO=2.058311s≤300s、RTO=0.475040s≤60s，JSONL 时间单调、终态 PASS。
- **生产身份缺口：BLOCKED（归 W7/部署面）。** scheduler LaunchAgent 直接以共享仓为工作目录和 PYTHONPATH，而非 immutable release；并行树变化可在下一自然 tick 改变生产 aggregate。此轮实时 health 最终忠实返回 BLOCKED，说明 fail-closed 生效，但也证明“冻结 d32 已稳定部署”不成立。

### 4. W5 旧账 reconciliation

- **PASS（带数据新鲜度说明）。** 冻结报告的 1967 行可由当前 live 文件的前 833858 bytes 精确复原，prefix SHA256=`cd0b1d...` 与报告一致；逐行 ID/line/source preview 全对，四态为 mapped 16、quarantine 1950、待人工 1、不一致 0；EventStore 16 事件 ID/哈希链/line_sha、append-only trigger 与四次 migration run 均独立对账通过。
- live 源在报告后 append-only 增至 1974 行（SHA256=`737c01...`）。用冻结 d32 工具在全新 `/tmp` 重跑：mapped 16、quarantine 1957、待人工 1、不一致 0；两轮导入 16→0、重复 0→16，守恒/幂等/链验证/源字节不变全部通过。故 1967 是有效历史快照，不是当前分母。

### 5. TLA+/TLC 与规约-代码一致性

- **PASS（仅限已声明有界范围）。** jar SHA256=`8cce75...`；`test_tla_spec.py` 10/10；真实 TLC rc0、7 invariant、2442 generated / 834 distinct / queue 0 / depth 12、No errors。
- 独立红探针：反转 `OutcomeStatus` 后 TLC rc12 且 `DoubleAxisNoWash` 被违反；篡改 `StageOrder` 一项后规约-代码 pytest rc1（1 failed, 9 passed）。
- 边界保持：cfg 明确仅 2 段、每段 2 attempt 与有限 version constraint，不能外推为全状态空间证明。

### 6. release 签名/SBOM（W7）

- **W7A 机制：PASS。** 四件套存在；keyring mode 0600；verify 六项全过；独立重建 1620c7c 的 tar 字节完全一致；独立翻转 tar 单字节后 verify rc1。`test_release_attest.py` 8/8。
- **W7B 最终集成候选：FAIL。** manifest/tar 绑定 `1620c7c...`、VERSION 3.7.1，并非 d32/3.8.3。`1620c7c..d32c859` 共 77 文件变化（42 add、35 modify，+59940/-1002）；该 tar 不含 `approval_issue.py`、`drill_runner.py`、W4 测试、TLA 测试/规约、`release_attest.py` 等本轮关键增量。四件套只能证明旧提交制品，不是本轮最终集成 release。
- **policy hash 错绑：FAIL。** 冻结方案实际 SHA256 为 64 字符 `96b864...51d3129f...c32306`；工具常量和已签 manifest 中为 61 字符 `96b864...51d9fc...c32306`。verify 不校验 policy_hash 与方案文件/固定期望，错误值仍 `VERIFY OK`。
- HMAC 对称、非非否认属于已声明已知边界，本项未重复作为新发现。

### 7. evidence index 20 条

- **FAIL。** 路径存在/均为文件/ID 唯一为 20/20；但只有 11/20 条具有非空裸 64hex `artifact_sha256`，这 11 条实算一致。其余 9 条为 null，不能称“实算 hash 20/20”。
- 按第六轮 F6-EVID 明示的十字段严格口径（run_id、40hex commit、environment、scope、ruleset、time、argv、real_rc、具体文件路径+实算 SHA、fresh_until），仅 6/20 完整；`repo_head_at_filing` 仍为 `07a9494...`，不是 d32。

### 8. W10 观察窗样本

- **FAIL / 未形成有效 Day 1。** 冻结 d32 只跟踪 `evidence/13-observation-window/README.md`，没有 `samples/` 快照。README 自身规定：必须 clean main SHA 且波间入仓，未入仓不计窗口。
- 活跃 `~/.wenqu/observation/samples/2026-10-08.json` 在 20:56 已被调度覆盖为 `head=1495913...`、`dirty=true`；active observation 全目录及冻结证据均找不到 `c9de6a4` 绑定文件。因此“clean c9de6a4 样本已存在并可起算”的声明当前不可复核。
- 14 天未到期是已知诚实缺口；本轮新增事实是 Day 1 合格样本并未被保全。

## 三、关键证据导航

| 证据 | 内容 |
|---|---|
| `00-baseline.txt`, `01-freeze-d32c859.txt` | 共享树起点与冻结 Git 对象 |
| `02-gh-run-json.txt`, `03-gh-run-human.txt`, `42-online-final-recheck.txt`, `48-online-final-2102.txt` | run 37778240376 与远端 main 实查 |
| `04-remote-main-live.txt`–`08-pr-merge-facts.txt` | branch protection、ruleset、check-runs、PR 合流 |
| `10b-live-7789-process.txt`, `11b-launchd-inventory.txt`, `12c-live-http-7789.txt`, `13-runtime-candidate-hash.txt` | 7789 进程/API/hash/LaunchAgent |
| `14-scheduler-snapshot-1.txt`, `16-scheduler-latest-drift.txt`, `38-scheduler-snapshot-2056.txt`, `41-scheduler-snapshot-2057.txt`, `47-scheduler-final-2101.txt` | 自然 tick、工作树时间线、PASS→BLOCKED |
| `36-w4-tests-d32.txt`, `39-w4-alert-dr-independent.txt`, `40-w4-db-outbox.txt`, `46b-dr-independent-math.txt` | W4 36 测试、通知、DR 独立对账 |
| `32-w5-artifact-inspect.txt`–`35-w5-live-drill-d32.txt` | W5 历史 1967 前缀与 live 1974 重跑 |
| `29-tla-pytest-tlc.txt`, `31c-tla-independent-mutations.txt` | 真 TLC 与独立应红变异 |
| `25-release-four-verify.txt`–`27-release-tests-d32.txt`, `43b-release-stale-policy-binding.txt`, `45-release-independent-rebuild-tamper.txt` | release 四件套、陈旧源提交、policy hash、重建/篡改 |
| `20-evidence-index-recompute.txt`, `22-sixth-report-evid-criteria.txt`, `23-evidence-index-strict-contract.txt` | 索引逐条实算与严格 6/20 |
| `44-observation-sample-binding.txt` | W10 样本存在性、SHA/dirty 绑定与仓内缺件 |

## 四、取证脚本自身更正说明

下列早期日志包含审计脚本/命令引用错误，已由后缀版本纠正，不作为产品失败依据：`10→10b`、`11→11b`、`12/12b→12c`、`17→17b`、`31/31b→31c`、`43→43b`、`46→46b`。每份文件均保留原命令、输出和 exit code，未删除或改写失败记录。

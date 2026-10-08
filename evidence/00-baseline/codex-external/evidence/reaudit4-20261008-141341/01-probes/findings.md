# 第四轮独立复审：第三轮 12 项失败探针逐条复核

## 1. 身份、边界与方法

- 产物仓：`/Users/maccc/Documents/wenqu-dist`
- 验收对象：`main@e4aba84c1dabe1342ea234321eea3d300bea24a5`
- 第三轮报告：`/private/tmp/codex-test/验收报告-第三轮.md`
- 12 项口径：第三轮报告第 292～303 行，从“伪签名+缺绑定”至“升级回滚”的连续 12 项；`§20`、`§25.1` 两项按总任务“常规核验”另行处理，不在本组重复计数。原文见 `00-third-round-12-source.txt`。
- 隔离副本：`/tmp/wenqu-reaudit4-probes-e4aba84.e0zspj`，由 `git archive HEAD` 生成、无 `.git`；`wenqu_pipeline.py` 与产物仓 SHA256 同为 `358e3d123a55c80bdc87e14dc939d7865b8f8607ca9a567b8d6f266d72c2bbcf`。见 `00-isolation-copy.txt`。
- 产物仓开始及中途均 clean；所有 SQLite、CAS、部署树、marker、审批测试 key 均只存在于 `/tmp` 临时目录。开始/中途证据见 `00-start-git-status.txt`、`00-mid-git-status.txt`。
- 用例不是调用修复方的 `test_wenqu_*` / `test_infra_hardening.py`，而是本轮新写的异源探针 `scripts/reaudit4_probe_suite.py`。每项日志均包含完整命令、stdout/stderr 与最终退出码。

## 2. 总结论

**11/12 项完全闭环；1/12 项仅部分闭环且安全目标仍 FAIL。**

- `01～10、12`：新反例均 `rc=0`，判定 **PASS / 完全闭环**。
- `11 Runner 逃逸`：普通、仍保留 PPID 关系的 `setsid` 子进程已能被补杀；但 `setsid + double-fork` 在超时前先 reparent 的 daemon 连续三次写出 timeout 后 marker，三次均 `rc=1`。判定 **部分闭环（安全目标 FAIL，仍是阻断项）**。
- 因此不能把“Runner 进程树终止”声明为全闭环；当前实现是 PPID 快照补杀，不是强进程隔离边界。

机器汇总见 `01-results-rollup.txt`；全部实现行证据见 `02-code-line-evidence.txt`。

## 3. 逐条判定

| # | 第三轮失败项 | 本轮独立新用例与实际结果 | 判定 | 实现行证据 | 原始日志 |
|---|---|---|---|---|---|
| 01 | 伪签名+缺绑定 | 用另一份合法信封的 HMAC 替换当前信封签名；另对删除 `policy_hash` 的信封用已登记测试 key 重新签名。前者以 `HMAC-SHA256 signature verification failed` 拒绝，后者以 `missing required field: policy_hash` 拒绝；run 保持 WAITING、nonce 未消费；正确签名正例恢复成功。`rc=0`。 | **PASS** | `approval_keys.py:63-82,177-185`；`wenqu_pipeline.py:306-343,1029-1203` | `logs/probe-01-forged-signature-missing-bindings.log` |
| 02 | risk 冒充 resume | 一份结构合法、正确签名的纯 risk 信封投到 `resume_waiting`，API 路由拒绝；一份 resume payload 在保留全部 resume 键后混入 risk 的 `severity`，正式 Schema 与 Broker 均拒绝；拒绝路径无消费，纯 resume 正例成功。`rc=0`。 | **PASS** | `wenqu_pipeline.py:324-343,1124-1188,1358-1363,1460-1468` | `logs/probe-02-risk-masquerade-resume.log` |
| 03 | 未恢复资源字符串假布尔 | 改用 `ext-unavail` 停等，把 `evidence_freshness_reverified` 设为带空白/大小写的字符串 `" FALSE "`，即使审批哈希精确绑定该值仍以“must be a real boolean”拒绝，nonce 不消费；真 bool 正例成功。`rc=0`。 | **PASS** | `wenqu_pipeline.py:284-297,762-810` | `logs/probe-03-false-preconditions.log` |
| 04 | 非 resume CAS | S1 RUNNING 时构造正确签名、空 finding 面的 LOW risk 授权，`expected_state_version=current-1`；以 action 类 CAS failure 拒绝、版本不推进、nonce 不消费；当前版本正例成功。`rc=0`。 | **PASS** | `wenqu_pipeline.py:1471-1522` | `logs/probe-04-nonresume-cas.log` |
| 05 | TIMEOUT/P1 洗白 | S7 `TIMEOUT+CONDITIONAL` 映射为 attempt FAILED，run 最终 FAILED；另构造 `LOW/P1` finding：声称覆盖其指纹的 risk 包被精确匹配拒绝，即便先消费空覆盖面授权，`complete_run` 仍因 P1 机器拒绝且 run 留在 RUNNING。`rc=0`。 | **PASS** | `wenqu_pipeline.py:819-868,1524-1542,2291-2368` | `logs/probe-05-timeout-p1-launder.log` |
| 06 | 控制事件直写 | 公共 `EventStore.append` 注入 `SUPERSEDED` 被拒，事件数/状态无变化；再绕过公共入口直插一条哈希链有效、但偷用另一合法事件 seal 的 `SUPERSEDED`，重放以 `PipelineCorruptionError` 拒绝。`rc=0`。 | **PASS** | `store.py:25-51,108-126`；`wenqu_pipeline.py:1733-1748,2012-2024` | `logs/probe-06-control-event-direct-write.log` |
| 07 | 仅事件重放丢 nonce | 消费一份 risk 授权后，只复制 `pipeline_events` 五列到全新 DB，不复制 `approval_consumptions`。新库旁表确为 0 行，但重放状态含 nonce digest，同 nonce 再消费由“事件正源已登记”拒绝。`rc=0`。 | **PASS** | `wenqu_pipeline.py:1288-1331,1366-1378,1762-1794` | `logs/probe-07-events-only-replay.log` |
| 08 | station v2→aggregator→dashboard 断链 | 手工构造 0/3/6 三个正式 v2 station（非调用仓内构造器），三份先过正式 Draft-07 Schema；aggregator 得 `PASS`、3/3 reported、0 malformed；其原样 JSON 快照被 dashboard `read_gate_aggregate()` 接受。`rc=0`。 | **PASS** | `gate_aggregator.py:158-232,266-317,394-415`；`dashboard/server.py:102-132` | `logs/probe-08-station-v2-chain.log` |
| 09 | EventStore 重试返回伪 hash/head 错位 | 先写 alpha 后关闭连接；reopen 后写 beta/gamma/delta，再以不同 JSON 键序重试 alpha。duplicate 返回原 alpha 在库 hash、总行数仍 4；`head()` 指 delta 链尖而非 alpha；全链 ok。`rc=0`。 | **PASS** | `store.py:108-179` | `logs/probe-09-eventstore-retry.log` |
| 10 | CAS 父目录竞态 | 在 `mkdir` 返回瞬间（不是修复方用例的 `os.open` 注入点）把新 shard 改名并换成指向根外的 symlink；`O_NOFOLLOW` 路径以 `IntegrityError` 拒绝，根外零写入。另把已打开的整个 CAS 根路径换成根外 symlink，持久 root dirfd 仍写原目录对象。`rc=0`。 | **PASS** | `runner.py:280-360,372-498` | `logs/probe-10-cas-parent-race.log` |
| 11 | Runner setsid 后代逃逸 | **对照闭环：**仍保留 PPID 关系的 `setsid` 子进程在 timeout 后未写 marker。**同族残余：**子进程 `setsid` 后 double-fork，第一子进程立即退出，使 daemon 在 timeout 前已 reparent；daemon 在 timeout 后成功写 marker。最终日志 `rc=1`，重复日志同样 `rc=1`；连同初次运行共 3/3 重现。所有逃逸探针 PID 均已显式 `SIGKILL` 清理。 | **部分闭环 / FAIL（阻断）** | `runner.py:149-175` 只从超时当下 `ps(pid,ppid)` 构建原 root PID 后代；`177-196` 的多轮扫描仍从已死亡 root PID 出发，无法重新发现此前已 reparent 到 launchd/PID 1 的 daemon。此根因判断由源码与动态 3 次重现共同支撑。 | `logs/probe-11-runner-escape.log`、`logs/probe-11-runner-escape-repeat.log`、`logs/probe-11-runner-escape-initial.log` |
| 12 | 升级失败回滚 | 构造 release 根含空格、`current` 位于多层异目录的拓扑，相对链接含多级 `..`；切到 `/` cwd 后 v2 自检失败，抛出含 rollback/re-verified 的 `DeployError`，current 精确回 v1，v1 再验成功。`rc=0`。 | **PASS** | `deploy_framework.py:228-236,295-345,350-410` | `logs/probe-12-upgrade-rollback.log` |

## 4. 唯一未闭环缺口：Runner daemon 化逃逸

### 4.1 可复现实锤

最终用例的同一命令记录在日志头部：

```text
env WENQU_REPO_COPY=/tmp/wenqu-reaudit4-probes-e4aba84.e0zspj \
  PYTHONDONTWRITEBYTECODE=1 python3 \
  .../scripts/reaudit4_probe_suite.py --probe 11
```

三次观测：

1. PID `17388`：`marker_exists=true`，`rc=1`；
2. PID `18366`：`marker_exists=true`，`rc=1`；
3. PID `18959`：`marker_exists=true`，`rc=1`。

最终/重复两轮还同时证明 attached-setsid 对照组 `marker_exists=false`，所以不是“整个补杀代码完全没运行”，而是 **PPID 关系在超时前消失** 的特定逃逸。

### 4.2 根因与影响

- `_descendants(root_pid)` 只读取某一时刻的 `pid→ppid` 图并从 `root_pid` 向下找；double-fork 中间进程提前退出后，daemon 已由 launchd/PID 1 接管，不再是原 root 的图后代。
- `_kill_tree()` 三轮仍以原 root PID 为根；root 被杀后再次扫描不会恢复历史亲缘关系。
- 影响：一个被判定 timeout 的非受信命令仍可在 runner 返回之后继续写文件、发网络请求或持锁；这违反“timeout 后进程树已终止”和 TrustedRunner 作为受信执行边界的关键不变量。
- 风险等级：**高 / P0-5 未关闭**。这不是已知的“seal 威胁模型边界”或时序证据缺口，而是本轮新增的可执行逃逸变体。

### 4.3 验收建议（不在本轮只读验收中修改）

不能只继续增加 `ps` 轮数。应把 runner 放入可强制收拢的 OS 级进程容器（Linux cgroup/pid namespace，或目标平台等价机制），或在命令能力面禁止 fork/setsid/daemon 化；若仅做用户态补强，至少需连续跟踪 fork 关系并在 reparent 前登记 PID，但仍不能把该方案等同于强隔离。修复后须保留本轮 `setsid+double-fork` 负例，并断言 marker 永不出现、逃逸 PID 不存活、返回延迟受控。

## 5. 证据索引

- `00-start-git-status.txt`：开始 HEAD/clean。
- `00-isolation-copy.txt`、`00-isolation-path.txt`：git archive 隔离副本及关键源码 hash 对账。
- `00-third-round-12-source.txt`：第三轮 12 项精确提取与口径。
- `00-mid-git-status.txt`：探针运行中产物仓仍 clean。
- `01-results-rollup.txt`：各日志 `PROBE_RESULT` 与退出码汇总。
- `02-code-line-evidence.txt`：12 项对应现役实现的带行号全文摘录。
- `99-end-git-status-and-cleanup.txt`：结束 HEAD/clean；五个已记录探针 PID 全部不存在。
- `scripts/reaudit4_probe_suite.py`：独立探针源码。
- `scripts/capture.sh`：命令/stdout/stderr/退出码捕获器。
- `logs/probe-01-*.log` ～ `logs/probe-12-*.log`：逐项完整原始执行记录；11 号含三次重现。

## 6. 子任务结论

第三轮 12 项失败探针不能判为“12/12 已关闭”。准确结论是：

> **11 项完全闭环；Runner 的普通 attached-setsid 情形已修，但 setsid+double-fork 提前 reparent 仍可逃逸，故第 11 项仅部分闭环且安全目标 FAIL。**

该缺口应回流 P0-5、W3/W5（按总报告口径由主验收方裁定），并阻止把 TrustedRunner 宣称为强进程隔离边界。

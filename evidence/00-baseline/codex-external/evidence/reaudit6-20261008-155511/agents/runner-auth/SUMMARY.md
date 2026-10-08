# 第六轮子审计 A 摘要（授权 / EventStore / CAS / Runner）

- 冻结被测体：`main@b259dac4248b14af6ec05e1b3fc7f61401aba6b6`
- 隔离副本：`/tmp/reaudit6-runner-auth.biRqsY`（由开始时 clean HEAD 的 `git archive` 生成）
- 证据目录：`/private/tmp/codex-test/evidence/reaudit6-20261008-155511/agents/runner-auth/`
- 原则：未调用修复方测试函数；所有已执行探针均使用隔离副本。

## 旧探针终态（本子审计负责范围）

| 旧探针 | 本轮独立变体结论 | rc | 完整日志 |
|---|---|---:|---|
| 01 HMAC / exact envelope binding | **PASS** | 0 | `logs/probe-01.log` |
| 02 risk / resume 路由与判别 | **PASS** | 0 | `logs/probe-02.log` |
| 03 严格布尔前置条件 | **PASS** | 0 | `logs/probe-03.log` |
| 04 非 resume 授权 CAS | **PASS** | 0 | `logs/probe-04.log` |
| 05 TIMEOUT / P1 不可洗白 | **PASS** | 0 | `logs/probe-05.log` |
| 06 控制事件入口与重放校验 | **PASS** | 0 | `logs/probe-06.log` |
| 07 仅事件重建后的 nonce 防重放 | **PASS** | 0 | `logs/probe-07.log` |
| 09 EventStore 并发幂等 / 链头 | **PASS** | 0 | `logs/probe-09.log` |
| 10 CAS 叶子竞态边界 | **PASS** | 0 | `logs/probe-10.log` |
| 11 Runner 终止 / token / reparent | **未执行、不得判 PASS** | N/A | 无；收到根审计方停测指令前尚未开始 |

说明：01–07、09–10 的 `PASS` 仅覆盖各日志所载独立变体，不替代未执行的 Runner 11，也不扩张为生产隔离结论。

## F4-AUTH-001 专项

**未完成 / BLOCKED（验收证据不足，不得认证闭环）。**

- 专项命令已启动，但独立验收脚本在参数矩阵阶段发生 harness `TypeError`，`rc=2`；日志：`logs/probe-auth.log`。
- 错误发生于专项全量断言完成前，属于验收夹具错误，不能据此判产品 FAIL，也不能以 01–07 的局部通过替代专项通过。
- 已完成的相关局部证据：01（签名/信封）、02（类型路由）、04（CAS）、07（nonce 事件正源）均 `rc=0`；但 action 封闭映射、payload 全语义、事务成对、receipt 全链及失败终态的组合验收未形成完整有效结果。

## P0 / W 结论建议

| 项目 | 结论 | 依据 |
|---|---|---|
| P0-2 七段状态机与审批 | **FAIL / PARTIAL** | 01–07 局部关闭；F4-AUTH 专项未完成，审批签发端亦属已知未建边界，不能关闭 P0。 |
| P0-5 Runner / CAS | **FAIL / PARTIAL** | CAS 独立变体通过（probe-10），但 Runner probe-11 未执行；容器级隔离与 Linux 通路仍是已知未实测边界。 |
| P0-6 EventStore / 迁移唯一正源 | **FAIL / PARTIAL** | EventStore 并发幂等、链头与 event-only nonce 重放通过（probe-07/09）；W5 迁移/对账与时序证据未到期，不能关闭唯一正源与迁移闭环。 |
| W2 Runner / 事件 / 授权 / CAS | **PARTIAL，不建议加到满分** | 01–07、09、10 有新实跑正证；11 与 F4-AUTH 专项缺失，且强隔离边界仍在。 |
| W5 旧账迁移 / 对账观察 | **BLOCKED / 未到期** | 本子审计未形成到期迁移观察与逐项对账新证据。 |

## 源仓零写与漂移边界

- 我未执行 `checkout/switch/commit/reset/merge/cherry-pick`，未向 `/Users/maccc/Documents/wenqu-dist` 写入文件，也未运行任何广泛进程清理命令。
- 开始快照在 `15:55:59+0800` 记录源仓为 clean `main@b259dac...`：`baseline/repo-state-start.txt`。
- 被测文件哈希见 `baseline/isolation-identity.txt`；后续探针只读取既有冻结副本。
- 根审计方随后报告源仓已漂移至其他分支/SHA；该漂移不是本子审计造成，且不影响上述冻结副本证据。收到停测指令后未再运行新测试。

## 证据完整性

- 独立脚本：`scripts/auth_event_probe.py`
- 逐命令完整输出及退出码：`logs/probe-*.log`
- 清单：`MANIFEST.sha256`


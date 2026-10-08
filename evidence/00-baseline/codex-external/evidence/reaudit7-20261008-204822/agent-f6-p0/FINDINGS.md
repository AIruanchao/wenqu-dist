# 第七轮子审计 A：F6 六项与 P0 十项（冻结 d32c859）

- 验收对象：`d32c859f9043798d9e8a4984e8f57aa64567e33c`
- 独立副本：`/tmp/wenqu-reaudit7-f6p0-22971`；所有破坏性探针均在该目录或另建 `/tmp` 副本。
- 源仓边界：本审计者对 `/Users/maccc/Documents/wenqu-dist` **零写入、零删除、零 checkout/restore、零部署**。审计结束时源仓已由外部并行会话漂移至 `1495913...` 且有删除/修改；仅作为环境事实记录，未恢复、未归因给 d32。

## F6 六项结论

| 项 | 判定 | 关键独立验证 |
|---|---|---|
| GATE-SCOPE | **FAIL** | 正常 manifest rc0；但修改 required 集并重算无密钥摘要后，且顶层 required 与 planner 不一致，Gate 仍 rc0/PASS。所谓冻结清单没有可信根与内部一致性校验。 |
| GATE-FORMAT-DUP | **PARTIAL** | 裸日期 RFC3339 已 rc2/BLOCKED；但同站重复件改变规则/工具/执行/发现语义后仍被当作 duplicate ignored，rc0/PASS。 |
| SCHEMA-BOUND | **PARTIAL** | Gate 镜像对 PASS 65/66 rc2；正式 Draft7 schema 直接校验仍 0 error，双正源不等价。 |
| TRC-GATE | **PARTIAL** | 删除任一专属文件，完整 acceptance rc1（已修）；但把一整个专属文件换成同数量 `def test_*(): pass`（24 个、assert=0），直接 rc0 且完整 acceptance 仍 66/66 rc0（未修）。 |
| TRC-PARSER | **PASS** | 缺方案、重复 ID 行、§20/§25 外单字节漂移三类均 rc2，`catalog_integrity=FAIL`；基线 rc0。 |
| EVID | **FAIL** | 20 条路径均为文件，但裸 64hex 且与文件实算一致 11/20、exact 40hex commit 13/20、§24.2 必填全非空 6/20、严格合同仅 5/20；索引 filing head 仍 `07a94945...`，非 d32。 |

F6 汇总：**1 PASS / 3 PARTIAL / 2 FAIL**；不能认定“六项全收口”。

## P0 十项同口径

| P0 | 判定 | 摘要 |
|---|---|---|
| P0-1 核心接线 | **PASS（d32 候选）** | core wiring 8/8；完整 acceptance 基线/变异上下文可执行。 |
| P0-2 七段状态机与审批 | **FAIL** | 正向签发套件 15 PASS/0 FAIL/1 SKIP，HMAC/nonce/TTL/轮换/吊销/审计存在；但高危消费端未校验联签，单签高危授权未拒；审批 payload 与实际 action target 不等未拒；现存 0644 keyring/secret 可直接加载。对账能事后发现旁路，但未阻断消费。 |
| P0-3 契约链/Gate | **FAIL** | manifest 可重写 required 并自算摘要后假绿；重复语义冲突仍被忽略。 |
| P0-4 Schema 不变量 | **PARTIAL** | 既有对抗回归 12/12；运行镜像拒 65/66，但正式 schema 仍接受。 |
| P0-5 Runner/CAS | **PARTIAL** | 基础设施套件相关正例全绿；已知 Linux `/proc`、容器/低权限/网络资源强隔离仍未实测。 |
| P0-6 EventStore 唯一正源 | **FAIL** | 新迁移写入 `pipeline_events` 且官方 6/6；但收编后旧 `events` 无任何只读触发/权限，隔离库 INSERT/UPDATE/DELETE 全部成功，并可在第二次迁移继续注入统一链，故“冻结只读/单正源”不成立。 |
| P0-7 部署/回滚 | **PARTIAL** | release attest 8/8、签名/SBOM/重打包拦截为真；但现役 `~/.wenqu/current` 不存在，dashboard/bin 仍直接文件布局，未证明现役不可变 release 激活链。 |
| P0-8 auto-merge | **PASS / 保持关闭** | d32 stub 精确 rc1；launchctl/process 无匹配 writer。 |
| P0-9 7789 控制面 | **PASS（模块化切换）** | active server/dashboard 四文件与 d32 候选逐字节一致；只监听回环；写请求 405 `WRITE_DISABLED`，旧写路由不再可用。当前 health BLOCKED 来自源仓并行漂移，不归责 d32。 |
| P0-10 证据/追踪/制品 | **FAIL** | parser 与删件门、签名制品接线有进展；但专属测试语义可空壳假绿，证据索引严格仅 5/20。 |

P0 汇总：**3 PASS / 3 PARTIAL / 4 FAIL**。硬安全断言仍有未拒路径，最终准入必须 **BLOCKED**。

## 关键安全断言

| 断言 | 结果 |
|---|---|
| 无可信根地改写 frozen manifest 应拒绝 | **未拒，rc0** |
| 重复站语义不全等应冲突 | **未拒，rc0** |
| 裸日期应拒绝 | **已拒，rc2** |
| PASS 65/66：正式 schema 与运行镜像均拒绝 | **正式 schema 未拒；镜像 rc2** |
| 缺 plan / 重复 ID / 全文件 SHA 漂移应拒绝 | **均已拒，rc2** |
| 删除 P1f 专属文件应拒绝 | **已拒，acceptance rc1** |
| 清空专属语义但保留函数数应拒绝 | **未拒，acceptance 66/66 rc0** |
| 高危审批缺联签应拒绝 | **消费端未拒** |
| 审批 payload 与实际 target 不等应拒绝 | **未拒** |
| 收编后的旧 events 应只读 | **未拒写；增删改均成功** |
| 7789 写请求应拒绝 | **已拒，405** |

## 计分建议（仅本子域）

- F6 完整闭环仅 1/6、P0 完整通过仅 3/10，不能因正向套件绿而消除硬负例。
- 建议对受影响工作包设置上限：`W1 ≤ 8/10`（formal schema 分叉）、`W2 ≤ 11/15`（审批消费与 legacy 正源）、`W3 ≤ 9/15`（manifest 与 P1f 语义门）、`W5 ≤ 5/8`（legacy 表未冻结）、`W7 ≤ 7/8`（现役非 immutable activation）、`W8 ≤ 6/7`（模块化身份通过但生产健康受外部漂移影响）。
- 无论其他工作包加分如何，当前至少五条硬断言未拒，最终状态建议保持 **BLOCKED**。

## 主要证据

- `10-gate-independent-probe.log`
- `11-trace-parser-independent.log`
- `12-p1f-eight-suite-baseline.log`
- `13-p1f-delete-required-red.log`
- `15-p1f-noop-semantic-bypass.log`
- `14-evidence-index-strict-audit.log` + `evidence-index-strict-audit.json`
- `30-approval-independent-probe.log`
- `31-approval-upstream-suite.log`
- `40-events-unified-independent-probe.log`
- `41-events-unified-upstream-suite.log`
- `20-p09-live-runtime.log`、`21-p09-runtime-dir-hash.log`
- `50-p0-targeted-upstream-suites.log`
- `51-p08-auto-merge-containment.log`
- `52-p07-live-layout.log`
- `60-source-anchors.log`
- `90-boundary-and-final-status.log`

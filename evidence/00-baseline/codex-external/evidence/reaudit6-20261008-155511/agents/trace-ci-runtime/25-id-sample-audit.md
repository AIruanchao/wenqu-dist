# §20 专属覆盖逐 ID 抽查（21 条，跨七文件）

口径：`完整`=实际调用被测产品路径，注入与期望两端均有非恒真断言；`部分`=有真实断言但缺少方案中的关键执行腿/只验证适配器；`不匹配`=测试名字存在，但实际注入或期望不是 §20 所述语义。七文件已在 `18-seven-dedicated-runtime.log` 独立运行，合计 99/99 PASS；本表审的是“PASS 的内容是否足够”，不是重复统计退出码。

| ID | 文件:行 | §20 注入 → 期望 | 实际断言摘要 | 判定 |
|---|---|---|---|---|
| GATE-01 | `test_ac_gate_family.py:227-247` | base ref 不存在/fetch 失败 → ERROR/BLOCKED | 真 git repo，坏 remote 与缺 ref；断言 exit=2/ERROR/NOT_EVALUATED 且失败工件落盘 | **完整** |
| MRG-03 | `test_ac_gate_family.py:527-547` | 同名伪造/旧 SHA → 不合流 | `GateAggregator` 对旧 SHA/同站冲突给 BLOCKED；未调用真实 merge controller/ruleset 验证“不合流” | **部分** |
| CI-09 | `test_ac_gate_family.py:709-767` | S7 递归输入/重复发布 → schema/DAG 拒绝并发布 FAILURE | Schema 拒非法字段、聚合回灌 BLOCKED、`to_github_status()` 返回 failure 字典；没有真实 check publisher/API 发布 | **部分** |
| AUTH-04 | `test_ac_auth_cond.py:495-535` | canonical/Unicode/audience 字节改变 → 验签失败 | Unicode、environment、scope、expires_at 四类未重签篡改均 `ApprovalRejected`，原信封可消费 | **完整** |
| COND-03 | `test_ac_auth_cond.py:952-1024` | 低风险接受+双授权 → 内部 CONDITIONAL；技术 context success/AUTHORIZED_CONDITIONAL；动作一次 | 聚合仍 CONDITIONAL，risk/action HMAC 消费与外部回执/一次性动作真实；但未断言发布的技术 context 为 success 且名为 `AUTHORIZED_CONDITIONAL` | **部分** |
| STOP-02 | `test_ac_auth_cond.py:698-729` | resource/ext-unavail 未恢复但已批准 → 不可 resume | 两 stop type 对 false/string false 均拒绝且零消费，真实恢复正控放行 | **完整** |
| ACT-01 | `test_ac_act_run.py:363-408` | technical PASS 无 exact action auth → context 可 PASS、controller 不动作 | PASS run 已终态，拒绝同时受 terminal 门影响；活 run 无授权拒绝但并非 technical PASS，关键组合未被单一反例隔离 | **部分** |
| ACT-04 | `test_ac_act_run.py:564-634` | 调用前/后 crash/回执丢失 → 先查外部事实；COMMITTED/FAILED_UNKNOWN；不盲重试 | 对“调用者传入的签名回执”验签并收口两终态、nonce 不可重用；没有外部事实查询器/真实 crash 后主动查询 | **部分** |
| RUN-02 | `test_ac_act_run.py:865-888` | timeout 后子孙进程 → 全终止、无孤儿写盘 | 真进程组+setsid+double-fork daemon，等候写盘窗口，marker 与 `ps` 双断言零存活 | **完整** |
| STATE-03 | `test_ac_state_mig.py:226-309` | 100×100 并发写 → 零丢失/重复 | 100 线程×100 真实 SQLite 连接，10000 行/唯一 ID/哈希链；另 20 并发同内容幂等仅一行 | **完整** |
| MIG-04 | `test_ac_state_mig.py:879-967` | 源行数不守恒 → 迁移失败 | 删目标 3 行后再次迁移会**补齐并成功**；“失败”腿是 sidecar/DB 路径不可写。Docstring 自认公共 API 构造不出计数不守恒 | **不匹配** |
| DB-02 | `test_ac_station_families.py:638-657` | 单条 DROP COLUMN/删 FK → FAIL | 两种单变更 payload 经真实 adapter 均 FAIL、恰一 finding、exit=1 | **完整（适配器层）** |
| TEN-06 | `test_ac_station_families.py:1099-1122` | Org A 动态访问/导出 Org B → 拒绝 | 未发真实请求；把上游自报 `negative=ALLOWED/DENIED` 的合成 payload 交给 adapter，证明 adapter 判定，不证明动态访问被系统拒绝 | **部分** |
| PERF-01 | `test_ac_station_families.py:1189-1216` | HTTP 500 但很快 → FAIL | 本机真 HTTP server 快速回 500，真实 RouteDynamicScanner 断言 FAIL/finding/覆盖 1/1 | **完整** |
| STA-01 | `test_ac_station_families.py:384-458` | 任一站 denominator 缩小 → 整线 BLOCKED | builder 强制 BLOCKED、手造 shrink+PASS 被校验器拒、站2子件缩水折叠站级 BLOCKED | **完整** |
| SCH-04 | `test_ac_ops_families.py:402-476` | catch-up/正常调度并发 → 一个 logical run | 双连接并发对同 `(job,scheduled_at)`，DB 恰一 run_id、重放不再副作用；如实记录事务前物理进程可能多执行，但“logical run”契约成立 | **完整（物理副作用仍是边界）** |
| ALT-02 | `test_ac_ops_families.py:778-845` | 到期 waiting 零 attempt/receipt → ERROR+告警，不以 watchdog exit0 记健康 | 测试自身 SQL 识别零 attempt；watchdog 报的是原作业 `FUNCTION_DEAD`，随后 dispatch 无 channel 才产 ERROR。未证明独立 watchdog 会因“零 attempt”本身告警 | **部分** |
| DOC-03 | `test_ac_ops_families.py:1113-1160` | policy/Skill 出现绕闸文本 → CI 阻断 | 扫描器 `scan()` **仅定义在测试函数内**，对临时文本自测；工作流/acceptance 没有产品化 detector，也不运行此文件 | **不匹配** |
| REL-02 | `test_ac_deploy_release.py:291-365` | 部署中 kill -9 → 旧 current 或完整新 current | 真子进程、大文件窗口、多延迟 SIGKILL，current 与所有命名 release 完整性逐一验 | **完整** |
| DEP-03 | `test_ac_deploy_release.py:459-537` | 新事件后回滚兼容二进制 → 零事件丢失 | 真 symlink 回滚与 7 条事件/哈希链/DB 文件指纹；但 v1/v2 reader/writer 实为同代码，仅 `version.txt` 不同，未覆盖跨版本 schema/reader 兼容 | **部分** |
| RB-01 | `test_ac_deploy_release.py:575-656` | 无预授权自动回滚/错误旧版本 → 拒绝 | Action gate 无/错类型审批拒且零落账；坏/缺/伪 previous 三类拒、current 保持，完好 previous 正控放行 | **完整** |

## 抽查汇总

- 完整：11/21。
- 部分：8/21。
- 不匹配：2/21（`MIG-04`、`DOC-03`）。
- 因此不能把词法扫描得到的 `99/131` 等同于“99 条完整实现”。本抽样不外推全量真实完成数，但已证伪“名字存在即断言真实”的口径。
- 对抗证明：把 `DOC-03` 函数替换成仅 `assert True` 后，专属套件仍 14/14、追踪仍 99、两者 rc=0（`19-hollow-*`）；删除七专属文件后，追踪仍 rc=0、acceptance 仍 64/64 rc=0（`20-delete7-*`）。

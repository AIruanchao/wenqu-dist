# 问渠与 Bug 管线威胁模型 v1.0

> 冻结日期：2026-10-07 | 血统：Codex 方案 §5 逐字收敛
> 每个威胁必须映射到至少一个控制和至少一个测试

## 1. 保护资产

| 资产 | 损失后果 |
|---|---|
| 合流与发布正确性 | 不该合的 PR 被合；发布带已知缺陷 |
| 人类授权不可伪造/重放/扩范围 | 决策权被机器或攻击者夺取 |
| 账本/证据完整性 | 审计链断裂——无法追责和复盘 |
| 租户隔离 | 跨租户数据泄漏 |
| 资金/权限业务不变量 | 坏账/越权 |
| 健康呈现真实性 | 决策者被误导（dashboard 比 Gate 更绿） |
| source/runtime 身份一致 | 运行体被热补后正源不知情 |
| 告警端到端可达 | 故障静默——无人知晓 |

## 2. 威胁→控制→测试映射

| # | 威胁 | 控制 | 红探针 |
|---|---|---|---|
| T-01 | 恶意 PR 伪造 check 名 | exact-SHA+精确名匹配+provenance 校验 | MRG-03 |
| T-02 | 旧 SHA 绿灯 | check commit oid ≠ head SHA → stale 拒合 | MRG-05 |
| T-03 | PR 自改 workflow 放行自己 | required checks 来自 policy commit，不可 PR 修改 | CI-07 |
| T-04 | localhost CSRF/恶意网页写决策 | Host/Origin/CORS/CSRF 防护+写鉴权 | UI-03 |
| T-05 | 日志/账本 XSS 注入 | textContent 安全模板+CSP | UI-02 |
| T-06 | 同 UID 并发 agent 干扰 | writer epoch+唯一写者+租约 | STATE-05 |
| T-07 | GitHub/npm/SSH 返回空/部分数据 | 空输出=ERROR 非零+断路 | SC-02 |
| T-08 | 磁盘满/只读/kill -9/断电 | WAL+事务+恢复+一致性备份 | STATE-04 |
| T-09 | 时钟跳变/PID 复用 | UTC aware+boot ID+时钟健康检测 | DR-01 |
| T-10 | 扫描范围静默缩小 | coverage denominator 缩小→BLOCKED | STA-01 |
| T-11 | 证据伪造（自报零发现/篡改/symlink） | trusted runner+CAS 哈希+symlink 拒绝 | GATE-04~06 |
| T-12 | 授权重放/扩范围/跨 SHA | nonce+scope+SHA 绑定+一次性消费 | AUTH-02 |
| T-13 | 迁移双写/两个 writer | writer epoch fencing+CAS | STATE-05 |
| T-14 | 回滚覆盖切换后新事件 | 前向兼容回滚+事件永不删除 | DEP-03 |
| T-15 | dashboard 串行拼接得出不一致结论 | aggregator 原子快照+input watermark | HLT-01 |

## 3. 最小可信基（TCB）

```text
scanner/plugin → 只产原始输出（不可信）
trusted runner → 捕获 argv/cwd/真实 rc/timeout/stdout/stderr/hash（可信起点）
schema normalizer → 严格验证+typed result（可信传递）
gate aggregator → 校验身份/TTL/required 集合/证据哈希（可信判定）
merge/release controller → 动作前重验 technical_eligible + action_authorization（可信执行）
dashboard → 只读展示，不写 Gate、不自算放行（只读）
```

## 4. 不声称抵御的

- root/物理控制权丢失
- GitHub 组织 owner 被完全攻陷
- 硬件级攻击（侧信道、固件）

## 5. 人类授权可信边界

同 UID 的 AI/runner 可能访问普通 Keychain 项——仅记录 actor 名不足以证明真人批准。高风险 stop point 须使用具备 user-presence 的独立 approval broker（Touch ID/系统认证/外部已认证渠道回执+nonce）。在该能力落地前，保持手工受保护流程，诚实标注「无法机器证明人类身份」。

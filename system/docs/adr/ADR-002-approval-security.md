# ADR-002：审批安全架构

## 状态
已接受（2026-10-07，Codex 方案 §6.5/§21.3 冻结）

## 背景
当前审批无签名、无 nonce、无 TTL、无 scope 绑定——任何同 UID 进程可伪造。

## 决策
审批采用判别联合（discriminated union）+ HMAC 签名 + 一次性消费。

## 架构

### 签发
```
approval broker（Touch ID/系统认证/外部渠道）
  → 构造 canonical payload（按 approval_type 含专属字段）
  → HMAC-SHA256(私钥, canonical_json(payload))
  → 签发 {envelope + payload + signature}
```

### 消费
```
消费者（gate/merge/release controller）
  → 验签（钉扎公钥）
  → 校验 nonce 唯一性（一次性）
  → 校验 scope/SHA/environment/state_version/TTL
  → 同事务原子消费（防并发双消费）
```

### 密钥隔离
- 私钥：Keychain 或 0600 文件——被测程序/runner 子进程/同 UID 进程不可读
- 公钥：钉扎在 policy commit——PR 不可修改

## 风险接受
- 同 UID AI 可能访问普通 Keychain 项 → 仅记录 actor 名不足以证明真人批准
- 在 Touch ID broker 落地前：保持手工受保护流程+诚实标注边界

## 后果
- 正：审批不可伪造/重放/扩范围
- 负：增加签名基础设施复杂度；第一阶段可用 HMAC+短 TTL 过渡

"""wenqu_core v2——Codex 方案 W2：Trusted Runner + SQLite 事件正源 + CAS + 授权

架构（ADR-001/002/003 实现）：
- runner.py：不可伪造退出码的唯一来源
- store.py：SQLite WAL append-only 事件正源
- evidence.py：Content-addressed store（sha256 寻址）
- approvals.py：判别联合审批消费
- source_gate.py：W3A 源闸基础件（fetch/merge-base diff/affected 范围/
  TrustedRunner 测试执行/精确 SHA 校验，产出 source-gate-result.json）
"""

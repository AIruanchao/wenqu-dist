"""wenqu_core v2——Codex 方案 W2：Trusted Runner + SQLite 事件正源 + CAS + 授权

架构（ADR-001/002/003 实现）：
- runner.py：不可伪造退出码的唯一来源
- store.py：SQLite WAL append-only 事件正源
- wenqu_pipeline.py：P0-2 七段状态机（S1..S7）+ 九类停等 +
  approval-v2 一次性审批原子消费 + RunManager（事件正源重放推导）
- evidence.py：Content-addressed store（sha256 寻址）
- approvals.py：判别联合审批消费
- source_gate.py：W3A 源闸基础件（fetch/merge-base diff/affected 范围/
  TrustedRunner 测试执行/精确 SHA 校验，产出 source-gate-result.json）

Bug 八站适配层（W6A/W6D）：
- bugscan_orchestrator.py：W6A 八站 Planner/Registry + 站0 冻结 + 站1 源闸适配
- station4_behavior.py：W6D 站4 行为面（E2eScanner/RouteDynamicScanner/
  WebGuiScanner → station-result-v2，分母自 tests/ 动态计算）
- station7_runtime.py：W6D 站7 运行时（哨兵活性/SLO/告警链端到端 →
  station-result-v2；不计收敛轮但可阻断发布；含站5/站6 占位接口）
"""

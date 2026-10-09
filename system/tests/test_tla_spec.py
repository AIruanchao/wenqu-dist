#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""specs/tla/wenqu_pipeline.tla ↔ wenqu_core/wenqu_pipeline.py 规约漂移对照。

W1 缺口闭环（Codex 多轮指出：无 Wenqu TLA/TLC）：TLA+ 规约已建立并经 TLC
模型检查（evidence/02-schemas-and-tla/）。本测试把规约中的正典常量表与
Python 正源逐项比对——任何一侧漂移（改 STAGES/转换表/双轴映射而未同步
规约，或反之）在此必红，防止"规约证明的不再是正在运行的系统"。

比对锚点（与 .tla 内"规约-代码映射总表"一致）：
  StageOrder ↔ STAGES；RunStates/RunTrans ↔ RUN_STATES/RUN_TRANSITIONS；
  AttemptStatuses/AttemptTrans ↔ ATTEMPT_STATES/ATTEMPT_TRANSITIONS；
  TerminalRun/TerminalAttempt ↔ TERMINAL_*_STATES；
  ExecStatuses/PolicyVerdicts ↔ EXECUTION_STATUSES/POLICY_VERDICTS；
  VerdictToStatus/OutcomeStatus ↔ verdict/outcome_to_attempt_status（25 对全积）；
  ValidOutcome ↔ validate_outcome 的 PASS-需-COMPLETED 半边；
  7 不变量 + 全部动作名在规约/配置中齐备。

运行：cd system && python3 -m pytest tests/test_tla_spec.py -q
（acceptance.sh 不跑本件——它守护 dist CLI 面；本件守护规约面。）
"""
import os
import re
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core import wenqu_pipeline as wqp               # noqa: E402
from wenqu_core.wenqu_pipeline import (                    # noqa: E402
    SevenStageStateMachine,
    InvalidOutcomeError,
)

TLA_PATH = os.path.join(REPO, os.pardir, "specs", "tla", "wenqu_pipeline.tla")
CFG_A_PATH = os.path.join(REPO, os.pardir, "specs", "tla", "wenqu_pipeline_A.cfg")
CFG_B_PATH = os.path.join(REPO, os.pardir, "specs", "tla", "wenqu_pipeline_B.cfg")
MUTATION_SCRIPT = os.path.join(REPO, os.pardir, "specs", "tla", "mutation_probes.sh")


def _tla_text() -> str:
    if not os.path.isfile(TLA_PATH):
        pytest.fail(f"TLA 规约缺失：{os.path.normpath(TLA_PATH)}（W1 缺口回退）")
    with open(TLA_PATH, encoding="utf-8") as fh:
        return fh.read()


def _quoted(value: str):
    return frozenset(m.group(1) for m in re.finditer(r'"([A-Z_]+)"', value))


def _definition_block(text: str, name: str) -> str:
    """取 `name ==` / `name(args) ==` 定义体（续行缩进；
    到下一个顶格定义或文件尾为止）。"""
    m = re.search(rf"^{name}(?:\([^)]*\))?\s*==(.*?)(?=^\S|\Z)", text, re.M | re.S)
    assert m, f"规约缺定义 {name}"
    return m.group(1)


def _table_rows(block: str):
    """解析记录表行：KEY |-> { "V1", "V2" } 或 KEY |-> "V"。
    返回 dict[str, frozenset[str]] / dict[str, str]。"""
    rows: dict = {}
    for m in re.finditer(r"(\w+)\s*\|->\s*(\{[^}]*\}|\"[A-Z_]+\")", block):
        key, val = m.group(1), m.group(2)
        rows[key] = _quoted(val) if val.startswith("{") else val.strip('"')
    return rows


# ---------------------------------------------------------------- 常量表 #
def test_stage_order_matches_stages():
    block = _definition_block(_tla_text(), "StageOrder")
    stages = tuple(re.findall(r'"(S\d_[A-Z_]+)"', block))
    assert stages == tuple(wqp.STAGES), (
        f"StageOrder 漂移：TLA {stages} != 代码 {tuple(wqp.STAGES)}")


def test_run_states_and_terminal():
    text = _tla_text()
    tla_run = _quoted(_definition_block(text, "RunStates"))
    tla_term = _quoted(_definition_block(text, "TerminalRun"))
    assert tla_run == frozenset(wqp.RUN_STATES)
    assert tla_term == frozenset(wqp.TERMINAL_RUN_STATES)


def test_run_transitions_table():
    rows = _table_rows(_definition_block(_tla_text(), "RunTrans"))
    code = {k: frozenset(v) for k, v in wqp.RUN_TRANSITIONS.items()}
    assert rows == code, f"RunTrans 漂移：TLA {rows} != 代码 {code}"


def test_attempt_states_terminal_and_transitions():
    text = _tla_text()
    assert _quoted(_definition_block(text, "AttemptStatuses")) \
        == frozenset(wqp.ATTEMPT_STATES)
    assert _quoted(_definition_block(text, "TerminalAttempt")) \
        == frozenset(wqp.TERMINAL_ATTEMPT_STATES)
    rows = _table_rows(_definition_block(text, "AttemptTrans"))
    code = {k: frozenset(v) for k, v in wqp.ATTEMPT_TRANSITIONS.items()}
    assert rows == code, f"AttemptTrans 漂移：TLA {rows} != 代码 {code}"


def test_double_axis_domains():
    text = _tla_text()
    assert _quoted(_definition_block(text, "ExecStatuses")) \
        == frozenset(wqp.EXECUTION_STATUSES)
    assert _quoted(_definition_block(text, "PolicyVerdicts")) \
        == frozenset(wqp.POLICY_VERDICTS)


# ------------------------------------------------------------ 双轴映射 #
def test_verdict_map_rows():
    rows = _table_rows(_definition_block(_tla_text(), "VerdictToStatus"))
    for verdict in wqp.POLICY_VERDICTS:
        expected = SevenStageStateMachine.verdict_to_attempt_status(verdict)
        assert rows[verdict] == expected, (
            f"VerdictToStatus[{verdict!r}] 漂移：TLA {rows[verdict]!r}"
            f" != 代码 {expected!r}")


def test_outcome_mapping_full_cross_product():
    """OutcomeStatus = IF e≠COMPLETED THEN FAILED ELSE VerdictToStatus[v]
    ——按规约文本逐字断言该结构，并对其全部 25 对双轴组合与代码
    outcome_to_attempt_status 语义比对。"""
    text = _tla_text()
    assert re.search(
        r'OutcomeStatus\(e,\s*v\)\s*==\s*IF e # "COMPLETED"'
        r'\s*THEN "FAILED"\s*ELSE VerdictToStatus\[v\]', text), (
        "OutcomeStatus 结构漂移：须为 e≠COMPLETED→FAILED，否则查 VerdictToStatus")
    verdict_rows = _table_rows(_definition_block(text, "VerdictToStatus"))
    for e in sorted(wqp.EXECUTION_STATUSES):
        for v in sorted(wqp.POLICY_VERDICTS):
            tla = "FAILED" if e != "COMPLETED" else verdict_rows[v]
            code = SevenStageStateMachine.outcome_to_attempt_status(e, v)
            assert tla == code, (
                f"双轴映射漂移 ({e},{v})：TLA {tla!r} != 代码 {code!r}")


def test_valid_outcome_pass_requires_completed():
    text = _tla_text()
    block = _definition_block(text, "ValidOutcome")
    assert '~(v = "PASS" /\\ e # "COMPLETED")' in block, (
        "ValidOutcome 漂移：缺 PASS-需-COMPLETED 半边（validate_outcome :1017）")
    with pytest.raises(InvalidOutcomeError):
        SevenStageStateMachine.validate_outcome("ERROR", "PASS")
    with pytest.raises(InvalidOutcomeError):
        SevenStageStateMachine.validate_outcome("TIMEOUT", "PASS")
    SevenStageStateMachine.validate_outcome("COMPLETED", "PASS")
    SevenStageStateMachine.validate_outcome("TIMEOUT", "CONDITIONAL")  # 折叠层容忍


# --------------------------------------------------- 规约结构与检查配置 #
REQUIRED_INVARIANTS = (
    "TypeOK", "NoSkipStages", "PriorPassedGate", "AttemptImmutable",
    "NonceOnceConsumed", "TerminalFinal", "DoubleAxisNoWash",
)
REQUIRED_ACTIONS = (
    "StartStage", "CompleteStage", "RaiseWaiting", "ConsumeResume",
    "ConsumeRisk", "FinishSucceeded", "FinishConditional", "FinishFailed",
    "CancelRun", "SupersedeRun", "NoOp",
)


def test_invariants_and_actions_defined():
    text = _tla_text()
    for inv in REQUIRED_INVARIANTS:
        assert re.search(rf"^{inv}\s*==", text, re.M), f"规约缺不变量 {inv}"
    for act in REQUIRED_ACTIONS:
        assert re.search(rf"^{act}\s*(\(|==)", text, re.M), f"规约缺动作 {act}"
    for act in REQUIRED_ACTIONS[:-1]:  # NoOp 也应在 Next 中
        assert re.search(rf"\\/\s*.*\b{act}\b", text), f"动作 {act} 未接入 Next"
    assert re.search(r"^Next\s*==", text, re.M)


def test_cfg_checks_all_invariants_and_bounds():
    """G9-03 双配置口径：cfg-A 七段全序×1 attempt；cfg-B 2 段×2 attempts。
    两配置都必须全列 7 不变量、SPECIFICATION Spec、CONSTRAINT Bounded。"""
    expected = {
        CFG_A_PATH: {  # 配置 A：七段全序 × 1 attempt（完整段序+五类终态）
            "stage_ids": r"StageIds\s*=\s*\{\s*1,\s*2,\s*3,\s*4,\s*5,\s*6,\s*7\s*\}",
            "hist": r"MaxHistLen\s*=\s*2",
            "ver": r"MaxVer\s*=\s*16",
        },
        CFG_B_PATH: {  # 配置 B：2 段 × 2 attempts（retry/CAS/nonce 重放）
            "stage_ids": r"StageIds\s*=\s*\{\s*1,\s*2\s*\}",
            "hist": r"MaxHistLen\s*=\s*4",
            "ver": r"MaxVer\s*=\s*14",
        },
    }
    for path, patterns in expected.items():
        if not os.path.isfile(path):
            pytest.fail(f"TLC 配置缺失：{os.path.normpath(path)}")
        with open(path, encoding="utf-8") as fh:
            cfg = fh.read()
        for inv in REQUIRED_INVARIANTS:
            assert re.search(rf"^\s+{inv}\s*$", cfg, re.M), (
                f"{os.path.basename(path)} 未检查 {inv}")
        assert re.search(r"SPECIFICATION\s+Spec", cfg), path
        assert re.search(r"CONSTRAINT\s+Bounded", cfg), path
        for label, pat in patterns.items():
            assert re.search(pat, cfg), (
                f"{os.path.basename(path)} 规模旋钮漂移（{label}）")


def test_bounded_uses_maxver_constant():
    """ver 封顶必须走 MaxVer 常量（cfg-A=16 才放得下 7 段×1 attempt+终态；
    硬编码小值会静默截断七段覆盖——正是 G9-03 要闭环的缺口形态）。"""
    text = _tla_text()
    assert re.search(r"^\s+MaxVer,?", text, re.M), "规约缺 MaxVer 常量声明"
    block = _definition_block(text, "Bounded")
    assert "ver <= MaxVer" in block, (
        "Bounded 漂移：ver 封顶必须引用 MaxVer（cfg 按配置注入）")


REQUIRED_MUTATION_PROBES = (
    "mut-A1_skip_stage", "mut-A2_relax_terminal", "mut-A3_nonce_replay",
    "mut-A4_pass_gate", "mut-B1_nonce_replay",
)


def test_mutation_probe_script_wired():
    """可证伪性接线：变异探针脚本存在且五个变异全部在列（跳段/放宽终态/
    nonce 重放×2 配置/PASS-需-COMPLETED 门）——缺一件即 G9-03 验收面回退。"""
    if not os.path.isfile(MUTATION_SCRIPT):
        pytest.fail(f"变异探针脚本缺失：{os.path.normpath(MUTATION_SCRIPT)}")
    with open(MUTATION_SCRIPT, encoding="utf-8") as fh:
        script = fh.read()
    for probe in REQUIRED_MUTATION_PROBES:
        assert probe in script, f"变异探针脚本缺 {probe}"
    for expect in ("NoSkipStages", "TerminalFinal", "NonceOnceConsumed",
                   "AttemptImmutable"):
        assert expect in script, f"变异探针脚本缺期望不变量 {expect}"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-v"]))

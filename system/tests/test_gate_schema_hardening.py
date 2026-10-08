#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F4 三洞加固回归——Codex 第四轮实锤假绿的根修复验（gate/schema/traceability）。

洞对应（正源：第四轮验收 findings；本文件是它们的对抗复验正本）：
  F4-GATE-001  聚合器吃 Schema-invalid 输入判 PASS
        -> test_f4_gate001_schema_invalid_input_blocked
        -> test_f4_gate001_legal_v2_full_chain_pass_dashboard_accept
        -> test_f4_gate001_mirror_jsonschema_consistency   （镜像↔schema 同步自测）
  F4-SCHEMA-001  五个跨字段 Schema 假绿（schema 文件 allOf/if-then 编码 + 镜像同步）
        -> test_f4_schema001_five_cross_field_rules
        -> test_f4_schema001_station_rules_via_aggregator_mirror
  F4-TRC-001  §20 语义篡改假绿（ac_traceability 只比 ID 集合）
        -> test_f4_trc001_semantic_tamper_detected
  R7-SCHEMA  PASS 等值级联 1..64→1..256 生成式扩展（>64 分母分叉闭合）
        -> test_r7_schema_cascade_256_denominator_fork_closed

纯标准库；可直接 `python3 system/tests/test_gate_schema_hardening.py`（exit 0=全绿），
也兼容 pytest。jsonschema 不可用时 schema 断言按仓内惯例降级跳过（镜像断言仍执行）。
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
ROOT = os.path.dirname(REPO)                                        # 仓根
sys.path.insert(0, REPO)

from wenqu_core.gate_aggregator import (  # noqa: E402
    BLOCKED, GateAggregator, mirror_validate_station_result_v2,
)

SCHEMAS = os.path.join(REPO, "schemas")
SHA = "1f" + "0" * 38
PLAN = os.path.join(ROOT, "evidence", "00-baseline", "codex-external", "方案.md")
PASS_N, FAIL_N, FAILURES = 0, 0, []


def _ck(name, cond, detail=""):
    global PASS_N, FAIL_N
    if cond:
        PASS_N += 1
        print(f"  ✓ {name}")
    else:
        FAIL_N += 1
        FAILURES.append(name)
        print(f"  ✗ {name} {detail}")


# ───────────────────────── 测试样例工厂 ─────────────────────────
def _v2(**over):
    """合法 station-result-v2（coverage 等比分母+非空工件+rc0+assertion PASS）。"""
    doc = {
        "schema_version": "2.0", "run_id": "run-f4-1", "station_id": 2,
        "attempt_id": "att-2", "execution_status": "COMPLETED",
        "policy_verdict": "PASS",
        "identity": {"project_id": "acme/erp", "commit_sha": SHA,
                     "environment": "staging", "scope_hash": "0" * 64,
                     "ruleset_hash": "0" * 64},
        "tool": {"name": "f4-probe", "version": "1.0"},
        "execution": {"argv_digest": "b" * 64,
                      "started_at": "2026-10-08T00:00:00Z",
                      "ended_at": "2026-10-08T00:00:01Z",
                      "actual_exit_code": 0, "expected_exit_set": [0],
                      "assertion_verdict": "PASS"},
        "coverage": {"denominator": 3, "scanned": 3},
        "artifacts": [{"cas_digest": "sha256:" + "c" * 64, "size": 128}],
    }
    doc.update(over)
    return doc


def _jsonschema_validator(name):
    """Draft7Validator + FormatChecker（注册严格 date-time——仓内既有惯例：
    rfc3339-validator 缺席时 jsonschema 的 date-time 检查空转）。"""
    import jsonschema
    from jsonschema import FormatChecker

    fc = FormatChecker()

    @fc.checks("date-time")
    def _strict_date_time(value):
        if not isinstance(value, str):
            return True
        from datetime import datetime
        text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
        try:
            datetime.fromisoformat(text)
            return True
        except ValueError:
            return False

    schema = json.load(open(os.path.join(SCHEMAS, name), encoding="utf-8"))
    return jsonschema.Draft7Validator(schema, format_checker=fc)


def _is_invalid(validator, doc):
    """jsonschema 断言 helper：True==被拒。不可用时返回 None（调用方降级）。"""
    import jsonschema
    try:
        validator.validate(doc)
        return False
    except jsonschema.ValidationError:
        return True


# ══════════════════════════════════════════════════════════════════════
# F4-GATE-001：聚合器吃 Schema-invalid 输入判 PASS（Codex 探针复刻）
# ══════════════════════════════════════════════════════════════════════
def test_f4_gate001_schema_invalid_input_blocked():
    """Codex 探针复刻：缺 tool/execution/coverage/artifacts 的残缺 v2
    （正式 Draft-07 校验拒绝）→ 聚合器必须 BLOCKED + technical_eligible=false。"""
    rogue = {
        "schema_version": "2.0", "station_id": 2,
        "execution_status": "COMPLETED", "policy_verdict": "PASS",
        "identity": {"commit_sha": SHA, "environment": "staging",
                     "scope_hash": "0" * 64},
    }
    try:
        v = _jsonschema_validator("station-result-v2.schema.json")
        _ck("F4-GATE-001 残缺 v2 被正式 schema 拒绝（复刻前提）",
            _is_invalid(v, rogue) is True)
    except ImportError:
        print("  (skip) jsonschema 未安装，schema 断言降级")

    errs = mirror_validate_station_result_v2(rogue)
    _ck("F4-GATE-001 镜像校验器同判残缺 v2 非法",
        bool(errs) and any("tool" in e or "execution" in e for e in errs),
        str(errs[:3]))

    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(rogue)
    out = agg.aggregate()
    _ck("F4-GATE-001 残缺 v2 聚合 BLOCKED", out["aggregate_outcome"] == BLOCKED,
        out["reason"])
    _ck("F4-GATE-001 technical_eligible=false", out["technical_eligible"] is False)
    _ck("F4-GATE-001 记 malformed（schema_invalid）",
        out["counts"]["malformed"] >= 1
        and out["stations"]["2"]["schema_valid"] is False)
    _ck("F4-GATE-001 github 状态不上绿",
        agg.to_github_status(out)["state"] == "failure")


def test_f4_gate001_legal_v2_full_chain_pass_dashboard_accept():
    """合法 v2（coverage 分母≥1 且等比 + 非空 artifacts + exit0 + assertion PASS）
    → 全链聚合 PASS + dashboard read_gate_aggregate ACCEPT。"""
    agg = GateAggregator({"2", "7"}, SHA, "staging")
    agg.add(_v2(station_id=2)).add(_v2(station_id=7, run_id="run-f4-7"))
    out = agg.aggregate()
    _ck("F4-GATE-001 合法 v2 双站聚合 PASS", out["aggregate_outcome"] == "PASS",
        out["reason"])
    _ck("F4-GATE-001 technical_eligible=true", out["technical_eligible"] is True)
    _ck("F4-GATE-001 站点登记 schema_valid=true",
        out["stations"]["2"]["schema_valid"] is True)

    spec = importlib.util.spec_from_file_location(
        "dash_server_f4", os.path.join(REPO, "dashboard", "server.py"))
    dash = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dash)
    with tempfile.TemporaryDirectory() as td:
        snap = os.path.join(td, "gate-aggregate.json")
        with open(snap, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False)
        os.environ["WENQU_GATE_AGGREGATE"] = snap
        r = dash.read_gate_aggregate()
        _ck("F4-GATE-001 dashboard 对合法聚合 ACCEPT（ok + PASS）",
            r.get("ok") is True and r["data"]["policy_verdict"] == "PASS", str(r))

        # 反向：BLOCKED 聚合喂 dashboard——结构 ACCEPT 但判定透传 BLOCKED（不洗白）
        agg2 = GateAggregator({"2"}, SHA, "staging")
        agg2.add({**_v2(), "coverage": {"denominator": 3, "scanned": 2}})
        blocked = agg2.aggregate()
        with open(snap, "w", encoding="utf-8") as fh:
            json.dump(blocked, fh, ensure_ascii=False)
        r2 = dash.read_gate_aggregate()
        _ck("F4-GATE-001 分母缩水聚合 → dashboard 透传 BLOCKED",
            r2.get("ok") is True and r2["data"]["policy_verdict"] == BLOCKED,
            str(r2))


def test_f4_gate001_mirror_jsonschema_consistency():
    """镜像校验器 ↔ schema 文件一致性自测（防两处漂移）。

    对正负样例组，mirror_validate_station_result_v2 与
    jsonschema+FormatChecker（严格 date-time）的合法/非法结论必须一致。
    已声明的唯一边界：PASS 的 scanned==denominator 在 schema 侧以 const 级联
    机器判定 1..256（draft-07 无法表达跨字段数值比较；R7-SCHEMA 分母分叉根修
    生成式扩展自 1..64），>256 时 schema 不判、镜像必拒——边界样例单独断言，
    不进一致性对照。
    """
    legal = _v2()
    samples = [  # (名字, 文档, 期望合法?)
        ("legal-full", legal, True),
        ("legal-minimal-fail-verdict",
         {k: v for k, v in legal.items()
          if k not in ("coverage", "artifacts", "finding_ids")}
         | {"policy_verdict": "FAIL"}, True),
        ("legal-conditional", legal | {"policy_verdict": "CONDITIONAL"}, True),
        ("legal-coverage-exclusions",
         legal | {"coverage": {"denominator": 4, "scanned": 4,
                               "exclusions": ["x"]}}, True),
        ("legal-error-not-evaluated",
         legal | {"execution_status": "ERROR", "policy_verdict": "NOT_EVALUATED"},
         True),
        ("legal-timeout-not-evaluated",
         legal | {"execution_status": "TIMEOUT",
                  "policy_verdict": "NOT_EVALUATED"}, True),
        ("bad-schema-version", legal | {"schema_version": "1.0"}, False),
        ("bad-run-id", legal | {"run_id": "run f4!"}, False),
        ("bad-station-id-str", legal | {"station_id": "2"}, False),
        ("bad-station-id-range", legal | {"station_id": 8}, False),
        ("bad-station-id-bool", legal | {"station_id": True}, False),
        ("bad-top-extra", legal | {"rogue_field": 1}, False),
        ("bad-missing-attempt-id",
         {k: v for k, v in legal.items() if k != "attempt_id"}, False),
        ("bad-exec-status-enum", legal | {"execution_status": "RUNNING"}, False),
        ("bad-verdict-enum", legal | {"policy_verdict": "SUCCESS"}, False),
        ("bad-identity-sha", legal | {"identity": dict(legal["identity"],
                                                       commit_sha="short")}, False),
        ("bad-identity-missing-scope",
         legal | {"identity": {"commit_sha": SHA, "environment": "staging"}}, False),
        ("bad-tool-missing-version",
         legal | {"tool": {"name": "t"}}, False),
        ("bad-exec-missing-exit",
         legal | {"execution": {k: v for k, v in legal["execution"].items()
                                if k != "actual_exit_code"}}, False),
        ("bad-exec-assertion-enum",
         legal | {"execution": dict(legal["execution"],
                                    assertion_verdict="MAYBE")}, False),
        ("bad-exec-exit-bool",
         legal | {"execution": dict(legal["execution"],
                                    actual_exit_code=False)}, False),
        ("bad-exec-expected-set-str",
         legal | {"execution": dict(legal["execution"],
                                    expected_exit_set=["0"])}, False),
        ("bad-date-time", legal | {"execution": dict(
            legal["execution"], started_at="not-a-date")}, False),
        ("bad-timeout-zero", legal | {"execution": dict(
            legal["execution"], timeout_s=0)}, False),
        ("bad-coverage-negative",
         legal | {"coverage": {"denominator": -1, "scanned": 0}}, False),
        ("bad-coverage-missing-scanned",
         legal | {"coverage": {"denominator": 3}}, False),
        ("bad-coverage-explicit-null", legal | {"coverage": None}, False),
        ("bad-artifacts-explicit-null", legal | {"artifacts": None}, False),
        ("bad-artifact-digest",
         legal | {"artifacts": [{"cas_digest": "md5:x", "size": 1}]}, False),
        ("bad-artifact-size-zero",
         legal | {"artifacts": [{"cas_digest": "sha256:" + "c" * 64,
                                 "size": 0}]}, False),
        ("bad-finding-ids-str",
         legal | {"finding_ids": "fnd_1"}, False),
        # PASS 分支（含 F4-SCHEMA-001 #2/#5 新跨字段）
        ("bad-pass-no-coverage", {k: v for k, v in legal.items()
                                  if k != "coverage"}, False),
        ("bad-pass-no-artifacts", {k: v for k, v in legal.items()
                                   if k != "artifacts"}, False),
        ("bad-pass-empty-artifacts", legal | {"artifacts": []}, False),
        ("bad-pass-exit-1",
         legal | {"execution": dict(legal["execution"],
                                    actual_exit_code=1)}, False),
        ("bad-pass-assertion-fail",
         legal | {"execution": dict(legal["execution"],
                                    assertion_verdict="FAIL")}, False),
        ("bad-pass-shrinkage-2of3",
         legal | {"coverage": {"denominator": 3, "scanned": 2}}, False),
        ("bad-pass-scanned-over-denominator",
         legal | {"coverage": {"denominator": 2, "scanned": 3}}, False),
        ("bad-pass-timeout-status",
         legal | {"execution_status": "TIMEOUT"}, False),
        ("bad-timeout-conditional",
         legal | {"execution_status": "TIMEOUT",
                  "policy_verdict": "CONDITIONAL"}, False),
        ("bad-blocked-conditional",
         legal | {"execution_status": "BLOCKED",
                  "policy_verdict": "CONDITIONAL"}, False),
    ]
    try:
        v = _jsonschema_validator("station-result-v2.schema.json")
    except ImportError:
        print("  (skip) jsonschema 未安装，一致性自测降级为镜像单侧断言")
        v = None

    mismatch = []
    for name, doc, expect_valid in samples:
        mirror_valid = not mirror_validate_station_result_v2(doc)
        if mirror_valid != expect_valid:
            mismatch.append(f"{name}: mirror={'ok' if mirror_valid else 'reject'}"
                            f" expect={'ok' if expect_valid else 'reject'}")
        if v is not None:
            js_invalid = _is_invalid(v, doc)
            js_valid = not js_invalid
            if js_valid != expect_valid:
                mismatch.append(f"{name}: jsonschema="
                                f"{'ok' if js_valid else 'reject'}"
                                f" expect={'ok' if expect_valid else 'reject'}")
            if js_valid != mirror_valid:
                mismatch.append(f"{name}: mirror={'ok' if mirror_valid else 'reject'}"
                                f" != jsonschema={'ok' if js_valid else 'reject'}")
    _ck(f"F4-GATE-001 镜像↔schema 一致性（{len(samples)} 样例零分歧）",
        not mismatch, "; ".join(mismatch[:4]))

    # R7-SCHEMA 分母分叉根修：级联已生成式扩展到 1..256——65/66 与 255/256
    # 缩水在级联内必须双侧拒（此前 schema 侧不判=与运行镜像分叉，第七轮实证）
    for sc, dn in ((65, 66), (255, 256), (100, 65)):
        doc = legal | {"coverage": {"denominator": dn, "scanned": sc}}
        _ck(f"F4-GATE-001 级联内 >64 缩水镜像拒 PASS {sc}/{dn}",
            bool(mirror_validate_station_result_v2(doc)))
        if v is not None:
            _ck(f"F4-GATE-001 级联内 >64 缩水正式 schema 拒 PASS {sc}/{dn}（R7 分叉闭合）",
                _is_invalid(v, doc) is True)
        eq = legal | {"coverage": {"denominator": sc, "scanned": sc}}
        _ck(f"F4-GATE-001 级联内 >64 等值镜像收 PASS {sc}/{sc}",
            not mirror_validate_station_result_v2(eq))
        if v is not None:
            _ck(f"F4-GATE-001 级联内 >64 等值正式 schema 收 PASS {sc}/{sc}（不误拒全扫）",
                _is_invalid(v, eq) is False)

    # 已声明边界：分母>256 的缩水在 schema 级联之外——镜像必拒（无界等式兜底）
    big_shrink = legal | {"coverage": {"denominator": 301, "scanned": 300}}
    _ck("F4-GATE-001 边界：>256 缩水镜像仍必拒（schema 级联外）",
        bool(mirror_validate_station_result_v2(big_shrink)))
    if v is not None:
        _ck("F4-GATE-001 边界记录：>256 缩水 schema 侧不判（不误拒合法大分母）",
            _is_invalid(v, big_shrink) is False)


# ══════════════════════════════════════════════════════════════════════
# F4-SCHEMA-001：五个跨字段规则（jsonschema+FormatChecker 全拒 + 镜像同步）
# ══════════════════════════════════════════════════════════════════════
def test_f4_schema001_five_cross_field_rules():
    """五洞样例经 jsonschema+FormatChecker 全拒、正例全过；测试侧镜像谓词同步。

    #1 evidence-v2：PASS + actual_exit_code 非 0 → 拒
    #2 station-result-v2：PASS 但 scanned < denominator（分母缩水）→ 拒
    #3 finding-event-v2：CLOSED→OPEN 非法转换（非 FINDING_REOPENED 载体）→ 拒
    #4 finding-event-v2：RISK_INVALIDATED 缺 state_from → 拒
    #5 run-event-v2 + station：TIMEOUT 执行 + CONDITIONAL 裁决 → 拒
    """
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        print("  (skip) jsonschema 未安装，五规则 schema 断言降级跳过")
        return

    ev_v = _jsonschema_validator("evidence-v2.schema.json")
    fe_v = _jsonschema_validator("finding-event-v2.schema.json")
    run_v = _jsonschema_validator("run-event-v2.schema.json")
    st_v = _jsonschema_validator("station-result-v2.schema.json")

    def evidence(**over):
        doc = {
            "schema_version": "2.0", "evidence_id": "ev_f4", "run_id": "run-f4",
            "identity": {"commit_sha": SHA, "environment": "staging",
                         "scope_hash": "0" * 64},
            "runner": {"runner_id": "r1", "version": "1"},
            "tool": {"name": "t", "version": "1"},
            "execution": {"argv_digest": "a" * 64,
                          "started_at": "2026-10-08T00:00:00Z",
                          "finished_at": "2026-10-08T00:00:01Z",
                          "actual_exit_code": 0},
            "verdict": "PASS", "fresh_until": "2026-10-09T00:00:00Z",
            "artifact": {"artifact_sha256": "d" * 64, "artifact_size": 10},
        }
        doc.update(over)
        return doc

    def finding(**over):
        doc = {
            "schema_version": "2.0", "event_type": "FINDING_REOPENED",
            "finding_id": "fnd_f4", "fingerprint": "fp", "severity": "LOW",
            "priority": "P3", "ts": "2026-10-08T00:00:00Z",
            "state_from": "CLOSED", "state_to": "OPEN",
        }
        doc.update(over)
        return doc

    def run_event(**over):
        doc = {
            "schema_version": "2.0", "event_type": "STAGE_COMPLETED",
            "run_id": "run-f4", "execution_status": "COMPLETED",
            "policy_verdict": "PASS",
            "identity": {"commit_sha": SHA, "environment": "staging",
                         "scope_hash": "0" * 64},
        }
        doc.update(over)
        return doc

    # 镜像谓词（与 schema 同步的测试侧可执行等价物）
    def mirror_evidence_pass_requires_rc0(d):
        rc = d.get("execution", {}).get("actual_exit_code")
        return not (d.get("verdict") == "PASS" and rc is not None and rc != 0)

    def mirror_finding_closed_successors(d):
        if d.get("state_from") == "CLOSED":
            return (d.get("event_type") == "FINDING_REOPENED"
                    and d.get("state_to") == "OPEN")
        if d.get("event_type") == "RISK_INVALIDATED":
            return (d.get("state_from") == "ACCEPTED_RISK"
                    and d.get("state_to") == "OPEN")
        if d.get("event_type") == "SUPERSEDED":
            return d.get("state_from") in (
                "OPEN", "FIXING", "FIXED_PENDING_VERIFY", "VERIFIED",
                "ACCEPTED_RISK")
        return True

    def mirror_hard_exec_verdicts(d):
        if d.get("execution_status") in ("ERROR", "BLOCKED", "TIMEOUT",
                                         "CANCELLED"):
            return d.get("policy_verdict") in ("FAIL", "NOT_EVALUATED",
                                               "NOT_APPLICABLE")
        return True

    cases = [
        # (名, validator, doc, 期望合法, 镜像谓词)
        ("#1 evidence PASS+rc2 拒", ev_v,
         evidence(execution=dict(evidence()["execution"], actual_exit_code=2)),
         False, mirror_evidence_pass_requires_rc0),
        ("#1 evidence PASS+rc0 过", ev_v, evidence(), True,
         mirror_evidence_pass_requires_rc0),
        ("#1 evidence FAIL+rc2 过", ev_v,
         evidence(verdict="FAIL",
                  execution=dict(evidence()["execution"], actual_exit_code=2)),
         True, mirror_evidence_pass_requires_rc0),
        ("#2 station PASS 缩水 2/3 拒", st_v,
         _v2(coverage={"denominator": 3, "scanned": 2}), False,
         lambda d: d.get("policy_verdict") != "PASS"
         or d.get("coverage", {}).get("scanned", -1)
         == d.get("coverage", {}).get("denominator", -2)),
        ("#2 station PASS 3/3 过", st_v, _v2(), True,
         lambda d: d.get("policy_verdict") != "PASS"
         or d.get("coverage", {}).get("scanned", -1)
         == d.get("coverage", {}).get("denominator", -2)),
        ("#3 finding CLOSED→OPEN 走 FINDING_CREATED 拒", fe_v,
         finding(event_type="FINDING_CREATED"), False,
         mirror_finding_closed_successors),
        ("#3 finding CLOSED→OPEN 走 SUPERSEDED 拒", fe_v,
         finding(event_type="SUPERSEDED"), False,
         mirror_finding_closed_successors),
        ("#3 finding 合法 FINDING_REOPENED CLOSED→OPEN 过", fe_v,
         finding(), True, mirror_finding_closed_successors),
        ("#4 finding RISK_INVALIDATED 缺 state_from 拒", fe_v,
         {k: v for k, v in finding(event_type="RISK_INVALIDATED").items()
          if k not in ("state_from", "state_to")}, False,
         mirror_finding_closed_successors),
        ("#4 finding RISK_INVALIDATED ACCEPTED_RISK→OPEN 过", fe_v,
         finding(event_type="RISK_INVALIDATED", state_from="ACCEPTED_RISK"),
         True, mirror_finding_closed_successors),
        ("#4 finding SUPERSEDED 缺 state_from 拒", fe_v,
         {k: v for k, v in finding(event_type="SUPERSEDED").items()
          if k != "state_from"}, False, mirror_finding_closed_successors),
        ("#5 run TIMEOUT+CONDITIONAL 拒", run_v,
         run_event(execution_status="TIMEOUT", policy_verdict="CONDITIONAL"),
         False, mirror_hard_exec_verdicts),
        ("#5 run COMPLETED+CONDITIONAL 过", run_v,
         run_event(policy_verdict="CONDITIONAL"), True,
         mirror_hard_exec_verdicts),
        ("#5 station TIMEOUT+CONDITIONAL 拒", st_v,
         _v2(execution_status="TIMEOUT", policy_verdict="CONDITIONAL"),
         False, mirror_hard_exec_verdicts),
    ]
    bad = []
    for name, validator, doc, expect_valid, mirror_pred in cases:
        js_valid = not _is_invalid(validator, doc)
        if js_valid != expect_valid:
            bad.append(f"{name}: jsonschema={'ok' if js_valid else 'reject'}"
                       f" expect={'ok' if expect_valid else 'reject'}")
        if mirror_pred(doc) != expect_valid:
            bad.append(f"{name}: mirror={'ok' if mirror_pred(doc) else 'reject'}"
                       f" expect={'ok' if expect_valid else 'reject'}")
    _ck(f"F4-SCHEMA-001 五规则 {len(cases)} 样例（schema+镜像谓词零分歧）",
        not bad, "; ".join(bad[:4]))


def test_f4_schema001_station_rules_via_aggregator_mirror():
    """站级 #2/#5 经聚合器镜像同步：schema-invalid 站必 BLOCKED（不产出 PASS）。"""
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(_v2(coverage={"denominator": 3, "scanned": 2}))   # 分母缩水
    out = agg.aggregate()
    _ck("F4-SCHEMA-001 #2 缩水 v2 聚合 BLOCKED",
        out["aggregate_outcome"] == BLOCKED
        and out["technical_eligible"] is False, out["reason"])

    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(_v2(execution_status="TIMEOUT", policy_verdict="CONDITIONAL"))
    out = agg.aggregate()
    _ck("F4-SCHEMA-001 #5 station TIMEOUT+CONDITIONAL 聚合 BLOCKED",
        out["aggregate_outcome"] == BLOCKED, out["reason"])


# ══════════════════════════════════════════════════════════════════════
# R7-SCHEMA（第七轮 P1）：PASS 等值级联 1..64 → 1..256 生成式扩展——
# >64 分母分叉闭合（正式 Draft-07 schema 此前对 65/66 缩水不判）；>256 由
# 镜像无界等式兜底（schema $comment 已声明边界）。
# ══════════════════════════════════════════════════════════════════════
def test_r7_schema_cascade_256_denominator_fork_closed():
    """R7 对抗复验：PASS 65/66 正式 schema 必拒；级联结构 1..256 生成式连续；
    >256 声明边界（schema 不判、镜像无界兜底、聚合纵深 BLOCKED）。"""
    schema = json.load(open(os.path.join(SCHEMAS, "station-result-v2.schema.json"),
                            encoding="utf-8"))
    cascade = schema["allOf"][1]["then"]["properties"]["coverage"]["allOf"]
    consts = [e["if"]["properties"]["scanned"]["const"] for e in cascade]
    _ck("R7-SCHEMA schema const 级联 1..256（生成式连续，逐条 then 等值锁定）",
        consts == list(range(1, 257))
        and all(e["then"]["properties"]["denominator"]["const"] == n
                for e, n in zip(cascade, range(1, 257))),
        f"n={len(consts)} head={consts[:2]} tail={consts[-2:]}")
    _ck("R7-SCHEMA $comment 声明 1..256 级联 + >256 镜像无界兜底",
        "1..256" in schema["$comment"] and ">256" in schema["$comment"]
        and "无界等式" in schema["$comment"])

    def _pass_doc(scanned, denominator):
        return _v2(coverage={"denominator": denominator, "scanned": scanned})

    try:
        v = _jsonschema_validator("station-result-v2.schema.json")
    except ImportError:
        print("  (skip) jsonschema 未安装，schema 断言降级（镜像断言仍执行）")
        v = None

    # 对抗复验正主：PASS 65/66（第六/七轮原样反例）正式 schema 必拒
    _ck("R7-SCHEMA 镜像拒 PASS 65/66（无界等式）",
        bool(mirror_validate_station_result_v2(_pass_doc(65, 66))))
    if v is not None:
        _ck("R7-SCHEMA 正式 schema 拒 PASS 65/66（>64 分叉闭合）",
            _is_invalid(v, _pass_doc(65, 66)) is True)

    # 级联上沿与出沿：256/256 双收；>256 等值双收（schema 不判但不误拒全扫）
    for sc, dn, expect_schema_reject in ((256, 255, True), (255, 256, True),
                                         (256, 256, False), (257, 257, False),
                                         (300, 300, False)):
        doc = _pass_doc(sc, dn)
        _ck(f"R7-SCHEMA 镜像 {'拒' if sc != dn else '收'} PASS {sc}/{dn}",
            bool(mirror_validate_station_result_v2(doc)) == (sc != dn))
        if v is not None:
            _ck(f"R7-SCHEMA schema {'拒' if expect_schema_reject else '收'} PASS {sc}/{dn}",
                _is_invalid(v, doc) is expect_schema_reject)

    # >256 缩水：schema 声明边界不判 + 镜像无界兜底必拒 + 聚合纵深 BLOCKED
    big = _pass_doc(300, 299)
    _ck("R7-SCHEMA >256 缩水镜像必拒（无界兜底）",
        bool(mirror_validate_station_result_v2(big)))
    if v is not None:
        _ck("R7-SCHEMA >256 缩水 schema 不判（声明边界，镜像兜底）",
            _is_invalid(v, big) is False)
    agg = GateAggregator({"2"}, SHA, "staging")
    agg.add(_pass_doc(65, 66))
    out = agg.aggregate()
    _ck("R7-SCHEMA 65/66 PASS 聚合 BLOCKED（schema_invalid 记 malformed）",
        out["aggregate_outcome"] == BLOCKED and out["technical_eligible"] is False
        and out["stations"]["2"]["schema_valid"] is False, out["reason"])


# ══════════════════════════════════════════════════════════════════════
# F4-TRC-001：§20 语义篡改假绿（ac_traceability 逐 ID 语义比对）
# ══════════════════════════════════════════════════════════════════════
def _run_trace_check(plan_path, json_path):
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "ac_traceability.py"),
         "--check", "--plan", plan_path, "--json", json_path],
        capture_output=True, text=True, timeout=300)
    return proc.returncode


def test_f4_trc001_semantic_tamper_detected():
    """正常 rc=0；改任一 ID 注入文本 → rc=2；改期望文本 → rc=2（ID 集合不动）。"""
    if not os.path.isfile(PLAN):
        print(f"  (skip) 方案快照不存在: {PLAN}")
        return
    with open(PLAN, encoding="utf-8") as fh:
        plan_text = fh.read()

    with tempfile.TemporaryDirectory() as td:
        plan_ok = os.path.join(td, "plan.md")
        with open(plan_ok, "w", encoding="utf-8") as fh:
            fh.write(plan_text)
        rc_ok = _run_trace_check(plan_ok, os.path.join(td, "m.json"))
        _ck("F4-TRC-001 基线方案 --check rc=0（冻结内容==方案原文）", rc_ok == 0,
            f"rc={rc_ok}")

        # 篡改注入：保留 GATE-04 ID，换注入文本（Codex 探针同款手法）
        marker_inj = "| GATE-04 | 内层 exit 7、自报零 finding | assertion FAIL/BLOCKED |"
        assert marker_inj in plan_text, "GATE-04 行锚点漂移，需同步测试"
        tampered_inj = plan_text.replace(
            marker_inj,
            "| GATE-04 | 内层 exit 0、一切正常 | assertion FAIL/BLOCKED |")
        p2 = os.path.join(td, "tamper_inj.md")
        with open(p2, "w", encoding="utf-8") as fh:
            fh.write(tampered_inj)
        rc2 = _run_trace_check(p2, os.path.join(td, "m2.json"))
        _ck("F4-TRC-001 篡改注入文本 → rc=2（语义漂移必红）", rc2 == 2,
            f"rc={rc2}")

        # 篡改期望：保留 COND-04 ID，换期望文本
        marker_exp = ("| COND-04 | P0/P1 尝试风险接受或条件授权 "
                      "| 拒绝并保持 BLOCKED |")
        assert marker_exp in plan_text, "COND-04 行锚点漂移，需同步测试"
        tampered_exp = plan_text.replace(
            marker_exp,
            "| COND-04 | P0/P1 尝试风险接受或条件授权 | 放行并记 PASS |")
        p3 = os.path.join(td, "tamper_exp.md")
        with open(p3, "w", encoding="utf-8") as fh:
            fh.write(tampered_exp)
        rc3 = _run_trace_check(p3, os.path.join(td, "m3.json"))
        _ck("F4-TRC-001 篡改期望文本 → rc=2（语义漂移必红）", rc3 == 2,
            f"rc={rc3}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    print(f"== F4 三洞加固回归（gate/schema/traceability，{len(tests)} 组）==")
    for t in tests:
        print(f"-- {t.__name__}")
        t()
    print("=" * 64)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        for name in FAILURES:
            print(f"  FAILED: {name}")
        sys.exit(1)
    print("ALL GREEN")

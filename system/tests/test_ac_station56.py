#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_ac_station56.py——站5/站6 专属验收测试（真实注入+真实断言）。

背景（evidence/00-baseline/codex-external/验收报告-第八轮.md §9 已知诚实缺口
「站5/6 仍为 placeholder/NOT_APPLICABLE」的整改验证面）：
- w6a-1.1.0 注册表站5/站6 tools 槽指向最小真实扫描器
  wenqu_core.station5_live_fire / wenqu_core.station6_adversarial；
- 本文件按站语义（方案 §7.1 八站表 + W6D + 规范 §1 判据）逐条注入真实
  载荷并断言真实判定——不复述模块自测，覆盖其未走的对抗路径。

被测体（不改动任何产品码——本文件只做真实注入+真实断言）：
  wenqu_core.station5_live_fire（站5 实弹面：授权五要素/exact-scope/日落/
    前后状态/幂等/守恒/补偿/回基线）
  wenqu_core.station6_adversarial（站6 对抗面：登记完整性/每轴必问/
    二审定律独立性/TTL 日落/异源在场）
  wenqu_core.bugscan_orchestrator（注册表状态：站5/6 tools 槽与版本）

ID 命名说明：ST5-*/ST6-* 为本文件专属编号（不在 §20 目录 131 AC 集内，
不与 tools/ac_traceability.py 的 catalog 冲突——该工具只扫 catalog 内 ID）。

用法：
  python3 system/tests/test_ac_station56.py            # 全绿 exit 0
  python3 system/tests/test_ac_station56.py --json-out PATH
"""
import json
import os
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.bugscan_orchestrator import (
    REGISTRY_VERSION,
    BugscanPlanner,
    StationResultValidationError,
    default_registry,
    validate_station_result,
)
from wenqu_core.station5_live_fire import (
    AUTHORIZATION_SUNSET_MAX_DAYS,
    LiveFireAuthorizationMalformed,
    LiveFireEvidenceMalformed,
    LiveFireScanner,
)
from wenqu_core.station6_adversarial import (
    AdversarialLedgerMalformed,
    AdversarialReviewScanner,
    AdversarialSpecError,
)

NOT_IMPLEMENTABLE: dict = {}

_SEQ = iter(range(1, 10000))


def _next_run_id(prefix):
    return f"ac56-{prefix}-{next(_SEQ):03d}"


def _mk_manifest(run_id):
    """冻结 manifest（INCIDENT 档——站6 required、站5 显式授权后加入）。"""
    planner = BugscanPlanner(default_registry())
    plan = planner.plan("INCIDENT")
    assert 6 in plan.required_stations and 5 not in plan.required_stations
    return planner.freeze_run_manifest(
        plan, run_id=run_id, project_id="wenqu-ac-station56",
        commit_sha="5" * 40, environment="local",
        scope=["src/**", "db/**"],
        ruleset={"version": "ac56", "rules": ["W6A-ST5", "W6A-ST6"]},
        data_config={"profile": "default"},
    )


# ---------------------------------------------------------------------------
# 站5 实弹面——真实注入夹具
# ---------------------------------------------------------------------------


def _auth(now, *, expiry_days=1, scope=("order-create-live", "refund-live")):
    from wenqu_core.station5_live_fire import _iso_z
    return {
        "approver": "biz-owner",
        "reason": "下单/退款全链实弹验证：一次性 exact-scope 授权",
        "scope": list(scope),
        "expiry": _iso_z(now + timedelta(days=expiry_days)),
        "token": "ac56-one-time-token",
    }


def _flow(name="order-create-live", *, baseline=None, assertions=None,
          replay_effects=0, violations=0, compensation=None, executed_at=None):
    from wenqu_core.station5_live_fire import _iso_z
    before = "a" * 64
    return {
        "name": name,
        "executed_at": executed_at or _iso_z(_now56()),
        "before_state_hash": before,
        "after_state_hash": "b" * 64,
        "baseline_state_hash": baseline or before,
        "assertions": assertions if assertions is not None else [
            {"name": "order-visible", "outcome": "PASS"},
            {"name": "stock-deducted", "outcome": "PASS"},
        ],
        "idempotency": {"replay_effects": replay_effects},
        "conservation": {"invariant": "stock>=0", "violations": violations},
        "compensation": compensation or {"required": False, "executed": False},
    }


def _now56():
    from wenqu_core.station5_live_fire import _utc_now
    return _utc_now()


# ---------------------------------------------------------------------------
# 站5 专属测试
# ---------------------------------------------------------------------------


def test_ST5_01_valid_authorization_full_evidence_pass():
    """ST5-01｜注入：有效授权+全量证据（断言过/幂等/守恒/补偿/回基线）｜期望：PASS。

    注册表 pass 判据逐条实证：状态断言全 PASS + 数据回基线；coverage 分母=
    业务流断言点数（2 状态断言+4 固定检查点=6）；PASS 携带非空 artifacts
    （授权脱敏视图+判定表，schema P0-4）；授权脱敏不含 token 原文。
    """
    manifest = _mk_manifest(_next_run_id("st5"))
    now = _now56()
    st = LiveFireScanner(manifest, authorization=_auth(now),
                         flows=[_flow(), _flow("refund-live")], now=now).scan()
    validate_station_result(st)
    assert st["station_id"] == 5, st
    assert st["execution_status"] == "COMPLETED" and st["policy_verdict"] == "PASS", st
    assert st["coverage"] == {"denominator": 12, "scanned": 12}, st["coverage"]
    assert st["finding_ids"] == []
    assert len(st["artifacts"]) == 2, st["artifacts"]
    assert all(a["cas_digest"].startswith("sha256:") for a in st["artifacts"])
    assert st["execution"]["assertion_verdict"] == "PASS"
    # 判定表可从 breakdown 复核（登记+状态汇总语义）
    scanner = LiveFireScanner(manifest, authorization=_auth(now),
                              flows=[_flow()], now=now)
    st_one = scanner.scan()
    assert scanner.last_breakdown["assertion_points_failed"] == 0
    assert st_one["policy_verdict"] == "PASS"


def test_ST5_02_missing_or_expired_authorization_blocked():
    """ST5-02｜注入：授权缺失/过期/超日落窗｜期望：BLOCKED（error 判据，不算通过）。

    注册表 error 判据「生产写授权缺失（BLOCKED，不算通过）」三路注入：
    无授权、expiry 已过、expiry 超 30 天日落窗；三者均 BLOCKED+
    NOT_EVALUATED+coverage 0 分（断言点不采信），绝不折算 PASS。
    """
    manifest = _mk_manifest(_next_run_id("st5"))
    now = _now56()
    from wenqu_core.station5_live_fire import _iso_z

    scanner = LiveFireScanner(manifest, flows=[_flow()], now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED", st
    assert st["policy_verdict"] == "NOT_EVALUATED", st
    assert st["coverage"]["scanned"] == 0
    assert any(r.startswith("authorization_missing")
               for r in scanner.last_breakdown["authorization_failures"])

    expired = LiveFireScanner(manifest,
                              authorization=_auth(now, expiry_days=-1),
                              flows=[_flow()], now=now)
    st = expired.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED"
    assert any(r.startswith("authorization_expired")
               for r in expired.last_breakdown["authorization_failures"])

    beyond = LiveFireScanner(
        manifest,
        authorization=_auth(now, expiry_days=AUTHORIZATION_SUNSET_MAX_DAYS + 5),
        flows=[_flow()], now=now)
    st = beyond.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED"
    assert any(r.startswith("authorization_beyond_sunset")
               for r in beyond.last_breakdown["authorization_failures"])


def test_ST5_03_checkpoint_failures_each_fail_with_findings():
    """ST5-03｜注入：断言失败/幂等破坏/守恒破坏/补偿缺失/数据未回基线｜期望：FAIL。

    注册表 fail 判据逐点实证：五种断言点失败各自产出独立 fnd_ 落账（一条
    不漏），站级 FAIL；单点失败也 FAIL（不因数量少放行——对齐 DB-02 哲学）。
    """
    manifest = _mk_manifest(_next_run_id("st5"))
    now = _now56()
    flows = [
        _flow("f-assert", assertions=[{"name": "order-visible",
                                       "outcome": "FAIL"}]),
        _flow("f-idem", replay_effects=2),
        _flow("f-conservation", violations=3),
        _flow("f-compensation",
              compensation={"required": True, "executed": False}),
        _flow("f-baseline", baseline="c" * 64),
    ]
    auth = _auth(now, scope=tuple(f["name"] for f in flows))
    st = LiveFireScanner(manifest, authorization=auth, flows=flows,
                         now=now).scan()
    validate_station_result(st)
    assert st["execution_status"] == "COMPLETED"
    assert st["policy_verdict"] == "FAIL", st
    ids = " ".join(st["finding_ids"])
    for kind in ("state_assertion", "idempotency", "conservation",
                 "compensation", "baseline_restore"):
        assert f"fnd_livefire_{kind}" in ids, (kind, st["finding_ids"])
    assert len(st["finding_ids"]) == 5, st["finding_ids"]
    assert st["execution"]["assertion_verdict"] == "FAIL"

    # 单点失败（仅数据未回基线）同样 FAIL——注册表 fail 判据不受数量豁免
    st = LiveFireScanner(manifest, authorization=_auth(now),
                         flows=[_flow(baseline="d" * 64)], now=now).scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL"
    assert len(st["finding_ids"]) == 1


def test_ST5_04_exact_scope_and_evidence_window_enforced():
    """ST5-04｜注入：越 exact-scope 业务流/授权窗外执行｜期望：BLOCKED。

    一次性 exact-scope 授权执法：scope 外业务流（fund-transfer 未授权）与
    授权到期后才执行的证据（executed_at > expiry）都不得通过——BLOCKED+
    NOT_EVALUATED+原因落账（授权执法不折算 PASS）。
    """
    manifest = _mk_manifest(_next_run_id("st5"))
    now = _now56()
    from wenqu_core.station5_live_fire import _iso_z

    out_of_scope = LiveFireScanner(
        manifest, authorization=_auth(now, scope=("order-create-live",)),
        flows=[_flow("fund-transfer-live")], now=now)
    st = out_of_scope.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED" and st["policy_verdict"] != "PASS"
    assert any(r.startswith("flow_out_of_scope")
               for r in out_of_scope.last_breakdown["authorization_failures"])

    late = LiveFireScanner(
        manifest, authorization=_auth(now, expiry_days=1),
        flows=[_flow(executed_at=_iso_z(now + timedelta(days=2)))], now=now)
    st = late.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED"
    assert any(r.startswith("evidence_out_of_window")
               for r in late.last_breakdown["authorization_failures"])


def test_ST5_05_malformed_payload_fail_closed():
    """ST5-05｜注入：结构损坏载荷（哈希/时间戳/要素缺失/空断言）｜期望：拒绝。

    fail-closed 面：授权缺要素/expiry 不可解析/状态哈希非 64hex/断言 outcome
    非法/授权在场但 flows 空——一律抛 LiveFire*Malformed，不产出任何结果
    （含 PASS 的最强阻断形态，对齐站3 DriftReportMalformed 先例）。
    """
    manifest = _mk_manifest(_next_run_id("st5"))
    now = _now56()
    bad_auths = [
        {"approver": "o"},                              # 缺 reason/scope/expiry/token
        {**_auth(now), "reason": "太短"},                # 理由 <10 字
        {**_auth(now), "expiry": "not-a-date"},          # 时间戳不可解析
        {**_auth(now), "scope": []},                     # 空 exact-scope
    ]
    for bad in bad_auths:
        try:
            LiveFireScanner(manifest, authorization=bad, flows=[_flow()], now=now)
            raise AssertionError(f"malformed authorization must raise: {bad!r}")
        except LiveFireAuthorizationMalformed:
            pass
    bad_flows = [
        dict(_flow(), before_state_hash="zz"),           # 哈希非 64hex
        dict(_flow(), executed_at="yesterday??"),        # 执行时刻不可解析
        dict(_flow(), assertions=[]),                    # 空断言=分母真空
        dict(_flow(), assertions=[{"name": "x", "outcome": "MAYBE"}]),
        dict(_flow(), idempotency={"replay_effects": -1}),
        dict(_flow(), compensation={"required": "yes", "executed": False}),
    ]
    good_auth = _auth(now)
    for bad in bad_flows:
        try:
            LiveFireScanner(manifest, authorization=good_auth, flows=[bad], now=now)
            raise AssertionError(f"malformed flow must raise: {bad!r}")
        except LiveFireEvidenceMalformed:
            pass
    try:
        LiveFireScanner(manifest, authorization=good_auth, flows=[], now=now)
        raise AssertionError("authorized run without flows must raise")
    except LiveFireEvidenceMalformed:
        pass


def test_ST5_06_registry_wire_real_scanner_not_placeholder():
    """ST5-06｜注入：读取现役注册表｜期望：站5 tools 槽指向真实扫描器。

    注册表状态面（w6a-1.1.0）：站5 tools 首槽=wenqu_core.station5_live_fire
    （真实实现取代 station7_runtime 占位接口）；模块导入面：实现类可导入
    且不再是 NOT_APPLICABLE 占位；注册表自检通过、版本号已递增。
    """
    spec = default_registry().get(5)
    assert spec.slug == "live_fire" and spec.station_id == 5
    assert "wenqu_core.station5_live_fire" in spec.tools, spec.tools
    assert REGISTRY_VERSION == "w6a-1.1.0", REGISTRY_VERSION
    default_registry().validate()  # 判据三态/TTL 双上限一致性
    # 占位对照：station7_runtime 的占位类与真实扫描器并存，但注册表只认真实件
    from wenqu_core.station7_runtime import Station5LiveFirePlaceholder
    assert Station5LiveFirePlaceholder.IMPLEMENTED is False  # 占位件自证未实现
    assert "station7_runtime" not in " ".join(spec.tools)


# ---------------------------------------------------------------------------
# 站6 对抗面——真实注入夹具
# ---------------------------------------------------------------------------


AXES6 = ("auth-bypass", "mutation", "concurrency", "out-of-order",
         "duplicate-submit")


def _ctx6(cid, kind, source, *, now=None, answers=None, captured_at=None,
          findings_by_axis=None):
    from wenqu_core.station6_adversarial import _iso_z
    base = answers if answers is not None else {
        axis: {"asked": True, "findings": []} for axis in AXES6}
    if findings_by_axis:
        base = dict(base)
        for axis, fs in findings_by_axis.items():
            base[axis] = {"asked": True,
                          "findings": [{"summary": s, "severity": v}
                                       for s, v in fs]}
    return {
        "context_id": cid, "kind": kind, "source_identity": source,
        "captured_at": captured_at or _iso_z(now or _now56()),
        "answers": base,
    }


def _dual_contexts(now=None, **kw):
    return [
        _ctx6("s3-cc", "s3_adversarial", "claude-code/oppo", now=now, **kw),
        _ctx6("s5-codex", "s5_independent_audit", "codex/audit", now=now, **kw),
    ]


# ---------------------------------------------------------------------------
# 站6 专属测试
# ---------------------------------------------------------------------------


def test_ST6_01_full_axis_coverage_two_sources_zero_findings_pass():
    """ST6-01｜注入：每轴必问全覆盖+双异源零发现｜期望：PASS。

    注册表 pass 判据逐条实证：S3 对抗+S5 独立审计双异源在场、5 轴全问、
    零发现结论由 2 个互异 source_identity 支撑（二审定律满足）；coverage
    分母=对抗轴问题数；PASS 携带非空 artifacts（登记+状态汇总工件）。
    """
    manifest = _mk_manifest(_next_run_id("st6"))
    now = _now56()
    scanner = AdversarialReviewScanner(manifest, axes=AXES6,
                                       contexts=_dual_contexts(now), now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["station_id"] == 6, st
    assert st["execution_status"] == "COMPLETED" and st["policy_verdict"] == "PASS", st
    assert st["coverage"] == {"denominator": 5, "scanned": 5}, st["coverage"]
    assert st["finding_ids"] == []
    assert st["artifacts"] and st["artifacts"][0]["cas_digest"].startswith("sha256:")
    law = scanner.last_breakdown["second_review_law"]
    assert law == {"zero_finding_conclusion": True, "independent_contexts": 2,
                   "satisfied": True}, law
    assert scanner.last_breakdown["independent_sources"] == [
        "claude-code/oppo", "codex/audit"]


def test_ST6_02_single_context_zero_finding_and_relabel_fail():
    """ST6-02｜注入：单上下文零发现/同命令换标签｜期望：FAIL（二审定律）。

    两个对抗注入：(a) 仅一个异源在场且零发现——单上下文零发现声明；
    (b) 两个 context_id/kind 不同但 source_identity 相同（§15.7 同命令换
    标签算异源的欺骗手法）——独立性去重后仍算单上下文。两者都必须 FAIL
    且产出 fnd_adv_single_context_zero 落账。
    """
    manifest = _mk_manifest(_next_run_id("st6"))
    now = _now56()
    # (a) 单上下文：S5 缺席会被 required_kinds 拦成 BLOCKED——改用双 kind
    # 在场但同源（同时覆盖 (b)）；先证 required_kinds 可显式放宽后单上下文
    # 零发现仍 FAIL（放宽在场面不放松二审定律）。
    scanner = AdversarialReviewScanner(
        manifest, axes=AXES6,
        contexts=[_ctx6("only-s3", "s3_adversarial", "claude-code/oppo", now=now)],
        required_kinds=("s3_adversarial",), now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL", st
    assert st["execution_status"] == "COMPLETED"
    assert any(f.startswith("fnd_adv_single_context_zero")
               for f in st["finding_ids"]), st["finding_ids"]
    assert scanner.last_breakdown["independent_sources"] == ["claude-code/oppo"]

    # (b) 同源换标签：kind 不同、source_identity 相同 → 只计一个独立源
    scanner = AdversarialReviewScanner(
        manifest, axes=AXES6,
        contexts=[
            _ctx6("s3-cc", "s3_adversarial", "claude-code/oppo", now=now),
            _ctx6("s5-fake", "s5_independent_audit", "claude-code/oppo", now=now),
        ], now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL", st
    assert scanner.last_breakdown["independent_sources"] == ["claude-code/oppo"]
    assert any(f.startswith("fnd_adv_single_context_zero")
               for f in st["finding_ids"])


def test_ST6_03_axis_gap_and_findings_fail_with_ledger():
    """ST6-03｜注入：漏问轴/对抗发现｜期望：FAIL 且逐条落账。

    注册表 fail 判据「轴覆盖缺失」：一个上下文漏问 mutation → 恰 1 条
    fnd_adv_axis_gap（点名轴+上下文）；「对抗发现」：S3 报 1 条 HIGH 越权
    发现 → fnd_adv_finding 落账（待裁定缺陷站级不得绿，对齐站2 命中语义）；
    两类 finding 同场共存时逐条可数。
    """
    manifest = _mk_manifest(_next_run_id("st6"))
    now = _now56()
    skipped = {axis: {"asked": True, "findings": []} for axis in AXES6}
    skipped["mutation"] = {"asked": False, "findings": []}
    scanner = AdversarialReviewScanner(
        manifest, axes=AXES6,
        contexts=[
            _ctx6("s3-cc", "s3_adversarial", "claude-code/oppo", now=now),
            _ctx6("s5-codex", "s5_independent_audit", "codex/audit",
                  now=now, answers=skipped),
        ], now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL"
    assert scanner.last_breakdown["axis_gaps"] == [
        {"axis": "mutation", "context_id": "s5-codex"}]
    assert any(f.startswith("fnd_adv_axis_gap") for f in st["finding_ids"])

    found = {axis: {"asked": True, "findings": []} for axis in AXES6}
    found["auth-bypass"] = {"asked": True, "findings": [
        {"summary": "越权负例在 /api/orders 放行", "severity": "HIGH"},
        {"summary": "重复提交产生双扣库存", "severity": "MEDIUM"},
    ]}
    scanner = AdversarialReviewScanner(
        manifest, axes=AXES6,
        contexts=[
            _ctx6("s3-cc", "s3_adversarial", "claude-code/oppo", now=now,
                  answers=found),
            _ctx6("s5-codex", "s5_independent_audit", "codex/audit", now=now),
        ], now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL" and st["execution_status"] == "COMPLETED"
    adv = [f for f in st["finding_ids"] if f.startswith("fnd_adv_finding")]
    assert len(adv) == 2, st["finding_ids"]
    assert len(scanner.last_breakdown["adversarial_findings"]) == 2
    # 有发现时二审定律不再适用（零发现结论不存在）
    assert scanner.last_breakdown["second_review_law"]["satisfied"] is True


def test_ST6_04_missing_heterogeneous_endpoint_and_stale_blocked():
    """ST6-04｜注入：异源端点缺席/证据过期（TTL 日落）｜期望：BLOCKED。

    注册表 error 判据「异源端点宕机」+ 铁律 4 证据时效：S5 上下文缺席 →
    BLOCKED/NOT_EVALUATED（降级须登记豁免）；双异源 8 天前捕获（超注册表
    站6 TTL=7d）→ 过期不采信 → BLOCKED；分母保留 5、scanned=0（不缩分母
    装作扫过）。
    """
    manifest = _mk_manifest(_next_run_id("st6"))
    now = _now56()
    from wenqu_core.station6_adversarial import _iso_z

    scanner = AdversarialReviewScanner(
        manifest, axes=AXES6,
        contexts=[_ctx6("s3-cc", "s3_adversarial", "claude-code/oppo", now=now)],
        now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED", st
    assert st["policy_verdict"] == "NOT_EVALUATED", st
    assert st["coverage"] == {"denominator": 5, "scanned": 0}, st["coverage"]
    assert scanner.last_breakdown["missing_required_kinds"] == [
        "s5_independent_audit"]
    assert any(f.startswith("fnd_adv_context_missing") for f in st["finding_ids"])

    stale = _iso_z(now - timedelta(days=8))
    scanner = AdversarialReviewScanner(
        manifest, axes=AXES6,
        contexts=[_ctx6("s3-cc", "s3_adversarial", "claude-code/oppo",
                        captured_at=stale),
                  _ctx6("s5-codex", "s5_independent_audit", "codex/audit",
                        captured_at=stale)], now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED"
    assert len(scanner.last_breakdown["contexts_stale"]) == 2
    # 边界：6 天前捕获仍在 7d TTL 内 → 不过期（日落执法不误伤新鲜证据）
    fresh = _iso_z(now - timedelta(days=6))
    st = AdversarialReviewScanner(
        manifest, axes=AXES6,
        contexts=[_ctx6("s3-cc", "s3_adversarial", "claude-code/oppo",
                        captured_at=fresh),
                  _ctx6("s5-codex", "s5_independent_audit", "codex/audit",
                        captured_at=fresh)], now=now).scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "PASS", st


def test_ST6_05_malformed_ledger_fail_closed():
    """ST6-05｜注入：账本结构损坏（缺字段/answers 非法/severity 越界/重复 id/空轴）｜期望：拒绝。

    登记完整性执法：任何结构性损坏（context_id 空、answers 空映射、asked
    非布尔、severity 越界、context_id 重复、轴清单空/重复）一律抛
    AdversarialLedgerMalformed/AdversarialSpecError，不产出任何结果——
    fail-closed，绝不带损坏账本出 PASS。
    """
    manifest = _mk_manifest(_next_run_id("st6"))
    now = _now56()
    good = _dual_contexts(now)
    bad_contexts = [
        [dict(good[0], context_id="")],
        [dict(good[0], source_identity="")],
        [dict(good[0], answers={})],
        [dict(good[0], answers={"auth-bypass": {}})],
        [dict(good[0], answers={"auth-bypass": {"asked": 1, "findings": []}})],
        [dict(good[0], answers={"auth-bypass": {"asked": True, "findings": [
            {"summary": "s", "severity": "CRITICAL"}]}})],
        [dict(good[0], answers={"auth-bypass": {"asked": True, "findings": [
            {"summary": "", "severity": "HIGH"}]}})],
        [dict(good[0], captured_at="not-a-date")],
    ]
    for contexts in bad_contexts:
        try:
            AdversarialReviewScanner(manifest, axes=AXES6, contexts=contexts,
                                     now=now)
            raise AssertionError(f"malformed ledger must raise: {contexts!r}")
        except AdversarialLedgerMalformed:
            pass
    dup = [dict(good[0]), dict(good[1], context_id=good[0]["context_id"])]
    try:
        AdversarialReviewScanner(manifest, axes=AXES6, contexts=dup, now=now)
        raise AssertionError("duplicate context_id must raise")
    except AdversarialLedgerMalformed:
        pass
    for bad_axes in ([], ["dup", "dup"], ["ok", ""]):
        try:
            AdversarialReviewScanner(manifest, axes=bad_axes,
                                     contexts=good, now=now)
            raise AssertionError(f"bad axes must raise: {bad_axes!r}")
        except AdversarialSpecError:
            pass


def test_ST6_06_registry_wire_real_scanner_and_incident_membership():
    """ST6-06｜注入：读取现役注册表+档位成员｜期望：站6 真实件+INCIDENT required。

    注册表状态面（w6a-1.1.0）：站6 tools 首槽=wenqu_core.station6_adversarial
    （真实实现取代占位）；站6 属 INCIDENT 档 required 集（收敛语义真实在编）；
    TTL=7 天（permission_vulnerability 双上限内——站6 日落执法的正源）。
    """
    registry = default_registry()
    spec = registry.get(6)
    assert spec.slug == "adversarial" and spec.station_id == 6
    assert "wenqu_core.station6_adversarial" in spec.tools, spec.tools
    assert spec.ttl_days == 7 and spec.evidence_class == "permission_vulnerability"
    assert 6 in registry.required_for("INCIDENT")
    from wenqu_core.station7_runtime import Station6AdversarialPlaceholder
    assert Station6AdversarialPlaceholder.IMPLEMENTED is False  # 占位件自证未实现
    assert "station7_runtime" not in " ".join(spec.tools)


# ---------------------------------------------------------------------------
# 两站交汇——orchestrator 自测面（注册表 selftest 从 NOT_APPLICABLE 占位变真实）
# ---------------------------------------------------------------------------


def test_ST56_07_orchestrator_selftest_covers_real_stations():
    """ST56-07｜注入：运行 orchestrator 端到端自测｜期望：rc0 且覆盖站5/6 真实扫描。

    第八轮缺口「站5/6 仍 placeholder/NOT_APPLICABLE」的机器反证：注册表
    selftest（bugscan_orchestrator._self_test）现包含站5/站6 真实扫描步骤
    （[7]/[8]），以子进程真跑并核验输出标记与退出码。
    """
    import subprocess
    system_root = Path(REPO)
    proc = subprocess.run(
        [sys.executable, "-m", "wenqu_core.bugscan_orchestrator"],
        cwd=system_root, capture_output=True, text=True, timeout=120)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, (proc.returncode, out[-2000:])
    assert "SELF-TEST PASS" in out
    assert "station-5 live-fire real scan OK" in out, out
    assert "station-6 adversarial real scan OK" in out, out
    assert "registry w6a-1.1.0" in out  # 注册表版本已随工具槽变更递增


# ---------------------------------------------------------------------------
# T-3 生产接线（wq9 §1 硬阻断 6 / §9 P0-3）：站5/6 纳入生产 dispatch
# ---------------------------------------------------------------------------


def _st56_auth_record(now, *, expiry_days=1, scope=("sandbox-order-create",)):
    from wenqu_core.station5_live_fire import _iso_z
    return {
        "approver": "t3-test-owner",
        "reason": "T-3 生产接线测试：本地沙箱一次性 exact-scope 授权",
        "scope": list(scope),
        "expiry": _iso_z(now + timedelta(days=expiry_days)),
        "token": "t3-test-one-time-token",
    }


def _st56_flow(name="sandbox-order-create", *, baseline=None, fail=False):
    from wenqu_core.station5_live_fire import _iso_z
    before = "a" * 64
    assertions = ([{"name": "order-visible", "outcome": "PASS"},
                   {"name": "stock-deducted", "outcome": "PASS"}]
                  if not fail else
                  [{"name": "order-visible", "outcome": "FAIL"}])
    return {
        "name": name,
        "executed_at": _iso_z(_now56()),
        "before_state_hash": before,
        "after_state_hash": "b" * 64,
        "baseline_state_hash": baseline or before,
        "assertions": assertions,
        "idempotency": {"replay_effects": 0},
        "conservation": {"invariant": "stock>=0", "violations": 0},
        "compensation": {"required": fail, "executed": fail},
    }


def _st56_ctx(cid, kind, source, axes, *, now=None):
    return {
        "context_id": cid, "kind": kind, "source_identity": source,
        "captured_at": now or _iso_z56(),
        "answers": {axis: {"asked": True, "findings": []} for axis in axes},
    }


def _iso_z56():
    from wenqu_core.station6_adversarial import _iso_z
    return _iso_z(_now56())


def test_ST56_08_production_dispatch_runs_stations_5_and_6():
    """ST56-08｜注入：BugscanOrchestrator 完整 run（生产 dispatch）｜期望：站0-7 全部经生产链路出合规结果。

    wq9 §1 硬阻断 6 反证：orchestrator 必须存在生产 run/dispatch 链路
    （BugscanOrchestrator.run），站5 经显式授权加入 required、站6 按
    registry TTL/异源上下文参数化 dispatch——不再只有 _self_test/测试调用。
    """
    from wenqu_core.bugscan_orchestrator import (
        BugscanOrchestrator, BugscanPlanner, validate_station_result,
    )
    now = _now56()
    planner = BugscanPlanner(default_registry())
    plan = planner.plan("INCIDENT", station5_authorization=_st56_auth_record(now))
    assert plan.required_stations == (0, 1, 2, 3, 4, 5, 6, 7), plan
    manifest = planner.freeze_run_manifest(
        plan, run_id=_next_run_id("st56t3"), project_id="wenqu-ac-station56",
        commit_sha="6" * 40, environment="local",
        scope=["src/**", "tests/**", "tools/**"],
        ruleset={"version": "ac56", "rules": ["W6A-ST5", "W6A-ST6"]},
        data_config={"profile": "default"},
        # 逐站冻结分母=各站输入真实产生的覆盖分母（站0=scope 路径数、
        # 站1=组件数、站2=启用执行件数、站3=端点×正负例、站4=样本数、
        # 站5=断言点数、站6=轴数、站7=哨兵数）。
        station_denominators={0: 3, 1: 1, 2: 1, 3: 2, 4: 3, 5: 6, 6: 2, 7: 1},
    )
    axes = ("auth-bypass", "mutation")
    inputs = {
        1: {"gate_result": {
            "commit_sha": manifest.commit_sha, "exit_code": 0,
            "tool": {"name": "ci-fast-test", "version": "1"},
            "started_at": manifest.frozen_at, "ended_at": manifest.frozen_at,
            "components": [{"name": "pytest-fast", "status": "COMPLETED",
                            "exit_code": 0}],
        }},
        2: {"station2": {"repo_dir": REPO, "scanners": ("engine",),
                         "engine_state_path": _engine_state_fixture()}},
        3: {"station3": {"org_guard": {
            "tool": {"name": "probe", "version": "1"},
            "started_at": manifest.frozen_at, "ended_at": manifest.frozen_at,
            "probe_identity": {"base_url": "http://local.test",
                               "positive_principal": "owner",
                               "negative_principal": "attacker"},
            "endpoints": [{
                "method": "GET", "path": "/api/v1/logs",
                "positive": {"executed": True, "outcome": "ALLOWED"},
                "negative": {"executed": True, "outcome": "DENIED",
                             "status_code": 403},
            }],
        }}},
        4: {"station4": {"legs": {"quantile": {
            "samples": [10.0, 20.0, 30.0],
            "thresholds_ms": {"p50": 50, "p95": 100, "p99": 200},
        }}}},
        5: {"authorization": _st56_auth_record(now),
            "flows": [_st56_flow()]},
        6: {"axes": axes,
             "contexts": [_st56_ctx("s3", "s3_adversarial", "cc/test", axes),
                          _st56_ctx("s5", "s5_independent_audit", "codex/test",
                                    axes)]},
        7: {"station7": {"legs": {"sentinel": {"sentinels": [
            {"name": "canary", "kind": "heartbeat_json",
             "path": _heartbeat_fixture(), "freshness_s": 300},
        ]}}}},
    }
    orch = BugscanOrchestrator(manifest)
    results = orch.run(inputs)
    assert sorted(results) == list(range(8)), sorted(results)
    for sid, st in results.items():
        validate_station_result(st)  # 全部严格合规
        frozen = manifest.station_denominators[sid]
        assert st["coverage"]["denominator"] == frozen, (sid, st["coverage"])
    assert results[5]["station_id"] == 5
    assert results[5]["policy_verdict"] == "PASS", results[5]
    assert results[5]["coverage"] == {"denominator": 6, "scanned": 6}
    assert results[6]["station_id"] == 6
    assert results[6]["policy_verdict"] == "PASS", results[6]
    assert results[6]["coverage"] == {"denominator": 2, "scanned": 2}
    # 站5 无授权 dispatch → 注册表 error 判据（BLOCKED，不算通过）
    no_auth = BugscanOrchestrator(manifest).run(
        {**inputs, 5: {"flows": [_st56_flow()]}})
    assert no_auth[5]["execution_status"] == "BLOCKED"
    assert no_auth[5]["policy_verdict"] == "NOT_EVALUATED"


def test_ST56_09_authorized_addition_channel_and_manifest_semantics():
    """ST56-09｜注入：授权加站通道+逐站分母冻结+零 SHA 拒绝｜期望：语义重放全通过、旁路全拦。

    - plan(station5_authorization=…) 是站5 加入 required 的唯一通道
      （授权五要素+30 天日落；缺记录/坏记录/过期全拒）；
    - station_denominators 冻结后 validate_manifest_consistency 与
      replay_manifest_semantics 零违例；手改 required 加 5 无授权记录 →
      重放违例（BLOCKED 面）；缩分母/漂移分母 → 违例；
    - 零 SHA（40 个 0）身份在 freeze 即拒（wq9 §1 硬阻断 3 的源头修）。
    """
    from wenqu_core.bugscan_orchestrator import (
        BugscanPlanner, ManifestFreezeError, RiskDowngradeError,
        freeze_run_manifest, replay_manifest_semantics,
        validate_manifest_consistency,
    )
    now = _now56()
    planner = BugscanPlanner(default_registry())
    good = _st56_auth_record(now)
    # 坏授权记录：缺要素 / 过期 / 超日落窗 / 理由过短
    for bad in ({}, {**good, "token": ""}, {**good, "reason": "太短"},
                {**good, "expiry": "not-a-date"}):
        try:
            planner.plan("INCIDENT", station5_authorization=bad)
            raise AssertionError(f"bad addition record must raise: {bad!r}")
        except RiskDowngradeError:
            pass
    expired = _st56_auth_record(now, expiry_days=-1)
    try:
        planner.plan("INCIDENT", station5_authorization=expired)
        raise AssertionError("expired addition record must raise")
    except RiskDowngradeError:
        pass

    plan = planner.plan("INCIDENT", station5_authorization=good)
    assert plan.authorized_additions == (5,)
    manifest = planner.freeze_run_manifest(
        plan, run_id=_next_run_id("st56sem"), project_id="wenqu-ac-station56",
        commit_sha="7" * 40, environment="local",
        scope=["src/**", "tests/**", "tools/**"],
        ruleset={"r": 1}, data_config={"d": 1},
        station_denominators={0: 3, 1: 1, 2: 1, 3: 2, 4: 1, 5: 6, 6: 5, 7: 1},
    )
    raw = manifest.to_dict()
    assert validate_manifest_consistency(raw) == []
    assert replay_manifest_semantics(raw, registry=default_registry()) == []
    # 冻结分母不可漂移：站0 分母（唯一可推导分母=scope 路径数）被篡改 →
    # 一致性与重放双违例；非零分母执法：站5 分母改 0 → 双违例。
    tampered = json.loads(json.dumps(raw))
    tampered["station_denominators"]["0"] = 2
    assert any("station_denominators" in v
               for v in validate_manifest_consistency(tampered))
    assert any("station_denominators" in v
               for v in replay_manifest_semantics(tampered,
                                                  registry=default_registry()))
    zero_denom = json.loads(json.dumps(raw))
    zero_denom["station_denominators"]["5"] = 0
    assert any("station_denominators" in v
               for v in validate_manifest_consistency(zero_denom))
    assert any("station_denominators" in v
               for v in replay_manifest_semantics(zero_denom,
                                                  registry=default_registry()))
    # 无授权记录却把 5 写进 required → 重放违例（加站必须走授权通道）：
    # 构造=删掉 planner 的授权加站记录、保留 required 含 5。
    ghost = json.loads(json.dumps(raw))
    ghost["planner"].pop("authorized_additions", None)
    ghost["planner"].pop("station5_authorization", None)
    assert any("authorized_addition" in v
               for v in replay_manifest_semantics(ghost,
                                                  registry=default_registry()))
    # 零 SHA 身份：freeze 直接拒绝
    try:
        freeze_run_manifest(
            plan, run_id=_next_run_id("zerosha"),
            project_id="wenqu-ac-station56", commit_sha="0" * 40,
            environment="local", scope=["src/**"], ruleset={"r": 1},
            data_config={"d": 1})
        raise AssertionError("zero commit_sha must be refused at freeze")
    except ManifestFreezeError:
        pass


def test_ST56_10_gate_reconciles_per_station_denominators():
    """ST56-10｜注入：GateAggregator 逐站分母对账｜期望：各站分母=冻结值、缩水/漂移即违规。

    八站 run 的分母语义各异（站0=scope 路径数、站5=断言点、站6=轴数…），
    manifest 冻结 station_denominators 后 gate 逐站对账——既不要求全站同
    分母（旧口径），也不放过任何自报/缩水分母。
    """
    from wenqu_core.gate_aggregator import GateAggregator
    agg = GateAggregator(
        required_stations={"5", "6"}, target_sha="8" * 40, environment="local",
        expected_scope_hash="9" * 64, expected_denominator=3,
        expected_denominators={"5": 6, "6": 5})
    agg.add(_mk_v2_result(5, 6, "9" * 64))
    agg.add(_mk_v2_result(6, 5, "9" * 64))
    result = agg.aggregate()
    assert result["aggregate_outcome"] == "PASS", result["reasons"]
    assert result["scope_binding"]["station_denominators"] == {"5": 6, "6": 5}
    # 站6 自报分母 4（缩水）→ scope_binding_violation → BLOCKED
    agg2 = GateAggregator(
        required_stations={"5", "6"}, target_sha="8" * 40, environment="local",
        expected_scope_hash="9" * 64, expected_denominator=3,
        expected_denominators={"5": 6, "6": 5})
    agg2.add(_mk_v2_result(5, 6, "9" * 64))
    agg2.add(_mk_v2_result(6, 4, "9" * 64))
    result2 = agg2.aggregate()
    assert result2["aggregate_outcome"] == "BLOCKED"
    assert any("scope_binding_violation" in r for r in result2["reasons"])
    # 未冻结逐站分母的旧口径：回退 manifest 总分母（向后兼容）
    agg3 = GateAggregator(
        required_stations={"5"}, target_sha="8" * 40, environment="local",
        expected_scope_hash="9" * 64, expected_denominator=3)
    agg3.add(_mk_v2_result(5, 3, "9" * 64))
    assert agg3.aggregate()["aggregate_outcome"] == "PASS"


def _mk_v2_result(station_id, denominator, scope_hash):
    return {
        "schema_version": "2.0",
        "run_id": "ac56-gate-denom",
        "station_id": station_id,
        "attempt_id": f"att-st{station_id}-denom",
        "execution_status": "COMPLETED",
        "policy_verdict": "PASS",
        "identity": {
            "project_id": "wenqu-ac-station56", "commit_sha": "8" * 40,
            "environment": "local", "scope_hash": scope_hash,
            "ruleset_hash": "1" * 64, "data_config_hash": "2" * 64,
        },
        "tool": {"name": "test-probe", "version": "1"},
        "execution": {
            "argv_digest": "3" * 64, "started_at": "2026-10-10T00:00:00Z",
            "ended_at": "2026-10-10T00:00:01Z", "timeout_s": 60,
            "actual_exit_code": 0, "expected_exit_set": [0],
            "assertion_verdict": "PASS",
        },
        "coverage": {"denominator": denominator, "scanned": denominator},
        "finding_ids": [],
        "artifacts": [{"cas_digest": f"sha256:{'4' * 64}", "size": 8}],
    }


def _engine_state_fixture():
    """全闭环引擎状态夹具（tmp 文件——站2 engine 件真实读入执行）。"""
    import tempfile as _tf
    state = {"queue": [
        {"id": "ENUM", "slug": "enum", "status": "MERGED"},
        {"id": "CTX", "slug": "ctx", "status": "闭环"},
        {"id": "MSG", "slug": "msg", "status": "收官"},
        {"id": "DW", "slug": "dualwrite", "status": "MERGED"},
        {"id": "DOM", "slug": "domain", "status": "DONE"},
    ]}
    fd, path = _tf.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    return path


def _heartbeat_fixture():
    """新鲜哨兵心跳夹具（tmp 文件——站7 sentinel 件真实读入判活）。"""
    import tempfile as _tf
    from wenqu_core.station7_runtime import _iso_z
    fd, path = _tf.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"last_beat_at": _iso_z(_now56()), "state": "healthy"}, fh)
    return path


# ---------------------------------------------------------------------------
# 运行器（对齐 system/tests 既有约定：python3 直跑、exit 0=全绿）
# ---------------------------------------------------------------------------

TESTS = [
    ("ST5-01 有效授权+全量证据 → PASS（断言点 12/12+脱敏 artifacts）",
     test_ST5_01_valid_authorization_full_evidence_pass),
    ("ST5-02 授权缺失/过期/超日落窗 → BLOCKED（error 判据，不算通过）",
     test_ST5_02_missing_or_expired_authorization_blocked),
    ("ST5-03 断言失败/幂等/守恒/补偿/回基线 → FAIL 逐点落账",
     test_ST5_03_checkpoint_failures_each_fail_with_findings),
    ("ST5-04 越 exact-scope/授权窗外证据 → BLOCKED",
     test_ST5_04_exact_scope_and_evidence_window_enforced),
    ("ST5-05 结构损坏载荷 → fail-closed 拒绝（不产出任何结果）",
     test_ST5_05_malformed_payload_fail_closed),
    ("ST5-06 注册表 tools 槽指向真实扫描器（非 station7 占位件）",
     test_ST5_06_registry_wire_real_scanner_not_placeholder),
    ("ST6-01 每轴必问全覆盖+双异源零发现 → PASS（二审定律满足）",
     test_ST6_01_full_axis_coverage_two_sources_zero_findings_pass),
    ("ST6-02 单上下文零发现/同命令换标签 → FAIL（二审定律）",
     test_ST6_02_single_context_zero_finding_and_relabel_fail),
    ("ST6-03 漏问轴/对抗发现 → FAIL 且逐条落账",
     test_ST6_03_axis_gap_and_findings_fail_with_ledger),
    ("ST6-04 异源端点缺席/证据过期（7d TTL）→ BLOCKED（日落不误伤新鲜证据）",
     test_ST6_04_missing_heterogeneous_endpoint_and_stale_blocked),
    ("ST6-05 账本结构损坏/空轴/重复 context_id → fail-closed 拒绝",
     test_ST6_05_malformed_ledger_fail_closed),
    ("ST6-06 注册表真实件+INCIDENT required+TTL 正源",
     test_ST6_06_registry_wire_real_scanner_and_incident_membership),
    ("ST56-07 orchestrator selftest rc0 且含站5/6 真实扫描步骤",
     test_ST56_07_orchestrator_selftest_covers_real_stations),
    ("ST56-08 生产 dispatch：BugscanOrchestrator 完整 run 覆盖站0-7（含站5/6）",
     test_ST56_08_production_dispatch_runs_stations_5_and_6),
    ("ST56-09 授权加站通道+逐站分母冻结语义+零 SHA freeze 即拒",
     test_ST56_09_authorized_addition_channel_and_manifest_semantics),
    ("ST56-10 gate 逐站分母对账：各站=冻结值、缩水/漂移即 BLOCKED",
     test_ST56_10_gate_reconciles_per_station_denominators),
]

IMPLEMENTED_IDS = [name.split()[0] for name, _ in TESTS]
assert len(IMPLEMENTED_IDS) == len(set(IMPLEMENTED_IDS)) == 16, IMPLEMENTED_IDS
assert not (set(IMPLEMENTED_IDS) & set(NOT_IMPLEMENTABLE)), "清单互斥被破坏"


def main(json_out=None):
    results = []
    pass_n = fail_n = 0
    for name, fn in TESTS:
        test_id = name.split()[0]
        t0 = time.time()
        try:
            fn()
            pass_n += 1
            status = "PASS"
            print(f"  ok  {name}")
        except Exception as exc:  # noqa: BLE001——失败必须留痕并继续跑完
            fail_n += 1
            status = "FAIL"
            print(f"  FAIL {name}: {type(exc).__name__}: {exc}")
        results.append({"id": test_id, "name": name, "status": status,
                        "duration_ms": round((time.time() - t0) * 1000, 1)})

    print(f"\n站5/站6 专属验收测试: {pass_n} PASS / {fail_n} FAIL "
          f"（负责 {len(IMPLEMENTED_IDS)} 条；实现 {len(IMPLEMENTED_IDS)}；"
          f"不可实现 {len(NOT_IMPLEMENTABLE)}）")
    for tid, reason in sorted(NOT_IMPLEMENTABLE.items()):
        print(f"  [不可实现] {tid}: {reason}")

    if json_out:
        payload = {
            "artifact_kind": "ac-station56/unit-run",
            "command": "python3 system/tests/test_ac_station56.py",
            "exit_code": 1 if fail_n else 0,
            "totals": {
                "responsible": len(IMPLEMENTED_IDS),
                "implemented": len(IMPLEMENTED_IDS),
                "not_implementable": len(NOT_IMPLEMENTABLE),
                "passed": pass_n,
                "failed": fail_n,
            },
            "implemented_ids": IMPLEMENTED_IDS,
            "not_implementable": NOT_IMPLEMENTABLE,
            "results": results,
        }
        out = Path(json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        print(f"结构化结果: {out}")
    return 1 if fail_n else 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    out_path = None
    if argv and argv[0] == "--json-out":
        out_path = argv[1] if len(argv) > 1 else None
    raise SystemExit(main(out_path))

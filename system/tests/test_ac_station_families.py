#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_ac_station_families.py——§20 验收 ID 专属测试·六族（本文件负责 29 条）。

负责族与 ID（正源：evidence/00-baseline/codex-external/方案.md §20.3/§20.5 表格，
注入/期望逐字对齐；tools/ac_traceability.py 冻结目录同源）：

  STA-01~02（站点结果/整线聚合）、DB-01~06（目录漂移）、SC-01~05（供应链）、
  ADV-01~02（advisory/公告面）、TEN-01~08（租户分母）、PERF-01~06（性能有效性）。

被测体（不改动任何产品码——本文件只做真实注入+真实断言）：
  wenqu_core.bugscan_orchestrator（STA 统一入口语义：分母缩水守卫/结果校验/manifest 冻结）
  wenqu_core.station2_static（SC 供应链 npm audit 适配、ADV 公告解析、STA 站2 聚合）
  wenqu_core.station3_contract（DB 目录漂移、契约对账、TEN 租户分母）
  wenqu_core.station4_behavior（STA 站4 腿、PERF HTTP 面）
  wenqu_core.station7_runtime（STA 站7 腿、PERF 指标面）

实现口径（诚实边界，逐条落在各测试 docstring）：
- 全部走模块内既有的桩/合成数据通道（_StubRunner 罐头应答、结构化 payload、
  本地 127.0.0.1 真实 HTTP 服务、fake-vitest 真子进程）——零外网、零真实 DB 连接。
- 29 条 ID 全部实现（本轮给 SC-03/SC-05、TEN-04、PERF-03/PERF-04 补齐了
  产品面通道：站2 SupplyChainScanner 增 lockfile 差异分析（SC-03）与快照
  签名/时效校验（SC-05）；站3 增 RawQueryTenantScanner 词法静态分析
  （TEN-04）；站4 增 QuantileLatencyScanner（PERF-03）与
  QueryCountProfileScanner（PERF-04））。NOT_IMPLEMENTABLE 登记清零。
- DB-06/PERF-02/PERF-05/PERF-06/TEN-01~03 为「本发行包可实现子面」的等价语义，
  覆盖边界在各自 docstring 中显式声明。

用法：
  python3 system/tests/test_ac_station_families.py            # 全绿 exit 0
  python3 system/tests/test_ac_station_families.py --json-out PATH
      （额外落结构化结果，供 evidence/04-unit-property-mutation/ac-station-families.json）
"""
import http.server
import json
import os
import sys
import tempfile
import threading
import time
from datetime import timedelta
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.runner import Evidence, TrustedRunner
from wenqu_core.bugscan_orchestrator import (
    BugscanPlanner,
    ManifestFreezeError,
    StationResultValidationError,
    _argv_digest,
    _hash_obj,
    _sha256_hex,
    _iso_z,
    _utc_now,
    build_station_result,
    default_registry,
    validate_station_result,
)
from wenqu_core.station2_static import (
    JSCPD_REPORT_NAME,
    CapturedRun,
    EngineFiveTypesScanner,
    RawTrustedRunner,
    Station2Static,
    SupplyChainScanner,
    build_snapshot_envelope,
)
from wenqu_core.station3_contract import (
    DRIFT_CHANGE_SEVERITY,
    UNKNOWN_CHANGE_SEVERITY,
    AllowlistEntryInvalid,
    ContractPayloadMalformed,
    DriftReportMalformed,
    EvidenceIdentityMismatch,
    NonReadOnlyDataSource,
    RawQueryScanMalformed,
    RawQueryTenantScanner,
    Station3Contract,
    Station3Error,
    derive_dynamic_denominator,
    prisma_dmmf_model_count,
)
from wenqu_core.station4_behavior import (
    E2eScanner,
    QueryCountProfileScanner,
    QuantileLatencyScanner,
    RouteDynamicScanner,
    combine_station4_results,
    percentile,
)
from wenqu_core.station7_runtime import (
    SentinelHealthScanner,
    SloMonitorScanner,
    combine_station7_results,
)

# ---------------------------------------------------------------------------
# 不可实现清单（§20 注入面在本发行包无对应通道——不硬凑、不设测试函数）
#
# 2026-10-08 起清零：SC-03/SC-05（站2 SupplyChainScanner 增 lockfile 差异
# 分析与快照签名/时效校验产品面）、TEN-04（站3 RawQueryTenantScanner）、
# PERF-03/PERF-04（站4 QuantileLatencyScanner/QueryCountProfileScanner）
# 均已具备真实注入通道并转为专属测试函数；保留空映射以维持
# implemented/not-implementable 集合等式断言的机械形态。
# ---------------------------------------------------------------------------

NOT_IMPLEMENTABLE: dict = {}

# ---------------------------------------------------------------------------
# 公共桩与夹具（范式参考各模块内嵌 selftest，独立成函数，按 §20 语义组织）
# ---------------------------------------------------------------------------

_SEQ = iter(range(1, 10000))


def _next_run_id(prefix):
    return f"ac-{prefix}-{next(_SEQ):03d}"


class _StubRunner(RawTrustedRunner):
    """罐头应答桩：不执行任何真实命令，按 argv 匹配返回 canned Evidence+字节。

    与站2 selftest 同范式：继承 RawTrustedRunner（argv 校验/安全构造血统不变），
    仅覆写 run_captured 供解析通道使用。
    """

    def __init__(self, script):
        super().__init__(timeout=30)
        self._script = list(script)

    def run_captured(self, argv, cwd=None):
        for match, respond in self._script:
            if match(list(argv)):
                evidence, out, err = respond(list(argv))
                return CapturedRun(evidence=evidence, stdout=out, stderr=err)
        raise AssertionError(f"stub runner: no canned response for {argv}")


def _ev(argv, rc, ts=None):
    return Evidence(
        argv=tuple(argv), cwd="/tmp", actual_exit_code=rc,
        stdout_sha256=_sha256_hex(b""), stderr_sha256=_sha256_hex(b""),
        argv_digest=_argv_digest(argv),
        timestamp=ts if ts is not None else time.time(),
        fresh_until=time.time() + 300.0, timed_out=False,
    )


def _ev_timeout(argv):
    return Evidence(
        argv=tuple(argv), cwd="/tmp", actual_exit_code=None,
        stdout_sha256=_sha256_hex(b""), stderr_sha256=_sha256_hex(b""),
        argv_digest=_argv_digest(argv), timestamp=time.time(),
        fresh_until=time.time() + 300.0, timed_out=True,
    )


def _j(v):
    return json.dumps(v).encode("utf-8")


ST2_IDENTITY = {
    "project_id": "wenqu-ac-station-families",
    "commit_sha": "e" * 40,
    "environment": "local",
    "scope_hash": "a" * 64,
    "ruleset_hash": "b" * 64,
    "data_config_hash": "c" * 64,
}


def _mk_st2_repo(tmp_path):
    """站2 聚合测试用仓：3 个 src 源文件 + app/pages 路由入口（分母=2）。"""
    repo = Path(tmp_path) / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "app" / "x").mkdir(parents=True)
    (repo / "pages").mkdir(parents=True)
    for name in ("a.ts", "b.ts", "c.ts"):
        (repo / "src" / name).write_text("const x = 1\n", encoding="utf-8")
    (repo / "app" / "x" / "page.tsx").write_text(
        "export default function P(){}\n", encoding="utf-8")
    (repo / "pages" / "y.tsx").write_text(
        "export default function Y(){}\n", encoding="utf-8")
    return repo


JSCPD_REPORT = {
    "duplicates": [
        {"firstFile": {"name": "a.ts", "path": "src/a.ts", "lines": 10, "start": 1},
         "secondFile": {"name": "b.ts", "path": "src/b.ts", "lines": 10, "start": 5},
         "lines": 10, "tokens": 50},
    ],
    "statistics": {"total": {"clones": 1, "duplicates": 1, "files": 3,
                             "lines": 1000, "percentage": "1.00%"}},
}

NPM_CLEAN = {
    "auditReportVersion": 2, "vulnerabilities": {},
    "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0,
                                     "high": 0, "critical": 0},
                 "dependencies": {"prod": 10, "dev": 2, "optional": 0,
                                  "peer": 0, "total": 12}},
}


def _npm_vulns(entries, dep_total=12):
    """entries: [(name, severity, range, title)] → npm audit JSON 载荷。"""
    vulns = {}
    for name, sev, rng, title in entries:
        via = [{"title": title}] if title is not None else ["malformed-ref"]
        vulns[name] = {"name": name, "severity": sev, "range": rng,
                       "via": via, "effects": [], "fixAvailable": True}
    counts = {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0}
    for _, sev, _, _ in entries:
        counts[sev if sev in counts else "high"] += 1
    return {
        "auditReportVersion": 2, "vulnerabilities": vulns,
        "metadata": {"vulnerabilities": counts,
                     "dependencies": {"prod": dep_total - 2, "dev": 2,
                                      "optional": 0, "peer": 0,
                                      "total": dep_total}},
    }


def _jscpd_respond(report):
    def _respond(argv):
        out_dir = Path(argv[argv.index("--output") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / JSCPD_REPORT_NAME).write_text(
            json.dumps(report, sort_keys=True, separators=(",", ":")),
            encoding="utf-8")
        return _ev(argv, 0), b"", b""
    return _respond


def _engine_cards(closed=True, drop=None):
    cards = [
        {"id": "ENUM-LITERALS", "slug": "enum", "status": "MERGED(PR#458 批A)"},
        {"id": "CTX-PENETRATION", "slug": "ctx", "status": "MERGED(PR#459)——闭环"},
        {"id": "MSG-STATIC", "slug": "msg", "status": "✅收官(七批)"},
        {"id": "API-ACTION-DUALWRITE", "slug": "dualwrite", "status": "批A/B MERGED(#495)"},
        {"id": "HARDCODED-DOMAIN-ENV", "slug": "envdomain", "status": "✅审计收官"},
    ]
    if drop is not None:
        cards = [c for c in cards if c["slug"] != drop]
    if not closed:
        cards[0]["status"] = "IN-FLIGHT 批B 进行中"
    return {"queue": cards, "cursor_inflight": None}


# ---- 站3/4/7 夹具 -----------------------------------------------------------

AC_DATA_CONFIG = {
    "db": {"connection_identity": "host=db-ac;db=erp;user=ro_scan",
           "read_only": True, "diff_direction": "actual_vs_expected"},
}

AC_DB_ID = AC_DATA_CONFIG["db"]


def _mk_manifest(run_id, *, data_config=None, now=None):
    now = now or _utc_now()
    planner = BugscanPlanner(default_registry())
    plan = planner.plan("STANDARD")
    return planner.freeze_run_manifest(
        plan, run_id=run_id, project_id="wenqu-ac-station-families",
        commit_sha="e" * 40, environment="local",
        scope=["src/**", "tests/**"],
        ruleset={"version": "ac-tests", "rules": ["W6A-ST2", "W6A-ST3",
                                                  "W6A-ST4", "W6A-ST7"]},
        data_config=data_config if data_config is not None else {"profile": "default"},
        now=now,
    ), now


def _mk_st3(data_config=None):
    """返回 (contract, ts)：manifest 冻结 + 站3 总适配（now 固定防 TTL 误伤）。"""
    manifest, now = _mk_manifest(_next_run_id("st3"), data_config=data_config)
    return Station3Contract(manifest, now=now), manifest.frozen_at


def _drift_payload(ts, *, db_identity=None, data_config=None, objects_total=3,
                   objects_scanned=None, changes=(), allowlist=(), **extra):
    payload = {
        "tool": {"name": "judge_drift.py", "version": "ac"},
        "started_at": ts, "ended_at": ts,
        "db_identity": dict(db_identity or AC_DB_ID),
        "objects_total": objects_total,
        "objects_scanned": objects_total if objects_scanned is None else objects_scanned,
        # 注：非 list/tuple 的 changes 原样透传（DB-03 未知格式注入需要）
        "changes": [dict(c) for c in changes]
        if isinstance(changes, (list, tuple)) else changes,
    }
    if data_config is not None:
        payload["data_config"] = data_config
    if isinstance(allowlist, (list, tuple)) and allowlist:
        payload["allowlist"] = [dict(a) for a in allowlist]
    payload.update(extra)
    return payload


def _og_payload(ts, endpoints, *, principals=None):
    payload = {
        "tool": {"name": "org-guard", "version": "ac"},
        "started_at": ts, "ended_at": ts,
        "probe_identity": principals or {
            "base_url": "http://app.local",
            "positive_principal": "orgA/alice",
            "negative_principal": "orgB/mallory",
        },
        "endpoints": endpoints,
    }
    return payload


def _ep(method, path, positive_outcome, negative_outcome, **extra):
    ep = {
        "method": method, "path": path,
        "positive": {"executed": True, "outcome": positive_outcome},
        "negative": {"executed": True, "outcome": negative_outcome},
    }
    ep.update(extra)
    return ep


def _http_server(handler_cls):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class _SilenceHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # 静音
        pass


class _OkHandler(_SilenceHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


class _Fast500Handler(_SilenceHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(500)  # 立即回 500——「HTTP 500 但很快」
        self.end_headers()
        self.wfile.write(b"boom")


FAKE_VITEST_SRC = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "args = sys.argv[1:]\n"
    "out = [a for a in args if a.startswith('--outputFile=')][0].split('=', 1)[1]\n"
    "tests_dir = [a for a in args if not a.startswith('-')][0]\n"
    "limit = int(next((a.split('=', 1)[1] for a in args if a.startswith('--limit=')), '0'))\n"
    "root = (Path.cwd() / tests_dir).resolve()\n"
    "files = sorted(p for p in root.rglob('*.test.ts'))\n"
    "if limit:\n"
    "    files = files[:limit]\n"
    "results = [{'name': str(f), 'status': 'passed'} for f in files]\n"
    "Path(out).write_text(json.dumps({'success': True, 'testResults': results}))\n"
)


# ---------------------------------------------------------------------------
# STA 族——站点结果/整线聚合（统一入口语义：bugscan_orchestrator + 各站）
# ---------------------------------------------------------------------------

def test_STA_01_any_station_denominator_shrink_blocks_line():
    """STA-01｜注入：任一站 denominator 缩小｜期望：整线 BLOCKED。

    三层机械语义各断言一次：
    (a) 统一入口 build_station_result：scanned<denominator → 强制
        BLOCKED/NOT_EVALUATED（调用方即便自报 COMPLETED/PASS 也被改写）；
    (b) validate_station_result：缩水+PASS 的手造结果必被拒（防旁路）；
    (c) 站2 整线：engine 删卡（五类宇宙分母 5、实际 4）→ 该子件 BLOCKED →
        站级聚合 coverage 3/4 → 整线 BLOCKED。
    """
    ident = dict(ST2_IDENTITY)
    base_exec = {
        "argv_digest": _argv_digest(["ac", "sta01"]),
        "started_at": _iso_z(_utc_now()), "ended_at": _iso_z(_utc_now()),
        "actual_exit_code": 0, "expected_exit_set": [0],
        "assertion_verdict": "PASS",
    }
    # (a) 统一守卫：站4/站7 任一站缩水一律折叠 BLOCKED
    for sid in (2, 4, 7):
        forced = build_station_result(
            run_id="ac-sta01", station_id=sid, attempt_id="att-sta01",
            execution_status="COMPLETED", policy_verdict="PASS",
            identity=ident, tool={"name": "ac", "version": "1"},
            execution=base_exec,
            coverage={"denominator": 5, "scanned": 3},
        )
        assert forced["execution_status"] == "BLOCKED", forced
        assert forced["policy_verdict"] == "NOT_EVALUATED", forced
        validate_station_result(forced)
    # (b) 防旁路：结构合法但「缩水+PASS」的结果过不了校验器
    #     （schema：COMPLETED+PASS 必须携带非空 artifacts——模板对齐真实契约）
    green = build_station_result(
        run_id="ac-sta01", station_id=3, attempt_id="att-sta01",
        execution_status="COMPLETED", policy_verdict="PASS",
        identity=ident, tool={"name": "ac", "version": "1"},
        execution=base_exec, coverage={"denominator": 5, "scanned": 5},
        artifacts=[{"cas_digest": f"sha256:{'0' * 64}", "size": 1}],
    )
    shrunk = dict(green)
    shrunk["coverage"] = {"denominator": 5, "scanned": 4}
    try:
        validate_station_result(shrunk)
        raise AssertionError("shrink+PASS must be rejected by validator")
    except StationResultValidationError as exc:
        assert "coverage shrink" in str(exc), exc
    # (c) 站2 整线：engine 宇宙缩水（缺 msg 卡）→ 整线 BLOCKED
    with tempfile.TemporaryDirectory() as tmp:
        repo = _mk_st2_repo(tmp)
        engine_state = repo.parent / "engine-state.json"
        engine_state.write_text(json.dumps(_engine_cards(drop="msg")),
                                encoding="utf-8")
        baseline = repo.parent / "baseline.json"
        baseline.write_text('{"clone_pairs": 1, "duplicated_lines": 10}',
                            encoding="utf-8")
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"],
             lambda a: (_ev(a, 0), _j(NPM_CLEAN), b"")),
            (lambda a: a[0] == "npx", _jscpd_respond(JSCPD_REPORT)),
            (lambda a: a[0] == "route-probe", lambda a: (_ev(a, 0), b"", b"")),
        ])
        report = Station2Static(
            _next_run_id("sta1"), identity=ST2_IDENTITY, repo_dir=str(repo),
            runner=runner, baseline_path=str(baseline),
            engine_state_path=str(engine_state),
            route_probe_argv=["route-probe", "--static"],
        ).scan()
        agg = report["station_result"]
        engine_sub = report["scanner_results"]["engine"]
        assert engine_sub["execution_status"] == "BLOCKED", engine_sub
        assert engine_sub["coverage"]["scanned"] == 4 \
            < engine_sub["coverage"]["denominator"] == 5
        assert agg["execution_status"] == "BLOCKED", agg
        assert agg["policy_verdict"] == "NOT_EVALUATED", agg
        assert agg["coverage"]["scanned"] == 3 < agg["coverage"]["denominator"] == 4
        validate_station_result(agg)


def test_STA_02_per_station_fault_keeps_evidence_aggregate_blocked():
    """STA-02｜注入：站2/3/4/7 逐站故障｜期望：继续独立取证，aggregate BLOCKED。

    对四个站各注入一处「单件故障」，断言：
    - 故障件的细粒度结果保留（独立取证不丢）；
    - 健康件照常完成并留证；
    - 站级/整站聚合 execution_status == BLOCKED（绝不记 PASS）。
    """
    # ---- 站2：supply 空输出=ERROR 子件，其余三件全绿 ----
    with tempfile.TemporaryDirectory() as tmp:
        repo = _mk_st2_repo(tmp)
        engine_state = repo.parent / "engine-state.json"
        engine_state.write_text(json.dumps(_engine_cards()), encoding="utf-8")
        baseline = repo.parent / "baseline.json"
        baseline.write_text('{"clone_pairs": 1, "duplicated_lines": 10}',
                            encoding="utf-8")
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"], lambda a: (_ev(a, 0), b"", b"")),
            (lambda a: a[0] == "npx", _jscpd_respond(JSCPD_REPORT)),
            (lambda a: a[0] == "route-probe", lambda a: (_ev(a, 0), b"", b"")),
        ])
        report = Station2Static(
            _next_run_id("sta2"), identity=ST2_IDENTITY, repo_dir=str(repo),
            runner=runner, baseline_path=str(baseline),
            engine_state_path=str(engine_state),
            route_probe_argv=["route-probe", "--static"],
        ).scan()
        subs = report["scanner_results"]
        assert set(subs) == {"supply", "dupscan", "engine", "route"}
        assert subs["supply"]["execution_status"] == "ERROR", subs["supply"]
        assert "supply" in report["notes"]
        for slug in ("dupscan", "engine", "route"):
            assert subs[slug]["execution_status"] == "COMPLETED", (slug, subs[slug])
            assert subs[slug]["policy_verdict"] == "PASS", (slug, subs[slug])
            validate_station_result(subs[slug])
        agg = report["station_result"]
        assert agg["execution_status"] == "BLOCKED", agg
        assert agg["policy_verdict"] == "NOT_EVALUATED", agg
        assert agg["coverage"]["scanned"] == 3 < agg["coverage"]["denominator"] == 4

    # ---- 站3：db_drift 分母缩水（DMMF 模型数>监控面）→ 组件 BLOCKED，聚合 BLOCKED ----
    dmmf = {"datamodel": {"models": [{"name": m} for m in
                                     ("Order", "User", "Invoice", "Tenant", "Audit")]}}
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    final = contract.run(
        openapi={"tool": {"name": "openapi-reconciler", "version": "ac"},
                 "started_at": ts, "ended_at": ts,
                 "openapi_spec": {"openapi": "3.0.0", "paths": {
                     "/api/orders": {"get": {"responses": {}}}}},
                 "actual_routes": [{"method": "GET", "path": "/api/orders"}]},
        db_drift=_drift_payload(ts, changes=[], prisma_dmmf=dmmf),
    )
    assert final["execution_status"] == "BLOCKED", final
    assert final["policy_verdict"] == "NOT_EVALUATED", final
    components = final["coverage"]
    assert components["scanned"] < components["denominator"]
    assert len(contract.last_component_results) == 2  # 独立取证保留
    oa_sub, db_sub = contract.last_component_results  # 组件顺序：openapi→db_drift
    assert db_sub["coverage"]["denominator"] == 5 and \
        db_sub["coverage"]["scanned"] == 3  # DMMF 下限抬高动态分母
    assert oa_sub["policy_verdict"] == "PASS", oa_sub
    validate_station_result(db_sub), validate_station_result(oa_sub)

    # ---- 站4：e2e 腿缩水（3 文件只执行 2）BLOCKED + 路由腿 PASS → 合并 BLOCKED ----
    manifest, _ = _mk_manifest(_next_run_id("st4"))
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        repo = tmpdir / "repo"
        (repo / "tests").mkdir(parents=True)
        for name in ("a.test.ts", "b.test.ts", "c.test.ts"):
            (repo / "tests" / name).write_text("// fake e2e\n", encoding="utf-8")
        fake_vitest = tmpdir / "fake_vitest.py"
        fake_vitest.write_text(FAKE_VITEST_SRC, encoding="utf-8")
        server = _http_server(_OkHandler)
        try:
            base_url = f"http://127.0.0.1:{server.server_address[1]}"
            e2e_leg = E2eScanner(
                manifest, repo_root=str(repo),
                runner=TrustedRunner(default_cwd=str(repo), timeout=60.0),
                vitest_argv=[sys.executable, str(fake_vitest),
                             "--outputFile={output_file}", "{tests_dir}", "--limit=2"],
                timeout_s=60,
            ).scan()
            route_leg = RouteDynamicScanner(
                manifest,
                routes=[{"name": "home", "method": "GET", "path": "/",
                         "expected_status": 200}],
                base_url=base_url,
            ).scan()
            validate_station_result(e2e_leg)
            validate_station_result(route_leg)
            assert e2e_leg["execution_status"] == "BLOCKED", e2e_leg
            assert e2e_leg["coverage"]["scanned"] == 2 \
                < e2e_leg["coverage"]["denominator"] == 3
            assert route_leg["policy_verdict"] == "PASS", route_leg
            combined = combine_station4_results([e2e_leg, route_leg])
            assert combined["execution_status"] == "BLOCKED", combined
            assert combined["policy_verdict"] == "NOT_EVALUATED", combined
            assert combined["coverage"]["scanned"] == 3 \
                < combined["coverage"]["denominator"] == 4
        finally:
            server.shutdown()
            server.server_close()

    # ---- 站7：哨兵探针不可读 BLOCKED + SLO 腿 PASS → 合并 BLOCKED ----
    manifest, _ = _mk_manifest(_next_run_id("st7"))
    now = _utc_now()
    with tempfile.TemporaryDirectory() as tmp:
        dead_probe = Path(tmp) / "no-such-heartbeat.json"
        sentinel_leg = SentinelHealthScanner(
            manifest,
            sentinels=[{"name": "argus", "kind": "heartbeat_json",
                        "path": str(dead_probe), "freshness_s": 300}],
            now=now,
        ).scan()
        slo_leg = SloMonitorScanner(
            manifest,
            slos=[{"name": "availability", "target": 0.999, "op": ">="},
                  {"name": "p95_latency_ms", "target": 800, "op": "<="}],
            snapshot={"availability": 0.9995, "p95_latency_ms": 640.0},
            now=now,
        ).scan()
        validate_station_result(sentinel_leg)
        validate_station_result(slo_leg)
        assert sentinel_leg["execution_status"] == "BLOCKED", sentinel_leg
        assert slo_leg["policy_verdict"] == "PASS", slo_leg
        combined = combine_station7_results([sentinel_leg, slo_leg])
        assert combined["execution_status"] == "BLOCKED", combined
        assert combined["policy_verdict"] == "NOT_EVALUATED", combined


# ---------------------------------------------------------------------------
# DB 族——目录漂移（station3.DbDriftScanner / judge_drift 报告消费面）
# ---------------------------------------------------------------------------

def test_DB_01_all_change_directions_recognized():
    """DB-01｜注入：[+]/[-]/[*]｜期望：全识别。

    注入面映射说明：judge_drift 的方向标记在本适配器契约里对应 change_type
    分类——[+]=新增类（CREATE/COLUMN_ADD）、[-]=删除类（COLUMN_DROP/TABLE_DROP/
    DROP）、[*]=修改类（ALTER/MODIFY/RENAME）。断言：
    - 九个方向各投一条 change → 恰好 9 条 finding（一条不漏=全识别）；
    - 未知 change_type 不被丢弃且定级 HIGH（fail-closed 最坏处理）；
    - 方向→严重级映射正源（DROP 类=HIGH）不被稀释。
    """
    assert DRIFT_CHANGE_SEVERITY["COLUMN_DROP"] == "HIGH"
    assert DRIFT_CHANGE_SEVERITY["TABLE_DROP"] == "HIGH"
    assert DRIFT_CHANGE_SEVERITY["DROP"] == "HIGH"
    assert DRIFT_CHANGE_SEVERITY["CREATE"] == "MEDIUM"
    assert DRIFT_CHANGE_SEVERITY["COLUMN_ADD"] == "MEDIUM"
    assert DRIFT_CHANGE_SEVERITY["ALTER"] == "MEDIUM"
    assert DRIFT_CHANGE_SEVERITY["MODIFY"] == "MEDIUM"
    assert DRIFT_CHANGE_SEVERITY["RENAME"] == "LOW"
    assert UNKNOWN_CHANGE_SEVERITY == "HIGH"
    changes = [
        {"object": "public.orders", "change_type": "CREATE"},          # [+]
        {"object": "public.users", "change_type": "COLUMN_ADD"},       # [+]
        {"object": "public.orders", "change_type": "COLUMN_DROP"},     # [-]
        {"object": "public.audit_log", "change_type": "TABLE_DROP"},   # [-]
        {"object": "public.orders_fk_users", "change_type": "DROP"},   # [-]
        {"object": "public.invoices", "change_type": "ALTER"},         # [*]
        {"object": "public.settings", "change_type": "MODIFY"},        # [*]
        {"object": "public.tenants", "change_type": "RENAME"},         # [*]
        {"object": "public.weird", "change_type": "SOMETHING_ELSE"},   # 未知
    ]
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    st = contract.db_drift_scanner().adapt(
        _drift_payload(ts, objects_total=9, changes=changes))
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL", st
    assert st["execution_status"] == "COMPLETED"
    assert len(st["finding_ids"]) == 9, st["finding_ids"]  # 全识别：9 投 9 中
    assert st["coverage"] == {"denominator": 9, "scanned": 9}
    # 未知类型也产出独立 finding（含对象名），不静默吞掉
    assert any("weird" in fid for fid in st["finding_ids"]), st["finding_ids"]


def test_DB_02_single_drop_column_or_fk_still_fails():
    """DB-02｜注入：仅一条 DROP COLUMN/删 FK｜期望：FAIL，不因数量少放行。

    两条独立注入：单条 COLUMN_DROP；单条 FK 删除（约束对象 DROP）。
    各自必须 FAIL 且恰 1 条 finding（exit 1=发现落账语义），绝不 PASS。
    """
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    for change in (
        {"object": "public.orders", "change_type": "COLUMN_DROP",
         "expected_hash": "a" * 64},
        {"object": "public.orders_fk_users", "change_type": "DROP",
         "expected_hash": "b" * 64},
    ):
        st = contract.db_drift_scanner().adapt(
            _drift_payload(ts, changes=[change]))
        validate_station_result(st)
        assert st["policy_verdict"] == "FAIL", (change, st)
        assert st["execution_status"] == "COMPLETED"
        assert len(st["finding_ids"]) == 1, st["finding_ids"]
        assert st["execution"]["actual_exit_code"] == 1  # 有发现→落账退出码


def test_DB_03_unknown_format_empty_output_rejected():
    """DB-03｜注入：未知格式/空输出/命令非零｜期望：ERROR。

    适配器 fail-closed 语义=畸形载荷直接拒绝（抛 DriftReportMalformed/
    ContractPayloadMalformed），不产出任何结果——ERROR 类且绝不折算 PASS。
    - 未知格式：changes 非列表 / 条目缺 change_type / hash 非 64hex；
    - 空输出：空载荷/缺必备字段（judge_drift 命令非零→无有效产物，走同一
      拒绝面——本包适配器不执行命令，该子注入与空输出同型，属契约边界）。
    """
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    scanner = contract.db_drift_scanner()
    bad_payloads = [
        _drift_payload(ts, changes="not-a-list"),                       # 未知格式
        _drift_payload(ts, changes=[{"object": "public.orders"}]),      # 缺 change_type
        _drift_payload(ts, changes=[{"object": "public.orders",
                                     "change_type": "DROP",
                                     "expected_hash": "zz"}]),          # hash 非 64hex
        _drift_payload(ts, objects_total=0),                            # 分母非法
        {},                                                             # 空输出
    ]
    for bad in bad_payloads:
        try:
            scanner.adapt(bad)
            raise AssertionError(f"malformed payload must be rejected: {bad!r}")
        except (DriftReportMalformed, ContractPayloadMalformed):
            pass


def test_DB_04_allowlist_expiry_or_hash_change_fails():
    """DB-04｜注入：allowlist 到期/对象 hash 变化｜期望：FAIL。

    - 白名单条目已过期（expires_at < now）→ 条目无效 → 漂移照常 FAIL；
    - 对象内容 hash 变化（content_hash ≠ 漂移绑定 hash）→ 三绑定不中 → FAIL；
    - 对照组：identity+hash+未过期全中 → 受治理漂移不落 finding（PASS）；
    - 到期晚于 now+30d 日落窗 → 条目本身非法（AllowlistEntryInvalid）。
    """
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    now = _utc_now()
    drop = {"object": "public.orders", "change_type": "DROP",
            "expected_hash": "a" * 64}
    fresh = {"object_identity": "public.orders", "content_hash": "a" * 64,
             "expires_at": _iso_z(now + timedelta(days=7)),
             "approver": "dba-owner", "reason": "归档下线已审批"}
    expired = dict(fresh, expires_at=_iso_z(now - timedelta(days=1)))
    hash_changed = dict(fresh, content_hash="c" * 64)

    st = contract.db_drift_scanner().adapt(
        _drift_payload(ts, changes=[drop], allowlist=[fresh]))
    assert st["policy_verdict"] == "PASS" and not st["finding_ids"], st  # 对照

    st = contract.db_drift_scanner().adapt(
        _drift_payload(ts, changes=[drop], allowlist=[expired]))
    assert st["policy_verdict"] == "FAIL", st  # 到期=无效
    assert len(st["finding_ids"]) == 1

    st = contract.db_drift_scanner().adapt(
        _drift_payload(ts, changes=[drop], allowlist=[hash_changed]))
    assert st["policy_verdict"] == "FAIL", st  # 对象 hash 变化=不匹配
    assert len(st["finding_ids"]) == 1

    beyond = dict(fresh, expires_at=_iso_z(now + timedelta(days=90)))
    try:
        contract.db_drift_scanner().adapt(
            _drift_payload(ts, changes=[drop], allowlist=[beyond]))
        raise AssertionError("beyond-30d sunset must be rejected")
    except AllowlistEntryInvalid:
        pass


def test_DB_05_wrong_db_role_or_writable_source_blocked():
    """DB-05｜注入：错 DB/role/transaction_read_only=off｜期望：BLOCKED。

    本发行包的等价机械语义：证据身份绑定失败 → 适配器 fail-closed 抛错、
    拒绝产出任何结果（含 PASS）——BLOCKED 的最强形态（铁律：绝不带可写/
    异库身份出账）。四路注入：
    - read_only=False（=transaction_read_only off）→ NonReadOnlyDataSource；
    - data_config 与冻结 manifest 不一致（错 DB/配置漂移）→ EvidenceIdentityMismatch；
    - diff_direction 非法（翻向证据不可混用）→ DriftReportMalformed；
    - connection_identity 疑似带凭据 → 证据身份拒绝入库。
    """
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    drift_ok = _drift_payload(ts, changes=[])

    try:
        contract.db_drift_scanner().adapt(_drift_payload(
            ts, db_identity=dict(AC_DB_ID, read_only=False)))
        raise AssertionError("writable identity must be refused")
    except NonReadOnlyDataSource:
        pass

    try:
        contract.db_drift_scanner().adapt(_drift_payload(
            ts, data_config={"db": {"connection_identity": "host=other;db=wrong"}}))
        raise AssertionError("data_config mismatch must be refused")
    except EvidenceIdentityMismatch:
        pass

    try:
        contract.db_drift_scanner().adapt(_drift_payload(
            ts, db_identity=dict(AC_DB_ID, diff_direction="reversed")))
        raise AssertionError("unknown diff direction must be refused")
    except DriftReportMalformed:
        pass

    try:
        contract.db_drift_scanner().adapt(_drift_payload(
            ts, db_identity=dict(AC_DB_ID,
                                 connection_identity="host=db;user=u;password=x")))
        raise AssertionError("credential-ish identity must be refused")
    except DriftReportMalformed:
        pass

    # 对照：只读+方向合法+data_config 一致 → 正常出结果（无阻断）
    st = contract.db_drift_scanner().adapt(drift_ok)
    assert st["policy_verdict"] == "PASS", st


def test_DB_06_golden_normalization_order_canonical():
    """DB-06｜注入：catalog 顺序、默认表达式、extension 对象｜期望：golden 规范化正确。

    覆盖边界（诚实声明）：默认表达式/extension 对象的 golden 规范化属
    judge_drift.py（上游工具，不在本发行包）；本包可测的规范化面为证据
    绑定链的 canonical 归一：
    - 成员（键）顺序无关：_hash_obj 对键序规范化，catalog 打乱顺序摘要不变；
    - 确定性：同内容重复计算摘要稳定；
    - 受监控对象全集必须是去重集合（重复 identity=golden 自相矛盾→拒绝）。
    """
    a = {"connection_identity": "host=db-ac;db=erp;user=ro_scan",
         "read_only": True, "diff_direction": "actual_vs_expected"}
    b = {k: a[k] for k in reversed(list(a))}  # 键序打乱
    assert _hash_obj(a) == _hash_obj(b)
    assert _hash_obj(a) == _hash_obj(a)  # 确定性

    contract, ts = _mk_st3(AC_DATA_CONFIG)
    st1 = contract.db_drift_scanner().adapt(_drift_payload(ts, changes=[]))
    # db_identity 键序不同的等价载荷 → 结果 coverage/verdict 一致（规范化无漂移）
    st2 = contract.db_drift_scanner().adapt(_drift_payload(
        ts, db_identity={k: AC_DB_ID[k] for k in reversed(list(AC_DB_ID))},
        changes=[]))
    assert st1["policy_verdict"] == st2["policy_verdict"] == "PASS"
    assert st1["coverage"] == st2["coverage"]

    try:
        contract.db_drift_scanner().adapt(_drift_payload(
            ts, objects_total=2,
            expected_objects=["public.orders", "public.orders"]))
        raise AssertionError("duplicate expected_objects must be rejected")
    except DriftReportMalformed:
        pass


# ---------------------------------------------------------------------------
# SC 族——供应链（station2.SupplyChainScanner：npm audit 适配）
# ---------------------------------------------------------------------------

def _supply_scan(tmp_path, payload_bytes, rc=1):
    repo = Path(tmp_path)
    repo.mkdir(parents=True, exist_ok=True)
    runner = _StubRunner([
        (lambda a: a[:2] == ["npm", "audit"],
         lambda a: (_ev(a, rc), payload_bytes, b"")),
    ])
    return SupplyChainScanner(runner=runner, run_id=_next_run_id("sc"),
                              identity=ST2_IDENTITY, repo_dir=str(repo)).scan()


def _lockfile_v3(*entries):
    """合成 package-lock v3：entries=(name, resolved, integrity, has_script)。"""
    packages = {"": {"name": "app", "version": "1.0.0", "lockfileVersion": 3}}
    for name, resolved, integrity, script in entries:
        entry = {"version": "1.0.0"}
        if resolved is not None:
            entry["resolved"] = resolved
        if integrity is not None:
            entry["integrity"] = integrity
        if script:
            entry["hasInstallScript"] = True
        packages[f"node_modules/{name}"] = entry
    return {"name": "app", "lockfileVersion": 3, "packages": packages}


def test_SC_01_valid_json_high_critical_fails():
    """SC-01｜注入：有效 JSON+HIGH/CRITICAL｜期望：FAIL。

    有效 JSON 载荷含 HIGH 与 CRITICAL 漏洞 → FAIL；findings 计数取解析列表
    （非自报数字）；HIGH→P1、CRITICAL→P0 不降级；coverage 分母=metadata 自报
    依赖总数（合法分母正源）。
    """
    payload = _npm_vulns([
        ("lodash", "high", "<4.17.21", "Prototype Pollution"),
        ("minimist", "critical", "<1.2.6", "Prototype Pollution"),
        ("qs", "moderate", ">=6.0.0 <6.0.4", "DoS"),
    ])
    with tempfile.TemporaryDirectory() as tmp:
        rep = _supply_scan(tmp, _j(payload))
        validate_station_result(rep.result)
        assert rep.result["policy_verdict"] == "FAIL", rep.result
        assert rep.result["execution_status"] == "COMPLETED"
        assert len(rep.findings) == 3  # 解析列表为正源（含 moderate 也落账）
        highs = [f for f in rep.findings if f.severity == "HIGH"]
        crits = [f for f in rep.findings if f.severity == "CRITICAL"]
        assert len(highs) == 1 and highs[0].priority == "P1"
        assert len(crits) == 1 and crits[0].priority == "P0"
        assert rep.result["finding_ids"] == [f.finding_id for f in rep.findings]


def test_SC_02_empty_json_or_registry_timeout_error():
    """SC-02｜注入：空 JSON/registry 超时｜期望：ERROR。

    - 空输出 → ERROR（T-07：空输出≠零发现）；
    - registry 超时（Evidence.timed_out）→ TIMEOUT/退出码 124（ERROR 类，
      绝不折算 PASS）；
    - npm exit ≥2（registry 不可达等环境错）→ ERROR。
    """
    with tempfile.TemporaryDirectory() as tmp:
        rep = _supply_scan(tmp, b"", rc=0)  # 空输出
        assert rep.result["execution_status"] == "ERROR", rep.result
        assert rep.result["policy_verdict"] == "NOT_EVALUATED"
        assert "empty" in rep.note, rep.note
        validate_station_result(rep.result)

        repo = Path(tmp)
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"],
             lambda a: (_ev_timeout(a), b"", b"")),
        ])
        rep = SupplyChainScanner(runner=runner, run_id=_next_run_id("sc"),
                                 identity=ST2_IDENTITY,
                                 repo_dir=str(repo)).scan()
        assert rep.result["execution_status"] == "TIMEOUT", rep.result
        assert rep.result["execution"]["actual_exit_code"] == 124
        assert rep.result["policy_verdict"] == "NOT_EVALUATED"
        validate_station_result(rep.result)

        rep = _supply_scan(tmp, b"network unreachable", rc=2)  # registry 环境错
        assert rep.result["execution_status"] == "ERROR", rep.result
        assert "exit code 2" in rep.note, rep.note
        validate_station_result(rep.result)


def test_SC_03_lockfile_diff_added_deps_counted():
    """SC-03｜注入：install script/resolved/integrity 变化｜期望：FAIL/人工审。

    站2 供应链扫描器 lockfile 变更差异分析面（合成 lockfile fixture 真实断言）：
    - diff 纯函数 aspect 语义：新增/resolved 变化/integrity 变化/新增 install
      script 各成独立变化位；同一包多 aspect 同时变化逐位落账；
    - 扫描面：新增依赖单独计入发现与分母（denominator=metadata 自报依赖总数
      +新增数）；每个变化位一条 HIGH/P1 finding（人工审语义=FAIL 落账）；
    - 对照负例：lockfile 完全一致 → 零 finding PASS、分母不加（探测器不对
      噪声开火）；基线缺失 → 无锚点 fail-closed ERROR。
    """
    baseline = _lockfile_v3(
        ("lodash", "https://registry/lodash/-/lodash-4.17.20.tgz",
         "sha512-" + "a" * 64, False),
        ("qs", "https://registry/qs.tgz", "sha512-" + "b" * 64, False),
        ("minimist", "https://registry/minimist.tgz", "sha512-" + "e" * 64, False),
    )
    current = _lockfile_v3(
        # lodash：resolved 变化 + integrity 变化 + 新增 install script（三位全变）
        ("lodash", "https://evil-mirror.example/lodash-4.17.21.tgz",
         "sha512-" + "c" * 64, True),
        ("qs", "https://registry/qs.tgz", "sha512-" + "b" * 64, False),
        ("newdep", "https://registry/newdep.tgz", "sha512-" + "d" * 64, False),
    )

    # diff 纯函数：aspect 级语义正源
    base_deps = SupplyChainScanner.parse_lockfile_dependencies(baseline)
    cur_deps = SupplyChainScanner.parse_lockfile_dependencies(current)
    assert set(base_deps) == {"lodash", "qs", "minimist"}
    diff = SupplyChainScanner.diff_lockfile_dependencies(base_deps, cur_deps)
    assert diff["added"] == ["newdep"], diff
    assert diff["removed"] == ["minimist"], diff
    assert [(c["name"], c["aspect"]) for c in diff["changes"]] == [
        ("lodash", "resolved"), ("lodash", "integrity"),
        ("lodash", "install_script"),
    ], diff["changes"]

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        (repo / "package-lock.json").write_text(json.dumps(current), encoding="utf-8")
        baseline_path = Path(tmp) / "baseline-lock.json"
        baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"],
             lambda a: (_ev(a, 0), _j(NPM_CLEAN), b"")),  # audit 自身零漏洞
        ])
        rep = SupplyChainScanner(
            runner=runner, run_id=_next_run_id("sc3"), identity=ST2_IDENTITY,
            repo_dir=str(repo), lockfile_baseline_path=str(baseline_path),
        ).scan()
        validate_station_result(rep.result)
        assert rep.result["policy_verdict"] == "FAIL", rep.result  # FAIL/人工审
        assert rep.result["execution_status"] == "COMPLETED"
        assert len(rep.findings) == 4, rep.findings  # 新增 1 + 三 aspect 位 3
        rules = sorted(f.rule_id for f in rep.findings)
        assert rules == [
            "supply/lockfile-diff-added",
            "supply/lockfile-diff-install_script",
            "supply/lockfile-diff-integrity",
            "supply/lockfile-diff-resolved",
        ], rules
        assert all(f.severity == "HIGH" and f.priority == "P1" for f in rep.findings)
        # 新增依赖单独计入分母：12（audit 自报总数）+1（newdep）=13
        assert rep.result["coverage"] == {"denominator": 13, "scanned": 13}
        assert "minimist" in rep.note, rep.note  # 移除依赖只入 note 不计分母

        # 对照：完全一致的 lockfile → PASS，分母不加、零 finding
        (repo / "package-lock.json").write_text(json.dumps(baseline), encoding="utf-8")
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"],
             lambda a: (_ev(a, 0), _j(NPM_CLEAN), b"")),
        ])
        rep = SupplyChainScanner(
            runner=runner, run_id=_next_run_id("sc3"), identity=ST2_IDENTITY,
            repo_dir=str(repo), lockfile_baseline_path=str(baseline_path),
        ).scan()
        validate_station_result(rep.result)
        assert rep.result["policy_verdict"] == "PASS", rep.result
        assert rep.result["coverage"] == {"denominator": 12, "scanned": 12}

        # 负例：基线缺失 → 无锚点 fail-closed ERROR（绝不 PASS）
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"],
             lambda a: (_ev(a, 0), _j(NPM_CLEAN), b"")),
        ])
        rep = SupplyChainScanner(
            runner=runner, run_id=_next_run_id("sc3"), identity=ST2_IDENTITY,
            repo_dir=str(repo),
            lockfile_baseline_path=str(Path(tmp) / "absent-lock.json"),
        ).scan()
        assert rep.result["execution_status"] == "ERROR", rep.result
        assert rep.result["policy_verdict"] == "NOT_EVALUATED"
        assert "anchor" in rep.note, rep.note


def test_SC_04_skip_audit_title_no_bypass():
    """SC-04｜注入：标题含 [skip-audit]｜期望：无绕过效果。

    漏洞条目标题（via[0].title）带 [skip-audit] 标记 → 判定矩阵不变：
    仍 FAIL、finding 照常落账；站2 聚合层同样 FAIL——标题标记零旁路效果。
    """
    payload = _npm_vulns([
        ("lodash", "high", "<4.17.21", "[skip-audit] Prototype Pollution"),
    ])
    with tempfile.TemporaryDirectory() as tmp:
        rep = _supply_scan(tmp, _j(payload))
        assert rep.result["policy_verdict"] == "FAIL", rep.result
        assert len(rep.findings) == 1
        assert rep.findings[0].severity == "HIGH"
        assert "[skip-audit]" in rep.findings[0].message, rep.findings[0].message
        validate_station_result(rep.result)

        repo = _mk_st2_repo(tmp)
        runner = _StubRunner([
            (lambda a: a[:2] == ["npm", "audit"],
             lambda a: (_ev(a, 1), _j(payload), b"")),
        ])
        report = Station2Static(
            _next_run_id("sc4"), identity=ST2_IDENTITY, repo_dir=str(repo),
            runner=runner, scanners=("supply",),
        ).scan()
        agg = report["station_result"]
        assert agg["policy_verdict"] == "FAIL", agg  # 聚合层同样无绕过
        assert agg["coverage"]["denominator"] == 1 and agg["coverage"]["scanned"] == 1
        assert "dupscan" in agg["coverage"]["exclusions"]  # 显式缩件记账


def test_SC_05_snapshot_signature_freshness_fail_closed():
    """SC-05｜注入：离线快照签名错误/过期/分页不全｜期望：BLOCKED。

    依赖基线快照（npm audit 载荷的离线信封）签名+时效校验面：
    - 合法信封（build_snapshot_envelope 真实签名通道生产，现场时间戳）→
      正常解析判定 PASS（校验面不误伤真源）；
    - 过期（8 天前捕获、签名本身合法）→ 该源数据不可用 → BLOCKED；
    - 签名错误（同 hash/时间戳、换签名）→ BLOCKED；
    - 载荷被改（content_hash 失配=签名后篡改）→ BLOCKED；
    - 无信封裸 JSON（未签名源）→ BLOCKED。
    全部失败路径 coverage 记 0/0（未验签内容连 metadata 分母都不采信）、
    NOT_EVALUATED、原因入 note——fail-closed，绝不折算 PASS。
    （『分页不全』子面沿用 ADV-02 的自报计数交叉核对机制=证据损坏 ERROR。）
    """
    key = "ac-snapshot-key"
    now = _utc_now()
    fresh = build_snapshot_envelope(NPM_CLEAN, key=key, captured_at=now)
    stale = build_snapshot_envelope(
        NPM_CLEAN, key=key, captured_at=now - timedelta(days=8))
    bad_sig = json.loads(json.dumps(fresh))
    bad_sig["snapshot"]["signature"] = "0" * 64
    tampered = json.loads(json.dumps(fresh))
    tampered["payload"]["metadata"]["dependencies"]["total"] = 999  # 签名后篡改

    def _scan(envelope):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp).mkdir(parents=True, exist_ok=True)
            runner = _StubRunner([
                (lambda a: a[:2] == ["npm", "audit"],
                 lambda a: (_ev(a, 0), _j(envelope), b"")),
            ])
            return SupplyChainScanner(
                runner=runner, run_id=_next_run_id("sc5"), identity=ST2_IDENTITY,
                repo_dir=str(tmp),
                snapshot_verify_key=key,
            ).scan()

    rep = _scan(fresh)
    validate_station_result(rep.result)
    assert rep.result["policy_verdict"] == "PASS", rep.result  # 真源不误伤
    assert rep.result["coverage"] == {"denominator": 12, "scanned": 12}
    assert "verified snapshot" in rep.note, rep.note

    cases = (
        ("expired", stale, "expired"),
        ("bad-signature", bad_sig, "signature verification failed"),
        ("tampered-payload", tampered, "content_hash mismatch"),
        ("unsigned-raw", NPM_CLEAN, "missing 'snapshot'"),
    )
    for name, envelope, marker in cases:
        rep = _scan(envelope)
        validate_station_result(rep.result)
        assert rep.result["execution_status"] == "BLOCKED", (name, rep.result)
        assert rep.result["policy_verdict"] == "NOT_EVALUATED", (name, rep.result)
        assert rep.result["coverage"] == {"denominator": 0, "scanned": 0}, (
            name, rep.result["coverage"])
        assert marker in rep.note, (name, rep.note)


# ---------------------------------------------------------------------------
# ADV 族——advisory/公告面（station2.SupplyChainScanner 解析通道）
# ---------------------------------------------------------------------------

def test_ADV_01_version_parser_anomaly_unknown_not_silent():
    """ADV-01｜注入：version parser 异常｜期望：UNKNOWN，不写 seen。

    本发行包等价语义（站2 advisory 解析通道）：版本/区间不可解析或 severity
    缺失的公告条目绝不静默当作「已看/干净」跳过——保守按 UNKNOWN 方向升
    HIGH/P1 并写入 findings 账（后续轮次仍可见）；条目结构性损坏（非对象）
    → 整份报告按证据损坏 ERROR。
    """
    anomaly = {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "weird-pkg": {  # severity 缺失 + range 非 semver 形态（parser 异常）
                "name": "weird-pkg", "severity": "", "range": "!!!not-semver!!!",
                "via": ["unparseable"], "effects": [], "fixAvailable": False},
        },
        "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0,
                                         "high": 1, "critical": 0},
                     "dependencies": {"prod": 5, "dev": 1, "optional": 0,
                                      "peer": 0, "total": 6}},
    }
    with tempfile.TemporaryDirectory() as tmp:
        rep = _supply_scan(tmp, _j(anomaly))
        assert rep.result["policy_verdict"] == "FAIL", rep.result
        assert len(rep.findings) == 1
        f = rep.findings[0]
        assert f.severity == "HIGH" and f.priority == "P1"  # UNKNOWN→保守升
        assert "weird-pkg" in f.message and "!!!not-semver!!!" in f.message
        assert rep.result["finding_ids"] == [f.finding_id]  # 写入账：不静默跳过

        corrupt = dict(anomaly)
        corrupt["vulnerabilities"] = {"bad": "not-an-object"}
        rep = _supply_scan(tmp, _j(corrupt))
        assert rep.result["execution_status"] == "ERROR", rep.result  # 损坏→ERROR


def test_ADV_02_multi_page_multi_range_full_traversal():
    """ADV-02｜注入：多页/多 range｜期望：全遍历。

    多页公告合流成单份 stdout + 每条带多 union/跨度 range → 解析列表全量
    遍历：6 投 6 中、finding_ids 互异且全在账；HIGH+ 计数交叉核对通过。
    截断子例（分页不全：自报 7 条 HIGH+ 但解析仅 5）→ 按证据损坏 ERROR。
    """
    entries = [
        ("lodash", "high", ">=1.0.0 <2.3.4 || 3.x", "Prototype Pollution"),
        ("minimist", "critical", "<1.2.6", "Prototype Pollution"),
        ("node-fetch", "high", ">=2.0.0 <2.6.7", "SSRF"),
        ("qs", "moderate", "6.x", "DoS"),
        ("ua-parser-js", "high", "0.7.18 - 0.7.29", "ReDoS"),
        ("shell-quote", "high", ">=1.6.0 <1.7.3", "RCE"),
    ]
    payload = _npm_vulns(entries, dep_total=37)
    with tempfile.TemporaryDirectory() as tmp:
        rep = _supply_scan(tmp, _j(payload))
        validate_station_result(rep.result)
        assert rep.result["policy_verdict"] == "FAIL", rep.result
        assert len(rep.findings) == 6, rep.findings  # 全遍历：一条不漏
        assert len(set(rep.result["finding_ids"])) == 6
        assert rep.result["coverage"] == {"denominator": 37, "scanned": 37}
        assert sum(1 for f in rep.findings
                   if f.severity in ("HIGH", "CRITICAL")) == 5

        truncated = _npm_vulns(entries, dep_total=37)
        truncated["metadata"]["vulnerabilities"]["high"] = 6  # 自报 7 条 HIGH+
        rep = _supply_scan(tmp, _j(truncated))
        assert rep.result["execution_status"] == "ERROR", rep.result
        assert "self-reported" in rep.note, rep.note


# ---------------------------------------------------------------------------
# TEN 族——租户分母（station3：DMMF 动态分母 + org 过滤矩阵）
# ---------------------------------------------------------------------------

def test_TEN_01_prisma_alias_reexport_wrapper_in_denominator():
    """TEN-01｜注入：Prisma alias/re-export/wrapper｜期望：纳入分析。

    覆盖边界：本包不做源级 AST 分析；Prisma 侧分母正源=DMMF（编译后已解析
    alias/re-export/wrapper 形态，统一表现为 datamodel.models 条目）。断言：
    - 别名/包装形态的模型条目全部计入 prisma_dmmf_model_count 与动态分母；
    - 监控面（objects_total）少于含别名的模型全集 → 分母缩水守卫 BLOCKED
      （纳入分析=不可因别名形态漏出分母）；
    - 重复名（假 alias 双计）被拒绝，防分母虚增。
    """
    models = ("Order", "User", "Invoice",
              "Organization",          # 正主 tenant model
              "OrganizationView",      # wrapper 视图模型
              "Org")                   # alias 形态
    dmmf = {"datamodel": {"models": [{"name": n} for n in models]}}
    assert prisma_dmmf_model_count(dmmf) == 6
    assert derive_dynamic_denominator(prisma_dmmf=dmmf)["denominator"] == 6

    contract, ts = _mk_st3(AC_DATA_CONFIG)
    st = contract.db_drift_scanner(prisma_dmmf=dmmf).adapt(
        _drift_payload(ts, objects_total=4, changes=[]))
    assert st["execution_status"] == "BLOCKED", st
    assert st["coverage"] == {"denominator": 6, "scanned": 4}

    dup = {"datamodel": {"models": [{"name": "Organization"},
                                     {"name": "Organization"}]}}
    try:
        prisma_dmmf_model_count(dup)
        raise AssertionError("duplicate model names must be rejected")
    except Station3Error:
        pass


def test_TEN_02_comment_organizationId_cannot_fool():
    """TEN-02｜注入：注释含 organizationId｜期望：不能欺骗。

    探针结果里夹带宣称「organizationId 已过滤」的注释字段——判定只认
    positive/negative 的真实执行结论：负例放行照样 FAIL（注释不能把越权
    说成安全），负例真拦时注释也不制造假阳性。
    """
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    leaked = _og_payload(ts, [
        _ep("GET", "/api/orders", "ALLOWED", "ALLOWED",
            comment="// organizationId filter applied (see PR#123)"),
    ])
    st = contract.org_guard_scanner().adapt(leaked)
    assert st["policy_verdict"] == "FAIL", st
    assert any("negative_allowed" in f for f in st["finding_ids"])
    assert st["coverage"] == {"denominator": 2, "scanned": 2}  # 注释不影响计量

    honest = _og_payload(ts, [
        _ep("GET", "/api/orders", "ALLOWED", "DENIED",
            comment="// organizationId filter applied"),
    ])
    st = contract.org_guard_scanner().adapt(honest)
    assert st["policy_verdict"] == "PASS", st
    assert not st["finding_ids"]
    validate_station_result(st)


def test_TEN_03_long_builder_included_in_analysis():
    """TEN-03｜注入：builder 超 300 字符｜期望：纳入分析。

    覆盖边界：本包无 token 级 builder 解析；「纳入分析」的等价机械语义=
    超长（>300 字符）builder 形态路径计入端点宇宙分母并被真实判定：
    - 全用例矩阵覆盖该端点 → scanned==denominator（PASS，确证纳入）；
    - 该端点负例放行 → finding 照常触发（分析真判它，不因长度跳过）。
    """
    long_path = "/api/org/" + "b" * 320 + "/relations?include=filters"
    assert len(long_path) > 300
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    ok = _og_payload(ts, [_ep("GET", long_path, "ALLOWED", "DENIED")])
    st = contract.org_guard_scanner().adapt(ok)
    assert st["policy_verdict"] == "PASS", st
    assert st["coverage"] == {"denominator": 2, "scanned": 2}  # 计入分母

    bad = _og_payload(ts, [_ep("GET", long_path, "ALLOWED", "ALLOWED")])
    st = contract.org_guard_scanner().adapt(bad)
    assert st["policy_verdict"] == "FAIL", st
    assert any("negative_allowed" in f for f in st["finding_ids"])


def test_TEN_04_queryraw_cross_tenant_static_analysis():
    """TEN-04｜注入：$queryRaw 跨租户｜期望：阻断。

    站3 RawQueryTenantScanner 的 SQL 字符串/queryRaw 调用点租户隔离静态分析：
    - 无租户谓词的查询点（含 $queryRaw/$executeRaw 与裸 SQL 模板字符串）
      → finding → FAIL（阻断语义：策略 FAIL 即阻断合流）；
    - 对抗负例：SELECT 列表里出现 organization_id 不能骗过判定（谓词区
      之外不算守卫）；SET 赋值不算守卫；间接 SQL（getSql(...)）无法证明
      有守卫→按无守卫处理；NOT IN/<>/!= 否定算子不构成租户约束；
    - 对照：谓词区内 org_id=/tenant_id = ANY 守卫 → PASS；
    - 分母缩水：声明 expected_query_sites 高于发现数 → BLOCKED；
      空文件载荷 → 畸形拒绝（防 vacuous PASS）。
    """
    src = "\n".join([
        "import { prisma } from './client'",                                  # L1
        "const leak = await prisma.$queryRaw`SELECT id FROM orders WHERE id = ${id}`",   # L2 无守卫
        "const ok1 = await prisma.$queryRaw`SELECT * FROM orders WHERE org_id = ${orgId}`",  # L3 守卫
        "const decoy = await prisma.$queryRaw`SELECT id, organization_id FROM orders WHERE id = ${id}`",  # L4 SELECT 列表骗术
        "const indirect = await prisma.$executeRaw(getSql(id))",             # L5 间接 SQL
        "const lit = `SELECT name FROM users`",                              # L6 裸 SQL 无守卫
        "const litOk = `DELETE FROM audit WHERE tenant_id = ANY(${ids})`",   # L7 守卫
    ]) + "\n"
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    payload = {
        "tool": {"name": "raw-query-tenant-scan", "version": "ac"},
        "started_at": ts, "ended_at": ts,
        "files": [{"path": "src/db/queries.ts", "content": src}],
    }
    st = contract.raw_query_scanner().adapt(payload)
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL", st            # 阻断
    assert st["execution_status"] == "COMPLETED"
    assert st["coverage"] == {"denominator": 6, "scanned": 6}  # 4 调用点+2 SQL 串
    assert len(st["finding_ids"]) == 4, st["finding_ids"]      # L2/L4/L5/L6
    for fid in st["finding_ids"]:
        assert "no_tenant" in fid, fid
    # 对抗细节：SELECT 列表骗术（L4）与间接 SQL（L5）都被抓——逐行核验
    assert any("_4_prisma_queryraw" in f for f in st["finding_ids"]), st["finding_ids"]
    assert any("_5_prisma_executeraw" in f for f in st["finding_ids"]), st["finding_ids"]
    assert any("_6_sql_string" in f for f in st["finding_ids"]), st["finding_ids"]

    # 谓词算子对抗（纯函数面）：NOT IN / <> / != 不构成租户守卫
    has = RawQueryTenantScanner.has_tenant_predicate
    cols = ("organization_id", "org_id", "tenant_id")
    assert has("SELECT 1 FROM orders WHERE org_id = ${org}", cols)
    assert has("SELECT 1 FROM orders WHERE o.tenant_id IN (${ids})", cols)
    assert not has("SELECT 1 FROM orders WHERE org_id NOT IN (${ids})", cols)
    assert not has("SELECT 1 FROM orders WHERE org_id <> ${other}", cols)
    assert not has("SELECT organization_id FROM orders", cols)   # 无谓词区
    assert not has(None, cols)                                   # 无法证明=无守卫

    # 对照：全守卫 → PASS（空 finding、2/2 全扫）
    guarded_src = "\n".join([
        "const a = await prisma.$queryRaw`SELECT * FROM orders WHERE organization_id = ${orgId}`",
        "const b = `UPDATE audit SET note = 'x' WHERE tenant_id = ANY(${ids})`",
    ]) + "\n"
    st = contract.raw_query_scanner().adapt({
        **payload, "files": [{"path": "src/db/safe.ts", "content": guarded_src}]})
    validate_station_result(st)
    assert st["policy_verdict"] == "PASS", st
    assert st["coverage"] == {"denominator": 2, "scanned": 2}
    assert not st["finding_ids"]

    # 分母缩水：声明宇宙 10、发现 6 → BLOCKED（探针漏读不得静默漏出分母）
    st = contract.raw_query_scanner().adapt({**payload, "expected_query_sites": 10})
    assert st["execution_status"] == "BLOCKED", st
    assert st["coverage"] == {"denominator": 10, "scanned": 6}

    # 空文件载荷 → 畸形拒绝（fail-closed，防 vacuous PASS）
    try:
        contract.raw_query_scanner().adapt({**payload, "files": []})
        raise AssertionError("empty files payload must be rejected")
    except RawQueryScanMalformed:
        pass


def test_TEN_05_non_export_download_path_scanned():
    """TEN-05｜注入：路径不含 export/download 的下载｜期望：纳入扫描。

    端点宇宙=spec∪实际探测（无 export/download 关键字白名单）——不含这
    两个关键词的取数路径照样进分母并被正/负例判定；其负例放行时 finding
    照发（扫描到位才会抓到），正例通负例拦时 PASS。
    """
    path_no_keywords = "/api/tenants/fetch-records"  # 不含 export/download
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    leaked = _og_payload(ts, [
        _ep("GET", path_no_keywords, "ALLOWED", "ALLOWED"),
    ])
    st = contract.org_guard_scanner().adapt(leaked)
    assert st["policy_verdict"] == "FAIL", st
    assert st["coverage"]["denominator"] == 2  # 纳入分母（正例+负例）
    assert any("fetch-records" in f or "negative_allowed" in f
               for f in st["finding_ids"])

    ok = _og_payload(ts, [_ep("GET", path_no_keywords, "ALLOWED", "DENIED")])
    st = contract.org_guard_scanner().adapt(ok)
    assert st["policy_verdict"] == "PASS", st
    assert st["coverage"] == {"denominator": 2, "scanned": 2}


def test_TEN_06_org_a_access_org_b_dynamically_denied():
    """TEN-06｜注入：Org A 访问/导出 Org B｜期望：动态拒绝。

    动态=运行时探针实测结论（非静态声明）：orgB 主体对 orgA 资源的负例
    放行（未动态拒绝）→ FAIL+negative_allowed finding；真实 DENIED → PASS。
    """
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    principals = {"base_url": "http://app.local",
                  "positive_principal": "orgA/alice",
                  "negative_principal": "orgB/mallory"}
    leaked = _og_payload(ts, [
        _ep("GET", "/api/orgs/%7BorgA%7D/exports", "ALLOWED", "ALLOWED"),
    ], principals=principals)
    st = contract.org_guard_scanner().adapt(leaked)
    assert st["policy_verdict"] == "FAIL", st
    assert any("negative_allowed" in f for f in st["finding_ids"])
    validate_station_result(st)

    denied = _og_payload(ts, [
        _ep("GET", "/api/orgs/%7BorgA%7D/exports", "ALLOWED", "DENIED"),
    ], principals=principals)
    st = contract.org_guard_scanner().adapt(denied)
    assert st["policy_verdict"] == "PASS", st
    assert not st["finding_ids"]


def test_TEN_07_new_tenant_model_grows_denominator():
    """TEN-07｜注入：target SHA 新增 tenant model｜期望：分母自动增加。

    同一监控面（objects_total=5）：DMMF 5 模型 → 分母 5、scanned 5 → PASS；
    target SHA 的 DMMF 新增 tenant model（6 个）→ 分母自动升至 6、scanned 5
    → 缩水守卫 BLOCKED（新模型不可静默漏出监控面）。
    """
    dmmf_5 = {"datamodel": {"models": [{"name": n} for n in
                                        ("Order", "User", "Invoice",
                                         "Tenant", "Audit")]}}
    dmmf_6 = {"datamodel": {"models": [{"name": n} for n in
                                        ("Order", "User", "Invoice",
                                         "Tenant", "Audit", "TenantProfile")]}}
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    st5 = contract.db_drift_scanner(prisma_dmmf=dmmf_5).adapt(
        _drift_payload(ts, objects_total=5, changes=[]))
    assert st5["policy_verdict"] == "PASS", st5
    assert st5["coverage"] == {"denominator": 5, "scanned": 5}

    st6 = contract.db_drift_scanner(prisma_dmmf=dmmf_6).adapt(
        _drift_payload(ts, objects_total=5, changes=[]))
    assert st6["coverage"]["denominator"] == 6, st6  # 分母自动增加
    assert st6["coverage"]["scanned"] == 5
    assert st6["execution_status"] == "BLOCKED", st6
    assert st6["policy_verdict"] == "NOT_EVALUATED", st6


def test_TEN_08_admin_cross_tenant_passes_role_negative_rejected():
    """TEN-08｜注入：合法管理员跨租户正例/普通角色负例｜期望：前者通、后者拒。

    正例=管理员跨租户合法访问（positive 必须 ALLOWED=通）；负例=普通角色
    跨租户（negative 必须 DENIED=拒）→ 双全时 PASS。任一翻转（正例被拒/
    负例放行）→ 对应 finding+FAIL。
    """
    contract, ts = _mk_st3(AC_DATA_CONFIG)
    principals = {"base_url": "http://app.local",
                  "positive_principal": "orgA/platform-admin",
                  "negative_principal": "orgA/viewer"}
    both_ok = _og_payload(ts, [
        _ep("GET", "/api/admin/tenant-export", "ALLOWED", "DENIED"),
    ], principals=principals)
    st = contract.org_guard_scanner().adapt(both_ok)
    validate_station_result(st)
    assert st["policy_verdict"] == "PASS", st  # 前者通、后者拒

    role_leak = _og_payload(ts, [
        _ep("GET", "/api/admin/tenant-export", "ALLOWED", "ALLOWED"),
    ], principals=principals)
    st = contract.org_guard_scanner().adapt(role_leak)
    assert st["policy_verdict"] == "FAIL", st  # 普通角色负例必须拒
    assert any("negative_allowed" in f for f in st["finding_ids"])

    admin_rejected = _og_payload(ts, [
        _ep("GET", "/api/admin/tenant-export", "DENIED", "DENIED"),
    ], principals=principals)
    st = contract.org_guard_scanner().adapt(admin_rejected)
    assert st["policy_verdict"] == "FAIL", st  # 合法管理员正例必须通
    assert any("positive_rejected" in f for f in st["finding_ids"])


# ---------------------------------------------------------------------------
# PERF 族——性能有效性（station4 HTTP 面 + station7 指标面 + 冻结哈希绑定）
# ---------------------------------------------------------------------------

def test_PERF_01_http_500_fast_still_fails():
    """PERF-01｜注入：HTTP 500 但很快｜期望：FAIL。

    本地真实 HTTP 服务立即回 500（快）；路由动态腿只认状态语义：探到但
    与期望不符 → FAIL+finding。快≠好——速度不参与判定，绝不因响应快折算
    通过（覆盖边界：本包不测延迟阈值，分位数面见文件头部不可实现清单）。
    """
    manifest, _ = _mk_manifest(_next_run_id("perf1"))
    server = _http_server(_Fast500Handler)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        t0 = time.time()
        st = RouteDynamicScanner(
            manifest,
            routes=[{"name": "orders", "method": "GET", "path": "/",
                     "expected_status": 200}],
            base_url=base, request_timeout_s=5.0,
        ).scan()
        elapsed = time.time() - t0
        assert elapsed < 3.0, elapsed  # 响应确实很快
        validate_station_result(st)
        assert st["coverage"]["scanned"] == 1  # 探到了（拿到真实 500 响应）
        assert st["policy_verdict"] == "FAIL", st
        assert st["execution_status"] == "COMPLETED"
        assert st["finding_ids"] and st["finding_ids"][0].startswith("fnd_route_")
    finally:
        server.shutdown()
        server.server_close()


def test_PERF_02_null_metrics_error_class():
    """PERF_02｜注入：SSH/TCC/null 指标｜期望：ERROR。

    覆盖边界：SSH/TCC 采集通道不在本包；等价机械语义=指标采集缺口
    （null/非数值/NaN）按未扫计：assertion=ERROR、策略 NOT_EVALUATED、
    缩水守卫折叠 BLOCKED——绝不折算 PASS，也绝不当作达标值。
    （函数名用下划线形态 PERF_02 与连字符形态同时登记追踪。）
    """
    manifest, now = _mk_manifest(_next_run_id("perf2"))
    slos = [{"name": "availability", "target": 0.999, "op": ">="},
            {"name": "p95_latency_ms", "target": 800, "op": "<="}]
    for bad_value in (None, "640ms", float("nan")):
        st = SloMonitorScanner(
            manifest, slos=slos,
            snapshot={"availability": 0.9995, "p95_latency_ms": bad_value},
            now=now,
        ).scan()
        validate_station_result(st)
        assert st["coverage"]["scanned"] == 1 < st["coverage"]["denominator"] == 2
        assert st["execution_status"] == "BLOCKED", st
        assert st["policy_verdict"] == "NOT_EVALUATED", st
        assert st["execution"]["assertion_verdict"] == "ERROR", st
        assert any(f.startswith("fnd_slo_missing") for f in st["finding_ids"])
    # 对照：数值齐全且达标 → PASS（缺口语义没有误伤正常面）
    st = SloMonitorScanner(
        manifest, slos=slos,
        snapshot={"availability": 0.9995, "p95_latency_ms": 640.0},
        now=now,
    ).scan()
    assert st["policy_verdict"] == "PASS", st


def test_PERF_03_tail_slow_samples_enter_p95_p99():
    """PERF-03｜注入：尾部极慢样本｜期望：正确进入 p95/p99。

    站4 QuantileLatencyScanner 指标分位数统计面（p50/p95/p99 真实计算+阈值判定）：
    - 算法正源：percentile 线性插值——1..100 恰得 p50=50.5/p95=95.05/p99=99.01；
    - 尾部注入：90 快样本(10ms)+10 极慢尾部(1000ms) → p95=p99=1000.0
      （极慢样本真实进入尾部分位数；中位数 10.0 仍被快样本多数掩盖——
      只看均值/中位数必然漏报，分位数面抓住）；
    - 阈值判定：p95 超 800 → 恰 1 条 finding+FAIL；p99=1000 未超 1200 不报；
    - 对照负例：全均匀快样本 → PASS 零 finding；
    - 采集缺口（None/非数值/NaN）→ 按未扫计 → 缩水守卫 BLOCKED。
    """
    manifest, _ = _mk_manifest(_next_run_id("perf3"))
    # 算法精确性（真实计算，非近似）
    vals = list(range(1, 101))
    assert percentile(vals, 0.50) == 50.5
    assert percentile(vals, 0.95) == 95.05
    assert percentile(vals, 0.99) == 99.01

    thresholds = {"p50": 20, "p95": 800, "p99": 1200}
    samples = [10.0] * 90 + [1000.0] * 10
    st = QuantileLatencyScanner(
        manifest, samples=samples, thresholds_ms=thresholds).scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL", st
    assert st["execution_status"] == "COMPLETED"
    assert st["coverage"] == {"denominator": 100, "scanned": 100}
    assert len(st["finding_ids"]) == 1, st["finding_ids"]  # 只 p95 超（800<1000<1200）
    assert st["finding_ids"][0].startswith("fnd_quantile_")
    probe = QuantileLatencyScanner(
        manifest, samples=samples, thresholds_ms=thresholds)
    probe.scan()
    assert probe.last_breakdown["quantiles"] == {
        "p50": 10.0, "p95": 1000.0, "p99": 1000.0}, probe.last_breakdown
    assert probe.last_breakdown["tripped"] == ["p95"]

    # 对照负例：全均匀快样本 → PASS
    st = QuantileLatencyScanner(
        manifest, samples=[10.0] * 100, thresholds_ms=thresholds).scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "PASS", st
    assert not st["finding_ids"]

    # 采集缺口：null/非数值/NaN → 未扫计 → 缩水守卫 BLOCKED（绝不折算 PASS）
    st = QuantileLatencyScanner(
        manifest, samples=[10.0, None, "640ms", float("nan")],
        thresholds_ms={"p95": 800}).scan()
    validate_station_result(st)
    assert st["coverage"] == {"denominator": 4, "scanned": 1}
    assert st["execution_status"] == "BLOCKED", st
    assert st["policy_verdict"] == "NOT_EVALUATED", st
    assert st["execution"]["assertion_verdict"] == "ERROR", st


def test_PERF_04_query_count_linear_n_plus_one():
    """PERF-04｜注入：输入 1→100，query count 线性｜期望：FAIL。

    站4 QueryCountProfileScanner 查询计数剖析面（N+1/超阈值→finding）：
    - §20 注入原样：输入 1→2 条查询、输入 100→101 条 → 最小二乘斜率≈1.0
      （每输入项 ≥1 查询=线性=N+1 形态）→ linear finding + 超上限 finding
      → FAIL；
    - 对照负例：批处理实现（1→3、100→3，斜率 0）→ PASS；
    - 两判定面独立：常数但超上限（1→50、100→50）→ 无线性 finding、两条
      超限 finding 照样 FAIL（常数形态不能洗绿超限）；
    - 单点不可证线性（斜率 None 只做上限判定）；
    - 剖析点结构非法 → 未扫计 → 缩水守卫 BLOCKED。
    """
    manifest, _ = _mk_manifest(_next_run_id("perf4"))
    n_plus_one = QueryCountProfileScanner(
        manifest,
        profiles=[{"input_size": 1, "query_count": 2},
                  {"input_size": 100, "query_count": 101}],
        max_query_count=10,
    )
    st = n_plus_one.scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL", st
    assert st["execution_status"] == "COMPLETED"
    assert st["coverage"] == {"denominator": 2, "scanned": 2}
    assert len(st["finding_ids"]) == 2, st["finding_ids"]  # 线性 1 + 超限 1
    assert st["finding_ids"][0].startswith("fnd_querycount_linear")
    assert st["finding_ids"][1].startswith("fnd_querycount_over")
    slope = n_plus_one.last_breakdown["least_squares"]["slope"]
    assert slope is not None and abs(slope - 1.0) < 1e-9, slope  # 真实线性

    # 对照：批处理（斜率 0、上限内）→ PASS
    batched = QueryCountProfileScanner(
        manifest,
        profiles=[{"input_size": 1, "query_count": 3},
                  {"input_size": 100, "query_count": 3}],
        max_query_count=10,
    )
    st = batched.scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "PASS", st
    assert not st["finding_ids"]
    assert batched.last_breakdown["least_squares"]["slope"] == 0.0

    # 独立判定面：常数但超上限 → 无线性 finding、两条超限 finding 仍 FAIL
    over = QueryCountProfileScanner(
        manifest,
        profiles=[{"input_size": 1, "query_count": 50},
                  {"input_size": 100, "query_count": 50}],
        max_query_count=10,
    )
    st = over.scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL", st
    assert len(st["finding_ids"]) == 2, st["finding_ids"]
    assert all(f.startswith("fnd_querycount_over") for f in st["finding_ids"])
    assert not over.last_breakdown["linear_tripped"]

    # 单点：不可证线性（slope None），上限判定照常
    single = QueryCountProfileScanner(
        manifest, profiles=[{"input_size": 5, "query_count": 4}],
        max_query_count=10)
    st = single.scan()
    assert st["policy_verdict"] == "PASS", st
    assert single.last_breakdown["least_squares"]["slope"] is None

    # 剖析点结构非法 → 缩水 BLOCKED（fail-closed）
    st = QueryCountProfileScanner(
        manifest,
        profiles=[{"input_size": 1, "query_count": 2}, {"input_size": "x"}],
        max_query_count=10,
    ).scan()
    validate_station_result(st)
    assert st["coverage"] == {"denominator": 2, "scanned": 1}
    assert st["execution_status"] == "BLOCKED", st
    assert st["policy_verdict"] == "NOT_EVALUATED", st


def test_PERF_05_baseline_threshold_tamper_blocked_by_hash():
    """PERF-05｜注入：修改 baseline/阈值试图洗绿｜期望：policy hash 阻断。

    覆盖边界：本包无独立性能基线文件；「基线/阈值冻结哈希阻断」的等价
    机械语义=两道真实哈希绑定：
    - run manifest 冻结 data_config（含阈值）后，载荷携带被改阈值 →
      data_config_hash 不一致 → EvidenceIdentityMismatch 拒绝（洗绿失败）；
    - 落盘 manifest 被改字节 → manifest_hash 校验失败 → ManifestFreezeError。
    """
    frozen = {"db": dict(AC_DB_ID),
              "perf_thresholds": {"p95_ms": 800, "error_rate": 0.01}}
    contract, ts = _mk_st3(frozen)
    tampered = {"db": dict(AC_DB_ID),
                "perf_thresholds": {"p95_ms": 8000, "error_rate": 0.5}}  # 洗绿
    try:
        contract.db_drift_scanner().adapt(
            _drift_payload(ts, data_config=tampered, changes=[]))
        raise AssertionError("threshold tamper must be blocked by frozen hash")
    except EvidenceIdentityMismatch:
        pass
    # 原封不动的冻结配置可通过（阻断只针对篡改）
    st = contract.db_drift_scanner().adapt(
        _drift_payload(ts, data_config=frozen, changes=[]))
    assert st["policy_verdict"] == "PASS", st

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "run-manifest.json"
        contract.manifest.save(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["identity"]["data_config_hash"] = "f" * 64  # 篡改冻结件
        path.write_text(json.dumps(data), encoding="utf-8")
        try:
            type(contract.manifest).load(path)
            raise AssertionError("tampered manifest must fail hash check")
        except ManifestFreezeError:
            pass


def test_PERF_06_endpoint_denominator_shrink_blocks_promotion():
    """PERF-06｜注入：样本/时长/endpoint 分母缩水｜期望：不得晋升 baseline。

    等价机械语义（覆盖边界见 docstring 顶部族说明）：endpoint 分母 2、实际
    只探到 1（另一端点不可达=样本缩水）→ 缩水守卫强制 BLOCKED/NOT_EVALUATED
    ——结果不可作为通过/晋升依据；直接构造 scanned<denominator 的结果同样
    被统一入口折叠 BLOCKED。
    """
    manifest, _ = _mk_manifest(_next_run_id("perf6"))
    server = _http_server(_OkHandler)
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        st = RouteDynamicScanner(
            manifest,
            routes=[
                {"name": "home", "method": "GET", "path": "/",
                 "expected_status": 200},
                {"name": "ghost", "method": "GET", "path": "/missing",
                 "expected_status": 404},
            ],
            base_url="http://127.0.0.1:1",  # 不可达 → ghost 缩水
            request_timeout_s=1.0,
        ).scan()
        # home 也走不可达 base：整腿 scanned 0/2 → 缩水 BLOCKED
        assert st["coverage"]["scanned"] < st["coverage"]["denominator"] == 2
        assert st["execution_status"] == "BLOCKED", st
        assert st["policy_verdict"] == "NOT_EVALUATED", st  # 不得晋升（非通过）
        assert st["execution"]["assertion_verdict"] == "ERROR", st
        validate_station_result(st)

        live = RouteDynamicScanner(
            manifest,
            routes=[{"name": "home", "method": "GET", "path": "/",
                     "expected_status": 200}],
            base_url=base,
        ).scan()
        assert live["policy_verdict"] == "PASS", live  # 对照：可达时不误伤
    finally:
        server.shutdown()
        server.server_close()

    # 统一入口同型注入：scanned<denominator 一律折叠（晋升通道不存在）
    forced = build_station_result(
        run_id="ac-perf6", station_id=4, attempt_id="att-perf6",
        execution_status="COMPLETED", policy_verdict="PASS",
        identity=dict(ST2_IDENTITY), tool={"name": "ac", "version": "1"},
        execution={"argv_digest": _argv_digest(["ac", "perf6"]),
                   "started_at": _iso_z(_utc_now()),
                   "ended_at": _iso_z(_utc_now()),
                   "actual_exit_code": 0, "expected_exit_set": [0],
                   "assertion_verdict": "PASS"},
        coverage={"denominator": 100, "scanned": 60},  # 样本/时长分母缩水
    )
    assert forced["execution_status"] == "BLOCKED", forced
    assert forced["policy_verdict"] == "NOT_EVALUATED", forced


# ---------------------------------------------------------------------------
# 运行器（对齐 system/tests 既有约定：python3 直跑、exit 0=全绿）
# ---------------------------------------------------------------------------

TESTS = [
    ("STA-01 任一站 denominator 缩小 → 整线 BLOCKED",
     test_STA_01_any_station_denominator_shrink_blocks_line),
    ("STA-02 站2/3/4/7 逐站故障 → 独立取证 + aggregate BLOCKED",
     test_STA_02_per_station_fault_keeps_evidence_aggregate_blocked),
    ("DB-01 [+]/[-]/[*] → 全识别",
     test_DB_01_all_change_directions_recognized),
    ("DB-02 仅一条 DROP COLUMN/删 FK → FAIL 不因数量少放行",
     test_DB_02_single_drop_column_or_fk_still_fails),
    ("DB-03 未知格式/空输出（命令非零同型面）→ ERROR 类拒绝",
     test_DB_03_unknown_format_empty_output_rejected),
    ("DB-04 allowlist 到期/对象 hash 变化 → FAIL",
     test_DB_04_allowlist_expiry_or_hash_change_fails),
    ("DB-05 错 DB/role/transaction_read_only=off → BLOCKED（fail-closed 拒绝）",
     test_DB_05_wrong_db_role_or_writable_source_blocked),
    ("DB-06 golden 规范化：catalog 键序 canonical + 对象全集去重（边界见 docstring）",
     test_DB_06_golden_normalization_order_canonical),
    ("SC-01 有效 JSON+HIGH/CRITICAL → FAIL",
     test_SC_01_valid_json_high_critical_fails),
    ("SC-02 空 JSON/registry 超时 → ERROR",
     test_SC_02_empty_json_or_registry_timeout_error),
    ("SC-03 install script/resolved/integrity 变化 → FAIL/人工审（新增依赖计入发现/分母）",
     test_SC_03_lockfile_diff_added_deps_counted),
    ("SC-04 标题含 [skip-audit] → 无绕过效果",
     test_SC_04_skip_audit_title_no_bypass),
    ("SC-05 离线快照签名错误/过期 → BLOCKED（fail-closed 源不可用）",
     test_SC_05_snapshot_signature_freshness_fail_closed),
    ("ADV-01 version parser 异常 → UNKNOWN（保守升 HIGH）不写 seen（不静默跳过）",
     test_ADV_01_version_parser_anomaly_unknown_not_silent),
    ("ADV-02 多页/多 range → 全遍历（截断=ERROR）",
     test_ADV_02_multi_page_multi_range_full_traversal),
    ("TEN-01 Prisma alias/re-export/wrapper → 纳入分析（DMMF 分母）",
     test_TEN_01_prisma_alias_reexport_wrapper_in_denominator),
    ("TEN-02 注释含 organizationId → 不能欺骗",
     test_TEN_02_comment_organizationId_cannot_fool),
    ("TEN-03 builder 超 300 字符 → 纳入分析（超长路径入分母并被判定）",
     test_TEN_03_long_builder_included_in_analysis),
    ("TEN-04 $queryRaw 跨租户 → 阻断（无租户谓词查询 finding）",
     test_TEN_04_queryraw_cross_tenant_static_analysis),
    ("TEN-05 路径不含 export/download 的下载 → 纳入扫描",
     test_TEN_05_non_export_download_path_scanned),
    ("TEN-06 Org A 访问/导出 Org B → 动态拒绝",
     test_TEN_06_org_a_access_org_b_dynamically_denied),
    ("TEN-07 target SHA 新增 tenant model → 分母自动增加",
     test_TEN_07_new_tenant_model_grows_denominator),
    ("TEN-08 合法管理员跨租户正例/普通角色负例 → 前者通、后者拒",
     test_TEN_08_admin_cross_tenant_passes_role_negative_rejected),
    ("PERF-01 HTTP 500 但很快 → FAIL",
     test_PERF_01_http_500_fast_still_fails),
    ("PERF-02 SSH/TCC/null 指标 → ERROR 类（采集缺口缩水折叠）",
     test_PERF_02_null_metrics_error_class),
    ("PERF-03 尾部极慢样本 → 正确进入 p95/p99（真实计算+阈值判定）",
     test_PERF_03_tail_slow_samples_enter_p95_p99),
    ("PERF-04 输入 1→100 query count 线性 → FAIL（N+1/超阈值剖析）",
     test_PERF_04_query_count_linear_n_plus_one),
    ("PERF-05 修改 baseline/阈值试图洗绿 → policy hash 阻断",
     test_PERF_05_baseline_threshold_tamper_blocked_by_hash),
    ("PERF-06 样本/时长/endpoint 分母缩水 → 不得晋升 baseline",
     test_PERF_06_endpoint_denominator_shrink_blocks_promotion),
]

IMPLEMENTED_IDS = [name.split()[0] for name, _ in TESTS]
assert len(IMPLEMENTED_IDS) == len(set(IMPLEMENTED_IDS)) == 29, IMPLEMENTED_IDS
assert not (set(IMPLEMENTED_IDS) & set(NOT_IMPLEMENTABLE)), "清单互斥被破坏"
assert set(IMPLEMENTED_IDS) | set(NOT_IMPLEMENTABLE) == {
    "STA-01", "STA-02",
    "DB-01", "DB-02", "DB-03", "DB-04", "DB-05", "DB-06",
    "SC-01", "SC-02", "SC-03", "SC-04", "SC-05",
    "ADV-01", "ADV-02",
    "TEN-01", "TEN-02", "TEN-03", "TEN-04", "TEN-05", "TEN-06", "TEN-07", "TEN-08",
    "PERF-01", "PERF-02", "PERF-03", "PERF-04", "PERF-05", "PERF-06",
}, "29 条 ID 集合等式不成立"


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

    print(f"\n§20 六族验收测试: {pass_n} PASS / {fail_n} FAIL "
          f"（负责 29 条；实现 {len(IMPLEMENTED_IDS)}；"
          f"不可实现 {len(NOT_IMPLEMENTABLE)}）")
    for tid, reason in sorted(NOT_IMPLEMENTABLE.items()):
        print(f"  [不可实现] {tid}: {reason}")

    if json_out:
        payload = {
            "artifact_kind": "ac-station-families/unit-run",
            "command": "python3 system/tests/test_ac_station_families.py",
            "exit_code": 1 if fail_n else 0,
            "totals": {
                "responsible": 29,
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

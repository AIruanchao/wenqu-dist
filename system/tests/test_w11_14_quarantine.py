#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W11-14 A 面 | Quarantine 一等控制面（R9-UI-QUARANTINE-ABSENT-011 根治）。

十轮 W8 扣三分「字节身份失败（已修）/HTTP auth 现役负例未验/真实浏览器 UI
未验」中 UI 侧根因：dashboard 无 quarantine 表面——fold 静默跳过坏 JSON 行、
无隔离区端点、ACCEPTED/OTHER 无点击接线。本件按方案 W11-14 节验收：

  1. Server 读取 quarantine sidecar（<project>/.quarantine 或 .quarantine.jsonl），
     且主账本解析失败（invalid_json / 非 dict / 缺 id）纳入隔离面——绝不静默跳过；
  2. 新增只读 /api/v1/quarantine：row_hash / project / source basename / line /
     reason / 安全时间戳 / 脱敏截断 preview；
  3. quarantine 不进入有效 finding 分母（total.findings / by_status 均不含）；
  4. ?items= 状态白名单 OPEN/FIXING/FIXED/VERIFIED/CLOSED/ACCEPTED/OTHER/
     QUARANTINE——非法值 400 INVALID_STATE_FILTER；
  5. ACCEPTED/OTHER/QUARANTINE 独立可点击节点 + 计数为 0 仍显示零态
     （前端源码契约；浏览器点击链由 system/tests/browser_e2e.py 真跑）；
  6. 源数据损坏（sidecar 坏 JSON）必须显式错误：/api/v1/quarantine 与
     ?items=QUARANTINE → 503 QUARANTINE_SOURCE_MALFORMED，base 端点携带
     quarantine_error 标记（绝不静默折算成 0）；
  7. 安全形态：XSS payload 在 preview 中作为数据无损往返（JSON+nosniff），
     preview 脱敏（控制字符剥离 + 长度截断），时间戳白名单字符集。

负例（红探针）纪律：对「故意不设防」形态各起一条对照腿，证明断言不瞎：
  - 无白名单/静默跳过的对照服务由断言形态本身覆盖（400 腿）；
  - 缓存失效腿：sidecar 追加后计数必须变化（防陈旧缓存伪绿）。

运行：python3 system/tests/test_w11_14_quarantine.py（独立 exit 0=全绿）
      或 python -m pytest system/tests/test_w11_14_quarantine.py -q
"""
from __future__ import annotations

import json
import socket
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SYSTEM = REPO / "system"
sys.path.insert(0, str(SYSTEM))

from wenqu_core.ui_probe import raw_request  # noqa: E402

from test_ac_ui_family import _Dash, _write_snapshot  # noqa: E402

DASH = SYSTEM / "dashboard"

# 方案 §W11-14 第 4 点：API 状态白名单（八态；非法 → 400）
WHITELIST = ("OPEN", "FIXING", "FIXED", "VERIFIED", "CLOSED",
             "ACCEPTED", "OTHER", "QUARANTINE")

XSS_PAYLOAD = '<img src=x onerror="window.__xssQ=1"><script>window.__xssQ2=1</script>'


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _api(dash, path):
    st, hd, body = raw_request("127.0.0.1", dash.port, "GET", path)
    try:
        j = json.loads(body)
    except ValueError:
        j = None
    return st, hd, j


def _mk_ledger(root: Path, rows: list[dict], extra_lines: list[str] = "",
               project: str = "projQ"):
    proj = root / project
    proj.mkdir(parents=True, exist_ok=True)
    with open(proj / "findings.jsonl", "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        for line in extra_lines:
            if line:
                fh.write(line + "\n")
    return proj


# ---------------------------------------------------------------------------
# 1+2+3+7：sidecar 读取 + fold 坏行入隔离 + 字段契约 + 分母排除 + 安全形态
# ---------------------------------------------------------------------------
def test_quarantine_api_surfaces_sidecar_and_bad_rows_with_contract():
    with tempfile.TemporaryDirectory(prefix="wq14a_") as tmp:
        sandbox = Path(tmp)
        with _Dash(sandbox) as dash:
            _write_snapshot(dash.snap, "PASS")
            rows = [
                {"id": "Q-1", "sev": "HIGH", "status": "OPEN", "title": "有效行",
                 "ts": "2026-10-05T10:00:00"},
            ]
            bad_lines = [
                '{"id": truncated malformed row',                     # invalid_json
                '["not", "a", "dict"]',                              # not_a_json_object
                '{"sev": "HIGH", "title": "无 id 行"}',               # missing_id
            ]
            proj = _mk_ledger(dash.ledger_root, rows, bad_lines)
            # sidecar（.quarantine.jsonl）：完整记录 + XSS payload + 控制字符
            with open(proj / ".quarantine.jsonl", "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "row_hash": "ab" * 32, "reason": "unknown_status:legacy-token",
                    "ts": "2026-10-01T00:00:00Z",
                    "preview": XSS_PAYLOAD + " 自隔离行 \x00\x01ctl", "line": 9,
                }, ensure_ascii=False) + "\n")
                fh.write(json.dumps({"reason": "missing_field:ts"}, ensure_ascii=False) + "\n")

            st, hd, j = _api(dash, "/api/v1/quarantine")
            assert st == 200, f"/api/v1/quarantine 应 200，实得 {st} {j}"
            assert hd.get("content-type", "").startswith("application/json"), "必须 JSON 传输"
            assert hd.get("x-content-type-options") == "nosniff", "nosniff 缺失"
            assert j["available"] is True, f"隔离面应可用: {j}"
            items = j["items"]
            # fold 三条坏行 + sidecar 两条 = 5 条
            assert j["total"] == len(items) == 5, \
                f"隔离面应 5 条（3 fold 坏行 + 2 sidecar），实得 {j['total']}: {items}"

            # 字段契约：每条都有 row_hash/project/source/line/reason/ts/preview
            for it in items:
                for k in ("row_hash", "project", "source", "reason", "preview"):
                    assert k in it and it[k] is not None, f"隔离记录缺 {k}: {it}"
                assert it["source"] == "findings.jsonl" or \
                    it["source"].startswith(".quarantine"), f"source 应为 basename: {it}"
                assert isinstance(it["line"], int) or it["line"] is None, "line 应为整数或 None"
                assert len(it["row_hash"]) == 64 and \
                    all(c in "0123456789abcdef" for c in it["row_hash"]), \
                    f"row_hash 应为 sha256 hex: {it['row_hash']}"
                assert len(it["preview"]) <= 200, "preview 必须截断"
                for ch in it["preview"]:
                    assert ord(ch) >= 0x20, f"preview 必须剥离控制字符: {it['preview']!r}"

            # fold 坏行 reason 分类 + 行号
            by_reason = {it["reason"]: it for it in items}
            assert "invalid_json" in by_reason, f"坏 JSON 行必须以 invalid_json 入隔离: {by_reason}"
            assert by_reason["invalid_json"]["line"] == 2, \
                f"invalid_json 行号应为 2（1-based），实得 {by_reason['invalid_json']}"
            assert by_reason["invalid_json"]["project"] == "projQ"
            assert by_reason["invalid_json"]["source"] == "findings.jsonl"
            assert "not_a_json_object" in by_reason and "missing_id" in by_reason, \
                f"非 dict / 缺 id 行也必须入隔离: {by_reason}"

            # sidecar 行：reason/row_hash 透传，preview 脱敏（XSS 作为数据在场）
            sc = [it for it in items if it["reason"] == "unknown_status:legacy-token"]
            assert len(sc) == 1 and sc[0]["row_hash"] == "ab" * 32, f"sidecar 记录应透传: {sc}"
            assert XSS_PAYLOAD in sc[0]["preview"], "XSS payload 应作为数据在场（无损往返）"
            assert "\x00" not in sc[0]["preview"], "控制字符必须剥离"
            # sidecar 缺 row_hash/line 的记录 → hash 现算、line=None
            sc2 = [it for it in items if it["reason"] == "missing_field:ts"]
            assert len(sc2) == 1 and len(sc2[0]["row_hash"]) == 64 \
                and sc2[0]["line"] is None, f"sidecar 缺省字段须现算/置 None: {sc2}"

            # 安全时间戳：白名单字符集（无换行/控制字符）
            for it in items:
                if it.get("ts"):
                    assert all(c.isdigit() or c in "T:+-.Zz " for c in str(it["ts"])), \
                        f"时间戳字符集越界: {it['ts']!r}"

            # 3) 分母排除：by_status 无 QUARANTINE、findings 总数不含隔离行
            st2, _, base = _api(dash, "/api/v1/bugscan-ledger")
            assert st2 == 200 and base["total"]["findings"] == 1, \
                f"隔离行不得进入有效 finding 分母，实得 {base['total']}"
            assert "QUARANTINE" not in base["total"]["by_status"], \
                f"by_status 不得含 QUARANTINE: {base['total']['by_status']}"
            assert base.get("quarantine_total") == 5, \
                f"base 端点应携带 quarantine_total=5，实得 {base.get('quarantine_total')}"

            # ?items=QUARANTINE 钻取：计数与隔离面一致、条目 st=QUARANTINE
            st3, _, drill = _api(dash, "/api/v1/bugscan-ledger?items=QUARANTINE")
            assert st3 == 200 and drill["items_state"] == "QUARANTINE", f"钻取失败: {drill}"
            assert drill["items_total"] == 5, f"钻取计数应 5，实得 {drill['items_total']}"
            assert all(x["st"] == "QUARANTINE" for x in drill["items"]), \
                f"钻取条目 st 必须为 QUARANTINE: {drill['items']}"
            assert any(XSS_PAYLOAD in (x.get("title") or x.get("preview") or "")
                       for x in drill["items"]), "钻取明细应含隔离 preview"

            # 缓存失效腿：sidecar 追加一行 → 计数必须变化（防陈旧缓存伪绿）
            with open(proj / ".quarantine.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"reason": "cache-buster"}, ensure_ascii=False) + "\n")
            st4, _, j4 = _api(dash, "/api/v1/quarantine")
            assert st4 == 200 and j4["total"] == 6, \
                f"sidecar 变化后隔离面必须重算（缓存失效），实得 {j4['total']}"


# ---------------------------------------------------------------------------
# 4：状态白名单 400
# ---------------------------------------------------------------------------
def test_items_state_whitelist_rejects_illegal_values():
    with tempfile.TemporaryDirectory(prefix="wq14b_") as tmp:
        with _Dash(Path(tmp)) as dash:
            _write_snapshot(dash.snap, "PASS")
            _mk_ledger(dash.ledger_root, [
                {"id": "W-1", "sev": "LOW", "status": "OPEN", "title": "x",
                 "ts": "2026-10-05T10:00:00"}])
            for state in WHITELIST:  # 八态全部 200（零态也 200）
                st, _, j = _api(dash, f"/api/v1/bugscan-ledger?items={state}")
                assert st == 200 and j["items_state"] == state, \
                    f"白名单态 {state} 应 200，实得 {st} {j}"
            for bad in ("BOGUS", "open", "OPEN%20EXTRA", "QUARANTINE%00", "DROP'TABLE",
                        "<script>", "../../etc/passwd"):
                st, _, j = _api(dash, f"/api/v1/bugscan-ledger?items={bad}")
                assert st == 400, f"非法过滤 {bad!r} 应 400，实得 {st} {j}"
                assert isinstance(j, dict) and j.get("error", {}).get("code") \
                    == "INVALID_STATE_FILTER", f"错误码应 INVALID_STATE_FILTER: {j}"


# ---------------------------------------------------------------------------
# 6：源数据损坏显式错误（sidecar 坏 JSON 绝不静默折算）
# ---------------------------------------------------------------------------
def test_corrupt_sidecar_is_explicit_error_not_silence():
    with tempfile.TemporaryDirectory(prefix="wq14c_") as tmp:
        sandbox = Path(tmp)
        with _Dash(sandbox) as dash:
            _write_snapshot(dash.snap, "PASS")
            proj = _mk_ledger(dash.ledger_root, [
                {"id": "C-1", "sev": "LOW", "status": "OPEN", "title": "ok",
                 "ts": "2026-10-05T10:00:00"}])
            (proj / ".quarantine").write_text(
                '{"reason": "good-row"}\n{"reason": broken json!!!\n', encoding="utf-8")

            # /api/v1/quarantine → 503 显式错误（含定位信息）
            st, _, j = _api(dash, "/api/v1/quarantine")
            assert st == 503, f"坏 sidecar 下 quarantine 端点应 503，实得 {st} {j}"
            err = j.get("error", {})
            assert err.get("code") == "QUARANTINE_SOURCE_MALFORMED", f"错误码漂移: {err}"
            assert "projQ" in str(err.get("detail", "")) or ".quarantine" in str(err.get("detail", "")), \
                f"错误应定位源文件，实得 {err}"

            # ?items=QUARANTINE → 503 显式错误
            st2, _, j2 = _api(dash, "/api/v1/bugscan-ledger?items=QUARANTINE")
            assert st2 == 503 and j2["error"]["code"] == "QUARANTINE_SOURCE_MALFORMED", \
                f"钻取面同样必须显式错误，实得 {st2} {j2}"

            # base 端点：不炸（其余账本面仍可用）但绝不静默——quarantine_error 在场
            st3, _, base = _api(dash, "/api/v1/bugscan-ledger")
            assert st3 == 200, f"base 端点不应整体炸掉: {st3} {base}"
            assert isinstance(base.get("quarantine_error"), dict) \
                and base["quarantine_error"].get("code") == "QUARANTINE_SOURCE_MALFORMED", \
                f"base 端点必须携带 quarantine_error（不静默），实得 {base.get('quarantine_error')}"

            # 修复 sidecar（删坏行）→ 恢复 200 且计数正确（好行仍可见）
            (proj / ".quarantine").write_text(
                '{"reason": "good-row"}\n', encoding="utf-8")
            st4, _, j4 = _api(dash, "/api/v1/quarantine")
            assert st4 == 200 and j4["total"] == 1, \
                f"修复后应恢复 200 且计 1 条，实得 {st4} {j4}"


# ---------------------------------------------------------------------------
# 5：零态可操作（API 级；浏览器点击链在 browser_e2e.py）+ 前端源码契约
# ---------------------------------------------------------------------------
def test_zero_state_and_frontend_contract():
    appjs = (DASH / "app.js").read_text(encoding="utf-8")
    # QUARANTINE 独立节点 + 三节点全部可点击（零态也可操作）源码契约
    assert "'QUARANTINE'" in appjs, "前端缺 QUARANTINE 状态节点"
    for node in ("'ACCEPTED'", "'OTHER'", "'QUARANTINE'"):
        assert node in appjs, f"前端缺 {node} 节点"
    assert "quarantine_total" in appjs, "前端必须读取 quarantine_total"
    assert "quarantine_error" in appjs, "前端必须呈现 quarantine_error（不静默）"
    # 全部外来文本只经 textContent（沿用 UI-02 契约，不得引入注入 API）
    for sink in ("innerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in appjs, f"app.js 不得含注入 API {sink}"

    with tempfile.TemporaryDirectory(prefix="wq14d_") as tmp:
        with _Dash(Path(tmp)) as dash:
            _write_snapshot(dash.snap, "PASS")
            _mk_ledger(dash.ledger_root, [
                {"id": "Z-1", "sev": "LOW", "status": "OPEN", "title": "只一条有效行",
                 "ts": "2026-10-05T10:00:00"}])
            # 无坏行、无 sidecar → 隔离面零态：200 + total 0（零态仍可查询可操作）
            st, _, j = _api(dash, "/api/v1/quarantine")
            assert st == 200 and j["available"] is True and j["total"] == 0, \
                f"零隔离面应 200+total 0（零态可查询），实得 {st} {j}"
            st2, _, base = _api(dash, "/api/v1/bugscan-ledger")
            assert base.get("quarantine_total") == 0, "零态 base 也应携带 quarantine_total=0"
            st3, _, drill = _api(dash, "/api/v1/bugscan-ledger?items=QUARANTINE")
            assert st3 == 200 and drill["items_total"] == 0 and drill["items"] == [], \
                f"零态钻取应 200 空集（可操作零态），实得 {st3} {drill}"
            # ACCEPTED/OTHER 零态钻取同样可操作
            for state in ("ACCEPTED", "OTHER"):
                st4, _, d4 = _api(dash, f"/api/v1/bugscan-ledger?items={state}")
                assert st4 == 200 and d4["items_total"] == 0, f"{state} 零态应可钻取: {d4}"


# ---------------------------------------------------------------------------
# 运行器（独立直跑：exit 0=全绿；与 pytest 双兼容）
# ---------------------------------------------------------------------------
def main() -> int:
    tests = [(n, fn) for n, fn in sorted(globals().items())
             if n.startswith("test_") and callable(fn)]
    passed = failed = 0
    failed_names: list[str] = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            failed_names.append(name)
            print(f"  FAIL  {name}: {exc}")
    print(f"RESULT: PASS={passed} FAIL={failed}"
          f"{'' if not failed else '  failed: ' + ', '.join(failed_names)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

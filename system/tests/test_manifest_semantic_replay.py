#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R8 第八轮 P0-3 残余对抗复验正本——签名 manifest 的 lane/TTL/scope/registry 语义重放。

洞 -> 测试映射（正源：Codex 第八轮验收 findings §8/§10.1；本文件是对抗复验正本，
与七轮 test_gate_manifest_trust.py 不同变体族——本轮攻击者**持有合法 release key**，
全部变体先做「内部完全自洽 + 真密钥重签」，只攻击语义面）：
  R8-GATE-LANE-REQ-001（P0）  持钥重签可把 FAST required 合法外观地缩到 [0]；
    降档记录缺要素/越底线/出允许集同样洗白
    -> test_r8_lane001_honest_front_door_and_required_shrink   （对照 PASS + 缩站 BLOCKED）
    -> test_r8_lane001_lane_downgrade_and_flag_lies            （档位谎报/升档旗标谎报）
    -> test_r8_lane001_downgrade_record_replay                 （降档五要素/底线/允许集重放）
  R8-GATE-TTL-SEMANTICS-002（P0）  TTL 不与 registry 对账、结果 freshness 不执行
    -> test_r8_ttl002_registry_ttl_replay_and_expansion        （扩/漂 TTL 全拒）
    -> test_r8_ttl002_freshness_enforcement                    （ended_at 过期 BLOCKED + 时间注入边界）
  R8-GATE-SCOPE-HASH-003（P0）  scope hash 不从内容重算；registry digest 可伪造
    -> test_r8_scope003_scope_hash_recompute                   （内容漂移/哈希谎报/非规范 scope）
    -> test_r8_scope003_registry_digest_and_signed_snapshot    （digest 对账 + --registry 可信根验签链）
  语义域单元面
    -> test_r8_replay_api_units                                （收敛轮数域/畸形输入不崩/幂等重放）

边界（诚实声明）：release key 持有者对 --registry 快照本身重签属于「根持有者=
策略持有者」——快照验签链保证的是外部 pin 件未被篡改，不提供对根自身的对抗；
该语义边界在 test_r8_scope003 中显式断言并留痕。

纯标准库；`python3 system/tests/test_manifest_semantic_replay.py`（exit 0=全绿），兼容 pytest。
"""

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import (  # noqa: E402
    ApprovalKeyring, KeyStateError, sign_envelope,
)
from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    BugscanPlanner, RegistryTrustError, default_registry,
    live_registry_view, load_trusted_registry_snapshot,
    replay_manifest_semantics, signed_registry_snapshot,
    validate_manifest_consistency,
)
from wenqu_core.gate_aggregator import (  # noqa: E402
    BLOCKED, GateAggregator, check_result_freshness,
)

CLI = os.path.join(REPO, "wenqu_core", "cli.py")
SHA = "5c" + "0" * 38
KEY_ID = "key_r8_manifest"
NOW = datetime.now(timezone.utc)
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


def _tail(text, n=220):
    return (text or "").replace("\n", " | ")[-n:]


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _h(obj):
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _resign(doc, secret, key_id=KEY_ID):
    """第八轮攻击者本体：内部完全自洽后用**真密钥**重签+重算 manifest_hash。

    与 freeze_run_manifest 签名面逐字节同构（签名覆盖 key_id 外全部内容、
    manifest_hash 覆盖含签名整体）——攻击件在 RunManifest.load/--verify-key
    验签链上完全合法；只能被语义重放拦下。
    """
    doc = copy.deepcopy(doc)
    doc["key_id"] = key_id
    doc.pop("signature", None)
    body = {k: v for k, v in doc.items()
            if k not in ("manifest_hash", "signature")}
    doc["signature"] = sign_envelope(secret, body)
    outer = {k: v for k, v in doc.items() if k != "manifest_hash"}
    doc["manifest_hash"] = _h(outer)
    return doc


def _freeze(lane="FAST", *, downgrade=None, downgrade_stations=(),
            run_id="run-r8", scope=("src/**", "tests/**", "tools/**")):
    planner = BugscanPlanner(default_registry())
    kwargs = {}
    if downgrade is not None:
        kwargs = {"downgrade": downgrade,
                  "downgrade_stations": downgrade_stations}
    plan = planner.plan(lane, **kwargs)
    keyring = ApprovalKeyring.generate(KEY_ID)
    manifest = planner.freeze_run_manifest(
        plan, run_id=run_id, project_id="r8/erp", commit_sha=SHA,
        environment="staging", scope=list(scope),
        ruleset={"version": "w6a-r8"}, data_config={"profile": "r8"},
        signing_keyring=keyring, signing_key_id=KEY_ID)
    return manifest, keyring


def _valid_downgrade(**over):
    rec = {
        "approver": "risk-owner-r8",
        "reason": "行为面浏览器环境维护窗口暂停八轮复验",
        "scope": "station 4 only",
        "expiry": (NOW + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "compensating_controls": ["人工抽检 e2e 日志"],
    }
    rec.update(over)
    return {k: v for k, v in rec.items() if v is not None}


def _bound(doc, station, *, ended=None):
    """与 manifest dict 完全对账的合法 station-result-v2（ended_at 动态新鲜）。"""
    ended = ended or (NOW - timedelta(seconds=60))
    identity = doc["identity"]
    return {
        "schema_version": "2.0", "run_id": doc["run_id"],
        "station_id": station, "attempt_id": f"att-r8-{station}",
        "execution_status": "COMPLETED", "policy_verdict": "PASS",
        "identity": {"project_id": "r8/erp",
                     "commit_sha": identity["commit_sha"],
                     "environment": identity["environment"],
                     "scope_hash": identity["scope_hash"],
                     "ruleset_hash": identity["ruleset_hash"],
                     "data_config_hash": identity["data_config_hash"]},
        "tool": {"name": "r8-fixture", "version": "1.0", "digest": "d" * 64},
        "execution": {
            "argv_digest": "b" * 64,
            "started_at": (ended - timedelta(seconds=5))
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ended_at": ended.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actual_exit_code": 0, "expected_exit_set": [0],
            "assertion_verdict": "PASS"},
        "coverage": {"denominator": doc["scope"]["denominator"],
                     "scanned": doc["scope"]["denominator"]},
        "finding_ids": [],
        "artifacts": [{"cas_digest": "sha256:" + "c" * 64, "size": 128}],
    }


def _results_dir(td, doc, stations, prefix="s", *, ended=None):
    paths = []
    for station in stations:
        path = os.path.join(td, f"{prefix}{station}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(_bound(doc, station, ended=ended), fh,
                      ensure_ascii=False)
        paths.append(path)
    return paths


def _gate(argv, timeout=120):
    r = subprocess.run([sys.executable, CLI, "gate"] + argv,
                       capture_output=True, text=True, timeout=timeout)
    try:
        payload = json.loads(r.stdout)
    except (json.JSONDecodeError, TypeError):
        payload = {}
    return r.returncode, payload


def _setup(td, lane="FAST", run_id="run-r8", *,
           mname="run-manifest.json", kname="keys.json", **freeze_kw):
    manifest, keyring = _freeze(lane, run_id=run_id, **freeze_kw)
    mpath = os.path.join(td, mname)
    manifest.save(mpath)
    kpath = os.path.join(td, kname)
    keyring.save_json(kpath)
    with open(mpath, encoding="utf-8") as fh:
        doc = json.load(fh)
    return manifest, keyring, mpath, kpath, doc


# ══════════════════════════════════════════════════════════════════════
# R8-GATE-LANE-REQ-001：lane/required 重放（P0）
# ══════════════════════════════════════════════════════════════════════
def test_r8_lane001_honest_front_door_and_required_shrink():
    """对照：诚实 manifest+新鲜结果 rc0 PASS；持钥者把 FAST required 同步缩到
    [0]（顶层/planner/TTL 全自洽+真密钥重签）→ 必 BLOCKED，签名证据 verified
    仍为 True（拦截来自语义重放，不是验签失败）。"""
    with tempfile.TemporaryDirectory(prefix="wq_r8a_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td)
        results = _results_dir(td, doc, [0, 1])
        rc, out = _gate(["--results", *results, "--manifest", mpath,
                         "--verify-key", kpath])
        _ck("R8-LANE-001 诚实 FAST 正门 rc=0 PASS", rc == 0
            and out.get("policy_verdict") == "PASS",
            f"rc={rc} {_tail(out.get('reason'))}")
        replay = out.get("manifest", {}).get("semantic_replay", {})
        _ck("R8-LANE-001 语义重放证据（code_anchored/digest_match/0 违例）",
            replay.get("source") == "code_anchored"
            and replay.get("digest_match") is True
            and replay.get("violations") == 0,
            _tail(json.dumps(replay)))

        secret = keyring.get_for_signing(KEY_ID)
        forged = copy.deepcopy(doc)
        forged["required_stations"] = [0]
        forged["planner"]["required_stations"] = [0]
        forged["station_ttls"] = {"0": doc["station_ttls"]["0"]}
        forged = _resign(forged, secret)
        fpath = os.path.join(td, "forged-shrink.json")
        with open(fpath, "w", encoding="utf-8") as fh:
            json.dump(forged, fh, ensure_ascii=False)
        r0 = os.path.join(td, "only0.json")
        with open(r0, "w", encoding="utf-8") as fh:
            json.dump(_bound(forged, 0), fh, ensure_ascii=False)
        rc2, out2 = _gate(["--results", r0, "--manifest", fpath,
                           "--verify-key", kpath])
        reasons = "".join(out2.get("reasons", []))
        _ck("R8-LANE-001 持钥缩 required→[0]（自洽+重签）rc=2 BLOCKED",
            rc2 == 2 and out2.get("aggregate_outcome") == BLOCKED,
            f"rc={rc2} {_tail(out2.get('reason'))}")
        _ck("R8-LANE-001 记 manifest_semantic_replay_violation + required 不符",
            "manifest_semantic_replay_violation" in reasons
            and "required_stations_not_registry_replayed" in reasons,
            _tail(reasons))
        _ck("R8-LANE-001 拦截独立于签名（verified 仍 True，policy 绝不 PASS）",
            out2.get("manifest", {}).get("signature", {}).get("verified") is True
            and out2.get("policy_verdict") != "PASS",
            _tail(json.dumps(out2.get("manifest", {}).get("signature"))))

        # 变体：STANDARD 无降档记录直接砍到 [0,1]（丢 2/3/4）
        manifest_s, keyring_s, mpath_s, kpath_s, doc_s = _setup(
            td, "STANDARD", run_id="run-r8-std",
            mname="run-manifest-std.json", kname="keys-std.json")
        forged2 = copy.deepcopy(doc_s)
        for key in ("required_stations",):
            forged2[key] = [0, 1]
        forged2["planner"]["required_stations"] = [0, 1]
        forged2["station_ttls"] = {k: v for k, v in doc_s["station_ttls"].items()
                                   if k in ("0", "1")}
        forged2 = _resign(forged2, keyring_s.get_for_signing(KEY_ID))
        fpath2 = os.path.join(td, "forged-std.json")
        with open(fpath2, "w", encoding="utf-8") as fh:
            json.dump(forged2, fh, ensure_ascii=False)
        results2 = _results_dir(td, forged2, [0, 1], prefix="std")
        rc3, out3 = _gate(["--results", *results2, "--manifest", fpath2,
                           "--verify-key", kpath_s])
        detail3 = "".join(out3.get("manifest", {}).get("semantic_replay", {})
                          .get("violations_detail", []))
        _ck("R8-LANE-001 STANDARD 静默砍站→[0,1]（dropped 留空）rc=2 BLOCKED"
            "+ required 与 registry 推导不符",
            rc3 == 2 and out3.get("policy_verdict") != "PASS"
            and "required_stations_not_registry_replayed" in detail3
            and "station_ttls_not_registry_replayed" in detail3,
            f"rc={rc3} {_tail(out3.get('reason'))} detail={_tail(detail3)}")
        # 同型变体：声明 dropped=[2,3,4] 但不带风险接受记录
        forged3 = copy.deepcopy(doc_s)
        forged3["required_stations"] = [0, 1]
        forged3["planner"]["required_stations"] = [0, 1]
        forged3["planner"]["dropped_stations"] = [2, 3, 4]
        forged3["station_ttls"] = {k: v for k, v in doc_s["station_ttls"].items()
                                   if k in ("0", "1")}
        forged3 = _resign(forged3, keyring_s.get_for_signing(KEY_ID))
        fpath3 = os.path.join(td, "forged-std-dropped.json")
        with open(fpath3, "w", encoding="utf-8") as fh:
            json.dump(forged3, fh, ensure_ascii=False)
        rc4, out4 = _gate(["--results", *results2, "--manifest", fpath3,
                           "--verify-key", kpath_s])
        detail4 = "".join(out4.get("manifest", {}).get("semantic_replay", {})
                          .get("violations_detail", []))
        _ck("R8-LANE-001 STANDARD dropped=[2,3,4] 无记录 rc=2 BLOCKED + "
            "downgrade_record_missing",
            rc4 == 2 and out4.get("policy_verdict") != "PASS"
            and "downgrade_record_missing" in detail4,
            f"rc={rc4} {_tail(out4.get('reason'))} detail={_tail(detail4)}")


def test_r8_lane001_lane_downgrade_and_flag_lies():
    """变体：lane_effective 谎报降档（STANDARD 请求→FAST 生效）；升档旗标/
    理由谎报；api 面单元复核。"""
    with tempfile.TemporaryDirectory(prefix="wq_r8b_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td)
        secret = keyring.get_for_signing(KEY_ID)
        results = _results_dir(td, doc, [0, 1])
        # lane 降档谎报：requested=STANDARD / effective=FAST / required=[0,1]
        lane_lie = copy.deepcopy(doc)
        lane_lie["planner"]["lane_requested"] = "STANDARD"
        lane_lie = _resign(lane_lie, secret)
        lpath = os.path.join(td, "lane-lie.json")
        with open(lpath, "w", encoding="utf-8") as fh:
            json.dump(lane_lie, fh, ensure_ascii=False)
        rc, out = _gate(["--results", *results, "--manifest", lpath,
                         "--verify-key", kpath])
        reasons = "".join(out.get("reasons", []))
        _ck("R8-LANE-001 lane 降档谎报（STANDARD→FAST）rc=2 BLOCKED",
            rc == 2 and "lane_downgrade_without_acceptance" in reasons,
            f"rc={rc} {_tail(reasons)}")
        # api 面：升档旗标谎报 / 幽灵理由
        flag_lie = copy.deepcopy(doc)
        flag_lie["planner"]["escalated"] = True
        issues = replay_manifest_semantics(flag_lie, registry=default_registry())
        _ck("R8-LANE-001 升档旗标谎报（escalated 无实升档）记违例",
            any("escalation_flag_inconsistent" in i for i in issues),
            _tail("; ".join(issues)))
        ghost = copy.deepcopy(doc)
        ghost["planner"]["escalation_reasons"] = ["touches_funds→INCIDENT"]
        issues2 = replay_manifest_semantics(ghost, registry=default_registry())
        _ck("R8-LANE-001 幽灵升档理由记违例",
            any("escalation_reasons_ghost" in i for i in issues2))
        honest_issues = replay_manifest_semantics(
            doc, registry=default_registry())
        _ck("R8-LANE-001 诚实 manifest 语义重放零违例", honest_issues == [],
            _tail("; ".join(honest_issues)))


def test_r8_lane001_downgrade_record_replay():
    """R8 降档重放：合法降档 PASS 对照 + 缺要素/过期/越底线/出允许集/不成对
    全 BLOCKED（记录以 planner 落账为准，gate 时点重新执法五要素+日落）。"""
    with tempfile.TemporaryDirectory(prefix="wq_r8c_") as td:
        # 对照：STANDARD 合法降档站4（五要素齐+7 天到期）→ rc0 PASS
        manifest, keyring, mpath, kpath, doc = _setup(
            td, "STANDARD", downgrade=_valid_downgrade(),
            downgrade_stations=(4,), run_id="run-r8-dg")
        results = _results_dir(td, doc, [0, 1, 2, 3], prefix="dg")
        rc, out = _gate(["--results", *results, "--manifest", mpath,
                         "--verify-key", kpath])
        _ck("R8-LANE-001 合法降档（五要素齐）rc=0 PASS",
            rc == 0 and out.get("policy_verdict") == "PASS",
            f"rc={rc} {_tail(out.get('reason'))}")

        secret = keyring.get_for_signing(KEY_ID)

        def _variant(name, mutate, expect_token, stations=(0, 1, 2, 3)):
            forged = copy.deepcopy(doc)
            mutate(forged)
            forged = _resign(forged, secret)
            vpath = os.path.join(td, f"dg-{name}.json")
            with open(vpath, "w", encoding="utf-8") as fh:
                json.dump(forged, fh, ensure_ascii=False)
            vresults = _results_dir(td, forged, list(stations),
                                    prefix=f"dg{name}")
            vrc, vout = _gate(["--results", *vresults, "--manifest", vpath,
                               "--verify-key", kpath])
            vreasons = "".join(vout.get("reasons", []))
            vdetail = "".join(
                vout.get("manifest", {}).get("semantic_replay", {})
                .get("violations_detail", []))
            _ck(f"R8-LANE-001 降档变体[{name}] rc=2 BLOCKED + {expect_token}",
                vrc == 2 and vout.get("policy_verdict") != "PASS"
                and "manifest_semantic_replay_violation" in vreasons
                and (expect_token in vreasons or expect_token in vdetail),
                f"rc={vrc} {_tail(vreasons)} detail={_tail(vdetail)}")

        _variant("缺 approver",
                 lambda d: d["planner"]["downgrade"].pop("approver"),
                 "risk_acceptance_invalid")
        _variant("理由过短",
                 lambda d: d["planner"]["downgrade"].update(reason="太短"),
                 "risk_acceptance_invalid")
        _variant("已过期到期",
                 lambda d: d["planner"]["downgrade"].update(
                     expiry=(NOW - timedelta(days=1))
                     .strftime("%Y-%m-%dT%H:%M:%SZ")),
                 "risk_acceptance_invalid")
        _variant("超 30 天日落",
                 lambda d: d["planner"]["downgrade"].update(
                     expiry=(NOW + timedelta(days=40))
                     .strftime("%Y-%m-%dT%H:%M:%SZ")),
                 "risk_acceptance_invalid")
        _variant("记录与事实不成对（删 dropped）",
                 lambda d: d["planner"].update(dropped_stations=[]),
                 "downgrade_record_without_dropped")
        # 越底线：手造 STANDARD required=[0]、dropped=[1]（planner 不可产，
        # 持钥者可写）——底线 {0,1} + 允许集双重违例
        floor = copy.deepcopy(doc)
        floor["required_stations"] = [0]
        floor["planner"]["required_stations"] = [0]
        floor["planner"]["dropped_stations"] = [1]
        floor["station_ttls"] = {"0": doc["station_ttls"]["0"]}
        floor = _resign(floor, secret)
        fpath = os.path.join(td, "dg-floor.json")
        with open(fpath, "w", encoding="utf-8") as fh:
            json.dump(floor, fh, ensure_ascii=False)
        fr = os.path.join(td, "dg-floor0.json")
        with open(fr, "w", encoding="utf-8") as fh:
            json.dump(_bound(floor, 0), fh, ensure_ascii=False)
        frc, fout = _gate(["--results", fr, "--manifest", fpath,
                           "--verify-key", kpath])
        freasons = "".join(fout.get("reasons", []))
        _ck("R8-LANE-001 降档越底线站1 rc=2 BLOCKED + downgrade_floor_violation",
            frc == 2 and "downgrade_floor_violation" in freasons,
            f"rc={frc} {_tail(freasons)}")
        # 出允许集：FAST 档 dropped=[6]（不在 FAST 基础集）
        mfast, kfast, mpath_fast, kpath_fast, doc_fast = _setup(
            td, "FAST", run_id="run-r8-oos",
            mname="run-manifest-oos.json", kname="keys-oos.json")
        oos = copy.deepcopy(doc_fast)
        oos["planner"]["downgrade"] = _valid_downgrade()
        oos["planner"]["dropped_stations"] = [6]
        oos = _resign(oos, kfast.get_for_signing(KEY_ID))
        opath = os.path.join(td, "dg-oos.json")
        with open(opath, "w", encoding="utf-8") as fh:
            json.dump(oos, fh, ensure_ascii=False)
        oresults = _results_dir(td, oos, [0, 1], prefix="oos")
        orc, oout = _gate(["--results", *oresults, "--manifest", opath,
                           "--verify-key", kpath_fast])
        odetail = "".join(oout.get("manifest", {}).get("semantic_replay", {})
                          .get("violations_detail", []))
        _ck("R8-LANE-001 降档出 registry 允许集（FAST dropped=[6]）rc=2 BLOCKED",
            orc == 2 and "downgrade_station_not_in_lane_set" in odetail,
            f"rc={orc} {_tail(oout.get('reason'))} detail={_tail(odetail)}")


# ══════════════════════════════════════════════════════════════════════
# R8-GATE-TTL-SEMANTICS-002：TTL 重放 + freshness（P0）
# ══════════════════════════════════════════════════════════════════════
def test_r8_ttl002_registry_ttl_replay_and_expansion():
    """变体：station_ttls 扩到 31 天/缩到 7 天（自洽+重签）→ 重放拒；
    删 TTL → 语义面同样记违例（与 5b 一致性面叠加，只增不减）。"""
    with tempfile.TemporaryDirectory(prefix="wq_r8d_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td)
        secret = keyring.get_for_signing(KEY_ID)
        results = _results_dir(td, doc, [0, 1])

        expand = copy.deepcopy(doc)
        expand["station_ttls"] = {"0": 31, "1": 30}
        expand = _resign(expand, secret)
        epath = os.path.join(td, "ttl-expand.json")
        with open(epath, "w", encoding="utf-8") as fh:
            json.dump(expand, fh, ensure_ascii=False)
        erc, eout = _gate(["--results", *results, "--manifest", epath,
                           "--verify-key", kpath])
        ereasons = "".join(eout.get("reasons", []))
        _ck("R8-TTL-002 扩 TTL→31 天（重签）rc=2 BLOCKED",
            erc == 2 and "station_ttls_not_registry_replayed" in ereasons,
            f"rc={erc} {_tail(ereasons)}")

        shrink = copy.deepcopy(doc)
        shrink["station_ttls"] = {"0": 7, "1": 7}
        shrink = _resign(shrink, secret)
        spath = os.path.join(td, "ttl-shrink.json")
        with open(spath, "w", encoding="utf-8") as fh:
            json.dump(shrink, fh, ensure_ascii=False)
        src_, sout = _gate(["--results", *results, "--manifest", spath,
                            "--verify-key", kpath])
        _ck("R8-TTL-002 漂移 TTL→7 天（重签）rc=2 BLOCKED",
            src_ == 2 and "station_ttls_not_registry_replayed"
            in "".join(sout.get("reasons", [])),
            f"rc={src_} {_tail(sout.get('reason'))}")

        deleted = copy.deepcopy(doc)
        deleted.pop("station_ttls")
        deleted = _resign(deleted, secret)
        dpath = os.path.join(td, "ttl-deleted.json")
        with open(dpath, "w", encoding="utf-8") as fh:
            json.dump(deleted, fh, ensure_ascii=False)
        drc, dout = _gate(["--results", *results, "--manifest", dpath,
                           "--verify-key", kpath])
        dreasons = "".join(dout.get("reasons", []))
        _ck("R8-TTL-002 删 station_ttls（重签）rc=2 + 语义面 station_ttls 违例",
            drc == 2 and "station_ttls" in dreasons
            and "manifest_semantic_replay_violation" in dreasons,
            f"rc={drc} {_tail(dreasons)}")


def test_r8_ttl002_freshness_enforcement():
    """freshness：ended_at+TTL≥gate 时点强制——40 天陈旧结果（签名合法）
    rc2 BLOCKED；api 时间注入边界：恰好 ended+TTL==now 新鲜、早 1 秒过期。"""
    with tempfile.TemporaryDirectory(prefix="wq_r8e_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td)
        stale = _results_dir(td, doc, [0, 1],
                             ended=NOW - timedelta(days=40))
        rc, out = _gate(["--results", *stale, "--manifest", mpath,
                         "--verify-key", kpath])
        reasons = "".join(out.get("reasons", []))
        _ck("R8-TTL-002 陈旧结果（ended 40d 前，TTL 30d）rc=2 BLOCKED",
            rc == 2 and "evidence_ttl_violation" in reasons,
            f"rc={rc} {_tail(reasons)}")
        _ck("R8-TTL-002 违例点名 evidence_ttl_expired + counts 落账",
            "evidence_ttl_expired" in reasons
            and out.get("counts", {}).get("ttl_violations", 0) >= 2,
            _tail(json.dumps(out.get("counts"))))
        st0 = out.get("stations", {}).get("0", {})
        _ck("R8-TTL-002 stations[0].ttl_fresh=false（逐站时效证据）",
            st0.get("ttl_fresh") is False, _tail(json.dumps(st0)))
        _ck("R8-TTL-002 freshness 证据块（mode=registry_ttl+as_of）",
            out.get("freshness", {}).get("mode") == "registry_ttl"
            and bool(out.get("freshness", {}).get("as_of")))

        # api 时间注入边界：ended + TTL == now 恰好新鲜；早 1 秒过期
        t = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)

        def _result_at(ended_iso):
            r = _bound(doc, 0)
            r["execution"]["started_at"] = ended_iso
            r["execution"]["ended_at"] = ended_iso
            return r

        boundary = _result_at("2026-09-08T12:00:00Z")   # t - 30d 恰好
        agg = GateAggregator({"0"}, SHA, "staging",
                             station_ttls={"0": 30}, now=t)
        agg.add(boundary)
        bout = agg.aggregate()
        _ck("R8-TTL-002 边界：ended+TTL==now 恰好新鲜（不 BLOCKED）",
            bout["counts"].get("ttl_violations", 0) == 0
            and bout["aggregate_outcome"] == "PASS",
            _tail(bout.get("reason")))
        expired = _result_at("2026-09-08T11:59:59Z")    # 早 1 秒
        agg2 = GateAggregator({"0"}, SHA, "staging",
                              station_ttls={"0": 30}, now=t)
        agg2.add(expired)
        eout2 = agg2.aggregate()
        _ck("R8-TTL-002 边界：早 1 秒即过期（BLOCKED + evidence_ttl_expired）",
            eout2["aggregate_outcome"] == BLOCKED
            and "evidence_ttl_expired" in "".join(eout2["reasons"]),
            _tail(eout2.get("reason")))
        # 单元面：check_result_freshness 直测（含畸形 ended_at fail-closed）
        _ck("R8-TTL-002 check_result_freshness 单元（fresh/过期/畸形）",
            check_result_freshness("2026-09-08T12:00:00Z", 30, now=t) is None
            and check_result_freshness(
                "2026-09-08T11:59:59Z", 30, now=t) == "evidence_ttl_expired"
            and check_result_freshness("not-a-date", 30, now=t)
            == "ttl_ended_at_missing_or_invalid")
        # 注入面护栏：naive now / 非法 TTL 表 → 构造期拒绝
        try:
            GateAggregator({"0"}, SHA, "staging", station_ttls={"0": 30},
                           now=datetime(2026, 10, 8, 12, 0, 0))
            _ck("R8-TTL-002 naive now 拒绝（ValueError）", False, "no raise")
        except ValueError:
            _ck("R8-TTL-002 naive now 拒绝（ValueError）", True)
        try:
            GateAggregator({"0"}, SHA, "staging", station_ttls={"0": 0})
            _ck("R8-TTL-002 TTL 表非正值拒绝（ValueError）", False, "no raise")
        except ValueError:
            _ck("R8-TTL-002 TTL 表非正值拒绝（ValueError）", True)


# ══════════════════════════════════════════════════════════════════════
# R8-GATE-SCOPE-HASH-003：scope hash 实算 + registry 可信根（P0）
# ══════════════════════════════════════════════════════════════════════
def test_r8_scope003_scope_hash_recompute():
    """变体：scope 内容漂移（哈希保留旧值）/哈希谎报（内容不动）——攻击者
    同步重绑站结果到谎报哈希，形成完全自洽链；仍被「从内容实算」拦下。"""
    with tempfile.TemporaryDirectory(prefix="wq_r8f_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td)
        secret = keyring.get_for_signing(KEY_ID)

        drift = copy.deepcopy(doc)
        drift["scope"]["paths"].append("rogue/**")
        drift["scope"]["paths"].sort()
        drift["scope"]["denominator"] = len(drift["scope"]["paths"])
        drift = _resign(drift, secret)
        dpath = os.path.join(td, "scope-drift.json")
        with open(dpath, "w", encoding="utf-8") as fh:
            json.dump(drift, fh, ensure_ascii=False)
        dresults = _results_dir(td, drift, [0, 1], prefix="drift")
        drc, dout = _gate(["--results", *dresults, "--manifest", dpath,
                           "--verify-key", kpath])
        dreasons = "".join(dout.get("reasons", []))
        _ck("R8-SCOPE-003 scope 内容漂移（旧 hash+重绑结果+重签）rc=2 BLOCKED",
            drc == 2 and "scope_hash_recompute_mismatch" in dreasons,
            f"rc={drc} {_tail(dreasons)}")

        lie = copy.deepcopy(doc)
        lie["identity"]["scope_hash"] = "e" * 64
        lie = _resign(lie, secret)
        lpath = os.path.join(td, "hash-lie.json")
        with open(lpath, "w", encoding="utf-8") as fh:
            json.dump(lie, fh, ensure_ascii=False)
        lresults = _results_dir(td, lie, [0, 1], prefix="lie")
        lrc, lout = _gate(["--results", *lresults, "--manifest", lpath,
                           "--verify-key", kpath])
        _ck("R8-SCOPE-003 scope hash 谎报（内容不动+重绑+重签）rc=2 BLOCKED",
            lrc == 2 and "scope_hash_recompute_mismatch"
            in "".join(lout.get("reasons", [])),
            f"rc={lrc} {_tail(lout.get('reason'))}")

        noncanon = copy.deepcopy(doc)
        noncanon["scope"]["paths"] = ["tests/**", "src/**"]
        issues = replay_manifest_semantics(noncanon,
                                           registry=default_registry())
        _ck("R8-SCOPE-003 非规范 scope（未升序）记违例（api 面）",
            any("scope_paths_not_canonical" in i for i in issues))
        dup = copy.deepcopy(doc)
        dup["scope"]["paths"] = ["src/**", "src/**", "tests/**",
                                 "tools/**"]
        issues2 = replay_manifest_semantics(dup, registry=default_registry())
        _ck("R8-SCOPE-003 重复路径 scope 记违例（api 面）",
            any("scope_paths_not_canonical" in i for i in issues2))


def test_r8_scope003_registry_digest_and_signed_snapshot():
    """registry digest 对账 + --registry 受保护快照验签链：
    伪造 digest/版本 → BLOCKED；诚实快照 → PASS；篡改/无签/他钥快照 → ERROR。"""
    with tempfile.TemporaryDirectory(prefix="wq_r8g_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td)
        secret = keyring.get_for_signing(KEY_ID)
        results = _results_dir(td, doc, [0, 1])

        forged = copy.deepcopy(doc)
        forged["registry_digest"] = "f" * 64
        forged = _resign(forged, secret)
        fpath = os.path.join(td, "digest-forged.json")
        with open(fpath, "w", encoding="utf-8") as fh:
            json.dump(forged, fh, ensure_ascii=False)
        frc, fout = _gate(["--results", *results, "--manifest", fpath,
                           "--verify-key", kpath])
        freasons = "".join(fout.get("reasons", []))
        freplay = fout.get("manifest", {}).get("semantic_replay", {})
        _ck("R8-SCOPE-003 伪造 registry digest（重签）rc=2 BLOCKED",
            frc == 2 and "registry_digest_mismatch" in freasons
            and freplay.get("digest_match") is False,
            f"rc={frc} {_tail(freasons)}")
        versioned = copy.deepcopy(doc)
        versioned["registry_version"] = "w6a-9.9.9"
        versioned = _resign(versioned, secret)
        vpath = os.path.join(td, "version-forged.json")
        with open(vpath, "w", encoding="utf-8") as fh:
            json.dump(versioned, fh, ensure_ascii=False)
        vrc, vout = _gate(["--results", *results, "--manifest", vpath,
                           "--verify-key", kpath])
        _ck("R8-SCOPE-003 伪造 registry_version rc=2 BLOCKED",
            vrc == 2 and "registry_version_mismatch"
            in "".join(vout.get("reasons", [])),
            f"rc={vrc} {_tail(vout.get('reason'))}")

        # 诚实受保护快照：release key 签发 → --registry 正门 PASS
        snap = signed_registry_snapshot(signing_keyring=keyring,
                                        signing_key_id=KEY_ID)
        spath = os.path.join(td, "registry-snapshot.json")
        with open(spath, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, ensure_ascii=False)
        src_, sout = _gate(["--results", *results, "--manifest", mpath,
                            "--verify-key", kpath, "--registry", spath])
        sreplay = sout.get("manifest", {}).get("semantic_replay", {})
        _ck("R8-SCOPE-003 --registry 验签快照正门 rc=0 PASS（source 落账）",
            src_ == 0 and sout.get("policy_verdict") == "PASS"
            and sreplay.get("source") == "signed_snapshot",
            f"rc={src_} {_tail(json.dumps(sreplay))}")

        # 篡改快照（弱化 FAST lane 表，保留旧签名）→ 验签拒 ERROR
        tampered = copy.deepcopy(snap)
        tampered["lane_required_stations"]["FAST"] = [0]
        tpath = os.path.join(td, "snapshot-tampered.json")
        with open(tpath, "w", encoding="utf-8") as fh:
            json.dump(tampered, fh, ensure_ascii=False)
        trc, tout = _gate(["--results", *results, "--manifest", mpath,
                           "--verify-key", kpath, "--registry", tpath])
        _ck("R8-SCOPE-003 篡改快照（弱化 lane 表不重签）rc=3 ERROR"
            "（mode=registry_trust_invalid）",
            trc == 3 and tout.get("mode") == "registry_trust_invalid",
            f"rc={trc} {_tail(tout.get('reason'))}")

        unsigned = copy.deepcopy(snap)
        unsigned.pop("signature")
        upath = os.path.join(td, "snapshot-unsigned.json")
        with open(upath, "w", encoding="utf-8") as fh:
            json.dump(unsigned, fh, ensure_ascii=False)
        urc, uout = _gate(["--results", *results, "--manifest", mpath,
                           "--verify-key", kpath, "--registry", upath])
        _ck("R8-SCOPE-003 无签名快照 rc=3 ERROR",
            urc == 3 and uout.get("mode") == "registry_trust_invalid",
            f"rc={urc} {_tail(uout.get('reason'))}")

        other = ApprovalKeyring.generate("key_attacker")
        other_snap = signed_registry_snapshot(signing_keyring=other,
                                              signing_key_id="key_attacker")
        opath = os.path.join(td, "snapshot-other-key.json")
        with open(opath, "w", encoding="utf-8") as fh:
            json.dump(other_snap, fh, ensure_ascii=False)
        orc, oout = _gate(["--results", *results, "--manifest", mpath,
                           "--verify-key", kpath, "--registry", opath])
        _ck("R8-SCOPE-003 他钥快照（key 不在验签 keyring）rc=3 ERROR",
            orc == 3 and oout.get("mode") == "registry_trust_invalid",
            f"rc={orc} {_tail(oout.get('reason'))}")

        # digest 自报不自证：stations 被改 + digest 同步重算 + 保留旧签名 →
        # HMAC 验签拒（签名覆盖含 digest 的整体；进程内 stations 键为 int）
        digest_lie = copy.deepcopy(snap)
        digest_lie["stations"][0]["ttl_days"] = 90
        digest_lie["registry_digest"] = _h(
            {"registry_version": digest_lie["registry_version"],
             "stations": digest_lie["stations"]})
        dpath2 = os.path.join(td, "snapshot-digest-lie.json")
        with open(dpath2, "w", encoding="utf-8") as fh:
            json.dump(digest_lie, fh, ensure_ascii=False)
        drc2, dout2 = _gate(["--results", *results, "--manifest", mpath,
                             "--verify-key", kpath, "--registry", dpath2])
        _ck("R8-SCOPE-003 快照 digest 同步重算但未重签 rc=3 ERROR",
            drc2 == 3 and dout2.get("mode") == "registry_trust_invalid",
            f"rc={drc2} {_tail(dout2.get('reason'))}")

        # 旗标面：--registry 无 --manifest / 无 --verify-key → flag_conflict
        f1rc, f1out = _gate(["--results", *results, "--registry", spath])
        _ck("R8-SCOPE-003 --registry 无 --manifest rc=3 flag_conflict",
            f1rc == 3 and f1out.get("mode") == "flag_conflict", f"rc={f1rc}")
        f2rc, f2out = _gate(["--results", *results, "--manifest", mpath,
                             "--registry", spath, "--allow-unsigned"])
        _ck("R8-SCOPE-003 --registry 无 --verify-key rc=3 flag_conflict",
            f2rc == 3 and f2out.get("mode") == "flag_conflict", f"rc={f2rc}")

        # 签发面 fail-closed：多 active 未显式 / rotated key 不得签快照
        multi = ApprovalKeyring({"key_a": "a" * 32, "key_b": "b" * 32})
        try:
            signed_registry_snapshot(signing_keyring=multi)
            _ck("R8-SCOPE-003 快照签发多 active 未显式拒", False, "no raise")
        except RegistryTrustError:
            _ck("R8-SCOPE-003 快照签发多 active 未显式拒", True)
        rotated = ApprovalKeyring(
            {"key_r": "r" * 32},
            metadata={"key_r": {"status": "rotated",
                                "rotated_at": "2026-10-01T00:00:00Z"}})
        try:
            signed_registry_snapshot(signing_keyring=rotated,
                                     signing_key_id="key_r")
            _ck("R8-SCOPE-003 rotated key 不得签快照", False, "no raise")
        except (RegistryTrustError, KeyStateError):
            _ck("R8-SCOPE-003 rotated key 不得签快照", True)

        # 诚实边界留痕：根持有者对快照本身重签=策略持有者（keyholder=root，
        # 非洞）——外部 pin 件的防篡改由验签链保证，对根自身无对抗
        root_signed = signed_registry_snapshot(signing_keyring=keyring,
                                               signing_key_id=KEY_ID)
        rpath2 = os.path.join(td, "snapshot-root-resigned.json")
        with open(rpath2, "w", encoding="utf-8") as fh:
            json.dump(root_signed, fh, ensure_ascii=False)
        view = load_trusted_registry_snapshot(rpath2, keyring=keyring)
        _ck("R8-SCOPE-003 keyholder=root 语义边界（验签链只保 pin 件完整性）",
            view.source == "signed_snapshot"
            and view.registry_digest == default_registry().registry_digest())


# ══════════════════════════════════════════════════════════════════════
# 语义域单元面（R8 replay API units）
# ══════════════════════════════════════════════════════════════════════
def test_r8_replay_api_units():
    """收敛轮数域（低于档位契约/超全局上限）、畸形输入不崩、视图/一致性
    分工（结构与语义两面前后一致）。"""
    with tempfile.TemporaryDirectory(prefix="wq_r8h_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td, "STANDARD",
                                                      run_id="run-r8-unit")
        low = copy.deepcopy(doc)
        low["planner"]["convergence_rounds"] = 1  # STANDARD 契约=2
        issues = replay_manifest_semantics(low, registry=default_registry())
        _ck("R8-UNIT 收敛轮数低于档位契约（STANDARD N=1）记违例",
            any("convergence_rounds_out_of_domain" in i for i in issues),
            _tail("; ".join(issues)))
        high = copy.deepcopy(doc)
        high["planner"]["convergence_rounds"] = 4  # 全局上限=3
        issues2 = replay_manifest_semantics(high, registry=default_registry())
        _ck("R8-UNIT 收敛轮数超全局上限（N=4）记违例",
            any("convergence_rounds_out_of_domain" in i for i in issues2))

        for label, payload in (("None", None), ("list", [1, 2]),
                               ("空对象", {}), ("planner 畸形",
                                                  {"planner": "x"})):
            issues3 = replay_manifest_semantics(
                payload, registry=default_registry())
            _ck(f"R8-UNIT 畸形输入[{label}]不崩且返回违例清单",
                isinstance(issues3, list) and all(
                    isinstance(i, str) for i in issues3))

        view = live_registry_view()
        _ck("R8-UNIT 代码锚定视图与 default_registry 同指纹",
            view.registry_digest == default_registry().registry_digest()
            and view.lane_required("FAST") == (0, 1)
            and view.ttl_for(0) == 30)
        _ck("R8-UNIT 视图未知 lane fail-closed（BugscanPlanError）",
            _raises(lambda: view.lane_required("NOPE")))
        # 分工：诚实件两面全绿；结构冲突件两面各自记账（语义面不吞结构面）
        _ck("R8-UNIT 诚实件 validate_manifest_consistency 亦零违例",
            validate_manifest_consistency(doc) == [])
        broken = copy.deepcopy(doc)
        broken["required_stations"] = [0, 1]  # 顶层缩水，planner 保持全集
        _ck("R8-UNIT 结构面与语义面同时记账（只增不减）",
            validate_manifest_consistency(broken) != []
            and replay_manifest_semantics(
                broken, registry=default_registry()) != [])


def _raises(fn):
    try:
        fn()
        return False
    except Exception:
        return True


# ══════════════════════════════════════════════════════════════════════
# 自跑器
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_r8") and callable(v)]
    print(f"== R8 第八轮 manifest 语义重放对抗复验（{len(tests)} 组）==")
    for t in tests:
        print(f"-- {t.__name__}")
        try:
            t()
        except Exception as exc:  # 测试自身崩溃=失败（不静默）
            import traceback
            traceback.print_exc()
            FAIL_N += 1
            FAILURES.append(f"{t.__name__} (CRASH: {exc})")
    print("=" * 64)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        for f in FAILURES:
            print(f"  ✗ {f}")
        sys.exit(1)
    print("ALL GREEN")
    sys.exit(0)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R8 第八轮 P0-3 残余对抗复验正本 + G9-06 同钥双改/unsigned 边界——
签名 manifest 的 lane/TTL/scope/registry 语义重放。

洞 -> 测试映射（正源：Codex 第八轮验收 findings §8/§10.1 + 第九轮预检
1.1/1.4-1；本文件是对抗复验正本，与七轮 test_gate_manifest_trust.py 不同
变体族——本轮攻击者**持有合法 release key**，全部变体先做「内部完全
自洽 + 真密钥重签」，只攻击语义面）：
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

G9-06（第九轮预检 1.4-1：registry 快照与 manifest 同一密钥签发，仍不是
独立语义根；R8-GATE-ALLOW-UNSIGNED-METADATA-004 残余：有签 artifact 可被
--allow-unsigned 跳过验签）：
  -> test_g906_same_key_double_sign_four_variants  （同钥双改四类变体全拒 rc3）
  -> test_g906_key_domain_purposes_enforced        （key 用途分域登记面执法）
  -> test_g906_scope_floor_registry_anchored       （scope 底线锚定 registry）
  -> test_g906_allow_unsigned_boundary             （已签必验签/诊断永不 PASS）

边界（诚实声明）：registry 快照签发 key 与 manifest 签名 key **相异但同
 custody**（同一持钥者两把 key）仍是「根持有者=策略持有者」——同钥双签
拒绝与用途分域能关闭的是「单 key 同步弱化 registry+manifest」的自由旁路，
key 保管分权是部署责任；该语义边界在 test_g906_* 中显式断言并留痕。

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
    BugscanPlanner, ManifestFreezeError, RegistryTrustError,
    default_registry, live_registry_view, load_trusted_registry_snapshot,
    registry_snapshot_core, replay_manifest_semantics,
    signed_registry_snapshot, validate_manifest_consistency,
)
from wenqu_core.bugscan_orchestrator import RunManifest  # noqa: E402
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

        # 诚实受保护快照（G9-06：快照 key 必须与 manifest key 相异）：
        # 建 registry 专用 key + 双 key 验签 keyring → --registry 正门 PASS
        reg_key = ApprovalKeyring.generate("key_r8_registry")
        dual = ApprovalKeyring({
            KEY_ID: keyring.get_for_signing(KEY_ID),
            "key_r8_registry": reg_key.get_for_signing("key_r8_registry"),
        })
        kdual = os.path.join(td, "keys-dual.json")
        dual.save_json(kdual)
        snap = signed_registry_snapshot(signing_keyring=reg_key,
                                        signing_key_id="key_r8_registry")
        spath = os.path.join(td, "registry-snapshot.json")
        with open(spath, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, ensure_ascii=False)
        src_, sout = _gate(["--results", *results, "--manifest", mpath,
                            "--verify-key", kdual, "--registry", spath])
        sreplay = sout.get("manifest", {}).get("semantic_replay", {})
        _ck("R8-SCOPE-003 --registry 验签快照正门（异钥）rc=0 PASS（source 落账）",
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
                           "--verify-key", kdual, "--registry", tpath])
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
                           "--verify-key", kdual, "--registry", upath])
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
                           "--verify-key", kdual, "--registry", opath])
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
                             "--verify-key", kdual, "--registry", dpath2])
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

        # G9-06：同钥重签（manifest key 签快照）已从「诚实边界」升级为拒绝
        # ——同钥双签=registry 非独立语义根（见 test_g906_same_key_*）。
        # 新诚实边界留痕：根持有者持**相异 key**（同 custody）仍可重签快照
        # （keyholder=root=策略持有者，非洞）；key 保管分权是部署责任。
        root_signed = signed_registry_snapshot(signing_keyring=reg_key,
                                               signing_key_id="key_r8_registry")
        rpath2 = os.path.join(td, "snapshot-root-resigned.json")
        with open(rpath2, "w", encoding="utf-8") as fh:
            json.dump(root_signed, fh, ensure_ascii=False)
        view = load_trusted_registry_snapshot(rpath2, keyring=dual,
                                              manifest_key_id=KEY_ID)
        _ck("R8-SCOPE-003 keyholder=root 语义边界（异钥同 custody 仍可重签——"
            "验签链只保 pin 件完整性，同钥双签已被 G9-06 拒绝）",
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


# ══════════════════════════════════════════════════════════════════════
# G9-06：同钥双改拒绝 + key 用途分域 + scope 底线锚定 + unsigned 边界
# （第九轮预检 1.4-1 / R8-GATE-ALLOW-UNSIGNED-METADATA-004 残余）
# ══════════════════════════════════════════════════════════════════════
REG_KEY_ID = "key_r9_registry"


def _weaken_resign_snapshot(secret, key_id, *, lane=None, floor=None,
                            ttl_class=None, rounds=None, scope_floor=None):
    """G9-06 攻击者快照弱化+重签（内容完全自洽：digest 重算+真密钥 HMAC）。

    与 signed_registry_snapshot 签名面逐字节同构（signature 覆盖含 key_id
    的快照全体）——弱化件在 load_trusted_registry_snapshot 验签链上完全
    合法，只能被同钥双签/用途分域拦下。
    """
    snap = registry_snapshot_core()
    if lane is not None:
        for lane_name, req in lane.items():
            snap["lane_required_stations"][lane_name] = list(req)
    if floor is not None:
        snap["downgrade_floor_stations"] = list(floor)
    if ttl_class is not None:
        for sid, (ev_class, ttl) in ttl_class.items():
            # 进程内 stations 键为 int（与既有 digest-lie 测试同口径）
            snap["stations"][sid]["evidence_class"] = ev_class
            snap["stations"][sid]["ttl_days"] = ttl
    if rounds is not None:
        snap["lane_convergence_rounds"].update(rounds)
    if scope_floor is not None:
        snap["required_scope_globs"] = list(scope_floor)
    snap["registry_digest"] = _h(
        {"registry_version": snap["registry_version"],
         "stations": snap["stations"]})
    snap["key_id"] = key_id
    snap["signature"] = sign_envelope(secret, snap)
    return snap


def _g906_case(td, name, snap, doc, stations, kpath, expect_reason="同钥"):
    """同钥双改变体执行器：弱化快照+弱化 manifest（同 key 重签）→ 必须
    rc3 registry_trust_invalid 且理由点名同钥双签。"""
    spath = os.path.join(td, f"g9-snap-{name}.json")
    with open(spath, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, ensure_ascii=False)
    mpath = os.path.join(td, f"g9-m-{name}.json")
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False)
    results = _results_dir(td, doc, list(stations), prefix=f"g9{name}")
    rc, out = _gate(["--results", *results, "--manifest", mpath,
                     "--verify-key", kpath, "--registry", spath])
    reason = out.get("reason") or ""
    _ck(f"G9-06 同钥双改[{name}] rc=3 registry_trust_invalid（{expect_reason}拒绝）",
        rc == 3 and out.get("mode") == "registry_trust_invalid"
        and ("同一 key" in reason or "同钥双签" in reason),
        f"rc={rc} mode={out.get('mode')} {_tail(reason)}")


def test_g906_same_key_double_sign_four_variants():
    """G9-06 任务A（先红后绿的绿侧正本；红侧=独立探针 probe-red-run2.txt）：
    registry 快照与 manifest **同一 key** 同步弱化（各自内容完全自洽+真
    密钥重签——持钥者可同钥双改）时必须拒绝：
      lane 缩到 [0] / TTL 7→30（evidence class 同步改）/ scope 重签缩水 /
      降档五要素拆底线（+收敛轮数弱化）全部 rc3，绝不 rc0/PASS；
    对照：诚实异钥（manifest key≠registry key）双签正门 rc0 PASS。
    """
    with tempfile.TemporaryDirectory(prefix="wq_g906a_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td)
        secret = keyring.get_for_signing(KEY_ID)
        results = _results_dir(td, doc, [0, 1])

        # 变体1：lane required 缩到 [0]（快照 lane 表+底线同步拆）
        snap1 = _weaken_resign_snapshot(
            secret, KEY_ID, lane={"FAST": [0]}, floor=[])
        doc1 = copy.deepcopy(doc)
        doc1["required_stations"] = [0]
        doc1["planner"]["required_stations"] = [0]
        doc1["station_ttls"] = {"0": doc["station_ttls"]["0"]}
        doc1 = _resign(doc1, secret)
        _g906_case(td, "lane-shrink", snap1, doc1, [0], kpath, "lane 缩[0]")

        # 变体2：TTL 7→30（站2/3 evidence_class 同步改 general 过铁律4 上限）
        manifest_s, keyring_s, mpath_s, kpath_s, doc_s = _setup(
            td, "STANDARD", run_id="run-g9-ttl",
            mname="run-manifest-ttl.json", kname="keys-ttl.json")
        secret_s = keyring_s.get_for_signing(KEY_ID)
        snap2 = _weaken_resign_snapshot(
            secret_s, KEY_ID,
            ttl_class={2: ("general", 30), 3: ("general", 30), 6: ("general", 30)})
        doc2 = copy.deepcopy(doc_s)
        doc2["station_ttls"] = {k: 30 for k in doc2["station_ttls"]}
        doc2["registry_digest"] = snap2["registry_digest"]
        doc2 = _resign(doc2, secret_s)
        _g906_case(td, "ttl-7-to-30", snap2, doc2, [0, 1, 2, 3, 4], kpath_s,
                   "TTL 7→30")

        # 变体3：scope 重签缩水（快照 scope 底线同步拆到 ["src/**"]）
        snap3 = _weaken_resign_snapshot(secret, KEY_ID,
                                        scope_floor=["src/**"])
        doc3 = copy.deepcopy(doc)
        doc3["scope"]["paths"] = ["src/**"]
        doc3["scope"]["denominator"] = 1
        doc3["identity"]["scope_hash"] = _h(
            {"paths": ["src/**"], "exclusions": []})
        doc3 = _resign(doc3, secret)
        _g906_case(td, "scope-resign", snap3, doc3, [0, 1], kpath, "scope 缩水")

        # 变体4：降档五要素拆底线（快照底线同步拆空→dropped=[1] 合法外观）
        snap4 = _weaken_resign_snapshot(secret, KEY_ID, floor=[])
        doc4 = copy.deepcopy(doc)
        doc4["planner"]["downgrade"] = _valid_downgrade()
        doc4["planner"]["dropped_stations"] = [1]
        doc4["required_stations"] = [0]
        doc4["planner"]["required_stations"] = [0]
        doc4["station_ttls"] = {"0": doc["station_ttls"]["0"]}
        doc4 = _resign(doc4, secret)
        _g906_case(td, "downgrade-floor", snap4, doc4, [0], kpath, "降档拆底线")

        # 变体5（语义域第五要素）：收敛轮数弱化（STANDARD 2→1 同步双改）
        snap5 = _weaken_resign_snapshot(secret_s, KEY_ID,
                                        rounds={"STANDARD": 1})
        doc5 = copy.deepcopy(doc_s)
        doc5["planner"]["convergence_rounds"] = 1
        doc5["registry_digest"] = snap5["registry_digest"]
        doc5 = _resign(doc5, secret_s)
        _g906_case(td, "convergence-1", snap5, doc5, [0, 1, 2, 3, 4], kpath_s,
                   "收敛轮数弱化")

        # 对照：诚实异钥双签正门（G9-06 后的诚实 --registry 形态）
        reg_key = ApprovalKeyring.generate(REG_KEY_ID)
        dual = ApprovalKeyring({
            KEY_ID: secret,
            REG_KEY_ID: reg_key.get_for_signing(REG_KEY_ID)})
        kdual = os.path.join(td, "keys-dual.json")
        dual.save_json(kdual)
        honest_snap = signed_registry_snapshot(signing_keyring=reg_key,
                                               signing_key_id=REG_KEY_ID)
        hspath = os.path.join(td, "snap-honest.json")
        with open(hspath, "w", encoding="utf-8") as fh:
            json.dump(honest_snap, fh, ensure_ascii=False)
        hrc, hout = _gate(["--results", *results, "--manifest", mpath,
                           "--verify-key", kdual, "--registry", hspath])
        _ck("G9-06 诚实 signed 正门（异钥快照）rc=0 PASS",
            hrc == 0 and hout.get("policy_verdict") == "PASS",
            f"rc={hrc} {_tail(hout.get('reason'))}")


def test_g906_key_domain_purposes_enforced():
    """G9-06 分域登记面（keyring meta ``purposes``，opt-in）：
    manifest 域 key 不得签 registry 快照（签发面+消费面）；registry 域
    key 不得签 manifest（冻结面+读回面）；未登记 purposes 的存量 key
    不受限（向后兼容）。"""
    with tempfile.TemporaryDirectory(prefix="wq_g906b_") as td:
        mk = ApprovalKeyring(
            {"key_dm": "d" * 32},
            metadata={"key_dm": {"purposes": ["manifest"]}})
        rk = ApprovalKeyring(
            {"key_dr": "e" * 32},
            metadata={"key_dr": {"purposes": ["registry"]}})
        # 签发面：manifest 域 key 签快照 → RegistryTrustError
        try:
            signed_registry_snapshot(signing_keyring=mk, signing_key_id="key_dm")
            _ck("G9-06 manifest 域 key 签快照（签发面）拒", False, "no raise")
        except RegistryTrustError as exc:
            _ck("G9-06 manifest 域 key 签快照（签发面）拒（用途域不符）",
                "用途域" in str(exc), _tail(str(exc)))
        # 消费面：攻击者持 secret 手签快照（绕过签发面）→ load 拒
        forged = _weaken_resign_snapshot("d" * 32, "key_dm", lane={"FAST": [0]},
                                         floor=[])
        fpath = os.path.join(td, "forged-snap.json")
        with open(fpath, "w", encoding="utf-8") as fh:
            json.dump(forged, fh, ensure_ascii=False)
        try:
            load_trusted_registry_snapshot(fpath, keyring=mk,
                                           manifest_key_id="key_other")
            _ck("G9-06 manifest 域 key 手签快照（消费面）拒", False, "no raise")
        except RegistryTrustError as exc:
            _ck("G9-06 manifest 域 key 手签快照（消费面）拒（分域混用）",
                "用途域混用" in str(exc) or "不含" in str(exc),
                _tail(str(exc)))
        # 冻结面：registry 域 key 签 manifest → ManifestFreezeError
        planner = BugscanPlanner(default_registry())
        plan = planner.plan("FAST")
        try:
            planner.freeze_run_manifest(
                plan, run_id="run-g9-dom", project_id="g9/erp", commit_sha=SHA,
                environment="staging", scope=["src/**", "tests/**", "tools/**"],
                ruleset={"v": 1}, data_config={"p": "d"},
                signing_keyring=rk, signing_key_id="key_dr")
            _ck("G9-06 registry 域 key 签 manifest（冻结面）拒", False,
                "no raise")
        except ManifestFreezeError as exc:
            _ck("G9-06 registry 域 key 签 manifest（冻结面）拒（用途域不符）",
                "用途域" in str(exc), _tail(str(exc)))
        # 读回面：已签 manifest 换用 registry 域口径 keyring 验 → 拒
        m = planner.freeze_run_manifest(
            plan, run_id="run-g9-dom2", project_id="g9/erp", commit_sha=SHA,
            environment="staging", scope=["src/**", "tests/**", "tools/**"],
            ruleset={"v": 1}, data_config={"p": "d"},
            signing_keyring=mk, signing_key_id="key_dm")
        mpath = os.path.join(td, "dm.json")
        m.save(mpath)
        reparse = ApprovalKeyring(
            {"key_dm": "d" * 32},
            metadata={"key_dm": {"purposes": ["registry"]}})
        try:
            RunManifest.load(mpath, keyring=reparse)
            _ck("G9-06 registry 域口径验已签 manifest（读回面）拒", False,
                "no raise")
        except ManifestFreezeError as exc:
            _ck("G9-06 registry 域口径验已签 manifest（读回面）拒",
                "用途域混用" in str(exc) or "不含" in str(exc),
                _tail(str(exc)))
        # 向后兼容：未登记 purposes 的存量 key 双域皆可（opt-in 登记面）
        legacy = ApprovalKeyring.generate("key_legacy")
        legacy_snap = signed_registry_snapshot(signing_keyring=legacy,
                                               signing_key_id="key_legacy")
        lpath = os.path.join(td, "legacy-snap.json")
        with open(lpath, "w", encoding="utf-8") as fh:
            json.dump(legacy_snap, fh, ensure_ascii=False)
        view = load_trusted_registry_snapshot(lpath, keyring=legacy)
        _ck("G9-06 未登记 purposes 的存量 key 不受限（opt-in）",
            view.source == "signed_snapshot"
            and legacy.key_purposes("key_legacy") is None)


def test_g906_scope_floor_registry_anchored():
    """G9-06 scope 语义域锚定：registry 快照/代码锚定视图都携带
    required_scope_globs 底线——manifest scope 缩水（重算 hash+重绑结果+
    真密钥重签，对 code_anchored 正源）→ scope_floor_violation BLOCKED；
    超集 scope 合法 rc0；快照缺底线/空底线不得作为重放正源。"""
    with tempfile.TemporaryDirectory(prefix="wq_g906c_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td)
        secret = keyring.get_for_signing(KEY_ID)
        results = _results_dir(td, doc, [0, 1])

        shrink = copy.deepcopy(doc)
        shrink["scope"]["paths"] = ["src/**"]      # 缩到底线之下
        shrink["scope"]["denominator"] = 1
        shrink["identity"]["scope_hash"] = _h(
            {"paths": ["src/**"], "exclusions": []})
        shrink = _resign(shrink, secret)
        spath = os.path.join(td, "scope-shrink.json")
        with open(spath, "w", encoding="utf-8") as fh:
            json.dump(shrink, fh, ensure_ascii=False)
        sres = _results_dir(td, shrink, [0, 1], prefix="shrink")
        src_, sout = _gate(["--results", *sres, "--manifest", spath,
                            "--verify-key", kpath])
        sreasons = "".join(sout.get("reasons", []))
        _ck("G9-06 scope 缩水（code_anchored 底线）rc=2 BLOCKED + "
            "scope_floor_violation",
            src_ == 2 and sout.get("policy_verdict") != "PASS"
            and "scope_floor_violation" in sreasons
            and "manifest_semantic_replay_violation" in sreasons,
            f"rc={src_} {_tail(sreasons)}")

        # 超集 scope（底线之上追加 docs/**）→ 合法 rc0
        wide, wkey = _freeze(scope=("docs/**", "src/**", "tests/**",
                                    "tools/**"))
        wpath = os.path.join(td, "scope-wide.json")
        wide.save(wpath)
        wkpath = os.path.join(td, "keys-wide.json")
        wkey.save_json(wkpath)
        wres = _results_dir(td, json.loads(wide.to_json()), [0, 1],
                            prefix="wide")
        wrc, wout = _gate(["--results", *wres, "--manifest", wpath,
                           "--verify-key", wkpath])
        _ck("G9-06 超集 scope（覆盖底线之上）rc=0 PASS",
            wrc == 0 and wout.get("policy_verdict") == "PASS",
            f"rc={wrc} {_tail(wout.get('reason'))}")

        # api 面：缩水 scope 记违例；诚实三 glob 零违例
        issues = replay_manifest_semantics(shrink,
                                           registry=default_registry())
        _ck("G9-06 replay api：缩水 scope 记 scope_floor_violation",
            any("scope_floor_violation" in i for i in issues),
            _tail("; ".join(issues)))
        issues2 = replay_manifest_semantics(
            json.loads(wide.to_json()), registry=default_registry())
        _ck("G9-06 replay api：超集 scope 零违例", issues2 == [],
            _tail("; ".join(issues2)))

        # 快照面：缺底线/空底线 → RegistryTrustError（不得作重放正源）
        reg_key = ApprovalKeyring.generate(REG_KEY_ID)
        for label, mutate in (
                ("缺 required_scope_globs",
                 lambda s: s.pop("required_scope_globs")),
                ("空 required_scope_globs",
                 lambda s: s.update(required_scope_globs=[]))):
            bad = signed_registry_snapshot(signing_keyring=reg_key,
                                           signing_key_id=REG_KEY_ID)
            mutate(bad)
            bad["signature"] = sign_envelope(
                reg_key.get_for_signing(REG_KEY_ID), bad)
            bpath = os.path.join(td, f"snap-bad-{label[:2]}.json")
            with open(bpath, "w", encoding="utf-8") as fh:
                json.dump(bad, fh, ensure_ascii=False)
            try:
                load_trusted_registry_snapshot(
                    bpath, keyring=reg_key, manifest_key_id=KEY_ID)
                _ck(f"G9-06 快照[{label}]拒绝作为重放正源", False, "no raise")
            except RegistryTrustError as exc:
                _ck(f"G9-06 快照[{label}]拒绝作为重放正源（scope 必须锚定）",
                    "required_scope_globs" in str(exc), _tail(str(exc)))


def test_g906_allow_unsigned_boundary():
    """G9-06 任务B（R8-GATE-ALLOW-UNSIGNED-METADATA-004 残余）：
    已签 artifact 永远必须验签——检测到 signature 却缺 verify key 时
    rc3（--allow-unsigned 不得跳过验签）；--allow-unsigned 仅对真正
    unsigned 诊断件可用且结论只能是 BLOCKED/NOT_EVALUATED，永不 PASS。"""
    with tempfile.TemporaryDirectory(prefix="wq_g906d_") as td:
        manifest, keyring, mpath, kpath, doc = _setup(td)
        results = _results_dir(td, doc, [0, 1])

        # B1：已签 manifest 只传 --allow-unsigned（无 verify key）→ rc3
        b1rc, b1out = _gate(["--results", *results, "--manifest", mpath,
                             "--allow-unsigned"])
        b1reason = b1out.get("reason") or ""
        _ck("G9-06 已签 manifest + --allow-unsigned（无 key）rc=3 不跳验签",
            b1rc == 3 and b1out.get("mode") == "manifest_invalid"
            and b1out.get("policy_verdict") != "PASS"
            and ("签名字段" in b1reason or "永远必须验签" in b1reason),
            f"rc={b1rc} {_tail(b1reason)}")
        # B1'：同件 --verify-key + --allow-unsigned → 正常验签 rc0（不误伤）
        b1prc, b1pout = _gate(["--results", *results, "--manifest", mpath,
                               "--verify-key", kpath, "--allow-unsigned"])
        _ck("G9-06 已签 manifest + --verify-key（allow-unsigned 不误伤）rc=0",
            b1prc == 0 and b1pout.get("policy_verdict") == "PASS",
            f"rc={b1prc} {_tail(b1pout.get('reason'))}")

        # B2：真 unsigned 诊断件 → BLOCKED/NOT_EVALUATED，永不 PASS
        unsigned = copy.deepcopy(doc)
        unsigned.pop("signature")
        unsigned.pop("key_id")
        unsigned.pop("manifest_hash")
        unsigned["manifest_hash"] = _h(
            {k: v for k, v in unsigned.items() if k != "manifest_hash"})
        upath = os.path.join(td, "unsigned.json")
        with open(upath, "w", encoding="utf-8") as fh:
            json.dump(unsigned, fh, ensure_ascii=False)
        ures = _results_dir(td, unsigned, [0, 1], prefix="uns")
        b2rc, b2out = _gate(["--results", *ures, "--manifest", upath,
                             "--allow-unsigned"])
        sig = b2out.get("manifest", {}).get("signature", {})
        _ck("G9-06 真 unsigned + --allow-unsigned rc=2 永不 PASS",
            b2rc == 2 and b2out.get("policy_verdict") in ("BLOCKED",
                                                          "NOT_EVALUATED")
            and b2out.get("aggregate_outcome") == BLOCKED
            and "unsigned_manifest_never_pass" in "".join(
                b2out.get("reasons", [])),
            f"rc={b2rc} {_tail(b2out.get('reason'))}")
        _ck("G9-06 unsigned 诊断件元数据如实（signed=false/"
            "allow_unsigned_downgrade=true）",
            sig.get("signed") is False
            and sig.get("verified") is False
            and sig.get("allow_unsigned_downgrade") is True,
            _tail(json.dumps(sig)))
        # B2'：真 unsigned + --verify-key 无 --allow-unsigned → 默认拒 rc3
        b2prc, b2pout = _gate(["--results", *ures, "--manifest", upath,
                               "--verify-key", kpath])
        _ck("G9-06 真 unsigned + --verify-key（无 allow-unsigned）rc=3 默认拒",
            b2prc == 3 and b2pout.get("mode") == "manifest_invalid",
            f"rc={b2prc} {_tail(b2pout.get('reason'))}")

        # API 面（RunManifest.load）：
        try:
            RunManifest.load(mpath)
            _ck("G9-06 load 已签件无 keyring 拒", False, "no raise")
        except ManifestFreezeError as exc:
            _ck("G9-06 load 已签件无 keyring 拒（已签 artifact 必须验签）",
                "永远必须验签" in str(exc) or "签名字段" in str(exc),
                _tail(str(exc)))
        try:
            RunManifest.load(mpath, allow_unsigned=True)
            _ck("G9-06 load 已签件 allow_unsigned 也不得跳验签", False,
                "no raise")
        except ManifestFreezeError:
            _ck("G9-06 load 已签件 allow_unsigned 也不得跳验签", True)
        legacy = RunManifest.load(upath)
        _ck("G9-06 load 真 unsigned 无 keyring 保持 legacy 口径可读",
            legacy.manifest_hash == unsigned["manifest_hash"])


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
             if k.startswith(("test_r8", "test_g906")) and callable(v)]
    print(f"== R8+G9-06 manifest 语义重放对抗复验（{len(tests)} 组）==")
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

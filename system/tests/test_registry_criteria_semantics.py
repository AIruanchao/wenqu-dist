#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W11-04 对抗复验正本——registry 判据三态语义（R10-REGISTRY-ERROR-
CRITERIA-CHAR-SPLIT-006 根修）。

洞 -> 测试映射（正源：wq10-report R10-...-006 + wq11-plan W11-04）：
  根因：8 站 ``error=("单句")`` 缺元组逗号 → ``to_dict()`` 的 ``list(str)``
  把整句静默拆成单字符数组；旧 validator 只查「非空」→ 部署位快照
  8/8 站 error 判据=单字符数组且验签全过。
    -> test_default_eight_stations_error_criteria_full_sentences（绿对照）
    -> test_constructor_rejects_str_bytes_and_malformed_shapes（构造面）
    -> test_validate_criteria_mapping_shape_rules（dict 形状面）
    -> test_to_dict_validates_before_serialization（旁路注入也拒）
    -> test_registry_validate_rejects_bypassed_malformed_criteria（注册表面）
    -> test_loader_rejects_malformed_criteria_even_validly_resigned（核心：
       合法 registry key 重签畸形内容 → loader 仍 RegistryTrustError）
    -> test_provision_cli_exit_codes（CLI 0/2/3 契约）

纯标准库；``python3 system/tests/test_registry_criteria_semantics.py``
（exit 0=全绿），兼容 pytest。
"""

import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope  # noqa: E402
from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    CriteriaValueError, REGISTRY_VERSION, StationCriteria, StationRegistry,
    RegistryTrustError, _hash_obj, default_registry,
    load_trusted_registry_snapshot, signed_registry_snapshot,
    validate_criteria_mapping,
)

TOOL = os.path.join(os.path.dirname(REPO), "tools", "provision_registry_root.py")
SENTENCE = "指纹计算失败（git 不可用/哈希异常）"  # 站0 error 判据原句（正源）
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


def _mk(**overrides):
    fields = {"pass_": ("全绿",), "fail": ("门红",), "error": (SENTENCE,)}
    fields.update(overrides)
    return StationCriteria(**fields)


# --------------------------------------------------------------- #
# 1) 默认八站——error 判据必须是完整句子（绿对照）
# --------------------------------------------------------------- #

def test_default_eight_stations_error_criteria_full_sentences():
    reg = default_registry()
    for spec in reg.all():
        items = spec.criteria.error
        _ck(f"站{spec.station_id} error 为非空元组",
            isinstance(items, tuple) and len(items) >= 1, repr(items))
        _ck(f"站{spec.station_id} error 每条为完整句（≥2 字符）",
            all(isinstance(x, str) and len(x) >= 2 for x in items), repr(items))
        _ck(f"站{spec.station_id} to_dict 不拆字符",
            spec.criteria.to_dict()["error"] == list(items))
    _ck("站0 error 原句逐字保留", reg.get(0).criteria.error == (SENTENCE,))
    _ck("版本已递增（w6a-1.2.0）", REGISTRY_VERSION == "w6a-1.2.0",
        REGISTRY_VERSION)
    _ck("registry_digest 已随修复变化",
        reg.registry_digest()
        != "3027e7c7fbf85ad307e4170b3ef13acf69b8b0f3dc132c7f4d9d34415fc3987f")


# --------------------------------------------------------------- #
# 2) 构造面——str/bytes/空/单字符/空白/超长/控制字符/重复/>16 全拒
# --------------------------------------------------------------- #

def test_constructor_rejects_str_bytes_and_malformed_shapes():
    cases = [
        ("str 退化（缺逗号原形）", SENTENCE),
        ("bytes 退化", (b"env broken",)),
        ("空元组", ()),
        ("单字符拆分数组", ("指", "纹")),
        ("纯空白条目", ("   ",)),
        ("首尾空白条目", (" 好句子的确如此 ",)),
        ("超长条目>512", ("长" * 513,)),
        ("控制字符条目", ("好句\n子",)),
        ("态内重复条目", (SENTENCE, SENTENCE)),
        (">16 条", tuple(f"编号{i:02d}的句子" for i in range(17))),
    ]
    for name, bad in cases:
        try:
            _mk(error=bad)
            _ck(f"构造拒 {name}", False, "no raise")
        except CriteriaValueError:
            _ck(f"构造拒 {name}", True)
    ok = _mk(error=["另一句合法判据", "再一句合法判据"])
    _ck("合法 list 输入归一 tuple",
        ok.error == ("另一句合法判据", "再一句合法判据"))


# --------------------------------------------------------------- #
# 3) dict 形状面——缺键/未知键/非映射/裸 str/空/字符数组 全拒
# --------------------------------------------------------------- #

def test_validate_criteria_mapping_shape_rules():
    base = {"pass": ["全绿"], "fail": ["门红"], "error": [SENTENCE]}
    docs = [
        ("非映射 list", [base]),
        ("缺 error 键", {k: v for k, v in base.items() if k != "error"}),
        ("未知键", {**base, "警示": ["x"]}),
        ("error 裸 str", {**base, "error": SENTENCE}),
        ("error 空 list", {**base, "error": []}),
        ("error 字符数组", {**base, "error": list(SENTENCE)}),
    ]
    for name, doc in docs:
        try:
            validate_criteria_mapping(doc, where="t")
            _ck(f"映射拒 {name}", False, "no raise")
        except CriteriaValueError:
            _ck(f"映射拒 {name}", True)
    out = validate_criteria_mapping(base, where="t")
    _ck("合法映射归一 tuple",
        out == {"pass": ("全绿",), "fail": ("门红",), "error": (SENTENCE,)})


# --------------------------------------------------------------- #
# 4) to_dict 旁路面——object.__setattr__ 注入也必须在出口被拦
# --------------------------------------------------------------- #

def test_to_dict_validates_before_serialization():
    sc = _mk()
    object.__setattr__(sc, "error", SENTENCE)
    try:
        sc.to_dict()
        _ck("to_dict 拒旁路 str", False, "no raise")
    except CriteriaValueError:
        _ck("to_dict 拒旁路 str", True)
    sc2 = _mk()
    object.__setattr__(sc2, "error", tuple(SENTENCE))
    try:
        sc2.to_dict()
        _ck("to_dict 拒旁路字符数组", False, "no raise")
    except CriteriaValueError:
        _ck("to_dict 拒旁路字符数组", True)


# --------------------------------------------------------------- #
# 5) StationRegistry——旁路注入畸形判据的站定义整体拒
# --------------------------------------------------------------- #

def test_registry_validate_rejects_bypassed_malformed_criteria():
    specs = list(default_registry().all())
    saved = specs[0].criteria.error
    object.__setattr__(specs[0].criteria, "error", tuple(SENTENCE))
    try:
        StationRegistry(tuple(specs))
        _ck("注册表拒旁路畸形判据", False, "no raise")
    except ValueError:
        _ck("注册表拒旁路畸形判据", True)
    finally:
        object.__setattr__(specs[0].criteria, "error", saved)


# --------------------------------------------------------------- #
# 6) 核心：合法 registry key 重签畸形内容 → loader 仍 RegistryTrustError
# --------------------------------------------------------------- #

def _resign_malformed(snap_path, secret, mutate):
    """读回合法快照 → 注入畸形判据 → digest 重算 + 真 key 重签（攻击本体）。"""
    with open(snap_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    mutate(doc)
    doc["registry_digest"] = _hash_obj(
        {"registry_version": doc["registry_version"],
         "stations": doc["stations"]})
    doc.pop("signature", None)
    doc["signature"] = sign_envelope(secret, doc)
    out = snap_path + ".malformed"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False)
    return out


def test_loader_rejects_malformed_criteria_even_validly_resigned():
    with tempfile.TemporaryDirectory(prefix="wq_w11_") as td:
        kid = "key_w11_registry"
        kr = ApprovalKeyring.generate(kid)
        secret = kr.get_for_signing(kid)
        snap = signed_registry_snapshot(signing_keyring=kr, signing_key_id=kid)
        spath = os.path.join(td, "snapshot.json")
        with open(spath, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, ensure_ascii=False)
        view = load_trusted_registry_snapshot(spath, keyring=kr)
        _ck("诚实快照 loader 通过",
            view.source == "signed_snapshot"
            and view.registry_version == REGISTRY_VERSION)
        mutations = [
            ("字符拆分数组（部署位原畸形）",
             lambda d: d["stations"]["0"]["criteria"].update(
                 error=list(d["stations"]["0"]["criteria"]["error"][0]))),
            ("error 裸字符串",
             lambda d: d["stations"]["3"]["criteria"].update(
                 error=d["stations"]["3"]["criteria"]["error"][0])),
            ("error 空数组",
             lambda d: d["stations"]["5"]["criteria"].update(error=[])),
            ("判据缺键（删 fail）",
             lambda d: d["stations"]["1"]["criteria"].pop("fail")),
            ("判据未知键",
             lambda d: d["stations"]["2"]["criteria"].update(警示=["x"])),
            ("空白条目",
             lambda d: d["stations"]["7"]["criteria"].update(error=["   "])),
            ("态内重复条目",
             lambda d: d["stations"]["4"]["criteria"].update(
                 error=["重复的句子", "重复的句子"])),
        ]
        for name, mutate in mutations:
            bad = _resign_malformed(spath, secret, mutate)
            try:
                load_trusted_registry_snapshot(bad, keyring=kr)
                _ck(f"loader 拒合法钥重签的{name}", False, "no raise")
            except RegistryTrustError as exc:
                _ck(f"loader 拒合法钥重签的{name}", "criteria" in str(exc),
                    str(exc)[:150])
        try:
            load_trusted_registry_snapshot(spath, keyring=kr,
                                           manifest_key_id=kid)
            _ck("同钥双签拒", False, "no raise")
        except RegistryTrustError:
            _ck("同钥双签拒", True)


# --------------------------------------------------------------- #
# 7) 签发/验证 CLI 退出码：0 / 2 参数 / 3 语义或信任失败
# --------------------------------------------------------------- #

def test_provision_cli_exit_codes():
    with tempfile.TemporaryDirectory(prefix="wq_w11_cli_") as td:
        kid = "key_w11_cli"
        kr = ApprovalKeyring.generate(kid)
        kpath = os.path.join(td, "keys.json")
        kr.save_json(kpath)
        out = os.path.join(td, "registry-root.json")
        env = dict(os.environ, PYTHONPATH=REPO)
        r0 = subprocess.run(
            [sys.executable, TOOL, "--keyring", kpath, "--key-id", kid,
             "--out", out, "--verify"],
            capture_output=True, text=True, env=env)
        _ck("CLI 正常签发+verify rc=0", r0.returncode == 0,
            f"{r0.returncode} {r0.stderr[-200:]}")
        _ck("CLI 产物 0600", oct(os.stat(out).st_mode & 0o777) == "0o600")
        _ck("CLI 产物判据非畸形",
            all(len(x) >= 2 for x in
                json.load(open(out))["stations"]["0"]["criteria"]["error"]))
        r2 = subprocess.run([sys.executable, TOOL], capture_output=True,
                            text=True, env=env)
        _ck("CLI 缺参数 rc=2", r2.returncode == 2)
        bad_kr = ApprovalKeyring(
            {kid: kr.get_for_signing(kid)},
            metadata={kid: {"purposes": ["manifest"]}})
        bad_path = os.path.join(td, "keys-manifest-domain.json")
        bad_kr.save_json(bad_path)
        r3 = subprocess.run(
            [sys.executable, TOOL, "--keyring", bad_path, "--key-id", kid,
             "--out", os.path.join(td, "never.json")],
            capture_output=True, text=True, env=env)
        _ck("CLI manifest 域钥签 registry rc=3", r3.returncode == 3,
            f"{r3.returncode} {r3.stderr[-200:]}")


if __name__ == "__main__":
    test_default_eight_stations_error_criteria_full_sentences()
    test_constructor_rejects_str_bytes_and_malformed_shapes()
    test_validate_criteria_mapping_shape_rules()
    test_to_dict_validates_before_serialization()
    test_registry_validate_rejects_bypassed_malformed_criteria()
    test_loader_rejects_malformed_criteria_even_validly_resigned()
    test_provision_cli_exit_codes()
    print(f"\n{'=' * 60}\nW11-04 criteria semantics: {PASS_N} passed, {FAIL_N} failed")
    if FAILURES:
        print("Failures:", *FAILURES, sep="\n  - ")
        sys.exit(1)
    print("ALL CRITERIA SEMANTICS TESTS PASSED")

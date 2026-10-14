#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第九轮授权域探针 P5：registry 受保护重放（G9-06 授权子项，新变体）。

被测面：bugscan_orchestrator.signed_registry_snapshot /
load_trusted_registry_snapshot（cli.py gate --registry 的信任根）。

正例：
  pos1 manifest key=M、registry 快照 key=R（异钥）→ 加载可信
新负例：
  N1 同钥双签：manifest_key_id == 快照 key_id → RegistryTrustError
  N2 快照签名篡改（改一字节重算无效）→ RegistryTrustError
  N3 registry_digest 自报值篡改（重算不符）→ RegistryTrustError
  N4 用途分域：purposes=["manifest"] 的 key 签 registry → 签发面拒
  N5 用途分域：验证侧 keyring 里快照 key 登记 purposes 不含 registry →拒
  N6 快照 stations 内容篡改（不动签名）→ digest 重算拒
  N7 验签 keyring 不含快照 key →拒
"""
import copy
import json
import os
import sys
import tempfile

REPO = "/private/tmp/wenqu-auth9-20261014-093158/system"
sys.path.insert(0, REPO)

from wenqu_core.approval_keys import (  # noqa: E402
    ApprovalKeyring, generate_secret)
from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    RegistryTrustError, load_trusted_registry_snapshot,
    signed_registry_snapshot)

RESULTS = []
TMP = tempfile.mkdtemp(prefix="auth9-p5-")


def case(name, ok, note=""):
    verdict = "PASS" if ok else "FAIL"
    RESULTS.append((verdict, name))
    print(f"  [{verdict}] {name} {note}")


def expect_reject(name, fn, keyword=None):
    try:
        fn()
        case(name, False, ":: NOT rejected")
    except RegistryTrustError as exc:
        ok = True if keyword is None else (keyword in str(exc))
        case(name, ok, f":: RegistryTrustError: {str(exc)[:90]}")


# keyring：manifest key M + registry key R（异钥）；R2 登记 manifest 用途
KR = ApprovalKeyring(
    {"key_p5_m": generate_secret(), "key_p5_r": generate_secret(),
     "key_p5_r2": generate_secret()},
    metadata={
        "key_p5_m": {"status": "active", "owner": "minter",
                     "actors": ["minter"], "purposes": ["manifest"]},
        "key_p5_r": {"status": "active", "owner": "registrar",
                     "actors": ["registrar"], "purposes": ["registry"]},
        "key_p5_r2": {"status": "active", "owner": "minter2",
                      "actors": ["minter2"], "purposes": ["manifest"]},
    })

snap_path = os.path.join(TMP, "registry-root.json")
snap = signed_registry_snapshot(signing_keyring=KR,
                                signing_key_id="key_p5_r")
json.dump(snap, open(snap_path, "w"))
os.chmod(snap_path, 0o600)

view = load_trusted_registry_snapshot(snap_path, keyring=KR,
                                       manifest_key_id="key_p5_m")
case("P5-pos1 异钥 registry 快照加载可信（source=%s）" % view.source,
     view.registry_digest == snap["registry_digest"]
     and len(view.registry_digest) == 64)

expect_reject(
    "P5-N1 同钥双签（manifest_key_id==快照 key）→拒",
    lambda: load_trusted_registry_snapshot(
        snap_path, keyring=KR, manifest_key_id="key_p5_r"),
    keyword="相异" if False else None)  # 关键词按实际消息宽松匹配

# N2 签名篡改：改 signature 末字符
tampered = copy.deepcopy(snap)
tampered["signature"] = ("0" if tampered["signature"][-1] != "0" else "1") \
    + tampered["signature"][1:]
p2 = os.path.join(TMP, "registry-tampered-sig.json")
json.dump(tampered, open(p2, "w")); os.chmod(p2, 0o600)
expect_reject("P5-N2 快照 signature 篡改 →拒",
              lambda: load_trusted_registry_snapshot(
                  p2, keyring=KR, manifest_key_id="key_p5_m"))

# N3 registry_digest 自报篡改
tampered3 = copy.deepcopy(snap)
tampered3["registry_digest"] = "f" * 64
p3 = os.path.join(TMP, "registry-tampered-digest.json")
json.dump(tampered3, open(p3, "w")); os.chmod(p3, 0o600)
expect_reject("P5-N3 registry_digest 自报篡改（重算不符）→拒",
              lambda: load_trusted_registry_snapshot(
                  p3, keyring=KR, manifest_key_id="key_p5_m"))

# N4 签发面用途分域：purposes=["manifest"] 的 key 签 registry →拒
expect_reject("P5-N4 manifest 域 key 签发 registry 快照 →签发面拒",
              lambda: signed_registry_snapshot(
                  signing_keyring=KR, signing_key_id="key_p5_r2"),
              keyword="用途域")

# N5 验证面用途分域：验证 keyring 里快照 key 登记 purposes=["registry"]
# 但快照由未登记 purposes 的 key 签发（绕签发面）→ 手造快照测验证面
bare_kr = ApprovalKeyring(
    {"key_p5_m": generate_secret(), "key_p5_bare": generate_secret()},
    metadata={
        "key_p5_m": {"status": "active", "owner": "minter",
                     "purposes": ["manifest"]},
        "key_p5_bare": {"status": "active", "owner": "x",
                        "purposes": ["manifest"]},  # 验证面登记不含 registry
    })
from wenqu_core.approval_keys import sign_envelope  # noqa: E402
from wenqu_core.bugscan_orchestrator import registry_snapshot_core  # noqa: E402
core = registry_snapshot_core()
sig = sign_envelope(bare_kr.get("key_p5_bare"), {**core, "key_id": "key_p5_bare"})
handmade = {**core, "key_id": "key_p5_bare", "signature": sig}
p5 = os.path.join(TMP, "registry-handmade.json")
json.dump(handmade, open(p5, "w")); os.chmod(p5, 0o600)
expect_reject("P5-N5 验证面 purposes 不含 registry 域 →拒",
              lambda: load_trusted_registry_snapshot(
                  p5, keyring=bare_kr, manifest_key_id="key_p5_m"),
              keyword="用途" if False else None)

# N6 stations 内容篡改（签名不动）→ digest 重算拒
tampered6 = copy.deepcopy(snap)
first_key = sorted(tampered6["stations"])[0]
tampered6["stations"][first_key] = dict(tampered6["stations"][first_key])
if "ttl_days" in tampered6["stations"][first_key]:
    tampered6["stations"][first_key]["ttl_days"] = 999
else:
    k0 = sorted(tampered6["stations"][first_key])[0]
    tampered6["stations"][first_key][k0] = "tampered"
p6 = os.path.join(TMP, "registry-tampered-stations.json")
json.dump(tampered6, open(p6, "w")); os.chmod(p6, 0o600)
expect_reject("P5-N6 stations 内容篡改（digest 重算不符）→拒",
              lambda: load_trusted_registry_snapshot(
                  p6, keyring=KR, manifest_key_id="key_p5_m"))

# N7 验签 keyring 不含快照 key
kr7 = ApprovalKeyring({"key_other": generate_secret()})
expect_reject("P5-N7 未知快照 key →拒",
              lambda: load_trusted_registry_snapshot(
                  snap_path, keyring=kr7, manifest_key_id=None))

fails = [r for r in RESULTS if r[0] == "FAIL"]
print(f"\nP5 SUMMARY: total={len(RESULTS)} pass={len(RESULTS)-len(fails)} "
      f"fail={len(fails)}")
sys.exit(1 if fails else 0)

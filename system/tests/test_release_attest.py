#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_release_attest.py——tools/release_attest.py（release manifest/签名/SBOM/
verify 四件套）全链自测。

锚点：删除 tools/release_attest.py 后此测试必红（文件级依赖 + 行为断言）。
任务冻结验收链（Codex 多轮缺口：制品无签名/SBOM）：

  build → sign → sbom → verify 全绿
  篡改 tar 一字节           → verify 必拒（exit 1）
  换 key 验签                → verify 必拒
  SBOM 字段完整性            → SPDX 2.3 必填字段/根包/逐文件 hash/验证码全断言

对抗加固（本仓红探针风格，fail-closed 全闭）：
  重打包攻击（改文件内容+自洽改 manifest 的 artifact/file hash）→ 签名拦截；
  篡改 manifest / sig / sbom 任一 → verify 必拒；
  未知 key_id / rotated key 签发 → sign 拒；revoked key 验签即拒；
  确定性构建：同 commit 两次 build → tar sha256 字节一致。

R7-REL-POLICY-HASH-011 根修回归钉（2026-10-08 第七轮 P0：release policy
hash 曾截损 61hex 且 verify 不校验绑定）：
  manifest.policy_hash.plan_sha256 必须是 64hex 且 == tar 内方案快照实算值
  == 冻结正源值；差一位 hex（重签自洽攻击）/ 61hex 截损（重签）/ 缺
  policy_hash / 成员不存在 → verify 必拒（exit 1）。

R8-REL-PIN-ROOT 根修回归钉（2026-10-08 第八轮 P0-7 残余：自洽替换可签
可验 + source commit 未验受保护根）：
  外部受保护 plan pin（--plan-pin/$WENQU_PLAN_PIN/默认位）冻结值必须同时
  == manifest.plan_sha256 == tar 内实算值；tar 方案替换 + manifest/签名/
  SBOM 全自洽重算的整套伪造 → verify 必拒（pin 断裂）；pin 缺失 / 值篡改 /
  权限过宽（组其他可写）→ 必拒。manifest.source_commit 指不存在 commit
  （幽灵 40hex，已重签）→ 必拒；--repo 树内方案 hash 漂移 → 必拒。

密钥纪律：测试只用 system/tests/fixtures/approval-keys.json（测试专用 HMAC
密钥，仓内公开）与运行时临时目录生成的临时 keyring；生产签发密钥绝不入档、
绝不回显。HMAC 为对称签名（tamper-evident，非非否认）——诚实边界见工具头注。

独立运行：python3 system/tests/test_release_attest.py
exit 0 = 全部用例绿。
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Dict, List, Tuple

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(TESTS_DIR))
TOOL = os.path.join(REPO_ROOT, "tools", "release_attest.py")
FIXTURE_KEYRING = os.path.join(TESTS_DIR, "fixtures", "approval-keys.json")

#: 方案冻结正源（独立字面量，非 import 同源——防同源盲区：若工具 import 链
#: 被改坏，此处独立钉住第七轮定案的 64hex 真值）。
PLAN_MEMBER = "evidence/00-baseline/codex-external/方案.md"
PLAN_SHA256_TRUTH = ("96b8646f6f08fd5fc408bc64f332dff0"
                     "aeabbb5bf51d3129fcaaa24612c32306")
#: 第七轮 P0 实锄的 61hex 截损值（R7-REL-POLICY-HASH-011 案发常量）。
PLAN_SHA256_BUGGY_61 = ("96b8646f6f08fd5fc408bc64f332dff0"
                        "aeabbb5bf51d9fcaaa24612c32306")

PASS_N = FAIL_N = 0


def check(name: str, fn) -> None:
    global PASS_N, FAIL_N
    print(f"  ---- {name}")
    try:
        fn()
    except AssertionError as exc:
        FAIL_N += 1
        print(f"    ❌ {exc}")
    except Exception as exc:  # noqa: BLE001 —— 环境错也按红处理
        FAIL_N += 1
        print(f"    ❌ [异常] {type(exc).__name__}: {exc}")
    else:
        PASS_N += 1
        print("    ✅")


def run_tool(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_pin(path: str, value: str = PLAN_SHA256_TRUTH,
              mode: int = 0o600) -> str:
    """产测试 plan pin（0600 纪律与 install-release.sh 部署 pin 同构）。"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(value + "\n")
    os.chmod(path, mode)
    return path


def full_chain(workdir: str, keyring: str = FIXTURE_KEYRING,
               key_id: str = "key_test_1"
               ) -> Tuple[str, str, str, str, subprocess.CompletedProcess]:
    """build+sign+sbom+verify 全链；返回 (tar, manifest, sig, sbom, verify_proc)。

    R8 起 verify 需要外部 plan pin：每链在 workdir 落一枚正确 pin 并以
    WENQU_PLAN_PIN 传给子进程（显式 --plan-pin 的对抗用例自行覆盖）。"""
    pin = write_pin(os.path.join(workdir, "plan.pin"))
    os.environ["WENQU_PLAN_PIN"] = pin
    r = run_tool("build", "--dist-dir", os.path.join(workdir, "dist"))
    assert r.returncode == 0, f"build 失败: {r.stderr}\n{r.stdout}"
    dist = os.path.join(workdir, "dist")
    tars = [f for f in os.listdir(dist) if f.endswith(".tar.gz")]
    assert len(tars) == 1, f"应恰有 1 个制品: {tars}"
    stem = os.path.join(dist, tars[0][: -len(".tar.gz")])
    manifest, sig, sbom = (f"{stem}.manifest.json", f"{stem}.release.sig",
                           f"{stem}.sbom.spdx.json")
    r = run_tool("sign", "--manifest", manifest, "--keyring", keyring,
                 "--key-id", key_id)
    assert r.returncode == 0, f"sign 失败: {r.stderr}"
    r = run_tool("sbom", "--manifest", manifest)
    assert r.returncode == 0, f"sbom 失败: {r.stderr}"
    v = run_tool("verify", "--manifest", manifest, "--keyring", keyring)
    return f"{stem}.tar.gz", manifest, sig, sbom, v


def write_keyring(path: str, keys: Dict[str, str],
                   meta: Dict[str, Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"keys": keys, "meta": meta}, fh)
    # R7-AUTH-KEY-PERM-006 对齐：loader 对非 0600 keyring fail-closed——
    # 测试自产 keyring 一律收紧到 0600（与生产 keyring 同纪律）。
    os.chmod(path, 0o600)


# ====================================================================== #
# 1. 全链绿 + 确定性构建
# ====================================================================== #
def test_full_chain_green_and_deterministic():
    with tempfile.TemporaryDirectory() as tmp:
        tar, manifest, sig, sbom, v = full_chain(tmp)
        assert v.returncode == 0, f"全链 verify 应绿:\n{v.stdout}\n{v.stderr}"
        for line in ("manifest-schema", "artifact-hash", "files-reconcile",
                     "plan-hash", "plan-pin", "source-commit", "signature",
                     "sbom-reconcile", "build-identity"):
            assert f"PASS  {line}" in v.stdout, f"缺 PASS {line}:\n{v.stdout}"
        # 四件套齐 + manifest 基本身份字段
        for p in (tar, manifest, sig, sbom):
            assert os.path.isfile(p), f"产物缺失: {p}"
        m = json.load(open(manifest, encoding="utf-8"))
        assert re.fullmatch(r"[0-9a-f]{40}", m["source_commit"]), \
            f"source_commit 应为完整 sha: {m['source_commit']}"
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                            m["built_at"]), f"built_at 非 ISO8601Z: {m['built_at']}"
        assert m["tool_version"] and m["argv"] and m["builder"]["user"], \
            "工具版本/argv/builder 缺失（evidence/09 填写规则：含 argv/commit/环境）"
        assert m["artifact"]["sha256"] == sha256_file(tar), "制品 hash 与实算不符"
        assert m["artifact"]["size"] == os.path.getsize(tar)
        assert len(m["files"]) == m["n_files"] >= 600, \
            f"发行树文件数异常: {m['n_files']}"
        # R7-011：policy_hash 必须实算=冻结=64hex（manifest 侧三重钉）
        ph = m["policy_hash"]
        assert re.fullmatch(r"[0-9a-f]{64}", ph["plan_sha256"]), \
            f"plan_sha256 非 64hex: {ph['plan_sha256']!r}"
        assert ph["plan_sha256"] == PLAN_SHA256_TRUTH, \
            f"plan_sha256 与冻结正源不符: {ph['plan_sha256']}"
        assert ph["plan_member"] == PLAN_MEMBER
        with tarfile.open(tar, "r:gz") as tf:
            fh_ = tf.extractfile(PLAN_MEMBER)
            assert fh_ is not None, f"tar 缺方案快照成员: {PLAN_MEMBER}"
            member_sha = hashlib.sha256(fh_.read()).hexdigest()
        assert ph["plan_sha256"] == member_sha, \
            "policy_hash.plan_sha256 与 tar 内方案快照实算值不等（绑定断裂）"

        # 确定性：同 commit 二次 build → tar 字节一致
        r2 = run_tool("build", "--dist-dir", os.path.join(tmp, "dist2"))
        assert r2.returncode == 0, r2.stderr
        tar2 = [os.path.join(tmp, "dist2", f) for f in
                os.listdir(os.path.join(tmp, "dist2"))
                if f.endswith(".tar.gz")][0]
        assert sha256_file(tar2) == m["artifact"]["sha256"], (
            "同 commit 重建 tar sha256 漂移——确定性构建破坏（gzip mtime 未钉死?）")


# ====================================================================== #
# 2. 篡改 tar 一字节 → verify 必拒
# ====================================================================== #
def test_tamper_tar_one_byte_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        tar, manifest, sig, sbom, v = full_chain(tmp)
        assert v.returncode == 0, "前置全链应绿"
        data = bytearray(open(tar, "rb").read())
        mid = len(data) // 2
        data[mid] ^= 0xFF  # 翻转一字节（保证值变）
        with open(tar, "wb") as fh:
            fh.write(bytes(data))
        v2 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v2.returncode != 0, f"篡改 tar 一字节后 verify 仍绿:\n{v2.stdout}"
        assert "FAIL" in v2.stdout, "应有 FAIL 行"
        assert "制品 hash/size 不符" in v2.stdout, \
            f"失败原因应指向制品 hash: {v2.stdout}"


# ====================================================================== #
# 3. 重打包攻击：改内容+自洽改 manifest → 签名拦截
# ====================================================================== #
def _repack_with_changed_file(tar_path: str, victim_suffix: str
                              ) -> Tuple[str, str]:
    """重建 tar（替换一个文件内容），返回 (新 tar 路径, 被改的成员名)。"""
    with tarfile.open(tar_path, "r:gz") as tf:
        members = tf.getmembers()
        victim = next(m for m in members
                      if m.isfile() and m.name.endswith(victim_suffix)
                      and "/evidence/" not in f"/{m.name}")
        payloads: Dict[str, bytes] = {}
        for m in members:
            if m.isfile():
                fh = tf.extractfile(m)
                payloads[m.name] = b"" if fh is None else fh.read()
    original = payloads[victim.name]
    payloads[victim.name] = original + b"\n# tampered by test\n"
    out = tar_path  # 原地重写
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as wtf:
        for m in members:
            if m.isfile():
                data = payloads[m.name]
                m.size = len(data)
                wtf.addfile(m, io.BytesIO(data))
            else:
                wtf.addfile(m)
    with open(out, "wb") as fh:
        with gzip.GzipFile(fileobj=fh, mode="wb", compresslevel=9,
                           mtime=0, filename="") as gz:
            gz.write(buf.getvalue())
    return out, victim.name


def test_repack_attack_selfconsistent_manifest_caught_by_signature():
    with tempfile.TemporaryDirectory() as tmp:
        tar, manifest, sig, sbom, v = full_chain(tmp)
        assert v.returncode == 0, "前置全链应绿"
        m = json.load(open(manifest, encoding="utf-8"))

        _repacked, victim = _repack_with_changed_file(tar, "CHANGELOG.md")
        new_sha = sha256_file(tar)
        new_size = os.path.getsize(tar)
        # 攻击者自洽更新 manifest：artifact hash/size + 被改文件的逐文件 hash/size
        with tarfile.open(tar, "r:gz") as tf:
            ti = tf.getmember(victim)
            fh = tf.extractfile(victim)
            victim_sha = hashlib.sha256(fh.read()).hexdigest()
            victim_size = ti.size
        m["artifact"]["sha256"] = new_sha
        m["artifact"]["size"] = new_size
        for f in m["files"]:
            if f["path"] == victim:
                f["sha256"] = victim_sha
                f["size"] = victim_size
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump(m, fh, ensure_ascii=False, indent=1, sort_keys=True)
        v2 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v2.returncode != 0, (
            "重打包+自洽改 manifest 后 verify 仍绿——detached 签名未覆盖 manifest!")
        assert "验签失败" in v2.stdout, \
            f"应被签名拦截（而非其他环节）:\n{v2.stdout}"
        # 逐文件对账本身应已自洽通过（证明拦截确实来自签名而非清单错配）
        assert "PASS  files-reconcile" in v2.stdout, v2.stdout


# ====================================================================== #
# 4. 换 key 验签必拒（未知 key_id / 同 id 不同 secret）
# ====================================================================== #
def test_wrong_key_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        tar, manifest, sig, sbom, v = full_chain(tmp)
        assert v.returncode == 0, "前置全链应绿"

        # 4a. 验签侧 keyring 完全不含 key_test_1（fixtures meta 里是别的 key）
        v2 = run_tool("verify", "--manifest", manifest,
                      "--keyring", os.path.join(
                          TESTS_DIR, "fixtures", "approval-keys-meta.json"))
        assert v2.returncode != 0, "未知 key_id（换 keyring）验签仍绿"
        assert "验签失败" in v2.stdout

        # 4b. 同 key_id、不同 secret（secret 泄露/替换场景）
        forged = os.path.join(tmp, "forged.json")
        write_keyring(forged, {"key_test_1": "f" * 64},
                      {"key_test_1": {"status": "active"}})
        v3 = run_tool("verify", "--manifest", manifest, "--keyring", forged)
        assert v3.returncode != 0, "同 key_id 不同 secret 验签仍绿"
        assert "验签失败" in v3.stdout

        # 4c. sig 自称别的 key_id → 验签必拒
        s = json.load(open(sig, encoding="utf-8"))
        s["key_id"] = "key_test_2"  # fixture 里存在但未签发过本 manifest
        with open(sig, "w", encoding="utf-8") as fh:
            json.dump(s, fh)
        v4 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v4.returncode != 0, "sig 换 key_id 后验签仍绿"


# ====================================================================== #
# 5. SBOM 字段完整性（SPDX 2.3 必填面 + 对账）
# ====================================================================== #
def test_sbom_field_integrity():
    with tempfile.TemporaryDirectory() as tmp:
        tar, manifest, sig, sbom, v = full_chain(tmp)
        assert v.returncode == 0, "前置全链应绿"
        m = json.load(open(manifest, encoding="utf-8"))
        b = json.load(open(sbom, encoding="utf-8"))

        assert b["spdxVersion"] == "SPDX-2.3", b["spdxVersion"]
        assert b["dataLicense"] == "CC0-1.0"
        assert b["SPDXID"] == "SPDXRef-DOCUMENT"
        assert isinstance(b["name"], str) and b["name"]
        assert re.match(r"^https://", b["documentNamespace"]), \
            b["documentNamespace"]
        ci = b["creationInfo"]
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                            ci["created"]), ci["created"]
        assert any(c.startswith("Tool: release_attest-")
                   for c in ci["creators"]), ci["creators"]

        roots = [p for p in b["packages"] if p["SPDXID"] == "SPDXRef-Package-Root"]
        assert len(roots) == 1
        root = roots[0]
        assert root["name"] == "wenqu-dist"
        assert root["versionInfo"] == m["version"], \
            "根包 versionInfo 必须等于 manifest.version（system/VERSION 自述）"
        assert root["filesAnalyzed"] is True
        assert any(c["algorithm"] == "SHA256"
                   and c["checksumValue"] == m["artifact"]["sha256"]
                   for c in root["checksums"]), "根包 checksum 未钉制品 sha256"

        # 逐文件：SPDX files ↔ manifest.files 一一对应（路径+hash）
        m_files = {f["path"]: f["sha256"] for f in m["files"]}
        b_files = {}
        for f in b["files"]:
            shas = [c["checksumValue"] for c in f["checksums"]
                    if c["algorithm"] == "SHA256"]
            assert len(shas) == 1, f"文件条目应恰 1 个 SHA256: {f['fileName']}"
            name = f["fileName"]
            name = name[2:] if name.startswith("./") else name
            b_files[name] = shas[0]
        assert len(b_files) == len(m_files) == m["n_files"], \
            f"SBOM/manifest 文件数不符: {len(b_files)} vs {len(m_files)}"
        assert b_files == m_files, "SBOM 逐文件 sha256 与 manifest 不符"

        # packageVerificationCode 自洽（SPDX：文件名排序拼 SHA256 再 SHA1）
        ordered = sorted(b["files"], key=lambda f: f["fileName"])
        joined = "".join(next(c["checksumValue"] for c in f["checksums"]
                              if c["algorithm"] == "SHA256") for f in ordered)
        expect_code = hashlib.sha1(joined.encode()).hexdigest()
        assert root["packageVerificationCode"][
            "packageVerificationCodeValue"] == expect_code, "验证码不自洽"

        # 关系：DESCRIBES 根包 + 根包 CONTAINS 全部文件
        rels = b["relationships"]
        assert any(r["relationshipType"] == "DESCRIBES"
                   and r["spdxElementId"] == "SPDXRef-DOCUMENT"
                   and r["relatedSpdxElement"] == "SPDXRef-Package-Root"
                   for r in rels)
        contains = [r for r in rels if r["relationshipType"] == "CONTAINS"
                    and r["spdxElementId"] == "SPDXRef-Package-Root"]
        assert len(contains) == m["n_files"], \
            f"CONTAINS 关系数 {len(contains)} != 文件数 {m['n_files']}"

        # 篡改 SBOM 一条文件 hash → verify 必拒
        b["files"][0]["checksums"][0]["checksumValue"] = \
            "0" * len(b["files"][0]["checksums"][0]["checksumValue"])
        with open(sbom, "w", encoding="utf-8") as fh:
            json.dump(b, fh, ensure_ascii=False, indent=1, sort_keys=True)
        v2 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v2.returncode != 0, "篡改 SBOM 文件 hash 后 verify 仍绿"
        assert "SBOM 对账失败" in v2.stdout, v2.stdout


# ====================================================================== #
# 6. 篡改 manifest / sig → verify 必拒
# ====================================================================== #
def test_tamper_manifest_and_sig_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        tar, manifest, sig, sbom, v = full_chain(tmp)
        assert v.returncode == 0, "前置全链应绿"

        # 6a. manifest 单字段篡改（version）→ HMAC 覆盖 manifest → 拒
        m = json.load(open(manifest, encoding="utf-8"))
        m["version"] = "9.9.9"
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump(m, fh, ensure_ascii=False, indent=1, sort_keys=True)
        v2 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v2.returncode != 0, "篡改 manifest 后 verify 仍绿"
        assert "验签失败" in v2.stdout, v2.stdout

        # 6b. sig 签名翻转一个 hex 字符 → 拒（常量时间比对不等）
        s = json.load(open(sig, encoding="utf-8"))
        old = s["signature"]
        s["signature"] = ("0" if old[0] != "0" else "1") + old[1:]
        with open(sig, "w", encoding="utf-8") as fh:
            json.dump(s, fh, ensure_ascii=False, indent=1, sort_keys=True)
        v3 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v3.returncode != 0, "篡改 sig 后 verify 仍绿"

        # 6c. 缺 sig 文件 → 拒（fail-closed：四件套不全不放行）
        os.unlink(sig)
        v4 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v4.returncode != 0, "缺 sig 文件 verify 仍绿"


# ====================================================================== #
# 7. key 生命周期：rotated 不得签发（可验存量）；revoked 验签即拒
# ====================================================================== #
def test_key_lifecycle_fail_closed():
    with tempfile.TemporaryDirectory() as tmp:
        tar, manifest, sig, sbom, v = full_chain(tmp)
        assert v.returncode == 0, "前置全链应绿"

        secret = json.load(open(FIXTURE_KEYRING, encoding="utf-8"))[
            "keys"]["key_test_1"]
        rotated = os.path.join(tmp, "rotated.json")
        write_keyring(rotated, {"key_test_1": secret},
                      {"key_test_1": {"status": "rotated",
                                      "rotated_at": "2026-10-08T00:00:00Z"}})
        # rotated key 签发新签名 → sign 拒（exit 2）
        r = run_tool("sign", "--manifest", manifest, "--keyring", rotated,
                     "--key-id", "key_test_1")
        assert r.returncode != 0, "rotated key 仍可签发新 release 签名"
        assert "rotated" in (r.stderr + r.stdout)
        # rotated key 验存量签名 → 仍绿（与审批体系语义一致：TTL 内存量不作废）
        vr = run_tool("verify", "--manifest", manifest, "--keyring", rotated)
        assert vr.returncode == 0, "rotated key 验存量签名被误拒"

        revoked = os.path.join(tmp, "revoked.json")
        write_keyring(revoked, {"key_test_1": secret},
                      {"key_test_1": {"status": "revoked",
                                      "revoked_at": "2026-10-08T00:00:00Z"}})
        vrev = run_tool("verify", "--manifest", manifest, "--keyring", revoked)
        assert vrev.returncode != 0, "revoked key 验签仍绿（应 fail-closed 即拒）"
        assert "验签失败" in vrev.stdout

        # 无 active key 的 keyring → sign 拒
        r2 = run_tool("sign", "--manifest", manifest, "--keyring", revoked)
        assert r2.returncode != 0, "全 revoked keyring 仍可进入签发"


# ====================================================================== #
# 8. verify 报告工件（--report 机器可读，证据登记用）
# ====================================================================== #
def test_verify_report_artifact():
    with tempfile.TemporaryDirectory() as tmp:
        tar, manifest, sig, sbom, v = full_chain(tmp)
        assert v.returncode == 0
        report = os.path.join(tmp, "report.json")
        vr = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING, "--report", report)
        assert vr.returncode == 0, vr.stdout
        rep = json.load(open(report, encoding="utf-8"))
        assert rep["schema"] == "wenqu-release-verify-report/1"
        assert rep["result"] == "PASS"
        ids = [c["check"] for c in rep["checks"]]
        for expect_id in ("manifest-schema", "artifact-hash",
                          "files-reconcile", "plan-hash", "plan-pin",
                          "source-commit", "signature", "sbom-reconcile",
                          "build-identity"):
            assert expect_id in ids, f"报告缺检查项 {expect_id}: {ids}"
        assert all(c["ok"] for c in rep["checks"])
        assert rep["keyring"].endswith("approval-keys.json")
        # R8：报告须回显 pin 与 git 仓（证据链：用了哪个外部根/正源）
        assert rep["plan_pin"] and rep["plan_pin"].endswith("plan.pin"), rep
        assert rep["repo"] and os.path.isdir(os.path.join(rep["repo"], ".git")), rep


# ====================================================================== #
# 9. R7-REL-POLICY-HASH-011：plan-hash 绑定（正确 / 差一位 / 61hex 截损 /
#    缺 policy_hash / 成员不存在 → verify 必拒）
# ====================================================================== #
def _rewrite_manifest(manifest: str, m: Dict[str, Any]) -> None:
    with open(manifest, "w", encoding="utf-8") as fh:
        json.dump(m, fh, ensure_ascii=False, indent=1, sort_keys=True)


def _resign(manifest: str) -> None:
    """用测试 key 对改过的 manifest 重签（攻击者持 key 的自洽攻击面）。"""
    r = run_tool("sign", "--manifest", manifest,
                 "--keyring", FIXTURE_KEYRING, "--key-id", "key_test_1")
    assert r.returncode == 0, f"重签失败: {r.stderr}"


def test_plan_hash_binding():
    with tempfile.TemporaryDirectory() as tmp:
        tar, manifest, sig, sbom, v = full_chain(tmp)
        assert v.returncode == 0, "前置全链应绿"
        assert "PASS  plan-hash" in v.stdout, v.stdout

        # 9a. 差一位 hex（64hex 合法格式、末位翻转）+ 重签自洽 → 必拒
        m = json.load(open(manifest, encoding="utf-8"))
        good = m["policy_hash"]["plan_sha256"]
        assert good == PLAN_SHA256_TRUTH, good
        bad_one = good[:-1] + ("0" if good[-1] != "0" else "1")
        assert len(bad_one) == 64 and bad_one != good
        m["policy_hash"]["plan_sha256"] = bad_one
        _rewrite_manifest(manifest, m)
        _resign(manifest)
        v2 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v2.returncode != 0, "plan hash 差一位（已重签自洽）verify 仍绿"
        assert "方案快照 sha256 与 manifest.policy_hash.plan_sha256 不符" \
            in v2.stdout, f"应被 plan-hash 等值校验拦截:\n{v2.stdout}"

        # 9b. 61hex 截损值（第七轮案发常量）+ 重签自洽 → 格式校验即拒
        m = json.load(open(manifest, encoding="utf-8"))
        m["policy_hash"]["plan_sha256"] = PLAN_SHA256_BUGGY_61
        _rewrite_manifest(manifest, m)
        _resign(manifest)
        v3 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v3.returncode != 0, "61hex 截损 plan hash（已重签）verify 仍绿"
        assert "应 64 位小写 hex" in v3.stdout, \
            f"应被 plan-hash 格式校验拦截:\n{v3.stdout}"

        # 9c. policy_hash 整体缺失 + 重签 → 必拒（fail-closed）
        m = json.load(open(manifest, encoding="utf-8"))
        del m["policy_hash"]
        _rewrite_manifest(manifest, m)
        _resign(manifest)
        v4 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v4.returncode != 0, "缺 policy_hash（已重签）verify 仍绿"
        assert "policy_hash 缺失" in v4.stdout, v4.stdout

        # 9d. plan_member 指向不存在成员 + 重签 → 必拒（9c 已删 policy_hash，
        #     此处重建完整对象只把成员路径指空）
        m = json.load(open(manifest, encoding="utf-8"))
        m["policy_hash"] = {
            "plan_member": "evidence/00-baseline/NOPE.md",
            "plan_sha256": PLAN_SHA256_TRUTH,
            "plan_sha256_frozen": PLAN_SHA256_TRUTH,
            "frozen_match": True,
        }
        _rewrite_manifest(manifest, m)
        _resign(manifest)
        v5 = run_tool("verify", "--manifest", manifest,
                      "--keyring", FIXTURE_KEYRING)
        assert v5.returncode != 0, "plan_member 指空成员（已重签）verify 仍绿"
        assert "归档缺方案快照成员" in v5.stdout, v5.stdout


# ====================================================================== #
# 10. R8-REL-PIN-ROOT：外部受保护 plan pin + source commit 树内绑定
#     （八轮 P0-7 残余：tar 方案替换+四件套全自洽重算曾 7 PASS）
# ====================================================================== #
def _repack_replacing_plan(tar_path: str) -> str:
    """整包重产 tar：替换方案快照成员内容（保持其余成员字节不变）。

    返回替换后方案内容的新 sha256（攻击者的新「冻结值」）。"""
    with tarfile.open(tar_path, "r:gz") as tf:
        members = tf.getmembers()
        payloads: Dict[str, bytes] = {}
        for m in members:
            if m.isfile():
                fh = tf.extractfile(m)
                payloads[m.name] = b"" if fh is None else fh.read()
    new_plan = payloads[PLAN_MEMBER] + b"\n<!-- tampered by round8 adversarial -->\n"
    payloads[PLAN_MEMBER] = new_plan
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as wtf:
        for m in members:
            if m.isfile():
                data = payloads[m.name]
                m.size = len(data)
                wtf.addfile(m, io.BytesIO(data))
            else:
                wtf.addfile(m)
    with open(tar_path, "wb") as fh:
        with gzip.GzipFile(fileobj=fh, mode="wb", compresslevel=9,
                           mtime=0, filename="") as gz:
            gz.write(buf.getvalue())
    return hashlib.sha256(new_plan).hexdigest()


def test_plan_pin_and_source_commit_root():
    saved_pin_env = os.environ.get("WENQU_PLAN_PIN")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tar, manifest, sig, sbom, v = full_chain(tmp)
            assert v.returncode == 0, f"前置全链应绿:\n{v.stdout}\n{v.stderr}"
            for line in ("PASS  plan-pin", "PASS  source-commit"):
                assert line in v.stdout, f"缺 {line}:\n{v.stdout}"

            # 10a. **八轮 P0-7 案发场景复现**：tar 内方案替换 + manifest
            #      逐文件/artifact/policy_hash 全自洽重算 + 重签 + SBOM 重产
            #      → verify 必拒（pin 外部受保护根断裂）。
            new_plan_sha = _repack_replacing_plan(tar)
            assert new_plan_sha != PLAN_SHA256_TRUTH
            m = json.load(open(manifest, encoding="utf-8"))
            m["artifact"]["sha256"] = sha256_file(tar)
            m["artifact"]["size"] = os.path.getsize(tar)
            with tarfile.open(tar, "r:gz") as tf:
                ti = tf.getmember(PLAN_MEMBER)
                fh = tf.extractfile(ti)
                plan_sha_in_tar = hashlib.sha256(fh.read()).hexdigest()
                plan_size = ti.size
            for f in m["files"]:
                if f["path"] == PLAN_MEMBER:
                    f["sha256"] = plan_sha_in_tar
                    f["size"] = plan_size
            # 攻击者连 policy_hash 声明也一并自洽（frozen 值都改成自己的）
            m["policy_hash"]["plan_sha256"] = plan_sha_in_tar
            m["policy_hash"]["plan_sha256_frozen"] = plan_sha_in_tar
            m["policy_hash"]["frozen_match"] = True
            _rewrite_manifest(manifest, m)
            _resign(manifest)
            r_sbom = run_tool("sbom", "--manifest", manifest)
            assert r_sbom.returncode == 0, r_sbom.stderr
            forged = run_tool("verify", "--manifest", manifest,
                              "--keyring", FIXTURE_KEYRING)
            assert forged.returncode != 0, (
                "tar 方案替换+四件套全自洽重算后 verify 仍绿——"
                "八轮 P0-7 自洽替换洞未修!")
            # 伪造件的内部自洽性须先通过（证明拦截确实来自外部 pin 而非清单
            # 错配）；签名有效性由 _resign rc=0 保证（sign 产出的签名 verify
            # 必认）——verify 本身 fail-fast，pin 断裂后不再跑到验签步。
            for line in ("PASS  artifact-hash", "PASS  files-reconcile",
                         "PASS  plan-hash"):
                assert line in forged.stdout, \
                    f"伪造件应先过内部对账（{line} 未过）:\n{forged.stdout}"
            assert "外部受保护根拦截" in forged.stdout, \
                f"应被 plan-pin 拦截:\n{forged.stdout}"

            # 10b. pin 值被改（差一位）→ manifest 与 pin 不符即拒
            full_chain(tmp)  # 重新拉一条干净链（10a 已污染工作件）
            pin2 = write_pin(os.path.join(tmp, "plan2.pin"),
                             value=PLAN_SHA256_TRUTH[:-1] + (
                                 "0" if PLAN_SHA256_TRUTH[-1] != "0" else "1"))
            v2 = run_tool("verify", "--manifest", manifest,
                          "--keyring", FIXTURE_KEYRING,
                          "--plan-pin", pin2)
            assert v2.returncode != 0, "pin 值篡改（差一位）verify 仍绿"
            assert "冻结值与 manifest.policy_hash.plan_sha256 不符" in v2.stdout

            # 10c. pin 缺失（显式指向不存在路径；--plan-pin 优先于 env）→ 拒
            v3 = run_tool("verify", "--manifest", manifest,
                          "--keyring", FIXTURE_KEYRING,
                          "--plan-pin", os.path.join(tmp, "no-such-pin"))
            assert v3.returncode != 0, "pin 缺失 verify 仍绿（须 fail-closed）"
            assert "plan pin 缺失" in v3.stdout, v3.stdout

            # 10d. pin 权限过宽（组/其他可写）→ 受保护根语义破坏即拒
            pin4 = write_pin(os.path.join(tmp, "plan4.pin"), mode=0o666)
            v4 = run_tool("verify", "--manifest", manifest,
                          "--keyring", FIXTURE_KEYRING,
                          "--plan-pin", pin4)
            assert v4.returncode != 0, "组/其他可写 pin verify 仍绿"
            assert "权限过宽" in v4.stdout, v4.stdout

            # 10e. manifest.source_commit 指不存在 commit（幽灵 40hex，重签
            #      自洽）→ git 对象库核验即拒
            full_chain(tmp)
            m = json.load(open(manifest, encoding="utf-8"))
            ghost = "deadbeef" * 5
            assert not re.fullmatch(ghost, m["source_commit"])
            m["source_commit"] = ghost
            m["source_commit_short"] = ghost[:7]
            _rewrite_manifest(manifest, m)
            _resign(manifest)
            v5 = run_tool("verify", "--manifest", manifest,
                          "--keyring", FIXTURE_KEYRING)
            assert v5.returncode != 0, "幽灵 source_commit（已重签）verify 仍绿"
            assert "source_commit 不在 git 对象库" in v5.stdout, v5.stdout

            # 10f. 正向对照：显式 --plan-pin 指向正确 pin → 绿（R8 新入口可用）
            full_chain(tmp)
            pin6 = write_pin(os.path.join(tmp, "plan6.pin"))
            v6 = run_tool("verify", "--manifest", manifest,
                          "--keyring", FIXTURE_KEYRING,
                          "--plan-pin", pin6)
            assert v6.returncode == 0, \
                f"正确显式 pin 应绿:\n{v6.stdout}\n{v6.stderr}"
    finally:
        # 环境清洁：恢复/清除本测试注入的 WENQU_PLAN_PIN
        if saved_pin_env is None:
            os.environ.pop("WENQU_PLAN_PIN", None)
        else:
            os.environ["WENQU_PLAN_PIN"] = saved_pin_env


TESTS: List[Tuple[str, Any]] = [
    ("全链绿（build+sign+sbom+verify）+ 确定性构建", test_full_chain_green_and_deterministic),
    ("篡改 tar 一字节 → verify 必拒", test_tamper_tar_one_byte_rejected),
    ("重打包攻击（自洽改 manifest）→ 签名拦截", test_repack_attack_selfconsistent_manifest_caught_by_signature),
    ("换 key 验签必拒（未知 key_id/同 id 异 secret/改 sig key_id）", test_wrong_key_rejected),
    ("SBOM 字段完整性（SPDX 2.3 必填面+逐文件对账+验证码）+ 篡改必拒", test_sbom_field_integrity),
    ("篡改 manifest/sig/缺件 → verify 必拒", test_tamper_manifest_and_sig_rejected),
    ("key 生命周期：rotated 不得签发/revoked 验签即拒", test_key_lifecycle_fail_closed),
    ("verify --report 机器可读报告工件", test_verify_report_artifact),
    ("plan-hash 绑定（正确/差一位/61hex 截损/缺 policy_hash/成员不存在）", test_plan_hash_binding),
    ("plan-pin 外部根+source commit（自洽替换/pin 缺失/篡改/过宽/幽灵 commit）", test_plan_pin_and_source_commit_root),
]


if __name__ == "__main__":
    print(f"release_attest 全链自测  tool={TOOL}")
    for name, fn in TESTS:
        check(name, fn)
    print(f"\nrelease_attest: {PASS_N} PASS / {FAIL_N} FAIL")
    sys.exit(1 if FAIL_N else 0)

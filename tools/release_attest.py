#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""release_attest.py —— release 制品 manifest / 签名 / SBOM / 验证独立打包工具。

背景（Codex 多轮缺口）：本仓有哈希清单链（仓根 SHA256-v*.txt、dist/ 候选包），
但制品**无签名、无 SBOM、无 build identity 绑定**（evidence/09 README 建档时
DEP-04 全空）。本工具补齐「打包即登记、发布即签名、收货即对账」三件套，
与 system/wenqu_core/deploy_framework.py 的部署侧 manifest 校验相互独立——
本工具只管「制品从哪个 commit 来、里面每个文件是什么」，不碰部署状态机
（DEP-04 签名字段由并行工作流在部署侧接线，两轨契约见 evidence/09 README）。

设计决策（冻结）：
- 制品正源 = ``git archive <commit>``：从 commit 对象导出干净树，**与工作树
  无关**（并行 agent 改工作树不影响制品内容）；tar 经 Python gzip 二次封装
  （mtime=0、压缩级 9）→ 同 commit 重建字节一致（确定性构建，可复验）。
- 签名 = wenqu_core.approval_keys 的 HMAC-SHA256（**只读 import**，复用
  sign_envelope/ApprovalKeyring 的 canonical JSON 与常量时间比对、
  revoked fail-closed 语义）；detached 签名文件含 key_id。
  诚实边界（§21.4）：对称 shared-secret 模型只提供 tamper-evident /
  防伪造，**不提供非否认（non-repudiation）**——与审批体系同一信任根，
  未建立独立 release signer 前不得声称「签名证明来源」。
- SBOM = SPDX 2.3 JSON（最简合法文档）：根包=发行版（versionInfo 取自
  归档内 system/VERSION），逐文件 SHA256 + packageVerificationCode；
  依赖信息从**归档内自述文件**提取（requirements*.txt/package.json/
  pyproject.toml/setup.py 等），无外部网络、无猜测。
- verify = tar 重算逐文件 hash 对 manifest + 验签 + SBOM 三方对账，
  任一不符 exit 非零（fail-closed：缺件/多件/错 hash/错权限/坏路径全拒）。

用法（纯标准库；仓根执行）：
  python3 tools/release_attest.py build  [--commit HEAD] [--dist-dir dist]
                                        [--prefix wenqu-dist] [--repo .]
  python3 tools/release_attest.py sign  --manifest PATH --keyring PATH
                                        [--key-id ID] [--out PATH]
  python3 tools/release_attest.py sbom  --manifest PATH [--out PATH]
  python3 tools/release_attest.py verify --manifest PATH --keyring PATH
                                        [--tar PATH] [--sig PATH] [--sbom PATH]
                                        [--report PATH]

产物命名（dist/ 下四件套，<name> = <prefix>-<shortsha>）：
  <name>.tar.gz           制品（git archive 干净树）
  <name>.manifest.json    逐文件清单（路径/类型/权限/大小/sha256 + build identity）
  <name>.release.sig      detached HMAC-SHA256 签名（含 key_id）
  <name>.sbom.spdx.json   SPDX 2.3 SBOM

exit 约定：0=通过；1=verify 判 FAIL（制品/签名/SBOM 任一不符）；2=用法/环境错。
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import getpass
import io
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import time
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_DIR = os.path.join(REPO_ROOT, "system")
if SYSTEM_DIR not in sys.path:
    sys.path.insert(0, SYSTEM_DIR)

# 只读 import：仅使用签发/验签函数与 keyring 读取，绝不写 keyring。
from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope  # noqa: E402

TOOL_NAME = "release_attest.py"
TOOL_VERSION = "1.0.0"
MANIFEST_SCHEMA = "wenqu-release-manifest/1"
SIG_SCHEMA = "wenqu-release-sig/1"
SBOM_SPDX_VERSION = "SPDX-2.3"

#: 方案正源哈希（tools/ac_traceability.py 冻结值同源）——manifest 落
#: policy_hash，把「验收目录来自哪份方案」钉进 build identity。
PLAN_SHA256 = "96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d9fcaaa24612c32306"

#: SBOM 依赖提取的自述文件清单（归档内按 basename 精确匹配；无网络）。
DEP_MANIFEST_BASENAMES = (
    "requirements.txt", "requirements-dev.txt", "requirements_test.txt",
    "package.json", "pyproject.toml", "setup.py", "Pipfile",
    "go.mod", "Cargo.toml", "Gemfile",
)

_SIG_HONESTY_NOTE = (
    "HMAC-SHA256 symmetric key (same trust root as approval keyring): "
    "tamper-evident / anti-forgery only, NOT non-repudiation (plan §21.4)"
)


# ---------------------------------------------------------------------- #
# 基础工具
# ---------------------------------------------------------------------- #
def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _build_id(short: str) -> str:
    return f"rel-{short}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _die(msg: str, code: int = 2) -> "None":
    print(f"[release_attest] ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _git(repo: str, *args: str) -> str:
    try:
        proc = subprocess.run(["git", "-C", repo, *args],
                              capture_output=True, text=True, check=True)
    except FileNotFoundError:
        _die("git 不可用（PATH 缺失）")
    except subprocess.CalledProcessError as exc:
        _die(f"git {' '.join(args)} 失败: "
             f"{(exc.stderr or exc.stdout).strip()[:200]}")
    return proc.stdout.strip()


def _safe_member_path(name: str) -> bool:
    """tar 成员路径防御：拒绝绝对路径 / .. 逃逸 / 反斜杠混淆（fail-closed）。"""
    if not name or name.startswith("/") or "\\" in name:
        return False
    parts = name.split("/")
    return all(p not in ("", "..", ".") for p in parts) and name != "./"


# ---------------------------------------------------------------------- #
# tar 枚举（build 与 verify 共用同一正源函数）
# ---------------------------------------------------------------------- #
def _iter_tar_records(tar_path: str
                      ) -> Tuple[List[Dict[str, Any]], List[str]]:
    """枚举 tar 内全部实体成员 → manifest 记录（含目录标记），返回 (记录, 意外成员)。"""
    records: List[Dict[str, Any]] = []
    unexpected: List[str] = []
    with tarfile.open(tar_path, "r:gz") as tf:
        for ti in tf:  # type: tarfile.TarInfo
            if not _safe_member_path(ti.name):
                unexpected.append(f"unsafe-path:{ti.name}")
                continue
            if ti.isdir():
                continue  # 目录由文件路径蕴含，不入清单
            if ti.isfile():
                fh = tf.extractfile(ti)
                if fh is None:
                    unexpected.append(f"unreadable:{ti.name}")
                    continue
                h = hashlib.sha256()
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
                records.append({
                    "path": ti.name,
                    "type": "file",
                    "mode": int(ti.mode & 0o7777),
                    "size": int(ti.size),
                    "sha256": h.hexdigest(),
                })
            elif ti.issym():
                target = ti.linkname or ""
                records.append({
                    "path": ti.name,
                    "type": "symlink",
                    "mode": int(ti.mode & 0o7777),
                    "size": len(target.encode("utf-8")),
                    "sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
                    "symlink_target": target,
                })
            else:
                unexpected.append(f"member-type:{ti.name}:{_member_kind(ti)}")
    records.sort(key=lambda r: r["path"])
    return records, unexpected


def _member_kind(ti: tarfile.TarInfo) -> str:
    for attr in ("islnk", "ischr", "isblk", "isfifo", "isdev"):
        if getattr(ti, attr)():
            return attr[2:]
    return f"type-{ti.type!r}"


def _read_member_bytes(tar_path: str, member: str,
                       limit: int = 1 << 20) -> Optional[bytes]:
    with tarfile.open(tar_path, "r:gz") as tf:
        ti = tf.getmember(member)
        fh = tf.extractfile(ti)
        if fh is None:
            return None
        return fh.read(limit)


# ---------------------------------------------------------------------- #
# build
# ---------------------------------------------------------------------- #
def cmd_build(args: argparse.Namespace) -> int:
    repo = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo, ".git")):
        _die(f"不是 git 仓库: {repo!r}")

    full = _git(repo, "rev-parse", "--verify", f"{args.commit}^{{commit}}")
    if not re.fullmatch(r"[0-9a-f]{40}", full):
        _die(f"rev-parse 未返回完整 commit sha: {full!r}")
    short = _git(repo, "rev-parse", "--short=7", full)
    subject = _git(repo, "log", "-1", "--format=%s", full)

    dist_dir = os.path.abspath(
        args.dist_dir if os.path.isabs(args.dist_dir)
        else os.path.join(repo, args.dist_dir))
    os.makedirs(dist_dir, exist_ok=True)
    name = f"{args.prefix}-{short}"
    tar_path = os.path.join(dist_dir, f"{name}.tar.gz")

    # git archive 导出干净树（读 commit 对象，与工作树无关）→ 确定性 gzip。
    arch = subprocess.run(
        ["git", "-C", repo, "archive", "--format=tar", full],
        capture_output=True, check=False)
    if arch.returncode != 0:
        _die(f"git archive {short} 失败: {arch.stderr.decode('utf-8', 'replace')[:200]}")
    with open(tar_path, "wb") as out:
        with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=9,
                           mtime=0, filename="") as gz:
            gz.write(arch.stdout)

    records, unexpected = _iter_tar_records(tar_path)
    if unexpected:
        os.unlink(tar_path)
        _die(f"归档含意外成员（fail-closed 不出包）: {unexpected[:5]}")

    # version 从归档内 system/VERSION 读（制品自述，不用工作树值）。
    version = "UNKNOWN"
    vbytes = _read_member_bytes(tar_path, "system/VERSION", limit=4096)
    if vbytes is not None:
        version = vbytes.decode("utf-8", "replace").strip() or "UNKNOWN"

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "build_id": _build_id(short),
        "built_at": _utc_now_iso(),
        "source_commit": full,
        "source_commit_short": short,
        "source_commit_subject": subject,
        "version": version,
        "policy_hash": {"plan_sha256": PLAN_SHA256},
        "builder": {
            "user": getpass.getuser(),
            "host": platform.node(),
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "argv": [TOOL_NAME, "build", "--commit", args.commit,
                 "--prefix", args.prefix],
        "artifact": {
            "path": f"{name}.tar.gz",
            "size": os.path.getsize(tar_path),
            "sha256": _sha256_file(tar_path),
            "source": f"git archive {full} (clean tree from commit object)",
            "deterministic_gzip": "mtime=0, level=9 —— 同 commit 重建字节一致",
        },
        "n_files": len(records),
        "files": records,
    }
    manifest_path = os.path.join(dist_dir, f"{name}.manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")

    print(f"BUILD OK  {name}")
    print(f"  commit   : {full} ({subject[:60]})")
    print(f"  version  : {version}  files: {len(records)}")
    print(f"  tar.gz   : {tar_path}")
    print(f"             sha256={manifest['artifact']['sha256']} "
          f"size={manifest['artifact']['size']}")
    print(f"  manifest : {manifest_path}")
    return 0


# ---------------------------------------------------------------------- #
# sign
# ---------------------------------------------------------------------- #
def _load_manifest(manifest_path: str) -> Dict[str, Any]:
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        _die(f"manifest 不可读/非 JSON: {manifest_path!r} ({exc})")
    if not isinstance(data, dict) or data.get("schema") != MANIFEST_SCHEMA:
        _die(f"manifest schema 不符（期望 {MANIFEST_SCHEMA}）: {manifest_path!r}")
    return data


def cmd_sign(args: argparse.Namespace) -> int:
    manifest_path = os.path.abspath(args.manifest)
    manifest = _load_manifest(manifest_path)

    try:
        ring = ApprovalKeyring.from_path(os.path.abspath(args.keyring))
    except (OSError, ValueError, KeyError) as exc:
        _die(f"keyring 加载失败: {exc}")

    key_id = args.key_id
    if key_id is None:
        active = ring.active_key_ids()
        if not active:
            _die("keyring 无 active key（全部 rotated/revoked/expired）——拒绝签名")
        key_id = active[0]
    try:
        secret = ring.get_for_signing(key_id)  # rotated/revoked/expired 全拒
    except KeyError as exc:
        _die(f"签名取 key 失败: {exc}")

    # 被签信封 = manifest + key_id 绑定（与 verify 侧 ApprovalKeyring.verify
    # 的 envelope 构造完全一致：verify 从信封读 key_id 查 key 后重算 HMAC——
    # 签名同时钉住「用哪把 key 签的」）。
    envelope = dict(manifest)
    envelope["key_id"] = key_id
    signature = sign_envelope(secret, envelope)  # canonical JSON HMAC-SHA256
    # canonical JSON 规范与 approval_keys._canonical_json 同源（排序+紧凑+
    # 非转义）——此处哈希仅为 sig 内信息性回显，验签权威仍是重算的 HMAC。
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    sig = {
        "schema": SIG_SCHEMA,
        "algorithm": "HMAC-SHA256",
        "key_id": key_id,
        "signed_object": "manifest",
        "signed_manifest_build_id": manifest.get("build_id"),
        "signed_manifest_canonical_sha256": hashlib.sha256(
            canonical.encode("utf-8")).hexdigest(),
        "signature": signature,
        "signed_at": _utc_now_iso(),
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "honesty": _SIG_HONESTY_NOTE,
    }
    out = args.out
    if out is None:
        stem = manifest_path[: -len(".manifest.json")] \
            if manifest_path.endswith(".manifest.json") else manifest_path
        out = stem + ".release.sig"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(sig, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"SIGN OK  key_id={key_id}  →  {out}")
    print(f"  signature={signature}")
    return 0


# ---------------------------------------------------------------------- #
# SBOM（SPDX 2.3 JSON，最简合法文档；依赖只从归档内自述文件提取）
# ---------------------------------------------------------------------- #
def _extract_deps(tar_path: str) -> Dict[str, Any]:
    """从归档内自述依赖文件提取 (name, version) 列表——无网络、无猜测。"""
    found_files: List[str] = []
    deps: List[Tuple[str, str]] = []
    with tarfile.open(tar_path, "r:gz") as tf:
        names = [n for n in tf.getnames()
                 if os.path.basename(n) in DEP_MANIFEST_BASENAMES]
        for member in sorted(names):
            if "/evidence/" in f"/{member}/":  # 证据快照里同名摘录不作依赖正源
                continue
            ti = tf.getmember(member)
            if not ti.isfile():
                continue
            fh = tf.extractfile(ti)
            if fh is None:
                continue
            text = fh.read(1 << 20).decode("utf-8", "replace")
            found_files.append(member)
            base = os.path.basename(member)
            if base.startswith("requirements"):
                for line in text.splitlines():
                    line = line.split("#", 1)[0].strip()
                    m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;]+)", line)
                    if m:
                        deps.append((m.group(1), m.group(2)))
            elif base == "package.json":
                try:
                    pkg = json.loads(text)
                    for section in ("dependencies", "devDependencies"):
                        for dep, ver in (pkg.get(section) or {}).items():
                            deps.append((str(dep), str(ver)))
                except json.JSONDecodeError:
                    pass  # 坏 JSON 不猜测——只登记文件名
            # pyproject.toml/setup.py 等：TOML/AST 全解析超出最简范围，
            # 只登记「文件存在」，不猜内容（诚实优先）。
    return {"found_files": found_files, "deps": sorted(set(deps))}


def _spdx_file_ref(idx: int) -> str:
    return f"SPDXRef-File-{idx:04d}"


def _pkg_verification_code(files: List[Dict[str, Any]]) -> str:
    """SPDX packageVerificationCode：按文件名排序拼接 SHA256 再 SHA1。"""
    ordered = sorted(files, key=lambda f: f["fileName"])
    joined = "".join(
        next(c["checksumValue"] for c in f["checksums"]
             if c["algorithm"] == "SHA256") for f in ordered)
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()


def cmd_sbom(args: argparse.Namespace) -> int:
    manifest_path = os.path.abspath(args.manifest)
    manifest = _load_manifest(manifest_path)
    base_dir = os.path.dirname(manifest_path)
    tar_path = os.path.abspath(
        args.tar or os.path.join(base_dir, manifest["artifact"]["path"]))
    if not os.path.isfile(tar_path):
        _die(f"制品不存在: {tar_path!r}")

    dep_info = _extract_deps(tar_path)
    version = manifest.get("version", "NOASSERTION")
    artifact_sha = manifest["artifact"]["sha256"]
    name = manifest["artifact"]["path"][: -len(".tar.gz")]

    spdx_files = []
    for i, rec in enumerate(manifest["files"]):
        spdx_files.append({
            "SPDXID": _spdx_file_ref(i),
            "fileName": f"./{rec['path']}",
            "checksums": [{"algorithm": "SHA256",
                           "checksumValue": rec["sha256"]}],
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": ["NOASSERTION"],
            "copyrightText": "NOASSERTION",
        })
    root_pkg = {
        "SPDXID": "SPDXRef-Package-Root",
        "name": "wenqu-dist",
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
        "packageVerificationCode": {
            "packageVerificationCodeValue":
                _pkg_verification_code(spdx_files)},
        "checksums": [{"algorithm": "SHA256", "checksumValue": artifact_sha}],
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "supplier": "NOASSERTION",
        "originator": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "summary": ("wenqu-dist 发行版（git archive 干净树制品）——"
                    f"source_commit {manifest['source_commit']}"),
    }
    packages = [root_pkg]
    relationships = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Package-Root",
    }]
    for i, rec in enumerate(manifest["files"]):
        relationships.append({
            "spdxElementId": "SPDXRef-Package-Root",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": _spdx_file_ref(i),
        })
    for j, (dep, ver) in enumerate(dep_info["deps"]):
        packages.append({
            "SPDXID": f"SPDXRef-Package-Dep-{j:03d}",
            "name": dep,
            "versionInfo": ver,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "supplier": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        })
        relationships.append({
            "spdxElementId": "SPDXRef-Package-Root",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": f"SPDXRef-Package-Dep-{j:03d}",
        })

    scanned_note = (
        f"in-repo dependency manifests scanned (basename match, no network): "
        f"{sorted(set(os.path.basename(b) for b in DEP_MANIFEST_BASENAMES))}; "
        f"found in archive: "
        f"{dep_info['found_files'] or 'NONE'}; parsed deps: "
        f"{len(dep_info['deps'])}。归档内无 requirements/package.json 时，"
        f"本发行版按仓内自述（README：cli 与工具均 stdlib-only）记为零第三方依赖。")

    sbom = {
        "spdxVersion": SBOM_SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": (
            f"https://wenqu-dist.invalid/spdx/{manifest['build_id']}/"
            f"{artifact_sha[:16]}"),
        "creationInfo": {
            "created": _utc_now_iso(),
            "creators": [f"Tool: release_attest-{TOOL_VERSION}",
                         f"Person: {getpass.getuser()}"],
            "comment": scanned_note,
        },
        "documentDescribes": ["SPDXRef-Package-Root"],
        "packages": packages,
        "files": spdx_files,
        "relationships": relationships,
    }
    out = args.out
    if out is None:
        stem = manifest_path[: -len(".manifest.json")] \
            if manifest_path.endswith(".manifest.json") else manifest_path
        out = stem + ".sbom.spdx.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(sbom, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"SBOM OK  →  {out}")
    print(f"  spdxVersion={SBOM_SPDX_VERSION}  root=wenqu-dist@{version}  "
          f"files={len(spdx_files)}  deps={len(dep_info['deps'])}")
    print("  verificationCode="
          f"{root_pkg['packageVerificationCode']['packageVerificationCodeValue']}")
    return 0


# ---------------------------------------------------------------------- #
# verify（tar ↔ manifest ↔ sig ↔ sbom 三方对账；任一不符 exit 1）
# ---------------------------------------------------------------------- #
def _load_json(path: str, what: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise VerifyFail(f"{what} 不可读/非 JSON: {path!r} ({exc})")
    if not isinstance(data, dict):
        raise VerifyFail(f"{what} 不是 JSON 对象: {path!r}")
    return data


class VerifyFail(Exception):
    pass


def cmd_verify(args: argparse.Namespace) -> int:
    manifest_path = os.path.abspath(args.manifest)
    base_dir = os.path.dirname(manifest_path)
    checks: List[Dict[str, Any]] = []
    tar_path = sig_path = sbom_path = None

    def record(ok: bool, cid: str, detail: str = "") -> None:
        checks.append({"check": cid, "ok": bool(ok), "detail": detail[:400]})
        mark = "PASS" if ok else "FAIL"
        print(f"  {mark}  {cid}" + (f"  {detail[:200]}" if detail else ""))

    try:
        manifest = _load_json(manifest_path, "manifest")
        if manifest.get("schema") != MANIFEST_SCHEMA:
            raise VerifyFail(f"manifest schema 不符: {manifest.get('schema')!r}")
        record(True, "manifest-schema", f"build_id={manifest.get('build_id')}")

        # --- 路径解析（dist/ 四件套同目录约定，可显式覆盖）---
        stem = manifest_path[: -len(".manifest.json")] \
            if manifest_path.endswith(".manifest.json") else manifest_path
        tar_path = os.path.abspath(
            args.tar or os.path.join(base_dir, manifest["artifact"]["path"]))
        sig_path = os.path.abspath(args.sig or stem + ".release.sig")
        sbom_path = os.path.abspath(args.sbom or stem + ".sbom.spdx.json")

        # --- 1) 制品 hash/size 对 manifest ---
        if not os.path.isfile(tar_path):
            raise VerifyFail(f"制品缺失: {tar_path!r}")
        actual_sha = _sha256_file(tar_path)
        actual_size = os.path.getsize(tar_path)
        exp_sha = str(manifest["artifact"]["sha256"])
        exp_size = manifest["artifact"]["size"]
        if actual_sha != exp_sha or actual_size != exp_size:
            raise VerifyFail(
                f"制品 hash/size 不符: sha256 {actual_sha} vs {exp_sha}, "
                f"size {actual_size} vs {exp_size}")
        record(True, "artifact-hash",
               f"sha256={actual_sha[:16]}… size={actual_size}")

        # --- 2) tar 逐文件重算 ↔ manifest.files（缺件/多件/漂移全拒）---
        records, unexpected = _iter_tar_records(tar_path)
        if unexpected:
            raise VerifyFail(f"归档含意外成员: {unexpected[:5]}")
        by_path_m = {r["path"]: r for r in manifest["files"]}
        by_path_a = {r["path"]: r for r in records}
        missing = sorted(set(by_path_m) - set(by_path_a))
        extra = sorted(set(by_path_a) - set(by_path_m))
        drift = [p for p in sorted(set(by_path_m) & set(by_path_a))
                 if by_path_m[p] != by_path_a[p]]
        if missing or extra or drift:
            raise VerifyFail(
                f"逐文件对账失败: missing={len(missing)} extra={len(extra)} "
                f"drift={len(drift)}"
                + (f" 例missing={missing[:3]}" if missing else "")
                + (f" 例extra={extra[:3]}" if extra else "")
                + (f" 例drift={drift[:3]}" if drift else ""))
        record(True, "files-reconcile", f"{len(records)}/{len(manifest['files'])} "
                                        "path+type+mode+size+sha256 全符")

        # --- 3) detached 签名验签（keyring 只读；revoked fail-closed）---
        sig = _load_json(sig_path, "release.sig")
        if sig.get("schema") != SIG_SCHEMA:
            raise VerifyFail(f"sig schema 不符: {sig.get('schema')!r}")
        key_id = sig.get("key_id")
        signature = sig.get("signature")
        try:
            ring = ApprovalKeyring.from_path(os.path.abspath(args.keyring))
        except (OSError, ValueError, KeyError) as exc:
            raise VerifyFail(f"keyring 加载失败: {exc}")
        envelope = dict(manifest)
        envelope["key_id"] = key_id
        envelope["signature"] = signature
        # ApprovalKeyring.verify：未知 key/revoked/签名不符 → False（常量时间比对）
        if not ring.verify(envelope):
            raise VerifyFail(
                f"验签失败（key_id={key_id!r}——未知/吊销/签名不符，fail-closed）")
        record(True, "signature", f"key_id={key_id} algorithm="
               f"{sig.get('algorithm')}（HMAC 对称：tamper-evident，非非否认）")

        # --- 4) SBOM 对账 ---
        sbom = _load_json(sbom_path, "sbom")
        sbom_problems = _check_sbom(sbom, manifest, actual_sha, records)
        if sbom_problems:
            raise VerifyFail("SBOM 对账失败: " + "; ".join(sbom_problems[:5]))
        record(True, "sbom-reconcile",
               f"spdxVersion={sbom.get('spdxVersion')} files="
               f"{len(sbom.get('files', []))} root="
               f"{[p for p in sbom.get('packages', []) if p.get('SPDXID') == 'SPDXRef-Package-Root'][0].get('versionInfo')}")

        # --- 5) build identity 回显（人工核对 commit/argv/builder）---
        record(True, "build-identity",
               f"commit={manifest['source_commit'][:12]}… "
               f"built_at={manifest.get('built_at')} tool="
               f"{manifest.get('tool')}@{manifest.get('tool_version')}")
    except VerifyFail as exc:
        record(False, "verify", str(exc))
    except (KeyError, TypeError) as exc:
        record(False, "verify", f"manifest/sig/sbom 结构缺字段: {exc!r}")

    ok = all(c["ok"] for c in checks)
    if args.report:
        payload = {
            "schema": "wenqu-release-verify-report/1",
            "verified_at": _utc_now_iso(),
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "manifest": manifest_path,
            "tar": tar_path,
            "sig": sig_path,
            "sbom": sbom_path,
            "keyring": os.path.abspath(args.keyring),
            "checks": checks,
            "result": "PASS" if ok else "FAIL",
        }
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=1, sort_keys=True)
            fh.write("\n")
        print(f"  report → {args.report}")

    print("VERIFY OK" if ok else "VERIFY FAILED")
    return 0 if ok else 1


def _check_sbom(sbom: Dict[str, Any], manifest: Dict[str, Any],
                artifact_sha: str, tar_records: List[Dict[str, Any]]
                ) -> List[str]:
    problems: List[str] = []
    if sbom.get("spdxVersion") != SBOM_SPDX_VERSION:
        problems.append(f"spdxVersion 应为 {SBOM_SPDX_VERSION}: "
                        f"{sbom.get('spdxVersion')!r}")
    if sbom.get("dataLicense") != "CC0-1.0":
        problems.append(f"dataLicense 应为 CC0-1.0: {sbom.get('dataLicense')!r}")
    if sbom.get("SPDXID") != "SPDXRef-DOCUMENT":
        problems.append(f"文档 SPDXID 应为 SPDXRef-DOCUMENT")
    if not sbom.get("documentNamespace"):
        problems.append("documentNamespace 缺失")
    ci = sbom.get("creationInfo") or {}
    if not ci.get("created") or not ci.get("creators"):
        problems.append("creationInfo.created/creators 缺失")
    roots = [p for p in sbom.get("packages", [])
             if isinstance(p, dict) and p.get("SPDXID") == "SPDXRef-Package-Root"]
    if len(roots) != 1:
        problems.append(f"根包应恰有 1 个 SPDXRef-Package-Root: {len(roots)}")
        return problems
    root = roots[0]
    if root.get("versionInfo") != manifest.get("version"):
        problems.append(f"根包 versionInfo {root.get('versionInfo')!r} != "
                        f"manifest.version {manifest.get('version')!r}")
    root_shas = [c.get("checksumValue") for c in root.get("checksums", [])
                 if isinstance(c, dict) and c.get("algorithm") == "SHA256"]
    if artifact_sha not in root_shas:
        problems.append(f"根包 SHA256 != 制品实算 sha256（{root_shas}）")
    if root.get("filesAnalyzed") is not True:
        problems.append("根包 filesAnalyzed 必须为 true（逐文件对账前提）")

    # SBOM files ↔ tar 实算逐文件对账
    sbom_files = sbom.get("files", [])
    sbom_by_name: Dict[str, str] = {}
    for f in sbom_files:
        if not isinstance(f, dict):
            problems.append("files 含非对象条目")
            continue
        sha = next((c.get("checksumValue") for c in f.get("checksums", [])
                    if isinstance(c, dict) and c.get("algorithm") == "SHA256"),
                   None)
        fname = f.get("fileName", "")
        canon = fname[2:] if fname.startswith("./") else fname
        sbom_by_name[canon] = sha or ""
    tar_by_path = {r["path"]: r["sha256"] for r in tar_records}
    if set(sbom_by_name) != set(tar_by_path):
        only_sbom = sorted(set(sbom_by_name) - set(tar_by_path))[:3]
        only_tar = sorted(set(tar_by_path) - set(sbom_by_name))[:3]
        problems.append(f"SBOM 文件集不符: 仅SBOM={only_sbom} 仅TAR={only_tar}")
    mismatch = [p for p in set(sbom_by_name) & set(tar_by_path)
                if sbom_by_name[p] != tar_by_path[p]]
    if mismatch:
        problems.append(f"SBOM 文件 hash 漂移: {sorted(mismatch)[:3]}")

    # packageVerificationCode 内部一致性（防 SBOM 自身被局部篡改）
    code = ((root.get("packageVerificationCode") or {})
            .get("packageVerificationCodeValue"))
    expected_code = _pkg_verification_code(sbom_files)
    if code != expected_code:
        problems.append(f"packageVerificationCode 不符: {code} != {expected_code}")

    rels = sbom.get("relationships", [])
    if not any(r.get("relationshipType") == "DESCRIBES"
               and r.get("spdxElementId") == "SPDXRef-DOCUMENT"
               and r.get("relatedSpdxElement") == "SPDXRef-Package-Root"
               for r in rels if isinstance(r, dict)):
        problems.append("缺 DOCUMENT--DESCRIBES-->Root 关系")
    if not any(r.get("relationshipType") == "CONTAINS"
               and r.get("spdxElementId") == "SPDXRef-Package-Root"
               for r in rels if isinstance(r, dict)):
        problems.append("缺 Root--CONTAINS-->File 关系")
    return problems


# ---------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="release 制品 manifest/签名/SBOM/verify 独立打包工具（纯标准库）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build", help="git archive 干净树→tar.gz+manifest")
    p_build.add_argument("--commit", default="HEAD")
    p_build.add_argument("--dist-dir", default="dist")
    p_build.add_argument("--prefix", default="wenqu-dist")
    p_build.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    p_build.set_defaults(func=cmd_build)

    p_sign = sub.add_parser("sign", help="对 manifest 做 detached HMAC-SHA256 签名")
    p_sign.add_argument("--manifest", required=True)
    p_sign.add_argument("--keyring", required=True)
    p_sign.add_argument("--key-id", default=None)
    p_sign.add_argument("--out", default=None)
    p_sign.set_defaults(func=cmd_sign)

    p_sbom = sub.add_parser("sbom", help="生成 SPDX 2.3 JSON SBOM")
    p_sbom.add_argument("--manifest", required=True)
    p_sbom.add_argument("--tar", default=None)
    p_sbom.add_argument("--out", default=None)
    p_sbom.set_defaults(func=cmd_sbom)

    p_verify = sub.add_parser("verify", help="tar+manifest+sig+sbom 四件套对账")
    p_verify.add_argument("--manifest", required=True)
    p_verify.add_argument("--keyring", required=True)
    p_verify.add_argument("--tar", default=None)
    p_verify.add_argument("--sig", default=None)
    p_verify.add_argument("--sbom", default=None)
    p_verify.add_argument("--report", default=None)
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

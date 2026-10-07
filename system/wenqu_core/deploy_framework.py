# -*- coding: utf-8 -*-
"""原子部署框架（Codex W7A）。

约束（不可降级）：
    D1 禁止 cp -R 原地覆盖：每次发布在 staging 目录全新构建（逐文件流式复制），
       再经同目录 rename 原子发布为不可变 release 目录；绝不向既有 release
       目录写入或覆盖任何内容；
    D2 安装自检失败 = 部署失败（不吞错）：自检 callable 抛错或返回假值 ->
       自动回滚到上一版并抛 DeployError（携带原始异常链与回滚结果，回滚失败
       也如实上报，绝不静默）；
    D3 rename 原子性：release 目录发布（os.rename）与 current symlink 切换
       （os.replace）均在同一目录内完成，瞬时生效、无中间态；
    D4 manifest 对账：缺件 / 多件 / 哈希漂移任一非空即 verify 失败。

manifest 契约（manifest.json，随 release 一起发布）::

    {
      "release_id":     "<UTC 时间戳>-<内容摘要前 12 位>",
      "created_at":     "<ISO8601 UTC>",
      "source_dir":     "<构建源绝对路径>",
      "content_digest": "<按排序路径+文件 SHA256 摘要>",
      "files":          [{"path": 相对路径, "sha256": ..., "size": ...}, ...]
    }

不可变性：release 常规文件发布后置为 0444；目录级不可变由构建协议保证
（release 命名空间只增不改，绝不复用已存在且 divergent 的 release_id；
内容完全一致的重复构建按幂等复用处理，reused=True）。

install_self_check 契约：``callable(release_dir) -> truthy`` 表示安装自检
通过；返回假值或抛出异常均判定为自检失败。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional

__all__ = [
    "DeployManager", "DeployError", "BuildError", "VerifyError", "SwitchError",
    "SelfCheckError", "MANIFEST_NAME",
]

MANIFEST_NAME = "manifest.json"
_CHUNK = 1024 * 1024


class DeployError(Exception):
    """部署框架基础错误。"""


class BuildError(DeployError):
    """release 构建失败。"""


class VerifyError(DeployError):
    """manifest 对账失败（缺件/多件/哈希漂移）。"""

    def __init__(self, report: Dict[str, Any]):
        super().__init__("manifest verification failed: " + json.dumps(
            {k: report.get(k) for k in ("missing", "extra", "drifted")},
            ensure_ascii=False, sort_keys=True))
        self.report = report


class SwitchError(DeployError):
    """symlink 原子切换失败。"""


class SelfCheckError(DeployError):
    """安装自检失败。"""


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _collect_files(root: str) -> List[str]:
    """收集 root 下全部常规文件的相对路径（排序，确定性遍历）。"""
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            found.append(os.path.relpath(os.path.join(dirpath, name), root))
    return found


class DeployManager:
    """原子部署管理器：build -> verify -> switch（-> 安装自检）-> rollback。"""

    def __init__(self, releases_root: str, current_link: str,
                 install_self_check: Optional[Callable[[str], bool]] = None) -> None:
        self.releases_root = os.path.abspath(releases_root)
        self.current_link = os.path.abspath(current_link)
        self.install_self_check = install_self_check

    # ------------------------------------------------------------------ #
    # 构建：不可变 release 目录 + manifest
    # ------------------------------------------------------------------ #
    def build(self, source_dir: str) -> Dict[str, Any]:
        """将 source_dir 构建为不可变 release 目录（全文件 SHA256 manifest）。

        D1：staging 全新构建 + rename 原子发布；绝不向既有 release 写入/覆盖。
        同秒同内容重复构建 -> 幂等复用已存在且完好的 release（reused=True）；
        release_id 冲突但内容 divergent/损坏 -> BuildError。
        """
        source = os.path.abspath(source_dir)
        if not os.path.isdir(source):
            raise BuildError(f"source_dir not found: {source}")
        os.makedirs(self.releases_root, exist_ok=True)

        rel_files = _collect_files(source)
        staging = tempfile.mkdtemp(prefix=".staging-", dir=self.releases_root)
        try:
            entries: List[Dict[str, Any]] = []
            digest = hashlib.sha256()
            for rel in rel_files:
                src = os.path.join(source, rel)
                dst = os.path.join(staging, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                file_hash = self._copy_stream_hash(src, dst)  # 逐文件流式复制，非 cp -R
                entries.append({"path": rel, "sha256": file_hash, "size": os.path.getsize(dst)})
                digest.update(rel.encode("utf-8") + b"\0" + file_hash.encode("ascii") + b"\0")
            content_digest = digest.hexdigest()

            release_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{content_digest[:12]}"
            final_dir = os.path.join(self.releases_root, release_id)

            manifest = {
                "release_id": release_id,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source_dir": source,
                "content_digest": content_digest,
                "files": sorted(entries, key=lambda e: e["path"]),
            }
            manifest_path = os.path.join(staging, MANIFEST_NAME)
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.write("\n")

            # 发布后只读（常规文件 0444；目录不可变由“只增不改”协议保证）
            for e in manifest["files"]:
                os.chmod(os.path.join(staging, e["path"]), 0o444)
            os.chmod(manifest_path, 0o444)

            if os.path.exists(final_dir):
                # 幂等复用：仅当既有 release 完好且内容摘要一致
                if self._reusable(final_dir, content_digest):
                    shutil.rmtree(staging, ignore_errors=True)
                    with open(os.path.join(final_dir, MANIFEST_NAME), encoding="utf-8") as fh:
                        existing = json.load(fh)
                    return {
                        "release_dir": final_dir,
                        "manifest_path": os.path.join(final_dir, MANIFEST_NAME),
                        "release_id": release_id,
                        "content_digest": content_digest,
                        "files": len(existing.get("files", [])),
                        "reused": True,
                    }
                raise BuildError(
                    f"release_id collision with divergent/broken existing release: {final_dir}")

            os.rename(staging, final_dir)  # D3：同目录 rename，原子发布
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise

        return {
            "release_dir": final_dir,
            "manifest_path": os.path.join(final_dir, MANIFEST_NAME),
            "release_id": release_id,
            "content_digest": content_digest,
            "files": len(entries),
            "reused": False,
        }

    @staticmethod
    def _copy_stream_hash(src: str, dst: str) -> str:
        """流式复制并计算 SHA256（边写边哈希，单次读盘）。"""
        digest = hashlib.sha256()
        with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
            for chunk in iter(lambda: fsrc.read(_CHUNK), b""):
                digest.update(chunk)
                fdst.write(chunk)
        return digest.hexdigest()

    def _reusable(self, final_dir: str, content_digest: str) -> bool:
        try:
            with open(os.path.join(final_dir, MANIFEST_NAME), encoding="utf-8") as fh:
                existing = json.load(fh)
            if existing.get("content_digest") != content_digest:
                return False
            return self.verify(final_dir, strict=False).get("ok") is True
        except (OSError, ValueError):
            return False

    # ------------------------------------------------------------------ #
    # 对账：manifest 校验
    # ------------------------------------------------------------------ #
    def verify(self, release_dir: str, strict: bool = True) -> Dict[str, Any]:
        """manifest 对账：缺件/多件/哈希漂移任一非空即失败（D4）。

        strict=True（默认）失败抛 VerifyError（携带完整报告）；
        strict=False 返回含 ``ok`` 布尔的报告，供调用方自行裁决。
        """
        release = os.path.abspath(release_dir)
        manifest_path = os.path.join(release, MANIFEST_NAME)
        if not os.path.isfile(manifest_path):
            report = {
                "ok": False, "release_dir": release, "release_id": None,
                "missing": [MANIFEST_NAME], "extra": [], "drifted": [], "checked": 0,
            }
            if strict:
                raise VerifyError(report)
            return report

        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        expected = {e["path"]: e["sha256"] for e in manifest.get("files", [])}
        actual = set(_collect_files(release)) - {MANIFEST_NAME}  # manifest 自身不在清单内
        expected_set = set(expected)

        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        drifted = sorted(
            p for p in expected_set & actual
            if _sha256_file(os.path.join(release, p)) != expected[p]
        )
        ok = not (missing or extra or drifted)
        report = {
            "ok": ok,
            "release_dir": release,
            "release_id": manifest.get("release_id"),
            "missing": missing,
            "extra": extra,
            "drifted": drifted,
            "checked": len(expected_set & actual),
        }
        if strict and not ok:
            raise VerifyError(report)
        return report

    # ------------------------------------------------------------------ #
    # 切换：原子 symlink
    # ------------------------------------------------------------------ #
    def switch(self, current_symlink: str, target: str) -> Dict[str, Any]:
        """原子切换 current symlink -> target（D3：临时链接 + os.replace）。"""
        link = os.path.abspath(current_symlink)
        target_abs = os.path.abspath(target)
        if not os.path.isdir(target_abs):
            raise SwitchError(f"switch target not found: {target_abs}")

        link_dir = os.path.dirname(link) or "."
        os.makedirs(link_dir, exist_ok=True)
        if os.path.lexists(link) and not os.path.islink(link):
            raise SwitchError(f"refuse to replace non-symlink path: {link}")

        previous = os.readlink(link) if os.path.islink(link) else None
        link_value = os.path.relpath(target_abs, link_dir)  # 相对链接，目录整体迁移不失效
        tmp_link = os.path.join(
            link_dir, f".{os.path.basename(link)}.switch-{os.getpid()}")
        if os.path.lexists(tmp_link):
            os.remove(tmp_link)
        os.symlink(link_value, tmp_link)
        try:
            os.replace(tmp_link, link)  # D3：rename 原子性，瞬时生效
        except OSError as exc:
            if os.path.lexists(tmp_link):
                os.remove(tmp_link)
            raise SwitchError(f"atomic symlink switch failed: {link} -> {target_abs}: {exc}") from exc

        return {
            "current_symlink": link,
            "previous": previous,
            "previous_abs": (
                os.path.normpath(os.path.join(link_dir, previous)) if previous else None),
            "target": target_abs,
            "link_value": link_value,
        }

    def rollback(self, current: str, previous: str) -> Dict[str, Any]:
        """切回兼容版：先对 previous release 做 manifest 完好性对账，再原子切回。

        previous 已损坏（缺件/漂移）时拒绝回切并抛错——绝不把流量切到坏包上。
        """
        prev = os.path.abspath(previous)
        if not os.path.isdir(prev):
            raise SwitchError(f"rollback target missing: {prev}")
        verify_report = self.verify(prev)
        result = self.switch(current, prev)
        result.update({"rolled_back": True, "verify": verify_report})
        return result

    # ------------------------------------------------------------------ #
    # 编排：build -> verify -> switch -> 安装自检
    # ------------------------------------------------------------------ #
    def deploy(self, source_dir: str) -> Dict[str, Any]:
        """完整部署：构建 -> 对账 -> 原子切换 -> 安装自检。

        D2：自检失败 = 部署失败——自动回滚上一版后抛 DeployError（原始异常链
        保留，回滚失败亦如实写入错误消息，绝不吞错）。
        """
        build_result = self.build(source_dir)
        verify_report = self.verify(build_result["release_dir"])  # 切换前对账
        switch_report = self.switch(self.current_link, build_result["release_dir"])

        try:
            if self.install_self_check is not None:
                check = self.install_self_check(build_result["release_dir"])
                if not check:
                    raise SelfCheckError(f"install self-check returned falsy: {check!r}")
        except Exception as exc:
            previous_abs = switch_report.get("previous_abs")
            rollback_note = "no previous release to roll back to; current link stays on failed release"
            if previous_abs and os.path.isdir(previous_abs):
                try:
                    self.rollback(self.current_link, previous_abs)
                    rollback_note = f"rolled back to {previous_abs}"
                except DeployError as rb_exc:
                    rollback_note = (f"ROLLBACK FAILED ({rb_exc}); "
                                     f"current link remains on failed release "
                                     f"{build_result['release_dir']}")
            raise DeployError(
                f"deploy failed at install self-check: {exc!r}; {rollback_note}"
            ) from exc

        return {
            "deployed": True,
            "release_id": build_result["release_id"],
            "release_dir": build_result["release_dir"],
            "build": build_result,
            "verify": verify_report,
            "switch": switch_report,
            "self_check": "passed",
        }

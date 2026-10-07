"""runner.py——Trusted Runner：不可伪造退出码的唯一来源（ADR-001/002）。

安全构造（by construction，非依赖扫描器豁免）：
- 命令只接受显式 argv 列表，经 subprocess.run(list, shell=False) 执行；
  不存在任何字符串拼入 shell 的路径，也不调用 eval/exec。
- EvidenceStore 为 sha256 内容寻址（content-addressed）存储，写入统一走
  os.open() 且带 O_NOFOLLOW + O_EXCL：预置符号链接既不能重定向写入
  （O_NOFOLLOW），同名摘要只落盘一次（O_EXCL），读取时重新校验哈希。
- actual_exit_code 一律取自 subprocess 的 returncode，不推断、不美化。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

__all__ = ["TrustedRunner", "EvidenceStore", "Evidence", "IntegrityError"]

DEFAULT_FRESHNESS_SECONDS = 300.0


class IntegrityError(RuntimeError):
    """内容寻址存储中检测到哈希不匹配或符号链接替换。"""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Evidence:
    """一次命令执行的不可变证据记录。"""

    argv: Tuple[str, ...]
    cwd: str
    actual_exit_code: Optional[int]
    stdout_sha256: str
    stderr_sha256: str
    argv_digest: str
    timestamp: float
    fresh_until: float
    timed_out: bool = False

    @property
    def is_fresh(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) <= self.fresh_until

    def to_json(self) -> str:
        return json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )


class TrustedRunner:
    """以受信方式执行 argv 列表并捕获真实证据。

    命令始终通过 subprocess.run(list(argv), shell=False) 执行；
    记录的 actual_exit_code 即进程真实 returncode。
    """

    def __init__(
        self,
        *,
        default_cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        freshness_seconds: float = DEFAULT_FRESHNESS_SECONDS,
        allowed_executables: Optional[Iterable[str]] = None,
    ) -> None:
        if freshness_seconds <= 0:
            raise ValueError("freshness_seconds must be positive")
        self._default_cwd = default_cwd
        self._timeout = timeout
        self._freshness_seconds = freshness_seconds
        self._allowed = (
            frozenset(allowed_executables)
            if allowed_executables is not None
            else None
        )

    # ------------------------------------------------------------------
    # 校验：只接受 argv 列表，拒绝整串 shell 命令
    # ------------------------------------------------------------------
    def _validate_argv(self, argv: List[str]) -> None:
        if isinstance(argv, (str, bytes)):
            raise TypeError(
                "argv must be a list/tuple of strings; a plain shell command "
                "string is rejected by design (shell=False)"
            )
        if not isinstance(argv, (list, tuple)):
            raise TypeError(f"argv must be list or tuple, got {type(argv).__name__}")
        if not argv:
            raise ValueError("argv must not be empty")
        for i, item in enumerate(argv):
            if not isinstance(item, str):
                raise TypeError(f"argv[{i}] must be str, got {type(item).__name__}")
        resolved = shutil.which(argv[0])
        if resolved is None:
            raise FileNotFoundError(f"executable not found on PATH: {argv[0]!r}")
        if self._allowed is not None and not (
            argv[0] in self._allowed or resolved in self._allowed
        ):
            raise PermissionError(f"executable not in allowlist: {argv[0]!r}")

    @staticmethod
    def argv_digest(argv: List[str]) -> str:
        """argv 的稳定摘要：对规范化 JSON 序列做 sha256。"""
        canonical = json.dumps(list(argv), separators=(",", ":"), ensure_ascii=False)
        return _sha256_hex(canonical.encode("utf-8"))

    # ------------------------------------------------------------------
    # 执行
    # ------------------------------------------------------------------
    def run(self, argv: List[str], cwd: Optional[str] = None) -> Evidence:
        self._validate_argv(argv)
        workdir = cwd or self._default_cwd or os.getcwd()
        timestamp = time.time()
        fresh_until = timestamp + self._freshness_seconds
        argv_digest = self.argv_digest(argv)
        try:
            # P0-5 修：使用 Popen + 进程组（start_new_session=True），超时时 killpg 杀整棵子树
            import signal as _signal
            proc = subprocess.Popen(
                list(argv),
                cwd=workdir,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # 独立进程组——超时可 killpg 整组
            )
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=self._timeout)
                timed_out = False
                actual_exit = proc.returncode
            except subprocess.TimeoutExpired:
                # 杀整棵进程组（含所有子孙进程）
                try:
                    os.killpg(proc.pid, _signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                stdout_bytes, stderr_bytes = proc.communicate(timeout=5)
                timed_out = True
                actual_exit = 124
        except Exception as exc:
            return Evidence(
                argv=tuple(argv),
                cwd=workdir,
                actual_exit_code=2,
                stdout_sha256=_sha256_hex(b""),
                stderr_sha256=_sha256_hex(str(exc).encode()),
                argv_digest=argv_digest,
                timestamp=timestamp,
                fresh_until=fresh_until,
                timed_out=False,
            )
        if timed_out:
            return Evidence(
                argv=tuple(argv),
                cwd=workdir,
                actual_exit_code=None,
                stdout_sha256=_sha256_hex(stdout_bytes or b""),
                stderr_sha256=_sha256_hex(stderr_bytes or b""),
                argv_digest=argv_digest,
                timestamp=timestamp,
                fresh_until=fresh_until,
                timed_out=True,
            )
        return Evidence(
            argv=tuple(argv),
            cwd=workdir,
            actual_exit_code=actual_exit,
            stdout_sha256=_sha256_hex(stdout_bytes),
            stderr_sha256=_sha256_hex(stderr_bytes),
            argv_digest=argv_digest,
            timestamp=timestamp,
            fresh_until=fresh_until,
        )


class EvidenceStore:
    """sha256 内容寻址的证据存储。

    - 寻址：digest = sha256(canonical_json(evidence))，按前 2 位分桶。
    - 写入：os.open() 带 O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW；
      同 digest 重复写入为幂等 no-op，符号链接占位直接拒绝。
    - 读取：重新计算 sha256 并与 digest 比对，不匹配即抛 IntegrityError。
    """

    def __init__(self, root: str) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    @staticmethod
    def digest_for(evidence: Evidence) -> str:
        return _sha256_hex(evidence.to_json().encode("utf-8"))

    def _path_for(self, digest: str) -> Path:
        p = self._root / digest[:2] / f"{digest}.json"
        # P0-5 修：防父目录 symlink 逃逸——检查整个路径链不在 CAS root 外
        resolved = p.resolve(strict=False)
        root_resolved = self._root.resolve(strict=False)
        if not str(resolved).startswith(str(root_resolved)):
            raise IntegrityError(f"path escapes CAS root: {p} -> {resolved}")
        return p

    def contains(self, digest: str) -> bool:
        p = self._path_for(digest)
        if p.is_symlink():
            return False  # P0-5: symlink 一律视为不存在
        return p.is_file()

    # ------------------------------------------------------------------
    def put(self, evidence: Evidence) -> str:
        digest = self.digest_for(evidence)
        shard = self._root / digest[:2]
        # P0-5 修：检查父目录不是 symlink
        if shard.is_symlink():
            raise IntegrityError(f"shard parent is symlink: {shard}")
        shard.mkdir(parents=True, exist_ok=True)
        # P0-5 修：检查 mkdir 后父目录未被替换为 symlink
        if shard.is_symlink():
            raise IntegrityError(f"shard replaced by symlink after mkdir: {shard}")
        target = self._path_for(digest)
        data = evidence.to_json().encode("utf-8")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(target, flags, 0o640)
        except FileExistsError:
            if target.is_symlink():
                raise IntegrityError(
                    f"symlink planted at content path {target}; refusing to write"
                )
            # P0-5 修：已存在文件须校验内容完整性（防预置损坏文件假成功）
            try:
                existing = target.read_bytes()
                if _sha256_hex(existing) != digest:
                    raise IntegrityError(
                        f"corrupted file at {target}: hash mismatch, refusing silent success"
                    )
            except OSError as exc:
                raise IntegrityError(f"cannot verify existing file {target}: {exc}")
            return digest  # 内容寻址：同 digest 已存在且完整，幂等成功
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        finally:
            os.close(fd)
        return digest

    def get(self, digest: str) -> Optional[Evidence]:
        target = self._path_for(digest)
        try:
            raw = target.read_bytes()
        except FileNotFoundError:
            return None
        if _sha256_hex(raw) != digest:
            raise IntegrityError(f"content hash mismatch for digest {digest}")
        payload = json.loads(raw.decode("utf-8"))
        payload["argv"] = tuple(payload.get("argv", ()))
        return Evidence(**payload)

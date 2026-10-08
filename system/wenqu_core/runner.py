"""runner.py——Trusted Runner：不可伪造退出码的唯一来源（ADR-001/002）。

安全构造（by construction，非依赖扫描器豁免）：
- 命令只接受显式 argv 列表，经 subprocess 执行（shell=False）；
  不存在任何字符串拼入 shell 的路径，也不调用 eval/exec。
- EvidenceStore 为 sha256 内容寻址（content-addressed）存储。P0-5 加固后：
  * 根边界按 dirfd 逐组件安全打开（O_NOFOLLOW），不再依赖字符串 startswith——
    父目录被替换为 symlink 的竞态无法越界读写 CAS 根外；
  * 打开 shard 后以 fstat 校验 st_dev 与根一致（防挂载点逃逸）；
  * 写入原子化：同目录私有 tmp（O_CREAT|O_EXCL）→ 写+fsync → os.replace →
    fsync 目录；中途失败自动清理 tmp，绝不留半写毒文件在最终路径；
    首次写中途被杀后重试可自愈（残缺文件检测到后安全原子重建）；
  * 预置 hardlink（st_nlink>1）一律视为可疑拒绝；symlink 一律拒绝。
- TrustedRunner P0-5 加固：超时终止 = killpg + 递归枚举进程树杀全部后代
  （setsid 逃逸进程组的子孙也死）；默认最小化环境白名单；可选命令 allowlist。
- TrustedRunner P0-8 加固（Codex 第四轮 daemon 化逃逸根修）：每次执行注入
  唯一 run token（环境变量 ``__WENQU_RUN_TOKEN__``，在环境白名单剥除
  **之后**追加的内部哨兵，不是用户变量）；超时击杀在 killpg + 进程树扫荡
  之外按 token 全系统扫杀——linux 逐 pid 读 ``/proc/<pid>/environ``，
  darwin 用 ``ps -AxE -o pid=,command=``（含环境输出）逐行匹配完整
  ``NAME=<crypto 随机值>`` 串。孙进程 setsid + double-fork、中间进程退出、
  daemon 被 PID 1 收养（PPID 图断裂、进程树快照必漏）时，token 仍在
  daemon 的 environ 里，照样命中击杀。诚实边界：主动清空自身 environ 的
  对抗 daemon 逃逸 token 扫描（killpg/进程树对其同样无效）——该形态超出
  本层防线，由部署面日志/审计兜底。
- actual_exit_code 一律取自 subprocess 的 returncode，不推断、不美化。
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat as _stat
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

__all__ = ["TrustedRunner", "EvidenceStore", "Evidence", "IntegrityError"]

DEFAULT_FRESHNESS_SECONDS = 300.0

# P0-5：子进程默认环境白名单——其余环境变量一律剥除（可经 env_passthrough 扩展）
DEFAULT_ENV_KEYS: Tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "HOME")

# P0-8：run token 哨兵环境变量名——每次 run() 注入唯一 crypto 随机值，
# 超时按 "NAME=value" 完整串全系统扫杀。它在白名单剥除之后追加：不是用户
# 变量、不参与白名单语义（WQ_SECRET_TOKEN 等敏感变量照常剥除）。
RUN_TOKEN_ENV: str = "__WENQU_RUN_TOKEN__"

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(RuntimeError):
    """内容寻址存储中检测到哈希不匹配、符号链接替换或 hardlink 预置。"""


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

    命令始终以 argv 列表执行（shell=False）；记录的 actual_exit_code 即进程真实
    returncode。

    P0-5 加固参数：
        allowlist / allowed_executables:
            可执行文件白名单（None=不限制，兼容既有调用方）。两者等价、可并存
            （取并集）；配置后 argv[0]（原始名或 which 解析结果）不在表内即拒。
        env_passthrough:
            在默认白名单 PATH/LANG/LC_ALL/TZ/TMPDIR/HOME 之外额外放行的环境变量名。
        inherit_env:
            True 时完全继承当前环境（旧默认行为，显式 opt-in 逃逸口）。
    """

    def __init__(
        self,
        *,
        default_cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        freshness_seconds: float = DEFAULT_FRESHNESS_SECONDS,
        allowed_executables: Optional[Iterable[str]] = None,
        allowlist: Optional[Iterable[str]] = None,
        env_passthrough: Optional[Iterable[str]] = None,
        inherit_env: bool = False,
    ) -> None:
        if freshness_seconds <= 0:
            raise ValueError("freshness_seconds must be positive")
        self._default_cwd = default_cwd
        self._timeout = timeout
        self._freshness_seconds = freshness_seconds
        _sets = [s for s in (allowed_executables, allowlist) if s is not None]
        self._allowed = frozenset().union(*_sets) if _sets else None
        self._inherit_env = bool(inherit_env)
        self._env_keys = frozenset(DEFAULT_ENV_KEYS) | frozenset(
            env_passthrough or ()
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
    # 进程树击杀（P0-5：setsid 子孙逃逸 killpg 的补杀）
    # ------------------------------------------------------------------
    @staticmethod
    def _descendants(root_pid: int) -> Set[int]:
        """以 `ps -o pid,ppid` 构建全量父子表，返回 root_pid 的全部后代 pid。

        darwin/linux 通用（`ps -axo pid=,ppid=`）。ps 不可用时返回空集
        （killpg 仍生效，能力降级不静默丢证据——调用方照常记 timed_out）。
        """
        try:
            proc = subprocess.run(
                ["ps", "-axo", "pid=,ppid="],
                capture_output=True, text=True, timeout=5, shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return set()
        ppids = {}
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                ppids[int(parts[0])] = int(parts[1])
        descendants: Set[int] = set()
        frontier = {root_pid}
        while frontier:
            nxt = {p for p, pp in ppids.items() if pp in frontier and p not in descendants}
            if not nxt:
                break
            descendants |= nxt
            frontier = nxt
        return descendants

    def _kill_tree(self, proc: subprocess.Popen,
                   token_pair: Optional[str] = None) -> None:
        """超时击杀：killpg + 进程树扫荡 + run token 全系统扫杀（P0-8）。

        三层互补：killpg 杀整进程组；_descendants 按 PPID 图补杀 setsid
        子孙；token 扫杀兜住 double-fork 后被 PID 1 收养的 daemon（root
        已死、PPID 图断裂——进程树快照必漏，token 在其 environ 仍可命中）。
        多轮扫荡至收敛（无新后代、无 token 命中残留），防快照后新孙。
        """
        import signal as _signal

        def _safe_kill(pid: int) -> None:
            if pid <= 1 or pid == os.getpid():
                return  # 绝不自杀 / 杀 init
            try:
                os.kill(pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

        for _round in range(3):
            snap = self._descendants(proc.pid)
            token_hits = (self._scan_token_pids(token_pair)
                          if token_pair else set())
            try:
                os.killpg(proc.pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            for pid in sorted(snap | token_hits | {proc.pid}):
                _safe_kill(pid)
            if proc.poll() is not None:
                late = self._descendants(proc.pid) - snap
                late_token = (self._scan_token_pids(token_pair)
                              if token_pair else set())
                if not late and not late_token:
                    break
            time.sleep(0.05)

    # ------------------------------------------------------------------
    # P0-8：按 run token 全系统扫描存活进程（daemon 化逃逸的收网）
    # ------------------------------------------------------------------
    @staticmethod
    def _scan_token_pids(token_pair: str) -> Set[int]:
        """返回 environ 携带本 run token 的全部进程 pid。

        - linux：逐 pid 读 ``/proc/<pid>/environ``（本用户进程可读；
          不可读的 pid 跳过，不误报）；
        - darwin/BSD：``ps -AxE -o pid=,command=``（``-E`` 附带环境输出）
          逐行匹配。

        匹配串是完整的 ``NAME=<crypto 随机值>``——不匹配裸名，杜绝无关
        误杀。两条通路都不可用时返回空集（killpg 与进程树扫杀仍然生效，
        能力降级不静默丢证据——调用方照常记 timed_out）。
        """
        hits: Set[int] = set()
        needle = token_pair.encode("utf-8")
        if os.path.isdir("/proc"):
            try:
                names = os.listdir("/proc")
            except OSError:
                names = []
            for name in names:
                if not name.isdigit():
                    continue
                try:
                    with open(os.path.join("/proc", name, "environ"),
                              "rb") as fh:
                        data = fh.read()
                except OSError:
                    continue
                if needle in data:
                    hits.add(int(name))
            return hits
        try:
            proc = subprocess.run(
                ["ps", "-AxE", "-o", "pid=,command="],
                capture_output=True, text=True, timeout=10, shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return hits
        for line in proc.stdout.splitlines():
            if token_pair in line:
                parts = line.split(None, 1)
                if parts and parts[0].isdigit():
                    hits.add(int(parts[0]))
        return hits

    # ------------------------------------------------------------------
    # 环境最小化（P0-5：默认白名单，其余剥除）
    # ------------------------------------------------------------------
    def _build_env(self) -> Optional[dict]:
        if self._inherit_env:
            return None  # None = 完全继承（subprocess 默认）
        env = {}
        for key in sorted(self._env_keys):
            value = os.environ.get(key)
            if value is not None:
                env[key] = value
        return env

    def _build_run_env(self, token_value: str) -> Dict[str, str]:
        """在白名单环境之上注入本次执行的唯一 run token（P0-8 内部哨兵）。

        token 在 env 白名单剥除**之后**追加：它是内部哨兵不是用户变量，
        不参与白名单语义（WQ_SECRET_TOKEN 等敏感变量照常剥除）；
        inherit_env=True 时以 os.environ 拷贝为底（与完整继承等价）再注入。
        token 从不写入 os.environ——runner 自身绝不会被 token 扫杀命中。
        """
        env = self._build_env()
        if env is None:
            env = dict(os.environ)
        env[RUN_TOKEN_ENV] = token_value
        return env

    # ------------------------------------------------------------------
    # 执行
    # ------------------------------------------------------------------
    def run(self, argv: List[str], cwd: Optional[str] = None) -> Evidence:
        self._validate_argv(argv)
        workdir = cwd or self._default_cwd or os.getcwd()
        timestamp = time.time()
        fresh_until = timestamp + self._freshness_seconds
        argv_digest = self.argv_digest(argv)
        # P0-8：每次执行注入唯一 run token——超时按 token 全系统扫杀
        # （double-fork 后被 PID 1 收养的 daemon 逃不出）。
        run_token = secrets.token_hex(24)
        token_pair = f"{RUN_TOKEN_ENV}={run_token}"
        try:
            # P0-5：独立进程组（start_new_session=True）——超时 killpg 整组
            proc = subprocess.Popen(
                list(argv),
                cwd=workdir,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._build_run_env(run_token),  # P0-5 白名单 + P0-8 token
                start_new_session=True,
            )
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=self._timeout)
                timed_out = False
                actual_exit = proc.returncode
            except subprocess.TimeoutExpired:
                # P0-5/P0-8：killpg + 进程树扫荡 + token 全系统扫杀——
                # setsid 逃逸的子孙、reparent 后的 daemon 都必须死
                self._kill_tree(proc, token_pair)
                try:
                    stdout_bytes, stderr_bytes = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    stdout_bytes, stderr_bytes = b"", b""
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
    """sha256 内容寻址的证据存储（P0-5 CAS 根修）。

    - 寻址：digest = sha256(canonical_json(evidence))，按前 2 位分桶。
    - 根边界：构造时打开根目录 dirfd 并记录 st_dev；之后一切 shard/文件访问均
      以 dir_fd 逐组件安全打开（O_NOFOLLOW），打开后 fstat 复核 st_dev 与根一致。
      父目录在检查后被替换为 symlink 的竞态直接失败（ELOOP→IntegrityError），
      不存在任何依赖字符串 startswith 的越界判断。
    - 写入原子化：同目录私有 tmp（O_CREAT|O_EXCL|O_NOFOLLOW）→ 全量写+fsync →
      os.replace（同目录 rename，原子）→ fsync 目录；任何中途失败清理 tmp。
      已存在同名摘要：内容一致=幂等成功；残缺（历史毒文件/半写）=检测后原子
      重建自愈；hardlink 预置（st_nlink>1）或 symlink=IntegrityError 拒绝。
    - 读取：重新计算 sha256 并与 digest 比对，不匹配即抛 IntegrityError；
      symlink/hardlink 同样拒绝。
    """

    def __init__(self, root: str) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        self._root_fd = os.open(str(self._root), flags)
        self._root_dev = os.fstat(self._root_fd).st_dev

    # ------------------------------------------------------------------
    @staticmethod
    def digest_for(evidence: Evidence) -> str:
        return _sha256_hex(evidence.to_json().encode("utf-8"))

    def _path_for(self, digest: str) -> Path:
        """仅用于错误消息展示的路径推导（安全边界不依赖本函数）。"""
        return self._root / digest[:2] / f"{digest}.json"

    @staticmethod
    def _validate_digest(digest: str) -> str:
        digest = str(digest).strip().lower()
        if not _DIGEST_RE.match(digest):
            raise IntegrityError(f"invalid digest (expect 64-hex): {digest!r}")
        return digest

    def _shard_dirfd(self, shard: str, *, create: bool = False) -> int:
        """以根 dirfd 安全打开 shard 目录（O_NOFOLLOW；create 时先 mkdir 再开）。

        返回目录 fd；shard 是 symlink / 跨设备 / 畸形名一律 IntegrityError。
        """
        if not re.fullmatch(r"[0-9a-f]{2}", shard):
            raise IntegrityError(f"invalid shard name: {shard!r}")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        try:
            fd = os.open(shard, os.O_RDONLY | directory | nofollow,
                         dir_fd=self._root_fd)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(shard, 0o755, dir_fd=self._root_fd)
            except FileExistsError:
                pass  # 并发创建——直接进入下方带 O_NOFOLLOW 的二次打开
            except OSError as exc:
                raise IntegrityError(f"cannot create shard dir {shard!r}: {exc}") from exc
            # mkdir 与 open 之间 shard 被换成 symlink → O_NOFOLLOW 拒绝（不逃逸）
            try:
                fd = os.open(shard, os.O_RDONLY | directory | nofollow,
                             dir_fd=self._root_fd)
            except OSError as exc:
                raise IntegrityError(
                    f"shard {shard!r} opened as symlink/replaced after mkdir: {exc}"
                ) from exc
        except OSError as exc:  # ELOOP（symlink）/ ENOTDIR 等——绝不逃逸
            raise IntegrityError(
                f"shard {shard!r} refuses to open safely (symlink/attack?): {exc}"
            ) from exc

        st = os.fstat(fd)
        if not _stat.S_ISDIR(st.st_mode) or st.st_dev != self._root_dev:
            os.close(fd)
            raise IntegrityError(
                f"shard {shard!r} is not a dir on the CAS root device "
                f"(dev {st.st_dev} != root {self._root_dev})"
            )
        return fd

    @staticmethod
    def _read_all(fd: int) -> bytes:
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def _open_file(self, dir_fd: int, name: str, flags: int) -> int:
        """在 dir_fd 内打开文件（强制 O_NOFOLLOW）；symlink 占位拒绝。"""
        try:
            return os.open(name, flags | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise IntegrityError(
                    f"symlink planted at content path {name!r}; refusing"
                ) from exc
            raise

    def _atomic_write(self, dir_fd: int, fname: str, data: bytes) -> None:
        """同目录私有 tmp → 写+fsync → os.replace 原子落位 → fsync 目录。

        任何中途失败清理 tmp；最终路径上永远只会出现完整内容。
        """
        tmp = f".tmp-{fname}.{os.getpid()}.{os.urandom(6).hex()}"
        try:
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o640,
                dir_fd=dir_fd,
            )
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, fname, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dir_fd)
            except OSError:
                pass
            raise
        try:
            os.fsync(dir_fd)  # 目录项持久化（best-effort：个别 FS 不支持）
        except OSError:
            pass

    def _existing_state(self, dir_fd: int, fname: str) -> Optional[os.stat_result]:
        """lstat 已存在文件；symlink/hardlink 在此返回前不判定（由调用方处置）。"""
        try:
            return os.stat(fname, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def contains(self, digest: str) -> bool:
        digest = self._validate_digest(digest)
        fname = f"{digest}.json"
        shard_fd = self._shard_dirfd(digest[:2])
        try:
            st = self._existing_state(shard_fd, fname)
        finally:
            os.close(shard_fd)
        if st is None or _stat.S_ISLNK(st.st_mode) or st.st_nlink > 1:
            return False  # 不存在 / symlink / hardlink 预置——一律视为不可用
        return _stat.S_ISREG(st.st_mode)

    # ------------------------------------------------------------------
    def put(self, evidence: Evidence) -> str:
        digest = self.digest_for(evidence)
        data = evidence.to_json().encode("utf-8")
        if not _DIGEST_RE.match(digest):  # 理论不可达；防御性保留
            raise IntegrityError(f"digest computation broken: {digest!r}")
        fname = f"{digest}.json"
        shard_fd = self._shard_dirfd(digest[:2], create=True)
        try:
            st = self._existing_state(shard_fd, fname)
            if st is not None:
                if _stat.S_ISLNK(st.st_mode):
                    raise IntegrityError(
                        f"symlink planted at content path {fname}; refusing to write"
                    )
                if st.st_nlink > 1:
                    # P0-5：预置 hardlink 视为可疑——拒绝（可能是根外文件的别名）
                    raise IntegrityError(
                        f"hardlink planted at content path {fname} "
                        f"(st_nlink={st.st_nlink}); refusing"
                    )
                # 已存在且声称同 digest：必须内容完整才算幂等成功
                fd = self._open_file(shard_fd, fname, os.O_RDONLY)
                try:
                    existing = self._read_all(fd)
                finally:
                    os.close(fd)
                if _sha256_hex(existing) == digest:
                    return digest  # 内容寻址幂等成功
                # 残缺/毒文件（历史半写）——安全原子重建自愈（P0-5）
            self._atomic_write(shard_fd, fname, data)
        finally:
            os.close(shard_fd)
        return digest

    def get(self, digest: str) -> Optional[Evidence]:
        digest = self._validate_digest(digest)
        fname = f"{digest}.json"
        try:
            shard_fd = self._shard_dirfd(digest[:2])
        except FileNotFoundError:
            return None
        try:
            st = self._existing_state(shard_fd, fname)
            if st is None:
                return None
            if _stat.S_ISLNK(st.st_mode):
                raise IntegrityError(f"symlink at content path {fname}; refusing")
            if st.st_nlink > 1:
                raise IntegrityError(
                    f"hardlink at content path {fname} (st_nlink={st.st_nlink}); refusing"
                )
            fd = self._open_file(shard_fd, fname, os.O_RDONLY)
            try:
                raw = self._read_all(fd)
            finally:
                os.close(fd)
        finally:
            os.close(shard_fd)
        if _sha256_hex(raw) != digest:
            raise IntegrityError(f"content hash mismatch for digest {digest}")
        payload = json.loads(raw.decode("utf-8"))
        payload["argv"] = tuple(payload.get("argv", ()))
        return Evidence(**payload)

    # ------------------------------------------------------------------
    def close(self) -> None:
        fd = getattr(self, "_root_fd", None)
        if fd is not None:
            try:
                os.close(fd)
            finally:
                self._root_fd = None

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

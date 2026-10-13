"""runner.py——Trusted Runner：不可伪造退出码的唯一来源（ADR-001/002）。

安全构造（by construction，非依赖扫描器豁免）：
- 命令只接受显式 argv 列表，经 subprocess 执行（shell=False）；
  不存在任何字符串拼入 shell 的路径，也不调用 eval/exec。
- EvidenceStore 为 sha256 内容寻址（content-addressed）存储。P0-5 加固后：
  * 根边界按 dirfd 逐组件安全打开（O_NOFOLLOW），不再依赖字符串 startswith——
    父目录被替换为 symlink 的竞态无法越界读写 CAS 根外；
  * 打开 shard 后以 fstat 校验 st_dev 与根一致（防挂载点逃逸）；
  * 预置 hardlink（st_nlink>1）一律视为可疑拒绝；symlink 一律拒绝。
- W11-10 严格不可变合同（十轮 W2「CAS 严格合同缺」根修）：
  * 发布一律 create-if-absent：私有 tmp（O_CREAT|O_EXCL|O_NOFOLLOW）→ 全量
    写+fsync → ``os.link()`` 平台 no-replace 原语原子落位（已存在即
    FileExistsError，绝不覆盖）→ unlink tmp → fsync 目录。最终路径上只会
    出现完整内容，且一经发布永不重写（无 os.replace 覆盖/自愈路径）。
  * 损坏对象（同 digest 不同内容/残缺半写）fail-closed：``IntegrityError``，
    原字节不动；修复只走独立管理员 ``quarantine()``（审计隔离后重建），
    CAS 运行面绝不自动"自愈"。
  * ``contains()`` 全量重验：类型（REG）+ ``nlink==1`` + 内容 hash。
  * 逻辑绑定层：``logical_key → immutable content_digest``（``bind``/
    ``binding_for``，no-replace 发布、同内容幂等、不同内容 BindingError）。
  * 字节面：``put_bytes``/``get_bytes``/``verify_receipt``——站工件
    cas_digest 必须能从真实 CAS 回读验证，普通文件 SHA 不得冒充 receipt。
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

__all__ = ["TrustedRunner", "EvidenceStore", "Evidence", "IntegrityError",
           "BindingError", "resolve_production_cas_root",
           "WENQU_CAS_ROOT_ENV", "WENQU_RELEASE_HOME_ENV"]

DEFAULT_FRESHNESS_SECONDS = 300.0

# W12-05：CAS 生产位=受管持久化路径（R11 硬阻断⑤根修）。scratch 根
# （WENQU_HOME=/tmp/... 的一次性 run）曾把全部站工件 .bin 连同 scratch
# 一起被系统清理吞掉——station-*.json 里的 cas_digest 从此无人能回读。
# 生产 CAS 根与 WENQU_HOME 解耦，落与 registry-root/release-keyring 同域的
# 受管发行根（~/.wenqu-dist-release/cas/），分辨率：
#   1. WENQU_CAS_ROOT（显式完整路径，最高优先）
#   2. WENQU_RELEASE_HOME 环境变量 + "/cas"（受管根整体迁移面）
#   3. 缺省 ~/.wenqu-dist-release/cas（与 tools/provision_registry_root.py
#      的受管根约定一致）
WENQU_CAS_ROOT_ENV = "WENQU_CAS_ROOT"
WENQU_RELEASE_HOME_ENV = "WENQU_RELEASE_HOME"
DEFAULT_RELEASE_HOME = "~/.wenqu-dist-release"


def resolve_production_cas_root() -> str:
    """解析生产 CAS 受管持久化根（scheduler production_tick 与 gate CLI
    共用同一正源——两者必须对账同一根，否则 tick 写入与 gate 回读错位）。

    环境读取即时求值（不缓存）：测试/部署可按进程注入隔离。
    """
    explicit = os.environ.get(WENQU_CAS_ROOT_ENV, "").strip()
    if explicit:
        return explicit
    release_home = os.environ.get(WENQU_RELEASE_HOME_ENV, "").strip()
    if not release_home:
        release_home = os.path.expanduser(DEFAULT_RELEASE_HOME)
    return os.path.join(release_home, "cas")

# P0-5：子进程默认环境白名单——其余环境变量一律剥除（可经 env_passthrough 扩展）
DEFAULT_ENV_KEYS: Tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "HOME")

# P0-8：run token 哨兵环境变量名——每次 run() 注入唯一 crypto 随机值，
# 超时按 "NAME=value" 完整串全系统扫杀。它在白名单剥除之后追加：不是用户
# 变量、不参与白名单语义（WQ_SECRET_TOKEN 等敏感变量照常剥除）。
RUN_TOKEN_ENV: str = "__WENQU_RUN_TOKEN__"

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(RuntimeError):
    """内容寻址存储中检测到哈希不匹配、符号链接替换或 hardlink 预置。

    W11-10 语义：本异常同时覆盖「CAS 损坏或信任环境异常」——损坏对象
    fail-closed（绝不 os.replace 自愈），修复仅走管理员 quarantine。"""

class BindingError(RuntimeError):
    """W11-10 逻辑绑定冲突：同 logical_key 试图绑定到不同 content_digest。"""


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
        # P0-5/P0-8：超时事实先于击杀记录——kill/收尸阶段任何异常
        # 不得把已发生的超时证据抹回 False（证据不丢语义）。
        timed_out = False
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
                actual_exit = proc.returncode
            except subprocess.TimeoutExpired:
                # 超时已发生：先锁定证据再击杀（kill_tree 及收尸的任何
                # 异常只能降级 stdout/stderr，不得翻转 timed_out）。
                timed_out = True
                # P0-5/P0-8：killpg + 进程树扫荡 + token 全系统扫杀——
                # setsid 逃逸的子孙、reparent 后的 daemon 都必须死
                self._kill_tree(proc, token_pair)
                try:
                    stdout_bytes, stderr_bytes = proc.communicate(timeout=5)
                except Exception:
                    stdout_bytes, stderr_bytes = b"", b""
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
        except Exception as exc:
            # 环境错误兜底：超时若已发生，证据仍按超时语义返回。
            return Evidence(
                argv=tuple(argv),
                cwd=workdir,
                actual_exit_code=None if timed_out else 2,
                stdout_sha256=_sha256_hex(b""),
                stderr_sha256=_sha256_hex(str(exc).encode()),
                argv_digest=argv_digest,
                timestamp=timestamp,
                fresh_until=fresh_until,
                timed_out=timed_out,
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
    """sha256 内容寻址的证据存储（P0-5 CAS 根修 + W11-10 严格不可变合同）。

    - 寻址：digest = sha256(canonical_json(evidence))，按前 2 位分桶；
      字节面（站工件）以 ``<digest>.bin`` 独立命名空间同桶共存。
    - 根边界：构造时打开根目录 dirfd 并记录 st_dev；之后一切 shard/文件访问均
      以 dir_fd 逐组件安全打开（O_NOFOLLOW），打开后 fstat 复核 st_dev 与根一致。
      父目录在检查后被替换为 symlink 的竞态直接失败（ELOOP→IntegrityError），
      不存在任何依赖字符串 startswith 的越界判断。
    - 发布（W11-10 严格合同）：create-if-absent——同目录私有 tmp
      （O_CREAT|O_EXCL|O_NOFOLLOW）→ 全量写+fsync → ``os.link()`` no-replace
      原语原子落位（已存在→FileExistsError，绝不覆盖）→ unlink tmp →
      fsync 目录；任何中途失败清理 tmp。最终路径只出现完整内容且一经发布
      永不重写：损坏对象（同 digest 不同内容）→ IntegrityError fail-closed
      （原字节不动），修复仅走管理员 ``quarantine()``（审计隔离→重建）。
    - 读取：单次读全量后重算 sha256 与 digest 比对，不匹配即抛 IntegrityError；
      symlink/hardlink 同样拒绝；``contains()`` 全量重验类型+nlink+hash。
    - 逻辑绑定（W11-10 §4）：``logical_key → immutable content_digest``，
      绑定记录以 no-replace 原语发布于 ``_bindings/``——同逻辑键不得
      重新绑定到不同内容（BindingError），同内容幂等。
    """

    #: 对象命名空间：Evidence JSON 与原始字节（站工件 receipt）。
    _NS_EVIDENCE = "json"
    _NS_BYTES = "bin"
    _INTERNAL_DIR_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")

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
        return self._dirfd_under((shard,), create=create)

    def _dirfd_under(self, names: Tuple[str, ...], *, create: bool = False) -> int:
        """从根 dirfd 逐组件安全打开子目录（全程 O_NOFOLLOW + st_dev 复核）。

        W11-10：shard 与内部区（``_bindings``/``_quarantine``）共用同一
        打开纪律；create 时逐级 mkdir（FileExistsError=并发创建，续开）。
        """
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        cur = os.dup(self._root_fd)
        try:
            for name in names:
                if not self._INTERNAL_DIR_RE.fullmatch(name) and not (
                        len(name) == 2 and re.fullmatch(r"[0-9a-f]{2}", name)):
                    raise IntegrityError(f"illegal internal dir name: {name!r}")
                try:
                    nxt = os.open(name, os.O_RDONLY | directory | nofollow,
                                  dir_fd=cur)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(name, 0o755, dir_fd=cur)
                    except FileExistsError:
                        pass  # 并发创建——直接进入下方带 O_NOFOLLOW 的二次打开
                    except OSError as exc:
                        raise IntegrityError(
                            f"cannot create dir {name!r}: {exc}") from exc
                    # mkdir 与 open 之间被换成 symlink → O_NOFOLLOW 拒绝（不逃逸）
                    try:
                        nxt = os.open(name, os.O_RDONLY | directory | nofollow,
                                      dir_fd=cur)
                    except OSError as exc:
                        raise IntegrityError(
                            f"dir {name!r} opened as symlink/replaced after "
                            f"mkdir: {exc}") from exc
                except OSError as exc:  # ELOOP（symlink）/ ENOTDIR 等——绝不逃逸
                    raise IntegrityError(
                        f"dir {name!r} refuses to open safely "
                        f"(symlink/attack?): {exc}"
                    ) from exc
                st = os.fstat(nxt)
                if not _stat.S_ISDIR(st.st_mode) or st.st_dev != self._root_dev:
                    os.close(nxt)
                    raise IntegrityError(
                        f"dir {name!r} is not a dir on the CAS root device "
                        f"(dev {st.st_dev} != root {self._root_dev})"
                    )
                os.close(cur)
                cur = nxt
            return cur
        except BaseException:
            os.close(cur)
            raise

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

    # ------------------------------------------------------------------
    # W11-10：no-replace 原子发布（create-if-absent；绝不覆盖既有对象）
    # ------------------------------------------------------------------
    def _publish_noreplace(self, dir_fd: int, fname: str, data: bytes) -> bool:
        """私有 tmp → 写+fsync → ``os.link`` no-replace 落位 → unlink tmp →
        fsync 目录。

        返回 True=本调用是发布胜出者；False=目标已存在（FileExistsError——
        并发竞态落败，由调用方复验在位对象后按幂等/冲突处置）。任何中途
        失败清理 tmp；最终路径一经发布永不重写（无 os.replace 路径）。
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
                os.fsync(fd)  # tmp 内容持久化（temp fsync）
            finally:
                os.close(fd)
            # 平台 no-replace 原语：link() 在目标已存在时原子失败（EEXIST），
            # 不会覆盖任何在位对象——32 并发同 digest 只有恰一个胜出者。
            try:
                os.link(tmp, fname, src_dir_fd=dir_fd, dst_dir_fd=dir_fd,
                        follow_symlinks=False)
            except NotImplementedError:  # 个别平台 dir_fd+follow 组合受限
                os.link(tmp, fname, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            except FileExistsError:
                self._unlink_quiet(dir_fd, tmp)
                return False
            self._unlink_quiet(dir_fd, tmp)
        except BaseException:
            self._unlink_quiet(dir_fd, tmp)
            raise
        try:
            os.fsync(dir_fd)  # 目录项持久化（best-effort：个别 FS 不支持）
        except OSError:
            pass
        return True

    @staticmethod
    def _unlink_quiet(dir_fd: int, name: str) -> None:
        try:
            os.unlink(name, dir_fd=dir_fd)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # W11-10：在位对象唯一复验入口（类型 + nlink + 单次读全量 hash）
    # ------------------------------------------------------------------
    def _read_verified(self, dir_fd: int, fname: str,
                       st: os.stat_result, digest: str) -> bytes:
        """lstat 快照复验 + 单次读全量重算 hash；返回原始字节。

        symlink / hardlink（nlink>1）/ 非普通文件 / hash 不匹配 →
        IntegrityError（损坏对象 fail-closed，绝不自愈）。
        """
        if _stat.S_ISLNK(st.st_mode):
            raise IntegrityError(
                f"symlink planted at content path {fname}; refusing")
        if st.st_nlink > 1:
            raise IntegrityError(
                f"hardlink planted at content path {fname} "
                f"(st_nlink={st.st_nlink}); refusing")
        if not _stat.S_ISREG(st.st_mode):
            raise IntegrityError(
                f"content path {fname} is not a regular file "
                f"(mode={oct(st.st_mode)})")
        fd = self._open_file(dir_fd, fname, os.O_RDONLY)
        try:
            data = self._read_all(fd)
        finally:
            os.close(fd)
        if _sha256_hex(data) != digest:
            raise IntegrityError(
                f"corrupted CAS object at {fname}: content hash mismatch for "
                f"digest {digest} (fail-closed; admin quarantine/repair "
                f"required——CAS 运行面绝不 os.replace 自愈)")
        return data

    def _existing_state(self, dir_fd: int, fname: str) -> Optional[os.stat_result]:
        """lstat 已存在文件；symlink/hardlink 在此返回前不判定（由调用方处置）。"""
        try:
            return os.stat(fname, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def _probe_object(self, digest: str, namespace: str) -> str:
        """返回 'ok' | 'missing'；损坏/symlink/hardlink 抛 IntegrityError。"""
        fname = f"{digest}.{namespace}"
        try:
            shard_fd = self._shard_dirfd(digest[:2])
        except FileNotFoundError:
            return "missing"
        try:
            st = self._existing_state(shard_fd, fname)
            if st is None:
                return "missing"
            self._read_verified(shard_fd, fname, st, digest)
            return "ok"
        finally:
            os.close(shard_fd)

    def contains(self, digest: str) -> bool:
        """W11-10 §3：全量重验——类型（REG）+ nlink==1 + 内容 hash。

        损坏/symlink/hardlink/非普通文件一律 False（不可用即不存在）。
        """
        digest = self._validate_digest(digest)
        try:
            return self._probe_object(digest, self._NS_EVIDENCE) == "ok"
        except IntegrityError:
            return False

    # ------------------------------------------------------------------
    # 发布（严格不可变：create-if-absent + 同 digest 同字节幂等）
    # ------------------------------------------------------------------
    def put(self, evidence: Evidence) -> str:
        digest = self.digest_for(evidence)
        if not _DIGEST_RE.match(digest):  # 理论不可达；防御性保留
            raise IntegrityError(f"digest computation broken: {digest!r}")
        return self._put_namespaced(
            digest, evidence.to_json().encode("utf-8"), self._NS_EVIDENCE)

    def put_bytes(self, data: bytes) -> str:
        """W11-10 §7：原始字节入 CAS（站工件 receipt 的正源）。

        digest = sha256(data)；同一合同：create-if-absent、同字节幂等、
        损坏目标 fail-closed（IntegrityError）、绝不覆盖。
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"put_bytes expects bytes, got {type(data).__name__}")
        data = bytes(data)
        return self._put_namespaced(_sha256_hex(data), data, self._NS_BYTES)

    def _put_namespaced(self, digest: str, data: bytes, namespace: str) -> str:
        fname = f"{digest}.{namespace}"
        shard_fd = self._shard_dirfd(digest[:2], create=True)
        try:
            st = self._existing_state(shard_fd, fname)
            if st is not None:
                # 已存在：同 digest 同字节=幂等成功；否则（毒对象/symlink/
                # hardlink）IntegrityError fail-closed——绝不重建覆盖。
                self._read_verified(shard_fd, fname, st, digest)
                return digest
            if not self._publish_noreplace(shard_fd, fname, data):
                # 并发竞态落败（对象已被他人发布）：复验在位对象。
                st2 = self._existing_state(shard_fd, fname)
                if st2 is None:
                    raise IntegrityError(
                        f"object {fname} vanished after concurrent publish; "
                        f"retry required")
                self._read_verified(shard_fd, fname, st2, digest)
            return digest
        finally:
            os.close(shard_fd)

    def get(self, digest: str) -> Optional[Evidence]:
        digest = self._validate_digest(digest)
        try:
            shard_fd = self._shard_dirfd(digest[:2])
        except FileNotFoundError:
            return None
        try:
            st = self._existing_state(shard_fd, f"{digest}.json")
            if st is None:
                return None
            raw = self._read_verified(shard_fd, f"{digest}.json", st, digest)
        finally:
            os.close(shard_fd)
        payload = json.loads(raw.decode("utf-8"))
        payload["argv"] = tuple(payload.get("argv", ()))
        return Evidence(**payload)

    def get_bytes(self, digest: str) -> Optional[bytes]:
        """W11-10 §7：按 digest 回读字节对象（单次读全量+hash 复验）。

        不存在 → None；损坏/symlink/hardlink → IntegrityError。
        """
        digest = self._validate_digest(digest)
        try:
            shard_fd = self._shard_dirfd(digest[:2])
        except FileNotFoundError:
            return None
        try:
            st = self._existing_state(shard_fd, f"{digest}.bin")
            if st is None:
                return None
            return self._read_verified(shard_fd, f"{digest}.bin", st, digest)
        finally:
            os.close(shard_fd)

    def verify_receipt(self, digest: str) -> bool:
        """W11-10 §7：station 工件 cas_digest 的真实 CAS 回读验证。

        只有「digest 在真实 CAS 中有完好字节对象」才 True——普通文件
        SHA（从未入库）不得冒充 CAS receipt。
        """
        try:
            return self._probe_object(digest, self._NS_BYTES) == "ok"
        except IntegrityError:
            return False

    # ------------------------------------------------------------------
    # W11-10 §4：逻辑绑定层（logical_key → immutable content_digest）
    # ------------------------------------------------------------------
    @staticmethod
    def _binding_address(logical_key: str) -> Tuple[str, str]:
        key_hash = hashlib.sha256(
            ("wenqu-binding-v1:" + logical_key).encode("utf-8")).hexdigest()
        return key_hash[:2], f"{key_hash}.json"

    def bind(self, logical_key: str, content_digest: str) -> str:
        """把逻辑键绑定到不可变内容 digest（返回该 digest）。

        - 绑定目标必须真实存在于 CAS（json/bin 任一命名空间且完好；
          损坏对象 → IntegrityError，不静默视作缺位）；
        - no-replace 发布：同 logical_key 只有第一个绑定生效；
        - 重绑同 digest = 幂等成功；重绑不同 digest = BindingError；
        - 并发竞态落败方读回唯一在位绑定后按上两条处置。
        """
        if (not isinstance(logical_key, str) or not logical_key
                or len(logical_key) > 1024):
            raise ValueError(
                "logical_key must be a non-empty str (<=1024 chars)")
        digest = self._validate_digest(content_digest)
        state = self._probe_object(digest, self._NS_EVIDENCE)
        if state == "missing":
            state = self._probe_object(digest, self._NS_BYTES)
        if state == "missing":
            raise IntegrityError(
                f"cannot bind {logical_key!r}: digest {digest} is not "
                f"present in CAS (refusing to bind ghost content)")
        shard, fname = self._binding_address(logical_key)
        payload = {
            "schema": 1,
            "logical_key": logical_key,
            "content_digest": digest,
        }
        data = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
        bdir_fd = self._dirfd_under(("_bindings", shard), create=True)
        try:
            st = self._existing_state(bdir_fd, fname)
            if st is not None:
                self._verify_binding(bdir_fd, fname, st, logical_key, digest)
                return digest
            if not self._publish_noreplace(bdir_fd, fname, data):
                st2 = self._existing_state(bdir_fd, fname)
                if st2 is None:
                    raise IntegrityError(
                        f"binding for {logical_key!r} vanished after "
                        f"concurrent publish; retry required")
                self._verify_binding(bdir_fd, fname, st2, logical_key, digest)
            return digest
        finally:
            os.close(bdir_fd)

    def _verify_binding(self, dir_fd: int, fname: str, st: os.stat_result,
                        logical_key: str, digest: str) -> None:
        """复验在位绑定：同 digest 幂等放行；不同 digest → BindingError。

        结构完整性双验：绑定文件地址由 logical_key 复算（防换位/错绑），
        symlink/hardlink/非普通文件按对象纪律拒绝。
        """
        if _stat.S_ISLNK(st.st_mode) or st.st_nlink > 1 \
                or not _stat.S_ISREG(st.st_mode):
            raise IntegrityError(
                f"binding path {fname!r} is tampered "
                f"(symlink/hardlink/type); refusing")
        fd = self._open_file(dir_fd, fname, os.O_RDONLY)
        try:
            body = self._read_all(fd)
        finally:
            os.close(fd)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise IntegrityError(
                f"corrupted binding file for {logical_key!r}: {exc}") from exc
        if not isinstance(payload, dict):
            raise IntegrityError(
                f"corrupted binding file for {logical_key!r}: not an object")
        _, expect_fname = self._binding_address(logical_key)
        if payload.get("logical_key") != logical_key or fname != expect_fname:
            raise IntegrityError(
                f"binding file {fname!r} does not address logical_key "
                f"{logical_key!r} (tampered binding registry?)")
        bound = payload.get("content_digest")
        if not isinstance(bound, str) or not _DIGEST_RE.match(bound):
            raise IntegrityError(
                f"binding for {logical_key!r} holds invalid content_digest "
                f"{bound!r}")
        if bound != digest:
            raise BindingError(
                f"logical key {logical_key!r} is already bound to content "
                f"{bound}; refusing to rebind to {digest} (logical bindings "
                f"are immutable)")

    def binding_for(self, logical_key: str) -> Optional[str]:
        """读回逻辑键当前绑定的 content_digest（未绑定 → None）。"""
        if not isinstance(logical_key, str) or not logical_key:
            raise ValueError("logical_key must be a non-empty str")
        shard, fname = self._binding_address(logical_key)
        try:
            bdir_fd = self._dirfd_under(("_bindings", shard))
        except FileNotFoundError:
            return None
        try:
            st = self._existing_state(bdir_fd, fname)
            if st is None:
                return None
            if _stat.S_ISLNK(st.st_mode) or st.st_nlink > 1 \
                    or not _stat.S_ISREG(st.st_mode):
                raise IntegrityError(
                    f"binding path for {logical_key!r} is tampered "
                    f"(symlink/hardlink/type); refusing")
            fd = self._open_file(bdir_fd, fname, os.O_RDONLY)
            try:
                body = self._read_all(fd)
            finally:
                os.close(fd)
        finally:
            os.close(bdir_fd)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise IntegrityError(
                f"corrupted binding file for {logical_key!r}: {exc}") from exc
        if not isinstance(payload, dict) \
                or payload.get("logical_key") != logical_key:
            raise IntegrityError(
                f"binding file does not address logical_key {logical_key!r} "
                f"(tampered binding registry?)")
        bound = payload.get("content_digest")
        if not isinstance(bound, str) or not _DIGEST_RE.match(bound):
            raise IntegrityError(
                f"binding for {logical_key!r} holds invalid content_digest "
                f"{bound!r}")
        return bound

    # ------------------------------------------------------------------
    # W11-10 §2：独立管理员 quarantine/repair（CAS 运行面之外唯一修复通道）
    # ------------------------------------------------------------------
    def quarantine(self, digest: str, *, reason: str,
                   namespace: str = "json") -> str:
        """把损坏/被预置的 CAS 对象移入 ``_quarantine/``（审计保留原字节）。

        - 仅管理员修复通道调用（生产写路径绝不自动触发）；
        - 健康对象拒绝隔离（不得借 quarantine 覆盖好对象）；
        - 迁移用 rename（os.replace）属显式管理员动作并落审计 sidecar；
          隔离后原路径可由 put() 以 no-replace 重建。
        返回隔离文件绝对路径（sidecar ``*.reason.json`` 同目录留痕）。
        """
        if namespace not in (self._NS_EVIDENCE, self._NS_BYTES):
            raise ValueError(f"unknown namespace: {namespace!r}")
        if not isinstance(reason, str) or len(reason.strip()) < 8:
            raise ValueError(
                "quarantine requires an audit reason (>= 8 chars)")
        digest = self._validate_digest(digest)
        fname = f"{digest}.{namespace}"
        shard_fd = self._shard_dirfd(digest[:2])
        try:
            st = self._existing_state(shard_fd, fname)
            if st is None:
                raise ValueError(f"nothing to quarantine at {fname}")
            try:
                self._read_verified(shard_fd, fname, st, digest)
                healthy = True
            except IntegrityError:
                healthy = False
            if healthy:
                raise ValueError(
                    f"object {fname} verifies healthy; refusing to quarantine")
            q_fd = self._dirfd_under(("_quarantine",), create=True)
            try:
                qname = f"{digest}.{namespace}.{time.time_ns()}.corrupt"
                os.replace(fname, qname, src_dir_fd=shard_fd, dst_dir_fd=q_fd)
                meta = {
                    "digest": digest,
                    "namespace": namespace,
                    "reason": reason,
                    "quarantined_at": time.time(),
                    "quarantined_by_pid": os.getpid(),
                }
                mfd = os.open(
                    qname + ".reason.json",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o640, dir_fd=q_fd)
                try:
                    blob = json.dumps(meta, ensure_ascii=False,
                                      sort_keys=True).encode("utf-8")
                    os.write(mfd, blob)
                    os.fsync(mfd)
                finally:
                    os.close(mfd)
                for fd in (shard_fd, q_fd):
                    try:
                        os.fsync(fd)
                    except OSError:
                        pass
                return os.path.join(str(self._root), "_quarantine", qname)
            finally:
                os.close(q_fd)
        finally:
            os.close(shard_fd)

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

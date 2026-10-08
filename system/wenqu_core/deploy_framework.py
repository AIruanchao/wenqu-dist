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
    D4 manifest 对账：缺件 / 多件 / 哈希漂移 / mode 漂移任一非空即 verify 失败。

manifest 契约（manifest.json，随 release 一起发布）::

    {
      "release_id":     "<UTC 时间戳>-<内容摘要前 12 位>",
      "created_at":     "<ISO8601 UTC>",
      "source_dir":     "<构建源绝对路径>",
      "content_digest": "<按排序路径+文件 SHA256 摘要>",
      "files":          [{"path": 相对路径, "sha256": ..., "size": ...,
                          "mode": "0555"|"0444"}, ...]
    }

不可变性：release 常规文件按「源文件 exec 位」定权限——含 exec 位的文件
（含无扩展可执行文件）发布后 0555 保持可执行；无 exec 位文件 0444（0644
带 shebang 的 .py 也不强加 exec）。目录级不可变由构建协议保证（release
命名空间只增不改，绝不复用已存在且 divergent 的 release_id；内容完全一致
的重复构建按幂等复用处理，reused=True）。

install_self_check 契约：``callable(release_dir) -> truthy`` 表示安装自检
通过；返回假值或抛出异常均判定为自检失败。
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import stat as _stat
import sys
import tempfile
import threading
import time
from collections.abc import Mapping as _AbcMapping
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # 同包相对导入（与 wenqu_pipeline 一致）；包上下文缺失时回退绝对导入
    from .approval_keys import ApprovalKeyring, sign_envelope  # type: ignore
except ImportError:  # pragma: no cover - 包上下文缺失（直接脚本执行）
    from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope  # type: ignore

__all__ = [
    "DeployManager", "DeployError", "BuildError", "VerifyError", "SwitchError",
    "SelfCheckError", "MANIFEST_NAME",
    "LeaseError", "SmokeIsolationError", "SchemaRangeError",
    "ActivationBlocked", "FailedBlockedError", "FuseOpenError",
    "ObservationWindowError",
    "DeployLease", "MigrationLock", "BackupProof", "BackupProofError",
    "scan_migrations", "run_isolated_self_check",
    "CURRENT_SCHEMA_VERSION", "DEPLOY_STATE_FILENAME", "LEASE_FILENAME",
]

MANIFEST_NAME = "manifest.json"
_CHUNK = 1024 * 1024

#: 当前 manifest 契约版本（DEP-05；随 manifest 契约演进单调递增）
CURRENT_SCHEMA_VERSION = 1

#: 部署状态机落盘文件（releases_root 下，点前缀=非 release 命名空间）
DEPLOY_STATE_FILENAME = ".deploy-state.json"

#: 部署 lease 锁文件名（DEP-01；flock，进程消亡自动释放）
LEASE_FILENAME = ".deploy-lease"

# 部署状态机状态（DEP-07/08）
STATE_IDLE = "IDLE"
STATE_ACTIVATING = "ACTIVATING"
STATE_ACTIVE = "ACTIVE"
STATE_FAILED_BLOCKED = "FAILED_BLOCKED"
STATE_ROLLED_BACK = "ROLLED_BACK"
STATE_FUSE_OPEN = "FUSE_OPEN"


class DeployError(Exception):
    """部署框架基础错误。"""


class BuildError(DeployError):
    """release 构建失败。"""


class VerifyError(DeployError):
    """manifest 对账失败（缺件/多件/哈希漂移/mode 漂移/签名/schema）。"""

    def __init__(self, report: Dict[str, Any]):
        super().__init__("manifest verification failed: " + json.dumps(
            {k: report.get(k) for k in ("missing", "extra", "drifted",
                                        "mode_drifted", "signature", "schema")},
            ensure_ascii=False, sort_keys=True))
        self.report = report


class SwitchError(DeployError):
    """symlink 原子切换失败。"""


class SelfCheckError(DeployError):
    """安装自检失败。"""


class LeaseError(DeployError):
    """部署 lease 争用失败（DEP-01：并发部署最多一个成功）。"""

    def __init__(self, message: str, lease_path: Optional[str] = None):
        super().__init__(message)
        self.lease_path = lease_path


class SmokeIsolationError(DeployError):
    """自检隔离边界被突破/误配（DEP-02：smoke 不得触生产 DB/state）。"""

    def __init__(self, message: str, denied_path: Optional[str] = None):
        super().__init__(message)
        self.denied_path = denied_path


class SchemaRangeError(DeployError):
    """previous release schema_version 超出兼容范围（DEP-05：拒绝回滚）。"""

    def __init__(self, message: str, schema_version: Any = None,
                 allowed_range: Optional[Tuple[int, int]] = None):
        super().__init__(message)
        self.schema_version = schema_version
        self.allowed_range = allowed_range


class ActivationBlocked(DeployError):
    """激活前被门禁拦截（DEP-06：旧 current 不变）。"""

    def __init__(self, message: str, reasons: Optional[List[str]] = None):
        super().__init__(message)
        self.reasons = list(reasons or [])


class FailedBlockedError(ActivationBlocked):
    """ACTIVATING 失败且无预授权 → FAILED_BLOCKED（DEP-07：不得自动回滚）。"""


class FuseOpenError(DeployError):
    """回滚也失败 → 熔断停等人工恢复（DEP-08：后续部署拒绝）。"""


class ObservationWindowError(DeployError):
    """观察窗内夹带 contract/down migration（DEP-09：拒绝）。"""

    def __init__(self, message: str, contraband: Optional[List[str]] = None,
                 remaining_seconds: float = 0.0):
        super().__init__(message)
        self.contraband = list(contraband or [])
        self.remaining_seconds = remaining_seconds


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stat_mode(path: str) -> int:
    """文件权限位（0777 掩码），供 manifest mode 对账。"""
    return _stat.S_IMODE(os.stat(path).st_mode)


def _collect_files(root: str) -> List[str]:
    """收集 root 下全部常规文件的相对路径（排序，确定性遍历）。"""
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            found.append(os.path.relpath(os.path.join(dirpath, name), root))
    return found


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------- #
# DEP-01：部署 lease / DEP-06：迁移锁（flock，进程消亡自动释放）
# ---------------------------------------------------------------------- #
class DeployLease:
    """flock 独占租约（DEP-01 部署互斥原语）。

    非阻塞仲裁：``acquire`` 用 ``LOCK_EX | LOCK_NB``——第二个争用者
    立即 ``LeaseError``，不排队（「两个部署者争 lease→最多一个成功」）。
    锁随文件描述符存活：持锁进程 kill -9 后内核自动释放，无陈锁残留。
    """

    def __init__(self, path: str, fd: int) -> None:
        self.path = os.path.abspath(path)
        self._fd = fd
        self._released = False

    @classmethod
    def acquire(cls, path: str, *, timeout: float = 0.0) -> "DeployLease":
        """获取 flock 独占租约；被争用即 LeaseError（timeout>0 时短重试）。"""
        path = os.path.abspath(path)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return cls(path, fd)
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LeaseError(
                        f"deploy lease held by another deployer: {path}",
                        lease_path=path) from None
                time.sleep(0.01)

    @property
    def held(self) -> bool:
        """租约当前是否被本对象持有。"""
        return not self._released

    def release(self) -> None:
        """释放租约（幂等；关闭 fd 即解锁）。"""
        if self._released:
            return
        self._released = True
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(self._fd)
        except OSError:
            pass

    def __enter__(self) -> "DeployLease":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.release()

    def __del__(self) -> None:  # noqa: D105 - 兜底释放
        try:
            self.release()
        except Exception:  # noqa: BLE001 - 析构绝不抛
            pass


class MigrationLock(DeployLease):
    """迁移锁（DEP-06）：与部署 lease 相互独立的第二把 flock。

    语义区分：deploy lease 保护发布命名空间互斥；migration lock 证明
    「本部署者持有 schema 迁移权」（与部署租约分属不同锁文件）。
    """


# ---------------------------------------------------------------------- #
# DEP-06：备份证明（marker 重哈希对账）
# ---------------------------------------------------------------------- #
class BackupProofError(ValueError):
    """备份证明无效（marker 缺失/未验证/工件哈希漂移）。"""


class BackupProof:
    """已验证的迁移前备份证明（DEP-06 激活门禁输入）。

    marker JSON 契约::

        {
          "kind":             "wenqu-backup-proof",
          "backup_id":        "<非空>",
          "created_at":       "<ISO8601>",
          "verified":         true,          # 快照自检位
          "artifact":         "<备份工件绝对路径>",
          "artifact_sha256":  "<64 hex>",    # verify 时重哈希对账
          "content_digest":   "<可选：绑定 release 内容摘要>"
        }

    ``BackupProof.verify(marker_path)`` 重哈希 artifact 并逐字段校验——
    工件被篡改/删除、verified 非 true、kind 不符一律 BackupProofError
    （fail-closed，绝不信任 marker 自述）。
    """

    def __init__(self, backup_id: str, artifact: str, artifact_sha256: str,
                 content_digest: Optional[str],
                 marker_path: Optional[str] = None) -> None:
        self.backup_id = backup_id
        self.artifact = artifact
        self.artifact_sha256 = artifact_sha256
        self.content_digest = content_digest
        self.marker_path = marker_path

    @property
    def valid(self) -> bool:
        """门禁时点复验：工件仍存在且哈希仍对（防 proof 构造后被篡改）。"""
        try:
            return _sha256_file(self.artifact) == self.artifact_sha256
        except OSError:
            return False

    @classmethod
    def verify(cls, marker_path: str) -> "BackupProof":
        try:
            with open(marker_path, encoding="utf-8") as fh:
                marker = json.load(fh)
        except (OSError, ValueError) as exc:
            raise BackupProofError(
                f"backup marker unreadable/invalid: {marker_path!r}: {exc}"
            ) from exc
        if not isinstance(marker, dict) or marker.get("kind") != "wenqu-backup-proof":
            raise BackupProofError(
                f"backup marker kind mismatch: {marker_path!r}")
        if marker.get("verified") is not True:
            raise BackupProofError(
                f"backup marker not verified (verified != true): {marker_path!r}")
        backup_id = marker.get("backup_id")
        if not isinstance(backup_id, str) or not backup_id.strip():
            raise BackupProofError("backup marker backup_id missing/empty")
        artifact = marker.get("artifact")
        expected = marker.get("artifact_sha256")
        if not isinstance(artifact, str) or not isinstance(expected, str):
            raise BackupProofError("backup marker artifact/sha256 missing")
        if not os.path.isfile(artifact):
            raise BackupProofError(
                f"backup artifact missing: {artifact!r}")
        actual = _sha256_file(artifact)
        if actual != expected:
            raise BackupProofError(
                f"backup artifact hash drift: expected {expected}, got {actual}")
        digest = marker.get("content_digest")
        if digest is not None and not isinstance(digest, str):
            raise BackupProofError("backup marker content_digest must be a string")
        return cls(backup_id, artifact, expected, digest,
                   marker_path=os.path.abspath(marker_path))


# ---------------------------------------------------------------------- #
# DEP-06/09：migration 扫描与 phase 甄别
# ---------------------------------------------------------------------- #
def scan_migrations(root: str) -> Dict[str, List[str]]:
    """扫描 release/source 内 ``migrations/`` 目录并按 phase 甄别。

    返回 ``{"files": [...], "expand": [...], "contract": [...],
    "down": [...]}``（相对 root 的路径，排序）。phase 判定：文件内容
    ``-- phase: expand|contract|down`` 标记优先，其次文件名关键词。
    无 migrations/ 目录时各列表为空（门禁不触发）。
    """
    result: Dict[str, List[str]] = {"files": [], "expand": [],
                                    "contract": [], "down": []}
    mig_root = os.path.join(root, "migrations")
    if not os.path.isdir(mig_root):
        return result
    for rel in _collect_files(mig_root):
        rel_from_root = os.path.join("migrations", rel)
        result["files"].append(rel_from_root)
        name = rel.lower()
        head = ""
        try:
            with open(os.path.join(mig_root, rel), encoding="utf-8",
                      errors="replace") as fh:
                head = fh.read(4096).lower()
        except OSError:
            head = ""
        if "-- phase: expand" in head or "expand" in name:
            result["expand"].append(rel_from_root)
        if "-- phase: contract" in head or "contract" in name:
            result["contract"].append(rel_from_root)
        if "-- phase: down" in head or "down" in name:
            result["down"].append(rel_from_root)
    for key in result:
        result[key] = sorted(set(result[key]))
    return result


# ---------------------------------------------------------------------- #
# DEP-02：自检隔离（audit-hook 守卫 + 一次性沙箱副本）
# ---------------------------------------------------------------------- #
class _SmokeAccessDenied(PermissionError):
    """守卫拒绝（标记类型：只转化守卫拒绝，不吞普通权限错误）。"""


_GUARDED_EVENTS = ("open", "os.stat", "os.listdir", "os.scandir",
                   "sqlite3.connect")


class _SmokeIsolationGuard:
    """进程级 audit-hook 路径守卫（安装一次，激活窗口内拒绝生产路径访问）。

    审计钩子一经安装不可移除（CPython 限制）——用模块级激活标志实现
    「仅在自检 callable 运行期间拦截」；路径比较一律 realpath 归一，
    符号链接逃逸（沙箱内符号链接指向生产库）同样被拒。
    """

    _install_lock = threading.Lock()
    _installed = False
    _active = False
    _current: Optional["_SmokeIsolationGuard"] = None

    def __init__(self, protected_roots: List[str]) -> None:
        self.roots = [os.path.realpath(r) for r in protected_roots]

    # -- 钩子（进程级，一次安装） ------------------------------------- #
    @classmethod
    def _audit_hook(cls, event: str, args: Tuple[Any, ...]) -> None:
        if not cls._active or cls._current is None:
            return
        if event not in _GUARDED_EVENTS:
            return
        cls._current._deny(event, args)

    @classmethod
    def _ensure_installed(cls) -> None:
        with cls._install_lock:
            if cls._installed:
                return
            sys.addaudithook(cls._audit_hook)
            cls._installed = True

    # -- 判定 ----------------------------------------------------------- #
    def _deny(self, event: str, args: Tuple[Any, ...]) -> None:
        if not args:
            return
        raw = args[0]
        if not isinstance(raw, (str, bytes, os.PathLike)):
            return
        path = os.fsdecode(raw)
        try:
            probe = os.path.realpath(path)
        except OSError:
            probe = os.path.abspath(path)
        for root in self.roots:
            if probe == root or probe.startswith(root + os.sep):
                raise _SmokeAccessDenied(
                    f"DEP-02 smoke isolation: access to protected production "
                    f"path denied (event={event}): {path!r} -> {probe!r}")

    def __enter__(self) -> "_SmokeIsolationGuard":
        _SmokeIsolationGuard._ensure_installed()
        _SmokeIsolationGuard._active = True
        _SmokeIsolationGuard._current = self
        return self

    def __exit__(self, *_exc: Any) -> None:
        _SmokeIsolationGuard._active = False
        _SmokeIsolationGuard._current = None


def _copy_tree_writable(src: str, dst: str) -> None:
    """复制 release 到沙箱并放开写位（沙箱是一次性隔离环境，非发布件）。"""
    shutil.copytree(src, dst)
    for dirpath, dirnames, filenames in os.walk(dst):
        for name in dirnames + filenames:
            target = os.path.join(dirpath, name)
            mode = _stat_mode(target)
            os.chmod(target, mode | 0o200)


def run_isolated_self_check(release_dir: str, check: Callable[[str], Any],
                            protected_paths: List[str]) -> Any:
    """在隔离环境中运行安装自检（DEP-02）。

    边界断言（fail-closed）：
    (1) release_dir 绝不在任何受保护生产区内；
    (2) 沙箱副本落点绝不在任何受保护生产区内；
    (3) 自检运行期间，一切对受保护路径的 open/stat/listdir/scandir/
        sqlite3.connect（含符号链接逃逸）被守卫拒绝——
        ``_SmokeAccessDenied`` 转化为 ``SmokeIsolationError``。
    自检在一次性沙箱副本上运行：自检的写入只落沙箱，真实 release
    不可变性不受影响（副本目录名保留 release_id，可观测隔离事实）。
    """
    roots = [os.path.realpath(str(p)) for p in protected_paths]
    release_real = os.path.realpath(release_dir)

    def _inside(path: str) -> Optional[str]:
        for root in roots:
            if path == root or path.startswith(root + os.sep):
                return root
        return None

    violator = _inside(release_real)
    if violator is not None:
        raise SmokeIsolationError(
            f"DEP-02 isolation boundary violated: release dir {release_real!r} "
            f"is inside protected production zone {violator!r}",
            denied_path=release_real)

    sandbox_parent = tempfile.mkdtemp(prefix=".smoke-sandbox-")
    sandbox = os.path.join(sandbox_parent, os.path.basename(
        release_real.rstrip(os.sep)))
    try:
        _copy_tree_writable(release_real, sandbox)
        sandbox_real = os.path.realpath(sandbox)
        violator = _inside(sandbox_real)
        if violator is not None:
            raise SmokeIsolationError(
                f"DEP-02 isolation boundary violated: smoke sandbox "
                f"{sandbox_real!r} landed inside protected zone {violator!r}",
                denied_path=sandbox_real)
        guard = _SmokeIsolationGuard(roots)
        try:
            with guard:
                return check(sandbox)
        except _SmokeAccessDenied as exc:
            raise SmokeIsolationError(str(exc), denied_path=str(exc)) from exc
    finally:
        shutil.rmtree(sandbox_parent, ignore_errors=True)


# ---------------------------------------------------------------------- #
# DEP-07/08/09：部署状态机落盘存储
# ---------------------------------------------------------------------- #
class _DeployStateStore:
    """部署状态机持久存储（releases_root/.deploy-state.json，原子写）。

    只有两个状态阻塞后续部署：FAILED_BLOCKED（DEP-07，等人工确认）、
    FUSE_OPEN（DEP-08，等人工恢复）；其余状态（含崩溃残留的
    ACTIVATING）不阻塞——新部署原子取代。
    """

    def __init__(self, releases_root: str) -> None:
        self.path = os.path.join(releases_root, DEPLOY_STATE_FILENAME)

    def load(self) -> Dict[str, Any]:
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def update(self, **fields: Any) -> Dict[str, Any]:
        """合并写（保留未提及字段，如 last_activated_at）；tmp+rename 原子。"""
        state = self.load()
        state.update(fields)
        state["updated_at"] = _utc_now_iso()
        tmp = f"{self.path}.tmp-{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, self.path)
        return state


class DeployManager:
    """原子部署管理器：build -> verify -> switch（-> 安装自检）-> rollback。

    §20 DEP 族扩展（全部可选、默认关闭——不配置即保持 W7A 原语义）：

    - ``lease_timeout``（DEP-01）：deploy 全程持有 flock 部署租约；
      默认 0=非阻塞单次尝试，争用者立即 LeaseError。
    - ``self_check_protected_paths``（DEP-02）：自检沙箱化 + 生产路径
      audit-hook 守卫。
    - ``release_keyring``/``release_signing_key``（DEP-04）：manifest
      HMAC 签名与验签（keyring 机制复用 approval_keys，只读 import）。
    - ``schema_range``（DEP-05）：manifest schema_version 兼容范围
      (min, max)，rollback 超范围拒绝。
    - ``fenced``（DEP-07）：激活失败无预授权 → FAILED_BLOCKED，
      不自动回滚（与 D2 自动回滚语义由该开关分轨）。
    - ``observation_seconds``（DEP-09）：激活观察窗，窗内 contract/down
      migration 拒绝。
    """

    def __init__(self, releases_root: str, current_link: str,
                 install_self_check: Optional[Callable[[str], bool]] = None, *,
                 release_keyring: Optional["ApprovalKeyring"] = None,
                 release_signing_key: Optional[str] = None,
                 auth_keyring: Optional["ApprovalKeyring"] = None,
                 schema_range: Optional[Tuple[int, int]] = None,
                 fenced: bool = False,
                 observation_seconds: float = 0.0,
                 self_check_protected_paths: Optional[List[str]] = None,
                 lease_timeout: float = 0.0) -> None:
        self.releases_root = os.path.abspath(releases_root)
        self.current_link = os.path.abspath(current_link)
        self.install_self_check = install_self_check
        # DEP-04：release 签名域（keyring 机制复用 approval_keys）
        self.release_keyring = release_keyring
        self.release_signing_key = release_signing_key
        # DEP-06/07/09：迁移门/回滚预授权/contract 授权的验签 keyring
        self.auth_keyring = auth_keyring
        # DEP-05：manifest schema 兼容范围
        if schema_range is not None:
            if (not isinstance(schema_range, tuple) or len(schema_range) != 2
                    or not all(isinstance(v, int) and not isinstance(v, bool)
                               for v in schema_range)
                    or schema_range[0] > schema_range[1]):
                raise ValueError(
                    f"schema_range must be (min, max) int tuple: {schema_range!r}")
        self.schema_range = schema_range
        # DEP-07：fenced 激活状态机
        self.fenced = bool(fenced)
        # DEP-09：激活观察窗（秒；0=关闭）
        self.observation_seconds = float(observation_seconds)
        # DEP-02：自检隔离（None=关闭，自检直跑真实 release 目录）
        self.self_check_protected_paths = (
            [os.path.abspath(str(p)) for p in self_check_protected_paths]
            if self_check_protected_paths is not None else None)
        # DEP-01：部署租约
        self.lease_timeout = float(lease_timeout)
        self._state = _DeployStateStore(self.releases_root)
        # DEP-02 边界断言（构造期 fail-closed）：发布区/current 绝不在
        # 受保护生产区内——隔离配置自相矛盾时立即拒绝，不留运行期侥幸。
        if self.self_check_protected_paths is not None:
            roots = [os.path.realpath(p) for p in self.self_check_protected_paths]
            for victim, label in ((os.path.realpath(self.releases_root),
                                   "releases_root"),
                                  (os.path.realpath(self.current_link),
                                   "current_link")):
                for root in roots:
                    if victim == root or victim.startswith(root + os.sep):
                        raise SmokeIsolationError(
                            f"DEP-02 isolation boundary misconfiguration: "
                            f"{label} {victim!r} inside protected zone "
                            f"{root!r}", denied_path=victim)

    # ------------------------------------------------------------------ #
    # 构建：不可变 release 目录 + manifest
    # ------------------------------------------------------------------ #
    def build(self, source_dir: str) -> Dict[str, Any]:
        """将 source_dir 构建为不可变 release 目录（全文件 SHA256+mode manifest）。

        D1：staging 全新构建 + rename 原子发布；绝不向既有 release 写入/覆盖。
        同秒同内容重复构建 -> 幂等复用已存在且完好的 release（reused=True）；
        release_id 冲突但内容 divergent/损坏 -> BuildError。
        P0-7 二次修：mode 策略按「源文件 exec 位」判定——源文件含任一 exec 位
        （0755 无扩展可执行文件同理）发布后保持可执行（0555）；否则 0444
        （0644 带 shebang 的 .py 不强加 exec）。manifest 逐文件记录 mode，
        verify() 对账 mode 漂移。
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
                # P0-7 修：mode 策略——源文件 exec 位决定发布后可执行性
                src_mode = os.stat(src).st_mode & 0o777
                exec_bit = bool(src_mode & 0o111)
                release_mode = 0o555 if exec_bit else 0o444
                os.chmod(dst, release_mode)
                entries.append({
                    "path": rel,
                    "sha256": file_hash,
                    "size": os.path.getsize(dst),
                    "mode": "%04o" % release_mode,
                })
                digest.update(rel.encode("utf-8") + b"\0" + file_hash.encode("ascii") + b"\0")
            content_digest = digest.hexdigest()

            release_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{content_digest[:12]}"
            final_dir = os.path.join(self.releases_root, release_id)

            manifest = {
                "release_id": release_id,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source_dir": source,
                "content_digest": content_digest,
                "schema_version": CURRENT_SCHEMA_VERSION,  # DEP-05
                "files": sorted(entries, key=lambda e: e["path"]),
            }
            # DEP-04：release 签名（keyring 机制复用 approval_keys——只读）
            if self.release_keyring is not None and self.release_signing_key:
                key_id = self.release_signing_key
                try:
                    secret = self.release_keyring.get_for_signing(key_id)
                except Exception as exc:  # noqa: BLE001 - KeyStateError 族
                    raise BuildError(
                        f"release signing key not eligible for signing "
                        f"(fail-closed): {key_id!r}: {exc!r}") from exc
                manifest["key_id"] = key_id
                manifest["signature"] = sign_envelope(secret, manifest)
            manifest_path = os.path.join(staging, MANIFEST_NAME)
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.write("\n")
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
    @staticmethod
    def _resolve_link_value(link_dir: str, value: str) -> str:
        """相对链接值一律相对 link 所在目录解析（绝不相对进程 cwd）。

        绝对值原样 normpath 返回。P0-7 修：previous/current 相对链接曾按
        进程 cwd 解析 → 误判不存在 → 跳过回滚 → current 留在失败版。
        """
        if os.path.isabs(value):
            return os.path.normpath(value)
        return os.path.normpath(os.path.join(link_dir, value))

    def verify(self, release_dir: str, strict: bool = True) -> Dict[str, Any]:
        """manifest 对账：缺件/多件/哈希漂移/mode 漂移任一非空即失败（D4）。

        strict=True（默认）失败抛 VerifyError（携带完整报告）；
        strict=False 返回含 ``ok`` 布尔的报告，供调用方自行裁决。
        P0-7 二次修：manifest 逐文件记录 mode；发布后 chmod 篡改（如 0444→
        0755）在 verify 即失败（mode_drifted），不再只校验内容哈希。
        """
        release = os.path.abspath(release_dir)
        manifest_path = os.path.join(release, MANIFEST_NAME)
        if not os.path.isfile(manifest_path):
            report = {
                "ok": False, "release_dir": release, "release_id": None,
                "missing": [MANIFEST_NAME], "extra": [], "drifted": [],
                "mode_drifted": [], "checked": 0,
            }
            if strict:
                raise VerifyError(report)
            return report

        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        if not isinstance(manifest, dict):
            manifest = {}
        # DEP-05：manifest 结构防御性解析——坏 manifest 设计内拒绝，不崩溃
        manifest_reason: Optional[str] = None
        try:
            entries = {e["path"]: e for e in manifest.get("files", [])}
            expected = {p: e["sha256"] for p, e in entries.items()}
        except (KeyError, TypeError):
            entries, expected = {}, {}
            manifest_reason = "manifest_invalid"
        # DEP-05：schema_version 类型/范围判定
        schema_reason: Optional[str] = None
        sv = manifest.get("schema_version")
        if sv is not None and (not isinstance(sv, int) or isinstance(sv, bool)):
            schema_reason = f"schema_version_invalid:{sv!r}"
            sv = None
        if self.schema_range is not None:
            if sv is None:
                schema_reason = schema_reason or "schema_version_missing"
            elif not (self.schema_range[0] <= sv <= self.schema_range[1]):
                schema_reason = (
                    f"schema_version_out_of_range:{sv} not in "
                    f"[{self.schema_range[0]},{self.schema_range[1]}]")
        # DEP-04：release 签名验签（自签/替换/revoked 全拒）
        signature_reason: Optional[str] = None
        if self.release_keyring is not None:
            key_id = manifest.get("key_id")
            signature = manifest.get("signature")
            if not key_id or not signature:
                signature_reason = "unsigned_release"
            elif not self.release_keyring.has(key_id):
                signature_reason = f"unknown_release_key:{key_id!r}"
            elif self.release_keyring.meta(key_id).get("status") == "revoked":
                signature_reason = f"revoked_release_key:{key_id!r}"
            elif (self.release_signing_key
                  and key_id != self.release_signing_key):
                signature_reason = (
                    f"release_key_replaced:{key_id!r} != pinned "
                    f"{self.release_signing_key!r}")
            elif not self.release_keyring.verify(manifest):
                signature_reason = "release_signature_mismatch"

        actual = set(_collect_files(release)) - {MANIFEST_NAME}  # manifest 自身不在清单内
        expected_set = set(expected)

        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        drifted = sorted(
            p for p in expected_set & actual
            if _sha256_file(os.path.join(release, p)) != expected[p]
        )
        # P0-7 修：mode 对账——manifest 记录了 mode 的文件，实际权限位必须一致
        mode_drifted = sorted(
            p for p in expected_set & actual
            if entries[p].get("mode") is not None
            and _stat_mode(os.path.join(release, p)) != int(entries[p]["mode"], 8)
        )
        ok = not (missing or extra or drifted or mode_drifted
                  or signature_reason or schema_reason or manifest_reason)
        report = {
            "ok": ok,
            "release_dir": release,
            "release_id": manifest.get("release_id"),
            "missing": missing,
            "extra": extra,
            "drifted": drifted,
            "mode_drifted": mode_drifted,
            "checked": len(expected_set & actual),
            "signature": signature_reason,   # DEP-04（None=通过/未启用）
            "schema": schema_reason or manifest_reason,  # DEP-05
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
                self._resolve_link_value(link_dir, previous) if previous else None),
            "target": target_abs,
            "link_value": link_value,
        }

    def rollback(self, current: str, previous: str) -> Dict[str, Any]:
        """切回兼容版：先对 previous release 做 manifest 完好性对账，再原子切回。

        previous 已损坏（缺件/漂移）时拒绝回切并抛错——绝不把流量切到坏包上。
        P0-7 修：previous 允许是相对链接值——一律相对 current 链接所在目录解析
        （不相对进程 cwd）。
        DEP-05：previous manifest 的 schema_version 超出 ``schema_range``
        兼容范围时拒绝回滚（SchemaRangeError，current 不变）——绝不把
        运行时切到读不懂的未来 schema 上。
        DEP-08：状态机处于 FUSE_OPEN（回滚曾失败熔断）时拒绝一切回滚，
        停等人工 ``resume_releases``。
        """
        # DEP-08：熔断检查
        fuse_state = self._state.load()
        if fuse_state.get("status") == STATE_FUSE_OPEN:
            raise FuseOpenError(
                f"release circuit fused open (ROLLBACK_FAILED); rollback "
                f"refused until manual resume_releases: "
                f"{fuse_state.get('detail', '')}")
        link = os.path.abspath(current)
        link_dir = os.path.dirname(link) or "."
        prev = self._resolve_link_value(link_dir, previous)
        if not os.path.isdir(prev):
            raise SwitchError(f"rollback target missing: {prev}")
        # DEP-05：schema 兼容范围判定（先于完好性对账，明确的专用拒绝）
        if self.schema_range is not None:
            sv = self._read_schema_version(prev)
            lo, hi = self.schema_range
            if sv is None or not (lo <= sv <= hi):
                raise SchemaRangeError(
                    f"previous release schema_version {sv!r} outside "
                    f"supported range [{lo},{hi}]; refusing rollback to "
                    f"{prev}", schema_version=sv, allowed_range=(lo, hi))
        verify_report = self.verify(prev)
        result = self.switch(link, prev)
        result.update({"rolled_back": True, "verify": verify_report})
        return result

    def _read_schema_version(self, release_dir: str) -> Optional[int]:
        """读 release manifest 的 schema_version（缺失/坏值 → None）。"""
        try:
            with open(os.path.join(release_dir, MANIFEST_NAME),
                      encoding="utf-8") as fh:
                manifest = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(manifest, dict):
            return None
        sv = manifest.get("schema_version")
        if isinstance(sv, int) and not isinstance(sv, bool):
            return sv
        return None

    # ------------------------------------------------------------------ #
    # 编排：lease -> build -> verify -> 迁移门/观察窗 -> switch -> 自检
    # ------------------------------------------------------------------ #
    def deploy(self, source_dir: str, *,
               migration_lock: Optional["MigrationLock"] = None,
               backup_proof: Optional[BackupProof] = None,
               expand_authorization: Optional[_AbcMapping] = None,
               contract_authorization: Optional[_AbcMapping] = None,
               rollback_authorization: Optional[_AbcMapping] = None,
               ) -> Dict[str, Any]:
        """完整部署：租约 -> 构建 -> 对账 -> 激活门禁 -> 原子切换 -> 安装自检。

        D2（legacy，默认）：自检失败 = 部署失败——自动回滚上一版后抛
        DeployError。P0-7 修：首次部署无上一版可回滚时，切回空/删除
        current link（不留在失败版上）；回滚后对回滚目标再跑一次
        self-check 复验。
        DEP-01：全程持有部署 lease——并发争用者 LeaseError（最多一个成功）。
        DEP-06：release 含 migrations/ 时，激活前必须持有迁移锁+已验证
        备份（+expand 授权），缺一即 ActivationBlocked（旧 current 不变）。
        DEP-07（fenced=True）：ACTIVATING 失败且无预授权 rollback
        envelope → FAILED_BLOCKED——不自动回滚、不继续发布，停等人工
        acknowledge_failed_block。
        DEP-08：恢复路径中的回滚再失败 → FUSE_OPEN 熔断（后续部署/回滚
        全拒，直至 resume_releases）。
        DEP-09：观察窗内夹带 contract/down migration → ObservationWindowError
        （独立 ddl_contract 授权可放行）。
        """
        # DEP-07/08：停等状态检查（FAILED_BLOCKED / FUSE_OPEN）
        entry_state = self._state.load()
        _status = entry_state.get("status")
        if _status == STATE_FUSE_OPEN:
            raise FuseOpenError(
                f"release circuit fused open (ROLLBACK_FAILED); deploy "
                f"refused until manual resume_releases: "
                f"{entry_state.get('detail', '')}")
        if _status == STATE_FAILED_BLOCKED:
            raise ActivationBlocked(
                f"previous deployment is FAILED_BLOCKED (release "
                f"{entry_state.get('release_id', '?')}); manual "
                f"acknowledgement (acknowledge_failed_block) required "
                f"before any further deploy")

        lease = self._acquire_deploy_lease()  # DEP-01
        try:
            build_result = self.build(source_dir)
            verify_report = self.verify(build_result["release_dir"])  # 切换前对账

            # DEP-06：激活前迁移门（无迁移则跳过）
            migrations = scan_migrations(build_result["release_dir"])
            if migrations["files"]:
                reasons = self._migration_gate_reasons(
                    migrations, migration_lock, backup_proof,
                    expand_authorization, build_result["content_digest"])
                if reasons:
                    raise ActivationBlocked(
                        f"activation BLOCKED by migration gate: {reasons}; "
                        f"old current unchanged; release "
                        f"{build_result['release_dir']} built but NOT "
                        f"activated", reasons=reasons)
            # DEP-09：观察窗门（contract/down 夹带）
            self._observation_gate(migrations, contract_authorization,
                                   build_result["content_digest"])

            # P0-7 修：切换前记录是否存在 current link（首次部署判定）
            _had_current = os.path.islink(self.current_link) or os.path.exists(self.current_link)
            _prev_target_raw = None
            _prev_target_abs = None
            if _had_current and os.path.islink(self.current_link):
                _prev_target_raw = os.readlink(self.current_link)
                # P0-7 修：相对链接值按 link 所在目录解析（不相对进程 cwd）
                _prev_target_abs = self._resolve_link_value(
                    os.path.dirname(self.current_link) or ".", _prev_target_raw)

            # DEP-07：fenced 激活状态机进入 ACTIVATING（落盘）
            if self.fenced:
                self._state.update(status=STATE_ACTIVATING,
                                   release_id=build_result["release_id"])

            switch_report = self.switch(self.current_link, build_result["release_dir"])

            try:
                check = self._run_self_check(build_result["release_dir"])
                if check is not None and not check:
                    raise SelfCheckError(f"install self-check returned falsy: {check!r}")
            except Exception as exc:
                if self.fenced:
                    # DEP-07：fenced 失败路径（预授权裁定回滚 vs FAILED_BLOCKED）
                    self._fenced_activation_failure(
                        exc, build_result, _had_current, _prev_target_abs,
                        rollback_authorization)
                    raise AssertionError("unreachable")  # pragma: no cover
                rollback_note = "no previous release to roll back to"
                if _prev_target_abs and os.path.isdir(_prev_target_abs):
                    try:
                        self.rollback(self.current_link, _prev_target_abs)
                        rollback_note = f"rolled back to {_prev_target_abs}"
                        # P0-7 修：回滚后对回滚目标再验一次 self-check
                        if self.install_self_check is not None:
                            try:
                                recheck = self._run_self_check(_prev_target_abs)
                                rollback_note += (
                                    "; rollback self-check re-verified"
                                    if recheck else
                                    "; WARNING: rollback target also fails self-check"
                                )
                            except Exception as sc_exc:  # noqa: BLE001
                                rollback_note += (
                                    f"; WARNING: rollback target self-check error: {sc_exc!r}")
                    except DeployError as rb_exc:
                        rollback_note = (f"ROLLBACK FAILED ({rb_exc}); "
                                         f"current link remains on failed release "
                                         f"{build_result['release_dir']}")
                        # DEP-08：回滚再失败 → 熔断停等人工
                        self._state.update(
                            status=STATE_FUSE_OPEN,
                            release_id=build_result["release_id"],
                            detail=f"rollback failed during deploy recovery: "
                                   f"{rb_exc}")
                elif not _had_current:
                    # P0-7 修：首次部署失败——删除 current link（不留在失败版上）
                    try:
                        os.unlink(self.current_link)
                        rollback_note = "first deploy: current link removed (no failed release active)"
                    except OSError:
                        rollback_note = f"first deploy: failed to remove current link, stays on failed release"
                raise DeployError(
                    f"deploy failed at install self-check: {exc!r}; {rollback_note}"
                ) from exc

            # 激活成功：状态机落 ACTIVE + 观察窗锚点（DEP-09 用）
            self._state.update(status=STATE_ACTIVE,
                               release_id=build_result["release_id"],
                               last_activated_at=time.time())

            return {
                "deployed": True,
                "release_id": build_result["release_id"],
                "release_dir": build_result["release_dir"],
                "build": build_result,
                "verify": verify_report,
                "switch": switch_report,
                "self_check": ("passed(isolated)" if
                               self.self_check_protected_paths is not None
                               else "passed"),
                "migrations": migrations,
            }
        finally:
            lease.release()

    # ------------------------------------------------------------------ #
    # DEP-01：部署租约
    # ------------------------------------------------------------------ #
    def _acquire_deploy_lease(self) -> DeployLease:
        return DeployLease.acquire(
            os.path.join(self.releases_root, LEASE_FILENAME),
            timeout=self.lease_timeout)

    # ------------------------------------------------------------------ #
    # DEP-02：自检调用（隔离包装 or 直跑）
    # ------------------------------------------------------------------ #
    def _run_self_check(self, release_dir: str) -> Any:
        if self.install_self_check is None:
            return None
        if self.self_check_protected_paths is not None:
            return run_isolated_self_check(
                release_dir, self.install_self_check,
                self.self_check_protected_paths)
        return self.install_self_check(release_dir)

    # ------------------------------------------------------------------ #
    # DEP-06：迁移门（迁移锁/备份验证/expand 授权）
    # ------------------------------------------------------------------ #
    def _migration_gate_reasons(
            self, migrations: Dict[str, List[str]],
            migration_lock: Optional["MigrationLock"],
            backup_proof: Optional[BackupProof],
            expand_authorization: Optional[_AbcMapping],
            content_digest: str) -> List[str]:
        reasons: List[str] = []
        if not (isinstance(migration_lock, DeployLease) and migration_lock.held):
            reasons.append("migration_lock_missing")
        if not (isinstance(backup_proof, BackupProof) and backup_proof.valid):
            reasons.append("backup_not_verified")
        elif backup_proof.content_digest is not None \
                and backup_proof.content_digest != content_digest:
            # 备份证明绑定的是另一个 release——不是本次激活的有效备份
            reasons.append("backup_not_verified")
        if migrations["expand"] and not self._validate_authorization(
                expand_authorization, "ddl", content_digest=content_digest):
            reasons.append("expand_migration_unauthorized")
        return reasons

    # ------------------------------------------------------------------ #
    # DEP-09：观察窗门（contract/down 夹带拒绝）
    # ------------------------------------------------------------------ #
    def _observation_gate(self, migrations: Dict[str, List[str]],
                          contract_authorization: Optional[_AbcMapping],
                          content_digest: str) -> None:
        if self.observation_seconds <= 0:
            return
        contraband = sorted(set(migrations["contract"]) | set(migrations["down"]))
        if not contraband:
            return
        state = self._state.load()
        last = state.get("last_activated_at")
        if not isinstance(last, (int, float)) or isinstance(last, bool):
            return  # 尚无激活锚点（首个 release）——无观察窗
        remaining = self.observation_seconds - (time.time() - float(last))
        if remaining <= 0:
            return  # 观察窗已过——常规通道（仍受 DEP-06 门约束）
        if self._validate_authorization(contract_authorization, "ddl_contract",
                                        content_digest=content_digest):
            return  # 独立授权变更（HMAC envelope 绑定 content_digest）
        raise ObservationWindowError(
            f"observation window active ({remaining:.1f}s remaining); "
            f"release smuggles contract/down migrations {contraband}; "
            f"independent ddl_contract authorization required",
            contraband=contraband, remaining_seconds=remaining)

    # ------------------------------------------------------------------ #
    # DEP-06/07/09：HMAC 授权 envelope 验证（keyring 机制复用 approval_keys）
    # ------------------------------------------------------------------ #
    def _validate_authorization(self, envelope: Optional[_AbcMapping],
                                expected_type: str, *,
                                content_digest: Optional[str] = None,
                                release_id: Optional[str] = None) -> bool:
        if not isinstance(envelope, _AbcMapping) or self.auth_keyring is None:
            return False
        if envelope.get("approval_type") != expected_type:
            return False
        if envelope.get("decision") != "approve":
            return False
        if not self.auth_keyring.verify(envelope):
            return False
        payload = envelope.get("payload")
        payload = payload if isinstance(payload, _AbcMapping) else {}
        if content_digest is not None \
                and payload.get("content_digest") != content_digest:
            return False
        if release_id is not None:
            claimed = payload.get("release_id")
            if claimed is not None and claimed != release_id:
                return False
        return True

    # ------------------------------------------------------------------ #
    # DEP-07：fenced 激活失败路径（预授权裁定：回滚 vs FAILED_BLOCKED）
    # ------------------------------------------------------------------ #
    def _fenced_activation_failure(
            self, exc: Exception, build_result: Dict[str, Any],
            had_current: bool, prev_target_abs: Optional[str],
            rollback_authorization: Optional[_AbcMapping]) -> None:
        authorized = self._validate_authorization(
            rollback_authorization, "rollback",
            release_id=build_result["release_id"])
        if authorized and prev_target_abs and os.path.isdir(prev_target_abs):
            try:
                self.rollback(self.current_link, prev_target_abs)
            except DeployError as rb_exc:
                # DEP-08：授权回滚再失败 → 熔断
                self._state.update(
                    status=STATE_FUSE_OPEN,
                    release_id=build_result["release_id"],
                    detail=f"authorized rollback failed during fenced "
                           f"activation: {rb_exc}")
                raise FuseOpenError(
                    f"fenced activation failed ({exc!r}) AND authorized "
                    f"rollback failed ({rb_exc!r}); state=FUSE_OPEN; "
                    f"current remains on failed release "
                    f"{build_result['release_dir']}; manual "
                    f"resume_releases required") from rb_exc
            self._state.update(status=STATE_ROLLED_BACK,
                               release_id=build_result["release_id"],
                               detail=f"fenced activation failed: {exc!r}")
            raise DeployError(
                f"fenced deploy failed at activation: {exc!r}; pre-authorized "
                f"rollback executed to {prev_target_abs}") from exc
        # DEP-07：无预授权（或预授权无效/无回滚目标）→ FAILED_BLOCKED：
        # 绝不自动回滚（current 留在失败 release 上，等待人工裁决），
        # 后续部署停等 acknowledge_failed_block。
        self._state.update(
            status=STATE_FAILED_BLOCKED,
            release_id=build_result["release_id"],
            detail=f"activation failed without valid pre-authorized "
                   f"rollback: {exc!r}")
        raise FailedBlockedError(
            f"ACTIVATING failed without pre-authorized rollback "
            f"({exc!r}); state=FAILED_BLOCKED; auto-rollback suppressed; "
            f"current remains on failed release "
            f"{build_result['release_dir']}; no further deploy until "
            f"manual acknowledge_failed_block") from exc

    # ------------------------------------------------------------------ #
    # DEP-07/08：人工恢复入口（停等解除的唯一通道）
    # ------------------------------------------------------------------ #
    def acknowledge_failed_block(self, *, operator: str,
                                 note: str = "") -> Dict[str, Any]:
        """人工确认 FAILED_BLOCKED（DEP-07 停等解除；操作者留痕落盘）。"""
        state = self._state.load()
        if state.get("status") != STATE_FAILED_BLOCKED:
            raise DeployError(
                f"no FAILED_BLOCKED state to acknowledge "
                f"(current status: {state.get('status', 'IDLE')!r})")
        self._state.update(
            status="ACKNOWLEDGED",
            acknowledged_by=operator, ack_note=note)
        return self._state.load()

    def resume_releases(self, *, operator: str,
                        note: str = "") -> Dict[str, Any]:
        """人工解除 FUSE_OPEN 熔断（DEP-08 停等恢复；操作者留痕落盘）。"""
        state = self._state.load()
        if state.get("status") != STATE_FUSE_OPEN:
            raise DeployError(
                f"no FUSE_OPEN state to resume "
                f"(current status: {state.get('status', 'IDLE')!r})")
        self._state.update(
            status="RESUMED", resumed_by=operator, resume_note=note)
        return self._state.load()

# -*- coding: utf-8 -*-
"""W11-02——运行时漂移检测、告警、熔断及自动恢复（核心库）。

覆盖风险：``R10-REL-ACTIVE-TREE-DRIFT-001``（现役 release 树被外部会话
热改：server.py 换字节 + 0444→0644。0444 非 UID 边界——同 UID 可 chmod
后改写；且存在未授权 drift-watcher 外部自动化在与部署位互操作，按敌对
干扰防线处理）。

与安装链的分工：
    install-release.sh 部署位是 ``$INSTALL_ROOT/releases/<40hex>/``（四件套
    + tree/，chmod -R a-w 只读化），``current`` symlink → ``<release>/tree``，
    ``.last-current`` 记录上一激活目标。本模块以**只读**方式对账该布局，
    唯一写面是 ``state/release-integrity.json``（原子发布）、
    ``releases/.recovery-journal.jsonl``（append-only）、``observation/
    alerts``（告警文本）与 ``incidents/``（封存 bundle）——绝不改写漂移
    现场（自动恢复以「新目录全新解压 + 原现场更名隔离」实现，原字节
    全保留）。

核心语义（对齐方案 W11-02 节）：
    1. ``audit_tree``——树 vs manifest 逐文件 sha256 对账（内容漂移）
       + **可写位对账**（激活协议 ``chmod -R a-w`` 的运行时不变量：
       树内任何常规文件/目录不得含写位——0444→0644 这类纯 mode 漂移
       在内容哈希不变时仍被判漂移）+ missing/extra/special（FIFO 等）。
    2. ``scan_cycle``——current + previous 全树对账 + current 身份钉
       （必须在受管 ``releases/<40hex>(.rN)?/tree`` 内）+ runtime overlay
       六项（static_gate_pass / current_tree_clean / rollback_ready /
       pid_argv_and_script_bytes_match / scheduler_pass_and_fresh /
       capacity_open_and_fresh——静态八站 PASS 只是其中一项，不能覆盖
       其余五项的红）。
    3. ``monitor_tick``——一个扫描周期：发布状态 → 漂移时 CRITICAL 告警
       + incident bundle 封存 + 活动观察窗作废 + 熔断（fuse OPEN 冻结
       install/rollback 入口）→ 按授权自动恢复（最多一次）。
    4. 自动恢复四前门（任一不过即 ``RecoveryRefused``，现场原样）：
       exact SHA ∈ 外部 roots allowed_commit（manifest 核心 digest 双对
       账）+ 本地四件套对账（坏 cache 拒）+ recovery permit 未过期
       （0600、commit 精确匹配）+ 本漂移事件未曾尝试过（一漂移一尝试，
       失败熔断等人工 ``unfuse``）。

退出码（sentinel 入口）：
    扫描器 ``scan``：0 clean / 2 monitor error / 3 drift 或策略阻断；
    daemon ``tick``：0=检测与裁决完成（即使裁决 BLOCKED），2=监控自身失败。

W11-03 衔接边界（显式登记）：``activation-state-v2.json``（双 pin 激活
事务）未合流 main——deployment epoch 目前由本模块 ``.recovery-journal.jsonl``
（append-only，kind/epoch/commit/ts 全留痕）独立维护：恢复事件 ``epoch+1``。
W11-03 合流后 activation-state-v2 应收编该 journal 的 epoch 语义（字段
对齐：``kind``/``epoch``/``commit``/``ts``/``detail``），本模块只依赖
``journal_read``/``next_epoch`` 两个读接口，收编面收敛在两函数内。

监控器单写纪律：``state/release-integrity.json`` 的唯一 writer 是本模块
（哨兵 com.wenqu.integrity）；scheduler tick / dashboard / install-release
只读（scheduler 对陈旧/漂移快照发 CRITICAL——见
``check_integrity_freshness``）。
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat as _stat
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:  # 同包相对导入；包上下文缺失时回退绝对导入（与 deploy_framework 一致）
    from .deploy_framework import _sha256_file  # type: ignore
except ImportError:  # pragma: no cover - 直接脚本执行
    from wenqu_core.deploy_framework import _sha256_file  # type: ignore

__all__ = [
    "INTEGRITY_SCHEMA", "JOURNAL_FILENAME", "STATE_RELPATH",
    "PERMIT_RELPATH", "SERVICES_CONFIG_FILENAME",
    "IntegrityPaths", "DriftError", "RecoveryRefused", "RecoveryError",
    "audit_tree", "resolve_release", "scan_cycle",
    "read_state", "write_state", "fuse_open",
    "monitor_tick", "scan_exit_code",
    "attempt_auto_recovery", "unfuse",
    "raise_critical_alarm", "archive_incident", "invalidate_active_windows",
    "audit_processes", "check_integrity_freshness",
    "journal_read", "next_epoch",
]

#: 状态文件 schema（原子发布；唯一 writer=哨兵）
INTEGRITY_SCHEMA = "wenqu-release-integrity/v1"

#: 恢复 journal（releases 根，append-only；W11-03 衔接见模块 docstring）
JOURNAL_FILENAME = ".recovery-journal.jsonl"

#: 状态文件相对 WENQU_HOME 的路径
STATE_RELPATH = os.path.join("state", "release-integrity.json")

#: recovery permit 相对 WENQU_HOME 的路径（部署授权流程仓外预置）
PERMIT_RELPATH = "release-recovery-permit.json"

#: 进程对账服务清单（可选；缺失 → pid 项 NOT_EVALUATED）
SERVICES_CONFIG_FILENAME = "release-integrity-services.json"

_PERMIT_SCHEMA = "wenqu-release-recovery-permit/1"

#: 受管 release 目录名：40hex commit（可带 .r<epoch> 恢复代次后缀）
_RELEASE_DIR_RE = re.compile(r"^([0-9a-f]{40})(?:\.r(\d+))?$")

#: 哨兵扫描周期缺省（launchd StartInterval 同步：300s）
SCAN_INTERVAL_DEFAULT = 300.0

#: 心跳/容量快照新鲜度缺省（2×扫描周期 + 1 周期余量）
FRESHNESS_TTL_DEFAULT = 900.0


class DriftError(RuntimeError):
    """漂移监控器基础错误。"""


class RecoveryRefused(DriftError):
    """自动恢复前置门未过（绝不触碰现场）。"""

    def __init__(self, reasons: List[str]):
        super().__init__("auto-recovery refused: " + "; ".join(reasons))
        self.reasons = list(reasons)


class RecoveryError(DriftError):
    """自动恢复已开始但执行失败（尝试已消耗，熔断等人工）。"""


# ---------------------------------------------------------------------- #
# 路径束（与 scheduler.ProductionPaths 同风格：env 可覆盖、测试可注入）
# ---------------------------------------------------------------------- #
class IntegrityPaths:
    """漂移哨兵的全部路径（WENQU_HOME=安装根；env 可覆盖，测试整体注入）。"""

    __slots__ = ("wenqu_home", "releases_root", "current_link",
                 "last_current", "state_path", "roots_path", "permit_path",
                 "journal_path", "incidents_root", "alerts_dir",
                 "observation_root", "heartbeat_path", "gate_aggregate_path",
                 "services_config_path", "release_attest_path")

    def __init__(self, *, wenqu_home: str,
                 release_attest_path: Optional[str] = None) -> None:
        self.wenqu_home = os.path.abspath(wenqu_home)
        self.releases_root = os.path.join(self.wenqu_home, "releases")
        self.current_link = os.path.join(self.wenqu_home, "current")
        self.last_current = os.path.join(self.releases_root, ".last-current")
        self.state_path = os.path.join(self.wenqu_home, STATE_RELPATH)
        self.roots_path = os.path.join(self.wenqu_home, "release-roots.json")
        self.permit_path = os.path.join(self.wenqu_home, PERMIT_RELPATH)
        self.journal_path = os.path.join(self.releases_root, JOURNAL_FILENAME)
        self.incidents_root = os.path.join(self.wenqu_home, "incidents")
        self.alerts_dir = os.path.join(self.wenqu_home, "observation",
                                       "alerts")
        self.observation_root = os.path.join(self.wenqu_home, "observation")
        self.heartbeat_path = os.path.join(self.observation_root,
                                           "heartbeat.json")
        self.gate_aggregate_path = os.path.join(self.wenqu_home, "state",
                                                "gate-aggregate.json")
        self.services_config_path = os.path.join(
            self.wenqu_home, SERVICES_CONFIG_FILENAME)
        # release_attest 正源解析：env > 显式注入 > current 树内 tools/
        # （哨兵随树发布；树外部署时须显式指定）。测试注入覆盖。
        self.release_attest_path = release_attest_path or (
            os.environ.get("WENQU_RELEASE_ATTEST")
            or self._current_tree_release_attest())

    @staticmethod
    def for_home(wenqu_home: str,
                 *, release_attest_path: Optional[str] = None
                 ) -> "IntegrityPaths":
        return IntegrityPaths(wenqu_home=wenqu_home,
                              release_attest_path=release_attest_path)

    @classmethod
    def from_env(cls) -> "IntegrityPaths":
        home = os.environ.get("WENQU_HOME") or os.path.expanduser("~/.wenqu")
        return cls(wenqu_home=home)

    def _current_tree_release_attest(self) -> Optional[str]:
        try:
            target = os.readlink(self.current_link)
        except OSError:
            return None
        if not target:
            return None
        tree = target if os.path.isabs(target) else os.path.normpath(
            os.path.join(os.path.dirname(self.current_link), target))
        cand = os.path.join(tree, "tools", "release_attest.py")
        return cand if os.path.isfile(cand) else None

    def ensure_dirs(self) -> None:
        for d in (os.path.dirname(self.state_path), self.alerts_dir,
                  self.incidents_root):
            os.makedirs(d, exist_ok=True)


def _utc_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _atomic_write_json(path: str, payload: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------------- #
# release_attest 只读复用（roots 对账 + tar 逐文件枚举 + 核心 digest）
# ---------------------------------------------------------------------- #
_RA_CACHE: Dict[str, Any] = {}


def _load_release_attest(path: Optional[str]) -> Any:
    """按需加载 tools/release_attest.py（只读复用其正源对账函数）。

    缺失/不可加载 → None（调用方降级：roots 门与恢复对账按 fail-closed
    处理，绝不因工具缺失而放行恢复）。
    """
    if not path or not os.path.isfile(path):
        return None
    key = os.path.abspath(path)
    if key not in _RA_CACHE:
        tools_dir = os.path.dirname(key)
        saved = sys.path[:]
        if tools_dir not in sys.path:  # release_attest 顶注 import 同目录模块
            sys.path.insert(0, tools_dir)
        try:
            spec = importlib.util.spec_from_file_location(
                f"_release_drift_attest_{len(_RA_CACHE)}", key)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            _RA_CACHE[key] = mod
        except Exception:  # noqa: BLE001 - 工具不可加载=能力降级，不崩哨兵
            _RA_CACHE[key] = None
        finally:
            sys.path[:] = saved
    return _RA_CACHE[key]


# ---------------------------------------------------------------------- #
# 树对账：内容 sha256 + 可写位（mode）不变量
# ---------------------------------------------------------------------- #
def _iter_tree_entries(tree: str) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """遍历树 → {relpath: {type, sha256, mode, link}}；收集不可 stat 的路径。

    遍历本身不可读（目录无 r/x 位）→ PermissionError 上抛：监控器无法
    完成对账属**监控自身失败**（monitor error），不是「树干净」也不是
    漂移判定——fail-visible，由 monitor_tick 收口为 MONITOR_ERROR。
    """
    entries: Dict[str, Dict[str, Any]] = {}
    broken: List[str] = []
    for dirpath, dirnames, filenames in os.walk(
            tree, onerror=lambda e: (_ for _ in ()).throw(e)):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, tree)
            try:
                st = os.lstat(full)
            except OSError:
                broken.append(rel)
                continue
            if _stat.S_ISLNK(st.st_mode):
                entries[rel] = {"type": "symlink",
                                "link": os.readlink(full),
                                "sha256": hashlib.sha256(
                                    os.readlink(full).encode("utf-8")).hexdigest()}
            elif _stat.S_ISDIR(st.st_mode):
                entries[rel] = {"type": "dir",
                                "mode": _stat.S_IMODE(st.st_mode)}
            elif _stat.S_ISREG(st.st_mode):
                entries[rel] = {"type": "file",
                                "mode": _stat.S_IMODE(st.st_mode),
                                "sha256": _sha256_file(full)}
            else:  # FIFO/socket/device——发行树契约外实体
                entries[rel] = {"type": "special",
                                "mode": _stat.S_IMODE(st.st_mode)}
    return entries, broken


def audit_tree(tree_dir: str, manifest_path: str) -> Dict[str, Any]:
    """树 vs manifest 全量对账（内容 + 可写位不变量）。

    判漂移面：
      - ``missing``/``extra``：manifest 清单 vs 实际实体差集（目录蕴含
        不入 manifest——tar 契约同 release_attest._iter_tar_records）；
      - ``drifted``：常规文件 sha256 不符（**换字节**，即事故形态①）；
      - ``mode_drifted``：含写位的文件/目录（激活协议 chmod -R a-w 的
        运行时不变量被破坏——**0444→0644**，即事故形态②；内容哈希不变
        也能抓）；
      - ``type_mismatch``：symlink↔file 错型；``special``：FIFO 等契约外
        实体；``broken``：不可 stat 路径。
    manifest 缺失/坏 → fail-closed（ok=False, reason=manifest_*）。
    """
    tree = os.path.abspath(tree_dir)
    report: Dict[str, Any] = {
        "tree_dir": tree, "manifest_path": manifest_path,
        "ok": False, "missing": [], "extra": [], "drifted": [],
        "mode_drifted": [], "type_mismatch": [], "special": [],
        "broken": [], "checked": 0, "reason": None,
    }
    try:
        st = os.stat(tree)
    except FileNotFoundError:
        report["reason"] = "tree_missing"
        return report
    except PermissionError:
        raise DriftError(f"tree_unreadable:{tree}（监控器无权对账=monitor error）")
    if not _stat.S_ISDIR(st.st_mode):
        report["reason"] = "tree_not_dir"
        return report
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        files = [e for e in manifest.get("files", [])
                 if isinstance(e, dict) and isinstance(e.get("path"), str)]
    except (OSError, ValueError, AttributeError):
        report["reason"] = "manifest_unreadable"
        return report
    if not isinstance(manifest, dict) or not files:
        report["reason"] = "manifest_invalid"
        return report

    expected: Dict[str, Dict[str, Any]] = {e["path"]: e for e in files}
    actual, broken = _iter_tree_entries(tree)
    report["broken"] = sorted(broken)

    for rel, ent in actual.items():
        if rel not in expected:
            # 目录蕴含（manifest 只记文件/symlink）不算 extra
            if ent["type"] != "dir":
                report["extra"].append(rel)
            continue
        want = expected[rel]
        want_type = want.get("type", "file")
        if want_type != ent["type"]:
            report["type_mismatch"].append(rel)
            continue
        report["checked"] += 1
        if want_type == "file":
            if want.get("sha256") != ent["sha256"]:
                report["drifted"].append(rel)
        elif want_type == "symlink":
            if want.get("sha256") != ent["sha256"]:
                report["drifted"].append(rel)
    report["missing"] = sorted(set(expected) - set(actual))

    # 可写位不变量：任何树内实体（文件/目录）不得含写位。
    # manifest 记录的是 tar 内 mode（0644/0755）——部署协议在激活时执行
    # chmod -R a-w，运行时不变量=无写位；据此抓纯 mode 漂移。
    for rel, ent in actual.items():
        mode = ent.get("mode")
        if mode is not None and (mode & 0o222):
            report["mode_drifted"].append(rel)

    report["extra"] = sorted(report["extra"])
    report["drifted"] = sorted(set(report["drifted"]))
    report["mode_drifted"] = sorted(set(report["mode_drifted"]))
    report["type_mismatch"] = sorted(report["type_mismatch"])
    report["special"] = sorted(rel for rel, e in actual.items()
                               if e["type"] == "special")
    report["ok"] = not (report["missing"] or report["extra"]
                        or report["drifted"] or report["mode_drifted"]
                        or report["type_mismatch"] or report["special"]
                        or report["broken"])
    return report


def resolve_release(tree_path: str, releases_root: str
                    ) -> Dict[str, Any]:
    """结构门（与 install-release.sh 回滚 [1/6] 同构）：

    tree 路径 → {ok, release_dir, commit, epoch, manifest_path, four_piece,
    structure_errors}。要求：末段=tree、父目录=releases/<40hex>(.rN)?、
    四件套（manifest 唯一 + tar/sig/sbom）齐。
    """
    root = os.path.realpath(releases_root)
    out: Dict[str, Any] = {
        "ok": False, "release_dir": None, "commit": None, "epoch": None,
        "manifest_path": None, "four_piece": {}, "structure_errors": [],
    }
    try:
        real = os.path.realpath(tree_path)
    except OSError:
        real = os.path.abspath(tree_path)
    parent, base = os.path.split(real.rstrip(os.sep))
    if base != "tree":
        out["structure_errors"].append(f"not_tree_dir:{real}")
        return out
    relparent = os.path.relpath(parent, root)
    if relparent.startswith("..") or os.path.isabs(relparent):
        out["structure_errors"].append(
            f"outside_releases_root:{parent} not under {root}")
        return out
    m = _RELEASE_DIR_RE.match(os.path.basename(parent))
    if not m:
        out["structure_errors"].append(
            f"release_dir_not_commit_sha:{os.path.basename(parent)}")
        return out
    out["commit"] = m.group(1)
    out["epoch"] = int(m.group(2)) if m.group(2) else 0
    out["release_dir"] = parent
    manifests = [p for p in _safe_glob(parent, "wenqu-dist-*.manifest.json")]
    if len(manifests) != 1:
        out["structure_errors"].append(
            f"manifest_not_unique:{len(manifests)}")
        return out
    out["manifest_path"] = manifests[0]
    stem = manifests[0][: -len(".manifest.json")]
    for ext in ("tar.gz", "release.sig", "sbom.spdx.json"):
        p = f"{stem}.{ext}"
        if not os.path.isfile(p):
            out["structure_errors"].append(f"four_piece_missing:{ext}")
        else:
            out["four_piece"][ext] = p
    out["ok"] = not out["structure_errors"]
    return out


def _safe_glob(dirpath: str, pattern: str) -> List[str]:
    """目录枚举（glob 语义）。不可读 → DriftError（fail-visible：对账链
    自身失败=monitor error，绝不静默当「结构不存在」的漂移判定）。"""
    import fnmatch
    try:
        names = os.listdir(dirpath)
    except PermissionError as exc:
        raise DriftError(
            f"release_dir_unreadable:{dirpath}（监控器无权枚举）") from exc
    return sorted(os.path.join(dirpath, n) for n in names
                  if fnmatch.fnmatch(n, os.path.basename(pattern)))


# ---------------------------------------------------------------------- #
# journal（append-only；W11-03 衔接正源——见模块 docstring）
# ---------------------------------------------------------------------- #
def journal_append(paths: "IntegrityPaths", entry: Dict[str, Any]) -> None:
    os.makedirs(paths.releases_root, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    with open(paths.journal_path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def journal_read(paths: "IntegrityPaths") -> List[Dict[str, Any]]:
    try:
        with open(paths.journal_path, encoding="utf-8") as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
    except (OSError, ValueError):
        return []
    return [r for r in rows if isinstance(r, dict)]


def next_epoch(paths: "IntegrityPaths") -> int:
    """当前 deployment epoch +1（正源=state，回落 journal 最大值）。"""
    state = read_state(paths)
    cur = state.get("deployment_epoch")
    if not isinstance(cur, int) or isinstance(cur, bool):
        cur = 0
    jmax = 0
    for e in journal_read(paths):
        v = e.get("epoch")
        if isinstance(v, int) and not isinstance(v, bool):
            jmax = max(jmax, v)
    return max(cur, jmax) + 1


# ---------------------------------------------------------------------- #
# 状态发布（唯一 writer=本模块；原子写）
# ---------------------------------------------------------------------- #
def read_state(paths: "IntegrityPaths") -> Dict[str, Any]:
    try:
        with open(paths.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_state(paths: "IntegrityPaths", state: Dict[str, Any]) -> None:
    state = dict(state)
    state["schema"] = INTEGRITY_SCHEMA
    _atomic_write_json(paths.state_path, state)


def fuse_open(paths: "IntegrityPaths") -> bool:
    return read_state(paths).get("fuse") == "OPEN"


# ---------------------------------------------------------------------- #
# 告警链（文本投递箱——与 scheduler make_alertbox_sender 同格式；best-effort）
# ---------------------------------------------------------------------- #
def raise_critical_alarm(paths: "IntegrityPaths", subject: str, body: str,
                         *, now: Optional[float] = None,
                         dedup_key: Optional[str] = None) -> Optional[str]:
    """CRITICAL 告警落文本投递箱（本地原子写，绝不抛——告警不阻断裁决）。

    格式与 scheduler make_alertbox_sender 一致（message_id/subject/body +
    receipts.jsonl 回执），供同一观察通道汇聚。
    """
    now = time.time() if now is None else now
    mid = "integrity-" + hashlib.sha256(
        (dedup_key or subject).encode("utf-8")).hexdigest()[:16]
    try:
        os.makedirs(paths.alerts_dir, exist_ok=True)
        name = f"{time.strftime('%Y%m%d-%H%M%S', time.gmtime(now))}-CRITICAL-{mid[:12]}.txt"
        path = os.path.join(paths.alerts_dir, name)
        text = (f"message_id: {mid}\nchannel: alertbox\nseverity: CRITICAL\n"
                f"sent_at: {_utc_iso(now)}\nsubject: {subject}\n"
                f"attempts_so_far: 1\n---\n{body}\n")
        _atomic_text(path, text)
        with open(os.path.join(paths.alerts_dir, "receipts.jsonl"), "a",
                  encoding="utf-8") as fh:
            fh.write(json.dumps({
                "message_id": mid, "channel": "alertbox", "file": name,
                "severity": "CRITICAL", "subject": subject,
                "receipt_at": _utc_iso(now), "attempt": 1,
            }, ensure_ascii=False) + "\n")
        return path
    except OSError:
        return None


def _atomic_text(path: str, text: str) -> None:
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


# ---------------------------------------------------------------------- #
# incident bundle 封存（只增不删）
# ---------------------------------------------------------------------- #
def archive_incident(paths: "IntegrityPaths", finding: Dict[str, Any],
                     *, now: float) -> Optional[str]:
    """封存漂移现场快照：integrity 状态副本 + 漂移实体 lstat 清单。

    绝不删除/改写漂移现场本体——bundle 只是对账报告与元数据快照。
    """
    try:
        ident = finding.get("incident_id") or "incident"
        d = os.path.join(paths.incidents_root,
                         f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))}-{ident}")
        os.makedirs(d, exist_ok=True)
        _atomic_write_json(os.path.join(d, "finding.json"), finding)
        meta: Dict[str, Any] = {"archived_at": _utc_iso(now), "entities": {}}
        cur = finding.get("current") or {}
        tree = cur.get("tree_dir")
        if tree and os.path.isdir(tree):
            for rel in (cur.get("drifted") or [])[:50]:
                try:
                    st = os.lstat(os.path.join(tree, rel))
                    meta["entities"][rel] = {
                        "mode": oct(_stat.S_IMODE(st.st_mode)),
                        "size": st.st_size, "mtime": st.st_mtime,
                    }
                except OSError:
                    meta["entities"][rel] = {"error": "lstat_failed"}
        _atomic_write_json(os.path.join(d, "tree-stat.json"), meta)
        return d
    except OSError:
        return None


# ---------------------------------------------------------------------- #
# 活动观察窗作废（复用 tools/window_manifest 正源；best-effort 留痕）
# ---------------------------------------------------------------------- #
_WM_CACHE: Dict[str, Any] = {}


def _load_window_manifest():
    if "wm" not in _WM_CACHE:
        cand = os.environ.get("WENQU_WINDOW_MANIFEST")
        if cand and os.path.isfile(cand):
            src = cand
        else:
            src = os.path.join(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))),
                "tools", "window_manifest.py")
        try:
            spec = importlib.util.spec_from_file_location(
                "_release_drift_wm", src)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            _WM_CACHE["wm"] = mod
        except Exception:  # noqa: BLE001
            _WM_CACHE["wm"] = None
    return _WM_CACHE["wm"]


def invalidate_active_windows(paths: "IntegrityPaths", reason: str,
                              *, now: float) -> List[str]:
    """作废全部活动观察窗（漂移后样本不可信）。返回作废的 window_id 列表。"""
    wm = _load_window_manifest()
    if wm is None:
        return []
    invalidated: List[str] = []
    try:
        active = wm.active_manifest(paths.observation_root, now=now)
    except Exception:  # noqa: BLE001 - 窗口环境异常不阻断熔断主链
        return invalidated
    if not active:
        return invalidated
    try:
        wm.invalidate_window(paths.observation_root,
                             active["window_id"], reason=reason,
                             principal="com.wenqu.integrity", now=now)
        invalidated.append(active["window_id"])
    except Exception:  # noqa: BLE001
        pass
    return invalidated


# ---------------------------------------------------------------------- #
# PID/argv/脚本字节运行时对账
# ---------------------------------------------------------------------- #
def audit_processes(current_tree: str,
                    services: List[Dict[str, Any]]) -> Dict[str, Any]:
    """按服务清单核对运行进程（-ww 无限宽：pytest 在 C 层注入幽灵
    COLUMNS=80，procps-ng 无 tty 时按其截断命令行——argv 匹配必断；
    BSD/procps 双平台 -ww 语义一致，CI Linux 实证）：argv 必须解析进 current 树且脚本字节可达。

    语义：切换 current 后常驻进程仍持旧 release 树 inode——argv 指向旧树
    的服务（或 must_be_running 服务缺位）→ 项 False；脚本路径在树内且
    可读（字节对账已由 audit_tree 覆盖，这里证明 argv 与树绑定未断）。
    """
    tree_real = os.path.realpath(current_tree)
    result: Dict[str, Any] = {"services": [], "terms": {},
                              "pid_argv_and_script_bytes_match": None}
    try:
        p = subprocess.run(["ps", "-axo", "pid=,command=", "-ww"],
                           capture_output=True, text=True, timeout=15)
        lines = [l.strip() for l in (p.stdout or "").splitlines() if l.strip()]
    except (OSError, subprocess.SubprocessError):
        lines = []
    all_pass: Optional[bool] = True if services else None
    for svc in services:
        label = str(svc.get("label", "?"))
        needle = str(svc.get("argv_contains", ""))
        rel = str(svc.get("script_relpath", ""))
        must = bool(svc.get("must_be_running", True))
        entry: Dict[str, Any] = {"label": label, "running_pid": None,
                                 "pass": False, "reason": ""}
        hits = []
        for line in lines:
            m = re.match(r"^(\d+)\s+(.*)$", line)
            if not m:
                continue
            pid, cmd = int(m.group(1)), m.group(2)
            if needle and needle in cmd and pid != os.getpid():
                hits.append((pid, cmd))
        if not hits:
            entry["reason"] = "not_running"
            if must:
                all_pass = False
                result["services"].append(entry)
                continue
            entry["pass"] = True  # 非必须服务缺位不算红
            result["services"].append(entry)
            continue
        pid, cmd = hits[0]
        entry["running_pid"] = pid
        script_abs = os.path.join(tree_real, rel)
        in_tree = False
        for tok in cmd.split():
            tok_real = os.path.realpath(tok) if os.sep in tok else tok
            if tok_real == script_abs or tok_real == os.path.join(tree_real, rel):
                in_tree = True
                break
        if not in_tree:
            entry["reason"] = "argv_not_in_current_tree"
        elif not os.path.isfile(script_abs):
            entry["reason"] = "script_bytes_unreachable"
        else:
            entry["pass"] = True
        if not entry["pass"]:
            all_pass = False
        result["services"].append(entry)
    result["pid_argv_and_script_bytes_match"] = all_pass
    result["terms"] = {"pid_argv_and_script_bytes_match": all_pass}
    return result


# ---------------------------------------------------------------------- #
# 扫描周期：current+previous 全树对账 + runtime overlay 六项
# ---------------------------------------------------------------------- #
def _read_json_safe(path: str) -> Optional[Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _audit_side(paths: "IntegrityPaths", tree_target: Optional[str]
                ) -> Dict[str, Any]:
    """对账单个激活位（current 或 previous）：结构门 + 全树审计。"""
    side: Dict[str, Any] = {
        "target": tree_target, "ok": False, "structure": None,
        "reason": None,
    }
    if not tree_target:
        side["reason"] = "no_target"
        return side
    structure = resolve_release(tree_target, paths.releases_root)
    side["structure"] = {k: structure[k] for k in
                         ("ok", "commit", "epoch", "structure_errors")}
    if not structure["ok"]:
        side["reason"] = "structure_gate_failed"
        return side
    report = audit_tree(tree_target, structure["manifest_path"])
    side.update({k: report[k] for k in
                 ("ok", "missing", "extra", "drifted", "mode_drifted",
                  "type_mismatch", "special", "broken", "checked",
                  "tree_dir")})
    return side


def scan_cycle(paths: "IntegrityPaths", *, now: Optional[float] = None
               ) -> Dict[str, Any]:
    """一个扫描周期的检测与裁决（纯检测面：不告警/不熔断/不恢复）。

    verdict 优先级：DRIFT（current 树/身份被破坏）> BLOCKED（策略阻断：
    previous 污染致 rollback 不稳、配置内进程 argv 断裂、FUNCTION_DEAD、
    capacity BLOCKED、scheduler 陈旧）> CLEAN。
    """
    now = time.time() if now is None else now
    ttl = float(os.environ.get("WENQU_INTEGRITY_TTL")
                or FRESHNESS_TTL_DEFAULT)

    # -- current 身份钉 --
    identity: Dict[str, Any] = {"ok": False, "errors": [],
                                "target": None}
    try:
        if not os.path.islink(paths.current_link):
            identity["errors"].append("current_not_symlink")
        else:
            raw = os.readlink(paths.current_link)
            identity["target"] = raw
            resolved = (raw if os.path.isabs(raw) else os.path.normpath(
                os.path.join(os.path.dirname(paths.current_link), raw)))
            identity["resolved"] = resolved
            structure = resolve_release(resolved, paths.releases_root)
            identity["structure_ok"] = structure["ok"]
            if not structure["ok"]:
                identity["errors"].append("current_outside_managed_releases")
    except OSError as exc:
        identity["errors"].append(f"current_unreadable:{exc}")
    identity["ok"] = not identity["errors"]

    # -- current / previous 全树对账 --
    cur_target = identity.get("resolved") if identity["ok"] else None
    current = _audit_side(paths, cur_target)
    prev_target = None
    try:
        with open(paths.last_current, encoding="utf-8") as fh:
            prev_raw = fh.read().strip()
        if prev_raw:
            prev_target = (prev_raw if os.path.isabs(prev_raw)
                           else os.path.normpath(os.path.join(
                               paths.releases_root, prev_raw)))
    except OSError:
        prev_target = None
    previous = _audit_side(paths, prev_target)
    previous["recorded"] = os.path.exists(paths.last_current)

    # -- runtime overlay 六项（方案 §6 正式判定） --
    gate = _read_json_safe(paths.gate_aggregate_path)
    if not isinstance(gate, dict):
        gate = None
    static_gate_pass = None
    if gate is not None:
        static_gate_pass = str(gate.get("policy_verdict")
                               or gate.get("overall") or "").upper() == "PASS"

    hb = _read_json_safe(paths.heartbeat_path)
    if not isinstance(hb, dict):
        hb = None
    function_dead = None
    scheduler_fresh = None
    capacity_open = None
    if hb is not None:
        health = hb.get("health")
        if isinstance(health, list):
            states = [str(h.get("state", "")) for h in health
                      if isinstance(h, dict)]
            if states:
                function_dead = any(s == "FUNCTION_DEAD" for s in states)
        cap = hb.get("capacity_gate")
        if isinstance(cap, dict):
            gate_state = str(cap.get("gate", "")).upper()
            if gate_state in ("OPEN", "BLOCKED", "UNKNOWN"):
                capacity_open = gate_state == "OPEN"
        tick_epoch = hb.get("tick_epoch")
        if isinstance(tick_epoch, (int, float)) and not isinstance(
                tick_epoch, bool):
            scheduler_fresh = (hb.get("tick_rc") == 0
                               and (now - float(tick_epoch)) <= ttl)

    services_cfg = _read_json_safe(paths.services_config_path)
    if not isinstance(services_cfg, list):
        services_cfg = None
    services: List[Dict[str, Any]] = []
    if isinstance(services_cfg, list):
        services = [s for s in services_cfg if isinstance(s, dict)]
    proc = audit_processes(cur_target, services) if cur_target else {
        "terms": {"pid_argv_and_script_bytes_match": None}, "services": []}

    # function_dead 诊断项（pass 语义：False=观察到 FUNCTION_DEAD——
    # 不在方案 §6 六项公式内，但计入 false_terms 联动 BLOCKED）
    function_dead_term = None if function_dead is None else (
        not function_dead)
    scheduler_pass = scheduler_fresh
    if scheduler_fresh is True and function_dead is True:
        scheduler_pass = False  # 进程活功能死=调度面不健康（SCH 面）
    terms = {
        "static_gate_pass": static_gate_pass,
        "current_tree_clean": current["ok"] if current.get("ok") is not None
        else False,
        "rollback_ready": (previous["ok"] if previous.get("recorded")
                           else None),
        "pid_argv_and_script_bytes_match":
            proc["terms"]["pid_argv_and_script_bytes_match"],
        "scheduler_pass_and_fresh": scheduler_pass,
        "capacity_open_and_fresh": capacity_open,
        "function_dead": function_dead_term,
    }
    # current 结构门失败 → current_tree_clean=False
    if current.get("reason") == "structure_gate_failed":
        terms["current_tree_clean"] = False

    false_terms = [k for k, v in terms.items() if v is False]
    none_terms = [k for k, v in terms.items() if v is None]
    runtime_verdict = ("BLOCKED" if false_terms
                       else ("NOT_EVALUATED" if none_terms else "PASS"))

    if not identity["ok"] or current.get("ok") is False:
        verdict = "DRIFT"
    elif false_terms:
        verdict = "BLOCKED"
    else:
        verdict = "CLEAN"

    commit = (current.get("structure") or {}).get("commit")
    finding: Dict[str, Any] = {
        "scanned_at": _utc_iso(now), "scanned_at_epoch": now,
        "verdict": verdict, "runtime_verdict": runtime_verdict,
        "identity": identity, "current": current, "previous": previous,
        "terms": terms, "services": proc["services"],
        "incident_id": (f"drift-{commit}-{int(now)}"
                        if verdict == "DRIFT" else None),
        "commit": commit,
    }
    return finding


def scan_exit_code(verdict: str) -> int:
    """扫描器退出码：0 clean / 2 monitor error / 3 drift 或策略阻断。"""
    if verdict == "CLEAN":
        return 0
    if verdict == "MONITOR_ERROR":
        return 2
    return 3


# ---------------------------------------------------------------------- #
# 自动恢复：四前门 + 新目录全新解压 + 现场隔离 + 恢复后重验
# ---------------------------------------------------------------------- #
_PERMIT_MODE_OK = 0o077  # 组/其他任何位即拒（>0600 语义，与 roots 同纪律）


def _verify_four_piece_core(ra: Any, release: Dict[str, Any],
                            roots_path: str) -> Dict[str, Any]:
    """四件套核心对账（离线：tar↔manifest↔外部 roots；无 git/keyring 面）。

    - tar sha256/size vs manifest.artifact（**坏 cache 在此拒**）；
    - tar 逐成员 vs manifest.files（path/type/mode/size/sha256 全对账）；
    - source_commit ∈ roots.allowed_commit + manifest 核心 digest 双对账
      （**exact SHA 已授权**；roots 权限/schema 由 _load_release_roots 拒）。
    返回 {ok, reasons}。
    """
    reasons: List[str] = []
    manifest_path = release["manifest_path"]
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        return {"ok": False, "reasons": [f"manifest_unreadable:{exc}"]}
    tar_path = release["four_piece"].get("tar.gz")
    if not tar_path or not os.path.isfile(tar_path):
        return {"ok": False, "reasons": ["four_piece_missing:tar.gz"]}
    try:
        actual_sha = _sha256_file(tar_path)
        actual_size = os.path.getsize(tar_path)
        art = manifest.get("artifact") or {}
        if (actual_sha != str(art.get("sha256"))
                or actual_size != art.get("size")):
            reasons.append("cache_tar_hash_size_mismatch（坏 cache）")
    except (OSError, EOFError) as exc:
        reasons.append(f"cache_tar_unreadable:{exc}")
    try:
        records, unexpected = ra._iter_tar_records(tar_path)
        if unexpected:
            reasons.append(f"tar_unexpected_members:{unexpected[:3]}")
        by_m = {r["path"]: r for r in manifest.get("files", [])}
        by_a = {r["path"]: r for r in records}
        missing = sorted(set(by_m) - set(by_a))
        extra = sorted(set(by_a) - set(by_m))
        drift = [p for p in sorted(set(by_m) & set(by_a))
                 if by_m[p] != by_a[p]]
        if missing or extra or drift:
            reasons.append(
                f"cache_tar_files_reconcile_failed: missing={missing[:3]} "
                f"extra={extra[:3]} drift={drift[:3]}")
    except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
        reasons.append(f"cache_tar_enumeration_failed:{exc}")
    try:
        roots = ra._load_release_roots(roots_path)
        sc = manifest.get("source_commit")
        if sc not in roots["entries"]:
            reasons.append(
                f"commit_not_in_allowed_commit:{sc}（exact SHA 未授权，"
                f"绝不自动恢复）")
        else:
            pinned = roots["entries"][sc]
            core = ra._manifest_core_digest(manifest)
            if pinned != core:
                reasons.append("roots_manifest_core_digest_mismatch")
    except Exception as exc:  # noqa: BLE001 - VerifyFail 族
        reasons.append(f"roots_gate_failed:{exc}")
    return {"ok": not reasons, "reasons": reasons}


def _check_permit(paths: "IntegrityPaths", commit: str,
                  *, now: float) -> List[str]:
    """recovery permit 前门：存在/0600/schema/精确 commit/未过期。"""
    reasons: List[str] = []
    p = paths.permit_path
    if not os.path.isfile(p):
        return [f"recovery_permit_missing:{p}（无授权绝不自动恢复）"]
    try:
        mode = _stat.S_IMODE(os.stat(p).st_mode)
        if mode & _PERMIT_MODE_OK:
            reasons.append(f"recovery_permit_mode_wide:{oct(mode)}（须 0600）")
        with open(p, encoding="utf-8") as fh:
            permit = json.load(fh)
    except (OSError, ValueError) as exc:
        reasons.append(f"recovery_permit_unreadable:{exc}")
        return reasons
    if not isinstance(permit, dict) \
            or permit.get("schema") != _PERMIT_SCHEMA:
        reasons.append("recovery_permit_schema_mismatch")
        return reasons
    if permit.get("commit") != commit:
        reasons.append(
            f"recovery_permit_commit_mismatch:{permit.get('commit')!r}"
            f"!={commit}（permit 须绑定 exact SHA）")
    exp = permit.get("expires_at")
    try:
        exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if datetime.fromtimestamp(now, tz=timezone.utc) >= exp_dt:
            reasons.append("recovery_permit_expired（过期 permit 不放行）")
    except (TypeError, ValueError):
        reasons.append(f"recovery_permit_expires_at_invalid:{exp!r}")
    return reasons


def _safe_extract(tar_path: str, dst: str) -> None:
    """安全解压：成员路径越根/绝对路径/.. 一律拒（tar 提取契约）。"""
    dst = os.path.realpath(dst)  # 前缀对账基准与成员同形（/var symlink 归一）
    os.makedirs(dst, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as tf:
        for ti in tf:
            name = ti.name
            if name.startswith("/") or ".." in name.split("/"):
                raise RecoveryError(f"unsafe tar member: {name}")
            target = os.path.realpath(os.path.join(dst, name))
            if not (target == dst or target.startswith(dst + os.sep)):
                raise RecoveryError(f"tar member escapes root: {name}")
            try:
                tf.extract(ti, dst, filter="data")
            except TypeError:  # pragma: no cover - py<3.12 无 filter 参数
                tf.extract(ti, dst)


def attempt_auto_recovery(paths: "IntegrityPaths",
                          finding: Dict[str, Any], *,
                          now: Optional[float] = None,
                          python_exe: Optional[str] = None
                          ) -> Dict[str, Any]:
    """按授权自动恢复：新目录、新 epoch、全新解压；原现场更名隔离保留。

    前门（全部通过才开始动现场；任一拒绝 → RecoveryRefused，零触碰）：
      1. exact SHA 已授权（roots allowed_commit + manifest 核心 digest）；
      2. 本地四件套有效（tar↔manifest 对账——坏 cache 拒）；
      3. recovery permit 未过期（0600 + commit 精确匹配）；
      4. 本漂移事件最多自动尝试一次（journal 事实）。
    执行（失败 → RecoveryError，尝试已消耗，熔断等人工 unfuse）：
      新目录 releases/<sha>.r<epoch> 复制四件套 + 全新解压 tree + 逐文件
      对账 + chmod a-w → 原子切换 current → 原漂移目录更名
      <sha>.quarantine-<epoch>（同文件系统 rename，字节零触碰）→ 恢复后
      重验（树审计 + auth 导入冒烟）→ journal/state 落盘。
    """
    now = time.time() if now is None else now
    current = finding.get("current") or {}
    structure = current.get("structure") or {}
    commit = structure.get("commit")
    release_dir = None
    # 从 current 链接实录解析漂移位（finding.structure 之外再核一次现场）
    try:
        raw = os.readlink(paths.current_link)
        resolved = (raw if os.path.isabs(raw) else os.path.normpath(
            os.path.join(os.path.dirname(paths.current_link), raw)))
        rel = resolve_release(resolved, paths.releases_root)
        if rel["ok"]:
            release_dir = rel["release_dir"]
            commit = rel["commit"]
            structure = rel
    except OSError:
        pass
    if not commit or not release_dir:
        raise RecoveryRefused(["current_release_unresolvable（无法定位漂移位）"])

    ra = _load_release_attest(paths.release_attest_path)
    if ra is None:
        raise RecoveryRefused([
            "release_attest_unavailable（roots/tar 对账正源缺失，"
            "绝不盲恢复）"])

    reasons: List[str] = []
    four = _verify_four_piece_core(ra, dict(
        manifest_path=structure.get("manifest_path")
        or next(iter([p for p in _safe_glob(release_dir,
                                            "wenqu-dist-*.manifest.json")]), None),
        four_piece=_four_piece_map(release_dir)), paths.roots_path)
    reasons.extend(four["reasons"])
    reasons.extend(_check_permit(paths, commit, now=now))

    journal = journal_read(paths)
    started = [e for e in journal if e.get("kind") == "recovery_started"]
    if started:
        reasons.append(
            f"auto_recovery_already_attempted:{len(started)}（最多一次，"
            f"失败熔断等人工 unfuse——不无限循环）")
    if reasons:
        raise RecoveryRefused(reasons)

    epoch = next_epoch(paths)
    manifest_path = structure.get("manifest_path") or _safe_glob(
        release_dir, "wenqu-dist-*.manifest.json")[0]
    stem = manifest_path[: -len(".manifest.json")]
    tar_path = stem + ".tar.gz"
    new_dir = os.path.join(paths.releases_root, f"{commit}.r{epoch}")
    if os.path.exists(new_dir):
        raise RecoveryRefused([f"epoch_dir_exists:{new_dir}（换 epoch 重试）"])

    journal_append(paths, {"kind": "recovery_started", "ts": _utc_iso(now),
                           "epoch": epoch, "commit": commit,
                           "detail": f"new dir {new_dir}"})
    try:
        os.makedirs(new_dir)
        for ext in ("manifest.json", "tar.gz", "release.sig",
                    "sbom.spdx.json"):
            src = f"{stem}.{ext}"
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(new_dir, os.path.basename(src)))
        new_tree = os.path.join(new_dir, "tree")
        _safe_extract(tar_path, new_tree)
        # 不可变化先行（与安装链同纪律：chmod -R a-w——激活态树无写位；
        # tar 内 mode 0644/0755 是归档形态，先解压→只读化→再对账，
        # 可写位不变量才成立于激活态语义）
        for dirpath, dirnames, filenames in os.walk(new_dir):
            for name in dirnames + filenames:
                target = os.path.join(dirpath, name)
                os.chmod(target,
                         _stat.S_IMODE(os.lstat(target).st_mode) & ~0o222)
        # 全新解压树逐文件对账（恢复后重验之一：字节）
        fresh_manifest = os.path.join(
            new_dir, os.path.basename(manifest_path))
        tree_audit = audit_tree(new_tree, fresh_manifest)
        if not tree_audit["ok"]:
            raise RecoveryError(
                f"fresh tree audit failed: {tree_audit}")

        # auth 冒烟：恢复树内 approval_keys 可导入（恢复后重验之二：auth）
        py = python_exe or sys.executable
        auth_ok = True
        auth_err = None
        try:
            pr = subprocess.run(
                [py, "-c",
                 "import sys; sys.path.insert(0, sys.argv[1]); "
                 "import approval_keys",
                 os.path.join(new_tree, "system", "wenqu_core")],
                timeout=60, capture_output=True)
            auth_ok = pr.returncode == 0
            if not auth_ok:
                auth_err = (pr.stderr or b"").decode("utf-8", "replace")[:200]
        except (OSError, subprocess.SubprocessError) as exc:
            auth_ok = False
            auth_err = repr(exc)
        if not auth_ok:
            raise RecoveryError(f"auth import smoke failed: {auth_err}")

        # 原子切换 current → 新树（临时 symlink + rename）
        link_dir = os.path.dirname(paths.current_link) or "."
        if os.path.exists(paths.current_link) and not os.path.islink(
                paths.current_link):
            raise RecoveryError(
                f"current 不是 symlink，拒绝覆盖: {paths.current_link}")
        tmp_link = os.path.join(link_dir, f".current.recovery-{os.getpid()}")
        if os.path.lexists(tmp_link):
            os.remove(tmp_link)
        os.symlink(new_tree, tmp_link)
        os.replace(tmp_link, paths.current_link)

        # 漂移现场隔离：同文件系统更名（字节零触碰、绝不删除）
        quarantine = os.path.join(
            paths.releases_root,
            f"{commit}.quarantine-{epoch}-"
            f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))}")
        quarantine_note = None
        try:
            os.rename(release_dir, quarantine)
        except OSError as exc:
            quarantine_note = f"quarantine_rename_failed:{exc}（现场原位保留）"
            quarantine = release_dir

        post_verify = {
            "tree_audit": {"ok": tree_audit["ok"],
                           "checked": tree_audit["checked"]},
            "auth_import_ok": auth_ok,
            "pid_argv_and_script_bytes_match": None,  # 常驻服务由 launchd 重载后核
            "noted_at": _utc_iso(now),
        }
        journal_append(paths, {
            "kind": "recovery_succeeded", "ts": _utc_iso(now),
            "epoch": epoch, "commit": commit,
            "detail": {"new_dir": new_dir, "quarantine": quarantine,
                       "quarantine_note": quarantine_note,
                       "post_verify": post_verify}})
        # 恢复是 epoch 变更的正源：成功即发布恢复后状态（direct-call 可观测；
        # monitor_tick 随后的整量写与本字段集一致，不产生分叉）
        recovered_state = read_state(paths)
        recovered_state.update({
            "verdict": "CLEAN", "runtime_verdict": "NOT_EVALUATED",
            "generated_at": _utc_iso(now), "generated_at_epoch": now,
            "deployment_epoch": epoch, "fuse": "CLOSED", "fuse_reason": None,
            "active_incident": None,
            "auto_recovery": {"status": "recovered", "epoch": epoch,
                              "at": _utc_iso(now), "commit": commit,
                              "quarantine": quarantine,
                              "post_verify": post_verify},
        })
        write_state(paths, recovered_state)
        return {"status": "recovered", "epoch": epoch, "commit": commit,
                "new_dir": new_dir, "quarantine": quarantine,
                "post_verify": post_verify,
                "quarantine_note": quarantine_note}
    except RecoveryError:
        journal_append(paths, {"kind": "recovery_failed", "ts": _utc_iso(now),
                               "epoch": epoch, "commit": commit,
                               "detail": "execution failed; fuse stays OPEN; "
                                         "manual unfuse required"})
        raise
    except Exception as exc:  # noqa: BLE001 - 任何意外失败按恢复失败熔断
        journal_append(paths, {"kind": "recovery_failed", "ts": _utc_iso(now),
                               "epoch": epoch, "commit": commit,
                               "detail": f"unexpected: {exc!r}"})
        raise RecoveryError(f"auto-recovery execution failed: {exc!r}"
                            ) from exc


def _four_piece_map(release_dir: str) -> Dict[str, str]:
    manifests = _safe_glob(release_dir, "wenqu-dist-*.manifest.json")
    if not manifests:
        return {}
    stem = manifests[0][: -len(".manifest.json")]
    return {"manifest.json": manifests[0],
            "tar.gz": stem + ".tar.gz",
            "release.sig": stem + ".release.sig",
            "sbom.spdx.json": stem + ".sbom.spdx.json"}


def unfuse(paths: "IntegrityPaths", *, operator: str, note: str,
           now: Optional[float] = None) -> Dict[str, Any]:
    """人工解除熔断（唯一通道；操作者留痕落 journal 与 state）。"""
    now = time.time() if now is None else now
    state = read_state(paths)
    if state.get("fuse") != "OPEN":
        raise DriftError(
            f"no OPEN fuse to clear (current fuse: "
            f"{state.get('fuse', 'N/A')!r})")
    state["fuse"] = "CLOSED"
    state["fuse_cleared_by"] = operator
    state["fuse_cleared_note"] = note
    state["fuse_cleared_at"] = _utc_iso(now)
    write_state(paths, state)
    journal_append(paths, {"kind": "unfused", "ts": _utc_iso(now),
                           "epoch": state.get("deployment_epoch", 0),
                           "commit": state.get("current", {}).get(
                               "structure", {}).get("commit")
                           if isinstance(state.get("current"), dict) else None,
                           "detail": {"operator": operator, "note": note}})
    return state


# ---------------------------------------------------------------------- #
# monitor tick：检测 → 裁决 → 告警/封存/作废/熔断 → （授权时）自动恢复
# ---------------------------------------------------------------------- #
def monitor_tick(paths: "IntegrityPaths", *, now: Optional[float] = None,
                 allow_recovery: bool = True
                 ) -> Dict[str, Any]:
    """一个 daemon tick。rc 语义：0=检测与裁决完成（含 BLOCKED/DRIFT）；
    2=监控自身失败（此时尽力发布 MONITOR_ERROR 状态与告警）。"""
    now = time.time() if now is None else now
    try:
        paths.ensure_dirs()
        prev_epoch_raw = read_state(paths).get("deployment_epoch")
        prev_epoch = prev_epoch_raw if isinstance(prev_epoch_raw, int) \
            and not isinstance(prev_epoch_raw, bool) else 0
        finding = scan_cycle(paths, now=now)
        journal_append(paths, {
            "kind": "scan_clean"
            if finding["verdict"] == "CLEAN"
            else f"scan_{finding['verdict'].lower()}",
            "ts": _utc_iso(now), "epoch": prev_epoch, "commit": finding.get("commit"),
            "detail": {"verdict": finding["verdict"],
                       "runtime_verdict": finding["runtime_verdict"]}})
    except Exception as exc:  # noqa: BLE001 - 监控自身失败面
        state = read_state(paths)
        state.update({
            "verdict": "MONITOR_ERROR",
            "fuse": state.get("fuse", "CLOSED"),
            "error": f"{type(exc).__name__}: {exc}",
            "generated_at": _utc_iso(now),
        })
        try:
            write_state(paths, state)
        except OSError:
            pass
        raise_critical_alarm(
            paths, "[wenqu] release-integrity 监控自身失败",
            f"扫描链异常：{type(exc).__name__}: {exc}\n"
            f"状态已按 MONITOR_ERROR 发布（fail-visible）；人工排查。", now=now)
        return {"rc": 2, "state": state, "finding": None,
                "error": f"{type(exc).__name__}: {exc}"}

    prev_state = read_state(paths)
    verdict = finding["verdict"]
    state: Dict[str, Any] = {
        "verdict": verdict,
        "runtime_verdict": finding["runtime_verdict"],
        "generated_at": finding["scanned_at"],
        "generated_at_epoch": finding["scanned_at_epoch"],
        "deployment_epoch": prev_state.get("deployment_epoch", 0)
        if isinstance(prev_state.get("deployment_epoch"), int) else 0,
        "current": _public_side(finding["current"]),
        "previous": _public_side(finding["previous"]),
        "identity": finding["identity"],
        "runtime_overlay": {
            "terms": finding["terms"],
            "verdict": finding["runtime_verdict"],
            "formula": "static_gate_pass AND current_tree_clean AND "
                       "rollback_ready AND pid_argv_and_script_bytes_match "
                       "AND scheduler_pass_and_fresh AND "
                       "capacity_open_and_fresh",
        },
        "services": finding["services"],
        "alarms": prev_state.get("alarms", []),
        "active_incident": prev_state.get("active_incident"),
    }
    if verdict in ("DRIFT", "BLOCKED"):
        first = prev_state.get("active_incident") != finding.get("incident_id") \
            or prev_state.get("verdict") == "CLEAN" \
            or not prev_state
        state["active_incident"] = finding.get("incident_id") \
            or prev_state.get("active_incident")
        # 熔断对象=发布完整性域（树漂移/身份断裂/回滚场景污染）；
        # FUNCTION_DEAD/capacity 只红 overlay 不冻结激活（各有处置通道）。
        fuse_reasons = []
        if verdict == "DRIFT":
            fuse_reasons.append("current_tree_drift")
        if not finding["identity"]["ok"]:
            fuse_reasons.append("current_identity_broken")
        if finding["terms"].get("rollback_ready") is False:
            fuse_reasons.append("rollback_scene_compromised")
        if fuse_reasons:
            state["fuse"] = "OPEN"
            state["fuse_reason"] = ",".join(fuse_reasons)
        else:
            state["fuse"] = prev_state.get("fuse", "CLOSED")
        if first:
            drift_paths = (finding["current"].get("drifted") or [])
            mode_paths = (finding["current"].get("mode_drifted") or [])
            body = (f"verdict={verdict} runtime={finding['runtime_verdict']}\n"
                    f"commit={finding.get('commit')}\n"
                    f"identity_errors={finding['identity']['errors']}\n"
                    f"drifted={drift_paths[:5]} mode_drifted={mode_paths[:5]}\n"
                    f"missing={(finding['current'].get('missing') or [])[:5]} "
                    f"extra={(finding['current'].get('extra') or [])[:5]}\n"
                    f"fuse={state.get('fuse')}（激活/回滚入口冻结，"
                    f"人工处置后 release-integrity-watch unfuse）")
            alert = raise_critical_alarm(
                paths,
                f"[wenqu] CRITICAL：现役 release 树漂移 verdict={verdict}",
                body, now=now,
                dedup_key=f"drift:{finding.get('commit')}:{int(now // 3600)}")
            if alert:
                state["alarms"] = (state["alarms"] + [alert])[-20:]
            bundle = archive_incident(paths, finding, now=now)
            if bundle:
                state["incident_bundle"] = bundle
            wid = invalidate_active_windows(
                paths, f"release tree drift: {finding.get('incident_id')}",
                now=now)
            if wid:
                state["invalidated_windows"] = wid
            journal_append(paths, {
                "kind": "fuse_opened" if state.get("fuse") == "OPEN"
                else "policy_blocked", "ts": _utc_iso(now),
                "epoch": state["deployment_epoch"],
                "commit": finding.get("commit"),
                "detail": {"reasons": fuse_reasons, "alert": alert,
                           "bundle": bundle, "invalidated_windows": wid}})
        # 自动恢复（仅发布完整性域红且被授权时）
        if allow_recovery and verdict == "DRIFT":
            try:
                result = attempt_auto_recovery(paths, finding, now=now)
                state.update({
                    "verdict": "CLEAN",
                    "runtime_verdict": "NOT_EVALUATED",
                    "fuse": "CLOSED",
                    "fuse_reason": None,
                    "deployment_epoch": result["epoch"],
                    "active_incident": None,
                    "auto_recovery": {
                        "status": "recovered", "epoch": result["epoch"],
                        "at": _utc_iso(now),
                        "quarantine": result["quarantine"],
                        "post_verify": result["post_verify"]},
                })
            except RecoveryRefused as exc:
                state["auto_recovery"] = {
                    "status": "refused", "at": _utc_iso(now),
                    "reasons": exc.reasons}
            except RecoveryError as exc:
                state["auto_recovery"] = {
                    "status": "failed", "at": _utc_iso(now),
                    "error": str(exc)}
                state["fuse"] = "OPEN"
                state["fuse_reason"] = "auto_recovery_failed"
    else:
        state["fuse"] = prev_state.get("fuse", "CLOSED")
        if state["fuse"] == "OPEN":
            state["fuse_reason"] = prev_state.get("fuse_reason")

    write_state(paths, state)
    return {"rc": 0, "state": state, "finding": finding}


def _public_side(side: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("target", "ok", "reason", "recorded", "tree_dir")
    out = {k: side.get(k) for k in keys if k in side}
    if isinstance(side.get("structure"), dict):
        out["structure"] = side["structure"]
    for k in ("missing", "extra", "drifted", "mode_drifted",
              "type_mismatch", "special", "broken", "checked"):
        if k in side:
            out[k] = side[k]
    return out


# ---------------------------------------------------------------------- #
# 只读消费面（scheduler 定时监控 / dashboard / install 链共用语义）
# ---------------------------------------------------------------------- #
def check_integrity_freshness(paths: "IntegrityPaths", *,
                              now: Optional[float] = None,
                              ttl: Optional[float] = None
                              ) -> Dict[str, Any]:
    """完整性快照消费侧检查（只读，绝不写状态）。

    返回 status：``clean`` / ``drift`` / ``blocked`` / ``monitor_error`` /
    ``fuse_open`` / ``stale`` / ``missing`` / ``malformed``。
    scheduler tick 对非 clean/stale/missing 发 CRITICAL（missing 只记录
    ——哨兵未部署的主机不制造噪音）。
    """
    now = time.time() if now is None else now
    ttl = ttl if ttl is not None else float(
        os.environ.get("WENQU_INTEGRITY_TTL") or FRESHNESS_TTL_DEFAULT)
    if not os.path.isfile(paths.state_path):
        return {"status": "missing",
                "detail": f"哨兵状态未发布: {paths.state_path}"}
    data = _read_json_safe(paths.state_path)
    if not isinstance(data, dict) or data.get("schema") != INTEGRITY_SCHEMA:
        return {"status": "malformed",
                "detail": f"状态不可解析/schema 不符: {paths.state_path}"}
    gen = data.get("generated_at_epoch")
    if not isinstance(gen, (int, float)) or isinstance(gen, bool):
        gen_iso = data.get("generated_at")
        try:
            gen = datetime.fromisoformat(
                str(gen_iso).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError):
            return {"status": "malformed",
                    "detail": "generated_at 不可解析"}
    if now - float(gen) > ttl:
        return {"status": "stale", "verdict": data.get("verdict"),
                "detail": f"快照龄 {int(now - gen)}s 超 TTL {int(ttl)}s"
                          f"（哨兵停摆?）", "data": data}
    verdict = str(data.get("verdict", "")).upper()
    if data.get("fuse") == "OPEN":
        return {"status": "fuse_open", "verdict": verdict,
                "fuse_reason": data.get("fuse_reason"), "data": data}
    if verdict == "DRIFT":
        return {"status": "drift", "verdict": verdict, "data": data}
    if verdict == "BLOCKED":
        return {"status": "blocked", "verdict": verdict, "data": data}
    if verdict == "MONITOR_ERROR":
        return {"status": "monitor_error", "verdict": verdict, "data": data}
    return {"status": "clean", "verdict": verdict, "data": data}

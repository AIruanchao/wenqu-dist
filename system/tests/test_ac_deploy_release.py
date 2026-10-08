#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——DEP-01~09 / RB-01 / REL-01~03（部署、回滚、发布）。

正源（逐字对齐）：
    evidence/00-baseline/codex-external/方案.md §20.4（REL-01~03）与
    §20.5（DEP-01~09、RB-01）表格的「注入/期望」列。

被测体：
    system/wenqu_core/deploy_framework.py
        DeployManager：build（不可变 release + manifest D1/D4）/ verify
        （缺件/多件/哈希漂移/mode 漂移对账）/ switch（D3 原子 symlink）/
        rollback（先验旧版完好再切回）/ deploy（D2 自检失败=部署失败并
        自动回滚+回滚后复验）——覆盖 REL-01/02/03、DEP-03、RB-01 的
        「错误旧版本」腿。
        wave6/p1f-gate 扩展（本文件对应产品语义全部落地，无 NOT_IMPLEMENTABLE）：
        - DEP-01：DeployLease（flock 部署租约，deploy 全程持有，非阻塞仲裁）
        - DEP-02：run_isolated_self_check（沙箱副本 + audit-hook 生产路径守卫）
        - DEP-04：manifest key_id/signature + release_keyring 验签
        - DEP-05：manifest schema_version + rollback schema_range 拒绝
        - DEP-06：迁移门（MigrationLock + BackupProof + expand ddl 授权）
        - DEP-07：fenced 状态机 ACTIVATING→FAILED_BLOCKED（无预授权不回滚）
        - DEP-08：ROLLBACK_FAILED→FUSE_OPEN 熔断停等 resume_releases
        - DEP-09：observation_seconds 观察窗拒绝 contract/down migration
    system/wenqu_core/wenqu_pipeline.py + approval_keys.py
        RunManager.reserve_action（F4-AUTH-001）——RB-01 的「无预授权
        自动回滚」腿；approval_keys 的 HMAC keyring 机制被 DEP-04/06/07/09
        只读复用（release 签名与授权 envelope 验签）。
    system/wenqu_core/store.py
        EventStore（pipeline_events append-only 哈希链）——DEP-03 正源。

覆盖边界（显式登记，不冒充完整验收面）：
    REL-03 的「doctor」= DeployManager 的 install_self_check 安装自检钩子
    （D2 契约面）；install.sh/hardening-doctor.sh 的安装期 doctor 面由
    test_infra_hardening.py F 节覆盖，本文件不重复。
    RB-01 完整语义 = 预授权腿（wenqu_pipeline F4-AUTH-001）+ 错误旧版本腿
    （deploy_framework rollback 完好性对账）双腿拼合；DEP-07 的 fenced
    「无预授权不得回滚」与 D2 legacy「自检失败自动回滚」由 DeployManager
    的 fenced 开关分轨共存（legacy 行为由 REL-03 持续复验）。

独立运行：python3 system/tests/test_ac_deploy_release.py [--json OUT.json]
exit 0 = 全部已实现用例绿；默认把逐 ID 结果写入
evidence/04-unit-property-mutation/ac-deploy-release.json。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
SYSTEM_DIR = HERE.parent          # system/
REPO_ROOT = SYSTEM_DIR.parent     # 仓根
if str(SYSTEM_DIR) not in sys.path:
    sys.path.insert(0, str(SYSTEM_DIR))

from wenqu_core.approval_keys import (  # noqa: E402
    ApprovalKeyring,
    generate_secret,
    sign_envelope,
)
from wenqu_core.deploy_framework import (  # noqa: E402
    DEPLOY_STATE_FILENAME,
    ActivationBlocked,
    BackupProof,
    BuildError,
    DeployError,
    DeployLease,
    DeployManager,
    FailedBlockedError,
    FuseOpenError,
    LeaseError,
    MigrationLock,
    ObservationWindowError,
    SchemaRangeError,
    SelfCheckError,
    SwitchError,
    VerifyError,
)
from wenqu_core.deploy_framework import SmokeIsolationError  # noqa: E402
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ActionError,
    ApprovalRejected,
    RunManager,
)

ARTIFACT_PATH = REPO_ROOT / "evidence" / "04-unit-property-mutation" / "ac-deploy-release.json"

# ---------------------------------------------------------------------- #
# 不可实现登记表（wave6/p1f-gate：DEP 族 8 项产品语义已全部落地为真实
# 用例，登记清零；保留空表结构以维持运行器契约——登记条目必须为 0 才算
# DEP 族全覆盖，不为「跳过」留缝）
# ---------------------------------------------------------------------- #
NOT_IMPLEMENTABLE: Dict[str, str] = {}

_SHA1 = "1f" + "0" * 38           # 40-hex git sha 形态（watermark 用）
_BIGFILE_BYTES = 16 * 1024 * 1024  # 拓宽 kill 窗口的大文件


# ---------------------------------------------------------------------- #
# 通用小工具
# ---------------------------------------------------------------------- #
def _ok(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)


def _expect_raise(exc_type: type, fn: Callable[..., Any],
                  *args: Any, **kwargs: Any) -> Exception:
    """调用 fn 期望抛出 exc_type；返回异常对象供断言细节。"""
    try:
        fn(*args, **kwargs)
    except exc_type as exc:  # type: ignore[misc]
        return exc
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(f"expected {exc_type.__name__} to be raised, but call returned")


def _mk_app_source(base: Path, name: str, *, healthy: bool = True,
                   flag: str = "", bigfile: bool = False) -> Path:
    """构建一个真实部署源目录（doctor.json 模拟安装自检健康位）。"""
    src = base / name
    (src / "bin").mkdir(parents=True, exist_ok=True)
    (src / "app.py").write_text("print('app')\n", encoding="utf-8")
    (src / "doctor.json").write_text(
        json.dumps({"ok": healthy, "flag": flag}), encoding="utf-8")
    if flag:
        (src / f"flag-{flag}.txt").write_text(flag + "\n", encoding="utf-8")
    if bigfile:
        (src / "bin" / "payload.bin").write_bytes(b"\xab\xcd" * (_BIGFILE_BYTES // 2))
    return src


def _real(path: Path | str) -> str:
    """macOS /var→/private/var 等符号链接归一后的可比路径。"""
    return os.path.realpath(str(path))


def _read_events_raw(db_path: Path) -> List[Tuple[int, str]]:
    conn_rows: List[Tuple[int, str]] = []
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    try:
        conn_rows = conn.execute(
            "SELECT seq, payload FROM pipeline_events ORDER BY seq").fetchall()
    finally:
        conn.close()
    return [(int(s), p) for s, p in conn_rows]


def _file_fingerprint(path: Path) -> Tuple[int, int]:
    st = path.stat()
    return (st.st_size, st.st_mtime_ns)


# ---------------------------------------------------------------------- #
# REL-01｜manifest 缺件/多件/错 hash → 部署失败
# ---------------------------------------------------------------------- #
def test_REL_01_manifest_missing_extra_hash_drift_deploy_fails(td: Path) -> None:
    """注入：release 缺件/多件/错 hash。期望：对账失败且部署失败、current 不变。

    三形态逐一注入真实 release 副本（shutil.copytree 保权限位），断言
    verify() 严格模式抛 VerifyError 且 report 指明具体形态；
    部署失败腿走真实 deploy() 调用链：向既有 release 注入多件后同秒重建
    同源 → build() 幂等复用对账失败 → BuildError（部署失败）且 current
    仍指向原 release（未切换）。
    """
    src = _mk_app_source(td, "src-v1", flag="rel1")
    releases = td / "rel1-root" / "releases"
    current = td / "rel1-root" / "current"
    mgr = DeployManager(str(releases), str(current))
    first = mgr.deploy(src)
    v1_dir = Path(first["release_dir"])
    _ok(_real(current) == _real(v1_dir), "前置：v1 部署成功且 current 指向 v1")

    # ---- 形态1：缺件（删除清单内文件）----
    t_missing = td / "tamper-missing"
    shutil.copytree(v1_dir, t_missing)
    (t_missing / "app.py").unlink()
    exc = _expect_raise(VerifyError, mgr.verify, str(t_missing))
    rep = exc.report
    _ok(rep["missing"] == ["app.py"], f"缺件必须精确指认 app.py: {rep}")
    _ok(rep["extra"] == [] and rep["drifted"] == [], f"仅缺件形态: {rep}")

    # ---- 形态2：多件（清单外私带文件）----
    t_extra = td / "tamper-extra"
    shutil.copytree(v1_dir, t_extra)
    (t_extra / "rogue-injected.txt").write_text("injected", encoding="utf-8")
    exc = _expect_raise(VerifyError, mgr.verify, str(t_extra))
    rep = exc.report
    _ok(rep["extra"] == ["rogue-injected.txt"], f"多件必须精确指认私带文件: {rep}")
    _ok(rep["missing"] == [] and rep["drifted"] == [], f"仅多件形态: {rep}")

    # ---- 形态3：错 hash（内容漂移、mode 复原以隔离哈希漂移形态）----
    t_drift = td / "tamper-drift"
    shutil.copytree(v1_dir, t_drift)
    victim = t_drift / "app.py"
    os.chmod(victim, 0o644)
    victim.write_text("print('tampered-payload')\n", encoding="utf-8")
    os.chmod(victim, 0o444)
    exc = _expect_raise(VerifyError, mgr.verify, str(t_drift))
    rep = exc.report
    _ok(rep["drifted"] == ["app.py"], f"错 hash 必须精确指认漂移文件: {rep}")
    _ok(rep["mode_drifted"] == [], f"mode 已复原，仅哈希漂移形态: {rep}")

    # ---- 形态4：manifest 本身缺失 ----
    t_nomanifest = td / "tamper-nomanifest"
    shutil.copytree(v1_dir, t_nomanifest)
    (t_nomanifest / "manifest.json").unlink()
    exc = _expect_raise(VerifyError, mgr.verify, str(t_nomanifest))
    _ok(exc.report["missing"] == ["manifest.json"],
        f"manifest 缺失必须指认 manifest.json: {exc.report}")

    # ---- 部署失败腿（真实 deploy 调用链）----
    # release_id = UTC 秒时间戳 + 内容摘要；同秒同源重建命中幂等复用分支，
    # 复用前对既有 release 做完好性对账——注入多件后对账失败 → BuildError
    # → deploy 失败。跨秒边界会生成新 release_id（碰撞不触发），换新根重试。
    observed_collision = False
    for attempt in range(6):
        root = td / f"rel1-deployfail-{attempt}"
        rel_a, cur_a = root / "releases", root / "current"
        m = DeployManager(str(rel_a), str(cur_a))
        good = m.deploy(src)
        live = Path(good["release_dir"])
        (live / "rogue-extra.txt").write_text("injected", encoding="utf-8")  # 多件注入
        try:
            m.deploy(src)
        except BuildError as bexc:
            _ok("collision" in str(bexc) and "divergent" in str(bexc),
                f"必须以 release_id 碰撞+内容分歧拒绝: {bexc}")
            _ok(_real(cur_a) == _real(live),
                "部署失败后 current 必须保持原 release（未切换）")
            observed_collision = True
            break
        # 跨秒：同内容新 release_id，碰撞未触发——换新根重试
    _ok(observed_collision,
        "6 次尝试内未观测到同秒碰撞拒绝——『注入坏包→部署失败』未实证")


# ---------------------------------------------------------------------- #
# REL-02｜部署中 kill -9 → 保持旧 current 或完整新 current
# ---------------------------------------------------------------------- #
_CHILD_DEPLOY = """\
import sys
sys.path.insert(0, {system_dir!r})
from wenqu_core.deploy_framework import DeployManager
mgr = DeployManager({releases!r}, {current!r})
result = mgr.deploy({source!r})
sys.stdout.write(result["release_id"] + "\\n")
"""


def test_REL_02_sigkill_mid_deploy_keeps_old_or_complete_new_current(td: Path) -> None:
    """注入：部署进程在大文件构建窗口内被 SIGKILL。期望：current 要么仍是
    旧 release，要么指向完整（对账通过）的新 release——绝无半写/悬空态。

    真实子进程跑 deploy()（16MiB 大文件拓宽构建窗口）；父进程在 staging
    目录出现后按不同延迟 kill -9，另设不杀的对照组。每次 kill 后断言：
    (1) current 为有效 symlink 且不指向 staging 残留；
    (2) current 目标 release 完整（verify 通过=旧版或完整新版二择）；
    (3) releases/ 下所有已命名（非点前缀）release 目录全部对账通过
        （命名 release 只经 os.rename 原子落位，绝不半写）。
    """
    src_v1 = _mk_app_source(td, "src-rel2-v1", flag="v1")
    src_v2 = _mk_app_source(td, "src-rel2-v2", flag="v2", bigfile=True)
    trials: List[Tuple[str, Optional[float]]] = [
        ("kill-at-staging", 0.0),
        ("kill-5ms", 0.005),
        ("kill-40ms", 0.04),
        ("kill-250ms", 0.25),
        ("control-no-kill", None),
    ]
    for name, delay in trials:
        root = td / f"rel2-{name}"
        releases, current = root / "releases", root / "current"
        mgr = DeployManager(str(releases), str(current))
        mgr.deploy(src_v1)  # 旧 current 先就位
        v1_real = _real(current)
        child_src = root / "child_deploy.py"
        child_src.write_text(
            _CHILD_DEPLOY.format(
                system_dir=str(SYSTEM_DIR), releases=str(releases),
                current=str(current), source=str(src_v2)),
            encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, str(child_src)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if delay is None:
            out, err = proc.communicate(timeout=180)
            _ok(proc.returncode == 0,
                f"{name}: 对照组 deploy 必须成功: rc={proc.returncode} {err[-300:]}")
            new_real = _real(current)
            _ok(new_real != v1_real, f"{name}: 对照组应切到新 release")
            _ok(mgr.verify(new_real)["ok"] is True,
                f"{name}: 对照组新 release 必须完整")
            continue
        # 等 staging 目录出现（构建已开始），再按延迟 kill -9
        deadline = time.time() + 60
        staging_seen = False
        while time.time() < deadline:
            if releases.is_dir() and any(
                    d.name.startswith(".staging-") for d in releases.iterdir()):
                staging_seen = True
                break
            time.sleep(0.002)
        _ok(staging_seen, f"{name}: 60s 内未见 staging 目录（子进程未进入构建）")
        if delay > 0:
            time.sleep(delay)
        proc.send_signal(signal.SIGKILL)
        proc.communicate(timeout=30)

        # 不变量 (1)：current 是有效 symlink，绝不指向 staging 残留
        _ok(os.path.islink(current), f"{name}: kill 后 current 仍是 symlink")
        target = _real(current)
        _ok(os.path.isdir(target), f"{name}: kill 后 current 目标存在")
        _ok(not Path(target).name.startswith(".staging-"),
            f"{name}: current 绝不指向 staging 半成品: {target}")
        # 不变量 (2)：current 目标完整（=旧 current 或完整新 current）
        rep = mgr.verify(target, strict=False)
        _ok(rep["ok"] is True,
            f"{name}: current 目标 release 必须对账通过: {rep}")
        # 不变量 (3)：所有已命名 release 无一半写
        for d in sorted(releases.iterdir()):
            if d.name.startswith("."):
                continue  # staging 残留允许存在（进程已被 kill），但绝不命名
            _ok(mgr.verify(str(d), strict=False)["ok"] is True,
                f"{name}: 已命名 release {d.name} 不得半写")


# ---------------------------------------------------------------------- #
# REL-03｜doctor 红 → 部署失败并回退
# ---------------------------------------------------------------------- #
def test_REL_03_doctor_red_deploy_fails_and_rolls_back(td: Path) -> None:
    """注入：安装自检（doctor 钩子）报红——健康位假值形态与探针崩溃形态。
    期望：部署失败（DeployError）并回退到上一版，且回退后复验旧版健康。

    doctor 为多组件探针（manifest 在位 + 健康位），断言：两种红形态都
    DeployError；异常链保留原始病因（__cause__）；current 回退到 v1；
    v1 完好；doctor 检查序列为新包→（回滚后复验）旧包。
    """
    root = td / "rel3-root"
    releases, current = root / "releases", root / "current"
    inspected: List[str] = []

    def doctor(release_dir: str) -> bool:
        inspected.append(os.path.basename(release_dir))
        with open(os.path.join(release_dir, "doctor.json"), encoding="utf-8") as fh:
            health = json.load(fh)
        components = {
            "manifest_present": os.path.isfile(
                os.path.join(release_dir, "manifest.json")),
            "health_flag": health.get("ok") is True,
        }
        if health.get("crash_probe"):
            raise RuntimeError("doctor probe crashed mid-check")
        return all(components.values())

    mgr = DeployManager(str(releases), str(current), install_self_check=doctor)
    src_v1 = _mk_app_source(td, "src-rel3-v1", healthy=True, flag="v1")
    r1 = mgr.deploy(src_v1)
    v1_real = _real(r1["release_dir"])
    _ok(_real(current) == v1_real, "前置：v1 部署成功")

    # ---- 红形态1：doctor 返回假值（健康位 ok=false）----
    src_v2 = _mk_app_source(td, "src-rel3-v2", healthy=False, flag="v2")
    exc = _expect_raise(DeployError, mgr.deploy, str(src_v2))
    msg = str(exc)
    _ok("rolled back" in msg and "re-verified" in msg,
        f"DeployError 必须携带回退+复验记录: {msg}")
    _ok(isinstance(exc.__cause__, SelfCheckError),
        f"异常链必须保留自检失败病因: {type(exc.__cause__)!r}")
    _ok(_real(current) == v1_real, "红形态1：current 必须回退到 v1")
    _ok(mgr.verify(v1_real)["ok"] is True, "回退目标 v1 完好")

    # ---- 红形态2：doctor 探针自身崩溃（红=异常同样成立）----
    src_v3 = _mk_app_source(td, "src-rel3-v3", healthy=False, flag="v3")
    (src_v3 / "doctor.json").write_text(
        json.dumps({"ok": False, "crash_probe": True, "flag": "v3"}),
        encoding="utf-8")
    exc = _expect_raise(DeployError, mgr.deploy, str(src_v3))
    _ok(isinstance(exc.__cause__, RuntimeError),
        f"崩溃形态必须以原始探针异常为因: {type(exc.__cause__)!r}")
    _ok(_real(current) == v1_real, "红形态2：current 仍回退到 v1")
    _ok(mgr.verify(v1_real)["ok"] is True, "回退目标 v1 仍完好")

    # doctor 检查序列：首绿 v1 → 新包红 → 回滚复验旧包绿，两种红形态各一轮
    _ok(len(inspected) == 5, f"doctor 必须恰好检查 5 次（首绿+两红各一+复验两绿）: {inspected}")
    _ok(inspected[0] == inspected[2] == inspected[4] == Path(v1_real).name,
        f"回滚后必须对旧包复验 doctor 两次: {inspected}")
    _ok(inspected[1] != inspected[3] and inspected[1] != Path(v1_real).name,
        f"两种红形态必须来自不同新包: {inspected}")


# ---------------------------------------------------------------------- #
# DEP-03｜新事件后回滚兼容二进制 → 事件零丢失
# ---------------------------------------------------------------------- #
_READER_SRC = """\
#!/usr/bin/env python3
# 冻结在 release 内的兼容读取器：只依赖 pipeline_events 稳定 schema
import json, sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
rows = conn.execute(
    "SELECT seq, payload FROM pipeline_events ORDER BY seq").fetchall()
conn.close()
print(json.dumps({"count": len(rows), "events": [json.loads(p) for _, p in rows]}))
"""

_WRITER_SRC = """\
#!/usr/bin/env python3
import sys
sys.path.insert(0, {system_dir!r})
from wenqu_core.store import EventStore
store = EventStore(sys.argv[1])
event_hash, inserted = store.append({{
    "kind": "business-event", "era": sys.argv[2], "n": int(sys.argv[3])}})
store.close()
sys.stdout.write(event_hash)
"""


def test_DEP_03_rollback_compatible_binary_zero_event_loss(td: Path) -> None:
    """注入：新版本运行期间写入新事件，随后回滚到兼容旧二进制。
    期望：事件零丢失——旧二进制（冻结读取器，经 current 链接执行）能读出
    全量事件（含新版本期间写入的），哈希链完好，head 不变，账本文件
    在回滚前后逐字节时间戳级未动（回滚只切 symlink，绝不碰事件账本）。
    """
    root = td / "dep3-root"
    releases, current = root / "releases", root / "current"
    db = root / "events.db"
    writer_src = _WRITER_SRC.format(system_dir=str(SYSTEM_DIR))

    src_v1 = td / "dep3-src-v1"
    (src_v1 / "bin").mkdir(parents=True)
    (src_v1 / "bin" / "reader.py").write_text(_READER_SRC, encoding="utf-8")
    (src_v1 / "bin" / "writer.py").write_text(writer_src, encoding="utf-8")
    (src_v1 / "version.txt").write_text("1\n", encoding="utf-8")
    src_v2 = td / "dep3-src-v2"
    shutil.copytree(src_v1, src_v2)
    (src_v2 / "version.txt").write_text("2\n", encoding="utf-8")  # 内容差异→新 release

    mgr = DeployManager(str(releases), str(current))
    r1 = mgr.deploy(src_v1)
    v1_dir = Path(r1["release_dir"])

    def run_current(script: str, *args: str) -> str:
        out = subprocess.run(
            [sys.executable, str(current / "bin" / script), *args],
            capture_output=True, text=True, timeout=60)
        _ok(out.returncode == 0, f"{script} 执行失败: {out.stderr[-300:]}")
        return out.stdout

    # 旧版本时代：写 2 条事件
    hashes_v1 = [run_current("writer.py", str(db), "v1-binary", str(n))
                 for n in (1, 2)]
    # 新版本部署并运行：再写 5 条事件
    mgr.deploy(src_v2)
    hashes_v2 = [run_current("writer.py", str(db), "v2-binary", str(n))
                 for n in range(1, 6)]
    all_hashes = hashes_v1 + hashes_v2
    _ok(len(set(all_hashes)) == 7, "7 条事件哈希必须各异")

    before_rows = _read_events_raw(db)
    _ok(len(before_rows) == 7, f"回滚前必须已有 7 条事件: {len(before_rows)}")
    store = EventStore(str(db))
    head_before = store.head()
    chain_before = store.verify_chain()
    store.close()
    _ok(head_before[1] == 7 and chain_before["ok"] is True,
        f"回滚前 head/链完好: {head_before} {chain_before}")

    # 账本文件（db/-wal/-shm）指纹——回滚绝不能触碰事件账本
    fingerprints_before = {
        str(p): _file_fingerprint(p)
        for p in (db, Path(str(db) + "-wal"), Path(str(db) + "-shm"))
        if p.exists()}

    mgr.rollback(str(current), str(v1_dir))  # 回滚到兼容旧二进制
    _ok(_real(current) == _real(v1_dir), "回滚后 current 必须指向 v1 release")

    for p, fp in fingerprints_before.items():
        _ok(_file_fingerprint(Path(p)) == fp,
            f"回滚触碰了事件账本文件: {p}")
    # 旧二进制（冻结读取器）读全量：零丢失
    payload = json.loads(run_current("reader.py", str(db)))
    _ok(payload["count"] == 7, f"旧二进制必须读出全部 7 条事件: {payload['count']}")
    eras = {}
    for ev in payload["events"]:
        eras.setdefault(ev["era"], set()).add(ev["n"])
    _ok(eras.get("v1-binary") == {1, 2},
        f"旧版本时代 2 条事件必须逐条在: {eras}")
    _ok(eras.get("v2-binary") == {1, 2, 3, 4, 5},
        f"新版本期间 5 条事件必须零丢失: {eras}")

    store = EventStore(str(db))
    head_after = store.head()
    chain_after = store.verify_chain()
    store.close()
    _ok(head_after == head_before and chain_after["ok"] is True,
        f"回滚后 head 与链校验必须与回滚前一致: {head_after} vs {head_before}")


# ---------------------------------------------------------------------- #
# RB-01｜无预授权自动回滚/错误旧版本 → 拒绝
# ---------------------------------------------------------------------- #
def _mk_signed_approval(ring: ApprovalKeyring, approval_type: str,
                        payload: Dict[str, Any]) -> Dict[str, Any]:
    """构造结构合法 + HMAC 真签名的审批 envelope（错误类型腿用）。"""
    now = datetime.now(timezone.utc)
    env: Dict[str, Any] = {
        "schema_version": "2.0",
        "approval_id": f"apr_{uuid.uuid4().hex[:12]}",
        "approval_type": approval_type,
        "key_id": "key_rb01",
        "run_id": "run-rb01-missing",
        "task_id": "task-rb01",
        "stop_event_id": "stop-rb01",
        "stop_type": "release",
        "stage": "S4_IMPLEMENT",
        "environment": "production",
        "authorized_scope": "deploy/rollback-drill",
        "policy_hash": "p" * 64,
        "ruleset_hash": "r" * 64,
        "input_watermark": _SHA1,
        "expected_state_version": 1,
        "actor": "human-approver",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": uuid.uuid4().hex + uuid.uuid4().hex[:8],
        "decision": "approve",
        "payload": payload,
        "signature": "",
    }
    env["signature"] = sign_envelope(ring.get("key_rb01"), env)
    return env


def test_RB_01_no_preauth_rollback_and_wrong_previous_refused(td: Path) -> None:
    """注入：无预授权的回滚动作 / 错误类型的合法签名审批 / 错误旧版本回滚。
    期望：全部拒绝，且零落账、current 绝不切到坏包。

    腿A（无预授权→拒绝）：RunManager.reserve_action("rollback") 无审批 →
    ActionError；持合法 HMAC 签名但类型为 release 的审批 → ApprovalRejected
    （类型不符）；两次拒绝后事件账本零条（绝不落事件）。
    腿B（错误旧版本→拒绝）：previous 内容漂移 / 目标不存在 / 非 release
    目录三种错误旧版本 → VerifyError/SwitchError 拒绝回切，current 保持 v2。
    """
    # ---- 腿A：无预授权的回滚动作预留一律拒绝（F4-AUTH-001）----
    db = td / "rb01-events.db"
    store = EventStore(str(db))
    ring = ApprovalKeyring.generate("key_rb01")
    rm = RunManager(store, keyring=ring)
    target = "deploy/prod-42"

    exc = _expect_raise(ActionError, rm.reserve_action,
                        "run-rb01-missing", "rollback", target)
    _ok("审批" in str(exc) or "approval" in str(exc),
        f"无授权预留必须以审批缺失拒绝: {exc}")
    _ok(store.head() == (None, 0), f"拒绝路径必须零落账: {store.head()}")

    release_payload = {
        "release_id": "20261008T000000Z-deadbeefcafe",
        "artifact_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
        "environment": "production",
        "previous_release_id": "20261001T000000Z-000000000000",
    }
    wrong_type = _mk_signed_approval(ring, "release", release_payload)
    exc = _expect_raise(ApprovalRejected, rm.reserve_action,
                        "run-rb01-missing", "rollback", target, wrong_type)
    _ok("approval_type" in str(exc) and "rollback" in str(exc),
        f"类型不符必须明确拒绝 rollback 预留: {exc}")
    _ok(store.head() == (None, 0), f"类型不符拒绝仍零落账: {store.head()}")
    store.close()

    # ---- 腿B：错误旧版本回滚一律拒绝（deploy_framework）----
    root = td / "rb01-root"
    releases, current = root / "releases", root / "current"
    mgr = DeployManager(str(releases), str(current))
    src_v1 = _mk_app_source(td, "src-rb-v1", flag="v1")
    src_v2 = _mk_app_source(td, "src-rb-v2", flag="v2")
    r1 = mgr.deploy(src_v1)
    v1_dir = Path(r1["release_dir"])
    mgr.deploy(src_v2)
    v2_real = _real(current)
    _ok(v2_real != _real(v1_dir), "前置：current 已在 v2")

    # B1：previous 内容漂移（错误旧版本：坏包）
    victim = v1_dir / "app.py"
    os.chmod(victim, 0o644)
    victim.write_text("print('poisoned-previous')\n", encoding="utf-8")
    os.chmod(victim, 0o444)
    exc = _expect_raise(VerifyError, mgr.rollback, str(current), str(v1_dir))
    _ok(exc.report["drifted"] == ["app.py"],
        f"坏旧版必须以内容漂移被拒: {exc.report}")
    _ok(_real(current) == v2_real, "B1 拒绝后 current 仍必须停在 v2（绝不切坏包）")

    # B2：回滚目标不存在
    exc = _expect_raise(SwitchError, mgr.rollback,
                        str(current), str(root / "no-such-release"))
    _ok("rollback target missing" in str(exc),
        f"不存在旧版必须以目标缺失拒绝: {exc}")
    _ok(_real(current) == v2_real, "B2 拒绝后 current 仍停在 v2")

    # B3：非 release 目录（无 manifest 的伪旧版本）
    fake_prev = root / "fake-previous"
    fake_prev.mkdir(parents=True)
    (fake_prev / "app.py").write_text("print('fake')\n", encoding="utf-8")
    exc = _expect_raise(VerifyError, mgr.rollback, str(current), str(fake_prev))
    _ok(exc.report["missing"] == ["manifest.json"],
        f"伪旧版必须以 manifest 缺失拒绝: {exc.report}")
    _ok(_real(current) == v2_real, "B3 拒绝后 current 仍停在 v2")

    # 正控：previous 完好时 rollback 正常放行（拒绝是因「错误旧版本」而非误杀）
    os.chmod(victim, 0o644)
    victim.write_text("print('app')\n", encoding="utf-8")
    os.chmod(victim, 0o444)
    mgr.rollback(str(current), str(v1_dir))
    _ok(_real(current) == _real(v1_dir), "正控：完好旧版回滚必须放行")


# ---------------------------------------------------------------------- #
# wave6/p1f-gate：DEP 族 8 项共用小工具
# ---------------------------------------------------------------------- #
def _mk_auth_env(ring: ApprovalKeyring, key_id: str, approval_type: str,
                 payload: Dict[str, Any], *, decision: str = "approve",
                 signature_override: Optional[str] = None) -> Dict[str, Any]:
    """构造 HMAC 真签名的授权 envelope（DEP-06/07/09 用；可注入坏签名）。"""
    env: Dict[str, Any] = {
        "approval_id": f"apr_{uuid.uuid4().hex[:12]}",
        "approval_type": approval_type,
        "key_id": key_id,
        "decision": decision,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
        "signature": "",
    }
    env["signature"] = (signature_override if signature_override is not None
                        else sign_envelope(ring.get(key_id), env))
    return env


def _mk_backup_proof(td: Path, name: str, *,
                     content_digest: Optional[str] = None) -> BackupProof:
    """构造真实备份工件 + marker 并走 BackupProof.verify 全量对账。"""
    backups = td / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    artifact = backups / f"{name}.db"
    artifact.write_bytes(f"backup-payload-{name}".encode("utf-8"))
    marker: Dict[str, Any] = {
        "kind": "wenqu-backup-proof",
        "backup_id": f"bk-{name}",
        "created_at": "2026-10-08T00:00:00Z",
        "verified": True,
        "artifact": str(artifact),
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }
    if content_digest is not None:
        marker["content_digest"] = content_digest
    marker_path = backups / f"{name}.marker.json"
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    return BackupProof.verify(str(marker_path))


def _read_deploy_state(releases_root: Path) -> Dict[str, Any]:
    with open(releases_root / DEPLOY_STATE_FILENAME, encoding="utf-8") as fh:
        return json.load(fh)


def _doctor_check(release_dir: str) -> bool:
    """读 release 内 doctor.json 健康位（DEP-07/08 自检）。"""
    with open(os.path.join(release_dir, "doctor.json"), encoding="utf-8") as fh:
        return json.load(fh).get("ok") is True


# ---------------------------------------------------------------------- #
# DEP-01｜两个部署者争 lease → 最多一个成功
# ---------------------------------------------------------------------- #
_CHILD_RACE = """\
import os, sys, time
sys.path.insert(0, {system_dir!r})
from wenqu_core.deploy_framework import DeployManager, LeaseError
go_path = {go!r}
while not os.path.exists(go_path):
    time.sleep(0.001)
try:
    mgr = DeployManager({releases!r}, {current!r})
    result = mgr.deploy({source!r})
    print("WIN:" + result["release_id"], flush=True)
except LeaseError as exc:
    print("LEASE-REFUSED", flush=True)
    sys.exit(3)
"""

_CHILD_HOLD_LEASE = """\
import sys, time
sys.path.insert(0, {system_dir!r})
from wenqu_core.deploy_framework import DeployLease
lease = DeployLease.acquire({lease_path!r})
print("HELD", flush=True)
time.sleep(30)
"""


def test_DEP_01_concurrent_deployers_lease_at_most_one_wins(td: Path) -> None:
    """注入：两个部署者争 lease。期望：最多一个成功。

    三层实证：(1) 真实并发——两个子进程以发令文件同刻起跑 deploy 同一
    16MiB 源（拉长租约持有窗口），断言恰一 WIN、一 LeaseError(exit 3)、
    current 指向胜者 release 且完好；(2) 确定性争用——进程内显式持锁后
    deploy 必须 LeaseError（current 不变），释放后同 manager 再 deploy
    成功（自身锁不死锁）；(3) 对抗负例——持锁进程被 SIGKILL 后租约随
    fd 由内核释放，下一部署立即成功（flock 无陈锁残留，区别于
    O_EXCL 锁文件方案）。
    """
    # ---- 层1：真实并发争用（最多一个成功）----
    observed_exactly_one = False
    for trial in range(3):
        root = td / f"dep1-race-{trial}"
        releases, current = root / "releases", root / "current"
        src_v1 = _mk_app_source(td, f"dep1-v1-{trial}", flag="base")
        src_big = _mk_app_source(td, f"dep1-big-{trial}", flag="big",
                                 bigfile=True)
        mgr = DeployManager(str(releases), str(current))
        r1 = mgr.deploy(src_v1)
        v1_real = _real(current)
        go = root / "go"
        go.parent.mkdir(parents=True, exist_ok=True)
        procs = []
        for i in (1, 2):
            script = root / f"racer-{i}.py"
            script.write_text(_CHILD_RACE.format(
                system_dir=str(SYSTEM_DIR), go=str(go),
                releases=str(releases), current=str(current),
                source=str(src_big)), encoding="utf-8")
            procs.append(subprocess.Popen(
                [sys.executable, str(script)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        go.write_text("go\n", encoding="utf-8")  # 发令：两部署者同刻起跑
        outs = [p.communicate(timeout=180) for p in procs]
        codes = [p.returncode for p in procs]
        wins = [o[0].strip() for o in outs if o[0].strip().startswith("WIN:")]
        refused = [o[0].strip() for o in outs if "LEASE-REFUSED" in o[0]]
        if not (len(wins) == 1 and len(refused) == 1
                and sorted(codes) == [0, 3]):
            continue  # 调度把两次尝试完全错开（无争用）——重试下一个 trial
        winner_id = wins[0].split(":", 1)[1]
        _ok(refused[0] == "LEASE-REFUSED", f"败者必须是租约拒绝: {outs}")
        _ok(_real(current) == _real(releases / winner_id),
            "current 必须指向胜者 release")
        _ok(mgr.verify(str(releases / winner_id))["ok"] is True,
            "胜者 release 必须完好")
        named = [d for d in releases.iterdir() if not d.name.startswith(".")]
        _ok(len(named) == 2, f"败者绝不能落 release（只建不激活都不允许）: "
                             f"{sorted(d.name for d in named)}")
        _ok(v1_real != _real(current), "胜者必须完成切换")
        observed_exactly_one = True
        break
    _ok(observed_exactly_one,
        "3 次 trial 内未观测到『恰一成功一拒绝』的真实争用")

    # ---- 层2：确定性争用 + 自释放 ----
    root = td / "dep1-det"
    releases, current = root / "releases", root / "current"
    src_a = _mk_app_source(td, "dep1-det-a", flag="a")
    src_b = _mk_app_source(td, "dep1-det-b", flag="b")
    mgr = DeployManager(str(releases), str(current))
    mgr.deploy(src_a)
    a_real = _real(current)
    hold = DeployLease.acquire(str(releases / ".deploy-lease"))
    exc = _expect_raise(LeaseError, mgr.deploy, str(src_b))
    _ok("lease" in str(exc), f"必须以租约被持拒绝: {exc}")
    _ok(_real(current) == a_real, "租约拒绝后 current 不得漂移")
    hold.release()
    mgr.deploy(src_b)  # 释放后同 manager 立即可部署（无自锁）
    _ok(_real(current) != a_real, "释放后部署必须成功切换")

    # ---- 层3：对抗负例——持锁进程被 kill -9，租约必须随内核释放 ----
    root = td / "dep1-crash"
    releases, current = root / "releases", root / "current"
    src_c = _mk_app_source(td, "dep1-crash-src", flag="c")
    mgr = DeployManager(str(releases), str(current))
    mgr.deploy(src_c)
    script = root / "hold_lease.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(_CHILD_HOLD_LEASE.format(
        system_dir=str(SYSTEM_DIR),
        lease_path=str(releases / ".deploy-lease")), encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _ok(proc.stdout.readline().strip() == "HELD", "子进程必须先确认持锁")
    proc.send_signal(signal.SIGKILL)
    proc.communicate(timeout=30)
    src_d = _mk_app_source(td, "dep1-crash-src2", flag="d")
    mgr.deploy(src_d)  # 陈锁不得阻塞后续部署
    _ok(Path(_real(current)).name != "", "kill 持锁者后部署必须成功")


# ---------------------------------------------------------------------- #
# DEP-02｜smoke 访问生产 DB/state → 隔离拒绝
# ---------------------------------------------------------------------- #
def test_DEP_02_smoke_isolation_denies_production_db_state_access(
        td: Path) -> None:
    """注入：部署自检（smoke）尝试访问生产 DB/state。期望：隔离拒绝。

    实证面：自检在一次性沙箱副本上运行（副本目录名=release_id，路径≠
    真实 release；沙箱内写入不污染真实 release 不可变性）；对生产路径
    的 open / sqlite3.connect / 沙箱内符号链接逃逸全部被 audit-hook 守卫
    拒绝（SmokeIsolationError，部署失败并按 D2 回滚旧版，生产文件字节
    未被读取/触碰）；发布区落在受保护区内属隔离误配——构造期即拒绝。
    """
    prod_root = td / "prod-state"
    (prod_root / "state").mkdir(parents=True)
    prod_db = prod_root / "state" / "events.db"
    prod_db.write_text("PROD-SECRET-EVENTS\n", encoding="utf-8")
    prod_before = prod_db.read_bytes()

    seen_dirs: List[str] = []

    def clean_smoke(release_dir: str) -> bool:
        seen_dirs.append(release_dir)
        with open(os.path.join(release_dir, "doctor.json"),
                  encoding="utf-8") as fh:
            return json.load(fh).get("ok") is True

    root = td / "dep2-root"
    releases, current = root / "releases", root / "current"
    mgr_clean = DeployManager(
        str(releases), str(current), install_self_check=clean_smoke,
        self_check_protected_paths=[str(prod_root)])

    src_v1 = _mk_app_source(td, "dep2-v1", healthy=True, flag="v1")
    r1 = mgr_clean.deploy(src_v1)
    v1_dir = Path(r1["release_dir"])
    _ok(r1["self_check"] == "passed(isolated)", "自检必须以隔离模式运行")
    _ok(len(seen_dirs) == 1, "首部署自检恰跑一次")
    sandbox_seen = Path(seen_dirs[0])
    _ok(sandbox_seen.name == v1_dir.name,
        f"沙箱副本必须保留 release_id 目录名: {sandbox_seen}")
    _ok(_real(sandbox_seen) != _real(v1_dir),
        "自检绝不能直跑真实 release 目录（必须沙箱隔离）")

    # 沙箱写入不污染真实 release（不可变性保持）
    def writer_smoke(release_dir: str) -> bool:
        with open(os.path.join(release_dir, "doctor.json"),
                  encoding="utf-8") as fh:
            ok = json.load(fh).get("ok") is True
        with open(os.path.join(release_dir, "smoke-scratch.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write("sandbox-only\n")
        return ok

    root_w = td / "dep2-writer"
    rel_w, cur_w = root_w / "releases", root_w / "current"
    mgr_w = DeployManager(
        str(rel_w), str(cur_w), install_self_check=writer_smoke,
        self_check_protected_paths=[str(prod_root)])
    rw = mgr_w.deploy(_mk_app_source(td, "dep2-w", healthy=True, flag="w"))
    _ok(mgr_w.verify(rw["release_dir"])["ok"] is True,
        "沙箱写入绝不能泄漏进真实 release（verify 多件即失败）")

    # ---- 生产访问三形态：open / sqlite3.connect / 符号链接逃逸 ----
    def _mk_bad_root(name: str, bad_smoke: Callable[[str], bool]
                     ) -> Tuple[Path, DeployManager, Path]:
        rt = td / f"dep2-{name}"
        rel, cur = rt / "releases", rt / "current"
        m0 = DeployManager(str(rel), str(cur), install_self_check=clean_smoke,
                           self_check_protected_paths=[str(prod_root)])
        m0.deploy(_mk_app_source(td, f"dep2-{name}-v1", flag="v1"))
        v1_real = _real(cur)
        m = DeployManager(str(rel), str(cur), install_self_check=bad_smoke,
                          self_check_protected_paths=[str(prod_root)])
        return rt, m, Path(v1_real)

    read_marker = td / "dep2-markers"
    read_marker.mkdir()

    def open_prod_smoke(release_dir: str) -> bool:
        with open(os.path.join(release_dir, "doctor.json"),
                  encoding="utf-8") as fh:
            json.load(fh)
        data = open(prod_db, "rb").read()          # 注入：读生产 DB
        (read_marker / "prod-read.txt").write_text(str(data), encoding="utf-8")
        return True

    _, m1, v1_1 = _mk_bad_root("open", open_prod_smoke)
    exc = _expect_raise(DeployError, m1.deploy,
                        str(_mk_app_source(td, "dep2-open-v2", flag="o2")))
    _ok(isinstance(exc.__cause__, SmokeIsolationError),
        f"必须以隔离拒绝为因: {type(exc.__cause__)!r}")
    _ok("DEP-02" in str(exc) and "isolation" in str(exc).lower(),
        f"DeployError 必须携带隔离拒绝详情: {exc}")
    _ok(not (read_marker / "prod-read.txt").exists(),
        "生产 DB 绝不能被读到（守卫在 open 即拒，读侧证据零产生）")
    rt1_cur = td / "dep2-open" / "current"
    _ok(_real(rt1_cur) == _real(v1_1),
        "隔离拒绝后必须回滚旧版（D2 保持），不留失败版在流量位")
    _ok(prod_db.read_bytes() == prod_before, "生产 DB 字节级未动")

    def sqlite_prod_smoke(release_dir: str) -> bool:
        conn = sqlite3.connect(str(prod_db))       # 注入：连生产 DB
        conn.close()
        return True

    _, m2, v1_2 = _mk_bad_root("sqlite", sqlite_prod_smoke)
    exc = _expect_raise(DeployError, m2.deploy,
                        str(_mk_app_source(td, "dep2-sqlite-v2", flag="s2")))
    _ok(isinstance(exc.__cause__, SmokeIsolationError),
        f"sqlite3.connect 生产库必须被隔离拒绝: {type(exc.__cause__)!r}")
    _ok(prod_db.read_bytes() == prod_before, "sqlite 通道同样零触碰")
    rt2_cur = td / "dep2-sqlite" / "current"
    _ok(_real(rt2_cur) == _real(v1_2), "sqlite 腿同样回滚到旧版")

    def symlink_escape_smoke(release_dir: str) -> bool:
        link = os.path.join(release_dir, "escape.db")
        if not os.path.lexists(link):
            os.symlink(prod_db, link)              # 沙箱内符号链接指向生产
        with open(link, "rb") as fh:               # 注入：经符号链接读生产
            fh.read()
        (read_marker / "symlink-read.txt").write_text("read", encoding="utf-8")
        return True

    _, m3, v1_3 = _mk_bad_root("symlink", symlink_escape_smoke)
    exc = _expect_raise(DeployError, m3.deploy,
                        str(_mk_app_source(td, "dep2-symlink-v2", flag="y2")))
    _ok(isinstance(exc.__cause__, SmokeIsolationError),
        f"符号链接逃逸必须被 realpath 归一后拒绝: {type(exc.__cause__)!r}")
    _ok(not (read_marker / "symlink-read.txt").exists(),
        "逃逸读取零得手")
    rt3_cur = td / "dep2-symlink" / "current"
    _ok(_real(rt3_cur) == _real(v1_3), "逃逸腿同样回滚到旧版")

    # ---- 边界断言（误配 fail-closed）：发布区落在受保护区内 ----
    bad_releases = prod_root / "releases"
    exc = _expect_raise(SmokeIsolationError, DeployManager,
                        str(bad_releases), str(prod_root / "current"),
                        clean_smoke, self_check_protected_paths=[str(prod_root)])
    _ok("boundary" in str(exc) and "misconfiguration" in str(exc),
        f"隔离误配必须构造期拒绝: {exc}")


# ---------------------------------------------------------------------- #
# DEP-04｜自签/替换/revoked release key → 拒绝
# ---------------------------------------------------------------------- #
def test_DEP_04_release_key_selfsign_replace_revoked_rejected(
        td: Path) -> None:
    """注入：自签 release / key 被替换（含签名体篡改）/ revoked key。
    期望：全部拒绝（verify/rollback fail-closed），current 绝不切上不可信
    release；合法签名链正常发布；已死 key 不得签发新 release（fail-closed）。

    keyring 机制复用 approval_keys（只读 import）：HMAC-SHA256 + key
    生命周期元数据（revoked 验签即拒）。release 签名域与审批域分离：
    manifest 增 key_id/signature，verify 按 pinned key 验签。
    """
    s_main, s_alt, s_dead, s_evil = (generate_secret() for _ in range(4))
    ring_def = ApprovalKeyring({
        "key_release_v1": s_main,
        "key_release_alt": s_alt,
    })
    root = td / "dep4-root"
    releases, current = root / "releases", root / "current"
    mgr = DeployManager(str(releases), str(current),
                        release_keyring=ring_def,
                        release_signing_key="key_release_v1")

    # ---- 正例：合法签名构建+部署+验签 ----
    src_v1 = _mk_app_source(td, "dep4-v1", flag="v1")
    r1 = mgr.deploy(src_v1)
    v1_dir = Path(r1["release_dir"])
    with open(v1_dir / "manifest.json", encoding="utf-8") as fh:
        manifest = json.load(fh)
    _ok(manifest.get("key_id") == "key_release_v1",
        f"manifest 必须携带 key_id: {manifest.get('key_id')}")
    _ok(isinstance(manifest.get("signature"), str)
        and len(manifest["signature"]) == 64,
        "manifest 必须携带 64-hex HMAC 签名")
    _ok(mgr.verify(str(v1_dir))["ok"] is True, "合法签名 verify 必须通过")
    _ok(_real(current) == _real(v1_dir), "正例：current 指向 v1")

    src_v2 = _mk_app_source(td, "dep4-v2", flag="v2")

    # ---- 腿1：自签（攻击者自建 keyring 签出的 release）----
    ring_evil = ApprovalKeyring({"key_evil": s_evil})
    mgr_evil = DeployManager(str(releases), str(root / "evil-current"),
                             release_keyring=ring_evil,
                             release_signing_key="key_evil")
    evil_dir = Path(mgr_evil.build(src_v2)["release_dir"])
    exc = _expect_raise(VerifyError, mgr.verify, str(evil_dir))
    _ok(str(exc.report["signature"]).startswith("unknown_release_key"),
        f"自签必须以未知 key 拒绝: {exc.report['signature']}")
    exc = _expect_raise(VerifyError, mgr.rollback, str(current), str(evil_dir))
    _ok("unknown_release_key" in str(exc.report["signature"]),
        "回滚到自签 release 必须被拒")
    _ok(_real(current) == _real(v1_dir), "拒绝后 current 仍指向可信 v1")

    # ---- 腿2：替换（manifest 改由另一把 active key 签出/key_id 漂移）----
    # 注：release_id = 时间戳+内容摘要——不同签发者必须用不同内容源构建
    # （同内容同秒会命中不可变命名空间的 divergent 碰撞拒绝，属 D1 契约）。
    src_v2_alt = _mk_app_source(td, "dep4-v2-alt", flag="v2-alt")
    mgr_alt = DeployManager(str(releases), str(root / "alt-current"),
                            release_keyring=ring_def,
                            release_signing_key="key_release_alt")
    alt_dir = Path(mgr_alt.build(src_v2_alt)["release_dir"])
    exc = _expect_raise(VerifyError, mgr.verify, str(alt_dir))
    _ok(str(exc.report["signature"]).startswith("release_key_replaced"),
        f"key 替换必须按 pinned key 拒绝: {exc.report['signature']}")
    _ok(_real(current) == _real(v1_dir), "替换腿拒绝后 current 不变")

    # ---- 腿2b：签名体/manifest 体篡改（同一把 key 但内容被改）----
    for label, mutate in (
        ("signature", lambda m: m.update(
            signature="0" * 64 if m["signature"][0] != "0" else "1" * 64)),
        ("body", lambda m: m.update(
            content_digest="f" * 64)),
    ):
        t_dir = td / f"dep4-tamper-{label}"
        shutil.copytree(v1_dir, t_dir)
        mpath = t_dir / "manifest.json"
        os.chmod(mpath, 0o644)
        with open(mpath, encoding="utf-8") as fh:
            tampered = json.load(fh)
        mutate(tampered)
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(tampered, fh, ensure_ascii=False, indent=2,
                      sort_keys=True)
            fh.write("\n")
        os.chmod(mpath, 0o444)
        exc = _expect_raise(VerifyError, mgr.verify, str(t_dir))
        _ok("release_signature_mismatch" in str(exc.report["signature"]),
            f"{label} 篡改必须以签名不匹配拒绝: {exc.report['signature']}")

    # ---- 腿3：未签名 release（fail-closed：配置了验签即拒无签名件）----
    plain_root = td / "dep4-plain"
    mgr_plain = DeployManager(str(plain_root / "releases"),
                              str(plain_root / "current"))
    unsigned_dir = Path(mgr_plain.build(
        _mk_app_source(td, "dep4-v2-plain", flag="v2-plain"))["release_dir"])
    exc = _expect_raise(VerifyError, mgr.verify, str(unsigned_dir))
    _ok(str(exc.report["signature"]).startswith("unsigned_release"),
        f"未签名 release 必须被拒: {exc.report['signature']}")

    # ---- 腿4：revoked key（签发时 active，验证时已吊销）----
    root_dead = td / "dep4-dead"
    rel_dead, cur_dead = root_dead / "releases", root_dead / "current"
    ring_alive = ApprovalKeyring({"key_release_dead": s_dead})
    mgr_alive = DeployManager(str(rel_dead), str(cur_dead),
                              release_keyring=ring_alive,
                              release_signing_key="key_release_dead")
    dead_dir = Path(mgr_alive.deploy(
        _mk_app_source(td, "dep4-dead-src", flag="dead"))["release_dir"])
    ring_revoked = ApprovalKeyring(
        {"key_release_dead": s_dead},
        metadata={"key_release_dead": {
            "status": "revoked", "revoked_at": "2026-01-01T00:00:00Z"}})
    mgr_revoked = DeployManager(str(rel_dead), str(cur_dead),
                                release_keyring=ring_revoked,
                                release_signing_key="key_release_dead")
    exc = _expect_raise(VerifyError, mgr_revoked.verify, str(dead_dir))
    _ok(str(exc.report["signature"]).startswith("revoked_release_key"),
        f"revoked key 验签即拒（即使签名本身正确）: {exc.report['signature']}")

    # ---- fail-closed 签发：已死 key 不得签发新 release ----
    exc = _expect_raise(BuildError, mgr_revoked.deploy,
                        str(_mk_app_source(td, "dep4-dead2", flag="dead2")))
    _ok("signing key not eligible" in str(exc),
        f"revoked key 签发必须 fail-closed: {exc}")

    # ---- 正例收尾：签名链完好时新 release 正常激活 ----
    mgr.deploy(_mk_app_source(td, "dep4-v2-final", flag="v2-final"))
    _ok(_real(current) != _real(v1_dir), "合法新签名 release 必须可激活")


# ---------------------------------------------------------------------- #
# DEP-05｜previous release 超 schema 范围 → 拒绝回滚
# ---------------------------------------------------------------------- #
def _forge_schema_release(src_release: Path, dst: Path,
                          schema_patch: Optional[int]) -> Path:
    """复制完好 release 并改写 manifest schema_version（None=删除字段）。"""
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src_release, dst)
    mpath = dst / "manifest.json"
    os.chmod(mpath, 0o644)
    with open(mpath, encoding="utf-8") as fh:
        manifest = json.load(fh)
    if schema_patch is None:
        manifest.pop("schema_version", None)
    else:
        manifest["schema_version"] = schema_patch
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(mpath, 0o444)
    return dst


def test_DEP_05_previous_release_schema_out_of_range_rollback_refused(
        td: Path) -> None:
    """注入：previous release manifest 的 schema_version 超出兼容范围。
    期望：拒绝回滚（SchemaRangeError/VerifyError 设计内拒绝），current
    绝不切到读不懂的未来（或过旧）schema；坏 manifest 以设计内报告拒绝
    而非未设计异常崩溃；在范围内的旧版照常放行（不误杀）。
    """
    root = td / "dep5-root"
    releases, current = root / "releases", root / "current"
    mgr = DeployManager(str(releases), str(current), schema_range=(1, 2))
    src_v1 = _mk_app_source(td, "dep5-v1", flag="v1")
    src_v2 = _mk_app_source(td, "dep5-v2", flag="v2")
    r1 = mgr.deploy(src_v1)
    v1_dir = Path(r1["release_dir"])
    mgr.deploy(src_v2)
    v2_real = _real(current)
    with open(v1_dir / "manifest.json", encoding="utf-8") as fh:
        _ok(json.load(fh).get("schema_version") == 1,
            "build 必须给 manifest 盖当前 schema_version=1")

    # ---- 未来 schema（99）：rollback 拒绝 + verify 设计内拒绝 ----
    future = _forge_schema_release(v1_dir, td / "dep5-future99", 99)
    exc = _expect_raise(SchemaRangeError, mgr.rollback, str(current), str(future))
    _ok("outside" in str(exc) and "refusing rollback" in str(exc),
        f"超范围必须明确拒绝回滚: {exc}")
    _ok(exc.schema_version == 99 and exc.allowed_range == (1, 2),
        "拒绝必须携带越界版本与合法范围")
    _ok(_real(current) == v2_real, "拒绝后 current 仍停在 v2")
    exc = _expect_raise(VerifyError, mgr.verify, str(future))
    _ok("schema_version_out_of_range" in str(exc.report["schema"]),
        f"verify 必须以 schema 越界拒绝（不崩溃）: {exc.report['schema']}")

    # ---- 过旧 schema（0）：同样拒绝 ----
    ancient = _forge_schema_release(v1_dir, td / "dep5-ancient0", 0)
    exc = _expect_raise(SchemaRangeError, mgr.rollback, str(current), str(ancient))
    _ok(exc.schema_version == 0, f"低于下界同样拒绝: {exc}")
    _ok(_real(current) == v2_real, "ancient 拒绝后 current 不变")

    # ---- 对抗负例：坏类型 schema_version / 字段缺失 / 坏 manifest ----
    garbage = _forge_schema_release(v1_dir, td / "dep5-garbage", None)
    mpath = garbage / "manifest.json"
    os.chmod(mpath, 0o644)
    data = json.loads(mpath.read_text(encoding="utf-8"))
    data["schema_version"] = "one"      # 字符串形态——不得以 TypeError 崩溃
    mpath.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(mpath, 0o444)
    exc = _expect_raise(VerifyError, mgr.verify, str(garbage))
    _ok(str(exc.report["schema"]).startswith("schema_version_invalid"),
        f"坏类型必须设计内拒绝: {exc.report['schema']}")
    exc = _expect_raise(SchemaRangeError, mgr.rollback, str(current), str(garbage))
    _ok(_real(current) == v2_real, "garbage 拒绝后 current 不变")

    missing = _forge_schema_release(v1_dir, td / "dep5-missing", None)
    exc = _expect_raise(SchemaRangeError, mgr.rollback, str(current), str(missing))
    _ok(exc.schema_version is None, "缺失 schema_version 同样拒绝回滚")

    broken = _forge_schema_release(v1_dir, td / "dep5-broken", 1)
    mpath = broken / "manifest.json"
    os.chmod(mpath, 0o644)
    data = json.loads(mpath.read_text(encoding="utf-8"))
    data["files"] = [{"path": "x"}]     # 缺 sha256 的坏清单——不崩溃
    mpath.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(mpath, 0o444)
    exc = _expect_raise(VerifyError, mgr.verify, str(broken))
    _ok(exc.report["schema"] == "manifest_invalid",
        f"坏 manifest 必须设计内拒绝: {exc.report['schema']}")

    # ---- 正控：范围内旧版回滚照常放行（拒绝是因 schema 越界而非误杀）----
    mgr.rollback(str(current), str(v1_dir))
    _ok(_real(current) == _real(v1_dir), "正控：范围内旧版回滚必须放行")


# ---------------------------------------------------------------------- #
# DEP-06｜无迁移锁/未验证备份/expand 超授权 → 激活前 BLOCKED
# ---------------------------------------------------------------------- #
def _mk_mig_source(td: Path, name: str, *, migrations: Dict[str, str],
                   healthy: bool = True) -> Path:
    src = _mk_app_source(td, name, healthy=healthy, flag=name)
    mig = src / "migrations"
    mig.mkdir(parents=True, exist_ok=True)
    for fname, body in migrations.items():
        (mig / fname).write_text(body, encoding="utf-8")
    return src


def test_DEP_06_migration_gate_lock_backup_expand_auth_blocked_before_activation(
        td: Path) -> None:
    """注入：release 夹带迁移但无迁移锁 / 备份未验证 / expand 超授权。
    期望：激活前 BLOCKED（ActivationBlocked 携带全部缺失原因），旧
    current 逐字节不变；三要素齐备（真锁+真备份对账+真 HMAC ddl 授权）
    才放行激活。对抗负例：伪造锁对象（非 flock 实例）、备份 marker
    自述 verified 但工件哈希漂移、授权类型不符/坏签名/digest 不绑定、
    备份证明绑定别的 release——全部 BLOCKED。
    """
    ring = ApprovalKeyring.generate("key_ops")
    root = td / "dep6-root"
    releases, current = root / "releases", root / "current"
    mgr = DeployManager(str(releases), str(current), auth_keyring=ring)
    src_v1 = _mk_app_source(td, "dep6-v1", flag="v1")
    mgr.deploy(src_v1)
    v1_real = _real(current)

    src_base = _mk_mig_source(td, "dep6-base", migrations={
        "000_baseline.sql": "-- baseline schema\nCREATE TABLE t (id INT);\n"})

    # ---- 腿1：无迁移锁+无备份 → BLOCKED（原因清单完整）----
    exc = _expect_raise(ActivationBlocked, mgr.deploy, str(src_base))
    _ok(exc.reasons == ["migration_lock_missing", "backup_not_verified"],
        f"缺锁缺备份必须双双列出: {exc.reasons}")
    _ok("old current unchanged" in str(exc), "BLOCKED 必须声明旧 current 不变")
    _ok(_real(current) == v1_real, "腿1 BLOCKED 后 current 仍在 v1")

    # ---- 腿2：持锁但备份未验证（含伪造锁对抗负例）----
    lock = MigrationLock.acquire(str(td / "dep6.mig.lock"))
    exc = _expect_raise(ActivationBlocked, mgr.deploy, str(src_base),
                        migration_lock=lock)
    _ok(exc.reasons == ["backup_not_verified"],
        f"持锁+缺备份必须只列备份原因: {exc.reasons}")
    _ok(_real(current) == v1_real, "腿2 BLOCKED 后 current 仍在 v1")

    fake_lock = type("FakeLock", (), {"held": True, "path": "/tmp/x"})()
    exc = _expect_raise(ActivationBlocked, mgr.deploy, str(src_base),
                        migration_lock=fake_lock)
    _ok("migration_lock_missing" in exc.reasons,
        f"伪造锁对象（非 flock 实例）不得过关: {exc.reasons}")

    proof = _mk_backup_proof(td, "dep6-ok")
    exc = _expect_raise(ActivationBlocked, mgr.deploy, str(src_base),
                        migration_lock=None, backup_proof=proof)
    _ok("migration_lock_missing" in exc.reasons, "锁缺位仍 BLOCKED")

    # 备份 marker 自述 verified=true 但工件被篡改 → BackupProof 拒绝
    art = td / "backups" / "dep6-ok.db"
    os.chmod(art, 0o644)
    art.write_bytes(b"tampered-after-marker")   # marker 记录的哈希失配
    try:
        BackupProof.verify(str(td / "backups" / "dep6-ok.marker.json"))
        raise AssertionError("工件漂移后 BackupProof.verify 必须拒绝")
    except Exception as exc2:  # noqa: BLE001 - BackupProofError(ValueError)
        _ok("hash drift" in str(exc2) or "drift" in str(exc2),
            f"备份工件哈希漂移必须被重哈希对账拒绝: {exc2}")
    # 对抗负例：proof 构造后工件再被篡改（stale proof）→ 门禁时点复验拒绝
    exc = _expect_raise(ActivationBlocked, mgr.deploy, str(src_base),
                        migration_lock=lock, backup_proof=proof)
    _ok(exc.reasons == ["backup_not_verified"],
        f"stale proof（构造后工件漂移）必须被门禁复验拒绝: {exc.reasons}")
    os.chmod(art, 0o644)
    art.write_bytes(f"backup-payload-dep6-ok".encode("utf-8"))  # 复原

    # ---- 腿3：expand 迁移超授权 ----
    src_expand = _mk_mig_source(td, "dep6-expand", migrations={
        "000_baseline.sql": "-- baseline\n",
        "001_expand.sql": "-- phase: expand\nALTER TABLE t ADD COLUMN c INT;\n"})
    info = mgr.build(src_expand)
    digest = info["content_digest"]
    proof_x = _mk_backup_proof(td, "dep6-expand", content_digest=digest)

    exc = _expect_raise(ActivationBlocked, mgr.deploy, str(src_expand),
                        migration_lock=lock, backup_proof=proof_x)
    _ok(exc.reasons == ["expand_migration_unauthorized"],
        f"无授权 expand 必须 BLOCKED: {exc.reasons}")
    _ok(_real(current) == v1_real, "腿3 BLOCKED 后 current 仍在 v1")

    wrong_type = _mk_auth_env(ring, "key_ops", "release",
                              {"content_digest": digest})
    bad_sig = _mk_auth_env(ring, "key_ops", "ddl",
                           {"content_digest": digest},
                           signature_override="0" * 64)
    wrong_digest = _mk_auth_env(ring, "key_ops", "ddl",
                                {"content_digest": "f" * 64})
    for env in (wrong_type, bad_sig, wrong_digest):
        exc = _expect_raise(ActivationBlocked, mgr.deploy, str(src_expand),
                            migration_lock=lock, backup_proof=proof_x,
                            expand_authorization=env)
        _ok(exc.reasons == ["expand_migration_unauthorized"],
            f"对抗授权（类型/签名/digest）必须一律 BLOCKED: {exc.reasons}")

    # 备份证明绑定另一个 release → 备份不算数
    proof_other = _mk_backup_proof(td, "dep6-other", content_digest="e" * 64)
    exc = _expect_raise(ActivationBlocked, mgr.deploy, str(src_expand),
                        migration_lock=lock, backup_proof=proof_other,
                        expand_authorization=_mk_auth_env(
                            ring, "key_ops", "ddl", {"content_digest": digest}))
    _ok(exc.reasons == ["backup_not_verified"],
        f"绑定别的 release 的备份必须不算数: {exc.reasons}")

    # ---- 正例：锁+备份+合法 ddl 授权 → 激活放行 ----
    ok_env = _mk_auth_env(ring, "key_ops", "ddl", {"content_digest": digest})
    r = mgr.deploy(str(src_expand), migration_lock=lock,
                   backup_proof=proof_x, expand_authorization=ok_env)
    _ok(r["deployed"] is True, "三要素齐备必须激活")
    _ok(_real(current) != v1_real, "激活后 current 必须切换")
    _ok(_read_deploy_state(releases)["status"] == "ACTIVE", "状态机落 ACTIVE")
    _ok(mgr.verify(r["release_dir"])["ok"] is True, "激活的 release 完好")


# ---------------------------------------------------------------------- #
# DEP-07｜ACTIVATING 失败且无预授权 → FAILED_BLOCKED，不得自动回滚
# ---------------------------------------------------------------------- #
def test_DEP_07_activating_failure_without_preauth_failed_blocked_no_auto_rollback(
        td: Path) -> None:
    """注入：fenced 部署在 ACTIVATING 阶段失败（自检红），且无预授权回滚。
    期望：FAILED_BLOCKED（落盘）；绝不自动回滚（current 停在失败 release
    上，旧版完好不动）；后续部署停等人工 acknowledge；持有效 rollback
    预授权时按授权回滚（ROLLED_BACK）；预授权类型不符/坏签名/绑定他版
    一律视同无预授权。
    """
    ring = ApprovalKeyring.generate("key_ops")

    # ---- 根A：无预授权 → FAILED_BLOCKED → 停等 → 人工确认恢复 ----
    root = td / "dep7-a"
    releases, current = root / "releases", root / "current"
    mgr = DeployManager(str(releases), str(current),
                        install_self_check=_doctor_check,
                        fenced=True, auth_keyring=ring)
    src_v1 = _mk_app_source(td, "dep7-v1", healthy=True, flag="v1")
    mgr.deploy(src_v1)
    v1_dir = Path(_real(current))
    _ok(_read_deploy_state(releases)["status"] == "ACTIVE", "前置：v1 ACTIVE")

    src_v2 = _mk_app_source(td, "dep7-v2", healthy=False, flag="v2")
    exc = _expect_raise(FailedBlockedError, mgr.deploy, str(src_v2))
    _ok("FAILED_BLOCKED" in str(exc) and "auto-rollback suppressed" in str(exc),
        f"必须进入 FAILED_BLOCKED 且声明未自动回滚: {exc}")
    state = _read_deploy_state(releases)
    _ok(state["status"] == "FAILED_BLOCKED", f"状态机必须落 FAILED_BLOCKED: {state}")
    v2_dir = Path(_real(current))
    _ok(v2_dir == Path(_real(releases / state["release_id"])),
        "current 必须留在失败 release 上（等人工裁决）")
    _ok(_real(v2_dir) != _real(v1_dir), "绝不能自动回滚到 v1")
    _ok(mgr.verify(str(v1_dir))["ok"] is True, "旧版 v1 完好未动")

    src_v3 = _mk_app_source(td, "dep7-v3", healthy=True, flag="v3")
    exc = _expect_raise(ActivationBlocked, mgr.deploy, str(src_v3))
    _ok("FAILED_BLOCKED" in str(exc) and "acknowledge" in str(exc),
        f"FAILED_BLOCKED 期间继续发布必须停等人工: {exc}")
    _ok(_real(current) == _real(v2_dir), "停等期间 current 不漂移")

    mgr.acknowledge_failed_block(operator="sre-lead", note="human triage")
    r3 = mgr.deploy(src_v3)
    _ok(r3["deployed"] is True and _real(current) == _real(r3["release_dir"]),
        "人工确认后健康 release 必须可发布")
    _ok(_read_deploy_state(releases)["status"] == "ACTIVE", "恢复后 ACTIVE")

    # ---- 根B：有预授权 → 授权回滚（ROLLED_BACK），可继续发布 ----
    root = td / "dep7-b"
    releases, current = root / "releases", root / "current"
    mgr = DeployManager(str(releases), str(current),
                        install_self_check=_doctor_check,
                        fenced=True, auth_keyring=ring)
    mgr.deploy(_mk_app_source(td, "dep7-v1b", healthy=True, flag="v1b"))
    v1_real = _real(current)
    preauth = _mk_auth_env(ring, "key_ops", "rollback",
                           {"environment": "production"})
    exc = _expect_raise(DeployError, mgr.deploy,
                        str(_mk_app_source(td, "dep7-v2b", healthy=False,
                                           flag="v2b")),
                        rollback_authorization=preauth)
    _ok(not isinstance(exc, FailedBlockedError),
        "有效预授权时不得进入 FAILED_BLOCKED")
    _ok("pre-authorized rollback executed" in str(exc),
        f"必须执行授权回滚并如实上报: {exc}")
    state = _read_deploy_state(releases)
    _ok(state["status"] == "ROLLED_BACK", f"状态机必须落 ROLLED_BACK: {state}")
    _ok(_real(current) == v1_real, "授权回滚后 current 回到 v1")
    r = mgr.deploy(_mk_app_source(td, "dep7-v3b", healthy=True, flag="v3b"))
    _ok(r["deployed"] is True, "授权回滚后可继续发布")

    # ---- 根C：对抗负例——无效预授权视同无预授权 ----
    for label, env in (
        ("wrong-type", _mk_auth_env(ring, "key_ops", "release", {})),
        ("bad-signature", _mk_auth_env(ring, "key_ops", "rollback", {},
                                       signature_override="0" * 64)),
        ("stale-release-binding", _mk_auth_env(
            ring, "key_ops", "rollback",
            {"release_id": "20200101T000000Z-stalestalestal"})),
        ("not-approved", _mk_auth_env(ring, "key_ops", "rollback", {},
                                      decision="reject")),
    ):
        root = td / f"dep7-c-{label}"
        releases, current = root / "releases", root / "current"
        m = DeployManager(str(releases), str(current),
                          install_self_check=_doctor_check,
                          fenced=True, auth_keyring=ring)
        m.deploy(_mk_app_source(td, f"dep7-{label}-v1", healthy=True,
                                flag=f"{label}1"))
        v1_real = _real(current)
        exc = _expect_raise(FailedBlockedError, m.deploy,
                            str(_mk_app_source(td, f"dep7-{label}-v2",
                                               healthy=False, flag=f"{label}2")),
                            rollback_authorization=env)
        _ok(_real(current) != v1_real,
            f"{label}: current 必须停在失败版（不回滚）")
        _ok(_read_deploy_state(releases)["status"] == "FAILED_BLOCKED",
            f"{label}: 无效预授权必须视同无预授权")


# ---------------------------------------------------------------------- #
# DEP-08｜ROLLBACK_FAILED → writer/merge/release 熔断停等人工恢复
# ---------------------------------------------------------------------- #
def test_DEP_08_rollback_failed_fuses_releases_until_manual_resume(
        td: Path) -> None:
    """注入：部署失败后的自动回滚本身也失败（previous 被投毒）。
    期望：进入 FUSE_OPEN 熔断（落盘持久）；后续一切 deploy 与 rollback
    拒绝（FuseOpenError，跨 DeployManager 实例仍生效）；current 如实
    停在失败 release；唯一恢复通道是人工 resume_releases（错的恢复
    通道被拒）；修复+恢复后发布恢复。
    """
    root = td / "dep8-root"
    releases, current = root / "releases", root / "current"
    mgr = DeployManager(str(releases), str(current),
                        install_self_check=_doctor_check)
    src_v1 = _mk_app_source(td, "dep8-v1", healthy=True, flag="v1")
    r1 = mgr.deploy(src_v1)
    v1_dir = Path(r1["release_dir"])

    # 投毒 v1：让随后自检失败部署的自动回滚必然失败
    victim = v1_dir / "app.py"
    os.chmod(victim, 0o644)
    victim.write_text("print('poisoned-previous')\n", encoding="utf-8")
    os.chmod(victim, 0o444)

    src_v2 = _mk_app_source(td, "dep8-v2", healthy=False, flag="v2")
    exc = _expect_raise(DeployError, mgr.deploy, str(src_v2))
    _ok("ROLLBACK FAILED" in str(exc),
        f"回滚失败必须如实上报（不静默）: {exc}")
    state = _read_deploy_state(releases)
    _ok(state["status"] == "FUSE_OPEN", f"状态机必须熔断: {state}")
    v2_dir = Path(_real(current))
    _ok("ROLLBACK_FAILED" in json.dumps(state) or state["status"] == "FUSE_OPEN",
        "熔断详情落盘")

    # ---- 熔断期：一切 release 操作拒绝 ----
    src_v3 = _mk_app_source(td, "dep8-v3", healthy=True, flag="v3")
    exc = _expect_raise(FuseOpenError, mgr.deploy, str(src_v3))
    _ok("resume_releases" in str(exc), f"必须指引人工恢复通道: {exc}")
    exc = _expect_raise(FuseOpenError, mgr.rollback, str(current), str(v1_dir))
    _ok("fused" in str(exc) or "fuse" in str(exc).lower(),
        f"熔断期直接回滚同样拒绝: {exc}")

    # 跨实例仍熔断（状态落盘于 releases 根，非进程内）
    mgr_fresh = DeployManager(str(releases), str(current),
                              install_self_check=_doctor_check)
    _expect_raise(FuseOpenError, mgr_fresh.deploy, str(src_v3))

    # ---- 错误恢复通道被拒 ----
    exc = _expect_raise(DeployError, mgr.acknowledge_failed_block,
                        operator="oops")
    _ok("no FAILED_BLOCKED" in str(exc),
        f"FAILED_BLOCKED 通道不能解 FUSE_OPEN: {exc}")

    # ---- 修复 + 人工 resume → 发布恢复 ----
    os.chmod(victim, 0o644)
    victim.write_text("print('app')\n", encoding="utf-8")
    os.chmod(victim, 0o444)
    state = mgr.resume_releases(operator="sre-lead", note="v1 repaired")
    _ok(state["status"] == "RESUMED" and state.get("resumed_by") == "sre-lead",
        f"人工恢复必须留痕: {state}")
    r3 = mgr.deploy(src_v3)
    _ok(r3["deployed"] is True, "恢复后健康发布必须成功")
    _ok(_real(current) == _real(r3["release_dir"]), "current 切到 v3")
    _ok(_read_deploy_state(releases)["status"] == "ACTIVE", "状态回 ACTIVE")


# ---------------------------------------------------------------------- #
# DEP-09｜观察窗内夹带 contract/down migration → 拒绝
# ---------------------------------------------------------------------- #
def test_DEP_09_observation_window_contract_down_migration_rejected(
        td: Path) -> None:
    """注入：激活观察窗内的 release 夹带 contract/down migration。
    期望：拒绝（ObservationWindowError，要求独立 ddl_contract 授权）；
    窗内 expand 迁移（持 ddl 授权）照常放行（不误伤非 contract 面）；
    独立授权的 contract 变更可进；观察窗过期后恢复常规通道。
    """
    ring = ApprovalKeyring.generate("key_ops")
    root = td / "dep9-root"
    releases, current = root / "releases", root / "current"
    mgr = DeployManager(str(releases), str(current), auth_keyring=ring,
                        observation_seconds=3600)   # 长窗：测试期内必在窗中
    src_v1 = _mk_app_source(td, "dep9-v1", flag="v1")
    mgr.deploy(src_v1)
    v1_real = _real(current)

    lock = MigrationLock.acquire(str(td / "dep9.mig.lock"))
    proof = _mk_backup_proof(td, "dep9")

    src_contract = _mk_mig_source(td, "dep9-contract", migrations={
        "001_contract_drop.sql": "-- phase: contract\nDROP INDEX idx_t;\n"})
    exc = _expect_raise(ObservationWindowError, mgr.deploy, str(src_contract),
                        migration_lock=lock, backup_proof=proof)
    _ok("observation window" in str(exc) and "ddl_contract" in str(exc),
        f"窗内 contract 必须拒绝并要求独立授权: {exc}")
    _ok(exc.contraband == ["migrations/001_contract_drop.sql"],
        f"违禁件必须精确指认: {exc.contraband}")
    _ok(exc.remaining_seconds > 3500, "剩余窗时必须如实携带")
    _ok(_real(current) == v1_real, "拒绝后 current 仍在 v1")

    src_down = _mk_mig_source(td, "dep9-down", migrations={
        "002_revoke.down.sql": "-- revoke migration\nDELETE FROM t;\n"})
    exc = _expect_raise(ObservationWindowError, mgr.deploy, str(src_down),
                        migration_lock=lock, backup_proof=proof)
    _ok(any(p.endswith("002_revoke.down.sql") for p in exc.contraband),
        f"down migration（文件名甄别）同样拒绝: {exc.contraband}")
    _ok(_real(current) == v1_real, "down 拒绝后 current 仍在 v1")

    # 混夹带（expand+contract 同包）：即便 expand 授权齐备也必须拒
    src_mixed = _mk_mig_source(td, "dep9-mixed", migrations={
        "001_expand_ok.sql": "-- phase: expand\nALTER TABLE t ADD c INT;\n",
        "002_contract_bad.sql": "-- phase: contract\nDROP INDEX idx_t;\n"})
    mixed_info = mgr.build(src_mixed)
    mixed_env = _mk_auth_env(ring, "key_ops", "ddl",
                             {"content_digest": mixed_info["content_digest"]})
    exc = _expect_raise(ObservationWindowError, mgr.deploy, str(src_mixed),
                        migration_lock=lock,
                        backup_proof=_mk_backup_proof(
                            td, "dep9-mixed",
                            content_digest=mixed_info["content_digest"]),
                        expand_authorization=mixed_env)
    _ok(any("contract" in p for p in exc.contraband),
        f"混夹带必须按 contract 拒绝（授权救不了 contract）: {exc.contraband}")
    _ok(_real(current) == v1_real, "混夹带拒绝后 current 仍在 v1")

    # ---- 窗内正例A：纯 expand（授权齐备）放行——不误伤 ----
    src_expand = _mk_mig_source(td, "dep9-expand", migrations={
        "001_expand.sql": "-- phase: expand\nALTER TABLE t ADD c INT;\n"})
    exp_info = mgr.build(src_expand)
    r_exp = mgr.deploy(str(src_expand), migration_lock=lock,
                       backup_proof=_mk_backup_proof(
                           td, "dep9-expand",
                           content_digest=exp_info["content_digest"]),
                       expand_authorization=_mk_auth_env(
                           ring, "key_ops", "ddl",
                           {"content_digest": exp_info["content_digest"]}))
    _ok(r_exp["deployed"] is True, "窗内纯 expand（授权齐备）必须放行")

    # ---- 窗内正例B：contract + 独立 ddl_contract 授权 → 放行 ----
    src_contract2 = _mk_mig_source(td, "dep9-contract2", migrations={
        "001_contract_drop.sql": "-- phase: contract\nDROP INDEX idx_t2;\n"})
    c2_info = mgr.build(src_contract2)
    r_c2 = mgr.deploy(str(src_contract2), migration_lock=lock,
                      backup_proof=_mk_backup_proof(
                          td, "dep9-contract2",
                          content_digest=c2_info["content_digest"]),
                      contract_authorization=_mk_auth_env(
                          ring, "key_ops", "ddl_contract",
                          {"content_digest": c2_info["content_digest"]}))
    _ok(r_c2["deployed"] is True, "独立 ddl_contract 授权必须放行")

    # 对抗：ddl（而非 ddl_contract）类型授权救不了 contract
    src_contract3 = _mk_mig_source(td, "dep9-contract3", migrations={
        "001_contract_drop.sql": "-- phase: contract\nDROP INDEX idx_t3;\n"})
    c3_info = mgr.build(src_contract3)
    exc = _expect_raise(ObservationWindowError, mgr.deploy, str(src_contract3),
                        migration_lock=lock,
                        backup_proof=_mk_backup_proof(
                            td, "dep9-contract3",
                            content_digest=c3_info["content_digest"]),
                        contract_authorization=_mk_auth_env(
                            ring, "key_ops", "ddl",
                            {"content_digest": c3_info["content_digest"]}))
    _ok("ddl_contract" in str(exc), "错误类型的授权不得放行 contract")

    # ---- 观察窗过期：恢复常规通道（不再以观察窗拒绝）----
    mgr_short = DeployManager(str(releases), str(current), auth_keyring=ring,
                              observation_seconds=0.4)
    time.sleep(0.5)
    r_after = mgr_short.deploy(str(src_contract3), migration_lock=lock,
                               backup_proof=_mk_backup_proof(
                                   td, "dep9-after",
                                   content_digest=c3_info["content_digest"]))
    _ok(r_after["deployed"] is True,
        "观察窗过期后 contract 走常规通道（迁移门）不再被观察窗拒绝")
    _ok(_real(current) == _real(r_after["release_dir"]), "current 切到新 release")


# ---------------------------------------------------------------------- #
# 运行器
# ---------------------------------------------------------------------- #
def _collect_tests() -> List[Tuple[str, Callable[[Path], None]]]:
    import re
    name_re = re.compile(r"^test_(REL|DEP|RB)_(\d{2})_")
    return [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn) and name_re.match(name)
    ]


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    json_out: Optional[str] = None
    if "--json" in argv:
        json_out = argv[argv.index("--json") + 1]
    import re
    name_re = re.compile(r"^test_(REL|DEP|RB)_(\d{2})_")

    tests = _collect_tests()
    print("=" * 72)
    print(f"§20 DEP/RB/REL 族专属验收测试（实现 {len(tests)} 条；"
          f"跳过 {len(NOT_IMPLEMENTABLE)} 条见 NOT_IMPLEMENTABLE 登记表）")
    for tid, reason in NOT_IMPLEMENTABLE.items():
        print(f"  SKIP {tid}: {reason}")
    print("-" * 72)
    records: List[Dict[str, Any]] = []
    failed: List[str] = []
    for name, fn in tests:
        match = name_re.match(name)
        assert match is not None
        test_id = f"{match.group(1)}-{match.group(2)}"
        with tempfile.TemporaryDirectory(prefix="ac-deploy-release-") as td:
            try:
                fn(Path(td))
                records.append({"id": test_id, "test": name, "passed": True})
                print(f"  PASS {test_id}  {name}")
            except Exception as exc:  # noqa: BLE001
                import traceback
                traceback.print_exc()
                failed.append(name)
                records.append({"id": test_id, "test": name, "passed": False})
                print(f"  FAIL {test_id}  {name}: {type(exc).__name__}: {exc}")
    print("-" * 72)
    print(f"结果: {len(records) - len(failed)}/{len(records)} passed"
          f"{'' if not failed else '；失败: ' + ', '.join(failed)}")
    out_path = Path(json_out) if json_out else ARTIFACT_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"逐 ID 结果已写: {out_path}")
    print("=" * 72)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

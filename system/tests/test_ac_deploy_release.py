#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§20 验收 ID 专属测试——DEP-01~09 / RB-01 / REL-01~03（部署、回滚、发布）。

正源（逐字对齐）：
    evidence/00-baseline/codex-external/方案.md §20.4（REL-01~03）与
    §20.5（DEP-01~09、RB-01）表格的「注入/期望」列。

被测体（不改动任何产品码；本文件为唯一新增测试文件）：
    system/wenqu_core/deploy_framework.py
        DeployManager：build（不可变 release + manifest D1/D4）/ verify
        （缺件/多件/哈希漂移/mode 漂移对账）/ switch（D3 原子 symlink）/
        rollback（先验旧版完好再切回）/ deploy（D2 自检失败=部署失败并
        自动回滚+回滚后复验）——覆盖 REL-01/02/03、DEP-03、RB-01 的
        「错误旧版本」腿。
    system/wenqu_core/wenqu_pipeline.py + approval_keys.py
        RunManager.reserve_action（F4-AUTH-001：action 预留必须消费对应
        类型 HMAC 审批，无授权/类型不符一律拒绝且零落账）——覆盖 RB-01
        的「无预授权自动回滚」腿（rollback 属封闭 action_type）。
    system/wenqu_core/store.py
        EventStore（pipeline_events append-only 哈希链）——DEP-03 的
        「新事件」正源：回滚切换绝不触碰事件账本。

可实现性裁定（诚实优先，不硬凑、不 xfail、不假绿）：
    本文件对 13 个 ID 中的 5 个给出专属真实测试（真实 tmp 目录构建、
    真实 SIGKILL 子进程、真实 HMAC 签名审批、真实 sqlite 事件账本）：
        REL-01 / REL-02 / REL-03 / DEP-03 / RB-01
    其余 8 个（DEP-01/02/04/05/06/07/08/09）在被测体与全仓产品码中
    没有对应可执行语义——逐条理由见模块级 NOT_IMPLEMENTABLE 登记
    （含 grep/通读证据），测试运行时显式输出，不以 skip 冒充通过。

覆盖边界（同样显式登记，不冒充完整验收面）：
    REL-03 的「doctor」= DeployManager 的 install_self_check 安装自检钩子
    （D2 契约面）；install.sh/hardening-doctor.sh 的安装期 doctor 面由
    test_infra_hardening.py F 节覆盖，本文件不重复。
    RB-01 完整语义 = 预授权腿（wenqu_pipeline F4-AUTH-001）+ 错误旧版本腿
    （deploy_framework rollback 完好性对账）双腿拼合；deploy_framework
    本身的 D2 契约是「自检失败自动回滚」（与 fenced 部署的「无预授权不得
    回滚」是两个不同层的产品决策，后者运行态语义未实现，见登记表）。

独立运行：python3 system/tests/test_ac_deploy_release.py [--json OUT.json]
exit 0 = 全部已实现用例绿；默认把逐 ID 结果写入
evidence/04-unit-property-mutation/ac-deploy-release.json。
"""
from __future__ import annotations

import json
import os
import shutil
import signal
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

from wenqu_core.approval_keys import ApprovalKeyring, sign_envelope  # noqa: E402
from wenqu_core.deploy_framework import (  # noqa: E402
    BuildError,
    DeployError,
    DeployManager,
    SelfCheckError,
    SwitchError,
    VerifyError,
)
from wenqu_core.store import EventStore  # noqa: E402
from wenqu_core.wenqu_pipeline import (  # noqa: E402
    ActionError,
    ApprovalRejected,
    RunManager,
)

ARTIFACT_PATH = REPO_ROOT / "evidence" / "04-unit-property-mutation" / "ac-deploy-release.json"

# ---------------------------------------------------------------------- #
# 不可实现登记表（模块级；语义在产品码中不存在，非测试跳过、不 xfail）
# ---------------------------------------------------------------------- #
NOT_IMPLEMENTABLE: Dict[str, str] = {
    "DEP-01": (
        "「两个部署者争 lease→最多一个成功」：DeployManager 无 lease/互斥原语——"
        "全仓 system/（wenqu_core/*.py、daemons/、install.sh）无 lease/flock/"
        "部署锁语义（grep 实证）；switch() 仅单次 os.replace 原子，两次并发 "
        "deploy 不同内容各建 release 后先后 switch（后者胜），无『最多一个"
        "成功』仲裁可注入。"),
    "DEP-02": (
        "「smoke 访问生产 DB/state→隔离拒绝」：产品无部署后 smoke runner 与"
        "隔离层（全仓 grep 无 smoke 语义）；install_self_check 钩子只收 "
        "release_dir 一个参数，无 DB/state 访问边界或沙箱判定。"),
    "DEP-04": (
        "「自签/替换/revoked release key→拒绝」：release 签名体系未实现——"
        "manifest.json 无 signature/key 字段，build/verify 只做 SHA256 内容与"
        " mode 对账（deploy_framework D1/D4），无 release key 验证语义；"
        "approval_keys.py 的 HMAC 属审批 envelope 域，非 release 域。"
        "（SBOM/签名按工单预告属未实现面。）"),
    "DEP-05": (
        "「previous release 超 schema 范围→拒绝回滚」：manifest 无 "
        "schema_version/版本范围字段，rollback() 只做完好性对账（missing/"
        "extra/drift/mode），无 schema 范围判定；『未来 schema manifest』在 "
        "verify 中以未设计异常（KeyError/ValueError）崩溃而非设计内拒绝，"
        "不冒充通过。"),
    "DEP-06": (
        "「无迁移锁/未验证备份/expand 超授权→激活前 BLOCKED」：deploy_framework"
        " 无迁移锁/备份验证/expand 授权语义（switch 前仅 manifest 对账）；"
        "wenqu_pipeline 的 ddl 审批 payload 字段只是授权账本 schema，无部署"
        "激活前的迁移门执行体。"),
    "DEP-07": (
        "「ACTIVATING 失败且无预授权→FAILED_BLOCKED；不得自动回滚」：产品无 "
        "ACTIVATING/FAILED_BLOCKED 部署状态机；deploy_framework D2 契约恰为"
        "『自检失败自动回滚到上一版』——与该 ID『不得自动回滚』的 fenced "
        "语义相反，不可反向断言硬凑。"),
    "DEP-08": (
        "「ROLLBACK_FAILED→writer/merge/release 熔断并停等人工恢复」：回滚失败"
        "仅如实上报（DeployError 消息含 ROLLBACK FAILED、current 留在失败版），"
        "无 writer/merge/release 熔断器与停等人工恢复语义（后续 deploy 不受"
        "阻断）。"),
    "DEP-09": (
        "「观察窗内夹带 contract/down migration→拒绝；要求独立授权变更」："
        "部署面无观察窗（observation window）概念，也不解析/甄别 release 内"
        " migration 文件内容，无对应拒绝语义。"),
}

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

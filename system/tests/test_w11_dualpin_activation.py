#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W11-03｜双 pin 激活事务与真实回滚状态机——专属验收测试（先红后绿）。

正源（逐字对齐）：
    /private/tmp/wq11-plan.md「W11-03｜双 pin 激活事务与真实回滚状态机」
    （L294 起）+ R10-REL-ROLLBACK-DUAL-PIN-005。

被测体：
    system/install-release.sh（主载体——激活/回滚全链）
    system/wenqu_core/release_state.py（新增——activation-state-v2 journal）

覆盖矩阵（任务 A/B/C/D）：
    A  激活 journal：
       - current 切换前「目标树全量 verify 通过」写入 journal（PREPARED）；
       - 四阶段 PREPARED→SYMLINK_SWITCHED→SMOKE_OK→COMMITTED 分阶段落盘；
       - journal 损坏/截断/篡改/链接/越根 → 检测 + BLOCKED（rc3 熔断）；
       - 每个 journal 阶段 kill -9 后只能恢复至 old 或 new（第三态熔断 rc3）。
    B  回滚目标健康管理：
       - 每次激活后对 .last-current 目标树全树对账，健康态落 journal；
       - 漂移目标标记 rollback_unavailable + ALARM；
       - 回滚入口拒用坏目标并点名 rollback_unavailable（rc1）；
       - 伪造 .last-current 指向漂移树 → rc1 拒 + 点名。
    C  真实回滚闭环三态：
       - 健康目标回滚 rc0；漂移目标拒 rc1；roll-forward rc0；双 pin 交换。
    D  附加防线（方案项 2/3/7 与验收行）：
       - 唯一 deploy lease/flock：并发安装最多一个提交；
       - 正向安装要求 current 也在 roots（roots 只有 target → 拒）；
       - 正向安装要求 current 树无漂移（漂移 → 拒，提示 recover-drift）；
       - current 树漂移不得冒充正常 rollback；独立 --recover-drift 保全现场
         并形成新 epoch；
       - rollback 无 journal（legacy 态）拒绝。

环境：测试自建微型 git 仓（两 commit + 冻结方案快照字节），真实跑
install-release.sh 全链（build/sign/sbom/verify/部署/切换/冒烟），不 mock。

独立运行：python3 -m pytest system/tests/test_w11_dualpin_activation.py -v
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
SYSTEM_DIR = HERE.parent
REPO_ROOT = SYSTEM_DIR.parent
INSTALL_SH = SYSTEM_DIR / "install-release.sh"
RELEASE_STATE = SYSTEM_DIR / "wenqu_core" / "release_state.py"
TOOL = REPO_ROOT / "tools" / "release_attest.py"
FIXTURE_KEYRING = HERE / "fixtures" / "approval-keys.json"
PLAN_MEMBER_REL = "evidence/00-baseline/codex-external/方案.md"

JOURNAL_NAME = "activation-state-v2.json"
WATERMARK_NAME = ".activation-epoch.json"
LEASE_NAME = ".deploy-lease.lock"

NON_TERMINAL = ("PREPARED", "SYMLINK_SWITCHED", "SMOKE_OK")


def _ok(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)


# ---------------------------------------------------------------------- #
# session 级装备：微型 git 仓（两 commit）+ keyring(0600) + roots(0600)
# ---------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def rig(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    base = tmp_path_factory.mktemp("w11-rig")
    repo = base / "repo"

    # 微型仓：system/ + tools/ + 冻结方案快照（字节必须与冻结正源一致，
    # 否则 release_attest build fail-closed）。
    shutil.copytree(SYSTEM_DIR, repo / "system",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(REPO_ROOT / "tools", repo / "tools",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (repo / "evidence/00-baseline/codex-external").mkdir(parents=True)
    shutil.copyfile(REPO_ROOT / PLAN_MEMBER_REL, repo / PLAN_MEMBER_REL)
    (repo / "README.md").write_text("w11-03 test repo\n", encoding="utf-8")

    def _git(*args: str) -> str:
        env = dict(os.environ)
        env.update({"GIT_AUTHOR_NAME": "w11", "GIT_AUTHOR_EMAIL": "w11@test",
                    "GIT_COMMITTER_NAME": "w11", "GIT_COMMITTER_EMAIL": "w11@test"})
        r = subprocess.run(["git", "-C", str(repo), *args],
                           capture_output=True, text=True, env=env, timeout=120)
        _ok(r.returncode == 0, f"git {args} 失败: {r.stderr}")
        return r.stdout.strip()

    _git("init", "-q", "-b", "main")
    _git("add", "-A")
    _git("commit", "-qm", "A: baseline tree")
    sha_a = _git("rev-parse", "HEAD")
    with open(repo / "system" / "VERSION", "a", encoding="utf-8") as fh:
        fh.write("w11-B\n")
    _git("add", "-A")
    _git("commit", "-qm", "B: version bump")
    sha_b = _git("rev-parse", "HEAD")

    # 预产两 commit 的 manifest → roots（manifest_sha256 = manifest 核心 digest）
    prebuild = base / "prebuild"
    for sha in (sha_a, sha_b):
        r = subprocess.run(
            [sys.executable, str(TOOL), "build", "--commit", sha,
             "--out-dir", str(prebuild), "--repo", str(repo)],
            capture_output=True, text=True, timeout=300)
        _ok(r.returncode == 0, f"预产 manifest 失败({sha[:8]}): {r.stderr[-300:]}")
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    spec = importlib.util.spec_from_file_location("ra", str(TOOL))
    ra = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ra)
    entries, plan_sha = [], ""
    for mf in sorted(prebuild.glob("*.manifest.json")):
        m = json.loads(mf.read_text(encoding="utf-8"))
        entries.append({"commit": m["source_commit"],
                        "manifest_sha256": ra._manifest_core_digest(m)})
        plan_sha = m["policy_hash"]["plan_sha256"]
    roots = base / "release-roots.json"
    roots.write_text(json.dumps({
        "schema": "wenqu-release-roots/1",
        "plan_sha256": plan_sha,
        "allowed_commit": entries}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    os.chmod(roots, 0o600)

    keyring = base / "keyring.json"
    shutil.copyfile(FIXTURE_KEYRING, keyring)
    os.chmod(keyring, 0o600)

    # 只含 B 的 roots（负例：roots 只有 target、没有 current）
    roots_only_b = base / "release-roots-only-b.json"
    roots_only_b.write_text(json.dumps({
        "schema": "wenqu-release-roots/1",
        "plan_sha256": plan_sha,
        "allowed_commit": [e for e in entries if e["commit"] == sha_b]},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(roots_only_b, 0o600)

    return SimpleNamespace(base=base, repo=repo, sha_a=sha_a, sha_b=sha_b,
                           roots=roots, roots_only_b=roots_only_b,
                           keyring=keyring)


# ---------------------------------------------------------------------- #
# e2e 小工具
# ---------------------------------------------------------------------- #
def run_install(iroot: Path, rig: SimpleNamespace, *extra: str, commit: str = "",
                env_extra: dict | None = None,
                timeout: int = 300) -> subprocess.CompletedProcess:
    argv = ["bash", str(INSTALL_SH)]
    if commit:
        argv.append(commit)
    argv += ["--repo", str(rig.repo), "--keyring", str(rig.keyring),
             "--install-root", str(iroot),
             "--release-roots", str(rig.roots), *extra]
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, env=env)


def out_of(p: subprocess.CompletedProcess) -> str:
    return (p.stdout or "") + (p.stderr or "")


def journal_path(iroot: Path) -> Path:
    return iroot / JOURNAL_NAME


def read_journal(iroot: Path) -> dict | None:
    p = journal_path(iroot)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def real_current(iroot: Path) -> str:
    return os.path.realpath(str(iroot / "current"))


def tree_of(iroot: Path, sha: str) -> Path:
    return iroot / "releases" / sha / "tree"


def _read_first(iroot: Path, sha: str, rel: str) -> bytes:
    return (tree_of(iroot, sha) / rel).read_bytes()


def _write_tree_file(iroot: Path, sha: str, rel: str, data: bytes) -> None:
    p = tree_of(iroot, sha) / rel
    os.chmod(p, 0o644)
    p.write_bytes(data)
    os.chmod(p, 0o444)


def drift_tree_file(iroot: Path, sha: str, rel: str = "README.md") -> bytes:
    """对已部署树注入漂移（改写一个清单内文件），返回原始字节。"""
    orig = _read_first(iroot, sha, rel)
    _write_tree_file(iroot, sha, rel, orig + b"\ndrifted-by-w11-test\n")
    return orig


def restore_tree_file(iroot: Path, sha: str, rel: str, orig: bytes) -> None:
    _write_tree_file(iroot, sha, rel, orig)


def release_state(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(RELEASE_STATE), *args],
                          capture_output=True, text=True, timeout=120)


# ---------------------------------------------------------------------- #
# 1) 单元面：release_state.py journal 状态机/完整性/健康管理
# ---------------------------------------------------------------------- #
def _mk_fake_release(iroot: Path, sha: str) -> Path:
    """在 iroot/releases/<40hex>/tree 造一个带 manifest 的微型 release。"""
    rel = iroot / "releases" / sha
    tree = rel / "tree"
    (tree / "system").mkdir(parents=True)
    (tree / "system" / "VERSION").write_text(sha[:8] + "\n", encoding="utf-8")
    (tree / "app.py").write_text("print('app')\n", encoding="utf-8")
    files = []
    for p in sorted(tree.rglob("*")):
        relpath = p.relative_to(tree).as_posix()
        if p.is_file():
            import hashlib
            files.append({"path": relpath, "type": "file", "size": p.stat().st_size,
                          "mode": p.stat().st_mode & 0o777,
                          "sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
    manifest = rel / "wenqu-dist-abc1234.manifest.json"
    manifest.write_text(json.dumps({"schema": "test", "files": files},
                                   ensure_ascii=False, indent=1), encoding="utf-8")
    return tree


def test_w11_unit_journal_state_machine_and_integrity(td: Path) -> None:
    """journal 四阶段推进/TOCTOU generation 守卫/损坏-截断-篡改-链接-越根全拒。"""
    import hashlib

    iroot = td / "iroot"
    iroot.mkdir()
    cur_link = iroot / "current"
    sha = "a" * 40
    tree = _mk_fake_release(iroot, sha)
    os.symlink(tree, cur_link)

    R = ["--install-root", str(iroot)]
    # begin（无 current 链接时首装：previous=None）
    os.unlink(cur_link)
    r = release_state("begin", *R, "--kind", "install",
                      "--target-tree", str(tree))
    _ok(r.returncode == 0, f"begin 失败: {r.stderr}")
    j = json.loads(journal_path(iroot).read_text(encoding="utf-8"))
    _ok(j["state"] == "PREPARED" and j["generation"] == 1,
        f"begin 必须落 PREPARED/generation=1: {j.get('state')}/{j.get('generation')}")
    _ok(j["target"]["sha"] == sha and j["target"]["tree_digest"],
        "begin 必须记录目标 sha + 全树实算 digest（verify 通过的证据）")

    # 非法跳段：PREPARED → SMOKE_OK 拒
    r = release_state("advance", *R, "--state", "SMOKE_OK",
                      "--expect-generation", "1")
    _ok(r.returncode == 1, f"跳段必须 rc1: rc={r.returncode}")

    # TOCTOU：expect-generation 不匹配拒
    r = release_state("advance", *R, "--state", "SYMLINK_SWITCHED",
                      "--expect-generation", "99")
    _ok(r.returncode == 1, f"generation 不匹配必须 rc1: rc={r.returncode}")

    # 正常推进 → SYMLINK_SWITCHED → SMOKE_OK → commit（指针守卫：current==target）
    os.symlink(tree, cur_link)
    for st in ("SYMLINK_SWITCHED", "SMOKE_OK"):
        r = release_state("advance", *R, "--state", st,
                          "--expect-generation", "1")
        _ok(r.returncode == 0, f"advance {st} 失败: {r.stderr}")
    r = release_state("commit", *R, "--expect-generation", "1",
                      "--current-link-expected", str(tree))
    _ok(r.returncode == 0, f"commit 失败: {r.stderr}")
    j = json.loads(journal_path(iroot).read_text(encoding="utf-8"))
    _ok(j["state"] == "COMMITTED" and j["epoch"] == 1
        and j["current"]["sha"] == sha,
        f"commit 必须换 pin+epoch+1: {j.get('state')}/{j.get('epoch')}")
    _ok(j["generation"] == 1, "commit 不得另起 generation")

    # commit 指针 TOCTOU：current 与预期不符拒
    r = release_state("commit", *R, "--expect-generation", "1",
                      "--current-link-expected", str(td / "elsewhere"))
    _ok(r.returncode == 1, f"指针不符的 commit 必须 rc1: rc={r.returncode}")

    # journal 权限纪律 + 完整性
    mode = os.stat(journal_path(iroot)).st_mode & 0o7777
    _ok(mode & 0o077 == 0, f"journal 必须 owner-only（>0600 即拒写）: {oct(mode)}")
    raw = journal_path(iroot).read_text(encoding="utf-8")
    body = json.loads(raw)
    integ = body.pop("integrity", None)
    _ok(isinstance(integ, str) and re.fullmatch(r"[0-9a-f]{64}", integ or ""),
        "journal 必须携带 64hex integrity 自洽哈希")
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False)
    _ok(hashlib.sha256(canon.encode("utf-8")).hexdigest() == integ,
        "integrity 必须等于正文 canonical sha256（损坏/篡改检测基础）")

    # 损坏三形态 → status rc3（熔断 BLOCKED）
    for label, mutate in (
        ("truncated", lambda t: t[: len(t) // 2]),
        ("tampered", lambda t: t.replace(f'"epoch": {j["epoch"]}',
                                         f'"epoch": {j["epoch"] + 5}', 1)),
        ("garbage", lambda t: "{not json"),
    ):
        journal_path(iroot).write_text(mutate(raw), encoding="utf-8")
        r = release_state("status", *R)
        _ok(r.returncode == 3,
            f"{label} journal 必须 status rc3（BLOCKED）: rc={r.returncode}")

    # 链接形态（symlink 顶替 journal）→ rc3
    good = json.loads(raw)
    journal_path(iroot).write_text(raw, encoding="utf-8")
    os.chmod(journal_path(iroot), 0o600)
    tmp_j = iroot / "journal.copy"
    tmp_j.write_text(raw, encoding="utf-8")
    journal_path(iroot).unlink()
    os.symlink(tmp_j, journal_path(iroot))
    r = release_state("status", *R)
    _ok(r.returncode == 3, f"symlink journal 必须 rc3: rc={r.returncode}")
    os.unlink(journal_path(iroot))
    journal_path(iroot).write_text(raw, encoding="utf-8")
    os.chmod(journal_path(iroot), 0o600)

    # 越根：target-tree 不在 releases 根下 → begin rc1
    r = release_state("begin", *R, "--kind", "install",
                      "--target-tree", str(td / "outside" / "tree"))
    _ok(r.returncode == 1, f"越根 target 必须 begin rc1: rc={r.returncode}")

    # 事务在途：非终态 journal 上再次 begin → rc1
    j2 = json.loads(journal_path(iroot).read_text(encoding="utf-8"))
    j2["state"] = "PREPARED"
    j2.pop("integrity")
    j2["integrity"] = hashlib.sha256(json.dumps(
        j2, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")).hexdigest()
    journal_path(iroot).write_text(json.dumps(j2, ensure_ascii=False),
                                   encoding="utf-8")
    os.chmod(journal_path(iroot), 0o600)
    r = release_state("begin", *R, "--kind", "install",
                      "--target-tree", str(tree))
    _ok(r.returncode == 1 and "recover" in out_of(r),
        f"在途事务再 begin 必须 rc1 并指引 recover: rc={r.returncode}")

    # watermark 存在而 journal 被删 → status rc3（journal 删除检测）
    j2["state"] = "SMOKE_OK"
    j2.pop("integrity")
    j2["integrity"] = hashlib.sha256(json.dumps(
        j2, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")).hexdigest()
    journal_path(iroot).write_text(json.dumps(j2, ensure_ascii=False),
                                   encoding="utf-8")
    os.chmod(journal_path(iroot), 0o600)
    release_state("commit", *R, "--expect-generation", "1",
                  "--current-link-expected", str(tree))  # 落 watermark
    journal_path(iroot).unlink()
    r = release_state("status", *R)
    _ok(r.returncode == 3,
        f"watermark 存在而 journal 缺失必须 rc3（删除检测）: rc={r.returncode}")


def test_w11_unit_recover_decision_and_health(td: Path) -> None:
    """recover 三态收敛判定 + check-rollback 健康管理（healthy/漂移/伪造指针）。"""
    iroot = td / "iroot"
    iroot.mkdir()
    sha_a, sha_b = "a" * 40, "b" * 40
    tree_a = _mk_fake_release(iroot, sha_a)
    tree_b = _mk_fake_release(iroot, sha_b)
    tree_c = _mk_fake_release(iroot, "c" * 40)
    cur = iroot / "current"

    R = ["--install-root", str(iroot)]

    def _begin_b() -> None:
        # 复位到干净态（journal/watermark/指针全清）→ 提交 A 事务 →
        # 开 B 事务并停在 PREPARED（模拟崩溃在途）。
        for p in (journal_path(iroot), iroot / WATERMARK_NAME):
            if p.exists():
                p.unlink()
        if os.path.lexists(cur):
            os.unlink(cur)
        os.symlink(tree_a, cur)
        release_state("begin", *R, "--kind", "install",
                      "--target-tree", str(tree_a))
        release_state("advance", *R, "--state", "SYMLINK_SWITCHED",
                      "--expect-generation", "1")
        release_state("advance", *R, "--state", "SMOKE_OK",
                      "--expect-generation", "1")
        release_state("commit", *R, "--expect-generation", "1",
                      "--current-link-expected", str(tree_a))
        os.unlink(cur)
        os.symlink(tree_b, cur)
        r = release_state("begin", *R, "--kind", "install",
                          "--target-tree", str(tree_b),
                          "--previous-tree", str(tree_a))
        assert r.returncode == 0, r.stderr

    # 形态1：PREPARED + current==target → finish_new
    _begin_b()
    r = release_state("recover", *R)
    _ok(r.returncode == 0 and '"finish_new"' in (r.stdout or ""),
        f"PREPARED+current==target 必须 finish_new: {r.stdout}{r.stderr}")

    # 形态2：PREPARED + current==previous → converge_old
    _begin_b()
    os.unlink(cur)
    os.symlink(tree_a, cur)
    r = release_state("recover", *R)
    _ok(r.returncode == 0 and '"converge_old"' in (r.stdout or ""),
        f"PREPARED+current==previous 必须 converge_old: {r.stdout}{r.stderr}")

    # 形态3：PREPARED + current 指向第三树 → fuse rc3（只许 old/new 两态）
    _begin_b()
    os.unlink(cur)
    os.symlink(tree_c, cur)
    r = release_state("recover", *R)
    _ok(r.returncode == 3 and "fuse" in (r.stdout + r.stderr).lower(),
        f"第三态必须 fuse rc3: rc={r.returncode} {r.stdout}{r.stderr}")

    # 终态 journal → recover none
    _begin_b()
    os.unlink(cur)
    os.symlink(tree_a, cur)
    release_state("recover", *R)  # converge_old 决策
    release_state("abort", *R, "--expect-generation", "2",
                  "--reason", "unit-converge-old")
    r = release_state("recover", *R)
    _ok(r.returncode == 0 and '"none"' in (r.stdout or ""),
        f"终态 journal recover 必须 none: {r.stdout}{r.stderr}")

    # ---- check-rollback 健康管理 ----
    # 健康目标：current=A committed、previous=B 完好 → healthy
    for p in (journal_path(iroot), iroot / WATERMARK_NAME):
        if p.exists():
            p.unlink()
    if os.path.lexists(cur):
        os.unlink(cur)
    os.symlink(tree_a, cur)
    release_state("begin", *R, "--kind", "install",
                  "--target-tree", str(tree_a), "--previous-tree", str(tree_b))
    release_state("advance", *R, "--state", "SYMLINK_SWITCHED",
                  "--expect-generation", "1")
    release_state("advance", *R, "--state", "SMOKE_OK",
                  "--expect-generation", "1")
    release_state("commit", *R, "--expect-generation", "1",
                  "--current-link-expected", str(tree_a))
    r = release_state("check-rollback", *R)
    _ok(r.returncode == 0 and "healthy" in (r.stdout or ""),
        f"健康回滚目标应 verdict=healthy: {r.stdout}{r.stderr}")
    j = json.loads(journal_path(iroot).read_text(encoding="utf-8"))
    _ok(j["health"]["previous_target"]["status"] == "healthy",
        f"健康态必须落 journal: {j.get('health')}")

    # 漂移目标：改 B 树一个文件 → rollback_unavailable + ALARM
    victim = tree_b / "app.py"
    victim.write_text("print('drifted')\n", encoding="utf-8")
    r = release_state("check-rollback", *R)
    _ok("rollback_unavailable" in (r.stdout + r.stderr),
        f"漂移必须点名 rollback_unavailable: {r.stdout}{r.stderr}")
    _ok("ALARM" in (r.stdout + r.stderr), "漂移必须 ALARM 告警")
    j = json.loads(journal_path(iroot).read_text(encoding="utf-8"))
    _ok(j["health"]["previous_target"]["status"] == "rollback_unavailable",
        f"漂移态必须落 journal: {j.get('health')}")
    _ok(j["health"]["previous_target"].get("drifted_files"),
        "漂移文件清单必须落 journal")
    victim.write_text("print('app')\n", encoding="utf-8")

    # 伪造 .last-current：指向与 journal previous 不同的树 → rollback_unavailable
    lc = iroot / "releases" / ".last-current"
    lc.write_text(str(tree_c) + "\n", encoding="utf-8")
    r = release_state("check-rollback", *R)
    _ok("rollback_unavailable" in (r.stdout + r.stderr)
        and "last-current" in (r.stdout + r.stderr).lower(),
        f"伪造 .last-current 必须点名: {r.stdout}{r.stderr}")
    j = json.loads(journal_path(iroot).read_text(encoding="utf-8"))
    _ok(j["health"]["previous_target"]["status"] == "rollback_unavailable",
        "伪造指针必须落 rollback_unavailable")


# ---------------------------------------------------------------------- #
# 2) A｜激活 journal 落盘 + 双 pin 交换（e2e）
# ---------------------------------------------------------------------- #
def test_w11_a_activation_journal_and_dual_pin(td: Path, rig) -> None:
    iroot = td / "iroot"
    p = run_install(iroot, rig, commit=rig.sha_a)
    _ok(p.returncode == 0, f"安装 A 失败: {out_of(p)[-400:]}")
    p = run_install(iroot, rig, commit=rig.sha_b)
    _ok(p.returncode == 0, f"安装 B 失败: {out_of(p)[-400:]}")

    j = read_journal(iroot)
    _ok(j is not None, f"激活后必须存在 {JOURNAL_NAME}")
    _ok(j["schema"] == "activation-state-v2", f"journal schema: {j.get('schema')}")
    _ok(j["state"] == "COMMITTED", f"终态必须 COMMITTED: {j.get('state')}")
    _ok(j["generation"] >= 2, f"两次激活 generation 至少 2: {j.get('generation')}")
    _ok(j["epoch"] >= 2, f"两次激活 epoch 至少 2: {j.get('epoch')}")
    _ok(j["current"]["sha"] == rig.sha_b and j["previous"]["sha"] == rig.sha_a,
        f"双 pin 必须交换（current=B/previous=A）: "
        f"{j.get('current', {}).get('sha', '')[:8]}/{j.get('previous', {}).get('sha', '')[:8]}")
    _ok(j["current"].get("tree_digest") and j["previous"].get("tree_digest"),
        "双 pin 必须各自记录全树 digest")
    _ok(j["current"].get("manifest_sha256") and j["previous"].get("manifest_sha256"),
        "双 pin 必须各自记录 manifest digest")
    _ok(j.get("roots_sha256"), "journal 必须记录 roots digest")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_b)),
        "current 必须指向 B 树")
    _ok((iroot / "releases" / ".last-current").read_text().strip()
        == str(tree_of(iroot, rig.sha_a)),
        ".last-current 必须与 journal previous pin 一致")
    # 激活时健康管理已跑：健康 previous
    _ok(j["health"]["previous_target"]["status"] == "healthy",
        f"激活后必须对 .last-current 目标做健康对账: {j.get('health')}")
    # journal 权限纪律
    mode = os.stat(journal_path(iroot)).st_mode & 0o7777
    _ok(mode & 0o077 == 0, f"journal 必须 owner-only: {oct(mode)}")


# ---------------------------------------------------------------------- #
# 3) A｜journal 损坏/截断/链接 → BLOCKED（rc3）
# ---------------------------------------------------------------------- #
def test_w11_a_journal_corruption_blocked(td: Path, rig) -> None:
    for label in ("truncated", "symlink"):
        iroot = td / f"corrupt-{label}"
        p = run_install(iroot, rig, commit=rig.sha_a)
        _ok(p.returncode == 0, f"[{label}] 前置安装 A 失败: {out_of(p)[-300:]}")
        # 制造在途事务（kill at PREPARED）再损坏
        p = run_install(iroot, rig, commit=rig.sha_b,
                        env_extra={"WENQU_FAILPOINT": "after_prepared"})
        _ok(p.returncode != 0, f"[{label}] failpoint kill 必须非零退出: rc={p.returncode}")
        j = read_journal(iroot)
        _ok(j is not None and j["state"] == "PREPARED",
            f"[{label}] kill 后 journal 必须停在 PREPARED: {j and j.get('state')}")
        if label == "truncated":
            raw = journal_path(iroot).read_text(encoding="utf-8")
            journal_path(iroot).write_text(raw[: len(raw) // 2], encoding="utf-8")
        else:
            raw = journal_path(iroot).read_text(encoding="utf-8")
            keep = iroot / "journal.keep"
            keep.write_text(raw, encoding="utf-8")
            journal_path(iroot).unlink()
            os.symlink(keep, journal_path(iroot))
        p = run_install(iroot, rig, commit=rig.sha_b)
        _ok(p.returncode == 3,
            f"[{label}] journal 损坏必须 rc3 BLOCKED（检测+熔断，不得 rc0 继续）: "
            f"rc={p.returncode}")
        _ok("activation-state" in out_of(p) or "journal" in out_of(p).lower(),
            f"[{label}] rc3 必须点名 journal: {out_of(p)[-300:]}")
        _ok(real_current(iroot) in (str(tree_of(iroot, rig.sha_a)),
                                    str(tree_of(iroot, rig.sha_b))),
            f"[{label}] BLOCKED 后 current 不得指向第三态")


# ---------------------------------------------------------------------- #
# 4) A｜kill -9 恢复矩阵：每阶段崩溃 → 只收敛 old 或 new
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("fp,expect_state,expect_current", [
    ("after_prepared", "PREPARED", "sha_a"),
    ("after_switched", "SYMLINK_SWITCHED", "sha_b"),
    ("after_smoke", "SMOKE_OK", "sha_b"),
])
def test_w11_a_kill_matrix_recovers_to_old_or_new(
        td: Path, rig, fp: str, expect_state: str, expect_current: str) -> None:
    iroot = td / f"kill-{fp}"
    p = run_install(iroot, rig, commit=rig.sha_a)
    _ok(p.returncode == 0, f"[{fp}] 前置安装 A 失败: {out_of(p)[-300:]}")
    p = run_install(iroot, rig, commit=rig.sha_b,
                    env_extra={"WENQU_FAILPOINT": fp})
    _ok(p.returncode != 0, f"[{fp}] failpoint kill 必须被杀（非零）: rc={p.returncode}")
    j = read_journal(iroot)
    _ok(j is not None and j["state"] == expect_state,
        f"[{fp}] kill 后 journal 必须停在 {expect_state}: {j and j.get('state')}")
    expect_tree = str(tree_of(iroot, getattr(rig, expect_current)))
    _ok(real_current(iroot) == expect_tree,
        f"[{fp}] kill 后 current 必须在 {expect_current}: {real_current(iroot)}")
    # 崩溃后重入：恢复只能收敛 old 或 new —— 本例收敛 new（B 健康可冒烟）
    p = run_install(iroot, rig, commit=rig.sha_b)
    _ok(p.returncode == 0,
        f"[{fp}] 恢复重入必须 rc0（幂等恢复/完成提交）: rc={p.returncode} "
        f"{out_of(p)[-400:]}")
    _ok(real_current(iroot) in (str(tree_of(iroot, rig.sha_a)),
                                str(tree_of(iroot, rig.sha_b))),
        f"[{fp}] 恢复后 current 只许 old/new")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_b)),
        f"[{fp}] 健康目标恢复必须收敛 new（B）: {real_current(iroot)}")
    j = read_journal(iroot)
    _ok(j["state"] == "COMMITTED" and j["current"]["sha"] == rig.sha_b,
        f"[{fp}] 恢复后 journal 必须 COMMITTED/current=B: "
        f"{j.get('state')}/{j.get('current', {}).get('sha', '')[:8]}")


def test_w11_a_recovery_fuse_on_foreign_current(td: Path, rig) -> None:
    """在途事务 + current 被换成第三树 → 恢复必须熔断 rc3（无第三态收敛）。"""
    iroot = td / "fuse"
    p = run_install(iroot, rig, commit=rig.sha_a)
    _ok(p.returncode == 0, f"前置安装 A 失败: {out_of(p)[-300:]}")
    p = run_install(iroot, rig, commit=rig.sha_b,
                    env_extra={"WENQU_FAILPOINT": "after_prepared"})
    _ok(p.returncode != 0, "failpoint kill 必须非零")
    # current 换成外来树（第三态）
    foreign = iroot / "releases" / ("9" * 40) / "tree"
    shutil.copytree(tree_of(iroot, rig.sha_a), foreign, dirs_exist_ok=True)
    link = iroot / "current"
    os.unlink(link)
    os.symlink(foreign, link)
    p = run_install(iroot, rig, commit=rig.sha_b)
    _ok(p.returncode == 3,
        f"第三态 current 必须熔断 rc3（不得静默继续）: rc={p.returncode}")


# ---------------------------------------------------------------------- #
# 5) B｜回滚目标健康管理（激活后对账 + 回滚入口拒坏目标 + 伪造指针）
# ---------------------------------------------------------------------- #
def test_w11_b_rollback_refuses_drifted_target_named(td: Path, rig) -> None:
    iroot = td / "drift-target"
    for sha in (rig.sha_a, rig.sha_b):
        p = run_install(iroot, rig, commit=sha)
        _ok(p.returncode == 0, f"安装 {sha[:8]} 失败: {out_of(p)[-300:]}")
    # 对 .last-current 目标（A）注入漂移
    orig = drift_tree_file(iroot, rig.sha_a, "README.md")
    p = run_install(iroot, rig, "--rollback")
    _ok(p.returncode == 1,
        f"漂移回滚目标必须 rc1 拒绝: rc={p.returncode}")
    _ok("rollback_unavailable" in out_of(p),
        f"拒绝必须点名 rollback_unavailable: {out_of(p)[-400:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_b)),
        "拒绝后 current 必须保持 B（绝不切坏目标）")
    j = read_journal(iroot)
    _ok(j["health"]["previous_target"]["status"] == "rollback_unavailable",
        f"回滚入口必须把坏目标健康态落 journal: {j.get('health')}")
    restore_tree_file(iroot, rig.sha_a, "README.md", orig)


def test_w11_b_forged_last_current_refused(td: Path, rig) -> None:
    """伪造 .last-current 指向漂移树 → rollback rc1 拒 + 点名 rollback_unavailable。"""
    iroot = td / "forged"
    for sha in (rig.sha_a, rig.sha_b):
        p = run_install(iroot, rig, commit=sha)
        _ok(p.returncode == 0, f"安装 {sha[:8]} 失败: {out_of(p)[-300:]}")
    # 伪造：把 A 的 release 目录复制成另一个 40hex 目录并对其树注入漂移，
    # 再把 .last-current 指向它（journal previous pin 仍为 A → 指针被顶替）。
    forged_sha = "7" * 40
    shutil.copytree(iroot / "releases" / rig.sha_a,
                    iroot / "releases" / forged_sha, dirs_exist_ok=True)
    victim = iroot / "releases" / forged_sha / "tree" / "README.md"
    os.chmod(victim, 0o644)
    victim.write_bytes(b"forged+drifted\n")
    os.chmod(victim, 0o444)
    (iroot / "releases" / ".last-current").write_text(
        str(iroot / "releases" / forged_sha / "tree") + "\n", encoding="utf-8")
    p = run_install(iroot, rig, "--rollback")
    _ok(p.returncode == 1, f"伪造指针必须 rc1 拒: rc={p.returncode}")
    _ok("rollback_unavailable" in out_of(p),
        f"伪造指针拒绝必须点名 rollback_unavailable: {out_of(p)[-400:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_b)),
        "伪造指针拒绝后 current 必须保持 B")


def test_w11_b_rollback_without_journal_refused(td: Path, rig) -> None:
    """legacy 态（.last-current 存在但无 activation journal）→ rollback 拒绝。"""
    iroot = td / "legacy"
    for sha in (rig.sha_a, rig.sha_b):
        p = run_install(iroot, rig, commit=sha)
        _ok(p.returncode == 0, f"安装 {sha[:8]} 失败: {out_of(p)[-300:]}")
    journal_path(iroot).unlink()
    (iroot / WATERMARK_NAME).unlink()
    p = run_install(iroot, rig, "--rollback")
    _ok(p.returncode != 0,
        f"无 journal 的 legacy 回滚必须拒绝（双 pin 不可核验）: rc={p.returncode}")
    _ok("journal" in out_of(p).lower() or "activation-state" in out_of(p),
        f"拒绝必须点名 journal 缺失: {out_of(p)[-300:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_b)),
        "legacy 拒绝后 current 保持 B")


# ---------------------------------------------------------------------- #
# 6) C｜三态闭环演练：健康 rc0 / 漂移拒 rc1 / roll-forward rc0
# ---------------------------------------------------------------------- #
def test_w11_c_three_state_closed_loop(td: Path, rig) -> None:
    iroot = td / "drill"
    p = run_install(iroot, rig, commit=rig.sha_a)
    _ok(p.returncode == 0, f"安装 A 失败: {out_of(p)[-300:]}")
    p = run_install(iroot, rig, commit=rig.sha_b)
    _ok(p.returncode == 0, f"安装 B 失败: {out_of(p)[-300:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_b)), "current=B")

    # ---- 态2：漂移目标拒 rc1 ----
    orig = drift_tree_file(iroot, rig.sha_a, "README.md")
    p = run_install(iroot, rig, "--rollback")
    _ok(p.returncode == 1, f"[态2] 漂移目标回滚必须 rc1: rc={p.returncode}")
    _ok("rollback_unavailable" in out_of(p), "[态2] 必须点名 rollback_unavailable")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_b)),
        "[态2] current 必须保持 B")

    # ---- 态1：健康目标 rc0（修复漂移后回滚选健康目标）----
    restore_tree_file(iroot, rig.sha_a, "README.md", orig)
    p = run_install(iroot, rig, "--rollback")
    _ok(p.returncode == 0, f"[态1] 健康目标回滚必须 rc0: rc={p.returncode} "
                           f"{out_of(p)[-400:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_a)),
        "[态1] 回滚后 current=A")
    j = read_journal(iroot)
    _ok(j["state"] == "COMMITTED" and j["current"]["sha"] == rig.sha_a
        and j["previous"]["sha"] == rig.sha_b,
        f"[态1] 回滚必须交换双 pin（current=A/previous=B）: "
        f"{j.get('current', {}).get('sha', '')[:8]}/{j.get('previous', {}).get('sha', '')[:8]}")
    _ok((iroot / "releases" / ".last-current").read_text().strip()
        == str(tree_of(iroot, rig.sha_b)),
        "[态1] .last-current 必须翻转为 B（roll-forward 备援）")
    ver = (tree_of(iroot, rig.sha_a) / "system" / "VERSION").read_text(
        encoding="utf-8").strip()
    _ok(ver, "[态1] 回滚位 VERSION 可读")

    # ---- 态3：roll-forward rc0（rollback 复用双 pin 再切回 B）----
    p = run_install(iroot, rig, "--rollback")
    _ok(p.returncode == 0, f"[态3] roll-forward 必须 rc0: rc={p.returncode} "
                           f"{out_of(p)[-400:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_b)),
        "[态3] roll-forward 后 current=B")
    j = read_journal(iroot)
    _ok(j["current"]["sha"] == rig.sha_b and j["previous"]["sha"] == rig.sha_a,
        "[态3] roll-forward 必须再次交换双 pin")
    _ok(j["epoch"] >= 4, f"[态3] 两次回滚各成新 epoch: {j.get('epoch')}")


# ---------------------------------------------------------------------- #
# 7) D｜正向防线：roots 须含 current / current 树漂移拒 / 并发 lease
# ---------------------------------------------------------------------- #
def test_w11_d_forward_refuses_when_current_not_in_roots(td: Path, rig) -> None:
    """roots 只有 target、没有 current → 正向安装拒绝（方案验收行）。"""
    iroot = td / "roots-wo-current"
    p = run_install(iroot, rig, commit=rig.sha_a)
    _ok(p.returncode == 0, f"前置安装 A 失败: {out_of(p)[-300:]}")
    argv = ["bash", str(INSTALL_SH), rig.sha_b,
            "--repo", str(rig.repo), "--keyring", str(rig.keyring),
            "--install-root", str(iroot),
            "--release-roots", str(rig.roots_only_b)]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    _ok(p.returncode == 1,
        f"roots 只含 target 不含 current 必须拒（rc1）: rc={p.returncode}")
    _ok("current" in out_of(p) and "allowed_commit" in out_of(p),
        f"拒绝必须说明 current 不在 roots: {out_of(p)[-400:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_a)),
        "拒绝后 current 保持 A")


def test_w11_d_forward_refuses_when_current_tree_drifted(td: Path, rig) -> None:
    """current 树漂移时不得继续正向安装（提示 recover-drift）。"""
    iroot = td / "cur-drift"
    p = run_install(iroot, rig, commit=rig.sha_a)
    _ok(p.returncode == 0, f"前置安装 A 失败: {out_of(p)[-300:]}")
    orig = drift_tree_file(iroot, rig.sha_a, "README.md")
    p = run_install(iroot, rig, commit=rig.sha_b)
    _ok(p.returncode == 1,
        f"current 树漂移必须拒新激活: rc={p.returncode}")
    _ok("recover-drift" in out_of(p),
        f"拒绝必须指引 recover-drift: {out_of(p)[-400:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_a)),
        "拒绝后 current 保持（漂移现场保全）")
    restore_tree_file(iroot, rig.sha_a, "README.md", orig)


def test_w11_d_concurrent_installers_lease(td: Path, rig) -> None:
    """唯一 deploy lease：lease 被持时安装拒绝；释放后放行。"""
    import fcntl
    iroot = td / "lease"
    iroot.mkdir(parents=True, exist_ok=True)
    lock_path = iroot / LEASE_NAME
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        p = run_install(iroot, rig, commit=rig.sha_a)
        _ok(p.returncode == 1,
            f"lease 被持时安装必须 rc1（并发安装最多一个提交）: rc={p.returncode}")
        _ok("lease" in out_of(p).lower(), f"必须点名 lease: {out_of(p)[-300:]}")
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    p = run_install(iroot, rig, commit=rig.sha_a)
    _ok(p.returncode == 0, f"释放后安装必须 rc0: {out_of(p)[-300:]}")


# ---------------------------------------------------------------------- #
# 8) D｜current 漂移不得冒充正常 rollback；--recover-drift 保全+新 epoch
# ---------------------------------------------------------------------- #
def test_w11_recover_drift_preserves_and_reactivates(td: Path, rig) -> None:
    iroot = td / "recover-drift"
    for sha in (rig.sha_a, rig.sha_b):
        p = run_install(iroot, rig, commit=sha)
        _ok(p.returncode == 0, f"安装 {sha[:8]} 失败: {out_of(p)[-300:]}")
    # current（B）树漂移
    orig = drift_tree_file(iroot, rig.sha_b, "README.md")
    # 正常 rollback：current 已漂移 → 拒绝（不得冒充）
    p = run_install(iroot, rig, "--rollback")
    _ok(p.returncode == 1,
        f"current 漂移时正常 rollback 必须拒: rc={p.returncode}")
    _ok("recover-drift" in out_of(p),
        f"必须指引 recover-drift 通道: {out_of(p)[-400:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_b)),
        "拒绝后漂移 current 原地保全")
    # recover-drift：保全现场 + 切到健康 previous + 新 epoch
    p = run_install(iroot, rig, "--recover-drift")
    _ok(p.returncode == 0,
        f"recover-drift 必须 rc0: rc={p.returncode} {out_of(p)[-500:]}")
    _ok(real_current(iroot) == str(tree_of(iroot, rig.sha_a)),
        "recover-drift 后 current=A（健康目标）")
    quarantine = list((iroot / "releases" / rig.sha_b).glob("tree.drifted-*"))
    _ok(len(quarantine) == 1,
        f"漂移树必须被隔离保全（tree.drifted-*）: "
        f"{[d.name for d in (iroot / 'releases' / rig.sha_b).iterdir()]}")
    _ok(b"drifted-by-w11-test" in (quarantine[0] / "README.md").read_bytes(),
        "隔离树必须保留漂移现场字节（证据不抹除）")
    j = read_journal(iroot)
    _ok(j["current"]["sha"] == rig.sha_a, "recover-drift 后 current pin=A")
    _ok(any(e.get("kind") == "recover_drift" for e in j.get("events", []))
        or j.get("kind") == "recover_drift" or j.get("quarantined_tree"),
        f"journal 必须留痕 recover_drift/隔离路径: {j.get('kind')} "
        f"{j.get('quarantined_tree')}")

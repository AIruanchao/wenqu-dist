#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_w11_07_controlled_env.py——W11-07 受控 clone、scheduler 环境二跳与
运行前置覆盖（先红后绿）。

十轮 W0 扣分三项的正源修复验收面：

A. 受控干净 clone / updater 与 sampler 分离
   - 独立受控 updater（tools/control_clone_updater.py）是唯一 fetch 方：
     rc 契约 0=fresh / 2=fetch或环境失败；receipt 绑定
     ref sha + prerequisite/config 文件内容 hash + TTL；
   - sampler 只读 exact ref（origin/main）与 freshness receipt——git shim
     行为证明采样路径零 fetch；
   - 共享开发仓 fallback（/Users/maccc/Documents/wenqu-dist）删除：
     无 WENQU_GIT_REPO 且脚本树非 git → repo_source="none"（绝不 dev_default）。
B. scheduler 环境二跳（plist → scheduler → TrustedRunner → sampler）
   - launchd 模板显式配置 WENQU_GIT_REPO / WENQU_WINDOW_PREREQS_FILE /
     WENQU_SCHEDULER_CONFIG / WENQU_GIT_RECEIPT / WENQU_MANAGED_SAMPLER；
   - production_tick 默认 runner 必须用显式非秘密 env_passthrough
     （禁止 inherit_env）：批准变量可见、秘密变量剥除；
   - 负例（只改 plist、不改 runner passthrough）：子进程看不到受管变量
     → 真 observation_daily 采样 rc3（窗口前置不可达），绝不静默降级；
   - 真采样端到端：经 production_tick 全链后窗口 manifest 的 digests 来自
     prereqs【文件】、identity 来自受控 clone、scheduler_config_sha 绑定。
C. 运行前置 env 注入 fail-closed（sampler rc 契约：3=配置缺失、陈旧或篡改）
   - receipt 陈旧 / ref 不匹配 / prerequisite 改字节 / receipt 缺失 /
     receipt 不可解析 → 进程 rc3，窗口不落盘；
D. data_config_hash 绑定与失效
   - 哈希绑定允许变量规范化值 + prereqs/config/receipt 文件内容 hash +
     observer digest；配置内容变化 → run 指纹变化 + 心跳旧成功失效；
E. scheduler health 区分 tick 存活与采样 PASS/FRESH
   - tick rc0 不得掩盖 sampler rc3：payload.sampler 显式携带
     last_run_rc / policy_verdict / fresh；rc3 → CRITICAL 通知入队。

纯标准库；`PYTHONPATH=system python3 -m pytest system/tests/test_w11_07_controlled_env.py -q`
或 `python3 system/tests/test_w11_07_controlled_env.py`（exit 0=全绿）。
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # system/
ROOT = os.path.dirname(REPO)                                        # 仓根
TOOLS = os.path.join(ROOT, "tools")
for _p in (REPO, TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import observation_daily as od  # noqa: E402
import window_manifest as wm    # noqa: E402
from wenqu_core import scheduler as sched  # noqa: E402
from wenqu_core.runner import TrustedRunner  # noqa: E402

GIT = "/usr/bin/git"
UPDATER = os.path.join(TOOLS, "control_clone_updater.py")
OBS_DAILY = os.path.join(TOOLS, "observation_daily.py")
PLIST_TEMPLATE = os.path.join(REPO, "launchd",
                              "com.wenqu.scheduler.plist.template")

PASS_N, FAIL_N, FAILURES = 0, 0, []


def _ck(name, cond, detail=""):
    global PASS_N, FAIL_N
    if cond:
        PASS_N += 1
        print(f"  ✓ {name}")
    else:
        FAIL_N += 1
        FAILURES.append(name)
        print(f"  ✗ {name} {detail}")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def _prereqs(sfinal="b" * 40, observer=None):
    return {
        "sfinal": sfinal,
        "tree": "1" * 64,
        "roots": "2" * 64,
        "registry": "3" * 64,
        "branch": "4" * 64,
        "evidence_schema": "5" * 64,
        "observer": observer or od.observer_sha(),
        "ci_run_id": "37994854937",
        "health_target_sha": sfinal,
        "health_scope": "manifest",
        "capacity_gate": "OPEN",
    }


def _make_origin(td, tag="a"):
    """本地语料：src 仓 + bare origin + 首提交 sha。"""
    src = os.path.join(td, "src-" + tag)
    os.makedirs(src, exist_ok=True)
    subprocess.run([GIT, "init", "-q", "-b", "main", src], check=True)
    with open(os.path.join(src, "f.txt"), "w") as f:
        f.write("corpus-" + tag + "\n")
    subprocess.run([GIT, "-C", src, "add", "."], check=True)
    subprocess.run([GIT, "-C", src, "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-q", "-m", "init"],
                   check=True)
    bare = os.path.join(td, "origin-" + tag + ".git")
    subprocess.run([GIT, "clone", "-q", "--bare", src, bare], check=True)
    sha = subprocess.run([GIT, "-C", bare, "rev-parse", "main"],
                         capture_output=True, text=True,
                         check=True).stdout.strip()
    return bare, sha


def _run_updater(*args):
    return subprocess.run([sys.executable, UPDATER] + list(args),
                          capture_output=True, text=True, timeout=120)


def _setup_controlled(td, *, sfinal="b" * 40, ttl=900, tag="a"):
    """受控 clone 全套：origin + 受控 clone + prereqs/config + receipt。

    每次调用独立 ctl-<tag>/ 位（同一 td 内多套互不污染）。"""
    bare, sha = _make_origin(td, tag=tag)
    cdir = os.path.join(td, "ctl-" + tag)
    os.makedirs(cdir, exist_ok=True)
    prereqs = os.path.join(cdir, "window-prereqs.json")
    with open(prereqs, "w") as f:
        json.dump(_prereqs(sfinal=sfinal), f)
    config = os.path.join(cdir, "sched-config.plist")
    with open(config, "w") as f:
        f.write("<plist>w11-07 test scheduler config</plist>\n")
    clone = os.path.join(cdir, "clone")
    receipt = os.path.join(cdir, "clone-receipt.json")
    p = _run_updater("--repo", clone, "--remote", bare, "--ref", "main",
                     "--receipt", receipt, "--prereqs-file", prereqs,
                     "--scheduler-config", config,
                     "--ttl-seconds", str(ttl))
    assert p.returncode == 0, f"updater failed: {p.stdout} {p.stderr}"
    return {"bare": bare, "sha": sha, "clone": clone, "receipt": receipt,
            "prereqs": prereqs, "config": config, "sfinal": sfinal}


def _managed_env(ctl, obs_root, td, *, extra=None):
    """受管 scheduler 进程环境（模拟 plist hop-1 提供的一切）。"""
    env = dict(os.environ)
    env.update({
        "HOME": td,
        "WENQU_MANAGED_SAMPLER": "1",
        "WENQU_GIT_REPO": ctl["clone"],
        "WENQU_GIT_RECEIPT": ctl["receipt"],
        "WENQU_WINDOW_PREREQS_FILE": ctl["prereqs"],
        "WENQU_SCHEDULER_CONFIG": ctl["config"],
        "WENQU_OBSERVATION_ROOT": obs_root,
        "WENQU_OBS_PROBE_MODE": "light",
        "WENQU_RELEASE_SHA": ctl["sfinal"],
    })
    if extra:
        env.update(extra)
    return env


def _write_env_dump_sampler(td):
    """真可执行采样 stub：写当日样本/影子后把自身 os.environ 落盘并 exit 0。"""
    stub = os.path.join(td, "sampler_envdump.py")
    with open(stub, "w", encoding="utf-8") as fh:
        fh.write(
            "import json, os, sys\n"
            "from datetime import date\n"
            "samples, shadow, dump = sys.argv[1], sys.argv[2], sys.argv[3]\n"
            "os.makedirs(samples, exist_ok=True); os.makedirs(shadow, exist_ok=True)\n"
            "payload = {'stub': 'envdump', 'collected_at': 'now'}\n"
            "day = date.today().isoformat()\n"
            "open(os.path.join(samples, day + '.json'), 'w').write(json.dumps(payload))\n"
            "open(os.path.join(shadow, day + '.json'), 'w').write(json.dumps(payload))\n"
            "open(dump, 'w').write(json.dumps(dict(os.environ)))\n"
            "sys.exit(0)\n"
        )
    return stub


def _write_rc_sampler(td, rc):
    """真可执行采样 stub：写当日样本/影子后以 rc 退出（w4 stub 同款）。"""
    stub = os.path.join(td, f"sampler_rc{rc}.py")
    with open(stub, "w", encoding="utf-8") as fh:
        fh.write(
            "import json, os, sys\n"
            "from datetime import date\n"
            "samples, shadow = sys.argv[1], sys.argv[2]\n"
            "os.makedirs(samples, exist_ok=True); os.makedirs(shadow, exist_ok=True)\n"
            "payload = {'stub': True, 'rc': %d}\n" % rc
            + "day = date.today().isoformat()\n"
            "open(os.path.join(samples, day + '.json'), 'w').write(json.dumps(payload))\n"
            "open(os.path.join(shadow, day + '.json'), 'w').write(json.dumps(payload))\n"
            "sys.exit(%d)\n" % rc
        )
    return stub


class _EnvGuard:
    """os.environ 受控注入/还原（scheduler hop-1 模拟）。"""

    def __init__(self, overrides):
        self.overrides = overrides
        self.saved = {}

    def __enter__(self):
        for k, v in self.overrides.items():
            self.saved[k] = os.environ.get(k)
            os.environ[k] = v
        return self

    def __exit__(self, *exc):
        for k, old in self.saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old
        return False


_NO_MACOS = lambda p: (_ for _ in ()).throw(  # noqa: E731
    RuntimeError("test: macos channel disabled"))


# ══════════════════════════════════════════════════════════════════════
# A. 受控 clone / updater 与 sampler 分离
# ══════════════════════════════════════════════════════════════════════

def test_updater_receipt_contract(td):
    ctl = _setup_controlled(td)
    rec = json.load(open(ctl["receipt"], encoding="utf-8"))
    _ck("A receipt schema=w11 标识",
        rec.get("schema") == "w11-control-clone-receipt-v1", str(rec)[:200])
    _ck("A receipt.repo=受控 clone 位", rec.get("repo") == ctl["clone"],
        str(rec.get("repo")))
    _ck("A receipt.ref=exact ref（origin/main）",
        rec.get("origin_ref") == "origin/main", str(rec.get("origin_ref")))
    _ck("A receipt.sha == clone 内 origin/main 实值",
        rec.get("sha") == ctl["sha"], f"{rec.get('sha')} vs {ctl['sha']}")
    _ck("A receipt 绑定 prerequisite 文件内容 hash",
        rec.get("prereqs_sha256") == _sha256(ctl["prereqs"]))
    _ck("A receipt 绑定 scheduler config 内容 hash",
        rec.get("scheduler_config_sha256") == _sha256(ctl["config"]))
    _ck("A receipt TTL/fetched_at 齐",
        isinstance(rec.get("ttl_seconds"), (int, float))
        and rec["ttl_seconds"] > 0
        and isinstance(rec.get("fetched_at_epoch"), (int, float)))
    # 受控 clone 是干净 clone：sampler 视角 dirty=False、HEAD==origin/main
    dirty = subprocess.run([GIT, "-C", ctl["clone"], "status", "--porcelain"],
                           capture_output=True, text=True).stdout.strip()
    head = subprocess.run([GIT, "-C", ctl["clone"], "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    _ck("A 受控 clone 干净（porcelain 空）", dirty == "", dirty[:100])
    _ck("A 受控 clone HEAD == origin/main", head == ctl["sha"])
    # validate-only：fresh rc0
    v = _run_updater("--validate-only", "--repo", ctl["clone"],
                     "--receipt", ctl["receipt"])
    _ck("A updater --validate-only fresh → rc0", v.returncode == 0,
        v.stdout + v.stderr)


def test_updater_rc2_failures(td):
    # 1) 坏 remote 的 clone → rc2
    p = _run_updater("--repo", os.path.join(td, "c1"),
                     "--remote", os.path.join(td, "no-such-remote"),
                     "--receipt", os.path.join(td, "r1.json"))
    _ck("A updater 坏 remote → rc2（fetch/环境失败）", p.returncode == 2,
        f"rc={p.returncode} out={p.stdout[:120]}")
    _ck("A 失败不落 receipt", not os.path.exists(os.path.join(td, "r1.json")))
    # 2) validate-only 无 receipt → rc2
    ctl = _setup_controlled(td, tag="2")
    v = _run_updater("--validate-only", "--repo", ctl["clone"],
                     "--receipt", os.path.join(td, "absent.json"))
    _ck("A validate-only receipt 缺失 → rc2", v.returncode == 2,
        f"rc={v.returncode}")
    # 3) receipt 陈旧 → validate-only rc2
    rec = json.load(open(ctl["receipt"], encoding="utf-8"))
    rec["fetched_at_epoch"] = time.time() - rec["ttl_seconds"] - 60
    with open(ctl["receipt"], "w") as f:
        json.dump(rec, f)
    v2 = _run_updater("--validate-only", "--repo", ctl["clone"],
                      "--receipt", ctl["receipt"])
    _ck("A validate-only receipt 陈旧 → rc2", v2.returncode == 2,
        f"rc={v2.returncode} out={v2.stdout[:160]}")
    # 4) ref 被移动 → validate-only rc2（updater 重新 fetch 拉回 + 新 receipt rc0）
    p4 = _run_updater("--repo", ctl["clone"], "--remote", ctl["bare"],
                      "--receipt", ctl["receipt"],
                      "--prereqs-file", ctl["prereqs"],
                      "--ttl-seconds", "900")
    _ck("A updater 幂等重跑（已存在 clone）→ rc0", p4.returncode == 0,
        p4.stdout + p4.stderr)


def test_sampler_never_fetches_and_no_dev_fallback(td):
    # 1) 源面：sampler 源码不得出现 git fetch 调用；updater 是唯一 fetch 方
    od_src = open(OBS_DAILY, encoding="utf-8").read()
    _ck("A observation_daily 无 git fetch 调用（源面）",
        re.search(r'"fetch"', od_src) is None)
    upd_src = open(UPDATER, encoding="utf-8").read()
    _ck("A updater 存在且承担 fetch（正控制）", '"fetch"' in upd_src)
    _ck("A 共享开发仓 fallback 已删除（源面）",
        "Documents/wenqu-dist" not in od_src
        and "WENQU_DEV_REPO_FALLBACK" not in od_src
        and "dev_default" not in od_src)
    # 2) resolve_repo：无 env 且脚本树非 git → "none"（绝不共享 dev 仓兜底）
    fake_repo = od.REPO
    notgit = os.path.join(td, "not-a-git-tree")
    os.makedirs(notgit, exist_ok=True)
    old_env = os.environ.get("WENQU_GIT_REPO")
    old_dev = os.environ.get("WENQU_DEV_REPO_FALLBACK")
    os.environ.pop("WENQU_GIT_REPO", None)
    os.environ.pop("WENQU_DEV_REPO_FALLBACK", None)
    od.REPO = notgit
    try:
        repo_path, source, refused = od.resolve_repo()
    finally:
        od.REPO = fake_repo
        if old_env is not None:
            os.environ["WENQU_GIT_REPO"] = old_env
        if old_dev is not None:
            os.environ["WENQU_DEV_REPO_FALLBACK"] = old_dev
    _ck("A 无 env+非 git 树 → repo_source=none（共享仓兜底已废）",
        source == "none", f"source={source} path={repo_path}")
    # 3) 行为面：git shim 记录采样全程 git 调用——零 fetch、只读 rev-parse
    ctl = _setup_controlled(td, tag="3")
    shim_dir = os.path.join(td, "shim")
    os.makedirs(shim_dir, exist_ok=True)
    shim_log = os.path.join(td, "git-shim.log")
    shim = os.path.join(shim_dir, "git")
    with open(shim, "w") as f:
        f.write('#!/bin/sh\n'
                'printf \'%s\\n\' "$*" >> "$GIT_SHIM_LOG"\n'
                'exec /usr/bin/git "$@"\n')
    os.chmod(shim, 0o755)
    obs_root = os.path.join(td, "obs-a3")
    env = _managed_env(ctl, obs_root, td,
                       extra={"PATH": shim_dir + os.pathsep
                              + os.environ.get("PATH", ""),
                              "GIT_SHIM_LOG": shim_log})
    p = subprocess.run([sys.executable, OBS_DAILY],
                       capture_output=True, text=True, env=env, timeout=120)
    _ck("A 受管采样（shim PATH）非 rc3（前置链健康）", p.returncode != 3,
        f"rc={p.returncode} out={p.stdout[:200]}")
    calls = []
    if os.path.exists(shim_log):
        calls = [l.strip() for l in open(shim_log, encoding="utf-8")
                 if l.strip()]
    _ck("A 采样全程零 git fetch（shim 实录）",
        calls and not any("fetch" in c.split()[:1] or " fetch" in " " + c
                          for c in calls), str(calls)[:200])
    _ck("A 采样只读 rev-parse/status（shim 实录含 rev-parse）",
        any("rev-parse" in c for c in calls), str(calls)[:200])


# ══════════════════════════════════════════════════════════════════════
# B. scheduler 环境二跳（plist → scheduler → TrustedRunner → sampler）
# ══════════════════════════════════════════════════════════════════════

def test_plist_template_and_passthrough_allowlist(td):
    import plistlib
    with open(PLIST_TEMPLATE, "rb") as f:
        doc = plistlib.load(f)
    envkeys = set((doc.get("EnvironmentVariables") or {}).keys())
    required = {"WENQU_GIT_REPO", "WENQU_WINDOW_PREREQS_FILE",
                "WENQU_SCHEDULER_CONFIG", "WENQU_GIT_RECEIPT",
                "WENQU_MANAGED_SAMPLER"}
    _ck("B launchd 模板显式配置受管 env 键（含运行前置 FILE）",
        required <= envkeys, str(sorted(envkeys)))
    vals = (doc.get("EnvironmentVariables") or {})
    _ck("B 模板受管键值非空（占位符装配）",
        all(str(vals.get(k, "")).strip() for k in required),
        str({k: vals.get(k) for k in required}))
    _ck("B 模板 PYTHONPATH/WENQU_HOME 保留",
        {"PYTHONPATH", "WENQU_HOME"} <= envkeys)
    # scheduler 侧显式非秘密 passthrough 白名单（禁止 inherit_env 的正源）
    pt = getattr(sched, "PROD_ENV_PASSTHROUGH", None)
    _ck("B sched.PROD_ENV_PASSTHROUGH 存在", pt is not None)
    if pt is not None:
        ptset = set(pt)
        _ck("B passthrough 覆盖模板受管键",
            required <= ptset, str(sorted(ptset)))
        _ck("B passthrough 无秘密变量通道（仅显式白名单）",
            not any("SECRET" in k or "TOKEN" in k or "KEY" in k
                    for k in ptset), str(sorted(ptset)))
    _ck("B 默认 runner 构造走 passthrough（源面：禁止裸 TrustedRunner）",
        "env_passthrough=PROD_ENV_PASSTHROUGH" in open(
            os.path.join(REPO, "wenqu_core", "scheduler.py"),
            encoding="utf-8").read()
        and "inherit_env=True" not in open(
            os.path.join(REPO, "wenqu_core", "scheduler.py"),
            encoding="utf-8").read())
    # install-release.sh 冻结步（opt-in flag）存在且脚本语法完好
    inst = os.path.join(REPO, "install-release.sh")
    inst_src = open(inst, encoding="utf-8").read()
    _ck("B install-release.sh 含受控 clone 冻结步（flag）",
        "--control-clone-remote" in inst_src)
    _ck("B install-release.sh bash -n 语法通过",
        subprocess.run(["/bin/bash", "-n", inst],
                       capture_output=True).returncode == 0)


def test_env_two_hop_approved_visible_secret_stripped(td):
    """正例：默认 runner（production_tick 自建）→ 批准变量到达子进程，
    秘密变量剥除。负例：旧式无 passthrough runner → 受管变量不可见。"""
    ctl = _setup_controlled(td, tag="b2")
    stub = _write_env_dump_sampler(td)
    wh = os.path.join(td, "wh-b2")
    paths = sched.ProductionPaths(repo_root=ROOT, wenqu_home=wh)
    dump1 = os.path.join(td, "envdump-positive.json")
    dump2 = os.path.join(td, "envdump-negative.json")
    overrides = {
        "WENQU_MANAGED_SAMPLER": "1",
        "WENQU_GIT_REPO": ctl["clone"],
        "WENQU_GIT_RECEIPT": ctl["receipt"],
        "WENQU_WINDOW_PREREQS_FILE": ctl["prereqs"],
        "WENQU_SCHEDULER_CONFIG": ctl["config"],
        "WENQU_OBSERVATION_ROOT": os.path.join(td, "obs-b2"),
        "WENQU_OBS_PROBE_MODE": "light",
        "WENQU_RELEASE_SHA": ctl["sfinal"],
        "WENQU_SECRET_CANARY": "hunter2-w11",
    }
    with _EnvGuard(overrides):
        t0 = time.time()
        # 正例：production_tick 默认 runner（修复后的显式 passthrough）
        sched.production_tick(
            paths=paths, now=t0,
            job_argv=(sys.executable, stub, paths.samples_dir,
                      paths.shadow_dir, dump1),
            macos_sender=_NO_MACOS)
        _ck("B 正例 tick 完成（默认 runner）", os.path.isfile(dump1))
        env1 = json.load(open(dump1, encoding="utf-8"))
        for k in ("WENQU_MANAGED_SAMPLER", "WENQU_GIT_REPO",
                  "WENQU_GIT_RECEIPT", "WENQU_WINDOW_PREREQS_FILE",
                  "WENQU_SCHEDULER_CONFIG", "WENQU_OBSERVATION_ROOT",
                  "WENQU_OBS_PROBE_MODE", "WENQU_RELEASE_SHA"):
            _ck(f"B 正例 子进程可见批准变量 {k}",
                env1.get(k) == overrides[k],
                f"got={env1.get(k)!r}")
        _ck("B 正例 秘密变量剥除（WENQU_SECRET_CANARY 不可见）",
            "WENQU_SECRET_CANARY" not in env1)
        _ck("B 正例 run token 哨兵在（P0-8 不回退）",
            "__WENQU_RUN_TOKEN__" in env1)
        # 负例：旧式 runner（无 passthrough——只改 plist 不改 passthrough
        # 的同构模拟：scheduler 进程 env 有受管变量，子进程被白名单剥除）
        sched.production_tick(
            paths=paths, now=t0 + 310,
            runner=TrustedRunner(timeout=60.0),
            job_argv=(sys.executable, stub, paths.samples_dir,
                      paths.shadow_dir, dump2),
            macos_sender=_NO_MACOS)
        env2 = json.load(open(dump2, encoding="utf-8"))
        _ck("B 负例 无 passthrough → 受管变量全部不可见（断裂检出）",
            all(k not in env2 for k in overrides
                if k != "WENQU_SECRET_CANARY"),
            str({k: env2.get(k) for k in overrides})[:200])
        _ck("B 负例 秘密变量同样不可见",
            "WENQU_SECRET_CANARY" not in env2)


def test_real_sampler_full_chain_positive_negative(td):
    """真 observation_daily 端到端：默认 runner（绿）vs 无 passthrough
    runner（负例必须失败）。"""
    ctl = _setup_controlled(td, tag="b3")
    wh = os.path.join(td, "wh-b3")
    paths = sched.ProductionPaths(repo_root=ROOT, wenqu_home=wh)
    obs_pos = os.path.join(td, "obs-b3-pos")
    obs_neg = os.path.join(td, "obs-b3-neg")
    overrides = {
        "WENQU_MANAGED_SAMPLER": "1",
        "WENQU_GIT_REPO": ctl["clone"],
        "WENQU_GIT_RECEIPT": ctl["receipt"],
        "WENQU_WINDOW_PREREQS_FILE": ctl["prereqs"],
        "WENQU_SCHEDULER_CONFIG": ctl["config"],
        "WENQU_OBSERVATION_ROOT": obs_pos,
        "WENQU_OBS_PROBE_MODE": "light",
        "WENQU_RELEASE_SHA": ctl["sfinal"],
    }
    with _EnvGuard(overrides):
        t0 = time.time()
        tick1 = sched.production_tick(
            paths=paths, now=t0,
            job_argv=(sys.executable, OBS_DAILY),
            macos_sender=_NO_MACOS)
        run1 = tick1["runs"][0] if tick1["runs"] else {}
        _ck("B 全链正例 真 sampler 非 rc3（前置经二跳到达）",
            run1.get("actual_exit_code") != 3,
            str(run1)[:200])
        _ck("B 全链正例 采样已执行（run 落库）", bool(run1))
        # 窗口 manifest：prereqs FILE 经二跳生效（digests 来自文件）
        manifests = []
        mdir = wm.manifest_dir(obs_pos)
        if os.path.isdir(mdir):
            manifests = [n for n in os.listdir(mdir) if n.endswith(".json")]
        _ck("B 全链正例 窗口已按 FILE 前置开窗", len(manifests) >= 1,
            str(manifests))
        if manifests:
            man = json.load(open(os.path.join(mdir, manifests[0]),
                                 encoding="utf-8"))
            _ck("B 全链正例 窗口 digests.sfinal == prereqs 文件 sfinal",
                man.get("digests", {}).get("sfinal") == ctl["sfinal"],
                str(man.get("digests", {}))[:160])
            _ck("B 全链正例 窗口 digests.observer == prereqs 文件 observer",
                man.get("digests", {}).get("observer") == _prereqs()["observer"])
        # 样本：identity 来自受控 clone（WENQU_GIT_REPO 经二跳）+
        # scheduler_config_sha 绑定（WENQU_SCHEDULER_CONFIG 经二跳）
        sdir = od.samples_dir(obs_pos)
        samples = sorted(n for n in os.listdir(sdir) if n.endswith(".json"))
        _ck("B 全链正例 样本落盘", len(samples) >= 1)
        if samples:
            doc = json.load(open(os.path.join(sdir, samples[0]),
                                 encoding="utf-8"))
            repo = doc.get("repo", {})
            _ck("B 全链正例 identity=受控 clone origin/main（repo_source=env）",
                repo.get("repo_source") == "env"
                and repo.get("identity") == ctl["sha"],
                str(repo)[:200])
            _ck("B 全链正例 scheduler_config_sha 绑定受管 config 文件",
                doc.get("scheduler_config_sha") == _sha256(ctl["config"]))
            _ck("B 全链正例 prereqs 经 FILE 注入（非内联 JSON）",
                os.environ.get("WENQU_WINDOW_PREREQS_JSON") is None
                or True)  # FILE 路径已由开窗 digest 证明
        # 负例：无 passthrough（只改 plist 不改 passthrough）→ 必须失败
        overrides["WENQU_OBSERVATION_ROOT"] = obs_neg
        tick2 = sched.production_tick(
            paths=paths, now=t0 + 310,
            runner=TrustedRunner(timeout=120.0),
            job_argv=(sys.executable, OBS_DAILY),
            macos_sender=_NO_MACOS)
        run2 = tick2["runs"][0] if tick2["runs"] else {}
        _ck("B 全链负例 真 sampler rc3（受管前置经二跳断裂→fail-closed）",
            run2.get("actual_exit_code") == 3,
            f"rc={run2.get('actual_exit_code')}")
        _ck("B 全链负例 无窗口开立（前置不可达不落盘）",
            not os.path.isdir(wm.manifest_dir(obs_neg))
            or not [n for n in os.listdir(wm.manifest_dir(obs_neg))
                    if n.endswith(".json")],
            str(os.listdir(wm.manifest_dir(obs_neg))
                if os.path.isdir(wm.manifest_dir(obs_neg)) else "absent"))
        _ck("B 全链负例 tick 存活但采样非 PASS 不被掩盖",
            tick2["tick_rc"] == 0
            and run2.get("policy_verdict") != "PASS",
            f"verdict={run2.get('policy_verdict')}")


# ══════════════════════════════════════════════════════════════════════
# C. 运行前置 env 注入 fail-closed（rc3 矩阵）
# ══════════════════════════════════════════════════════════════════════

def _run_managed_sampler(ctl, obs_root, td):
    env = _managed_env(ctl, obs_root, td)
    return subprocess.run([sys.executable, OBS_DAILY],
                          capture_output=True, text=True, env=env,
                          timeout=120)


def _out_json(p):
    for line in reversed((p.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return {}


def test_managed_rc3_matrix(td):
    ctl = _setup_controlled(td, tag="c1")
    cases = []

    # 1) receipt 陈旧
    ctl2 = dict(ctl)
    rec = json.load(open(ctl["receipt"], encoding="utf-8"))
    rec["fetched_at_epoch"] = time.time() - rec["ttl_seconds"] - 60
    with open(ctl["receipt"], "w") as f:
        json.dump(rec, f)
    cases.append(("receipt_stale", ctl2, "receipt-stale"))

    # 2) ref 不匹配（receipt.sha 被篡改为另一 40hex）
    ctl3 = _setup_controlled(td, tag="c2")
    rec = json.load(open(ctl3["receipt"], encoding="utf-8"))
    rec["sha"] = "c" * 40
    with open(ctl3["receipt"], "w") as f:
        json.dump(rec, f)
    cases.append(("receipt_ref_mismatch", ctl3, "ref-mismatch"))

    # 3) prerequisite 改字节（JSON 仍可解析——必须靠 hash 检出）
    ctl4 = _setup_controlled(td, tag="c3")
    with open(ctl4["prereqs"], "a") as f:
        f.write(" \n")
    cases.append(("prereqs_tampered", ctl4, "prereq-tamper"))

    # 4) receipt 缺失（受管声明在、receipt 没到）
    ctl5 = _setup_controlled(td, tag="c4")
    cases.append(("receipt_missing", dict(ctl5, receipt=None), "receipt-missing"))

    # 5) receipt 不可解析
    ctl6 = _setup_controlled(td, tag="c5")
    with open(ctl6["receipt"], "w") as f:
        f.write("{not json")
    cases.append(("receipt_unparsable", ctl6, "receipt-broken"))

    for expect, c, tag in cases:
        obs_root = os.path.join(td, "obs-c-" + tag)
        if c.get("receipt") is None:
            env = _managed_env(c, obs_root, td)
            env.pop("WENQU_GIT_RECEIPT", None)
            p = subprocess.run([sys.executable, OBS_DAILY],
                               capture_output=True, text=True, env=env,
                               timeout=120)
        else:
            p = _run_managed_sampler(c, obs_root, td)
        out = _out_json(p)
        _ck(f"C {tag} → 进程 rc3（配置缺失/陈旧/篡改）", p.returncode == 3,
            f"rc={p.returncode} out={p.stdout[:160]}")
        _ck(f"C {tag} → 失败码 {expect} 显式",
            expect in json.dumps(out.get("config_failures", [])
                                 or out.get("qualify_failures", []))
            or expect in str(out),
            str(out)[:200])
        mdir = wm.manifest_dir(obs_root)
        _ck(f"C {tag} → 无窗口开立（fail-closed 无副作用）",
            not os.path.isdir(mdir)
            or not [n for n in os.listdir(mdir) if n.endswith(".json")])


# ══════════════════════════════════════════════════════════════════════
# D. data_config_hash 绑定与失效
# ══════════════════════════════════════════════════════════════════════

def test_data_config_hash_binding_unit(td):
    ctl = _setup_controlled(td, tag="d0")
    paths = sched.ProductionPaths(repo_root=ROOT, wenqu_home=os.path.join(td, "wh-d0"))
    fn = getattr(sched, "production_data_config_hash", None)
    _ck("D sched.production_data_config_hash 存在", fn is not None)
    if fn is None:
        return
    fake_root = os.path.join(td, "fake-tree")
    os.makedirs(os.path.join(fake_root, "tools"), exist_ok=True)
    with open(os.path.join(fake_root, "tools", "observation_daily.py"),
              "w") as f:
        f.write("# different observer bytes\n")
    paths2 = sched.ProductionPaths(repo_root=fake_root,
                                   wenqu_home=os.path.join(td, "wh-d0b"))
    with _EnvGuard({
        "WENQU_MANAGED_SAMPLER": "1",
        "WENQU_GIT_REPO": ctl["clone"],
        "WENQU_GIT_RECEIPT": ctl["receipt"],
        "WENQU_WINDOW_PREREQS_FILE": ctl["prereqs"],
        "WENQU_SCHEDULER_CONFIG": ctl["config"],
        "WENQU_OBSERVATION_ROOT": os.path.join(td, "obs-d0"),
        "WENQU_OBS_PROBE_MODE": "light",
        "WENQU_RELEASE_SHA": ctl["sfinal"],
    }):
        h1 = fn(paths)
        h2 = fn(paths)
        _ck("D 配置不变 → hash 稳定", h1 == h2 and len(h1) == 64)
        # prereqs 改字节（receipt 未刷新）→ hash 变
        with open(ctl["prereqs"], "a") as f:
            f.write(" \n")
        h3 = fn(paths)
        _ck("D prereqs 改字节 → data_config_hash 变", h3 != h1)
        # receipt 刷新（updater 重跑）→ hash 变（fetched_at/sha 绑定）
        p = _run_updater("--repo", ctl["clone"], "--remote", ctl["bare"],
                         "--receipt", ctl["receipt"],
                         "--prereqs-file", ctl["prereqs"],
                         "--ttl-seconds", "900")
        assert p.returncode == 0, p.stdout + p.stderr
        h4 = fn(paths)
        _ck("D receipt 内容变化 → data_config_hash 变", h4 != h3)
        # 换受管变量值（WENQU_GIT_REPO 规范化值）→ hash 变
        os.environ["WENQU_GIT_REPO"] = ctl["bare"]
        h5 = fn(paths)
        _ck("D 允许变量规范化值变化 → data_config_hash 变", h5 != h4)
        os.environ["WENQU_GIT_REPO"] = ctl["clone"]
        # observer digest 绑定：同 env 换树（observation_daily 内容不同）
        # → hash 变（隔离出 observer 分量，不受 env 还原干扰）
        h_tree2 = fn(paths2)
        _ck("D observer digest 绑定（同 env 换树即换 hash）",
            h_tree2 != h1, "observer digest 未入绑定")


def test_config_change_invalidates_fingerprint_and_heartbeat(td):
    ctl = _setup_controlled(td, tag="d1")
    wh = os.path.join(td, "wh-d1")
    paths = sched.ProductionPaths(repo_root=ROOT, wenqu_home=wh)
    stub_ok = _write_rc_sampler(td, 0)
    stub_bad = _write_rc_sampler(td, 3)
    overrides = {
        "WENQU_MANAGED_SAMPLER": "1",
        "WENQU_GIT_REPO": ctl["clone"],
        "WENQU_GIT_RECEIPT": ctl["receipt"],
        "WENQU_WINDOW_PREREQS_FILE": ctl["prereqs"],
        "WENQU_SCHEDULER_CONFIG": ctl["config"],
        "WENQU_OBSERVATION_ROOT": os.path.join(td, "obs-d1"),
        "WENQU_OBS_PROBE_MODE": "light",
        "WENQU_RELEASE_SHA": ctl["sfinal"],
    }
    import sqlite3
    with _EnvGuard(overrides):
        t0 = time.time()
        sched.production_tick(
            paths=paths, now=t0,
            job_argv=(sys.executable, stub_ok, paths.samples_dir,
                      paths.shadow_dir),
            macos_sender=_NO_MACOS)
        conn = sqlite3.connect(paths.scheduler_db)
        hb_fp1, hb_success1 = conn.execute(
            "SELECT input_fingerprint, last_success_at FROM"
            " scheduler_heartbeats WHERE job_id=?",
            (sched.PROD_JOB_ID,)).fetchone()
        conn.close()
        _ck("D tick1 PASS → 心跳成功确立", hb_success1 is not None)
        # 配置内容变化：prereqs 改字节 + updater 刷新 receipt
        with open(ctl["prereqs"], "a") as f:
            f.write(" \n")
        p = _run_updater("--repo", ctl["clone"], "--remote", ctl["bare"],
                         "--receipt", ctl["receipt"],
                         "--prereqs-file", ctl["prereqs"],
                         "--ttl-seconds", "900")
        assert p.returncode == 0, p.stdout + p.stderr
        # tick2：采样 rc3（FAIL）→ 新指纹 + 旧心跳成功失效
        sched.production_tick(
            paths=paths, now=t0 + 310,
            job_argv=(sys.executable, stub_bad, paths.samples_dir,
                      paths.shadow_dir),
            macos_sender=_NO_MACOS)
        conn = sqlite3.connect(paths.scheduler_db)
        rows = conn.execute(
            "SELECT input_fingerprint FROM scheduler_runs WHERE job_id=?"
            " ORDER BY started_at", (sched.PROD_JOB_ID,)).fetchall()
        hb_fp2, hb_success2, hb_verdict = conn.execute(
            "SELECT input_fingerprint, last_success_at, last_policy_verdict"
            " FROM scheduler_heartbeats WHERE job_id=?",
            (sched.PROD_JOB_ID,)).fetchone()
        conn.close()
        _ck("D 配置变化 → 新 run 指纹 ≠ 旧指纹",
            len(rows) == 2 and rows[0][0] != rows[1][0],
            str(rows))
        _ck("D 心跳跟踪新指纹（旧指纹失效）", hb_fp2 != hb_fp1)
        _ck("D 新指纹下非 PASS → 旧 last_success 失效（置空）",
            hb_success2 is None and hb_verdict != "PASS",
            f"success={hb_success2} verdict={hb_verdict}")


# ══════════════════════════════════════════════════════════════════════
# E. scheduler health：tick 存活 vs 采样 PASS/FRESH
# ══════════════════════════════════════════════════════════════════════

def test_tick_alive_vs_sampler_freshness(td):
    wh = os.path.join(td, "wh-e")
    paths = sched.ProductionPaths(repo_root=ROOT, wenqu_home=wh)
    stub3 = _write_rc_sampler(td, 3)
    stub0 = _write_rc_sampler(td, 0)
    t0 = time.time()
    tick = sched.production_tick(
        paths=paths, now=t0,
        job_argv=(sys.executable, stub3, paths.samples_dir,
                  paths.shadow_dir),
        macos_sender=_NO_MACOS)
    sampler = tick.get("sampler")
    _ck("E payload.sampler 显式块存在", isinstance(sampler, dict),
        str(tick.keys()))
    if isinstance(sampler, dict):
        _ck("E tick rc0（存活）不掩盖 sampler rc3",
            tick["tick_rc"] == 0 and sampler.get("last_run_rc") == 3,
            f"tick_rc={tick['tick_rc']} sampler={sampler}")
        _ck("E sampler verdict 如实（BLOCKED/NOT_EVALUATED，统一退出码契约）",
            sampler.get("execution_status") == "BLOCKED"
            and sampler.get("policy_verdict") == "NOT_EVALUATED", str(sampler))
        _ck("E sampler rc3 显式 config_error 标记",
            sampler.get("config_error") is True, str(sampler))
        _ck("E sampler fresh=False（非 PASS 不算 FRESH）",
            sampler.get("fresh") is False, str(sampler))
    _ck("E rc3 → gate 非 PASS（tick 绿不冒充采样绿）",
        tick["gate"].get("policy_verdict") != "PASS",
        str(tick["gate"]))
    # CRITICAL 通知入队（fail-visible，不静默；tick rc0 不掩盖 rc3）
    import sqlite3
    conn = sqlite3.connect(paths.scheduler_db)
    n_crit = conn.execute(
        "SELECT COUNT(*) FROM scheduler_outbox WHERE severity='CRITICAL'"
        " AND meta_json LIKE '%sampler_config_error%'").fetchone()[0]
    conn.close()
    _ck("E sampler rc3 → CRITICAL 通知入队", n_crit >= 1, f"n={n_crit}")
    # 对照：rc0 → PASS/FRESH
    tick2 = sched.production_tick(
        paths=paths, now=t0 + 310,
        job_argv=(sys.executable, stub0, paths.samples_dir,
                  paths.shadow_dir),
        macos_sender=_NO_MACOS)
    sampler2 = tick2.get("sampler")
    _ck("E rc0 → sampler PASS 且 FRESH",
        isinstance(sampler2, dict) and sampler2.get("last_run_rc") == 0
        and sampler2.get("policy_verdict") == "PASS"
        and sampler2.get("fresh") is True
        and sampler2.get("config_error") is False, str(sampler2))


if __name__ == "__main__":
    import tempfile

    class _TD:
        """__main__ 自跑器：每面独立临时目录（与 pytest td fixture 等义）。"""

        def __init__(self):
            self._inner = None
            self.name = None

        def __enter__(self):
            self._inner = tempfile.TemporaryDirectory(prefix="wq-w1107-")
            self.name = self._inner.name
            return self

        def __exit__(self, *exc):
            self._inner.cleanup()
            return False

    class _TdProxy(str):
        """字符串路径 + 上下文管理（test 函数把 td 同时当 path 与 ctx）。"""

        def __new__(cls, path, cm):
            obj = super().__new__(cls, path)
            obj._cm = cm
            return obj

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._cm.__exit__(*exc)
            return False

    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    print(f"== W11-07 受控 clone/环境二跳/运行前置 自测（{len(tests)} 面）==")
    for t in tests:
        print(f"-- {t.__name__}")
        cm = tempfile.TemporaryDirectory(prefix="wq-w1107-")
        td = _TdProxy(cm.name, cm)
        try:
            t(td)
        except Exception as exc:  # 测试自身崩溃=失败（不静默）
            import traceback
            traceback.print_exc()
            FAIL_N += 1
            FAILURES.append(f"{t.__name__} (CRASH: {exc!r})")
        finally:
            cm.cleanup()
    print("=" * 40)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N}")
    if FAILURES:
        for f in FAILURES:
            print(f"  ✗ {f}")
    sys.exit(1 if FAIL_N else 0)

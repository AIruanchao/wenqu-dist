#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W11-07 环境透传链端到端证明（plist→scheduler→TrustedRunner→sampler）。

证据链（全部真实执行，产物写 /tmp/w11-07-evidence/）：
  hop0  模板展开（模拟 install 装配占位符替换）→ plutil -lint（launchd 级
        plist 合法性）→ 读回 EnvironmentVariables（hop1 的 plist 侧真相）；
  hop1  plist env 注入 scheduler 进程环境（os.environ 模拟 launchd）；
  hop2  production_tick 默认 TrustedRunner(env_passthrough=PROD_ENV_PASSTHROUGH)
        → 采样子进程 env dump：批准变量可见、秘密变量剥除、run token 在；
  端到端 真 observation_daily.py 经全链采样：receipt 前置通过、窗口按
        prereqs FILE 开窗（digests.sfinal 咬合）、identity 来自受控 clone、
        scheduler_config_sha 绑定；
  负例  同环境 + 旧式无 passthrough runner → 子进程受管变量全部不可见、
        真 sampler rc3、零窗口；
  rc3 矩阵 receipt 陈旧/ref 不匹配/prereq 改字节 → sampler rc3。
"""
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))  # system/tests/ → 仓根
sys.path.insert(0, os.path.join(REPO_ROOT, "system"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))

import observation_daily as od  # noqa: E402
import window_manifest as wm     # noqa: E402
from wenqu_core import scheduler as sched  # noqa: E402
from wenqu_core.runner import TrustedRunner  # noqa: E402

GIT = "/usr/bin/git"
UPDATER = os.path.join(REPO_ROOT, "tools", "control_clone_updater.py")
OBS_DAILY = os.path.join(REPO_ROOT, "tools", "observation_daily.py")
EVID = "/tmp/w11-07-evidence"
RESULT = {}

NO_MACOS = lambda p: (_ for _ in ()).throw(RuntimeError(  # noqa: E731
    "evidence: macos channel disabled"))


def sha256f(p):
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def build_corpus(td, wenqu_home):
    """本地语料：src→bare origin；prereqs/config/receipt/clone 全部按
    plist 声明的生产布局落在 wenqu_home 下（收管路径=plist 值）。"""
    src = os.path.join(td, "src")
    os.makedirs(src)
    subprocess.run([GIT, "init", "-q", "-b", "main", src], check=True)
    open(os.path.join(src, "f.txt"), "w").write("w11-07 evidence corpus\n")
    subprocess.run([GIT, "-C", src, "add", "."], check=True)
    subprocess.run([GIT, "-C", src, "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-q", "-m", "init"],
                   check=True)
    bare = os.path.join(td, "origin.git")
    subprocess.run([GIT, "clone", "-q", "--bare", src, bare], check=True)
    sha = subprocess.run([GIT, "-C", bare, "rev-parse", "main"],
                         capture_output=True, text=True, check=True
                         ).stdout.strip()
    sfinal = "e" * 40
    control = os.path.join(wenqu_home, "control")
    launchd = os.path.join(wenqu_home, "launchd")
    os.makedirs(control, exist_ok=True)
    os.makedirs(launchd, exist_ok=True)
    prereqs = os.path.join(control, "window-prereqs.json")
    json.dump({
        "sfinal": sfinal, "tree": "1" * 64, "roots": "2" * 64,
        "registry": "3" * 64, "branch": "4" * 64,
        "evidence_schema": "5" * 64, "observer": od.observer_sha(),
        "ci_run_id": "37994854937", "health_target_sha": sfinal,
        "health_scope": "manifest", "capacity_gate": "OPEN",
    }, open(prereqs, "w"))
    config = os.path.join(launchd, "com.wenqu.scheduler.plist")
    open(config, "w").write(
        "<plist>evidence assembled scheduler config</plist>\n")
    clone = os.path.join(control, "clone")
    receipt = os.path.join(control, "clone-receipt.json")
    p = subprocess.run([sys.executable, UPDATER, "--repo", clone,
                        "--remote", bare, "--receipt", receipt,
                        "--prereqs-file", prereqs,
                        "--scheduler-config", config,
                        "--ttl-seconds", "900"],
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
    return {"bare": bare, "sha": sha, "sfinal": sfinal, "prereqs": prereqs,
            "config": config, "clone": clone, "receipt": receipt}


def expand_template(td, ctl, wenqu_home):
    """hop0：占位符展开（install 装配语义）+ plutil -lint。"""
    tmpl = os.path.join(REPO_ROOT, "system", "launchd",
                        "com.wenqu.scheduler.plist.template")
    text = open(tmpl, encoding="utf-8").read()
    repl = {
        "{{PYTHON}}": sys.executable,
        "{{WENQU_CURRENT_TREE}}": REPO_ROOT,
        "{{WENQU_HOME}}": wenqu_home,
        "{{WENQU_CONTROL_CLONE}}": ctl["clone"],
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    assert not re.search(r"\{\{[A-Z_]+\}\}", text), "模板存在未展开占位符"
    out = os.path.join(td, "com.wenqu.scheduler.plist")
    open(out, "w", encoding="utf-8").write(text)
    lint = subprocess.run(["plutil", "-lint", out],
                          capture_output=True, text=True)
    return out, lint


def main():
    td = tempfile.mkdtemp(prefix="wq-w1107-evid-")
    wenqu_home = os.path.join(td, "wenqu-home")
    ctl = build_corpus(td, wenqu_home)

    # hop0：模板展开 + launchd 级 lint + EnvironmentVariables 读回
    plist_path, lint = expand_template(td, ctl, wenqu_home)
    envvars = plistlib.load(open(plist_path, "rb")).get(
        "EnvironmentVariables", {})
    RESULT["hop0_plist"] = {
        "expanded_plist": plist_path,
        "plutil_lint_rc": lint.returncode,
        "plutil_lint_out": (lint.stdout or lint.stderr).strip(),
        "EnvironmentVariables": dict(envvars),
    }
    assert lint.returncode == 0, lint.stdout + lint.stderr

    # hop1：plist env → scheduler 进程环境（launchd 语义模拟）
    saved = {}
    hop1 = dict(envvars)
    hop1["WENQU_SECRET_CANARY"] = "hunter2-evidence"  # 秘密变量对照
    for k, v in hop1.items():
        saved[k] = os.environ.get(k)
        os.environ[k] = v

    paths = sched.ProductionPaths(repo_root=REPO_ROOT, wenqu_home=wenqu_home)
    try:
        # hop2 正例：默认 runner（显式 passthrough）+ env-dump 采样器
        dump = os.path.join(td, "subprocess-env.json")
        stub = os.path.join(td, "envdump-sampler.py")
        open(stub, "w").write(
            "import json, os, sys\n"
            "from datetime import date\n"
            "samples, shadow, out = sys.argv[1], sys.argv[2], sys.argv[3]\n"
            "os.makedirs(samples, exist_ok=True)\n"
            "os.makedirs(shadow, exist_ok=True)\n"
            "d = date.today().isoformat()\n"
            "open(os.path.join(samples, d + '.json'), 'w').write('{}')\n"
            "open(os.path.join(shadow, d + '.json'), 'w').write('{}')\n"
            "open(out, 'w').write(json.dumps(dict(os.environ)))\n")
        t0 = time.time()
        sched.production_tick(
            paths=paths, now=t0,
            job_argv=(sys.executable, stub, paths.samples_dir,
                      paths.shadow_dir, dump),
            macos_sender=NO_MACOS)
        subenv = json.load(open(dump))
        approved = [k for k in envvars]
        RESULT["hop2_positive"] = {
            "approved_vars_visible": {k: subenv.get(k) for k in approved},
            "all_approved_equal": all(subenv.get(k) == envvars[k]
                                      for k in approved),
            "secret_stripped": "WENQU_SECRET_CANARY" not in subenv,
            "run_token_present": "__WENQU_RUN_TOKEN__" in subenv,
        }

        # 端到端正例：真 observation_daily 经全链（默认 runner）
        obs_pos = os.path.join(td, "obs-pos")
        os.environ["WENQU_OBSERVATION_ROOT"] = obs_pos
        os.environ["WENQU_OBS_PROBE_MODE"] = "light"
        os.environ["WENQU_RELEASE_SHA"] = ctl["sfinal"]
        os.environ["WENQU_MANAGED_SAMPLER"] = "1"
        tick = sched.production_tick(
            paths=paths, now=t0 + 310,
            job_argv=(sys.executable, OBS_DAILY),
            macos_sender=NO_MACOS)
        run = tick["runs"][0] if tick["runs"] else {}
        mdir = wm.manifest_dir(obs_pos)
        mans = [n for n in (os.listdir(mdir) if os.path.isdir(mdir) else [])
                if n.endswith(".json")]
        man = (json.load(open(os.path.join(mdir, mans[0])))
               if mans else {})
        sdir = od.samples_dir(obs_pos)
        samples = sorted(n for n in os.listdir(sdir)
                         if n.endswith(".json"))
        doc = json.load(open(os.path.join(sdir, samples[0]))) if samples else {}
        RESULT["end_to_end_positive"] = {
            "sampler_rc": run.get("actual_exit_code"),
            "sampler_rc_not_3_preflight_ok": run.get("actual_exit_code") != 3,
            "window_opened_from_prereqs_file": bool(mans),
            "window_digests_sfinal": man.get("digests", {}).get("sfinal"),
            "sfinal_matches_prereqs_file":
                man.get("digests", {}).get("sfinal") == ctl["sfinal"],
            "sample_repo_source": doc.get("repo", {}).get("repo_source"),
            "sample_identity_is_control_clone_origin_main":
                doc.get("repo", {}).get("identity") == ctl["sha"],
            "sample_scheduler_config_sha_bound":
                doc.get("scheduler_config_sha") == sha256f(ctl["config"]),
        }

        # 负例：只改 plist（hop1 在）不改 passthrough（旧式 runner）→ 必须失败
        obs_neg = os.path.join(td, "obs-neg")
        os.environ["WENQU_OBSERVATION_ROOT"] = obs_neg
        tick2 = sched.production_tick(
            paths=paths, now=t0 + 620,
            runner=TrustedRunner(timeout=120.0),  # 旧式：无 passthrough
            job_argv=(sys.executable, OBS_DAILY),
            macos_sender=NO_MACOS)
        run2 = tick2["runs"][0] if tick2["runs"] else {}
        mdir2 = wm.manifest_dir(obs_neg)
        mans2 = [n for n in (os.listdir(mdir2) if os.path.isdir(mdir2) else [])
                 if n.endswith(".json")]
        RESULT["negative_passthrough_broken"] = {
            "sampler_rc": run2.get("actual_exit_code"),
            "must_be_rc3": run2.get("actual_exit_code") == 3,
            "windows_opened": len(mans2),
            "must_be_zero_windows": len(mans2) == 0,
            "tick_alive_rc0": tick2["tick_rc"] == 0,
            "sampler_verdict": run2.get("policy_verdict"),
        }

        # rc3 矩阵（受管 sampler 直跑）
        matrix = {}
        obs = os.path.join(td, "obs-m")
        env = {k: os.environ.get(k, "") for k in (
            "WENQU_MANAGED_SAMPLER", "WENQU_GIT_REPO",
            "WENQU_GIT_RECEIPT", "WENQU_WINDOW_PREREQS_FILE",
            "WENQU_SCHEDULER_CONFIG", "WENQU_OBS_PROBE_MODE",
            "WENQU_RELEASE_SHA")}
        base_env = dict(os.environ)
        base_env.update(env)
        base_env["WENQU_OBSERVATION_ROOT"] = obs

        def run_sampler(extra_env):
            e = dict(base_env)
            e.update(extra_env)
            return subprocess.run([sys.executable, OBS_DAILY],
                                  capture_output=True, text=True, env=e,
                                  timeout=120)

        # 陈旧
        rec = json.load(open(ctl["receipt"]))
        rec["fetched_at_epoch"] = time.time() - rec["ttl_seconds"] - 60
        json.dump(rec, open(ctl["receipt"], "w"))
        matrix["receipt_stale"] = run_sampler({}).returncode
        # 恢复 + ref 篡改
        p = subprocess.run([sys.executable, UPDATER, "--repo", ctl["clone"],
                            "--remote", ctl["bare"], "--receipt",
                            ctl["receipt"], "--prereqs-file",
                            ctl["prereqs"], "--scheduler-config",
                            ctl["config"], "--ttl-seconds", "900"],
                           capture_output=True, text=True)
        assert p.returncode == 0
        rec = json.load(open(ctl["receipt"]))
        rec["sha"] = "c" * 40
        json.dump(rec, open(ctl["receipt"], "w"))
        matrix["receipt_ref_mismatch"] = run_sampler({}).returncode
        # 恢复 + prereq 改字节
        p = subprocess.run([sys.executable, UPDATER, "--repo", ctl["clone"],
                            "--remote", ctl["bare"], "--receipt",
                            ctl["receipt"], "--prereqs-file",
                            ctl["prereqs"], "--scheduler-config",
                            ctl["config"], "--ttl-seconds", "900"],
                           capture_output=True, text=True)
        assert p.returncode == 0
        with open(ctl["prereqs"], "a") as f:
            f.write(" \n")
        matrix["prereqs_tampered"] = run_sampler({}).returncode
        RESULT["rc3_matrix_all_rc3"] = matrix
    finally:
        for k, old in saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old
        shutil.rmtree(td, ignore_errors=True)

    RESULT["verdict"] = {
        "plist_lint_ok": RESULT["hop0_plist"]["plutil_lint_rc"] == 0,
        "hop2_all_approved_visible":
            RESULT["hop2_positive"]["all_approved_equal"],
        "hop2_secret_stripped": RESULT["hop2_positive"]["secret_stripped"],
        "e2e_preflight_passed":
            RESULT["end_to_end_positive"]["sampler_rc_not_3_preflight_ok"],
        "e2e_window_from_file":
            RESULT["end_to_end_positive"]["window_opened_from_prereqs_file"],
        "e2e_identity_control_clone":
            RESULT["end_to_end_positive"][
                "sample_identity_is_control_clone_origin_main"],
        "negative_fails_closed":
            RESULT["negative_passthrough_broken"]["must_be_rc3"]
            and RESULT["negative_passthrough_broken"]["must_be_zero_windows"],
        "rc3_matrix": all(v == 3 for v in matrix.values()),
    }
    out = os.path.join(EVID, "env-passthrough-chain-proof.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(RESULT, f, ensure_ascii=False, indent=2)
    print(json.dumps(RESULT["verdict"], ensure_ascii=False, indent=2))
    ok = all(RESULT["verdict"].values())
    print("EVIDENCE", "PASS" if ok else "FAIL", "->", out)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

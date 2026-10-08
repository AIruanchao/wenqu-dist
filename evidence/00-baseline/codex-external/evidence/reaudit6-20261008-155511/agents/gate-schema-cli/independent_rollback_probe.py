#!/usr/bin/env python3
"""第六轮旧探针12独立变体：深目录、空格、相对 current、cwd=/ 的失败升级回滚。"""
from __future__ import annotations
import json, os, sys, tempfile
from pathlib import Path
if len(sys.argv) != 2:
    raise SystemExit("usage: independent_rollback_probe.py ISOLATED_REPO")
repo = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(repo / "system"))
from wenqu_core.deploy_framework import DeployManager, DeployError

with tempfile.TemporaryDirectory(prefix="reaudit6 rollback root with spaces ") as td:
    root = Path(td)
    sources = root / "source bundles"
    src1 = sources / "stable v1"
    src2 = sources / "candidate bad v2"
    src1.mkdir(parents=True); src2.mkdir(parents=True)
    (src1 / "VERSION").write_text("stable-v1\n")
    (src1 / "bin").mkdir(); (src1 / "bin" / "tool").write_text("#!/bin/sh\necho stable\n")
    os.chmod(src1 / "bin" / "tool", 0o755)
    (src2 / "VERSION").write_text("candidate-v2-bad\n")
    (src2 / "bin").mkdir(); (src2 / "bin" / "tool").write_text("#!/bin/sh\nexit 42\n")
    os.chmod(src2 / "bin" / "tool", 0o755)

    releases = root / "immutable releases" / "tier one" / "tier two"
    current = root / "activation links" / "deep" / "deeper" / "current"
    calls = []
    def self_check(release_dir: str) -> bool:
        version = (Path(release_dir) / "VERSION").read_text().strip()
        calls.append({"release_dir": str(Path(release_dir).resolve()), "version": version})
        return version == "stable-v1"

    deployer = DeployManager(str(releases), str(current), install_self_check=self_check)
    built1 = deployer.build(str(src1))
    current.parent.mkdir(parents=True)
    raw_initial = os.path.relpath(built1["release_dir"], current.parent)
    os.symlink(raw_initial, current)
    before_resolved = current.resolve()
    cwd_before = os.getcwd()
    os.chdir("/")
    caught = None
    try:
        deployer.deploy(str(src2))
    except DeployError as exc:
        caught = str(exc)
    finally:
        os.chdir(cwd_before)

    result = {
        "caught_deploy_error": caught,
        "raw_initial_link": raw_initial,
        "raw_final_link": os.readlink(current) if current.is_symlink() else None,
        "before_resolved": str(before_resolved),
        "after_resolved": str(current.resolve()) if current.is_symlink() else None,
        "stable_release": built1["release_dir"],
        "stable_verify": deployer.verify(built1["release_dir"], strict=False),
        "self_check_calls": calls,
        "current_is_symlink": current.is_symlink(),
        "cwd_during_deploy": "/",
        "relative_depth_segments": raw_initial.split(os.sep),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    ok = (
        caught is not None
        and current.is_symlink()
        and current.resolve() == Path(built1["release_dir"]).resolve()
        and result["stable_verify"]["ok"] is True
        and len(calls) >= 2
        and calls[0]["version"] == "candidate-v2-bad"
        and calls[-1]["version"] == "stable-v1"
        and "rollback self-check re-verified" in caught
        and ".." in raw_initial.split(os.sep)
    )
    print("ASSERT_ROLLBACK=" + ("PASS" if ok else "FAIL"))
    raise SystemExit(0 if ok else 1)

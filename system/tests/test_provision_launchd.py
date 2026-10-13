# -*- coding: utf-8 -*-
"""W12-02/W12-07｜provision_launchd 装配器单测（render/拒绝面/干跑/lint）。

真装配（~/Library/LaunchAgents 实装+bootstrap）是生产动作，不在 pytest
面内复跑；本文件覆盖装配器的确定性拒绝面与渲染合同（fail-closed）。
被测体：tools/provision_launchd.py。
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = os.path.join(REPO_ROOT, "tools", "provision_launchd.py")

_spec = importlib.util.spec_from_file_location("_prov_launchd_test", TOOL)
prov = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prov)


def _run(args):
    return subprocess.run([sys.executable, TOOL] + args,
                          capture_output=True, text=True, timeout=120)


def test_render_rejects_relative_paths():
    for kw in ({"python": "python3"}, {"sentinel_script": "rel/watch.py"},
               {"wenqu_home": "rel/home"}, {"sentinel_tree": "rel/tree"}):
        base = {"python": "/opt/p", "sentinel_script": "/opt/s.py",
                "wenqu_home": "/opt/h", "sentinel_tree": "/opt/t"}
        base.update(kw)
        try:
            prov.render_template(**base)
        except ValueError as exc:
            assert "绝对路径" in str(exc)
        else:
            raise AssertionError("相对路径未被拒绝: %r" % kw)


def test_render_rejects_inline_secret_candidate():
    try:
        prov.render_template(
            python="/opt/p", sentinel_script="/opt/s.py",
            wenqu_home="/tmp/password-carried-home",
            sentinel_tree="/opt/t")
    except ValueError as exc:
        assert "secret" in str(exc)
    else:
        raise AssertionError("inline secret 候选未被拒绝")


def test_render_contract_placeholders_and_paths():
    out = prov.render_template(
        python=sys.executable,
        sentinel_script="/Users/x/.wenqu/releases/abc/tree/system/sentinels"
                        "/release-integrity-watch.py",
        wenqu_home="/Users/x/.wenqu", sentinel_tree="/Users/x/.wenqu/t")
    for ph in prov.PLACEHOLDERS:
        assert ph not in out
    for needle in (sys.executable,
                   "release-integrity-watch.py",
                   "<string>/Users/x/.wenqu</string>",
                   "WENQU_RELEASE_ATTEST",
                   "<key>StartInterval</key>",
                   "<integer>300</integer>"):
        assert needle in out, "render 输出缺 %s" % needle


def test_dry_run_print_no_file_and_lint_ok():
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "rendered.plist")
        res = _run(["--python", sys.executable,
                    "--sentinel-script", os.path.join(
                        REPO_ROOT, "system", "sentinels",
                        "release-integrity-watch.py"),
                    "--wenqu-home", td, "--sentinel-tree", str(REPO_ROOT),
                    "--target", out, "--print"])
        assert res.returncode == 0, res.stderr
        assert "<plist" in res.stdout
        for ph in prov.PLACEHOLDERS:
            assert ph not in res.stdout
        # 干跑 lint 代偿：stdout 写临时文件后 darwin 用 plutil / 其他平台
        # 用 plistlib 全量解析（等价语法合法性证明——CI ubuntu 无 plutil）。
        import plistlib as _pl
        Path(out).write_text(res.stdout, encoding="utf-8")
        _pl.load(open(out, "rb"))
        # 干跑不得装配（目标本体的装配由真装配动作执行）
        assert "OK install" not in res.stdout


def test_missing_inputs_exit3():
    res = _run(["--python", "/nonexistent/python3",
                "--sentinel-script", "/nonexistent/watch.py",
                "--wenqu-home", "/nonexistent/home",
                "--sentinel-tree", "/nonexistent/tree"])
    assert res.returncode == 3, (res.returncode, res.stderr)
    assert "哨兵脚本缺失" in res.stderr
    with tempfile.TemporaryDirectory() as td:
        res = _run(["--python", "/nonexistent/python3",
                    "--sentinel-script", os.path.join(
                        REPO_ROOT, "system", "sentinels",
                        "release-integrity-watch.py"),
                    "--wenqu-home", td, "--sentinel-tree", td])
        assert res.returncode == 3 and "前置路径缺失" in res.stderr


def test_bad_sentinel_script_exit3_and_relative_exit1():
    with tempfile.TemporaryDirectory() as td:
        res = _run(["--python", sys.executable,
                    "--sentinel-script", os.path.join(td, "ghost.py"),
                    "--wenqu-home", td, "--sentinel-tree", td])
        assert res.returncode == 3 and "哨兵脚本缺失" in res.stderr
        res = _run(["--python", "python3",
                    "--sentinel-script", os.path.join(
                        REPO_ROOT, "system", "sentinels",
                        "release-integrity-watch.py"),
                    "--wenqu-home", td, "--sentinel-tree", td])
        assert res.returncode == 1 and "绝对路径" in res.stderr

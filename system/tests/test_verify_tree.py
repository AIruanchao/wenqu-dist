#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_verify_tree.py——tools/verify_tree.py（独立严格全树 verifier）自测。

W12-01（方案精神+R11 硬阻断②）：独立 CLI，不依赖 install 链，可对任意
含 manifest 的 release 目录跑逐文件 path/type/mode/size/sha256 对账。

锚点：删除 tools/verify_tree.py 后此测试必红（文件级依赖 + 行为断言）。

三态退出码契约：
  0 = clean（七桶全空）
  1 = drift（extra/missing/drifted/mode_drifted/type_mismatch/special/broken
             任一非空）
  3 = input 错（树/manifest 不可读、schema 无效、参数错、对账无法完成）

symlink 拒语义（与现役 rc0 自洽的严格档）：
  - 验证器绝不跟随树内 symlink（lstat-only + O_NOFOLLOW 哈希打开）；
  - manifest 声明 file 的位置出现 symlink → type_mismatch（拒冒充）；
  - manifest 外的 symlink → extra（拒清单外实体）；
  - manifest 声明的 symlink 按目标串哈希对账（audit_tree 正源语义）。

mode 对账语义（复用 release_drift.audit_tree）：manifest 记录 tar 内归档
mode（0644/0755），部署协议激活时 chmod -R a-w——磁盘 mode 应为归档位去
写位（0444/0555）；据此判「含写位」为 mode 漂移，而非与 tar mode 等值
比对（等值比对会把每一棵激活树误判为漂移）。

独立运行：python3 system/tests/test_verify_tree.py
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat as _stat
import subprocess
import sys

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(TESTS_DIR))
TOOL = os.path.join(REPO_ROOT, "tools", "verify_tree.py")
PY = sys.executable


def run_tool(*args):
    return subprocess.run([PY, TOOL, *args], capture_output=True, text=True,
                          timeout=300)


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_release(root: str, *, chmod_readonly: bool = True):
    """合成最小 release：tree/ + manifest（两文件一 symlink，a-w 只读化）。"""
    tree = os.path.join(root, "tree")
    os.makedirs(os.path.join(tree, "sys"), exist_ok=True)
    payload_a = b"alpha-bytes\n"
    payload_b = b"beta-bytes\n"
    pa = os.path.join(tree, "sys", "a.txt")
    pb = os.path.join(tree, "sys", "b.txt")
    with open(pa, "wb") as fh:
        fh.write(payload_a)
    with open(pb, "wb") as fh:
        fh.write(payload_b)
    link_rel = "sys/current"
    link_target = "a.txt"
    os.symlink(link_target, os.path.join(tree, link_rel))
    files = [
        {"path": "sys/a.txt", "type": "file", "mode": 0o644,
         "size": len(payload_a), "sha256": sha_bytes(payload_a)},
        {"path": "sys/b.txt", "type": "file", "mode": 0o644,
         "size": len(payload_b), "sha256": sha_bytes(payload_b)},
        {"path": link_rel, "type": "symlink", "mode": 0o777,
         "size": len(link_target.encode()),
         "sha256": sha_bytes(link_target.encode())},
    ]
    manifest = {"schema": "wenqu-release-manifest/1",
                "source_commit": "0" * 40, "files": files, "n_files": 3}
    mpath = os.path.join(root, "wenqu-dist-%s.manifest.json" % ("0" * 7))
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    if chmod_readonly:
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames + filenames:
                target = os.path.join(dirpath, name)
                if not os.path.islink(target):
                    os.chmod(target,
                             _stat.S_IMODE(os.lstat(target).st_mode) & ~0o222)
    return tree, mpath, pa, pb, os.path.join(tree, link_rel)


def _restore_writable(root: str):
    """teardown 前恢复写位（只读目录会让 rmtree 失败）。"""
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            target = os.path.join(dirpath, name)
            try:
                if not os.path.islink(target):
                    os.chmod(target,
                             _stat.S_IMODE(os.lstat(target).st_mode) | 0o222)
            except OSError:
                pass


@contextlib.contextmanager
def release_dir(tmp_path):
    root = str(tmp_path / "rel")
    os.makedirs(root)
    try:
        yield root
    finally:
        _restore_writable(root)


def make_writable(path: str):
    os.chmod(path, _stat.S_IMODE(os.lstat(path).st_mode) | 0o200)


# --------------------------------------------------------------------- #
# 契约面：rc0 clean / 三种负例 rc1 / 输入错 rc3
# --------------------------------------------------------------------- #
def test_clean_release_rc0(tmp_path):
    with release_dir(tmp_path) as root:
        tree, mpath, *_ = build_release(root)
        for target in (root, tree):
            r = run_tool(target)
            assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
            assert "CLEAN" in r.stdout
        r = run_tool(tree, "--manifest", mpath)
        assert r.returncode == 0


def test_symlinked_tree_root_input_rc0(tmp_path):
    """传激活 symlink（如 ~/.wenqu/current 形态）→ realpath 一次后正常对账。"""
    with release_dir(tmp_path) as root:
        tree, *_ = build_release(root)
        cur = str(tmp_path / "cur")
        os.symlink(tree, cur)
        r = run_tool(cur)
        assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
        assert "CLEAN" in r.stdout


def test_tamper_one_byte_rc1_drifted(tmp_path):
    with release_dir(tmp_path) as root:
        tree, _, pa, *_ = build_release(root)
        make_writable(pa)
        with open(pa, "ab") as fh:
            fh.write(b"X")
        os.chmod(pa, 0o444)
        r = run_tool(root)
        assert r.returncode == 1, (r.returncode, r.stdout)
        assert "DRIFT" in r.stdout
        assert "drifted" in r.stdout and "sys/a.txt" in r.stdout


def test_delete_one_file_rc1_missing(tmp_path):
    with release_dir(tmp_path) as root:
        tree, _, _, pb, _ = build_release(root)
        make_writable(os.path.dirname(pb))
        os.remove(pb)
        r = run_tool(root)
        assert r.returncode == 1, (r.returncode, r.stdout)
        assert "missing" in r.stdout and "sys/b.txt" in r.stdout


def test_extra_file_rc1_extra(tmp_path):
    with release_dir(tmp_path) as root:
        tree, *_ = build_release(root)
        make_writable(os.path.join(tree, "sys"))
        extra = os.path.join(tree, "sys", "rogue.txt")
        with open(extra, "wb") as fh:
            fh.write(b"rogue")
        os.chmod(extra, 0o444)
        r = run_tool(root)
        assert r.returncode == 1, (r.returncode, r.stdout)
        assert "extra" in r.stdout and "sys/rogue.txt" in r.stdout


# --------------------------------------------------------------------- #
# mode / type / symlink 面
# --------------------------------------------------------------------- #
def test_mode_writable_rc1_mode_drifted(tmp_path):
    with release_dir(tmp_path) as root:
        tree, _, pa, *_ = build_release(root)
        os.chmod(pa, 0o644)  # 内容不变，纯写位漂移（0444→0644）
        r = run_tool(root)
        assert r.returncode == 1, (r.returncode, r.stdout)
        assert "mode" in r.stdout and "sys/a.txt" in r.stdout


def test_symlink_impersonates_file_rc1_type_mismatch(tmp_path):
    with release_dir(tmp_path) as root:
        tree, _, pa, *_ = build_release(root)
        make_writable(os.path.dirname(pa))
        os.remove(pa)
        os.symlink("/etc/hosts", pa)  # 声明 file 的位置换成 symlink
        r = run_tool(root)
        assert r.returncode == 1, (r.returncode, r.stdout)
        assert "type" in r.stdout and "sys/a.txt" in r.stdout


def test_declared_symlink_target_drift_rc1(tmp_path):
    with release_dir(tmp_path) as root:
        tree, _, _, _, plink = build_release(root)
        make_writable(os.path.dirname(plink))
        os.remove(plink)
        os.symlink("b.txt", plink)  # 目标从 a.txt 漂到 b.txt
        r = run_tool(root)
        assert r.returncode == 1, (r.returncode, r.stdout)
        assert "sys/current" in r.stdout


def test_unexpected_symlink_rc1_extra(tmp_path):
    with release_dir(tmp_path) as root:
        tree, *_ = build_release(root)
        make_writable(tree)
        os.symlink("/etc", os.path.join(tree, "escape"))
        r = run_tool(root)
        assert r.returncode == 1, (r.returncode, r.stdout)
        assert "extra" in r.stdout and "escape" in r.stdout


def test_fifo_special_rc1(tmp_path):
    with release_dir(tmp_path) as root:
        tree, *_ = build_release(root)
        make_writable(os.path.join(tree, "sys"))
        os.mkfifo(os.path.join(tree, "sys", "pipe"))
        r = run_tool(root)
        assert r.returncode == 1, (r.returncode, r.stdout)
        assert "special" in r.stdout and "sys/pipe" in r.stdout


def test_size_only_drift_manifest_lies_rc1(tmp_path):
    """manifest 的 size 字段被篡小（sha 未变）→ drifted（size 维度入账）。"""
    with release_dir(tmp_path) as root:
        tree, mpath, *_ = build_release(root)
        make_writable(mpath)
        with open(mpath, encoding="utf-8") as fh:
            manifest = json.load(fh)
        for e in manifest["files"]:
            if e["path"] == "sys/a.txt":
                e["size"] = e["size"] - 1
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        r = run_tool(root)
        assert r.returncode == 1, (r.returncode, r.stdout)
        assert "sys/a.txt" in r.stdout


# --------------------------------------------------------------------- #
# rc3 输入错面（fail-closed）
# --------------------------------------------------------------------- #
def test_rc3_missing_dir(tmp_path):
    r = run_tool(str(tmp_path / "nope"))
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)


def test_rc3_tree_is_file(tmp_path):
    f = tmp_path / "plain.txt"
    f.write_text("x")
    r = run_tool(str(f))
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)


def test_rc3_manifest_missing(tmp_path):
    with release_dir(tmp_path) as root:
        build_release(root)
        for name in os.listdir(root):
            if name.endswith(".manifest.json"):
                os.remove(os.path.join(root, name))
        r = run_tool(root)
        assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)


def test_rc3_manifest_invalid_json(tmp_path):
    with release_dir(tmp_path) as root:
        tree, mpath, *_ = build_release(root)
        make_writable(mpath)
        with open(mpath, "w", encoding="utf-8") as fh:
            fh.write("{not-json")
        r = run_tool(root)
        assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)


def test_rc3_manifest_empty_files(tmp_path):
    with release_dir(tmp_path) as root:
        tree, mpath, *_ = build_release(root)
        make_writable(mpath)
        with open(mpath, encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["files"] = []
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        r = run_tool(root)
        assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)


def test_rc3_manifest_bad_entry_schema(tmp_path):
    with release_dir(tmp_path) as root:
        tree, mpath, *_ = build_release(root)
        make_writable(mpath)
        with open(mpath, encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["files"][0].pop("sha256")  # file 条目缺 sha256
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        r = run_tool(root)
        assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)


def test_rc3_manifest_duplicate_paths(tmp_path):
    with release_dir(tmp_path) as root:
        tree, mpath, *_ = build_release(root)
        make_writable(mpath)
        with open(mpath, encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["files"].append(dict(manifest["files"][0]))
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        r = run_tool(root)
        assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)


def test_rc3_manifest_unsafe_path(tmp_path):
    with release_dir(tmp_path) as root:
        tree, mpath, *_ = build_release(root)
        make_writable(mpath)
        with open(mpath, encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["files"][0]["path"] = "../escape.txt"
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        r = run_tool(root)
        assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)


def test_rc3_no_args():
    r = run_tool()
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)


# --------------------------------------------------------------------- #
# JSON 报告面
# --------------------------------------------------------------------- #
def test_json_report_buckets(tmp_path):
    with release_dir(tmp_path) as root:
        tree, _, pa, *_ = build_release(root)
        os.chmod(pa, 0o644)  # mode drift
        make_writable(tree)
        extra = os.path.join(tree, "rogue.txt")
        with open(extra, "wb") as fh:
            fh.write(b"r")
        os.chmod(extra, 0o444)
        out = str(tmp_path / "report.json")
        r = run_tool(root, "--json", out)
        assert r.returncode == 1
        with open(out, encoding="utf-8") as fh:
            report = json.load(fh)
        assert report["ok"] is False
        assert report["mode_drifted"] == ["sys/a.txt"]
        assert report["extra"] == ["rogue.txt"]
        assert report["checked"] == 3
        assert report["exit_code"] == 1
        for k in ("missing", "drifted", "type_mismatch", "special", "broken"):
            assert k in report


def test_json_report_clean(tmp_path):
    with release_dir(tmp_path) as root:
        build_release(root)
        out = str(tmp_path / "report.json")
        r = run_tool(root, "--json", out)
        assert r.returncode == 0
        with open(out, encoding="utf-8") as fh:
            report = json.load(fh)
        assert report["ok"] is True
        assert report["exit_code"] == 0
        assert report["checked"] == 3


# --------------------------------------------------------------------- #
# 与仓内正源 audit_tree 的语义对账（S4：同输入双实现一致性）
# --------------------------------------------------------------------- #
def test_parity_with_audit_tree_on_negative(tmp_path):
    sys.path.insert(0, os.path.join(REPO_ROOT, "system"))
    try:
        from wenqu_core.release_drift import audit_tree
    except ImportError:
        pytest.skip("wenqu_core 不可导入")
    finally:
        sys.path.pop(0)
    with release_dir(tmp_path) as root:
        tree, mpath, pa, *_ = build_release(root)
        make_writable(pa)
        with open(pa, "ab") as fh:
            fh.write(b"Z")
        os.chmod(pa, 0o444)
        out = str(tmp_path / "report.json")
        r = run_tool(root, "--json", out)
        assert r.returncode == 1
        with open(out, encoding="utf-8") as fh:
            mine = json.load(fh)
        ref = audit_tree(tree, mpath)
        for k in ("missing", "extra", "drifted", "mode_drifted",
                  "type_mismatch", "special", "broken", "ok", "checked"):
            assert mine[k] == ref[k], (k, mine[k], ref[k])


if __name__ == "__main__":
    raise SystemExit(pytest.main([os.path.abspath(__file__), "-q"]))

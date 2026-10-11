#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/merge-ci-evidence.sh merge 身份门回归测试（R9-INFRA-CI-MERGEKIND-001）。

九轮基建域验收新 P1：merge 证据收集器计算了父数（is_merge_commit 落 JSON）
却未纳入 verdict——单父 main push commit（如 ff050bb）双平台全绿仍被判
PASS/rc0，非合并提交可取得「合并提交精确双平台记录」绿证据。

根修后语义（tools/merge-ci-evidence.sh 判定步）：
  - 父数 >= 2 的 merge commit 才可 PASS；
  - 单父/零父 commit = 非合并证据目标 → verdict=NOT_MERGE_COMMIT、rc1
    （JSON 与判定一致；gh 实查 run 原始数据仍如实落档）。

本测试用 stub gh（PATH 注入，无网络）+ 临时 git 仓（plumbing 构造，
无 checkout）覆盖：
  R9 负例复现 -> test_single_parent_push_commit_green_runs_must_not_pass
  零父根提交 -> test_zero_parent_root_commit_green_runs_must_not_pass
  真 merge 正例 -> test_two_parent_merge_commit_green_runs_pass
  既有语义保持 -> test_two_parent_merge_commit_red_run_fails
  JSON/rc 一致性 -> 每个 case 均断言 verdict==PASS <=> rc==0

纯标准库；可直接 `python3 system/tests/test_merge_ci_evidence.py`
（exit 0=全绿），也兼容 pytest。
"""
import json
import os
import stat
import subprocess
import sys
import tempfile

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(TESTS_DIR))  # 仓根
SCRIPT = os.path.join(REPO_ROOT, "tools", "merge-ci-evidence.sh")

STUB_GH = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
conclusion = os.environ.get("MERGE_CI_STUB_CONCLUSION", "success")
if "list" in args:
    i = args.index("--commit")
    sha = args[i + 1]
    json.dump([{
        "databaseId": 424242, "event": "push", "headSha": sha,
        "status": "completed", "conclusion": conclusion,
        "workflowName": "acceptance",
        "createdAt": "2026-10-11T00:00:00Z",
        "updatedAt": "2026-10-11T00:05:00Z",
        "url": "https://example.invalid/runs/424242",
    }], sys.stdout)
    print()
elif "view" in args:
    json.dump({
        "databaseId": 424242, "headSha": "stub", "event": "push",
        "status": "completed", "conclusion": conclusion,
        "jobs": [
            {"name": "matrix (ubuntu-latest)", "status": "completed",
             "conclusion": "success"},
            {"name": "matrix (macos-latest)", "status": "completed",
             "conclusion": "success"},
        ],
    }, sys.stdout)
    print()
else:
    print("stub-gh: unsupported invocation: %r" % args, file=sys.stderr)
    sys.exit(2)
'''


def _git(repo, *args, stdin_text=None):
    proc = subprocess.run(
        ["git", "-C", repo, *args], input=stdin_text,
        capture_output=True, text=True)
    assert proc.returncode == 0, f"git {args} 失败: {proc.stderr}"
    return proc.stdout.strip()


def _make_commit(repo, files, parents, msg):
    """plumbing 构造 commit（不动 index/工作树，禁 checkout 红线兼容）。"""
    entries = []
    for name in sorted(files):
        blob = _git(repo, "hash-object", "-w", "--stdin",
                    stdin_text=files[name])
        entries.append(f"100644 blob {blob}\t{name}")
    tree = _git(repo, "mktree", stdin_text="\n".join(entries))
    args = ["commit-tree", tree, "-m", msg]
    for p in parents:
        args += ["-p", p]
    return _git(repo, *args)


def _fixture(tmp):
    """临时 git 仓：A(零父) → B(单父)；C(另一子线)；M(B+C 双亲 merge)。"""
    repo = os.path.join(tmp, "repo")
    subprocess.run(["git", "init", "-q", repo], check=True,
                   capture_output=True)
    _git(repo, "config", "user.email", "proof@test.invalid")
    _git(repo, "config", "user.name", "proof")
    a = _make_commit(repo, {"a": "a"}, [], "A: root")
    b = _make_commit(repo, {"a": "a", "b": "b"}, [a], "B: single parent push")
    c = _make_commit(repo, {"a": "a", "c": "c"}, [a], "C: side branch")
    m = _make_commit(repo, {"a": "a", "b": "b", "c": "c"}, [b, c],
                     "M: merge commit")
    return repo, {"A": a, "B": b, "C": c, "M": m}


def _run_script(repo, sha, tmp, conclusion="success"):
    """stub gh 注入 PATH 后实跑脚本，返回 (rc, verdict, payload)。"""
    bin_dir = os.path.join(tmp, "stubbin")
    os.makedirs(bin_dir, exist_ok=True)
    stub = os.path.join(bin_dir, "gh")
    with open(stub, "w", encoding="utf-8") as fh:
        fh.write(STUB_GH)
    os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR | stat.S_IXGRP
             | stat.S_IXOTH)
    out_dir = os.path.join(tmp, "out")
    os.makedirs(out_dir, exist_ok=True)
    env = dict(os.environ)
    env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    env["MERGE_CI_STUB_CONCLUSION"] = conclusion
    proc = subprocess.run(
        ["bash", SCRIPT, sha, "--repo", repo, "--branch", "main",
         "--slug", "proof/example", "--out-dir", out_dir],
        env=env, capture_output=True, text=True)
    jsons = [f for f in os.listdir(out_dir) if f.endswith(".json")]
    assert len(jsons) == 1, f"应恰好落一个证据 JSON，实得 {jsons}"
    with open(os.path.join(out_dir, jsons[0]), encoding="utf-8") as fh:
        payload = json.load(fh)
    return proc.returncode, payload, proc


def _assert_verdict_rc_consistent(rc, payload):
    """JSON 与判定一致：verdict==PASS <=> rc==0（核心契约）。"""
    verdict = payload["verdict"]
    if verdict == "PASS":
        assert rc == 0, f"verdict=PASS 但 rc={rc}（JSON/判定不一致）"
    else:
        assert rc != 0, f"verdict={verdict} 但 rc=0（JSON/判定不一致）"


def _case(tmpname, sha_name, conclusion, want_rc_zero, want_verdict,
          want_merge):
    with tempfile.TemporaryDirectory(prefix=tmpname) as tmp:
        repo, shas = _fixture(tmp)
        rc, payload, proc = _run_script(repo, shas[sha_name], tmp,
                                        conclusion=conclusion)
        assert payload["verdict"] == want_verdict, (
            f"{sha_name}: verdict 应为 {want_verdict}，实得 "
            f"{payload['verdict']}（stdout: {proc.stdout.strip()[:400]}）")
        assert payload["is_merge_commit"] is want_merge, (
            f"{sha_name}: is_merge_commit 应为 {want_merge}")
        _assert_verdict_rc_consistent(rc, payload)
        assert payload["verdict_reason"], "verdict_reason 不得为空"
        return rc, payload


def test_single_parent_push_commit_green_runs_must_not_pass():
    """R9-INFRA-CI-MERGEKIND-001 负例复现：单父+双平台全绿 → 不得 PASS。"""
    rc, payload = _case("mcie-single-", "B", "success",
                        want_rc_zero=False, want_verdict="NOT_MERGE_COMMIT",
                        want_merge=False)
    assert rc == 1, f"单父绿 run 应 rc1，实得 rc={rc}"
    assert len(payload["commit_parents"]) == 1
    # run 原始证据仍落档（审计价值保持）：stub run 在 push_runs 中可见
    assert any(r.get("databaseId") == 424242
               for r in payload["push_runs"]), "非 merge 拒绝时 run 数据仍须落档"


def test_zero_parent_root_commit_green_runs_must_not_pass():
    """零父根提交同样不是合并证据目标（七·2·4 固化负例之一）。"""
    rc, _ = _case("mcie-root-", "A", "success",
                  want_rc_zero=False, want_verdict="NOT_MERGE_COMMIT",
                  want_merge=False)
    assert rc == 1


def test_two_parent_merge_commit_green_runs_pass():
    """真 merge（父数=2）+ 双平台全绿 → 保持 PASS/rc0（正例不回归）。"""
    _case("mcie-merge-", "M", "success",
          want_rc_zero=True, want_verdict="PASS", want_merge=True)


def test_two_parent_merge_commit_red_run_fails():
    """merge commit 但 run 非 success → FAIL/rc1（既有证据不足语义保持）。"""
    _case("mcie-red-", "M", "failure",
          want_rc_zero=False, want_verdict="FAIL", want_merge=True)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    print(f"== merge-ci-evidence merge 身份门回归（{len(tests)} 组）==")
    failed = 0
    for t in tests:
        print(f"-- {t.__name__}")
        try:
            t()
        except Exception as exc:  # 崩溃=失败，不静默
            import traceback
            traceback.print_exc()
            failed += 1
    print("=" * 40)
    print(f"RESULT: {'PASS' if not failed else 'FAIL'} "
          f"({len(tests) - failed}/{len(tests)})")
    sys.exit(1 if failed else 0)

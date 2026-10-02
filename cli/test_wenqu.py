# -*- coding: utf-8 -*-
"""wenqu CLI 端到端契约测试（subprocess 黑盒——与语言/宿主零耦合，只认退出码与输出）。"""
import json
import subprocess
import sys

nl = chr(10)
from pathlib import Path

import pytest

CLI = str(Path(__file__).parent / "wenqu")

def jl(d):
    """jsonl 行构造（一行一 JSON，带换行）。"""
    return json.dumps(d, ensure_ascii=False) + nl


def wq(home, *args, expect=None):
    r = subprocess.run([sys.executable, CLI, "--home", str(home), *args],
                       capture_output=True, text=True, encoding="utf-8")
    if expect is not None:
        assert r.returncode == expect, f"{args} 退出 {r.returncode}≠{expect}\n{r.stdout}\n{r.stderr}"
    return r


@pytest.fixture()
def repo(tmp_path):
    (tmp_path / "r").mkdir()
    (tmp_path / "r" / "a.py").write_text("x=1\n", encoding="utf-8")
    (tmp_path / "r" / "b.sh").write_text("echo hi\n", encoding="utf-8")
    return tmp_path / "r"


def test_selftest_zero_dep():
    wq(tmp_home(), "selftest", expect=0)


def test_init_scope_freeze_idempotent(repo, tmp_path):
    h1, h2 = tmp_path / "h1", tmp_path / "h2"
    o1 = wq(h1, "init", "--path", str(repo), expect=0).stdout
    o2 = wq(h2, "init", "--path", str(repo), expect=0).stdout
    hash1 = o1.split("scope_hash=")[1].split("，")[0]
    assert hash1 and hash1 in o2, "同范围两次冻结 hash 应一致"


def test_init_ignores_junk_dirs(repo, tmp_path):
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "x.js").write_text("junk", encoding="utf-8")
    o = wq(tmp_path / "h", "init", "--path", str(repo), expect=0).stdout
    assert "2 文件" in o, "SKIP_DIRS 未生效"


def test_ingest_rejects_dirty_and_dup(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"id":"B-1","sev":"HIGH","status":"OPEN"}\n'
                   '{"id":"B-1","sev":"HIGH","status":"OPEN"}\n'
                   '{"id":"B-2","sev":"X","status":"OPEN"}\n'
                   '{"id":"B-3","sev":"HIGH","status":"也许吧"}\n', encoding="utf-8")
    r = wq(h, "ingest", "--path", str(repo), str(bad), expect=2)
    assert "原子拒绝" in r.stderr and "0 条入账" in r.stderr  # 加固⑥：默认全有或全无


def test_dialect_normalization(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    f = tmp_path / "cn.jsonl"
    f.write_text(json.dumps({"id": "CN-1", "severity": "高", "status": "OPEN"}, ensure_ascii=False) + "\n",
                 encoding="utf-8")
    wq(h, "ingest", "--path", str(repo), str(f), expect=0)
    o = wq(h, "findings", "--sev", "HIGH").stdout
    assert "CN-1" in o and "HIGH" in o, "severity/高 双方言未归一"


def test_close_append_only_and_verify_gate(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    f = tmp_path / "f.jsonl"
    f.write_text('{"id":"F-1","sev":"LOW","status":"OPEN","title":"t"}\n', encoding="utf-8")
    wq(h, "ingest", "--path", str(repo), str(f), expect=0)
    wq(h, "verify", "--path", str(repo), "--allow-open", "0", expect=1)
    wq(h, "close", "--path", str(repo), "F-1", "--to", "CLOSED", "--note", "测试", expect=0)
    wq(h, "verify", "--path", str(repo), "--allow-open", "0", expect=0)
    led = (h / "findings.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(led) == 2 and led[0].startswith("{") and '"transition"' in led[1], "append-only 破坏"


def test_close_rejects_unknown_and_empty(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    wq(h, "close", "--path", str(repo), "GHOST", "--note", "x", expect=2)


def test_run_unknown_station(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    wq(h, "run", "--path", str(repo), "no-such", expect=2)


def tmp_home():
    import tempfile
    return Path(tempfile.mkdtemp()) / "h"


def test_auto_id_collision_guard():
    import importlib.util
    from importlib.machinery import SourceFileLoader
    spec = importlib.util.spec_from_loader("wenqu_mod", SourceFileLoader("wenqu_mod", CLI))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    a, b = m._auto_id("tests"), m._auto_id("tests")
    assert a != b, "同秒同站双 FAIL 的 AUTO id 应互异（加固①）"


def test_scope_drift_detection(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo), expect=0)
    wq(h, "verify", "--path", str(repo), "--check-scope", "--allow-open", "99", expect=0)
    (repo / "a.py").write_text("x = 2  # 改动\n", encoding="utf-8")
    r = wq(h, "verify", "--path", str(repo), "--check-scope", "--allow-open", "99", expect=1)
    assert "范围漂移" in r.stdout, "漂移未报"
    wq(h, "verify", "--path", str(repo), "--check-scope", "--allow-drift", "--allow-open", "99", expect=0)
    (repo / "a.py").write_text("x=1\n", encoding="utf-8")
    wq(h, "verify", "--path", str(repo), "--check-scope", "--allow-open", "99", expect=0)


def test_include_flag(repo, tmp_path):
    (repo / "c.js").write_text("j;", encoding="utf-8")
    o = wq(tmp_path / "h", "init", "--path", str(repo), "--include", ".py", expect=0).stdout
    assert "1 文件" in o, "--include 未收窄范围（仅 .py 应=1，.sh/.js 排除）"


def test_transition_schema_guard(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    f = tmp_path / "f.jsonl"
    f.write_text('{"id":"T-1","sev":"LOW","status":"OPEN"}\n', encoding="utf-8")
    wq(h, "ingest", "--path", str(repo), str(f), expect=0)
    bad = tmp_path / "badtr.jsonl"
    bad.write_text('{"kind":"transition","id":"T-1","to":"随便什么"}\n', encoding="utf-8")
    wq(h, "ingest", "--path", str(repo), str(bad), expect=2)


def test_show_reveals_transition_chain(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    f = tmp_path / "f.jsonl"
    f.write_text('{"id":"S-1","sev":"LOW","status":"OPEN"}\n', encoding="utf-8")
    wq(h, "ingest", "--path", str(repo), str(f), expect=0)
    wq(h, "close", "--path", str(repo), "S-1", "--note", "审计可见性测试", expect=0)
    o = wq(h, "show", "--path", str(repo), "S-1", expect=0).stdout
    assert '"meta"' in o and "审计可见性测试" in o and '"from": "OPEN"' in o and '"to": "CLOSED"' in o and '"转移链"' in o  # v0.2#19 命名空间格式


def test_orphan_transition_rejected(repo, tmp_path):
    h = tmp_path / 'h'
    wq(h, 'init', '--path', str(repo))
    f = tmp_path / 'ghost.jsonl'
    f.write_text(jl({'kind':'transition','id':'GHOST-9','to':'CLOSED'}), encoding='utf-8')
    r = wq(h, 'ingest', '--path', str(repo), str(f), expect=2)
    assert '孤儿转移' in r.stderr
    wq(h, 'findings', '--path', str(repo), expect=0)  # 账本未被砖死

def test_partial_flag_restores_old_behavior(repo, tmp_path):
    h = tmp_path / 'h'
    wq(h, 'init', '--path', str(repo))
    f = tmp_path / 'mix.jsonl'
    f.write_text(jl({'id':'P-1','sev':'LOW','status':'OPEN'})+jl({'id':'P-2','sev':'BAD','status':'OPEN'}), encoding='utf-8')
    r = wq(h, 'ingest', '--path', str(repo), '--partial', str(f), expect=2)
    assert '入账 1 条' in r.stdout and '拒绝 1' in r.stdout

def test_include_bare_suffix_normalized(repo, tmp_path):
    (repo / 'copy').write_text('not-python', encoding='utf-8')  # 裸 py 若不加点会误匹配
    o = wq(tmp_path / 'h', 'init', '--path', str(repo), '--include', 'py', expect=0).stdout
    assert '1 文件' in o, '裸后缀未归一为 .py（copy 被误扫）'


def test_v02_repair_roundtrip(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    f = tmp_path / "f.jsonl"
    f.write_text(jl({"id": "R-1", "sev": "LOW", "status": "OPEN"}), encoding="utf-8")
    wq(h, "ingest", "--path", str(repo), str(f), expect=0)
    led = h / "findings.jsonl"
    led.write_text(led.read_text(encoding="utf-8") + "{坏行\n", encoding="utf-8")  # 人为损坏
    wq(h, "findings", "--path", str(repo), expect=2)  # 损坏账本应报错
    wq(h, "repair", "--path", str(repo), expect=0)  # v0.2#7
    o = wq(h, "findings", "--path", str(repo), expect=0).stdout
    assert "R-1" in o
    assert (h / "findings.jsonl.quarantine").exists()


def test_v02_gate_flag_and_statemachine(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    f = tmp_path / "f.jsonl"
    f.write_text(jl({"id": "G-1", "sev": "HIGH", "status": "FIXED"}), encoding="utf-8")
    wq(h, "ingest", "--path", str(repo), str(f), expect=0)
    wq(h, "findings", "--path", str(repo), "--sev", "HIGH", expect=0)  # 有 HIGH 但无 gate → 0
    wq(h, "findings", "--path", str(repo), "--sev", "HIGH", "--gate", expect=1)  # v0.2#15
    wq(h, "close", "--path", str(repo), "G-1", "--to", "FIXING", "--note", "终态横跳应拒", expect=2)  # v0.2#14
    wq(h, "close", "--path", str(repo), "G-1", "--to", "OPEN", "--note", "重开合法", expect=0)
    wq(h, "close", "--path", str(repo), "G-1", "--to", "FIXING", "--note", "allow-any 逃生门", "--allow-any", expect=0)


def test_v02_init_force_guard(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo), expect=0)
    f = tmp_path / "f.jsonl"
    f.write_text(jl({"id": "F-1", "sev": "LOW", "status": "OPEN"}), encoding="utf-8")
    wq(h, "ingest", "--path", str(repo), str(f), expect=0)
    (repo / "new.py").write_text("y=2\n", encoding="utf-8")  # 范围漂移
    wq(h, "init", "--path", str(repo), expect=2)  # v0.2#11：账本非空+漂移 → 拒
    wq(h, "init", "--path", str(repo), "--force", expect=0)


def test_v02_utc_timestamps(repo, tmp_path):
    h = tmp_path / "h"
    wq(h, "init", "--path", str(repo))
    f = tmp_path / "f.jsonl"
    f.write_text(jl({"id": "U-1", "sev": "LOW", "status": "OPEN"}), encoding="utf-8")
    wq(h, "ingest", "--path", str(repo), str(f), expect=0)
    led = (h / "findings.jsonl").read_text(encoding="utf-8")
    import time as _t; _utc = _t.strftime("%Y-%m-%dT%H:%M", _t.gmtime()); assert ('"ts": "' + _utc[:16]) in led or (_t.strftime("%Y-%m-%dT%H:%M", _t.localtime()) != _utc and False), "ts 须为 UTC（gmtime）——原断言 A and B or C 空转，localtime 回归照绿（S4-7）"

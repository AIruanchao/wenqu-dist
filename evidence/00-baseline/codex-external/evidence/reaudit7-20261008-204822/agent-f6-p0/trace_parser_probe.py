#!/usr/bin/env python3
"""第七轮独立追踪 parser 探针。所有变异均在临时目录。"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

repo = Path(sys.argv[1]).resolve()
tool = repo / "tools/ac_traceability.py"
plan = repo / "evidence/00-baseline/codex-external/方案.md"


def run(name, plan_path):
    out = root / f"{name}.json"
    p = subprocess.run(
        [sys.executable, str(tool), "--check", "--json", str(out),
         "--plan", str(plan_path)], cwd=repo, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    doc = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    pc = doc.get("meta", {}).get("plan_cross_check") or {}
    print(json.dumps({
        "probe": name,
        "rc": p.returncode,
        "catalog_integrity": doc.get("meta", {}).get("catalog_integrity"),
        "plan_sha256_match": doc.get("meta", {}).get("plan_sha256_match"),
        "plan_check_ok": pc.get("ok"),
        "duplicate_row_count": pc.get("duplicate_row_count"),
        "problem_count": len(doc.get("meta", {}).get("catalog_problems") or []),
        "stdout_tail": p.stdout[-400:],
    }, ensure_ascii=False, sort_keys=True))
    return p.returncode, doc


with tempfile.TemporaryDirectory(prefix="reaudit7-trace-") as td:
    root = Path(td)
    rc, d = run("control", plan)
    assert rc == 0
    assert d["meta"]["catalog_integrity"] == "OK"
    assert d["meta"]["plan_sha256_match"] is True

    rc, d = run("missing_plan", root / "does-not-exist.md")
    assert rc == 2 and d["meta"]["catalog_integrity"] == "FAIL"

    original = plan.read_text(encoding="utf-8")
    # 在 §20 内插入一条与 GATE-01 完全相同的数据行。
    gate_line = next(line for line in original.splitlines()
                     if line.startswith("| GATE-01 |"))
    pos = original.index("# 21.")
    dup = original[:pos] + gate_line + "\n" + original[pos:]
    dup_path = root / "duplicate.md"
    dup_path.write_text(dup, encoding="utf-8")
    rc, d = run("duplicate_identical_row", dup_path)
    pc = d["meta"]["plan_cross_check"]
    assert rc == 2 and d["meta"]["catalog_integrity"] == "FAIL"
    assert pc["duplicate_row_count"] >= 1

    # 仅在 §20/§25 之外追加一个字节：语义表不变，也必须被全文件 SHA 拦下。
    outside = root / "outside_section_byte.md"
    outside.write_text(original + "\nX", encoding="utf-8")
    rc, d = run("outside_section_sha_drift", outside)
    assert rc == 2 and d["meta"]["catalog_integrity"] == "FAIL"
    assert d["meta"]["plan_sha256_match"] is False

print("RESULT: parser missing/duplicate/full-file-sha probes all fail-closed")

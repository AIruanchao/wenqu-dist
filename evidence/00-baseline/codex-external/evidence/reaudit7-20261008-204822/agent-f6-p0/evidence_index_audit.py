#!/usr/bin/env python3
"""严格逐条复算 evidence/evidence-index.json，不信自报。"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

repo = Path(sys.argv[1]).resolve()
src = repo / "evidence/evidence-index.json"
out_path = Path(sys.argv[2]).resolve()
doc = json.loads(src.read_text(encoding="utf-8"))
entries = doc.get("entries")
assert isinstance(entries, list)

required = (
    "entry_id", "run_id", "commit", "environment", "scope", "ruleset",
    "time", "argv", "real_rc", "artifact_sha256", "evidence_path",
    "fresh_until",
)
sha40_exact = re.compile(r"^[0-9a-f]{40}$")
sha40_any = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
sha64_exact = re.compile(r"^[0-9a-f]{64}$")

rows = []
for e in entries:
    p = e.get("evidence_path")
    path = repo / p if isinstance(p, str) else None
    is_file = bool(path and path.is_file())
    is_dir = bool(path and path.is_dir())
    actual = None
    if is_file:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        actual = h.hexdigest()
    artifact = e.get("artifact_sha256")
    commit = e.get("commit")
    nonempty = {}
    for k in required:
        v = e.get(k)
        nonempty[k] = not (
            v is None or v == "" or v == [] or v == {}
        )
    row = {
        "entry_id": e.get("entry_id"),
        "all_required_nonempty": all(nonempty.values()),
        "missing_or_empty": [k for k, ok in nonempty.items() if not ok],
        "commit_exact_40hex": isinstance(commit, str) and bool(sha40_exact.fullmatch(commit)),
        "commit_contains_40hex": isinstance(commit, str) and bool(sha40_any.search(commit)),
        "path_regular_file": is_file,
        "path_is_directory": is_dir,
        "artifact_hash_bare_64hex": isinstance(artifact, str) and bool(sha64_exact.fullmatch(artifact)),
        "artifact_hash_matches_file": is_file and isinstance(artifact, str) and artifact == actual,
        "actual_sha256": actual,
    }
    # 用户本轮声明的三项核心合同：完整 SHA、文件级路径、文件实算 hash。
    row["declared_three_way_contract"] = (
        row["commit_exact_40hex"] and row["path_regular_file"]
        and row["artifact_hash_matches_file"]
    )
    # 第六轮严格合同再加 run/环境/scope/ruleset/time/argv/rc/freshness 非空。
    row["strict_contract"] = row["declared_three_way_contract"] and row["all_required_nonempty"]
    rows.append(row)

def count(key):
    return sum(bool(r[key]) for r in rows)

report = {
    "index_path": str(src.relative_to(repo)),
    "repo_head": os.popen(f"git -C {repo!s} rev-parse HEAD").read().strip(),
    "repo_head_at_filing": doc.get("repo_head_at_filing"),
    "entries": len(rows),
    "counts": {
        "all_required_nonempty": count("all_required_nonempty"),
        "commit_exact_40hex": count("commit_exact_40hex"),
        "commit_contains_40hex": count("commit_contains_40hex"),
        "path_regular_file": count("path_regular_file"),
        "artifact_hash_bare_64hex": count("artifact_hash_bare_64hex"),
        "artifact_hash_matches_file": count("artifact_hash_matches_file"),
        "declared_three_way_contract": count("declared_three_way_contract"),
        "strict_contract": count("strict_contract"),
    },
    "rows": rows,
}
out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"entries": len(rows), **report["counts"]}, ensure_ascii=False, sort_keys=True))
for row in rows:
    if not row["strict_contract"]:
        print(json.dumps({
            "entry_id": row["entry_id"],
            "missing_or_empty": row["missing_or_empty"],
            "commit_exact_40hex": row["commit_exact_40hex"],
            "path_regular_file": row["path_regular_file"],
            "artifact_hash_bare_64hex": row["artifact_hash_bare_64hex"],
            "artifact_hash_matches_file": row["artifact_hash_matches_file"],
        }, ensure_ascii=False, sort_keys=True))
sys.exit(0 if report["counts"]["strict_contract"] == len(rows) else 1)

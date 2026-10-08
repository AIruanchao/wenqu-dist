#!/usr/bin/env python3
"""方案.md 交接前静态一致性检查。只读，不执行生产动作。"""
from __future__ import annotations
import hashlib, json, re, sys
from collections import Counter, defaultdict, deque
from pathlib import Path

plan = Path(sys.argv[1] if len(sys.argv) > 1 else "方案.md").resolve()
root = plan.parent
raw = plan.read_bytes()
checks: list[dict] = []

def record(name: str, ok: bool, detail: str) -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})

try:
    text = raw.decode("utf-8", errors="strict")
    record("utf8", True, f"{len(raw)} bytes")
except UnicodeDecodeError as exc:
    record("utf8", False, str(exc)); text = raw.decode("utf-8", errors="replace")
lines = text.splitlines()
record("no_nul", "\x00" not in text, "NUL absent" if "\x00" not in text else "NUL present")
record("frontmatter", len(lines) > 2 and lines[0] == "---" and "---" in lines[1:20], "YAML delimiters")

fences = [i for i,l in enumerate(lines,1) if l.strip().startswith("```")]
record("code_fences", len(fences) % 2 == 0, f"count={len(fences)}")

# Markdown table structure: every contiguous pipe-table block must keep a fixed column count.
table_errors=[]; in_fence=False; current=[]
for i,l in enumerate(lines+[''],1):
    if l.strip().startswith('```'):
        in_fence=not in_fence
    if not in_fence and l.startswith('|') and l.endswith('|'):
        current.append((i,l.count('|')-1))
    else:
        if current:
            counts={c for _,c in current}
            if len(counts)!=1: table_errors.append({"lines":[x for x,_ in current],"columns":sorted(counts)})
            current=[]
record("markdown_tables", not table_errors, "all table blocks consistent" if not table_errors else json.dumps(table_errors,ensure_ascii=False))

required_headings = [
    "# 8. 实施依赖图", "# 12. 工作包 W3A/W3B", "# 20. 强制红探针与验收矩阵",
    "## 25.1 全部验收 ID 的反向需求/AC 映射", "# 27. 本方案自身验证要求",
    "# 28. ZCode 首轮落刀靶点"
]
missing_headings=[h for h in required_headings if h not in text]
record("required_sections", not missing_headings, "present" if not missing_headings else str(missing_headings))

headings=[l for l in lines if l.startswith("#")]
heading_dups={k:v for k,v in Counter(headings).items() if v>1}
section_ids=re.findall(r"^#{1,6}\s+(\d+(?:\.\d+)*)\b", text, re.M)
section_dups={k:v for k,v in Counter(section_ids).items() if v>1}
record("heading_uniqueness", not heading_dups and not section_dups,
       f"headings={len(headings)}, duplicate_headings={heading_dups or 'none'}, duplicate_sections={section_dups or 'none'}")
section_refs=set(re.findall(r"§\s*(\d+(?:\.\d+)*)", text))
missing_refs=sorted(section_refs-set(section_ids))
record("section_references", not missing_refs, f"refs={sorted(section_refs)}, missing={missing_refs}")

placeholder = re.findall(r"(?im)\b(?:TODO|TBD|FIXME)\b|待补(?:充|全)?|<待[^>]*>", text)
record("no_placeholders", not placeholder, "none" if not placeholder else repr(placeholder[:10]))
record("blocked_boundary", "current_release_decision: BLOCKED" in text and "方案已验证，不等于整改已验证" in text,
       "current decision and boundary explicit")

allowed_work = {"W0","W1","W2","W3","W3A","W3B","W4","W5","W6","W6A","W6B","W6C","W6D","W7","W7A","W7B","W8","W9","W10"}
work_refs=set(re.findall(r"\bW(?:10|[0-9])[A-Z]?\b",text))
record("work_package_refs", work_refs <= allowed_work and {"W0","W1","W2","W3A","W3B","W4","W5","W6A","W6B","W6C","W6D","W7A","W7B","W8","W9","W10"} <= work_refs,
       f"refs={','.join(sorted(work_refs))}; undefined={','.join(sorted(work_refs-allowed_work)) or 'none'}")

# The authoritative DAG is duplicated here intentionally: if prose dependencies change, update both and review the diff.
edges = {
 "W0":["W1"], "W1":["W2"], "W2":["W3A","W5","W7A"], "W3A":["W6A"],
 "W6A":["W6B","W6C","W6D","W3B","W4","W8","W7B"],
 "W6B":["W3B","W4","W8","W7B"], "W6C":["W3B","W4","W8","W7B"],
 "W6D":["W3B","W4","W8","W7B"], "W3B":["W8","W7B"], "W5":["W8","W7B"],
 "W7A":["W4","W8","W7B"], "W4":["W7B"], "W8":["W7B"], "W7B":["W9"], "W9":["W10"]
}
nodes=set(edges)
for vs in edges.values(): nodes.update(vs)
ind={n:0 for n in nodes}
for u,vs in edges.items():
    for v in vs: ind[v]+=1
q=deque(sorted(n for n,d in ind.items() if d==0)); topo=[]
while q:
    u=q.popleft(); topo.append(u)
    for v in edges.get(u,[]):
        ind[v]-=1
        if ind[v]==0: q.append(v)
record("dag_acyclic", len(topo)==len(nodes), "topo="+"→".join(topo) if len(topo)==len(nodes) else "cycle detected")
for token in ["W3A+W6A+W6B+W6C+W6D", "W3B+W4+W5+W6A～W6D+W7A+W8", "W7B ──→ W9"]:
    record("dag_text_"+hashlib.sha1(token.encode()).hexdigest()[:8], token in text, token)

# Test definition/mapping equality.
try:
    s20=text.split("# 20.",1)[1].split("\n# 21.",1)[0]
    s251=text.split("## 25.1",1)[1].split("\n---",1)[0]
except IndexError:
    s20=s251=""
defined=re.findall(r"^\|\s*([A-Z]+-\d+)\s*\|",s20,re.M)
dup={k:v for k,v in Counter(defined).items() if v>1}
record("test_ids_unique", not dup, f"defined={len(defined)}, duplicates={dup or 'none'}")

def expand_ranges(s: str) -> set[str]:
    out=set()
    # FAMILY-01～12
    for fam,a,b in re.findall(r"\b([A-Z]+)-(\d+)～(\d+)\b",s):
        width=len(a)
        out.update(f"{fam}-{i:0{width}d}" for i in range(int(a),int(b)+1))
    # singleton not already covered
    for fam,n in re.findall(r"\b([A-Z]+)-(\d+)\b",s): out.add(f"{fam}-{n}")
    return out
mapped=set()
for row in s251.splitlines():
    if re.match(r"^\|\s*[A-Z]+-\d+", row):
        first=row.strip("|").split("|",1)[0].strip()
        mapped.update(expand_ranges(first))
record("test_traceability_set_equality", set(defined)==mapped,
       f"defined={len(set(defined))}, mapped={len(mapped)}, missing={sorted(set(defined)-mapped)}, extra={sorted(mapped-set(defined))}")

# Finding-family matrix integrity and test references.
try: fsec=text.split("# 25.",1)[1].split("## 25.1",1)[0]
except IndexError: fsec=""
fids=re.findall(r"^\|\s*(FND-\d+)\s*\|",fsec,re.M)
record("fnd_ids", fids==[f"FND-{i:03d}" for i in range(1,22)], f"count={len(fids)}, ids={fids}")
fnd_rows=[l for l in fsec.splitlines() if re.match(r"^\|\s*FND-\d+\s*\|",l)]
bad_rows=[]
for row in fnd_rows:
    cells=[c.strip() for c in row.strip('|').split('|')]
    if len(cells)!=5 or any(not c for c in cells): bad_rows.append(row)
    for tid in expand_ranges(cells[3] if len(cells)>3 else ''):
        if tid not in set(defined): bad_rows.append(f"undefined {tid} in {cells[0]}")
record("fnd_rows_complete", not bad_rows, "all 21 rows complete" if not bad_rows else repr(bad_rows))
record("legacy_reconcile_boundary", "481 条逐项 reconciliation 索引" in text and "不在本方案验证阶段冒充已完成" in text,
       "legacy 481 explicitly deferred to W5")

# Stop types and protected-action invariants.
stopsec=text.split("### 6.2.1",1)[1].split("### 6.2.2",1)[0] if "### 6.2.1" in text else ""
stops=["ambiguity","prod-write","ddl","release","scope","fund-auth","exm-fuse","resource","ext-unavail"]
missing_stops=[s for s in stops if f"`{s}`" not in stopsec]
rows=[l for l in stopsec.splitlines() if re.match(r"^\|\s*\d+\s*\|",l)]
record("nine_stop_types", len(rows)==9 and not missing_stops and all("一次性" in r for r in rows),
       f"rows={len(rows)}, missing={missing_stops}, all_one_time={all('一次性' in r for r in rows)}")
for invariant in ["technical_eligible", "action_eligible", "valid_exact_action_authorization", "NoStageAdvanceWithoutPriorStagePass", "NoMergeOrReleaseUnlessActionEligible", "ACTION_FAILED_UNKNOWN"]:
    record("invariant_"+invariant.lower(), invariant in text, invariant)

# Key source anchors exist now; content is a time-bound snapshot, not a deployment assertion.
source_paths=[]
if "# 28." in text:
    sec28=text.split("# 28.",1)[1]
    source_paths=[]
    for row in sec28.splitlines():
        m=re.match(r"^\|\s*`(/[^`]+)`\s*\|", row)
        if m: source_paths.append(m.group(1))
missing_paths=[p for p in source_paths if not Path(p).exists()]
record("source_targets_exist", len(source_paths)>=15 and not missing_paths, f"count={len(source_paths)}, missing={missing_paths}")

# Evidence manifest integrity (manifest intentionally does not hash itself).
evdir=root/"evidence"/"reaudit-20261007"; manifest=evdir/"manifest.sha256"; mismatches=[]; entries=0
if manifest.exists():
    for line in manifest.read_text(encoding='utf-8').splitlines():
        if not line.strip(): continue
        m=re.match(r"^([0-9a-f]{64})\s+\*?(?:\./)?(.+)$",line)
        if not m: mismatches.append("bad-line:"+line); continue
        want,rel=m.groups(); p=evdir/rel; entries+=1
        if not p.is_file(): mismatches.append("missing:"+rel); continue
        got=hashlib.sha256(p.read_bytes()).hexdigest()
        if got!=want: mismatches.append("hash:"+rel)
else: mismatches.append("manifest missing")
record("evidence_manifest", entries>0 and not mismatches, f"entries={entries}, issues={mismatches}")

ok=all(c["ok"] for c in checks)
out={"schema":"plan-validation-v1","plan":str(plan),"plan_sha256":hashlib.sha256(raw).hexdigest(),"checks":checks,"passed":sum(c['ok'] for c in checks),"failed":sum(not c['ok'] for c in checks),"ok":ok}
print(json.dumps(out,ensure_ascii=False,indent=2))
sys.exit(0 if ok else 1)

#!/usr/bin/env python3
from pathlib import Path
import hashlib
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: make-trace-mutations.py PLAN OUTDIR")

src = Path(sys.argv[1])
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
text = src.read_text(encoding="utf-8")

def one(name: str, old: str, new: str) -> None:
    n = text.count(old)
    assert n >= 1, (name, old, n)
    # 只改首个命中，防止 §25.1 范围文本等无关位置被连带改写。
    payload = text.replace(old, new, 1)
    p = out / f"{name}.md"
    p.write_text(payload, encoding="utf-8")
    print(f"{name}: replacements=1 sha256={hashlib.sha256(p.read_bytes()).hexdigest()} path={p}")

one("id-drift",
    "| GATE-01 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |",
    "| GATE-99 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |")
one("semantic-injection-drift",
    "| GATE-01 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |",
    "| GATE-01 | base ref 存在且 fetch 成功 | ERROR/BLOCKED |")
one("semantic-expectation-drift",
    "| GATE-01 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |",
    "| GATE-01 | base ref 不存在/fetch 失败 | PASS |")
one("section251-metadata-drift",
    "| GATE-01～12 | REQ-EVID-001 / AC-EVID-FAIL-CLOSED | W2/W3A/W3B | raw rc、CAS、before/after |",
    "| GATE-01～12 | REQ-EVID-TAMPER / AC-EVID-FAIL-CLOSED | W2/W3A/W3B | raw rc、CAS、before/after |")
one("duplicate-identical-row",
    "| GATE-01 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |",
    "| GATE-01 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |\n"
    "| GATE-01 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |")
one("poison-first-row",
    "| GATE-01 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |",
    "| GATE-01 | poison-first 独立注入 | PASS |\n"
    "| GATE-01 | base ref 不存在/fetch 失败 | ERROR/BLOCKED |")

p = out / "outside-sections-byte-drift.md"
p.write_text(text + "\n<!-- reaudit7 independent outside-section byte drift -->\n", encoding="utf-8")
print(f"outside-sections-byte-drift: append=1 sha256={hashlib.sha256(p.read_bytes()).hexdigest()} path={p}")

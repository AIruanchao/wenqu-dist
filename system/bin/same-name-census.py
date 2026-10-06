#!/usr/bin/env python3
"""same-name-census —— 同名函数多胞胎普查（jscpd 短块维度的互补件）

jscpd 抓 ≥min-lines 的长块克隆；本件抓「同名函数跨文件散播」（含 3-4 行短函数，
jscpd 不计但会语义漂移）。普查战役（2026-10-06~07，r9~r15 七批）沉淀：244 份位归正源。

用法：
  python3 scripts/dupscan/same-name-census.py [--min N] [--jsx]
    --min N   只报 ≥N 份位的族（默认 2）
    --jsx     连 React 组件（返回 JSX）族也报（默认只报纯函数）

判读铁律（战役沉淀）：
  1. normalize 后 md5 同体才可机械收编（剥 export/async 前缀+空白归一——r11 实锄盲区）；
  2. 同名异构（各文件自己的逻辑）止刀有据，不追；
  3. 近义不同体（如 strict/lenient、签名宽窄）禁盲合，挂语义裁定；
  4. 工单必带「宁缺勿错」跳过条款+收编后残留逐文件核对。
"""
import argparse
import collections
import hashlib
import os
import re
import sys

PAT = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(", re.M)
SKIP = {"generateMetadata", "generateStaticParams", "default",
        "GET", "POST", "PATCH", "DELETE", "PUT", "HEAD", "OPTIONS"}


def extract_all(path):
    try:
        txt = open(path, errors="ignore").read()
    except OSError:
        return []
    out = []
    for m in PAT.finditer(txt):
        name = m.group(1)
        if name in SKIP:
            continue
        i = txt.find("{", m.start())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(txt):
            if txt[j] == "{":
                depth += 1
            elif txt[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= len(txt):
            continue
        out.append((name, txt[m.start():j + 1]))
    return out


def norm(body: str) -> str:
    return re.sub(r"\s+", " ", body.replace("export ", "").replace("async ", "")).strip()


def is_pure_fn(body: str) -> bool:
    tail = body.split("return", 1)[-1][:3]
    return "<" not in tail and "React" not in body[:60]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min", type=int, default=2)
    ap.add_argument("--jsx", action="store_true")
    ap.add_argument("--root", default="src")
    a = ap.parse_args()

    bodies = collections.defaultdict(lambda: collections.defaultdict(list))
    for root, dirs, files in os.walk(a.root):
        dirs[:] = [d for d in dirs if d != "node_modules"]
        for f in files:
            if not f.endswith((".ts", ".tsx")) or f.endswith(".test.ts"):
                continue
            p = os.path.join(root, f)
            for name, body in extract_all(p):
                if not a.jsx and not is_pure_fn(body):
                    continue
                h = hashlib.md5(norm(body).encode()).hexdigest()[:8]
                bodies[name][h].append((p, len(body.splitlines())))

    total = 0
    for name, groups in sorted(bodies.items(), key=lambda kv: kv[0]):
        for h, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            fs = sorted(set(p for p, _ in items))
            if len(fs) >= a.min:
                total += len(fs)
                lines = items[0][1]
                print(f"{len(fs)}× {name} ({lines}L) [{h}]")
                for f in fs:
                    print(f"   {f}")
    print(f"-- 共 {total} 份位", file=sys.stderr)


if __name__ == "__main__":
    main()

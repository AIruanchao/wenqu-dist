#!/usr/bin/env python3
"""check-openapi-compat —— openapi 向后兼容门（机械门④，r19 新增）

防破坏性变更静默合流：diff 当前 openapi.json 与形状基线（docs/api/openapi-compat-baseline.json），
出现消费方破坏性变更即红，须 PR 标题带 [L3]（生产变更级）并随 PR 更新基线才放行。

检测三类破坏（MVP 口径，覆盖主消费方断链场景）：
  1. path/method 删除
  2. requestBody schema：可选字段变必填（required 列表新增）、字段删除
  3. response schema：字段删除、类型变更

非破坏（放行）：新增 path、新增可选字段、description/examples 变化。
基线更新：`python3 scripts/gates/check-openapi-compat.py --update-baseline`（[L3] PR 合流后跑）。

用法：
  python3 scripts/gates/check-openapi-compat.py                 # 检查模式（CI/pre-push）
  python3 scripts/gates/check-openapi-compat.py --update-baseline
"""
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OPENAPI = os.path.join(REPO, "docs/api/openapi.json")
BASELINE = os.path.join(REPO, "docs/api/openapi-compat-baseline.json")
L3_RE = re.compile(r"\[L3\]")


def shape_of(spec: dict) -> dict:
    """从 openapi 提取兼容性形状骨架（paths/methods/schema 字段名+required+类型，丢弃描述类噪音）。"""
    out = {}
    for path, item in (spec.get("paths") or {}).items():
        for method, op in (item or {}).items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            key = f"{method.upper()} {path}"
            entry = {}
            rb = op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
            req = schema_fields(rb)
            if req:
                entry["request"] = req
            resp_fields = {}
            for code, r in (op.get("responses") or {}).items():
                sc = r.get("content", {}).get("application/json", {}).get("schema", {})
                f = schema_fields(sc)
                if f:
                    resp_fields[str(code)] = f
            if resp_fields:
                entry["responses"] = resp_fields
            out[key] = entry
    return out


def schema_fields(schema: dict, depth: int = 0) -> dict:
    """递归提取 schema 形状：{字段名: 类型, __required__: [...]}。"""
    if depth > 4 or not isinstance(schema, dict):
        return {}
    out = {}
    props = schema.get("properties")
    if isinstance(props, dict):
        req = set(schema.get("required") or [])
        out["__required__"] = sorted(req)
        for name, sub in props.items():
            t = sub.get("type") or ("ref:" + sub.get("$ref", "?").split("/")[-1] if "$ref" in sub else "?")
            inner = schema_fields(sub, depth + 1)
            if inner and t in ("object", "array"):
                out[name] = {"t": t, "f": inner}
            else:
                out[name] = t
    items = schema.get("items")
    if isinstance(items, dict) and depth < 4:
        inner = schema_fields(items, depth + 1)
        if inner:
            return {"t": "array", "f": inner}
    return out


def diff_breaking(old: dict, new: dict) -> list:
    breaks = []
    for key in sorted(set(old) - set(new)):
        breaks.append(f"端点删除: {key}")
    for key in sorted(set(old) & set(new)):
        o, n = old[key], new[key]
        oreq = set(o.get("request", {}).get("__required__", []))
        nreq = set(n.get("request", {}).get("__required__", []))
        for f in sorted(nreq - oreq):
            breaks.append(f"{key} 请求体字段变必填: {f}")
        for f in sorted(set(o.get("request", {})) - set(n.get("request", {})) - {"__required__"}):
            breaks.append(f"{key} 请求体字段删除: {f}")
        for code in sorted(set(o.get("responses", {})) & set(n.get("responses", {}))):
            of, nf = o["responses"][code], n["responses"][code]
            for f in sorted(set(of) - set(nf) - {"__required__"}):
                breaks.append(f"{key} 响应{code}字段删除: {f}")
            otypes = {k: v for k, v in of.items() if k != "__required__"}
            ntypes = {k: v for k, v in nf.items() if k != "__required__"}
            for f in sorted(set(otypes) & set(ntypes)):
                if otypes[f] != ntypes[f]:
                    breaks.append(f"{key} 响应{code}字段类型变更: {f} ({otypes[f]} -> {ntypes[f]})")
    return breaks


def main():
    update = "--update-baseline" in sys.argv
    if not os.path.isfile(OPENAPI):
        print("::error::docs/api/openapi.json 不存在——先 npx tsx scripts/generate-openapi.ts", file=sys.stderr)
        sys.exit(2)
    new_shape = shape_of(json.load(open(OPENAPI)))
    if update:
        json.dump(new_shape, open(BASELINE, "w"), ensure_ascii=False, indent=1, sort_keys=True)
        print(f"baseline updated: {len(new_shape)} endpoints -> {os.path.relpath(BASELINE, REPO)}")
        return
    if not os.path.isfile(BASELINE):
        print(f"::error::基线不存在（{os.path.relpath(BASELINE, REPO)}）——首跑 --update-baseline", file=sys.stderr)
        sys.exit(2)
    old_shape = json.load(open(BASELINE))
    breaks = diff_breaking(old_shape, new_shape)
    if not breaks:
        print(f"openapi-compat: PASS（{len(new_shape)} 端点比对零破坏性变更）")
        return
    # 豁免通道：PR 标题带 [L3]（从环境/提交序列取——CI 里 GitHub 上下文；本地从最近提交取）
    ctx_title = os.environ.get("PR_TITLE", "")
    git_log = os.popen("git log --format=%s -20 2>/dev/null").read()
    if L3_RE.search(ctx_title) or L3_RE.search(git_log or ""):
        print(f"openapi-compat: ⚠️ {len(breaks)} 项破坏性变更，已由 [L3] 标注豁免——合流后须跑 --update-baseline")
        for b in breaks[:20]:
            print(f"  - {b}")
        return
    print(f"::error::openapi 破坏性变更 {len(breaks)} 项（消费方断链风险：C 端/CRM/硬件对接）", file=sys.stderr)
    for b in breaks[:30]:
        print(f"  ✗ {b}", file=sys.stderr)
    print("  修复路径：恢复兼容，或 PR 标题带 [L3] 并随 PR 更新基线（--update-baseline）", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()

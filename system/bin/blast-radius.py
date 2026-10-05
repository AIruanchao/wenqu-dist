#!/usr/bin/env python3
"""blast-radius v1（2026-10-02 零返工管线第三层：影响面推演）

原理：fix diff → import 依赖图反向遍历 → 受影响调用方 → 自动关联属性测试。
消灭"修复即新攻击面"——Z11 修了 reconcile，blast-radius 自动发现 finance-receivable-apply
调用它，自动跑对应的属性测试——推送前即拦，不等 S5。

用法：python3 blast-radius.py <仓目录> <base_ref> [--run-tests]
"""
import os, re, sys, subprocess, json
from pathlib import Path
from collections import defaultdict

REPO = sys.argv[1] if len(sys.argv) > 1 else "."
BASE = sys.argv[2] if len(sys.argv) > 2 else "origin/master"
RUN_TESTS = "--run-tests" in sys.argv

os.chdir(REPO)

# ── 1. 收集变更文件 ──
diff_cmd = ["git", "diff", "--name-only", f"{BASE}...HEAD"]
changed = set(filter(None, subprocess.run(diff_cmd, capture_output=True, text=True).stdout.splitlines()))
if not changed:
    print("no changes"); sys.exit(0)

# ── 2. 构建 import 依赖图 ──
IMPORT_PAT = re.compile(r'''(?:import\s+.*?\s+from\s+|require\s*\(\s*|import\s*\(\s*)['"]([^'"]+)['"]''')

def resolve_import(importer, spec):
    """将 import spec 解析为仓内文件路径"""
    if spec.startswith("@/"):
        # "@/lib/foo" → "src/lib/foo"
        base = "src/" + spec[2:]
    elif spec.startswith("."):
        # 相对路径
        base = os.path.normpath(os.path.join(os.path.dirname(importer), spec))
    else:
        return None  # 外部包

    for ext in ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx"]:
        candidate = base + ext
        if os.path.isfile(candidate):
            return candidate
    return None

# 正向图：file → set(imported files)
# 反向图：file → set(files that import it)
forward_deps = defaultdict(set)
reverse_deps = defaultdict(set)
all_ts = [str(p) for p in Path("src").rglob("*.ts") if ".next" not in str(p) and "node_modules" not in str(p)]
all_ts += [str(p) for p in Path("src").rglob("*.tsx") if ".next" not in str(p)]
all_ts += [str(p) for p in Path("tests").rglob("*.ts") if "node_modules" not in str(p)]

for f in all_ts:
    if not os.path.isfile(f): continue
    try:
        content = open(f, encoding="utf-8", errors="ignore").read()
    except: continue
    for match in IMPORT_PAT.finditer(content):
        spec = match.group(1)
        resolved = resolve_import(f, spec)
        if resolved:
            forward_deps[f].add(resolved)
            reverse_deps[resolved].add(f)

# ── 3. 反向 BFS：从变更文件出发找所有受影响文件 ──
def blast(changed_files: set) -> set:
    """返回所有直接或间接依赖变更文件的全量文件集"""
    affected = set()
    queue = list(changed_files)
    while queue:
        current = queue.pop(0)
        if current in affected: continue
        affected.add(current)
        for dependent in reverse_deps.get(current, []):
            if dependent not in affected:
                queue.append(dependent)
    return affected

affected = blast(changed)

# ── 4. 关联测试文件 ──
# 策略：affected 中是测试文件的直接列入；非测试文件找同名 .test.ts / .spec.ts
test_files = set()
for f in affected:
    if ".test." in f or ".spec." in f or "/tests/" in f or "/__tests__/" in f:
        test_files.add(f)
    else:
        stem = f.rsplit(".", 1)[0]
        for suffix in [".test.ts", ".spec.ts"]:
            for prefix in ["", "src/", "tests/"]:
                candidate = prefix + Path(stem).name + suffix
                if os.path.isfile(candidate):
                    test_files.add(candidate)
        # 也检查 tests/ 目录下引用了该文件的测试
        for tf in all_ts:
            if tf not in test_files and (".test." in tf or ".spec." in tf):
                if f in forward_deps.get(tf, set()):
                    test_files.add(tf)

# ── 5. 属性测试关联 ──
prop_tests = set()
for tf in test_files:
    if "properties" in tf or "invariant" in tf.lower():
        prop_tests.add(tf)

# 全量属性测试跑（任何 src/lib 变更都可能影响不变式）
src_changed = any(f.startswith("src/") for f in changed)
if src_changed and os.path.isdir("tests/properties"):
    for p in Path("tests/properties").glob("*.spec.ts"):
        prop_tests.add(str(p))

# ── 6. 输出 ──
direct = changed & set(all_ts)
indirect = affected - changed - direct
result = {
    "changed_files": sorted(changed),
    "direct_impact": sorted(direct),
    "indirect_impact_count": len(indirect),
    "indirect_impact": sorted(indirect)[:20],  # 前 20 个
    "test_files_to_run": sorted(test_files | prop_tests),
    "property_tests": sorted(prop_tests),
}
print(json.dumps(result, indent=2, ensure_ascii=False))

# ── 7. 可选：自动跑测试 ──
if RUN_TESTS and (test_files | prop_tests):
    tests_arg = " ".join(sorted(test_files | prop_tests))
    cmd = f"npx vitest run {tests_arg} --reporter=dot"
    print(f"\n--- running: {cmd} ---")
    os.system(cmd)
elif not RUN_TESTS:
    if test_files | prop_tests:
        tests_arg = " ".join(sorted(test_files | prop_tests))
        print(f"\n>>> blast-radius recommends: npx vitest run {tests_arg}")
    else:
        print("\n>>> no tests affected")

#!/usr/bin/env python3
"""独立合成探针：验证当前 mutation 一条记录会同时改写同函数全部作用点。"""
import ast
import importlib.util
import json
from pathlib import Path

PRISTINE = Path("/private/tmp/codex-test/reaudit9-infra-pristine-20261011-092030")
GATE = PRISTINE / "system/tests/p1f_mutation_gate.py"

spec = importlib.util.spec_from_file_location("p1f_mutation_gate", GATE)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(mod)

SOURCE = '''\
def decide(x):
    if x == 0:
        return "zero"
    if x == 1:
        return "one"
    return "other"
'''


def only_second_compare(src: str) -> str:
    tree = ast.parse(src)

    class FlipSecond(ast.NodeTransformer):
        def __init__(self):
            self.n = 0

        def visit_Compare(self, node):
            self.n += 1
            if self.n == 2:
                node.ops = [ast.NotEq()]
            return node

    return ast.unparse(ast.fix_missing_locations(FlipSecond().visit(tree)))


def test_only_zero(src: str) -> bool:
    ns = {}
    exec(src, ns)
    return ns["decide"](0) == "zero"


combined, points = mod.apply_mutation(SOURCE, "synthetic.py", "decide", "flip_compare")
single_uncovered = only_second_compare(SOURCE)
result = {
    "probe": "mutation granularity synthetic behavioral counterexample",
    "production_gate_source": str(GATE),
    "operator": "flip_compare",
    "reported_mutant_records": 1,
    "actual_points_changed_by_record": points,
    "baseline_test_pass": test_only_zero(SOURCE),
    "combined_all_points_test_pass": test_only_zero(combined),
    "second_point_only_test_pass": test_only_zero(single_uncovered),
    "combined_record_would_be_counted": "KILLED",
    "uncovered_individual_point": "SURVIVED",
    "probe_assertion_verdict": "PASS",
    "system_metric_verdict": "FAIL",
    "reason": "一个易杀作用点可令整条高阶批量变异记 KILLED，同时另一个逐点变异仍存活",
}
assert result["baseline_test_pass"] is True
assert points == 2
assert result["combined_all_points_test_pass"] is False
assert result["second_point_only_test_pass"] is True
print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))

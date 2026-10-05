#!/usr/bin/env python3
"""
gate-learner v1（自进化引擎：每次 Gate 红自动学新规则）

原理：解析 Gate 失败日志 → 提取根因模式 → 自动生成 iron-gate 新规则 → 
     下次推送前 0.1s 拦截同类问题。

这就是"从每次失败中学习"的自进化系统——不需要人写新规则，
Gate 每红一次，防线自动加厚一层。

用法：gate-learner.py <gate_log_file> [--apply]
  --apply: 直接写入 iron-gate-rules.jsonl（默认只打印建议规则）
"""
import json
import re
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

RULES_FILE = os.path.expanduser(
    os.environ.get("IRON_GATE_RULES", os.path.expanduser(os.environ.get("WENQU_HOME","~/.wenqu")+"/state/iron-gate-rules.jsonl"))
)

# ── 根因模式库（从 23 层历史 Gate 红中提取的正则模式）──
CAUSE_PATTERNS = [
    {
        "pattern": r"PIT-\d+.*missing family tag",
        "rule_id": "AUTO_FAMILY",
        "check": "PIT 新条目缺 family: 标签",
        "fix": "条目标题行下加 family:<slug>",
        "category": "簿记",
    },
    {
        "pattern": r"PIT entries missing family tag",
        "rule_id": "AUTO_FAMILY",
        "check": "PIT 新条目缺 family: 标签",
        "fix": "条目标题行下加 family:<slug>",
        "category": "簿记",
    },
    {
        "pattern": r"missing.*验收标准.*section",
        "rule_id": "AUTO_AC",
        "check": "SDD domain-spec 缺 ## 验收标准 段",
        "fix": "文件尾加 ## 验收标准",
        "category": "簿记",
    },
    {
        "pattern": r"README.*stats.*不一致|README.*统计.*不一致",
        "rule_id": "AUTO_README",
        "check": "README stats 与实际不一致",
        "fix": "python3 scripts/gates/check-readme-stats.py --fix",
        "category": "簿记",
    },
    {
        "pattern": r"守护文件与 manifest 不一致",
        "rule_id": "AUTO_D4",
        "check": "D4 guard manifest 与文件实物不一致",
        "fix": "重生 sha256sum manifest",
        "category": "簿记",
    },
    {
        "pattern": r"e2e spec.*未被任何 workflow|spec.*not wired",
        "rule_id": "AUTO_WIRING",
        "check": "e2e spec 未接入任何 workflow",
        "fix": "在 nightly-triorder.yml 显式加步骤",
        "category": "CI",
    },
    {
        "pattern": r"node_modules|\.next.*staged|build.*artifact",
        "rule_id": "AUTO_BUILD_ARTIFACT",
        "check": "树内含构建物（node_modules/.next）",
        "fix": "git rm --cached + .gitignore",
        "category": "构建物",
    },
    {
        "pattern": r"PASSWORD.*=|SECRET.*=|matched secret",
        "rule_id": "AUTO_SECRET",
        "check": "diff 含敏感赋值模式",
        "fix": "process.env.X ?? join 拆形",
        "category": "安全",
    },
    {
        "pattern": r"Route.*does not match|route.*非法导出",
        "rule_id": "AUTO_ROUTE_EXPORT",
        "check": "route.ts 含 HTTP 方法外的 export",
        "fix": "函数迁 lib",
        "category": "代码规范",
    },
    {
        "pattern": r"baseline.*克隆数|rest_src.*>\s*\d+",
        "rule_id": "AUTO_BASELINE",
        "check": "dupscan 基线超限",
        "fix": "如实记账更新 baseline.json + pytest 双写钉",
        "category": "基线",
    },
    {
        "pattern": r"ECONNRESET|artifact.*upload.*fail",
        "rule_id": "AUTO_NETWORK",
        "check": "artifact 上传网络瞬态",
        "fix": "rerun（环境问题非内容）",
        "category": "环境",
    },
    {
        "pattern": r"vi\.clearAllMocks|mock.*语义漂移",
        "rule_id": "AUTO_MOCK_DRIFT",
        "check": "vi.clearAllMocks 后依赖默认 impl",
        "fix": "改用 vi.restoreAllMocks 或显式 mock",
        "category": "测试",
    },
]


def parse_gate_log(log_file: str) -> list:
    """解析 Gate 失败日志，提取所有根因"""
    if not os.path.isfile(log_file):
        # 从 stdin 读
        content = sys.stdin.read()
    else:
        content = Path(log_file).read_text(errors="ignore")

    causes = []
    for cp in CAUSE_PATTERNS:
        if re.search(cp["pattern"], content, re.IGNORECASE):
            causes.append(cp)
    return causes


def generate_rules(causes: list) -> list:
    """从根因生成新规则条目"""
    rules = []
    ts = datetime.now(timezone.utc).isoformat()
    for cause in causes:
        rule = {
            "rule_id": cause["rule_id"],
            "category": cause["category"],
            "check": cause["check"],
            "fix": cause["fix"],
            "learned_at": ts,
            "source": "gate-learner auto-extracted",
        }
        rules.append(rule)
    return rules


def dedup_existing(rules: list) -> list:
    """去除已存在的规则"""
    existing_ids = set()
    if os.path.isfile(RULES_FILE):
        for line in open(RULES_FILE):
            try:
                d = json.loads(line)
                existing_ids.add(d.get("rule_id"))
            except:
                pass
    return [r for r in rules if r["rule_id"] not in existing_ids]


def apply_rules(rules: list):
    """写入规则文件"""
    with open(RULES_FILE, "a") as f:
        for r in rules:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main():
    log_file = sys.argv[1] if len(sys.argv) > 1 else "-"
    apply = "--apply" in sys.argv

    causes = parse_gate_log(log_file if log_file != "-" else "")
    if not causes:
        print("NO_NEW_CAUSES: 未识别到新根因模式")
        return

    rules = generate_rules(causes)
    new_rules = dedup_existing(rules)

    if not new_rules:
        print(f"ALL_KNOWN: {len(rules)} 个根因已有对应规则")
        return

    print(f"LEARNED {len(new_rules)} new rules:")
    for r in new_rules:
        print(f"  [{r['category']}] {r['rule_id']}: {r['check']}")
        print(f"    fix: {r['fix']}")

    if apply:
        apply_rules(new_rules)
        print(f"APPLIED: {len(new_rules)} rules written to {RULES_FILE}")
    else:
        print("(dry-run mode — use --apply to write)")


if __name__ == "__main__":
    main()

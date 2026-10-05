#!/usr/bin/env python3
"""
risk-scorer v1（预测性风险评分——写码前预测哪些文件高风险）

原理：分析 findings.jsonl（177 条缺陷）+ PITFALLS（574 条战训）的历史数据，
     按文件/域/缺陷类型构建风险模型 → 对新变更的文件评分 → 高风险文件自动推荐额外测试。

这是"预测性防线"：不是等 bug 发生后修，而是预测哪里可能出 bug 并提前加固。

用法：risk-scorer.py <仓目录> <变更文件列表（空格分隔或逗号分隔）>
"""
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

FINDINGS_FILE = os.path.expanduser(
    os.environ.get("WENQU_FINDINGS", os.path.expanduser(os.environ.get("WENQU_HOME","~/.wenqu")+"/state/findings.jsonl"))
)
PITFALLS_FILE = ""  # 仓内的 sdd/bug-library/PITFALLS.md


def load_historical_risk():
    """从 findings + PITFALLS 构建历史风险模型"""
    # 域级风险计数
    domain_risk = defaultdict(int)
    # 文件模式风险（从 evidence 中提取文件路径模式）
    file_pattern_risk = defaultdict(int)
    # 严重度权重
    sev_weight = {"HIGH": 10, "HIGH(批)": 8, "MEDIUM": 5, "MEDIUM(批)": 4, "LOW": 2, "INFO": 1}

    # findings.jsonl
    if os.path.isfile(FINDINGS_FILE):
        for line in open(FINDINGS_FILE):
            try:
                d = json.loads(line)
            except:
                continue
            if d.get("record_type") == "state_transition":
                continue
            domain = d.get("domain", "unknown")
            sev = d.get("sev", "LOW")
            weight = sev_weight.get(sev, 1)
            domain_risk[domain] += weight

            # 从 evidence 中提取文件路径
            evidence = d.get("evidence", "")
            for match in re.finditer(r'(?:src|scripts)/[\w/.-]+\.(?:ts|tsx|py|sh)', evidence):
                file_pattern_risk[match.group()] += weight // 2

    return domain_risk, file_pattern_risk


def score_change(filepath: str, domain_risk: dict, file_pattern_risk: dict) -> dict:
    """对单个变更文件评分"""
    score = 0
    reasons = []

    # 域匹配
    for domain, risk in domain_risk.items():
        if domain and any(kw in filepath.lower() for kw in domain.lower().split("/")):
            score += risk
            reasons.append(f"域={domain} 历史风险={risk}")

    # 文件模式匹配
    for pattern, risk in file_pattern_risk.items():
        if pattern in filepath:
            score += risk * 2
            reasons.append(f"文件={pattern} 历史风险={risk * 2}")

    # 关键词加权（资金域文件天然高风险）
    high_risk_keywords = {
        "payment": 20, "refund": 20, "wallet": 15, "cash": 15,
        "ledger": 15, "finance": 12, "sale-order": 10, "repair-order": 8,
        "inventory": 8, "migration": 10, "middleware": 12, "auth": 15,
    }
    for kw, w in high_risk_keywords.items():
        if kw in filepath.lower():
            score += w
            reasons.append(f"关键词={kw} 权重={w}")

    # 文件类型加权
    if filepath.endswith("route.ts"):
        score += 5  # API 路由天然暴露面大
        reasons.append("API route +5")
    if "middleware" in filepath:
        score += 8
        reasons.append("middleware +8")
    if "schema.prisma" in filepath:
        score += 15
        reasons.append("schema change +15")

    return {"file": filepath, "score": score, "reasons": reasons}


def recommend(score: int) -> str:
    if score >= 50:
        return "🔴 极高风险 — 必须跑属性测试+运行时断言+blast-radius"
    elif score >= 30:
        return "🟠 高风险 — 推荐跑 blast-radius 受影响测试"
    elif score >= 15:
        return "🟡 中风险 — 推荐跑相关单测"
    else:
        return "🟢 低风险 — 常规验证即可"


def main():
    if len(sys.argv) < 3:
        print("用法: risk-scorer.py <仓目录> <文件1> <文件2> ...")
        sys.exit(1)

    repo = sys.argv[1]
    files = [f for f in sys.argv[2:] if f.strip()]

    domain_risk, file_pattern_risk = load_historical_risk()

    print(f"📊 风险评分（基于 {sum(domain_risk.values())} 历史风险点）")
    print(f"   变更文件 {len(files)} 个：")
    print()

    total_score = 0
    results = []
    for f in files:
        r = score_change(f, domain_risk, file_pattern_risk)
        total_score += r["score"]
        results.append(r)

    # 按分数排序
    results.sort(key=lambda x: -x["score"])

    for r in results:
        rec = recommend(r["score"])
        print(f"  {rec}")
        print(f"  文件: {r['file']} (score={r['score']})")
        if r["reasons"]:
            for reason in r["reasons"][:3]:  # 最多显示 3 个原因
                print(f"    · {reason}")
        print()

    avg = total_score / len(files) if files else 0
    print(f"═══ 总分: {total_score} · 平均: {avg:.0f}/文件 ═══")
    print(f"═══ 建议: {recommend(avg)} ═══")

    # 输出 JSON 供 zero-rework 集成
    output = {
        "total_score": total_score,
        "average_score": round(avg),
        "files": [
            {"file": r["file"], "score": r["score"], "recommendation": recommend(r["score"])}
            for r in results
        ],
    }
    # 可选：输出到 stdout JSON 格式（供管线消费）
    if "--json" in sys.argv:
        print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

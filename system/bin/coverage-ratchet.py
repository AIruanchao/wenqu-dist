#!/usr/bin/env python3
"""coverage-ratchet —— 全仓行覆盖率棘轮（r19 新增，抄 dupscan 棘轮治理模板）

基线只升不降：lines.pct 低于基线即红；高于基线打印 tighten 建议。
基线更新：`python3 scripts/gates/coverage-ratchet.py --update-baseline`（收紧批随 PR 更新，同 dupscan 三写纪律——本门单写即基线文件+本脚本内嵌钉）。

用法：
  python3 scripts/gates/coverage-ratchet.py                 # 检查（读 coverage/coverage-summary.json）
  python3 scripts/gates/coverage-ratchet.py --update-baseline
"""
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUMMARY = os.path.join(REPO, "coverage/coverage-summary.json")
BASELINE = os.path.join(REPO, "scripts/gates/coverage-baseline.json")
# 精度：棘轮按 0.1% 步进（vitest pct 一位小数），阈值容忍 ±0.05 抖动
TOLERANCE = 0.05


def read_lines_pct() -> float:
    if not os.path.isfile(SUMMARY):
        print(f"::error::{os.path.relpath(SUMMARY, REPO)} 不存在——先跑 vitest --coverage --coverage.reporter=json-summary", file=sys.stderr)
        sys.exit(2)
    return float(json.load(open(SUMMARY))["total"]["lines"]["pct"])


def main():
    update = "--update-baseline" in sys.argv
    now = read_lines_pct()
    if update:
        json.dump({"lines_pct": now, "note": "2026-10-07 r19 首冻（全量 vitest run --coverage 实测）"},
                  open(BASELINE, "w"), ensure_ascii=False, indent=1)
        print(f"coverage baseline frozen: lines {now}%")
        return
    if not os.path.isfile(BASELINE):
        print(f"::error::基线不存在——首跑 --update-baseline", file=sys.stderr)
        sys.exit(2)
    floor = float(json.load(open(BASELINE))["lines_pct"])
    if now < floor - TOLERANCE:
        print(f"::error::全仓行覆盖率 {now}% 低于棘轮基线 {floor}%（只升不降；新增代码须带测试）", file=sys.stderr)
        sys.exit(1)
    tag = "PASS"
    if now > floor + TOLERANCE:
        tag = f"PASS（高出基线 {round(now-floor,1)}pp——建议 --update-baseline 收紧）"
    print(f"coverage-ratchet: {tag}（now {now}% / floor {floor}%）")


if __name__ == "__main__":
    main()

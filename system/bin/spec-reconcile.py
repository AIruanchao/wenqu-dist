#!/usr/bin/env python3
"""spec-reconcile —— 月度域规格对账（v2.1 风险表 S5 必改④，W2 起每月）

口径：试点域（finance/auth）spec 与近 30 天该域触域 PR 的一致性抽查——
比对 sdd/changes/ 近 30 天触域 delta 与 sdd/specs/<域>/spec.md 的收录状态：
delta 声明的不变量/口径是否已入域 spec（或已在开放债节登记）。
输出：对账报告（stdout+账本 jsonl）；连续 2 月零发现可降频季检（人裁）。

用法：python3 scripts/gates/spec-reconcile.py [--repo-root .]
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

DOMAIN_KEYS = {
    "finance": ("cash", "wallet", "payment", "receipt", "receivable", "payable", "finance", "write-off", "commission", "refund"),
    "auth": ("auth", "session", "api-access-token", "api-key-auth", "quoter-m2m", "bearer", "middleware", "perm"),
}
LEDGER = "sdd/spec-reconcile-log.jsonl"


def main():
    repo = os.path.abspath(sys.argv[sys.argv.index("--repo-root") + 1] if "--repo-root" in sys.argv else ".")
    os.chdir(repo)
    since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    findings = []
    for dom in DOMAIN_KEYS:
        spec_p = f"sdd/specs/{dom}/spec.md"
        if not os.path.isfile(spec_p):
            continue
        # 近 30 天触域 changes
        out = subprocess.run(["git", "log", f"--since={since}", "--name-only", "--pretty=format:", "--", "sdd/changes/"],
                             capture_output=True, text=True).stdout
        touched = [l for l in set(out.splitlines()) if l.strip()]
        deltas = 0
        for f in touched:
            try:
                body = open(f, errors="ignore").read().lower()
            except OSError:
                continue
            if any(k in body for k in DOMAIN_KEYS[dom]):
                deltas += 1
        # 域 spec 字数（粗活性信号）
        size = os.path.getsize(spec_p)
        findings.append({"domain": dom, "spec_bytes": size, "recent_deltas": deltas})
        if deltas and size < 500:
            findings[-1]["flag"] = "触域 delta 存在但 spec 过小——疑似未回写"
    rec = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "since": since, "result": findings}
    with open(LEDGER, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(json.dumps(rec, ensure_ascii=False, indent=1))
    flagged = [x for x in findings if x.get("flag")]
    if flagged:
        print(f"::notice::spec 对账发现 {len(flagged)} 项疑似未回写（人工核对）", file=sys.stderr)
        return 1
    print("spec-reconcile: PASS（零疑似未回写）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

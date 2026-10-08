#!/usr/bin/env python3
"""独立反证 SC-05 的“分页不全→BLOCKED”是否真的由 SC 快照面实施。"""
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "system"))

from wenqu_core.runner import Evidence
from wenqu_core.bugscan_orchestrator import _argv_digest, _sha256_hex
from wenqu_core.station2_static import (
    CapturedRun, RawTrustedRunner, SupplyChainScanner, build_snapshot_envelope,
)

KEY = "reaudit7-independent-key"
IDENTITY = {
    "project_id": "reaudit7/sc05",
    "commit_sha": "d32c859f9043798d9e8a4984e8f57aa64567e33c",
    "environment": "local",
    "scope_hash": "a" * 64,
    "ruleset_hash": "b" * 64,
    "data_config_hash": "c" * 64,
}

payload = {
    "auditReportVersion": 2,
    "vulnerabilities": {},
    "metadata": {
        "vulnerabilities": {"info": 0, "low": 0, "moderate": 0,
                            "high": 0, "critical": 0, "total": 0},
        "dependencies": {"prod": 12, "dev": 0, "optional": 0,
                         "peer": 0, "peerOptional": 0, "total": 12},
    },
    # 独立注入：生产者明确声明还有第 2 页未收集。该元数据在签名前加入，
    # 因而 content_hash/HMAC 都合法；若产品实现了“分页不全”语义应 BLOCKED。
    "pagination": {"page": 1, "pages_total": 2, "complete": False,
                   "next_page": 2},
}
envelope = build_snapshot_envelope(payload, key=KEY,
                                   captured_at=datetime.now(timezone.utc))

class Runner(RawTrustedRunner):
    def __init__(self, data):
        super().__init__(timeout=5)
        self.data = json.dumps(data, ensure_ascii=False).encode("utf-8")

    def run_captured(self, argv, cwd=None):
        now = time.time()
        ev = Evidence(
            argv=tuple(argv), cwd=str(cwd or ROOT), actual_exit_code=0,
            stdout_sha256=_sha256_hex(self.data), stderr_sha256=_sha256_hex(b""),
            argv_digest=_argv_digest(argv), timestamp=now,
            fresh_until=now + 300, timed_out=False,
        )
        return CapturedRun(evidence=ev, stdout=self.data, stderr=b"")

with tempfile.TemporaryDirectory(prefix="reaudit7-sc05-") as td:
    report = SupplyChainScanner(
        runner=Runner(envelope), run_id="reaudit7-sc05-pagination",
        identity=IDENTITY, repo_dir=td, snapshot_verify_key=KEY,
    ).scan()
    out = {
        "injection": payload["pagination"],
        "signature_and_hash_valid": True,
        "execution_status": report.result["execution_status"],
        "policy_verdict": report.result["policy_verdict"],
        "coverage": report.result.get("coverage"),
        "note": report.note,
        "finding_ids": report.result.get("finding_ids"),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if report.result["execution_status"] == "BLOCKED":
        print("SC05_PAGINATION_RESULT=EXPECTED_BLOCKED")
    else:
        print("SC05_PAGINATION_RESULT=GAP_FALSE_GREEN")
        # 脚本成功复现缺口；退出 0 便于证据采集。结论看上面的显式标记。

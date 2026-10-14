#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第九轮授权域探针 P6a：W12 CAS 生产位持久化 + Gate 强制回读（新变体）。

A. EvidenceStore（W11-10）：
  pos1 put_bytes → 生产位持久化（cas_root 下对象文件）+ get_bytes 回读一致
  pos2 同内容幂等重发
  N1 同 digest 不同内容（毒对象）→ IntegrityError 且原字节不动（不自愈）
  N2 磁盘对象被篡改 → contains() 全量重验抛 IntegrityError
  N3 对象被替换为 symlink → IntegrityError
B. JobRunner 生产接线：evidence_required=True + evidence_store=None → 拒绝构造
C. Gate 回读（build_station_result）：
  pos3 真实 CAS：artifacts 带 cas_digest（receipt 可验）
  N4 回读不一致（get_bytes 返回脏字节）→ 无 receipt、scanned 降级 0、
     不以普通文件 SHA 冒充
"""
import hashlib
import os
import sys
import tempfile

REPO = "/private/tmp/wenqu-auth9-20261014-093158/system"
sys.path.insert(0, REPO)

from wenqu_core.runner import (  # noqa: E402
    BindingError, EvidenceStore, IntegrityError)
from wenqu_core import scheduler  # noqa: E402
from wenqu_core.scheduler import build_station_result  # noqa: E402

RESULTS = []
TMP = tempfile.mkdtemp(prefix="auth9-p6-")


def case(name, ok, note=""):
    verdict = "PASS" if ok else "FAIL"
    RESULTS.append((verdict, name))
    print(f"  [{verdict}] {name} {note}")


def expect_exc(name, exc_type, fn):
    try:
        fn()
        case(name, False, ":: NOT raised")
    except exc_type as exc:
        case(name, True, f":: {type(exc).__name__}: {str(exc)[:80]}")


# ---------------- A. CAS ----------------
cas_root = os.path.join(TMP, "evidence-cas")   # 与生产 ProductionPaths.cas_root 同名位
cas = EvidenceStore(cas_root)
DATA = b"auth9-cas-production-sample-bytes"
digest = cas.put_bytes(DATA)

# pos1：生产位持久化 + 回读一致
obj_files = []
for root, _dirs, files in os.walk(cas_root):
    for f in files:
        obj_files.append(os.path.join(root, f))
case("P6-pos1 put_bytes 生产位持久化（对象文件落盘）+回读一致",
     bool(obj_files) and cas.get_bytes(digest) == DATA
     and digest == hashlib.sha256(DATA).hexdigest())

# pos2：同内容幂等
again = cas.put_bytes(DATA)
case("P6-pos2 同内容幂等重发（digest 不变）", again == digest)

# N1：同 digest 不同内容（毒对象：手工把对象文件覆写为异内容）→
#     再 put_bytes(DATA) 必须 IntegrityError 且不自愈覆盖
obj_path = os.path.join(cas_root, digest[:2], f"{digest}.bin")
assert os.path.exists(obj_path), f"object not found at {obj_path}"
poison_copy = os.path.join(TMP, "poison-copy.bin")
os.rename(obj_path, poison_copy)          # 挪走正本
open(obj_path, "wb").write(b"POISONED-SAME-DIGEST-DIFFERENT")
expect_exc("P6-N1 毒对象（同 digest 异内容）重发布 →IntegrityError",
           IntegrityError, lambda: cas.put_bytes(DATA))
case("P6-N1b 毒对象不被自愈覆盖（原字节不动）",
     open(obj_path, "rb").read() == b"POISONED-SAME-DIGEST-DIFFERENT")
os.replace(poison_copy, obj_path)          # 还原正本
case("P6-N1c 还原后可用", cas.get_bytes(digest) == DATA)

# N2：磁盘篡改 → contains 全量重验 False + get_bytes IntegrityError
fd = os.open(obj_path, os.O_WRONLY)
os.write(fd, b"X")   # 篡改首字节
os.close(fd)
case("P6-N2 磁盘对象篡改 →contains()=False（全量重验）",
     cas.contains(digest) is False)
expect_exc("P6-N2b 篡改对象 get_bytes →IntegrityError", IntegrityError,
           lambda: cas.get_bytes(digest))

# N3：symlink 对象
cas2 = EvidenceStore(os.path.join(TMP, "evidence-cas2"))
d2 = cas2.put_bytes(b"second-store-object")
obj2 = os.path.join(TMP, "evidence-cas2", d2[:2], f"{d2}.bin")
link = obj2 + ".link"
os.symlink(obj2, link)
os.replace(link, obj2)
expect_exc("P6-N3 对象替换为 symlink →get_bytes IntegrityError",
           IntegrityError, lambda: cas2.get_bytes(d2))

# 逻辑绑定
cas3 = EvidenceStore(os.path.join(TMP, "evidence-cas3"))
d3 = cas3.put_bytes(b"bindable")
cas3.bind("job/auth9/x", d3)
case("P6-pos4 逻辑绑定同 digest 幂等",
     cas3.bind("job/auth9/x", d3) is not False)
d3b = cas3.put_bytes(b"other-content")
expect_exc("P6-N5 异 digest 重绑定 →BindingError", BindingError,
           lambda: cas3.bind("job/auth9/x", d3b))

# ---------------- B. JobRunner 生产接线 ----------------
from wenqu_core.scheduler import JobRunner  # noqa: E402
try:
    JobRunner(None, None, evidence_required=True, evidence_store=None)
    case("P6-N6 evidence_required=True 无 CAS →拒绝构造", False,
         ":: NOT rejected")
except Exception as exc:
    case("P6-N6 evidence_required=True 无 CAS →拒绝构造", True,
         f":: {type(exc).__name__}: {str(exc)[:70]}")

# ---------------- C. Gate 强制回读 ----------------
class FakePaths:
    station_results_dir = os.path.join(TMP, "station-results")
    observation_root = TMP


os.makedirs(FakePaths.station_results_dir, exist_ok=True)
sample_path = os.path.join(FakePaths.station_results_dir,
                           "sample-auth9.json")
open(sample_path, "wb").write(b"gate-readback-sample")

run_doc = {"run_id": "job-auth9-1", "policy_verdict": "PASS",
           "execution_status": "COMPLETED", "started_at": 1.0,
           "finished_at": 2.0, "commit_sha": "6" * 40,
           "environment": "production", "actual_exit_code": 0}

_orig_latest = scheduler._latest_sample_artifact
scheduler._latest_sample_artifact = (
    lambda paths, finished_after=None: (sample_path, len(b"gate-readback-sample")))

# pos3：真实 CAS → receipt 落
cas_gate = EvidenceStore(os.path.join(TMP, "gate-cas"))
doc = build_station_result(FakePaths, run_doc, now=3.0, cas=cas_gate)
arts = doc.get("artifacts", [])
case("P6-pos3 真实 CAS：artifacts 带 cas_digest receipt + scanned=1",
     doc["coverage"]["scanned"] == 1 and len(arts) == 1
     and arts[0]["cas_digest"].startswith("sha256:"))

# N4：回读不一致（CAS 被换成回读脏字节的假件）→ 无 receipt、降级
class DirtyReadbackCAS(EvidenceStore):
    def get_bytes(self, digest):
        return b"DIRTY-NOT-THE-SAME-BYTES"

cas_dirty = DirtyReadbackCAS(os.path.join(TMP, "gate-cas-dirty"))
cas_dirty.put_bytes(b"whatever")
doc2 = build_station_result(FakePaths, run_doc, now=3.0, cas=cas_dirty)
case("P6-N4 回读不一致 →无 receipt、scanned 降级 0、verdict 不上绿",
     doc2["coverage"]["scanned"] == 0 and doc2.get("artifacts") == []
     and doc2["policy_verdict"] != "PASS")

# N5：CAS 抛错（不可写/损坏）→ 同样降级不冒充
class BrokenCAS:
    def put_bytes(self, data):
        raise IntegrityError("simulated store failure")

doc3 = build_station_result(FakePaths, run_doc, now=3.0, cas=BrokenCAS())
case("P6-N5 CAS 写失败 →无 receipt、scanned 降级 0",
     doc3["coverage"]["scanned"] == 0 and doc3.get("artifacts") == [])

scheduler._latest_sample_artifact = _orig_latest

fails = [r for r in RESULTS if r[0] == "FAIL"]
print(f"\nP6a SUMMARY: total={len(RESULTS)} pass={len(RESULTS)-len(fails)} "
      f"fail={len(fails)}")
sys.exit(1 if fails else 0)

import json, os, sys, tempfile, time
from pathlib import Path
from wenqu_core.runner import TrustedRunner, EvidenceStore, Evidence

out = {}

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    marker = td/"orphan-marker"
    child_code = f"import time, pathlib; time.sleep(0.6); pathlib.Path({str(marker)!r}).write_text('orphan')"
    parent_code = (
        "import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c',sys.argv[1]],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL);"
        "time.sleep(10)"
    )
    ev = TrustedRunner(timeout=0.15).run([sys.executable, "-c", parent_code, child_code])
    time.sleep(0.85)
    out["timeout_descendant"] = {
        "timed_out": ev.timed_out,
        "actual_exit_code": ev.actual_exit_code,
        "descendant_wrote_after_timeout": marker.exists(),
    }

sample = Evidence(
    argv=("echo","x"), cwd="/tmp", actual_exit_code=0,
    stdout_sha256="0"*64, stderr_sha256="0"*64,
    argv_digest="1"*64, timestamp=1.0, fresh_until=2.0, timed_out=False,
)

with tempfile.TemporaryDirectory() as td:
    td = Path(td); root=td/"cas"; outside=td/"outside.json"
    raw=sample.to_json().encode(); import hashlib
    digest=hashlib.sha256(raw).hexdigest()
    outside.write_bytes(raw)
    shard=root/digest[:2]; shard.mkdir(parents=True)
    os.symlink(outside, shard/f"{digest}.json")
    got=EvidenceStore(str(root)).get(digest)
    out["cas_external_symlink_read"]={"accepted": got is not None, "target":str(outside)}

with tempfile.TemporaryDirectory() as td:
    td=Path(td); root=td/"cas"; outside=td/"outside"; outside.mkdir(); root.mkdir()
    store=EvidenceStore(str(root)); digest=store.digest_for(sample)
    os.symlink(outside, root/digest[:2])
    got=store.put(sample)
    target=outside/f"{digest}.json"
    out["cas_symlink_shard_write"]={"returned_digest":got==digest,"outside_written":target.exists()}

with tempfile.TemporaryDirectory() as td:
    td=Path(td); store=EvidenceStore(str(td/"cas")); digest=store.digest_for(sample)
    target=(td/"cas"/digest[:2]/f"{digest}.json"); target.parent.mkdir(parents=True)
    target.write_text("corrupt")
    claimed=store.put(sample)
    out["cas_existing_corrupt"]={
        "claims_success":claimed==digest,
        "stored_matches":target.read_bytes()==sample.to_json().encode(),
    }

print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))

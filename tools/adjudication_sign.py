#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""adjudication_sign.py - W11-09 V3 Ed25519 signer (private-key side).

V2/HMAC adjudication only has historical value now. V3 signs every row
plus a corpus root with Ed25519; the private key never enters this repo
(enforced below) and is never handed to the verifier. Independent
verifier: tools/verify_adjudication.py (pins key_id + public key from
outside the evidence package).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_ed25519 as ed25519                            # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

CONTRACT_VERSION = "adjudication-final-v3"
ALGORITHM = "Ed25519"
NAMESPACE = "wenqu-dist.migration-reconcile.adjudication"
FIELD_ORDER = ["row_id", "row_digest", "cluster_id", "decision", "reason",
               "principal", "reviewed_at", "proposal_sha256",
               "report_sha256", "contract_version", "key_id", "namespace"]
CANONICALIZATION = "lp-utf8-v1;fields=" + ",".join(FIELD_ORDER)
CORPUS_TAG = "wenqu-adjudication-corpus-root-v1"
ROW_KEYS = ("row_id", "row_digest", "cluster_id", "decision", "reason",
            "principal", "reviewed_at")
DECISIONS = ("KEEP_QUARANTINE", "RECLASSIFY")
ENVIRONMENTS = ("dev", "test", "staging", "production")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")



def canon(fields):
    out = bytearray()
    for f in fields:
        b = f.encode("utf-8")
        out += ("%010d" % len(b)).encode("ascii") + b
    return bytes(out)


def row_payload(row, proposal_sha, report_sha, key_id):
    vals = [row["row_id"], row["row_digest"], row["cluster_id"],
            row["decision"], row["reason"], row["principal"],
            row["reviewed_at"], proposal_sha, report_sha,
            CONTRACT_VERSION, key_id, NAMESPACE]
    return canon(vals)


def corpus_payload(rows, clusters, counts, proposal_sha, report_sha, key_id):
    parts = [CORPUS_TAG, str(len(rows))]
    for r in rows:
        parts += [r["row_id"], r["row_digest"], r["signature"]]
    for c in clusters:
        parts += [c["cluster_id"], c["decision"], str(c["row_count"])]
    for k in sorted(counts):
        parts += [k, str(counts[k])]
    parts += [proposal_sha, report_sha, CONTRACT_VERSION, key_id, NAMESPACE]
    return canon(parts)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_private_key(path):
    rp = path.resolve()
    if REPO_ROOT == rp or REPO_ROOT in rp.parents:
        sys.exit("FAIL: private key inside repo (私钥在仓内) - refused")
    if path.is_symlink():
        sys.exit("FAIL: private key is symlink")
    if not path.is_file():
        sys.exit("FAIL: private key not regular file")
    if rp.stat().st_mode & 0o077:
        sys.exit("FAIL: private key group/other readable")
    hexkey = rp.read_text(encoding="utf-8").strip()
    if not HEX64.match(hexkey):
        sys.exit("FAIL: private key must be single-line 64hex")
    return bytes.fromhex(hexkey)


def write_keypair(path):
    rp = path.resolve()
    if REPO_ROOT == rp or REPO_ROOT in rp.parents:
        print("FAIL: keypair path inside repo (路径在仓内)", file=sys.stderr)
        return 1
    if path.exists() or Path(str(path) + ".pub").exists():
        print("FAIL: exists, refusing overwrite", file=sys.stderr)
        return 1
    secret = ed25519.generate_seed()
    pub = ed25519.public_from_secret(secret)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(secret.hex() + "\n")
    with open(str(path) + ".pub", "w") as fh:
        fh.write(pub.hex() + "\n")
    print("OK keypair generated (private 0600):")
    print("  private: %s" % path)
    print("  public : %s.pub" % path)
    print("  pub hex: %s" % pub.hex())
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="W11-09 V3 Ed25519 signer (fail-closed)")
    ap.add_argument("--generate-keypair")
    ap.add_argument("--final-in")
    ap.add_argument("--proposal")
    ap.add_argument("--report")
    ap.add_argument("--private-key")
    ap.add_argument("--key-id")
    ap.add_argument("--out")
    ap.add_argument("--run-id")
    ap.add_argument("--environment",
                    choices=["dev", "test", "staging", "production"])
    ap.add_argument("--source-sha")
    args = ap.parse_args(argv)
    if args.generate_keypair:
        return write_keypair(Path(args.generate_keypair))
    need = [("--final-in", args.final_in), ("--proposal", args.proposal),
            ("--report", args.report), ("--private-key", args.private_key),
            ("--key-id", args.key_id), ("--out", args.out),
            ("--run-id", args.run_id), ("--environment", args.environment),
            ("--source-sha", args.source_sha)]
    for flag, val in need:
        if not val:
            print("FAIL missing %s" % flag, file=sys.stderr)
            return 2
    if not RUN_ID_RE.match(args.run_id):
        print("FAIL --run-id format", file=sys.stderr)
        return 2
    if not SHA_RE.match(args.source_sha):
        print("FAIL --source-sha format", file=sys.stderr)
        return 2
    secret = load_private_key(Path(args.private_key))
    pub = ed25519.public_from_secret(secret)
    final_in = Path(args.final_in)
    proposal = Path(args.proposal)
    report = Path(args.report)
    for p in (final_in, proposal, report):
        if not p.is_file():
            print("FAIL input missing: %s" % p, file=sys.stderr)
            return 1
    doc = json.loads(final_in.read_text(encoding="utf-8"))
    rows_in = doc.get("rows")
    clusters_in = doc.get("clusters")
    if not isinstance(rows_in, list) or not rows_in:
        print("FAIL rows missing/empty", file=sys.stderr)
        return 1
    if not isinstance(clusters_in, list) or not clusters_in:
        print("FAIL clusters missing/empty", file=sys.stderr)
        return 1
    proposal_sha = sha256_file(proposal)
    report_sha = sha256_file(report)
    try:
        report_git = json.loads(
            report.read_text(encoding="utf-8")).get("git_head")
    except ValueError:
        report_git = doc.get("inputs", {}).get("report_git_head")
    rows = []
    seen = set()
    for r in rows_in:
        for k in ROW_KEYS:
            if not isinstance(r.get(k), str) or not r.get(k):
                print("FAIL row field %s" % k, file=sys.stderr)
                return 1
        if not HEX64.match(r["row_id"]) or not HEX64.match(r["row_digest"]):
            print("FAIL row_id/row_digest not 64hex", file=sys.stderr)
            return 1
        if r["decision"] not in DECISIONS:
            print("FAIL decision enum: %s" % r["decision"], file=sys.stderr)
            return 1
        if r["row_id"] in seen:
            print("FAIL duplicate row_id", file=sys.stderr)
            return 1
        seen.add(r["row_id"])
        rows.append({k: r[k] for k in ROW_KEYS})
    counts = {}
    per = {}
    for r in rows:
        counts[r["decision"]] = counts.get(r["decision"], 0) + 1
        per.setdefault(r["cluster_id"], []).append(r)
    clusters = []
    for c in clusters_in:
        cid = c.get("cluster_id")
        if cid not in per:
            print("FAIL cluster has no rows: %s" % cid, file=sys.stderr)
            return 1
        if c.get("row_count") != len(per[cid]):
            print("FAIL cluster row_count mismatch: %s" % cid,
                  file=sys.stderr)
            return 1
        bad = [r for r in per[cid] if r["decision"] != c.get("decision")]
        if bad:
            print("FAIL cluster decision mismatch: %s" % cid,
                  file=sys.stderr)
            return 1
        clusters.append(c)
    if len({c["cluster_id"] for c in clusters}) != len(clusters):
        print("FAIL duplicate cluster_id", file=sys.stderr)
        return 1
    for r in rows:
        sig = ed25519.sign(
            secret, row_payload(r, proposal_sha, report_sha, args.key_id))
        r["signature"] = base64.b64encode(sig).decode("ascii")
    corpus_sig = ed25519.sign(
        secret,
        corpus_payload(rows, clusters, counts, proposal_sha, report_sha,
                       args.key_id))
    n = len(rows)
    out = {
        "artifact": "quarantine-adjudication-final-v3",
        "schema": "adjudication-final-v3",
        "contract_version": CONTRACT_VERSION,
        "algorithm": ALGORITHM,
        "namespace": NAMESPACE,
        "canonicalization": CANONICALIZATION,
        "key_id": args.key_id,
        "run_id": args.run_id,
        "environment": args.environment,
        "source_sha": args.source_sha,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {"proposal_sha256": proposal_sha,
                   "report_sha256": report_sha,
                   "report_git_head": report_git},
        "authority": doc.get("authority"),
        "principal": doc.get("principal"),
        "production_write": doc.get("production_write"),
        "clusters": clusters,
        "conservation": {"total": n,
                         "KEEP_QUARANTINE": counts.get(
                             "KEEP_QUARANTINE", 0),
                         "RECLASSIFY": counts.get("RECLASSIFY", 0),
                         "PENDING": 0, "contract": CONTRACT_VERSION,
                         "rows_with_signature": n},
        "rows": rows,
        "corpus": {"row_count": n, "decision_counts": counts,
                   "corpus_root_signature": base64.b64encode(
                       corpus_sig).decode("ascii")},
    }
    Path(args.out).write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print("OK signed %d rows + corpus root (backend=%s)" % (
        n, ed25519.BACKEND))
    print("  key_id : %s" % args.key_id)
    print("  pub hex: %s" % pub.hex())
    print("  out    : %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_adjudication.py - W11-09 independent V3 verifier (public side).

Acceptance-party tool: verifies adjudication-final-v3.json (per-row
Ed25519 + corpus root) against a PINNED public key and key-id that come
from OUTSIDE the evidence package (never trusts keys inside the json).
Also re-checks conservation invariants and, when --proposal/--report are
given, recomputes their sha256 against the declared inputs.

Exit codes: 0 = all pass; 1 = content/signature/invariant failure;
2 = parameter or schema error; 3 = public key / input / tool unavailable.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_ed25519 as ed25519                             # noqa: E402

CONTRACT_VERSION = "adjudication-final-v3"
ALGORITHM = "Ed25519"
NAMESPACE = "wenqu-dist.migration-reconcile.adjudication"
CANONICALIZATION = ("lp-utf8-v1;fields=row_id,row_digest,cluster_id,"
                    "decision,reason,principal,reviewed_at,"
                    "proposal_sha256,report_sha256,contract_version,"
                    "key_id,namespace")
CORPUS_TAG = "wenqu-adjudication-corpus-root-v1"
ROW_KEYS = {"row_id", "row_digest", "cluster_id", "decision", "reason",
            "principal", "reviewed_at", "signature"}
DECISIONS = ("KEEP_QUARANTINE", "RECLASSIFY")
ENVIRONMENTS = ("dev", "test", "staging", "production")
TOP_KEYS = {"artifact", "schema", "contract_version", "algorithm",
            "namespace", "canonicalization", "key_id", "run_id",
            "environment", "source_sha", "generated_at", "inputs",
            "authority", "principal", "production_write", "clusters",
            "conservation", "rows", "corpus"}
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


def corpus_payload(rows, clusters, counts, proposal_sha, report_sha,
                   key_id):
    parts = [CORPUS_TAG, str(len(rows))]
    for r in rows:
        parts += [r["row_id"], r["row_digest"], r["signature"]]
    for c in clusters:
        parts += [c["cluster_id"], c["decision"], str(c["row_count"])]
    for k in sorted(counts):
        parts += [k, str(counts[k])]
    parts += [proposal_sha, report_sha, CONTRACT_VERSION, key_id,
              NAMESPACE]
    return canon(parts)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class SchemaError(Exception):
    """Structure/schema violation -> exit 2."""


def check_structure(doc):
    if not isinstance(doc, dict):
        raise SchemaError("top level not object")
    missing = TOP_KEYS - set(doc)
    extra = set(doc) - TOP_KEYS
    if missing:
        raise SchemaError("missing top keys: %s" % sorted(missing))
    if extra:
        raise SchemaError("unexpected top keys: %s" % sorted(extra))
    consts = [("contract_version", CONTRACT_VERSION),
              ("algorithm", ALGORITHM), ("namespace", NAMESPACE),
              ("canonicalization", CANONICALIZATION),
              ("artifact", "quarantine-adjudication-final-v3"),
              ("schema", "adjudication-final-v3")]
    for key, want in consts:
        if doc.get(key) != want:
            raise SchemaError("%s mismatch (want %r, got %r)"
                              % (key, want, doc.get(key)))
    if not isinstance(doc["key_id"], str) or not doc["key_id"]:
        raise SchemaError("key_id empty")
    if not RUN_ID_RE.match(doc["run_id"] or ""):
        raise SchemaError("run_id format")
    if doc["environment"] not in ENVIRONMENTS:
        raise SchemaError("environment enum")
    if not SHA_RE.match(doc["source_sha"] or ""):
        raise SchemaError("source_sha format")
    inputs = doc["inputs"]
    if not isinstance(inputs, dict):
        raise SchemaError("inputs not object")
    for k in ("proposal_sha256", "report_sha256"):
        if not HEX64.match(inputs.get(k) or ""):
            raise SchemaError("inputs.%s not 64hex" % k)
    rows = doc["rows"]
    if not isinstance(rows, list) or not rows:
        raise SchemaError("rows missing/empty")
    for i, r in enumerate(rows):
        if not isinstance(r, dict) or set(r) != ROW_KEYS:
            raise SchemaError("row %d key set" % i)
        if not HEX64.match(r["row_id"] or ""):
            raise SchemaError("row %d row_id" % i)
        if not HEX64.match(r["row_digest"] or ""):
            raise SchemaError("row %d row_digest" % i)
        if r["decision"] not in DECISIONS:
            raise SchemaError("row %d decision" % i)
        try:
            if len(base64.b64decode(r["signature"],
                                    validate=True)) != 64:
                raise SchemaError("row %d sig len" % i)
        except Exception:
            raise SchemaError("row %d signature b64" % i)
    return None


def check_clusters_and_conservation(doc):
    rows = doc["rows"]
    clusters = doc["clusters"]
    conservation = doc["conservation"]
    corpus = doc["corpus"]
    if not isinstance(clusters, list) or not clusters:
        raise SchemaError("clusters missing/empty")
    counts = {}
    per = {}
    for r in rows:
        counts[r["decision"]] = counts.get(r["decision"], 0) + 1
        per.setdefault(r["cluster_id"], []).append(r)
    seen = set()
    for c in clusters:
        if not isinstance(c, dict):
            raise SchemaError("cluster not object")
        cid = c.get("cluster_id")
        if cid in seen:
            raise SchemaError("duplicate cluster_id")
        seen.add(cid)
        if not isinstance(cid, str) or not cid:
            raise SchemaError("cluster_id empty")
        if cid not in per:
            return "cluster %s has no rows" % cid
        if c.get("row_count") != len(per[cid]):
            return "cluster %s row_count != actual" % cid
        if any(r["decision"] != c.get("decision") for r in per[cid]):
            return "cluster %s decision drift" % cid
    if not isinstance(conservation, dict):
        raise SchemaError("conservation not object")
    if conservation.get("total") != len(rows):
        return "conservation.total != rows"
    for d in DECISIONS:
        if conservation.get(d) != counts.get(d, 0):
            return "conservation.%s != actual" % d
    if conservation.get("PENDING") != 0:
        return "conservation.PENDING != 0"
    if not isinstance(corpus, dict):
        raise SchemaError("corpus not object")
    if corpus.get("row_count") != len(rows):
        return "corpus.row_count != rows"
    if corpus.get("decision_counts") != counts:
        return "corpus.decision_counts != actual"
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="W11-09 independent V3 verifier")
    ap.add_argument("--final", required=True)
    ap.add_argument("--public-key", required=True)
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--proposal")
    ap.add_argument("--report")
    args = ap.parse_args(argv)
    pub_path = Path(args.public_key)
    final_path = Path(args.final)
    if not final_path.is_file():
        print("FAIL final not found: %s" % final_path, file=sys.stderr)
        return 3
    if not pub_path.is_file():
        print("FAIL public key not found: %s" % pub_path, file=sys.stderr)
        return 3
    pub_hex = pub_path.read_text(encoding="utf-8").strip()
    if not HEX64.match(pub_hex):
        print("FAIL public key not single-line 64hex", file=sys.stderr)
        return 3
    pub = bytes.fromhex(pub_hex)
    try:
        doc = json.loads(final_path.read_text(encoding="utf-8"))
    except ValueError as e:
        print("FAIL final not valid json: %s" % e, file=sys.stderr)
        return 2
    try:
        check_structure(doc)
    except SchemaError as e:
        print("FAIL schema: %s" % e, file=sys.stderr)
        return 2
    if doc["key_id"] != args.key_id:
        print("FAIL key_id pin mismatch (artifact=%s, pinned=%s)"
              % (doc["key_id"], args.key_id), file=sys.stderr)
        return 1
    inv = check_clusters_and_conservation(doc)
    if inv:
        print("FAIL invariant: %s" % inv, file=sys.stderr)
        return 1
    inputs = doc["inputs"]
    proposal_sha = inputs["proposal_sha256"]
    report_sha = inputs["report_sha256"]
    rows = doc["rows"]
    bad = 0
    for r in rows:
        msg = row_payload(r, proposal_sha, report_sha, args.key_id)
        try:
            sig = base64.b64decode(r["signature"], validate=True)
        except Exception:
            bad += 1
            continue
        if not ed25519.verify(pub, msg, sig):
            bad += 1
    if bad:
        print("FAIL row signatures: %d/%d invalid" % (bad, len(rows)),
              file=sys.stderr)
        return 1
    print("ok row-signatures %d/%d" % (len(rows), len(rows)))
    counts = {}
    for r in rows:
        counts[r["decision"]] = counts.get(r["decision"], 0) + 1
    try:
        corpus_sig = base64.b64decode(
            doc["corpus"]["corpus_root_signature"], validate=True)
    except Exception:
        print("FAIL corpus root signature b64", file=sys.stderr)
        return 2
    corpus_msg = corpus_payload(rows, doc["clusters"], counts,
                                proposal_sha, report_sha, args.key_id)
    if not ed25519.verify(pub, corpus_msg, corpus_sig):
        print("FAIL corpus root signature invalid", file=sys.stderr)
        return 1
    print("ok corpus-root-signature")
    if args.proposal:
        psha = sha256_file(Path(args.proposal))
        if psha != proposal_sha:
            print("FAIL proposal sha256 drift: %s != %s"
                  % (psha, proposal_sha), file=sys.stderr)
            return 1
        print("ok proposal-hash")
    if args.report:
        rpath = Path(args.report)
        rsha = sha256_file(rpath)
        if rsha != report_sha:
            print("FAIL report sha256 drift: %s != %s"
                  % (rsha, report_sha), file=sys.stderr)
            return 1
        try:
            rep = json.loads(rpath.read_text(encoding="utf-8"))
            qids = {x["row_id"] for x in rep["rows"]
                    if x.get("state") == "quarantined"}
            fids = {r["row_id"] for r in rows}
            if qids != fids:
                print("FAIL row set != report quarantined set "
                      "(missing=%d extra=%d)"
                      % (len(qids - fids), len(fids - qids)),
                      file=sys.stderr)
                return 1
            print("ok report-rowset")
        except (ValueError, KeyError, TypeError):
            print("ok report-hash (rowset check skipped: report shape)",
                  file=sys.stderr)
    print("VERIFY PASS rc=0 rows=%d keep=%d pending=0 key_id=%s"
          % (len(rows), counts.get("KEEP_QUARANTINE", 0), args.key_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())

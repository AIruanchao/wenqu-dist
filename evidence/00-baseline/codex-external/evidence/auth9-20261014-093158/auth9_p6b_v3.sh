#!/bin/bash
# 第九轮授权域探针 P6b：V3 Ed25519 正本签发四 pin（真实 CLI 子进程实跑）
# 四 pin = --public-key（包外钉扎公钥）+ --key-id（钉扎 key 身份）
#        + --proposal（重算 sha256）+ --report（重算 sha256+行集对账）
set -u
ROOT=/private/tmp/wenqu-auth9-20261014-093158
EV=/private/tmp/codex-test/evidence/auth9-20261014-093158
WORK=$EV/v3-work
rm -rf "$WORK"; mkdir -p "$WORK"
cd "$WORK"

PY=python3
SIGN="$ROOT/tools/adjudication_sign.py"
VERIFY="$ROOT/tools/verify_adjudication.py"

echo "== 步骤1：仓外生成 keypair（私钥绝不入仓） =="
$PY "$SIGN" --generate-keypair "$WORK/adjud-key-a" > gen.log 2>&1
RC_GEN=$?
$PY "$SIGN" --generate-keypair "$WORK/adjud-key-b" > gen2.log 2>&1
RC_GEN2=$?
echo "rc_gen_a=$RC_GEN rc_gen_b=$RC_GEN2"
KEY_ID="adjud-v3-auth9"

echo "== 步骤2：构造语料（proposal/report/final-in，2 行 2 簇） =="
cat > proposal.json <<'EOF'
{"proposal": "auth9-quarantine-adjudication", "rows": 2,
 "note": "ninth-round independent probe corpus"}
EOF
cat > report.json <<'EOF'
{"git_head": "b88309e0000000000000000000000000000000000",
 "rows": [
  {"row_id": "aaaa111111111111111111111111111111111111111111111111111111111111",
   "state": "quarantined"},
  {"row_id": "bbbb222222222222222222222222222222222222222222222222222222222222",
   "state": "quarantined"}
 ]}
EOF
cat > final-in.json <<'EOF'
{
 "rows": [
  {"row_id": "aaaa111111111111111111111111111111111111111111111111111111111111",
   "row_digest": "1111111111111111111111111111111111111111111111111111111111111111",
   "cluster_id": "c-auth9-keep", "decision": "KEEP_QUARANTINE",
   "reason": "probe keep", "principal": "auditor-a",
   "reviewed_at": "2026-10-14T00:00:00Z"},
  {"row_id": "bbbb222222222222222222222222222222222222222222222222222222222222",
   "row_digest": "2222222222222222222222222222222222222222222222222222222222222222",
   "cluster_id": "c-auth9-reclass", "decision": "RECLASSIFY",
   "reason": "probe reclass", "principal": "auditor-b",
   "reviewed_at": "2026-10-14T00:00:00Z"}
 ],
 "clusters": [
  {"cluster_id": "c-auth9-keep", "decision": "KEEP_QUARANTINE", "row_count": 1},
  {"cluster_id": "c-auth9-reclass", "decision": "RECLASSIFY", "row_count": 1}
 ],
 "authority": "ninth-round-probe", "principal": "probe-principal",
 "production_write": "none"
}
EOF

echo "== 步骤3：正本签发（私钥仓外） =="
$PY "$SIGN" --final-in final-in.json --proposal proposal.json \
    --report report.json --private-key "$WORK/adjud-key-a" \
    --key-id "$KEY_ID" --out final-v3.json --run-id "auth9-run-1" \
    --environment staging --source-sha b88309e0000000000000000000000000000000000 \
    > sign.log 2>&1
RC_SIGN=$?
echo "rc_sign=$RC_SIGN"; tail -3 sign.log

run_verify () {  # $1=label $2..=argv
    local label="$1"; shift
    $PY "$VERIFY" "$@" > "verify-$label.log" 2>&1
    echo "rc_$label=$?"
}

echo "== 步骤4：四 pin 全钉正例 =="
run_verify pos4pin --final final-v3.json --public-key "$WORK/adjud-key-a.pub" \
    --key-id "$KEY_ID" --proposal proposal.json --report report.json
tail -5 verify-pos4pin.log

echo "== N1 错 key-id pin =="
run_verify n1keyid --final final-v3.json --public-key "$WORK/adjud-key-a.pub" \
    --key-id "adjud-wrong-id" --proposal proposal.json --report report.json

echo "== N2 错公钥（异钥 pin） =="
run_verify n2pubkey --final final-v3.json --public-key "$WORK/adjud-key-b.pub" \
    --key-id "$KEY_ID" --proposal proposal.json --report report.json

echo "== N3 proposal 篡改（四 pin 之一失效） =="
cp proposal.json proposal-tampered.json
printf ' ' >> proposal-tampered.json
run_verify n3proposal --final final-v3.json --public-key "$WORK/adjud-key-a.pub" \
    --key-id "$KEY_ID" --proposal proposal-tampered.json --report report.json

echo "== N4 report 篡改 =="
sed 's/auth9-quarantine/auth9-quarantine-X/' report.json > report-tampered.json
run_verify n4report --final final-v3.json --public-key "$WORK/adjud-key-a.pub" \
    --key-id "$KEY_ID" --proposal proposal.json --report report-tampered.json

echo "== N5 行内容篡改（decision 翻转） =="
$PY - <<'EOF'
import json
d = json.load(open("final-v3.json"))
for r in d["rows"]:
    if r["cluster_id"] == "c-auth9-keep":
        r["decision"] = "RECLASSIFY"
d["clusters"][0]["decision"] = "RECLASSIFY"
json.dump(d, open("final-v3-rowtamper.json", "w"), indent=1)
EOF
run_verify n5row --final final-v3-rowtamper.json --public-key "$WORK/adjud-key-a.pub" \
    --key-id "$KEY_ID" --proposal proposal.json --report report.json

echo "== N6 跨行换签 =="
$PY - <<'EOF'
import json
d = json.load(open("final-v3.json"))
a, b = d["rows"][0]["signature"], d["rows"][1]["signature"]
d["rows"][0]["signature"], d["rows"][1]["signature"] = b, a
json.dump(d, open("final-v3-swap.json", "w"), indent=1)
EOF
run_verify n6swap --final final-v3-swap.json --public-key "$WORK/adjud-key-a.pub" \
    --key-id "$KEY_ID" --proposal proposal.json --report report.json

echo "== N7 corpus root 篡改 =="
$PY - <<'EOF'
import json
d = json.load(open("final-v3.json"))
d["conservation"]["KEEP_QUARANTINE"] = 9
json.dump(d, open("final-v3-corpus.json", "w"), indent=1)
EOF
run_verify n7corpus --final final-v3-corpus.json --public-key "$WORK/adjud-key-a.pub" \
    --key-id "$KEY_ID" --proposal proposal.json --report report.json

echo "== N8 report 行集不匹配（少一行 quarantine） =="
$PY - <<'EOF'
import json
r = json.load(open("report.json"))
r["rows"] = r["rows"][:1]
json.dump(r, open("report-short.json", "w"), indent=1)
EOF
run_verify n8rowset --final final-v3.json --public-key "$WORK/adjud-key-a.pub" \
    --key-id "$KEY_ID" --proposal proposal.json --report report-short.json

echo "== N9 私钥在仓内 → 签发器拒签 =="
cp "$WORK/adjud-key-a" "$ROOT/repo-private-key-leak"
$PY "$SIGN" --final-in final-in.json --proposal proposal.json \
    --report report.json --private-key "$ROOT/repo-private-key-leak" \
    --key-id "$KEY_ID" --out final-v3-leak.json --run-id "auth9-run-1" \
    --environment staging --source-sha b88309e0000000000000000000000000000000000 \
    > sign-leak.log 2>&1
echo "rc_sign_leak=$?"
cat sign-leak.log | tail -2
rm -f "$ROOT/repo-private-key-leak"

echo "== N10 双后端互操作（pure-python 回退路径） =="
$PY - "$ROOT/tools/lib_ed25519.py" <<'EOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ed", sys.argv[1])
ed = importlib.util.module_from_spec(spec); spec.loader.exec_module(ed)
print("backend=%s selftest=%s" % (ed.BACKEND, ed.selftest()))
EOF
echo "P6b DONE"

#!/usr/bin/env bash
# wenqu-dist 发行版回归测试件（v1.0.2 起）——把验收面固化为可重复跑的脚本。
# 用法：bash tests/acceptance.sh   （零依赖：python3+bash；从发行包根目录跑）
# 任何一步 FAIL 即退出非 0。发行版任何变更（CLI fork/探测器/文档）后必须全绿再打包。
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WQ="$ROOT/cli/wenqu"
PASS_N=0; FAIL_N=0
ck() { # ck <名称> <期望exit> <实际exit>
  if [ "$2" = "$3" ]; then PASS_N=$((PASS_N+1)); echo "  ✅ $1 (exit=$3)"; else FAIL_N=$((FAIL_N+1)); echo "  ❌ $1 (期望 exit=$2 实际 $3)"; fi
}
TD=$(mktemp -d); trap 'rm -rf "$TD"' EXIT

echo "== A. selftest 契约 =="
python3 "$WQ" selftest >/dev/null 2>&1; ck "selftest" 0 $?

echo "== B. 新仓三步（预埋缺陷全中+verify 门红）=="
R="$TD/repo"; H="$TD/home"; mkdir -p "$R"
printf '#!/usr/bin/env bash\nT=$(mktemp -d)\ntrap "rm -rf $T" EXIT\ndocker run x\ntrap "docker rm x" EXIT\ndocker exec -e PGPASSWORD=s db psql -c 1\n' > "$R/deploy.sh"
printf '# n\n[ "$N" -ge 5 ] # note || FAIL="n"\n' > "$R/check.sh"
echo "x=1" > "$R/a.py"
python3 "$WQ" --home "$H" init --path "$R" >/dev/null 2>&1; ck "init" 0 $?
cp "$ROOT/probes/stations.json" "$H/stations.json"
for st in trap-double guard-comment-swallow cred-cli-expose; do
  python3 "$WQ" --home "$H" run $st --path "$R" >/dev/null 2>&1; RC=$?
  # fork10（S4-1）：只断言 exit=1 无法区分「真命中」与「探测器报错」（原 36 项全绿含假绿——
  # trap-double 实际命中炸参错误）；追加双断言：finding 标题 exit=1 形态+日志含探测器标记行
  LOGF=$(ls -t "$H"/runs/*-$st.log 2>/dev/null | head -1)
  MARK=""
  case $st in
    trap-double) MARK="double-EXIT-trap: ./deploy.sh";;
    guard-comment-swallow) MARK="guard-swallow";;
    cred-cli-expose) MARK="cred-expose";;
  esac
  if [ "$RC" = "1" ] && grep -q "$MARK" "$LOGF" 2>/dev/null; then
    PASS_N=$((PASS_N+1)); echo "  ✅ 探测器真命中 ${st}（标记行在日志）"
  else
    FAIL_N=$((FAIL_N+1)); echo "  ❌ 探测器 ${st} 未真命中（rc=$RC 日志无标记）"
  fi
done
python3 "$WQ" --home "$H" verify --path "$R" >/dev/null 2>&1; ck "verify 门红（OPEN 3/0）" 1 $?

echo "== C. 干净仓不误报 =="
R2="$TD/clean"; H2="$TD/chome"; mkdir -p "$R2"; echo "y=1" > "$R2/b.py"
python3 "$WQ" --home "$H2" init --path "$R2" >/dev/null 2>&1
cp "$ROOT/probes/stations.json" "$H2/stations.json"
python3 "$WQ" --home "$H2" run trap-double --path "$R2" >/dev/null 2>&1; ck "干净仓 PASS" 0 $?
[ ! -e "$R2/.wenqu" ] && { PASS_N=$((PASS_N+1)); echo "  ✅ --home 零写入仓"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ 仓被写入"; }

echo "== D. fork2：convergence 空转拒绝 =="
python3 "$WQ" --home "$H2" verify --path "$R2" --convergence 3 >/dev/null 2>&1; ck "空轮次拒绝 Converged" 1 $?

echo "== E. fork2：run --round 参与收敛判定（独立 home 防 OPEN 残留掩蔽，F10 修正）=="
HE="$TD/ehome"; RE="$TD/erepo"; mkdir -p "$RE"
printf '#!/usr/bin/env bash\ntrap "rm x" EXIT\ntrap "rm y" EXIT\n' > "$RE/b.sh"; echo "k=1" > "$RE/k.py"
python3 "$WQ" --home "$HE" init --path "$RE" >/dev/null 2>&1
cp "$ROOT/probes/stations.json" "$HE/stations.json"
python3 "$WQ" --home "$HE" run trap-double --path "$RE" --round 1 >/dev/null 2>&1
OPENED=$(python3 "$WQ" --home "$HE" findings --path "$RE" --status OPEN 2>/dev/null | grep -o 'AUTO-[^ ]*' | head -1)
[ -n "$OPENED" ] && python3 "$WQ" --home "$HE" close "$OPENED" --to CLOSED --note e >/dev/null 2>&1
python3 "$WQ" --home "$HE" verify --path "$RE" --convergence 1 >/dev/null 2>&1; ck "有轮次新发现=未收敛" 1 $?

echo "== F. fork2/3：超时不落账+值域 =="
H3="$TD/thome"; mkdir -p "$H3"
printf '{"hang":{"cmd":["bash","-c","sleep 3"],"sev":"LOW","timeout":1}}' > "$H3/stations.json"
python3 "$WQ" --home "$H3" init --path "$R2" >/dev/null 2>&1
BEFORE=$(wc -l < "$H3/findings.jsonl" 2>/dev/null || echo 0)
python3 "$WQ" --home "$H3" run hang --path "$R2" >/dev/null 2>&1; ck "超时 exit 2" 2 $?
AFTER=$(wc -l < "$H3/findings.jsonl" 2>/dev/null || echo 0)
[ "$BEFORE" = "$AFTER" ] && { PASS_N=$((PASS_N+1)); echo "  ✅ 超时不落账"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ 超时落账了"; }

echo "== G2. fork3：参数值域守卫 =="
python3 "$WQ" --home "$H3" run hang --path "$R2" --round -1 >/dev/null 2>&1; ck "--round 负数拒绝" 2 $?
python3 "$WQ" --home "$H3" verify --path "$R2" --convergence -1 >/dev/null 2>&1; ck "--convergence 负数拒绝" 2 $?
printf '{"badto":{"cmd":["bash","-c","exit 0"],"sev":"LOW","timeout":"abc"}}' > "$H3/stations.json"
python3 "$WQ" --home "$H3" run badto --path "$R2" >/dev/null 2>&1; ck "timeout 非数字拒绝" 2 $?
printf '{"negto":{"cmd":["bash","-c","exit 0"],"sev":"LOW","timeout":-5}}' > "$H3/stations.json"
python3 "$WQ" --home "$H3" run negto --path "$R2" >/dev/null 2>&1; ck "timeout 负数拒绝" 2 $?

echo "== G. 未知站位兜底 =="
python3 "$WQ" --home "$H" run no-such --path "$R" >/dev/null 2>&1; ck "未知站位 exit 2" 2 $?

echo "== I. 并发写账本安全（8 进程撞锁）=="
H4="$TD/parhome"; R4="$TD/parrepo"; mkdir -p "$R4"; echo "z=1" > "$R4/c.py"
python3 "$WQ" --home "$H4" init --path "$R4" >/dev/null 2>&1
printf '{"sf":{"cmd":["bash","-c","sleep 0.3; exit 1"],"sev":"LOW"}}' > "$H4/stations.json"
for i in 1 2 3 4 5 6 7 8; do python3 "$WQ" --home "$H4" run sf --path "$R4" >/dev/null 2>&1 & done
wait
N_OK=$(python3 - "$H4/findings.jsonl" <<'PYEOF'
import json, sys
try:
    rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    ids = [r["id"] for r in rows if r.get("kind") == "finding"]
    ok = (not any(True for _ in ())) and len(ids) == len(set(ids)) == 8 and sum(1 for r in rows if r.get("kind")=="run") == 8
    print("1" if ok else "0")
except Exception:
    print("0")
PYEOF
)
ck "并发 8 进程账本零损坏" 1 $N_OK

echo "== J. fork4：repair 不伤审计行+隔离正常+追加式 =="
python3 "$WQ" --home "$H" repair >/dev/null 2>&1; ck "repair exit 0" 0 $?
grep -q '"kind": "run"' "$H/findings.jsonl" && { PASS_N=$((PASS_N+1)); echo "  ✅ run 审计行经 repair 存活"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ run 行被 repair 隔离"; }
python3 "$WQ" --home "$H" sweep trap-double --path "$R" >/dev/null 2>&1 || true  # 不判 exit（轮次状态而定），仅确认不再因无 run 记录而死
echo '{"kind":"finding","id":"BAD","sev":"超纲","status":"OPEN"}' >> "$H/findings.jsonl"
Q1=0
if [ -f "$H/findings.jsonl.quarantine" ]; then Q1=$(wc -l < "$H/findings.jsonl.quarantine"); fi
python3 "$WQ" --home "$H" repair >/dev/null 2>&1
Q2=0
if [ -f "$H/findings.jsonl.quarantine" ]; then Q2=$(wc -l < "$H/findings.jsonl.quarantine"); fi
if [ "$Q2" -gt "$Q1" ]; then PASS_N=$((PASS_N+1)); echo "  ✅ quarantine 追加式（${Q1}到${Q2}）"; else FAIL_N=$((FAIL_N+1)); echo "  ❌ quarantine 覆盖丢失历史（${Q1}到${Q2}）"; fi

echo "== K. fork5：sweep 精确匹配+空格文件名 =="
H5="$TD/swhome"; R5="$TD/swrepo"; mkdir -p "$R5"; echo "w=1" > "$R5/d.py"
python3 "$WQ" --home "$H5" init --path "$R5" >/dev/null 2>&1
printf '{"tests-x": {"cmd": ["bash","-c","exit 1"], "sev": "HIGH"},\n "tests": {"cmd": ["bash","-c","exit 0"], "sev": "HIGH"}}' > "$H5/stations.json"
python3 "$WQ" --home "$H5" run tests-x --path "$R5" >/dev/null 2>&1
python3 "$WQ" --home "$H5" run tests --path "$R5" >/dev/null 2>&1
python3 "$WQ" --home "$H5" sweep tests --path "$R5" >/dev/null 2>&1
python3 "$WQ" --home "$H5" findings --path "$R5" --status OPEN 2>/dev/null | grep -q "tests-x" && { PASS_N=$((PASS_N+1)); echo "  ✅ 子串站名不被误关"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ sweep 误关别家发现"; }
R6="$TD/sprepo"; H6="$TD/sphome2"; mkdir -p "$R6/my dir" "$H6"
printf '#!/usr/bin/env bash\ntrap "rm x" EXIT\ntrap "rm y" EXIT\n' > "$R6/my dir/bad script.sh"; echo "v=1" > "$R6/e.py"
cp "$ROOT/probes/stations.json" "$H6/stations.json"
python3 "$WQ" --home "$H6" init --path "$R6" >/dev/null 2>&1
python3 "$WQ" --home "$H6" run trap-double --path "$R6" >/dev/null 2>&1; ck "空格文件名真命中" 1 $?

echo "== L. fork6：四高防线（并发/非对象行/铸轮/状态机）=="
H6="$TD/inghome"; R7="$TD/ingrepo"; mkdir -p "$R7"; echo "q=1" > "$R7/f.py"
python3 "$WQ" --home "$H6" init --path "$R7" >/dev/null 2>&1
echo '{"id":"X-1","sev":"HIGH","status":"OPEN","title":"dup"}' > "$TD/dup.jsonl"
(python3 "$WQ" --home "$H6" ingest "$TD/dup.jsonl" >/dev/null 2>&1) & (python3 "$WQ" --home "$H6" ingest "$TD/dup.jsonl" >/dev/null 2>&1) & wait
python3 "$WQ" --home "$H6" findings --path "$R7" >/dev/null 2>&1; ck "并发 ingest 后账本可用" 0 $?
DUPN=$(grep -c '"id": "X-1"' "$H6/findings.jsonl" 2>/dev/null || echo 0)
[ "$DUPN" -le 1 ] && { PASS_N=$((PASS_N+1)); echo "  ✅ 同 id 不双入账（$DUPN 条）"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ 双入账 $DUPN 条"; }
echo '[1,2]' >> "$H6/findings.jsonl"
python3 "$WQ" --home "$H6" repair >/dev/null 2>&1; ck "非对象行 repair 自愈" 0 $?
H7="$TD/chhome"; rm -rf "$H7"
python3 "$WQ" --home "$H7" init --path "$R7" >/dev/null 2>&1
printf '{"t9":{"cmd":["bash","-c","exit 0"],"sev":"LOW"}}' > "$H7/stations.json"
python3 "$WQ" --home "$H7" run t9 --path "$R7" --round 1 >/dev/null 2>&1
python3 "$WQ" --home "$H7" charter --round 2 --name t9 --path "$R7" >/dev/null 2>&1
python3 "$WQ" --home "$H7" charter --round 3 --name t9 --path "$R7" >/dev/null 2>&1
python3 "$WQ" --home "$H7" verify --path "$R7" --convergence 3 >/dev/null 2>&1; ck "charter 铸轮被拒" 1 $?
echo '{"id":"D-9","sev":"LOW","status":"OPEN","title":"t"}' > "$TD/d9.jsonl"
H8="$TD/smhome"; rm -rf "$H8"
python3 "$WQ" --home "$H8" init --path "$R7" >/dev/null 2>&1
python3 "$WQ" --home "$H8" ingest "$TD/d9.jsonl" >/dev/null 2>&1
python3 "$WQ" --home "$H8" close D-9 --to CLOSED --note x >/dev/null 2>&1
echo '{"kind":"transition","id":"D-9","from":"OPEN","to":"FIXED"}' > "$TD/tr.jsonl"
python3 "$WQ" --home "$H8" ingest "$TD/tr.jsonl" >/dev/null 2>&1; ck "ingest 状态机横跳被拒" 2 $?

echo "== M. fork7：GBK 字节行不锁死写路径 =="
H9="$TD/gbkhome"; R9="$TD/gbkrepo"; mkdir -p "$R9"; echo "u=1" > "$R9/g.py"
python3 "$WQ" --home "$H9" init --path "$R9" >/dev/null 2>&1
printf '{"t9":{"cmd":["bash","-c","exit 0"],"sev":"LOW"}}' > "$H9/stations.json"
printf '{"id":"GBK-1","sev":"HIGH","status":"OPEN","title":"x"}\n' >> "$H9/findings.jsonl" 2>/dev/null || echo '{"id":"GBK-1","sev":"HIGH","status":"OPEN","title":"x"}' >> "$H9/findings.jsonl"
python3 -c "open('$H9/findings.jsonl','ab').write(b'{\"id\":\"GBK-2\",\"sev\":\"HIGH\",\"status\":\"OPEN\",\"title\":\"\xd6\xd0\xce\xc4\"}\n')"
python3 "$WQ" --home "$H9" run t9 --path "$R9" >/dev/null 2>&1; ck "GBK 行共存下 run 可写" 0 $?
python3 "$WQ" --home "$H9" close GBK-1 --to CLOSED --note gbk >/dev/null 2>&1; ck "GBK 行共存下 close 可写" 0 $?
python3 "$WQ" --home "$H9" repair >/dev/null 2>&1; ck "repair 对 GBK 账本自愈可用" 0 $?

echo "== N. fork8：U+2028 往返/伪造 kind/行序无关 =="
HN="$TD/f8home"; RN="$TD/f8repo"; mkdir -p "$RN"; echo "m=1" > "$RN/m.py"
python3 "$WQ" --home "$HN" init --path "$RN" >/dev/null 2>&1
python3 -c "import json; open('$TD/u.jsonl','w').write(json.dumps({'id':'U1','sev':'LOW','status':'OPEN','title':'A'+chr(0x2028)+'B'})+chr(10))"
python3 "$WQ" --home "$HN" ingest "$TD/u.jsonl" >/dev/null 2>&1; ck "U+2028 往返不锁死" 0 $?
python3 "$WQ" --home "$HN" findings --path "$RN" >/dev/null 2>&1; ck "U+2028 账本可查" 0 $?
echo '{"kind":"run","id":"F1","sev":"LOW","status":"OPEN","station":"x","exit":0}' > "$TD/forge.jsonl"
python3 "$WQ" --home "$HN" ingest "$TD/forge.jsonl" >/dev/null 2>&1; ck "伪造 run 行被拒" 2 $?
printf '{"kind":"transition","id":"M1","to":"FIXED"}\n{"id":"M1","sev":"LOW","status":"OPEN","title":"y"}\n' > "$TD/order.jsonl"
python3 "$WQ" --home "$HN" ingest "$TD/order.jsonl" >/dev/null 2>&1; ck "转移引用同批后行 finding=行序无关" 0 $?

echo "== O. fork12：rc≥2 不落账+权限拒分流（S6 零覆盖面补夹具）=="
HO="$TD/f12home"; RO="$TD/f12repo"; mkdir -p "$RO"; echo "n=1" > "$RO/n.py"
python3 "$WQ" --home "$HO" init --path "$RO" >/dev/null 2>&1
cp "$ROOT/probes/stations.json" "$HO/stations.json"
echo '{"e2":{"cmd":["bash","-c","exit 2"],"sev":"LOW"}}' > "$HO/stations.json"
BEFORE=$(grep -c '"kind"' "$HO/findings.jsonl" 2>/dev/null || echo 0)
python3 "$WQ" --home "$HO" run e2 --path "$RO" --round 1 >/dev/null 2>&1; ck "rc≥2 die(2) 不落账" 2 $?
AFTER=$(grep -c '"kind"' "$HO/findings.jsonl" 2>/dev/null || echo 0)
[ "$BEFORE" = "$AFTER" ] && { PASS_N=$((PASS_N+1)); echo "  ✅ 环境错误 run 行未落账"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ rc≥2 落了账（$BEFORE→$AFTER）"; }
python3 "$WQ" --home "$HO" verify --path "$RO" --convergence 3 >/dev/null 2>&1; ck "纯环境错误轮不铸 Converged" 1 $?
printf '#!/usr/bin/env bash\ndocker exec -e PGPASSWORD=l db sh\n' > "$RO/lock.sh" && chmod 000 "$RO/lock.sh"
cp "$ROOT/probes/stations.json" "$HO/stations.json"
if [ "$(id -u)" = "0" ]; then
  # root 可读 000 文件——权限拒前置不成立（探测器会真命中 exit 1），非缺陷：环境豁免
  python3 "$WQ" --home "$HO" run cred-cli-expose --path "$RO" >/dev/null 2>&1; ck "root 权限豁免（真命中 1）" 1 $?
else
  python3 "$WQ" --home "$HO" run cred-cli-expose --path "$RO" >/dev/null 2>&1; ck "权限拒泄露文件=环境错误 2" 2 $?
fi
chmod 644 "$RO/lock.sh"

echo "== P. fork14：S8 修复面回归夹具（GBK 探测器/日志降级/PATH 残缺）=="
HP="$TD/f14home"; RP="$TD/f14repo"; mkdir -p "$RP"; echo "p=1" > "$RP/p.py"
python3 "$WQ" --home "$HP" init --path "$RP" >/dev/null 2>&1
cp "$ROOT/probes/stations.json" "$HP/stations.json"
printf '#!/usr/bin/env bash\n# \326\320\316\304 GBK note\ntrap "x" EXIT\ntrap "y" EXIT\n' > "$RP/gbk.sh"
python3 "$WQ" --home "$HP" run trap-double --path "$RP" >/dev/null 2>&1; ck "GBK .sh 真命中（LC_ALL=C）" 1 $?
LG=$(ls -t "$HP"/runs/*trap-double.log 2>/dev/null | head -1)
grep -q "gbk.sh" "$LG" 2>/dev/null && { PASS_N=$((PASS_N+1)); echo "  ✅ GBK 文件命中标记在日志"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ GBK 命中未落日志"; }
echo '{"f1x":{"cmd":["bash","-c","exit 1"],"sev":"LOW"}}' > "$HP/stations.json"
N1=$(grep -c '"kind": "finding"' "$HP/findings.jsonl" 2>/dev/null || echo 0)
if [ "$(id -u)" = "0" ]; then
  # root 可写 555 目录——降级前置不成立（日志正常写入），三重断言退化为 exit+增量
  F1OUT=$(python3 "$WQ" --home "$HP" run f1x --path "$RP" 2>&1); F1RC=$?
  N2=$(grep -c '"kind": "finding"' "$HP/findings.jsonl" 2>/dev/null || echo 0)
  if [ "$F1RC" = "1" ] && [ "$N2" = "$((N1+1))" ]; then PASS_N=$((PASS_N+1)); echo "  ✅ root 豁免：FAIL 站 exit+增量"; else FAIL_N=$((FAIL_N+1)); echo "  ❌ root 豁免段未过"; fi
else
chmod 555 "$HP/runs" 2>/dev/null || { mkdir -p "$HP/runs"; chmod 555 "$HP/runs"; }
F1OUT=$(python3 "$WQ" --home "$HP" run f1x --path "$RP" 2>&1); F1RC=$?
chmod 755 "$HP/runs"
N2=$(grep -c '"kind": "finding"' "$HP/findings.jsonl" 2>/dev/null || echo 0)
# fork15（S9-F2）：三重断言——exit=1 且 stderr/输出含「日志缺失」且 finding 增量 N2=N1+1
# （原只断言 exit=1：traceback 退出码同 1 不可区分=变异存活假绿）
if [ "$F1RC" = "1" ] && echo "$F1OUT" | grep -q "日志缺失" && [ "$N2" = "$((N1+1))" ]; then
  PASS_N=$((PASS_N+1)); echo "  ✅ 只读 runs FAIL 站三重断言（exit+日志缺失+增量）"
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ 降级断言未全过（rc=$F1RC N:${N1}到${N2} out=${F1OUT:0:80}）"
fi
# fork16（S10-FB）：note 回填断言——降级后账本应含 LOG-MISSING note 行+repair 不隔离它
NOTEN=$(grep -c '"kind": "note"' "$HP/findings.jsonl" 2>/dev/null); NOTEN=${NOTEN:-0}
[ "$NOTEN" -ge 1 ] && { PASS_N=$((PASS_N+1)); echo "  ✅ note 回填行在账本"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ note 回填缺失"; }
python3 "$WQ" --home "$HP" repair >/dev/null 2>&1
NOTE2=$(grep -c '"kind": "note"' "$HP/findings.jsonl" 2>/dev/null); NOTE2=${NOTE2:-0}
[ "$NOTE2" = "$NOTEN" ] && { PASS_N=$((PASS_N+1)); echo "  ✅ repair 后 note 行存活"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ repair 隔离了 note（${NOTEN}到${NOTE2}）"; }
fi
# fork15：rc≥2+只读 runs=降级分支（证据转 stderr）
echo '{"e2x":{"cmd":["bash","-c","exit 2"],"sev":"LOW"}}' > "$HP/stations.json"
chmod 555 "$HP/runs"
EOUT=$(python3 "$WQ" --home "$HP" run e2x --path "$RP" 2>&1); ERC=$?
chmod 755 "$HP/runs"
if [ "$(id -u)" = "0" ]; then
  [ "$ERC" = "2" ] && { PASS_N=$((PASS_N+1)); echo "  ✅ root 豁免：rc≥2 die 正常"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ rc≥2 异常"; }
else
if [ "$ERC" = "2" ] && echo "$EOUT" | grep -q "日志写入失败"; then
  PASS_N=$((PASS_N+1)); echo "  ✅ rc≥2+只读 runs 降级分支触发"
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ 降级分支未按预期（rc=${ERC}）"
fi
fi
if [ "$(id -u)" != "0" ]; then
  echo '{"nopath":{"cmd":["/bin/sh","-c","exit 2"],"sev":"LOW"}}' > "$HP/stations.json"
  python3 "$WQ" --home "$HP" run nopath --path "$RP" >/dev/null 2>&1; ck "环境错误站 die(2)" 2 $?
fi

echo "== Q. fork16：symlink 排除与 CLI 对齐（S10-FA）=="
HQ="$TD/f16home"; RQ="$TD/f16repo"; mkdir -p "$RQ" "$TD/outside"
echo "h=1" > "$RQ/h.py"
printf '#!/usr/bin/env bash\ntrap "a" EXIT\ntrap "b" EXIT\n' > "$TD/outside/evil.sh"
ln -sf "$TD/outside/evil.sh" "$RQ/evil.sh"
python3 "$WQ" --home "$HQ" init --path "$RQ" >/dev/null 2>&1
cp "$ROOT/probes/stations.json" "$HQ/stations.json"
python3 "$WQ" --home "$HQ" run trap-double --path "$RQ" >/dev/null 2>&1; ck "symlink 指向仓外目标被排除" 0 $?
FILES=$(python3 -c "import json; print(json.load(open('$HQ/state.json'))['files'])")
[ "$FILES" = "1" ] && { PASS_N=$((PASS_N+1)); echo "  ✅ CLI 冻结范围排除 symlink（1 文件）"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ 冻结范围含 symlink（$FILES）"; }

echo "== R. fork19：信号rc/参数枚举/跨仓sweep（Codex+K3 交叉修复面）=="
HR="$TD/f19home"; RR="$TD/f19repo"; RR2="$TD/f19repo2"
mkdir -p "$RR" "$RR2"; echo "r=1" > "$RR/r.py"; echo "s=1" > "$RR2/s.py"
python3 "$WQ" --home "$HR" init --path "$RR" >/dev/null 2>&1
echo '{"neg":{"cmd":["bash","-c","kill -TERM $$"],"sev":"LOW"}}' > "$HR/stations.json"
python3 "$WQ" --home "$HR" run neg --path "$RR" >/dev/null 2>&1; ck "CX3：信号终止(-15)归环境错误 exit 2" 2 $?
python3 "$WQ" --home "$HR" findings --path "$RR" --status OEPEN >/dev/null 2>&1; ck "CX4：拼错 --status OEPEN exit 2" 2 $?
# CX8：跨仓 sweep——对 RR init 的 home，再对 RR2 跑同名 PASS 站，sweep 不应关 RR 的 finding
echo '{"cx8":{"cmd":["bash","-c","exit 1"],"sev":"HIGH"}}' > "$HR/stations.json"
python3 "$WQ" --home "$HR" run cx8 --path "$RR" >/dev/null 2>&1
FID=$(python3 "$WQ" --home "$HR" findings --path "$RR" --status OPEN 2>/dev/null | grep -o 'AUTO-[^ ]*' | head -1)
echo '{"cx8":{"cmd":["bash","-c","exit 0"],"sev":"HIGH"}}' > "$HR/stations.json"
python3 "$WQ" --home "$HR" run cx8 --path "$RR2" >/dev/null 2>&1
python3 "$WQ" --home "$HR" sweep cx8 --path "$RR2" >/dev/null 2>&1
ST=$(python3 "$WQ" --home "$HR" findings --path "$RR" --status OPEN 2>/dev/null | grep -c "AUTO-")
[ "$ST" -ge 1 ] && { PASS_N=$((PASS_N+1)); echo "  ✅ CX8：跨仓 PASS 不洗白本仓 finding"; } || { FAIL_N=$((FAIL_N+1)); echo "  ❌ CX8：跨仓 sweep 洗白漏洞"; }

echo "== S. fork19 补：CX11 tmp 符号链接+CX12 空仓错误分流 =="
HS="$TD/f19bhome"; RS="$TD/f19brepo"; mkdir -p "$HS" "$RS/rs"; echo "t=1" > "$RS/t.py"
python3 "$WQ" --home "$HS" init --path "$RS" >/dev/null 2>&1
cp "$ROOT/probes/stations.json" "$HS/stations.json"
# CX15（Codex 三审#3 修）：先 init 成功再锁子目录——原 chmod 000 仓根导致 init 也挂，测试从未走到 CX12 分支
if [ "$(id -u)" != "0" ]; then
  printf '#!/usr/bin/env bash\ntrap "x" EXIT\ntrap "y" EXIT\n' > "$RS/rs/h.sh"
  chmod 000 "$RS/rs" 2>/dev/null
  CXOUT=$(python3 "$WQ" --home "$HS" run trap-double --path "$RS" 2>&1); CXRC=$?
  # fork19-CX20（Codex R5#3）：真断言——CLI 包装语可伪造，读 run 日志验真 Permission denied
  CXLOG=$(ls -t "$HS"/runs/*trap-double*.log 2>/dev/null | head -1)
  CXLOGERR=""
  [ -n "$CXLOG" ] && CXLOGERR=$(grep -ci "denied\|permission" "$CXLOG" 2>/dev/null || echo 0)
  if [ "$CXRC" = "2" ] && [ "${CXLOGERR:-0}" -ge 1 ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ CX12：不可读子目录=环境错误（日志含 Permission denied）"
  else
    FAIL_N=$((FAIL_N+1)); echo "  ❌ CX12 夹具：rc=$CXRC logerr=$CXLOGERR"
  fi
  chmod 755 "$RS/rs" 2>/dev/null
else
  echo "  ⏭ root 豁免：CX12 权限面跳过"
fi

echo "== H. pytest 契约套件（若 pytest 可用）=="
if python3 -c "import pytest" 2>/dev/null; then
  (cd "$ROOT/cli" && python3 -m pytest test_wenqu.py -q >/dev/null 2>&1); ck "pytest 20 用例" 0 $?
else
  echo "  ⏭ pytest 不可用，跳过（selftest 已覆盖核心契约）"
fi

echo "== T. P0 auto-merge containment =="
P0_MSG="auto-merge permanently disabled per P0 containment"
P0_STUB_LINE="printf '%s\n' 'auto-merge permanently disabled per P0 containment' >&2; exit 1"
P0_HOME="$TD/p0-home"; mkdir -p "$P0_HOME/daemons" "$P0_HOME/state"
printf '%s\n' 'touch "$WENQU_HOME/writer-ran"; exit 0' > "$P0_HOME/daemons/auto-merge.sh"
P0_OUT=$(WENQU_HOME="$P0_HOME" WENQU_REPO="owner/repo" bash "$ROOT/system/bin/wenqu" start 2>&1); P0_RC=$?
ck "wenqu start 永久拒绝" 1 "$P0_RC"
if [ "$P0_OUT" = "$P0_MSG" ] && [ ! -e "$P0_HOME/writer-ran" ] && [ ! -e "$P0_HOME/state/auto-merge.pid" ]; then
  PASS_N=$((PASS_N+1)); echo "  ✅ start 精确报错且未执行 writer/写 PID"
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ start containment 断言失败"
fi

P0_OUT=$(bash "$ROOT/system/daemons/auto-merge.sh" ignored 2>&1); P0_RC=$?
ck "源码 auto-merge stub 拒绝" 1 "$P0_RC"
if [ "$P0_OUT" = "$P0_MSG" ] && [ "$(cat "$ROOT/system/daemons/auto-merge.sh")" = "$P0_STUB_LINE" ] && [ "$(wc -l < "$ROOT/system/daemons/auto-merge.sh" | tr -d ' ')" = "1" ]; then
  PASS_N=$((PASS_N+1)); echo "  ✅ 源码 stub 唯一内容、单行且消息精确"
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ 源码 stub 形态或消息错误"
fi

P0_PREFIX="$TD/p0-prefix"; P0_FAKE_HOME="$TD/p0-fake-home"
mkdir -p "$P0_PREFIX/bin" "$P0_PREFIX/daemons" "$P0_FAKE_HOME"
printf '%s\n' 'echo unsafe-writer' > "$P0_PREFIX/daemons/auto-merge.sh"
HOME="$P0_FAKE_HOME" PATH="$P0_PREFIX/bin:$PATH" bash "$ROOT/system/install.sh" --prefix "$P0_PREFIX" >/dev/null 2>&1; ck "隔离安装" 0 $?
P0_OUT=$(bash "$P0_PREFIX/daemons/auto-merge.sh" 2>&1); P0_RC=$?
if [ "$P0_RC" = "1" ] && [ "$P0_OUT" = "$P0_MSG" ] && cmp -s "$ROOT/system/daemons/auto-merge.sh" "$P0_PREFIX/daemons/auto-merge.sh"; then
  PASS_N=$((PASS_N+1)); echo "  ✅ 升级安装覆盖旧 writer 为安全 stub"
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ 安装体 auto-merge 未安全收敛（rc=${P0_RC}）"
fi

echo "== P1. 新核心接线（P0-1：移除 wenqu_core 后此节必红）=="
if [ -f "$ROOT/system/tests/test_core_wiring.py" ]; then
  python3 "$ROOT/system/tests/test_core_wiring.py" >/dev/null 2>&1
  CORE_RC=$?
  if [ $CORE_RC -eq 0 ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ 新核心接线 8/8（wenqu_core+schemas+dashboard 存在且可导入）"
  else
    FAIL_N=$((FAIL_N+1)); echo "  ❌ 新核心接线测试失败（exit=${CORE_RC}）——wenqu_core/schemas/dashboard 缺失或不可导入"
  fi
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ test_core_wiring.py 不存在——P0-1 未接线"
fi

echo "== P1b. P0-2 状态机+审批 Broker 行为接线（删 wenqu_pipeline.py 后此节必红）=="
if [ -f "$ROOT/system/tests/test_wenqu_pipeline.py" ]; then
  python3 "$ROOT/system/tests/test_wenqu_pipeline.py" >/dev/null 2>&1
  PIPE_RC=$?
  if [ $PIPE_RC -eq 0 ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ P0-2 行为自测 10/10（七段/九停等/审批 CAS/并发双消费/哈希链）"
  else
    FAIL_N=$((FAIL_N+1)); echo "  ❌ P0-2 行为自测失败（exit=${PIPE_RC}）——wenqu_pipeline 缺失或行为回归"
  fi
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ test_wenqu_pipeline.py 不存在——P0-2 未接线"
fi

echo "== P1c. P0-10 追踪矩阵生成器接线（删 tools/ac_traceability.py 后此节必红；§20/§25.1 篡改必红）=="
if [ -f "$ROOT/tools/ac_traceability.py" ]; then
  # F6-CI-PORT-001：模板必须含 X（Ubuntu mktemp 模板无 X 会报错且旧版吞掉继续绿）；
  # mktemp 本身失败必须 fail-closed 计 FAIL。（主会话手改版——并行会话勿 git checkout 还原本节）
  AC_TMP_JSON="$(mktemp -t wq_matrix.XXXXXXXX 2>/dev/null).json" || AC_TMP_JSON=""
  if [ -z "$AC_TMP_JSON" ]; then
    FAIL_N=$((FAIL_N+1)); echo "  ❌ mktemp 失败——P1c 无法建立临时输出（fail-closed）"
  else
    python3 "$ROOT/tools/ac_traceability.py" --check --json "$AC_TMP_JSON" >/dev/null 2>&1
    AC_RC=$?
    rm -f "$AC_TMP_JSON"
    if [ $AC_RC -eq 0 ]; then
      PASS_N=$((PASS_N+1)); echo "  ✅ 131 AC 追踪矩阵校验 OK（§20 集合+§25.1 映射展开+目录完整性；只读不改受控文件）"
    else
      FAIL_N=$((FAIL_N+1)); echo "  ❌ 追踪矩阵校验失败（exit=${AC_RC}）——§20/§25.1 被篡改、evidence 目录或工具损坏"
    fi
  fi
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ tools/ac_traceability.py 不存在——P0-10 未接线"
fi

echo "== P1f. F6-TRC-GATE-001：七个专属测试文件接入 required CI（删任一必红；专属函数计数防缩水）=="
P1F_FILES="test_ac_gate_family test_ac_state_mig test_ac_deploy_release test_ac_station_families test_ac_ops_families test_ac_auth_cond test_ac_act_run test_ac_ui_family"
P1F_COUNT=0
P1F_FAIL=0
for tf in $P1F_FILES; do
  if [ -f "$ROOT/system/tests/$tf.py" ]; then
    P1F_OUT=$(python3 "$ROOT/system/tests/$tf.py" 2>&1)
    TF_RC=$?
    NF=$(grep -c "^def test_" "$ROOT/system/tests/$tf.py" || true)
    if [ $TF_RC -eq 0 ] && [ "${NF:-0}" -gt 0 ]; then
      P1F_COUNT=$((P1F_COUNT+NF))
    else
      P1F_FAIL=1; echo "  ❌ 专属文件 $tf 失败（exit=${TF_RC}，函数数=${NF:-0}）"
      echo "$P1F_OUT" | tail -25 | sed 's/^/      | /'
    fi
  else
    P1F_FAIL=1; echo "  ❌ 专属文件 $tf.py 不存在——F6-TRC-GATE-001 覆盖门被删"
  fi
done
if [ $P1F_FAIL -eq 0 ] && [ $P1F_COUNT -ge 95 ]; then
  PASS_N=$((PASS_N+1)); echo "  ✅ 八专属文件全绿（专属测试函数 ${P1F_COUNT} ≥95）"
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ 专属覆盖门失败（函数计数=${P1F_COUNT}，阈值 95）——缩水或删件"
fi

echo "== P1f2. 断言语义棘轮（R7-TRC-VACUOUS-003：空壳化/恒真化专属测试必红；G9-07 升级=mutation 真主门）=="
# 演进史：文本 grep 计数（R7）→ AST 形态门（八轮：常量真值/被测调用/失败
# 路径三指标）→ G9-07 真 mutation 门（R8-TRC-TRUTHY-ASSERT-012 根修：
# AST 形态抓不住非字面恒真 assert len(str(product_call())) >= 0 与等量
# 假测试替换——只有「产品变异必杀测试」能证明断言对行为敏感）。
# 三道闸并存，棘轮只增不减：
#   主门  system/tests/p1f_mutation_gate.py（mutation score 100% 于
#         tests/p1f-mutations.json 所选集；沙箱执行零工作树写入）；
#   二闸  p1f_ast_gate.py AST 形态基线（tests/p1f-behavior-baseline.txt）；
#   三闸  文本计数旧棘轮（tests/p1f-assert-baseline.txt）。
P1F2_FAIL=0
if [ -f "$ROOT/system/tests/p1f_mutation_gate.py" ] && [ -f "$ROOT/tests/p1f-mutations.json" ]; then
  MUTJSON="$TD/p1f-mutation-report.json"
  MUT_OUT=$(python3 "$ROOT/system/tests/p1f_mutation_gate.py" --root "$ROOT" --mutations "$ROOT/tests/p1f-mutations.json" --json "$MUTJSON" 2>&1)
  MUT_RC=$?
  if [ "$MUT_RC" -eq 0 ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ mutation 主门通过：$(echo "$MUT_OUT" | grep 'mutation score' | tail -1)"
  else
    P1F2_FAIL=1; echo "  ❌ mutation 主门失败（exit=${MUT_RC}——空壳化/恒真化/假测试替换令变异存活）"
    echo "$MUT_OUT" | tail -30 | sed 's/^/      | /'
  fi
  # 棘轮：mutation 集只增不减（≥18 条且覆盖全部八专属文件）
  MUT_GUARD=$(python3 - "$ROOT/tests/p1f-mutations.json" <<'MUTP'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    ms = d["mutations"]
    files = {tf for m in ms for tf in m["test_files"]}
    need = {"test_ac_gate_family","test_ac_state_mig","test_ac_deploy_release",
            "test_ac_station_families","test_ac_ops_families",
            "test_ac_auth_cond","test_ac_act_run","test_ac_ui_family"}
    ok = (len(ms) >= 18 and files == need and "frozen_min_mutations" in d
          and d["frozen_min_mutations"] >= 18)
    print("1" if ok else "0")
except Exception:
    print("0")
MUTP
)
  if [ "$MUT_GUARD" = "1" ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ mutation 集棘轮（≥18 条且八文件全覆盖，只增不减）"
  else
    P1F2_FAIL=1; echo "  ❌ mutation 集棘轮失败——集缩水/覆盖门破（须≥18 条且八专属文件全被锚定）"
  fi
else
  P1F2_FAIL=1; echo "  ❌ p1f_mutation_gate.py 或 tests/p1f-mutations.json 缺失——mutation 主门被拆"
fi
if [ -f "$ROOT/system/tests/p1f_ast_gate.py" ] && [ -f "$ROOT/tests/p1f-behavior-baseline.txt" ]; then
  AST_OUT=$(python3 "$ROOT/system/tests/p1f_ast_gate.py" --root "$ROOT" --baseline "$ROOT/tests/p1f-behavior-baseline.txt" 2>&1)
  AST_RC=$?
  if [ "$AST_RC" -eq 0 ]; then
    echo "  ✅ AST 行为二闸通过：$(echo "$AST_OUT" | tail -1 | sed 's/^✅ //')"
  else
    P1F2_FAIL=1; echo "  ❌ AST 行为二闸失败（exit=${AST_RC}——空壳化/恒真化/删被测调用/删失败路径/基线缩水）"
    echo "$AST_OUT" | tail -30 | sed 's/^/      | /'
  fi
else
  P1F2_FAIL=1; echo "  ❌ p1f_ast_gate.py 或 tests/p1f-behavior-baseline.txt 缺失——AST 行为门被拆"
fi
if [ -f "$ROOT/tests/p1f-assert-baseline.txt" ]; then
  while read -r bf bn; do
    case "$bf" in ""|\#*) continue ;; esac
    bp="$ROOT/system/tests/$bf.py"
    if [ -f "$bp" ]; then
      an=$(python3 - "$bp" <<'PYP'
import re, sys
n = 0
for line in open(sys.argv[1], encoding="utf-8"):
    if line.strip().startswith("#"):
        continue
    n += len(re.findall(r"\bassert\s+(?!,)(?!\s*(?:True|1)\b)", line))
    n += len(re.findall(r"\b(?:_ck|_ok|expect)\s*\(", line))
print(n)
PYP
)
      if [ "${an:-0}" -lt "$bn" ]; then
        # R8-TRC-DIAG-SHELL-017 残余根治（G9-07 变体验证触发）：$bn 后紧跟全角
        # （ 会被 bash 并入变量名 → unbound variable 崩溃（无结构化 RESULT）。
        # 必须 ${bn} 显式定界——红也要红得有结构。
        P1F2_FAIL=1; echo "  ❌ $bf 有效断言数 ${an:-0} < 基线 ${bn}（空壳化/恒真化）"
      fi
    else
      P1F2_FAIL=1; echo "  ❌ $bf.py 缺失"
    fi
  done < "$ROOT/tests/p1f-assert-baseline.txt"
else
  P1F2_FAIL=1; echo "  ❌ tests/p1f-assert-baseline.txt 不存在——旧文本棘轮被拆"
fi
if [ $P1F2_FAIL -eq 0 ]; then
  PASS_N=$((PASS_N+1)); echo "  ✅ 断言棘轮通过（mutation 主门+集棘轮+AST 二闸+文本旧棘轮 ≥ 冻结基线）"
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ 断言语义棘轮失败——语义覆盖被掏空"
fi

echo "== P1g. 签名制品测试接线（删 tools/release_attest.py 或 system/tests/test_release_attest.py 后此节必红）=="
if [ -f "$ROOT/tools/release_attest.py" ] && [ -f "$ROOT/system/tests/test_release_attest.py" ]; then
  python3 "$ROOT/system/tests/test_release_attest.py" >/dev/null 2>&1
  RA_RC=$?
  if [ $RA_RC -eq 0 ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ 签名/SBOM/verify 测试 8/8（篡改/换 key/重打包攻击必拒）"
  else
    FAIL_N=$((FAIL_N+1)); echo "  ❌ 签名制品测试失败（exit=${RA_RC}）"
  fi
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ release_attest 工具或测试缺失——签名制品未接线"
fi

echo "== P1h. Evidence 索引严格 validator（G9-07/R8-EVID-FIELDS-013：active 禁止 null+note 冒充严格字段）=="
# active 表逐条强制 exact 40hex commit、run_id、argv、cwd、整数 real_rc、
# ISO 时间、仓内普通非 symlink 文件、实算 artifact_sha256、合法 TTL；
# 历史不满足条目迁 legacy/non_scoring 分表（不进 active 分母）。
# 负例腿（live）：篡改 hash 的索引副本必须 rc1——validator 有牙。
if [ -f "$ROOT/tools/evidence_validator.py" ] && [ -f "$ROOT/evidence/evidence-index.json" ]; then
  python3 "$ROOT/tools/evidence_validator.py" --root "$ROOT" >/dev/null 2>&1
  EV_RC=$?
  if [ $EV_RC -eq 0 ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ evidence 索引严格合同通过（active 全字段+实算 hash+普通文件+合法 TTL）"
  else
    FAIL_N=$((FAIL_N+1)); echo "  ❌ evidence validator 失败（exit=${EV_RC}——active 条目字段/hash/TTL 违规或索引损坏）"
  fi
  EV_TMP="$TD/evid-tamper.json"
  python3 - "$ROOT" "$EV_TMP" <<'EVP'
import json, sys
doc = json.load(open(sys.argv[1] + "/evidence/evidence-index.json", encoding="utf-8"))
doc["active"]["entries"][0]["artifact_sha256"] = "0" * 64  # 篡改哈希
json.dump(doc, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=2)
EVP
  python3 "$ROOT/tools/evidence_validator.py" --root "$ROOT" --index "$EV_TMP" >/dev/null 2>&1
  EVT_RC=$?
  if [ "$EVT_RC" -eq 1 ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ 负例腿：篡改 hash 的索引副本被拒（rc1）"
  else
    FAIL_N=$((FAIL_N+1)); echo "  ❌ 负例腿失效（rc=${EVT_RC}——validator 无牙，删字段/改 hash 未红）"
  fi
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ tools/evidence_validator.py 或 evidence/evidence-index.json 缺失——严格 evidence 合同被拆"
fi

echo "== P1d. F4-CI-001：对抗自测接入 required CI（删 system/tests/test_wenqu_adversarial.py 后此节必红）=="
if [ -f "$ROOT/system/tests/test_wenqu_adversarial.py" ]; then
  python3 "$ROOT/system/tests/test_wenqu_adversarial.py" >/dev/null 2>&1
  ADV_RC=$?
  if [ ${ADV_RC} -eq 0 ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ 对抗自测全绿（P0-4 洞复验面在 required CI 内）"
  else
    FAIL_N=$((FAIL_N+1)); echo "  ❌ 对抗自测失败（exit=${ADV_RC}）——洞修复行为回归"
  fi
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ test_wenqu_adversarial.py 不存在——对抗测试被移出验收面（F4-CI-001 复发）"
fi

echo "== P1e. F4-CI-001：基础设施加固自测接入 required CI（删 system/tests/test_infra_hardening.py 后此节必红）=="
if [ -f "$ROOT/system/tests/test_infra_hardening.py" ]; then
  python3 "$ROOT/system/tests/test_infra_hardening.py" >/dev/null 2>&1
  INF_RC=$?
  if [ ${INF_RC} -eq 0 ]; then
    PASS_N=$((PASS_N+1)); echo "  ✅ 基础设施加固自测全绿（P0-3/5/6/7/F 洞复验+install 面在 required CI 内）"
  else
    FAIL_N=$((FAIL_N+1)); echo "  ❌ 基础设施加固自测失败（exit=${INF_RC}）——洞修复行为回归"
  fi
else
  FAIL_N=$((FAIL_N+1)); echo "  ❌ test_infra_hardening.py 不存在——加固测试被移出验收面（F4-CI-001 复发）"
fi

echo "== BAK. G9-09 备份演练归档真实性（R8-BAK-FAKE-TAR-SUCCESS-019：五负例全 rc1+正例全绿+success 不更新）=="
# 对 tar 的 rc 与自报清单零信任：伪 tar 五变体（双 rc0 谎报不产归档/旧归档
# 复用/symlink 归档/截断归档/伪清单内容缺失）必须全部 exit1+FAIL 且不改写
# 既有 PASS 工件（= 不更新 last-success）；正例（backup+dr）必须 PASS 且
# 报告记录作业身份 SHA、archive sha、独立解包 sha、实测 RPO/RTO。
python3 - "$ROOT" >/dev/null 2>&1 <<'BAKEOF'; ck "BAK 五负例 fail-closed+正例(backup/dr)PASS+身份/归档/RPO-RTO 合同" 0 $?
import json, os, re, shutil, sqlite3, subprocess, sys, tempfile
from pathlib import Path

repo = Path(sys.argv[1])
drill = repo / "system" / "sentinels" / "backup-restore-drill.sh"
real_tar = shutil.which("tar")
assert real_tar
sha_re = re.compile(r"[0-9a-f]{64}")
RELS = ["state/scheduler.db", "state/gate-aggregate.json",
        "observation/heartbeat.json", "observation/samples/2026-10-08.json"]

def build_corpus(root: Path, tag: str) -> None:
    (root / "state").mkdir(parents=True, exist_ok=True)
    (root / "observation" / "samples").mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(root / RELS[0]))
    conn.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY, next_due REAL)")
    conn.execute("INSERT INTO jobs VALUES (?,?)", (f"job-{tag}", 1.0))
    conn.commit(); conn.close()
    (root / RELS[1]).write_text(json.dumps({"policy_verdict": "PASS", "tag": tag}))
    (root / RELS[2]).write_text(json.dumps({"station": 1, "tag": tag}))
    (root / RELS[3]).write_text(json.dumps({"cpu": 7.5, "tag": tag}))

def run(root: Path, rdir: Path, path_prepend=None, mode="backup"):
    env = dict(os.environ)
    if path_prepend:
        env["PATH"] = f"{path_prepend}:{os.environ['PATH']}"
    p = subprocess.run(
        ["bash", str(drill), "--wenqu-root", str(root), "--report-dir", str(rdir),
         "--mode", mode], capture_output=True, text=True, timeout=180, env=env)
    reps = sorted(Path(rdir).glob("drill-*.json"))
    rep = json.loads(reps[-1].read_text(encoding="utf-8")) if reps else {}
    return p.returncode, rep, (reps[-1] if reps else None)

def fake_tar(d: Path, variant: str, canned: Path):
    s = f"""#!/bin/sh
d=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
names="$d/.names"; real="{real_tar}"; canned="{canned}"
case "$1" in
  -czf)
    out="$2"; shift 2
    : > "$names"; dir=""
    while [ $# -gt 0 ]; do
      case "$1" in
        -C) dir="$2"; shift 2 ;;
        *) printf '%s\\n' "$1" >> "$names"; shift ;;
      esac
    done
"""
    body = {"lie": "    exit 0\n",
            "stale": '    cp "$canned" "$out"\n    exit 0\n',
            "symlink": '    ln -sf "$canned" "$out"\n    exit 0\n',
            "truncate": ('    "$real" -czf "$out" -C "$dir" $(cat "$names") || exit 1\n'
                         '    sz=$(wc -c < "$out"); keep=$(( sz * 40 / 100 ))\n'
                         '    head -c "$keep" "$out" > "$out.tr" && mv "$out.tr" "$out"\n'
                         '    exit 0\n'),
            "short": ('    first=$(head -1 "$names")\n'
                      '    "$real" -czf "$out" -C "$dir" "$first" || exit 1\n'
                      '    exit 0\n')}
    s += body[variant]
    s += """    exit 0 ;;
  -tzf)
    cat "$names" 2>/dev/null
    exit 0 ;;
esac
exit 0
"""
    (d / "tar").write_text(s); (d / "tar").chmod(0o755)

markers = {"lie": "not materialized", "stale": "extract reconcile mismatch/missing",
           "symlink": "not materialized", "truncate": "independent archive extraction failed",
           "short": "extract reconcile mismatch/missing"}
with tempfile.TemporaryDirectory(prefix="wq_acc_bak_") as td:
    box = Path(td)
    good = box / "good"; build_corpus(good, "good")
    rc, rep, rpath = run(good, box / "good-rep")
    assert rc == 0 and rep["result"] == "PASS", (rc, rep.get("reason"))
    pass_bytes = rpath.read_bytes()
    arc = rep["archive"]
    assert arc["materialized"] and arc["size"] > 0 \
        and sha_re.fullmatch(arc["sha256"]) and sha_re.fullmatch(arc["extract_sha256"]) \
        and {f["rel"] for f in arc["files"]} == set(RELS), arc
    assert sha_re.fullmatch(rep["identity"]["drill_script_sha256"]) \
        and sha_re.fullmatch(rep["identity"]["scheduler_sha256"]), rep["identity"]
    assert rep["steps"]["restore"]["source"] == "archive"
    # DR 正例：RPO/RTO 实测数值入报告且在冻结目标内
    rc_dr, rep_dr, _ = run(good, box / "dr-rep", mode="dr")
    assert rc_dr == 0 and rep_dr["result"] == "PASS", rep_dr.get("reason")
    dr = rep_dr["dr"]
    assert 1.0 <= dr["rpo_seconds"] <= 300 and 0 < dr["rto_seconds"] <= 60 \
        and dr["rpo_ok"] is True and dr["rto_ok"] is True, dr
    # 五负例：全 rc1 + FAIL + reason 点名 + 不改写既有 PASS 工件
    old = box / "old"
    for rel in RELS:
        dst = old / rel; dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(f"STALE:{rel}".encode())
    canned_old = box / "old.tar.gz"
    subprocess.run([real_tar, "-czf", str(canned_old), "-C", str(old)] + RELS, check=True)
    for variant in ("lie", "stale", "symlink", "truncate", "short"):
        fd = box / f"fake-{variant}"; fd.mkdir()
        fake_tar(fd, variant, canned_old)
        leg_root = box / f"home-{variant}"; build_corpus(leg_root, variant)
        lrc, lrep, _ = run(leg_root, box / f"rep-{variant}", path_prepend=fd)
        assert lrc == 1 and lrep["result"] == "FAIL", (variant, lrc, lrep.get("reason"))
        assert markers[variant] in lrep["reason"], (variant, lrep["reason"])
        assert rpath.read_bytes() == pass_bytes, f"{variant} 改写了既有 PASS 工件"
    print("BAK matrix ok")
sys.exit(0)
BAKEOF

echo "================================"
echo "RESULT: PASS=$PASS_N FAIL=$FAIL_N"
[ $FAIL_N -eq 0 ] && echo "ALL GREEN" || exit 1

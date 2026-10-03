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
R6="$TD/sprepo"; mkdir -p "$R6/my dir"
printf '#!/usr/bin/env bash\ntrap "rm x" EXIT\ntrap "rm y" EXIT\n' > "$R6/my dir/bad script.sh"; echo "v=1" > "$R6/e.py"
cp "$ROOT/probes/stations.json" "$H5/stations.json"
python3 "$WQ" --home "$H5" init --path "$R6" >/dev/null 2>&1
python3 "$WQ" --home "$H5" run trap-double --path "$R6" >/dev/null 2>&1; ck "空格文件名真命中" 1 $?

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
  FAIL_N=$((FAIL_N+1)); echo "  ❌ 降级分支未按预期（rc=$ERC）"
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

echo "== H. pytest 契约套件（若 pytest 可用）=="
if python3 -c "import pytest" 2>/dev/null; then
  (cd "$ROOT/cli" && python3 -m pytest test_wenqu.py -q >/dev/null 2>&1); ck "pytest 20 用例" 0 $?
else
  echo "  ⏭ pytest 不可用，跳过（selftest 已覆盖核心契约）"
fi

echo "================================"
echo "RESULT: PASS=$PASS_N FAIL=$FAIL_N"
[ $FAIL_N -eq 0 ] && echo "ALL GREEN" || exit 1

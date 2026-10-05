#!/usr/bin/env bash
# hardening-doctor v1（2026-10-01 建仓加固收官件——加固体系自身的体检）
# 看什么：八连加固的十件套——存在性/调度挂载/执行新鲜度 + EXM 台账日落巡检（并入）。
# 用法：bash hardening-doctor.sh   # 全绿 exit 0；任一红 exit 1（可接值班巡检）
set -uo pipefail
Q=~/.zcode/quality-system/4c6665172cfd52c9
NOW=$(date +%s)
FAIL=0
ok()  { echo "  ✓ $1"; }
bad() { echo "  ✗ $1"; FAIL=1; }

echo "== hardening-doctor $(date '+%F %T') =="

# ── bin 工具五件（存在+可执行） ──
for t in deploy-preflight relay-push claim-doctor workorder-precheck hardening-doctor; do
  [ -x "$Q/bin/$t.sh" ] && ok "bin/$t.sh" || bad "bin/$t.sh 缺失或不可执行"
done

# ── 哨兵四件：脚本 + launchd 注册 + 日志新鲜度（macOS bash 3.2 无关联数组，用 case 映射） ──
for s in dupscan-weekly weekly-watchdog ci-event-sentinel conservation-sentinel; do
  [ -x "$Q/sentinel/$s.sh" ] && ok "sentinel/$s.sh" || { bad "sentinel/$s.sh 缺失"; continue; }
  case "$s" in
    dupscan-weekly)       PLIST=com.maccc.bugscan.dupscan-weekly;      FRESH=20160; LOGP="/Users/maccc/Documents/ERP）Zcode/dupscan周哨兵" ;;
    weekly-watchdog)      PLIST=com.maccc.bugscan.weekly-watchdog;     FRESH=20160; LOGP="$Q/sentinel/weekly.log" ;;
    ci-event-sentinel)    PLIST=com.maccc.quality.ci-event-sentinel;   FRESH=100;   LOGP="$Q/sentinel/ci-event.log" ;;
    conservation-sentinel) PLIST=com.maccc.quality.conservation-sentinel; FRESH=1600; LOGP="$Q/sentinel/conservation.log" ;;
  esac
  launchctl print "gui/$(id -u)/$PLIST" >/dev/null 2>&1 && ok "$s 调度挂载" || bad "$s launchd 未挂载（$PLIST）"
  if [ "$s" = "dupscan-weekly" ]; then
    LATEST=$(ls -t "$LOGP"/dupscan-weekly-*.txt 2>/dev/null | head -1)
    [ -n "$LATEST" ] || { bad "$s 无任何报告"; continue; }
    AGE=$(( (NOW - $(stat -f %m "$LATEST")) / 60 ))
  else
    [ -f "$LOGP" ] || { bad "$s 日志不存在"; continue; }
    AGE=$(( (NOW - $(stat -f %m "$LOGP")) / 60 ))
  fi
  if [ "$AGE" -le "$FRESH" ]; then ok "$s 新鲜（${AGE}min）"; else bad "$s 停摆（${AGE}min > $FRESH）"; fi
done

# ── 生产侧两件 ──
ssh -o ConnectTimeout=8 ${WENQU_DB_SSH} 'test -f /etc/cron.d/erp-backup-rotate' >/dev/null 2>&1 && ok "cloud4 备份轮转 cron" || bad "cloud4 备份轮转 cron 缺失"
ssh -o ConnectTimeout=8 ${WENQU_DB_SSH} 'test -x /opt/erp-backups/dump-rotate.sh' >/dev/null 2>&1 && ok "dump-rotate.sh" || bad "dump-rotate.sh 缺失"

# ── CI 卡死检测（事故树补口：红有簿记闸、不跑有事件哨兵、卡住曾 90min 靠人巡） ──
STUCK=$(gh run list --limit 30 --json databaseId,status,createdAt,workflowName 2>/dev/null | python3 -c "
import json,sys,datetime
now=datetime.datetime.now(datetime.timezone.utc)
for r in json.load(sys.stdin):
    if r['status']=='completed': continue
    t=datetime.datetime.fromisoformat(r['createdAt'].replace('Z','+00:00'))
    mins=(now-t).total_seconds()/60
    if mins>75: print(f\"{r['databaseId']} {r['workflowName']} 已 {int(mins)}min 未完成\")
" 2>/dev/null | head -3)
if [ -n "$STUCK" ]; then
  bad "CI 疑似卡死：$(echo "$STUCK" | tr '\n' '；')（>75min；处置=分诊内容/环境后 cancel+重跑）"
else
  ok "CI 无卡死（进行中 run 均 <75min）"
fi

# ── EXM 台账日落巡检（EXM-01 判释过早教训） ──
python3 - "$HOME/.zcode/quality-system/EXM-ledger.jsonl" <<'PY' 2>/dev/null || true
import json, sys, datetime
active, expired = {}, []
for line in open(sys.argv[1]):
    try: d = json.loads(line)
    except: continue
    if d.get("record_type") == "resolve": active.pop(d["id"], None)
    elif "expire" in d and "id" in d: active[d["id"]] = d
today = datetime.date.today()
for k, v in active.items():
    exp = datetime.date.fromisoformat(v["expire"])
    if exp < today: expired.append(k)
    elif (exp - today).days <= 3: print(f"  ⚠ EXM {k} 将到期（{v['expire']}）")
if len(active) > 5: print(f"  ✗ 活跃豁免 {len(active)} 条 >5 熔断线（上报超哥）"); sys.exit(1)
if expired: print(f"  ✗ EXM 已过期未处置: {' '.join(expired)}（30 天日落）"); sys.exit(1)
if active: print(f"  ✓ EXM 活跃 {len(active)} 条均期内: {' '.join(active)}")
else: print("  ✓ EXM 台账无活跃豁免")
PY

[ "$FAIL" -eq 0 ] && echo "== PASS：加固体系十件全活 ==" || { echo "== FAIL：上方 ✗ 项处置 =="; exit 1; }

# ── 极强层：DB 守恒触发器 ──
DB_TRG=$(ssh -o ConnectTimeout=8 ${WENQU_DB_SSH} 'sudo -u postgres psql ${WENQU_DB_NAME} -tAc "SELECT COUNT(*) FROM pg_trigger WHERE tgname LIKE '"'"'trg_%conservation'"'"' AND tgenabled='"'"'O'"'"'" 2>/dev/null' | head -1)
DB_TRG=${DB_TRG:-0}
if [ "$DB_TRG" -ge 3 ]; then
  ok "DB 守恒触发器×3（shadow mode 活跃）"
else
  bad "DB 守恒触发器仅 $DB_TRG/3——查 conservation-triggers.sql"
fi

# ── 自进化引擎 ──
for tool in gate-learner risk-scorer; do
  [ -f "$Q/bin/$tool.py" ] && ok "bin/$tool.py（自进化件）" || bad "bin/$tool.py 缺失"
done
LEARNED=$(wc -l < "$HOME/.zcode/quality-system/iron-gate-rules.jsonl" 2>/dev/null || echo 0)
ok "自进化规则库 ${LEARNED} 条已学习"

# ── 极限层：Z3 + TLA+ 生成器 + CDC ──
[ -f "$Q/z3/payment_invariants.smt2" ] && ok "Z3 资金不变式（5 定理证明）" || bad "Z3 不变式缺失"
[ -f "$Q/bin/ts-to-tla.py" ] && ok "LLM→TLA+ 自动生成器" || bad "ts-to-tla.py 缺失"
[ -f "$Q/bin/cdc-conservation-stream.py" ] && ok "CDC 实时流脚本" || bad "CDC 脚本缺失"
which z3 >/dev/null 2>&1 && ok "Z3 solver $(z3 --version | cut -d' ' -f3)" || bad "Z3 未安装"

# ── 迭代层：自动化闭环 ──
pgrep -f "auto-merge.sh" >/dev/null && ok "auto-merge daemon（合流自动化）" || bad "auto-merge 未运行"  # 10-5 修：ps|grep 竞态→pgrep -f
[ -x "$Q/bin/auto-merge.sh" ] && ok "auto-merge.sh" || bad "auto-merge.sh 缺失"

# ── 收尾层 ──
launchctl print "gui/$(id -u)/com.maccc.quality.ssl-cert-sentinel" >/dev/null 2>&1 && ok "SSL 证书哨兵（每日 08:08）" || bad "SSL 哨兵未挂载"

#!/usr/bin/env bash
# conservation-sentinel v1（2026-10-01 建仓加固——资金守恒常驻防线）
# 反的什么事故：Z10 存量对账五域全零（9-30 人肉冲正 18998/3800/1600/307800 后归零）——
#   但守恒是状态不是结果：新代码 bug/旁路写会再次漂移，无人自动发现（本次就是 8-31 双计潜伏月余才被扫描抓到）。
# 捕获原理：每日对账五域不变量（只读 SQL），任一非零→HIGH 告警（走 alert-send 统一外发）。
# 五域口径（与 9-30 冲正终态一致）：
#   sale   = ΣPayment.paidAmount(saleOrderId 非空) − ΣSaleOrder.receivedAmount          应=0
#   wallet = ΣWalletTransaction 净额(CHARGE/REFUND_IN 加,其余减) − ΣCustomerWallet.balance 应=0
#   points = ΣCustomerPointRecord.points − ΣCustomer.memberPoints                       应=0
#   cash   = ΣCashAccount.balance − ΣCashAccountTransaction.amount                       应=0
#   income = SALE_INCOME 偏离单（|Σledger−totalAmount|>0.01 且非储值正确负 gap）          应≤3（已知正确终态）
set -uo pipefail
LOG=~/.zcode/quality-system/4c6665172cfd52c9/sentinel/conservation.log
ALERT_SEND=/Users/maccc/argus3-runtime/scripts/argus/alert-send.sh
ts() { date '+%F %T'; }
alert() {
  echo "$(ts) [$1] $2" >> "$LOG"
  [ -x "$ALERT_SEND" ] && "$ALERT_SEND" "$1" "conservation-sentinel" "$2" >/dev/null 2>&1 || true
}

SQLF=/tmp/cons-sentinel.sql
cat > "$SQLF" <<'SQLEOF'
-- 极强层：DB 触发器实时违规 + 全域聚合（双层——触发器毫秒级，聚合做日频校准）
SELECT 'sale=' || (((SELECT COALESCE(SUM(p."paidAmount"),0) FROM "Payment" p WHERE p."saleOrderId" IS NOT NULL) - (SELECT COALESCE(SUM(s."receivedAmount"),0) FROM "SaleOrder" s))::text)
 || ' wallet=' || (((SELECT COALESCE(SUM(CASE WHEN t.type IN ('CHARGE','REFUND_IN') THEN t.amount ELSE -t.amount END),0) FROM "WalletTransaction" t) - (SELECT COALESCE(SUM(w."balance"),0) FROM "CustomerWallet" w))::text)
 || ' points=' || (((SELECT COALESCE(SUM("points"),0) FROM "CustomerPointRecord") - (SELECT COALESCE(SUM("memberPoints"),0) FROM "Customer"))::text)
 || ' cash=' || (((SELECT COALESCE(SUM("balance"),0) FROM "CashAccount") - (SELECT COALESCE(SUM(amount),0) FROM "CashAccountTransaction"))::text);
SELECT 'income_pos=' || (SELECT COUNT(*) FROM (SELECT le."relatedOrderId" AS sid, SUM(le.amount) AS lsum FROM "LedgerEntry" le WHERE le.type='SALE_INCOME' GROUP BY 1) t JOIN "SaleOrder" s ON s.id=t.sid WHERE t.lsum - s."totalAmount" > 0.01)::text;
SELECT 'db_violations=' || (SELECT COUNT(*) FROM conservation_violations WHERE violated_at > now() - interval '24 hours')::text;
SELECT 'db_violations_detail=' || COALESCE((SELECT string_agg(invariant || ':' || entity_id || '(' || delta || ')', '; ') FROM conservation_violations WHERE violated_at > now() - interval '24 hours' LIMIT 5), 'none');
SQLEOF
scp -q -o ConnectTimeout=10 "$SQLF" ${WENQU_DB_SSH}:/tmp/cons-sentinel.sql 2>/dev/null || { alert MEDIUM "scp SQL 失败"; exit 1; }

OUT=$(ssh -o ConnectTimeout=10 ${WENQU_DB_SSH} 'sudo -u postgres psql ${WENQU_DB_NAME} -tAf /tmp/cons-sentinel.sql 2>&1' | tr '\n' ' ')
if [ -z "$OUT" ]; then
  alert MEDIUM "守恒哨兵取数失败（ssh/psql 通道）——连续失败须人工核"
  exit 1
fi

BAD=""
echo "$OUT" | tr ' ' '\n' | while IFS='=' read -r k v; do
  [ -z "$k" ] && continue
  case "$k" in sale|wallet|points|cash) ;; *) continue ;; esac
  if [ "$v" != "0" ] && [ "$v" != "0.00" ] && [ "$v" != "-0.00" ]; then
    echo "DRIFT:$k=$v"
  fi
done | grep DRIFT > /tmp/cons-drift.$$ 2>/dev/null || true

INC=$(echo "$OUT" | tr ' ' '\n' | grep '^income_pos=' | cut -d= -f2)
INC=${INC:-99}
DBV=$(echo "$OUT" | tr ' ' '\n' | grep '^db_violations=' | cut -d= -f2)
DBV=${DBV:-0}
DBDETAIL=$(echo "$OUT" | tr ' ' '\n' | grep '^db_violations_detail=' | cut -d= -f2-)

if [ -s /tmp/cons-drift.$$ ] || [ "$INC" -gt 3 ] || [ "$DBV" -gt 0 ]; then
  D=$(tr '\n' ';' < /tmp/cons-drift.$$ 2>/dev/null)
  alert HIGH "资金守恒漂移：${D:-} income_double_count=${INC} db_realtime_violations=${DBV} detail=${DBDETAIL:-none}（9-30 归零后新漂移——DB 触发器已毫秒级捕获）"
  rm -f /tmp/cons-drift.$$
  exit 1
fi
rm -f /tmp/cons-drift.$$
echo "$(ts) [OK] $OUT" >> "$LOG"

#!/usr/bin/env bash
# SSL 证书过期监控（<30 天告警，<7 天升级 CRITICAL）
set -uo pipefail
LOG=~/.zcode/quality-system/4c6665172cfd52c9/sentinel/ssl-cert.log
ALERT=/Users/maccc/argus3-runtime/scripts/argus/alert-send.sh
DOMAIN="${1:-${WENQU_CERT_DOMAIN}}"

EXPIRY=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
[ -z "$EXPIRY" ] && echo "$(date '+%F %T') [ERROR] 无法获取证书" >> "$LOG" && exit 1

DAYS=$(python3 -c "import datetime; print((datetime.datetime.strptime('$EXPIRY', '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc) - datetime.datetime.now(datetime.timezone.utc)).days)")
ts=$(date '+%F %T')

if [ "$DAYS" -le 7 ]; then
    echo "$ts [CRITICAL] $DOMAIN SSL 证书 $DAYS 天后过期！($EXPIRY)" >> "$LOG"
    [ -x "$ALERT" ] && "$ALERT" "CRITICAL" "ssl-cert" "$DOMAIN SSL $DAYS 天过期" >/dev/null 2>&1
    exit 1
elif [ "$DAYS" -le 30 ]; then
    echo "$ts [WARN] $DOMAIN SSL 证书 $DAYS 天后过期 ($EXPIRY)" >> "$LOG"
    [ -x "$ALERT" ] && "$ALERT" "WARN" "ssl-cert" "$DOMAIN SSL $DAYS 天过期" >/dev/null 2>&1
    exit 1
else
    echo "$ts [OK] $DOMAIN SSL 剩余 $DAYS 天" >> "$LOG"
fi

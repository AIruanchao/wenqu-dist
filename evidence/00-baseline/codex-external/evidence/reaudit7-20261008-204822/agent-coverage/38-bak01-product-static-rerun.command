grep -nE '(^|[^[:alnum:]_])(cp|tar|success|result|mktemp)' system/sentinels/backup-restore-drill.sh | sed -n '1,240p'; grep -n 'run_drill' system/tests/test_ac_ops_families.py | head -20; true

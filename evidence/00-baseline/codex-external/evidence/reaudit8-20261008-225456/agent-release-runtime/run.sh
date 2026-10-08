#!/bin/bash
set -uo pipefail
if [ "$#" -lt 2 ]; then echo 'usage: run.sh ID COMMAND...' >&2; exit 64; fi
id=$1; shift
E=$(cd "$(dirname "$0")" && pwd)
out="$E/${id}.out"
cmd="$*"
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
  printf '=== id=%s ===\n=== started_utc=%s ===\n=== cwd=%s ===\n=== command ===\n%s\n=== output ===\n' "$id" "$start" "$PWD" "$cmd"
} > "$out"
set +e
/bin/bash -lc "$cmd" >> "$out" 2>&1
rc=$?
set -e
end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '\n=== exit_code=%s ===\n=== ended_utc=%s ===\n' "$rc" "$end" >> "$out"
escaped=$(printf '%s' "$cmd" | tr '\t\r\n' '   ')
printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$start" "$end" "$rc" "$escaped" >> "$E/commands.tsv"
printf 'id=%s rc=%s output=%s\n' "$id" "$rc" "$out"
exit 0

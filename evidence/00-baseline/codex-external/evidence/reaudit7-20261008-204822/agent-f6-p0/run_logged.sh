#!/bin/bash
set -u
if [ "$#" -lt 2 ]; then
  echo "usage: $0 LOGFILE COMMAND..." >&2
  exit 64
fi
log=$1
shift
mkdir -p "$(dirname "$log")"
cmd=$(printf '%q ' "$@")
{
  printf 'TIMESTAMP_UTC: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'CWD: %s\n' "$PWD"
  printf 'COMMAND: %s\n' "$cmd"
  printf '%s\n' 'OUTPUT_BEGIN'
} > "$log"
set +e
"$@" >> "$log" 2>&1
rc=$?
set -e
{
  printf '%s\n' 'OUTPUT_END'
  printf 'EXIT_CODE: %s\n' "$rc"
} >> "$log"
exit "$rc"

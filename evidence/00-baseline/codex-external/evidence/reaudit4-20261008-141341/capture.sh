#!/bin/bash
set -u
out=$1; shift
{
  echo "timestamp=$(TZ=Asia/Shanghai date -Iseconds)"
  printf 'cwd=%q\n' "$PWD"
  printf 'command='; printf '%q ' "$@"; echo
  echo '--- stdout+stderr ---'
} > "$out"
set +e
"$@" >> "$out" 2>&1
rc=$?
set -e
{
  echo '--- end ---'
  echo "exit_code=$rc"
} >> "$out"
exit 0

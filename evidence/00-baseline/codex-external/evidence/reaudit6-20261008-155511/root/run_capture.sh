#!/bin/bash
set +e
name="$1"; shift
out="$ROOT_EVD/root/regression/${name}.log"
mkdir -p "$(dirname "$out")"
{
 echo "CAPTURED_AT=$(date -Ins)"
 printf 'COMMAND='; printf '%q ' "$@"; echo
 echo '--- OUTPUT ---'
 "$@"
 rc=$?
 echo "--- EXIT_CODE=$rc ---"
 exit "$rc"
} >"$out" 2>&1

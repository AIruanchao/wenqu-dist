#!/usr/bin/env bash
set -u
if [ "$#" -lt 2 ]; then echo "usage: capture.sh OUT COMMAND..." >&2; exit 64; fi
out=$1; shift
mkdir -p "$(dirname "$out")"
{
  printf 'COMMAND:'
  printf ' %q' "$@"
  printf '\nSTART: %s\n' "$(date -Iseconds)"
  "$@"
  rc=$?
  printf '\nEXIT_CODE: %s\nEND: %s\n' "$rc" "$(date -Iseconds)"
  exit "$rc"
} >"$out" 2>&1

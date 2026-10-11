#!/usr/bin/env bash
set -u
out=$1
shift
cmd=$*
mkdir -p "$(dirname "$out")"
{
  printf 'timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'pwd=%s\n' "$PWD"
  printf 'command=%s\n' "$cmd"
  printf '%s\n' '--- output begin ---'
  set +e
  bash -o pipefail -lc "$cmd"
  rc=$?
  set -e
  printf '%s\n' '--- output end ---'
  printf 'exit_code=%s\n' "$rc"
} >"$out" 2>&1
exit 0

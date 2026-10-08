#!/bin/bash
set -u
if [ "$#" -lt 2 ]; then
  echo "usage: capture.sh LOG COMMAND..." >&2
  exit 64
fi
log=$1
shift
mkdir -p "$(dirname "$log")"
{
  printf '[started_utc=%s]\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '[cwd=%s]\n' "$PWD"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  rc=$?
  printf '[exit_code=%s]\n' "$rc"
  printf '[finished_utc=%s]\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  exit "$rc"
} >"$log" 2>&1

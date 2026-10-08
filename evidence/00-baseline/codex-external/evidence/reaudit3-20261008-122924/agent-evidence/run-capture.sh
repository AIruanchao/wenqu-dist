#!/usr/bin/env bash
set +e
if [[ $# -lt 2 ]]; then echo 'usage: run-capture.sh <name> <command>' >&2; exit 64; fi
name="$1"; shift
cmd="$*"
out="$(cd "$(dirname "$0")" && pwd)/${name}.log"
{
  printf 'TIMESTAMP_START=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'CWD=%s\n' "$PWD"
  printf 'COMMAND=%s\n' "$cmd"
  printf '%s\n' '--- OUTPUT BEGIN ---'
  bash -o pipefail -lc "$cmd"
  rc=$?
  printf '%s\n' '--- OUTPUT END ---'
  printf 'EXIT_CODE=%s\n' "$rc"
  printf 'TIMESTAMP_END=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$out" 2>&1
rc=$(awk -F= '/^EXIT_CODE=/{x=$2} END{print x}' "$out")
printf '%s\n' "$out"
exit "${rc:-1}"

#!/bin/bash
set -u
if [ "$#" -lt 3 ]; then
  echo "usage: run-cmd.sh LABEL WORKDIR COMMAND" >&2
  exit 64
fi
label=$1
workdir=$2
cmd=$3
base="$(cd "$(dirname "$0")" && pwd)/$label"
printf '%s\n' "$cmd" > "${base}.command"
printf '%s\n' "$workdir" > "${base}.cwd"
date -u +%Y-%m-%dT%H:%M:%SZ > "${base}.started_at"
(cd "$workdir" && /bin/bash -lc "$cmd") > "${base}.stdout" 2> "${base}.stderr"
rc=$?
printf '%s\n' "$rc" > "${base}.exit_code"
date -u +%Y-%m-%dT%H:%M:%SZ > "${base}.finished_at"
{
  printf 'COMMAND: %s\n' "$cmd"
  printf 'WORKDIR: %s\n' "$workdir"
  printf 'EXIT_CODE: %s\n' "$rc"
  printf '%s\n' '--- STDOUT ---'
  cat "${base}.stdout"
  printf '%s\n' '--- STDERR ---'
  cat "${base}.stderr"
} > "${base}.log"
printf '%s rc=%s\n' "$label" "$rc"
exit 0

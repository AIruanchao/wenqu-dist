#!/usr/bin/env python3
import datetime
import os
import pathlib
import shlex
import subprocess
import sys

if len(sys.argv) < 4:
    raise SystemExit("usage: run_cmd.py LABEL CWD COMMAND...")

label, cwd = sys.argv[1:3]
command = " ".join(sys.argv[3:])
base = pathlib.Path(__file__).resolve().parent
logs = base / "logs"
logs.mkdir(parents=True, exist_ok=True)
safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
existing = sorted(logs.glob(safe + "*.log"))
log_path = logs / f"{safe}-{len(existing)+1:03d}.log"
started = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()
proc = subprocess.run(
    ["/bin/zsh", "-lc", command],
    cwd=cwd,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    errors="replace",
)
ended = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()
body = (
    f"label: {label}\nstarted: {started}\nended: {ended}\n"
    f"cwd: {cwd}\ncommand: {command}\nexit_code: {proc.returncode}\n"
    "--- output ---\n" + proc.stdout
)
log_path.write_text(body, encoding="utf-8")
tsv = base / "commands.tsv"
if not tsv.exists():
    tsv.write_text("started\tended\tlabel\tcwd\tcommand\texit_code\tlog\n", encoding="utf-8")
def cell(s):
    return str(s).replace("\t", " ").replace("\n", "\\n")
with tsv.open("a", encoding="utf-8") as fh:
    fh.write("\t".join(map(cell, [started, ended, label, cwd, command, proc.returncode, log_path.name])) + "\n")
sys.stdout.write(proc.stdout)
sys.stderr.write(f"\n[reaudit8] label={label} rc={proc.returncode} log={log_path}\n")
raise SystemExit(proc.returncode)

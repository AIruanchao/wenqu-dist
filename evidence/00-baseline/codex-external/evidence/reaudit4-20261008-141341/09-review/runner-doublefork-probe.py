import os, sys, tempfile, time, signal
from pathlib import Path
sys.path.insert(0, os.path.join(sys.argv[1], 'system'))
from wenqu_core.runner import TrustedRunner

td = Path(tempfile.mkdtemp(prefix='reaudit4-runner-doublefork-'))
marker = td/'marker'
pidfile = td/'pid'
child = td/'child.py'
child.write_text('''import os,sys,time\nmarker,pidfile=sys.argv[1:3]\np=os.fork()\nif p==0:\n os.setsid()\n q=os.fork()\n if q==0:\n  open(pidfile,"w").write(str(os.getpid()))\n  time.sleep(1.0)\n  open(marker,"w").write("escaped")\n  time.sleep(3.0)\n  os._exit(0)\n os._exit(0)\ntime.sleep(5)\n''')
r=TrustedRunner(timeout=0.35, allowlist=[sys.executable])
ev=r.run([sys.executable,str(child),str(marker),str(pidfile)])
time.sleep(1.25)
pid = int(pidfile.read_text()) if pidfile.exists() else None
alive=False
if pid:
 try: os.kill(pid,0); alive=True
 except ProcessLookupError: pass
print({'timed_out':ev.timed_out,'actual_exit_code':ev.actual_exit_code,'marker_exists':marker.exists(),'escaped_pid':pid,'escaped_alive':alive})
if pid:
 try: os.kill(pid, signal.SIGKILL)
 except ProcessLookupError: pass
# Probe success means defense blocked marker. Return 1 when escape occurred.
raise SystemExit(1 if marker.exists() else 0)

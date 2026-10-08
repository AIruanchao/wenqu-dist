#!/usr/bin/env python3
import json, os, sys, tempfile, time
from pathlib import Path
sys.path.insert(0,'/Users/maccc/Documents/wenqu-dist/system')
import wenqu_core.runner as runner_mod
from wenqu_core.runner import EvidenceStore, Evidence, IntegrityError, TrustedRunner

def ev():
 return Evidence(argv=('echo','x'),cwd='/tmp',actual_exit_code=0,stdout_sha256='a'*64,stderr_sha256='b'*64,argv_digest='c'*64,timestamp=1.0,fresh_until=2.0)

def emit(name, fn):
 try:
  v=fn(); print(f'{name}: RESULT={v!r}')
 except Exception as e:
  print(f'{name}: EXCEPTION={type(e).__name__}: {e}')

# Fixed cases
base=Path(tempfile.mkdtemp(prefix='reaudit3-cas-basic-'))
store=EvidenceStore(str(base/'cas'))
d=store.digest_for(ev()); shard=base/'cas'/d[:2]; shard.mkdir(parents=True)
outside=base/'outside.json'; outside.write_bytes(ev().to_json().encode())
os.symlink(outside, shard/(d+'.json'))
emit('CAS_final_symlink_get_should_reject', lambda: store.get(d))

base2=Path(tempfile.mkdtemp(prefix='reaudit3-cas-corrupt-')); s2=EvidenceStore(str(base2/'cas')); d2=s2.digest_for(ev()); p2=base2/'cas'/d2[:2]/(d2+'.json'); p2.parent.mkdir(parents=True); p2.write_bytes(b'corrupt')
emit('CAS_corrupt_preexisting_put_should_reject', lambda: s2.put(ev()))

# Same-level prefix escape: /.../cas -> /.../casevil passes string startswith test.
base3=Path(tempfile.mkdtemp(prefix='reaudit3-cas-prefix-')); root3=base3/'cas'; evil3=base3/'casevil'; evil3.mkdir(); s3=EvidenceStore(str(root3))
mal='aa/../../../casevil/probe'; target3=evil3/'probe.json'; target3.write_text('outside')
emit('CAS_prefix_escape_resolved_path', lambda: str(s3._path_for(mal)))
emit('CAS_prefix_escape_contains_outside', lambda: s3.contains(mal))

# Hardlink is accepted as existing CAS content, violating explicit hardlink rejection.
base4=Path(tempfile.mkdtemp(prefix='reaudit3-cas-hardlink-')); s4=EvidenceStore(str(base4/'cas')); d4=s4.digest_for(ev()); p4=base4/'cas'/d4[:2]/(d4+'.json'); p4.parent.mkdir(parents=True); out4=base4/'outside-evidence'; out4.write_bytes(ev().to_json().encode()); os.link(out4,p4)
emit('CAS_hardlink_nlink_before', lambda: (os.stat(out4).st_nlink, os.stat(p4).st_nlink))
emit('CAS_hardlink_put_should_reject', lambda: s4.put(ev()))

# Deterministic TOCTOU: swap checked shard directory to symlink exactly at os.open.
base5=Path(tempfile.mkdtemp(prefix='reaudit3-cas-race-put-')); root5=base5/'cas'; outside5=base5/'outside'; outside5.mkdir(); s5=EvidenceStore(str(root5)); d5=s5.digest_for(ev()); shard5=root5/d5[:2]; target5=shard5/(d5+'.json'); old_open=runner_mod.os.open; swapped={'v':False}
def racing_open(path, flags, mode=0o777, *args, **kwargs):
 if Path(path)==target5 and not swapped['v']:
  swapped['v']=True
  os.rename(shard5, root5/(d5[:2]+'.checked'))
  os.symlink(outside5, shard5)
 return old_open(path,flags,mode,*args,**kwargs)
runner_mod.os.open=racing_open
try: emit('CAS_parent_swap_put_result', lambda: s5.put(ev()))
finally: runner_mod.os.open=old_open
emit('CAS_parent_swap_outside_file_exists', lambda: (outside5/(d5+'.json')).exists())

# Deterministic TOCTOU read: safe at resolve, parent swapped before read_bytes; get consumes outside file.
base6=Path(tempfile.mkdtemp(prefix='reaudit3-cas-race-get-')); root6=base6/'cas'; outside6=base6/'outside'; outside6.mkdir(); s6=EvidenceStore(str(root6)); d6=s6.digest_for(ev()); shard6=root6/d6[:2]; shard6.mkdir(parents=True); target6=shard6/(d6+'.json'); target6.write_bytes(ev().to_json().encode()); (outside6/(d6+'.json')).write_bytes(ev().to_json().encode())
old_read=Path.read_bytes; swapread={'v':False}
def racing_read(self):
 if self==target6 and not swapread['v']:
  swapread['v']=True
  os.rename(shard6,root6/(d6[:2]+'.checked'))
  os.symlink(outside6,shard6)
 return old_read(self)
Path.read_bytes=racing_read
try: emit('CAS_parent_swap_get_reads_outside', lambda: s6.get(d6))
finally: Path.read_bytes=old_read

# Direct-write partial failure leaves poison file; no private tmp + fsync + rename.
base7=Path(tempfile.mkdtemp(prefix='reaudit3-cas-partial-')); root7=base7/'cas'; s7=EvidenceStore(str(root7)); d7=s7.digest_for(ev()); p7=root7/d7[:2]/(d7+'.json'); old_write=runner_mod.os.write; calls={'n':0}
def broken_write(fd, buf):
 calls['n']+=1
 if calls['n']==1: return old_write(fd, bytes(buf[:5]))
 raise OSError('injected disk failure after partial write')
runner_mod.os.write=broken_write
try: emit('CAS_partial_first_put', lambda: s7.put(ev()))
finally: runner_mod.os.write=old_write
emit('CAS_partial_file_size', lambda: p7.stat().st_size if p7.exists() else None)
emit('CAS_partial_retry_poisoned', lambda: s7.put(ev()))

# Runner timeout: ordinary descendant stays in group and should die.
td=Path(tempfile.mkdtemp(prefix='reaudit3-runner-')); marker1=td/'ordinary'; code1="import subprocess,time,sys; subprocess.Popen([sys.executable,'-c',\"import time,pathlib;time.sleep(.7);pathlib.Path(r'%s').write_text('alive')\"]); time.sleep(5)" % marker1
r=TrustedRunner(timeout=.2); out=r.run([sys.executable,'-c',code1]); time.sleep(1)
print('RUNNER_ordinary_descendant: timed_out=%r marker_exists=%r' % (out.timed_out,marker1.exists()))
# Escaped descendant creates its own session and survives killpg.
marker2=td/'escaped'; code2="import subprocess,time,sys; subprocess.Popen([sys.executable,'-c',\"import time,pathlib;time.sleep(.7);pathlib.Path(r'%s').write_text('alive')\"],start_new_session=True); time.sleep(5)" % marker2
out2=r.run([sys.executable,'-c',code2]); time.sleep(1)
print('RUNNER_setsid_descendant: timed_out=%r marker_exists=%r marker=%r' % (out2.timed_out,marker2.exists(),marker2.read_text() if marker2.exists() else None))
# Default runner inherits environment and permits arbitrary shell executable.
os.environ['WENQU_FAKE_SECRET_FOR_AUDIT']='sentinel-value'
envmark=td/'env'; shellmark=td/'shell'
r0=TrustedRunner(timeout=2)
o3=r0.run([sys.executable,'-c',"import os,pathlib; pathlib.Path(r'%s').write_text(os.environ.get('WENQU_FAKE_SECRET_FOR_AUDIT','MISSING'))" % envmark])
o4=r0.run(['/bin/sh','-c',"printf shell-ran > '%s'" % shellmark])
print('RUNNER_env_inheritance: rc=%r value=%r' % (o3.actual_exit_code,envmark.read_text() if envmark.exists() else None))
print('RUNNER_default_allowlist_disabled_shell: rc=%r marker=%r' % (o4.actual_exit_code,shellmark.read_text() if shellmark.exists() else None))

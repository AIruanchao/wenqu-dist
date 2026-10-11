#!/usr/bin/env python3
import os,sys,subprocess,hashlib,stat,re
repo,root,commit=sys.argv[1:4]
resolved=subprocess.check_output(['git','-C',repo,'rev-parse',commit],text=True).strip()
raw=subprocess.check_output(['git','-C',repo,'ls-tree','-rz','-r','--full-tree',resolved])
git={}
for rec in raw.split(b'\0'):
 if not rec: continue
 meta,p=rec.split(b'\t',1); mode,typ,oid=meta.decode().split(); git[p.decode('utf-8','surrogateescape')]=(mode,oid)
fs={}
for dp,dns,fns in os.walk(root,followlinks=False):
 # symlink dirs are emitted via dns; record and do not descend
 for name in list(dns):
  p=os.path.join(dp,name)
  if os.path.islink(p):
   rel=os.path.relpath(p,root); fs[rel]=p; dns.remove(name)
 for name in fns:
  p=os.path.join(dp,name); fs[os.path.relpath(p,root)]=p
missing=sorted(set(git)-set(fs)); extra=sorted(set(fs)-set(git)); mm=[]
p=subprocess.Popen(['git','-C',repo,'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
for path,(gmode,oid) in git.items():
 p.stdin.write((oid+'\n').encode());p.stdin.flush(); h=p.stdout.readline().decode().split(); n=int(h[2]); blob=p.stdout.read(n); assert p.stdout.read(1)==b'\n'
 fp=fs.get(path)
 if fp is None: continue
 st=os.lstat(fp)
 if stat.S_ISLNK(st.st_mode): data=os.readlink(fp).encode('utf-8','surrogateescape'); fmode='120000'
 elif stat.S_ISREG(st.st_mode):
  with open(fp,'rb') as f:data=f.read()
  fmode='100755' if st.st_mode & 0o111 else '100644'
 else: data=b'';fmode='other'
 if data!=blob or fmode!=gmode: mm.append((path,gmode,fmode,hashlib.sha256(blob).hexdigest(),hashlib.sha256(data).hexdigest()))
p.stdin.close();p.wait()
print('requested_ref='+commit);print('resolved_commit='+resolved);print('resolved_is_40hex='+str(bool(re.fullmatch(r'[0-9a-f]{40}',resolved))))
print('git_entries='+str(len(git)));print('snapshot_entries='+str(len(fs)));print('missing='+str(len(missing)));print('extra='+str(len(extra)));print('content_or_exec_type_mismatch='+str(len(mm)))
if missing[:3]: print('missing_examples='+repr(missing[:3]))
if extra[:3]: print('extra_examples='+repr(extra[:3]))
if mm[:3]: print('mismatch_examples='+repr(mm[:3]))
ok=not missing and not extra and not mm and p.returncode==0
print('SNAPSHOT_EQUALS_ORIGIN_MAIN='+str(ok));sys.exit(0 if ok else 1)

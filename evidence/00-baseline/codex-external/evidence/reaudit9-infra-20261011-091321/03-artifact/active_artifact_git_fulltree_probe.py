#!/usr/bin/env python3
import json, hashlib, subprocess, sys, os, re
repo, manifest_path = sys.argv[1:3]
with open(manifest_path, encoding='utf-8') as f:
    man=json.load(f)
commit=man['source_commit']
raw=subprocess.check_output(['git','-C',repo,'ls-tree','-rz','-r','--full-tree',commit])
entries={}
for rec in raw.split(b'\0'):
    if not rec: continue
    meta,path_b=rec.split(b'\t',1)
    mode,typ,oid=meta.decode('ascii').split()
    path=path_b.decode('utf-8','surrogateescape')
    entries[path]=(mode,typ,oid)
manifest={x['path']:x for x in man['files']}
print('source_commit='+commit)
print('source_commit_is_40hex='+str(bool(re.fullmatch(r'[0-9a-f]{40}',commit))))
print('git_entry_count='+str(len(entries)))
print('manifest_entry_count='+str(len(manifest)))
missing=sorted(set(entries)-set(manifest)); extra=sorted(set(manifest)-set(entries))
print('missing_from_manifest='+str(len(missing)))
print('extra_in_manifest='+str(len(extra)))
mode_map={'100644':('file',0o664),'100755':('file',0o775),'120000':('symlink',0o777)}
mode_mismatch=[]; blob_mismatch=[]
# One persistent batch avoids 2964 subprocesses.
p=subprocess.Popen(['git','-C',repo,'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
assert p.stdin and p.stdout
for path,(mode,typ,oid) in entries.items():
    p.stdin.write((oid+'\n').encode('ascii')); p.stdin.flush()
    hdr=p.stdout.readline().decode('ascii').rstrip('\n').split()
    if len(hdr)!=3 or hdr[1] != 'blob':
        raise RuntimeError(f'bad cat-file response {path!r}: {hdr!r}')
    n=int(hdr[2]); data=p.stdout.read(n); term=p.stdout.read(1)
    if term != b'\n': raise RuntimeError('cat-file framing error')
    got=manifest.get(path)
    if got is None: continue
    expected=mode_map.get(mode)
    if expected is None or (got.get('type'),got.get('mode')) != expected:
        mode_mismatch.append((path,mode,got.get('type'),got.get('mode')))
    digest=hashlib.sha256(data).hexdigest()
    if got.get('size') != len(data) or got.get('sha256') != digest:
        blob_mismatch.append((path,len(data),digest,got.get('size'),got.get('sha256')))
p.stdin.close(); p.wait()
print('mode_type_mismatch='+str(len(mode_mismatch)))
print('blob_size_hash_mismatch='+str(len(blob_mismatch)))
if missing[:3]: print('missing_examples='+repr(missing[:3]))
if extra[:3]: print('extra_examples='+repr(extra[:3]))
if mode_mismatch[:3]: print('mode_mismatch_examples='+repr(mode_mismatch[:3]))
if blob_mismatch[:3]: print('blob_mismatch_examples='+repr(blob_mismatch[:3]))
ok=not(missing or extra or mode_mismatch or blob_mismatch) and p.returncode==0
print('FULL_TREE_MATCH='+str(ok))
sys.exit(0 if ok else 1)

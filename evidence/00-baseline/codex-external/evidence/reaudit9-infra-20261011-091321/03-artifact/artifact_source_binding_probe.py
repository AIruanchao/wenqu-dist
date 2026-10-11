#!/usr/bin/env python3
"""独立负例：只改非方案源码，随后同步 manifest；不触碰被测仓。"""
import io, tarfile, gzip, hashlib, json, os, sys
manifest_path=sys.argv[1]
target='src/engine.py'
replacement=b'VALUE = "TAMPERED_NOT_IN_GIT_COMMIT"\n'
with open(manifest_path,encoding='utf-8') as f: manifest=json.load(f)
tar_path=os.path.join(os.path.dirname(manifest_path),manifest['artifact']['path'])
raw_tar=io.BytesIO()
old=None
with tarfile.open(tar_path,'r:gz') as src, tarfile.open(fileobj=raw_tar,mode='w') as dst:
    for member in src.getmembers():
        data=None
        if member.isfile():
            fh=src.extractfile(member); data=fh.read() if fh else b''
            if member.name==target:
                old=data; data=replacement; member.size=len(data)
        dst.addfile(member,io.BytesIO(data) if data is not None else None)
if old is None: raise SystemExit('target missing')
with open(tar_path,'wb') as out:
    with gzip.GzipFile(filename='',mode='wb',fileobj=out,compresslevel=9,mtime=0) as gz:
        gz.write(raw_tar.getvalue())
def hfile(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()
manifest['artifact']['sha256']=hfile(tar_path)
manifest['artifact']['size']=os.path.getsize(tar_path)
for rec in manifest['files']:
    if rec.get('path')==target:
        rec['size']=len(replacement)
        rec['sha256']=hashlib.sha256(replacement).hexdigest()
        break
else: raise SystemExit('manifest target missing')
with open(manifest_path,'w',encoding='utf-8') as f:
    json.dump(manifest,f,ensure_ascii=False,indent=2,sort_keys=True); f.write('\n')
print(json.dumps({
 'target':target,
 'old_bytes':old.decode('utf-8','replace'),
 'new_bytes':replacement.decode(),
 'new_tar_sha256':manifest['artifact']['sha256'],
 'new_manifest_file_sha256':hashlib.sha256(replacement).hexdigest(),
 'source_commit_still':manifest['source_commit'],
 'artifact_source_claim_still':manifest['artifact']['source'],
},ensure_ascii=False,indent=2))

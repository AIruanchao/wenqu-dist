#!/usr/bin/env python3
import json, subprocess, sys, tempfile
from pathlib import Path
repo=Path(sys.argv[1]).resolve(); tool=repo/'tools/ac_traceability.py'; source=repo/'evidence/00-baseline/codex-external/方案.md'
text=source.read_text(encoding='utf-8')
# 新用例：不复用仓内测试输入；分别打击目录语义、映射语义、目录外字节与缺件。
sec20=text.index('# 20.')
sec25=text.index('# 25.')
sec26=text.index('# 26.')
variants={}
# 只在 §20 中把一个既有 ID 替成不存在 ID。
prefix,chunk,suffix=text[:sec20],text[sec20:sec25],text[sec25:]
assert 'GATE-12' in chunk
variants['section20_id_substitution']=prefix+chunk.replace('GATE-12','GATE-92',1)+suffix
# 只在 §25.1 范围改变需求 ID，目录本体保持不动。
prefix,chunk,suffix=text[:sec25],text[sec25:sec26],text[sec26:]
assert 'REQ-EVID-001' in chunk
variants['section25_mapping_substitution']=prefix+chunk.replace('REQ-EVID-001','REQ-EVID-901',1)+suffix
# 在 §20/§25 外、EOF 后追加零宽字符；语义 parser 可能看不见，整文件哈希必须拦。
variants['outside_sections_zero_width_byte']=text+'\u200b'

def invoke(name,path,out):
 p=subprocess.run([sys.executable,str(tool),'--check','--plan',str(path),'--json',str(out)],cwd=repo,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 doc=json.loads(out.read_text(encoding='utf-8')) if out.exists() else {}
 meta=doc.get('meta',{}); pc=meta.get('plan_cross_check') or {}
 return {'case':name,'rc':p.returncode,'catalog_integrity':meta.get('catalog_integrity'),'plan_sha256_match':meta.get('plan_sha256_match'),'plan_check_ok':pc.get('ok'),'problem_count':len(meta.get('catalog_problems') or []),'stdout_tail':p.stdout[-700:]}
with tempfile.TemporaryDirectory(prefix='reaudit9-plan-probe-') as td:
 d=Path(td); rows=[]
 rows.append(invoke('control',source,d/'control.json'))
 rows.append(invoke('missing_plan',d/'absent.md',d/'missing.json'))
 for name,body in variants.items():
  p=d/(name+'.md'); p.write_text(body,encoding='utf-8'); rows.append(invoke(name,p,d/(name+'.json')))
print(json.dumps(rows,ensure_ascii=False,indent=2))
assert rows[0]['rc']==0 and rows[0]['catalog_integrity']=='OK'
for row in rows[1:]: assert row['rc']!=0 and row['catalog_integrity']=='FAIL',row
print('RESULT: PASS — baseline green; missing/§20/§25.1/outside-byte all red')

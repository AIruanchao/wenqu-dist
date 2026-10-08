cp -a /private/tmp/wenqu-reaudit7-20261008-204822 '/tmp/wq7b-schema-mutation-15100-71815'; git -C '/tmp/wq7b-schema-mutation-15100-71815' reset --hard HEAD >/dev/null; python3 - <<'PY'
import json
from pathlib import Path
p=Path('/tmp/wq7b-schema-mutation-15100-71815/system/schemas/approval-v2.schema.json')
d=json.loads(p.read_text())
old=d['properties']['nonce']['minLength']
d['properties']['nonce']['minLength']=0
p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
print('nonce.minLength',old,'->',d['properties']['nonce']['minLength'])
PY
git -C '/tmp/wq7b-schema-mutation-15100-71815' diff -- system/schemas/approval-v2.schema.json

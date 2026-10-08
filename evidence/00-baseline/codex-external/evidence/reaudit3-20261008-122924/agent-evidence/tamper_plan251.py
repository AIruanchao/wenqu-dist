from pathlib import Path
p=Path(__import__('sys').argv[1]); s=p.read_text(); a=s.index('## 25.1'); b=s.index('# 26.'); sec=s[a:b]
assert 'REQ-EVID-001' in sec
sec=sec.replace('REQ-EVID-001','REQ-EVID-TAMPER',1)
p.write_text(s[:a]+sec+s[b:])

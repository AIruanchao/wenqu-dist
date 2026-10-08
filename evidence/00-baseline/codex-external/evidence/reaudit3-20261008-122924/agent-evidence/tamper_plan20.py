from pathlib import Path
p=Path(__import__('sys').argv[1]); s=p.read_text(); a=s.index('# 20.'); b=s.index('# 21.'); sec=s[a:b]
assert 'GATE-01' in sec
sec=sec.replace('GATE-01','GATX-01',1)
p.write_text(s[:a]+sec+s[b:])

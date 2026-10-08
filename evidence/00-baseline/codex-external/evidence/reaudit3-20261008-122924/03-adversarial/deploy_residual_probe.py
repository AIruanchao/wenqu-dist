import os, sys, tempfile, pathlib, stat, json
sys.path.insert(0, '/Users/maccc/Documents/wenqu-dist/system')
from wenqu_core.deploy_framework import DeployManager, DeployError
with tempfile.TemporaryDirectory(prefix='reaudit3-deploy-') as td:
    root=pathlib.Path(td); src1=root/'src1'; src2=root/'src2'; rels=root/'releases'; current=root/'current'
    src1.mkdir(); src2.mkdir()
    # 真实入口常见形态：无扩展名、shebang、源执行位 0755
    p=src1/'wenqu'; p.write_text('#!/bin/sh\necho v1\n'); p.chmod(0o755)
    q=src2/'wenqu'; q.write_text('#!/bin/sh\necho v2\n'); q.chmod(0o755)
    dm=DeployManager(str(rels),str(current), install_self_check=lambda _: True)
    r1=dm.deploy(str(src1))
    mode=stat.S_IMODE((pathlib.Path(r1['release_dir'])/'wenqu').stat().st_mode)
    print('NO_EXTENSION_EXEC_MODE', oct(mode), 'EXECUTABLE', bool(mode & 0o111))
    print('MANIFEST_KEYS', sorted(json.load(open(pathlib.Path(r1['release_dir'])/'manifest.json')).keys()))
    # 第二版失败，current 是相对链接；正确行为应回旧版，但实现用 cwd 解析 previous
    dm2=DeployManager(str(rels),str(current), install_self_check=lambda _: False)
    try:
        dm2.deploy(str(src2))
    except DeployError as e:
        print('DEPLOY_ERROR', str(e))
    print('CURRENT_LINK', os.readlink(current) if current.is_symlink() else None)
    print('OLD_LINK_VALUE', r1['switch']['link_value'])
    print('ROLLED_BACK_TO_OLD', current.is_symlink() and os.readlink(current)==r1['switch']['link_value'])

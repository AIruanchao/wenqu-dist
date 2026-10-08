#!/usr/bin/env python3
import json,os,stat,sys,tempfile,time
from pathlib import Path
ROOT=Path('/Users/maccc/Documents/wenqu-dist'); sys.path.insert(0,str(ROOT/'system'))
from wenqu_core.deploy_framework import DeployManager,DeployError
res={}
with tempfile.TemporaryDirectory(prefix='reaudit3-p07-') as td:
 base=Path(td); releases=base/'releases'; current=base/'current'
 src=base/'src'; src.mkdir()
 sh=src/'run.sh'; sh.write_text('#!/bin/sh\nexit 0\n'); sh.chmod(0o755)
 ext=src/'runner'; ext.write_text('#!/bin/sh\nexit 0\n'); ext.chmod(0o755)
 plainpy=src/'notexec.py'; plainpy.write_text('#!/usr/bin/env python3\nprint(1)\n'); plainpy.chmod(0o644)
 dm=DeployManager(str(releases),str(current),lambda _:True)
 b=dm.build(str(src)); rd=Path(b['release_dir'])
 modes={p.name:oct(stat.S_IMODE(p.stat().st_mode)) for p in [rd/'run.sh',rd/'runner',rd/'notexec.py']}
 manifest=json.loads((rd/'manifest.json').read_text())
 # mode drift is invisible
 (rd/'run.sh').chmod(0o444)
 verify_after_mode_change=dm.verify(str(rd),strict=False)
 res['mode_probe']={'source_modes':{'run.sh':'0o755','runner':'0o755','notexec.py':'0o644'},'release_modes':modes,
   'manifest_file_entry_keys':sorted(manifest['files'][0]),'verify_after_chmod_0555_to_0444':verify_after_mode_change}
 # first failed deploy
 base2=base/'first'; srcf=base2/'src'; srcf.mkdir(parents=True); (srcf/'x.sh').write_text('#!/bin/sh\nexit 0\n'); (srcf/'x.sh').chmod(0o755)
 cur2=base2/'current'; dm2=DeployManager(str(base2/'releases'),str(cur2),lambda _:False)
 try: dm2.deploy(str(srcf)); err=None
 except DeployError as e: err=str(e)
 res['first_failure']={'error':err,'current_lexists':os.path.lexists(cur2),'current_islink':cur2.is_symlink()}
 # existing release then failed update: relative previous target must roll back
 base3=base/'upgrade'; s1=base3/'s1'; s2=base3/'s2'; s1.mkdir(parents=True); s2.mkdir()
 (s1/'v.sh').write_text('#!/bin/sh\necho 1\n'); (s2/'v.sh').write_text('#!/bin/sh\necho 2\n')
 (s1/'v.sh').chmod(0o755); (s2/'v.sh').chmod(0o755)
 cur3=base3/'current'; rel3=base3/'releases'
 ok=DeployManager(str(rel3),str(cur3),lambda _:True).deploy(str(s1)); before=os.readlink(cur3); before_real=os.path.realpath(cur3)
 try: DeployManager(str(rel3),str(cur3),lambda _:False).deploy(str(s2)); up_err=None
 except DeployError as e: up_err=str(e)
 after=os.readlink(cur3); after_real=os.path.realpath(cur3)
 res['upgrade_failure']={'before_link':before,'before_real':before_real,'error':up_err,'after_link':after,'after_real':after_real,
   'rolled_back_to_before':before_real==after_real,'failed_release_remained_active':before_real!=after_real}
 expected={'version','source_commit','quality_policy_commit','build_id','built_at','builder','schema_version','policy_hash','files','artifact_sha256','python/node/runtime identity','dependency lock/SBOM hash','min_schema_version','max_schema_version','attestation/signature'}
 actual=set(manifest)
 res['manifest']={'actual_top_keys':sorted(actual),'missing_plan_fields':sorted(expected-actual)}
 install=(ROOT/'system/install.sh').read_text()
 res['installer']={'contains_cp_R': 'cp -R' in install,'contains_doctor_or_true': 'doctor 2>&1 || true' in install,'imports_DeployManager': 'DeployManager' in install}
res['assessment']={
 'claimed_sh_exec_fix_passes':res['mode_probe']['release_modes']['run.sh']=='0o555',
 'claimed_first_failure_link_cleanup_passes':res['first_failure']['current_lexists'] is False,
 'residual_extensionless_exec_loses_bit':res['mode_probe']['release_modes']['runner']=='0o444',
 'residual_nonexec_shebang_py_gains_bit':res['mode_probe']['release_modes']['notexec.py']=='0o555',
 'residual_mode_not_verified':res['mode_probe']['verify_after_chmod_0555_to_0444']['ok'] is True,
 'residual_upgrade_failure_not_rolled_back':res['upgrade_failure']['failed_release_remained_active'],
 'residual_manifest_incomplete':bool(res['manifest']['missing_plan_fields']),
 'residual_installer_bypasses_framework':res['installer']['contains_cp_R'] and res['installer']['contains_doctor_or_true'] and not res['installer']['imports_DeployManager'],
}
print(json.dumps(res,ensure_ascii=False,indent=2))
assert all(res['assessment'].values())

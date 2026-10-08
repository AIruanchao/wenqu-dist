import sys
sys.path.insert(0, '/private/tmp/wenqu-reaudit7-20261008-204822/system')
from wenqu_core.deploy_framework import DeployManager
mgr = DeployManager('/private/tmp/codex-test/evidence/reaudit7-20261008-204822/root-regression/pytest-tmp/pytest-of-maccc/pytest-0/test_REL_02_sigkill_mid_deploy0/rel2-control-no-kill/releases', '/private/tmp/codex-test/evidence/reaudit7-20261008-204822/root-regression/pytest-tmp/pytest-of-maccc/pytest-0/test_REL_02_sigkill_mid_deploy0/rel2-control-no-kill/current')
result = mgr.deploy('/private/tmp/codex-test/evidence/reaudit7-20261008-204822/root-regression/pytest-tmp/pytest-of-maccc/pytest-0/test_REL_02_sigkill_mid_deploy0/src-rel2-v2')
sys.stdout.write(result["release_id"] + "\n")

import sys, time
sys.path.insert(0, '/private/tmp/wenqu-reaudit7-20261008-204822/system')
from wenqu_core.deploy_framework import DeployLease
lease = DeployLease.acquire('/private/tmp/codex-test/evidence/reaudit7-20261008-204822/root-regression/pytest-tmp/pytest-of-maccc/pytest-0/test_DEP_01_concurrent_deploye0/dep1-crash/releases/.deploy-lease')
print("HELD", flush=True)
time.sleep(30)

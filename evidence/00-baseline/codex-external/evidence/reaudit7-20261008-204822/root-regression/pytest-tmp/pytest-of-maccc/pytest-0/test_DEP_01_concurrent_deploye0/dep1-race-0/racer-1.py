import os, sys, time
sys.path.insert(0, '/private/tmp/wenqu-reaudit7-20261008-204822/system')
from wenqu_core.deploy_framework import DeployManager, LeaseError
go_path = '/private/tmp/codex-test/evidence/reaudit7-20261008-204822/root-regression/pytest-tmp/pytest-of-maccc/pytest-0/test_DEP_01_concurrent_deploye0/dep1-race-0/go'
while not os.path.exists(go_path):
    time.sleep(0.001)
try:
    mgr = DeployManager('/private/tmp/codex-test/evidence/reaudit7-20261008-204822/root-regression/pytest-tmp/pytest-of-maccc/pytest-0/test_DEP_01_concurrent_deploye0/dep1-race-0/releases', '/private/tmp/codex-test/evidence/reaudit7-20261008-204822/root-regression/pytest-tmp/pytest-of-maccc/pytest-0/test_DEP_01_concurrent_deploye0/dep1-race-0/current')
    result = mgr.deploy('/private/tmp/codex-test/evidence/reaudit7-20261008-204822/root-regression/pytest-tmp/pytest-of-maccc/pytest-0/test_DEP_01_concurrent_deploye0/dep1-big-0')
    print("WIN:" + result["release_id"], flush=True)
except LeaseError as exc:
    print("LEASE-REFUSED", flush=True)
    sys.exit(3)

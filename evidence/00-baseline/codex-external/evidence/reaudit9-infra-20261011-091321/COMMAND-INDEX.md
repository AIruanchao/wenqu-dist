# 第九轮基建域命令—退出码—输出索引

冻结对象：`origin/main@7eeb8a13107e8b52771f5b8784af8266ed0551b9`。以下仅列摘要；对应文件保留完整 stdout/stderr、时间及退出码。

| ID | 命令（敏感路径已脱敏） | rc | 关键输出/系统判定 | 原始证据 |
|---|---|---:|---|---|
| C01 | `shasum -a 256 evidence/00-baseline/codex-external/方案.md` | 0 | `96b8646...c32306`，与输入冻结值相等 | `00-input/input-hashes.txt` |
| C02 | `git archive --format=tar origin/main \| tee <sha> \| tar -x -C <pristine>` | 0 | HEAD `7eeb8a1...51b9`；2964/2964；writable=0 | `00-input/pristine-reference.txt` |
| C03 | `PYTHONPATH=system python3 system/tests/test_events_unified.py` | 0 | 8 PASS/0 FAIL（正向回归） | `02-migration/17-existing-legacy-regression.txt` |
| C04 | `python3 independent_legacy_permission_probe.py` | 0 | probe 自证通过，但 `system_verdict=FAIL`；同权 writer 可撤 trigger、伪造 digest 后导入恶意行 | `02-migration/20-independent-rowversion-writeauthority-probe.txt` |
| C05 | `release_attest.py verify <live-current> --release-roots <external> --repo <git-objects>` | 0 | roots/方案/签名/SBOM/files/build identity 全 PASS，2964/2964 | `03-artifact/15-live-current-artifact.txt`、`16-live-current-verify-report.json` |
| C06 | `python3 active_artifact_git_fulltree_probe.py <repo> <manifest>` | 0 | 现役 artifact↔声明 commit 全树 2964/2964；`FULL_TREE_MATCH=True` | `03-artifact/18-live-artifact-vs-git-fulltree.txt` |
| C07 | `python3 artifact_source_binding_probe.py`（合成 key/roots；改非方案源码并同步 manifest/SBOM/签名） | 0 | Git blob≠tar/manifest，但 verifier `VERIFY OK`、rc0；系统 FAIL | `03-artifact/10-source-binding-baseline.log`、`12-source-binding-tamper.log` |
| C08 | `urllib http://127.0.0.1:7789/api/v1/{health,components}` + current realpath | 0 | health=`BLOCKED`、eligible=false、target=40 个零；current release `bb38...` 40hex | `04-runtime/17-live-api-focused-root.txt` |
| C09 | `launchctl print gui/$UID/com.wenqu.scheduler` + SQLite `mode=ro` 查询 | 0 | 300s、launchd last exit0；子作业 rc3、BLOCKED/NOT_EVALUATED、不刷新 success、告警已送 | `04-runtime/02-launchd-scheduler.txt`、`05-scheduler-db-readonly.txt` |
| C10 | 读取最新 sample/window manifest | 0 | `repo.identity=bb38...` 40hex；最后样本 07:34；07:36 窗口 invalidated (`sfinal=null`) | `04-runtime/08-latest-observation-root-check.txt`、`15-window-manifest-live-root.txt` |
| C11 | `gh run list/view ...`、`gh api .../check-runs`、`gh api .../branches/main/protection` | 0 | main/HEAD/run/job/保护规则实时回读 | `05-ci/01-live-github-ci-and-rules.txt`、`@@CI_FINAL@@` |
| C12 | `bash tools/merge-ci-evidence.sh ff050bbb...`（单父 main push） | 0 | `is_merge_commit=false`，却 `verdict=PASS`；负例预期非零，FAIL_OPEN | `05-ci/05-merge-ci-nonmerge-negative.txt` |
| C13 | `python3 system/tests/p1f_mutation_gate.py ...` | 0 | 冻结集 18/18 KILLED，表面 100% | `06-assertion/06-mutation-gate-baseline.txt` |
| C14 | `python3 08-independent-mutation-granularity-probe.py` | 0 | 组合 mutant KILLED；第二作用点单变异 SURVIVED；系统 metric FAIL | `06-assertion/08-independent-mutation-granularity-probe.txt` |
| C15 | `python3 plan_change_probe.py <fresh-archive>` | 0（wrapper） | control rc0；缺方案/§20/§25.1/目录外字节各 rc2 | `07-regular/03-plan-change-probes.txt` |
| C16 | 删除 `wenqu_pipeline.py` 后 `bash tests/acceptance.sh` | 1 | 63 PASS/8 FAIL | `07-regular/04-anchor-module-removal.txt` |
| C17 | 删除 `approval-v2.schema.json` 后 `bash tests/acceptance.sh` | 1 | 69 PASS/3 FAIL | `07-regular/05-anchor-schema-removal.txt` |
| C18 | 删除 `tools/ac_traceability.py` 后 `bash tests/acceptance.sh` | 1 | 69 PASS/3 FAIL | `07-regular/06-anchor-tool-removal.txt` |
| C19 | 删除 `test_ac_auth_cond.py` 后 `bash tests/acceptance.sh` | 1 | 69 PASS/2 FAIL；coverage/mutation/AST 均红 | `07-regular/07-critical-test-removal.txt` |
| C20 | `python3 tools/evidence_validator.py --root <fresh>` | 0 | active=3，legacy/non-scoring=23；严格 validator PASS | `07-regular/02-evidence-index-recalc.txt` |
| C21 | `python3 independent_index_recalc.py <fresh>` | 0 | 26/26 路径、普通文件、SHA；active 字段/TTL 合法 | `07-regular/02-evidence-index-recalc.txt` |
| C22 | `release_attest.py verify {cf6d10e,b44b087,2bd59ab} --plan-pin <frozen>` | 0/0/0 | 三历史四件套自洽；换现役 roots 后 rc1/1/1（不在 allowlist） | `07-regular/01-dist-fourtuple-verify.txt` |
| C23 | `release_attest.py build --commit b44b087 ...`; `cmp rebuilt stored`; 路径集对账 | 0/0/0 | tar byte-for-byte 同 SHA；2942/2942 路径全等 | `07-regular/08-dist-source-tree-rebuild.txt` |
| C24 | 纯 archive：`bash tests/acceptance.sh` | 1 | 71 PASS/1 FAIL；仅 release-attest 因无 `.git` | `08-tests/acceptance.txt` |
| C25 | 精确 Git 副本：`bash tests/acceptance.sh` | 0 | 72 PASS/0 FAIL，但结束 tracked evidence 为 `M` | `08-tests/gitbound-acceptance-pytest-dual.txt` |
| C26 | 精确 Git 副本：`python3 -m pytest cli/test_wenqu.py -q` | 0 | 20 nodeids | `07-regular/11-pytest-dual-gitbound.txt` |
| C27 | 精确 Git 副本：`python3 -m pytest -q` | 0 | 323 nodeids；2 skip 标记；其余通过 | `07-regular/11-pytest-dual-gitbound.txt` |
| C28 | 干净精确 Git 副本：`python3 system/tests/test_ac_ops_families.py`，前后 `git status`/SHA 对账 | 0 | 18/18 PASS，但 tracked JSON SHA 改变并留下 `M`；`system_verdict=FAIL` | `08-tests/acceptance-tracked-evidence-pollution.txt` |
| C29 | `python3 09-real-doc-drift-nonblocking-probe.py <pristine>` + 真实 DOC-02 运行交叉核对 | 0 | README 声明 66/64、脚本实算 74；真实 `blocked=true` 只打印，DOC-02 仍 PASS；系统 FAIL | `06-assertion/09-real-doc-drift-nonblocking-probe.txt`、`08-tests/acceptance-tracked-evidence-pollution.txt` |

说明：C04/C07/C12/C14/C28/C29 的命令 rc0 表示“对抗探针成功复现预设反例”，不表示被测系统通过；系统判定以最后一列和证据中的 `system_verdict` 为准。

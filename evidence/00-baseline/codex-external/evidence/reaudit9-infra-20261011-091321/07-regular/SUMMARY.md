# 第九轮基建域——常规核验子结论

## 冻结边界

- 产品源码/测试/制品读取均以 `origin/main@7eeb8a13107e8b52771f5b8784af8266ed0551b9` 的新 `git archive` 或精确带 `.git` clone 为准。
- 共享 snapshot 并行产生 `.pytest_cache` 与 1 个 tracked evidence blob 漂移；共享仓另有 3 个 dist tar 删除。均记录为环境事实，不计产品新发现，也未作为后续判定输入。
- 纯 `git archive` 没有 `.git`，`test_release_attest.py` 会因“不是 git 仓库”得到 0 PASS/11 FAIL、rc1；因此 baseline acceptance/pytest 和三移除完整门都在加回精确 Git 元数据的独立副本执行。这是验收载体边界，不是产品缺陷。

## 结果

| 核验 | 实跑结果 | 判定 |
|---|---|---|
| 三移除锚点 | 删除 `wenqu_pipeline.py` → acceptance `63/8 rc1`；删除 `approval-v2.schema.json` → `69/3 rc1`；删除 `tools/ac_traceability.py` → `69/3 rc1` | PASS，均必红 |
| 关键测试删件 | 删除 `test_ac_auth_cond.py` → coverage、mutation、AST 同时红；acceptance `69/2 rc1` | PASS |
| 方案三类变更 | §20 ID 替换 rc2、§25.1 映射替换 rc2、目录外零宽字节 rc2；缺方案额外 rc2；control rc0 | PASS |
| 证据索引实算 | 官方 validator rc0；独立逐条复算 active=3、legacy=23，26/26 普通非空文件且 hash 相等，active 40hex/argv/rc/TTL 合法 | PASS（仅证明所列 3 个 active，不能外推覆盖全部本轮事项） |
| dist checksum/四件套 | origin/main 中 checksum 清单 rc0；3 个历史四件套在公开冻结 plan pin 下 artifact/files/plan 三等值/source commit/signature/SBOM 全 rc0 | PASS（历史工件完整性） |
| 外部 roots | 同 3 个仓内历史制品被现役 roots 全部 rc1 拒绝，因为 commit 不在 current allowlist | PASS（fail-closed）；不等于本轮 HEAD 有可发布制品 |
| 源码树绑定/可重建 | `b44b087` 从 Git 对象重建 tar 与仓内 tar SHA256 完全相等、`cmp rc0`；2942/2942 path 集合完全相等 | PASS |
| pytest 双口径 | 精确 Git clone：`python3 -m pytest cli/test_wenqu.py -q` rc0（20 nodeids）；仓根 `python3 -m pytest -q` rc0（323 nodeids，进度中 2 skip） | PASS |
| baseline acceptance | 根验收精确 Git clone记录为 `PASS=72 FAIL=0`、rc0（跨目录证据 `08-tests/gitbound-acceptance-pytest-dual.txt`） | PASS |

## 缺口/边界（不新增计数）

1. 仓内三组 dist 是历史提交；现役受保护 roots 正确拒绝它们。现役外部 `current` 制品由制品域主证据另行核验。
2. active evidence 严格条目只有 3 项，其余 23 项明确为 legacy/non-scoring；validator 的通过不代表本轮所有结论均已进入 active 索引。
3. 仓根 pytest rc0，但输出有 `PytestReturnNotNoneWarning`；当前不是失败，后续 pytest 兼容性应治理。

## 主要证据

- `09-fresh-archive-provenance.txt`、`12-shared-snapshot-pollution-boundary.txt`
- `04-anchor-module-removal.txt`～`07-critical-test-removal.txt`、`13-anchor-targeted-confirmation.txt`
- `03-plan-change-probes.txt`
- `02-evidence-index-recalc.txt`
- `00-release-root-inventory.txt`、`01-dist-fourtuple-verify.txt`、`08-dist-source-tree-rebuild.txt`
- `10-pure-archive-release-attest-boundary.txt`、`11-pytest-dual-gitbound.txt`

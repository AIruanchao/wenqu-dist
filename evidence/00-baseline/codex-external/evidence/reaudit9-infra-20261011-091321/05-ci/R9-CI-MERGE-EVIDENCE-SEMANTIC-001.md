# R9-CI-MERGE-EVIDENCE-SEMANTIC-001（P1，新发现）

## 结论

`tools/merge-ci-evidence.sh` 会计算并把 `is_merge_commit` 写入 JSON，但该布尔量没有进入 verdict 条件。因此，一个只有单亲的历史 `main` direct-push，只要存在同名双平台成功 job，就会被脚本以 rc=0 判成“merge CI evidence: PASS”。这不能证明“合并提交精确主线双平台记录”。

## 独立复现

- 工具源码：`origin/main@7eeb8a13107e8b52771f5b8784af8266ed0551b9` 的 `git archive` blob。
- 负例提交：`ff050bbb9c95c04ecb975900f5440f9bfcd1a447`。
- 实算父提交数：1；JSON `is_merge_commit=false`。
- 命令：`bash FRESH/tools/merge-ci-evidence.sh ff050... --repo <只读对象库> --branch main --slug AIruanchao/wenqu-dist --out-dir <证据目录>`。
- 预期：非 merge 必须非零拒绝。
- 实际：rc=0，`verdict=PASS`，选择 run `37727549548`。

完整命令/输出见 `05-merge-ci-nonmerge-negative.txt`，机器结果见 `nonmerge-probe-fresh/merge-ci-ff050bb.json`。

## 影响与去重

这是本轮新增的证据器语义假阳性；不是把八轮已知的“精确 merge CI 尚缺”重复计数。它会让修复件为错误的提交类别签发 PASS，影响 W3 的精确合流证据可信度。分支保护仍缺方案四个稳定 context、CODEOWNERS/ruleset/merge_group 属八轮已知残余，本发现不重复计入那些缺口。

## 建议

verdict 前强制目标提交满足冻结的 merge 形态（至少双亲，并按策略校验 base/head/PR）；同时绑定当前受保护分支、workflow commit/ref、可信 App ID 与实时 required contexts。加入单亲 direct-push、旧 workflow、同名 job 伪造/过期 run 的负例。

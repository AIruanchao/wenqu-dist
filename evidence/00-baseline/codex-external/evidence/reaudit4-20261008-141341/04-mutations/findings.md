# 第四轮复审：移除锚点与 Schema 变异核验

## 边界

- 被验正源：`/Users/maccc/Documents/wenqu-dist`，`HEAD=e4aba84c1dabe1342ea234321eea3d300bea24a5`。
- 正源验前、验后 `git status --porcelain=v1 --untracked-files=all` 均为空，`git diff --exit-code=0`。
- 所有删件、篡改仅发生在 `/tmp`（macOS 实路径显示为 `/private/tmp`）独立 clone；未修改产物仓。

## 结论

| 核验 | 独立操作与结果 | 判定 |
|---|---|---|
| 模块移除锚点 | 删除 `system/wenqu_core/wenqu_pipeline.py`；`test_core_wiring.py` rc=1（7/1），`test_wenqu_pipeline.py` rc=1，完整 acceptance rc=1（58/4） | PASS，删模块必红 |
| Schema 移除锚点 | 删除 `system/schemas/approval-v2.schema.json`；core wiring rc=1（7/1），pipeline rc=1（9/1），acceptance rc=1（60/2） | PASS，删 Schema 必红 |
| 工具移除锚点 | 删除 `tools/ac_traceability.py`；直接调用 rc=2，acceptance rc=1（61/1），P1c 明确失败 | PASS，删工具必红 |
| Schema 篡改交叉验证 | 将 `nonce.minLength` 从 16 放宽为 0；独立一字节 nonce 交叉探针检出 Schema/Broker 分歧 rc=7；pipeline rc=1（9/1）；acceptance rc=1（61/1） | PASS，语义放宽被交叉验证及总门检出 |

## 关键证据

- 模块：`01-module-remove.log`、`02-module-core-wiring.log`、`03-module-pipeline.log`、`04-module-acceptance.log`。
- Schema 删除：`05-schema-remove.log`、`06-schema-core-wiring.log`、`07-schema-pipeline.log`、`08-schema-acceptance.log`。
- 工具删除：`09-tool-remove.log`、`10-tool-direct.log`、`11-tool-acceptance.log`。
- Schema 语义变异：`12-schema-tamper.log`、`13-schema-independent-crosscheck.log`、`14-schema-pipeline-crosscheck.log`、`15-schema-tamper-acceptance.log`、`independent-schema-crosscheck.py`。
- 正源保护：`00-source-identity.log`、`99-source-postcondition.log`。

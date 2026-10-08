# 第四轮复审：acceptance 全量与 P1c 只读性

## 结论

- 在 `/tmp` 独立 clone、`HEAD=e4aba84c1dabe1342ea234321eea3d300bea24a5` 运行 `bash tests/acceptance.sh`：**62 PASS / 0 FAIL，ALL GREEN，rc=0**。
- 运行前后：
  - `git status --porcelain=v1 --untracked-files=all` 均为空；
  - `git diff --exit-code=0`、`git diff --cached --exit-code=0`；
  - `evidence/traceability-matrix.json` SHA256 前后同为 `0081439c8d25dd375079795ba3e2c3359b4d05a234d0ebf3ab88812b870dcd20`；
  - HEAD 未变化。
- 单独复跑 P1c 等价命令 `python3 tools/ac_traceability.py --check --json <仓外临时文件>`：rc=0，仓外 JSON 非空；前后工作树为空、受控 matrix 哈希不变、`git diff --exit-code=0`。
- 因而第三轮指出的 P1c 改写受控 matrix 副作用已关闭；P1c 当前为只读源仓、临时输出落仓外。

## 边界

本结论只证明当前未篡改基线的 62 项 acceptance 与只读性。`05-trace` 的独立语义变异另证：保持 §20 ID 不变仅改注入文本时，P1c/acceptance 仍会假绿；不能用本次基线 62/62 覆盖该缺口。

## 证据

- `00-isolated-path.txt`、`01-clone.log`、`02-before.log`。
- `03-acceptance-full.log`。
- `04-after-readonly.log`。
- `05-p1c-readonly.log`、`traceability-live.json`。

# wenqu-dist 真实第三仓首跑报告（毕业考，2026-10-03）

对象：~/Documents/market-monitor-main（生产监控组件仓，407 个 py/sh 文件）——发行版 v1.0.18 的首个真实仓实弹。

## 三步协议（全通）
1. `init --home <外置>`：407 文件范围冻结，scope_hash=d4e5816c3a552e64 ✓
2. 探测器三站：**trap-double 真命中**（deploy/hot-deploy.sh）；guard/cred 正确 PASS（该仓无对应模式=真阴性）✓
3. `verify`：正确红（OPEN 1/0）✓
4. 零写入核验：生产仓无 .wenqu、git 状态未变 ✓

## 命中分析（真阳性）
`deploy/hot-deploy.sh` L110（if 分支内，4 格缩进）与 L137（顶格）各设 `trap 'kill $PROBE_PID' EXIT`——**bash trap EXIT 是脚本级全局，分支内设置会被后写覆盖**；作者意图为分支级清理（bash 语义做不到）。与 ccc 仓 restore-drill.sh 双 trap（BSF-39 前身）同族模式。实际后果有限（两处清理动作等价、PROBE_PID 复用），但模式危险：后续维护若在分支 trap 里放非等价清理即静默失效。定性=MEDIUM 模式命中（处置权归仓主，按发行版红线不直改）。

## 结论
- 发行版在真实生产仓：协议全通+真阳性+真阴性双验证——**毕业考通过**。
- 首跑未击中声明五项盲区（BOM/CR-only 等形态未出现）；命中属已知能力确认而非盲区击中——**条件放行声明维持有效，不触发重开**。
- 战训评估：「分支内 trap 意图分支级清理」为 trap-double 已覆盖模式的语义变体，独立探测器固化价值低——记录于本报告即可。

# wenqu-dist 问渠发行版 v1.0（2026-10-02）

问渠=系统性缺陷工程轨道（八站一环一本账）。本包=仓中立发行版：任何新项目/存量仓拿来即用。

## 包内三件

```
wenqu-dist/
├── cli/wenqu            # CLI 执行器 v0.3.0-fork24-maccc（stdlib-only 单文件；fork1-24 修复史见 CHANGELOG）
├── cli/test_wenqu.py    # CLI 契约测试套件（pytest）
├── cli/README.md        # CLI 用法（上游版）
├── probes/stations.json # 初始三域探测器（trap-double/guard-comment-swallow/cred-cli-expose）
├── docs/问渠轨道规范-发行版-v2.0.md  # ★先读这个——轨道规范（站/档/账本/收敛/探测器规约）
└── tests/acceptance.sh   # 回归测试件（65 项验收面，含变异闭环+P1~P1f 六锚点；包内任何变更后跑它，全绿再发；项数随加固演进以脚本 RESULT 为准）
```

## 新仓接入（三步）

```bash
# 1. 立轨：范围冻结+建账本
python3 cli/wenqu init --path <你的仓>
#    （账本外置到仓外：--home 是全局参数须放在子命令前——
#     python3 cli/wenqu --home <目录> init --path <你的仓>）

# 2. 挂探测器（可选但推荐；此后每轮机械面免费）
cp probes/stations.json <你的仓>/.wenqu/stations.json
#    （用 --home 外置时拷到 <home>/stations.json，不是仓内 .wenqu/）
python3 cli/wenqu run trap-double --path <你的仓>   # exit 1=有发现已自动落账
#    （--home 同样前置：python3 cli/wenqu --home <目录> run trap-double --path <你的仓>）

# 3. 收口门（CI 可挂：有 OPEN 即红）
python3 cli/wenqu verify --path <你的仓> --allow-open 0
```

配套 `verify --convergence N`（递归清零机器门）/`sweep`（站位 PASS 自动关账）/`charter`（反方评审发射）/`repair`（账本自愈）——详见 cli/README.md。

## 与 agent 会话的配合（轨道不是大脑）

规范（docs/）给 agent 读：定档判断、异源对抗审、HIGH 亲验、跨仓委托 SOP、收敛声明都由会话侧执行；CLI/探测器提供机械件与账本纪律。把 docs/ 规范加入项目的 agent 指令（如 AGENTS.md 引用）即可让任意 agent 会话按问渠轨道作业。

## 血统与上游

- 方法论正源：maccc `~/.agents/skills/bug-scan-pipeline/SKILL.md` v1.8（ERP 主仓重装管线）。
- CLI 正源：ccc 治理线 `办公系统/wenqu-cli/` v0.3.0；版本史见 CHANGELOG.md。本包 fork 均带源码注释标记：BSF-37（argparse choices 锁死插座）+ BSF-38（convergence 空转）另加固 run 超时防线与 --round 轮次落账；修法已回报 serve-v4 待上游采纳。
- 实测履历：F4 跨仓扫描（37 发现，两轮异源+HIGH 全亲验）+ fork 集成测试四绿 + 三探测器实弹全中真缺陷。

## CI（平台证据第三环境）

`.github/workflows/acceptance.yml`（macOS+Ubuntu 双矩阵×release-check+64 项+pytest+selftest）已备——推送到 GitHub 即生效，永久闭掉条件放行声明的平台证据盲区（#5）；main 已开分支保护（双平台 required+strict+enforce_admins），合流走 PR 正门。

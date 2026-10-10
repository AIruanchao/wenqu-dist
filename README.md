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
└── tests/acceptance.sh   # 回归测试件（66 项验收面，含变异闭环+P1~P1g 七锚点；包内任何变更后跑它，全绿再发；项数随加固演进以脚本 RESULT 为准）
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

## Release 构建与安装链（G9-12：外部授权根 + fail-closed 安装器）

**构建输出两模式**（`tools/release_attest.py build`，互斥）：

- `--dist-dir dist`（默认，**存证模式**）：仓内 `dist/` 输出，用于存证 PR——
  制品随仓归档、可追溯；
- `--out-dir /仓外路径`（**生产模式**）：强制仓外输出（路径落在仓内即拒绝），
  生产安装链专用——不污染源码树，已存证制品零触碰。

**生产安装链**（`system/install-release.sh`）只消费**外部预置授权文件**
`release-roots.json`（生产位 `~/.wenqu/release-roots.json`；0600 owner-only；
`allowed_commit`（每项 `{commit, manifest_sha256}`）+ `plan_sha256`，由部署
授权流程仓外预置，安装器绝不生成/回写，也不调用 `roots-template`）：

1. 授权门（构建前 fail-closed）：roots 存在 → 权限无组/其他位 → 目标
   commit 在 `allowed_commit` 内（外部授权=side commit 拒绝正门；授权流程
   只收录 main push CI 已绿的确切 SHA）→ commit 为 origin/main 可达血统；
2. 仓外构建四件套 + `verify --release-roots` 四重对账（allowed_commit /
   plan_sha256 == manifest == tar 实算 / manifest 核心 digest——核心
   digest=manifest 去易变字段 build_id/built_at/builder/argv 的 canonical
   sha256，同 commit 异时重建稳定、内容篡改必断裂）；
3. 幂等复验/部署位复验均显式 `if verify; then …; else fail`——verify 真实
   rc 驱动，篡改既有 release 重跑安装器必 rc1（旧版 `verify || true` 吞 rc
   fail-open 已删除）；
4. 部署 → 只读化（chmod a-w 失败即中止）→ `current` 原子切换（rename(2)）。

`roots-template` 子命令：对已授权构建的 manifest **打印** roots 骨架
JSON（不写文件）——部署授权流程人工取值审核后落位并 chmod 600；安装链
脚本内不得调用（`grep roots-template system/` 可审计此边界）。
HMAC 对称签名=tamper-evident，非非否认（§21.4 诚实边界）。

### 回滚信任链（G9-13：`--rollback` 与正向链同一信任链）

九轮验收 `R9-REL-ROLLBACK-ROOT-BYPASS-004`：旧 `--rollback` 仅凭
`.last-current` 指向目录存在即切 `current`——绕过 roots/manifest/签名/
SBOM/哈希/血统，不冒烟不复验。现回滚六段 fail-closed，任一段失败=rc1：

1. **结构门**：回滚目标必须是受管 `releases/<40hex>/tree`（realpath 后
   不得逃出 releases 根——任意目录顶替即拒）；部署位四件套
   （tar/manifest/sig/SBOM）恰一套完整；`manifest.source_commit` 必须等于
   目录 SHA（目录改名/顶包即拒）；
2. **外部授权门**（与正向门同构）：roots（0600）`allowed_commit` 必须收录
   回滚目标 SHA——**回滚授权语义=roots 同时容纳现役与回滚目标两个 SHA**
   （部署授权流程预置双条目；四件套自洽签名不放行）；main 血统不可达即拒；
3. **四件套 verify**（`release_attest.py verify --release-roots`）：
   tar 逐文件 hash、plan_sha256 三方等值、manifest 核心 digest 对账
   roots、source commit git 正源、HMAC 验签、SBOM 对账——篡改 manifest
   一字节即在核心 digest/验签处断裂；报告落
   `releases/rollback-verify-report.<sha>.json`；
4. **解出树逐文件 sha256 对账 manifest**（部署后落盘篡改抽核，只读不删证据）；
5. **切换前实录 current**（补偿锚点）→ `rename(2)` 原子切换；
6. **切换后冒烟**：可达性/身份（readlink+VERSION）+ health
   （`wenqu_core.scheduler` 从回滚位导入）+ auth（回滚位 `approval_keys`
   加载 keyring，0600 纪律同生产）+ 可选 `--reload-scheduler`/
   `--reload-dashboard`（活性回读）；**任一失败自动补偿**：切回原
   `current` 并 rc1，`.last-current` 保持原值供审计。

回滚成功后 `.last-current` 交换为原 current——下一次 `--rollback` 即
roll-forward 备援。回滚演练三态（合法回滚 rc0 / roll-forward rc0 / 篡改
目标拒收 rc1 + 补偿态）见 `system/install-release.sh` 文件头注与九轮
整改证据链。


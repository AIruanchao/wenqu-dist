# launchd 受版本管理模板与注册表（G9-01/G9-02 唯一 writer）

本目录是 wenqu launchd 作业的**仓内正源**。此前生产 plist 均为手工
out-of-band 创建（无版本、无审计）——2026-10-09 审计发现观察采样面存在
**三个**写入口：`com.wenqu.scheduler`（每 5 分钟 tick）、
`com.wenqu.observation`（每日 09:05 直跑开发树 observation_daily.py）、
`com.wenqu.observation-window`（legacy 每日 08:00 独立作业，写
`~/Documents/.../观察窗日志.jsonl`）——多 writer + 秒级命名 + os.replace
构成第八轮 R8-OBS-COLLISION-016 的根因组合。

## 注册表（唯一观察采样入口）

| Label | 状态 | 说明 |
|---|---|---|
| `com.wenqu.scheduler` | **唯一合法** | 模板 `com.wenqu.scheduler.plist.template`；tick 内以 TrustedRunner 真跑 `tools/observation_daily.py`（argv/cwd 全部落在不可变 current 树） |
| `com.wenqu.observation` | **退役/禁止** | 旧独立日采样作业；install/scheduler 装配不得注册；运行面发现即 rc1 |
| `com.wenqu.observation-window` | **退役/禁止** | legacy 观察窗独立作业；同上 |

装配纪律：

1. install / scheduler 装配只安装本目录模板展开后的 `com.wenqu.scheduler`；
   本仓任何代码与模板**不得**定义或注册上表两个禁止 label
   （`system/tests/test_observation_window.py` 有机械断言）。
2. 观察样本（`~/.wenqu/observation/samples|shadow`）只允许
   `com.wenqu.scheduler` tick 一个 writer 写入。
3. 巡检/装配后必须跑唯一 writer 审计（rc0=收敛；发现第二 writer=rc1）：

```bash
python3 tools/window_harvest.py --root ~/.wenqu/observation \
    --audit-writers --launchagents ~/Library/LaunchAgents
```

4. 生产机器退役旧作业的操作步骤（bootout + 移除 plist）属于
   `install-release.sh` 装配动作（G9-01 面），不在本目录自动化。

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
| `com.wenqu.scheduler` | **唯一合法** | 模板 `com.wenqu.scheduler.plist.template`；tick 内以 TrustedRunner 真跑 `tools/observation_daily.py`（argv/cwd 全部落在不可变 current 树）。**W11-13：唯一 backup 作业 `w4.backup-restore-drill` 亦注册在本 scheduler tick 内**（每日 03:17 UTC 跑 `system/sentinels/backup-restore-drill.sh --mode release-dr`，Sfinal 字节备份恢复演练；与手工演练共用 `$WENQU_HOME/state/backup-drill.lock` 进程锁禁重叠；唯一性审计 `wenqu_core.scheduler.audit_unique_backup_job`——DB/launchd/cron/argv 四面） |
| `com.wenqu.integrity` | **合法（W11-02）** | 模板 `com.wenqu.integrity.plist.template`（StartInterval=300）；每 tick 对 current+previous 全树做内容+mode 双对账，原子发布 `state/release-integrity.json`（该文件**唯一 writer**）；漂移时 CRITICAL 告警+incident 封存+观察窗作废+熔断（冻结激活/回滚入口）+按授权自动恢复。scheduler/dashboard/install-release 对该状态只读 |
| `com.wenqu.observation` | **退役/禁止** | 旧独立日采样作业；install/scheduler 装配不得注册；运行面发现即 rc1 |
| `com.wenqu.observation-window` | **退役/禁止** | legacy 观察窗独立作业；同上 |
| `com.wenqu.dashboard` | **合法（UI 面）** | 模板 `com.wenqu.dashboard.plist.template`（W11-08）；只写采样外的 dashboard UI 面，与本表观察采样正交。**只携带 `WENQU_DASHBOARD_KEY_FILE` 路径**，任何密钥内容/inline `WENQU_DASHBOARD_KEY` 禁止入 plist（`system/tests/test_ac_ui_family.py` W11-08 腿有机械断言） |

backup 作业唯一性纪律（W11-13，十轮 W4 扣分「无最终字节备份正演练及唯一
backup 作业闭环」根治）：

1. 全系统**恰有一个** enabled backup 作业：scheduler 注册表内的
   `w4.backup-restore-drill`；**不得**出现任何直接执行
   `backup-restore-drill.sh` 的 launchd plist 或 crontab 条目（第二入口）。
2. 审计正源：`wenqu_core.scheduler.audit_unique_backup_job`（DB+launchd+
   cron+argv 四面；装配/巡检/验收入口）；scheduler tick 每次对注册表面
   自审（fail-visible CRITICAL 告警）。
3. last-success（`observation/drills/last-success.json`）只能由演练脚本在
   完整 PASS+fsync 后原子推进——失败/BLOCKED 运行绝不触碰。

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

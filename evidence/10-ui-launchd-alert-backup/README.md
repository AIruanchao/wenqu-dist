# 10-ui-launchd-alert-backup — UI/launchd/告警/备份证据

## 证据类型

- **UI（W8）**：Playwright trace/DOM 断言/截图（UI-01～07）、安全探针（XSS/CSRF/DNS rebinding）
  原始输出、Gate 红时总体必须 BLOCKED 的对照记录（UI-04）、健康分原子性证据（HLT-01）；
- **launchd/调度（W4/W7B）**：真实 launchd 环境的 job 清单回读、权限（Documents/TCC）探针、
  心跳与 last_success 语义证据（SCH-01～03/06/07）；
- **告警 Outbox（W4）**：send attempt/receipt/dead-letter 记录（ALT-01/02）；
- **备份（W4/W7A）**：checkpoint/restore 演练记录（BAK-01）。

## 关联测试 ID

UI-01～07、HLT-01、SCH-01～03/06/07、ALT-01～02、BAK-01。

## 当前状态（2026-10-08 W4 生产闭环续作后更新）

**PARTIAL——launchd 调度/告警回执/备份演练三面已有真机实证（本目录）；Playwright 真实
浏览器证据仍为 0**：

| 项 | 状态 |
|---|---|
| `system/dashboard/` 四文件（index/app.css/app.js/server.py） | 存在；接线测试断言存在性（CI 绿）；**P0-9/W8（2026-10-08）**：server.py 增透传前保守过滤——零 SHA(0*40) 身份占位→BLOCKED(identity_missing)、self-declared 聚合→NOT_EVALUATED，非 PASS 原样透传，UI-04b 五腿+--self-check 双腿+真 CLI 端到端对抗实证（`dashboard-7789-immutable-switch-20261008.json` + `adversarial-health-conservative-reverify-20261008.json`）；**未提交——live 生效待下一 release** |
| com.wenqu.dashboard launchd（W8 现役 UI） | **真机切 immutable 激活链实证（2026-10-08 16:33Z）**：plist 改指 `~/.wenqu/current/system/dashboard/server.py`（current→releases/2bd59ab…/tree 验签部署链）+WENQU_REPO_DIR/WorkingDirectory=current；bootout/bootstrap 后三探针绿（health 200 / decide 双路径 405 WRITE_DISABLED / 页面 200）、launchctl env 回读核；旧 plist 备份 `com.wenqu.dashboard.plist.pre-immutable-switch.bak`；30s 脉冲+早断对抗 pid 稳定；联动 `install-release.sh --reload-dashboard`（current 切换后须重载才重解析）。注意：现役 immutable 版仍为修复前代码——live health 对零 SHA/self-declared 快照仍透传 PASS，闭合须 commit 后出下一 release（诚实边界，登记 pending） |
| /api/decide 安全加固（Origin/Host/Auth-Key/CSRF 四检查+默认拒） | commit 1858a75，CI run 37660552501 绿（2026-10-07）；但为代码+单元级，无独立安全探针落档 |
| UI XSS escD/七态钻取等 Codex 三审修复 | v3.6.1～v3.6.3 提交在册；无 Playwright trace |
| com.wenqu.observation-window launchd | 外部 reaudit 证实已装载（每日 08:00），回读未固化 |
| com.wenqu.scheduler launchd（W4 生产调度） | **真机挂载+首跑实证（2026-10-08）**：`launchctl print` 回读 last exit code=0；首 tick（09:16:49Z）bootstrap 真跑采样器 COMPLETED/PASS，真 wenquctl gate 聚合 PASS（target_sha 绑 HEAD），心跳 FRESH，`~/.wenqu/observation/heartbeat.json` + `logs/scheduler-*.jsonl` 落盘；清单固化 `launchd-inventory.json`（三 agent 真回读+plist sha256+W4 运行态）。注：plist 直用 /opt/homebrew/bin/python3——launchd GUI 下 /bin/bash 无 Documents TCC 授权（bash 壳 exit 126，2026-10-08 首挂实测；launchd err 日志每次 spawn 截断故不留存）；到期机制经 09:27:11/09:32:11 两轮自然调度 run PASS 自续实证；gate 快照走 `--allow-self-declared` 诊断模式（F6-GATE-SCOPE-001 契约——shadow 数据源不冒充发布门，快照如实记 mode=self_declared_diagnostic） |
| 告警 outbox 回执（ALT-01/02） | **生产双通道实证（2026-10-08）**：W4 上线通告经真 osascript（macos 通道 SENT attempt=1）+ 文本投递箱（alertbox SENT + `~/.wenqu/observation/alerts/receipts.jsonl` 回执 + txt 落盘）；attempt/receipt/死信审计行在 `~/.wenqu/state/scheduler.db` 的 `scheduler_outbox` 表。故障路径（通知失败→死信→投递箱必成功）由 `system/tests/test_w4_production.py` 面2 注入真故障实证（35/35 绿） |
| 备份 checkpoint/restore（BAK-01） | **真机演练实证（2026-10-08 09:18:43Z）**：`system/sentinels/backup-restore-drill.sh` 对真实 `~/.wenqu`（5 文件语料：scheduler.db/gate-aggregate.json/heartbeat.json/当日 samples+shadow）快照→篡改（实测 sha 已变防伪造演练）→恢复→逐文件 cmp 字节级对账 PASS 4/4；报告 `~/.wenqu/observation/drills/drill-20261008T091843Z.json` |
| Playwright / 真实浏览器门（§17.5） | **无** |

## 填写规则

1. UI 证据必须是 Playwright trace/视频级工件；DOM 存在或 HTTP 200 不构成完成证据。
2. launchd 类证据须来自真机 `launchctl print`/`launchctl list` 原始输出。
3. 告警类须含 attempt→receipt 全链；只有 watchdog exit 0 不算送达。

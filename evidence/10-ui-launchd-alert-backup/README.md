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

## 当前状态（2026-10-08 建档时点）

**PARTIAL——dashboard 面与 /api/decide 加固有 CI 绿证据；Playwright 真实浏览器证据、
launchd 真环境证据、告警回执、备份演练全部为 0**：

| 项 | 状态 |
|---|---|
| `system/dashboard/` 四文件（index/app.css/app.js/server.py） | 存在；接线测试断言存在性（CI 绿） |
| /api/decide 安全加固（Origin/Host/Auth-Key/CSRF 四检查+默认拒） | commit 1858a75，CI run 37660552501 绿（2026-10-07）；但为代码+单元级，无独立安全探针落档 |
| UI XSS escD/七态钻取等 Codex 三审修复 | v3.6.1～v3.6.3 提交在册；无 Playwright trace |
| com.wenqu.observation-window launchd | 外部 reaudit 证实已装载（每日 08:00），回读未固化 |
| Playwright / 真实浏览器门（§17.5） | **无** |
| 告警 outbox 回执（ALT-01/02） | **无** |
| 备份 checkpoint/restore（BAK-01） | **无** |

## 填写规则

1. UI 证据必须是 Playwright trace/视频级工件；DOM 存在或 HTTP 200 不构成完成证据。
2. launchd 类证据须来自真机 `launchctl print`/`launchctl list` 原始输出。
3. 告警类须含 attempt→receipt 全链；只有 watchdog exit 0 不算送达。

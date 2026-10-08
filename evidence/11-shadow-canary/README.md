# 11-shadow-canary — W9 Shadow/Canary 切换证据

## 证据类型

- Shadow 阶段（§18.1/§18.2）：新管线与旧管线并行运行的对账输出、判定指标（分歧率、
  假阳/假阴计数）、shadow 判定期满记录；
- Canary 阶段（§18.3）：灰度范围、停止条件触发（或未触发）的原始指标、
  每日 canary 报告；
- 切换证据（§18.4）：切换决策记录、切换前后对照、回退预案激活状态。

## 关联测试 ID

本目录主要承接 §18 门槛证据；STA-01/02（站点分母/逐站故障聚合语义）的运行态版本也归此。

## W9 shadow v2 语义（2026-10-09 重做，旧 v1 废止）

**背景**：P0-9/W8 后现役 7789 已切 `~/.wenqu/current` 不可变树上的 modular
server，旧 v1 语义「7789 legacy vs 本仓影子实例」比对对象失效——连续多轮
采样 `compare` 全 null（7789 侧旧探针仍打已废止的未版本化 `/api/health`，
404 API_VERSION_REQUIRED），W9 shadow 时钟空转无收证能力。

**v2 口径**（tools/observation_daily.py，样本落 `~/.wenqu/observation/shadow/`）：

- 比对对象：**现役实例（7789）vs current 树新起临时实例**——每次采样从
  `~/.wenqu/current/system/dashboard/server.py` 起随机端口临时实例
  （env 剥离 `WENQU_HOME`/`WENQU_GATE_AGGREGATE` 保证与生产同源，
  `WENQU_HEALTH_HISTORY` 重定向至观察日志目录防影子实例共享文件副作用），
  就绪后抓双方 `/api/v1/health` 做结构化比对，finally 必杀影子进程。
- 比对内容（`compare` 字段，schema=w9-shadow-compare-v2，不再 null）：
  key 集合相等性 + 剔除 `generated_at` 时变字段后的稳定字段逐字段相等性
  （policy_verdict / aggregate_outcome / technical_eligible / counts /
  stations / cli_exit 等判定与 score 类字段全覆盖，差异字段逐一列
  `{field, live, shadow}`）；任一侧无 200 JSON 才记 null+note（不可比不猜）。
- identity：两侧 server.py 文件 sha256——7789 侧经 lsof→PID→ps argv 解析
  现役脚本路径后哈希，current 侧取激活树文件哈希；`file_hash_equal`
  暴露「current symlink 切换后 7789 未重启」的陈旧进程漂移。
- gate-aggregate 同源性：样本记 `gate_aggregate_source`（共同正源
  `~/.wenqu/state/gate-aggregate.json` 的 sha256/size/mtime）——两侧 health
  同读一份快照，行为差异只能来自代码面，比对据此可归因。
- 语义意图：v2 检测的是「现役运行态 vs current 树基准」的漂移（陈旧进程/
  代码漂移/运行态污染），这是 7789 已模块化后 W9 收证唯一有意义的 shadow 面。

**收证口径**：v2 样本 `compare.equal=true` 连续累积（见 canary 计数）+
`identity.file_hash_equal=true` 为「现役≡current 基准」的机器证据。

## W9 canary 窗口（到期收证准备）

- shadow 样本新增 `canary` 字段：**2026-10-10 00:00（本地）前
  `status=NOT_DUE`（未到期，计数 null）**；自 2026-10-10 00:00 起 **48h
  窗口内 `status=IN_WINDOW`，`equal_count`/`mismatch_count`/
  `not_comparable_count` 为扫描 `~/.wenqu/observation/shadow/` 既有样本
  聚合的 compare.equal 累计投影计数**（含当次样本自身，绝不凭空生成）；
  窗口关闭后 `CLOSED` 封口计数。
- 到期判定消费方式：窗口结束时 `mismatch_count==0 且 not_comparable_count==0`
  即 48h 零分歧收证；任何 mismatch/不可比样本需人工归因后才能关闭 W9。

## B5 容量闸接线状态（2026-10-09 关闭遗留）

「容量闸未接线」遗留已双侧关闭（capacity_monitor.py 本体零改动——judge()
契约已够，接线为纯消费）：

1. **采样器侧**：tools/observation_daily.py 样本 `disk` 字段旁新增
   `capacity_gate` 字段——导入 `system/wenqu_core/capacity_monitor`，
   `collect_disk_sample(~)` 真实采集后 `judge(peak_budget=0)`（观察采样无
   §22 迁移/发布峰值预算）；severity=CRITICAL → `capacity_gate=BLOCKED`。
2. **scheduler 生产 tick 侧**：`wenqu_core.scheduler.capacity_preflight()`
   在每个 tick 消费到期作业前前置检查（judge wenqu_home 挂载点），结果
   记入 tick payload/heartbeat.json 的 `capacity_gate` 字段；BLOCKED 时经
   outbox 双通道发 CRITICAL 告警（dedup 小时窗）。
   **刻意不阻断观察采样**：§22「不足即 BLOCKED」的处置对象是迁移/发布
   峰值操作（八分量峰值预算）；观察 tick 是 KB 级 JSON 追加写，容量压力下
   停观测=自毁唯一告警通道，且 tick 契约是「活着并如实上报」（tick_rc=0
   语义不变）。判定链异常如实记 gate=UNKNOWN，不猜 OPEN。
3. launchd plist 无需变更（无新增 env/路径）。

**实态注记（2026-10-09）**：本机 Data 卷实测 used_ratio≈0.923 > 0.90 阈值，
采样与 tick 均如实记录 `capacity_gate=BLOCKED`（CAP_USED_RATIO_EXCEEDED）+
CRITICAL 告警——这是接线生效的实证，同时是待人工处置的容量事实（非接线缺陷）。

## 当前状态（2026-10-09 更新）

- shadow v2 已上线（仓内 tools/observation_daily.py；生产经 release 部署链
  生效——当前激活 release 2bd59ab 内仍为旧 v1 采样器，下一 release 安装后
  生产 tick 产出 v2 样本）；手动跑采样器已产出含结构化 compare/identity/
  canary/capacity_gate 的样本（见 `~/.wenqu/observation/shadow|samples/`）。
- canary 窗口未到期（NOT_DUE），等待 2026-10-10 起算。
- 旧 v1 null-compare 样本（≤2026-10-09 早期）仅作历史观测事实保留，不具
  W9 收证效力。

## 填写规则

1. shadow 对账必须双管线同输入，输出逐条 diff，不许抽样代替全量。
2. canary 停止条件必须量化（阈值+实际值+触发时间），人工「看起来正常」无效。

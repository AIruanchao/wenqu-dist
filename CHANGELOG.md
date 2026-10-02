# wenqu-dist CHANGELOG（版本唯一正源）

三轴版本：发行版（本包）／CLI fork（cli/wenqu 的 VERSION）／规范（docs/ 文件名）。发行版号统摄全部。

- **v1.0.6（2026-10-02 加固五）**：CLI fork5——🔴BSF-20261002-40（sweep 用 id 子串匹配站名：站名互为子串时误关别家发现，实测 sweep tests 把 tests-x 的 AUTO 关成 FIXED=数据破坏级；精确数据 provenance.station 早就在账本里却用子串猜）改 provenance 精确匹配；探测器 trap-double 补 $f 引号（空格文件名原致 awk 拆参报错→假发现）。剩余命令全量审（init/_scope_files/ingest/sweep/charter）归位——cmd_init 的 --force/#5 符号链接防逃逸/#17 读守卫确认为上游已修好面。acceptance 24 项。
- **v1.0.5（2026-10-02 加固四）**：CLI fork4——🔴BSF-20261002-39（repair v0.2 件不认识 v0.3 行类：run/charter 审计行被当「未知 kind」隔离，实测一次 repair 清空审计链+连锁废掉 sweep；跨版本同族半改）白名单修复；repair 重写账本改走与 append 共用的 `_ledger_lock`（原绕锁裸 read→write 并发丢行）；quarantine 追加式防隔离历史覆盖。文档补全：cli/README fork 行为段、spec §4 timeout+空输入短路规约。acceptance 22 项（J 段 repair 行为+I 段并发）；含一个测试脚本自身战训（`$Q1→` 多字节字符拼进变量名→set -u 假 unbound，修=大括号包裹）。
- **v1.0.4（2026-10-02 加固三·验证性）**：零代码变更，证据面补全——①并发实弹入测试件（8 进程撞锁账本零损坏，新 I 段第 19 项）；②Linux 跨平台全套 18 项在 WSL Ubuntu/Python 3.10.12 全绿（已验证平台=macOS arm64 + Linux）；③上游并发修复（23 条评审 #1/#2/#4：判龄夺锁/finally 释放/整批 os.replace）fork 副本亲验有效；④fork3 post-fix 复扫零新攻击面。攻击面收敛曲线：37→38→值域三面→零。
- **v1.0.3（2026-10-02 加固二）**：CLI fork3——①timeout 值域校验（非数字/零/负数 die exit 2；原非数字裸 traceback、负值误导性立即超时）②--round 负数拒绝（防污染 verify --convergence 轮次集合——负轮号可参与/伪造连续性）③--convergence <1 拒绝。攻击面来源=fork2 自身引入（post-fix 复扫实锄：三面全真）。acceptance.sh 扩至 18 项（首跑全绿）。
- v1.0.2（2026-10-02 加固一）：CLI fork2——BSF-38 convergence 空转根修（三前置：轮次≥N+连续+零新发现；原 converged 初值 True 直接过 exit code 门）；run --round 轮次落账；subprocess 超时防线（per-station timeout 默认 300s）。探测器加固（trap-double 空仓守卫+全站 timeout）。新增 tests/acceptance.sh（14 项）。
- v1.0.1（2026-10-02 验收修订）：独立评审 6 发现全采纳（convergence 边界条款/README --home 语序与探测器路径/站0 会话侧职责/charter 平台注记/append-only 例外/id 通用化）。
- v1.0（2026-10-02 首版）：规范模板（bug-scan-pipeline v1.8 去 ERP 指针）+ CLI fork1（BSF-37 argparse choices 锁死插座修复）+ 三域探测器。履历：F4 跨仓扫描 37 发现全链+清零实弹+pytest 20 无回归。

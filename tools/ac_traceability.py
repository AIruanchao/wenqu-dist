#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ac_traceability.py — Codex 方案 §20 全部 131 个验收 ID 的追踪矩阵生成器（P0-10）。

正源：Codex 重构方案 /private/tmp/codex-test/方案.md
  SHA256 96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306
  §20（20.1～20.5）定义全部测试 ID 的注入/期望；§25.1 给出 ID 范围→需求/AC/工作包/证据类映射。
本工具把 §20/§25.1 全量转录为冻结目录（PLAN_TEST_CATALOG），运行时扫描仓内测试资产，
对每个 ID 判定是否有对应的测试文件或测试函数，并输出 JSON 追踪矩阵与覆盖率统计。

用法：
  python3 tools/ac_traceability.py                 # 扫描 + 写 evidence/traceability-matrix.json + 输出统计
  python3 tools/ac_traceability.py --json PATH     # 指定输出路径
  python3 tools/ac_traceability.py --plan PATH     # 用真实方案文件交叉校验 ID 集合（可选）
  python3 tools/ac_traceability.py --check         # 目录完整性失败时 exit 2（CI 用）

判定口径（诚实优先）：
  implemented=true  仅当：某测试文件中存在「以该 ID 命名/标注的测试函数或用例」
      （.py: ID 出现在 test_*/selftest 函数体内或函数名含 ID；.sh: ID 字面量出现在测试脚本中）。
  implemented=false 但 test_file 非空时，test_file 指向 PROXY_ALIASES 登记的相邻测试
      （部分覆盖，match_type=proxy_partial）——代理测试不冒充专属验收。
证据口径：evidence_path 为 evidence/ 下含该 ID 的非 README 工件（本工具自身输出除外）。
"""
import argparse
import ast
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAN_SHA256 = "96b8646f6f08fd5fc408bc64f332dff0aeabbb5bf51d3129fcaaa24612c32306"
EXPECTED_TOTAL = 131

# ---------------------------------------------------------------- 冻结目录：§25.1 前缀元数据
# (req, ac, work_packages, evidence_class)
PREFIX_META = {
    "GATE": ("REQ-EVID-001", "AC-EVID-FAIL-CLOSED", "W2/W3A/W3B", "raw rc、CAS、before/after"),
    "AUTH": ("REQ-AUTH-001", "AC-AUTH-ONE-TIME", "W1/W2", "signed payload、replay log"),
    "ACT": ("REQ-ACT-001", "AC-ACT-SAGA", "W2/W3B/W7B", "outbox、external receipt、reconcile"),
    "MRG": ("REQ-MERGE-001", "AC-MERGE-EXACT-SHA", "W3B", "ruleset、check、merge audit"),
    "STATE": ("REQ-STATE-001", "AC-STATE-APPEND-ONLY", "W1/W2", "event log、property/crash run"),
    "MIG": ("REQ-MIG-001", "AC-MIG-RECONCILE", "W5", "row mapping、decision、quarantine"),
    "DB": ("REQ-DB-001", "AC-DB-FOUR-TRACK", "W6C", "catalog diff、DB identity"),
    "SC": ("REQ-SC-001", "AC-SC-FAIL-CLOSED", "W6B", "audit JSON、SBOM、signature"),
    "ADV": ("REQ-ADV-001", "AC-ADV-COMPLETE", "W6B", "pages/ranges fixture"),
    "TEN": ("REQ-TENANT-001", "AC-TENANT-DENOMINATOR", "W6C", "DMMF/AST/runtime probes"),
    "PERF": ("REQ-PERF-001", "AC-PERF-VALID", "W6D", "raw samples/profile/baseline auth"),
    "SCH": ("REQ-SCHED-001", "AC-SCHED-RESULT", "W4", "launchd/job result/freshness"),
    "ALT": ("REQ-ALERT-001", "AC-ALERT-DELIVERED", "W4", "outbox/attempt/receipt/dead-letter"),
    "BAK": ("REQ-BACKUP-001", "AC-BACKUP-RESTORABLE", "W4/W7A", "checkpoint/restore drill"),
    "REL": ("REQ-RELEASE-001", "AC-RELEASE-MANIFEST", "W7A/W7B", "manifest/build identity"),
    "STOP": ("REQ-STOP-001", "AC-STOP-AUTH-AND-FACT", "W1/W2", "nine-type matrix/events"),
    "RUN": ("REQ-RUNNER-001", "AC-RUNNER-ISOLATED", "W2", "sandbox/quota/process-tree logs"),
    "CI": ("REQ-CI-001", "AC-CI-TERMINAL", "W3B", "check runs/ruleset/DAG validation"),
    "COND": ("REQ-COND-001", "AC-COND-NOT-PASS", "W1/W2/W3B", "risk/action auth、attestation、context"),
    "RISK": ("REQ-RISK-001", "AC-RISK-INVALIDATE", "W2/W5", "revoke/invalidate/reopen events"),
    "STA": ("REQ-STATION-001", "AC-STATION-COVERAGE", "W6A~W6D/W3B", "station results/aggregate"),
    "DEP": ("REQ-DEPLOY-001", "AC-DEPLOY-FENCED", "W7A/W7B", "lease/migration/activation events"),
    "RB": ("REQ-ROLLBACK-001", "AC-ROLLBACK-EXACT", "W7B", "preauthorization/compatibility/drill"),
    "UI": ("REQ-UI-001", "AC-UI-TRUTHFUL-SECURE", "W8", "Playwright/DOM/security trace"),
    "HLT": ("REQ-HEALTH-001", "AC-HEALTH-ATOMIC", "W8", "input watermark/snapshot retry"),
    "DOC": ("REQ-DOC-001", "AC-DOC-REGISTRY-CONSISTENT", "W1/W10", "generated consistency report"),
    "CAP": ("REQ-CAP-001", "AC-CAP-SAFE-MARGIN", "W0/W7A", "peak budget/disk-full injection"),
    "DR": ("REQ-DR-001", "AC-DR-RPO-RTO", "W4/W7B/W10", "restored state/RPO/RTO timing"),
}

# ---------------------------------------------------------------- 冻结目录：§20 逐 ID（注入, 期望）
# 逐字转录自方案 §20.1～§20.5 表格。
ID_DEFS = {
    # -- §20.1 Gate、授权、合流 --
    ("GATE", 1): ("base ref 不存在/fetch 失败", "ERROR/BLOCKED"),
    ("GATE", 2): ("零测试、scope 未证明纯文档", "BLOCKED"),
    ("GATE", 3): ("test runner/依赖缺失", "ERROR"),
    ("GATE", 4): ("内层 exit 7、自报零 finding", "assertion FAIL/BLOCKED"),
    ("GATE", 5): ("artifact symlink/hardlink/根外", "BLOCKED"),
    ("GATE", 6): ("artifact hash 篡改", "BLOCKED"),
    ("GATE", 7): ("commit/env/scope/ruleset 不符", "BLOCKED"),
    ("GATE", 8): ("evidence 过 TTL", "BLOCKED"),
    ("GATE", 9): ("N=-1/0/超上限", "参数错误"),
    ("GATE", 10): ("超过 N+1", "BLOCKED 等人工裁定"),
    ("GATE", 11): ("同命令换 S 标签", "不计异源轮"),
    ("GATE", 12): ("unsigned flip/adjudication", "BLOCKED"),
    ("AUTH", 1): ("无授权 resume", "拒绝"),
    ("AUTH", 2): ("过期/重放/扩范围/旧 state_version", "拒绝"),
    ("AUTH", 3): ("AI/runner 尝试自行签发高风险批准", "拒绝"),
    ("ACT", 1): ("technical PASS，但无 exact merge/release action authorization",
                 "context 可表技术 PASS，controller 不动作"),
    ("ACT", 2): ("action、method、head/merge-group、artifact/env 任一不符",
                 "Action Authorization Gate failure，拒绝动作"),
    ("ACT", 3): ("check 发布前/后 crash 或回执丢失", "outbox 幂等恢复；同一 check_run 更新，不产生伪双绿"),
    ("ACT", 4): ("merge/release 调用前/后 crash 或回执丢失", "先查询外部事实；COMMITTED 或 FAILED_UNKNOWN；绝不盲重试"),
    ("ACT", 5): ("外部陈旧绿、dispatcher/App 失联", "direct merge 被角色/ruleset 拒绝；动作保持 BLOCKED"),
    ("ACT", 6): ("merge/release/DDL/prod-write payload 使用错误 discriminator 或缺专属字段", "schema 拒绝"),
    ("MRG", 1): ("Fast 绿、Security 红", "不合流"),
    ("MRG", 2): ("没有 Fast、Gate 红", "不合流"),
    ("MRG", 3): ("check 同名伪造/旧 SHA", "不合流"),
    ("MRG", 4): ("pending/skipped/neutral/cancelled", "不合流"),
    ("MRG", 5): ("head 在聚合后改变", "旧结论失效"),
    ("MRG", 6): ("GitHub 429/空 JSON/超时", "断路，不合流"),
    # -- §20.2 状态、账本、迁移 --
    ("STATE", 1): ("任意 stage/status", "schema 拒绝"),
    ("STATE", 2): ("../、绝对路径、NUL、超长 ID", "拒绝"),
    ("STATE", 3): ("100×100 并发写", "零丢失/重复"),
    ("STATE", 4): ("事务各点 kill -9", "全有或全无"),
    ("STATE", 5): ("双 writer epoch", "所有写入拒绝"),
    ("STATE", 6): ("WAITING 终态残留", "SUPERSEDED 事件，不静默删"),
    ("MIG", 1): ("坏 JSON/未知状态", "quarantine+BLOCKED"),
    ("MIG", 2): ("缺审批信息的 ACCEPTED", "invalid/reopen"),
    ("MIG", 3): ("两次迁移", "结果幂等一致"),
    ("MIG", 4): ("源行数不守恒", "迁移失败"),
    ("MIG", 5): ("project key 冲突", "明确冲突，不拆成假项目"),
    # -- §20.3 Bug 扫描器 --
    ("DB", 1): ("[+]/[-]/[*]", "全识别"),
    ("DB", 2): ("仅一条 DROP COLUMN/删 FK", "FAIL，不因数量少放行"),
    ("DB", 3): ("未知格式/空输出/命令非零", "ERROR"),
    ("DB", 4): ("allowlist 到期/对象 hash 变化", "FAIL"),
    ("SC", 1): ("有效 JSON+HIGH/CRITICAL", "FAIL"),
    ("SC", 2): ("空 JSON/registry 超时", "ERROR"),
    ("SC", 3): ("install script/resolved/integrity 变化", "FAIL/人工审"),
    ("SC", 4): ("标题含 [skip-audit]", "无绕过效果"),
    ("ADV", 1): ("version parser 异常", "UNKNOWN，不写 seen"),
    ("ADV", 2): ("多页/多 range", "全遍历"),
    ("TEN", 1): ("Prisma alias/re-export/wrapper", "纳入分析"),
    ("TEN", 2): ("注释含 organizationId", "不能欺骗"),
    ("TEN", 3): ("builder 超 300 字符", "纳入分析"),
    ("TEN", 4): ("$queryRaw 跨租户", "阻断"),
    ("TEN", 5): ("路径不含 export/download 的下载", "纳入扫描"),
    ("TEN", 6): ("Org A 访问/导出 Org B", "动态拒绝"),
    ("PERF", 1): ("HTTP 500 但很快", "FAIL"),
    ("PERF", 2): ("SSH/TCC/null 指标", "ERROR"),
    ("PERF", 3): ("尾部极慢样本", "正确进入 p95/p99"),
    ("PERF", 4): ("输入 1→100，query count 线性", "FAIL"),
    # -- §20.4 调度、发布、UI --
    ("SCH", 1): ("launchd 无 Documents 权限", "ERROR+告警"),
    ("SCH", 2): ("脚本 FAIL 后 touch heartbeat", "测试抓获、last_success 不变"),
    ("SCH", 3): ("睡眠错过周期", "唤醒补跑"),
    ("ALT", 1): ("provider 500/超时", "outbox 重试/dead-letter"),
    ("BAK", 1): ("磁盘满/tar/backup 失败", "不更新 success"),
    ("REL", 1): ("manifest 缺件/多件/错 hash", "部署失败"),
    ("REL", 2): ("部署中 kill -9", "保持旧 current 或完整新 current"),
    ("REL", 3): ("doctor 红", "部署失败并回退"),
    ("UI", 1): ("少一个闭合标签", "构建/启动门失败"),
    ("UI", 2): ("XSS 日志/账本文本", "不执行"),
    ("UI", 3): ("CSRF/伪 Origin/text/plain 写入", "拒绝"),
    ("UI", 4): ("Gate 红、其他项高分", "总体 BLOCKED"),
    ("UI", 5): ("ACCEPTED/OTHER/quarantine", "均可钻取"),
    # -- §20.5 补充契约、隔离与治理探针 --
    ("STOP", 1): ("九种 stop type 使用错误类型审批", "全拒绝"),
    ("STOP", 2): ("resource/ext-unavail 未恢复但已批准", "仍不可 resume"),
    ("STOP", 3): ("九种 stop type 的客观条件已满足但缺一次性授权", "九类全部拒绝 resume"),
    ("STATE", 7): ("普通事件把 PASSED 改回 RUNNING", "拒绝"),
    ("STATE", 8): ("FAILED 重试", "新 attempt，旧证据不覆盖"),
    ("STATE", 9): ("SHA/scope/policy 变化", "强制新 run"),
    ("STATE", 10): ("WAITING/FAILED attempt 直接改回 RUNNING", "拒绝；追加新 attempt 后由 stage projection 指向它"),
    ("STATE", 11): ("S7 CONDITIONAL 缺 risk authorization", "S7/run 终判 FAILED；后续批准只能创建新 run，不得写 WAITING"),
    ("AUTH", 4): ("canonical payload/Unicode/audience 任一字节改变", "验签失败"),
    ("AUTH", 5): ("并发双消费 approval", "恰一成功"),
    ("AUTH", 6): ("key revoked/clock rollback/无 user-presence", "拒绝"),
    ("RUN", 1): ("被测程序读取 Keychain/SSH agent/生产配置", "隔离拒绝"),
    ("RUN", 2): ("timeout 后子孙进程", "全部终止，无孤儿写盘"),
    ("RUN", 3): ("fork bomb/输出爆量/网络外连", "配额/allowlist 阻断"),
    ("CI", 5): ("fork、merge_group、check 不产生", "明确 FAILURE/BLOCKED"),
    ("CI", 6): ("CODEOWNERS 文件存在但 ruleset 未强制", "doctor ERROR"),
    ("CI", 7): ("未授权 App 发布同名 context/旧 details URL", "不可信、阻断"),
    ("CI", 8): ("Wenqu Gate 缺失但 Bugscan 绿", "不合流"),
    ("CI", 9): ("S7 把 Wenqu Required Gate 当自身输入、重复发布或递归聚合", "schema/DAG 校验拒绝并发布 FAILURE"),
    ("MRG", 7): ("最后校验后 head 变化", "expected-SHA 原子拒绝"),
    ("COND", 1): ("CONDITIONAL 无 risk authorization", "technical eligibility=false，技术 context failure"),
    ("COND", 2): ("授权跨 SHA/env/扩 finding 集/重放", "拒绝"),
    ("COND", 3): ("合法低风险接受、其余全 PASS、risk 与 action 两类精确授权",
                  "内部仍 CONDITIONAL；技术 context=success/AUTHORIZED_CONDITIONAL；Action Gate 成功后动作恰一次"),
    ("COND", 4): ("P0/P1 尝试风险接受或条件授权", "拒绝并保持 BLOCKED"),
    ("COND", 5): ("授权后新增 finding、TTL 到期、SHA/scope/policy/watermark 变化",
                  "authorization、attestation、context 失效；动作前重验拒绝"),
    ("COND", 6): ("并发双消费或动作失败后重放 attestation", "最多一次消费；失败后须新授权"),
    ("RISK", 1): ("主动撤销或 fingerprint/severity/policy/control 改变", "追加 REVOKED/INVALIDATED，立即重开并可进入修复链"),
    ("DB", 5): ("错 DB/role/transaction_read_only=off", "BLOCKED"),
    ("DB", 6): ("catalog 顺序、默认表达式、extension 对象", "golden 规范化正确"),
    ("SC", 5): ("离线快照签名错误/过期/分页不全", "BLOCKED"),
    ("TEN", 7): ("target SHA 新增 tenant model", "分母自动增加"),
    ("TEN", 8): ("合法管理员跨租户正例/普通角色负例", "前者通、后者拒"),
    ("PERF", 5): ("修改 baseline/阈值试图洗绿", "policy hash 阻断"),
    ("PERF", 6): ("样本/时长/endpoint 分母缩水", "不得晋升 baseline"),
    ("STA", 1): ("任一站 denominator 缩小", "整线 BLOCKED"),
    ("STA", 2): ("站2/3/4/7逐站故障", "继续独立取证，aggregate BLOCKED"),
    ("SCH", 4): ("catch-up 与正常调度并发", "只有一个 logical run"),
    ("SCH", 5): ("scheduler 整体故障", "独立 watchdog 仍告警"),
    ("SCH", 6): ("one-shot job", "只写 wenqu namespace"),
    ("SCH", 7): ("COMPLETED+NOT_APPLICABLE 或过期/异指纹 PASS", "不刷新任何实体的 last_success"),
    ("DEP", 1): ("两个部署者争 lease", "最多一个成功"),
    ("DEP", 2): ("smoke 访问生产 DB/state", "隔离拒绝"),
    ("DEP", 3): ("新事件后回滚兼容二进制", "事件零丢失"),
    ("DEP", 4): ("自签/替换/revoked release key", "拒绝"),
    ("DEP", 5): ("previous release 超 schema 范围", "拒绝回滚"),
    ("DEP", 6): ("无迁移锁/未验证备份/expand 超授权", "激活前 BLOCKED，旧 current 不变"),
    ("DEP", 7): ("ACTIVATING 失败且无预授权", "FAILED_BLOCKED；不得自动回滚或继续发布"),
    ("DEP", 8): ("ROLLBACK_FAILED", "writer/merge/release 熔断并停等人工恢复"),
    ("DEP", 9): ("观察窗内夹带 contract/down migration", "拒绝；要求独立授权变更"),
    ("RB", 1): ("无预授权自动回滚/错误旧版本", "拒绝"),
    ("UI", 6): ("DNS rebinding/伪 Host/未认证日志读取", "拒绝"),
    ("UI", 7): ("慢请求/高并发/超大日志", "不耗尽资源"),
    ("HLT", 1): ("聚合期间输入 watermark 变化", "snapshot 作废重算"),
    ("DOC", 1): ("one-shot 停等数量/枚举漂移", "CI 阻断"),
    ("DOC", 2): ("bug skill 版本/清单/验收数量漂移", "CI 阻断"),
    ("DOC", 3): ("policy/Skill 出现 L4、--admin、force-with-lease 或 skip 绕闸文本", "CI 阻断"),
    ("DOC", 4): ("文档宣称现役/PASS，但 registry 或 Gate 为 BLOCKED", "CI 阻断"),
    ("ALT", 2): ("waiting 到期但零 send attempt/receipt", "ERROR+告警，不能以 watchdog exit0 记健康"),
    ("CAP", 1): ("峰值空间超过安全余量或磁盘满", "切换 BLOCKED，旧证据和 current 均完整"),
    ("DR", 1): ("恢复演练", "实测满足冻结 RPO/RTO"),
}

SECTION_OF = {}  # (prefix, num) -> "20.x"
for _id in [
    *[("GATE", i) for i in range(1, 13)], *[("AUTH", i) for i in range(1, 4)],
    *[("ACT", i) for i in range(1, 7)], *[("MRG", i) for i in range(1, 7)],
]:
    SECTION_OF[_id] = "20.1"
for _id in [*[("STATE", i) for i in range(1, 7)], *[("MIG", i) for i in range(1, 6)]]:
    SECTION_OF[_id] = "20.2"
for _id in [
    *[("DB", i) for i in range(1, 5)], *[("SC", i) for i in range(1, 5)],
    *[("ADV", i) for i in range(1, 3)], *[("TEN", i) for i in range(1, 7)],
    *[("PERF", i) for i in range(1, 5)],
]:
    SECTION_OF[_id] = "20.3"
for _id in [
    *[("SCH", i) for i in range(1, 4)], ("ALT", 1), ("BAK", 1),
    *[("REL", i) for i in range(1, 4)], *[("UI", i) for i in range(1, 6)],
]:
    SECTION_OF[_id] = "20.4"
# 其余（§20.5 补充）在构建目录时兜底。

# ---------------------------------------------------------------- 代理测试登记（诚实部分覆盖）
# 只登记确实存在且语义相邻的仓内测试；implemented 仍为 false（无 §20 ID 专属用例）。
PROXY_ALIASES = {
    "GATE-02": {
        "test_file": "system/tests/test_core_wiring.py",
        "test_function": "test_gate_aggregator_blocks_empty",
        "note": "空 required_stations → BLOCKED 与 GATE-02『零测试→BLOCKED』语义相邻；"
                "但非完整注入面（无 base ref/纯文档 scope 判定），不冒充专属验收",
    },
    "COND-04": {
        "test_file": "system/tests/test_core_wiring.py",
        "test_function": "test_schema_rejects_p0_accepted_risk",
        "note": "Schema 层拒 CRITICAL ACCEPTED_RISK（P0-4 批 e00de14 已扩到全量加固）；"
                "COND-04 还要求条件授权拒绝与保持 BLOCKED 的状态机行为，未覆盖",
    },
    "STATE-03": {
        "test_file": "tests/acceptance.sh",
        "test_function": "I 节 并发 8 进程撞锁写账本零损坏 / L 节 并发 ingest 同 id 不双入账",
        "note": "并发正确性语义相邻，但对象是遗留 cli findings.jsonl 账本，"
                "非 wenqu_core EventStore（100×100 规模亦未达），不冒充专属验收",
    },
}

# 扫描根（相对 REPO_ROOT）：测试资产可能所在目录
SCAN_ROOTS = ["tests", "system/tests", "cli", "system/wenqu_core", "probes"]
EVIDENCE_ROOT = os.path.join(REPO_ROOT, "evidence")
SELF_OUTPUT_NAMES = {"traceability-matrix.json"}


def build_catalog():
    """构建 131 个 ID 的冻结目录并做完整性自检。"""
    catalog = {}
    for (prefix, num), (injection, expectation) in ID_DEFS.items():
        test_id = f"{prefix}-{num:02d}"
        req, ac, wps, ev_class = PREFIX_META[prefix]
        catalog[test_id] = {
            "prefix": prefix,
            "section": SECTION_OF.get((prefix, num), "20.5"),
            "injection": injection,
            "expectation": expectation,
            "req": req,
            "ac": ac,
            "work_packages": wps,
            "evidence_class": ev_class,
        }
    problems = []
    if len(catalog) != EXPECTED_TOTAL:
        problems.append(f"目录数量 {len(catalog)} != {EXPECTED_TOTAL}")
    # 前缀分母核对（§25.1 范围展开）
    expected_counts = {
        "GATE": 12, "AUTH": 6, "ACT": 6, "MRG": 7, "STATE": 11, "MIG": 5, "DB": 6,
        "SC": 5, "ADV": 2, "TEN": 8, "PERF": 6, "SCH": 7, "ALT": 2, "BAK": 1,
        "REL": 3, "STOP": 3, "RUN": 3, "CI": 5, "COND": 6, "RISK": 1, "STA": 2,
        "DEP": 9, "RB": 1, "UI": 7, "HLT": 1, "DOC": 4, "CAP": 1, "DR": 1,
    }
    actual_counts = {}
    for tid in catalog:
        actual_counts[tid.split("-")[0]] = actual_counts.get(tid.split("-")[0], 0) + 1
    if actual_counts != expected_counts:
        for k in sorted(set(expected_counts) | set(actual_counts)):
            if expected_counts.get(k) != actual_counts.get(k):
                problems.append(
                    f"前缀 {k}: 期望 {expected_counts.get(k)} 实际 {actual_counts.get(k)}")
    # 编号连续性（CI 特例：05~09）
    ranges = {"CI": (5, 9)}
    for tid in catalog:
        prefix, num = tid.split("-")[0], int(tid.split("-")[1])
        lo, hi = ranges.get(prefix, (1, expected_counts[prefix]))
        if not (lo <= num <= hi):
            problems.append(f"ID {tid} 超出定义范围 {lo}~{hi}")
    dup = EXPECTED_TOTAL - len(catalog)
    if dup:
        problems.append(f"疑似重复/缺失 {dup} 项")
    return catalog, problems


def cross_check_plan(plan_path, catalog):
    """可选：解析方案 §20 表格，与冻结目录做 ID 集合等式校验 + 逐 ID 语义比对。

    F4-TRC-001 根修（Codex 第四轮实锤）：旧版只比 ID 集合——保留 ID 不动、
    只改该行「注入/期望」文本的语义篡改全绿。现从 §20.1～§20.5 表格逐行解析
    (ID, 注入, 期望)，与冻结目录（ID_DEFS 转录）做归一化语义比对：
    去首尾空白、markdown 反引号剥离、全半角标点归一、连续空白折叠。
    任一 ID 语义漂移 → semantic problems → --check exit 2。
    """
    try:
        with open(plan_path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        return {"ok": False, "error": f"读取方案失败: {e}", "plan_ids": None}
    body = text
    # 只取 §20～§21 之间的正文，避免 §25 表格里的范围写法（GATE-01～12）污染集合
    m20 = re.search(r"^# 20\.", body, re.M)
    m21 = re.search(r"^# 21\.", body, re.M)
    if m20 and m21:
        body = body[m20.start():m21.start()]
    ids = set(re.findall(r"\b([A-Z]{2,5}-\d{2})\b", body))
    plan_ids = {i for i in ids if not re.match(r"^(FND|W\d)", i)}
    frozen = set(catalog)
    # ---- 逐 ID 语义比对（F4-TRC-001）------------------------------------
    semantic_problems = []
    row_re = re.compile(
        r"^\|\s*([A-Z]{2,5}-\d{2})\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$")
    plan_semantics = {}
    for line in body.splitlines():
        mm = row_re.match(line)
        if mm:
            plan_semantics[mm.group(1)] = (mm.group(2), mm.group(3))
    if not plan_semantics:
        semantic_problems.append("§20 表格解析出 0 行数据行（格式漂移？）")
    for tid in sorted(frozen):
        if tid not in plan_semantics:
            # 集合等式已另行报告；这里防「ID 在正文他处出现但表格行被删」的缝隙
            semantic_problems.append(f"§20 表格缺 {tid} 行（或行格式无法解析）")
            continue
        plan_inj, plan_exp = plan_semantics[tid]
        frozen_inj = catalog[tid]["injection"]
        frozen_exp = catalog[tid]["expectation"]
        if _norm_semantic(plan_inj) != _norm_semantic(frozen_inj):
            semantic_problems.append(
                f"{tid} 注入语义漂移: 方案={plan_inj!r} 冻结={frozen_inj!r}")
        if _norm_semantic(plan_exp) != _norm_semantic(frozen_exp):
            semantic_problems.append(
                f"{tid} 期望语义漂移: 方案={plan_exp!r} 冻结={frozen_exp!r}")
    for tid in sorted(set(plan_semantics) - frozen):
        semantic_problems.append(f"§20 表格行 {tid} 不在冻结目录中")
    return {
        "ok": plan_ids == frozen and not semantic_problems,
        "plan_only": sorted(plan_ids - frozen),
        "frozen_only": sorted(frozen - plan_ids),
        "plan_ids_count": len(plan_ids),
        "frozen_count": len(frozen),
        "semantic_ok": not semantic_problems,
        "semantic_problems": semantic_problems,
        "semantic_rows_parsed": len(plan_semantics),
    }


# 全角→半角标点归一表（语义比对用；只归一标点，不动字母/数字/汉字）
_FW_PUNCT = {
    "，": ",", "、": ",", "。": ".", "？": "?", "！": "!", "：": ":",
    "；": ";", "（": "(", "）": ")", "～": "~", "「": '"', "」": '"',
    "『": '"', "』": '"', "“": '"', "”": '"', "‘": "'", "’": "'",
    "【": "[", "】": "]", "《": "<", "》": ">", "　": " ",
}


def _norm_semantic(s):
    """§20 语义归一化：去 markdown 反引号、全半角标点归一、折叠空白、去首尾。"""
    if not isinstance(s, str):
        return "" if s is None else str(s)
    out = s.replace("`", "")
    out = "".join(_FW_PUNCT.get(ch, ch) for ch in out)
    out = re.sub(r"\s+", " ", out)
    return out.strip()


def _norm_meta(s):
    """§25.1 表格与冻结元数据的归一化：全角～→半角~、去首尾空白。"""
    return s.replace("～", "~").strip()


def cross_check_plan_251(plan_path, catalog):
    """真解析方案 §25.1 映射表：范围展开成 ID 集合 + 逐前缀四列元数据对账。

    防的是第三轮验收实锤的假绿：篡改 §25.1 映射（换 REQ/AC/工作包/证据类）
    时旧版工具根本不解析该表却声称"§25.1 集合等式"。
    """
    try:
        with open(plan_path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        return {"ok": False, "error": f"读取方案失败: {e}"}
    m = re.search(r"^## 25\.1\b", text, re.M)
    if not m:
        return {"ok": False, "error": "方案中未找到 §25.1 小节"}
    rest = text[m.start():]
    m_end = re.search(r"^# 2[6-9]\.|^---\s*$", rest[m.end() - m.start():], re.M)
    section = rest if not m_end else rest[: m.end() - m.start() + m_end.start()]
    row_re = re.compile(
        r"^\|\s*([A-Z]{2,5})-(\d{2})(?:～(\d{2}))?\s*\|([^|]+)\|([^|]+)\|([^|]+)\|")
    expanded, meta, problems = set(), {}, []
    for line in section.splitlines():
        mm = row_re.match(line)
        if not mm:
            continue
        prefix, lo = mm.group(1), int(mm.group(2))
        hi = int(mm.group(3)) if mm.group(3) else lo
        req_ac, work_packages, evidence_class = mm.group(4), mm.group(5), mm.group(6)
        parts = [p.strip() for p in req_ac.split("/", 1)]
        if len(parts) != 2 or not parts[0].startswith("REQ-") or not parts[1].startswith("AC-"):
            problems.append(f"§25.1 行 {prefix}-{lo:02d}～{hi:02d} 需求/AC 列格式非法: {req_ac.strip()!r}")
            continue
        for n in range(lo, hi + 1):
            tid = f"{prefix}-{n:02d}"
            if tid in expanded:
                problems.append(f"§25.1 重复展开 ID: {tid}")
            expanded.add(tid)
        meta[prefix] = (_norm_meta(req_ac.replace(" / ", "/", 1)),
                        _norm_meta(work_packages), _norm_meta(evidence_class))
    if not expanded:
        return {"ok": False, "error": "§25.1 表格解析出 0 行（格式漂移？）"}
    frozen = set(catalog)
    if expanded != frozen:
        problems.append(f"§25.1 展开集合≠冻结目录: 仅方案={sorted(expanded - frozen)} 仅冻结={sorted(frozen - expanded)}")
    for prefix, plan_meta in sorted(meta.items()):
        frozen_meta = PREFIX_META.get(prefix)
        if frozen_meta is None:
            problems.append(f"§25.1 前缀 {prefix} 不在冻结元数据中")
            continue
        norm_frozen = (_norm_meta(frozen_meta[0] + "/" + frozen_meta[1]),
                       _norm_meta(frozen_meta[2]), _norm_meta(frozen_meta[3]))
        if plan_meta != norm_frozen:
            problems.append(f"§25.1 前缀 {prefix} 四列元数据与冻结值不符: 方案={plan_meta} 冻结={norm_frozen}")
    return {"ok": not problems, "problems": problems,
            "expanded_count": len(expanded), "frozen_count": len(frozen)}


EXCLUDE_DIRS = {"__pycache__", ".pytest_cache", ".git", "node_modules"}


def iter_test_files():
    for root_rel in SCAN_ROOTS:
        root = os.path.join(REPO_ROOT, root_rel)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
            for fn in filenames:
                if fn.endswith((".py", ".sh")):
                    yield os.path.join(dirpath, fn)


TESTISH_NAME = re.compile(r"(^test_|_self_test$|^_?selftest|self_test)", re.I)


def scan_python(path, wanted_forms):
    """在 .py 中定位 ID 出现点，归属到 test 型函数才算 implemented。"""
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
        tree = ast.parse(src)
    except (OSError, SyntaxError, UnicodeDecodeError) as e:
        return {}, f"parse 失败: {e}"
    funcs = []  # (name, lineno, end_lineno)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append((node.name, node.lineno, node.end_lineno or node.lineno))
    lines = src.splitlines()
    hits = {}
    for form in wanted_forms:
        for i, line in enumerate(lines, start=1):
            if form in line:
                owner = None
                for name, lo, hi in funcs:
                    if lo <= i <= hi:
                        owner = name
                        break
                if owner is not None and TESTISH_NAME.search(owner):
                    hits.setdefault(form, []).append((owner, i))
    return hits, None


def scan_shell(path, wanted_forms):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError) as e:
        return {}, f"read 失败: {e}"
    hits = {}
    for form in wanted_forms:
        for i, line in enumerate(lines, start=1):
            if form in line and not line.strip().startswith("#"):
                hits.setdefault(form, []).append(("(script-case)", i))
    return hits, None


def collect_test_matches(catalog):
    """返回 {test_id: {"test_file":..., "test_function":..., "line":...}}（专属命中）。"""
    # 归一化形态：GATE-01 / GATE_01（函数名下划线写法）
    id_forms = {}
    for tid in catalog:
        prefix, num = tid.split("-")
        id_forms[tid] = [f"{prefix}-{num}", f"{prefix}_{num}", f"test_{prefix}_{num}"]
    matches = {}
    scanned = []
    all_forms = sorted({f for forms in id_forms.values() for f in forms})
    for path in iter_test_files():
        rel = os.path.relpath(path, REPO_ROOT)
        scanned.append(rel)
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue
        present = [f for f in all_forms if f in content]
        if not present:
            continue
        if path.endswith(".py"):
            hits, err = scan_python(path, present)
        else:
            hits, err = scan_shell(path, present)
        if err:
            continue
        # form -> test_id 反查
        for tid, forms in id_forms.items():
            for form in forms:
                if form in hits:
                    owner, line = hits[form][0]
                    matches.setdefault(tid, {
                        "test_file": rel, "test_function": owner,
                        "line": line, "match_kind": "dedicated",
                    })
                    break
    return matches, scanned


def collect_evidence_matches(catalog):
    """evidence/ 下含 ID 的非 README 工件（排除本工具输出）。"""
    matches = {}
    if not os.path.isdir(EVIDENCE_ROOT):
        return matches
    for dirpath, dirnames, filenames in os.walk(EVIDENCE_ROOT):
        for fn in filenames:
            if fn == "README.md" or fn in SELF_OUTPUT_NAMES or fn.endswith(".sha256"):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, REPO_ROOT)
            try:
                if os.path.getsize(p) > 2_000_000:
                    continue
                with open(p, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            for tid in catalog:
                if tid in content:
                    matches.setdefault(tid, rel)
    return matches


def git_head():
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description="§20 131 验收 ID 追踪矩阵生成器")
    ap.add_argument("--json", default=os.path.join(EVIDENCE_ROOT, "traceability-matrix.json"),
                    help="输出 JSON 路径（默认 evidence/traceability-matrix.json）")
    ap.add_argument("--plan",
                    default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                         "evidence", "00-baseline", "codex-external", "方案.md"),
                    help="方案文件路径（默认仓内快照 evidence/00-baseline/codex-external/方案.md；存在则做 ID 集合交叉校验）")
    ap.add_argument("--check", action="store_true",
                    help="目录完整性/集合校验失败时 exit 2")
    args = ap.parse_args()

    catalog, problems = build_catalog()
    integrity_ok = not problems

    plan_check = None
    if args.plan and os.path.isfile(args.plan):
        plan_check = cross_check_plan(args.plan, catalog)
        if not plan_check.get("ok", False):
            if (plan_check.get("plan_only") or plan_check.get("frozen_only")
                    or plan_check.get("error")):
                problems.append(f"方案交叉校验不一致: {plan_check.get('plan_only')}/{plan_check.get('frozen_only')}")
            for p in (plan_check.get("semantic_problems") or [])[:20]:
                # F4-TRC-001：逐 ID 语义漂移必须计入 problems（--check exit 2）
                problems.append(f"§20 语义漂移: {p}")
        plan_check_251 = cross_check_plan_251(args.plan, catalog)
        if not plan_check_251.get("ok", False):
            problems.append("§25.1 映射交叉校验不一致: " + "; ".join(
                plan_check_251.get("problems") or [plan_check_251.get("error", "未知")]))

    direct, scanned = collect_test_matches(catalog)
    evidence_map = collect_evidence_matches(catalog)

    matrix = {}
    n_impl = n_proxy = 0
    for tid in sorted(catalog):
        meta = catalog[tid]
        entry = {
            "implemented": False,
            "test_file": "",
            "evidence_path": "",
            "match_type": "missing",
            "test_function": "",
            "section": meta["section"],
            "injection": meta["injection"],
            "expectation": meta["expectation"],
            "req": meta["req"],
            "ac": meta["ac"],
            "work_packages": meta["work_packages"],
            "evidence_class": meta["evidence_class"],
        }
        if tid in direct:
            entry.update(implemented=True, match_type="dedicated",
                         test_file=direct[tid]["test_file"],
                         test_function=direct[tid]["test_function"],
                         line=direct[tid]["line"])
            n_impl += 1
        elif tid in PROXY_ALIASES:
            pa = PROXY_ALIASES[tid]
            entry.update(implemented=False, match_type="proxy_partial",
                         test_file=pa["test_file"],
                         test_function=pa["test_function"],
                         proxy_note=pa["note"])
            n_proxy += 1
        if tid in evidence_map:
            entry["evidence_path"] = evidence_map[tid]
        matrix[tid] = entry

    total = len(matrix)
    missing = total - n_impl - n_proxy
    by_prefix = {}
    for tid, e in matrix.items():
        pfx = tid.split("-")[0]
        st = by_prefix.setdefault(pfx, {"total": 0, "dedicated": 0, "proxy": 0})
        st["total"] += 1
        if e["match_type"] == "dedicated":
            st["dedicated"] += 1
        elif e["match_type"] == "proxy_partial":
            st["proxy"] += 1

    now = datetime.now(timezone(timedelta(hours=8)))
    report = {
        "meta": {
            "tool": "tools/ac_traceability.py",
            "generated_at": now.isoformat(timespec="seconds"),
            "repo_root": REPO_ROOT,
            "repo_head": git_head(),
            "plan_source": "/private/tmp/codex-test/方案.md",
            "plan_sha256": PLAN_SHA256,
            "catalog_integrity": "OK" if integrity_ok else "FAIL",
            "catalog_problems": problems,
            "plan_cross_check": plan_check,
            "scanned_files": scanned,
            "scan_roots": SCAN_ROOTS,
            "proxy_policy": "代理测试不冒充专属验收：implemented 仅在存在以该 ID 命名/标注的测试函数或用例时为 true",
        },
        "stats": {
            "total_ids": total,
            "dedicated_implemented": n_impl,
            "proxy_partial": n_proxy,
            "missing": missing,
            "dedicated_coverage_pct": round(100.0 * n_impl / total, 2) if total else 0.0,
            "dedicated_plus_proxy_pct": round(100.0 * (n_impl + n_proxy) / total, 2) if total else 0.0,
            "by_prefix": by_prefix,
        },
        "matrix": matrix,
    }

    out_path = args.json
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")

    # ---------------- 覆盖率统计输出 ----------------
    print("=" * 64)
    print("Codex 方案 §20 验收 ID 追踪矩阵（P0-10）")
    print(f"生成时间: {report['meta']['generated_at']}  HEAD: {report['meta']['repo_head'] or 'N/A'}")
    print(f"目录完整性: {report['meta']['catalog_integrity']}  "
          f"(冻结 {total} ID，期望 {EXPECTED_TOTAL})")
    if plan_check is not None:
        print(f"方案交叉校验(§20 集合等式): {'PASS' if not (plan_check.get('plan_only') or plan_check.get('frozen_only')) else 'FAIL'}"
              f"  方案侧 {plan_check.get('plan_ids_count')} vs 冻结 {plan_check.get('frozen_count')}")
        if not plan_check.get("ok"):
            print(f"  仅方案有: {plan_check.get('plan_only')}  仅冻结有: {plan_check.get('frozen_only')}")
        print(f"方案交叉校验(§20 逐 ID 语义比对): "
              f"{'PASS' if plan_check.get('semantic_ok') else 'FAIL'}"
              f"  解析表格行 {plan_check.get('semantic_rows_parsed')}")
        for p in (plan_check.get("semantic_problems") or [])[:5]:
            print(f"  §20 语义漂移: {p}")
        print(f"方案交叉校验(§25.1 映射展开+四列元数据): "
              f"{'PASS' if plan_check_251.get('ok') else 'FAIL'}"
              f"  展开 {plan_check_251.get('expanded_count')} vs 冻结 {plan_check_251.get('frozen_count')}")
        for p in (plan_check_251.get("problems") or [])[:5]:
            print(f"  §25.1 问题: {p}")
    elif args.plan and not os.path.isfile(args.plan):
        print(f"方案交叉校验: SKIP（{args.plan} 不存在，使用内置冻结目录 sha256 锚定）")
    print("-" * 64)
    print(f"总计测试 ID        : {total}")
    print(f"专属已实现          : {n_impl}  ({report['stats']['dedicated_coverage_pct']}%)")
    print(f"代理部分覆盖(不计实现): {n_proxy}")
    print(f"缺失                : {missing}")
    print(f"专属+代理覆盖参考   : {report['stats']['dedicated_plus_proxy_pct']}%")
    print("-" * 64)
    print(f"{'前缀':<8}{'总数':>4}{'专属':>6}{'代理':>6}")
    for pfx in sorted(by_prefix, key=lambda x: (-by_prefix[x]["total"], x)):
        st = by_prefix[pfx]
        print(f"{pfx:<8}{st['total']:>4}{st['dedicated']:>6}{st['proxy']:>6}")
    print("-" * 64)
    if n_impl:
        print("已实现 ID:", ", ".join(t for t in sorted(matrix) if matrix[t]["implemented"]))
    if n_proxy:
        print("代理覆盖 ID:", ", ".join(t for t in sorted(matrix)
                                        if matrix[t]["match_type"] == "proxy_partial"))
    print(f"输出: {os.path.relpath(out_path, REPO_ROOT)}  (扫描 {len(scanned)} 个测试文件)")
    print("=" * 64)

    if args.check and problems:
        for p in problems:
            print(f"INTEGRITY-FAIL: {p}", file=sys.stderr)
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()

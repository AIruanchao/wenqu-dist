#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# specs/tla/mutation_probes.sh —— G9-03 变异探针（TLC 可证伪性实证）
#
# 目的：证明双配置模型检查不是空转——对规约守卫做单点外科变异
#（跳段启动 / 放宽 run 终态 / 去掉 nonce 一次性 / 去掉 PASS-需-COMPLETED
# 门），TLC 必须当场变红（对应不变量 violated）。全部变异在 /tmp 副本上
# 执行，不触碰仓内规约正本。
#
# 变异清单（锚点为 wenqu_pipeline.tla 内唯一文本串，缺失/多义即失败）：
#   mut-A1_skip_stage    StartStage 去 CurStage=i 守卫     → NoSkipStages 红
#                        （cfg-A 七段下：后段可先于前段 PASSED 启动）
#   mut-A2_relax_terminal FinishSucceeded 去 AllPassedNow  → TerminalFinal 红
#                        （cfg-A 七段下：SUCCEEDED 而七段未全 PASSED）
#   mut-A3_nonce_replay  ConsumeRisk 去 nonceUsed[n]=0     → NonceOnceConsumed 红
#                        （同一审批原子二次消费=nonce 重放）
#   mut-A4_pass_gate     CompleteStage 去 ValidOutcome      → AttemptImmutable 红
#                        （归因复跑：仅 DoubleAxisNoWash 时 P_WASH 金丝雀红）
#   mut-B1_nonce_replay  同 mut-A3，跑 cfg-B（2 段×2 attempts 面的可证伪性）
#
# 用法：mutation_probes.sh [输出目录（默认 /tmp/g9-03-evidence）]
# 退出码：0=全部按预期变红；1=有变异意外绿/锚点失效/TLC 未跑。
# ---------------------------------------------------------------------------
set -u

BASEDIR=$(cd "$(dirname "$0")" && pwd)
JAR=${TLA2TOOLS_JAR:-"$BASEDIR/../../system/bin/tla2tools.jar"}
OUTDIR=${1:-/tmp/g9-03-evidence}
LOG="$OUTDIR/mutation-probes.log"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/wq-tla-mut.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUTDIR"
: > "$LOG"

if [ ! -f "$JAR" ]; then
    echo "FATAL: tla2tools.jar not found at $JAR" | tee -a "$LOG"
    exit 1
fi
command -v java >/dev/null 2>&1 || { echo "FATAL: java not on PATH" | tee -a "$LOG"; exit 1; }

# mutate <tla路径> <变异名> <锚点> <替换串>：锚点必须恰好出现一次
mutate() {
    python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import sys
path, name, anchor, repl = sys.argv[1:5]
with open(path, encoding="utf-8") as fh:
    text = fh.read()
n = text.count(anchor)
if n != 1:
    sys.exit(f"mutation {name}: anchor not unique (count={n})")
with open(path, "w", encoding="utf-8") as fh:
    fh.write(text.replace(anchor, repl))
PYEOF
}

# run_tlc <dir> <cfg名> <期望violated不变量> —— 输出 tee 进总日志
run_probe() {
    local dir="$1" cfg="$2" expect="$3"
    local out
    out=$(cd "$dir" && java -Xmx2g -cp "$JAR" tlc2.TLC -workers 1 \
          -config "$cfg" wenqu_pipeline.tla 2>&1)
    local rc=$?
    printf '%s\n' "$out" >> "$LOG"
    if printf '%s' "$out" | grep -q "Error: Invariant $expect is violated"; then
        echo "RED as expected (rc=$rc): $expect violated"
        return 0
    fi
    echo "UNEXPECTED GREEN (rc=$rc): expected $expect violation not found"
    return 1
}

PASS_ALL=0

# ---- 变异锚点（与 wenqu_pipeline.tla 正本逐字对应；漂移即 count!=1 失败）----
A_SKIP='    /\ CurStage = i
    /\ LastOf(i) # "RUNNING"'
A_SKIP_REPL='    /\ LastOf(i) # "RUNNING"'

A_TERM='    /\ AllPassedNow
    /\ rstate'"'"' = "SUCCEEDED"'
A_TERM_REPL='    /\ rstate'"'"' = "SUCCEEDED"'

A_NONCE='    /\ n \in RiskApprovals
    /\ nonceUsed[n] = 0'
A_NONCE_REPL='    /\ n \in RiskApprovals'

A_GATE='    /\ ValidOutcome(e, v)
'
A_GATE_REPL=''

probe() { # <变异名> <cfg> <期望> <锚点> <替换>
    local name="$1" cfg="$2" expect="$3" anchor="$4" repl="$5"
    local dir="$WORK/$name"
    mkdir -p "$dir"
    cp "$BASEDIR"/wenqu_pipeline.tla "$BASEDIR"/wenqu_pipeline_A.cfg \
       "$BASEDIR"/wenqu_pipeline_B.cfg "$dir"/
    if ! mutate "$dir/wenqu_pipeline.tla" "$name" "$anchor" "$repl"; then
        echo "=== mutation: $name ===" >> "$LOG"
        echo "FATAL: anchor drift for $name" | tee -a "$LOG"
        PASS_ALL=1
        return
    fi
    echo "=== mutation: $name (cfg=$cfg, expect=$expect) ===" >> "$LOG"
    echo "--- probe: $name (cfg=$cfg, expect: $expect violated)"
    if ! run_probe "$dir" "$cfg" "$expect"; then PASS_ALL=1; fi
}

echo "G9-03 mutation probes $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG"
echo "jar: $JAR ; workdir: $WORK" >> "$LOG"

probe mut-A1_skip_stage    wenqu_pipeline_A.cfg NoSkipStages      "$A_SKIP"  "$A_SKIP_REPL"
probe mut-A2_relax_terminal wenqu_pipeline_A.cfg TerminalFinal    "$A_TERM"  "$A_TERM_REPL"
probe mut-A3_nonce_replay  wenqu_pipeline_A.cfg NonceOnceConsumed "$A_NONCE" "$A_NONCE_REPL"
probe mut-A4_pass_gate     wenqu_pipeline_A.cfg AttemptImmutable  "$A_GATE"  "$A_GATE_REPL"
probe mut-B1_nonce_replay  wenqu_pipeline_B.cfg NonceOnceConsumed "$A_NONCE" "$A_NONCE_REPL"

# ---- 归因复跑：mut-A4 在仅含 DoubleAxisNoWash 的 cfg 下应报金丝雀 ----
ATTR="$WORK/mut-A4-pass-gate-attribution"
mkdir -p "$ATTR"
cp "$WORK/mut-A4_pass_gate/wenqu_pipeline.tla" "$ATTR"/
sed -e 's/^  TypeOK$//' -e 's/^  NoSkipStages$//' -e 's/^  PriorPassedGate$//' \
    -e 's/^  AttemptImmutable$//' -e 's/^  NonceOnceConsumed$//' \
    -e 's/^  TerminalFinal$//' "$BASEDIR/wenqu_pipeline_A.cfg" \
    > "$ATTR/wenqu_pipeline_A.cfg"
echo "=== attribution: mut-A4 with DoubleAxisNoWash-only cfg ===" >> "$LOG"
echo "--- probe: mut-A4 attribution (expect: DoubleAxisNoWash violated [P_WASH])"
if ! run_probe "$ATTR" wenqu_pipeline_A.cfg DoubleAxisNoWash; then PASS_ALL=1; fi

echo "================================================" >> "$LOG"
if [ "$PASS_ALL" = 0 ]; then
    echo "ALL MUTATION PROBES RED AS EXPECTED" | tee -a "$LOG"
    exit 0
fi
echo "SOME MUTATION PROBES UNEXPECTEDLY GREEN — see $LOG" | tee -a "$LOG"
exit 1

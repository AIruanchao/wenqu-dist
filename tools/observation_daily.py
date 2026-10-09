#!/usr/bin/env python3
"""W10 观察窗 + W9 shadow 每日采样器（只读，不改产品码，仓外落盘）。

W10 观察窗样本（~/.wenqu/observation/samples/YYYY-MM-DD.json）：
  host / repo HEAD / dirty / ci_latest_main / dashboard launchd state /
  7789 现役实例 health（/api/v1/health 优先，旧 /api/health 回退）/ 磁盘 used 占比 /
  容量闸（capacity_monitor.judge 真实采集判定；CRITICAL → capacity_gate=BLOCKED）
W9 shadow 时钟（~/.wenqu/observation/shadow/YYYY-MM-DD.json）：
  v2 语义（2026-10-09，八轮 identity=null 旧语义废止）：7789 已切模块化后，
  旧「7789 legacy vs 本仓影子」比对对象失效。改为「现役实例（7789）vs
  current 树新起临时实例」——从 ~/.wenqu/current/system/dashboard/server.py
  起随机端口临时实例（env 对齐生产：剥离 WENQU_HOME/WENQU_GATE_AGGREGATE，
  health 走投重定向至观察日志目录，杜绝影子实例副作用），就绪后抓双方
  /api/v1/health 做结构化比对：key 集合 + 剔除 generated_at 后的稳定字段
  逐字段相等性（policy_verdict/aggregate_outcome/counts/stations 等
  判定与 score 类字段全覆盖）；identity 记录两侧 server.py 文件 sha256
  （7789 侧经 lsof→PID→ps argv 解析现役脚本路径；current 侧取激活树），
  gate-aggregate 同源性以源文件 sha256 落样本佐证；finally 必杀影子进程。
  canary 字段：W9 到期收证准备——2026-10-10 00:00（本地）前 status=NOT_DUE；
  起 48h 窗口内累计统计 shadow 样本 compare.equal 计数（扫描 shadow/ 目录
  既有样本聚合，不凭空生成）。

设计约束：
  - 纯标准库；单探针失败记 null / error，绝不中断整体采样。
  - 文件保留 30 天，超期轮转删除；同日重跑覆盖当日文件（当日以最新样本为准）。
  - 结束 print 一行 JSON 摘要。
  - subprocess 一律参数列表 + shell=False；URL 用常量拼接（不用 f-string）。

注：modular server（system/dashboard/server.py）的 health 契约路径是
  /api/v1/health（未版本化 /api/health 已废止，返回 404 API_VERSION_REQUIRED）。
  7789 与影子实例两侧均优先 /api/v1/health 的 200 JSON；原始探测结果都会落盘。

P0-9/W8 适配（2026-10-08）：现役 7789 已从旧 legacy 单文件/可变树拷贝切到
  ~/.wenqu/current 不可变树上的 modular server（com.wenqu.dashboard plist 直指
  current symlink）——7789 的 health 契约路径同归 /api/v1/health。
  7789 探测改为优先 /api/v1/health，无 200 JSON 再退回 /api/health（旧实例
  兼容）；两条路径的原始结果均落盘。只读 GET 探测语义不变。

B5 容量闸接线（2026-10-09，采样器侧）：样本 disk 字段旁记 capacity_gate
  ——导入本仓 system/wenqu_core/capacity_monitor，collect_disk_sample 真实
  采集 home 挂载点后 CapacityMonitor.judge() 判定（默认规格 0.90 阈值 /
  2GiB 最小余量；观察采样无 §22 峰值预算，peak_budget=0）；severity=CRITICAL
  → capacity_gate=BLOCKED。导入失败如实记 error，绝不中断采样。
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import date, datetime, timedelta, timezone
from urllib import error as urlerror
from urllib import request as urlrequest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 不可变部署位（~/.wenqu/current）无 .git：git 探针按候选回退到真实仓
# （env 优先，其次脚本位置，最后开发仓默认路径）
if not os.path.isdir(os.path.join(REPO, ".git")):
    for _cand in (os.environ.get("WENQU_GIT_REPO"),
                  "/Users/maccc/Documents/wenqu-dist"):
        if _cand and os.path.isdir(os.path.join(_cand, ".git")):
            REPO = _cand
            break
OBS_ROOT = os.path.expanduser("~/.wenqu/observation")
SAMPLES_DIR = os.path.join(OBS_ROOT, "samples")
SHADOW_DIR = os.path.join(OBS_ROOT, "shadow")
LOGS_DIR = os.path.join(OBS_ROOT, "logs")
KEEP_DAYS = 30

# W9 shadow v2：影子实例改从不可变激活树起（与生产 7789 同源代码面）。
WENQU_HOME = os.path.expanduser("~/.wenqu")
CURRENT_TREE_ROOT = os.path.join(WENQU_HOME, "current")
CURRENT_SERVER = os.path.join(CURRENT_TREE_ROOT, "system", "dashboard", "server.py")
GATE_AGGREGATE_PATH = os.path.join(WENQU_HOME, "state", "gate-aggregate.json")
# health JSON 中的时变字段：两侧各自 GET 时刻不同必差，不参与相等性比对。
VOLATILE_HEALTH_FIELDS = ("generated_at",)

# W9 canary 窗口（本地墙钟）：2026-10-10 00:00 起 48h 累计计数。
CANARY_WINDOW_HOURS = 48
try:  # 本地时区锚点（模块导入期取一次，样本内落 ISO 串可审计）
    _CANARY_START = datetime(2026, 10, 10, 0, 0, 0).astimezone()
except (OSError, OverflowError, ValueError):
    _CANARY_START = datetime(2026, 10, 10, 0, 0, 0, tzinfo=timezone.utc)

UID = os.getuid()
HOST_LOCAL = "127.0.0.1"
LEGACY_PORT = 7789
LEGACY_BASE = "http://" + HOST_LOCAL + ":" + str(LEGACY_PORT)
# P0-9/W8：7789 现役已切 immutable modular server——health 契约路径为
# /api/v1/health；旧 /api/health 仅作 legacy 回退探测（只读语义不变）。
LEGACY_HEALTH_URL_V1 = LEGACY_BASE + "/api/v1/health"
LEGACY_HEALTH_URL = LEGACY_BASE + "/api/health"
DASHBOARD_LABEL = "com.wenqu.dashboard"
LAUNCHD_TARGET = "gui/" + str(UID) + "/" + DASHBOARD_LABEL
UA = "wenqu-observation/1.0"
HTTP_TIMEOUT = 8.0
GH_TIMEOUT = 45.0
SHADOW_READY_TIMEOUT = 15.0

# launchd 上下文 PATH 极简，gh/homebrew 工具需要显式兜底解析
_BIN_FALLBACK_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")

# 绕过任何 HTTP(S)_PROXY 环境变量：全部目标都是 localhost
_OPENER = urlrequest.build_opener(urlrequest.ProxyHandler({}))


def _log(msg):
    sys.stderr.write("[observation] " + msg + "\n")
    sys.stderr.flush()


def find_bin(name):
    found = shutil.which(name)
    if found:
        return found
    for d in _BIN_FALLBACK_DIRS:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def run_cmd(argv, timeout, cwd=None):
    """跑一条命令，永不抛异常。返回 {"returncode", "stdout", "stderr", "error"}。"""
    try:
        p = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return {
            "returncode": p.returncode,
            "stdout": (p.stdout or "").strip(),
            "stderr": (p.stderr or "").strip()[:500],
            "error": None,
        }
    except Exception as e:  # FileNotFoundError / TimeoutExpired / OSError
        return {
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": str(e)[:300],
        }


def http_get_json(url, timeout=HTTP_TIMEOUT):
    """GET 一个 URL 并解析 JSON，永不抛异常。返回 {"status", "json", "error"}。"""
    req = urlrequest.Request(url, headers={"Accept": "application/json", "User-Agent": UA})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            body = resp.read(262144).decode("utf-8", "replace")
            status = getattr(resp, "status", None) or resp.getcode()
        parsed = None
        if body:
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
        return {"status": status, "json": parsed, "error": None if parsed is not None else "body_not_json"}
    except urlerror.HTTPError as e:
        body = ""
        try:
            body = e.read(262144).decode("utf-8", "replace")
        except Exception:
            pass
        parsed = None
        try:
            parsed = json.loads(body) if body else None
        except ValueError:
            parsed = None
        return {"status": e.code, "json": parsed, "error": "http_" + str(e.code)}
    except Exception as e:
        return {"status": None, "json": None, "error": str(e)[:200]}


def http_status_only(url, timeout=2.0):
    """轻探：返回 HTTP 状态码 int；连接层失败返回 None（用于就绪轮询）。"""
    req = urlrequest.Request(url, headers={"User-Agent": UA})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return getattr(resp, "status", None) or resp.getcode()
    except urlerror.HTTPError as e:
        return e.code
    except Exception:
        return None


def safe(fn):
    """单探针兜底：任何异常转为 {"error": ...}，不中断采样。"""
    try:
        val = fn()
        return val if val is not None else {"error": "probe_returned_null"}
    except Exception as e:
        return {"error": str(e)[:300]}


# ---------------------------------------------------------------- W10 探针

def probe_host():
    uname_bin = find_bin("uname")
    if not uname_bin:
        return {"error": "uname not found"}
    r = run_cmd([uname_bin, "-a"], timeout=10)
    return r["stdout"] if r["returncode"] == 0 and r["stdout"] else {"error": r["error"] or ("rc=" + str(r["returncode"]) + " " + r["stderr"][:120])}


def probe_repo():
    git_bin = find_bin("git")
    if not git_bin:
        return {"error": "git not found"}
    # R7-OBS-SAMPLE-014：身份正源=fetch 后的 origin/main——不受共享工作树漂移/误删影响
    run_cmd([git_bin, "fetch", "origin", "main"], timeout=90, cwd=REPO)
    ident_r = run_cmd([git_bin, "rev-parse", "origin/main"], timeout=15, cwd=REPO)
    head_r = run_cmd([git_bin, "rev-parse", "HEAD"], timeout=15, cwd=REPO)
    dirty_r = run_cmd([git_bin, "status", "--porcelain"], timeout=15, cwd=REPO)
    head = head_r["stdout"] if head_r["returncode"] == 0 else None
    identity = ident_r["stdout"] if ident_r["returncode"] == 0 else None
    dirty_files = [ln for ln in dirty_r["stdout"].splitlines() if ln.strip()] if dirty_r["returncode"] == 0 else None
    return {
        "path": REPO,
        "identity": identity,
        "identity_error": None if identity else (ident_r["error"] or ident_r["stderr"][:200]),
        "worktree_head": head,
        "head_error": None if head else (head_r["error"] or head_r["stderr"][:200]),
        "dirty": (len(dirty_files) > 0) if dirty_files is not None else None,
        "dirty_files": dirty_files if dirty_files is not None else None,
        "dirty_error": None if dirty_files is not None else dirty_r["error"],
    }


def probe_ci_latest_main():
    gh_bin = find_bin("gh")
    if not gh_bin:
        return None
    r = run_cmd(
        [gh_bin, "run", "list", "--branch", "main", "--limit", "1",
         "--json", "status,conclusion,databaseId,createdAt,headSha,displayTitle,workflowName"],
        timeout=GH_TIMEOUT,
        cwd=REPO,
    )
    if r["returncode"] != 0 or not r["stdout"]:
        return {"error": r["error"] or ("rc=" + str(r["returncode"]) + " " + r["stderr"][:200])}
    try:
        runs = json.loads(r["stdout"])
    except ValueError:
        return {"error": "gh output not json"}
    if not isinstance(runs, list) or not runs:
        return {"error": "no runs returned"}
    return runs[0]


def probe_dashboard_launchd():
    launchctl_bin = find_bin("launchctl")
    if not launchctl_bin:
        return {"error": "launchctl not found"}
    r = run_cmd([launchctl_bin, "print", LAUNCHD_TARGET], timeout=15)
    if r["returncode"] != 0:
        return {"state": None, "returncode": r["returncode"], "error": r["error"] or r["stderr"][:200]}
    m = re.search(r"^\s*state\s*=\s*(\S+)", r["stdout"], re.MULTILINE)
    return {"state": m.group(1) if m else None, "returncode": 0, "error": None if m else "state line not found"}


def probe_legacy_health():
    """探测 7789 现役实例 health（只读 GET）。

    P0-9/W8 适配：现役 7789 已是 immutable modular server（契约路径
    /api/v1/health）。优先取 v1 的 200 JSON；无 200 JSON 时退回旧
    /api/health（legacy 实例兼容）。返回值带 path 标记实际命中路径，
    两条路径的原始状态码都随样本落盘（观测面完整，不丢事实）。
    """
    v1 = http_get_json(LEGACY_HEALTH_URL_V1)
    if v1.get("status") == 200 and isinstance(v1.get("json"), dict):
        return dict(v1, path="/api/v1/health")
    old = http_get_json(LEGACY_HEALTH_URL)
    if old.get("status") == 200 and isinstance(old.get("json"), dict):
        return dict(old, path="/api/health")
    return {"v1_raw": {"status": v1.get("status"), "error": v1.get("error")},
            "unversioned_raw": {"status": old.get("status"), "error": old.get("error")},
            "status": None, "json": None,
            "note": "7789 两路径均无 200 JSON（v1=契约路径；unversioned=legacy 回退）"}


def probe_disk():
    st = os.statvfs(os.path.expanduser("~"))
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    avail = st.f_bavail * st.f_frsize
    total = used + avail
    return {
        "mount": os.path.expanduser("~"),
        "used_bytes": used,
        "avail_bytes": avail,
        "used_pct": round(used * 100.0 / total, 1) if total > 0 else None,
    }


def probe_capacity_gate():
    """B5 容量闸接线（采样器侧）：真实采集 → capacity_monitor.judge() 判定。

    导入本仓 system/wenqu_core/capacity_monitor（纯 stdlib）；观察采样不做
    §22 迁移/发布峰值操作，peak_budget=0（比率阈值 0.90 / 最小余量 2GiB
    走默认产品契约规格）。severity=CRITICAL → capacity_gate=BLOCKED。
    导入/判定失败如实记 error，绝不中断整体采样。"""
    system_dir = os.path.join(REPO, "system")
    try:
        if system_dir not in sys.path:
            sys.path.insert(0, system_dir)
        from wenqu_core.capacity_monitor import CapacityMonitor, collect_disk_sample
    except Exception as e:
        return {"error": "wenqu_core.capacity_monitor import failed: " + str(e)[:200]}
    try:
        disk = collect_disk_sample(os.path.expanduser("~"))
        finding = CapacityMonitor().judge(disk)
        return {
            "capacity_gate": "BLOCKED" if finding["severity"] == "CRITICAL" else "OPEN",
            "code": finding["code"],
            "severity": finding["severity"],
            "message": finding["message"],
            "violations": finding["violations"],
            "used_ratio": finding["used_ratio"],
            "used_ratio_threshold": finding["used_ratio_threshold"],
            "headroom_bytes": finding["headroom_bytes"],
            "min_headroom_bytes": finding["min_headroom_bytes"],
            "peak_budget_bytes": finding["peak_budget_bytes"],
            "judged_at": finding["judged_at"],
            "sample": finding["sample"],
            "source": "wenqu_core.capacity_monitor.judge(collect_disk_sample(~), peak_budget=0)",
        }
    except Exception as e:
        return {"error": "capacity judge failed: " + str(e)[:200]}


# ---------------------------------------------------------------- W9 shadow v2

def pick_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((HOST_LOCAL, 0))
        return s.getsockname()[1]
    finally:
        s.close()


def stop_process_tree(proc):
    """必杀：先 SIGTERM 进程组，3s 不退再 SIGKILL。返回终止方式。"""
    if proc.poll() is not None:
        return "already_exited_rc=" + str(proc.returncode)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except OSError:
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=3)
        return "term"
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        return "kill"


def sha256_file(path):
    """只读哈希；不可读/缺失返回 None（如实，不猜）。"""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(262144), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def probe_live_identity():
    """现役 7789 实例身份：lsof 找监听 PID → ps 取 argv 解析实际执行的
    server.py 路径 → 文件 sha256；lsof cwd（launchd 解析 current 后的真实
    release 树）作辅助证据（current symlink 切换后未重启的陈旧进程可由
    cwd 与 health 行为差异暴露）。任一步失败只记 error，不抛。"""
    out = {
        "pid": None,
        "argv_script": None,
        "argv_script_sha256": None,
        "cwd": None,
        "cwd_server_py": None,
        "cwd_server_sha256": None,
        "error": None,
    }
    lsof = find_bin("lsof")
    ps = find_bin("ps")
    if not lsof or not ps:
        out["error"] = "lsof/ps not found (lsof=%s ps=%s)" % (lsof, ps)
        return out
    r = run_cmd([lsof, "-nP", "-tiTCP:" + str(LEGACY_PORT), "-sTCP:LISTEN"], timeout=10)
    pids = [ln.strip() for ln in r["stdout"].splitlines() if ln.strip().isdigit()]
    if not pids:
        out["error"] = ("no listener on port " + str(LEGACY_PORT)
                        + (": " + (r["error"] or r["stderr"][:120]) if (r["error"] or r["stderr"]) else ""))
        return out
    pid = pids[0]
    out["pid"] = int(pid)
    # cwd：lsof 全量输出中 " cwd " 行的最后一列（macOS 实测形态）
    cw = run_cmd([lsof, "-nP", "-p", pid], timeout=10)
    for ln in cw["stdout"].splitlines():
        if " cwd " in ln:
            parts = ln.split()
            if len(parts) >= 2:
                out["cwd"] = parts[-1]
                cand = os.path.join(parts[-1], "system", "dashboard", "server.py")
                out["cwd_server_py"] = cand
                out["cwd_server_sha256"] = sha256_file(cand)
            break
    # argv：ps command= 输出中第一个 *server.py 参数即现役脚本
    cmd = run_cmd([ps, "-p", pid, "-o", "command="], timeout=10)
    try:
        argv = shlex.split(cmd["stdout"]) if cmd["returncode"] == 0 else []
    except ValueError:
        argv = cmd["stdout"].split()
    for a in argv:
        if a.endswith("server.py"):
            out["argv_script"] = a
            out["argv_script_sha256"] = sha256_file(a)
            break
    if out["argv_script"] is None and out["cwd"] is None:
        out["error"] = "cannot resolve running script (ps=" + cmd["stdout"][:160] + ")"
    return out


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def compare_health(live, shadow):
    """W9 shadow v2 结构化比对：现役实例 vs current 树临时实例。

    口径：
    - key 集合相等性（全字段；两侧代码/契约漂移直接暴露为 only_* 列表）；
    - 稳定字段逐字段相等性：剔除 VOLATILE_HEALTH_FIELDS（generated_at）后
      canonical JSON 对比，差异字段逐一列 {field, live, shadow}——
      policy_verdict / aggregate_outcome / technical_eligible / counts /
      stations / cli_exit 等 score 类与判定类字段全在其中显式覆盖；
    - policy_verdict / aggregate_outcome 单独镜像 equality（判定代表字段，
      便于 W9 到期收证时直接消费）。
    任一侧无 200 JSON → 全量记 null + note（不可比时不猜），但不再产出
    旧 v1 的整包 null：可比对字段一定给出布尔结论。"""
    out = {
        "schema": "w9-shadow-compare-v2",
        "basis": "live-7789 vs current-tree temp instance, /api/v1/health",
        "live_status": live.get("status") if isinstance(live, dict) else None,
        "shadow_status": shadow.get("status") if isinstance(shadow, dict) else None,
        "key_sets_equal": None,
        "only_live": None,
        "only_shadow": None,
        "stable_fields_equal": None,
        "differing_fields": None,
        "live_policy_verdict": None,
        "shadow_policy_verdict": None,
        "policy_verdict_equal": None,
        "live_aggregate_outcome": None,
        "shadow_aggregate_outcome": None,
        "aggregate_outcome_equal": None,
        "equal": None,
        "note": None,
    }
    lj = live.get("json") if isinstance(live, dict) and live.get("status") == 200 else None
    sj = shadow.get("json") if isinstance(shadow, dict) and shadow.get("status") == 200 else None
    if not isinstance(lj, dict):
        out["note"] = "7789 /api/v1/health 无 200 JSON（现役实例不可观测），无法比对"
        return out
    if not isinstance(sj, dict):
        out["live_policy_verdict"] = lj.get("policy_verdict") if isinstance(lj.get("policy_verdict"), str) else None
        out["live_aggregate_outcome"] = lj.get("aggregate_outcome") if isinstance(lj.get("aggregate_outcome"), str) else None
        out["note"] = "current 树临时实例 health 无 200 JSON（影子未就绪/启动失败），无法比对"
        return out
    lk = set(lj.keys())
    sk = set(sj.keys())
    out["only_live"] = sorted(lk - sk)
    out["only_shadow"] = sorted(sk - lk)
    out["key_sets_equal"] = lk == sk
    nonvol_only = [k for k in (lk ^ sk) if k not in VOLATILE_HEALTH_FIELDS]
    diffs = []
    for k in sorted(lk & sk):
        if k in VOLATILE_HEALTH_FIELDS:
            continue
        if _canonical(lj.get(k)) != _canonical(sj.get(k)):
            diffs.append({"field": k, "live": lj.get(k), "shadow": sj.get(k)})
    out["differing_fields"] = diffs
    out["stable_fields_equal"] = (not diffs) and (not nonvol_only)
    for side, doc, pkey, okey in (("live", lj, "live_policy_verdict", "live_aggregate_outcome"),
                                  ("shadow", sj, "shadow_policy_verdict", "shadow_aggregate_outcome")):
        out[pkey] = doc.get("policy_verdict") if isinstance(doc.get("policy_verdict"), str) else None
        out[okey] = doc.get("aggregate_outcome") if isinstance(doc.get("aggregate_outcome"), str) else None
    if out["live_policy_verdict"] is not None and out["shadow_policy_verdict"] is not None:
        out["policy_verdict_equal"] = out["live_policy_verdict"] == out["shadow_policy_verdict"]
    if out["live_aggregate_outcome"] is not None and out["shadow_aggregate_outcome"] is not None:
        out["aggregate_outcome_equal"] = out["live_aggregate_outcome"] == out["shadow_aggregate_outcome"]
    out["equal"] = out["stable_fields_equal"]
    out["note"] = (
        "稳定字段全等（剔除 %s）——现役实例与 current 树临时实例行为一致" % (VOLATILE_HEALTH_FIELDS,)
        if out["equal"]
        else "存在稳定字段/键集差异——现役实例与 current 树存在代码或数据漂移，逐字段见 differing_fields/only_*"
    )
    return out


def probe_shadow():
    """W9 shadow v2：current 树起临时实例 vs 7789 现役实例，结构化比对。

    影子实例 env 对齐生产（launchd com.wenqu.dashboard 不设 WENQU_HOME/
    WENQU_GATE_AGGREGATE/WENQU_HEALTH_HISTORY）：剥离前两者保证 health 同源
    于 ~/.wenqu/state/gate-aggregate.json；health 走投重定向到观察日志目录，
    影子实例零共享文件副作用。finally 必杀影子进程（进程组）。"""
    if not os.path.isfile(CURRENT_SERVER):
        return {"error": "current-tree server.py not found: " + CURRENT_SERVER
                        + "（激活链缺失——影子实例无从起）"}
    port = pick_free_port()
    base_url = "http://" + HOST_LOCAL + ":" + str(port)
    ping_url = base_url + "/api/v1/ping"
    v1_health_url = base_url + "/api/v1/health"
    unversioned_health_url = base_url + "/api/health"
    today_str = date.today().isoformat()
    server_log_path = os.path.join(LOGS_DIR, "shadow-server-" + today_str + ".log")

    result = {
        "port": port,
        "server_pid": None,
        "server_py": CURRENT_SERVER,
        "server_py_realpath": os.path.realpath(CURRENT_SERVER),
        "ready": False,
        "ready_seconds": None,
        "server_log": server_log_path,
        "terminated": None,
    }
    # env：剥离会影响 health 正源解析的变量；走投重定向防共享文件写入
    env = {k: v for k, v in os.environ.items()
           if k not in ("WENQU_HOME", "WENQU_GATE_AGGREGATE", "WENQU_HEALTH_HISTORY")}
    env["WENQU_HEALTH_HISTORY"] = os.path.join(
        LOGS_DIR, "shadow-health-history-" + today_str + ".jsonl")
    logf = open(server_log_path, "ab")
    try:
        proc = subprocess.Popen(
            [sys.executable, CURRENT_SERVER, "--port", str(port)],
            start_new_session=True,
            stdout=logf,
            stderr=subprocess.STDOUT,
            cwd=CURRENT_TREE_ROOT,
            env=env,
        )
        result["server_pid"] = proc.pid
        t0 = time.monotonic()
        while (time.monotonic() - t0) < SHADOW_READY_TIMEOUT:
            if proc.poll() is not None:
                result["ready_error"] = "server exited early rc=" + str(proc.returncode)
                break
            code = http_status_only(ping_url, timeout=2.0)
            if code is not None:
                result["ready"] = True
                result["ready_http"] = code
                result["ready_seconds"] = round(time.monotonic() - t0, 2)
                break
            time.sleep(0.5)
        else:
            result["ready_error"] = "not ready within " + str(int(SHADOW_READY_TIMEOUT)) + "s"

        live = probe_legacy_health()
        v1_health = http_get_json(v1_health_url)
        unversioned_health = http_get_json(unversioned_health_url)

        # 影子侧比对主源：/api/v1/health 200 JSON；无 200 时保留原始结果
        # （404/503 结构化错误态），如实观测。
        shadow_health = v1_health
        if not (v1_health.get("status") == 200 and isinstance(v1_health.get("json"), dict)):
            if unversioned_health.get("status") == 200 and isinstance(unversioned_health.get("json"), dict):
                shadow_health = unversioned_health

        result["shadow_health"] = shadow_health
        result["shadow_health_path"] = "/api/v1/health" if shadow_health is v1_health else "/api/health"
        result["shadow_health_v1_raw"] = {"status": v1_health.get("status"), "error": v1_health.get("error")}
        result["shadow_health_unversioned_raw"] = {"status": unversioned_health.get("status"), "error": unversioned_health.get("error")}
        result["live_health"] = live

        # identity：两侧文件 hash（7789 现役脚本 vs current 激活树脚本）
        live_ident = probe_live_identity()
        shadow_sha = sha256_file(CURRENT_SERVER)
        result["identity"] = {
            "live": live_ident,
            "shadow": {
                "server_py": CURRENT_SERVER,
                "realpath": os.path.realpath(CURRENT_SERVER),
                "sha256": shadow_sha,
            },
            "file_hash_equal": (
                live_ident.get("argv_script_sha256") == shadow_sha
                if (live_ident.get("argv_script_sha256") and shadow_sha) else None
            ),
            "note": "file_hash_equal=None 表示任一侧 hash 不可得（如实不可比，不猜）",
        }

        # gate-aggregate 同源性：两侧 health 的共同正源快照（sha+size+mtime）
        try:
            gst = os.stat(GATE_AGGREGATE_PATH)
            result["gate_aggregate_source"] = {
                "path": GATE_AGGREGATE_PATH,
                "sha256": sha256_file(GATE_AGGREGATE_PATH),
                "size": gst.st_size,
                "mtime": datetime.fromtimestamp(gst.st_mtime, tz=timezone.utc).isoformat(),
                "note": "两侧 /api/v1/health 的同源正源（WENQU_GATE_AGGREGATE 均未设，同走默认路径）",
            }
        except OSError as e:
            result["gate_aggregate_source"] = {"path": GATE_AGGREGATE_PATH, "error": str(e)[:200]}

        result["compare"] = compare_health(live, shadow_health)
    finally:
        if result.get("server_pid") is not None:
            result["terminated"] = stop_process_tree(proc)
        logf.close()
    return result


def build_canary(current_equal, now_dt=None):
    """W9 canary 窗口状态（W9 到期收证准备）。

    - 2026-10-10 00:00（本地）前：status=NOT_DUE，计数 null（未到期不计数）；
    - 起 48h 窗口内：IN_WINDOW，扫描 shadow/ 目录既有样本聚合 compare.equal
      累计计数（equal/mismatch/not_comparable 三分类 + 样本时间跨度）；
    - 窗口关闭后：CLOSED（末次封口计数，同样只来自已落盘样本）。
    current_equal 为本样本自身 compare.equal（True/False/None）——计入窗口
    内累计。计数只来自已落盘样本 + 本样本，绝不凭空生成。"""
    now_dt = now_dt or datetime.now().astimezone()
    start = _CANARY_START
    end = start + timedelta(hours=CANARY_WINDOW_HOURS)
    out = {
        "window_hours": CANARY_WINDOW_HOURS,
        "start_at": start.isoformat(),
        "end_at": end.isoformat(),
        "status": None,
        "equal_count": None,
        "mismatch_count": None,
        "not_comparable_count": None,
        "scanned_files": None,
        "first_sample_at": None,
        "last_sample_at": None,
        "note": None,
    }
    if now_dt < start:
        out["status"] = "NOT_DUE"
        out["note"] = "canary 窗口未到期（" + start.isoformat() + " 起 48h）；当前只积累 shadow 样本，计数自窗口开启起算"
        return out
    out["status"] = "IN_WINDOW" if now_dt < end else "CLOSED"
    start_u = start.astimezone(timezone.utc)
    end_u = end.astimezone(timezone.utc)
    eq = mm = nc = 0
    first_at = last_at = None
    scanned = 0
    try:
        names = sorted(os.listdir(SHADOW_DIR))
    except OSError:
        names = []

    def _acc(cmp_):
        nonlocal eq, mm, nc
        if isinstance(cmp_, dict) and cmp_.get("schema") == "w9-shadow-compare-v2":
            v = cmp_.get("equal")
            if v is True:
                eq += 1
                return
            if v is False:
                mm += 1
                return
        nc += 1

    for name in names:
        if not name.endswith(".json"):
            continue
        path = os.path.join(SHADOW_DIR, name)
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError):
            continue  # 损坏样本不计数不中断
        ts = doc.get("collected_at")
        dt = None
        try:
            dt = datetime.fromisoformat(str(ts)) if ts else None
            if dt is not None and dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            dt = None
        if dt is None or not (start_u <= dt.astimezone(timezone.utc) <= end_u):
            continue
        scanned += 1
        _acc(doc.get("shadow", {}).get("compare") if isinstance(doc.get("shadow"), dict) else None)
        iso = dt.astimezone(timezone.utc).isoformat()
        first_at = iso if first_at is None or iso < first_at else first_at
        last_at = iso if last_at is None or iso > last_at else last_at
    # 本样本自身计入窗口累计（尚未落盘，先并入）
    scanned += 1
    _acc({"schema": "w9-shadow-compare-v2", "equal": current_equal})
    now_iso = now_dt.astimezone(timezone.utc).isoformat()
    first_at = first_at if first_at is not None and first_at < now_iso else (first_at or now_iso)
    last_at = now_iso if last_at is None or now_iso > last_at else last_at
    out["equal_count"] = eq
    out["mismatch_count"] = mm
    out["not_comparable_count"] = nc
    out["scanned_files"] = scanned
    out["first_sample_at"] = first_at
    out["last_sample_at"] = last_at
    out["note"] = "窗口内 shadow 样本 compare.equal 累计计数（扫描 " + SHADOW_DIR + " 既有样本 + 本样本聚合）"
    return out


# ---------------------------------------------------------------- 落盘与轮转

def write_json_atomic(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp, path)


def rotate(dirpath):
    """按文件名日期删除超过 KEEP_DAYS 天的样本。"""
    cutoff = date.today() - timedelta(days=KEEP_DAYS)
    removed = []
    try:
        names = os.listdir(dirpath)
    except OSError:
        return removed
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            d = datetime.strptime(name[:-len(".json")], "%Y-%m-%d").date()
        except ValueError:
            continue
        if d < cutoff:
            try:
                os.remove(os.path.join(dirpath, name))
                removed.append(name)
            except OSError:
                pass
    return removed


def main():
    for d in (SAMPLES_DIR, SHADOW_DIR, LOGS_DIR):
        os.makedirs(d, exist_ok=True)
    today = date.today().isoformat()
    now_iso = datetime.now(timezone.utc).isoformat()

    repo_info = safe(probe_repo)

    sample = {
        "window": "W10-observation",
        "day_index_note": "14 天观察窗，当日启动（launchd 每日 09:05 触发）",
        "collected_at": now_iso,
        "host": safe(probe_host),
        "repo": repo_info,
        "ci_latest_main": safe(probe_ci_latest_main),
        "dashboard_launchd": safe(probe_dashboard_launchd),
        "legacy_health": safe(probe_legacy_health),
        "disk": safe(probe_disk),
        "capacity_gate": safe(probe_capacity_gate),  # B5：disk 旁容量闸（CRITICAL→BLOCKED）
    }

    shadow_probe = safe(probe_shadow)
    shadow = {
        "window": "W9-shadow-clock",
        "collected_at": now_iso,
        "shadow": shadow_probe,
        # canary：W9 到期收证——未到期 NOT_DUE；2026-10-10 起 48h compare.equal 累计
        "canary": build_canary(shadow_probe.get("compare", {}).get("equal")
                               if isinstance(shadow_probe, dict) else None),
    }

    # R7-OBS-SAMPLE-014：样本永不覆盖——同日追加时间戳后缀，首样本一经落盘即保全
    def _no_clobber(base, today_str, payload):
        path = os.path.join(base, today_str + ".json")
        if os.path.isfile(path):
            stamp = time.strftime("%H%M%S")
            path = os.path.join(base, today_str + "-" + stamp + ".json")
            payload = dict(payload, append_note="same-day append; identity 见 repo.identity")
        write_json_atomic(path, payload)
        return path

    sample_path = _no_clobber(SAMPLES_DIR, today, sample)
    shadow_path = _no_clobber(SHADOW_DIR, today, shadow)
    rotate(SAMPLES_DIR)
    rotate(SHADOW_DIR)

    ci = sample["ci_latest_main"]
    sh = shadow["shadow"]
    cmp_ = sh.get("compare") if isinstance(sh, dict) else None
    ident = sh.get("identity") if isinstance(sh, dict) else None
    cap = sample["capacity_gate"]
    summary = {
        "ok": True,
        "sample_path": sample_path,
        "shadow_path": shadow_path,
        "ci_latest_main": (ci.get("status") + "/" + str(ci.get("conclusion")) + " run=" + str(ci.get("databaseId"))) if isinstance(ci, dict) and ci.get("status") else (ci if isinstance(ci, dict) else None),
        "shadow_compare_equal": cmp_.get("equal") if isinstance(cmp_, dict) else None,
        "shadow_compare": cmp_,
        "shadow_identity_file_hash_equal": ident.get("file_hash_equal") if isinstance(ident, dict) else None,
        "shadow_ready": sh.get("ready") if isinstance(sh, dict) else None,
        "canary_status": shadow["canary"].get("status") if isinstance(shadow.get("canary"), dict) else None,
        "dashboard_launchd_state": sample["dashboard_launchd"].get("state") if isinstance(sample["dashboard_launchd"], dict) else None,
        "disk_used_pct": sample["disk"].get("used_pct") if isinstance(sample["disk"], dict) else None,
        "capacity_gate": cap.get("capacity_gate") if isinstance(cap, dict) else None,
        "capacity_code": cap.get("code") if isinstance(cap, dict) else None,
        "repo_head": repo_info.get("worktree_head") if isinstance(repo_info, dict) else None,
        "repo_dirty": repo_info.get("dirty") if isinstance(repo_info, dict) else None,
    }
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()

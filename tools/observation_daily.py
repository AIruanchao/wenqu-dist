#!/usr/bin/env python3
"""W10 观察窗 + W9 shadow 采样器（只读探测，仓外落盘）——G9-02 v2。

v2（2026-10-09，G9-02：O_EXCL、hash chain、动态窗口）：
  - 样本文件名 = UTC 纳秒紧凑串 + 随机片段（`YYYYMMDDTHHMMSSnnnnnnnnn-<hex8>.json`），
    创建一律 `os.open(O_CREAT|O_EXCL|O_NOFOLLOW)`——碰撞/预置 symlink
    fail-visible（错误记录落 errors/，进程 rc1；绝不 os.replace 覆盖、
    绝不跟随 symlink、绝不静默跳过）（R8-OBS-COLLISION-016）。
  - 每条样本记录 hash chain 字段：epoch_id / sequence / prev_sha256 /
    sample_sha256 / release_sha / observer_sha / scheduler_config_sha；
    首条 prev=GENESIS(0*64)。链头读取在 samples/.chain.lock（flock）内完成。
  - 动态窗口：窗口起点不再是任何硬编码日期——T0=首条合格样本时刻，
    登记于 <root>/windows/<window_id>.json sealed manifest（见
    tools/window_manifest.py）；W9 canary 锚点同为 T0。
  - identity fail-visible（R8-OBS-NOGIT-015）：WENQU_GIT_REPO 一经设置即
    权威——指向不存在/非 git 路径时拒绝静默回退，样本 qualified=false +
    显式 identity_error + fallback_refused=true，进程 rc1。
  - 进程 rc 契约：0=合格样本落盘；1=落盘但样本不合格（identity/provenance
    缺失）或创建碰撞/symlink 失败；3=证据环境错误（根不可写、manifest
    歧义等）。scheduler 侧 expected_exit_set=(0,)：rc1 → COMPLETED/FAIL →
    CRITICAL 通知（fail-visible 接线）。
  - rotation：识别新旧两代命名；当前窗口（active epoch）证据绝不删除。

W9 shadow v2 语义（2026-10-09，八轮 identity=null 旧语义废止）不变：
「现役实例（7789）vs current 树新起临时实例」结构化比对，详见
probe_shadow/compare_health；shadow 文件同样走 O_EXCL 不可覆盖路径
（schema=obs-shadow-v2，携带 epoch_id/window_id 供 rotation 保护）。

设计约束：纯标准库；单探针失败记 null/error，绝不中断整体采样；
subprocess 一律参数列表 + shell=False；测试经 WENQU_OBSERVATION_ROOT /
WENQU_OBS_PROBE_MODE=light / tmp HOME 注入，绝不写真实 ~/.wenqu。
"""
import fcntl
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
import uuid
from datetime import date, datetime, timedelta, timezone
from urllib import error as urlerror
from urllib import request as urlrequest

_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)
import window_manifest as wm  # noqa: E402  动态窗口 manifest 单一正源

REPO = os.path.dirname(_TOOLS_DIR)  # 代码/导入正源（脚本所在树）
# ---------------------------------------------------------------- git 身份仓解析
_DEV_REPO_FALLBACK = os.environ.get("WENQU_DEV_REPO_FALLBACK",
                                    "/Users/maccc/Documents/wenqu-dist")


def _is_git_worktree(path):
    """真 git 仓：目录存在且含 .git（普通仓=目录；worktree=文件）。"""
    if not path or not os.path.isdir(path):
        return False
    return os.path.exists(os.path.join(path, ".git"))


def resolve_repo():
    """git 探针身份仓解析（每次调用重算，不缓存 env）。

    WENQU_GIT_REPO 一经设置即权威（R8-OBS-NOGIT-015 remediation）：
      - 合法 git 仓 → 使用之（repo_source=env）；
      - 无效（不存在/非 git）→ 拒绝静默回退（repo_source=env_invalid，
        fallback_refused=True）——后续 git 探针全部显式报错。
    未设置：脚本所在树是 git 仓 → 用之；否则受控开发仓兜底；再否则
    无 git 可用（identity_error 如实记录）。"""
    env_repo = os.environ.get("WENQU_GIT_REPO")
    if env_repo:
        if _is_git_worktree(env_repo):
            return env_repo, "env", None
        return env_repo, "env_invalid", env_repo
    if _is_git_worktree(REPO):
        return REPO, "script", None
    if _is_git_worktree(_DEV_REPO_FALLBACK):
        return _DEV_REPO_FALLBACK, "dev_default", None
    return REPO, "none", None


def observation_root():
    """观察证据根（env 可注入；生产=~/.wenqu/observation）。"""
    return (os.environ.get("WENQU_OBSERVATION_ROOT")
            or os.path.expanduser("~/.wenqu/observation"))


def samples_dir(root=None):
    return os.path.join(root or observation_root(), "samples")


def shadow_dir(root=None):
    return os.path.join(root or observation_root(), "shadow")


def errors_dir(root=None):
    return os.path.join(root or observation_root(), "errors")


LOGS_DIR = os.path.join(observation_root(), "logs")
KEEP_DAYS = 30

# ---------------------------------------------------------------- v2 契约常量
SAMPLE_SCHEMA = "obs-sample-v2"
SHADOW_SCHEMA = "obs-shadow-v2"
GENESIS_SHA = "0" * 64
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
# 新命名：UTC 纳秒紧凑串 + uuid 片段（字典序=时间序；30 天 rotation 可解析）
NEW_SAMPLE_NAME_RE = r"^(\d{8})T\d{15}-[0-9a-f]{8}\.json$"
_NEW_NAME_RE = re.compile(NEW_SAMPLE_NAME_RE)
# 旧命名（legacy，仅供 rotation 识别）：YYYY-MM-DD[-HHMMSS].json（本地日期）
_LEGACY_NAME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:-\d{6})?\.json$")

# W9 canary 窗缺省时长（小时）；锚点=窗口 manifest 的 t0（动态，非硬编码日期）
CANARY_WINDOW_HOURS = 48.0

UID = os.getuid()
HOST_LOCAL = "127.0.0.1"
LEGACY_PORT = 7789
LEGACY_BASE = "http://" + HOST_LOCAL + ":" + str(LEGACY_PORT)
LEGACY_HEALTH_URL_V1 = LEGACY_BASE + "/api/v1/health"
LEGACY_HEALTH_URL = LEGACY_BASE + "/api/health"
DASHBOARD_LABEL = "com.wenqu.dashboard"
LAUNCHD_TARGET = "gui/" + str(UID) + "/" + DASHBOARD_LABEL
UA = "wenqu-observation/2.0"
HTTP_TIMEOUT = 8.0
GH_TIMEOUT = 45.0
SHADOW_READY_TIMEOUT = 15.0

WENQU_HOME = os.path.expanduser("~/.wenqu")
CURRENT_TREE_ROOT = os.path.join(WENQU_HOME, "current")
CURRENT_SERVER = os.path.join(CURRENT_TREE_ROOT, "system", "dashboard", "server.py")
GATE_AGGREGATE_PATH = os.path.join(WENQU_HOME, "state", "gate-aggregate.json")
VOLATILE_HEALTH_FIELDS = ("generated_at",)

_BIN_FALLBACK_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")
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
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return {
            "returncode": p.returncode,
            "stdout": (p.stdout or "").strip(),
            "stderr": (p.stderr or "").strip()[:500],
            "error": None,
        }
    except Exception as e:  # FileNotFoundError / TimeoutExpired / OSError
        return {"returncode": None, "stdout": "", "stderr": "",
                "error": str(e)[:300]}


def http_get_json(url, timeout=HTTP_TIMEOUT):
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
    return r["stdout"] if r["returncode"] == 0 and r["stdout"] else {
        "error": r["error"] or ("rc=" + str(r["returncode"]) + " " + r["stderr"][:120])}


def probe_repo():
    """git 身份探针（R7-OBS-SAMPLE-014 + G9-02 E fail-visible）。

    身份正源 = fetch 后的 origin/main；WENQU_GIT_REPO 无效时拒绝静默回退
    （fallback_refused=True，identity=None + 显式 identity_error）——绝不
    把 identity=null 的样本混进合格分母。"""
    git_bin = find_bin("git")
    base = {
        "worktree_head": None, "head_error": None,
        "dirty": None, "dirty_files": None, "dirty_error": None,
    }
    repo_path, source, refused = resolve_repo()
    out = dict(base, path=repo_path, repo_source=source,
               identity=None, identity_error=None,
               fallback_refused=bool(refused))
    if not git_bin:
        out["identity_error"] = "git not found"
        return out
    if refused:
        out["identity_error"] = (
            "WENQU_GIT_REPO invalid (not a git worktree): " + refused
            + "；silent fallback refused (G9-02 identity fail-visible)")
        out["head_error"] = "repo invalid; git probes skipped"
        return out
    run_cmd([git_bin, "fetch", "origin", "main"], timeout=90, cwd=repo_path)
    ident_r = run_cmd([git_bin, "rev-parse", "origin/main"], timeout=15, cwd=repo_path)
    head_r = run_cmd([git_bin, "rev-parse", "HEAD"], timeout=15, cwd=repo_path)
    dirty_r = run_cmd([git_bin, "status", "--porcelain"], timeout=15, cwd=repo_path)
    head = head_r["stdout"] if head_r["returncode"] == 0 else None
    identity = ident_r["stdout"] if ident_r["returncode"] == 0 else None
    dirty_files = [ln for ln in dirty_r["stdout"].splitlines() if ln.strip()] \
        if dirty_r["returncode"] == 0 else None
    out.update({
        "identity": identity,
        "identity_error": None if identity else (ident_r["error"] or ident_r["stderr"][:200]),
        "worktree_head": head,
        "head_error": None if head else (head_r["error"] or head_r["stderr"][:200]),
        "dirty": (len(dirty_files) > 0) if dirty_files is not None else None,
        "dirty_files": dirty_files,
        "dirty_error": None if dirty_files is not None else dirty_r["error"],
    })
    return out


def probe_ci_latest_main():
    gh_bin = find_bin("gh")
    if not gh_bin:
        return None
    repo_path, _src, _ref = resolve_repo()
    r = run_cmd(
        [gh_bin, "run", "list", "--branch", "main", "--limit", "1",
         "--json", "status,conclusion,databaseId,createdAt,headSha,displayTitle,workflowName"],
        timeout=GH_TIMEOUT, cwd=repo_path,
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
        return {"state": None, "returncode": r["returncode"],
                "error": r["error"] or r["stderr"][:200]}
    m = re.search(r"^\s*state\s*=\s*(\S+)", r["stdout"], re.MULTILINE)
    return {"state": m.group(1) if m else None, "returncode": 0,
            "error": None if m else "state line not found"}


def probe_legacy_health():
    """探测 7789 现役实例 health（只读 GET；契约路径 /api/v1/health）。"""
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
    """B5 容量闸接线（采样器侧）：真实采集 → capacity_monitor.judge() 判定。"""
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


def observer_sha():
    """采样器自身文件 sha256（chain 的 observer_sha 正源）。"""
    return sha256_file(os.path.abspath(__file__)) or GENESIS_SHA


def resolve_release_sha():
    """release 身份：env 权威 → current symlink（releases/<sha>/tree）。"""
    v = os.environ.get("WENQU_RELEASE_SHA")
    if v:
        return v if SHA1_RE.match(v) else None
    try:
        target = os.path.realpath(os.path.join(
            os.environ.get("WENQU_HOME", WENQU_HOME), "current"))
        m = re.search(r"([0-9a-f]{40})(?:/tree)?$", target)
        if m:
            return m.group(1)
    except OSError:
        pass
    return None


def resolve_scheduler_config_sha():
    """scheduler 配置面 hash：env 指定文件 → launchd plist。缺失= None
    （样本不合格，fail-visible——不猜）。"""
    p = os.environ.get("WENQU_SCHEDULER_CONFIG")
    if not p:
        p = os.path.expanduser("~/Library/LaunchAgents/com.wenqu.scheduler.plist")
    return sha256_file(p)


def probe_live_identity():
    """现役 7789 实例身份（lsof→PID→ps argv→server.py sha256）。"""
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
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def compare_health(live, shadow):
    """W9 shadow v2 结构化比对：现役实例 vs current 树临时实例。"""
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
    """W9 shadow v2：current 树起临时实例 vs 7789 现役实例，结构化比对。"""
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
        shadow_health = v1_health
        if not (v1_health.get("status") == 200 and isinstance(v1_health.get("json"), dict)):
            if unversioned_health.get("status") == 200 and isinstance(unversioned_health.get("json"), dict):
                shadow_health = unversioned_health

        result["shadow_health"] = shadow_health
        result["shadow_health_path"] = "/api/v1/health" if shadow_health is v1_health else "/api/health"
        result["shadow_health_v1_raw"] = {"status": v1_health.get("status"), "error": v1_health.get("error")}
        result["shadow_health_unversioned_raw"] = {"status": unversioned_health.get("status"), "error": unversioned_health.get("error")}
        result["live_health"] = live

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


def build_canary(current_equal, now_dt=None, *, anchor_iso=None,
                 window_hours=CANARY_WINDOW_HOURS, root=None):
    """W9 canary 窗口状态——动态锚点版（G9-02：硬编码固定起点已废除）。

    锚点 anchor_iso = 当前窗口 manifest 的 t0（首条合格样本时刻）：
      - 无锚点（窗口尚未出首样）→ NOT_DUE，计数 null（未到期不计数）；
      - 锚后 window_hours（默认 48h）内 → IN_WINDOW，扫描 shadow/ 目录既有
        样本聚合 compare.equal 累计计数（equal/mismatch/not_comparable）；
      - 窗口关闭后 → CLOSED（末次封口计数，同样只来自已落盘样本）。
    current_equal 为本样本自身 compare.equal（True/False/None）——计入窗口
    内累计。计数只来自已落盘样本 + 本样本，绝不凭空生成。"""
    now_dt = now_dt or datetime.now().astimezone()
    root = root or observation_root()
    out = {
        "window_hours": window_hours,
        "anchor": anchor_iso,
        "status": None,
        "equal_count": None,
        "mismatch_count": None,
        "not_comparable_count": None,
        "scanned_files": None,
        "first_sample_at": None,
        "last_sample_at": None,
        "note": None,
    }
    start = wm.parse_iso(anchor_iso)
    if start is None:
        out["status"] = "NOT_DUE"
        out["note"] = ("canary 锚点（窗口 t0=首条合格样本时刻）未确立——"
                       "未到期不计数；起点不再硬编码（G9-02 动态窗口）")
        return out
    start = start.astimezone(timezone.utc)
    end = start + timedelta(hours=window_hours)
    out["anchor"] = start.isoformat()
    if now_dt < start:
        out["status"] = "NOT_DUE"
        out["note"] = "canary 窗口未到期（锚点 " + start.isoformat() + " 起）"
        return out
    out["status"] = "IN_WINDOW" if now_dt < end else "CLOSED"
    start_u, end_u = start, end
    eq = mm = nc = 0
    first_at = last_at = None
    scanned = 0
    try:
        names = sorted(os.listdir(shadow_dir(root)))
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
        path = os.path.join(shadow_dir(root), name)
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
    out["note"] = "窗口内 shadow 样本 compare.equal 累计计数（锚点=t0，扫描既有样本 + 本样本聚合）"
    return out


# ---------------------------------------------------------------- v2 落盘原语
# G9-02 A：样本创建一律 O_CREAT|O_EXCL|O_NOFOLLOW——绝不 os.replace；
# 碰撞/预置 symlink → fail-visible（错误记录落 errors/，绝不静默跳过）。

def gen_sample_name(now_ns=None):
    """样本文件名：UTC 纳秒紧凑串 + uuid4 片段（同秒并发必不同名）。"""
    return wm.utc_ns_stamp(now_ns) + "-" + uuid.uuid4().hex[:8] + ".json"


def write_sample_exclusive(dirpath, payload, *, name=None, attempts=3,
                           now_ns=None, kind="exclusive_create_failed"):
    """以 O_CREAT|O_EXCL|O_NOFOLLOW 独占创建一个 JSON 证据文件。

    - name=None：每次尝试生成新随机名（纳秒+uuid——正常路径零碰撞）；
    - name 给定：固定名（负测预置 symlink/同名文件时逐次如实记录尝试）。
    全部尝试失败 → 错误记录写入 <dirpath 上级>/errors/（fail-visible，
    绝不静默跳过）。
    返回 {"path": 绝对路径 | None, "error": None | 失败结构}。失败结构：
      {"error": "exclusive_create_failed", "attempts": [
          {"candidate", "reason": "exists"|"open_error", ...}]}"""
    attempts_errors = []
    for _ in range(max(1, attempts)):
        cand = name if name is not None else gen_sample_name(now_ns)
        if name is None:
            now_ns = None  # 随机路径：下一次尝试取新 time_ns + 新 uuid
        path = os.path.join(dirpath, cand)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o644)
        except FileExistsError:
            attempts_errors.append({"candidate": cand, "reason": "exists"})
            continue
        except OSError as e:
            # ELOOP（预置 symlink 被 O_NOFOLLOW 拒绝）/EACCES 等：如实记录
            attempts_errors.append({"candidate": cand, "reason": "open_error",
                                    "errno": e.errno, "error": str(e)[:160]})
            continue
        data = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            attempts_errors.append({"candidate": cand, "reason": "write_error",
                                    "error": str(e)[:160]})
            continue
        return {"path": path, "error": None}
    err = {"error": "exclusive_create_failed", "attempts": attempts_errors}
    record_creation_error(os.path.dirname(os.path.abspath(dirpath)),
                          kind, err)
    return {"path": None, "error": err}


def record_creation_error(root, kind, detail):
    """fail-visible 错误记录（errors/，同样 O_EXCL；再失败则 stderr 兜底）。

    非递归：错误记录自身失败只落 stderr，绝不再触发记录路径。"""
    payload = {
        "schema": "obs-create-error-v1",
        "kind": kind,
        "detail": detail,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "pid": os.getpid(),
    }
    path = None
    try:
        edir = errors_dir(root)
        os.makedirs(edir, exist_ok=True)
        cand = os.path.join(
            edir, "err-" + wm.utc_ns_stamp() + "-" + uuid.uuid4().hex[:8]
            + ".json")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(cand, flags, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        path = cand
    except OSError:
        path = None
    if path is None:
        _log("creation-error record failed: " + json.dumps(payload)[:300])
    return path


class ChainLock:
    """样本链互斥（flock samples/.chain.lock）——链头读取+落盘原子化。"""

    def __init__(self, sdir):
        self._path = os.path.join(sdir, ".chain.lock")
        self._fd = None

    def __enter__(self):
        self._fd = os.open(self._path, os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except OSError:
            os.close(self._fd)
            self._fd = None
            raise
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None
        return False


def chain_lock(sdir):
    return ChainLock(sdir)


def _iter_epoch_samples(sdir, epoch_id):
    """列出某 epoch 的全部 v2 样本 (doc, path)——legacy/损坏/symlink 跳过。"""
    out = []
    try:
        names = sorted(os.listdir(sdir))
    except OSError:
        return out
    for n in names:
        if not n.endswith(".json"):
            continue
        p = os.path.join(sdir, n)
        try:
            if os.path.islink(p):
                continue
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(d, dict) and d.get("schema") == SAMPLE_SCHEMA \
                and d.get("epoch_id") == epoch_id:
            out.append((d, p))
    return out


def latest_chain_head(sdir, epoch_id):
    """链头 (max_sequence, sample_sha256)；空链 → (0, None)。"""
    head = (0, None)
    for d, _p in _iter_epoch_samples(sdir, epoch_id):
        seq = d.get("sequence")
        if isinstance(seq, int) and seq > head[0]:
            head = (seq, d.get("sample_sha256"))
    return head


def find_epoch_head_sample(sdir, epoch_id):
    """链首样本 (sequence==1) → (doc, path)；无 → (None, None)。"""
    for d, p in _iter_epoch_samples(sdir, epoch_id):
        if d.get("sequence") == 1:
            return d, p
    return None, None


def compute_sample_sha256(doc_without_sample_sha):
    """sample_sha256 = sha256(canonical(doc 除 sample_sha256 键外))。"""
    return hashlib.sha256(
        _canonical(doc_without_sample_sha).encode("utf-8")).hexdigest()


def qualify_identity(repo_info):
    """identity 合格判定：repo.identity 必须是 40hex（fail-visible，不猜）。

    返回 (qualified, failures)；failures ∈ {"repo_identity_missing"}。"""
    identity = repo_info.get("identity") if isinstance(repo_info, dict) else None
    if isinstance(identity, str) and SHA1_RE.match(identity):
        return True, []
    return False, ["repo_identity_missing"]


def _resolve_window(root, now_dt):
    """（须持链锁）取当前活跃 manifest；过期 open 窗懒封口；无则 auto-open。"""
    docs, _ = wm.load_manifests(root)
    for m in docs:
        if m.get("status") != "open":
            continue
        end = wm.parse_iso(m.get("end_at"))
        if end is not None and now_dt > end:
            try:
                wm.seal_window(root, m["window_id"], now=now_dt)
            except wm.WindowError:
                pass  # 损坏/冲突 manifest 不阻断采样；active 解析会再暴露
    m = wm.active_manifest(root, now=now_dt)  # 歧义 → WindowAmbiguityError
    if m is not None:
        return m
    return wm.open_window(root, now=now_dt)


def record_sample(root, core, *, identity=None, release_sha=None,
                  scheduler_config_sha=None, collected_at=None, now=None,
                  probe_mode="full"):
    """采样落盘唯一编排：manifest 解析 → 链头 → 合格判定 → O_EXCL 落盘 →
    首样回填 manifest（T0 锚定）。

    返回 {"rc", "path", "doc", "manifest", "qualified", "qualify_failures"}：
      rc=0 合格样本；rc=1 落盘但不合格/创建失败；rc=3 证据环境错误。"""
    sdir = samples_dir(root)
    try:
        for d in (sdir, errors_dir(root), wm.manifest_dir(root),
                  shadow_dir(root)):
            os.makedirs(d, exist_ok=True)
    except OSError as e:
        return {"rc": 3, "path": None, "doc": None, "manifest": None,
                "qualified": False, "qualify_failures": ["obs_root_unwritable"],
                "error": "observation root unwritable: %s" % e}
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    collected = collected_at or now_dt.astimezone(timezone.utc).isoformat()
    try:
        with chain_lock(sdir):
            try:
                manifest = _resolve_window(root, now_dt)
            except wm.WindowError as e:
                return {"rc": 3, "path": None, "doc": None, "manifest": None,
                        "qualified": False,
                        "qualify_failures": ["window_manifest_error"],
                        "error": str(e)}
            head_seq, head_sha = latest_chain_head(
                sdir, manifest["epoch_id"])
            qualified, failures = qualify_identity(core.get("repo"))
            rel = (resolve_release_sha() if release_sha is None
                   else release_sha)
            scs = (resolve_scheduler_config_sha()
                   if scheduler_config_sha is None else scheduler_config_sha)
            if not (isinstance(rel, str) and SHA1_RE.match(rel)):
                failures = failures + ["release_sha_missing"]
                qualified = False
            if not (isinstance(scs, str) and SHA256_RE.match(scs)):
                failures = failures + ["scheduler_config_sha_missing"]
                qualified = False
            doc = {
                "schema": SAMPLE_SCHEMA,
                "window": "W10-observation",
                "window_id": manifest["window_id"],
                "epoch_id": manifest["epoch_id"],
                "day_index_note": ("观察窗动态化：T0=首条合格样本时刻，"
                                   "窗口参数见 windows/ manifest（G9-02）"),
                "collected_at": collected,
                "probe_mode": probe_mode,
            }
            doc.update(core)
            doc.update({
                "sequence": head_seq + 1,
                "prev_sha256": head_sha or GENESIS_SHA,
                "release_sha": rel,
                "observer_sha": observer_sha(),
                "scheduler_config_sha": scs,
                "qualified": qualified,
                "qualify_failures": failures,
            })
            doc["sample_sha256"] = compute_sample_sha256(doc)
            res = write_sample_exclusive(sdir, doc,
                                         kind="sample_create_failed")
            if res["path"] is None:
                # 错误记录已由原语写入 errors/（fail-visible）
                return {"rc": 1, "path": None, "doc": doc,
                        "manifest": manifest, "qualified": qualified,
                        "qualify_failures": failures, "error": res["error"]}
            if head_seq == 0:
                try:
                    manifest = wm.note_first_sample(
                        root, manifest,
                        sample_sha256=doc["sample_sha256"],
                        t0_iso=collected, now=now_dt)
                except wm.WindowError as e:
                    # 首样已落盘但 manifest 回填失败：如实记录（窗口起点证据缺失
                    # 由收割器暴露），样本本身保留
                    record_creation_error(root, "manifest_first_sample_failed",
                                          str(e))
            return {"rc": 0 if qualified else 1, "path": res["path"],
                    "doc": doc, "manifest": manifest, "qualified": qualified,
                    "qualify_failures": failures}
    except OSError as e:
        return {"rc": 3, "path": None, "doc": None, "manifest": None,
                "qualified": False, "qualify_failures": ["chain_lock_error"],
                "error": "chain lock failed: %s" % e}


# ---------------------------------------------------------------- 轮转

def _sample_epoch_of(path):
    """读文件的 epoch_id（v2 样本/影子；非 v2 或损坏 → None）。"""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    return d.get("epoch_id") if isinstance(d, dict) else None


def rotate(dirpath, *, keep_days=KEEP_DAYS, protect_epoch=None,
           protect_mtime_since=None):
    """按文件名日期删除超期样本——新旧两代命名都识别；当前窗口证据绝不删。

    - 新命名（UTC 纳秒）：按名内 UTC 日期 vs cutoff(UTC)；
    - 旧命名（YYYY-MM-DD[-HHMMSS]，本地日期）：保持原语义；
    - 无法识别的 .json：不动（保守——绝不删看不懂的证据）；
    - protect_epoch：文件 epoch_id 命中当前窗口 → 保留（即便名字日期超期）；
    - protect_mtime_since：mtime 在保护窗内 → 保留。"""
    removed = []
    cutoff_new = datetime.now(timezone.utc).date() - timedelta(days=keep_days)
    cutoff_legacy = date.today() - timedelta(days=keep_days)
    try:
        names = os.listdir(dirpath)
    except OSError:
        return removed
    for name in names:
        if not name.endswith(".json"):
            continue
        m_new = _NEW_NAME_RE.match(name)
        if m_new:
            try:
                d = datetime.strptime(m_new.group(1), "%Y%m%d").date()
            except ValueError:
                continue
            cutoff = cutoff_new
        else:
            m_old = _LEGACY_NAME_RE.match(name)
            if not m_old:
                continue  # 不识别 → 保守保留
            try:
                d = date(int(m_old.group(1)), int(m_old.group(2)),
                         int(m_old.group(3)))
            except ValueError:
                continue
            cutoff = cutoff_legacy
        if d >= cutoff:
            continue
        path = os.path.join(dirpath, name)
        if protect_mtime_since is not None:
            try:
                if os.path.getmtime(path) >= protect_mtime_since:
                    continue
            except OSError:
                continue
        if protect_epoch is not None and _sample_epoch_of(path) == protect_epoch:
            continue  # 当前窗口证据：绝不删
        try:
            os.remove(path)
            removed.append(name)
        except OSError:
            pass
    return removed


# ---------------------------------------------------------------- main

def main(argv=None):
    light = os.environ.get("WENQU_OBS_PROBE_MODE") == "light"
    root = observation_root()
    try:
        for d in (samples_dir(root), shadow_dir(root), LOGS_DIR,
                  errors_dir(root), wm.manifest_dir(root)):
            os.makedirs(d, exist_ok=True)
    except OSError as e:
        print(json.dumps({"ok": False, "rc": 3,
                          "error": "observation root unwritable: %s" % e},
                         ensure_ascii=False))
        return 3
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()

    def _skipped():
        return {"skipped": "light-mode"}

    repo_info = safe(probe_repo)
    sample_core = {
        "host": _skipped() if light else safe(probe_host),
        "repo": repo_info,
        "ci_latest_main": _skipped() if light else safe(probe_ci_latest_main),
        "dashboard_launchd": _skipped() if light else safe(probe_dashboard_launchd),
        "legacy_health": _skipped() if light else safe(probe_legacy_health),
        "disk": safe(probe_disk),
        "capacity_gate": safe(probe_capacity_gate),
    }
    rec = record_sample(root, sample_core, collected_at=now_iso,
                        now=now_dt, probe_mode="light" if light else "full")
    if rec["rc"] == 3:
        print(json.dumps({"ok": False, "rc": 3,
                          "error": rec.get("error"),
                          "qualify_failures": rec.get("qualify_failures")},
                         ensure_ascii=False))
        return 3
    manifest = rec["manifest"]
    doc = rec["doc"]

    # W9 shadow（同样 O_EXCL 不可覆盖；携带 epoch/window 供 rotation 保护）
    shadow_probe = _skipped() if light else safe(probe_shadow)
    man_doc = None
    try:
        man_doc = wm.load_manifest(root, manifest["window_id"])
    except wm.WindowError:
        man_doc = manifest
    anchor = (man_doc or {}).get("t0")
    canary_hours = (man_doc or {}).get("canary_hours") or CANARY_WINDOW_HOURS
    shadow = {
        "schema": SHADOW_SCHEMA,
        "window": "W9-shadow-clock",
        "window_id": manifest["window_id"],
        "epoch_id": manifest["epoch_id"],
        "collected_at": now_iso,
        "shadow": shadow_probe,
        "canary": build_canary(
            shadow_probe.get("compare", {}).get("equal")
            if isinstance(shadow_probe, dict) else None,
            now_dt=now_dt, anchor_iso=anchor, window_hours=canary_hours,
            root=root),
    }
    wres = write_sample_exclusive(shadow_dir(root), shadow,
                                  kind="shadow_create_failed")
    shadow_path = wres["path"]
    shadow_error = wres["error"]

    # rotation：当前窗口证据保护（epoch 命中绝不删）
    rotate(samples_dir(root), protect_epoch=manifest["epoch_id"])
    rotate(shadow_dir(root), protect_epoch=manifest["epoch_id"])

    rc = rec["rc"]
    if shadow_path is None:
        rc = 1  # shadow 证据创建失败同样 fail-visible

    summary = {
        "ok": rc == 0,
        "rc": rc,
        "sample_path": rec["path"],
        "shadow_path": shadow_path,
        "shadow_create_error": shadow_error,
        "window_id": manifest["window_id"],
        "epoch_id": manifest["epoch_id"],
        "sequence": doc["sequence"],
        "qualified": doc["qualified"],
        "qualify_failures": doc["qualify_failures"],
        "repo_head": repo_info.get("worktree_head")
        if isinstance(repo_info, dict) else None,
        "repo_identity": repo_info.get("identity")
        if isinstance(repo_info, dict) else None,
        "repo_fallback_refused": repo_info.get("fallback_refused")
        if isinstance(repo_info, dict) else None,
        "canary_status": shadow["canary"].get("status"),
        "capacity_gate": sample_core["capacity_gate"].get("capacity_gate")
        if isinstance(sample_core["capacity_gate"], dict) else None,
        "disk_used_pct": sample_core["disk"].get("used_pct")
        if isinstance(sample_core["disk"], dict) else None,
        "shadow_compare_equal": (
            shadow_probe.get("compare", {}).get("equal")
            if isinstance(shadow_probe, dict) else None),
    }
    print(json.dumps(summary, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    sys.exit(main())

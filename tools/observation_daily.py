#!/usr/bin/env python3
"""W10 观察窗 + W9 shadow 每日采样器（只读，不改产品码，仓外落盘）。

W10 观察窗样本（~/.wenqu/observation/samples/YYYY-MM-DD.json）：
  host / repo HEAD / dirty / ci_latest_main / dashboard launchd state /
  legacy 7789 /api/health / 磁盘 used 占比
W9 shadow 时钟（~/.wenqu/observation/shadow/YYYY-MM-DD.json）：
  起本仓 system/dashboard/server.py 于随机空闲端口（影子实例，与 7789 legacy 并存），
  就绪后抓双方 health JSON 做 key 集合 / score 相等性比对，finally 必杀影子进程。

设计约束：
  - 纯标准库；单探针失败记 null / error，绝不中断整体采样。
  - 文件保留 30 天，超期轮转删除；同日重跑覆盖当日文件（当日以最新样本为准）。
  - 结束 print 一行 JSON 摘要。
  - subprocess 一律参数列表 + shell=False；URL 用常量拼接（不用 f-string）。

注：modular server（system/dashboard/server.py）的 health 契约路径是
  /api/v1/health（未版本化 /api/health 已废止，返回 404 API_VERSION_REQUIRED）。
  shadow 比对优先取 /api/v1/health 的 200 JSON；两条路径的原始探测结果都会落盘。
"""
import json
import os
import re
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
SERVER_PY = os.path.join(REPO, "system", "dashboard", "server.py")
OBS_ROOT = os.path.expanduser("~/.wenqu/observation")
SAMPLES_DIR = os.path.join(OBS_ROOT, "samples")
SHADOW_DIR = os.path.join(OBS_ROOT, "shadow")
LOGS_DIR = os.path.join(OBS_ROOT, "logs")
KEEP_DAYS = 30

UID = os.getuid()
HOST_LOCAL = "127.0.0.1"
LEGACY_PORT = 7789
LEGACY_BASE = "http://" + HOST_LOCAL + ":" + str(LEGACY_PORT)
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
    return http_get_json(LEGACY_HEALTH_URL)


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


# ---------------------------------------------------------------- W9 shadow

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


def compare_health(legacy, modular):
    """key 集合相等性 / score 相等性 / 键差。不可比时字段记 null，不猜。"""
    out = {
        "key_sets_equal": None,
        "score_equal": None,
        "only_legacy": None,
        "only_modular": None,
        "legacy_score": None,
        "modular_score": None,
        "note": None,
    }
    lj = legacy.get("json") if isinstance(legacy, dict) and legacy.get("status") == 200 else None
    mj = modular.get("json") if isinstance(modular, dict) and modular.get("status") == 200 else None
    if not isinstance(lj, dict):
        out["note"] = "legacy /api/health 无 200 JSON，无法比对"
        return out
    if not isinstance(mj, dict):
        out["legacy_score"] = lj.get("score") if isinstance(lj.get("score"), (int, float)) else None
        out["note"] = "modular health 无 200 JSON（当前为结构化错误态），无法比对"
        return out
    lk = set(lj.keys())
    mk = set(mj.keys())
    out["only_legacy"] = sorted(lk - mk)
    out["only_modular"] = sorted(mk - lk)
    out["key_sets_equal"] = lk == mk
    ls = lj.get("score")
    ms = mj.get("score")
    out["legacy_score"] = ls if isinstance(ls, (int, float)) and not isinstance(ls, bool) else None
    out["modular_score"] = ms if isinstance(ms, (int, float)) and not isinstance(ms, bool) else None
    if out["legacy_score"] is not None and out["modular_score"] is not None:
        out["score_equal"] = out["legacy_score"] == out["modular_score"]
    else:
        out["note"] = "至少一方缺 numeric score 字段，score 不比对"
    return out


def probe_shadow():
    if not os.path.isfile(SERVER_PY):
        return {"error": "server.py not found: " + SERVER_PY}
    port = pick_free_port()
    base_url = "http://" + HOST_LOCAL + ":" + str(port)
    ping_url = base_url + "/api/v1/ping"
    v1_health_url = base_url + "/api/v1/health"
    unversioned_health_url = base_url + "/api/health"
    server_log_path = os.path.join(LOGS_DIR, "shadow-server-" + date.today().isoformat() + ".log")

    result = {
        "port": port,
        "server_pid": None,
        "ready": False,
        "ready_seconds": None,
        "server_log": server_log_path,
        "terminated": None,
    }
    logf = open(server_log_path, "ab")
    try:
        proc = subprocess.Popen(
            [sys.executable, SERVER_PY, "--port", str(port)],
            start_new_session=True,
            stdout=logf,
            stderr=subprocess.STDOUT,
            cwd=REPO,
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

        legacy = probe_legacy_health()
        v1_health = http_get_json(v1_health_url)
        unversioned_health = http_get_json(unversioned_health_url)

        # 比对主源：优先 200 JSON 的 v1；否则退回未版本化路径的 200 JSON；
        # 都没有时保留 v1 原始结果（含 503/404 结构化错误），如实观测。
        modular = v1_health
        modular_path = "/api/v1/health"
        if not (v1_health.get("status") == 200 and isinstance(v1_health.get("json"), dict)):
            if unversioned_health.get("status") == 200 and isinstance(unversioned_health.get("json"), dict):
                modular = unversioned_health
                modular_path = "/api/health"

        result["modular_health"] = modular
        result["modular_health_path"] = modular_path
        result["modular_health_v1_raw"] = {"status": v1_health.get("status"), "error": v1_health.get("error")}
        result["modular_health_unversioned_raw"] = {"status": unversioned_health.get("status"), "error": unversioned_health.get("error")}
        result["legacy_health"] = legacy
        result["compare"] = compare_health(legacy, modular)
    finally:
        if result.get("server_pid") is not None:
            result["terminated"] = stop_process_tree(proc)
        logf.close()
    return result


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
    }

    shadow = {
        "window": "W9-shadow-clock",
        "collected_at": now_iso,
        "shadow": safe(probe_shadow),
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
    summary = {
        "ok": True,
        "sample_path": sample_path,
        "shadow_path": shadow_path,
        "ci_latest_main": (ci.get("status") + "/" + str(ci.get("conclusion")) + " run=" + str(ci.get("databaseId"))) if isinstance(ci, dict) and ci.get("status") else (ci if isinstance(ci, dict) else None),
        "shadow_compare": cmp_,
        "shadow_ready": sh.get("ready") if isinstance(sh, dict) else None,
        "dashboard_launchd_state": sample["dashboard_launchd"].get("state") if isinstance(sample["dashboard_launchd"], dict) else None,
        "disk_used_pct": sample["disk"].get("used_pct") if isinstance(sample["disk"], dict) else None,
        "repo_head": repo_info.get("head") if isinstance(repo_info, dict) else None,
        "repo_dirty": repo_info.get("dirty") if isinstance(repo_info, dict) else None,
    }
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()

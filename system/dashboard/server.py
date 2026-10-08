#!/usr/bin/env python3
"""wenqu dashboard server —— W8 结构重构+安全加固版（Codex W8）

自单文件 wenqu-dashboard.py v3.1 拆分：index.html + app.css + app.js + server.py。
本文件只做服务端；威胁模型对照 docs/security/threat-model.md：
  - T-04 localhost CSRF/DNS rebinding：严格 Host 校验 + Origin/Sec-Fetch-Site 校验 + CORS 默认拒绝
  - T-05 日志/账本 XSS：CSP + 前端 textContent（见 app.js）；服务器补齐安全响应头
  - 不变量 10：dashboard 只能等于或比权威聚合器更保守——/api/v1/health 只读 gate_aggregator
    快照透传，绝不再自算加权分
第一阶段（写接口关闭）：POST /api/decide → 405。

R7 加固（第七轮验收根修，2026-10-08）：
  - R7-UI-LOG-AUTH-009：/api/v1/logs 加鉴权——WENQU_DASHBOARD_KEY 配置后须携带
    匹配的 X-Auth-Key；未配置 key 时该端点默认 403（fail-closed，与写接口
    关闭同范式）。日志是敏感数据面，绝不匿名可读。
  - R7-UI-LOG-BYTES-010：日志响应字节上限（WENQU_LOG_MAX_BYTES，默认 1MiB）——
    超限按字节截断并带 "truncated": true 标记；病态单行超长只回前缀字节，
    不再整行返回 6MiB。

用法：
  python3 server.py [--port 7789] [--log]
  python3 server.py --port 7789 --self-check   # 自检输出 PASS 并退出
"""
import argparse
import collections
import hmac
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

SERVER_VERSION = "wenqu-dashboard-w8/1.0"
DASH_DIR = os.path.dirname(os.path.abspath(__file__))
WQ = os.environ.get("WENQU_HOME", os.path.expanduser("~/.wenqu"))
PORT_DEFAULT = 7789

MAX_BODY = 65536                 # 请求体上限（字节）
RATE_WINDOW = 30.0               # 速率限制窗口（秒）
RATE_MAX = 150                   # 窗口内每客户端 IP 最大请求数（前端 5s 轮询 ~10 端点 = 60/30s，留余量）
REQUEST_TIMEOUT = 15             # 单连接读超时（秒）
AGGREGATE_TTL = float(os.environ.get("WENQU_AGGREGATE_TTL", "1800"))  # 快照新鲜度上限（秒）
HISTORY_INTERVAL = 600           # 健康度走势写入周期（秒）——独立定时任务，不在 GET 路径写
LOG_MAX_BYTES_DEFAULT = 1048576  # /api/v1/logs 响应字节上限默认 1MiB（R7-UI-LOG-BYTES-010）


def _log_max_bytes():
    """/api/v1/logs 响应字节上限（WENQU_LOG_MAX_BYTES 可配；非法/非正值回落默认）。"""
    raw = os.environ.get("WENQU_LOG_MAX_BYTES", "")
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return LOG_MAX_BYTES_DEFAULT
    return n if n > 0 else LOG_MAX_BYTES_DEFAULT


def _fit_logs_bytes(out, cap):
    """日志映射 → 序列化字节，硬保证总长 ≤ cap（R7-UI-LOG-BYTES-010）。

    超限时按「末文件末行」逐字节回裁（保内容前缀，病态单行只回前缀字节），
    并在载荷中加 "truncated": true 标记；未截断时不加该键——正常响应形状
    与旧版完全一致（既有消费方零扰动）。cap 连键名都放不下时物理截断兜底。
    """
    def ser(obj):
        return json.dumps(obj, ensure_ascii=False).encode("utf-8")

    obj = dict(out)
    body = ser(obj)
    if len(body) <= cap:
        return body
    obj["truncated"] = True
    body = ser(obj)
    guard = 0
    while len(body) > cap and guard < 4096:
        guard += 1
        names = [k for k in sorted(obj, reverse=True) if k != "truncated" and obj[k]]
        if not names:
            break  # 已无内容可裁（cap 极小）——退出走物理兜底
        key = names[0]
        lines = obj[key].split("\n")
        for idx in range(len(lines) - 1, -1, -1):
            if not lines[idx]:
                continue
            cur = lines[idx].encode("utf-8", errors="replace")
            excess = len(body) - cap
            keep = max(0, len(cur) - excess - 16)
            lines[idx] = cur[:keep].decode("utf-8", errors="ignore") if keep else ""
            break
        else:
            obj[key] = ""
            body = ser(obj)
            continue
        obj[key] = "\n".join(lines)
        body = ser(obj)
    if len(body) > cap:  # 物理兜底：病态小 cap（连键名+标记都放不下）
        body = body[:cap]
    return body

CSP_HEADER = ("default-src 'self'; script-src 'self'; style-src 'self'; "
              "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}

COMPONENTS = {
    "bin": ["wenqu-env.sh", "iron-gate.sh", "blast-radius.py", "cursor-auto-verify.sh",
            "deploy-preflight.sh", "hardening-doctor.sh", "wenqu-dashboard.py"],
    "sentinels": ["ci-event-sentinel.sh", "conservation-sentinel.sh", "ssl-cert-sentinel.sh"],
    "daemons": ["auto-merge.sh", "conservation-daemon.py"],
}

_LOG_ENABLED = False
_EP_CACHE = {}  # 慢端点 TTL 缓存 {name: {"ts": monotonic, "data": bytes}}
_EP_CACHE_LOCK = threading.Lock()


def _cache_get(name, ttl):
    with _EP_CACHE_LOCK:
        b = _EP_CACHE.get(name)
        if b and b.get("data") is not None and time.monotonic() - b["ts"] < ttl:
            return b["data"]
    return None


def _cache_put(name, data):
    with _EP_CACHE_LOCK:
        _EP_CACHE[name] = {"ts": time.monotonic(), "data": data}


# ───────────────────────────── 速率限制 ─────────────────────────────
class RateLimiter:
    """每客户端 IP 滑动窗口限速（只可能来自 127.0.0.1——服务器仅绑定回环）。"""

    def __init__(self, max_n, window):
        self.max_n = max_n
        self.window = window
        self._hits = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def allow(self, ip):
        now = time.monotonic()
        with self._lock:
            dq = self._hits[ip]
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(dq) >= self.max_n:
                return False
            dq.append(now)
            return True


_LIMITER = RateLimiter(RATE_MAX, RATE_WINDOW)


# ───────────────────── gate aggregator 快照（只读） ─────────────────────
def read_gate_aggregate():
    """读权威聚合器原子快照（不变量 10：dashboard 不自算，只透传）。
    返回 {"ok": True, "data": snapshot} 或 {"ok": False, "code": ..., "detail": ...}。
    数据源缺失/过期/畸形 → 结构化 ERROR（由调用方以 503 返回，绝不 200+空集）。"""
    path = os.environ.get("WENQU_GATE_AGGREGATE") or os.path.join(WQ, "state", "gate-aggregate.json")
    if not os.path.isfile(path):
        return {"ok": False, "code": "AGGREGATOR_UNAVAILABLE",
                "detail": "权威聚合器快照不存在：%s（gate_aggregator 产出后自动出现）" % path}
    try:
        with open(path, encoding="utf-8") as f:
            snap = json.load(f)
    except (OSError, ValueError) as e:
        return {"ok": False, "code": "AGGREGATOR_MALFORMED", "detail": "快照不可读/无法解析：%s" % e}
    if not isinstance(snap, dict):
        return {"ok": False, "code": "AGGREGATOR_MALFORMED", "detail": "快照不是 JSON 对象"}
    gen = snap.get("generated_at") or snap.get("ts")
    if not isinstance(gen, str) or not gen:
        return {"ok": False, "code": "AGGREGATOR_MALFORMED", "detail": "快照缺 generated_at/ts 时间戳字段"}
    try:
        dt = datetime.fromisoformat(gen.replace("Z", "+00:00"))
    except ValueError:
        return {"ok": False, "code": "AGGREGATOR_MALFORMED", "detail": "generated_at 不是 ISO 时间戳"}
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - dt).total_seconds()
    if age > AGGREGATE_TTL or age < -120:
        return {"ok": False, "code": "AGGREGATOR_STALE",
                "detail": "快照龄 %ds 超出 TTL %ds（时间戳异常或聚合器停摆）" % (int(age), int(AGGREGATE_TTL))}
    if not any(k in snap for k in ("policy_verdict", "overall", "verdict")):
        return {"ok": False, "code": "AGGREGATOR_MALFORMED", "detail": "快照缺 policy_verdict/overall 判定字段"}
    return {"ok": True, "data": snap}


def _health_history_path():
    return os.environ.get("WENQU_HEALTH_HISTORY",
                          os.path.expanduser("~/Documents/ERP）Zcode/健康度走势.jsonl"))


def health_history_writer(stop_evt):
    """独立定时任务：周期性把 aggregator 快照落一行走势（GET 路径零写——严格只读）。
    快照不可用时静默跳过（不写伪数据）；距末行 < INTERVAL*0.9 时不重复追加。"""
    path = _health_history_path()
    while True:
        r = read_gate_aggregate()
        if r["ok"]:
            snap = r["data"]
            score = snap.get("score")
            verdict = snap.get("policy_verdict") or snap.get("overall") or snap.get("verdict")
            if isinstance(score, (int, float)) or verdict:
                try:
                    last_ts = ""
                    if os.path.isfile(path):
                        with open(path, encoding="utf-8", errors="ignore") as f:
                            for l in f:
                                if l.strip():
                                    last_ts = l
                    gap_ok = True
                    if last_ts:
                        try:
                            prev = datetime.fromisoformat(json.loads(last_ts).get("ts", "").replace("Z", "+00:00"))
                            if prev.tzinfo is None:
                                prev = prev.replace(tzinfo=timezone.utc)
                            gap_ok = (datetime.now(timezone.utc) - prev).total_seconds() > HISTORY_INTERVAL * 0.9
                        except (ValueError, OSError):
                            gap_ok = True
                    if gap_ok:
                        with open(path, "a", encoding="utf-8") as f:
                            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                                "score": score if isinstance(score, (int, float)) else None,
                                                "verdict": verdict}, ensure_ascii=False) + "\n")
                except (OSError, ValueError):
                    pass
        if stop_evt.wait(HISTORY_INTERVAL):
            return


# ───────────────────────────── 数据读取（全部只读） ─────────────────────────────
def read_components():
    out = {}
    for grp, items in COMPONENTS.items():
        out[grp] = [{"name": n, "ok": os.path.isfile(os.path.join(WQ, grp, n))} for n in items]
    ver = ""
    try:
        with open(os.path.join(WQ, "VERSION"), encoding="utf-8") as f:
            ver = f.read().strip()
    except OSError:
        pass
    return {"version": ver, **out}


def read_daemons():
    daemons, state = {}, os.path.join(WQ, "state")
    if os.path.isdir(state):
        for f in os.listdir(state):
            if f.endswith(".pid"):
                try:
                    with open(os.path.join(state, f), encoding="utf-8") as fh:
                        pid = int(fh.read().strip())
                    os.kill(pid, 0)
                    st = "运行中"
                except (OSError, ValueError):
                    st = "已退出"
                daemons[f[:-4]] = st
    cron = 0
    try:
        cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5
                              ).stdout.count("wenqu/sentinels")
    except (OSError, subprocess.SubprocessError):
        pass
    return {"daemons": daemons, "cron": cron}


def read_ratchet():
    for cand in ("scripts/dupscan/baseline.json",
                 os.path.join(os.environ.get("WENQU_REPO_DIR", ""), "scripts/dupscan/baseline.json")):
        if cand and os.path.isfile(cand):
            try:
                with open(cand, encoding="utf-8") as f:
                    d = json.load(f)
                return {"available": True, "layers": {
                    k: {"clones": v.get("clones"), "rate": v.get("duplicate_rate_pct")}
                    for k, v in d.get("layers", {}).items()}}
            except (OSError, ValueError):
                pass
    return {"available": False}


def _rounds_path():
    path = os.environ.get("WENQU_LEDGER")
    if not path:
        for cand in ("ERP）Zcode/持续修复引擎/engine-rounds.jsonl", "持续修复引擎/engine-rounds.jsonl"):
            p = os.path.expanduser(f"~/Documents/{cand}")
            if os.path.isfile(p):
                return p
    return path


def read_rounds():
    rounds = []
    path = _rounds_path()
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                lines = [l for l in f if l.strip()][-8:]
            for l in lines:
                try:
                    d = json.loads(l)
                except ValueError:
                    continue
                rnd = d.get("round") or d.get("id") or ""
                ts = str(d.get("ts", ""))[5:16]
                st = d.get("state") or d.get("summary") or d.get("title") or ""
                label = str(st)[:60] or d.get("type", "")
                rounds.append({"ts": ts, "label": f"r{rnd} {label}" if rnd else label})
        except OSError:
            pass
    return {"rounds": rounds}


def read_rounds_heat():
    days = collections.Counter()
    path = _rounds_path()
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for l in f:
                    if not l.strip():
                        continue
                    try:
                        d = json.loads(l)
                    except ValueError:
                        continue
                    ts = str(d.get("ts") or d.get("time") or "")[:10]
                    if ts:
                        days[ts] += 1
        except OSError:
            pass
    out = []
    for i in range(29, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        out.append({"d": day[5:], "n": days.get(day, 0)})
    return out


def read_logs():
    cap = _log_max_bytes()
    cache_name = "logs:%d" % cap
    cached = _cache_get(cache_name, 15)  # 日志尾 15s 滞后可接受
    if cached is not None:
        return cached
    out, logdir = {}, os.path.join(WQ, "logs")
    if os.path.isdir(logdir):
        for f in sorted(os.listdir(logdir)):
            if f.endswith(".log"):
                try:
                    r = subprocess.run(["tail", "-n", "20", os.path.join(logdir, f)],
                                       capture_output=True, text=True, timeout=5)
                    out[f] = r.stdout or "(空)"
                except (OSError, subprocess.SubprocessError):
                    pass
    if not out:
        out["(说明)"] = "哨兵经 wenqu cron 安装后，日志将出现在 ~/.wenqu/logs/"
    # R7-UI-LOG-BYTES-010：响应硬字节上限——超限按字节截断 + truncated 标记
    data = _fit_logs_bytes(out, cap)
    _cache_put(cache_name, data)
    return data


def read_health_history():
    out = []
    try:
        with open(_health_history_path(), encoding="utf-8", errors="ignore") as f:
            for l in f:
                if not l.strip():
                    continue
                try:
                    d = json.loads(l)
                except ValueError:
                    continue
                out.append({"ts": str(d.get("ts", ""))[5:16], "score": d.get("score"),
                            "verdict": d.get("verdict")})
    except OSError:
        pass
    return out[-48:]


def read_decisions(want_all):
    out = []
    env = os.environ.get("WENQU_DECISIONS",
                         os.path.expanduser("~/Documents/ERP）Zcode/决策台账.jsonl"))
    try:
        with open(env, encoding="utf-8", errors="ignore") as f:
            for l in f:
                if not l.strip():
                    continue
                try:
                    d = json.loads(l)
                except ValueError:
                    continue
                if d.get("status") == "待拍" or want_all:
                    row = {k: d.get(k) for k in ("id", "cat", "q", "opt", "ttl", "red", "ts", "intent")}
                    if want_all:
                        row["status"] = d.get("status")
                    out.append(row)
    except OSError:
        pass
    return out


# ── bugscan-ledger（折叠语义与单文件版同源，逐字移植） ──
_LEDGER_CACHE = {"stamp": None, "data": None}
_LEDGER_LOCK = threading.Lock()


def _norm_status(s):
    """账本状态归一——多源异构历史归一到 §4 正源状态机五态+FIXED 过渡+OTHER 残差。"""
    if s is None:
        return "OTHER"
    t = str(s).strip()
    if not t:
        return "OTHER"
    tl = t.lower()
    if tl.startswith("open"):
        return "OPEN"
    if tl.startswith("partially-fixed") or tl.startswith("partially_fixed"):
        return "FIXING"
    if tl.startswith("fixing"):
        return "FIXING"
    if tl.startswith("fixed+verified") or t.startswith("VERIFIED_CLOSED") or tl.startswith("partially-verified"):
        return "VERIFIED"
    if tl.startswith("fixed") or tl.startswith("corrected") or tl.startswith("done") or tl.startswith("mitigated") or tl.startswith("documented"):
        return "FIXED"
    if tl.startswith("verified"):
        return "VERIFIED"
    if tl.startswith("closed") or tl.startswith("rejected"):
        return "CLOSED"
    if tl.startswith("accepted"):
        return "ACCEPTED"
    return "OTHER"


def _norm_sev(s):
    if s is None:
        return "OTHER"
    t = str(s).strip().lower()
    if not t:
        return "OTHER"
    toks = [w for w in re.split(r"[^a-z]+", t) if w]

    def hit(*stems):
        return any(w == st or w.startswith(st + "-") for w in toks for st in stems)

    if hit("crit", "critical"):
        return "HIGH"
    if hit("high"):
        return "HIGH"
    if hit("med", "medium"):
        return "MED"
    if hit("low"):
        return "LOW"
    if hit("info") or t == "pass":
        return "INFO"
    return "OTHER"


def _fold_project(f):
    """单项目账本折叠：finding 行按 id 去重取末次为初始态；同 id 末次 state_transition 的
    目标态覆盖初始态（防幻影 OPEN）。"""
    cur, trans, sev_of, title_of, ts_of, last = {}, {}, {}, {}, {}, ""
    with open(f, encoding="utf-8", errors="ignore") as fh:
        for l in fh:
            l = l.strip()
            if not l:
                continue
            try:
                d = json.loads(l)
            except ValueError:
                continue
            if not isinstance(d, dict) or not ("id" in d or "finding_id" in d):
                continue
            fid = str(d.get("id") or d.get("finding_id"))
            ts = str(d.get("ts") or d.get("time") or "")
            if ts > last:
                last = ts
            if "record_type" in d:
                tr = str(d.get("transition", ""))
                if "->" in tr:
                    src_side, to_state = tr.split("->", 1)[0].strip().upper(), tr.rsplit(">", 1)[1].strip()
                    if src_side.startswith("SEVERITY"):
                        sev_to = to_state.split("(")[0].strip()
                        if sev_to and _norm_sev(sev_to) != "OTHER":
                            sev_of[fid] = sev_to
                    elif to_state and _norm_status(to_state) != "OTHER":
                        trans[fid] = to_state
                continue
            cur[fid] = d.get("status") or d.get("state")
            raw_sev = d.get("sev") or d.get("severity")
            if raw_sev is not None and _norm_sev(raw_sev) != "OTHER":
                sev_of[fid] = raw_sev
            t = str(d.get("title") or d.get("desc") or "").strip()
            if t:
                title_of[fid] = t
            if ts:
                ts_of[fid] = ts
    return cur, trans, sev_of, title_of, ts_of, last


def _ledger_files(root):
    """采集账本文件集及其 (mtime_ns,size) 签名（basename 级白名单，拒绝穿越）。"""
    files = {}
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return files
    for name in names:
        if name != os.path.basename(name) or ".." in name or name.startswith("."):
            continue
        f = os.path.realpath(os.path.join(root, name, "findings.jsonl"))
        if not (f == root or f.startswith(root + os.sep)) or not os.path.isfile(f):
            continue
        try:
            st = os.stat(f)
        except OSError:
            continue
        files[f] = (st.st_mtime_ns, st.st_size)
    return files


def bugscan_ledger():
    root = os.path.realpath(os.path.expanduser(
        os.environ.get("WENQU_BUGSCAN_LEDGER", "~/.zcode/quality-system/bugscan-ledger")))
    if not os.path.isdir(root):
        return {"available": False}
    files = _ledger_files(root)
    stamp = frozenset(files.items())
    with _LEDGER_LOCK:
        if _LEDGER_CACHE["stamp"] == stamp:
            return _LEDGER_CACHE["data"]
        try:
            data = _bugscan_ledger_impl(files)
        except Exception as e:  # 边缘兜底，不炸端点（fail-soft，返回稳定错误）
            return {"available": False, "error": f"{type(e).__name__}: {e}"}
        _LEDGER_CACHE["stamp"] = stamp
        _LEDGER_CACHE["data"] = data
        return data


def _bugscan_ledger_impl(files):
    projects = []
    tot_status, tot_sev = {}, {}
    tot_findings, tot_last = 0, ""
    all_items = []
    stale_open = 0
    STALE_DAYS = 14
    now = datetime.now()
    for f in files:
        cur, trans, sev_of, title_of, ts_of, last = _fold_project(f)
        if not cur:
            continue
        key = os.path.basename(os.path.dirname(f))
        by_status, by_sev = {}, {}
        for fid, init_status in cur.items():
            stt = _norm_status(trans.get(fid) or init_status)
            by_status[stt] = by_status.get(stt, 0) + 1
            sv = _norm_sev(sev_of.get(fid))
            by_sev[sv] = by_sev.get(sv, 0) + 1
            stale = False
            if stt == "OPEN":
                t = str(ts_of.get(fid, ""))[:19]
                try:
                    if t:
                        dt = datetime.fromisoformat(t)
                        if (now - dt).days > STALE_DAYS:
                            stale = True
                            stale_open += 1
                except ValueError:
                    pass
            all_items.append({"st": stt, "id": fid, "sev": sv, "title": title_of.get(fid, "")[:90],
                              "proj": key, "stale": stale, "ts": str(ts_of.get(fid, ""))[:10]})
        projects.append({"key": key, "findings": len(cur), "by_status": by_status,
                         "by_sev": by_sev, "last_ts": last[:16]})
        tot_findings += len(cur)
        for k, v in by_status.items():
            tot_status[k] = tot_status.get(k, 0) + v
        for k, v in by_sev.items():
            tot_sev[k] = tot_sev.get(k, 0) + v
        if last > tot_last:
            tot_last = last
    projects.sort(key=lambda p: -p["findings"])
    sev_rank = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3, "OTHER": 4}
    all_items.sort(key=lambda x: (sev_rank.get(x["sev"], 9), x["proj"]))
    return {"available": True, "projects": projects,
            "total": {"findings": tot_findings, "by_status": tot_status, "by_sev": tot_sev,
                      "last_ts": tot_last[:16]},
            "open_total": sum(1 for x in all_items if x["st"] == "OPEN"),
            "open_items": [x for x in all_items if x["st"] == "OPEN"][:60],
            "stale_open": stale_open,
            "_all_items": all_items}


# ───────────────────────────── HTTP 处理器 ─────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = SERVER_VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT  # 单连接读超时（慢速攻击面收敛）

    def log_message(self, fmt, *args):
        if _LOG_ENABLED:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ── 安全响应头（每个响应都带；永不发 Access-Control-Allow-* = CORS 默认拒绝） ──
    def _sec_headers(self):
        for k, v in (("Content-Security-Policy", CSP_HEADER),
                     ("X-Content-Type-Options", "nosniff"),
                     ("X-Frame-Options", "DENY"),
                     ("Cache-Control", "no-store"),
                     ("Referrer-Policy", "no-referrer")):
            self.send_header(k, v)

    def _send(self, code, data, ctype="application/json; charset=utf-8", allow=None):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.send_response(code)
        self._sec_headers()
        self.send_header("Content-Type", ctype)
        if allow:
            self.send_header("Allow", allow)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, code, obj, allow=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), allow=allow)

    def _err(self, code, err_code, detail, allow=None):
        self._json(code, {"error": {"code": err_code, "detail": detail}}, allow=allow)

    # ── 入口安全闸：Host（防 DNS rebinding）→ Origin/Sec-Fetch-Site（CORS 默认拒绝）→ 速率限制 ──
    def _gate(self):
        try:
            ip = self.client_address[0] or "?"
        except Exception:
            ip = "?"
        if not self._host_ok():
            self.close_connection = True
            self._err(403, "HOST_FORBIDDEN", "Host 头不是允许的本地源（DNS rebinding 防护）")
            return False
        if not self._origin_ok():
            self.close_connection = True
            self._err(403, "CROSS_ORIGIN_DENIED", "跨源请求被拒绝（CORS 默认拒绝）")
            return False
        if not _LIMITER.allow(ip):
            self.close_connection = True
            self._err(429, "RATE_LIMITED", "超过 %d 请求/%ds" % (RATE_MAX, int(RATE_WINDOW)))
            return False
        return True

    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        if not host:
            return False
        if host.startswith("["):  # IPv6 字面量
            h, _, rest = host[1:].partition("]")
            port = rest[1:] if rest.startswith(":") else ""
        else:
            h, _, port = host.partition(":")
        h = h.lower().rstrip(".")
        if h not in ("127.0.0.1", "localhost", "::1"):
            return False
        if port and port != str(self.server.server_address[1]):
            return False
        return True

    def _origin_ok(self):
        origin = self.headers.get("Origin")
        if origin:
            port = self.server.server_address[1]
            allowed = {"http://127.0.0.1:%d" % port, "http://localhost:%d" % port}
            if origin.rstrip("/") not in allowed:
                return False
        sfs = self.headers.get("Sec-Fetch-Site")
        if sfs and sfs not in ("same-origin", "none"):
            return False
        return True

    # ── /api/v1/logs 鉴权（R7-UI-LOG-AUTH-009）：未配置 WENQU_DASHBOARD_KEY →
    #    默认 403（fail-closed，与写接口关闭同范式）；配置后须携带匹配的
    #    X-Auth-Key（hmac 常数时间比较，防时序侧信道）——日志敏感面绝不匿名可读 ──
    def _logs_auth(self):
        key = (os.environ.get("WENQU_DASHBOARD_KEY") or "").strip()
        if not key:
            return False, "LOGS_AUTH_UNCONFIGURED"
        provided = self.headers.get("X-Auth-Key") or ""
        if not hmac.compare_digest(provided.encode("utf-8", "replace"),
                                   key.encode("utf-8", "replace")):
            return False, "LOGS_AUTH_FORBIDDEN"
        return True, ""

    # ── 静态文件（白名单精确匹配——无路径参数即无穿越面） ──
    def _serve_static(self, fname, ctype):
        try:
            with open(os.path.join(DASH_DIR, fname), "rb") as f:
                data = f.read()
        except OSError as e:
            return self._err(500, "STATIC_READ_ERROR", str(e))
        self._send(200, data, ctype)

    # ── GET：严格只读（零写路径；health 只读 aggregator 快照） ──
    def do_GET(self):
        if not self._gate():
            return
        path = self.path.split("?", 1)[0]
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        if path in STATIC_FILES:
            fname, ctype = STATIC_FILES[path]
            return self._serve_static(fname, ctype)
        if not path.startswith("/api/"):
            return self._err(404, "NOT_FOUND", "路径不存在：%s" % path)
        if not path.startswith("/api/v1/"):
            return self._err(404, "API_VERSION_REQUIRED", "API 已版本化为 /api/v1/*；未版本化路径已废止")
        ep = path[len("/api/v1/"):]
        qs = parse_qs(query)

        if ep == "ping":
            return self._json(200, {"pong": True, "server": SERVER_VERSION})
        if ep == "components":
            return self._json(200, read_components())
        if ep == "daemons":
            return self._json(200, read_daemons())
        if ep == "ratchet":
            return self._json(200, read_ratchet())
        if ep == "rounds":
            return self._json(200, read_rounds())
        if ep == "rounds-heat":
            return self._json(200, read_rounds_heat())
        if ep == "logs":
            ok, code = self._logs_auth()
            if not ok:
                self.close_connection = True
                return self._err(403, code,
                                 "日志端点需鉴权：配置 WENQU_DASHBOARD_KEY 并携带匹配的 "
                                 "X-Auth-Key（未配置 key 时默认 403——fail-closed）")
            return self._send(200, read_logs())
        if ep == "health":
            r = read_gate_aggregate()
            if not r["ok"]:
                return self._err(503, r["code"], r["detail"])
            out = dict(r["data"])
            out.setdefault("source", "gate-aggregator")
            return self._json(200, out)
        if ep == "health-history":
            return self._json(200, read_health_history())
        if ep == "bugscan-ledger":
            d = bugscan_ledger()
            if "_all_items" in d:  # 无参请求不下发内部全集；?items=STATE 按状态过滤钻取
                want = (qs.get("items") or [""])[0]
                d = dict(d)
                full = d.pop("_all_items")
                if want:
                    d["items_state"] = want
                    d["items_total"] = sum(1 for x in full if x["st"] == want)
                    d["items"] = [x for x in full if x["st"] == want][:60]
            return self._json(200, d)
        if ep == "decisions":
            return self._json(200, read_decisions(want_all="1" in (qs.get("all") or [])))
        return self._err(404, "NOT_FOUND", "未知端点：/api/v1/%s" % ep)

    def do_HEAD(self):
        if not self._gate():
            return
        path = self.path.split("?", 1)[0]
        if path in STATIC_FILES:
            fname, ctype = STATIC_FILES[path]
            try:
                size = os.path.getsize(os.path.join(DASH_DIR, fname))
            except OSError:
                return self._err(404, "NOT_FOUND", path)
            self.send_response(200)
            self._sec_headers()
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            return
        self._err(404, "NOT_FOUND", "HEAD 仅支持静态资源")

    # ── POST：第一阶段写接口全关（/api/decide → 405）；其余路径做体量/类型校验后 404 ──
    def do_POST(self):
        if not self._gate():
            return
        path = self.path.split("?", 1)[0]
        if path in ("/api/decide", "/api/v1/decide"):
            self.close_connection = True
            return self._err(405, "WRITE_DISABLED",
                             "第一阶段关闭写接口（decide POST 已禁用）——只读仪表盘", allow="GET, HEAD")
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if te and te != "identity":
            self.close_connection = True
            return self._err(411, "LENGTH_REQUIRED", "不支持 chunked 请求体")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            return self._err(400, "BAD_LENGTH", "Content-Length 非法")
        if n > MAX_BODY:
            self.close_connection = True
            return self._err(413, "BODY_TOO_LARGE", "请求体超限（>%d 字节）" % MAX_BODY)
        if n > 0:
            ct = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ct != "application/json":  # Content-Type 精确校验（仅接受 application/json）
                self.close_connection = True
                return self._err(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type 必须为 application/json")
            try:
                self.rfile.read(n)
            except OSError:
                return
        self._err(404, "NOT_FOUND", "POST 端点不存在（第一阶段写接口全关）")

    def _method_not_allowed(self):
        if not self._gate():
            return
        self.close_connection = True
        self._err(405, "METHOD_NOT_ALLOWED", "方法不被允许", allow="GET, HEAD")

    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_OPTIONS = _method_not_allowed  # 不回 CORS 预检头 = 跨源预检必败


# ───────────────────────────── 自检 ─────────────────────────────
def self_check(port):
    global _LOG_ENABLED
    _LOG_ENABLED = False
    print("== wenqu dashboard W8 self-check ==")
    fails = []

    def ck(name, cond):
        print(("  ✓ " if cond else "  ✗ ") + name)
        if not cond:
            fails.append(name)

    def readf(p):
        try:
            with open(os.path.join(DASH_DIR, p), encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    # ── 静态检查 ──
    ck("index.html/app.css/app.js 三件在位",
       all(os.path.isfile(os.path.join(DASH_DIR, x)) for x in ("index.html", "app.css", "app.js")))
    html = readf("index.html")
    js = readf("app.js")
    css = readf("app.css")
    src = readf("server.py")
    ck("CSP meta（default-src/script-src/style-src 'self'）",
       "default-src 'self'" in html and "script-src 'self'" in html and "style-src 'self'" in html)
    ck("安全 meta：nosniff / frame-ancestors 'none' / no-store / no-referrer",
       "nosniff" in html and "frame-ancestors 'none'" in html and "no-store" in html and "no-referrer" in html)
    ck("引用 app.css 与 app.js（外链，无内联脚本）",
       'href="app.css"' in html and 'src="app.js"' in html and "<style" not in html)
    ck("四页签容器 ov/pipe/deck/bugdeck + data-t 导航",
       all('id="%s"' % x in html for x in ("ov", "pipe", "deck", "bugdeck")) and html.count("data-t=") == 4)
    ck("index.html 无内联事件（onclick=）", "onclick=" not in html)
    ck("index.html div 平衡", html.count("<div") == html.count("</div>"))
    # UI-01 第七轮根修（R7 实证：只对 div 计数，删 </span> 漏报）——字符串配对门
    # 补全常见标签开闭计数：任一标签开闭不齐必须红（void 标签 meta/link 不入列）。
    tag_pairs = ("span", "div", "p", "a", "li", "ul", "ol", "table", "thead",
                 "tbody", "tr", "td", "th", "script", "style", "title",
                 "head", "body", "html", "h1", "h2", "h3", "nav", "button",
                 "details", "summary", "b", "i")
    imbalance = []
    for tag in tag_pairs:
        n_open = len(re.findall(r"<%s(?=[\s/>])" % tag, html, re.I))
        n_close = len(re.findall(r"</%s\s*>" % tag, html, re.I))
        if n_open != n_close:
            imbalance.append("%s 开%d/闭%d" % (tag, n_open, n_close))
    ck(("index.html 常见标签开闭配对平衡（span/div/p/a/li/…/html 共 %d 类）" % len(tag_pairs))
       if not imbalance else
       ("index.html 标签开闭配对失衡（配对门）: " + "; ".join(imbalance)),
       not imbalance)
    ck("app.js 零 innerHTML/insertAdjacentHTML/document.write（T-05 XSS 面）",
       "innerHTML" not in js and "insertAdjacentHTML" not in js and "document.write" not in js)
    ck("app.js textContent + showTab(data-t) + /api/v1/",
       "textContent" in js and "dataset.t" in js and "showTab" in js and "/api/v1/" in js)
    ck("app.css 非空且含核心类", len(css) > 1500 and ".scard" in css and ".hidden" in css and ".errbox" in css)
    ck("server.py 关键控制存在（版本化/限速/405/Host/回环绑定）",
       all(t in src for t in ("/api/v1/", "RateLimiter", "405", "_host_ok", "127.0.0.1", "ThreadingHTTPServer")))

    # ── 动态检查：起真实服务打真实请求 ──
    bind_port = port
    warn = None
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", bind_port), Handler)
    except OSError:
        warn = "端口 %d 被占用（旧实例仍在跑），动态检查改用临时回环端口" % bind_port
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        bind_port = srv.server_address[1]
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        import http.client as hc

        def req(method, path, headers=None, body=None):
            conn = hc.HTTPConnection("127.0.0.1", bind_port, timeout=10)
            try:
                conn.request(method, path, body=body, headers=headers or {})
                r = conn.getresponse()
                data = r.read()
                hdrs = {k.lower(): v for k, v in r.getheaders()}
            finally:
                conn.close()
            try:
                j = json.loads(data)
            except ValueError:
                j = None
            return r.status, hdrs, data, j

        s, h, b, j = req("GET", "/")
        ck("GET / → 200 text/html", s == 200 and h.get("content-type", "").startswith("text/html"))
        csp = h.get("content-security-policy", "")
        ck("响应头 CSP 含 default-src 'self' + frame-ancestors 'none'",
           "default-src 'self'" in csp and "frame-ancestors 'none'" in csp)
        ck("响应头 nosniff/DENY/no-store/no-referrer",
           h.get("x-content-type-options") == "nosniff" and h.get("x-frame-options") == "DENY"
           and h.get("cache-control") == "no-store" and h.get("referrer-policy") == "no-referrer")
        ck("无 Access-Control-Allow-* 头（CORS 默认拒绝）",
           not any(k.startswith("access-control-allow-") for k in h))
        ck("页面含 CSP meta 与四容器",
           b"Content-Security-Policy" in b and all(('id="%s"' % x).encode() in b
                                                   for x in ("ov", "pipe", "deck", "bugdeck")))
        s, h, _, _ = req("GET", "/app.css")
        ck("GET /app.css → 200 text/css", s == 200 and h.get("content-type", "").startswith("text/css"))
        s, h, _, _ = req("GET", "/app.js")
        ck("GET /app.js → 200 application/javascript",
           s == 200 and h.get("content-type", "").startswith("application/javascript"))
        s, _, _, j = req("GET", "/api/v1/ping")
        ck("GET /api/v1/ping → 200 pong", s == 200 and isinstance(j, dict) and j.get("pong") is True)
        s, _, _, j = req("GET", "/api/v1/components")
        ck("GET /api/v1/components → 200 含 version", s == 200 and isinstance(j, dict) and "version" in j)
        s, _, _, j = req("GET", "/api/v1/health")
        ck("/api/v1/health 读 gate_aggregator（200 判定透传 或 503 结构化 ERROR，绝不 200+空集）",
           (s == 200 and isinstance(j, dict) and any(k in j for k in ("policy_verdict", "overall", "verdict")))
           or (s == 503 and isinstance(j, dict) and isinstance(j.get("error"), dict)
               and bool(j["error"].get("code"))))
        s, _, _, j = req("POST", "/api/decide", headers={"Content-Type": "application/json"},
                         body=json.dumps({"id": "x", "action": "take"}))
        ck("POST /api/decide → 405（第一阶段写接口关闭）",
           s == 405 and isinstance(j, dict) and j.get("error", {}).get("code") == "WRITE_DISABLED")
        s, _, _, _ = req("POST", "/api/v1/decide", headers={"Content-Type": "application/json"}, body="{}")
        ck("POST /api/v1/decide → 405", s == 405)
        s, _, _, j = req("GET", "/api/components")
        ck("未版本化 /api/* → 404 API_VERSION_REQUIRED",
           s == 404 and isinstance(j, dict) and j.get("error", {}).get("code") == "API_VERSION_REQUIRED")
        s, _, _, _ = req("GET", "/", headers={"Host": "evil.example.com:%d" % bind_port})
        ck("伪 Host（DNS rebinding）→ 403", s == 403)
        s, _, _, _ = req("GET", "/", headers={"Origin": "http://evil.example.com"})
        ck("跨源 Origin → 403", s == 403)
        s, _, _, _ = req("GET", "/", headers={"Sec-Fetch-Site": "cross-site"})
        ck("Sec-Fetch-Site: cross-site → 403", s == 403)
        s, _, _, j = req("POST", "/api/v1/x", headers={"Content-Length": "1000000"}, body="x")
        ck("超大请求体 → 413", s == 413 and j.get("error", {}).get("code") == "BODY_TOO_LARGE")
        s, _, _, j = req("POST", "/api/v1/x", headers={"Content-Type": "text/plain"}, body="hello")
        ck("Content-Type 非 application/json → 415",
           s == 415 and j.get("error", {}).get("code") == "UNSUPPORTED_MEDIA_TYPE")
        s, _, _, _ = req("GET", "/../server.py")
        ck("路径穿越 /../server.py → 404", s == 404)
        s, _, _, _ = req("OPTIONS", "/api/v1/ping")
        ck("OPTIONS（CORS 预检）→ 405 且无 ACAO", s == 405)
        # 日志端点鉴权（R7-UI-LOG-AUTH-009，沙箱 key 现场注入，跑完还原环境）
        _saved_key = os.environ.get("WENQU_DASHBOARD_KEY")
        try:
            os.environ.pop("WENQU_DASHBOARD_KEY", None)
            s, _, _, j = req("GET", "/api/v1/logs")
            ck("/api/v1/logs 未配置 key → 403 LOGS_AUTH_UNCONFIGURED（fail-closed）",
               s == 403 and isinstance(j, dict)
               and j.get("error", {}).get("code") == "LOGS_AUTH_UNCONFIGURED")
            os.environ["WENQU_DASHBOARD_KEY"] = "selfcheck-log-key"
            s, _, _, j = req("GET", "/api/v1/logs")
            ck("/api/v1/logs 配置 key 但无 X-Auth-Key → 403",
               s == 403 and j.get("error", {}).get("code") == "LOGS_AUTH_FORBIDDEN")
            s, _, _, j = req("GET", "/api/v1/logs", headers={"X-Auth-Key": "wrong-key"})
            ck("/api/v1/logs 错误 X-Auth-Key → 403",
               s == 403 and j.get("error", {}).get("code") == "LOGS_AUTH_FORBIDDEN")
            s, _, _, _ = req("GET", "/api/v1/logs", headers={"X-Auth-Key": "selfcheck-log-key"})
            ck("/api/v1/logs 正确 X-Auth-Key → 200", s == 200)
        finally:
            if _saved_key is None:
                os.environ.pop("WENQU_DASHBOARD_KEY", None)
            else:
                os.environ["WENQU_DASHBOARD_KEY"] = _saved_key
        # 速率限制（放最后：耗尽窗口不影响前面用例）
        limited = 0
        for _ in range(RATE_MAX + 60):
            st, _, _, _ = req("GET", "/api/v1/ping")
            if st == 429:
                limited += 1
        ck("速率限制触发（连续请求超 %d/%ds 出现 429）" % (RATE_MAX, int(RATE_WINDOW)), limited > 0)
    finally:
        srv.shutdown()
        srv.server_close()

    if warn:
        print("  ⚠ " + warn)
    if fails:
        print("RESULT: FAIL（%d 项未过：%s）" % (len(fails), "; ".join(fails)))
        return 1
    print("RESULT: PASS")
    return 0


# ───────────────────────────── 入口 ─────────────────────────────
def main(argv=None):
    global _LOG_ENABLED
    ap = argparse.ArgumentParser(description="wenqu dashboard W8（只读安全版）")
    ap.add_argument("--port", type=int, default=PORT_DEFAULT, help="监听端口（默认 %d）" % PORT_DEFAULT)
    ap.add_argument("--self-check", action="store_true", help="自检：静态+动态安全用例，输出 PASS/FAIL 后退出")
    ap.add_argument("--log", action="store_true", help="输出访问日志到 stderr")
    args = ap.parse_args(argv)

    if args.self_check:
        sys.exit(self_check(args.port))

    _LOG_ENABLED = args.log
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)  # 仅回环绑定
    stop_evt = threading.Event()
    writer = threading.Thread(target=health_history_writer, args=(stop_evt,), daemon=True,
                              name="health-history-writer")  # 写入与 GET 解耦：独立定时任务
    writer.start()
    print(f"wenqu dashboard (W8) → http://127.0.0.1:{args.port}  (Ctrl-C 停；写接口第一阶段已关)")
    print(f"  health 正源 = gate_aggregator 快照（{os.environ.get('WENQU_GATE_AGGREGATE') or os.path.join(WQ, 'state', 'gate-aggregate.json')}）")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()
        srv.shutdown()
        srv.server_close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""window_manifest.py——G9-02 动态观察窗 manifest（sealed window manifest）。

替代旧硬编码窗口起点（2026-10-10 一类）：窗口的 T0 不再写死在代码里，
而是「首条合格样本时刻」；起止、时长、Sfinal、tree/roots digests、首样本
hash 全部登记在 `<observation_root>/windows/<window_id>.json`：

  {
    "schema": "obs-window-manifest-v1",
    "window_id":  "w-<utc-ns>-<hex>",     # 唯一，open 时生成/指定
    "epoch_id":   "e-<uuid4>",            # 样本 hash chain 的链属
    "kind":       "w10-observation",
    "status":     "open" | "sealed",      # sealed 后不可再变更
    "created_at": ISO-UTC,
    "duration_hours": 336.0,              # 窗口时长（T0+duration=end）
    "sfinal":     "<40hex | null>",
    "digests":    {"tree": …, "roots": …, "release": …},
    "t0":                 null | ISO,     # 首条合格样本时刻（动态起点）
    "first_sample_sha256": null | hex,
    "start_at":   null | ISO,             # == t0
    "end_at":     null | ISO,             # == t0 + duration
    "sealed_at":  null | ISO,
    "canary_hours": 48,                   # W9 canary 窗（锚点同样是 t0）
    "history":    [ {action, at, detail} … ]
  }

生命周期：
  open_window()      O_EXCL 创建 status=open（存在同 id → 拒绝）；T2 收紧
                     （R9-OBS-T0-QUALIFICATION-002）：开窗必须携带十项前置
                     要素（prerequisites），缺任一/任一非法 →
                     WindowPrereqError（CLI rc3），绝不 sfinal=null 起钟；
  note_first_sample() W11-05：锚定【最早合格】样本——原子记录 t0 /
                     first_qualified_sequence / first_qualified_sample_sha256
                     / pre_t0_attempts（锚点前样本审计，不进分母不使窗口
                     失败）；仅 open 期可写，幂等，锚点冲突 → rc1/rc3 语义；
  seal_window()      封口（幂等；未锚定时按严格链重选最早合格样本补锚，
                     不采信样本自报 qualified）；
  invalidate_window() W11-06 单一提交点：不可变 <wid>.invalidated.json 是
                     唯一作废提交点（O_EXCL|O_NOFOLLOW 临时文件 + fsync +
                     原子 no-overwrite publish + fsync 目录）；manifest 原字
                     节保持不动，reader 经 effective_status 计算 effective
                     状态；同参数幂等 rc0 / 参数冲突 rc1 / 损坏·hash·symlink
                     rc3；legacy（event+已改 manifest）兼容识别；
  repair_anchor()    W11-05 崩溃恢复：样本在、锚无 → 严格链重选最早合格
                     补锚（rc0 已锚/补锚/无需；1 暂无合格；3 坏链/冲突）；
  active_manifest()  取当前唯一「open 且未过期」的 manifest；多个活跃
                     manifest = 环境错误（WindowAmbiguityError）；作废事件
                     在场的窗口绝不活跃；从未锚定且名义到期不占活跃位。
互斥（W11-05）：根级 windows/.window.lock 覆盖 open/sample/anchor/seal/
invalidate（flock 跨进程 + 线程本地重入）。

T0 十项前置（T0_PREREQUISITES，开窗 digests 块唯一来源，缺一=拒开）：
  1  sfinal             release 终 SHA（40hex 非零；--release）
  2  tree               commit tree 摘要（64hex 非零）
  3  roots              roots digest（64hex 非零）
  4  registry           registry 语义 digest（64hex 非零）
  5  branch             branch governance digest（64hex 非零）
  6  evidence_schema    evidence active schema digest（64hex 非零）
  7  observer           observer 脚本 digest（64hex 非零；样本 observer_sha 咬合）
  8  ci_run_id          exact CI run id（数字非空）
  9  health             health 面：health_target_sha==sfinal 且非零、
                       health_scope 非 self_declared
  10 capacity           capacity_gate 必须为 OPEN（BLOCKED/CRITICAL=拒开）

纪律：纯标准库；测试全部经 tmp 根注入，不写真实 ~/.wenqu。
CLI rc 契约：0=成功；1=冲突/失败；3=证据环境错误（含十项前置缺失/非法）。
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

SCHEMA = "obs-window-manifest-v1"
INVALIDATION_SCHEMA = "obs-window-invalidation-v1"
DEFAULT_DURATION_HOURS = 336.0  # W10 观察窗缺省 14 天
DEFAULT_CANARY_HOURS = 48.0

# CLI 直跑时把自身注册为 import 名——防止 __main__ 与 window_manifest 双实例
# （否则窗口锁的线程本地重入状态分裂，嵌套 acquire 会开新 fd 被 flock 自锁死）
if __name__ == "__main__" and "window_manifest" not in sys.modules:
    sys.modules["window_manifest"] = sys.modules[__name__]

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA64_RE = re.compile(r"^[0-9a-f]{64}$")
CI_RUN_RE = re.compile(r"^[0-9]{1,64}$")
ZERO40 = "0" * 40
ZERO64 = "0" * 64

#: T0 十项前置正名表（名称, 语义）——资格判定/收割/作废共用同一正源。
T0_PREREQUISITES = (
    ("sfinal", "release 终 SHA（40hex 非零；--release）"),
    ("tree", "commit tree 摘要（64hex 非零）"),
    ("roots", "roots digest（64hex 非零）"),
    ("registry", "registry 语义 digest（64hex 非零）"),
    ("branch", "branch governance digest（64hex 非零）"),
    ("evidence_schema", "evidence active schema digest（64hex 非零）"),
    ("observer", "observer 脚本 digest（64hex 非零；样本 observer_sha 咬合）"),
    ("ci_run_id", "exact CI run id（数字非空）"),
    ("health", "health_target_sha==sfinal 非零 + health_scope 非 self_declared"),
    ("capacity", "capacity_gate 必须为 OPEN（BLOCKED/CRITICAL=拒开）"),
)

#: digests 块物理键（health 一项展开为 target_sha+scope 两键）。
PREREQ_DIGEST_KEYS = ("sfinal", "tree", "roots", "registry", "branch",
                      "evidence_schema", "observer", "ci_run_id",
                      "health_target_sha", "health_scope", "capacity_gate")

__all__ = [
    "SCHEMA", "INVALIDATION_SCHEMA", "T0_PREREQUISITES", "PREREQ_DIGEST_KEYS",
    "WindowError", "WindowPrereqError", "WindowAmbiguityError",
    "WindowConflictError", "WindowCorruptError", "manifest_dir",
    "manifest_path", "invalidation_path", "window_lock_path", "window_lock",
    "load_manifests", "load_manifest", "load_event", "effective_status",
    "window_invalidated", "validate_prerequisites", "prerequisites_from_env",
    "open_window", "seal_window", "note_first_sample", "invalidate_window",
    "repair_anchor", "active_manifest", "parse_iso", "utc_ns_stamp",
]


class WindowError(RuntimeError):
    """manifest 操作失败（已存在 / 状态非法 / 找不到等）。"""


class WindowPrereqError(WindowError):
    """T0 十项前置缺失/非法——fail-closed 拒开（CLI rc3）。"""


class WindowAmbiguityError(WindowError):
    """多个活跃 manifest——证据环境错误（rc3 语义）。"""


class WindowConflictError(WindowError):
    """与既有权威记录冲突（如锚点冲突/作废参数冲突）——CLI rc1 语义。"""


class WindowCorruptError(WindowError):
    """manifest/event 损坏、hash 不符、symlink 或不可读——CLI rc3 语义。"""


def utc_ns_stamp(now_ns=None):
    """UTC 纳秒紧凑串：YYYYMMDDTHHMMSS + 9 位纳秒（定宽，字典序=时间序）。"""
    ns = time.time_ns() if now_ns is None else int(now_ns)
    dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%S") + "%09d" % (ns % 1_000_000_000)


def parse_iso(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def manifest_dir(root):
    return os.path.join(root, "windows")


def manifest_path(root, window_id):
    return os.path.join(manifest_dir(root), window_id + ".json")


def invalidation_path(root, window_id):
    return os.path.join(manifest_dir(root), window_id + ".invalidated.json")


def window_lock_path(root):
    """W11-05 根级单一窗口锁：覆盖 open、sample、anchor、seal、invalidate。"""
    return os.path.join(manifest_dir(root), ".window.lock")


_lock_tls = threading.local()


class _ReentrantWindowLock:
    """flock 互斥（跨进程）+ 线程本地重入计数（同线程嵌套 open/seal/anchor
    不自锁死）；不同线程各持独立 fd——flock 语义下照常串行。"""

    def __init__(self, root):
        self._root = root

    def __enter__(self):
        depth = getattr(_lock_tls, "depth", 0)
        if depth == 0:
            path = window_lock_path(self._root)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                os.close(fd)
                raise
            _lock_tls.fd = fd
        _lock_tls.depth = depth + 1
        return self

    def __exit__(self, *exc):
        _lock_tls.depth = getattr(_lock_tls, "depth", 1) - 1
        if _lock_tls.depth == 0:
            fd = getattr(_lock_tls, "fd", None)
            _lock_tls.fd = None
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
        return False


def window_lock(root):
    return _ReentrantWindowLock(root)


def load_event(root, window_id):
    """读取作废事件（W11-06 唯一提交点）。无事件 → None；symlink/损坏/
    schema 不符 → WindowCorruptError（fail-visible，绝不静默跳过）。"""
    ipath = invalidation_path(root, window_id)
    if os.path.islink(ipath):
        raise WindowCorruptError(
            "invalidation event is a symlink (refusing): %s" % ipath)
    if not os.path.exists(ipath):
        return None
    try:
        with open(ipath, encoding="utf-8") as f:
            ev = json.load(f)
    except (OSError, ValueError) as e:
        raise WindowCorruptError(
            "invalidation event unreadable for %s: %s" % (window_id, e)) from e
    if not isinstance(ev, dict) or ev.get("schema") != INVALIDATION_SCHEMA:
        raise WindowCorruptError(
            "invalidation event bad schema for %s: %s" % (window_id, ipath))
    return ev


def _manifest_bytes_sha256(root, window_id):
    mpath = manifest_path(root, window_id)
    try:
        with open(mpath, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise WindowCorruptError(
            "manifest unreadable for %s: %s" % (window_id, e)) from e
    return raw, hashlib.sha256(raw).hexdigest()


def _verify_event_binding(root, window_id, manifest, event,
                          *, original_sha=None):
    """事件绑定校验：window/epoch 一致；genesis-未改形态（manifest status
    非 invalidated）要求事件 hash 与当前 manifest 字节严格咬合（篡改→
    WindowCorruptError）。legacy 已改 manifest 形态（旧 writer 双写完成态）
    不再逐字节比较——事件即权威（W11-06 合法兼容）。"""
    if event.get("window_id") != window_id:
        raise WindowCorruptError(
            "invalidation event window_id mismatch: %r != %r"
            % (event.get("window_id"), window_id))
    if event.get("epoch_id") != manifest.get("epoch_id"):
        raise WindowCorruptError(
            "invalidation event epoch_id mismatch for %s" % window_id)
    if manifest.get("status") == "invalidated":
        return  # legacy 已改 manifest 完成态：识别为 invalidated（不重起旧窗）
    if original_sha is None:
        _raw, original_sha = _manifest_bytes_sha256(root, window_id)
    if event.get("original_manifest_sha256") != original_sha:
        raise WindowCorruptError(
            "invalidation event hash mismatch for %s: event=%s manifest=%s "
            "(manifest mutated after invalidation? fail-closed)"
            % (window_id, str(event.get("original_manifest_sha256"))[:16],
               original_sha[:16]))


def effective_status(root, window_id):
    """W11-06 effective status：事件存在 → invalidated（无论 manifest 本体
    status）；撕裂态（manifest 已 invalidated 但无事件）→ WindowCorruptError。
    返回 (status, event|None)。"""
    manifest = load_manifest(root, window_id)
    event = load_event(root, window_id)
    if event is not None:
        _verify_event_binding(root, window_id, manifest, event)
        return "invalidated", event
    if manifest.get("status") == "invalidated":
        raise WindowCorruptError(
            "torn invalidation state: manifest %s status=invalidated but no "
            "audit event (pre-W11-06 writer tear; manual repair required)"
            % window_id)
    return manifest.get("status"), None


def window_invalidated(root, window_id):
    """事件在场即作废（撕裂/损坏 fail-visible 抛错）。"""
    status, _ev = effective_status(root, window_id)
    return status == "invalidated"


def _fsync_dir(dirpath):
    """目录 fsync（发布事件后落目录项；平台不支持则尽力而为）。"""
    try:
        dfd = os.open(dirpath, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dfd)
    except OSError:
        pass  # 某些平台对目录 fd fsync 不支持——尽力而为
    finally:
        os.close(dfd)


def _publish_event_no_overwrite(ipath, record):
    """W11-06 发布原语：O_EXCL|O_NOFOLLOW 临时文件 → write+fsync → 原子
    no-overwrite publish（link）→ fsync 目录。目标已存在 → 返回 False。"""
    d = os.path.dirname(ipath)
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, ".tmp-inval-" + uuid.uuid4().hex[:12] + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(tmp, flags, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, ipath)  # 原子 no-overwrite publish
        except FileExistsError:
            return False
        except OSError as e:
            raise WindowError(
                "cannot publish invalidation record %s: %s" % (ipath, e)) from e
        _fsync_dir(d)
        return True
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _atomic_write_json(path, payload):
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def _new_ids(now_ns=None):
    return ("w-" + utc_ns_stamp(now_ns) + "-" + uuid.uuid4().hex[:6],
            "e-" + uuid.uuid4().hex)


def validate_prerequisites(prereqs):
    """T0 十项前置校验（fail-closed）。返回 failures 列表（空=全部通过）。

    每条失败码：``missing:<key>`` / ``invalid:<key>`` / ``zero:<key>`` /
    ``mismatch:health_target_sha!=sfinal`` /
    ``self_declared:health_scope`` / ``capacity_not_open:capacity_gate``。"""
    p = prereqs if isinstance(prereqs, dict) else {}
    failures = []

    def _need(key, checker):
        if key not in p or p.get(key) in (None, ""):
            failures.append("missing:%s" % key)
            return
        bad = checker(p[key])
        if bad:
            failures.append(bad)

    for key in ("sfinal",):
        _need(key, lambda v: None if (isinstance(v, str) and SHA40_RE.match(v))
              else "invalid:%s" % key)
        if isinstance(p.get(key), str) and p[key] == ZERO40:
            failures.append("zero:%s" % key)
    for key in ("tree", "roots", "registry", "branch", "evidence_schema",
                "observer"):
        _need(key, lambda v, k=key: None if (isinstance(v, str)
                                             and SHA64_RE.match(v))
              else "invalid:%s" % k)
        if isinstance(p.get(key), str) and p[key] == ZERO64:
            failures.append("zero:%s" % key)
    _need("ci_run_id", lambda v: None if (isinstance(v, str)
                                          and CI_RUN_RE.match(v))
          else "invalid:ci_run_id")
    _need("health_target_sha", lambda v: None if (isinstance(v, str)
                                                  and SHA40_RE.match(v)
                                                  and v != ZERO40)
          else "invalid:health_target_sha")
    if ("health_target_sha" in p and p.get("health_target_sha") not in (None, "")
            and isinstance(p.get("sfinal"), str) and p["sfinal"]
            and p.get("health_target_sha") != p.get("sfinal")):
        failures.append("mismatch:health_target_sha!=sfinal")
    _need("health_scope", lambda v: None if (isinstance(v, str) and v.strip())
          else "invalid:health_scope")
    if isinstance(p.get("health_scope"), str) \
            and "self_declared" in p["health_scope"].lower():
        failures.append("self_declared:health_scope")
    _need("capacity_gate", lambda v: None if v == "OPEN"
          else "capacity_not_open:capacity_gate")
    # 保序去重
    seen, ordered = set(), []
    for f in failures:
        if f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered


def prerequisites_from_env(env=None):
    """从受管环境解析十项前置（供采样器 auto-open 使用，缺/坏 fail-closed）。

    来源（按序）：``WENQU_WINDOW_PREREQS_JSON``（内联 JSON 对象）或
    ``WENQU_WINDOW_PREREQS_FILE``（JSON 文件路径）。
    返回 (prereqs_dict_or_None, failures)；failures 非空时 prereqs=None。"""
    env = os.environ if env is None else env
    raw = env.get("WENQU_WINDOW_PREREQS_JSON")
    path = env.get("WENQU_WINDOW_PREREQS_FILE")
    if raw:
        try:
            doc = json.loads(raw)
        except ValueError as e:
            return None, ["prereqs_json_unparsable:%s" % str(e)[:120]]
    elif path:
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError) as e:
            return None, ["prereqs_file_unreadable:%s" % str(e)[:120]]
    else:
        return None, ["prereqs_absent:"
                      "no WENQU_WINDOW_PREREQS_JSON/WENQU_WINDOW_PREREQS_FILE"]
    if not isinstance(doc, dict):
        return None, ["prereqs_not_object"]
    failures = validate_prerequisites(doc)
    return (None, failures) if failures else (doc, [])


def open_window(root, *, window_id=None, epoch_id=None,
                duration_hours=DEFAULT_DURATION_HOURS,
                kind="w10-observation", canary_hours=DEFAULT_CANARY_HOURS,
                now=None, prerequisites=None):
    """创建一个新窗口 manifest（O_EXCL；同 window_id 已存在 → WindowError）。

    T2 收紧：必须携带十项前置 prerequisites（缺任一/任一非法 →
    WindowPrereqError）；十项要素全量写入 manifest 的 digests 块，
    顶层 sfinal=digests.sfinal——绝不 sfinal=null 起钟。"""
    if not isinstance(prerequisites, dict) or not prerequisites:
        raise WindowPrereqError(
            "window open refused: T0 ten prerequisites required "
            "(sfinal/tree/roots/registry/branch/evidence_schema/observer/"
            "ci_run_id/health/capacity); refusing to start clock with "
            "sfinal=null (R9-OBS-T0-QUALIFICATION-002)")
    failures = validate_prerequisites(prerequisites)
    if failures:
        raise WindowPrereqError(
            "window open refused: T0 prerequisites invalid: %s"
            % "; ".join(failures))
    wid, eid = _new_ids()
    wid = window_id or wid
    eid = epoch_id or eid
    if not re.match(r"^[A-Za-z0-9._:-]{1,128}$", wid):
        raise WindowError("illegal window_id: %r" % wid)
    if not re.match(r"^[A-Za-z0-9._:-]{1,128}$", eid):
        raise WindowError("illegal epoch_id: %r" % eid)
    path = manifest_path(root, wid)
    if os.path.exists(path):
        raise WindowError("window already exists: %s" % wid)
    if duration_hours is not None and float(duration_hours) <= 0:
        raise WindowError("duration_hours must be > 0")
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    digests = {k: prerequisites[k] for k in PREREQ_DIGEST_KEYS}
    doc = {
        "schema": SCHEMA,
        "window_id": wid,
        "epoch_id": eid,
        "kind": kind,
        "status": "open",
        "created_at": now_dt.astimezone(timezone.utc).isoformat(),
        "duration_hours": float(duration_hours),
        "sfinal": digests["sfinal"],
        "digests": digests,
        "t0": None,
        "first_sample_sha256": None,
        "start_at": None,
        "end_at": None,
        "sealed_at": None,
        "canary_hours": float(canary_hours),
        "history": [{"action": "open", "at":
                     now_dt.astimezone(timezone.utc).isoformat(),
                     "detail": "manifest created (O_EXCL); T0 ten "
                               "prerequisites sealed into digests"}],
    }
    try:
        with window_lock(root):  # W11-05：open 与 sample/anchor/seal/invalidate 同锁
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False, indent=2)
                f.write("\n")
    except FileExistsError:
        raise WindowError("window already exists: %s" % wid) from None
    except OSError as e:
        raise WindowError("cannot create manifest %s: %s" % (path, e)) from e
    return doc


def load_manifests(root):
    """读取全部 manifest。返回 (docs, errors)；errors 为证据环境错误清单。"""
    docs, errors = [], []
    d = manifest_dir(root)
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return docs, errors
    for n in names:
        if not n.endswith(".json") or n.endswith(".harvest.json") \
                or n.endswith(".invalidated.json"):
            continue
        p = os.path.join(d, n)
        try:
            with open(p, encoding="utf-8") as f:
                doc = json.load(f)
            if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
                errors.append({"file": n, "code": "bad_schema"})
                continue
            docs.append(doc)
        except (OSError, ValueError) as e:
            errors.append({"file": n, "code": "unparsable",
                           "error": str(e)[:200]})
    docs.sort(key=lambda m: (m.get("created_at") or "", m.get("window_id")))
    return docs, errors


def load_manifest(root, window_id):
    """单读一个 manifest；缺失/损坏 → WindowCorruptError（W11-06 rc3 语义）。"""
    p = manifest_path(root, window_id)
    try:
        with open(p, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        raise WindowCorruptError(
            "cannot load manifest %s: %s" % (window_id, e)) from e
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise WindowCorruptError("manifest %s bad schema" % window_id)
    return doc


def note_first_sample(root, manifest, *, sample_sha256, t0_iso, now=None,
                      sequence=None, pre_t0_attempts=None):
    """锚定 T0 到【合格】样本（W11-05）：原子记录 t0 /
    first_qualified_sequence / first_qualified_sample_sha256（兼容别名
    first_sample_sha256）/ pre_t0_attempts（锚点前样本审计：保留、严格验链、
    不进观察窗分母）。

    - 仅 open 期可写；作废窗（事件在场）拒绝变更（W11-06）；
    - 幂等：同锚 sha 重复提交 → 原样返回；
    - 冲突：已锚定到不同 sha → WindowConflictError（repair rc3 语义）。"""
    wid = manifest.get("window_id")
    if window_invalidated(root, wid):
        raise WindowError(
            "window %s invalidated; refuse anchor mutation" % wid)
    if manifest.get("status") != "open":
        raise WindowError("manifest %s not open (refuse mutation)" % wid)
    existing = (manifest.get("first_qualified_sample_sha256")
                or manifest.get("first_sample_sha256"))
    if existing:
        if existing == sample_sha256:
            return manifest  # 幂等
        raise WindowConflictError(
            "anchor conflict: window %s already anchored to %s; refusing %s"
            % (wid, existing, sample_sha256))
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    t0 = parse_iso(t0_iso)
    if t0 is None:
        raise WindowError("bad t0_iso: %r" % t0_iso)
    t0 = t0.astimezone(timezone.utc)
    end = t0 + timedelta(hours=float(manifest.get("duration_hours")
                                      or DEFAULT_DURATION_HOURS))
    iso = now_dt.astimezone(timezone.utc).isoformat()
    manifest = dict(manifest)
    manifest.update({
        "t0": t0.isoformat(),
        "first_sample_sha256": sample_sha256,
        "first_qualified_sequence": sequence,
        "first_qualified_sample_sha256": sample_sha256,
        "pre_t0_attempts": pre_t0_attempts or [],
        "start_at": t0.isoformat(),
        "end_at": end.isoformat(),
        "history": manifest.get("history", []) + [{
            "action": "first_sample", "at": iso,
            "detail": "t0 anchored to earliest qualified sample "
                      "(sequence=%s)" % sequence}],
    })
    _atomic_write_json(manifest_path(root, manifest["window_id"]), manifest)
    return manifest


def seal_window(root, window_id, *, first_sample=None, now=None):
    """封口窗口（幂等）。t0 未定时按 W11-05 严格重算最早合格样本补锚
    （解析全部样本、重算 hash、验链、按 sequence 重判资格——不采信样本
    自报 qualified）；作废窗（事件在场）拒绝封口。"""
    with window_lock(root):
        manifest = load_manifest(root, window_id)
        if window_invalidated(root, window_id):
            raise WindowError("window %s invalidated; seal refused"
                              % window_id)
        if manifest.get("status") == "sealed":
            return manifest
        now_dt = now or datetime.now(timezone.utc)
        if isinstance(now_dt, (int, float)):
            now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
        iso = now_dt.astimezone(timezone.utc).isoformat()
        if manifest.get("t0") is None:
            import observation_daily as od  # 同目录；严格链/资格单一正源
            anchored = False
            if isinstance(first_sample, dict) \
                    and first_sample.get("sample_sha256") \
                    and first_sample.get("collected_at"):
                cand = dict(first_sample)
                stored = cand.get("sample_sha256")
                recomputed = od.compute_sample_sha256(
                    {k: v for k, v in cand.items() if k != "sample_sha256"})
                ok, _reasons = od.qualify_sample_strict(cand, manifest)
                if stored == recomputed and ok:
                    try:
                        manifest = note_first_sample(
                            root, manifest,
                            sample_sha256=stored,
                            t0_iso=cand["collected_at"], now=now_dt,
                            sequence=cand.get("sequence"))
                        anchored = True
                    except WindowError:
                        anchored = False
            if not anchored:
                # 严格重算（样本目录全量解析+验链+最早合格样本，不采信自报）
                od.try_anchor_first_qualified(root, manifest, now=now_dt)
        manifest = load_manifest(root, window_id)
        manifest = dict(manifest)
        manifest["status"] = "sealed"
        manifest["sealed_at"] = iso
        manifest["history"] = manifest.get("history", []) + [{
            "action": "seal", "at": iso, "detail": "window sealed"}]
        _atomic_write_json(manifest_path(root, manifest["window_id"]), manifest)
        return manifest


def invalidate_window(root, window_id, *, reason, principal, now=None,
                      expect_manifest_sha256=None):
    """W11-06 作废单一提交点（R10-OBS-INVALIDATE-ATOMICITY-003）。

    - 不再同时修改两个权威文件：manifest 原字节保持不动，不可变
      ``<window>.invalidated.json`` 是唯一作废提交点，reader 计算
      effective status（见 effective_status）；
    - 事件绑定 window_id / epoch_id / 原 manifest 字节 sha256 / reason /
      principal / invalidated_at；
    - 发布：O_EXCL|O_NOFOLLOW 临时文件 → write+fsync → 原子 no-overwrite
      publish（link）→ fsync 目录；任何 failpoint 只留下「open 且无事件」
      或「invalidated 且事件完整」两种状态；
    - 幂等/冲突：同 reason+principal → 返回既有记录（rc0）；不同 →
      WindowConflictError（rc1）；预置/篡改/symlink/hardlink/hash 不符 →
      WindowCorruptError（rc3）；
    - legacy 兼容：event+已改 manifest（旧 writer 完成态）识别为已作废；
      撕裂态（manifest 已 invalidated 无事件）→ rc3，绝不静默补写。
    返回作废事件 dict。"""
    if not isinstance(reason, str) or not reason.strip():
        raise WindowError("invalidate requires non-empty reason")
    if not isinstance(principal, str) or not principal.strip():
        raise WindowError("invalidate requires non-empty principal")
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    with window_lock(root):  # 与 sample/anchor/seal/open 同锁串行
        manifest = load_manifest(root, window_id)
        _raw, original_sha = _manifest_bytes_sha256(root, window_id)
        if expect_manifest_sha256 is not None \
                and expect_manifest_sha256 != original_sha:
            raise WindowCorruptError(
                "manifest hash mismatch for %s: expected %s, on disk %s"
                % (window_id, expect_manifest_sha256[:16], original_sha[:16]))
        event = load_event(root, window_id)
        if event is not None:
            _verify_event_binding(root, window_id, manifest, event,
                                  original_sha=original_sha)
            if event.get("reason") == reason \
                    and event.get("principal") == principal:
                return event  # 同参数幂等（rc0）
            raise WindowConflictError(
                "invalidation record exists for %s with different "
                "reason/principal (recorded reason=%r principal=%r; "
                "refusing %r/%r)"
                % (window_id, event.get("reason"), event.get("principal"),
                   reason, principal))
        if manifest.get("status") == "invalidated":
            raise WindowCorruptError(
                "manifest %s status=invalidated but audit event missing "
                "(torn state from pre-W11-06 writer; manual repair required)"
                % window_id)
        iso = now_dt.astimezone(timezone.utc).isoformat()
        record = {
            "schema": INVALIDATION_SCHEMA,
            "window_id": window_id,
            "epoch_id": manifest.get("epoch_id"),
            "invalidated_at": iso,
            "reason": reason,
            "principal": principal,
            "original_manifest_sha256": original_sha,
            "original_manifest": manifest,
            "note": "single commit point (W11-06): genesis manifest bytes "
                    "retained unchanged; effective status computed by "
                    "reader (effective_status); never deleted",
        }
        published = _publish_event_no_overwrite(
            invalidation_path(root, window_id), record)
        if not published:
            # publish 撞上既有文件（锁外写手/竞态残留）→ 按事件既有内容裁定
            event = load_event(root, window_id)
            if event is None:
                raise WindowCorruptError(
                    "invalidation record path occupied by non-event file: %s"
                    % invalidation_path(root, window_id))
            _verify_event_binding(root, window_id, manifest, event,
                                  original_sha=original_sha)
            if event.get("reason") == reason \
                    and event.get("principal") == principal:
                return event
            raise WindowConflictError(
                "invalidation record exists for %s with different "
                "reason/principal" % window_id)
        return record


def repair_anchor(root, window_id=None, *, now=None):
    """W11-05 修复入口：样本已落盘、锚定缺失（崩溃恢复）时按严格链重选
    最早合格样本补锚。

    返回 dict（含 rc）：0 已锚（校验一致）/补锚成功/无需修改；
    1 暂无合格样本；3 坏链或冲突（含撕裂/作废/歧义）。"""
    import observation_daily as od
    with window_lock(root):
        try:
            if window_id:
                manifest = load_manifest(root, window_id)
            else:
                docs, _errs = load_manifests(root)
                opens = [m for m in docs if m.get("status") == "open"]
                if not opens:
                    return {"rc": 0, "status": "nothing_to_repair",
                            "detail": "no open window under %s"
                                      % manifest_dir(root)}
                if len(opens) > 1:
                    return {"rc": 3, "status": "ambiguous",
                            "detail": "multiple open windows: %s" % [
                                m.get("window_id") for m in opens]}
                manifest = opens[0]
            wid = manifest["window_id"]
            if manifest.get("status") == "sealed":
                return {"rc": 0, "status": "no_repair_needed",
                        "detail": "window %s sealed (not repairable scope)"
                                  % wid}
            status, _ev = effective_status(root, wid)
            if status == "invalidated":
                return {"rc": 3, "status": "invalidated",
                        "detail": "window %s invalidated; no repair" % wid}
            chain = od.strict_epoch_chain(
                od.samples_dir(root), manifest.get("epoch_id"),
                manifest=manifest)
            if chain["failures"]:
                return {"rc": 3, "status": "chain_broken",
                        "chain_failures": chain["failures"]}
            anchored_sha = (manifest.get("first_qualified_sample_sha256")
                            or manifest.get("first_sample_sha256"))
            if anchored_sha:
                fq = chain["first_qualified"]
                if fq is None or fq[1].get("sample_sha256") != anchored_sha:
                    return {"rc": 3, "status": "anchor_conflict",
                            "detail": "manifest anchor does not match "
                                      "earliest qualified sample in chain"}
                return {"rc": 0, "status": "already_anchored",
                        "window_id": wid,
                        "first_qualified_sequence":
                            manifest.get("first_qualified_sequence")}
            res = od.try_anchor_first_qualified(root, manifest, now=now)
            if res["status"] == "anchored":
                return {"rc": 0, "status": "anchored", "window_id": wid,
                        "first_qualified_sequence": res.get("sequence"),
                        "t0": res.get("t0")}
            if res["status"] == "none":
                return {"rc": 1, "status": "no_qualified_sample",
                        "window_id": wid,
                        "detail": "no qualified sample in epoch chain yet"}
            if res["status"] == "chain_error":
                return {"rc": 3, "status": "chain_broken",
                        "chain_failures": res.get("chain_failures")}
            return {"rc": 3, "status": res["status"], "window_id": wid}
        except WindowCorruptError as e:
            return {"rc": 3, "status": "corrupt", "error": str(e)}
        except WindowError as e:
            return {"rc": 3, "status": "error", "error": str(e)}


def active_manifest(root, *, now=None):
    """当前唯一「open 且未过期」的 manifest。

    - 无 → None（调用方可 auto-open 新窗口）；
    - 多个 → WindowAmbiguityError（证据环境错误，rc3）；
    - W11-06：事件在场的窗口 effective=invalidated，绝不活跃（撕裂/损坏
      事件 fail-visible 抛 WindowCorruptError）；
    - 过期判定：end_at 已定且 now > end_at；从未锚定（end 为空）的窗口按
      名义到期（created_at + duration_hours）计——T0 死锁窗口不再永久占用
      活跃位（W11-05）。
    """
    now_dt = now or datetime.now(timezone.utc)
    if isinstance(now_dt, (int, float)):
        now_dt = datetime.fromtimestamp(now_dt, tz=timezone.utc)
    docs, _ = load_manifests(root)
    active = []
    for m in docs:
        if m.get("status") != "open":
            continue
        # W11-06：作废事件在场 → effective invalidated → 不活跃
        ev = load_event(root, m.get("window_id", ""))
        if ev is not None:
            _verify_event_binding(root, m["window_id"], m, ev)
            continue
        end = parse_iso(m.get("end_at"))
        if end is not None and now_dt > end:
            continue
        if end is None and m.get("t0") is None:
            created = parse_iso(m.get("created_at"))
            try:
                dur = float(m.get("duration_hours") or DEFAULT_DURATION_HOURS)
            except (TypeError, ValueError):
                dur = DEFAULT_DURATION_HOURS
            if created is not None and now_dt > created + timedelta(hours=dur):
                continue  # 从未锚定且名义到期：不再活跃（由 seal/收割裁决）
        active.append(m)
    if len(active) > 1:
        raise WindowAmbiguityError(
            "multiple active windows: %s"
            % ", ".join(m.get("window_id", "?") for m in active))
    return active[0] if active else None


# ---------------------------------------------------------------- CLI

def _cli(argv=None):
    ap = argparse.ArgumentParser(
        prog="window_manifest",
        description="G9-02/T2 动态观察窗 manifest（open 需十项前置/seal/"
                    "invalidate 作废/show/list）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_open = sub.add_parser("open", help="创建新窗口 manifest（十项前置缺一=rc3 拒开）")
    p_open.add_argument("--root", required=True)
    p_open.add_argument("--window-id")
    p_open.add_argument("--duration-hours", type=float,
                        default=DEFAULT_DURATION_HOURS)
    p_open.add_argument("--canary-hours", type=float,
                        default=DEFAULT_CANARY_HOURS)
    p_open.add_argument("--kind", default="w10-observation")
    # T0 十项前置（缺任一 → rc3 拒开；--release 即 sfinal）
    p_open.add_argument("--release", "--sfinal", dest="release",
                        help="T0-1 release 终 SHA（40hex 非零）")
    p_open.add_argument("--tree", help="T0-2 commit tree 摘要（64hex）")
    p_open.add_argument("--roots", help="T0-3 roots digest（64hex）")
    p_open.add_argument("--registry", help="T0-4 registry 语义 digest（64hex）")
    p_open.add_argument("--branch", help="T0-5 branch governance digest（64hex）")
    p_open.add_argument("--evidence-schema", help="T0-6 evidence active "
                        "schema digest（64hex）")
    p_open.add_argument("--observer", help="T0-7 observer 脚本 digest（64hex）")
    p_open.add_argument("--ci-run-id", help="T0-8 exact CI run id（数字）")
    p_open.add_argument("--health-target-sha", help="T0-9 health target SHA "
                        "（40hex 非零且==release）")
    p_open.add_argument("--health-scope", help="T0-9 health scope（非 "
                        "self_declared）")
    p_open.add_argument("--capacity-gate", help="T0-10 容量闸（必须 OPEN）")
    p_inv = sub.add_parser("invalidate",
                           help="作废窗口（单一提交点=W11-06，不删文件）")
    p_inv.add_argument("--root", required=True)
    p_inv.add_argument("--window-id", required=True)
    p_inv.add_argument("--reason", required=True,
                       help="作废原因（入审计记录）")
    p_inv.add_argument("--principal", required=True,
                       help="作废人（入审计记录）")
    p_inv.add_argument("--expect-manifest-sha256", dest="expect_sha",
                       help="期望的原 manifest 字节 sha256（不符 → rc3）")
    p_rep = sub.add_parser(
        "repair", help="W11-05 锚定修复（最早合格样本补锚；rc0/1/3）")
    p_rep.add_argument("--root", required=True)
    p_rep.add_argument("--window-id")
    p_seal = sub.add_parser("seal", help="封口窗口（幂等）")
    p_seal.add_argument("--root", required=True)
    p_seal.add_argument("--window-id", required=True)
    p_show = sub.add_parser("show", help="打印 manifest")
    p_show.add_argument("--root", required=True)
    p_show.add_argument("--window-id")
    p_list = sub.add_parser("list", help="列出全部 manifest")
    p_list.add_argument("--root", required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "open":
            prerequisites = {
                "sfinal": args.release,
                "tree": args.tree,
                "roots": args.roots,
                "registry": args.registry,
                "branch": args.branch,
                "evidence_schema": args.evidence_schema,
                "observer": args.observer,
                "ci_run_id": args.ci_run_id,
                "health_target_sha": args.health_target_sha,
                "health_scope": args.health_scope,
                "capacity_gate": args.capacity_gate,
            }
            failures = validate_prerequisites(prerequisites)
            if failures:
                print(json.dumps({"rc": 3, "refused": "open",
                                  "error": "T0 ten prerequisites invalid: %s"
                                           % "; ".join(failures),
                                  "failures": failures}, ensure_ascii=False))
                return 3
            doc = open_window(args.root, window_id=args.window_id,
                              duration_hours=args.duration_hours,
                              canary_hours=args.canary_hours,
                              prerequisites=prerequisites, kind=args.kind)
            print(json.dumps({"rc": 0, "window_id": doc["window_id"],
                              "epoch_id": doc["epoch_id"],
                              "sfinal": doc["sfinal"],
                              "digests_sealed": len(doc["digests"])},
                             ensure_ascii=False))
            return 0
        if args.cmd == "invalidate":
            record = invalidate_window(
                args.root, args.window_id, reason=args.reason,
                principal=args.principal,
                expect_manifest_sha256=args.expect_sha)
            print(json.dumps({"rc": 0,
                              "window_id": record["window_id"],
                              "status": "invalidated",
                              "invalidated_at": record["invalidated_at"],
                              "reason": record["reason"],
                              "principal": record["principal"],
                              "original_manifest_sha256":
                                  record["original_manifest_sha256"],
                              "record_file":
                                  os.path.basename(
                                      invalidation_path(args.root,
                                                        args.window_id))},
                             ensure_ascii=False))
            return 0
        if args.cmd == "repair":
            result = repair_anchor(args.root, args.window_id)
            out = dict(result)
            out["rc"] = int(result.get("rc", 3))
            print(json.dumps(out, ensure_ascii=False, default=str))
            return out["rc"]
        if args.cmd == "seal":
            doc = seal_window(args.root, args.window_id)
            print(json.dumps({"rc": 0, "status": doc["status"],
                              "window_id": doc["window_id"]}))
            return 0
        if args.cmd == "show":
            doc = (load_manifest(args.root, args.window_id)
                   if args.window_id else active_manifest(args.root))
            if doc is None:
                print(json.dumps({"error": "no active manifest"}))
                return 3
            print(json.dumps(doc, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "list":
            docs, errors = load_manifests(args.root)
            print(json.dumps({"windows": [
                {"window_id": m["window_id"], "status": m["status"],
                 "epoch_id": m["epoch_id"],
                 "sfinal": m.get("sfinal")} for m in docs],
                "errors": errors}, ensure_ascii=False))
            return 0
    except WindowPrereqError as e:
        print(json.dumps({"rc": 3, "refused": "open", "error": str(e)}))
        return 3
    except WindowAmbiguityError as e:
        print(json.dumps({"rc": 3, "error": str(e)}))
        return 3
    except WindowConflictError as e:  # W11-06：参数冲突 → rc1
        print(json.dumps({"rc": 1, "error": str(e)}))
        return 1
    except WindowCorruptError as e:   # W11-06：损坏/hash/symlink → rc3
        print(json.dumps({"rc": 3, "error": str(e)}))
        return 3
    except WindowError as e:
        print(json.dumps({"rc": 1, "error": str(e)}))
        return 1
    except OSError as e:
        print(json.dumps({"rc": 3, "error": str(e)}))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(_cli())

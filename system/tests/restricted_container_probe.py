#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""restricted_container_probe.py——W11-11：真实受限容器隔离不变量探针（W2 扣分根治）。

背景（十轮 W2 扣分「受限容器腿缺」）：CI 从未在「固定 digest 镜像 + 非 root +
只读 rootfs + pids/memory/cpu 限额」的真容器里执行过 Linux /proc token 扫杀与
TrustedRunner 超时击杀真腿。本探针由 acceptance.yml 的 required job
``restricted-container`` 在容器**内部**执行（docker run --user 非 root --read-only
--network none --cap-drop ALL --security-opt no-new-privileges --pids-limit
--memory --cpus + 仓库只读挂载 + /tmp 独立 tmpfs + 禁 Docker socket + 禁 pyc）。

退出码合同（与方案 W11-11 一致）：
  0   全部隔离不变量实测通过（含 W2 真腿全部运行且全绿）；
  1   任何限制可绕过（不变量被攻破 / 真腿失败）；
  2   参数错误（期望限额/UID 环境变量缺失或非法——docker run 参数面配错）；
  3   /proc、cgroup 或测量面不可验证（绝不 SKIP——缺环境=红，不是跳过）；
  124 由外层 timeout 产生（本脚本自身不返回 124）。

环境契约（由 workflow/预验 docker run -e 注入）：
  WQ_PIDS_LIMIT     期望 --pids-limit（int）
  WQ_MEMORY_BYTES   期望 --memory 字节数（int）
  WQ_CPU_QUOTA      期望 cpu.max quota（微秒，int）
  WQ_CPU_PERIOD     期望 cpu.max period（微秒，int）
  WQ_UID/WQ_GID     期望 --user 的 uid/gid（int，均不得为 0）
  WQ_COMMIT_SHA     触发 commit（仅记录进证据输出）
  PYTHONDONTWRITEBYTECODE=1（禁 pyc 合同）

用法（容器内）：
  python3 /wq/system/tests/restricted_container_probe.py
本机 docker 预验与 CI 同参数（见 /tmp/w11-11-evidence/ 与 workflow 注释）。
"""
import errno
import os
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import time

PROBE = os.path.abspath(__file__)
DEFAULT_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(PROBE)))
REPO_ROOT = os.environ.get("WQ_REPO_ROOT", DEFAULT_REPO_ROOT)

PASS_N, FAIL_N, FAILURES = 0, 0, []

#: W2 真腿清单：容器内必须全部运行（缺环境不得 SKIP）。self-runner 模式
#: （纯标准库，无网络也能跑），exit 0 + 输出 "RESULT: PASS=n FAIL=0" 判绿。
W2_LEGS = [
    ("linux-proc 真腿（/proc environ token 扫杀命中+收敛；TrustedRunner "
     "超时击杀 setsid+double-fork 逃逸 daemon）",
     "system/tests/test_linux_proc_path.py"),
    ("Runner 环境剥离/timeout/孙进程终止（P0-5/P0-8 daemon 化逃逸对抗）",
     "system/tests/test_runner_daemon.py"),
    ("CAS 负例（symlink swap/hardlink 预置/半写毒文件/SIGKILL 中断恢复）",
     "system/tests/test_infra_hardening.py"),
]

OOM_CHILD_CODE = (
    "import sys\n"
    "try:\n"
    "    with open('/proc/self/oom_score_adj', 'w') as fh:\n"
    "        fh.write('1000')\n"          # 让 cgroup OOM 必选本进程（父探针免误杀）
    "except OSError:\n"
    "    pass\n"
    "target = int(sys.argv[1])\n"
    "total = 0\n"
    "chunk = 1 << 20\n"
    "held = []\n"
    "while total < target:\n"             # 必须持引用：逐 MiB 触碰页，RSS 真实
    "    held.append(bytearray(chunk))\n" # 增长到限额之上（temp 对象会被 GC
    "    total += chunk\n"                # 回收，RSS 不涨=假越限——预验实锤过）
    "print('ALLOC_OK', total)\n"
)

SPIN_CHILD_CODE = (
    "import time\n"
    "end = time.time() + 3.0\n"
    "while time.time() < end:\n"
    "    pass\n"
)


def _ck(name, cond, detail=""):
    global PASS_N, FAIL_N
    if cond:
        PASS_N += 1
        print(f"  ✓ {name}", flush=True)
    else:
        FAIL_N += 1
        FAILURES.append(name)
        print(f"  ✗ {name} {detail}", flush=True)


def _die(code, tag, msg):
    """不可继续：参数错（2）或测量面不可验证（3）——缺环境绝不 SKIP。"""
    print(f"[{tag}] {msg}", flush=True)
    print(f"PROBE_EXIT={code} tag={tag}", flush=True)
    sys.exit(code)


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


def _status_field(name):
    for line in _read("/proc/self/status").splitlines():
        if line.startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    return None


def _write_fails(path):
    """真实写试探（非 os.access 推测）：OSError=只读生效。"""
    try:
        with open(path, "w") as fh:
            fh.write("wq-probe")
        return False  # 写成功 = 限制被绕过
    except OSError:
        return True


# ── 1. 参数面（exit 2）──────────────────────────────────────────────────
def _env_int(key, minimum=None):
    raw = os.environ.get(key)
    if raw is None or not raw.isdigit():
        _die(2, "PARAM_ERROR",
             f"缺少/非法环境变量 {key}={raw!r}——docker run 参数面与探针合同不符")
    val = int(raw)
    if minimum is not None and val < minimum:
        _die(2, "PARAM_ERROR", f"{key}={val} 低于最小值 {minimum}")
    return val


# ── 2. 测量面（exit 3：缺环境不得 SKIP）─────────────────────────────────
def _require_surface():
    if sys.platform != "linux":
        _die(3, "SURFACE_UNVERIFIABLE",
             f"非 Linux 平台（{sys.platform}）——受限容器真腿仅 Linux /proc 实测，"
             "不得降级为 SKIP")
    for path in ("/proc/self/status", "/proc/self/stat", "/sys/class/net"):
        if not os.path.exists(path):
            _die(3, "SURFACE_UNVERIFIABLE", f"测量面缺失：{path}")
    cg = "/sys/fs/cgroup"
    if not os.path.exists(os.path.join(cg, "cgroup.controllers")):
        _die(3, "SURFACE_UNVERIFIABLE",
             f"{cg} 不是 cgroup v2（无 cgroup.controllers）——限额读数面不可验证")
    for f in ("pids.max", "pids.current", "memory.max", "memory.swap.max",
              "cpu.max"):
        if not os.path.exists(os.path.join(cg, f)):
            _die(3, "SURFACE_UNVERIFIABLE", f"cgroup v2 读数面缺失：{cg}/{f}")


# ── 3. 隔离不变量（失败 → exit 1）───────────────────────────────────────
def _mount_fstype(mountpoint):
    """读 /proc/mounts，返回 mountpoint 最顶层（最后一条）挂载的 fstype。"""
    found = None
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == mountpoint:
                    found = parts[2]
    except OSError:
        _die(3, "SURFACE_UNVERIFIABLE", "/proc/mounts 不可读")
    return found


def _check_identity(uid, gid):
    _ck("不变量：euid 非 root 且等于合同 UID", os.geteuid() == uid != 0,
        f"euid={os.geteuid()} expect={uid}")
    _ck("不变量：egid 非 root 且等于合同 GID", os.getegid() == gid != 0,
        f"egid={os.getegid()} expect={gid}")


def _check_filesystems():
    # 挂载层内核真值（statvfs ST_RDONLY / /proc/mounts）——非 root 写试探会先
    # 撞 EACCES，无法区分权限拒绝与只读挂载；只读合同必须以挂载标志钉死。
    _ck("不变量：rootfs 挂载只读（statvfs ST_RDONLY）",
        bool(os.statvfs("/").f_flag & os.ST_RDONLY),
        f"flags={os.statvfs('/').f_flag:#x}")
    _ck(f"不变量：源码树只读挂载（statvfs ST_RDONLY @ {REPO_ROOT}）",
        bool(os.statvfs(REPO_ROOT).f_flag & os.ST_RDONLY),
        f"flags={os.statvfs(REPO_ROOT).f_flag:#x}")
    _ck("不变量：/tmp 独立 tmpfs（/proc/mounts 顶层 fstype）",
        _mount_fstype("/tmp") == "tmpfs",
        f"fstype={_mount_fstype('/tmp')!r}")
    # 行为面：真实写试探（写失败=拒绝生效；/tmp 按合同可写）
    _ck("不变量：rootfs 写入被拒（/ 真实写试探）", _write_fails("/.wq-rootfs-probe"))
    _ck("不变量：rootfs 写入被拒（/usr 真实写试探）",
        _write_fails("/usr/.wq-rootfs-probe"))
    _ck("不变量：源码树写入被拒（仓根真实写试探）",
        _write_fails(os.path.join(REPO_ROOT, ".wq-ro-probe")),
        f"repo={REPO_ROOT}")
    _ck("不变量：源码树写入被拒（system/tests 真实写试探）",
        _write_fails(os.path.join(os.path.dirname(PROBE), ".wq-ro-probe")))
    probe_tmp = None
    try:
        fd, probe_tmp = tempfile.mkstemp(prefix=".wq-tmp-probe-", dir="/tmp")
        with os.fdopen(fd, "w") as fh:
            fh.write("wq")
        ok = os.path.exists(probe_tmp)
        _ck("不变量：/tmp 独立 tmpfs 按合同可写（临时根可用）", ok,
            f"path={probe_tmp}")
    finally:
        if probe_tmp:
            try:
                os.unlink(probe_tmp)
            except OSError:
                pass


def _check_caps():
    _ck("不变量：CapEff=0（--cap-drop ALL+非 root 联合效果，内核真值）",
        (_status_field("CapEff") or "") == "0000000000000000",
        f"CapEff={_status_field('CapEff')}")
    _ck("不变量：NoNewPrivs=1（no-new-privileges 生效）",
        (_status_field("NoNewPrivs") or "") == "1",
        f"NoNewPrivs={_status_field('NoNewPrivs')}")


def _check_network():
    ifaces = set(os.listdir("/sys/class/net"))
    _ck("不变量：--network none（仅 lo，无外部网卡）", ifaces <= {"lo"},
        f"ifaces={sorted(ifaces)}")
    routed = []
    try:
        lines = _read("/proc/net/route").splitlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[0] != "lo":
                routed.append(line)
    except OSError:
        _die(3, "SURFACE_UNVERIFIABLE", "/proc/net/route 不可读")
    _ck("不变量：路由表无非 lo 表项（无出网路径）", not routed,
        f"routed={routed[:3]}")
    connected = False
    detail = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("192.0.2.1", 80))   # TEST-NET-1：合同上不可路由
        connected = True
    except OSError as exc:
        detail = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    _ck("不变量：TCP 出网连接必失败（socket 实测）", not connected, detail)


def _check_no_docker_socket():
    hits = [p for p in ("/var/run/docker.sock", "/run/docker.sock",
                        "/run/docker.pid") if os.path.exists(p)]
    _ck("不变量：Docker socket/PID 均不可达（未挂载且不存在）", not hits,
        f"found={hits}")


def _check_pids_limit(expected):
    import signal

    pmax = _read("/sys/fs/cgroup/pids.max")
    _ck(f"不变量：pids.max 限额可读且等于合同值 {expected}", pmax == str(expected),
        f"pids.max={pmax}")
    children, fork_err, saturated_current = [], None, None
    deadline = time.time() + 30.0
    try:
        while time.time() < deadline:
            try:
                pid = os.fork()
            except OSError as exc:
                fork_err = exc
                try:
                    saturated_current = _read("/sys/fs/cgroup/pids.current")
                except OSError:
                    pass
                break
            if pid == 0:                  # 子进程：纯睡眠占坑，等待父回收
                time.sleep(120)
                os._exit(0)
            children.append(pid)
    finally:
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except (ChildProcessError, OSError):
                pass
    errno_ok = fork_err is not None and fork_err.errno in (
        errno.EAGAIN, errno.ENOMEM)
    _ck("不变量：pids 限额真实生效（fork 饱和时被拒 EAGAIN/ENOMEM）", errno_ok,
        f"fork_err={fork_err!r}")
    _ck("不变量：饱和瞬间 pids.current == pids.max（顶到上限被拦）",
        saturated_current == pmax and pmax != "max",
        f"current={saturated_current} max={pmax}")
    _ck("不变量：进程数从未超过限额（children < limit）",
        len(children) < expected, f"forked={len(children)} limit={expected}")
    _ck("不变量：回收后 pids.current 回落（探针无泄漏）",
        _read("/sys/fs/cgroup/pids.current") != saturated_current,
        f"now={_read('/sys/fs/cgroup/pids.current')}")


def _check_memory_limit(expected_bytes):
    mmax = _read("/sys/fs/cgroup/memory.max")
    _ck(f"不变量：memory.max 限额可读且等于合同值 {expected_bytes}",
        mmax == str(expected_bytes), f"memory.max={mmax}")
    smax = _read("/sys/fs/cgroup/memory.swap.max")
    _ck("不变量：memory.swap.max=0（--memory-swap==memory，禁 swap 绕过）",
        smax == "0", f"swap.max={smax}")
    target = expected_bytes + (192 << 20)   # 限额 +192MiB 必然越限
    try:
        proc = subprocess.run(
            [sys.executable, "-c", OOM_CHILD_CODE, str(target)],
            capture_output=True, text=True, timeout=120,
        )
        rc, out = proc.returncode, (proc.stdout + proc.stderr)
    except subprocess.TimeoutExpired:
        rc, out = 124, "child timeout"
    _ck("不变量：memory 限额真实生效（越限子进程被 OOM 击杀/拒绝，未吃满限额+192MiB）",
        rc != 0 and "ALLOC_OK" not in out,
        f"rc={rc} out_tail={out[-120:]!r}")


def _check_cpu_limit(quota, period):
    cmax = _read("/sys/fs/cgroup/cpu.max").split()
    _ck(f"不变量：cpu.max 限额可读且等于合同值 {quota} {period}",
        len(cmax) == 2 and cmax[0] == str(quota) and cmax[1] == str(period),
        f"cpu.max={cmax}")
    quota_cpus = quota / period
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.time()
    procs = [subprocess.Popen([sys.executable, "-c", SPIN_CHILD_CODE])
             for _ in range(4)]
    for proc in procs:
        proc.wait()
    wall = time.time() - t0
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_used = (after.ru_utime + after.ru_stime) - (before.ru_utime
                                                    + before.ru_stime)
    _ck("不变量：CPU 限额真实生效（4 路满转实测 CPU≤配额×墙钟×1.5+1s）",
        cpu_used <= quota_cpus * wall * 1.5 + 1.0 and cpu_used >= 1.0,
        f"cpu={cpu_used:.2f}s wall={wall:.2f}s quota={quota_cpus}cpus "
        f"ratio={cpu_used / wall:.2f}")


def _check_no_pyc():
    _ck("不变量：PYTHONDONTWRITEBYTECODE=1（禁 pyc 合同注入）",
        os.environ.get("PYTHONDONTWRITEBYTECODE") == "1")
    _ck("不变量：sys.dont_write_bytecode 生效", bool(sys.dont_write_bytecode))
    moddir = tempfile.mkdtemp(prefix="wq-nopyc-", dir="/tmp")
    try:
        mod = os.path.join(moddir, "wq_probe_nopyc_mod.py")
        with open(mod, "w") as fh:
            fh.write("X = 41 + 1\n")
        sys.path.insert(0, moddir)
        import wq_probe_nopyc_mod  # noqa: F401
        pycache = os.path.join(moddir, "__pycache__")
        _ck("不变量：真实 import 后无 __pycache__ 落盘（tmpfs 可写仍零 pyc）",
            not os.path.exists(pycache) and wq_probe_nopyc_mod.X == 42,
            f"pycache={pycache}")
    finally:
        shutil.rmtree(moddir, ignore_errors=True)


# ── 4. W2 真腿（容器内全部运行；失败 → exit 1）─────────────────────────
def _run_w2_legs():
    for title, rel in W2_LEGS:
        path = os.path.join(REPO_ROOT, rel)
        if not os.path.exists(path):
            _die(3, "SURFACE_UNVERIFIABLE", f"W2 真腿文件缺失：{path}")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=420, cwd="/tmp",
            )
            out = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired as exc:
            _ck(f"W2 真腿：{rel}（{title}）", False, "真腿超时 420s")
            print((exc.output or "")[-400:] if isinstance(exc.output, str)
                  else "", flush=True)
            continue
        tail = [ln for ln in out.splitlines() if ln.strip()][-6:]
        for ln in tail:
            print(f"    | {ln}", flush=True)
        _ck(f"W2 真腿全绿：{rel}（{title}）",
            proc.returncode == 0 and "RESULT: PASS=" in out
            and "FAIL=0" in out,
            f"rc={proc.returncode}")
        if rel.endswith("test_linux_proc_path.py"):
            _ck("W2 真腿：linux-proc 两真腿零 SKIP（缺环境不得 SKIP）",
                "⏭ SKIP" not in out and "SKIP" not in out,
                "输出含 SKIP——真腿被降级跳过")


# ── main ────────────────────────────────────────────────────────────────
def main():
    uid = _env_int("WQ_UID", minimum=1)
    gid = _env_int("WQ_GID", minimum=1)
    pids_limit = _env_int("WQ_PIDS_LIMIT", minimum=16)
    memory_bytes = _env_int("WQ_MEMORY_BYTES", minimum=64 << 20)
    cpu_quota = _env_int("WQ_CPU_QUOTA", minimum=1000)
    cpu_period = _env_int("WQ_CPU_PERIOD", minimum=1000)
    sha = os.environ.get("WQ_COMMIT_SHA", "unset")

    _require_surface()

    print("== W11-11 真实受限容器隔离不变量探针 ==", flush=True)
    print(f"  repo={REPO_ROOT} probe={PROBE}", flush=True)
    print(f"  commit_sha={sha} image-contract: 非 root uid={uid} gid={gid} "
          f"pids={pids_limit} mem={memory_bytes}B cpu={cpu_quota}/{cpu_period}",
          flush=True)

    print("-- 身份（非 root UID/GID）", flush=True)
    _check_identity(uid, gid)
    print("-- 文件系统（rootfs 只读 / 源码树只读 / tmpfs 可写）", flush=True)
    _check_filesystems()
    print("-- 权能（CapEff=0 / NoNewPrivs=1）", flush=True)
    _check_caps()
    print("-- 网络（none）与 Docker socket 不可达", flush=True)
    _check_network()
    _check_no_docker_socket()
    print("-- cgroup 限额：可读且真实生效", flush=True)
    _check_pids_limit(pids_limit)
    _check_memory_limit(memory_bytes)
    _check_cpu_limit(cpu_quota, cpu_period)
    print("-- 禁 pyc", flush=True)
    _check_no_pyc()
    print("-- W2 真腿（Runner 剥离/超时/孙进程终止 + CAS 负例 + linux-proc）",
          flush=True)
    _run_w2_legs()

    print("=" * 40, flush=True)
    print(f"RESULT: PASS={PASS_N} FAIL={FAIL_N} "
          f"commit_sha={sha} uid={os.geteuid()} gid={os.getegid()}", flush=True)
    if FAILURES:
        for item in FAILURES:
            print(f"  ✗ {item}", flush=True)
    print(f"PROBE_EXIT={1 if FAIL_N else 0} "
          f"({'BYPASS_DETECTED' if FAIL_N else 'ALL_INVARIANTS_HELD'})",
          flush=True)
    sys.exit(1 if FAIL_N else 0)


if __name__ == "__main__":
    main()

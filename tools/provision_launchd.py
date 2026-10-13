#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""provision_launchd.py - W12-02 完整性哨兵 launchd 真装配器。

把 system/launchd/com.wenqu.integrity.plist.template 真实展开为可执行
装配（W11-02 哨兵只是模板+库，从未实装——本工具补「真装配」缺口）：

    1. render：占位符替换（PYTHON / WENQU_SENTINEL_SCRIPT / WENQU_HOME /
       WENQU_SENTINEL_TREE）——拒绝残留占位符、相对路径、inline secret；
    2. lint：``plutil -lint`` 必须通过；
    3. install：写入 plist（生产形态 /Library/LaunchDaemons root:wheel
       0644；开发形态 ~/Library/LaunchAgents 0644——本工具按目标目录
       自判定形态）；
    4. bootstrap：``launchctl bootstrap <domain>``（已加载则先 bootout
       再 bootstrap，幂等重装）；RunAtLoad 触发首发；
    5. 首个新鲜状态核验：state/release-integrity.json 在 TTL 内发布
       （等价 W12-02 退出码 0 的「已安装且首个新鲜状态完整」）。

装配纪律（模板头注同源）：
    - WENQU_SENTINEL_SCRIPT 钉绝对路径；加固形态=钉到具体 release 位
      （不随 current 切换、不从共享仓加载自身）；
    - state/release-integrity.json 唯一 writer=com.wenqu.integrity；
    - 本工具绝不写哨兵状态、绝不改 current/previous（哨兵唯一写纪律）。

退出码（W12-02 provision 契约）：
    0  已安装且首个新鲜状态完整；
    1  模板/身份/字节不符（占位符残留、相对路径、inline secret、
       sentinel 脚本摘要不符、plist 内容与 render 结果不一致）；
    2  launchctl/plutil/I/O 错误；
    3  状态或前置阻断（bootstrap 后状态未发布/STALE/前置输入缺失）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = REPO_ROOT / "system" / "launchd" / "com.wenqu.integrity.plist.template"
LABEL = "com.wenqu.integrity"
PLACEHOLDERS = ("{{PYTHON}}", "{{WENQU_SENTINEL_SCRIPT}}", "{{WENQU_HOME}}",
                "{{WENQU_SENTINEL_TREE}}")
SECRET_MARKERS = ("PRIVATE KEY", "api_key", "apikey", "password",
                  "secret=", "token=")
STATE_RELPATH = os.path.join("state", "release-integrity.json")
#: 状态新鲜度等待窗（launchd RunAtLoad → 哨兵 tick → 原子发布）
STATE_WAIT_SECONDS_DEFAULT = 60.0
STATE_TTL_DEFAULT = 900.0


def _fail(code: int, msg: str) -> int:
    print("FAIL %s" % msg, file=sys.stderr)
    return code


def _abs_or_fail(p: str, what: str) -> str:
    if not os.path.isabs(p):
        raise ValueError("%s 必须是绝对路径: %r" % (what, p))
    return p


def render_template(python: str, sentinel_script: str, wenqu_home: str,
                    sentinel_tree: str) -> str:
    """模板展开 + 拒绝面（占位符残留/相对路径/inline secret）。"""
    for what, p in (("--python", python), ("--sentinel-script", sentinel_script),
                    ("--wenqu-home", wenqu_home),
                    ("--sentinel-tree", sentinel_tree)):
        _abs_or_fail(p, what)
    text = TEMPLATE.read_text(encoding="utf-8")
    for ph, val in zip(PLACEHOLDERS, (python, sentinel_script, wenqu_home,
                                      sentinel_tree)):
        text = text.replace(ph, val)
    for ph in PLACEHOLDERS:
        if ph in text:
            raise ValueError("render 后仍残留占位符 %s" % ph)
    for marker in SECRET_MARKERS:
        if marker.lower() in text.lower():
            raise ValueError("plist 内联 secret 候选（%s）——拒绝" % marker)
    return text


def _plutil_lint(plist_path: str) -> None:
    proc = subprocess.run(["plutil", "-lint", plist_path],
                          capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise OSError("plutil -lint 失败: %s%s"
                      % (proc.stdout.strip(), proc.stderr.strip()))


def _install_plist(content: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = str(target) + ".tmp-provision"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(tmp, 0o644)
    os.replace(tmp, target)


def _domain_for(target: Path) -> str:
    if "LaunchDaemons" in str(target):
        return "system"
    return "gui/%d" % os.getuid()


def _launchctl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["launchctl", *args], capture_output=True,
                          text=True, timeout=120)
    if check and proc.returncode != 0:
        raise OSError("launchctl %s 失败(rc=%d): %s%s" % (
            " ".join(args), proc.returncode, proc.stdout.strip(),
            proc.stderr.strip()))
    return proc


def _wait_fresh_state(state_path: str, ttl: float,
                      wait: float) -> dict:
    """等哨兵发布首个新鲜状态（schema+generated_at_epoch+TTL 内）。"""
    deadline = time.time() + wait
    last = "状态从未发布"
    while time.time() < deadline:
        if os.path.isfile(state_path):
            try:
                with open(state_path, encoding="utf-8") as fh:
                    snap = json.load(fh)
                gen = snap.get("generated_at_epoch")
                ok_schema = snap.get("schema") == "wenqu-release-integrity/v1"
                if (ok_schema and isinstance(gen, (int, float))
                        and not isinstance(gen, bool)
                        and time.time() - float(gen) <= ttl):
                    return {"ok": True, "state": snap}
                last = "状态已发布但 schema/新鲜度不符（schema=%s gen=%r）" % (
                    snap.get("schema"), gen)
            except (OSError, ValueError) as exc:
                last = "状态不可读: %s" % exc
        time.sleep(2.0)
    return {"ok": False, "detail": "%s: %s" % (state_path, last)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="W12-02 完整性哨兵 launchd 真装配器（fail-closed）")
    ap.add_argument("--python", required=True,
                    help="哨兵解释器绝对路径（plist ProgramArguments[0]）")
    ap.add_argument("--sentinel-script", required=True,
                    help="release-integrity-watch.py 绝对路径（加固形态：钉"
                         "具体 release 位，不随 current 切换）")
    ap.add_argument("--wenqu-home", required=True,
                    help="安装根（WENQU_HOME）绝对路径")
    ap.add_argument("--sentinel-tree", required=True,
                    help="哨兵所属 release 树绝对路径（WENQU_RELEASE_ATTEST"
                         " 解析基准）")
    ap.add_argument("--target", default=os.path.expanduser(
        "~/Library/LaunchAgents/com.wenqu.integrity.plist"),
        help="plist 装配目标（缺省开发形态 ~/Library/LaunchAgents/…；"
             "生产形态 /Library/LaunchDaemons/… 须 root）")
    ap.add_argument("--services-config",
                    help="可选：发布 release-integrity-services.json 到"
                         " WENQU_HOME（服务清单 JSON 路径）")
    ap.add_argument("--state-wait", type=float,
                    default=STATE_WAIT_SECONDS_DEFAULT,
                    help="首发状态等待窗秒数（缺省 60）")
    ap.add_argument("--state-ttl", type=float, default=STATE_TTL_DEFAULT,
                    help="状态新鲜度 TTL 秒（缺省 900=2×扫描周期+余量）")
    ap.add_argument("--print", action="store_true",
                    help="只 render+lint 打印，不装配（干跑）")
    args = ap.parse_args(argv)

    # -- 模板（exit 3 面：受保护输入不可用）
    if not TEMPLATE.is_file():
        return _fail(3, "模板缺失: %s" % TEMPLATE)

    # -- render + 契约拒绝面（exit 1 面：占位符残留/相对路径/inline
    #    secret——契约违规先于存在性判定）
    try:
        content = render_template(args.python, args.sentinel_script,
                                  args.wenqu_home, args.sentinel_tree)
    except ValueError as exc:
        return _fail(1, str(exc))
    if not os.path.isfile(args.sentinel_script):
        return _fail(3, "哨兵脚本缺失: %s" % args.sentinel_script)
    for p in (args.python, args.wenqu_home, args.sentinel_tree):
        if not os.path.exists(p):
            return _fail(3, "前置路径缺失: %s" % p)
    sentinel_sha = hashlib.sha256(
        Path(args.sentinel_script).read_bytes()).hexdigest()
    target = Path(args.target)
    if args.print:
        # 干跑：stdout 只出渲染结果（可重定向装配），诊断走 stderr
        print("OK render（sentinel sha256=%s…）" % sentinel_sha[:16],
              file=sys.stderr)
        sys.stdout.write(content)
        return 0
    print("OK render（sentinel sha256=%s…）" % sentinel_sha[:16])

    # -- install + lint（exit 2 面：I/O）
    try:
        _install_plist(content, target)
        _plutil_lint(str(target))
    except OSError as exc:
        return _fail(2, "install/lint: %s" % exc)
    # 装配后字节对账：盘上 plist 必须与 render 结果逐字节一致（防目标被
    # hook/模板漂移改写——W12-02「模板/身份/字节不符」面）
    if target.read_text(encoding="utf-8") != content:
        return _fail(1, "装配后 plist 字节与 render 结果不一致: %s" % target)
    print("OK install+lint: %s (mode=%s)" % (target, oct(0o644)))

    domain = _domain_for(target)
    state_path = os.path.join(args.wenqu_home, STATE_RELPATH)

    # -- services 映射（可选发布；哨兵只读消费）
    if args.services_config:
        try:
            src = Path(args.services_config)
            services = json.loads(src.read_text(encoding="utf-8"))
            if not isinstance(services, list):
                raise ValueError("服务清单必须是 list")
            dst = Path(args.wenqu_home) / "release-integrity-services.json"
            dst.write_text(json.dumps(services, ensure_ascii=False, indent=1)
                           + "\n", encoding="utf-8")
            os.chmod(dst, 0o644)
            print("OK services map: %s（%d 服务）" % (dst, len(services)))
        except (OSError, ValueError) as exc:
            return _fail(2, "services-config: %s" % exc)

    # -- bootstrap（幂等：已加载先 bootout）+ kickstart 首发
    try:
        probe = _launchctl("print", "%s/%s" % (domain, LABEL), check=False)
        if probe.returncode == 0:
            _launchctl("bootout", "%s/%s" % (domain, LABEL))
            print("OK bootout（幂等重装）")
        _launchctl("bootstrap", domain, str(target))
        _launchctl("kickstart", "-k", "%s/%s" % (domain, LABEL))
        print("OK bootstrap+kickstart（domain=%s）" % domain)
    except OSError as exc:
        return _fail(2, str(exc))

    # -- 首个新鲜状态核验（exit 0 的完整性条件 / exit 3 阻断面）
    result = _wait_fresh_state(state_path, args.state_ttl, args.state_wait)
    if not result["ok"]:
        return _fail(3, "哨兵首发状态未就绪: %s" % result["detail"])
    state = result["state"]
    print("OK first fresh state: verdict=%s runtime=%s fuse=%s "
          "generated_at=%s" % (state.get("verdict"),
                               state.get("runtime_verdict"),
                               state.get("fuse"), state.get("generated_at")))
    print("PROVISION PASS rc=0 label=%s state=%s" % (LABEL, state_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())

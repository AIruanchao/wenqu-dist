#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""release-integrity-watch——W11-02 漂移哨兵入口（launchd com.wenqu.integrity）。

用法（详见 --help）：
    scan                          单次扫描（exit 0 clean / 2 monitor error /
                                  3 drift 或策略阻断）
    tick                          一个 daemon tick（exit 0=检测与裁决完成，
                                  即使裁决 BLOCKED；2=监控自身失败）
    daemon [--interval N]         常驻循环（每 N 秒一个 tick；N 缺省 300
                                  = launchd StartInterval 同步）
    unfuse --operator X --note Y  人工解除熔断（唯一通道；留痕 journal+state）
    status                        只读打印当前状态（JSON）

部署形态：launchd 模板 system/launchd/com.wenqu.integrity.plist.template
（StartInterval=300，与扫描周期一致——漂移 ≤ 一个扫描周期内 Gate/health
变红）。哨兵是 state/release-integrity.json 的唯一 writer；scheduler/
dashboard/install-release 只读。

敌对干扰防线背景：现役 release 树曾被外部会话热改（server.py 换字节 +
0444→0644）；0444 非 UID 边界（同 UID 可 chmod 后改写）；存在未授权
drift-watcher 外部自动化与部署位互操作——本哨兵对树做内容+mode 双对账，
任何写面（告警/incident/journal）不触碰漂移现场本体。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_SYSTEM = os.path.dirname(_HERE)
if _SYSTEM not in sys.path:
    sys.path.insert(0, _SYSTEM)

try:
    from wenqu_core import release_drift as rd
except ImportError:  # pragma: no cover - 直接脚本执行回退
    sys.path.insert(0, os.path.join(_SYSTEM))
    from wenqu_core import release_drift as rd


def _cmd_scan(args: argparse.Namespace) -> int:
    paths = rd.IntegrityPaths.from_env()
    try:
        finding = rd.scan_cycle(paths, now=time.time())
    except Exception as exc:  # noqa: BLE001 - 监控自身失败=exit 2
        print(f"[integrity] MONITOR ERROR: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(finding, ensure_ascii=False, indent=2))
    else:
        cur = finding.get("current") or {}
        print(f"[integrity] verdict={finding['verdict']} "
              f"runtime={finding['runtime_verdict']} "
              f"commit={finding.get('commit')}")
        for key in ("drifted", "mode_drifted", "missing", "extra"):
            hits = cur.get(key) or []
            if hits:
                print(f"  {key}: {hits[:5]}")
    return rd.scan_exit_code(finding["verdict"])


def _cmd_tick(args: argparse.Namespace) -> int:
    paths = rd.IntegrityPaths.from_env()
    result = rd.monitor_tick(paths, now=time.time(),
                             allow_recovery=not args.no_recovery)
    if args.json:
        print(json.dumps({"rc": result["rc"], "state": result["state"]},
                         ensure_ascii=False, indent=2))
    else:
        state = result["state"]
        print(f"[integrity] tick verdict={state.get('verdict')} "
              f"fuse={state.get('fuse')} epoch="
              f"{state.get('deployment_epoch')} rc={result['rc']}")
    return result["rc"]


def _cmd_daemon(args: argparse.Namespace) -> int:
    paths = rd.IntegrityPaths.from_env()
    interval = max(5.0, float(args.interval))
    print(f"[integrity] daemon start interval={interval}s "
          f"home={paths.wenqu_home}", flush=True)
    while True:
        try:
            result = rd.monitor_tick(paths, now=time.time())
            state = result["state"]
            print(f"[integrity] {state.get('generated_at')} "
                  f"verdict={state.get('verdict')} fuse={state.get('fuse')}",
                  flush=True)
        except Exception as exc:  # noqa: BLE001 - tick 失败不能杀 daemon
            print(f"[integrity] tick crashed: {type(exc).__name__}: {exc}",
                  file=sys.stderr, flush=True)
        time.sleep(interval)


def _cmd_unfuse(args: argparse.Namespace) -> int:
    paths = rd.IntegrityPaths.from_env()
    try:
        state = rd.unfuse(paths, operator=args.operator, note=args.note)
    except rd.DriftError as exc:
        print(f"[integrity] ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"[integrity] fuse cleared by {args.operator} "
          f"(verdict={state.get('verdict')}——下一扫描周期重判，"
          f"漂移仍在会重新熔断)")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    paths = rd.IntegrityPaths.from_env()
    print(json.dumps(rd.read_state(paths), ensure_ascii=False, indent=2))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="W11-02 release 漂移哨兵（检测/告警/熔断/自动恢复）")
    sub = ap.add_subparsers(dest="command")

    p = sub.add_parser("scan", help="单次扫描（0/2/3）")
    p.add_argument("--json", action="store_true", help="输出 JSON")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("tick", help="一个 daemon tick（0=裁决完成；2=监控失败）")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-recovery", action="store_true",
                   help="本 tick 禁用自动恢复（只检测+熔断）")
    p.set_defaults(func=_cmd_tick)

    p = sub.add_parser("daemon", help="常驻循环")
    p.add_argument("--interval", type=float, default=300.0,
                   help="扫描周期秒（缺省 300=launchd StartInterval）")
    p.set_defaults(func=_cmd_daemon)

    p = sub.add_parser("unfuse", help="人工解除熔断（留痕）")
    p.add_argument("--operator", required=True)
    p.add_argument("--note", required=True)
    p.set_defaults(func=_cmd_unfuse)

    p = sub.add_parser("status", help="打印当前状态 JSON")
    p.set_defaults(func=_cmd_status)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

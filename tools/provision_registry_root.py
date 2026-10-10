#!/usr/bin/env python3
"""部署位 registry root 供给器（T-9/W1：部署位独立保管的签名 registry 快照）。

产出 ~/.wenqu-dist-release/registry-root.json（0600）：
  - signed_registry_snapshot 产物（registry 全量站定义+digest HMAC 签名）；
  - 签名 key 必须与 manifest 签名 key 相异（G9-06 同钥双签无条件拒——
    registry 快照与 manifest 同 key = 非独立语义根）；
  - --verify 回读+同钥/异钥自检（同钥 load 必须 RegistryTrustError）。

用法：
  PYTHONPATH=system python3 tools/provision_registry_root.py \
      --keyring ~/.wenqu-dist-release/release-keyring.json --key-id <registry 专用 key> \
      [--out ~/.wenqu-dist-release/registry-root.json] [--verify]
仅签发部署件；不写 ~/.wenqu/state、不触碰 gate 现役聚合。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "system"))

from wenqu_core.approval_keys import ApprovalKeyring  # noqa: E402
from wenqu_core.bugscan_orchestrator import (  # noqa: E402
    RegistryTrustError, load_trusted_registry_snapshot, signed_registry_snapshot)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="registry root 供给器（T-9）")
    ap.add_argument("--keyring", required=True)
    ap.add_argument("--key-id", required=True,
                    help="registry 专用签发 key（必须与 manifest 签名 key 相异）")
    ap.add_argument("--out", default=os.path.expanduser(
        "~/.wenqu-dist-release/registry-root.json"))
    ap.add_argument("--verify", action="store_true",
                    help="落位后回读验签+同钥拒收自检")
    args = ap.parse_args(argv)

    keyring = ApprovalKeyring.from_path(args.keyring)
    snap = signed_registry_snapshot(signing_keyring=keyring,
                                    signing_key_id=args.key_id)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snap, ensure_ascii=False, indent=1) + "\n",
                   encoding="utf-8")
    os.chmod(out, 0o600)

    if args.verify:
        # 异钥（正确形态）：回读验签通过
        view = load_trusted_registry_snapshot(out, keyring=keyring)
        print(f"verify: registry_digest={view.registry_digest[:16]}… OK")
        # 同钥拒收自检（G9-06 语义：manifest_key_id 相同必须拒）
        try:
            load_trusted_registry_snapshot(out, keyring=keyring,
                                           manifest_key_id=args.key_id)
            print("verify: ❌ 同钥未拒收（语义根独立性失败）", file=sys.stderr)
            return 1
        except RegistryTrustError:
            print("verify: 同钥拒收 OK（独立语义根）")
    print(f"registry root 落位: {out} ({oct(os.stat(out).st_mode & 0o777)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

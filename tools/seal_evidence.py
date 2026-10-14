#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""seal_evidence.py —— 证据目录 Seal 工具（W12-12/S11 历史 Seal 与证据根）。

背景（W12-12）：九轮以来的证据散落各处（红绿跑记录、gate 回执、原始 API
回包），缺一个「封存即不可变」的收口动作：对整个证据目录生成
MANIFEST.sha256（逐文件哈希清单）+ EVIDENCE-INDEX.md（人读索引）并把
发布树**只读化**（文件 0444 / 目录 0555）。Seal 之后任何对密封树的写入
（新增/改写/删改）都会在 verify 时以哈希/完备性/权限违例暴露。

设计决策（冻结）：
- **发布 = O_EXCL 逐文件创建**：dest 根用 os.mkdir（已存在即拒），dest 内
  每个文件用 open(..., "xb")（O_CREAT|O_EXCL）——**绝不覆盖任何已存在
  文件**；重复 seal 同一 dest 必然 rc2，不存在「静默重写证据」路径。
- **拷贝语义（非移动）**：source 原样保留（并行 agent 可能仍在写）；seal
  产出独立只读副本。dest 与 source 互不为子目录（防自引用/嵌套拷贝）。
- **fail-closed 预检**：source 里的符号链接（证据树含 symlink = 可被替换
  的引用，不是字节证据）、含换行的文件名（破坏 shasum 清单格式）、空目录
  （0 文件无可封存内容）一律 rc1 拒绝——**绝不半密封**：预检通过才开始
  拷贝；中途失败留下的 partial 目录没有完整 MANIFEST，自明非密封。
- **MANIFEST.sha256 与 shasum -c 兼容**：注释头（# 开头，shasum 忽略）+
  逐行 "<sha256>  <relpath>"，按 relpath 排序（确定性重建：同 source 同
  字节序）。`cd <sealed> && shasum -a 256 -c MANIFEST.sha256` 可独立复验。
- **只读化在最后**：全部文件写完并 fsync（文件+目录）后才 chmod——
  0444 文件 / 0555 目录，自底向上，dest 根最后。
- **verify 三轨对账**：①逐文件哈希重算对 MANIFEST；②完备性（sealed 树
  内文件与 manifest 条目双向一致，多一件=违例）；③只读位（任何文件/目录
  带写位=违例）。缺 EVIDENCE-INDEX.md 同为违例。

用法（纯标准库）：
  python3 tools/seal_evidence.py seal --source DIR --dest DIR [--label TEXT]
      # seal：对 source 生成密封只读发布树到 dest（dest 必须不存在）
  python3 tools/seal_evidence.py verify --sealed DIR
      # verify：对照 MANIFEST 重算+完备性+只读位核验

exit：0=成功（seal 完成 / verify 完好）；
      1=证据/密封内容违例（source 空/含 symlink/坏文件名；verify 时
        哈希漂移/缺件/多件/可写位/无 MANIFEST）；
      2=用法/环境错（参数缺失、source 不存在、dest 已存在、路径嵌套、
        权限不足、目标目录不存在等）。
"""
import argparse
import datetime
import hashlib
import os
import stat
import sys

SCHEMA = "wenqu-seal-evidence/1"


def die(rc, msg):
    print(f"seal-evidence: {msg}", file=sys.stderr)
    sys.exit(rc)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def prescan(source):
    """遍历 source 收集全部常规文件（排序后）。违例 fail-closed rc1。"""
    files = []
    anomalies = []
    for root, dirs, names in os.walk(source):
        for d in list(dirs):
            if os.path.islink(os.path.join(root, d)):
                anomalies.append(f"symlink 目录: {os.path.join(root, d)}")
        for n in names:
            p = os.path.join(root, n)
            if os.path.islink(p):
                anomalies.append(f"symlink 文件: {p}")
                continue
            if "\n" in n or "\r" in n:
                anomalies.append(f"文件名含换行（破坏清单格式）: {p}")
                continue
            if not os.path.isfile(p):
                anomalies.append(f"非常规文件（fifo/socket/dev）: {p}")
                continue
            files.append(os.path.relpath(p, source))
    if anomalies:
        for a in anomalies[:20]:
            print(f"seal-evidence: [anomaly] {a}", file=sys.stderr)
        die(1, f"source 预检违例 {len(anomalies)} 处（symlink/坏文件名/非常规文件）——拒绝密封")
    files.sort()
    return files


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def cmd_seal(args):
    source = os.path.abspath(args.source)
    dest = os.path.abspath(args.dest)
    if not os.path.isdir(source):
        die(2, f"source 不存在或不是目录: {source}")
    if os.path.exists(dest):
        die(2, f"dest 已存在（O_EXCL 发布，绝不覆盖既有内容）: {dest}")
    if source == dest or dest.startswith(source + os.sep) or source.startswith(dest + os.sep):
        die(2, f"source 与 dest 互为子目录，拒绝自引用密封: {source} vs {dest}")

    files = prescan(source)
    if not files:
        die(1, f"source 为空（0 个文件），无可封存内容: {source}")

    total_bytes = 0
    entries = []  # (relpath_posix, size, sha256)
    try:
        os.mkdir(dest)  # O_EXCL 语义：已存在即 FileExistsError
    except FileExistsError:
        die(2, f"dest 已存在（O_EXCL 发布，绝不覆盖既有内容）: {dest}")
    except OSError as e:
        die(2, f"dest 创建失败（父目录存在？权限?）: {dest}: {e}")

    rel_of_dest_file = set()
    for rel in files:
        rel_posix = rel.replace(os.sep, "/")
        src_path = os.path.join(source, rel)
        dst_path = os.path.join(dest, rel)
        dst_dir = os.path.dirname(dst_path)
        try:
            os.makedirs(dst_dir, exist_ok=True)  # 中间目录可已存在（如 dest 根）
            with open(src_path, "rb") as sfh, open(dst_path, "xb") as dfh:
                h = hashlib.sha256()
                n = 0
                for chunk in iter(lambda: sfh.read(1 << 16), b""):
                    h.update(chunk)
                    dfh.write(chunk)
                    n += len(chunk)
                dfh.flush()
                os.fsync(dfh.fileno())
        except FileExistsError:
            die(2, f"目标文件已存在（O_EXCL 违例，绝不覆盖）: {dst_path}")
        except OSError as e:
            print(f"seal-evidence: [warn] partial 未完成密封留在 {dest}（无完整 "
                  f"MANIFEST，自明非密封，可人工删除）", file=sys.stderr)
            die(2, f"拷贝失败: {src_path} -> {dst_path}: {e}")
        entries.append((rel_posix, n, h.hexdigest()))
        total_bytes += n
        rel_of_dest_file.add(rel_posix)

    sealed_at = utcnow()
    label = args.label or source

    # MANIFEST.sha256（shasum -c 兼容：注释行 # 开头被忽略）。
    # 确定性纪律：清单头只含**内容派生**字段（file_count/total_bytes）——
    # sealed_at/label/source 等易变字段一律不进 MANIFEST（只在 INDEX 里），
    # 因此「同 source 字节 → 同 MANIFEST → 同 seal_digest」，跨时异地
    # 重建可互证；seal_digest 漂移 ⇔ 文件集或内容漂移。
    manifest = []
    manifest.append(f"# wenqu-seal-manifest {SCHEMA}")
    manifest.append(f"# file_count: {len(entries)}")
    manifest.append(f"# total_bytes: {total_bytes}")
    manifest.append(f"# format: <sha256>  <relpath>  （可用 shasum -a 256 -c 独立复验）")
    for rel_posix, size, digest in entries:
        manifest.append(f"{digest}  {rel_posix}")
    manifest_text = "\n".join(manifest) + "\n"
    manifest_bytes = manifest_text.encode("utf-8")
    seal_digest = hashlib.sha256(manifest_bytes).hexdigest()
    try:
        with open(os.path.join(dest, "MANIFEST.sha256"), "xb") as fh:
            fh.write(manifest_bytes)
            fh.flush()
            os.fsync(fh.fileno())
    except FileExistsError:
        die(2, f"MANIFEST.sha256 已存在（O_EXCL 违例）: {dest}")

    # EVIDENCE-INDEX.md（人读索引）
    index = []
    index.append(f"# EVIDENCE-INDEX — {label}")
    index.append("")
    index.append(f"- schema: `{SCHEMA}`")
    index.append(f"- sealed_at: {sealed_at}")
    index.append(f"- source: `{source}`")
    index.append(f"- tool: `tools/seal_evidence.py seal`")
    index.append(f"- file_count: {len(entries)}")
    index.append(f"- total_bytes: {total_bytes}")
    index.append(f"- seal_digest（MANIFEST.sha256 自身 sha256）: `{seal_digest}`")
    index.append(f"- 只读化: 文件 0444 / 目录 0555（发布后 chmod，verify 核验写位=0）")
    index.append("")
    index.append("## 文件清单")
    index.append("")
    index.append("| # | relpath | bytes | sha256 |")
    index.append("|---|---|---|---|")
    for i, (rel_posix, size, digest) in enumerate(entries, 1):
        safe = rel_posix.replace("|", "\\|").replace("`", "'")
        index.append(f"| {i} | `{safe}` | {size} | `{digest}` |")
    index.append("")
    index.append("## 复验方法")
    index.append("")
    index.append("```bash")
    index.append("python3 tools/seal_evidence.py verify --sealed <本目录>")
    index.append("cd <本目录> && shasum -a 256 -c MANIFEST.sha256   # 独立于本工具的复验")
    index.append("```")
    try:
        with open(os.path.join(dest, "EVIDENCE-INDEX.md"), "xb") as fh:
            fh.write(("\n".join(index) + "\n").encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
    except FileExistsError:
        die(2, f"EVIDENCE-INDEX.md 已存在（O_EXCL 违例）: {dest}")

    # 只读化：自底向上，文件 0444 → 目录 0555，dest 根最后
    for root, dirs, names in os.walk(dest, topdown=False):
        for n in names:
            os.chmod(os.path.join(root, n), 0o444)
        os.chmod(root, 0o555)
    os.chmod(dest, 0o555)

    print(f"sealed: {dest}")
    print(f"  files={len(entries)} bytes={total_bytes} seal_digest={seal_digest}")
    print(f"  manifest={os.path.join(dest, 'MANIFEST.sha256')}")
    print(f"  index={os.path.join(dest, 'EVIDENCE-INDEX.md')}")
    sys.exit(0)


def parse_manifest(sealed):
    """解析 MANIFEST.sha256 → {relpath: sha256}；坏行/坏 hex = 违例 rc1。"""
    path = os.path.join(sealed, "MANIFEST.sha256")
    if not os.path.isfile(path):
        die(1, f"缺 MANIFEST.sha256（被删除或从未密封）: {path}")
    mapping = {}
    bad = 0
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n").rstrip("\r")
            if not line or line.startswith("#"):
                continue
            parts = line.split("  ", 1)
            if (len(parts) != 2 or len(parts[0]) != 64
                    or any(c not in "0123456789abcdef" for c in parts[0])
                    or not parts[1]):
                bad += 1
                print(f"seal-evidence: [violation] MANIFEST 第 {lineno} 行格式非法: {line[:100]}",
                      file=sys.stderr)
                continue
            mapping[parts[1]] = parts[0]
    if bad:
        die(1, f"MANIFEST.sha256 有 {bad} 行非法（截损/篡改嫌疑）")
    if not mapping:
        die(1, "MANIFEST.sha256 无有效条目（空清单）")
    return mapping


def cmd_verify(args):
    sealed = os.path.abspath(args.sealed)
    if not os.path.isdir(sealed):
        die(2, f"--sealed 目录不存在: {sealed}")
    manifest = parse_manifest(sealed)
    violations = []

    if not os.path.isfile(os.path.join(sealed, "EVIDENCE-INDEX.md")):
        violations.append("缺 EVIDENCE-INDEX.md")

    on_disk = {}
    for root, dirs, names in os.walk(sealed):
        for n in names:
            p = os.path.join(root, n)
            rel = os.path.relpath(p, sealed).replace(os.sep, "/")
            on_disk[rel] = p

    # ① 完备性：manifest 与磁盘双向一致（多一件=违例）。
    # MANIFEST.sha256 自身与 EVIDENCE-INDEX.md 是密封树的固有元文件，
    # 不参与清单（清单无法含自身哈希）——豁免完备性比对，但仍受只读位核验。
    SEAL_META = {"MANIFEST.sha256", "EVIDENCE-INDEX.md"}
    extra = sorted(set(on_disk) - set(manifest) - SEAL_META)
    missing = sorted(set(manifest) - set(on_disk))
    for rel in extra:
        violations.append(f"多出文件（不在 MANIFEST）: {rel}")
    for rel in missing:
        violations.append(f"缺文件（MANIFEST 有而磁盘无）: {rel}")

    # ② 哈希重算
    for rel in sorted(set(manifest) & set(on_disk)):
        digest = sha256_file(on_disk[rel])
        if digest != manifest[rel]:
            violations.append(f"哈希漂移: {rel} manifest={manifest[rel]} actual={digest}")

    # ③ 只读位：任何文件/目录带写位 = 违例
    WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    for root, dirs, names in os.walk(sealed):
        for n in names:
            p = os.path.join(root, n)
            if os.stat(p).st_mode & WRITE_BITS:
                violations.append(
                    f"文件带写位（未只读化/被改权限）: {os.path.relpath(p, sealed)}")
        if os.stat(root).st_mode & WRITE_BITS:
            violations.append(
                f"目录带写位（未只读化/被改权限）: {os.path.relpath(root, sealed)}")

    if violations:
        for v in violations[:50]:
            print(f"seal-evidence: [violation] {v}", file=sys.stderr)
        die(1, f"verify 失败：{len(violations)} 处违例（哈希漂移/完备性/只读位）")

    print(f"verified: {sealed}")
    print(f"  files={len(manifest)} 只读位=0 哈希全对 完备性双向一致")
    sys.exit(0)


def main():
    ap = argparse.ArgumentParser(prog="seal_evidence.py",
                                 description="证据目录 Seal：MANIFEST.sha256 + EVIDENCE-INDEX.md + 只读化（O_EXCL 发布）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_seal = sub.add_parser("seal", help="对 source 生成密封只读发布树到 dest")
    p_seal.add_argument("--source", required=True, help="证据源目录（原样保留，不移动）")
    p_seal.add_argument("--dest", required=True, help="密封发布目录（必须不存在；O_EXCL）")
    p_seal.add_argument("--label", default="", help="索引标题（默认 source 路径）")
    p_seal.set_defaults(func=cmd_seal)
    p_verify = sub.add_parser("verify", help="对照 MANIFEST 复验密封树")
    p_verify.add_argument("--sealed", required=True, help="已密封目录")
    p_verify.set_defaults(func=cmd_verify)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

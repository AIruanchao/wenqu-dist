#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""quarantine_adjudicate.py —— W5 quarantine 裁定辅助工具（只建议，不替人裁定）。

背景（八轮诚实缺口）：reconcile-report.json 有 1950 条 quarantine 行待人工裁定。
本工具把 1950 行逐行决策压缩为「聚类级」决策，目标是最小化真人工作量。

铁律（与 tools/w5_reconcile.py 同源）：
    1. 只读：唯一写入位置是 --out-dir（默认 evidence/07-migration-reconcile/
       adjudication/）。绝不写任何库（不 import sqlite3、不 touch
       migrated-events.db）、绝不写 legacy 源目录、绝不修改 reconcile-report.json。
    2. 只建议不裁定：产出 adjudication-proposal.json + summary.md；任何
       RECLASSIFY 建议都带 requires_human_approval=true，未经人工批准不生效。
    3. 零自造别名：状态映射唯一正源 = system/wenqu_core/ledger_migrator.py 的
       STATUS_ALIASES（冻结正源；导入失败则降级用报告内 known_statuses 并显式
       记 degraded）。本工具绝不发明 PASS/FAIL 之外的新映射。
    4. fail-closed：任何完整性自检失败 → exit 1，不产出半成品结论。

聚类方法（确定性、可审计）：
    特征 = quarantine reason（missing_field:ts / no_mappable_status(candidates=X)）
         × 内容特征（从源文件整行提取；逐行重算 row_id 与报告比对，验不上退回
           截断 preview 并显式标记 unverified）
    规则有序表（首中即定簇），每行记录命中的 rule_id：
      R1 missing_ts 且某候选字段值命中冻结别名表  → SUBMIT_HUMAN（ts 无法确定性恢复）
      R2 missing_ts（且无可映射状态）             → KEEP_QUARANTINE
      R3 候选值为 dict（结构化巡检快照）          → KEEP_QUARANTINE
      R4 候选值命中冻结别名表（迁移器漏网）       → RECLASSIFY+目标状态（预期 0 行）
      R5 候选值为 token 且属近失族 NEARMISS       → SUBMIT_HUMAN（附拟议目标）
      R6 候选值为 token（长尾/过程态）            → KEEP_QUARANTINE（清单全列可拉回）
      R7 候选值为叙事文本                         → KEEP_QUARANTINE
      R8 候选字段全缺（无状态字段的工作日志行）   → KEEP_QUARANTINE
      R9 源行验不上（退回 preview 无法判形）      → SUBMIT_HUMAN
      R10 兜底未分类                              → SUBMIT_HUMAN（fail-visible）

近失族 NEARMISS（SUBMIT_HUMAN；语义近失但不在冻结表，扩表=版本化变更须人工）：
      DONE→拟议 FIXED_PENDING_VERIFY（M3 先例：FIXED 未验证不承认）
      GREEN_FAMILY（含 GREEN/绿）→拟议 PASS（口径风险：仓库态观测≠finding 状态）
      PARTIAL→拟议 CONDITIONAL（语义近似=猜测，须人工签字）
      MERGED / FIXED_VERIFIED→无拟议（PR 生命周期/VERIFIED 超出冻结表语义）

产物：
    adjudication-proposal.json —— 机器可读全量提案（聚类/建议/row_ids/假想四态）
    summary.md —— 人读版：聚类统计+建议分布+需真人看的最小集合+一键预览

用法：
    python3 tools/quarantine_adjudicate.py
    python3 tools/quarantine_adjudicate.py --report <path> --out-dir <dir>

退出码：0 = 聚类完备 + 守恒自检全过 + 产物落盘；1 = 任一失败（fail-closed）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TOOL_VERSION = "1.0.0"
ARTIFACT = "quarantine-adjudication-proposal"

SUGGESTION_KEEP = "KEEP_QUARANTINE"
SUGGESTION_RECLASSIFY = "RECLASSIFY"
SUGGESTION_HUMAN = "SUBMIT_HUMAN"
_SUGGESTIONS = (SUGGESTION_KEEP, SUGGESTION_RECLASSIFY, SUGGESTION_HUMAN)

REPO_ROOT = Path(__file__).resolve().parents[1]

#: 近失 token 族 → 拟议目标（None=无拟议，须人工自定）；扩表须人工+版本化
NEARMISS_FAMILIES: Dict[str, Dict[str, Any]] = {
    "DONE": {
        "proposed_target": "FIXED_PENDING_VERIFY",
        "rationale": "fix 完成态；M3 先例 FIXED→FIXED_PENDING_VERIFY（完成但无验证证据时上限即 FPV）。"
                     "前提：人工确认这些 fix 工作项与 finding 账本同口径、无 finding_id 断链风险。",
    },
    "GREEN_FAMILY": {
        "proposed_target": "PASS",
        "rationale": "巡检全绿判定族（token 含 GREEN/绿）。口径风险：这是仓库态观测而非 finding 状态，"
                     "拟议 PASS 仅在人工裁定『巡检轮入账』成立时有效。",
    },
    "PARTIAL": {
        "proposed_target": "CONDITIONAL",
        "rationale": "语义近似 CONDITIONAL，但这是猜测——冻结别名表无 PARTIAL，须人工签字才可扩表。",
    },
    "MERGED": {
        "proposed_target": None,
        "rationale": "PR 生命周期态，冻结表无 finding 状态对应；无拟议目标，人工定夺保留隔离或另行处理。",
    },
    "FIXED_VERIFIED": {
        "proposed_target": None,
        "rationale": "VERIFIED 不在冻结 KNOWN_STATUSES；上限 FIXED_PENDING_VERIFY 还是保留隔离，人工定夺。",
    },
}

#: token 形状判定：单段、≤40 字符、仅字母/数字/_-/中文/冒号（含全角冒号）
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-\u4e00-\u9fff:：]+$")

RULES_DOC = [
    ("R1", "missing_ts_with_mappable_status", SUGGESTION_HUMAN,
     "缺 ts 但状态可映射：状态可入账而时间戳无法确定性恢复，人工可从上下文/邻行补 ts"),
    ("R2", "missing_ts_no_mappable_status", SUGGESTION_KEEP,
     "缺 ts 且无可映射状态（双重不满足）：无可恢复入账要素，维持隔离"),
    ("R3", "state_structured_snapshot", SUGGESTION_KEEP,
     "候选值为 dict（结构化巡检快照）：非状态语义，维持隔离"),
    ("R4", "frozen_alias_reclassifiable", SUGGESTION_RECLASSIFY,
     "候选值命中冻结别名表（迁移器首选链漏网的后位字段）：确定性可映射（预期 0 行）"),
    ("R5", "nearmiss_token", SUGGESTION_HUMAN,
     "token 属近失族（DONE/GREEN 族/PARTIAL/MERGED/FIXED-VERIFIED）：扩别名表=版本化变更，须人工裁定"),
    ("R6", "token_longtail", SUGGESTION_KEEP,
     "token 长尾/过程态（确认态/in-flight/wait/等CI/观察 one-off 等）：非 finding 状态语义，"
     "维持隔离；全量 token 清单在提案中列出，人工可随时拉回个别行"),
    ("R7", "narrative_worklog", SUGGESTION_KEEP,
     "叙事文本（action 工作日志/带空格短语）：无状态语义，维持隔离（源数据本性，非工具缺陷）"),
    ("R8", "no_status_field_worklog", SUGGESTION_KEEP,
     "四个候选状态字段全缺的工作日志行（summary/note 型）：无状态可映射，维持隔离"),
    ("R9", "source_line_unverified", SUGGESTION_HUMAN,
     "源行 row_id 验不上（源文件已变且该行位移），退回截断 preview 无法判形：人工核原文"),
    ("R10", "residual_unclassified", SUGGESTION_HUMAN,
     "兜底：规则未覆盖（本工具规则缺陷，fail-visible，须人工+规则迭代）"),
]


# ---------------------------------------------------------------------- #
# 冻结正源加载（零自造别名）
# ---------------------------------------------------------------------- #
def load_frozen_aliases(report: Dict[str, Any]) -> Tuple[Dict[str, str], List[str], bool]:
    """优先 import 冻结正源 STATUS_ALIASES；失败降级为报告 known_statuses 自映射。"""
    degraded = False
    try:
        sys.path.insert(0, str(REPO_ROOT / "system"))
        from wenqu_core.ledger_migrator import STATUS_ALIASES  # type: ignore
        aliases = dict(STATUS_ALIASES)
        src = "system/wenqu_core/ledger_migrator.py STATUS_ALIASES（冻结正源）"
    except Exception:                                     # noqa: BLE001
        known = list(report["normalization"]["known_statuses"])
        aliases = {s: s for s in known}
        src = "报告 normalization.known_statuses 自映射（降级：ledger_migrator 导入失败）"
        degraded = True
    return aliases, [src], degraded


# ---------------------------------------------------------------------- #
# 源文件整行富化（只读 + 逐行 row_id 验证）
# ---------------------------------------------------------------------- #
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_source_lines(report: Dict[str, Any]) -> Tuple[Dict[str, List[str]], List[Dict[str, Any]]]:
    """只读加载源文件行；返回 (file→lines, 文件级核验信息)。不修改任何源文件。"""
    lines_by_file: Dict[str, List[str]] = {}
    info: List[Dict[str, Any]] = []
    for meta in report.get("source", {}).get("files", []):
        fp = Path(meta["file"])
        entry: Dict[str, Any] = {"file": meta["file"], "sha256_recorded": meta.get("sha256")}
        try:
            actual = sha256_file(fp)
            entry["sha256_actual"] = actual
            entry["sha_match"] = actual == meta.get("sha256")
            text = fp.read_text(encoding="utf-8")
            lines_by_file[meta["file"]] = text.splitlines()
            entry["readable"] = True
        except OSError as exc:
            entry["readable"] = False
            entry["error"] = str(exc)
            entry["sha_match"] = None
        info.append(entry)
    return lines_by_file, info


def full_line_for(row: Dict[str, Any], lines_by_file: Dict[str, List[str]]) -> Optional[str]:
    """取整行原文并重算 row_id 比对；验不上返回 None（调用方退回 preview）。"""
    lines = lines_by_file.get(row.get("source_file"))
    if not lines:
        return None
    n = row.get("line_no")
    if not isinstance(n, int) or n < 1 or n > len(lines):
        return None
    raw = lines[n - 1]
    rid = hashlib.sha256(
        (row["source_file"] + "\n" + str(n) + "\n" + raw).encode("utf-8")
    ).hexdigest()
    return raw if rid == row.get("row_id") else None


# ---------------------------------------------------------------------- #
# 特征提取与聚类（确定性规则，首中即定）
# ---------------------------------------------------------------------- #
def token_family(value: str) -> str:
    s = value.strip().upper().replace("-", "_")
    return "GREEN_FAMILY" if ("GREEN" in s or "绿" in s) else s


def candidate_fields_from_reason(reason: str) -> List[str]:
    if reason.startswith("no_mappable_status") and "candidates=" in reason:
        raw = reason.split("candidates=", 1)[1].rstrip(")")
        return [f for f in raw.split(",") if f and f != "none"]  # none=无候选字段
    return []


def effective_candidate(obj: Dict[str, Any], fields: List[str]) -> Tuple[Optional[str], Optional[str], bool]:
    """返回 (首个非空字符串候选字段名, 其值, 是否存在 dict 候选)。"""
    first_str_field, first_str_val, has_dict = None, None, False
    for f in fields:
        v = obj.get(f)
        if isinstance(v, dict):
            has_dict = True
        if first_str_field is None and isinstance(v, str) and v.strip():
            first_str_field, first_str_val = f, v.strip()
    return first_str_field, first_str_val, has_dict


def classify_row(row: Dict[str, Any], obj: Optional[Dict[str, Any]],
                 aliases: Dict[str, str]) -> Dict[str, Any]:
    """单行 → 特征 + 簇判定。obj=parsed 整行（已验 row_id）；None=退回 preview。"""
    reason = row.get("reason") or ""
    feats: Dict[str, Any] = {
        "reason": reason,
        "reason_kind": "missing_ts" if reason == "missing_field:ts"
        else ("no_mappable_status" if reason.startswith("no_mappable_status") else "other"),
        "candidate_fields": candidate_fields_from_reason(reason),
        "value_shape": None, "token_family": None, "candidate_field": None,
        "mappable_candidate": None,
    }
    if obj is None:
        feats["value_shape"] = "unverified"
        feats["cluster"] = "source_line_unverified"
        feats["rule_id"] = "R9"
        return feats

    fields = feats["candidate_fields"]
    if feats["reason_kind"] == "missing_ts":
        # ts 别名链外无法判形；先看候选状态是否本可映射
        m_field, m_val, _ = effective_candidate(obj, ["status", "verdict", "state", "result"])
        if m_field and m_val and m_val.upper() in aliases:
            feats.update(value_shape="missing_ts_mappable",
                         mappable_candidate=f"{m_field}={m_val}",
                         cluster="missing_ts_with_mappable_status", rule_id="R1")
        else:
            feats.update(value_shape="missing_ts_unmappable",
                         cluster="missing_ts_no_mappable_status", rule_id="R2")
        return feats

    if feats["reason_kind"] == "no_mappable_status":
        f, v, has_dict = effective_candidate(obj, fields)
        feats["candidate_field"] = f
        if f is None:
            if has_dict:
                feats.update(value_shape="dict", cluster="state_structured_snapshot", rule_id="R3")
            elif not fields:
                feats.update(value_shape="absent",
                             cluster="no_status_field_worklog", rule_id="R8")
            else:
                feats.update(value_shape="nonstring",
                             cluster="no_status_field_worklog", rule_id="R8")
            return feats
        # 首个字符串候选存在（首链未映射）——后位字段是否命中冻结表（迁移器漏网）
        if v.upper() in aliases:
            feats.update(value_shape="token", token_family=token_family(v),
                         mappable_candidate=f"{f}={v}",
                         cluster="frozen_alias_reclassifiable", rule_id="R4")
            return feats
        if len(v) <= 40 and _TOKEN_RE.fullmatch(v):
            fam = token_family(v)
            feats.update(value_shape="token", token_family=fam)
            if fam in NEARMISS_FAMILIES:
                feats.update(cluster=f"nearmiss_token:{fam}", rule_id="R5")
            else:
                feats.update(cluster=f"token_longtail:{f}", rule_id="R6")
        else:
            feats.update(value_shape="narrative",
                         cluster=f"narrative_worklog:{f}", rule_id="R7")
        return feats

    # reason 缺失/异形 → 兜底
    feats.update(value_shape="unknown", cluster="residual_unclassified", rule_id="R10")
    return feats


CLUSTER_META = {cid: (rid, sugg) for rid, cid, sugg, _ in RULES_DOC}


def suggestion_for(cluster_id: str) -> Tuple[str, Optional[str], str, bool]:
    """簇 → (建议, 拟议目标, 理由, 需人工批准)。"""
    rule_id, sugg = CLUSTER_META.get(cluster_id.split(":")[0], ("R10", SUGGESTION_HUMAN))
    desc = next((d for r, _c, _s, d in RULES_DOC if r == rule_id), "")
    if sugg == SUGGESTION_RECLASSIFY:
        return sugg, None, desc, True
    if cluster_id.startswith("nearmiss_token:"):
        fam = cluster_id.split(":", 1)[1]
        meta = NEARMISS_FAMILIES.get(fam, {"proposed_target": None, "rationale": ""})
        return sugg, meta["proposed_target"], \
            f"[{fam}] {meta['rationale']} 拟议目标仅为选项，扩表须人工+版本化变更。", True
    return sugg, None, desc, False


# ---------------------------------------------------------------------- #
# 主流程
# ---------------------------------------------------------------------- #
def build_proposal(report: Dict[str, Any], report_path: Path) -> Dict[str, Any]:
    aliases, alias_src, degraded = load_frozen_aliases(report)
    known_statuses = list(report["normalization"]["known_statuses"])
    lines_by_file, file_info = load_source_lines(report)

    rows = [r for r in report["rows"] if r.get("state") == "quarantined"]
    if not rows:
        raise SystemExit("fail-closed: 报告中无 quarantined 行，无需裁定")

    verified = fallback = 0
    clusters: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        raw = full_line_for(row, lines_by_file)
        obj = None
        if raw is not None:
            try:
                parsed = json.loads(raw)
                obj = parsed if isinstance(parsed, dict) else None
            except (json.JSONDecodeError, ValueError):
                obj = None  # 坏 JSON 行：整行不可判形 → R9
        if raw is None or obj is None:
            fallback += 1
        else:
            verified += 1
        feats = classify_row(row, obj, aliases)
        cid = feats["cluster"]
        c = clusters.setdefault(cid, {
            "cluster_id": cid, "rule_id": feats["rule_id"], "size": 0,
            "reasons": Counter(), "value_shapes": Counter(), "token_families": Counter(),
            "candidate_fields": Counter(), "row_refs": [], "row_ids": [],
        })
        c["size"] += 1
        c["reasons"][feats["reason"]] += 1
        c["value_shapes"][feats["value_shape"] or "?"] += 1
        if feats["token_family"]:
            c["token_families"][feats["token_family"]] += 1
        if feats["candidate_field"]:
            c["candidate_fields"][feats["candidate_field"]] += 1
        if feats["mappable_candidate"]:
            c["candidate_fields"][f"mappable:{feats['mappable_candidate']}"] += 1
        c["row_refs"].append({"line_no": row["line_no"],
                              "preview": (row.get("preview") or "")[:120]})
        c["row_ids"].append(row["row_id"])

    # 簇级建议
    dist = {s: {"clusters": 0, "rows": 0} for s in _SUGGESTIONS}
    cluster_out: List[Dict[str, Any]] = []
    for cid in sorted(clusters, key=lambda k: (-clusters[k]["size"], k)):
        c = clusters[cid]
        sugg, target, rationale, needs_human = suggestion_for(cid)
        dist[sugg]["clusters"] += 1
        dist[sugg]["rows"] += c["size"]
        cluster_out.append({
            "cluster_id": cid,
            "rule_id": c["rule_id"],
            "suggestion": sugg,
            "proposed_target": target,
            "requires_human_approval": needs_human,
            "rationale": rationale,
            "size": c["size"],
            "evidence": {
                "reasons": dict(c["reasons"]),
                "value_shapes": dict(c["value_shapes"]),
                "candidate_fields": dict(c["candidate_fields"]),
                "token_families": dict(c["token_families"].most_common()),
            },
            "sample_rows": c["row_refs"][:3],
            "row_ids": c["row_ids"],
        })

    # ---- 一键预览：按建议重分类后的四态假想值（纯算术，不写任何库） ----
    cur = report["four_state_summary"]
    reclass_rows = dist[SUGGESTION_RECLASSIFY]["rows"]
    human_rows = dist[SUGGESTION_HUMAN]["rows"]
    proposed_rows = sum(c["size"] for c in cluster_out
                        if c["suggestion"] == SUGGESTION_HUMAN and c["proposed_target"])
    scenario_a = {
        "mapped": cur["mapped"] + reclass_rows,
        "quarantined": cur["quarantined"] - reclass_rows,
        "待人工": cur["待人工"],
        "不一致": cur["不一致"],
        "total": cur["total"],
    }
    added = Counter()
    for c in cluster_out:
        if c["suggestion"] == SUGGESTION_HUMAN and c["proposed_target"]:
            added[c["proposed_target"]] += c["size"]
    scenario_b = {
        "mapped": cur["mapped"] + reclass_rows + proposed_rows,
        "quarantined": cur["quarantined"] - reclass_rows - proposed_rows,
        "待人工": cur["待人工"],
        "不一致": cur["不一致"],
        "total": cur["total"],
    }
    hypothetical = {
        "current": cur,
        "scenario_A_按建议执行": {
            **scenario_a,
            "note": f"RECLASSIFY {reclass_rows} 行入账；SUBMIT_HUMAN {human_rows} 行维持隔离待裁；"
                    "正式四态不变（本数据集 RECLASSIFY=0）",
        },
        "scenario_B_拟议全批准上限": {
            **scenario_b,
            "note": f"SUBMIT_HUMAN 中带拟议目标的 {proposed_rows} 行按拟议入账（假想上限，"
                    "须逐簇人工批准+版本化扩表后另行再录）；无拟议目标簇维持隔离",
        },
        "scenario_B_新增事件状态分布": dict(added),
        "warning": "假想值：本工具不写迁移库/不写任何库；数字仅为人工决策预览",
    }

    # ---- 需真人看的最小集合 ----
    decision_clusters = [{
        "cluster_id": c["cluster_id"], "size": c["size"],
        "proposed_target": c["proposed_target"], "rationale": c["rationale"],
        "question": human_question(c),
    } for c in cluster_out if c["suggestion"] == SUGGESTION_HUMAN]
    confirmation_clusters = [{
        "cluster_id": c["cluster_id"], "size": c["size"],
        "sample_rows": c["sample_rows"], "rationale": c["rationale"],
    } for c in cluster_out if c["suggestion"] != SUGGESTION_HUMAN]

    proposal = {
        "artifact": ARTIFACT,
        "tool": "tools/quarantine_adjudicate.py",
        "tool_version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "positioning": "裁定辅助：只建议不替人裁定；RECLASSIFY 一律 requires_human_approval=true；"
                       "本工具不写任何库",
        "input": {
            "report_path": str(report_path),
            "report_sha256": sha256_file(report_path),
            "report_generated_at": report.get("generated_at"),
            "report_git_head": report.get("git_head"),
            "quarantine_rows": len(rows),
            "four_state_summary": cur,
        },
        "source_enrichment": {
            "mode": "full_line_per_row_verified" if fallback == 0 else "mixed_fallback_preview",
            "files": file_info,
            "file_level_note": "源文件在报告生成后有追加（sha 不匹配属预期）；逐行以 row_id "
                               "重算为准，验不上的行退回 preview 并入 R9 簇",
            "rows_row_id_verified": verified,
            "rows_fallback_preview": fallback,
        },
        "frozen_tables": {
            "status_aliases_source": alias_src,
            "known_statuses": known_statuses,
            "aliases_key_count": len(aliases),
            "import_degraded": degraded,
            "zero_self_invented_aliases": True,
        },
        "method": {
            "feature_space": "quarantine reason（missing_field:ts / no_mappable_status(candidates=X)）"
                             "× 内容特征（整行 JSON 的候选字段值形状：dict/token/narrative/absent；"
                             "token 再按近失族/长尾分）",
            "rules": [{"rule_id": r, "cluster": c, "suggestion": s, "description": d}
                      for r, c, s, d in RULES_DOC],
            "nearmiss_families": NEARMISS_FAMILIES,
            "principles": [
                "零自造别名：映射唯一正源=STATUS_ALIASES（冻结）；近失族仅拟议、须人工扩表",
                "不猜填：无法确定性映射的一律不给 RECLASSIFY",
                "fail-visible：规则覆盖不到的行入 residual_unclassified → SUBMIT_HUMAN",
            ],
        },
        "clusters": cluster_out,
        "cluster_count": len(cluster_out),
        "suggestion_distribution": dist,
        "human_minimal_set": {
            "decision_clusters": decision_clusters,
            "confirmation_clusters": confirmation_clusters,
            "rows_under_human_decision": human_rows,
            "compression": f"{len(rows)} 行 → {len(decision_clusters)} 个裁定簇 + "
                           f"{len(confirmation_clusters)} 个确认簇（簇级签字+抽查，免逐行）",
            "decision_output_contract": "人工逐簇给 {cluster_id: {disposition: KEEP_QUARANTINE|"
                                        "RECLASSIFY, target: <KNOWN_STATUS>|null}}；批准后的再录"
                                        "由人工走版本化扩表+迁移器重跑通道，本工具不执行",
        },
        "hypothetical_four_state": hypothetical,
    }
    return proposal


def human_question(cluster: Dict[str, Any]) -> str:
    cid = cluster["cluster_id"]
    size, target = cluster["size"], cluster["proposed_target"]
    if cid.startswith("nearmiss_token:"):
        fam = cid.split(":", 1)[1]
        if target:
            return f"{fam} 族 {size} 行：是否批准扩别名 {fam}→{target} 入账？（拟议仅是选项）"
        return f"{fam} 族 {size} 行：保留隔离还是另行定夺？（无拟议目标）"
    if cid == "missing_ts_with_mappable_status":
        return f"{size} 行状态可映射但缺 ts：人工能否从上下文补 ts 后再录？"
    if cid in ("source_line_unverified", "residual_unclassified"):
        return f"{size} 行无法机器判形/规则未覆盖：人工核原文并反馈规则迭代"
    return f"{size} 行需人工裁定"


# ---------------------------------------------------------------------- #
# 完整性自检（fail-closed）
# ---------------------------------------------------------------------- #
def self_checks(proposal: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
    rows = [r for r in report["rows"] if r.get("state") == "quarantined"]
    report_ids = [r["row_id"] for r in rows]
    clustered_ids = [rid for c in proposal["clusters"] for rid in c["row_ids"]]
    checks: Dict[str, Any] = {}
    checks["partition_row_ids_set_equal"] = sorted(clustered_ids) == sorted(report_ids)
    checks["partition_no_duplicate"] = len(clustered_ids) == len(set(clustered_ids))
    checks["sum_cluster_sizes_eq_quarantined"] = (
        sum(c["size"] for c in proposal["clusters"]) == len(rows)
        == report["four_state_summary"]["quarantined"])
    checks["no_empty_cluster"] = all(c["size"] > 0 for c in proposal["clusters"])
    checks["suggestion_enum_valid"] = all(
        c["suggestion"] in _SUGGESTIONS for c in proposal["clusters"])
    known = set(report["normalization"]["known_statuses"])
    checks["targets_within_known_statuses"] = all(
        c["proposed_target"] in (None, ) or c["proposed_target"] in known
        for c in proposal["clusters"])
    dist_rows = sum(v["rows"] for v in proposal["suggestion_distribution"].values())
    checks["distribution_rows_conserved"] = dist_rows == len(rows)
    cur = report["four_state_summary"]
    for key in ("scenario_A_按建议执行", "scenario_B_拟议全批准上限"):
        s = proposal["hypothetical_four_state"][key]
        checks[f"hypothetical_{key[:11]}_conserved"] = (
            s["mapped"] + s["quarantined"] + s["待人工"] + s["不一致"] == cur["total"])
    checks["all_passed"] = all(bool(v) for v in checks.values())
    proposal["self_checks"] = checks
    return checks


def content_digest(proposal: Dict[str, Any]) -> str:
    body = {k: v for k, v in proposal.items() if k != "generated_at"}
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------- #
# summary.md（人读版）
# ---------------------------------------------------------------------- #
def render_summary(proposal: Dict[str, Any]) -> str:
    inp, dist = proposal["input"], proposal["suggestion_distribution"]
    hyp = proposal["hypothetical_four_state"]
    hms = proposal["human_minimal_set"]
    se = proposal["source_enrichment"]
    ft = proposal["frozen_tables"]
    L: List[str] = []
    L.append("# Quarantine 裁定提案（辅助建议，非裁定）\n")
    L.append(f"- 生成：{proposal['generated_at']}（tool=tools/quarantine_adjudicate.py v{TOOL_VERSION}）")
    L.append(f"- 输入报告：`{inp['report_path']}`（sha256={inp['report_sha256'][:16]}…，"
             f"报告生成于 {inp['report_generated_at']}，git_head={inp['report_git_head']}）")
    L.append(f"- 范围：quarantine {inp['quarantine_rows']} 行；定位=**只建议不替人裁定、不写任何库**\n")

    L.append("## 聚类统计（{0} 簇）\n".format(proposal["cluster_count"]))
    L.append("| 簇 | 规则 | 值形状 | 建议裁定 | 拟议目标 | 行数 | 依据摘要 |")
    L.append("|---|---|---|---|---|---|---|")
    for c in proposal["clusters"]:
        shapes = "+".join(f"{k}×{v}" for k, v in c["evidence"]["value_shapes"].items())
        rat = c["rationale"].replace("|", "/")[:60]
        target = c["proposed_target"] or "—"
        L.append(f"| `{c['cluster_id']}` | {c['rule_id']} | {shapes} | **{c['suggestion']}** "
                 f"| {target} | {c['size']} | {rat} |")
    L.append("")
    L.append("## 建议分布\n")
    L.append("| 建议裁定 | 簇数 | 行数 |")
    L.append("|---|---|---|")
    for s in _SUGGESTIONS:
        L.append(f"| {s} | {dist[s]['clusters']} | {dist[s]['rows']} |")
    L.append(f"| **合计** | **{proposal['cluster_count']}** | **{sum(v['rows'] for v in dist.values())}** |\n")

    L.append("## 需真人看的最小集合\n")
    L.append(f"**{hms['compression']}**；直接处于人工裁定下的行数："
             f"**{hms['rows_under_human_decision']} / {inp['quarantine_rows']}**。\n")
    L.append("### A. 裁定簇（须逐簇给决定）\n")
    L.append("| 簇 | 行数 | 拟议目标 | 裁定问题 |")
    L.append("|---|---|---|---|")
    for d in hms["decision_clusters"]:
        q = d["question"].replace("|", "/")
        L.append(f"| `{d['cluster_id']}` | {d['size']} | {d['proposed_target'] or '—'} | {q} |")
    L.append("\n### B. 确认簇（簇级签字+抽查即可，免逐行）\n")
    L.append("| 簇 | 行数 | 依据 | 抽样（行号） |")
    L.append("|---|---|---|---|")
    for c in hms["confirmation_clusters"]:
        rat = c["rationale"].replace("|", "/")[:70]
        samples = ", ".join(str(s["line_no"]) for s in c["sample_rows"])
        L.append(f"| `{c['cluster_id']}` | {c['size']} | {rat} | {samples} |")
    L.append(f"\n裁定输出契约：{hms['decision_output_contract']}\n")

    L.append("## 一键预览：按建议重分类后的四态统计（假想值，不写迁移库）\n")
    L.append("| 状态 | 现状 | 场景A·按建议执行 | 场景B·拟议全批准上限 |")
    L.append("|---|---|---|---|")
    cur, a, b = hyp["current"], hyp["scenario_A_按建议执行"], hyp["scenario_B_拟议全批准上限"]
    for k, label in (("mapped", "mapped（已入账）"), ("quarantined", "quarantined（隔离）"),
                     ("待人工", "待人工"), ("不一致", "不一致"), ("total", "合计")):
        L.append(f"| {label} | {cur[k]} | {a[k]} | {b[k]} |")
    added = hyp.get("scenario_B_新增事件状态分布") or {}
    if added:
        L.append(f"\n场景B 新增事件状态分布：{json.dumps(added, ensure_ascii=False)}")
    L.append(f"\n- 场景A注：{a['note']}")
    L.append(f"- 场景B注：{b['note']}")
    L.append(f"- {hyp['warning']}\n")

    L.append("## 方法与证据边界\n")
    L.append(f"- 特征空间：{proposal['method']['feature_space']}")
    L.append(f"- 别名正源：{ft['status_aliases_source'][0] if ft['status_aliases_source'] else '—'}"
             f"（keys={ft['aliases_key_count']}，零自造别名，import_degraded={ft['import_degraded']}）")
    L.append(f"- 源富化：mode={se['mode']}；逐行 row_id 重算验证 {se['rows_row_id_verified']}/{inp['quarantine_rows']}"
             f"，退回 preview {se['rows_fallback_preview']} 行；{se['file_level_note']}")
    L.append("- RECLASSIFY 仅在候选值命中冻结别名表时给出（本数据集预期 0 行——迁移器已取走全部可映射行）；"
             "近失族拟议目标全部 requires_human_approval=true")
    L.append("- 完整规则表与逐簇 token 清单见 adjudication-proposal.json")
    sc = proposal["self_checks"]
    L.append(f"\n## 自检（fail-closed）\n")
    for k, v in sc.items():
        L.append(f"- {k}: {'PASS' if v else 'FAIL'}")
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="quarantine 裁定辅助（只建议不裁定，不写任何库）")
    ap.add_argument("--report", default=str(REPO_ROOT / "evidence/07-migration-reconcile/reconcile-report.json"))
    ap.add_argument("--out-dir", default=None, help="默认=<报告目录>/adjudication")
    args = ap.parse_args(argv)

    report_path = Path(args.report).resolve()
    if not report_path.is_file():
        print(f"fail-closed: 报告不存在 {report_path}", file=sys.stderr)
        return 1
    out_dir = Path(args.out_dir).resolve() if args.out_dir else report_path.parent / "adjudication"

    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    proposal = build_proposal(report, report_path)
    checks = self_checks(proposal, report)
    if not checks["all_passed"]:
        print(f"fail-closed: 自检未全过 {json.dumps(checks, ensure_ascii=False)}", file=sys.stderr)
        return 1
    proposal["content_digest"] = content_digest(proposal)

    out_dir.mkdir(parents=True, exist_ok=True)
    prop_path = out_dir / "adjudication-proposal.json"
    summ_path = out_dir / "summary.md"
    with open(prop_path, "w", encoding="utf-8") as f:
        json.dump(proposal, f, ensure_ascii=False, indent=1, sort_keys=False)
    with open(summ_path, "w", encoding="utf-8") as f:
        f.write(render_summary(proposal))

    dist = proposal["suggestion_distribution"]
    print(f"OK 聚类 {proposal['cluster_count']} 簇 / {dist and sum(v['rows'] for v in dist.values())} 行")
    for s in _SUGGESTIONS:
        print(f"  {s}: clusters={dist[s]['clusters']} rows={dist[s]['rows']}")
    hms = proposal["human_minimal_set"]
    print(f"  需真人裁定簇: {len(hms['decision_clusters'])} "
          f"(覆盖 {hms['rows_under_human_decision']} 行) + "
          f"确认簇 {len(hms['confirmation_clusters'])}")
    print(f"  自检 all_passed={proposal['self_checks']['all_passed']} "
          f"content_digest={proposal['content_digest'][:16]}…")
    print(f"产物: {prop_path}")
    print(f"      {summ_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

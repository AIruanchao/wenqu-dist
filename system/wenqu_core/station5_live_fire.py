# -*- coding: utf-8 -*-
"""station5_live_fire.py——Codex 方案 W6D：Bug 八站·站5 实弹面（最小真实语义）。

血统与契约正源：
- Codex 方案 §7.1 八站表·站5 实弹：「授权后的真单或沙箱链、幂等、补偿、
  清理」，required 证据=「授权+前后状态」；
- Codex 方案 W6D：站5=受控合成租户/实弹授权、幂等、守恒、补偿、清理和
  前后状态；§15.7：真单/生产写必须单独授权，并预先定义清理、补偿、幂等
  和守恒；
- 《问渠轨道规范（发行版 v2.0）》§1 站5 判据：pass=状态断言全 PASS+数据
  回基线；fail=状态断言失败/数据未回基线；error=生产写授权缺失
  （BLOCKED，不算通过）；
- schemas/station-result-v2.schema.json：结果严格合规。

诚实边界（为何这是「最小真实语义」而非占位）：
- 真实业务流全链操作本身（生产写）按注册表 notes「不在任何自动档
  required 集内——必须显式授权后加入」，由持所有者口令的执行体在站外
  完成；本扫描器消费其真实产物（授权记录+逐流执行证据）做机器可判定面：
  授权五要素/日落合规、exact-scope 覆盖、前后状态、幂等（重复提交零额外
  效应）、守恒（不变量违例数）、补偿（失败路径补偿执行）、清理（回基线
  哈希对账）——即方案 required 证据「授权+前后状态」的完整机器判定。
- 纯人工部分（所有者签发口令本身）不硬凑机器化：一次性 exact-scope 授权
  的签发与吊销在上游授权系统；本扫描器只做「登记+状态汇总」式的证据
  完整性与日落执法（expiry 30 天日落窗、证据须落在授权窗内）。

业务流证据契约（每流一 mapping；结构损坏=LiveFireEvidenceMalformed）::

    {
      "name": "order-create-live",              # 非空，须在授权 scope 内
      "executed_at": "2026-10-09T01:02:03Z",    # ISO-8601，须 ≤ 授权 expiry
      "before_state_hash":  "<64hex>",          # 操作前状态指纹
      "after_state_hash":   "<64hex>",          # 操作后状态指纹
      "baseline_state_hash":"<64hex>",          # 清理后基线（须==before）
      "assertions": [                           # 状态断言（含正/负例）
          {"name": "order-visible", "outcome": "PASS"},
      ],
      "idempotency":  {"replay_effects": 0},    # 重复提交额外效应数（须 0）
      "conservation": {"invariant": "stock>=0", "violations": 0},
      "compensation": {"required": False, "executed": False},
    }

覆盖口径（注册表 coverage_denominator=业务流断言点数）：
- denominator = Σ(每流状态断言数 + 4 个固定检查点：幂等/守恒/补偿/回基线)；
- scanned = 完成判定的断言点数。结构合法的证据必然全量判定（判得出才
  算扫到——站7 同一哲学）；结构性损坏整体拒绝（fail-closed，站3 先例）。

判定矩阵（冻结）：
- authorization 缺失/过期/超 30 天日落窗/证据越窗/越 exact-scope
  → BLOCKED + NOT_EVALUATED（注册表 error 判据：生产写授权缺失不算通过）；
- 任一断言点 FAIL（状态断言失败/幂等破坏/守恒破坏/补偿缺失/数据未回
  基线）→ COMPLETED + FAIL + 逐点 finding 落账；
- 授权有效且全断言点 PASS → COMPLETED + PASS（coverage 满分 + 非空
  artifacts，schema P0-4 硬约束）。

安全构造（by construction）：
- 纯 stdlib；无外部命令、无 shell、无 eval/exec——本站判定全部进程内
  完成（RunManifest.to_station_result / 站7 进程内腿同一先例，
  actual_exit_code=0 只表示判定逻辑自身正常结束，绝不代表发生过生产写）。
- 身份三源一律取冻结 manifest 正源，绝不采信证据载荷自报身份。
- 授权记录入 artifacts 时脱敏：只留 approver/scope/expiry 与 token 指纹
  （sha256 前 12 位），不回显任何凭据原文。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .bugscan_orchestrator import (
    RunManifest,
    build_station_result,
    validate_station_result,
)
from .runner import TrustedRunner

__all__ = [
    "STATION_ID",
    "REQUIRES_EXPLICIT_AUTHORIZATION",
    "COUNTS_TOWARD_CONVERGENCE",
    "BLOCKS_RELEASE",
    "AUTHORIZATION_SUNSET_MAX_DAYS",
    "LiveFireStationError",
    "LiveFireAuthorizationMalformed",
    "LiveFireEvidenceMalformed",
    "LiveFireAuthorization",
    "LiveFireScanner",
    "scan_station5",
]

__version__ = "1.0.0"

STATION_ID = 5

#: 站5 必须显式授权后才可加入 run（注册表 notes：不在任何自动档 required 集内）。
REQUIRES_EXPLICIT_AUTHORIZATION: bool = True

#: 站5 计入收敛轮（显式授权加入后与常规站同语义）。
COUNTS_TOWARD_CONVERGENCE: bool = True

#: 站5 可阻断发布：授权缺失/断言失败时发布门不得放行。
BLOCKS_RELEASE: bool = True

#: 授权日落窗上限（天）——对齐 bugscan_orchestrator.RISK_ACCEPTANCE_MAX_DAYS
#: 的 30 天日落先例（一次性 exact-scope 授权不允许无限期存续）。
AUTHORIZATION_SUNSET_MAX_DAYS = 30

#: 状态哈希形态（sha256 hex）。
_RE_STATE_HASH_LEN = 64


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class LiveFireStationError(ValueError):
    """站5 适配器基类错误——一律 fail-closed。"""


class LiveFireAuthorizationMalformed(LiveFireStationError):
    """授权记录结构性损坏：非对象/缺必备字段/字段形态非法。"""


class LiveFireEvidenceMalformed(LiveFireStationError):
    """业务流证据结构性损坏：缺字段/哈希非 64hex/时间戳不可解析。"""


# ---------------------------------------------------------------------------
# 基础工具（与 station7_runtime 同算法的本地实现，保持模块自包含）
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_obj(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _sha256_hex(canonical.encode("utf-8"))


def _parse_ts(value: Any, what: str,
              exc: type = LiveFireEvidenceMalformed) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise exc(f"{what} must be a non-empty ISO-8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as err:
        raise exc(f"{what} is not ISO-8601: {value!r}") from err
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _attempt_id(run_id: str, tag: str) -> str:
    seed = _hash_obj({"run_id": run_id, "tag": tag, "ts": _iso_z(_utc_now())})
    return f"att-{tag}-{seed[:12]}"


def _finding_id(prefix: str, seed: str) -> str:
    safe = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in prefix)
    return f"fnd_{safe}_{_sha256_hex(seed.encode('utf-8'))[:12]}"


def _require_manifest(manifest: RunManifest) -> RunManifest:
    if not isinstance(manifest, RunManifest):
        raise LiveFireStationError(
            f"manifest must be RunManifest, got {type(manifest).__name__}"
        )
    return manifest


def _manifest_identity(manifest: RunManifest) -> Dict[str, Any]:
    """身份三源一律取冻结 manifest 正源，绝不采信证据载荷自报身份。"""
    identity: Dict[str, Any] = {
        "project_id": manifest.project_id,
        "commit_sha": manifest.commit_sha,
        "environment": manifest.environment,
        "scope_hash": manifest.scope_hash,
        "ruleset_hash": manifest.ruleset_hash,
        "data_config_hash": manifest.data_config_hash,
    }
    if manifest.lockfile_hash:
        identity["lockfile_hash"] = manifest.lockfile_hash
    return identity


def _cas_artifact(payload: bytes) -> Optional[Dict[str, Any]]:
    """字节载荷 → CAS 工件条目；空载荷（0B）无证据价值，返回 None。"""
    if not payload:
        return None
    return {"cas_digest": f"sha256:{_sha256_hex(payload)}", "size": len(payload)}


# ---------------------------------------------------------------------------
# LiveFireAuthorization——一次性 exact-scope 生产写授权记录（五要素）
# ---------------------------------------------------------------------------


class LiveFireAuthorization:
    """所有者明确口令的一次性 exact-scope 生产写授权（冻结值对象）。

    五要素对齐 finding-event-v2 risk_acceptance / RiskAcceptance 先例：
    approver（所有者）/ reason（≥10 字）/ scope（exact 流名集合，非空）/
    expiry（ISO-8601）+ token（一次性口令指纹标识，非空）。

    语义执法分工（冻结）：
    - 结构面（本类 from_mapping/validate）：五要素齐全、形态合法、理由
      ≥10 字、expiry 可解析——损坏抛 LiveFireAuthorizationMalformed
      （最强 fail-closed：不产出任何结果，含 PASS）；
    - 语义面（LiveFireScanner._check_authorization）：过期/超 30 天日落
      窗/证据越窗/越 exact-scope → BLOCKED + NOT_EVALUATED 结果落账
      （注册表 error 判据：不算通过——比异常温和、比放行严格）。
    """

    __slots__ = ("approver", "reason", "scope", "expiry", "token")

    def __init__(
        self,
        approver: str,
        reason: str,
        scope: Iterable[str],
        expiry: str,
        token: str,
    ) -> None:
        self.approver = approver
        self.reason = reason
        self.scope: Tuple[str, ...] = tuple(scope)
        self.expiry = expiry
        self.token = token

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "LiveFireAuthorization":
        if not isinstance(data, Mapping):
            raise LiveFireAuthorizationMalformed(
                f"authorization must be a mapping, got {type(data).__name__}"
            )
        missing = [k for k in ("approver", "reason", "scope", "expiry", "token")
                   if not data.get(k)]
        if missing:
            raise LiveFireAuthorizationMalformed(
                f"authorization missing required fields: {missing} "
                "（所有者/理由/范围/到期/一次性口令 缺一不可）"
            )
        scope_raw = data["scope"]
        if isinstance(scope_raw, str):
            scope_names = [scope_raw]
        elif isinstance(scope_raw, (list, tuple)):
            scope_names = list(scope_raw)
        else:
            raise LiveFireAuthorizationMalformed(
                f"authorization.scope must be a string or list of flow names, "
                f"got {type(scope_raw).__name__}"
            )
        if not scope_names or any(not isinstance(n, str) or not n.strip()
                                  for n in scope_names):
            raise LiveFireAuthorizationMalformed(
                "authorization.scope must contain at least one non-empty flow name"
            )
        if len(set(scope_names)) != len(scope_names):
            raise LiveFireAuthorizationMalformed(
                "authorization.scope contains duplicate flow names"
            )
        return cls(
            approver=str(data["approver"]),
            reason=str(data["reason"]),
            scope=tuple(n.strip() for n in scope_names),
            expiry=str(data["expiry"]),
            token=str(data["token"]),
        )

    def expiry_at(self) -> datetime:
        """解析到期时刻（不可解析=结构性损坏，fail-closed 抛错）。"""
        return _parse_ts(self.expiry, "authorization.expiry",
                         exc=LiveFireAuthorizationMalformed)

    def validate(self) -> datetime:
        """结构自检（理由长度等）；返回到期时刻。语义日落执法在扫描器。"""
        if len(self.reason.strip()) < 10:
            raise LiveFireAuthorizationMalformed(
                f"authorization reason too short ({len(self.reason.strip())} chars; "
                "须 ≥10 字，对齐 finding-event-v2 minLength 先例"
            )
        return self.expiry_at()

    def redacted(self) -> Dict[str, Any]:
        """脱敏视图（入 artifacts/账本用；token 只留指纹，不回显原文）。"""
        return {
            "approver": self.approver,
            "scope": list(self.scope),
            "expiry": self.expiry,
            "token_fingerprint": _sha256_hex(self.token.encode("utf-8"))[:12],
        }


# ---------------------------------------------------------------------------
# LiveFireScanner——站5 唯一入口：授权+前后状态证据面真实判定
# ---------------------------------------------------------------------------


class LiveFireScanner:
    """站5 实弹面扫描器：对真实仓内实弹执行产物（授权+逐流证据）做判定。

    用法::

        scanner = LiveFireScanner(
            manifest,
            authorization={"approver": "owner", "reason": "…（≥10 字）…",
                           "scope": ["order-create-live"], "expiry": "…Z",
                           "token": "one-time-token"},
            flows=[{...业务流证据契约...}],
        )
        station_result = scanner.scan()   # station-result-v2

    authorization=None → 注册表 error 判据（生产写授权缺失→BLOCKED，不算
    通过）；结构性损坏一律抛 LiveFireAuthorizationMalformed /
    LiveFireEvidenceMalformed（fail-closed，不产出任何结果）。
    """

    STATION_ID = STATION_ID

    def __init__(
        self,
        manifest: RunManifest,
        *,
        authorization: Optional[Mapping[str, Any]] = None,
        flows: Iterable[Mapping[str, Any]] = (),
        now: Optional[datetime] = None,
    ) -> None:
        _require_manifest(manifest)
        self._manifest = manifest
        self._now = now or _utc_now()
        self._authorization: Optional[LiveFireAuthorization] = None
        if authorization is not None:
            auth = LiveFireAuthorization.from_mapping(authorization)
            auth.validate()  # 结构自检（要素形态/理由长度/expiry 可解析）
            self._authorization = auth
        self._flows: List[Dict[str, Any]] = [
            self._validate_flow(dict(f), i) for i, f in enumerate(flows or ())
        ]
        if not self._flows and self._authorization is not None:
            raise LiveFireEvidenceMalformed(
                "flows must contain at least one entry（授权在场却无业务流证据="
                "空分母，禁止 vacuous 判定）"
            )
        self.last_breakdown: Dict[str, Any] = {}

    # -- 结构校验（fail-closed：损坏即抛，不产出结果） -----------------------

    @staticmethod
    def _require_hash(value: Any, field: str, index: int) -> str:
        if not isinstance(value, str) or len(value) != _RE_STATE_HASH_LEN \
                or any(ch not in "0123456789abcdef" for ch in value):
            raise LiveFireEvidenceMalformed(
                f"flows[{index}].{field} must be a 64-char lowercase hex "
                f"sha256 state hash, got {value!r}"
            )
        return value

    @classmethod
    def _validate_flow(cls, flow: Mapping[str, Any], index: int) -> Dict[str, Any]:
        if not isinstance(flow, Mapping):
            raise LiveFireEvidenceMalformed(
                f"flows[{index}] must be a mapping, got {type(flow).__name__}"
            )
        name = flow.get("name")
        if not isinstance(name, str) or not name.strip():
            raise LiveFireEvidenceMalformed(
                f"flows[{index}].name must be a non-empty string"
            )
        executed_at = _parse_ts(flow.get("executed_at"),
                                f"flows[{index}].executed_at")
        assertions_raw = flow.get("assertions")
        if not isinstance(assertions_raw, (list, tuple)) or not assertions_raw:
            raise LiveFireEvidenceMalformed(
                f"flows[{index}].assertions must be a non-empty list of "
                "{\"name\",\"outcome\"} entries"
            )
        assertions: List[Dict[str, Any]] = []
        for j, a in enumerate(assertions_raw):
            if not isinstance(a, Mapping):
                raise LiveFireEvidenceMalformed(
                    f"flows[{index}].assertions[{j}] must be a mapping"
                )
            a_name = a.get("name")
            outcome = a.get("outcome")
            if not isinstance(a_name, str) or not a_name.strip():
                raise LiveFireEvidenceMalformed(
                    f"flows[{index}].assertions[{j}].name must be non-empty"
                )
            if outcome not in ("PASS", "FAIL"):
                raise LiveFireEvidenceMalformed(
                    f"flows[{index}].assertions[{j}].outcome must be "
                    f"'PASS' or 'FAIL', got {outcome!r}"
                )
            assertions.append({"name": a_name.strip(), "outcome": outcome})

        idem = flow.get("idempotency")
        if not isinstance(idem, Mapping) or not isinstance(idem.get("replay_effects"), int) \
                or isinstance(idem.get("replay_effects"), bool) \
                or idem.get("replay_effects") < 0:
            raise LiveFireEvidenceMalformed(
                f"flows[{index}].idempotency must be "
                "{\"replay_effects\": int>=0}"
            )
        cons = flow.get("conservation")
        if not isinstance(cons, Mapping) or not isinstance(cons.get("violations"), int) \
                or isinstance(cons.get("violations"), bool) or cons.get("violations") < 0:
            raise LiveFireEvidenceMalformed(
                f"flows[{index}].conservation must be "
                "{\"invariant\": str, \"violations\": int>=0}"
            )
        comp = flow.get("compensation")
        if not isinstance(comp, Mapping) or not isinstance(comp.get("required"), bool) \
                or not isinstance(comp.get("executed"), bool):
            raise LiveFireEvidenceMalformed(
                f"flows[{index}].compensation must be "
                "{\"required\": bool, \"executed\": bool}"
            )
        return {
            "name": name.strip(),
            "executed_at": executed_at,
            "before_state_hash": cls._require_hash(
                flow.get("before_state_hash"), "before_state_hash", index),
            "after_state_hash": cls._require_hash(
                flow.get("after_state_hash"), "after_state_hash", index),
            "baseline_state_hash": cls._require_hash(
                flow.get("baseline_state_hash"), "baseline_state_hash", index),
            "assertions": assertions,
            "idempotency": dict(idem),
            "conservation": dict(cons),
            "compensation": dict(comp),
        }

    # -- 授权语义执法（返回失败原因清单；空=通过） ---------------------------

    def _check_authorization(self) -> List[str]:
        """授权缺失/过期/超日落窗/证据越窗/越 exact-scope → 原因清单。"""
        if self._authorization is None:
            return ["authorization_missing: 生产写授权缺失（注册表 error 判据："
                    "BLOCKED，不算通过）"]
        reasons: List[str] = []
        auth = self._authorization
        now = self._now
        expiry = auth.expiry_at()
        if expiry <= now:
            reasons.append(
                f"authorization_expired: 授权已于 {auth.expiry} 到期"
                f"（{AUTHORIZATION_SUNSET_MAX_DAYS}d 日落执法）")
        if expiry > now + timedelta(days=AUTHORIZATION_SUNSET_MAX_DAYS):
            reasons.append(
                "authorization_beyond_sunset: 授权到期超出 "
                f"{AUTHORIZATION_SUNSET_MAX_DAYS}d 日落窗（一次性 exact-scope "
                "授权不得无限期存续）")
        scope_set = set(auth.scope)
        for flow in self._flows:
            if flow["name"] not in scope_set:
                reasons.append(
                    f"flow_out_of_scope: 业务流 {flow['name']!r} 不在授权 "
                    f"exact-scope {sorted(scope_set)} 内（越授权生产写）")
            if flow["executed_at"] > expiry:
                reasons.append(
                    f"evidence_out_of_window: 业务流 {flow['name']!r} 执行时刻 "
                    f"{_iso_z(flow['executed_at'])} 晚于授权到期 {auth.expiry}"
                    "（授权窗外生产写证据不可采）")
        return reasons

    # -- 断言点判定 ----------------------------------------------------------

    @staticmethod
    def _checkpoint_failures(flow: Mapping[str, Any]) -> List[Dict[str, Any]]:
        """逐断言点判定；返回失败点清单（空=全 PASS）。"""
        failures: List[Dict[str, Any]] = []
        for a in flow["assertions"]:
            if a["outcome"] != "PASS":
                failures.append({"flow": flow["name"], "kind": "state_assertion",
                                 "point": a["name"]})
        if flow["idempotency"]["replay_effects"] != 0:
            failures.append({"flow": flow["name"], "kind": "idempotency",
                             "point": "replay_effects="
                                      f"{flow['idempotency']['replay_effects']}"})
        if flow["conservation"]["violations"] != 0:
            failures.append({"flow": flow["name"], "kind": "conservation",
                             "point": f"invariant={flow['conservation'].get('invariant')!r}"
                                      f" violations={flow['conservation']['violations']}"})
        comp = flow["compensation"]
        if comp["required"] and not comp["executed"]:
            failures.append({"flow": flow["name"], "kind": "compensation",
                             "point": "required_but_not_executed"})
        if flow["baseline_state_hash"] != flow["before_state_hash"]:
            failures.append({"flow": flow["name"], "kind": "baseline_restore",
                             "point": "baseline_state_hash != before_state_hash"
                                      "（数据未回基线）"})
        return failures

    def scan(self) -> Dict[str, Any]:  # noqa: C901——判定矩阵天然分支多
        started = _iso_z(_utc_now())
        auth_reasons = self._check_authorization()
        denominator = sum(
            len(f["assertions"]) + 4 for f in self._flows
        ) if self._authorization is not None else 0

        argv = ["wenqu_core.station5_live_fire", "live-fire-adjudicate",
                self._manifest.run_id] + sorted(f["name"] for f in self._flows)

        # ---- 授权面失败：BLOCKED（注册表 error 判据——绝不算通过） ----------
        if auth_reasons:
            note = "; ".join(auth_reasons)
            finding_ids = [
                _finding_id("livefire_auth", f"{self._manifest.run_id}:{r}")
                for r in auth_reasons[:1]
            ]
            table = {
                "judged_at": started,
                "station": "live_fire",
                "authorization": (
                    self._authorization.redacted()
                    if self._authorization is not None else None
                ),
                "authorization_failures": auth_reasons,
                "flows_total": len(self._flows),
                "assertion_points_evaluated": 0,
                "coverage_note": "授权无效→断言点全部不采信（0/0 非 vacuous："
                                 "verdict 已 NOT_EVALUATED）",
            }
            ended = _iso_z(_utc_now())
            self.last_breakdown = dict(table)
            return build_station_result(
                run_id=self._manifest.run_id,
                station_id=self.STATION_ID,
                attempt_id=_attempt_id(self._manifest.run_id, "st5-livefire"),
                execution_status="BLOCKED",
                policy_verdict="NOT_EVALUATED",
                identity=_manifest_identity(self._manifest),
                tool={"name": "wenqu_core.station5_live_fire.LiveFireScanner",
                      "version": __version__},
                execution={
                    "argv_digest": TrustedRunner.argv_digest(argv),
                    "started_at": started,
                    "ended_at": ended,
                    "actual_exit_code": 0,  # 判定进程内完成（先例见模块 docstring）
                    "expected_exit_set": [0],
                    "assertion_verdict": "ERROR",
                },
                coverage={"denominator": denominator, "scanned": 0},
                finding_ids=finding_ids,
                artifacts=[_cas_artifact(
                    json.dumps(table, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8"))],
            )

        # ---- 授权有效：逐断言点判定 -----------------------------------------
        failures: List[Dict[str, Any]] = []
        for flow in self._flows:
            failures.extend(self._checkpoint_failures(flow))
        scanned = denominator  # 结构合法证据全量判定（判得出才算扫到）

        if failures:
            execution_status, policy_verdict, assertion = "COMPLETED", "FAIL", "FAIL"
        else:
            execution_status, policy_verdict, assertion = "COMPLETED", "PASS", "PASS"

        finding_ids = [
            _finding_id(f"livefire_{f['kind']}", f"{self._manifest.run_id}:"
                        f"{f['flow']}:{f['point']}")
            for f in failures
        ]

        table = {
            "judged_at": started,
            "station": "live_fire",
            "authorization": self._authorization.redacted(),
            "flows_total": len(self._flows),
            "assertion_points_total": denominator,
            "assertion_points_failed": len(failures),
            "failed_checkpoints": failures,
            "flows": [
                {
                    "name": f["name"],
                    "executed_at": _iso_z(f["executed_at"]),
                    "before_state_hash": f["before_state_hash"],
                    "after_state_hash": f["after_state_hash"],
                    "baseline_state_hash": f["baseline_state_hash"],
                    "baseline_restored": (
                        f["baseline_state_hash"] == f["before_state_hash"]),
                    "assertions": f["assertions"],
                    "idempotency": f["idempotency"],
                    "conservation": f["conservation"],
                    "compensation": f["compensation"],
                }
                for f in self._flows
            ],
        }
        ended = _iso_z(_utc_now())
        self.last_breakdown = {
            k: table[k] for k in (
                "judged_at", "flows_total", "assertion_points_total",
                "assertion_points_failed", "failed_checkpoints")
        }
        return build_station_result(
            run_id=self._manifest.run_id,
            station_id=self.STATION_ID,
            attempt_id=_attempt_id(self._manifest.run_id, "st5-livefire"),
            execution_status=execution_status,
            policy_verdict=policy_verdict,
            identity=_manifest_identity(self._manifest),
            tool={"name": "wenqu_core.station5_live_fire.LiveFireScanner",
                  "version": __version__},
            execution={
                "argv_digest": TrustedRunner.argv_digest(argv),
                "started_at": started,
                "ended_at": ended,
                "actual_exit_code": 0,
                "expected_exit_set": [0],
                "assertion_verdict": assertion,
            },
            coverage={"denominator": denominator, "scanned": scanned},
            finding_ids=finding_ids,
            artifacts=[
                _cas_artifact(json.dumps(
                    table, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False).encode("utf-8")),
                _cas_artifact(json.dumps(
                    self._authorization.redacted(), sort_keys=True,
                    separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
            ],
        )


def scan_station5(
    manifest: RunManifest,
    *,
    authorization: Optional[Mapping[str, Any]] = None,
    flows: Iterable[Mapping[str, Any]] = (),
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """站5 便捷入口（构造 LiveFireScanner 并立即 scan）。"""
    return LiveFireScanner(
        manifest, authorization=authorization, flows=flows, now=now,
    ).scan()


# ---------------------------------------------------------------------------
# 端到端自证（python3 -m wenqu_core.station5_live_fire）
# ---------------------------------------------------------------------------


def _self_test() -> int:
    from datetime import timedelta as _td

    from .bugscan_orchestrator import BugscanPlanner, default_registry

    registry = default_registry()
    planner = BugscanPlanner(registry)
    # 站5 不在任何自动档 required 集——显式授权后才加入：以 STANDARD 计划
    # 冻结 manifest，再独立跑站5（语义与生产用法一致）。
    plan = planner.plan("STANDARD")
    assert 5 not in plan.required_stations  # 注册表 notes 语义自证
    sha = "1" * 40
    manifest = planner.freeze_run_manifest(
        plan,
        run_id="selftest-st5-001",
        project_id="wenqu-selftest",
        commit_sha=sha,
        environment="local",
        scope=["src/**"],
        ruleset={"version": "w6d", "rules": ["W6A-ST5"]},
        data_config={"profile": "default"},
    )
    now = _utc_now()
    expiry = _iso_z(now + _td(days=1))
    good_auth = {
        "approver": "biz-owner",
        "reason": "下单全链实弹验证：一次性 exact-scope 授权",
        "scope": ["order-create-live"],
        "expiry": expiry,
        "token": "one-time-token-selftest",
    }
    before, after = "a" * 64, "b" * 64
    good_flow = {
        "name": "order-create-live",
        "executed_at": _iso_z(now),
        "before_state_hash": before,
        "after_state_hash": after,
        "baseline_state_hash": before,  # 清理后回基线
        "assertions": [
            {"name": "order-visible", "outcome": "PASS"},
            {"name": "stock-deducted", "outcome": "PASS"},
        ],
        "idempotency": {"replay_effects": 0},
        "conservation": {"invariant": "stock>=0", "violations": 0},
        "compensation": {"required": False, "executed": False},
    }

    # [1] PASS：授权有效 + 断言点 6/6（2 状态断言 + 幂等/守恒/补偿/回基线）
    st = LiveFireScanner(manifest, authorization=good_auth,
                         flows=[good_flow], now=now).scan()
    validate_station_result(st)
    assert st["station_id"] == 5 and st["policy_verdict"] == "PASS"
    assert st["coverage"] == {"denominator": 6, "scanned": 6}
    assert st["artifacts"], "PASS 必须携带非空 artifacts（schema P0-4）"
    print(f"[1] live-fire PASS OK: 6/6 断言点全过，授权脱敏入证 "
          f"({st['artifacts'][0]['cas_digest'][:19]}…)")

    # [2] 授权缺失 → BLOCKED/NOT_EVALUATED（注册表 error 判据）
    scanner = LiveFireScanner(manifest, flows=[good_flow], now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED"
    assert st["policy_verdict"] == "NOT_EVALUATED"
    assert st["coverage"] == {"denominator": 0, "scanned": 0}
    assert scanner.last_breakdown["authorization_failures"] == [
        "authorization_missing: 生产写授权缺失（注册表 error 判据：BLOCKED，不算通过）"]
    print("[2] live-fire no-auth OK: BLOCKED/NOT_EVALUATED（不算通过）")

    # [3] 数据未回基线 + 断言失败 → FAIL 逐点落账
    broken = dict(good_flow, baseline_state_hash="c" * 64)
    broken["assertions"] = [{"name": "order-visible", "outcome": "FAIL"}]
    st = LiveFireScanner(manifest, authorization=good_auth,
                         flows=[broken], now=now).scan()
    validate_station_result(st)
    assert st["policy_verdict"] == "FAIL" and st["execution_status"] == "COMPLETED"
    assert any("state_assertion" in f for f in st["finding_ids"])
    assert any("baseline_restore" in f for f in st["finding_ids"])
    print(f"[3] live-fire FAIL OK: 状态断言失败+数据未回基线 → {st['finding_ids']}")

    # [4] 授权过期/越 exact-scope → BLOCKED
    expired_auth = dict(good_auth, expiry=_iso_z(now - _td(days=1)))
    scanner = LiveFireScanner(manifest, authorization=expired_auth,
                              flows=[good_flow], now=now)
    st = scanner.scan()
    validate_station_result(st)
    assert st["execution_status"] == "BLOCKED"
    assert any(r.startswith("authorization_expired")
               for r in scanner.last_breakdown["authorization_failures"])
    out_of_scope = dict(good_flow, name="fund-transfer-live")
    scanner = LiveFireScanner(manifest, authorization=good_auth,
                              flows=[out_of_scope], now=now)
    st = scanner.scan()
    assert st["execution_status"] == "BLOCKED"
    assert any(r.startswith("flow_out_of_scope")
               for r in scanner.last_breakdown["authorization_failures"])
    print("[4] live-fire auth enforcement OK: 过期/越 scope → BLOCKED")

    # [5] 结构损坏 → fail-closed 异常（不产出任何结果）
    for bad in (
        {"approver": "o"},                                    # 缺要素
        dict(good_auth, expiry="not-a-date"),                 # 时间戳非法
        dict(good_auth, scope=[]),                            # 空 scope
    ):
        try:
            LiveFireScanner(manifest, authorization=bad, flows=[good_flow],
                            now=now)
            raise AssertionError("malformed authorization must raise")
        except LiveFireAuthorizationMalformed:
            pass
    bad_flow = dict(good_flow, before_state_hash="zz")
    try:
        LiveFireScanner(manifest, authorization=good_auth, flows=[bad_flow],
                        now=now)
        raise AssertionError("malformed flow must raise")
    except LiveFireEvidenceMalformed:
        pass
    print("[5] live-fire fail-closed OK: 结构损坏一律拒绝")

    assert REQUIRES_EXPLICIT_AUTHORIZATION and COUNTS_TOWARD_CONVERGENCE
    print("SELF-TEST PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

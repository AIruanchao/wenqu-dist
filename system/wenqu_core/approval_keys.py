# -*- coding: utf-8 -*-
"""approval_keys.py——审批签发密钥登记 + HMAC-SHA256 真实验签（P0-2/P0-4 加固）。

Codex 第三轮对抗实锤 #1：approval.signature 只验长度（>= 32 字符），
伪造任意字符串即可通过并把缺字段的 envelope 消费掉。本模块把 signature
从"形状断言"升级为可验证的 HMAC-SHA256：

- keyring：key_id → secret 的受管登记，两种载体（目录型 / JSON 文件型）；
- 签名：signature = hex(hmac_sha256(secret,
              canonical_json(envelope_without_signature)))；
- 验签：ApprovalBroker 在消费前查 key_id → secret 并重算比对
  （hmac.compare_digest，防时序侧信道）；无 key_id / 未知 key_id /
  验签失败一律 ApprovalRejected（fail-closed，绝不静默择优）。

密钥管理边界（诚实声明）：
- secret 以明文落在 keyring 路径——与仓库/事件库/审批文件的物理隔离、
  文件权限（0600）是部署责任；
- 对称 shared-secret 模型防伪造/防篡改，不提供非否认（non-repudiation）；
- 纯标准库实现（hmac/hashlib/secrets/json），无第三方依赖。

P0-2 残余（审批签发端，2026-10-08）：key 生命周期元数据扩展——
- 每 key 元数据：status（active/rotated/revoked）+ rotated_at/rotated_to +
  revoked_at + expiry（ISO8601，可选）+ created_at；
- 轮换：旧 key 标 rotated——**仍可验存量签名**（TTL 内已签发的审批不作废），
  但不可再签发新审批；
- 吊销：revoked——**验签即拒**（fail-closed），并把拒绝事件记入 keyring
  事件账本（目录型 keyring：``<dir>/keyring-events.jsonl``，append-only）；
- 过期：expiry 只阻断**新签发**；存量验证仍以信封自身 TTL 为准（撤销才是
  显式的「验签即拒」控制）；
- 目录型 keyring 的受管写入（``wenquctl keys create/rotate/revoke``）：
  目录 0700（目录需要 x 位才能访问内容——「owner-only 0600 语义」对目录
  的可执行落地），secret/meta 文件 0600，与 wenquctl/文档一致。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from typing import Any, Dict, List, Mapping, Optional

__all__ = [
    "ApprovalKeyring",
    "KeyNotFoundError",
    "KeyStateError",
    "KeyRevokedError",
    "KeyRotatedError",
    "KeyExpiredError",
    "KEY_STATUS_ACTIVE",
    "KEY_STATUS_ROTATED",
    "KEY_STATUS_REVOKED",
    "KEY_STATUSES",
    "KEYRING_EVENTS_FILENAME",
    "generate_secret",
    "sign_envelope",
    "verify_envelope",
    "ensure_keyring_dir",
    "write_key_to_dir",
    "save_key_meta",
    "append_keyring_event",
]

#: key_id 命名约束（与 approval-v2.schema.json 的 pattern 一致）
KEY_ID_PATTERN = "key_[a-zA-Z0-9_-]+"

_SIGNATURE_LEN = 64  # hmac-sha256 hex


class KeyNotFoundError(KeyError):
    """key_id 未在 keyring 登记。"""


# ---------------------------------------------------------------------- #
# P0-2 残余：key 生命周期元数据（status/rotated_at/expiry）
# ---------------------------------------------------------------------- #

KEY_STATUS_ACTIVE = "active"
KEY_STATUS_ROTATED = "rotated"
KEY_STATUS_REVOKED = "revoked"
KEY_STATUSES = frozenset({KEY_STATUS_ACTIVE, KEY_STATUS_ROTATED,
                          KEY_STATUS_REVOKED})

#: 目录型 keyring 的生命周期事件账本文件名（append-only，0600）
KEYRING_EVENTS_FILENAME = "keyring-events.jsonl"

#: secret/meta 文件与目录的权限（owner-only；目录需 x 位故为 0700）
_SECRET_FILE_MODE = 0o600
_KEYRING_DIR_MODE = 0o700


class KeyStateError(KeyError):
    """key 生命周期状态不允许该操作（fail-closed）。"""


class KeyRevokedError(KeyStateError):
    """key 已吊销——验签即拒，不得用于签发。"""


class KeyRotatedError(KeyStateError):
    """key 已轮换——可验存量，不得签发新审批。"""


class KeyExpiredError(KeyStateError):
    """key 已过期（expiry）——不得签发新审批。"""


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _parse_iso_or_none(value: Any, field: str) -> Optional[float]:
    """元数据 ISO 时间戳 → epoch；空值返回 None，坏值抛 ValueError。"""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    import datetime
    if not isinstance(value, str):
        raise ValueError(f"key meta {field} must be an ISO8601 string")
    try:
        return datetime.datetime.fromisoformat(
            value.replace("Z", "+00:00")).timestamp()
    except ValueError as exc:
        raise ValueError(
            f"key meta {field} is not a valid ISO8601 timestamp: "
            f"{value!r}") from exc


def generate_secret(nbytes: int = 32) -> str:
    """生成新密钥（crypto 随机，hex 编码）。"""
    if nbytes < 16:
        raise ValueError("secret entropy too low: nbytes must be >= 16")
    return secrets.token_hex(nbytes)


def _canonical_json(obj: Any) -> str:
    """与 wenqu_pipeline/store 完全一致的规范化 JSON（排序+紧凑+非转义）。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sign_envelope(secret: str, envelope: Mapping[str, Any]) -> str:
    """对 envelope（不含 signature 字段）计算 HMAC-SHA256 签名（64 hex）。"""
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty string")
    body = {k: v for k, v in dict(envelope).items() if k != "signature"}
    mac = hmac.new(secret.encode("utf-8"),
                   _canonical_json(body).encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def verify_envelope(secret: str, envelope: Mapping[str, Any],
                    signature: str) -> bool:
    """重算并常量时间比对签名；任何形状不符直接 False（不抛错）。"""
    if not isinstance(signature, str) or len(signature) != _SIGNATURE_LEN:
        return False
    try:
        expected = sign_envelope(secret, envelope)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, signature)


class ApprovalKeyring:
    """key_id → secret 登记（只读视图；生成/写入经 ``save`` 显式落盘）。

    P0-2 残余扩展：可选 metadata（status/rotated_at/expiry）——

    - ``get_for_signing``：仅 active 且未过期的 key 可签发（rotated/revoked/
      expired/未知 一律抛对应 KeyStateError）；
    - ``verify``：revoked 的 key **验签即拒**（返回 False 并尽力把拒绝事件
      记入 keyring 事件账本）；rotated/expired 仍可验存量（信封 TTL 兜底）；
    - 无 metadata 的旧 keyring（如 tests/fixtures/approval-keys.json）
      全部 key 默认 active——向后兼容，P0-2/P0-4 既有行为不变。
    """

    def __init__(self, keys: Optional[Mapping[str, str]] = None,
                 metadata: Optional[Mapping[str, Mapping[str, Any]]] = None,
                 event_log_path: Optional[str] = None) -> None:
        self._keys: Dict[str, str] = {}
        self._meta: Dict[str, Dict[str, Any]] = {}
        # 目录型 keyring 的生命周期/吊销拒绝事件账本（append-only jsonl）
        self._event_log_path = event_log_path
        for key_id, secret in dict(keys or {}).items():
            self._register(key_id, secret)
        for key_id, meta in dict(metadata or {}).items():
            if key_id not in self._keys:
                raise ValueError(
                    f"keyring metadata references unknown key_id {key_id!r}")
            self._meta[key_id] = self._normalize_meta(key_id, meta)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_key_id(key_id: str) -> None:
        import re

        if not isinstance(key_id, str) or not re.fullmatch(KEY_ID_PATTERN,
                                                           key_id):
            raise ValueError(
                f"invalid key_id {key_id!r}: must match ^{KEY_ID_PATTERN}$")

    def _register(self, key_id: str, secret: str) -> None:
        self._validate_key_id(key_id)
        if not isinstance(secret, str) or len(secret) < 16:
            raise ValueError(
                f"secret for {key_id!r} must be a string of >= 16 chars")
        self._keys[key_id] = secret

    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_meta(key_id: str,
                        meta: Mapping[str, Any]) -> Dict[str, Any]:
        """校验并规范化单 key 元数据（未知字段拒绝，防拼写漂移）。"""
        if not isinstance(meta, Mapping):
            raise ValueError(f"key meta for {key_id!r} must be an object")
        allowed = {"status", "created_at", "rotated_at", "rotated_to",
                   "revoked_at", "expiry", "description"}
        stray = sorted(set(meta) - allowed)
        if stray:
            raise ValueError(
                f"key meta for {key_id!r} has unknown fields {stray} "
                f"(allowed: {sorted(allowed)})")
        normalized: Dict[str, Any] = {
            "status": meta.get("status", KEY_STATUS_ACTIVE)}
        if normalized["status"] not in KEY_STATUSES:
            raise ValueError(
                f"key meta status for {key_id!r} must be one of "
                f"{sorted(KEY_STATUSES)}, got {normalized['status']!r}")
        for ts_field in ("created_at", "rotated_at", "revoked_at", "expiry"):
            if ts_field in meta:
                _parse_iso_or_none(meta[ts_field], ts_field)  # 形状校验
                normalized[ts_field] = meta[ts_field]
        if "rotated_to" in meta:
            rotated_to = meta["rotated_to"]
            if rotated_to is not None:
                ApprovalKeyring._validate_key_id(rotated_to)
            normalized["rotated_to"] = rotated_to
        if "description" in meta:
            normalized["description"] = meta["description"]
        if normalized["status"] == KEY_STATUS_ROTATED and \
                not normalized.get("rotated_at"):
            raise ValueError(
                f"key meta for {key_id!r}: rotated key must carry rotated_at")
        if normalized["status"] == KEY_STATUS_REVOKED and \
                not normalized.get("revoked_at"):
            raise ValueError(
                f"key meta for {key_id!r}: revoked key must carry revoked_at")
        return normalized

    # ------------------------------------------------------------------ #
    @classmethod
    def from_path(cls, path: str) -> "ApprovalKeyring":
        """从目录或 JSON 文件加载 keyring。

        - 目录型：``<dir>/<key_id>.secret``（文本文件，首行非空白即 secret）；
          P0-2 残余：可选 ``<dir>/<key_id>.meta.json`` 元数据边车
          （status/rotated_at/expiry），缺省全部 active；目录内
          ``keyring-events.jsonl`` 为生命周期/吊销拒绝事件账本路径；
        - 文件型：JSON——推荐 ``{"keys": {key_id: secret}, "meta": {...}}``，
          兼容顶层扁平 ``{key_id: secret}``（键必须匹配 key_id 命名）。
        """
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"keyring path not found: {path!r}")
        keys: Dict[str, str] = {}
        if os.path.isdir(path):
            meta: Dict[str, Dict[str, Any]] = {}
            for name in sorted(os.listdir(path)):
                if name.endswith(".secret"):
                    key_id = name[: -len(".secret")]
                    with open(os.path.join(path, name), "r",
                              encoding="utf-8") as fh:
                        secret = fh.read().strip()
                    keys[key_id] = secret
                    meta_file = os.path.join(path, f"{key_id}.meta.json")
                    if os.path.exists(meta_file):
                        with open(meta_file, "r", encoding="utf-8") as fh:
                            meta[key_id] = json.load(fh)
            return cls(keys, metadata=meta,
                       event_log_path=os.path.join(
                           path, KEYRING_EVENTS_FILENAME))
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"keyring file {path!r} must hold a JSON object")
        raw = data.get("keys", data)
        if not isinstance(raw, dict):
            raise ValueError(
                f"keyring file {path!r}: 'keys' must be an object")
        file_meta = data.get("meta", data.get("metadata"))
        if file_meta is not None and not isinstance(file_meta, dict):
            raise ValueError(
                f"keyring file {path!r}: 'meta' must be an object")
        return cls(raw, metadata=file_meta)

    # ------------------------------------------------------------------ #
    @classmethod
    def generate(cls, key_id: str, *, secret: Optional[str] = None,
                 nbytes: int = 32) -> "ApprovalKeyring":
        """生成单 key keyring（测试/初始化用；secret 省略则 crypto 随机）。"""
        return cls({key_id: secret if secret is not None
                    else generate_secret(nbytes)})

    def save_json(self, path: str) -> None:
        """把 keyring（含元数据）落盘为 JSON 文件（0600，供下次 from_path 加载）。"""
        payload = json.dumps({"keys": dict(self._keys),
                              "meta": dict(self._meta)},
                             indent=2, ensure_ascii=False)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")

    # ------------------------------------------------------------------ #
    # P0-2 残余：生命周期元数据视图与签发资格
    # ------------------------------------------------------------------ #
    def meta(self, key_id: str) -> Dict[str, Any]:
        """单 key 元数据副本（无元数据的 key 返回 {status: active}）。"""
        if key_id not in self._keys:
            raise KeyNotFoundError(
                f"key_id {key_id!r} not registered in keyring "
                f"(known: {sorted(self._keys)})") from None
        return dict(self._meta.get(key_id, {"status": KEY_STATUS_ACTIVE}))

    def _key_expired(self, key_id: str) -> bool:
        expiry = self._meta.get(key_id, {}).get("expiry")
        if expiry is None:
            return False
        epoch = _parse_iso_or_none(expiry, "expiry")
        return epoch is not None and epoch <= time.time()

    def _key_status(self, key_id: str) -> str:
        return self._meta.get(key_id, {}).get("status", KEY_STATUS_ACTIVE)

    def can_sign(self, key_id: str) -> bool:
        """key 是否可用于**签发新审批**（active 且未过期）。"""
        if key_id not in self._keys:
            return False
        if self._key_status(key_id) != KEY_STATUS_ACTIVE:
            return False
        return not self._key_expired(key_id)

    def active_key_ids(self) -> List[str]:
        """全部可签发 key（active 且未过期，排序稳定）。"""
        return sorted(k for k in self._keys if self.can_sign(k))

    def get_for_signing(self, key_id: str) -> str:
        """签发用取 key：仅 active 且未过期——其余状态显式抛错（fail-closed）。

        - revoked → KeyRevokedError（验签即拒，更不得签发）；
        - rotated → KeyRotatedError（可验存量，不得签发新审批）；
        - expired → KeyExpiredError（expiry 只阻断新签发）；
        - 未登记 → KeyNotFoundError。
        """
        if key_id not in self._keys:
            raise KeyNotFoundError(
                f"key_id {key_id!r} not registered in keyring "
                f"(known: {sorted(self._keys)})") from None
        status = self._key_status(key_id)
        if status == KEY_STATUS_REVOKED:
            raise KeyRevokedError(
                f"key_id {key_id!r} 已吊销（revoked "
                f"{self._meta[key_id].get('revoked_at', '?')}）——"
                "不得签发新审批")
        if status == KEY_STATUS_ROTATED:
            raise KeyRotatedError(
                f"key_id {key_id!r} 已轮换（rotated_at="
                f"{self._meta[key_id].get('rotated_at', '?')}, rotated_to="
                f"{self._meta[key_id].get('rotated_to', '?')}）——"
                "可验存量签名，不得签发新审批")
        if self._key_expired(key_id):
            raise KeyExpiredError(
                f"key_id {key_id!r} 已过期（expiry="
                f"{self._meta[key_id].get('expiry')!r}）——不得签发新审批")
        return self._keys[key_id]

    def has(self, key_id: str) -> bool:
        return key_id in self._keys

    def get(self, key_id: str) -> str:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyNotFoundError(
                f"key_id {key_id!r} not registered in keyring "
                f"(known: {sorted(self._keys)})") from None

    def key_ids(self) -> List[str]:
        return sorted(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    # ------------------------------------------------------------------ #
    def verify(self, approval: Mapping[str, Any]) -> bool:
        """按 envelope.key_id 查 key 并验 signature；任何缺失即 False。

        P0-2 残余：revoked 的 key **验签即拒**（即使签名本身正确），
        并尽力把拒绝事件记入 keyring 事件账本（目录型 keyring；
        记账失败不吞掉拒绝——拒绝优先）；rotated/expired 仍可验存量。
        """
        if not isinstance(approval, Mapping):
            return False
        key_id = approval.get("key_id")
        signature = approval.get("signature")
        if not isinstance(key_id, str) or key_id not in self._keys:
            return False
        if self._key_status(key_id) == KEY_STATUS_REVOKED:
            self._record_revoked_rejection(key_id, approval)
            return False
        return verify_envelope(self._keys[key_id], approval, signature)

    def _record_revoked_rejection(self, key_id: str,
                                  approval: Mapping[str, Any]) -> None:
        """把「revoked key 验签被拒」记入事件账本（best-effort，绝不放行）。"""
        if not self._event_log_path:
            return
        record = {
            "record_type": "REVOKED_KEY_VERIFY_REJECTED",
            "ts": _utc_now_iso(),
            "key_id": key_id,
            "approval_id": approval.get("approval_id"),
            "approval_type": approval.get("approval_type"),
            "run_id": approval.get("run_id"),
            "note": "revoked key signature rejected (fail-closed)",
        }
        try:
            append_keyring_event(self._event_log_path, record)
        except OSError:
            # 记账失败不改变判定：验签结果仍是「拒」。
            return


# ====================================================================== #
# P0-2 残余：目录型受管 keyring 写入（wenquctl keys create/rotate/revoke）
# ====================================================================== #

def _write_private_file(path: str, data: str) -> None:
    """以 0600 写文件（O_EXCL 不用——rotate/list 需要覆盖 meta）。"""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 _SECRET_FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
    os.chmod(path, _SECRET_FILE_MODE)  # 掩盖既有宽权限文件


def ensure_keyring_dir(path: str) -> None:
    """创建/收敛 keyring 目录为 owner-only（0700——目录需要 x 位）。"""
    os.makedirs(path, mode=_KEYRING_DIR_MODE, exist_ok=True)
    os.chmod(path, _KEYRING_DIR_MODE)


def write_key_to_dir(keyring_dir: str, key_id: str, secret: str,
                     meta: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """把 secret（0600）+ 元数据边车 ``<key_id>.meta.json``（0600）写入目录。

    返回规范化后的元数据。目录必须是受管 keyring 目录（0700）。
    """
    ApprovalKeyring._validate_key_id(key_id)  # noqa: SLF001 —— 复用命名约束
    ensure_keyring_dir(keyring_dir)
    _write_private_file(os.path.join(keyring_dir, f"{key_id}.secret"),
                        secret + "\n")
    normalized = ApprovalKeyring._normalize_meta(  # noqa: SLF001
        key_id, dict(meta or {}))
    normalized.setdefault("created_at", _utc_now_iso())
    normalized = ApprovalKeyring._normalize_meta(key_id, normalized)
    save_key_meta(keyring_dir, key_id, normalized)
    return normalized


def save_key_meta(keyring_dir: str, key_id: str,
                  meta: Mapping[str, Any]) -> None:
    """（覆盖）写单 key 元数据边车 ``<key_id>.meta.json``（0600）。"""
    normalized = ApprovalKeyring._normalize_meta(key_id, dict(meta))  # noqa: SLF001
    payload = json.dumps(normalized, indent=2, ensure_ascii=False,
                         sort_keys=True)
    _write_private_file(os.path.join(keyring_dir, f"{key_id}.meta.json"),
                        payload + "\n")


def append_keyring_event(event_log_path: str,
                         record: Mapping[str, Any]) -> None:
    """append-only 追加一条 keyring 生命周期事件（jsonl，0600，单次 write）。"""
    line = json.dumps(dict(record), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)
    fd = os.open(event_log_path,
                 os.O_WRONLY | os.O_CREAT | os.O_APPEND, _SECRET_FILE_MODE)
    try:
        os.write(fd, (line + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(event_log_path, _SECRET_FILE_MODE)

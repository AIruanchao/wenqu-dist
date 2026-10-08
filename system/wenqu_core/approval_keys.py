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
- key 撤销 = 从 keyring 移除该 key_id（未知 key 即拒，天然 fail-closed）；
- 纯标准库实现（hmac/hashlib/secrets/json），无第三方依赖。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from typing import Any, Dict, List, Mapping, Optional

__all__ = [
    "ApprovalKeyring",
    "KeyNotFoundError",
    "generate_secret",
    "sign_envelope",
    "verify_envelope",
]

#: key_id 命名约束（与 approval-v2.schema.json 的 pattern 一致）
KEY_ID_PATTERN = "key_[a-zA-Z0-9_-]+"

_SIGNATURE_LEN = 64  # hmac-sha256 hex


class KeyNotFoundError(KeyError):
    """key_id 未在 keyring 登记。"""


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
    """key_id → secret 登记（只读视图；生成/写入经 ``save`` 显式落盘）。"""

    def __init__(self, keys: Optional[Mapping[str, str]] = None) -> None:
        self._keys: Dict[str, str] = {}
        for key_id, secret in dict(keys or {}).items():
            self._register(key_id, secret)

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
    @classmethod
    def from_path(cls, path: str) -> "ApprovalKeyring":
        """从目录或 JSON 文件加载 keyring。

        - 目录型：``<dir>/<key_id>.secret``（文本文件，首行非空白即 secret）；
        - 文件型：JSON——推荐 ``{"keys": {key_id: secret}}``，
          兼容顶层扁平 ``{key_id: secret}``（键必须匹配 key_id 命名）。
        """
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"keyring path not found: {path!r}")
        keys: Dict[str, str] = {}
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if not name.endswith(".secret"):
                    continue
                key_id = name[: -len(".secret")]
                with open(os.path.join(path, name), "r",
                          encoding="utf-8") as fh:
                    secret = fh.read().strip()
                keys[key_id] = secret
            return cls(keys)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"keyring file {path!r} must hold a JSON object")
        raw = data.get("keys", data)
        if not isinstance(raw, dict):
            raise ValueError(
                f"keyring file {path!r}: 'keys' must be an object")
        return cls(raw)

    # ------------------------------------------------------------------ #
    @classmethod
    def generate(cls, key_id: str, *, secret: Optional[str] = None,
                 nbytes: int = 32) -> "ApprovalKeyring":
        """生成单 key keyring（测试/初始化用；secret 省略则 crypto 随机）。"""
        return cls({key_id: secret if secret is not None
                    else generate_secret(nbytes)})

    def save_json(self, path: str) -> None:
        """把 keyring 落盘为 JSON 文件（0600，供下次 from_path 加载）。"""
        payload = json.dumps({"keys": dict(self._keys)}, indent=2,
                             ensure_ascii=False)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")

    # ------------------------------------------------------------------ #
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
        """按 envelope.key_id 查 key 并验 signature；任何缺失即 False。"""
        if not isinstance(approval, Mapping):
            return False
        key_id = approval.get("key_id")
        signature = approval.get("signature")
        if not isinstance(key_id, str) or key_id not in self._keys:
            return False
        return verify_envelope(self._keys[key_id], approval, signature)

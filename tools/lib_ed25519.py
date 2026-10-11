#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lib_ed25519.py —— Ed25519 最小封装（W11-09 裁定独立验签通道共用）。

后端选择（fail-closed）：
    1. 优先 ``cryptography``（``Ed25519PrivateKey``），快且侧信道稳妥；
    2. 无 ``cryptography`` 时退回内置纯 Python RFC 8032 参考实现
       （慢、非常数时间——见下方诚实边界）；
    3. import 时自跑 RFC 8032 TEST 1 向量（空消息），不符直接
       ``RuntimeError``——本模块被 adjudication_sign.py /
       verify_adjudication.py import 失败即工具不可用（退出码 3）。

密钥文件格式（冻结）：
    - 私钥文件：单行 64 个 hex 字符（32 字节 raw seed），0600；
    - 公钥文件：单行 64 个 hex 字符（32 字节 raw public key），0644；
    - 不用 PEM：纯 Python 后端也要能读，hex 是两后端公共格式。

诚实边界：
    - 纯 Python 后端非常数时间（double-and-add），只作无 cryptography
      环境的验签/离线签可用性兜底；生产高频签名建议装 cryptography；
    - 本模块只做原语，不做私钥文件权限/路径策略（那是调用方闸口）。
"""
from __future__ import annotations

import hashlib
import os

# ---------------------------------------------------------------------- #
# 后端探测 + RFC 8032 TEST 1（空消息）自检向量
# ---------------------------------------------------------------------- #
_TEST_SECRET = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc4"
    "4449c5697b326919703bac031cae7f60")
_TEST_PUBLIC = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a"
    "0ee172f3daa62325af021a68f707511a")
_TEST_SIG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a"
    "84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46b"
    "d25bf5f0595bbe24655141438e7a100b")

BACKEND = None
try:                                                    # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
    BACKEND = "cryptography"
except Exception:                                       # noqa: BLE001
    BACKEND = "pure-python"


# ---------------------------------------------------------------------- #
# 纯 Python RFC 8032 参考实现（Edwards25519，扩展坐标）
# ---------------------------------------------------------------------- #
if BACKEND == "pure-python":
    _p = 2 ** 255 - 19
    _l = 2 ** 252 + 27742317777372353535851937790883648493
    _d = 0

    def _inv(x: int) -> int:
        return pow(x, _p - 2, _p)

    _d = -121665 * _inv(121666) % _p
    _I = pow(2, (_p - 1) // 4, _p)

    def _xrecover(y: int) -> int:
        xx = (y * y - 1) * _inv(_d * y * y + 1)
        x = pow(xx, (_p + 3) // 8, _p)
        if (x * x - xx) % _p != 0:
            x = x * _I % _p
        if x % 2 != 0:
            x = _p - x
        return x

    _By = 4 * _inv(5) % _p
    _Bx = _xrecover(_By)
    _B = (_Bx, _By, 1, _Bx * _By % _p)

    def _edwards_add(P, Q):
        x1, y1, z1, t1 = P
        x2, y2, z2, t2 = Q
        a = (y1 - x1) * (y2 - x2) % _p
        b = (y1 + x1) * (y2 + x2) % _p
        c = t1 * 2 * _d * t2 % _p
        d = z1 * 2 * z2 % _p
        e, f, g, h = b - a, d - c, d + c, b + a
        return (e * f % _p, g * h % _p, f * g % _p, e * h % _p)

    def _scalarmult(P, e: int):
        Q = (0, 1, 1, 0)
        while e > 0:
            if e & 1:
                Q = _edwards_add(Q, P)
            P = _edwards_add(P, P)
            e >>= 1
        return Q

    def _oncurve(P) -> bool:
        x, y, z, t = P
        return (z % _p != 0 and x * y % _p == z * t % _p
                and (y * y - x * x - z * z - _d * t * t) % _p == 0)

    def _point_compress(P) -> bytes:
        x, y, z, _t = P
        zi = _inv(z)
        x = x * zi % _p
        y = y * zi % _p
        return int.to_bytes(y | ((x & 1) << 255), 32, "little")

    def _point_decompress(s: bytes):
        if len(s) != 32:
            return None
        y = int.from_bytes(s, "little")
        sign = y >> 255
        y &= (1 << 255) - 1
        x = _xrecover(y)
        if x & 1 != sign:
            x = _p - x
        P = (x, y, 1, x * y % _p)
        return P if _oncurve(P) else None

    def _secret_expand(secret: bytes):
        h = hashlib.sha512(secret).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        return a, h[32:]

    def _pp_pub(secret: bytes) -> bytes:
        a, _ = _secret_expand(secret)
        return _point_compress(_scalarmult(_B, a))

    def _pp_sign(secret: bytes, msg: bytes) -> bytes:
        a, prefix = _secret_expand(secret)
        A = _point_compress(_scalarmult(_B, a))
        r = int.from_bytes(
            hashlib.sha512(prefix + msg).digest(), "little") % _l
        R = _point_compress(_scalarmult(_B, r))
        h = int.from_bytes(
            hashlib.sha512(R + A + msg).digest(), "little") % _l
        s = (r + h * a) % _l
        return R + int.to_bytes(s, 32, "little")

    def _pp_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
        if len(public) != 32 or len(sig) != 64:
            return False
        A = _point_decompress(public)
        if A is None:
            return False
        Rs = sig[:32]
        R = _point_decompress(Rs)
        if R is None:
            return False
        s = int.from_bytes(sig[32:], "little")
        if s >= _l:
            return False
        h = int.from_bytes(
            hashlib.sha512(Rs + public + msg).digest(), "little") % _l
        sB = _scalarmult(_B, s)
        hA = _scalarmult(A, h)
        RhA = _edwards_add(R, hA)
        x1, y1, z1, _ = sB
        x2, y2, z2, _ = RhA
        return ((x1 * z2 - x2 * z1) % _p == 0
                and (y1 * z2 - y2 * z1) % _p == 0)


# ---------------------------------------------------------------------- #
# 公共 API（两个后端同签名）
# ---------------------------------------------------------------------- #
def generate_seed() -> bytes:
    """32 字节随机 seed（os.urandom）。"""
    return os.urandom(32)


def public_from_secret(secret: bytes) -> bytes:
    if len(secret) != 32:
        raise ValueError("secret 必须是 32 字节")
    if BACKEND == "cryptography":
        sk = Ed25519PrivateKey.from_private_bytes(secret)
        return sk.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
    return _pp_pub(secret)


def sign(secret: bytes, msg: bytes) -> bytes:
    if len(secret) != 32:
        raise ValueError("secret 必须是 32 字节")
    if BACKEND == "cryptography":
        return Ed25519PrivateKey.from_private_bytes(secret).sign(msg)
    return _pp_sign(secret, msg)


def verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    if BACKEND == "cryptography":
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
            return True
        except Exception:                               # noqa: BLE001
            return False
    return _pp_verify(public, msg, sig)


def _selftest() -> None:
    if public_from_secret(_TEST_SECRET) != _TEST_PUBLIC:
        raise RuntimeError("Ed25519 自检失败：公钥向量不符")
    if sign(_TEST_SECRET, b"") != _TEST_SIG:
        raise RuntimeError("Ed25519 自检失败：签名向量不符")
    if not verify(_TEST_PUBLIC, b"", _TEST_SIG):
        raise RuntimeError("Ed25519 自检失败：验签向量不符")
    if verify(_TEST_PUBLIC, b"x", _TEST_SIG):
        raise RuntimeError("Ed25519 自检失败：负例通过了验签")


_selftest()

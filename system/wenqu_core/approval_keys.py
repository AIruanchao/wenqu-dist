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

R7-AUTH-KEY-PERM-006（Codex 第七轮，2026-10-08）：loader 权限 fail-closed——
- keyring 文件非 0600（或目录型 keyring 目录非 0700、secret/meta 文件非
  0600）时 ``from_path`` 一律 ``KeyringPermissionError`` 拒绝加载（0644 的
  keyring 意味着本机任意用户可读密钥——加载它就是把门焊死在敞开状态）；
- 显式豁免清单：``DEV_FIXTURE_EXEMPT_ROOTS``（本仓 ``system/tests/fixtures``
  目录，按本模块位置锚定——内含公开测试密钥，权限宽不构成泄密面）；
  清单内路径在权限不符时仍可加载（发行包自测在全新 checkout（umask 022
  →0644）上必须可用）；
- ``WENQU_KEYRING_DEV_FIXTURES=1``：显式把上述豁免开到任意 dev 路径
  （本机联调加载宽松权限 keyring 的唯一正门）；``=0`` 则连清单内也严格
  拒绝（strict 模式自证）。生产 keyring 永远落在清单外——无豁免。

R7-AUTH-DUAL-CONSUME-005：``sign_envelope`` 签名体排除 ``cosignatures``
（信封联签数组——联签与主签同体：主签/联签都对「除 signature 与
cosignatures 外的信全体」计算 HMAC；不存在该键时行为与旧版逐字节一致）。
新增 ``ApprovalKeyring.verify_detached``——消费端对联签条目按 key_id 取
secret 验 detached HMAC（未知/revoked key 一律 False，fail-closed）。

R8-KEY-LIFECYCLE-001（Codex 第八轮 P0-2 残余①，2026-10-08）：key 生命周期
按 **envelope.issued_at** 执法——``verify``/``verify_detached`` 在验签前
对信封携带的 ``issued_at`` 执法 key 元数据时间窗（``key_lifecycle_rejection``）：
- ``issued_at`` 晚于 ``rotated_at``/``expiry`` → 拒（**退休后签的批不能
  消费**——直接持 secret 手签的旁路面关闭；合法存量（签发早于轮换）不受
  影响，边界取闭区间：issued_at == rotated_at 属轮换前存量，放行）；
- ``issued_at`` 早于 ``created_at`` → 拒（时间穿越——key 尚不存在时的
  签名必伪）；
- revoked → 无条件拒（既有语义保持，优先级最高）；
- 拒绝同样尽力记入 keyring 事件账本（``KEY_LIFECYCLE_VERIFY_REJECTED``）；
- 信封不带 ``issued_at``（如外部回执 ts 体、最小化测试 dict）→ 无从执法，
  跳过窗口检查（诚实边界：消费端 ``ApprovalBroker`` 路径先过结构校验，
  ``issued_at`` 必在，执法面闭合；keyring 裸用面不强制）；
- 无生命周期元数据的存量 keyring（fixtures）→ 全放行（向后兼容）。

R8-SIGNER-PRINCIPAL-004（Codex 第八轮 P0-2 残余③）：key 元数据新增
``owner``/``actors`` 登记字段（key 签发时登记——``write_key_to_dir``/
``save_key_meta`` 的 meta 直传）——``ApprovalKeyring.key_actors`` 暴露
登记面供消费端执法：envelope.actor 必须 ∈ 签名 key 的 actors（同一 actor
不能冒用两把不属于他的 key 凑联签）；未登记 actors 的存量 key 不受限
（诚实边界：登记面是 opt-in，CLI ``keys create`` 未接线属后续工作项）。

G9-06（第九轮预检 1.4-1：同钥双签非独立语义根）：key 元数据新增
``purposes`` 用途分域登记字段（如 ``["manifest"]``/``["registry"]``）——
``ApprovalKeyring.key_purposes`` 暴露登记面，供 registry 快照/manifest
验签端执法「签名 key 分域、不得混用」；未登记的存量 key 不受用途限制
（opt-in，与 actors 同型；同钥双签拒绝在消费端无条件执法、不依赖登记面）。
R8-AUTH-RETIRED-KEY-005（G9-04 根修，2026-10-09）：退休 key 不可回填——
受控 issuer 签发时生成**单调序号签发 receipt**（``IssueReceiptLedger``，
锚定 keyring 目录内 append-only 审计文件 ``issue-receipts.jsonl``：seq
单调递增 + 逐行 chain_prev 哈希链 + 逐行 receipt_hmac）：
- 消费侧（``ApprovalKeyring.issue_receipt_rejection``）：受管（目录型）
  keyring 的信封消费必须验证 receipt 在链上真实存在、seq/envelope 绑定
  一致、签发时刻在退休窗口内——无 receipt 的信封一律拒绝（fail-closed）；
  持旧 secret 离线手签可回填 ``issued_at``，但无法在 append-only 链上追加
  合法 receipt，退休回填面关闭；
- 轮换/吊销盘点（``save_key_meta``）：meta 落 rotated/revoked 时把链上
  当前最大 seq 记为 ``retired_receipt_seq``（退休后再出现的更大 seq 一律
  非退休前签发）；
- 诚实边界：receipt regime 只对**目录型受管 keyring**（wenquctl keys 正门）
  生效——文件型/内存 keyring（测试夹具、dev 联调）无受控审计根，不执法
  （与 keyring 权限豁免面同构）；审计文件自身的不可篡改性（0600 + 追加
  写 + 哈希链检出篡改）是部署责任，防持有旧 secret 但无文件写权限的
  攻击者（威胁模型正源），不防能改写 keyring 目录的 root 级攻击者。

R9-AUTH-RECEIPT-COLDSTART-001（G9 后续 T1 根修，2026-10-10）：genesis
锚 + 消费端 fail-closed——
- keyring 初始化（``write_key_to_dir``）/首次签发（``append`` 对空账本）
  时写入**不可删除的 genesis 行**（``RECEIPT_GENESIS``：epoch 随机标记 +
  created_at + 锚 key + HMAC），receipt 链从 genesis 起链；
- 消费端判定收紧为「受管（目录型）keyring 存在 → receipt regime **必须**
  激活」：账本文件缺失（genesis 被删）、账本被截断（首行非 genesis）、
  退休 key 缺 ``retired_receipt_seq`` 盘点，一律 fail-closed 拒绝——
  不再存在「regime 未激活」放行分支（旧洞：删账本文件后旧 key 新签+
  回填 issued_at 旁路通过）。

R9-AUTH-RECEIPT-CONCURRENCY-013（G9 后续 T1 根修，2026-10-10）：receipt
分配竞窗关闭——``append`` 全程持 ``fcntl.flock`` 排他文件锁（打开-锁定-
读取-分配-写入同锁临界区），锁内做 seq 唯一性断言 + 全链 prev 链验证
（genesis 在位/seq 严格递增/链衔接/HMAC 一致），单次 ``os.write`` 落行；
``save_key_meta`` 的退休盘点（``retired_receipt_seq``）同样在锁内读取
``max_seq``——并发签发下的盘点不再取到撕裂值。
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

__all__ = [
    "ApprovalKeyring",
    "KeyNotFoundError",
    "KeyStateError",
    "KeyRevokedError",
    "KeyRotatedError",
    "KeyExpiredError",
    "KeyringPermissionError",
    "IssueReceiptLedger",
    "ISSUE_RECEIPTS_FILENAME",
    "RECEIPT_GENESIS_RECORD_TYPE",
    "KEY_STATUS_ACTIVE",
    "KEY_STATUS_ROTATED",
    "KEY_STATUS_REVOKED",
    "KEY_STATUSES",
    "KEYRING_EVENTS_FILENAME",
    "DEV_FIXTURE_EXEMPT_ROOTS",
    "KEYRING_DEV_FIXTURES_ENV",
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

#: 目录型 keyring 的**签发 receipt 审计根**文件名（R8-AUTH-RETIRED-KEY-005：
#: 单调 seq + 哈希链 + 逐行 HMAC——退休回填的不可伪造锚点）
ISSUE_RECEIPTS_FILENAME = "issue-receipts.jsonl"

#: receipt 账本首行 genesis 锚记录类型（R9-AUTH-RECEIPT-COLDSTART-001：
#: keyring 出生即写入、不可删除——账本缺失/截断（无 genesis）一律 fail-closed）
RECEIPT_GENESIS_RECORD_TYPE = "RECEIPT_GENESIS"

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


class KeyringPermissionError(ValueError):
    """keyring/secret 路径权限过宽（非 0600/0700）——loader fail-closed 拒载。

    R7-AUTH-KEY-PERM-006：``ApprovalKeyring.from_path`` 对权限不符的
    keyring 一律抛本异常（``ValueError`` 子类——消费端 ``default_keyring``
    的 except (OSError, ValueError) 会把它收敛为空 keyring，全部验签拒绝，
    同样 fail-closed）。豁免通道见 ``DEV_FIXTURE_EXEMPT_ROOTS`` 与
    ``KEYRING_DEV_FIXTURES_ENV``。
    """


# ====================================================================== #
# R8-AUTH-RETIRED-KEY-005（G9-04）：签发 receipt 审计根
# ——受控 issuer 侧追加、消费侧（broker→keyring）重放校验的单一正源。
# ====================================================================== #

#: receipt 行键集封闭（additionalProperties 语义）
_ISSUE_RECEIPT_FIELDS = frozenset({
    "record_type", "key_id", "seq", "approval_id", "nonce_digest",
    "issued_at", "ts", "chain_prev", "receipt_hmac",
})

#: genesis 锚行键集封闭（R9-AUTH-RECEIPT-COLDSTART-001）
_RECEIPT_GENESIS_FIELDS = frozenset({
    "record_type", "key_id", "epoch", "created_at", "seq", "chain_prev",
    "genesis_hmac",
})

#: 链起点零值（genesis.chain_prev——genesis 之前无行）
_ZERO_PREV = "0" * 64


class IssueReceiptLedger:
    """签发 receipt 账本（append-only jsonl，0600，逐行哈希链+HMAC）。

    R8-AUTH-RETIRED-KEY-005 根修的锚点：受控 issuer 每签发一份审批前追加
    一条 receipt（seq 单调递增、``chain_prev``=前一行 canonical JSON 的
    sha256、``receipt_hmac``=签名 key secret 对本行除 hmac 外全字段的
    HMAC-SHA256）。持旧 secret 的攻击者可以手签任意信封与回填时间，但
    无法在受保护目录内追加合法 receipt——消费侧只认链上真实存在的签发。

    R9-AUTH-RECEIPT-COLDSTART-001（T1 根修）：账本首行是**genesis 锚**
    （``RECEIPT_GENESIS``：epoch 随机标记+created_at+锚 key+HMAC）——
    keyring 初始化（``write_key_to_dir``）/首次签发时写入，receipt 链从
    genesis 起链。首行非 genesis（被截断/伪造/旧版无锚账本）= 账本破损，
    消费与追加双双 fail-closed。

    R9-AUTH-RECEIPT-CONCURRENCY-013（T1 根修）：``append`` 在
    ``fcntl.flock`` 排他锁内完成「读取-验证-seq 分配-写入」整个临界区
    （锁内 seq 唯一性断言 + 全链 prev 链验证），单次 ``os.write`` 落行
    ——并发 issuer 不可能分到重复 seq 或分叉链。

    - ``append``（issuer 侧）：锁内 genesis 保障 + seq=max+1 + 链与 HMAC；
    - ``verify_chain``（消费侧）：重放全链——无 genesis/坏行/键集不闭/
      seq 非严格递增/链断/未知 key/receipt_hmac 不符即断（fail-closed）；
    - ``by_seq``：seq → receipt 行（消费侧按信封 ``issue_receipt.seq``
      查找并做 envelope 等值绑定）。

    纯标准库；与 ``IssuanceAudit``（签发审计账本）职责分离：审计账本记
    「批了什么」（对账面），receipt 链锚定「何时真实签发过」（时间执法面）。
    """

    def __init__(self, path: str, *,
                 secret_of: Optional[Mapping[str, str]] = None) -> None:
        """``secret_of``：key_id → secret（receipt_hmac 重算用；消费侧传
        keyring 视图，issuer 侧传 ``{key_id: secret}`` 单键映射即可）。"""
        if not path or not path.strip():
            raise ValueError("receipts ledger path must be non-empty")
        self.path = path
        self._secret_of = dict(secret_of or {})

    # ------------------------------------------------------------------ #
    @staticmethod
    def _canonical(obj: Any) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)

    @classmethod
    def _line_digest(cls, record: Mapping[str, Any]) -> str:
        return hashlib.sha256(
            cls._canonical(record).encode("utf-8")).hexdigest()

    def _receipt_hmac(self, record: Mapping[str, Any]) -> str:
        secret = self._secret_of.get(str(record.get("key_id")))
        if secret is None:
            raise KeyNotFoundError(
                f"receipt key_id {record.get('key_id')!r} 不在 secret 视图")
        body = {k: v for k, v in dict(record).items() if k != "receipt_hmac"}
        return hmac.new(secret.encode("utf-8"),
                        self._canonical(body).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _genesis_hmac(self, record: Mapping[str, Any]) -> str:
        secret = self._secret_of.get(str(record.get("key_id")))
        if secret is None:
            raise KeyNotFoundError(
                f"genesis 锚 key_id {record.get('key_id')!r} 不在 secret 视图")
        body = {k: v for k, v in dict(record).items()
                if k != "genesis_hmac"}
        return hmac.new(secret.encode("utf-8"),
                        self._canonical(body).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _make_genesis(self, anchor_key_id: str) -> Dict[str, Any]:
        """构造 genesis 锚行（epoch 随机标记+创建时间+锚 key+HMAC）。"""
        record: Dict[str, Any] = {
            "record_type": RECEIPT_GENESIS_RECORD_TYPE,
            "key_id": anchor_key_id,
            "epoch": secrets.token_hex(16),
            "created_at": _utc_now_iso(),
            "seq": 0,
            "chain_prev": _ZERO_PREV,
        }
        record["genesis_hmac"] = self._genesis_hmac(record)
        return record

    # ------------------------------------------------------------------ #
    # 文件读取（锁内 fd 直读与路径读取共用同一解析器）
    @staticmethod
    def _parse_records_text(text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"receipt line {lineno} is not JSON: {exc}") from None
            if not isinstance(rec, dict):
                raise ValueError(
                    f"receipt line {lineno} is not an object")
            out.append(rec)
        return out

    @staticmethod
    def _read_fd_records(fd: int) -> List[Dict[str, Any]]:
        """从已打开 fd 读全量并解析（调用方负责持锁；读前 seek 0）。"""
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: List[bytes] = []
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            chunks.append(block)
        return IssueReceiptLedger._parse_records_text(
            b"".join(chunks).decode("utf-8"))

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        written = os.write(fd, data)
        if written != len(data):
            raise OSError(
                f"receipt ledger short write: {written}/{len(data)} bytes")

    # ------------------------------------------------------------------ #
    def max_seq(self) -> int:
        """链上当前最大 seq（空账本/文件不存在=0）。坏行抛 ValueError。"""
        return max((int(r.get("seq", 0)) for r in self.records()),
                   default=0)

    def locked_max_seq(self) -> int:
        """在文件锁内读取当前最大 seq（退休盘点用——并发签发下不取撕裂值）。

        与 ``append`` 的「读-验-分配-写」临界区互斥：读到的 max_seq 要么
        已含并发在途 append 的结果、要么严格早于它（后者属轮换后签发，
        消费侧 receipt 门本就拒绝）。
        """
        if not os.path.exists(self.path):
            return 0
        fd = os.open(self.path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            records = self._read_fd_records(fd)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return max((int(r.get("seq", 0)) for r in records), default=0)

    def records(self) -> List[Dict[str, Any]]:
        """读取全部账本行（genesis+receipts；不做链校验；坏 JSON/非对象行
        抛 ValueError）。"""
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            return self._parse_records_text(fh.read())

    # ------------------------------------------------------------------ #
    def _scan_chain(self, records: List[Dict[str, Any]]) -> None:
        """全链重放校验（结构 + 密码学）；任一失败抛 ValueError（fail-closed）。

        校验项：首行必须是 genesis（键集封闭/seq=0/chain_prev 零值/
        genesis_hmac 一致）；其后逐行 ISSUE_RECEIPT（键集封闭/seq 严格
        递增/chain_prev 衔接/receipt_hmac 与 secret 视图重算一致）。
        """
        if not records:
            raise ValueError(
                "账本为空——genesis 锚缺失（文件缺失/被清空/被截断，"
                "fail-closed，R9-AUTH-RECEIPT-COLDSTART-001）")
        first = records[0]
        stray = sorted(set(first) - _RECEIPT_GENESIS_FIELDS)
        if stray or "genesis_hmac" not in first:
            raise ValueError(
                f"record 1: genesis 字段不闭: "
                f"{stray or 'missing genesis_hmac'}")
        if first.get("record_type") != RECEIPT_GENESIS_RECORD_TYPE:
            raise ValueError(
                "record 1: genesis 锚缺失（首行非 RECEIPT_GENESIS——账本"
                "被截断/伪造/旧版无锚，fail-closed，"
                "R9-AUTH-RECEIPT-COLDSTART-001）")
        if first.get("seq") != 0 or first.get("chain_prev") != _ZERO_PREV:
            raise ValueError("record 1: genesis seq/chain_prev 畸形")
        try:
            expected_genesis_hmac = self._genesis_hmac(first)
        except KeyNotFoundError as exc:
            raise ValueError(f"record 1: {exc}") from None
        if not hmac.compare_digest(str(first["genesis_hmac"]),
                                   expected_genesis_hmac):
            raise ValueError("record 1: genesis_hmac mismatch")
        expected_prev = self._line_digest(first)
        last_seq = 0
        for idx, rec in enumerate(records[1:], 2):
            stray = sorted(set(rec) - _ISSUE_RECEIPT_FIELDS)
            if stray or "receipt_hmac" not in rec:
                raise ValueError(
                    f"record {idx}: fields not closed: "
                    f"{stray or 'missing receipt_hmac'}")
            if rec.get("record_type") != "ISSUE_RECEIPT":
                raise ValueError(f"record {idx}: bad record_type")
            seq = rec.get("seq")
            if not (isinstance(seq, int) and not isinstance(seq, bool)
                    and seq == last_seq + 1):
                raise ValueError(
                    f"record {idx}: seq {seq!r} 不是严格递增"
                    f"（期望 {last_seq + 1}）")
            last_seq = seq
            if rec.get("chain_prev") != expected_prev:
                raise ValueError(f"record {idx}: chain_prev mismatch")
            try:
                expected_hmac = self._receipt_hmac(rec)
            except KeyNotFoundError as exc:
                raise ValueError(f"record {idx}: {exc}") from None
            if not hmac.compare_digest(str(rec["receipt_hmac"]),
                                       expected_hmac):
                raise ValueError(f"record {idx}: receipt_hmac mismatch")
            expected_prev = self._line_digest(rec)

    # ------------------------------------------------------------------ #
    def ensure_genesis(self, *, anchor_key_id: str) -> Dict[str, Any]:
        """保障账本 genesis 锚在位（keyring 初始化正门；幂等、持锁）。

        - 账本缺失/为空 → 锚定 ``anchor_key_id`` 写入 genesis（0600）；
        - genesis 已在位 → 全链校验通过后原样返回（幂等）；
        - 账本有内容但无 genesis（截断/伪造/旧版）→ ValueError（锚不可
          删——fail-closed，不静默补锚改写历史链）。
        """
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, _SECRET_FILE_MODE)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            records = self._read_fd_records(fd)
            if not records:
                genesis = self._make_genesis(anchor_key_id)
                data = (self._canonical(genesis) + "\n").encode("utf-8")
                os.lseek(fd, 0, os.SEEK_END)
                self._write_all(fd, data)
            else:
                self._scan_chain(records)  # 无 genesis/坏链 → ValueError
                genesis = records[0]
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        os.chmod(self.path, _SECRET_FILE_MODE)
        return genesis

    # ------------------------------------------------------------------ #
    def append(self, *, key_id: str, approval_id: str, nonce_digest: str,
               issued_at: str) -> Dict[str, Any]:
        """追加一条签发 receipt（flock 临界区：genesis 保障→全链验证→
        seq=max+1 唯一分配→单次 write；0600）。

        R9-AUTH-RECEIPT-CONCURRENCY-013：读取-验证-分配-写入全程持
        ``fcntl.flock`` 排他锁——并发 issuer 串行进入临界区，seq 唯一且
        链无分叉；锁内全链 prev 验证保证绝不向破损/截断（无 genesis）的
        账本续签（fail-closed）。
        """
        record: Dict[str, Any] = {
            "record_type": "ISSUE_RECEIPT",
            "key_id": key_id,
            "approval_id": approval_id,
            "nonce_digest": nonce_digest,
            "issued_at": issued_at,
            "ts": _utc_now_iso(),
        }
        prefix = b""
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, _SECRET_FILE_MODE)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            records = self._read_fd_records(fd)
            if not records:
                # 首次签发：先落 genesis 锚（锚定本次签名 key——其 secret
                # 必在视图内，receipt_hmac 同样依赖它）
                genesis = self._make_genesis(key_id)
                prefix = (self._canonical(genesis) + "\n").encode("utf-8")
                chain_prev = self._line_digest(genesis)
                last_seq = 0
            else:
                self._scan_chain(records)  # 无 genesis/断链 → ValueError
                chain_prev = self._line_digest(records[-1])
                last_seq = int(records[-1]["seq"])
            seq = last_seq + 1
            # seq 唯一性断言（scan 已保证严格递增；显式断言防回归——
            # 若触发说明锁或扫描被破坏，宁拒不分叉）
            existing_seqs = {r.get("seq") for r in records}
            if seq in existing_seqs:  # pragma: no cover —— 防御性断言
                raise ValueError(
                    f"seq 分配唯一性断言失败：seq={seq} 已在链上"
                    f"（R9-AUTH-RECEIPT-CONCURRENCY-013 fail-closed）")
            record["seq"] = seq
            record["chain_prev"] = chain_prev
            record["receipt_hmac"] = self._receipt_hmac(record)
            data = prefix + (self._canonical(record) + "\n").encode("utf-8")
            os.lseek(fd, 0, os.SEEK_END)
            self._write_all(fd, data)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        os.chmod(self.path, _SECRET_FILE_MODE)
        return record

    # ------------------------------------------------------------------ #
    def verify_chain(self) -> Dict[str, Any]:
        """重放校验全链；返回 {ok, length, break_at, reason}。

        校验项（任一失败即断）：首行 genesis 锚（键集封闭/seq=0/零值
        chain_prev/genesis_hmac 一致——R9-AUTH-RECEIPT-COLDSTART-001）、
        其后逐行 ISSUE_RECEIPT 键集封闭、seq 严格递增、chain_prev 逐行
        衔接、receipt_hmac 与 secret 视图重算一致。空账本/文件缺失=锚
        缺失，fail-closed 不 ok。
        """
        try:
            records = self.records()
        except ValueError as exc:
            return {"ok": False, "length": None, "break_at": None,
                    "reason": f"unreadable: {exc}"}
        try:
            self._scan_chain(records)
        except ValueError as exc:
            return {"ok": False, "length": len(records), "break_at": None,
                    "reason": str(exc)}
        return {"ok": True, "length": len(records), "break_at": None,
                "reason": None}

    def by_seq(self, seq: int) -> Optional[Dict[str, Any]]:
        """按 seq 查 receipt 行（不校验链——调用方须先 ``verify_chain``）。"""
        for rec in self.records():
            if rec.get("seq") == seq:
                return rec
        return None


#: 显式豁免清单：本仓测试夹具目录（内含公开测试密钥，权限宽不构成泄密面；
#  全新 checkout 的 fixtures 文件按 umask 落 0644——发行包自测必须可用）。
DEV_FIXTURE_EXEMPT_ROOTS: Tuple[str, ...] = (
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "tests", "fixtures"),
)

#: 豁免显式开关：``=1`` 把豁免开到任意 dev 路径（联调正门）；
#: ``=0`` 连清单内也严格拒绝（strict 自证）；未设置=仅清单内豁免。
KEYRING_DEV_FIXTURES_ENV = "WENQU_KEYRING_DEV_FIXTURES"


def _dev_fixtures_mode() -> str:
    import os as _os
    return _os.environ.get(KEYRING_DEV_FIXTURES_ENV, "").strip()


def _path_in_exemption(path: str) -> bool:
    """路径（realpath 归一）是否落在显式豁免清单内。"""
    real = os.path.realpath(path)
    return any(real == os.path.realpath(root)
               or real.startswith(os.path.realpath(root) + os.sep)
               for root in DEV_FIXTURE_EXEMPT_ROOTS)


def _permission_violations(path: str) -> List[str]:
    """收集 keyring 路径的权限违规项（文件型查自身；目录型查目录+成员）。"""
    import stat as _stat
    violations: List[str] = []

    def _mode(p: str) -> int:
        return _stat.S_IMODE(os.stat(p).st_mode)

    if os.path.isdir(path):
        if _mode(path) != _KEYRING_DIR_MODE:
            violations.append(
                f"{path}: mode {oct(_mode(path))} != 0700（keyring 目录须 "
                "owner-only）")
        for name in sorted(os.listdir(path)):
            member = os.path.join(path, name)
            if not os.path.isfile(member):
                continue
            if name.endswith(".secret") or name.endswith(".meta.json"):
                if _mode(member) != _SECRET_FILE_MODE:
                    violations.append(
                        f"{member}: mode {oct(_mode(member))} != 0600")
            elif name in (KEYRING_EVENTS_FILENAME,
                          ISSUE_RECEIPTS_FILENAME):
                if _mode(member) != _SECRET_FILE_MODE:
                    violations.append(
                        f"{member}: mode {oct(_mode(member))} != 0600")
        return violations
    if _mode(path) != _SECRET_FILE_MODE:
        violations.append(
            f"{path}: mode {oct(_mode(path))} != 0600（keyring 文件须 "
            "owner-only）")
    return violations


def _enforce_keyring_permissions(path: str) -> None:
    """R7-AUTH-KEY-PERM-006：权限不符即拒载（豁免清单/env 通道除外）。

    - 严格模式（``WENQU_KEYRING_DEV_FIXTURES=0``）：无任何豁免；
    - 缺省：仅 ``DEV_FIXTURE_EXEMPT_ROOTS``（本仓 tests/fixtures）豁免；
    - 显式豁免（``=1``）：任意路径豁免（dev 联调正门——生产禁止设置）。
    """
    violations = _permission_violations(path)
    if not violations:
        return
    mode = _dev_fixtures_mode()
    if mode == "1":
        return  # 显式开豁免（dev fixtures 模式）
    if mode != "0" and _path_in_exemption(path):
        return  # 清单内路径豁免（公开测试密钥；全新 checkout 0644 亦可自测）
    raise KeyringPermissionError(
        "keyring 权限过宽，fail-closed 拒绝加载（R7-AUTH-KEY-PERM-006）: "
        + "; ".join(violations)
        + "——收敛为 0600（目录 0700）后重试；测试夹具路径走 "
        "DEV_FIXTURE_EXEMPT_ROOTS 豁免，或显式注入 "
        f"{KEYRING_DEV_FIXTURES_ENV}=1（仅限 dev）")


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
    """对 envelope 计算 HMAC-SHA256 签名（64 hex）。

    签名体 = 信封除 ``signature`` 与 ``cosignatures`` 外的全字段
    （R7-AUTH-DUAL-CONSUME-005：主签与联签对同一「信封体」独立计算 HMAC；
    ``cosignatures`` 键不存在时签名体与旧版逐字节一致——向后兼容）。
    """
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty string")
    body = {k: v for k, v in dict(envelope).items()
            if k not in ("signature", "cosignatures")}
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
                 event_log_path: Optional[str] = None,
                 receipts_path: Optional[str] = None) -> None:
        self._keys: Dict[str, str] = {}
        self._meta: Dict[str, Dict[str, Any]] = {}
        # 目录型 keyring 的生命周期/吊销拒绝事件账本（append-only jsonl）
        self._event_log_path = event_log_path
        # 目录型 keyring 的签发 receipt 审计根（R8-AUTH-RETIRED-KEY-005）：
        # 文件型/内存 keyring 无受控审计根（None——receipt regime 不适用）
        self._receipts_path = receipts_path
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
        """校验并规范化单 key 元数据（未知字段拒绝，防拼写漂移）。

        R8-SIGNER-PRINCIPAL-004：新增 ``owner``（非空 str）/``actors``
        （非空、唯一、非空 str 列表；owner 若同时给出必须 ∈ actors）——
        签发时登记的 principal 面，消费端据以执法 envelope.actor 归属。
        """
        if not isinstance(meta, Mapping):
            raise ValueError(f"key meta for {key_id!r} must be an object")
        allowed = {"status", "created_at", "rotated_at", "rotated_to",
                   "revoked_at", "expiry", "description", "owner", "actors",
                   "purposes", "retired_receipt_seq"}
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
        # R8-SIGNER-PRINCIPAL-004：owner/actors 登记面（签发时登记）
        if "owner" in meta:
            owner = meta["owner"]
            if not (isinstance(owner, str) and owner.strip()):
                raise ValueError(
                    f"key meta owner for {key_id!r} must be a non-empty "
                    "string（principal 登记面不得为空）")
            normalized["owner"] = owner
        if "actors" in meta:
            actors = meta["actors"]
            if (not isinstance(actors, (list, tuple)) or not actors
                    or not all(isinstance(a, str) and a.strip()
                               for a in actors)):
                raise ValueError(
                    f"key meta actors for {key_id!r} must be a non-empty "
                    "list of non-empty strings（principal 登记面）")
            if len(set(actors)) != len(list(actors)):
                raise ValueError(
                    f"key meta actors for {key_id!r} must be unique")
            normalized["actors"] = list(actors)
        if "owner" in normalized and "actors" in normalized \
                and normalized["owner"] not in normalized["actors"]:
            raise ValueError(
                f"key meta owner for {key_id!r} ({normalized['owner']!r}) "
                "must appear in actors（登记面自洽）")
        # G9-06（R8-GATE 预检 1.4-1：同钥双签非独立语义根）：key 用途分域
        # 登记面——签发时登记该 key 可用于哪些用途域（如 manifest/registry），
        # 消费端据以执法「registry 快照 key 与 manifest key 不得同钥/混用」。
        # 未登记 purposes 的存量 key 不受限（opt-in——与 actors 登记面同型）。
        if "purposes" in meta:
            purposes = meta["purposes"]
            purpose_re = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
            if (not isinstance(purposes, (list, tuple)) or not purposes
                    or not all(isinstance(p, str) and purpose_re.fullmatch(p)
                               for p in purposes)):
                raise ValueError(
                    f"key meta purposes for {key_id!r} must be a non-empty "
                    "list of purpose tokens（^[a-z][a-z0-9_-]{0,31}$，"
                    "如 [\"manifest\"]/[\"registry\"]——用途分域登记面）")
            if len(set(purposes)) != len(list(purposes)):
                raise ValueError(
                    f"key meta purposes for {key_id!r} must be unique")
            normalized["purposes"] = list(purposes)
        # R8-AUTH-RETIRED-KEY-005：退休 receipt 盘点（轮换/吊销时刻链上
        # 最大 seq——退休后更大 seq 的信封一律非退休前签发）
        if "retired_receipt_seq" in meta:
            rrs = meta["retired_receipt_seq"]
            if not (isinstance(rrs, int) and not isinstance(rrs, bool)
                    and rrs >= 1):
                raise ValueError(
                    f"key meta retired_receipt_seq for {key_id!r} must be "
                    f"integer >= 1, got {rrs!r}")
            normalized["retired_receipt_seq"] = rrs
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

        R7-AUTH-KEY-PERM-006：权限 fail-closed——文件型须 0600；目录型须
        目录 0700 且 secret/meta/事件账本文件全 0600；不符即
        ``KeyringPermissionError`` 拒载（豁免通道见模块 docstring：
        ``DEV_FIXTURE_EXEMPT_ROOTS`` 清单 + ``WENQU_KEYRING_DEV_FIXTURES``）。
        """
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"keyring path not found: {path!r}")
        _enforce_keyring_permissions(path)
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
                           path, KEYRING_EVENTS_FILENAME),
                       receipts_path=os.path.join(
                           path, ISSUE_RECEIPTS_FILENAME))
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

    # ------------------------------------------------------------------ #
    # R8-KEY-LIFECYCLE-001：按 envelope.issued_at 执法 key 生命周期时间窗
    # R8-SIGNER-PRINCIPAL-004：principal 登记面访问器
    # ------------------------------------------------------------------ #
    def key_lifecycle_rejection(self, key_id: str,
                                issued_at: Any) -> Optional[str]:
        """信封 ``issued_at`` 对 key 生命周期时间窗的执法判定。

        返回拒绝原因（str）或 ``None``（在窗内/无从执法）。规则：

        - ``issued_at`` 为 ``None``（信封不带时间戳——外部回执/最小测试
          dict）→ ``None``（无从执法，跳过；消费端 Broker 路径结构校验
          已强制 ``issued_at`` 在位，执法面在消费链闭合）；
        - ``issued_at`` 畸形/不可解析 → 拒绝原因（fail-closed）；
        - ``issued_at`` 早于 ``created_at``（登记在位时）→ 拒（时间穿越）；
        - ``issued_at`` 晚于 ``rotated_at``（登记在位时）→ 拒（退休后
          签的批不能消费；边界闭区间：== 属轮换前存量，放行）；
        - ``issued_at`` 晚于 ``expiry``（登记在位时）→ 拒（过期后签发）；
        - revoked 的无条件拒在 ``verify``/``verify_detached`` 前置分支，
          不在本方法（本方法只管时间窗）。
        """
        if issued_at is None:
            return None
        if not isinstance(issued_at, str) or not issued_at.strip():
            return (f"envelope issued_at 缺失/畸形（{issued_at!r}）——"
                    "无法执法 key 生命周期时间窗（fail-closed）")
        try:
            ts = _parse_iso_or_none(issued_at, "issued_at")
        except ValueError:
            return (f"envelope issued_at 不是合法 ISO8601: {issued_at!r}")
        if ts is None:
            return None
        meta = self._meta.get(key_id, {})
        checks = (
            ("created_at", "早于", lambda t, b: t < b),
            ("rotated_at", "晚于", lambda t, b: t > b),
            ("expiry", "晚于", lambda t, b: t > b),
        )
        for field, verb, violated in checks:
            raw = meta.get(field)
            if raw is None:
                continue
            try:
                bound = _parse_iso_or_none(raw, field)
            except ValueError:
                return (f"key meta {field} 不可解析（{raw!r}）——"
                        "生命周期执法 fail-closed")
            if bound is not None and violated(ts, bound):
                return (f"envelope issued_at {issued_at} {verb} key "
                        f"{field} {raw}（退休后签的批不能消费/时间穿越"
                        "一律拒——R8-KEY-LIFECYCLE-001）")
        return None

    def key_actors(self, key_id: str) -> Optional[Tuple[str, ...]]:
        """key 的 principal 登记面（meta.actors）；未登记返回 ``None``。

        R8-SIGNER-PRINCIPAL-004：消费端据以执法 envelope.actor ∈ actors；
        未登记 actors 的存量 key 不受限（登记面 opt-in——诚实边界）。
        """
        if key_id not in self._keys:
            raise KeyNotFoundError(
                f"key_id {key_id!r} not registered in keyring "
                f"(known: {sorted(self._keys)})") from None
        actors = self._meta.get(key_id, {}).get("actors")
        if actors is None:
            return None
        return tuple(actors)

    def key_purposes(self, key_id: str) -> Optional[Tuple[str, ...]]:
        """key 的用途分域登记面（meta.purposes）；未登记返回 ``None``。

        G9-06（同钥双签非独立语义根）：登记面供消费端执法
        「registry 快照签名 key 与 manifest 签名 key 分域」——例如
        manifest 域 key 不得签 registry 快照、registry 域 key 不得签
        manifest。未登记 purposes 的存量 key 不受用途限制（opt-in——
        与 actors 登记面同型；同钥双签拒绝不依赖登记面，无条件执法）。
        """
        if key_id not in self._keys:
            raise KeyNotFoundError(
                f"key_id {key_id!r} not registered in keyring "
                f"(known: {sorted(self._keys)})") from None
        purposes = self._meta.get(key_id, {}).get("purposes")
        if purposes is None:
            return None
        return tuple(purposes)
    # ------------------------------------------------------------------ #
    # R8-AUTH-RETIRED-KEY-005：签发 receipt regime（受管目录型 keyring 专属）
    # ------------------------------------------------------------------ #
    def receipts_ledger_path(self) -> Optional[str]:
        """签发 receipt 审计根路径（目录型受管 keyring 才有；其他 None）。"""
        return self._receipts_path

    def receipts_ledger(self) -> Optional[IssueReceiptLedger]:
        """以本 keyring 的 secret 视图构造 receipt 账本（消费/签发共用）。"""
        if self._receipts_path is None:
            return None
        return IssueReceiptLedger(self._receipts_path,
                                  secret_of=dict(self._keys))

    def issue_receipt_rejection(self,
                                approval: Mapping[str, Any]) -> Optional[str]:
        """信封的签发 receipt 执法判定（返回拒绝原因或 None=通过/不适用）。

        R8-AUTH-RETIRED-KEY-005：受管（目录型）keyring 的信封消费要求：

        1. 信封必须携带 ``issue_receipt={"seq": int}``（无 receipt 一律拒
           ——fail-closed，回填 ``issued_at`` 手签的信封无法伪造链上锚点）；
        2. receipt 链完整（genesis 锚在位 + 哈希链 + 逐行 HMAC + seq 严格
           递增重放通过）；
        3. 链上该 seq 的 receipt 与信封等值绑定（key_id/approval_id/
           nonce 摘要/issued_at 四项全等——防挪用他人 receipt）；
        4. key 元数据带 ``retired_receipt_seq`` 时 receipt.seq 不得超过
           （退休盘点后的更大 seq 一律非退休前签发）。

        R9-AUTH-RECEIPT-COLDSTART-001（T1 根修）：**受管（目录型）keyring
        存在 → receipt regime 必须激活**——账本文件缺失（genesis 锚被删）、
        账本被截断（连 genesis 都没有）、退休 key 缺 ``retired_receipt_seq``
        盘点，一律 fail-closed 拒绝；不再存在「regime 未激活」放行分支
        （旧洞：删账本后旧 key 新签+回填 issued_at 旁路通过）。
        文件型/内存 keyring（无受控审计根）仍返回 None（不受管，不适用）。
        """
        if self._receipts_path is None:
            return None
        if not os.path.exists(self._receipts_path):
            return ("受管 keyring 的签发 receipt 审计根缺失"
                    f"（{ISSUE_RECEIPTS_FILENAME} 不存在——genesis 锚被删/"
                    "账本未初始化）：受管 keyring 存在即 receipt regime 必须"
                    "激活，一律 fail-closed 拒绝"
                    "（R9-AUTH-RECEIPT-COLDSTART-001）")
        ledger = self.receipts_ledger()
        assert ledger is not None  # _receipts_path 已判空
        receipt = approval.get("issue_receipt") if isinstance(
            approval, Mapping) else None
        key_id = approval.get("key_id") if isinstance(
            approval, Mapping) else None
        approval_id = approval.get("approval_id") if isinstance(
            approval, Mapping) else None
        if not (isinstance(receipt, Mapping)
                and isinstance(receipt.get("seq"), int)
                and not isinstance(receipt.get("seq"), bool)
                and receipt.get("seq") >= 1
                and set(receipt) == {"seq"}):
            return (f"信封缺少合法 issue_receipt（{{seq:int}}）——受管 "
                    "keyring 的审批必须由受控 issuer 签发并携带单调序号 "
                    "receipt（R8-AUTH-RETIRED-KEY-005 fail-closed）")
        chain = ledger.verify_chain()
        if not chain["ok"]:
            return (f"签发 receipt 审计链校验失败（{chain['reason']}）——"
                    "无法证明任何签发时刻（fail-closed）")
        line = ledger.by_seq(receipt["seq"])
        if line is None:
            return (f"issue_receipt.seq={receipt['seq']} 不在受控审计链上"
                    "（离线伪造/挪用不存在的签发——fail-closed）")
        import hashlib as _hl
        expected = {
            "key_id": key_id,
            "approval_id": approval_id,
            "nonce_digest": (_hl.sha256(str(
                approval.get("nonce", "")).encode("utf-8")).hexdigest()
                if isinstance(approval, Mapping) else None),
            "issued_at": approval.get("issued_at"),
        }
        for field, want in expected.items():
            if line.get(field) != want:
                return (f"receipt 与信封绑定不一致（{field}: receipt="
                        f"{line.get(field)!r} != envelope={want!r}）——"
                        "receipt 不得跨信封挪用（fail-closed）")
        meta = self._meta.get(str(key_id), {})
        retired = meta.get("retired_receipt_seq")
        if isinstance(retired, int) and not isinstance(retired, bool) \
                and receipt["seq"] > retired:
            return (f"receipt.seq={receipt['seq']} 晚于退休盘点 "
                    f"retired_receipt_seq={retired}——退休后签的批不能消费"
                    "（R8-AUTH-RETIRED-KEY-005）")
        # R9-AUTH-RECEIPT-COLDSTART-001：退休盘点缺失 fail-closed——regime
        # 激活（受管 keyring+genesis 在位）下轮换/吊销的 key 必须带
        # retired_receipt_seq；缺失=元数据被篡改或盘点时账本已被抹，拒。
        if meta.get("status") in (KEY_STATUS_ROTATED, KEY_STATUS_REVOKED) \
                and not (isinstance(retired, int)
                         and not isinstance(retired, bool)):
            return (f"退休 key {key_id}（status={meta.get('status')!r}）缺 "
                    "retired_receipt_seq 退休盘点——regime 激活下的轮换/吊销"
                    "必须落盘点（缺失=元数据被篡改或账本被抹，fail-closed，"
                    "R9-AUTH-RECEIPT-COLDSTART-001）")
        return None

    def _record_principal_rejection(self, key_id: str,
                                    approval: Mapping[str, Any],
                                    actor: str) -> None:
        """把「signer principal 绑定被拒」记入事件账本（best-effort，不放行）。"""
        if not self._event_log_path:
            return
        record = {
            "record_type": "PRINCIPAL_VERIFY_REJECTED",
            "ts": _utc_now_iso(),
            "key_id": key_id,
            "actor": actor,
            "approval_id": approval.get("approval_id"),
            "approval_type": approval.get("approval_type"),
            "run_id": approval.get("run_id"),
            "note": "envelope actor not in key actors registry "
                    "(fail-closed, R8-SIGNER-PRINCIPAL-004)",
        }
        try:
            append_keyring_event(self._event_log_path, record)
        except OSError:
            # 记账失败不改变判定：验签结果仍是「拒」。
            return

    def _record_lifecycle_rejection(self, key_id: str,
                                    approval: Mapping[str, Any],
                                    reason: str) -> None:
        """把「生命周期时间窗执法被拒」记入事件账本（best-effort，不放行）。"""
        if not self._event_log_path:
            return
        record = {
            "record_type": "KEY_LIFECYCLE_VERIFY_REJECTED",
            "ts": _utc_now_iso(),
            "key_id": key_id,
            "approval_id": approval.get("approval_id"),
            "approval_type": approval.get("approval_type"),
            "run_id": approval.get("run_id"),
            "reason": reason,
            "note": "issued_at outside key lifecycle window (fail-closed)",
        }
        try:
            append_keyring_event(self._event_log_path, record)
        except OSError:
            # 记账失败不改变判定：验签结果仍是「拒」。
            return

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

        R8-KEY-LIFECYCLE-001：rotated/expired 的「存量」语义收窄为
        **签发时间窗内**的存量——envelope.issued_at 晚于 rotated_at/
        expiry 即拒（退休后手签的批不能消费）；早于 created_at 即拒
        （时间穿越）。信封不带 issued_at 时无从执法（保持旧行为，
        消费端 Broker 路径结构校验强制其在位）。

        R8-SIGNER-PRINCIPAL-004：key 登记 actors 且信封携带 actor 时，
        actor ∉ 登记面即拒（兜底层——直用 keyring.verify 的消费面自动
        继承；Broker 消费链另有带明确消息的先行显式门）。
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
        reason = self.key_lifecycle_rejection(key_id,
                                               approval.get("issued_at"))
        if reason is not None:
            self._record_lifecycle_rejection(key_id, approval, reason)
            return False
        # 先密码学后 principal（G9-04 排序裁定）：HMAC 失败优先报「验签
        # 失败」——篡改 actor 的信封在 HMAC 层就死（消息不被 principal
        # 拒绝掩蔽）；HMAC 有效而 actor 冒用在 membership 层拒。
        if not verify_envelope(self._keys[key_id], approval, signature):
            return False
        # R8-SIGNER-PRINCIPAL-004：key 登记 actors 且信封携带 actor 时，
        # membership 在验签通过后执法（bugscan/deploy 等直用 keyring.verify
        # 的消费面自动继承；信封不携带 actor 的体——manifest/registry/
        # 外部回执——无从执法，跳过）。消费端 Broker 另有带明确消息的
        # 显式门（消息语义不因本兜底而劣化）。
        actors = self._meta.get(key_id, {}).get("actors")
        envelope_actor = approval.get("actor")
        if actors and isinstance(envelope_actor, str) \
                and envelope_actor not in actors:
            self._record_principal_rejection(key_id, approval,
                                              envelope_actor)
            return False
        return True

    def verify_signature_only(self, approval: Mapping[str, Any]) -> bool:
        """纯密码学验签（HMAC 重算比对；不含 revoked/生命周期/principal 执法）。

        G9-04 失败归因用：消费端 ``verify`` 失败时区分「密码学失败」与
        「principal membership 拒绝」——两者都返回 False，消息归因由调用
        方以本方法复核（crypto 过而 verify 败=membership 因；crypto 败=
        伪签名/篡改，无论 actor 是否同时冒用一律报验签失败）。
        """
        if not isinstance(approval, Mapping):
            return False
        key_id = approval.get("key_id")
        if not isinstance(key_id, str) or key_id not in self._keys:
            return False
        return verify_envelope(self._keys[key_id], approval,
                               approval.get("signature"))

    def verify_detached(self, key_id: str, body: Mapping[str, Any],
                        signature: str) -> bool:
        """验 detached HMAC：按 key_id 取 secret 对 body 重算比对。

        R7-AUTH-DUAL-CONSUME-005 消费端联签验证用——联签条目
        ``{key_id, actor, signature}`` 的 signature 是该 key 对「信封体」
        （envelope 去掉 signature/cosignatures）的独立 HMAC。语义与
        ``verify`` 同源：未知 key / revoked key 一律 False（fail-closed，
        revoked 拒绝同样尽力记入事件账本）；rotated/expired 的存量语义
        同样收窄为 issued_at 时间窗内（R8-KEY-LIFECYCLE-001——联签与主签
        同一执法面：退休后手签的联签一样不能消费）。
        """
        if not isinstance(key_id, str) or key_id not in self._keys:
            return False
        if self._key_status(key_id) == KEY_STATUS_REVOKED:
            self._record_revoked_rejection(key_id, {
                "approval_id": None, "approval_type": "cosignature",
                "run_id": None,
                "note": "revoked cosign key rejected (fail-closed)"})
            return False
        reason = self.key_lifecycle_rejection(
            key_id, body.get("issued_at") if isinstance(body, Mapping)
            else None)
        if reason is not None:
            self._record_lifecycle_rejection(key_id, dict(body), reason)
            return False
        return verify_envelope(self._keys[key_id], body, signature)

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

    R9-AUTH-RECEIPT-COLDSTART-001：受管 keyring 出生即写入 receipt 账本
    genesis 锚（首个 key 创建时；后续幂等）——受管 keyring 存在即 receipt
    regime 激活，不存在「从未签发=不执法」窗口。
    """
    ApprovalKeyring._validate_key_id(key_id)  # noqa: SLF001 —— 复用命名约束
    ensure_keyring_dir(keyring_dir)
    _write_private_file(os.path.join(keyring_dir, f"{key_id}.secret"),
                        secret + "\n")
    # genesis 锚（幂等）：secret 视图取 keyring 目录内全部既有 key 的
    # secret（受管正门读自家目录）——保证锚定首个 key 的 genesis_hmac
    # 在全链校验中可验，后续加 key 不会因视图缺锚 key 而误拒。
    view: Dict[str, str] = {}
    for name in sorted(os.listdir(keyring_dir)):
        if name.endswith(".secret"):
            with open(os.path.join(keyring_dir, name), "r",
                      encoding="utf-8") as fh:
                sibling = fh.read().strip()
            if sibling:
                view[name[: -len(".secret")]] = sibling
    view[key_id] = secret
    IssueReceiptLedger(
        os.path.join(keyring_dir, ISSUE_RECEIPTS_FILENAME),
        secret_of=view).ensure_genesis(anchor_key_id=key_id)
    normalized = ApprovalKeyring._normalize_meta(  # noqa: SLF001
        key_id, dict(meta or {}))
    normalized.setdefault("created_at", _utc_now_iso())
    normalized = ApprovalKeyring._normalize_meta(key_id, normalized)
    save_key_meta(keyring_dir, key_id, normalized)
    return normalized


def save_key_meta(keyring_dir: str, key_id: str,
                  meta: Mapping[str, Any]) -> None:
    """（覆盖）写单 key 元数据边车 ``<key_id>.meta.json``（0600）。

    R8-AUTH-RETIRED-KEY-005：写入 rotated/revoked 终态且 keyring 目录内
    存在签发 receipt 审计根时，自动盘点 ``retired_receipt_seq``（=链上
    当前最大 seq；已盘点不覆盖——首次退休时刻为准）。R9-CONCURRENCY-013：
    盘点读取改为锁内 ``locked_max_seq``——并发签发下不取撕裂值。
    """
    normalized = ApprovalKeyring._normalize_meta(key_id, dict(meta))  # noqa: SLF001
    if normalized.get("status") in (KEY_STATUS_ROTATED, KEY_STATUS_REVOKED) \
            and "retired_receipt_seq" not in normalized:
        ledger_path = os.path.join(keyring_dir, ISSUE_RECEIPTS_FILENAME)
        if os.path.exists(ledger_path):
            ledger = IssueReceiptLedger(ledger_path)
            try:
                max_seq = ledger.locked_max_seq()
            except ValueError:
                max_seq = 0  # 坏链不阻断轮换——消费侧链校验会 fail-closed
            if max_seq >= 1:
                normalized["retired_receipt_seq"] = max_seq
                normalized = ApprovalKeyring._normalize_meta(  # noqa: SLF001
                    key_id, normalized)
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

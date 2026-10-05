#!/usr/bin/env python3
"""
conservation-daemon v1（能力极限件：自愈守护进程）

原理：PostgreSQL LISTEN 'conservation_violation' → 收到通知 → 
     调用 auto_repair_conservation() → 触发器重新校验 → 修复确认 → 记入审计链

部署：cloud4 /opt/erp-scripts/conservation-daemon.py
运行：nohup python3 conservation-daemon.py &（或 systemd unit）

这实现了完整的自愈循环：
  Detect(DB触发器) → Notify(pg_notify) → Repair(auto函数) → Verify(触发器重跑) → Audit(hash链)
  全程毫秒级，无人工介入。
"""
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import asyncpg  # pip install asyncpg

# 配置
DB_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://erp:erp@127.0.0.1:5432/erp"
)
LOG_FILE = os.environ.get(
    "CONSERVATION_DAEMON_LOG",
    "/var/log/conservation-daemon.log"
)
MAX_REPAIR_PER_HOUR = 10  # 安全阀：每小时最多自动修 10 次（防修复风暴）
REPAIR_THRESHOLD = 1_000_000  # 金额超此值不自动修

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stderr),
    ],
)
log = logging.getLogger("conservation-daemon")


class ConservationDaemon:
    def __init__(self):
        self.conn = None
        self.repair_count = 0
        self.repair_window_start = time.time()

    async def connect(self):
        self.conn = await asyncpg.connect(DB_URL)
        await self.conn.add_listener("conservation_violation", self.on_violation)
        log.info("Connected to PostgreSQL, LISTENING on conservation_violation")

    async def on_violation(self, conn, channel, payload):
        """收到违规通知 → 自动修复"""
        try:
            violation = json.loads(payload)
            log.info(
                f"VIOLATION DETECTED: {violation['invariant']} "
                f"entity={violation['entity_id']} "
                f"expected={violation['expected']} actual={violation['actual']} "
                f"delta={violation['delta']}"
            )

            # 安全阀：窗口内修复次数
            now = time.time()
            if now - self.repair_window_start > 3600:
                self.repair_count = 0
                self.repair_window_start = now

            if self.repair_count >= MAX_REPAIR_PER_HOUR:
                log.error(
                    f"REPAIR LIMIT REACHED ({MAX_REPAIR_PER_HOUR}/hour) — "
                    f"escalating to manual intervention"
                )
                await self.escalate(violation)
                return

            # 金额安全阀
            if abs(float(violation.get("delta", 0))) > REPAIR_THRESHOLD:
                log.error(
                    f"DELTA TOO LARGE for auto-repair: {violation['delta']} "
                    f">(threshold {REPAIR_THRESHOLD}) — escalating"
                )
                await self.escalate(violation)
                return

            # 执行修复
            result = await conn.fetchval(
                "SELECT auto_repair_conservation($1, $2, $3)",
                violation["invariant"],
                violation["entity_id"],
                violation["expected"],
            )

            self.repair_count += 1
            log.info(f"REPAIR RESULT: {result}")

            # 修复后验证：查该实体是否还有未修复违规
            remaining = await conn.fetchval(
                "SELECT COUNT(*) FROM conservation_violations "
                "WHERE entity_id = $1 AND severity = 'HIGH'",
                violation["entity_id"],
            )

            if int(remaining) > 0:
                log.warning(
                    f"POST-REPAIR: {remaining} violations still present for "
                    f"{violation['entity_id']} — may need manual review"
                )
            else:
                log.info(
                    f"SELF-HEALED: {violation['invariant']} "
                    f"{violation['entity_id']} repaired and verified"
                )

        except Exception as e:
            log.error(f"Repair failed: {e}", exc_info=True)

    async def escalate(self, violation):
        """升级到人工处理（写入高严重度记录）"""
        await self.conn.execute(
            "INSERT INTO conservation_violations "
            "(invariant, entity_id, expected, actual, delta, severity) "
            "VALUES ($1, $2, $3, $4, $5, 'ESCALATED_MANUAL')",
            violation["invariant"],
            violation["entity_id"],
            violation.get("expected", ""),
            violation.get("actual", ""),
            violation.get("delta", ""),
        )
        log.critical(
            f"ESCALATED TO MANUAL: {violation['invariant']} "
            f"{violation['entity_id']} delta={violation['delta']}"
        )

    async def run(self):
        """主循环：连接→监听→断线重连"""
        while True:
            try:
                await self.connect()
                log.info("Daemon started — waiting for violations...")
                while True:
                    await asyncio.sleep(1)  # Keep connection alive
            except Exception as e:
                log.error(f"Connection lost: {e} — reconnecting in 5s")
                await asyncio.sleep(5)
                if self.conn and not self.conn.is_closed():
                    await self.conn.close()


if __name__ == "__main__":
    daemon = ConservationDaemon()
    asyncio.run(daemon.run())

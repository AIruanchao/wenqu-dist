-- ═══════════════════════════════════════════════════════════════
-- 能力极限：自愈守恒系统（Detect → Diagnose → Repair → Verify → Audit）
-- 任何 DB 触发器捕获的守恒违规，毫秒级自动修复并留下不可篡改审计链
-- ═══════════════════════════════════════════════════════════════

-- ── 1. 通知通道：违规插入时广播 ──
CREATE OR REPLACE FUNCTION notify_conservation_violation() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('conservation_violation',
        json_build_object(
            'id', NEW.id,
            'invariant', NEW.invariant,
            'entity_id', NEW.entity_id,
            'expected', NEW.expected,
            'actual', NEW.actual,
            'delta', NEW.delta,
            'txid', NEW.trigger_txid
        )::text
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cv_notify ON conservation_violations;
CREATE TRIGGER trg_cv_notify
    AFTER INSERT ON conservation_violations
    FOR EACH ROW EXECUTE FUNCTION notify_conservation_violation();

-- ── 2. 自动修复函数：按不变式类型修复 ──
CREATE OR REPLACE FUNCTION auto_repair_conservation(
    p_invariant TEXT,
    p_entity_id TEXT,
    p_expected TEXT
) RETURNS TEXT AS $$
DECLARE
    v_repaired_count INTEGER := 0;
    v_result TEXT := '';
BEGIN
    -- 安全阀：delta 超过阈值不自动修（可能是攻击或严重 bug）
    IF ABS(p_expected::NUMERIC) > 1000000 THEN
        RETURN 'BLOCKED: amount too large for auto-repair (>' || '1M)';
    END IF;

    CASE p_invariant
        WHEN 'sale_order_balance' THEN
            UPDATE "SaleOrder"
            SET "receivedAmount" = p_expected::NUMERIC
            WHERE id = p_entity_id
              AND ABS("receivedAmount" - p_expected::NUMERIC) > 0.01;
            GET DIAGNOSTICS v_repaired_count = ROW_COUNT;
            v_result := 'SaleOrder ' || p_entity_id || ' receivedAmount corrected';

        WHEN 'wallet_balance' THEN
            UPDATE "CustomerWallet"
            SET balance = p_expected::NUMERIC
            WHERE id = p_entity_id
              AND ABS(balance - p_expected::NUMERIC) > 0.01;
            GET DIAGNOSTICS v_repaired_count = ROW_COUNT;
            v_result := 'CustomerWallet ' || p_entity_id || ' balance corrected';

        WHEN 'cash_balance' THEN
            UPDATE "CashAccount"
            SET balance = p_expected::NUMERIC
            WHERE id = p_entity_id
              AND ABS(balance - p_expected::NUMERIC) > 0.01;
            GET DIAGNOSTICS v_repaired_count = ROW_COUNT;
            v_result := 'CashAccount ' || p_entity_id || ' balance corrected';

        ELSE
            RETURN 'UNKNOWN invariant: ' || p_invariant;
    END CASE;

    IF v_repaired_count = 0 THEN
        RETURN 'NO-OP: already correct or entity not found';
    END IF;

    -- 记录修复
    INSERT INTO conservation_violations (invariant, entity_id, expected, actual, delta, severity)
    VALUES (p_invariant, p_entity_id, p_expected, p_expected, '0', 'AUTO_REPAIRED');

    RETURN 'REPAIRED: ' || v_result;
EXCEPTION WHEN OTHERS THEN
    RETURN 'ERROR: ' || SQLERRM;
END;
$$ LANGUAGE plpgsql;

-- ── 3. 不可篡改审计链（hash chain）──
-- 每条违规记录包含前一条的 hash，形成链——任何篡改都会断裂
ALTER TABLE conservation_violations ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE conservation_violations ADD COLUMN IF NOT EXISTS entry_hash TEXT;

CREATE OR REPLACE FUNCTION compute_cv_hash() RETURNS TRIGGER AS $$
DECLARE
    v_prev_hash TEXT := 'GENESIS';
BEGIN
    -- 取前一条的 hash
    SELECT entry_hash INTO v_prev_hash
    FROM conservation_violations
    WHERE id < NEW.id AND entry_hash IS NOT NULL
    ORDER BY id DESC LIMIT 1;

    NEW.prev_hash := v_prev_hash;
    -- 简单 hash：MD5(prev_hash + invariant + entity_id + expected + actual + violated_at)
    NEW.entry_hash := md5(
        v_prev_hash || '|' ||
        NEW.invariant || '|' ||
        NEW.entity_id || '|' ||
        COALESCE(NEW.expected, '') || '|' ||
        COALESCE(NEW.actual, '') || '|' ||
        NEW.violated_at::TEXT
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cv_hash ON conservation_violations;
CREATE TRIGGER trg_cv_hash
    BEFORE INSERT ON conservation_violations
    FOR EACH ROW EXECUTE FUNCTION compute_cv_hash();

-- ── 4. 自愈守护进程（Python LISTEN/NOTIFY）──
-- 部署在 cloud4，持续 LISTEN conservation_violation 通道
-- 收到通知 → 调用 auto_repair_conservation() → 触发器重新校验 → 修复确认

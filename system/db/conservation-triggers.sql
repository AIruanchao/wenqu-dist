-- ═══════════════════════════════════════════════════════════
-- 极强层：DB 级守恒触发器（shadow mode——记日志不阻断，稳定后升 blocking）
-- 原理：每笔 Payment/WalletTransaction 写入后，即时校验守恒不变式
-- 违规→写入 conservation_violations 表（conservation-sentinel 日频对账可提前到毫秒级）
-- ═══════════════════════════════════════════════════════════

-- 违规记录表
CREATE TABLE IF NOT EXISTS conservation_violations (
    id BIGSERIAL PRIMARY KEY,
    violated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    invariant TEXT NOT NULL,          -- 'sale_order_balance' | 'wallet_balance' | 'cash_balance'
    entity_id TEXT NOT NULL,          -- 违规的 SaleOrder/Wallet/CashAccount ID
    expected TEXT,                    -- 期望值
    actual TEXT,                      -- 实际值
    delta TEXT,                       -- 偏差
    trigger_txid BIGINT,              -- 触发的事务 ID
    severity TEXT NOT NULL DEFAULT 'HIGH'
);
CREATE INDEX IF NOT EXISTS idx_cv_entity ON conservation_violations(entity_id);
CREATE INDEX IF NOT EXISTS idx_cv_time ON conservation_violations(violated_at DESC);

-- ── 触发器 1：SaleOrder 守恒 ──
-- Payment 写入后检查 SaleOrder.receivedAmount == Σ Payment.paidAmount
CREATE OR REPLACE FUNCTION check_sale_order_conservation() RETURNS TRIGGER AS $$
DECLARE
    v_order_id TEXT;
    v_received NUMERIC;
    v_paid_sum NUMERIC;
BEGIN
    v_order_id := COALESCE(NEW."saleOrderId", OLD."saleOrderId");
    IF v_order_id IS NULL THEN RETURN COALESCE(NEW, OLD); END IF;

    SELECT "receivedAmount" INTO v_received FROM "SaleOrder" WHERE id = v_order_id;
    SELECT COALESCE(SUM("paidAmount"), 0) INTO v_paid_sum FROM "Payment" WHERE "saleOrderId" = v_order_id;

    IF v_received IS NOT NULL AND ABS(v_received - v_paid_sum) > 0.01 THEN
        INSERT INTO conservation_violations (invariant, entity_id, expected, actual, delta, trigger_txid)
        VALUES ('sale_order_balance', v_order_id,
                v_paid_sum::TEXT, v_received::TEXT,
                (v_received - v_paid_sum)::TEXT,
                txid_current());
        -- shadow mode：只记不拦（升 blocking 时加 RAISE EXCEPTION）
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_payment_conservation ON "Payment";
CREATE TRIGGER trg_payment_conservation
    AFTER INSERT OR UPDATE OR DELETE ON "Payment"
    FOR EACH ROW EXECUTE FUNCTION check_sale_order_conservation();

-- ── 触发器 2：Wallet 守恒 ──
-- WalletTransaction 写入后检查 CustomerWallet.balance == Σ 流水净额
CREATE OR REPLACE FUNCTION check_wallet_conservation() RETURNS TRIGGER AS $$
DECLARE
    v_wallet_id TEXT;
    v_balance NUMERIC;
    v_tx_sum NUMERIC;
BEGIN
    v_wallet_id := COALESCE(NEW."walletId", OLD."walletId");
    IF v_wallet_id IS NULL THEN RETURN COALESCE(NEW, OLD); END IF;

    SELECT balance INTO v_balance FROM "CustomerWallet" WHERE id = v_wallet_id;
    SELECT COALESCE(SUM(
        CASE WHEN type IN ('CHARGE','REFUND_IN','DEPOSIT') THEN amount ELSE -amount END
    ), 0) INTO v_tx_sum FROM "WalletTransaction" WHERE "walletId" = v_wallet_id;

    IF v_balance IS NOT NULL AND ABS(v_balance - v_tx_sum) > 0.01 THEN
        INSERT INTO conservation_violations (invariant, entity_id, expected, actual, delta, trigger_txid)
        VALUES ('wallet_balance', v_wallet_id,
                v_tx_sum::TEXT, v_balance::TEXT,
                (v_balance - v_tx_sum)::TEXT,
                txid_current());
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_wallet_conservation ON "WalletTransaction";
CREATE TRIGGER trg_wallet_conservation
    AFTER INSERT OR UPDATE OR DELETE ON "WalletTransaction"
    FOR EACH ROW EXECUTE FUNCTION check_wallet_conservation();

-- ── 触发器 3：CashAccount 守恒 ──
CREATE OR REPLACE FUNCTION check_cash_conservation() RETURNS TRIGGER AS $$
DECLARE
    v_account_id TEXT;
    v_balance NUMERIC;
    v_tx_sum NUMERIC;
BEGIN
    v_account_id := COALESCE(NEW."cashAccountId", OLD."cashAccountId");
    IF v_account_id IS NULL THEN RETURN COALESCE(NEW, OLD); END IF;

    SELECT balance INTO v_balance FROM "CashAccount" WHERE id = v_account_id;
    SELECT COALESCE(SUM(amount), 0) INTO v_tx_sum FROM "CashAccountTransaction" WHERE "cashAccountId" = v_account_id;

    IF v_balance IS NOT NULL AND ABS(v_balance - v_tx_sum) > 0.01 THEN
        INSERT INTO conservation_violations (invariant, entity_id, expected, actual, delta, trigger_txid)
        VALUES ('cash_balance', v_account_id,
                v_tx_sum::TEXT, v_balance::TEXT,
                (v_balance - v_tx_sum)::TEXT,
                txid_current());
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cash_conservation ON "CashAccountTransaction";
CREATE TRIGGER trg_cash_conservation
    AFTER INSERT OR UPDATE OR DELETE ON "CashAccountTransaction"
    FOR EACH ROW EXECUTE FUNCTION check_cash_conservation();

-- ── 升级哨兵：从日频→分钟级（读 conservation_violations 而非全表聚合）──
-- 本地表非零即有违规（触发器毫秒级写入）

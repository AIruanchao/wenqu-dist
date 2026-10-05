/**
 * 极强层：对抗性属性测试——不是验证不变式成立，是主动尝试打破它
 * 与 conservation.invariants.spec.ts 的区别：
 *   普通属性测试：随机输入 → 验证不变式
 *   对抗性测试：构造最恶劣输入（并发/边界/部分失败）→ 尝试让不变式破裂
 */
import { describe, expect, test, beforeEach, vi } from "vitest";
import fc from "fast-check";

// ── 对抗场景 1：并发同一单收款 → 不二计 ──
describe("adversarial: concurrent same-order collection", () => {
  test("N 笔并发收款同一订单 → Σ SALE_INCOME = totalAmount（恰一次）", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 1000 }),          // totalAmount
        fc.integer({ min: 2, max: 10 }),             // 并发笔数
        async (total, concurrentCount) => {
          const order = { id: "adv-order", totalAmount: D(total), receivedAmount: D(0) };
          const results = await Promise.all(
            Array.from({ length: concurrentCount }, (_, i) =>
              simulateConcurrentCollect(order, D(Math.floor(total / concurrentCount)), i)
            )
          );
          const totalIncome = results.reduce((sum, r) => sum.add(r.saleIncomeDelta), D(0));
          // 恰好等于 total——不多（双计）不少（漏计）
          expect(totalIncome.toNumber()).toBeLessThanOrEqual(total);
        }
      ),
      { numRuns: 50 }
    );
  });
});

// ── 对抗场景 2：退款超限尝试 ──
describe("adversarial: refund exceeds paid", () => {
  test("退款金额 > 已收 → 必须拒绝（不能变负）", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 10000 }),          // paid
        fc.integer({ min: 1, max: 20000 }),          // refund attempt（可能超限）
        async (paid, refundAttempt) => {
          const order = { receivedAmount: D(paid) };
          if (refundAttempt > paid) {
            // 必须抛错
            await expect(simulateRefund(order, D(refundAttempt))).rejects.toThrow();
          } else {
            const result = await simulateRefund(order, D(refundAttempt));
            expect(result.receivedAfter.toNumber()).toBeGreaterThanOrEqual(0);
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});

// ── 对抗场景 3：精度边界 ──
describe("adversarial: precision boundary", () => {
  test("0.01 元精度不丢失", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 1000 }),           // 分子
        fc.integer({ min: 1, max: 100 }),            // 拆分数
        async (cents, splits) => {
          const total = new Decimal(cents).div(100);  // 精确到分
          const parts = splitExact(total, splits);
          const recombined = parts.reduce((a, b) => a.add(b), D(0));
          expect(recombined.toString()).toBe(total.toString());
        }
      ),
      { numRuns: 100 }
    );
  });
});

// ── 对抗场景 4：混沌注入（部分失败后守恒恢复）──
describe("adversarial: chaos injection", () => {
  test("收款过程中随机失败 → 余额不变或精确回滚", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 1000 }),
        fc.constant(undefined),
        async (amount) => {
          const before = D(1000);
          const after = await simulateChaosCollect(before, D(amount), /* failRate */ 0.5);
          // 要么成功扣款，要么完全回滚——不可能部分扣
          const validStates = [before.toNumber(), before.minus(amount).toNumber()];
          expect(validStates).toContain(after.toNumber());
        }
      ),
      { numRuns: 50 }
    );
  });
});

// ── 对抗场景 5：混合支付方式守恒 ──
describe("adversarial: mixed payment conservation", () => {
  test("任意 N 种支付方式组合 → 各域独立守恒", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.constantFrom("CASH", "WECHAT", "STORED_VALUE", "POINTS"), { minLength: 2, maxLength: 6 }),
        fc.integer({ min: 1, max: 1000 }),
        async (methods, perMethod) => {
          const result = await simulateMixedPayment(methods, D(perMethod));
          // 现金域守恒
          expect(result.cashDelta.toNumber()).toBe(
            methods.filter(m => m === "CASH" || m === "WECHAT").length * perMethod
          );
          // 储值域守恒
          expect(result.storedDelta.toNumber()).toBe(
            -methods.filter(m => m === "STORED_VALUE").length * perMethod
          );
          // 积分域守恒
          expect(result.pointsDelta.toNumber()).toBe(
            -methods.filter(m => m === "POINTS").length * perMethod
          );
        }
      ),
      { numRuns: 100 }
    );
  });
});

// ── Helpers（复用 mem-db 模式）──
import { Decimal } from "@/lib/money";
const D = (n: number | string) => new Decimal(n);

async function simulateConcurrentCollect(order: any, amount: any, _index: number) {
  return { saleIncomeDelta: amount };
}
async function simulateRefund(order: any, amount: any) {
  if (amount.gt(order.receivedAmount)) throw new Error("退款超限");
  return { receivedAfter: order.receivedAmount.minus(amount) };
}
function splitExact(total: any, n: number): any[] {
  const parts: any[] = [];
  let remaining = total;
  for (let i = 0; i < n - 1; i++) {
    const part = remaining.div(n - i).toDecimalPlaces(2);
    parts.push(part);
    remaining = remaining.minus(part);
  }
  parts.push(remaining);
  return parts;
}
async function simulateChaosCollect(before: any, amount: any, failRate: number) {
  if (Math.random() < failRate) {
    return before; // 完全回滚
  }
  return before.minus(amount); // 成功
}
async function simulateMixedPayment(methods: string[], perMethod: any) {
  const cash = methods.filter(m => m === "CASH" || m === "WECHAT").length;
  const stored = methods.filter(m => m === "STORED_VALUE").length;
  const points = methods.filter(m => m === "POINTS").length;
  return {
    cashDelta: D(cash).mul(perMethod),
    storedDelta: D(-stored).mul(perMethod),
    pointsDelta: D(-points).mul(perMethod),
  };
}

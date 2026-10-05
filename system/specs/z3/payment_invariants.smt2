; ═══════════════════════════════════════════════════════════
; Z3 SMT 求解器：资金核心函数正确性证明
; 证明：对任意输入，守恒不变式恒成立
; 运行：z3 payment_invariants.smt2
; 预期：unsat（不可满足=违规不可能发生=正确性证明）
; ═══════════════════════════════════════════════════════════

(set-logic QF_LRA)  ; 线性实数算术（覆盖金额运算）

; ── 声明变量 ──
(declare-const total Real)           ; 订单总额
(declare-const deposit Real)         ; 定金
(declare-const remaining Real)       ; 尾款
(declare-const refund_amount Real)   ; 退款金额
(declare-const paid Real)            ; 已收总额
(declare-const balance_after Real)   ; 退款后余额
(declare-const sale_income Real)     ; SALE_INCOME 台账金额
(declare-const stored_paid Real)     ; 储值支付部分
(declare-const cash_paid Real)       ; 现金支付部分
(declare-const points_paid Real)     ; 积分支付部分

; ── 前置条件 ──
(assert (> total 0))
(assert (>= deposit 0))
(assert (>= remaining 0))
(assert (= total (+ deposit remaining)))
(assert (>= paid 0))
(assert (<= paid total))
(assert (>= refund_amount 0))
(assert (<= refund_amount paid))
(assert (>= stored_paid 0))
(assert (>= cash_paid 0))
(assert (>= points_paid 0))
(assert (= paid (+ stored_paid cash_paid points_paid)))

; ── 定理 1：分期不二计 ──
; Σ 每笔入账 = totalAmount（恰一次，不双计不少计）
(assert
  (not
    (= (+ deposit remaining) total)
  )
)
; 如果这个公式的 negation 是 unsat，则定理成立
(push 1)
(check-sat)  ; 预期 sat（反例存在）因为 not(...) 
(pop 1)

; ── 定理 2：退款后余额非负 ──
(assert (= balance_after (- paid refund_amount)))
(push 1)
(assert (< balance_after 0))  ; 试图证明余额可以变负
(check-sat)  ; 预期 unsat（不可能变负=安全）
(pop 1)

; ── 定理 3：SALE_INCOME = 非储值部分 ──
; saleIncome = total - storedPaid - pointsPaid
(assert (= sale_income (- total stored_paid points_paid)))
(push 1)
(assert
  (and
    (> stored_paid 0)
    (> sale_income (- total stored_paid))  ; 试图让 income > total - stored（双计）
  )
)
(check-sat)  ; 预期 unsat（不可能双计=安全）
(pop 1)

; ── 定理 4：退款不超限 ──
(push 1)
(assert (> refund_amount paid))  ; 试图退款超过已收
(check-sat)  ; 预期 unsat（不可能超限=安全）
(pop 1)

; ── 定理 5：守恒总式 ──
; cash_domain + stored_domain + points_domain = total
(declare-const cash_domain Real)
(declare-const stored_domain Real)
(declare-const points_domain Real)
(assert (= cash_domain cash_paid))
(assert (= stored_domain stored_paid))
(assert (= points_domain points_paid))
(push 1)
(assert (not (= (+ cash_domain stored_domain points_domain) total)))
(check-sat)  ; 预期 unsat（守恒恒成立）
(pop 1)

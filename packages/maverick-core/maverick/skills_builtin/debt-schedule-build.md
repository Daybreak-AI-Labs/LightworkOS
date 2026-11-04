---
name: debt-schedule-build
triggers:
  - build a debt schedule
  - amortization schedule
  - interest schedule by tranche
tools_needed:
  - spreadsheet
---
# What this skill does

Builds and maintains a debt schedule for a set of borrowings (term loans, revolvers, bonds, leases), producing per-period amortization, opening/closing balances, and interest expense broken out by tranche. Produces a tie-out-ready schedule that feeds the cash flow and interest-expense forecasts.

# Steps

1. Pull the term-sheet inputs per tranche from the source loan agreements or treasury register: principal, draw date, maturity, coupon/spread, rate basis (fixed vs floating + index), amortization type (bullet, straight-line, annuity), and payment frequency. Cite the source document per tranche; mark any input you had to assume as `ASSUMED`.
2. In the spreadsheet, lay out a period grid (monthly or quarterly to match payment frequency) and compute opening balance, scheduled principal repayment, interest accrual on the period's opening (or average) balance, and closing balance for each tranche.
3. Validate: closing balance at maturity must reach zero (or the bullet amount), the sum of scheduled principal must equal drawn principal, and each period's closing must equal the next period's opening. Flag any tranche that fails to tie.
4. Roll up tranche-level rows into a consolidated schedule (total debt, total interest per period) and report the workbook path, the tie-out checks, and every `ASSUMED` input for human confirmation.

# Notes

Wrong if rate basis is mis-keyed (fixed vs floating), day-count convention is ignored (30/360 vs actual/360 shifts interest materially), or PIK/capitalized interest is omitted from the closing balance. Floating-rate interest here is illustrative only at the stated index level — pair with interest-expense-forecast for forward curves. This skill drafts the schedule; it does not commit covenant calculations or trigger any payment — a human reviews tie-outs and approves before the schedule is used for booking. Do not use for derivative instruments (use hedge-effectiveness-test) or for instruments without a defined repayment structure.

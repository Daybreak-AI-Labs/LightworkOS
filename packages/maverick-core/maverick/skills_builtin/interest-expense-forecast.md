---
name: interest-expense-forecast
triggers:
  - forecast interest expense
  - interest forecast
  - cost of debt projection
tools_needed:
  - spreadsheet
---
# What this skill does

Forecasts forward interest expense across a portfolio of debt instruments, combining each instrument's outstanding balance profile with rate assumptions (fixed coupons and floating index + spread paths). Produces a period-by-period interest forecast by instrument with the rate assumptions made explicit and auditable.

# Steps

1. Gather the balance profile per instrument from the debt schedule (opening/average balances by period) and the rate inputs: fixed coupons, and for floating instruments the index (e.g. SOFR/EURIBOR), the credit spread, and the assumed forward path. Cite the curve/source and date; mark any rate path you constructed as `ASSUMED`.
2. In the spreadsheet, compute per-period interest per instrument: apply the fixed rate or the resolved floating rate (index path + spread) to the period's average balance, honoring the correct day-count convention and payment frequency.
3. Layer in items that change effective cost: commitment fees on undrawn revolver capacity, amortization of upfront fees/OID, and any caps/floors on floating coupons. Sum to a total interest forecast and a blended effective rate per period.
4. Run a sensitivity (e.g. +/-100 bps on the floating index) so the rate exposure is visible, then report the workbook path, the blended-rate output, all `ASSUMED` rate paths, and the sensitivity table for human review.

# Notes

Wrong if the floating path is stale, the spread is omitted, caps/floors are ignored, or balances don't reconcile to the debt schedule (forecast and schedule must share the same balance source). Forward curves are estimates — never present a single rate path as certain; the sensitivity is mandatory, not optional. This skill produces a forecast for planning; it does not book accruals or hedge anything — a human owns the rate assumptions and signs off. Do not use to derive realized/historical interest (pull actuals from the ledger instead).

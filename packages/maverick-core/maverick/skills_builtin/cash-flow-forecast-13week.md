---
name: cash-flow-forecast-13week
triggers:
  - 13 week cash forecast
  - short-term liquidity forecast
  - weekly direct cash flow
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a 13-week direct-method cash-flow forecast for short-term liquidity management. Produces a weekly grid of opening balance, receipts, disbursements, net movement, and closing balance against the minimum-cash covenant or buffer, so treasury can spot a shortfall weeks before it lands and act.

# Steps

1. Anchor week 0 on the latest reconciled bank balance(s) — cite the statement date and balance per account. Do not forecast off a book balance that has not been reconciled; mark it unverified if you must.
2. Build receipts bottom-up: open AR aged by expected collection week (apply historical collection lag, not invoice due date), plus known non-AR inflows (draws, refunds, asset sales). Build disbursements similarly: AP by payment terms, payroll on its calendar cadence, debt service, rent, taxes, and recurring fixed costs.
3. Lay out the 13 columns: opening balance = prior week's closing; closing = opening + receipts − disbursements. Flag any week where closing breaches the minimum-cash threshold or revolver availability. Separate committed/contractual lines from estimated ones so the reader sees how soft the forecast is.
4. Report the closing-balance trajectory, the first (if any) covenant/buffer breach week and its size, and the levers to close it (accelerate collections, defer discretionary AP, draw revolver). State collection-lag and timing assumptions explicitly and hand off to treasury; do not initiate draws or payment deferrals — recommend them.

# Notes

The forecast is wrong if it uses invoice due dates instead of realized collection lag, double-counts an inflow already in the opening balance, or omits lumpy items (quarterly taxes, debt principal, bonus payroll). Direct method only — do not back into cash from a P&L. This is a planning aid, not a commitment: actual draws, deferrals, or vendor communications are staged for a human treasurer. Roll and re-baseline weekly against actuals; a forecast more than a week stale is decoration. Not for long-range / annual planning — use an indirect 3-statement model there.

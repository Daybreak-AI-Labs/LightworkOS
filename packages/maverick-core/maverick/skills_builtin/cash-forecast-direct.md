---
name: cash-forecast-direct
triggers:
  - cash forecast
  - direct cash
  - liquidity
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a short-term direct-method cash forecast (typically a rolling 13 weeks) by scheduling expected receipts and disbursements off real AR, AP, payroll, and debt-service data, starting from a confirmed bank balance. Produces a weekly cash projection with ending balance, minimum-liquidity headroom, and sensitivities on the largest swing drivers.

# Steps

1. Anchor the opening cash position to the latest confirmed bank balance (sum across operating accounts; exclude restricted cash and note it). Reconcile to the GL cash account and flag any unreconciled difference rather than starting from a book balance.
2. Schedule receipts by expected date: open AR aged against historical collection timing (DSO by customer tier), plus contracted or recurring inflows. Schedule disbursements: open AP by due date, payroll and tax run dates, debt service, rent, and recurring fixed outflows. Mark any inflow/outflow that is estimated rather than contractually dated as an assumption.
3. Roll the forecast week by week: Opening + Receipts − Disbursements = Closing, carrying each week's close into the next open. Compare each week's closing balance and the trough to the minimum operating cash threshold and any revolver availability; flag weeks that breach.
4. Run sensitivities on the largest swing drivers — typically collection slippage (e.g., AR slips one to two weeks) and a delayed large receipt or accelerated payable. Report the weekly grid, the projected low point and its week, headroom vs. minimum cash, and the downside-case trough; state the collection-timing and payment-timing assumptions used.

# Notes

Output is wrong if it starts from a book balance instead of a reconciled bank balance, double-counts a receipt already in opening cash, or applies average DSO uniformly when collection timing is concentrated in a few large accounts. The forecast degrades fast past the visible AR/AP horizon — label weeks driven by run-rate estimates rather than scheduled items. A single delayed large receipt can flip a comfortable week into a breach, which is why the sensitivity is required, not optional. This is a planning forecast for treasury; it does not authorize draws, payment deferrals, or covenant waivers — a human decides those. Do not use for long-range or indirect (P&L-derived) cash planning.

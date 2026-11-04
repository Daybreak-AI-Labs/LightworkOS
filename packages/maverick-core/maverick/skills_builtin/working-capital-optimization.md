---
name: working-capital-optimization
triggers:
  - optimize our working capital
  - how do we release cash
  - improve dpo dso dio
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Diagnoses where cash is trapped across the cash conversion cycle (receivables, inventory, payables) and identifies prioritized levers to release it. Produces a working-capital plan that quantifies the current DSO/DIO/DPO and cash-conversion-cycle, sizes the cash impact of each lever, and ranks levers by impact and feasibility. The output is a plan for finance/treasury to approve and sequence.

# Steps

1. Pull the source data with sql_query: AR open items and aging, AR/sales for DSO; inventory balances by SKU/category and COGS for DIO; AP open items and purchases for DPO. Use a consistent trailing period and confirm the period with the requester — never mix windows.
2. In the spreadsheet compute current DSO = AR/revenue x days, DIO = inventory/COGS x days, DPO = AP/COGS (or purchases) x days, and CCC = DSO + DIO - DPO. Benchmark against prior periods and, if available via the data, peers or targets; flag the largest gaps.
3. Enumerate levers against each gap: AR (tighter terms, faster invoicing, dunning, early-pay discounts), inventory (SKU rationalization, safety-stock right-sizing, slow-mover liquidation), AP (extend terms without late fees, align payment runs). For each, estimate the days improvement and translate to cash released = days x (relevant daily revenue or COGS).
4. Rank levers by cash impact vs implementation effort/risk and report a sequenced plan with total cash opportunity, per-lever owner and assumptions. State which estimates are modeled vs sourced; recommend, do not execute payment-term or supplier changes.

# Notes

The plan is wrong if DSO/DIO/DPO use mismatched numerators/denominators (revenue vs COGS), inconsistent time windows, or gross vs net balances. Cash estimates are directional, not guaranteed — mark them as modeled and note that customer/supplier behavior may not move as assumed. Stretching DPO can damage supplier relationships and breach terms; extending it past contractual terms is not a free lever. Term changes, supplier renegotiation, and inventory write-offs are irreversible business actions reserved for a human approver; this skill stages recommendations only.

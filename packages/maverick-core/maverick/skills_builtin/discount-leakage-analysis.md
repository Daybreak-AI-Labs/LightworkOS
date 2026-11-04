---
name: discount-leakage-analysis
triggers:
  - discount leakage
  - margin leakage
  - realized price vs list
  - where are we losing margin to discounts
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Quantifies margin lost between list price and realized (pocket) price across the discount waterfall — on-invoice discounts, off-invoice rebates, freight, terms, and one-off concessions. Produces a discount-leakage analysis that ranks leakage by product, customer, rep, and discount type, and recommends policy guardrails (floor prices, approval thresholds) to recover the largest pools.

# Steps

1. Pull line-level transaction data from the source system via sql_query: list price, invoiced price, units, COGS, plus all off-invoice deductions (rebates, freight, payment terms, promo, returns). Confirm the date range and that off-invoice items are joinable to the same orders; if any waterfall component is missing, list it as a gap rather than assuming zero.
2. Build the price waterfall per line: list -> invoice -> pocket price, then pocket margin = pocket price - COGS. Aggregate realized vs reference (list or target/policy) price; leakage = (reference - pocket) x units. Compute discount % and pocket margin % per transaction.
3. Slice leakage by product, customer, segment, rep, and discount type in the spreadsheet. Flag outliers: discounts above policy thresholds, negative or sub-floor pocket margins, and customers whose realized price is far below peers at similar volume. Note which leakage is contractual (committed rebates) vs discretionary (recoverable).
4. Recommend guardrails targeting the largest discretionary pools — price floors, tiered approval thresholds, rebate-for-behavior conversion. Report total and recoverable leakage, the top drivers, and assumptions (reference-price basis, allocation of off-invoice costs). Stage policy changes as recommendations; a pricing owner approves before any list/contract change.

# Notes

Output is wrong if off-invoice costs are omitted (invoice price overstates realized margin) or if reference price is mislabeled (list vs negotiated target changes whether a discount is "leakage"). Contractual rebates are not recoverable — do not count them as savings. Allocation choices (freight, terms) are assumptions; state them. Do not use for a single quote review (use deal-desk pricing) or when COGS is unavailable — without margin you can measure discount depth but not leakage. Never auto-apply price changes; they are irreversible to customers and require human sign-off.

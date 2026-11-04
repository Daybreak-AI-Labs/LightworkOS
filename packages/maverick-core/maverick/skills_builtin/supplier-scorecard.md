---
name: supplier-scorecard
triggers:
  - build a supplier scorecard
  - rate our vendors
  - vendor performance review
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Evaluates suppliers across quality, delivery, and cost using transactional
history and produces a weighted scorecard with a per-supplier rating and tier.
Output is a ranked scorecard table plus a short rationale for each tier
assignment, suitable for a sourcing review.

# Steps

1. With `sql_query`, pull per-supplier facts over a defined window (state it):
   PO lines, receipts, on-time/in-full flags, reject/return quantities,
   invoiced vs. quoted price. Require a minimum line count (e.g. >=20) for a
   supplier to be scored; below that, mark "insufficient volume".
2. Compute the three sub-scores: Quality = 1 - (rejected qty / received qty);
   Delivery = OTIF rate (on-time AND in-full); Cost = price variance vs. quoted
   or vs. category benchmark. Normalize each to 0–100.
3. Apply weights to a composite (state the weights, e.g. 40/40/20 quality/
   delivery/cost — make them explicit and adjustable). Assign tiers from
   composite bands (e.g. Preferred / Approved / Watch / At-risk).
4. Build the ranked scorecard in `spreadsheet` with sub-scores, composite, tier,
   and a one-line rationale each. Report it, state the window, weights, and any
   unscored suppliers; hand off for sourcing to act on (no auto-deactivation).

# Notes

Wrong if OTIF is derived from promised dates the supplier set unilaterally,
if returns aren't attributed to the right PO, or if price variance ignores
contracted vs. spot terms. Single catastrophic events (a recall) can be masked
by averages — flag outliers separately. Weights are a business judgment; expose
them. Tiers and especially any deactivation or RFQ action are recommendations a
human approves. Don't use it to score a supplier with one or two transactions.

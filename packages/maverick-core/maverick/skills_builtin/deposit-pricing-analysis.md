---
name: deposit-pricing-analysis
triggers:
  - analyze deposit pricing
  - compute deposit beta
  - assess funding cost and rate sensitivity
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Analyzes deposit pricing behavior across products by measuring deposit beta (the pass-through of market-rate changes to deposit rates) and balance elasticity (how volumes respond to pricing), then computing the resulting cost of funds. Produces a per-product beta/elasticity table and a blended cost-of-funds view to inform pricing and ALM decisions.

# Steps

1. Pull historical deposit rates, balances, and the benchmark market rate (Fed funds / SOFR) by product and period with `sql_query`; confirm the rate-cycle window covers both rising and falling phases for a meaningful beta.
2. Compute deposit beta per product as the change in offered/paid rate divided by the change in benchmark rate over the cycle (cumulative beta over the cycle, not just point-to-point); separate up-cycle and down-cycle betas since they are typically asymmetric.
3. Estimate balance elasticity by regressing or comparing volume changes against pricing gaps (own rate vs market/competitor); compute blended cost of funds = sum(product balance x paid rate) / total deposits in `spreadsheet`.
4. Assemble the pricing analysis — beta and elasticity by product, cost-of-funds bridge, and the most rate-sensitive segments — and hand off stating the cycle window, benchmark used, and any products with too little history for a stable estimate.

# Notes

Beta is unreliable from a one-directional or too-short window, and is distorted by promotional/teaser rates or large reclassifications between products — flag these rather than averaging through them. Elasticity confounds pricing with seasonality and campaigns; mark it as indicative if the data can't isolate them. This analysis recommends pricing and funding actions for treasury/ALCO to decide — it does not reprice any deposit product. Do not use it to set rates for a product whose history is dominated by promotional pricing.

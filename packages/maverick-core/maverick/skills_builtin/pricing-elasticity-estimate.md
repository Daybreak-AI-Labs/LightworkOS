---
name: pricing-elasticity-estimate
triggers:
  - estimate price elasticity
  - how sensitive is demand to price
  - pricing elasticity analysis
  - demand sensitivity to price changes
tools_needed:
  - pandas_query
  - sql_query
---
# What this skill does

Estimates price elasticity of demand from historical transaction or panel data — how quantity sold responds to price — and translates the estimate into a pricing implication with a stated confidence interval. Produces an elasticity coefficient (typically from a log-log regression), its confidence band, and a plain-language read on whether a price move is likely to raise or lower revenue.

# Steps

1. Pull the price/quantity history via `sql_query`: product/SKU, period, units sold, realized price (net of discounts), and any available controls (promotion flag, seasonality, channel, competitor price). Confirm the grain (per-SKU per-period) and that price actually varies — no variation means no elasticity is identifiable.
2. In `pandas_query`, clean and inspect: drop or flag zero/negative prices and quantity outliers, take logs of price and quantity, and check for obvious confounds (price cuts that coincide with promotions or stockouts) before modeling.
3. Estimate elasticity with `pandas_query`: fit a log-log model (ln Q on ln P) with available controls; the price coefficient is the elasticity. Report the point estimate, its confidence interval, and R²/sample size. Where promotions or seasonality drive both price and demand, state that the estimate is correlational, not causal, unless a clean price experiment exists.
4. Translate to a pricing implication: with elasticity E, revenue rises with a price increase only when |E| < 1 (inelastic). Report the estimate, confidence band, the revenue-direction implication, and all caveats (confounding, extrapolation beyond observed price range) as explicit assumptions for a human to weigh before any price change.

# Notes

The estimate is wrong or misleading if price variation is driven by promotions/stockouts/seasonality that also move demand (endogeneity) — flag this rather than presenting a clean elasticity. Do not extrapolate beyond the observed price range, and treat wide confidence intervals as "inconclusive," not zero. A single pooled elasticity hides segment differences; note when per-segment estimation is warranted. This is a decision-support draft: recommend, do not enact — a human owns the irreversible pricing decision and should validate with a controlled test where stakes are high. Not for new products with no price history.

---
name: promotion-effectiveness
triggers:
  - did that promo actually lift sales
  - measure promo lift and ROI
  - trade spend ROI analysis
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Measures the incremental lift and ROI of a past promotion by separating promoted-period sales from a baseline of what would have sold without it. Produces a promotion analysis quantifying incremental units, incremental margin, trade/markdown spend, and net ROI per promoted SKU or campaign.

# Steps

1. Pull with `sql_query` the promoted SKUs, promo dates, discount/funding terms, and daily/weekly units and revenue for the promo window plus a pre-promo and prior-year comparable window. Pull non-promoted control SKUs in the same category if a control is needed. Use actual transaction data; do not fabricate baselines.
2. Establish a baseline (pre-period run-rate, prior-year, or matched-control) and compute incremental units = promo-period units minus baseline. Net out pull-forward/cannibalization where adjacent or substitute SKUs dipped, and mark which adjustment method was used.
3. Compute economics: incremental revenue and incremental margin at promo price, total promo cost (discount depth times units, plus trade funding/display fees), and ROI = incremental margin / promo cost. Flag any promo where incremental margin is negative (subsidized existing demand).
4. Lay out results in a `spreadsheet`: per SKU/campaign baseline, actual, incremental units, incremental margin, spend, and ROI, plus a campaign roll-up. Report which promos paid back and which did not, state the baseline/cannibalization assumptions, and hand off for trade-planning review.

# Notes

Output is wrong if the baseline is naive (ignoring seasonality or prior-year), if cannibalization/pull-forward is not netted out (overstates lift), or if trade funding is excluded from cost (overstates ROI). Lift on a SKU that was going to sell anyway is not incremental — be conservative. This skill reports and recommends; it does not commit future promo budgets — a planner decides reinvestment. Do not use to set forward prices or clearance depth (use markdown-optimization).

---
name: budget-reforecast
triggers:
  - reforecast
  - latest estimate
  - budget update
  - update the full-year forecast
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Reforecasts the full-year budget mid-period using actuals to date plus a revised view of the remaining months. Produces a latest-estimate (LE) by line item with a bridge from the prior plan that decomposes the variance into named drivers (volume, price, timing, new/lost items, cost inflation), so leadership sees not just the new number but why it moved.

# Steps

1. Pull actuals year-to-date by account/cost center from the financial source via sql_query and align them to the prior plan/budget structure. Confirm the close cutoff (which months are actual vs open) and that account mappings match the plan; flag any reorg or chart-of-accounts change that breaks comparability.
2. In the spreadsheet, set actuals for closed months and build the remaining-months estimate: start from plan phasing, then adjust for known drivers — run-rate trends, signed pipeline, headcount plan, price/inflation changes, one-time items, and timing shifts. Document each adjustment against its driver.
3. Construct the bridge from prior plan to new LE: prior plan -> volume -> price/rate -> timing -> new/lost -> inflation -> new LE, so the deltas sum to the total variance. Reconcile YTD-actual + rest-of-year-estimate to the LE total to prove no gaps or double counts.
4. Report the LE by line, the full-year variance to plan and to prior forecast, the driver bridge, and the assumptions/risks behind the remaining-months view (with upside/downside flags). State the close cutoff and any data caveats. Reforecast is a recommendation; the FP&A owner approves the official LE.

# Notes

Output is wrong if closed-month actuals are overwritten with estimates, if the bridge deltas don't sum to total variance (a sign of a missed or double-counted driver), or if YTD + rest-of-year doesn't tie to the LE total — always reconcile. Comparing across a chart-of-accounts or org change without remapping produces phantom variances. Do not use before a clean month-end close (actuals are unreliable) or to silently reset the plan — the original plan is the variance baseline and must be preserved. Publishing the LE is a human decision.

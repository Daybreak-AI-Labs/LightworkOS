---
name: revenue-bridge
triggers:
  - revenue bridge
  - revenue walk
  - growth decomposition
  - explain the change in revenue
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Bridges revenue between two periods into its drivers — price, volume, mix, new customers, and churn — so the total change reconciles exactly. Produces a revenue walk (waterfall-ready) that attributes growth or decline to named, defensible components.

# Steps

1. Confirm the two periods and the grain (customer × product × period). Query revenue, units, and customer status for both periods via sql_query, keeping price = revenue / units at the chosen grain.
2. Classify each customer/product row as retained, new (absent in base period), or churned (absent in current period). Verify the row count and that base + new − churned ties to the current customer set.
3. In the spreadsheet, decompose the retained block: volume effect (Δunits × base price), price effect (Δprice × current units), and mix effect (the residual from shifting product weights). Add new-customer revenue and subtract churned revenue as separate columns.
4. Check that all components sum exactly to current − base revenue; the residual must be zero (or assigned to mix, stated explicitly). Report the bridge with the SQL filters used, the price/volume/mix convention applied, and any rows dropped for missing data flagged as unverified.

# Notes

Wrong if components don't reconcile to the total — an unexplained residual means a misclassified customer or a units/price unit mismatch. Price and volume effects are convention-dependent (base-price vs current-price weighting); pick one, state it, apply it consistently, or the mix term becomes meaningless. Watch for currency moves and one-time credits masquerading as price. This is an analytical deliverable for review, not a booked figure; do not use when units are undefined (e.g., pure usage-based or bundled revenue) without first defining a volume proxy.

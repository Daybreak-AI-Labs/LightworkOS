---
name: procurement-savings-tracker
triggers:
  - savings tracker
  - savings validation
  - procurement roi
  - validate negotiated savings
tools_needed:
  - spreadsheet
---
# What this skill does

Tracks and validates procurement savings initiatives from claimed value through finance-recognized realization, distinguishing savings type (hard/cost-reduction vs. soft/cost-avoidance) and establishing a defensible baseline for each. Produces a savings tracker that reconciles claimed vs. realized value and flags unsupported or double-counted claims. It validates and recommends; finance owns recognition.

# Steps

1. Load each initiative into the spreadsheet from the source the user provides: initiative ID, category, supplier, claimed savings, savings type, baseline method (prior price, budget, market index, or first-bid), start date, and the owner. Flag any initiative missing a documented baseline — an unbaselined claim is unverifiable.
2. Validate each baseline and recompute savings from first principles: (baseline unit price - new unit price) x realized volume, prorated for the period. Compare to the claimed figure; mark variances and any one-time vs. recurring/annualized confusion. Classify type explicitly (hard reduction hits budget; cost-avoidance does not).
3. Check for double counting (same spend claimed by two initiatives), volume assumptions not yet realized, and FX or index movement masquerading as negotiated savings. Tie realized amounts to actuals where available; mark anything resting on projected volume as "forecast, not realized."
4. Report the tracker with columns for baseline, claimed, validated, and realized-to-date, plus a per-initiative status (Validated / Adjusted / Unsupported) and the total reconciled savings — stating baseline assumptions and routing recognition sign-off to finance.

# Notes

The most common errors are an inflated or undocumented baseline, counting cost-avoidance as cash savings, annualizing a one-time event, and double-counting shared spend — each must be caught, not carried. Do not assert realization without tie-out to actuals; "forecast" and "realized" are different columns for a reason. This is a validation/recommendation step — finance, not this skill, recognizes savings to the P&L. Do not use it to set targets or to model future-year savings (that is forecasting, not tracking).

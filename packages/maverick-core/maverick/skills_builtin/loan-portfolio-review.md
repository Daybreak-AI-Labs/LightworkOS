---
name: loan-portfolio-review
triggers:
  - review a loan portfolio
  - assess loan quality
  - check portfolio concentration
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Reviews the credit quality of a loan portfolio by profiling risk-grade distribution, delinquency and non-accrual trends, and concentration exposures (industry, geography, single-obligor, collateral type). Produces a portfolio review pack with a risk-grade migration view, a concentration table against limits, and a flagged-exposures list.

# Steps

1. Pull the loan book from the source-of-record with `sql_query` (balance, risk grade, days past due, accrual status, industry/NAICS, region, collateral, origination date); confirm the as-of date and that the grade scale matches the current policy.
2. Profile quality: tabulate balance and count by risk grade, compute delinquency buckets (30/60/90+ DPD), non-accrual and classified (special-mention/substandard/doubtful) totals, and grade migration vs the prior period if available.
3. Compute concentrations in `spreadsheet`: top-N obligors, industry and geographic shares, collateral mix; compare each against the portfolio's stated concentration limits and flag breaches or near-breaches.
4. Assemble the review pack — quality summary, migration, concentration-vs-limit table, and a list of materially adverse or limit-breaching exposures — and hand off stating the as-of date, grade-scale version, and any segments excluded or with missing data.

# Notes

Output is misleading if balances are pulled at an inconsistent as-of date, if the risk-grade scale changed mid-period (migration becomes noise), or if participations/syndications are double-counted. Mark exposures with missing grade or collateral data rather than dropping them silently. This is a review deliverable for a credit committee or chief credit officer to act on — it recommends, it does not reclassify or charge off any loan. Do not use as a substitute for a per-credit deep dive on the flagged names.

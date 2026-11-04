---
name: rent-roll-analysis
triggers:
  - rent roll
  - tenant analysis
  - lease expirations
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Turns a property's raw rent roll into a structured analysis of in-place income quality: weighted-average lease term (WALT), lease-rollover schedule by year, and tenant/industry concentration. Produces a tabular summary plus flagged risks (near-term expirations, single-tenant dependence, below-market rents) that a credit or acquisitions analyst can act on.

# Steps

1. Load the rent roll from its source (`sql_query` against the asset DB, or `spreadsheet` for an uploaded file). Confirm the unit of each column — annual vs. monthly rent, NNN vs. gross, SF vs. units — before any math; do not assume.
2. Normalize each tenant row: occupied SF/units, in-place base rent (annualized), lease start/end, and any escalations or options. Reconcile the total against the property's stated occupancy and gross potential rent; note discrepancies rather than silently adjusting.
3. Compute WALT (SF- or rent-weighted, state which), then build the rollover schedule: % of income/SF expiring each year for the next 5-10 years. Compute concentration: top-5 tenant share of income, and largest single-industry share.
4. Report a summary table (WALT, occupancy, rollover by year, concentration) with a short risk note. State every assumption (weighting basis, treatment of vacant and month-to-month units, mid-lease renewals) and mark any field that was missing or inferred.

# Notes

Output is wrong if rent periodicity is mixed (monthly summed as annual) or if vacant/MTM units are counted as in-place term — these are the common errors; isolate them explicitly. Distinguish executed leases from LOIs/proposals. This is analysis, not underwriting: recommend, do not commit capital or sign anything. Do not use for a single-tenant net lease where rollover analysis is trivial, or when the rent roll lacks lease dates (WALT is uncomputable — say so).

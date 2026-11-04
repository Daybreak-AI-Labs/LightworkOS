---
name: stress-test-scenario
triggers:
  - run a capital stress test
  - ccar scenario analysis
  - stress capital under adverse scenario
tools_needed:
  - spreadsheet
---
# What this skill does

Runs a regulatory-style capital stress test (CCAR/DFAST-shaped) by projecting losses, pre-provision net revenue, and risk-weighted assets under a defined macro scenario, then reporting the impact on capital ratios. Produces a scenario impact table and a minimum-CET1-over-horizon summary for each scenario run.

# Steps

1. Load the supervisory or internal scenario path (GDP, unemployment, rates, HPI, equity) and the starting balance sheet, capital stack, and RWA in `spreadsheet`; confirm the scenario source and horizon (typically 9 quarters) before projecting.
2. Map scenario variables to loss drivers — translate macro paths into stressed PD/LGD or net charge-off rates per portfolio, and project pre-provision net revenue and RWA over each quarter; cite the model or factor table behind each mapping.
3. Roll forward capital quarter by quarter: starting CET1 + PPNR - provisions - other losses - dividends/AOCI effects, dividing by stressed RWA to get the ratio path; capture the minimum CET1/Tier-1/leverage ratio across the horizon for each scenario (baseline, adverse, severely adverse).
4. Report the scenario impact table (peak loss, trough capital ratio, quarter of trough) and compare trough ratios against regulatory minimums plus buffers, handing off with assumptions stated (scenario vintage, dividend policy, AOCI treatment, any portfolios proxied).

# Notes

Results are wrong if the scenario vintage is stale, if losses and PPNR are projected on inconsistent quarters, or if RWA is held flat when the scenario implies migration. Mark any portfolio whose loss path is proxied rather than modeled. This is a draft analytic run for the capital-planning/CCAR team to review and challenge — it is not a filed result and does not set the capital plan. Do not use for ad-hoc single-position shocks; this is balance-sheet-wide.

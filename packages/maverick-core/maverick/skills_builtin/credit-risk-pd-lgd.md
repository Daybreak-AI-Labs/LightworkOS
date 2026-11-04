---
name: credit-risk-pd-lgd
triggers:
  - estimate credit risk parameters
  - compute pd lgd ead
  - loss given default and exposure at default
tools_needed:
  - spreadsheet
  - pandas_query
---
# What this skill does

Estimates the three core credit-loss parameters — Probability of Default (PD), Loss Given Default (LGD), and Exposure at Default (EAD) — for a loan or counterparty book, calibrated to rating grades. Produces a parameter table per grade plus an Expected Loss (EL = PD x LGD x EAD) roll-up, suitable as an input to ECL/IFRS-9 or regulatory capital workflows.

# Steps

1. Load the obligor/facility dataset (defaults flag, recoveries, balances, collateral, rating grade) with `pandas_query`; confirm the default definition (e.g. 90+ DPD or non-accrual) and the observation window before computing anything.
2. Estimate PD per rating grade as the realized default rate over the window (defaulted obligors / obligors at start of period); for thin grades, smooth toward a pooled/through-the-cycle rate and flag the small-sample grades.
3. Estimate LGD as 1 minus the recovery rate on resolved defaults (net of collateral and recovery costs, discounted to default date); estimate EAD from drawn balance plus a credit-conversion-factor on undrawn commitments. Use only resolved/closed defaults for LGD — exclude in-flight workouts or mark them as a sensitivity.
4. Assemble the PD/LGD/EAD table by grade in `spreadsheet`, compute EL per grade and total, report sample counts and the calibration window, and hand off stating assumptions (default definition, discount rate, CCF source, any grades on smoothed PDs).

# Notes

Output is wrong if PD and LGD are estimated over mismatched windows, if open workouts inflate apparent recoveries (survivorship), or if EAD ignores undrawn lines. Thin grades produce unstable PDs — never report a single-obligor grade rate as if it were calibrated. These are model estimates for review, not approved risk parameters: a model-validation/credit officer signs off before they feed capital or provisioning. Do not use for a single named exposure where a bespoke expert judgment overrides pooled statistics.

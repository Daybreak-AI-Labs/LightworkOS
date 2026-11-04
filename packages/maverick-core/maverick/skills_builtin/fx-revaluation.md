---
name: fx-revaluation
triggers:
  - fx revaluation
  - currency translation
  - foreign currency remeasurement
tools_needed:
  - spreadsheet
---
# What this skill does

Revalues foreign-currency-denominated balances (monetary assets/liabilities, intercompany loans, foreign-entity trial balances) at period-end rates and reports the resulting gains and losses. Produces an FX revaluation schedule that separates P&L remeasurement impact from the cumulative translation adjustment (CTA) in equity.

# Steps

1. Pull the foreign-currency balances by account and currency from the ledger or trial balance, each with its functional currency and the historical rate it was booked at. Pull the period-end spot rates (and average rates for P&L-translated items) from the treasury rate source; cite the rate source and date, mark any rate you had to interpolate as `ASSUMED`.
2. Classify each balance: monetary items remeasured through P&L (remeasurement, e.g. ASC 830 functional-currency exposures) vs. translation of a foreign entity's statements to reporting currency (assets/liabilities at closing rate, equity at historical, P&L at average) which flows to CTA.
3. In the spreadsheet, compute revalued amounts: restate each balance at the appropriate rate, take the delta versus carrying value, and route it to either FX gain/loss (P&L) or CTA (equity) per the classification.
4. Reconcile: total reval delta = P&L impact + CTA movement, and the CTA roll-forward (opening + current movement) should tie. Report the workbook path, the P&L and CTA splits, the rate sources, and every `ASSUMED` rate for human review.

# Notes

Wrong if monetary vs. non-monetary classification is mixed up (non-monetary items stay at historical rate), if the wrong rate type is used (closing vs. average vs. historical), or if intercompany balances aren't eliminated/flagged consistently on both sides. CTA and P&L routing is judgment-bearing — when functional currency designation is unclear, mark it and escalate rather than guessing. This skill drafts the reval schedule and proposed entries; it does not post to the ledger — a human reviews the classification and approves the journal. Do not use for derivative/hedge revaluation (use hedge-effectiveness-test).

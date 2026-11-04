---
name: flux-analysis
triggers:
  - flux analysis
  - variance explanation
  - why did it move
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Explains period-over-period movements in financial line items (actual vs prior period, or actual vs budget/forecast) at the driver level for a given entity and period. Output is a flux analysis that lists each material movement with its dollar and percent change, the underlying driver, and the transactions or accounts that caused it — only for variances breaching a stated threshold.

# Steps

1. Confirm the comparison basis (MoM, QoQ, YoY, or actual-vs-budget), entity, periods, and the materiality thresholds (a dollar floor AND a percent floor — both must trip to require an explanation). Pull both periods' balances by account or line item with sql_query and compute the delta in dollars and percent.
2. Filter to movements that breach the threshold. For each, drill into the driver: query the contributing transactions, sub-accounts, volume vs rate effects, one-time items, reclasses, or new activity. Tie the explanation to real records — name the vendor/customer/JE/event, not a generic "increased costs."
3. Distinguish recurring drivers from one-time or non-recurring items, and separate true economic change from accounting reclassifications or timing. Cross-check against any related reconciliation or accrual so the explanation is consistent with the close.
4. Report the flux: each material line with prior amount, current amount, dollar delta, percent delta, and the driver-level explanation with source references. State assumptions (thresholds used, comparison basis, FX treatment) and mark any movement you could not fully explain as unexplained rather than guessing. Hand off to the reviewer for sign-off.

# Notes

The analysis is wrong if it explains immaterial noise (threshold not applied), if explanations are generic ("costs went up") instead of driver-level with references, or if a reclass is mistaken for a real economic change. An unexplained material variance must be labeled unexplained — never fabricate a plausible-sounding driver. This skill describes and recommends; it does not adjust the ledger. Cite the queries and transactions behind every driver; mark unverified drivers. Do not use it to tie an account to support (use account-reconciliation) or to size a period-end estimate (use accruals-estimate).

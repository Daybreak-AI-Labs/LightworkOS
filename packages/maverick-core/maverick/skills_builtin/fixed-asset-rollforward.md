---
name: fixed-asset-rollforward
triggers:
  - fixed asset rollforward
  - depreciation schedule
  - capex roll
tools_needed:
  - spreadsheet
---
# What this skill does

Rolls a fixed-asset register and accumulated depreciation forward one period, reconciling opening balances to closing balances through additions, disposals, and period depreciation. Produces a tie-out-ready FA rollforward (gross cost and accumulated depreciation, by asset class) whose net book value foots to the trial balance.

# Steps

1. Load the prior-period closing FA register and depreciation schedule from the spreadsheet; capture opening gross cost, opening accumulated depreciation, and NBV by asset class. Confirm the opening balances tie to the prior closing rollforward — if they do not, stop and flag the break.
2. Pull current-period activity: capitalized additions (with in-service date), disposals/retirements (cost and accumulated depreciation removed, plus proceeds), and any reclasses or impairments. Tag each line to its asset class and useful life; mark any item lacking a source document as unverified.
3. Compute period depreciation per asset using the register's method (straight-line unless stated), prorating additions by in-service date and stopping depreciation on disposed assets. Sum gain/loss on disposals = proceeds − (cost − accumulated depreciation).
4. Build the rollforward: Opening + Additions − Disposals ± Reclass = Closing, for both gross cost and accumulated depreciation, with NBV derived. Foot every column and cross-foot every row; reconcile closing NBV to the GL fixed-asset and accumulated-depreciation accounts. Report the rollforward, the GL variance (target zero), the disposal gain/loss, and any unverified or untied items; state the depreciation method and proration convention assumed.

# Notes

Output is wrong if additions are depreciated for a full period instead of prorated, if disposed assets keep depreciating, or if accumulated depreciation on disposals is not reversed — each breaks the GL tie. Mismatched useful lives or method assumptions silently distort period expense; cite the register's stated convention rather than guessing. A nonzero GL variance is a finding, not a rounding tolerance — investigate before signing off. This is a draft schedule for accountant review; do not post journal entries or finalize disposals from it — a human approves write-offs and impairments. Do not use for tax depreciation (MACRS/bonus) — this is book basis only.

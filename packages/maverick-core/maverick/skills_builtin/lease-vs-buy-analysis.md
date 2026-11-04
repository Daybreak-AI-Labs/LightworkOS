---
name: lease-vs-buy-analysis
triggers:
  - lease vs buy this asset
  - should we lease or purchase
  - financing decision for equipment
tools_needed:
  - spreadsheet
---
# What this skill does

Evaluates whether to acquire an asset by purchasing (cash or debt-financed) versus leasing it, over a common analysis horizon. Produces a side-by-side after-tax cash-flow model with the NPV of each option, the cheaper alternative and its margin, plus the qualitative factors a number cannot capture. The output is a recommendation for a financing decision-maker.

# Steps

1. Collect the real inputs into the spreadsheet: purchase price, useful life and depreciation method, salvage/residual value, lease term, payment schedule and timing, any down payment or end-of-term purchase option, the marginal tax rate, and the discount rate (after-tax cost of capital or incremental borrowing rate). Flag any input that is estimated.
2. Build the BUY cash flows: outflow (or loan amortization with deductible interest), depreciation tax shields, maintenance/insurance borne by owner, and the after-tax salvage inflow at horizon end. Build the LEASE cash flows: periodic payments and their tax deductibility, plus end-of-term obligations (return, renew, or exercise purchase option).
3. Discount both streams at the same after-tax rate to a common horizon and compute each NPV (and equivalent annual cost if terms differ in length). Run sensitivity on the discount rate, residual value, and tax rate since these flip the result most often.
4. Report the NPV table, the recommended option and its dollar/percentage advantage, the sensitivity range, and qualitative factors (balance-sheet/covenant impact, obsolescence and flexibility, maintenance responsibility, ownership of upside, off-balance-sheet vs ASC 842/IFRS 16 capitalization). State assumptions explicitly and hand off; do not commit to a contract.

# Notes

The analysis is wrong if buy and lease are discounted at different rates, if tax shields are omitted on either side, or if terms of unequal length are compared on raw NPV instead of equivalent annual cost. Under ASC 842 / IFRS 16 most leases now hit the balance sheet — do not sell "off-balance-sheet" as an automatic lease advantage; verify classification. Residual/salvage assumptions drive the result; mark them unverified when not contractually fixed. Signing or financing is an irreversible commitment decided by a human; this skill only recommends.

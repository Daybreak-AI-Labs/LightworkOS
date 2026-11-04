---
name: allowance-cecl-roll
triggers:
  - cecl
  - allowance roll
  - loan loss reserve
  - roll forward the credit loss allowance
tools_needed:
  - spreadsheet
---
# What this skill does

Rolls the credit-loss allowance (ACL/CECL) forward one period: beginning balance, provision expense, charge-offs, and recoveries, reconciling to the ending balance. Produces an auditable allowance roll-forward table that ties to the general ledger and supports the provision booked in the income statement.

# Steps

1. Pull the prior-period ending allowance balance from the ledger or last close, segmented the same way the reserve is held (portfolio segment / pool). Note the segmentation source; do not collapse pools.
2. Gather the period's gross charge-offs and recoveries by segment from loan servicing data, and the modeled expected-loss balance (CECL reserve need) for the ending portfolio.
3. In the spreadsheet, build the roll: ending = beginning − charge-offs + recoveries + provision, and SOLVE provision as the plug that brings beginning to the modeled ending reserve. Show net charge-offs separately.
4. Tie the ending balance to the modeled CECL requirement, the provision to the income statement, and report the table with each input's source plus any unverified figures flagged. State assumptions (segmentation, model date, any management overlay).

# Notes

Wrong if the provision is hard-set instead of solved as the plug, or if charge-offs/recoveries are netted before the roll (regulators want gross). A management overlay or qualitative (Q-factor) adjustment is a judgment input — surface it as a distinct line, never bury it in provision. Mark any figure not traced to the ledger as unverified. This produces a draft roll for finance/accounting review; booking the provision entry is an irreversible action a human approves. Do not use for IFRS 9 stage transitions (different model) without confirming the standard in scope.

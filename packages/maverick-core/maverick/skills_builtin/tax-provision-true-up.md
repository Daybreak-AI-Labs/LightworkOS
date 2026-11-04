---
name: tax-provision-true-up
triggers:
  - provision to return
  - true up
  - rttp
tools_needed:
  - spreadsheet
---
# What this skill does

Reconciles the income-tax provision booked in the financial statements to the amounts on the as-filed tax return (the return-to-provision, or RTTP, true-up). Produces a provision-to-return true-up schedule that lists each book-vs-return difference, the resulting current and deferred tax adjustments, and the net journal entry to record. Output is a draft adjustment for tax-department review.

# Steps

1. Load the two source figures into a spreadsheet: the estimated provision (current tax, deferred items, by jurisdiction) and the corresponding as-filed return amounts. Use the actual filed return and booked provision on record — do not estimate either side; flag any line missing a source.
2. Line up each component (taxable income, permanent differences, temporary differences, credits, payments/estimates, apportionment) and compute the per-line variance between provision and return.
3. Classify each variance as current vs deferred and as a true-up to tax expense vs a balance-sheet reclass; carry temporary-difference variances into the deferred tax asset/liability rollforward so DTA/DTL ties out.
4. Produce the true-up schedule plus the proposed net journal entry (debit/credit, account, jurisdiction), and hand off to the tax lead. State assumptions (rates used, jurisdictions in scope) and list any unreconciled difference left open.

# Notes

The output is wrong if temporary-difference true-ups are run through current tax expense instead of deferred, or if the deferred rollforward no longer ties after the adjustment — always re-foot the DTA/DTL. Use the as-filed return, not a draft, or the true-up reverses next period. Verify the statutory/blended rate against the period; do not assume a prior-year rate. This is a draft journal entry: posting to the ledger and any restatement decision belong to the controller/tax director. Do not use before the return is actually filed, or for jurisdictions where no provision was originally booked.

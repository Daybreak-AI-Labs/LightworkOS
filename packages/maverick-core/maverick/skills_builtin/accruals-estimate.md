---
name: accruals-estimate
triggers:
  - accrual
  - accrue
  - period end estimate
tools_needed:
  - spreadsheet
---
# What this skill does

Estimates and supports period-end accruals (expenses incurred but not yet invoiced, or revenue earned but not yet billed) for a given entity and period. Output is an accrual schedule documenting each accrual's amount, estimation basis, supporting evidence, the proposed journal entry, and the reversal plan for the following period.

# Steps

1. Confirm the period, entity, and the accrual population to assess — recurring accruals from the prior period's schedule plus any new known obligations (open POs, signed contracts, services received, period-end bonus/commission, utilities, professional fees). Load the prior-period accrual schedule via spreadsheet as the baseline so recurring items are not missed.
2. For each accrual, select an estimation basis and document it: actuals-to-date run-rate, contract/PO amount prorated to period-end, vendor estimate, or a percentage-of-completion. Compute the accrual amount and attach the support (PO number, contract clause, vendor email, prior invoice trend). Do not accrue an amount with no basis.
3. Compare the new estimate to the prior accrual and to the eventual actual where known (true-up). Flag accruals that have consistently over- or under-estimated so the basis can be corrected, and note any accrual being released because the underlying invoice arrived.
4. Report the accrual schedule: per item — amount, basis, support reference, proposed JE (debit/credit accounts), and reversal/true-up plan (auto-reverse next period vs. carry). State assumptions (proration method, FX, cutoff) and stage the journal entries for a human preparer/reviewer to post — recommend, do not post.

# Notes

The schedule is wrong if an accrual has no documented basis, if the prior-period baseline was ignored (recurring accrual dropped), or if a reversal plan is missing (accruals that never reverse double-count expense). Persistent over/under-accrual is a basis problem — surface the trend, don't just re-book last month's number. This skill estimates and recommends; posting and releasing accruals are the human's call. Cite the support for every accrual; mark any estimate lacking hard support as unverified judgment. Do not use it to explain why a balance moved (use flux-analysis) or to tie an account to support (use account-reconciliation).

---
name: compensation-dispute-review
triggers:
  - commission dispute
  - comp dispute
  - pay query
  - my commission looks wrong
tools_needed:
  - spreadsheet
  - sql_query
---
# What this skill does

Reviews a sales-compensation or commission dispute by reconstructing the disputed
payout from source deal/quota data against the governing comp plan, and producing a
defensible review that states the recomputed amount, the variance from what was paid,
and the exact plan clause that drives the result. Output is a draft determination for a
comp/finance owner to approve — it does not adjust pay.

# Steps

1. Capture the dispute facts from the claimant: rep, pay period, the figure they
   expected vs. what they were paid, and the specific deals/quota in question. Note any
   figure you could not get in writing as unverified.
2. Pull the source data with `sql_query` (closed-won deals, amounts, close/booking
   dates, splits, clawbacks, quota attainment for the period) and the rep's plan terms
   (rate, accelerators/decelerators, caps, draw, payout timing, crediting rules).
3. Recompute the commission line by line in a `spreadsheet`: attainment to tier,
   apply rate/accelerators, splits, caps, and any clawback or draw recovery. Show the
   formula per deal so the math is auditable; flag any deal whose credit timing or
   eligibility is ambiguous under the plan.
4. Compare recomputed vs. paid, isolate the root cause to a specific plan clause or a
   data error (e.g., wrong close date, missing split, tier mis-applied), and report the
   variance, the cited clause, and a recommended adjustment — stating assumptions and
   marking any unverified input. Hand off to the comp/finance owner; do not change pay.

# Notes

The output is wrong if you recompute against the wrong plan version (plans change by
period — match the plan effective for the disputed period) or against pre-clawback/raw
deal data instead of credited bookings. Crediting and split rules are the usual culprit
and must be cited from the plan text, not assumed. Mark any figure the claimant gave
verbally as unverified until confirmed in the system of record. This is a draft
determination only: pay adjustments, clawback reversals, and exceptions are irreversible
financial actions and require a human comp/finance approver. Do not use for designing a
new plan or for non-quota incentive pay (use the relevant comp-design procedure).

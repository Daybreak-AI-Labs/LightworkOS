---
name: lease-classification-asc842
triggers:
  - asc 842
  - lease accounting
  - classify a lease as finance vs operating
tools_needed:
  - spreadsheet
---
# What this skill does

Classifies a single lease as finance or operating under ASC 842 and measures the initial right-of-use (ROU) asset and lease liability. Produces a worksheet that documents the five classification tests, the discounted payment schedule, and the day-one journal entries, so a controller can post and a reviewer can re-perform the math.

# Steps

1. Pull the lease terms from the executed contract: commencement date, lease term (including reasonably certain renewals/terminations), fixed payments per period, variable payments tied to an index, residual-value guarantees, purchase options, and any incentives or initial direct costs. Record the source document and page for each input; mark any term you inferred as unverified.
2. Determine the discount rate: use the rate implicit in the lease if readily determinable, otherwise the lessee's incremental borrowing rate for the term and currency. State which rate was used and why.
3. Apply the five ASC 842-10-25-2 classification tests in a spreadsheet (transfer of ownership; reasonably certain purchase option; lease term ≥ major part of remaining economic life; PV of payments + guaranteed residual ≥ substantially all of fair value; specialized-asset/no-alternative-use). If any test is met, classify as finance; otherwise operating. Show each test's pass/fail with its computed value.
4. Build the payment schedule, discount it to the lease liability, set the ROU asset (liability + prepaid/initial direct costs − incentives), and generate the day-one entry plus the period-1 amortization split. Report the classification, ROU asset, liability, and discount rate, stating which inputs were inferred vs. sourced, and hand off to the controller for posting.

# Notes

Output is wrong if the term omits reasonably-certain options, if variable index-based payments are excluded from the liability, or if the wrong discount rate is applied — all three change classification and measurement. Short-term leases (≤12 months) may use the practical expedient; flag rather than auto-apply. This is a draft for accounting review: do not post journal entries automatically — a qualified preparer approves. Do not use for lessor accounting, sale-leaseback, or non-US-GAAP (IFRS 16 has no operating/finance split for lessees).

---
name: rate-case-cost-of-service
triggers:
  - rate case
  - cost of service
  - revenue requirement
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a cost-of-service study supporting a regulated utility rate filing: derives the revenue requirement from rate base, allowed return, expenses, and taxes, then functionalizes, classifies, and allocates costs to customer classes. Output is a documented workbook a regulatory team can defend before a commission.

# Steps

1. Assemble the test-year inputs in spreadsheet from the filing record: rate base (net plant + working capital - accumulated deferred taxes), O&M expense, depreciation, taxes, and the commission-authorized rate of return — cite the source schedule/account for each figure; mark any placeholder as unverified.
2. Compute the revenue requirement: RR = (rate base x allowed return) + operating expenses + depreciation + taxes. Show the return, expense, and tax components separately and reconcile total to the filing's stated ask.
3. Functionalize costs (production/transmission/distribution/customer), classify (demand/energy/customer), and allocate to classes using documented allocation factors (e.g., coincident-peak demand, energy throughput, customer count); keep each allocator and its driver traceable in the workbook.
4. Produce the class revenue requirement and resulting cost-based unit costs, compare to present revenues to show each class's subsidy/rate-of-return, and hand off with every assumption, allocation factor, and jurisdictional adjustment stated, noting which figures are unverified pending the filing record.

# Notes

Wrong if the test year is inconsistent (mixing historical and forecast bases), allocation factors don't match the jurisdiction's approved methodology, or known regulatory adjustments (disallowances, normalization, riders) are skipped — results then misstate the requirement and invite intervenor challenge. This study recommends; the filed revenue requirement, class allocations, and resulting rate design are decisions for the regulatory team and ultimately the commission. Do not use for unregulated/competitive offerings, which are not cost-of-service ratemaking.

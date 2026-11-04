---
name: cost-allocation-driver
triggers:
  - cost allocation
  - allocate overhead costs
  - shared services chargeback
tools_needed:
  - spreadsheet
---
# What this skill does

Assigns shared, indirect, or overhead costs to cost objects (departments, products, projects, entities) using defensible drivers. Produces an allocation model showing each cost pool, its driver, the absorption rate, and the resulting charge per object, so the splits are transparent, reconcilable to the total, and survive an audit or intercompany review.

# Steps

1. Define the cost pools to allocate (e.g., IT, facilities, HR, corporate) and pull their actual total cost from the source ledger — cite the GL account/period. Confirm the grand total you will allocate; every dollar must land somewhere and the model must foot back to it.
2. Choose a driver for each pool that has a causal link to consumption (headcount for HR, square footage for facilities, ticket count or seats for IT, revenue or machine-hours for production overhead). Record the driver source and date; mark any driver you estimated rather than measured.
3. Compute the absorption rate per pool (pool cost ÷ total driver units) and multiply by each object's driver units to get its charge. Handle reciprocal services (e.g., IT serves HR and vice versa) with a step-down or simultaneous-equation method, and state which you used.
4. Reconcile total charges to the pool totals (must equal — show the tie-out), surface the largest few allocations and any object whose charge moved sharply vs. prior period, and report the rates and basis. State driver assumptions and hand off; do not push intercompany or chargeback journal entries automatically — recommend them for finance approval.

# Notes

The model is wrong if allocations don't foot to the source total, if a driver has no causal link to the cost (allocating IT by revenue when usage is by seat invites disputes), or if reciprocal services are ignored and double-count. Beware drivers that are themselves outputs of the allocation (circularity). This produces recommended charges; intercompany billing, transfer-pricing entries, and customer-facing chargebacks are irreversible and need a human owner — stage, don't post. Not a substitute for activity-based costing where per-transaction precision is required.

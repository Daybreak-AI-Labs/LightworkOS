---
name: zero-based-budget
triggers:
  - zero based budget
  - zbb
  - justify spend
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a zero-based budget for a cost area by rebuilding spend from zero rather than adjusting prior-year actuals. Decomposes the area into cost packages, each justified by the activity and volume that drives it, and assembles a budget package showing what is funded, what is cut, and the rationale for every line.

# Steps

1. Define the cost area and its baseline: pull current/prior-year actual spend by line item from the source the user provides, so the zero-based build can be compared against today's run-rate. Cite the baseline source; do not assume figures.
2. Decompose the area into cost packages (discrete activities or services, e.g. "tier-2 support coverage", "MarTech stack", "office facilities"). For each, identify the driver (tickets, headcount, seats, sq ft) and the unit cost, sourced or marked as an assumption.
3. In the spreadsheet, build each package from its driver x unit cost at the volume the business actually requires — not last year's number — and tier each package as essential / important / discretionary with a one-line justification. Sum to the zero-based total.
4. Compare zero-based total vs baseline, rank packages by value-for-cost, show the savings from de-funding discretionary tiers, and hand off the package. State driver assumptions per line and flag every proposed cut for owner review.

# Notes

The budget is wrong if "required volume" is just last year's volume relabeled (that defeats zero-based) or if shared/allocated costs are missed or double-counted across packages — reconcile the package sum back to the total cost area. Tiering is a recommendation; de-funding a package is an irreversible-feeling decision that the budget owner and Finance must approve before execution. Don't use ZBB for trivial or fixed-by-contract spend where the effort exceeds the savings, or when there's no time to justify each line — use incremental benchmarking instead.

---
name: network-optimization
triggers:
  - network optimization
  - distribution network
  - facility siting
tools_needed:
  - spreadsheet
  - pandas_query
---
# What this skill does

Analyzes and recommends a supply-chain distribution network design: which facilities (DCs, plants, cross-docks) to operate and which demand each should serve. Produces a cost-to-serve breakdown per lane/customer and a facility-siting recommendation comparing the current footprint against candidate alternatives. Output is a decision-support analysis, not an executed network change.

# Steps

1. Load the network inputs into pandas_query: customer demand by location, existing facility list with fixed/variable costs and capacities, freight rates (inbound + outbound) by lane, and candidate sites. Confirm units (volume, weight, currency, period) and flag any missing fields before modeling.
2. Build cost-to-serve per customer: assign each demand point to its lowest-landed-cost facility (transport + handling + facility variable cost), summing inbound, outbound, and fixed-cost allocation. Respect capacity constraints; if demand exceeds capacity, note the overflow rather than silently reassigning.
3. Run scenarios in the spreadsheet: baseline (current footprint) vs. each candidate siting option (add, close, or relocate). For each, compute total landed cost, average cost-to-serve, service distance/time, and capacity utilization.
4. Report the recommended footprint with the cost delta vs. baseline, the cost-to-serve table, and siting rationale. State assumptions (rates held flat, demand forecast horizon, no lead-time modeling) and mark facility open/close as a staged recommendation for a human to approve.

# Notes

Output is wrong if freight rates are stale, demand is double-counted across periods, or capacity constraints are ignored (produces an infeasible "optimal" network). This is a heuristic lowest-cost assignment, not a solver-grade MILP — flag it as such; for tightly constrained problems recommend a dedicated optimizer. Siting decisions are capital-intensive and irreversible: always present as a recommendation with sensitivity to demand/rate swings, never auto-commit. Do not use for real-time routing (use transportation-optimization) or intra-facility layout (use warehouse-slotting).

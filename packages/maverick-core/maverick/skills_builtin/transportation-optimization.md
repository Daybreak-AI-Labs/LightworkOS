---
name: transportation-optimization
triggers:
  - transportation optimization
  - routing
  - mode selection
tools_needed:
  - spreadsheet
  - pandas_query
---
# What this skill does

Builds a transportation plan that selects the lowest-cost feasible mode (parcel, LTL, FTL, intermodal, air) per shipment and sequences stops into routes that respect capacity and time-window constraints. Produces a shipment-level plan with mode assignment, route grouping, and the cost/service trade-offs behind each choice. Output is a planning recommendation a dispatcher or planner approves before tendering.

# Steps

1. Load shipments into pandas_query: origin, destination, weight/volume/units, ready time, delivery window, and service requirement. Load the rate basis (parcel zone, LTL class/weight breaks, FTL per-mile + minimums, accessorials) and vehicle/equipment capacities. Confirm units and flag shipments missing a window or weight.
2. For each shipment compute the landed cost under every eligible mode, honoring weight breaks, minimum charges, and transit-time vs. delivery-window feasibility. Eliminate modes that miss the window; keep the cost of the next-feasible option for the trade-off view.
3. Consolidate compatible shipments (same lane/day, under vehicle capacity) and sequence multi-stop routes to minimize distance/time while respecting windows and max drive/duty limits. In the spreadsheet compare consolidated routing vs. shipment-by-shipment to quantify savings.
4. Report the plan: per-shipment mode + route assignment, total cost, the cheaper-but-infeasible alternatives flagged for visibility, and overall consolidation savings vs. baseline. State assumptions (rates current, no live traffic/ELD modeling, deterministic transit times) and stage the plan for planner approval before carrier tender.

# Notes

Output is wrong if weight breaks or minimum charges are mis-applied (LTL/parcel costs swing hard at breakpoints), if time windows are ignored (a cheaper mode that arrives late is not feasible), or if capacity is exceeded on a consolidated route. Routing here is heuristic nearest-neighbor/savings, not a guaranteed-optimal VRP solver — flag it; escalate dense/large fleets to a dedicated solver. Tendering to carriers is an external commitment: stage the plan, do not auto-tender. Do not use for facility footprint decisions (use network-optimization).

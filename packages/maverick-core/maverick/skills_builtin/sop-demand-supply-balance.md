---
name: sop-demand-supply-balance
triggers:
  - run the S&OP cycle
  - reconcile demand and supply for this month
  - prepare the S&OP review package
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Runs the Sales & Operations Planning (S&OP) reconciliation for a planning horizon and produces the executive review package. Output: a consensus demand plan vs. constrained supply plan by product family / period, the projected inventory or backlog position, an explicit list of gaps (shortfalls, excess, capacity constraints) with options and financial impact, and the decisions/escalations a human leadership team must make.

# Steps

1. With sql_query, assemble the demand signal: statistical forecast, sales/marketing overrides, open orders, and committed pipeline by product family and period over the planning horizon. Reconcile the consensus demand number and show how each adjustment moves it off the baseline forecast — keep overrides attributable, never silently merged.
2. With sql_query, assemble the supply picture: on-hand inventory, scheduled production/purchase receipts, and capacity/material constraints (lines, suppliers, lead times). In the spreadsheet, build the projected available balance per family per period (opening inventory + supply − demand) to expose where it goes negative (shortfall) or excessive (overstock).
3. Identify and size the gaps: for each shortfall/excess quantify volume, the period it bites, and revenue-at-risk or excess-inventory carrying cost. Draft balancing options (expedite, build-ahead, reallocate, overtime, defer/substitute, demand-shaping) with feasibility and cost — present trade-offs, do not unilaterally pick.
4. Assemble the S&OP package in the spreadsheet (demand vs. constrained supply, inventory/backlog projection, gap and decision log, assumptions and data-as-of date) and report it for the consensus/executive review. State assumptions and hand off — the plan is a recommendation; leadership owns the demand/supply trade-off and any commitment.

# Notes

The package is wrong if demand and supply are pulled as-of different dates (the balance won't tie), if forecast overrides are baked in without attribution (no one can challenge them), or if gaps are shown without financial impact (leadership can't prioritize). Constrained supply must respect real capacity and lead times — an unconstrained plan that "meets" demand is fiction. Cite the source system and data-as-of timestamp for every number; mark forecast and override figures as planning assumptions, not actuals. Production commitments, expedites, and purchase orders are costly and binding: this skill stages options for human decision in the S&OP review; it does not place orders or release the plan. Not for daily/short-horizon execution scheduling (MRP/dispatch) — S&OP is the aggregate, multi-period balancing layer.

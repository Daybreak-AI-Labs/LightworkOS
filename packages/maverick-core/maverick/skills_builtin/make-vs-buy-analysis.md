---
name: make-vs-buy-analysis
triggers:
  - should we make or buy this part
  - outsource decision for this component
  - insource vs supplier analysis
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a make-vs-buy (insource vs outsource) sourcing decision for a specific component, subassembly, or service by comparing total cost of ownership of each option across the relevant volume and horizon, then surfacing the non-cost factors that can override cost. Produces a TCO comparison and a recommendation with a stated breakeven volume.

# Steps

1. Confirm the decision scope: the exact part/service, annual volume (and its uncertainty), the time horizon, and whether internal capacity already exists or must be built. Gather the cost inputs for both options — make: direct material, direct labor, variable overhead, tooling/capex, and capacity opportunity cost; buy: unit price, tooling/NRE, inbound logistics, incoming inspection, and supplier management overhead. Mark any input you could not source as an assumption.
2. In a `spreadsheet`, model TCO per option over the horizon at the expected volume, keeping fixed and variable costs separate. Compute the breakeven volume where make and buy cross, and run the volume up/down to show sensitivity. Use fully loaded internal rates, not direct labor alone — partial costing is the classic way make looks falsely cheap.
3. Score the qualitative factors that cost alone misses: IP/strategic control, quality and lead-time risk, supplier concentration and switching cost, capacity flexibility, and regulatory/compliance exposure. Note where a qualitative factor should override the cheaper option.
4. Report the TCO comparison, breakeven volume, sensitivity, and a clear recommendation tied to the expected volume and the qualitative overrides. State every cost assumption and the horizon. Frame it as a recommendation; the sourcing commitment is a human/governance decision.

# Notes

The analysis is wrong if make costs exclude capex/tooling amortization, opportunity cost of capacity, or overhead — these make insourcing look artificially cheap. A single-point volume estimate is fragile; always show breakeven and sensitivity so the reader sees how robust the call is. Do not treat a quoted unit price as TCO — add NRE, logistics, inspection, and supplier-management cost. Not for picking among multiple existing suppliers (that is a supplier-selection/RFQ task) and not for a build-vs-buy software platform decision unless cost structure is genuinely comparable.

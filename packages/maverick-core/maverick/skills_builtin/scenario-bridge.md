---
name: scenario-bridge
triggers:
  - scenario bridge
  - case comparison
  - base bull bear walk
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a waterfall ("bridge") that explains the gap between two scenario outcomes (e.g. base -> bull, or forecast -> actual) by attributing the total delta to individual drivers. Produces a scenario bridge with driver-level deltas that sum exactly to the end-to-end change.

# Steps

1. Pin the start and end scenarios, each with its outcome value and full set of driver inputs from a sourced model. Confirm both outcomes are verified; record the total delta to be explained.
2. List the drivers that differ between scenarios. Attribute the delta by flipping one driver at a time from its start to its end value (sequential walk), recording the marginal change each flip produces; hold a fixed flip order and disclose it, since order affects interaction allocation.
3. Sum the driver-level deltas and reconcile to the total change — the bridge must close to zero residual. Park any unexplained gap as an explicit "interaction/other" bar rather than silently absorbing it.
4. Render the waterfall start -> drivers -> end and return the contribution table. Report the largest contributors, the flip order used, and any residual, noting assumptions.

# Notes

The bridge is wrong if the bars do not sum to the actual start-to-end delta, or if a residual is hidden inside a driver bar. With interacting drivers, attribution depends on flip order — state it; do not present one ordering as the unique truth. This explains a difference; it does not endorse a scenario or trigger any action. Do not use when the two scenarios share no comparable driver structure.

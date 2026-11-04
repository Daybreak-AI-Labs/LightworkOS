---
name: capacity-planning-ops
triggers:
  - capacity planning
  - capacity model
  - resource planning
tools_needed:
  - spreadsheet
---
# What this skill does

Models available operational capacity against forecast demand across a planning horizon to surface utilization, slack, and bottlenecks. Produces a capacity plan (demand vs. effective capacity by period and resource) that operations leaders use to decide on hiring, shifts, overtime, or load deferral.

# Steps

1. Gather the real inputs into the spreadsheet: demand forecast per period (units or work-hours), the resource set (people, machines, lines), nominal capacity per resource, and the planning horizon. Mark any forecast that is an assumption versus a committed order — never invent demand to fill a horizon.
2. Convert nominal capacity to EFFECTIVE capacity per period by applying real availability factors: shift hours, utilization/uptime, planned downtime/maintenance, absenteeism, and yield/scrap. State each factor and its source; an unadjusted "nameplate" capacity will overstate what is achievable.
3. Compute load per period (demand translated to required hours/units via standard rates), then utilization = load / effective capacity, and slack = effective capacity − load. Flag periods where utilization exceeds a threshold (e.g. >85–90%) as at-risk and any period over 100% as overloaded.
4. Identify the bottleneck resource(s) — the lowest effective-capacity step gating throughput — and summarize the plan with options (overtime, added shift, hire, defer/level demand). Hand off the period-by-period table and report the availability factors and forecast assumptions used.

# Notes

Wrong if nameplate capacity is used without availability factors, if demand and capacity are in mismatched units (units vs. hours — convert via standard rates), or if a single aggregate hides a stage-level bottleneck (model the constraining step, not just totals). Capacity-add recommendations (hiring, capex, shift changes) are irreversible and costly — present as options for a human to decide, do not commit. Do not use for finite scheduling/sequencing; this is rough-cut capacity, not a detailed schedule.

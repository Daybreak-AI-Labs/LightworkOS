---
name: workforce-capacity-plan
triggers:
  - workforce plan
  - headcount plan
  - capacity planning
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a workforce capacity plan that quantifies the gap between demand (work that must be delivered) and supply (current and projected headcount), then produces a hiring/redeployment model to close it. Output is a per-team, per-period plan showing required FTE, available FTE, the net gap, and a phased hiring schedule with cost implications.

# Steps

1. Pull demand drivers and current roster from source systems: query HRIS for active headcount by team/role/level and query the demand source (ticket/case volume, pipeline, production targets, or a stated business plan) via `sql_query`. Record the time horizon and granularity (e.g. monthly for 4 quarters) actually requested.
2. Convert demand to required FTE using an explicit productivity assumption (units per FTE per period) — pull the rate from historical actuals if available, otherwise mark it as an assumption and state the value used. Compute available FTE from current roster minus expected attrition (use the org's observed attrition rate; flag if unknown).
3. In a `spreadsheet`, lay out periods as columns and teams/roles as rows; compute required FTE, available FTE, and gap = required − available for each cell. Add a hiring model row that distributes net hires across periods accounting for time-to-fill and ramp-to-productivity lag.
4. Summarize the gap, the recommended hiring/redeployment schedule, and total incremental cost; hand off to the requester. State every assumption (productivity rate, attrition, time-to-fill, ramp) explicitly and flag which were derived from data vs. estimated.

# Notes

The plan is wrong if demand-to-FTE conversion uses a fabricated productivity rate — always source it from actuals or mark it unverified. Attrition and ramp lag are the two most common omissions and both understate the gap. Do not auto-execute hiring: this skill produces a recommended plan for a human (HR/finance/leadership) to approve, since headcount commitments are budget-irreversible. Not for individual role backfills or org-design/restructuring questions — use it only when planning aggregate capacity against a demand signal.

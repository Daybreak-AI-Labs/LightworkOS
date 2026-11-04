---
name: store-labor-scheduling
triggers:
  - build next week's store schedule
  - match staffing to traffic
  - workforce scheduling for the store
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a store labor schedule that matches staffed hours to forecast demand by daypart, covering required tasks and service levels at the lowest viable labor cost within scheduling and budget constraints. Produces a shift-level schedule by day and role with demand-matched coverage and a labor-cost summary.

# Steps

1. Pull with `sql_query` the demand drivers (forecast or trailing traffic/transactions/sales by day and daypart), the labor standard (hours per unit of demand or required coverage per task), available associates with roles, pay rates, and availability/max-hours, plus the labor-hour or labor-percent budget. Use real roster and forecast data; do not invent associates or availability.
2. Translate demand into required headcount per daypart per role using the labor standard, including fixed coverage (open/close, minimum-staffing/safety) regardless of traffic.
3. Assign associates to shifts honoring availability, max hours, required breaks/rest rules, and role qualifications; minimize over/under-coverage versus the requirement and keep total cost within budget. Flag any daypart that cannot be covered with the available roster.
4. Output the schedule in a `spreadsheet`: associate, role, day, shift start/end, hours, and a coverage-vs-requirement and cost line per daypart. Report total scheduled hours, labor cost versus budget, and any coverage gaps; state forecast assumptions and hand off for manager approval.

# Notes

Output is wrong if it violates availability or labor/break-compliance rules, schedules someone into overtime unintentionally, or leaves a daypart below minimum staffing. A schedule that hits budget but misses peak coverage is a failure — surface gaps rather than silently understaffing. This skill drafts a proposed schedule; it does not publish shifts or notify associates — a manager reviews compliance and approves before posting. Do not use for long-range headcount/hiring planning or for a single one-off shift swap.

---
name: workforce-plan-build
triggers:
  - workforce plan
  - headcount plan
  - capacity plan
  - build a hiring model
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a workforce/headcount plan that reconciles labor SUPPLY against DEMAND over a defined horizon and produces a hiring/attrition model with the resulting gap and cost. Handles the goal class "how many people, in which roles, by when, and what does it cost" — output is a defensible plan a finance partner can challenge line by line.

# Steps

1. Establish demand with `sql_query` and stakeholder inputs: required FTE by role/function/period, driven by the actual demand signal (revenue plan, ticket volume, production targets, project pipeline). Record the driver and the productivity ratio (units per FTE) you applied for each role.
2. Establish supply: pull current headcount by role, then project forward applying attrition (use trailing 12-month actuals by role, not a flat company average), planned internal moves, and in-flight requisitions. Net supply against demand to get the gap per role per period.
3. In `spreadsheet`, build the hiring model: open roles, time-to-fill and ramp time per role, monthly hires needed to close the gap on time, and fully-loaded cost (salary + on-cost multiplier). Add a scenario toggle for at least base / stretch / constrained demand so the plan isn't single-point.
4. Output the plan: supply-vs-demand bridge, gap by role and period, hiring schedule, and total cost by scenario. End by reporting assumptions explicitly (attrition rate source, productivity ratios, on-cost multiplier, horizon) and hand off to Finance/HRBP for sign-off.

# Notes

Wrong if it uses a single blended attrition rate (hides role-specific churn), ignores time-to-fill and ramp (a Q4 gap can't be closed by a Q4 hire), or omits the on-cost multiplier (understates cost 25-40%). Mark any number that came from a stakeholder estimate rather than system data as "input, unverified." This skill DRAFTS a plan; approving requisitions, budget, or RIF actions are irreversible and reserved for a human leader. Do not use for individual comp decisions or for legally sensitive reductions without HR/legal in the loop.

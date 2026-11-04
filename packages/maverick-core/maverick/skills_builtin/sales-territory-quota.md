---
name: sales-territory-quota
triggers:
  - territory quota
  - quota setting
  - capacity planning
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a territory and quota plan: assigns accounts/segments to reps, sets per-rep quotas, and checks the plan for balance (even opportunity across reps) and attainability (quotas grounded in capacity and historical attainment). Produces a territory map plus a quota table with the math shown — TAM/pipeline per territory, headcount, ramp, and a top-down/bottom-up reconciliation a sales leader can approve.

# Steps

1. Pull the inputs with sql_query: account universe with firmographics and segment, historical bookings by account/rep, current pipeline, rep roster with hire/ramp dates, and the company revenue target. Note coverage gaps (e.g. accounts with no owner, reps with no history) and never fabricate account values or attainment rates.
2. Segment and balance territories in a spreadsheet: distribute accounts so each territory has comparable potential (weighted TAM + active pipeline + prior bookings). Compute a balance metric (e.g. max/min potential ratio or coefficient of variation across territories) and rebalance until the spread is defensible.
3. Set quotas bottom-up and top-down: bottom-up from territory potential x expected win rate, adjusted for rep ramp (prorate quota for partial-tenure reps); top-down by allocating the company target across territories. Reconcile the two and surface the gap explicitly.
4. Test attainability: compare each proposed quota to the rep's (or comparable rep's) historical attainment and to ramp stage. Flag quotas above a sensible multiple of trailing attainment as STRETCH/at-risk; flag thin territories that can't support their quota.
5. Report the plan: territory assignment table, quota table with the derivation shown, balance and attainability metrics, and a list of flagged territories/reps. State assumptions (win rate, ramp curve) and hand off to sales leadership and ops for approval before quotas are communicated.

# Notes

The plan is wrong if balance is asserted without a computed metric, if ramping reps carry full quota, or if the bottom-up sum and top-down target are never reconciled (a plan that doesn't add up to the number). Quotas drive comp and are demotivating to reset mid-period: this skill drafts and recommends — a sales leader approves and a human communicates them. Garbage-in risk is high: if sql_query returns sparse history or unowned accounts, say so and mark affected quotas UNVERIFIED rather than guessing. Do not use to retroactively adjust an in-flight quota dispute (that's a comp/ops exception, not territory planning).

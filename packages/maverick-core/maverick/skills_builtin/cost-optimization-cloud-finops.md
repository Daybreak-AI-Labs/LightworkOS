---
name: cost-optimization-cloud-finops
triggers:
  - reduce our cloud spend
  - run a FinOps cost optimization
  - where is cloud cost being wasted
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Analyzes cloud billing and utilization data to find concrete, quantified spend-reduction opportunities. Output: a FinOps analysis covering rightsizing of over-provisioned resources, idle/orphaned waste, commitment coverage (Reserved Instances / Savings Plans / CUDs), and storage/data-transfer tiering — each line with an estimated monthly saving, effort, and risk, rolled up into a prioritized savings roadmap.

# Steps

1. With sql_query, pull the cost and usage detail from the billing export (e.g. CUR/FOCUS/billing dataset): cost by service, account, region, tag/owner, and resource over a representative trailing window (>= 30 days, ideally 90 to capture monthly cycles). Reconcile the total against the actual invoice before analyzing — if tagging coverage is low, report that as a finding, since untagged spend can't be allocated.
2. Find waste and rightsizing candidates by joining cost to utilization metrics: idle/stopped-but-billed resources, orphaned volumes/IPs/snapshots, and instances/DBs whose p95 CPU/memory sits well under capacity. Recommend a target size only where utilization data backs it; mark resources lacking metrics as `needs-monitoring`, not as savings.
3. Analyze commitment coverage and elasticity: compute on-demand spend eligible for RIs/Savings Plans/CUDs, current coverage and utilization, and model a commitment level against STEADY-STATE baseline load (not peak), so you don't over-commit. Add storage class tiering and data-transfer/egress reductions. Use spreadsheet to model each scenario's monthly saving and breakeven.
4. Build the prioritized roadmap in the spreadsheet — saving x confidence vs. effort/risk, flagging which actions are reversible (rightsize, tier) vs. binding (1–3yr commitments) — and report. State assumptions (window, tag coverage, excluded accounts) and hand off; recommend, do not execute deletions or purchase commitments.

# Notes

The analysis is wrong if it optimizes a non-representative window (a quiet month understates RI value; a spike month over-sizes), trusts unreconciled billing data, or recommends rightsizing/termination without utilization evidence — deleting an "idle" resource that serves a quarterly job causes an outage. Every saving figure must trace to billing/usage data; label modeled or projected numbers as estimates, never as booked savings. Commitments and resource deletions are irreversible or financially binding: this skill stages them as recommendations with breakeven and risk for a human (and finance) to approve and execute. Not for application-level cost (per-feature unit economics) unless cost-allocation tags support it, and not a substitute for an architecture review.

---
name: blue-green-canary-plan
triggers:
  - canary
  - blue green
  - safe deploy
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a deployment plan for a blue-green or canary release of a service version. Output specifies the traffic-shift schedule, the health signals watched at each step, and the automatic rollback triggers with their thresholds. Handles the "cut over to a new version without an outage" goal class.

# Steps

1. Gather real inputs: service name, current (stable) and target (new) version, deploy topology (load balancer / service mesh / DNS), and how traffic is split. Decide blue-green (instant cutover with a standby fleet) vs canary (incremental %); state why. Mark anything unknown UNVERIFIED.
2. Run `knowledge_search` for this service's SLOs, dashboards, alert rules, and any prior failed-deploy postmortems; cite them and flag missing baselines.
3. Define the traffic shift: for canary, the % steps and soak time per step (e.g. 1% → 10% → 50% → 100%); for blue-green, the cutover gate plus the period both fleets stay warm before decommissioning blue. Tie each step to the signals from step 2 (error rate, p95/p99 latency, saturation, key business metric).
4. Define rollback triggers as numeric conditions ("error rate > 2% over 5 min" → revert to stable), who/what executes them (automated vs human), revert time, and post-revert verification. Report the plan and hand off, stating assumptions and the cutover owner.

# Notes

Wrong if rollback triggers are qualitative ("looks bad") instead of thresholded, or if the plan omits keeping the stable version routable during the soak. Blue-green needs enough standby capacity for full traffic; canary needs per-cohort metric isolation — note if either is unavailable. Do not use when the new version is not wire-compatible with the old (shared DB schema, queue formats) — pair with a migration runbook first. Traffic shifts and the final cutover are staged for a human to approve; cite all SLO/threshold values to a source and never fabricate baselines.

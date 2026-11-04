---
name: capacity-plan
triggers:
  - capacity plan for this service
  - infra sizing for projected load
  - will it scale to next quarter
tools_needed:
  - spreadsheet
  - pandas_query
---
# What this skill does

Sizes infrastructure (compute, memory, storage, connections, throughput) for a projected load over a stated horizon. Produces a capacity plan: a demand model grounded in historical metrics, per-resource sizing with explicit headroom, and the scale-up/scale-out triggers that say when to act. Handles the goal class "given growth assumptions, how much do we provision and when."

# Steps

1. Pull the real baseline: load current utilization from observed metrics (peak and p95 RPS, CPU, memory, storage growth/day, connection counts) via `pandas_query` over the metrics export. Record the measurement window and units; do not assume a baseline you cannot source.
2. Build the demand model in `spreadsheet`: project load over the horizon from a STATED growth assumption (linear, compound %, or event-driven). Label the assumption and its origin (PM forecast, trailing trend, launch plan). Compute peak demand, not just average — size to the peak plus a stated headroom buffer (e.g. 30 percent) so you absorb spikes and one-node failures.
3. Convert demand to resources per tier: required instances/cores/RAM/IOPS/storage = projected peak / per-unit capacity, rounded up, plus headroom and N+1 redundancy. Cross-check against any hard ceilings (quotas, license caps, single-node limits) and flag where the plan hits one.
4. Define trigger thresholds (e.g. "scale out at 70 percent sustained CPU over 10 min", "add storage at 75 percent full") and report the plan: baseline, demand model with assumptions, per-tier sizing, headroom, triggers, and the date each resource is projected to saturate. State every assumption explicitly and mark unverified inputs.

# Notes

The plan is wrong if it sizes to average instead of peak, omits redundancy/failure headroom, or hides the growth assumption — a number with no stated assumption is not a plan. Garbage baseline metrics (wrong window, missing peaks) propagate silently; verify the source window. This recommends sizing and triggers; it does NOT auto-provision — actual scaling, quota increases, and spend commitments are irreversible and staged for a human to approve. Do not use for latency/architecture redesign (that is a perf investigation, not capacity), or when no historical load data exists (then it is a guess, label it as such).

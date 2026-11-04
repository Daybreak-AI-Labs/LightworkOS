---
name: rate-limiting-design
triggers:
  - rate limiting
  - throttling
  - quota design
tools_needed:
  - knowledge_search
---
# What this skill does

Designs rate limiting and throttling for an API or service and produces a concrete policy: the algorithm, the limiting key/dimension, the numeric limits and windows, and the over-limit response behavior. Output is an implementable spec tied to the service's real traffic and capacity, with degradation and abuse-handling addressed — not a single global "100 req/s".

# Steps

1. Gather the inputs from real data: endpoint traffic distribution, downstream capacity/SLA, abuse vectors, and any fairness or tiering requirements. Use `knowledge_search` to retrieve documented traffic baselines, peak patterns, and existing quota tiers; mark figures you assumed rather than confirmed.
2. Select the algorithm to match the need: token bucket (bursty, allows controlled spikes), leaky bucket (smooth output), fixed window (simple, boundary-burst risk), or sliding window (accurate, costlier) — and justify the choice against the traffic shape.
3. Define the limiting dimensions and numeric limits: key by API key / user / IP / tenant / endpoint (and combinations), set per-key limits and windows from capacity headroom, and layer tiers (free vs. paid) plus a global backstop to protect downstreams. Specify distributed-counter storage if multi-instance.
4. Report the policy as a table (scope/key → algorithm → limit → window → tier) plus over-limit behavior — 429 with `Retry-After`, rate-limit headers, queue vs. reject, graceful degradation. State assumptions and flag limits that need load validation before rollout, leaving enforcement changes to a human.

# Notes

Wrong if limits are pulled from thin air rather than capacity/traffic data, or if it omits the over-limit response and client signaling (`Retry-After`, headers) that lets callers back off. Single-instance counters silently break across a cluster — specify shared/distributed state or say it is single-node. Cite traffic/capacity sources via `knowledge_search`; do not invent peak numbers. Limits that are too aggressive cause outages, so present them as a staged/validated rollout — a human enables enforcement in production, not this skill.

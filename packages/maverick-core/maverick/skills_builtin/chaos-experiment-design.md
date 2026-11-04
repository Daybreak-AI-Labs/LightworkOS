---
name: chaos-experiment-design
triggers:
  - design a chaos experiment
  - run a resilience test
  - plan fault injection
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a single controlled chaos/resilience experiment for a named service or dependency. Output is a runnable experiment spec: a steady-state hypothesis, the fault to inject and its blast radius, the metrics that confirm or refute the hypothesis, and explicit abort criteria with a rollback path. It targets one failure mode per experiment, not a broad "break things" sweep.

# Steps

1. Establish steady state via knowledge_search: pull the target service's normal SLIs (latency p50/p99, error rate, throughput, saturation) and their current dashboards. Write the steady-state hypothesis as a measurable assertion ("p99 stays under N ms and error rate under M% while the fault is active"). Mark any baseline number you cannot source as `[unverified]`.
2. Choose exactly one fault grounded in a real dependency: instance kill, latency injection, dependency timeout, network partition, resource exhaustion, or clock skew. State why this fault maps to a plausible real-world failure for this service.
3. Scope the blast radius small first: a single instance/AZ/canary cohort, a bounded time window, and a non-peak schedule. Define the metrics watched during the run and the exact abort criteria (thresholds on SLIs or customer-impact signals) that trigger immediate halt and rollback.
4. Assemble the spec: hypothesis, fault, blast radius, observed metrics, abort criteria, rollback procedure, and pre-conditions (monitoring live, on-call notified, kill switch ready). Hand off the draft for an owner to approve; explicitly stage execution in production as requiring human sign-off and a verified rollback.

# Notes

Wrong output looks like: no measurable steady-state hypothesis, no abort criteria, an unbounded blast radius, or multiple faults injected at once so a result cannot be attributed. Never design an experiment without a tested rollback and a halt switch. Do NOT use this when the service has no monitoring or baseline (you cannot detect deviation), during an active incident, or in production before it has run cleanly in staging. The skill drafts and recommends; arming and running the experiment in production is a human-approved, irreversible-staged action.

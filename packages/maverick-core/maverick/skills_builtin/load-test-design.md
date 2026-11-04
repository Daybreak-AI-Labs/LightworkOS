---
name: load-test-design
triggers:
  - design a load test
  - set up a stress test
  - plan a performance test
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a load or stress test for a service or endpoint. Output is a complete test design: a realistic workload model, the load profile and stages, the SLA/SLO pass-fail thresholds, the metrics to capture, and the test environment and data plan. It produces a test that proves a specific capacity or SLA question, not an undirected "send traffic" run.

# Steps

1. Define the question and workload via knowledge_search: pull production traffic mix (endpoint distribution, request sizes, read/write ratio, think time, concurrency), peak vs average rates, and the SLO targets. State the test's goal precisely — capacity at SLO, breakpoint (stress), soak/endurance, or spike. Mark any traffic figure you cannot source as `[unverified]`.
2. Build the workload model from that mix: weighted scenarios, parameterized test data (and a plan to seed/reset it), realistic pacing and think time, and warm-up. Avoid the common error of hammering one endpoint with zero think time unless the goal is explicitly a stress breakpoint.
3. Specify the load profile and stages — ramp-up, steady-state hold, and (for stress) step increases until SLO breach; (for soak) a long hold to surface leaks. Define pass/fail SLAs as thresholds (p99 latency, error rate, throughput) and the metrics captured on both load generator and system under test (latency percentiles, error rate, CPU/mem, saturation, downstream impact).
4. Plan the environment: an isolated load-test target sized like prod (note any divergence), generator capacity so the tool is not the bottleneck, and observability wired up. Hand off the design with goal, workload, profile, and SLAs stated; flag that running against shared or production environments requires human approval and traffic isolation.

# Notes

Wrong output looks like: an unrealistic workload (single endpoint, no think time when modeling real users), no pass/fail SLA so results are uninterpretable, or a load generator too small to reach target load. Source the workload mix from real traffic; do not invent the distribution. Do NOT use this when SLOs are undefined (nothing to assert against) or when the test would hit production without isolation and approval. The skill drafts the design and recommends thresholds; executing the test against shared or production infrastructure is a human-approved action.

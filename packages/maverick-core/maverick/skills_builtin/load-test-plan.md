---
name: load-test-plan
triggers:
  - write a load test plan
  - design a performance / stress test
  - plan a soak test before launch
tools_needed:
  - knowledge_search
---
# What this skill does

Produces an executable load-test plan that validates whether a system meets its performance targets under realistic and peak demand. Output: a plan with a workload model (scenarios, mix, think time), explicit SLAs/SLOs, a ramp profile (baseline -> peak -> soak -> spike), pass/fail criteria, environment and data requirements, and observability hooks — ready for a performance engineer to implement in a load tool.

# Steps

1. With knowledge_search, pull the real traffic baseline and targets: current and projected RPS/concurrency, peak-to-average ratio, the SLOs (e.g. p95/p99 latency, error rate, throughput) and any contractual SLAs. If a number is missing, mark it as an explicit assumption to confirm — never fabricate a target.
2. Build the workload model from observed usage: enumerate the top user journeys / endpoints, their relative mix (% of traffic), payload sizes, and think time. Ground the mix in real telemetry from knowledge_search; flag any scenario whose weight is estimated rather than measured.
3. Define the ramp profile and test types: warm-up, steady-state baseline, ramp to peak, soak (sustained hours to expose leaks/saturation), and a spike/stress test to find the breaking point. For each phase state duration, target load, and pass/fail thresholds tied to the SLOs from step 1.
4. Specify environment parity (prod-like sizing, representative data volume, third-party/mock boundaries), the metrics and dashboards to capture (latency percentiles, error rate, saturation: CPU/mem/queue depth/DB), and report. State assumptions and hand off to the engineer who will run it — do not execute load against production without explicit human sign-off.

# Notes

The plan is wrong if SLAs are vague ("should be fast"), if it tests against an under-provisioned or empty-data environment (results won't transfer), or if it only measures averages — tail latency (p95/p99) is where users feel pain. A test that never reaches saturation proves nothing about headroom; a soak shorter than the leak's time-constant will pass falsely. Cite the telemetry source for every baseline number; mark projected/peak figures as assumptions. Running real load is destabilizing and can page on-call or breach rate limits: this skill DRAFTS the plan and stages it; a human approves and runs it, and never fires a stress test at production without a maintenance window. Not for micro-benchmarking a single function or for correctness testing.

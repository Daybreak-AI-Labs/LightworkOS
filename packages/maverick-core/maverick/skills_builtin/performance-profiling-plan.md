---
name: performance-profiling-plan
triggers:
  - plan a performance profiling investigation
  - investigate latency
  - find the bottleneck
tools_needed:
  - knowledge_search
---
# What this skill does

Plans a performance profiling investigation for a service or workflow that is slow or resource-heavy. Output is a structured plan: the symptom quantified, ranked candidate hypotheses for the bottleneck, the profiling method and measurements to confirm each, and a sequencing that isolates one variable at a time. It tells you what to measure and in what order, not a guess at the fix.

# Steps

1. Quantify the symptom via knowledge_search: pull the latency/throughput/resource graphs, the affected percentile (p50 vs p99 tail differ in cause), the workload shape, and any recent change that correlates with onset. State the symptom as a number against a target ("p99 is N ms vs SLO of M ms"); mark unsourced figures `[unverified]`.
2. Enumerate ranked hypotheses across the stack — CPU-bound code, lock/contention, N+1 or slow queries, GC pressure, I/O or network wait, cold caches, downstream dependency latency, queueing/saturation. Order them by likelihood given the symptom signature (e.g. tail-only latency points at contention or GC, not steady CPU).
3. For each hypothesis pick a measurement that confirms or kills it: CPU/wall flame graph, query EXPLAIN and slow-query log, lock/async profiler, GC logs, RED/USE dashboards, distributed trace spans. Specify the environment (prod-shadow, staging under load, or read-only prod profiling) and the overhead/safety of each tool.
4. Sequence the work to change one variable at a time and capture a before baseline so any improvement is measurable. Hand off the plan with the top hypothesis, its measurement, and expected signal called out; note that profiling production carries overhead and any code or config change is staged for human review after the bottleneck is proven.

# Notes

Wrong output looks like: jumping to a fix before measuring, profiling without a baseline (no way to prove improvement), or conflating the symptom percentile (optimizing p50 when p99 is the problem). Tie every hypothesis to a concrete measurement; do not assert a root cause from intuition. Do NOT use this when there is no reproducible workload or no observability to measure against. The skill plans and recommends measurements; running profilers in production and applying any optimization are human-approved actions.

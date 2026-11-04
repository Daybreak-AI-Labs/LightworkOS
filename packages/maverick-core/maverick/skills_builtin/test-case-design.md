---
name: test-case-design
triggers:
  - test cases
  - test design
  - test scenarios
tools_needed:
  - knowledge_search
---
# What this skill does

Designs concrete test cases for a single feature or behavior, covering positive (happy path), negative (error/invalid input), and edge (boundary/rare) scenarios. Produces an enumerated case list — each with preconditions, inputs, steps, and expected result — ready for a human or automation to implement.

# Steps

1. Pin down the behavior under test: read the feature's spec, acceptance criteria, or interface contract. Use `knowledge_search` to retrieve the actual requirements and any existing test conventions; do not invent expected results — derive them from the spec, and mark any behavior the spec leaves undefined.
2. Apply systematic design techniques: equivalence partitioning and boundary-value analysis on each input, decision tables for combined conditions, and state transitions where the feature is stateful. This forces coverage beyond the obvious happy path.
3. Enumerate cases in three buckets — positive (valid inputs produce correct output), negative (invalid input, errors, permission denials, exhausted resources are handled gracefully), and edge (min/max boundaries, empty/null, concurrency, idempotency, ordering). Give each a stable id, preconditions, inputs, steps, and a precise expected result.
4. Report the cases as a table grouped by bucket, noting which requirement each traces to. Call out gaps where the spec is ambiguous and state your assumed expected result so a human can confirm before implementation.

# Notes

A case is wrong if its expected result is asserted rather than derived from a requirement — cite the source line or mark it as an assumption. Watch for missing negative/edge coverage: a suite that is all happy-path passes while the feature is broken. This skill designs cases; it does not execute them or guarantee the spec is correct — surface contradictions in the spec instead of papering over them. Use test-strategy-design first when the question is which levels to test at, not which inputs to cover.

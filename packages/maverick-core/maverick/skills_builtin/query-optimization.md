---
name: query-optimization
triggers:
  - sql optimization
  - slow query
  - query tuning
tools_needed:
  - sql_query
---
# What this skill does

Takes a single slow or expensive SQL query and produces a semantically equivalent rewrite that runs cheaper, with plan analysis proving the gain. Output is the optimized query plus a before/after plan comparison and a note of which rewrite (join reorder, predicate pushdown, subquery-to-join, removed function-on-column, etc.) drove the improvement.

# Steps

1. Capture the baseline: run the query through `sql_query` with `EXPLAIN ANALYZE` and record the plan — scan types, join algorithms, actual vs. estimated rows, sorts, and total cost/time. Confirm the query's current result so the rewrite can be checked for equivalence.
2. Locate the cost drivers: non-sargable predicates (functions/casts on indexed columns), implicit type coercions, redundant DISTINCT/ORDER BY, correlated subqueries, SELECT *, and cardinality misestimates where actual rows diverge sharply from estimated.
3. Apply targeted rewrites one at a time — sargable predicates, subquery-to-JOIN, EXISTS over IN, explicit column lists, join-order/CTE-materialization hints — re-running `EXPLAIN ANALYZE` after each and verifying the result set is unchanged. Keep only rewrites that measurably lower cost.
4. Report the final optimized query with the before/after plans and the dominant fix. State assumptions (data volume, existing indexes) and note any rewrite that trades readability for speed so a human can accept the tradeoff.

# Notes

Wrong if the rewrite changes results — always verify row-for-row equivalence, especially around NULLs, DISTINCT, and outer joins where rewrites silently alter semantics. A plan from a tiny dataset can invert at production scale; mark gains as unverified when run against non-representative data. If the real fix is a missing index rather than query shape, hand off to database-index-tuning instead of forcing a rewrite. Do not run rewrites that mutate data; this skill optimizes read queries — staging/schema changes are a human decision.

---
name: database-index-tuning
triggers:
  - index tuning
  - slow query
  - query optimization
tools_needed:
  - sql_query
  - read_file
---
# What this skill does

Diagnoses slow or table-scanning SQL workloads and produces concrete index recommendations backed by query-plan evidence. Output is a ranked list of proposed indexes (table, columns, type) each justified by a captured EXPLAIN/EXPLAIN ANALYZE plan showing the scan it eliminates, plus the estimated write/storage cost.

# Steps

1. Collect the real workload: read the slow query (from `read_file` on the source, a logged query, or the user-supplied statement) and capture its current plan with `sql_query` running `EXPLAIN ANALYZE` (or backend equivalent). Record actual rows, scan types, and cost — do not estimate from the query text alone.
2. Identify the access bottleneck: pinpoint sequential/full scans, high-cost joins, and sorts on large row counts. Map each to the predicate columns (WHERE, JOIN ON, ORDER BY, GROUP BY) that an index could cover; check existing indexes first so you do not duplicate one.
3. Propose candidate indexes — column order driven by selectivity and equality-before-range, considering composite and covering/INCLUDE indexes — then validate each by creating it in a scratch/replica context and re-running `EXPLAIN ANALYZE` to prove the plan changed (scan → index seek, lower cost).
4. Report the ranked recommendations with before/after plans, expected gain, and the write-amplification/storage tradeoff. State assumptions (data distribution, read/write ratio) and hand off DDL as staged — a human applies indexes to production.

# Notes

Wrong if recommendations rest on row-count estimates instead of a captured plan, or ignore that the index adds write/storage overhead. Index choice depends on real data distribution; a plan from an empty or unrepresentative table misleads — flag when stats are stale or the sample is small. Creating indexes on a live production table can lock/block; never present DDL as auto-apply — stage it (CONCURRENTLY/ONLINE where supported) for a human to schedule. Not for fixing genuinely bad query structure — route that to query-optimization first.

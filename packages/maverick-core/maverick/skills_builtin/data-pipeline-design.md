---
name: data-pipeline-design
triggers:
  - data pipeline
  - etl design
  - elt pipeline
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a batch data pipeline from stated requirements: the sources to ingest,
the transformations to apply, the target model, and the operational SLAs.
Produces a design document a data engineer can implement — source inventory,
transform stages, schedule/SLA, and failure/recovery handling.

# Steps

1. Gather requirements from real inputs: which sources (systems, tables, files),
   target consumers and their freshness need, expected volume, and any compliance
   constraints. Use `knowledge_search` to find existing source schemas, prior
   pipelines, and platform conventions; do not assume a schema you have not seen.
2. Define the source inventory and ingestion mode per source — full vs
   incremental, the watermark/change column, expected volume, and idempotency
   strategy. Flag sources with no reliable change key as full-reload (and note the
   cost) rather than inventing a watermark.
3. Specify the transform stages in order (cleanse, dedupe, conform/join, derive,
   aggregate), the grain at each stage, and the target model (staging → core →
   marts). State idempotency and reprocessing/backfill behavior so a rerun is
   safe. Note where late-arriving or out-of-order data is handled.
4. Set the schedule and SLAs (run cadence, max latency, freshness target), define
   failure handling (retries, dead-letter, partial-failure isolation, alerting),
   and hand off the design stating assumptions (volumes, source contracts) and any
   requirement that is still unverified.

# Notes

The design is wrong if incremental loads lack a dependable watermark, if a rerun
is not idempotent (silent duplication/loss), or if SLAs are asserted without a
volume/latency basis. Distinguish ETL vs ELT by where compute lives and say which
you chose and why. This is a design recommendation, not an implementation —
provisioning infra or scheduling production jobs is a human decision. Do not use
for streaming/real-time pipelines (different failure model) or for a one-off
ad-hoc extract.

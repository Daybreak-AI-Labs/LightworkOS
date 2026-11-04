---
name: data-contract-author
triggers:
  - author data contract
  - define schema sla
  - producer consumer contract
  - data contract spec
tools_needed:
  - read_file
  - sql_query
  - knowledge_search
---
# What this skill does

This skill authors a producer/consumer data contract for a dataset, stream, or table: the schema (fields, types, nullability, semantics), the freshness and quality SLAs, the allowed-values and key constraints, ownership, and an explicit breaking-vs-non-breaking change policy — plus the validation checks that enforce the contract in a pipeline or CI. It turns an implicit, fragile producer/consumer handshake into an explicit, testable agreement so a schema change doesn't silently break downstream consumers. The output is a contract spec and a set of validation check definitions, staged for the producing and consuming teams; it does not deploy checks, alter the schema, or gate a pipeline on its own.

# Steps

1. Use read_file and sql_query to profile the actual data: column names, types, null rates, distinct/allowed values, key uniqueness, row-volume cadence, and observed freshness lag. Use knowledge_search to identify the consumers and the semantics each field is expected to carry (so the contract documents meaning, not just types).
2. Draft the schema section: each field with type, nullability, semantic description, and allowed values/ranges; declare the primary key and uniqueness; document units and enumerations explicitly so consumers can't misread them.
3. Define the SLAs and policy: freshness (max staleness), quality thresholds (max null rate, referential checks, row-count bounds), the owner/on-call, and the change policy — what counts as a breaking change (removing/renaming a field, narrowing a type, changing semantics) versus additive, and the required deprecation/notice process for breaking changes.
4. Specify the validation checks that enforce all of the above (schema assertions, null/range/uniqueness tests, freshness and volume checks) as concrete check definitions, and stage the contract + checks for both teams to ratify. Mark that wiring the checks into CI/the pipeline and enforcing the gate are human deployment steps.

# Notes

A data contract is only real if it is testable: every clause (a field's nullability, a freshness SLA, an allowed-value set) should map to a concrete validation check — a contract with no enforcing checks is just a comment. Semantics matter as much as types: document what a field means and its units, because most downstream breakage is a misunderstood column, not a type error. The breaking-change policy is the contract's teeth — define additive vs breaking precisely and require a deprecation window for breaking changes; align with any proto/contract additive-only rule the platform enforces. This skill authors the spec and check definitions; it does not deploy checks, change the producer's schema, or block a pipeline — those are human/CI steps. Profile real data first so SLAs reflect reality, not aspiration.

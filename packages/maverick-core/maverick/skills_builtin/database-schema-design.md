---
name: database-schema-design
triggers:
  - schema design
  - data model
  - table design
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a relational schema for a given domain: tables, columns with types, primary and foreign keys, indexes, constraints, and the normalization level chosen. The output is a reviewable schema (DDL or table spec) with the rationale for keys, indexes, and any deliberate denormalization, grounded in the real entities and access patterns, not a textbook example.

# Steps

1. Gather the real inputs: the entities and their relationships, the dominant read/write queries, cardinality and volume estimates, and consistency/uniqueness requirements. If access patterns are unstated, list them as open questions — indexes and denormalization decisions depend on them.
2. Run `knowledge_search` for existing schemas, naming conventions, and the target engine's constraints (e.g. Postgres vs MySQL type and index support) so the design fits the platform; cite the conventions you follow.
3. Model entities as tables in 3NF first: choose primary keys (natural vs surrogate), define foreign keys with the correct ON DELETE/UPDATE behavior, add NOT NULL/UNIQUE/CHECK constraints, and pick column types deliberately. Justify any denormalization by the specific query it serves.
4. Add indexes driven by the actual query predicates and join columns, noting the write-cost trade-off; flag wide or low-selectivity indexes. Document migration ordering if this evolves an existing schema.
5. Hand off the schema as DDL plus a short rationale per non-obvious decision, stating assumptions about volume/access and flagging anything that needs a human DBA to approve before applying to a live database.

# Notes

The design is wrong if it indexes for queries that don't exist, or omits a foreign key/uniqueness constraint that the domain requires. Don't invent access patterns to justify a structure — mark assumptions explicitly. Cite platform/convention sources. Generating DDL is fine; applying it to a real database (especially a migration on existing data) is irreversible and must be staged for a human to run after review. Not for non-relational stores or pure query tuning on an existing, fixed schema.

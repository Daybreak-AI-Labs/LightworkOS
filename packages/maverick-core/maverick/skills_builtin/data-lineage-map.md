---
name: data-lineage-map
triggers:
  - map the lineage of this table
  - impact analysis before a schema change
  - where does this column come from
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Maps the end-to-end lineage of a dataset or column: its upstream sources, the transforms that produce it, and the downstream consumers that depend on it. Produces a directed lineage map plus an impact list usable for breaking-change review, root-cause tracing, or deprecation planning. The output names real objects, not placeholders.

# Steps

1. Fix the target node (table, view, or column) and the direction(s) needed: upstream (sources), downstream (consumers), or both. Use `knowledge_search` to locate pipeline/DAG definitions, dbt models, and ETL job docs that reference the target.
2. Trace upstream with `sql_query` against the warehouse's information_schema/catalog and view definitions to resolve source tables and the SELECT/JOIN/transform logic feeding the target; record each hop and the transform applied (filter, aggregate, join key, derivation).
3. Trace downstream by searching for objects that read the target — dependent views, materializations, scheduled jobs, dashboards, and exports — via catalog dependencies and `knowledge_search` over BI/job metadata. Flag any edge you could not confirm in the catalog as `UNVERIFIED`.
4. Assemble the lineage map (sources -> transforms -> target -> consumers) and an impact list ranked by consumer criticality. Report it for the requesting change, stating which edges are catalog-confirmed versus inferred. Do not execute any schema change off this map — it informs the human's decision.

# Notes

The map is wrong if it misses a consumer (silent breakage on change) or guesses a transform — prefer catalog/view-definition evidence and mark inferred edges. Dynamic SQL, app-layer queries, and external exports may be invisible to the catalog; call out these blind spots explicitly rather than implying full coverage. Lineage is read-only analysis: never drop, rename, or alter objects. Not for systems with no queryable catalog and no pipeline docs — there's nothing to ground the trace.

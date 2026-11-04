---
name: semantic-layer-design
triggers:
  - design a metrics layer
  - define canonical metric definitions
  - build a semantic layer for analytics
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a semantic (metrics) layer that gives a single canonical definition for each business metric across BI tools and queries. Produces metric definitions (name, formula, grain, filters, allowed dimensions), the underlying entity/join model, and naming/governance conventions. The output is a spec engineers can implement in dbt-metrics, LookML, Cube, or an equivalent.

# Steps

1. Inventory the metrics the business actually uses and their current definitions. Use `knowledge_search` to pull existing dashboard formulas, spreadsheet definitions, and analyst docs — surface conflicting definitions of the same metric (e.g. two "active users") rather than silently picking one.
2. Model the entities and joins underneath: identify base tables, primary keys, and the dimension tables metrics roll up by. Define each metric's grain and the join path; flag any join you cannot confirm from schema/docs as `UNVERIFIED`.
3. Author canonical metric definitions: name, exact aggregation formula, time grain, default and required filters, allowed dimensions, and ownership. Resolve each naming conflict explicitly and record the decision and rationale; define conventions (naming, additivity rules, semi-additive handling).
4. Assemble the semantic-layer spec (entity model + metric catalog + conventions + governance owners), list assumptions and unresolved definition conflicts, and hand off to data engineering for implementation. Note that adopting a definition as canonical is a stakeholder decision.

# Notes

The design fails if a metric's formula or grain is guessed, or if a definition conflict is hidden — every metric must trace to a verifiable source or be marked unverified, and conflicts must be raised, not papered over. Watch for non-additive metrics (ratios, distinct counts) that cannot be summed across dimensions. This skill recommends canonical definitions; a human/stakeholder approves which becomes official. Not for a single throwaway report that needs no shared, reusable definitions.

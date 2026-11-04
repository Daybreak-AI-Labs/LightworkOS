---
name: data-quality-rules
triggers:
  - data quality rules
  - data validation
  - dq checks
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Defines a data-quality rule set for a dataset across the standard DQ dimensions
(completeness, validity, uniqueness, consistency, timeliness, accuracy). Produces
a rule table: per column/relationship, the dimension, the concrete check, the
threshold, and the action on breach — implementable as assertions in a DQ runner.

# Steps

1. Profile the target table with `sql_query` before writing rules: row count,
   null rate per column, distinct counts, value ranges/patterns, and min/max of
   timestamps. Base every rule on observed data, not assumptions about it.
2. Use `knowledge_search` to pull the column's business meaning, the source
   contract, and any reference/lookup lists. Identify keys (uniqueness), required
   fields (completeness), formats/domains (validity), and cross-field or
   cross-table invariants (consistency).
3. Write one check per rule with an explicit, measurable threshold — e.g.
   `null_rate(email) <= 0.5%`, `unique(order_id) = 100%`, `status in (<lookup>)`,
   `max(loaded_at) within 24h`. Calibrate thresholds from the profile so they
   catch regressions without firing on normal variance; mark any threshold set
   without a basis as `provisional` to tune after observation.
4. Assign each rule a severity and breach action (block load / warn / quarantine
   row), and hand off the rule table grouped by dimension, stating assumptions
   (profile sample, source contract) and which thresholds are provisional.

# Notes

The rule set is wrong if thresholds are arbitrary (false alarms erode trust, or
too-loose checks miss real breaks), if a "required" field is enforced without
confirming it is truly mandatory, or if accuracy is claimed without a trusted
reference. Block-on-breach actions can halt a pipeline — that escalation is a
human decision; default new rules to warn/quarantine and recommend promotion.
Profile-derived thresholds are provisional until validated against history. Do
not use to assert data is correct against ground truth you do not have.

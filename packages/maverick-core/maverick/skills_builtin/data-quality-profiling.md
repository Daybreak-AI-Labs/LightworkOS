---
name: data-quality-profiling
triggers:
  - profile the data quality of this dataset
  - is this data fit to use
  - data fitness check before we build on it
tools_needed:
  - pandas_query
  - sql_query
---
# What this skill does

Assesses whether a dataset is fit for an intended use by profiling it across completeness, validity, uniqueness, consistency, and freshness. Handles the goal class "before we report on / model / migrate this data, can we trust it." Produces a data-quality profile: per-column metrics, the rules that failed, concrete bad-row examples, and a fit-for-use verdict tied to the stated purpose.

# Steps

1. Establish the intended use and the table/file under review — fitness is relative to purpose (a column that is 5 percent null may be fine for analytics, fatal for a join key). Load the dataset via `sql_query` (warehouse) or `pandas_query` (file/extract) and capture row count, columns, types, and the snapshot time.
2. Profile completeness and shape: null/blank rate per column, distinct counts, min/max/range, and distribution sketch for key fields. Flag columns whose null rate or cardinality contradicts their declared role (e.g. nulls in a primary key, low cardinality in a supposed unique id).
3. Check validity and consistency against real rules: type/format conformance (dates, emails, enums), referential integrity / orphaned foreign keys, duplicate keys, and out-of-range or negative values where impossible. For each rule, capture the failure count AND a few example offending rows — never report a metric without a sourced example.
4. Assess freshness (max/last-updated timestamp vs. expected cadence) and report: per-dimension scorecard, failed rules with counts and examples, the freshness gap, and a fit-for-use verdict for the STATED purpose (fit / fit-with-caveats / not fit). State assumptions about expected rules and hand off remediation suggestions.

# Notes

The profile is wrong if it reports aggregate percentages with no offending examples, judges fitness without a stated use, or silently samples a subset and presents it as the whole (note any sampling). A clean profile is not a guarantee of correctness — it checks structure and rules, not semantic truth; say so. This recommends a verdict and remediation; it does NOT mutate, dedupe, or delete data — any cleanup that changes the source is irreversible and staged for a human. Do not use as a substitute for business validation of meaning, or on data you only partially loaded without flagging the gap.

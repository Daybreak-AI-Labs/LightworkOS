---
name: cohort-retention-analysis
triggers:
  - cohort analysis
  - retention curve
  - how do cohorts retain
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Measures how a metric (active users, revenue, repeat orders) evolves over time for groups that share a common start event, typically signup or first-purchase month. Produces a cohort/retention triangle (cohort rows x periods-since-start columns) plus decay insights: where retention plateaus, which cohorts are best/worst, and whether recent cohorts are improving.

# Steps

1. Confirm the cohort grain and metric with the requester: cohort key (e.g. signup month), period unit (day/week/month), retention definition (active = ≥1 qualifying event in the period), and the analysis window. Do not assume monthly if the data is sparse.
2. With `sql_query`, derive each subject's cohort label from their first event, then for every cohort x period bucket count distinct retained subjects. Anchor period 0 at the start event so period N is "N units after first seen." Validate that cohort sizes (period 0) reconcile to total acquired subjects.
3. Pivot into a triangle with `spreadsheet`: cohort rows, period columns, cells = retained count and retained % of that cohort's period-0 size. The lower-right is necessarily empty (recent cohorts have not aged); never extrapolate into it.
4. Read the decay: first-period drop, where the curve flattens (the retained core), and the trend across cohorts down each period column. Report the triangle, the % and absolute curves, and call out anomalies. State assumptions (retention definition, window) and hand off; flag any cohort with too few subjects as low-confidence.

# Notes

Output is wrong if period 0 is misaligned (off-by-one inflates or deflates the whole curve), if "active" mixes definitions across periods, or if immature cohorts are compared at periods they have not reached. Distinct-count must dedupe within a period; raw event counts overstate retention. Counts under a small-n threshold (e.g. <30) are noise — mark them, do not headline them. Use a separate revenue/expansion analysis for dollar retention; this skill is for the subject-count curve unless the metric is explicitly monetary. This is descriptive analysis only — do not recommend irreversible lifecycle or budget actions off a triangle without a human reviewing cohort maturity.

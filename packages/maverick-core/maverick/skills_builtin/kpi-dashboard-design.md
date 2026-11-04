---
name: kpi-dashboard-design
triggers:
  - design a KPI dashboard
  - build an operating metrics scorecard
  - what metrics should the leadership dashboard show
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Designs a finance or operating KPI dashboard for a stated audience (board, exec team, function lead). Produces a dashboard spec: the metric set with precise definitions and source queries, targets and thresholds, and a layout grouping metrics into a readable hierarchy. Handles the goal class of "decide what to measure, define it unambiguously, and lay it out" — not the BI-tool build itself.

# Steps

1. Clarify the audience and the decisions the dashboard must support, then select 8-15 KPIs that map to those decisions (avoid vanity metrics). For each, write a precise definition: numerator, denominator, time grain, and inclusion/exclusion rules.
2. Validate each metric against the real data with sql_query — confirm the source table exists, the field has coverage, and a sample value is sane. Mark any metric whose source is missing or unreliable as unverified rather than shipping a definition nothing can compute.
3. In the spreadsheet, set targets, thresholds (green/amber/red), and comparison bases (vs plan, prior period, YoY) per metric. Group metrics into a layout: headline KPIs top, drivers and leading indicators beneath, with each tile naming its owner and refresh cadence.
4. Output the dashboard spec — metric dictionary, source query per metric, thresholds, and the tile layout — and report it. State assumptions about data availability and hand off; metric definitions and targets are owned by the function lead and need their sign-off before the build.

# Notes

Wrong if a metric is defined ambiguously (two teams compute it differently) or if a tile has no validated data source behind it — every metric must trace to a real query. Too many tiles defeats the purpose; cap the count and push detail to drill-downs. Thresholds and targets are business judgments, not the designer's call — stage them for the owner. Not for building the live dashboard in a specific BI tool, and not a substitute for data-quality remediation when the underlying source is unreliable.

---
name: dashboard-design
triggers:
  - design a BI dashboard
  - report design for stakeholders
  - lay out an analytics dashboard
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Designs an analytics dashboard scoped to a specific audience and decision. Produces a dashboard spec: the metrics and their definitions, the chart type and layout per panel, filters/drilldowns, refresh cadence, and the data sources backing each panel. The output is implementation-ready for Looker, Tableau, Metabase, or similar.

# Steps

1. Pin the audience and the decisions they make from this dashboard (e.g. execs tracking weekly revenue vs. ops triaging a queue). Use `knowledge_search`/stakeholder input to derive the 5-9 metrics that drive those decisions; reject vanity metrics that map to no decision.
2. Validate each metric against the warehouse with `sql_query`: confirm the column/formula exists, check the grain and a sample value, and verify the data is fresh enough for the intended refresh cadence. Mark any metric whose source you could not confirm as `UNVERIFIED`.
3. Lay out panels by priority for the audience: headline KPIs top-left, supporting trends and breakdowns below, detail tables last. Specify per panel the chart type, dimensions, default filters, drilldowns, and time range. Use `spreadsheet` to mock the panel grid and sample values for review.
4. Assemble the spec (audience + decision + metric list with sources + panel layout + filters + refresh cadence), state assumptions and any unverified metric, and hand off for build. Note that publishing to a shared/exec workspace is a human decision.

# Notes

A dashboard is wrong when panels don't map to a decision, a metric's source/grain was assumed rather than queried, or refresh cadence lags the decision window. Over-stuffed dashboards (20+ panels, no hierarchy) fail the audience — enforce the headline-then-detail structure. This skill produces a spec and mock; it does not publish live dashboards or grant access. Not for a one-off question better answered by a single query than a standing dashboard.

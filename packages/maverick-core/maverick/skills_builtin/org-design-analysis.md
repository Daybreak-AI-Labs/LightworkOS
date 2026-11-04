---
name: org-design-analysis
triggers:
  - org design
  - spans and layers
  - reorg analysis
  - organization structure review
tools_needed:
  - spreadsheet
---
# What this skill does

Analyzes an existing organization's design through spans of control and management layers, surfaces structural inefficiency (over/under-spanned managers, excess layers, fragmented teams), and frames redesign options with trade-offs. Handles the goal class "is this org structured well, and what are the alternatives" — output is a diagnostic plus staged options, not a finished reorg.

# Steps

1. Load the reporting roster into `spreadsheet`: each employee with manager ID, level/grade, function, and location. Validate the hierarchy first — flag orphaned records, cycles, and managers missing from the roster — because a broken tree corrupts every downstream metric.
2. Compute the structural metrics: span of control per manager (direct reports), management layers from CEO to each leaf, and the count of single-report or "manager of managers only" chains. Tabulate distribution, not just averages — averages hide the long tail.
3. Flag outliers against a stated norm (e.g., target span 5-8 for managers, fewer layers for flatter orgs) and call out where the norm legitimately differs (specialist/safety-critical functions warrant tighter spans — note these as intentional, not defects).
4. Present 2-3 redesign options (e.g., flatten a layer, consolidate sub-scale teams, rebalance spans) each with the headcount/layer impact and the trade-off (cost vs. control vs. career path). End by reporting findings with the norms and assumptions used, and hand off to leadership — the org chart is a decision they own.

# Notes

Wrong if it judges every manager against one universal span target (context-blind), reports only the mean span (masks extremes), or treats a data-quality artifact (orphan node) as a real structural finding. Spans/layers describe structure, not performance — don't infer that a wide-span manager is overloaded or a narrow one is redundant without corroborating data; mark such inferences "hypothesis." This skill ANALYZES and PROPOSES options; selecting a structure and moving/eliminating roles are irreversible and reserved for human leadership with HR/legal review. Do not use to name individuals for removal.

---
name: kpi-tree-design
triggers:
  - design a kpi tree
  - build a metric tree
  - define north star metrics
tools_needed:
  - spreadsheet
---
# What this skill does

Designs a KPI tree for a function (growth, support, sales, ops): a single north-star metric decomposed into the driver and input metrics that mathematically or causally roll up to it. Produces a structured tree in a spreadsheet showing each metric, its definition, its parent, and the relationship, so a team can see which levers move the top-line number.

# Steps

1. Confirm the function, its single north-star metric, and the time horizon with the requester. If more than one north star is proposed, force a choice — a tree has one root. Capture the precise definition and current value of the north star.
2. Decompose the north star one level at a time into 2-4 driver metrics, stating the relationship for each (e.g. Revenue = Customers x ARPU, or causal: faster first-response -> higher CSAT). Continue until leaves are input metrics a team can directly act on.
3. Build the tree in a `spreadsheet`: one row per metric with columns for metric name, definition, parent, relationship type (formula/causal), current value, and owner. Mark any value you could not source as UNVERIFIED.
4. Hand off the spreadsheet, state which relationships are formulaic vs assumed-causal, and flag leaf metrics that lack a clear owner or data source.

# Notes

The output is wrong if children don't actually roll up to the parent (broken math) or if a "causal" link is asserted without evidence — label causal links as hypotheses, not facts. Keep it to one north star; multiple roots mean it's a dashboard, not a tree. Current values must be sourced or marked UNVERIFIED, never fabricated. This is a design draft for the function owner to validate against their data; do not use it to set targets or compensation without their review.

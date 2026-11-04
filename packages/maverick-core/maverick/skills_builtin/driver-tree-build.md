---
name: driver-tree-build
triggers:
  - build a driver tree
  - value tree for this metric
  - decompose the metric into drivers
tools_needed:
  - spreadsheet
---
# What this skill does

Decomposes a single target metric (revenue, margin, CAC, churn, throughput) into a hierarchy of mathematically connected drivers, so every leaf input rolls up to the top number through explicit operators. Produces a driver tree where each node carries its formula, current value, and unit, and the root recomputes to the actual metric.

# Steps

1. Identify the target metric and its observed value from the source model or dataset; record the unit and period. Do not proceed if the metric is ambiguous or the value is unverified — flag it.
2. Decompose top-down one level at a time using exact identities (e.g. Revenue = Units x Price; Margin = Revenue - COGS). Each parent must equal an explicit combine (sum/product/ratio) of its children — no orphan or hand-waved nodes.
3. Recurse until leaves are controllable levers or raw inputs you can source. Tie every leaf to a cell/source value; mark any estimated leaf as unverified.
4. In the spreadsheet, wire children -> parents with live formulas and confirm the root recomputes to the observed metric (reconcile to zero). Report the tree, the leaf-lever list, and any node that did not reconcile, stating which leaves are assumptions.

# Notes

The output is wrong if a parent does not equal the combination of its children (broken identity) or if leaves double-count overlapping effects. Keep operators exact — additive trees and multiplicative trees do not mix without a clear conversion node. This is a structuring/analysis aid: it does not change the underlying model. Do not use it when the metric has no clean decomposition (e.g. a black-box ML score) — say so instead of forcing a tree.

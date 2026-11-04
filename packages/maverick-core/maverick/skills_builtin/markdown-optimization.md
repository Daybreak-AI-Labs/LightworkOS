---
name: markdown-optimization
triggers:
  - markdown the slow movers
  - clearance plan for end-of-season
  - price reduction schedule by SKU
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a SKU-level markdown (clearance) plan that sets the timing and depth of price reductions to clear aged or overstocked inventory while protecting margin. Produces a markdown schedule recommending which SKUs to mark down, by how much, and on what cadence, with projected sell-through and margin impact.

# Steps

1. Pull the candidate set with `sql_query`: per SKU, on-hand units, weeks-of-supply, sell-through rate, age/weeks-since-receipt, current price, unit cost, and any existing markdown. Filter to SKUs meeting clearance criteria (e.g. weeks-of-supply over threshold or past season cutoff). Use real catalog/inventory data only — do not invent SKUs or costs.
2. For each SKU, compute the gap to a clearance exit date and estimate the discount depth needed to hit target sell-through, using observed price-elasticity or historical markdown response where available; mark assumptions explicitly where elasticity is unknown.
3. Sequence reductions into a staged cadence (e.g. first markdown depth, escalation steps and dates) so deeper cuts only trigger if interim sell-through misses target. Keep each step above the salvage/cost floor unless explicitly clearing below cost.
4. Assemble the plan in a `spreadsheet`: SKU, current price, each markdown step with date and depth, projected units cleared, ending inventory, and margin/markdown-dollar impact. Report the total margin give-up and units cleared, state elasticity assumptions, and hand off for merchant sign-off.

# Notes

Output is wrong if it ignores cost floors (marking below cost without intent), double-counts SKUs already on an active markdown, or applies a blanket discount instead of SKU-specific depth. Elasticity estimates are approximate — flag any SKU where the depth is a guess rather than data-backed. This skill drafts and recommends a markdown plan; price changes are irreversible to customers and competitive perception, so a merchant approves before any reduction goes live. Do not use for everyday/promotional pricing (use promotion-effectiveness) or for newly received full-price assortment.

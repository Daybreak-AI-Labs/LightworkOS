---
name: margin-bridge
triggers:
  - margin bridge
  - gross margin walk
  - margin decomposition
  - explain the change in gross margin
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Decomposes the change in gross margin (rate and/or dollars) between two periods into its drivers: price, input/unit cost, volume, and mix. Produces a margin bridge that attributes each basis point or dollar of margin movement to a named cause, reconciling to the reported margin change.

# Steps

1. Confirm the two periods, the margin definition (gross margin $ vs % and what sits in COGS), and the grain. Query revenue, units, and COGS for both periods via sql_query at product level; derive unit price and unit cost.
2. Compute the bridge components on the retained product set: price effect (Δprice × current units), cost effect (−Δunit cost × current units), volume effect (Δunits × base unit margin), and mix effect (shift in product weights at base margins) as the residual.
3. In the spreadsheet, lay out beginning margin, each driver column, and ending margin; for a rate bridge also show the denominator (revenue) effect so price and mix don't double-count. Confirm the components sum to current − base margin exactly.
4. Report the bridge with the COGS scope and price/cost/volume/mix convention stated, sources cited per input, and any products excluded for missing cost data flagged as unverified. State assumptions on cost allocation.

# Notes

Wrong if the margin definition is ambiguous (which costs are in COGS, fully-absorbed vs variable) — the bridge inherits that ambiguity. Rate bridges and dollar bridges are different decompositions; don't mix them. Mix is the residual and absorbs any classification error, so a large unexplained mix term signals a data problem, not a real driver. Unallocated or stepped fixed costs distort unit cost — note them. This is a draft analysis for finance review, not a restated figure; a human validates before it informs pricing or guidance decisions.

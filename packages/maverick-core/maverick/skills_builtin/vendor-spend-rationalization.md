---
name: vendor-spend-rationalization
triggers:
  - vendor rationalization
  - consolidate vendors
  - tail spend
---
# What this skill does

Analyzes vendor spend to identify consolidation and tail-spend reduction opportunities, then produces a rationalization plan with estimated savings. Output is a ranked set of consolidation moves (redundant vendors, fragmented categories, off-contract spend) with a defensible savings estimate per move.

# Steps

1. Pull vendor-level spend via `sql_query` — vendor, normalized category, annual spend, transaction count, contract/PO coverage — and aggregate to one row per vendor; normalize name variants so the same supplier isn't split.
2. Profile the base in `spreadsheet`: rank by spend, isolate the long tail (e.g. bottom-decile spend / high vendor count), and cluster vendors serving the same category to surface redundancy and maverick (off-contract) spend.
3. For each consolidation candidate, model the savings basis explicitly — volume leverage to a preferred vendor, tail elimination, or contract/price standardization — and state the assumed savings rate and its source (benchmark vs estimate, mark estimates as such).
4. Assemble the plan ranked by net savings and switching effort, with per-move rationale and total addressable savings, and hand off — stating data coverage (spend % captured), the time window, and that savings are pre-negotiation estimates pending sourcing validation.

# Notes

Output is wrong if name variants aren't merged (overstates vendor count, understates per-vendor spend), if savings rates are applied without a stated basis, or if one-time/pass-through spend is treated as recurring addressable. Switching costs, contractual exit terms, and single-source/critical-supplier risk must be noted — do not recommend cutting a sole-source vendor blind. This recommends a plan; it does not terminate contracts or notify vendors — procurement and a human owner decide irreversible moves. Skip when spend data lacks category or contract fields needed to find redundancy.

---
name: lcr-hqla-classification
triggers:
  - lcr
  - hqla
  - net cash outflow
  - liquidity coverage ratio
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Classifies high-quality liquid assets into Level 1 / 2A / 2B with the prescribed haircuts and composition caps, nets stressed 30-day cash outflows against capped inflows, and computes the liquidity coverage ratio. The goal class is "compute the LCR": build the HQLA numerator under the caps and the net-cash-outflow denominator under the inflow cap, and produce the ratio.

# Steps

1. Read the asset inventory and contractual flows with read_file and classify HQLA: Level 1 (cash, central-bank reserves, top-grade sovereigns) at no haircut; Level 2A (lower-rated sovereigns, certain agency/covered bonds) at a 15% haircut; Level 2B (certain corporates, equities) at larger haircuts. Search knowledge_search for the current eligibility and haircut schedule.
2. Apply the composition caps to the numerator: Level 2 assets combined are capped at 40% of total HQLA, and Level 2B is capped at 15%; compute the adjusted HQLA stock after haircuts and caps.
3. Build the denominator: total expected cash OUTflows over the 30-day stress (applying the run-off rates to deposits and funding) less total expected cash INflows, where inflows are capped at 75% of outflows so a bank cannot rely entirely on inflows.
4. Compute LCR = adjusted HQLA / net cash outflows over 30 days, and report it against the 100% minimum, showing the caps and haircuts that bound the result.

# Notes

The two caps are where LCR calculations go wrong: the 40% Level-2 / 15% Level-2B composition caps on the numerator, and the 75% inflow cap on the denominator — ignoring any of them overstates the ratio. Haircuts apply BEFORE the caps. The denominator is a stressed 30-day NET outflow, not a contractual gross figure; run-off and inflow rates are prescribed assumptions, not the bank's own estimates. This skill computes and reports the ratio with its components for treasury and regulatory-reporting review; it does not file the regulatory return.

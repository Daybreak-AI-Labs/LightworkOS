---
name: expansion-whitespace-analysis
triggers:
  - find whitespace in this account
  - where can we expand this customer
  - identify upsell opportunities
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Maps unrealized expansion potential ("whitespace") across an existing account and produces a prioritized set of expansion plays. Compares what the customer owns and uses against the full product/seat/business-unit surface to surface concrete upsell and cross-sell opportunities with a rationale and qualification signal for each.

# Steps

1. Confirm the account. Pull current state via `sql_query`: products/SKUs owned, seats provisioned vs. active, business units/regions covered, and consumption against entitlements.
2. Build the whitespace map by comparing owned/used surface against the full catalog and the account's org footprint; identify untapped products, under-licensed teams, and adjacent business units.
3. Run `knowledge_search` over account notes, QBRs, and stated goals to qualify each gap with a buying signal (expressed need, growth, exec sponsor) and disqualify dead ends.
4. Prioritize plays by fit and signal strength; for each, give the opportunity, supporting evidence, rough scope, and a suggested next step. Hand off to the AE/CSM, flagging unverified usage data and stating assumptions.

# Notes

Wrong if an opportunity is asserted without a usage/need signal (spray-and-pray), if it ignores known blockers (budget freeze, contract constraints), or if it double-counts already-sold capacity. Tie each play to sourced data. Pricing, quotes, and outreach are staged for a human to approve — don't contact the customer. Not for net-new logos or for accounts already at full product adoption.

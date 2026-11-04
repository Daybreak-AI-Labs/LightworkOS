---
name: network-design-siting
triggers:
  - network design analysis
  - where should we locate the facility
  - distribution network siting
tools_needed:
  - spreadsheet
  - pandas_query
---
# What this skill does

Decides where to locate facilities or distribution centers by modeling cost-to-serve across candidate sites against demand. Produces a network analysis that compares siting options on total landed cost (transport + facility + inventory) and service level, ending in a ranked siting recommendation. Handles greenfield DC placement, network consolidation, and re-balancing after a demand shift.

# Steps

1. Assemble the real inputs: demand by location (volume/weight per destination), candidate site coordinates with fixed/variable facility costs, and freight rates or a distance-based cost proxy. If any of demand, rates, or candidate sites is missing, name the gap and stop short of a recommendation rather than fabricating figures.
2. With pandas_query, compute distance (or transit cost) from each candidate site to each demand point and the per-site cost-to-serve = inbound + outbound transport + facility cost + carrying cost, scaled by demand. Capture service level (e.g. % of demand within a transit-time threshold) alongside cost.
3. In a spreadsheet, build the option comparison: each candidate site (or combination) as a scenario with total landed cost, service-level coverage, and capacity headroom. Run sensitivity on the load-bearing assumptions (demand growth, fuel/freight rate, facility fixed cost).
4. Report the network analysis with the cost-to-serve table, the cost-vs-service trade-off, and a ranked siting recommendation. State every assumption and which input is unverified; present the lead option plus the runner-up so a human owner makes the capital decision — do not commit a site.

# Notes

The output is wrong if it optimizes transport cost alone and ignores service level or capacity — the cheapest site that misses the transit-time target is not the answer. Distance proxies understate real freight when lane rates are asymmetric; use actual rates when available and mark proxy-based numbers as approximate. Garbage demand data produces a confidently wrong site, so validate volumes before modeling. Do not use for facility-level layout or routing problems, and never treat the recommendation as a siting decision — capital commitments are irreversible and stay with a human.

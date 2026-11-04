---
name: market-entry-analysis
triggers:
  - market entry
  - expansion analysis
  - new market
tools_needed:
  - web_search
  - spreadsheet
---
# What this skill does

Assesses whether and how a company should enter a new market (a geography, segment, or category). Produces a structured market-entry analysis covering market sizing (TAM/SAM/SOM), recommended entry mode (organic, partnership/JV, acquisition, licensing), and the key risks and a go/no-go lean. Sizing math is shown and traceable, not asserted.

# Steps

1. Define the target market precisely: who the buyer is, the offering, the geography, and the time horizon. State any boundary you assumed when the user left it open.
2. Size the market with `web_search` for demand drivers, population/spend, growth rate, and comparable players; build TAM/SAM/SOM in a `spreadsheet` with every input cell sourced and the formula chain visible. Mark any estimate without a citation as `[unverified]`.
3. Evaluate entry modes against capital, speed, control, and risk: organic build, partnership/JV, acquisition, or license/distributor. Score each mode and name the trade-offs for this specific entrant.
4. Surface risks across regulatory, competitive, operational, and FX/macro dimensions; for each, note likelihood and a possible mitigation.
5. Report: deliver the sizing table, the ranked entry modes, the risk register, and a go / no-go / conditional-go lean with the conditions named. Restate assumptions and flag `[unverified]` inputs and any single-point sensitivity.

# Notes

The analysis is wrong when sizing is a single round number with no input trail, when TAM is confused with realistically-capturable SOM, or when a mode is recommended without weighing capital and control. Treat the go/no-go as a recommendation that a human commits — entry spend is largely irreversible, so stage the decision. Do not use to map competitors in an already-entered market (use competitive-landscape-map), and do not proceed while the target market is undefined.

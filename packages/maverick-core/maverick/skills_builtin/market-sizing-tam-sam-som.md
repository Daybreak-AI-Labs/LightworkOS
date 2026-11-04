---
name: market-sizing-tam-sam-som
triggers:
  - market sizing
  - tam sam som
  - how big is the market
tools_needed:
  - web_search
  - spreadsheet
---
# What this skill does

Estimates a market's size at three nested levels — Total Addressable Market (TAM), Serviceable Available Market (SAM), and Serviceable Obtainable Market (SOM) — using both a top-down (analyst/industry figure narrowed by filters) and a bottom-up (units × price × adoption) method, then reconciles the two. Produces a TAM/SAM/SOM stack with every assumption sourced and a stated confidence based on how far the two methods diverge.

# Steps

1. Define the market crisply: product category, geography, customer segment, and time horizon. Ambiguity here invalidates everything downstream — restate the definition back before sizing.
2. Top-down: web_search for a published industry/analyst market figure matching the definition; cite the source and date. Narrow it to SAM via explicit filters (geography, segment, channel) and to SOM via a defensible share assumption tied to competition/capacity.
3. Bottom-up: in the spreadsheet, build TAM from primitives — number of potential customers × units each × average price (× purchase frequency if recurring). Cite each driver's source; mark estimated drivers unverified. Apply the same segment/share filters to reach SAM and SOM.
4. Reconcile the two TAM figures: if they differ by more than ~2x, find which assumption drives the gap and report a range, not a point. Hand off the TAM/SAM/SOM stack with method-by-method numbers, the reconciliation, named sources, and a confidence rating.

# Notes

The dominant failure mode is double-counting (summing overlapping segments) or unit mismatch (revenue vs. seats vs. devices) — keep one consistent unit per level. A single uncited top-down number is not market sizing; the bottom-up cross-check is what makes the estimate defensible, so never skip it. Stale source figures (>2-3 years) drift badly in fast markets — note the source year. Treat all outputs as estimates for planning; do not present SOM as a revenue forecast or commitment, and flag that a human should validate share assumptions against actual competitive data.

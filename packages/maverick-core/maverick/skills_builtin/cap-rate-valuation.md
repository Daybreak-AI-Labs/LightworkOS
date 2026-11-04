---
name: cap-rate-valuation
triggers:
  - cap rate valuation
  - income approach
  - noi valuation
tools_needed:
  - spreadsheet
---
# What this skill does

Values an income-producing property by direct capitalization: derives stabilized net operating income (NOI), applies a supported capitalization rate, and returns an indicated value with sensitivity. Produces a valuation memo showing the NOI build, the cap-rate derivation from comparables, and a value range — the income approach a senior appraiser would defend.

# Steps

1. Build stabilized NOI in `spreadsheet`: effective gross income (gross potential rent less vacancy/credit loss, plus other income) minus operating expenses. Use in-place or market figures explicitly — state which — and exclude debt service, capex, depreciation, and income tax from NOI.
2. Derive the cap rate from evidence, not assumption: pull comparable sales (sale price ÷ NOI) for like property type, vintage, and market; reconcile to a point rate. Cite each comp's source; mark any rate that is a broker quote or survey rather than a closed transaction.
3. Apply Value = NOI ÷ cap rate. Run sensitivity: tabulate value across a cap-rate band (e.g. ±50-75 bps) and across the NOI low/base/high cases, so the output is a range, not a false-precision single number.
4. Report the indicated value range, the concluded point value, the NOI build, and the cap-rate support table. State assumptions (stabilized vs. trailing NOI, market vs. contract rent, expense ratio) and note that this is the income approach only — reconcile against sales-comparison/cost if those exist.

# Notes

Output is wrong if non-operating items (capex, reserves done inconsistently, debt service) leak into NOI, or if the cap rate is borrowed from a different property type/market than the comps support. A reserve-for-replacement convention must match between subject and comps. This is a draft valuation for review — it does not set a transaction price or a loan basis; a human decides those. Do not use when income is not stabilized (heavy lease-up, development) — DCF is the right tool there.

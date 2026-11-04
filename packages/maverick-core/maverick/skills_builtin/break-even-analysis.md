---
name: break-even-analysis
triggers:
  - break even
  - breakeven point
  - margin of safety
tools_needed:
  - spreadsheet
---
# What this skill does

Computes the unit volume or price at which contribution margin exactly covers fixed cost, plus the margin of safety against a planned or actual volume. Produces a break-even point (units and revenue), the per-unit and ratio contribution margin, and the sensitivity of break-even to the key cost/price drivers. Use it to validate pricing, capacity, or go/no-go decisions for a product or line.

# Steps

1. Pull the three required inputs from the source model: fixed cost (period total), variable cost per unit, and selling price per unit. Cite the cell/source for each; if any is a planning assumption rather than actuals, mark it unverified.
2. Compute unit contribution margin (price − variable cost) and the contribution margin ratio (CM / price). If CM is zero or negative, stop and report — there is no finite break-even, the product loses money on every unit.
3. Compute break-even units (fixed cost / unit CM) and break-even revenue (fixed cost / CM ratio). Round units UP to the next whole unit, since fractional units don't cover cost.
4. Compute margin of safety against the planned/actual volume (actual − break-even, as units and as % of actual). Run a one-variable sensitivity table (e.g. ±10% on price and on variable cost) in the spreadsheet, then report the break-even, margin of safety, and which driver moves break-even most — stating which inputs were assumptions.

# Notes

Single-product math only: a blended break-even across a product mix requires a weighted-average CM and is invalid if the mix shifts — flag this and switch to mix-weighted CM if multiple products share the fixed cost. Misclassifying a semi-variable cost (e.g. stepped capacity, commissions) as purely fixed or purely variable is the most common error and silently distorts the answer; split mixed costs before computing. Break-even assumes linearity (constant price and unit variable cost across the range) — note this when volumes imply volume discounts or overtime. This skill recommends a break-even target; the pricing or capacity commitment is a human decision.

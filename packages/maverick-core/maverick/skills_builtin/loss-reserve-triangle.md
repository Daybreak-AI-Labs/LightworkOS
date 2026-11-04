---
name: loss-reserve-triangle
triggers:
  - loss triangle
  - ibnr
  - chain ladder
  - reserve estimate
tools_needed:
  - read_file
  - spreadsheet
---
# What this skill does

Builds paid and incurred loss-development triangles, selects age-to-age link ratios and a tail factor, and reconciles a chain-ladder estimate against a Bornhuetter-Ferguson estimate into a reserve range including IBNR. The goal class is "estimate unpaid claim liabilities actuarially": develop losses to ultimate, compare methods, and express a range rather than a single brittle point.

# Steps

1. Read the claims data with read_file and arrange it into development triangles by accident (or report) period and development age, building both paid and incurred triangles in a spreadsheet.
2. Compute age-to-age (link) ratios for each development interval, select ratios (averages, judgment, or weighted), and choose a tail factor to develop beyond the observed triangle to ultimate.
3. Apply the chain-ladder method (ultimate = latest diagonal x cumulative development factor) and separately the Bornhuetter-Ferguson method (which blends an a-priori expected loss with the chain-ladder development), so immature periods are not over-leveraged.
4. Reconcile the two: chain-ladder for mature periods, BF for green/volatile recent periods, and present a reserve range with IBNR = ultimate less paid (or less case-incurred), documenting the selection judgment at each step.

# Notes

Chain-ladder is unstable for the most recent, least-developed periods because a small early movement is multiplied by a large development factor — that is exactly where Bornhuetter-Ferguson belongs, anchoring on an expected loss ratio. The tail factor is a judgment call that can swing the answer materially; document and stress it. A single point estimate hides the uncertainty; a range is the honest output. Watch for changes in case-reserving practice or mix that break the triangle's homogeneity assumption. This skill produces an actuarial estimate for the actuary's review and sign-off; it does not book the reserve.

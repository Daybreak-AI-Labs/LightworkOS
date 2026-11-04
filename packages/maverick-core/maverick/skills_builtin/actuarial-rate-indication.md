---
name: actuarial-rate-indication
triggers:
  - rate indication
  - actuarial pricing
  - loss cost review
tools_needed:
  - spreadsheet
---
# What this skill does

Produces an actuarial rate indication for a line of business: the percentage rate change supported by historical experience. It develops losses to ultimate, trends premium and losses to the prospective policy period, loads expenses and profit, and outputs the indicated rate change with each component shown so an actuary can review the math.

# Steps

1. Pull the experience period from the source exhibit (earned premium, paid/incurred losses, claim counts by accident year, exposure base). Confirm the number of years and the on-level/current rate level basis; do not invent missing years — flag them.
2. Develop losses to ultimate: build the paid (or incurred) triangle, compute age-to-age link ratios, select LDFs (volume-weighted or judgmental), apply the tail factor, and record selected ultimates per year.
3. Apply trend: bring premium to current rate level (on-leveling), trend ultimate losses and exposures to the midpoint of the prospective period using the stated annual trend rates. Show the trend factor and the period used.
4. Compute the indicated change: indicated rate = (trended ultimate loss + LAE) / (on-level earned premium) / permissible loss ratio, where permissible = 1 - expense ratio - profit/contingency load. Report the indicated change %, every component (loss ratio, LDFs, trend, expense load, credibility weight if used), and assumptions; stage as a recommendation for actuarial sign-off.

# Notes

Wrong when LDF selection or tail is unjustified, premium is not on-leveled (overstates indication), trend period midpoints are off, or credibility weighting against a complement is omitted on thin data. Mark any judgmental selection as such and cite the experience exhibit. This is an indication, not a filed rate — regulatory filing, rate capping, and final selection are human/regulatory decisions. Do not use for an individual-risk price (that is underwriting/experience rating), only for portfolio-level rate level.

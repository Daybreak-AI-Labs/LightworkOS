---
name: opex-driver-model
triggers:
  - opex model
  - cost driver model
  - expense planning
  - model operating expense by driver
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a driver-based operating-expense model that projects opex from underlying volume, headcount, and rate assumptions rather than flat growth percentages. Produces a transparent opex plan where each line ties to a named driver (heads × loaded cost, transactions × unit cost, % of revenue) and totals reconcile to a target or prior actuals.

# Steps

1. Pull prior-period actual opex by category (cost center or G/L line) and identify the natural driver for each: headcount-driven (salaries, benefits), volume-driven (cloud, payment fees), or fixed/step (rent, software seats). Cite the actuals source.
2. For each category gather the driver value and rate — e.g., headcount by team × fully-loaded cost per head, or transaction volume × unit rate. Calibrate rates against actuals so the model reproduces the base period before projecting.
3. In the spreadsheet, build category = driver × rate with assumptions in clearly labeled input cells; add hiring ramp timing for headcount and step thresholds for capacity-based fixed costs. Keep one assumption per cell, no hard-coded outputs.
4. Roll categories to total opex, reconcile the base year to actuals (variance should be near zero), and report the model with every driver and rate sourced or marked as an assumption, plus a short note on the ramp and step logic. Flag any rate not grounded in actuals as unverified.

# Notes

Wrong if the base period doesn't reconcile to actuals — an uncalibrated rate makes every projected period wrong. A flat %-growth line hiding inside a "driver" model defeats the purpose; only use %-of-revenue where a true variable relationship exists. Step costs (additional rent, license tiers) move in jumps, not smoothly — model the threshold or the plan understates hiring-driven cost. Fully-loaded cost per head must include benefits, taxes, and tooling, not base salary alone. This is a planning draft for FP&A review; headcount and spend commitments are irreversible actions a human approves before execution.

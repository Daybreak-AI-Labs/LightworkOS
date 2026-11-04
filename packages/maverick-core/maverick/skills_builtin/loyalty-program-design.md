---
name: loyalty-program-design
triggers:
  - design a loyalty program
  - rewards program
  - retention program design
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Designs a customer loyalty/rewards program: tier structure, earn and burn mechanics, and the underlying economics (liability, breakage, margin impact). Produces a design doc with a working economic model, not just a tier diagram.

# Steps

1. Establish objectives and constraints: target behavior (frequency, spend, retention), eligible segments, and budget/margin ceiling. Pull baseline metrics (purchase frequency, AOV, margin) and any existing program rules via `knowledge_search`. State which inputs are real vs assumed.
2. Design the structure: tiers with entry thresholds and benefits, the earn rule (points per spend/action), and the burn rule (redemption value and catalog). Keep point value (cost per point redeemed) explicit and consistent.
3. Model the economics in `spreadsheet`: projected points issued, expected redemption/breakage rate, outstanding liability, and net margin impact per tier and overall. Run a low/expected/high scenario; flag where the program goes margin-negative.
4. Report the design with the tier table, earn/burn rules, the economic model, and a rollout/guardrail plan (caps, expiry, fraud limits). State all assumptions and which figures are modeled vs sourced; stage launch approval for a human.

# Notes

Output is wrong if point value is undefined, breakage is assumed away (overstating margin), or liability is omitted — unredeemed points are a real balance-sheet obligation. Mark every assumed rate as assumed and cite sourced baselines. Earn/burn rates and tier thresholds set lasting financial commitments and customer expectations, so launch is a human decision, not an automated one. Don't use this for a one-off promo or discount (no ongoing points/tier mechanic).

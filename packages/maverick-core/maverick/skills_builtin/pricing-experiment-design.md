---
name: pricing-experiment-design
triggers:
  - design pricing test
  - packaging experiment
  - price elasticity test
tools_needed:
  - spreadsheet
  - sql_query
  - knowledge_search
---
# What this skill does

This skill frames a rigorous pricing or packaging experiment — an A/B test, a geo/cohort holdout, or a Van Westendorp / Gabor-Granger survey — into a fully specified design document so a human can decide whether to run it. It fixes the hypothesis, the unit of randomization, the eligible segments, the primary and guardrail metrics, the minimum detectable effect (MDE) with the required sample size and power, and an explicit rollback plan. The output is a design and analysis plan only; this skill never alters a live price, plan, or entitlement, and it never ships a test without a documented human commit.

# Steps

1. Use knowledge_search to pull the current price book, prior pricing tests, the monetization model, and any legal/grandfathering constraints; restate the decision the test must inform (e.g. "does a 15% list increase on the Pro tier hurt conversion more than it lifts ARPA?") as a falsifiable hypothesis with a null.
2. Use sql_query to size the eligible population and baseline rates (visit->trial->paid conversion, ARPA, churn) per candidate segment, and to compute the historical variance of the primary metric — you need that variance to size the test.
3. Use spreadsheet to compute the MDE, required sample size, and runtime for the chosen power (default 80%) and alpha (default 0.05); define the unit of randomization (visitor, account, or geo), the primary metric, and the guardrail metrics (refunds, churn, support tickets, downgrade) that auto-halt the test.
4. Assemble the design doc: hypothesis, variants, segments, randomization, metrics, MDE/power, runtime, guardrails, analysis method (frequentist or sequential), and a concrete rollback (revert to the control price for new and in-flight buyers). Stage it for a named approver and mark it DRAFT — no price changes until a human commits.

# Notes

Never mutate a live price, coupon, or entitlement from this skill — the deliverable stops at a staged plan. Watch for price tests that strand existing customers: spell out grandfathering and honor in-flight quotes, since changing a price under someone mid-purchase is both a trust and often a legal problem. A test underpowered for its MDE will read as "no effect" when the effect is real, so refuse to greenlight a runtime that can't reach significance; say so explicitly. Guardrail metrics must be able to stop the test automatically — list them, don't just mention them. Survey-based elasticity (Van Westendorp) estimates willingness-to-pay but is not a substitute for a live conversion test; label which method produced which number.

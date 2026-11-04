---
name: experiment-design-product
triggers:
  - design a product experiment
  - set up an A/B test for this feature
  - feature test plan
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a runnable product experiment (typically an A/B or holdout test) for a proposed change: a falsifiable hypothesis, a primary metric and supporting metrics, guardrail metrics, and the sizing/duration needed to read it. Output is an experiment-design spec a team can implement and analyze without ambiguity.

# Steps

1. State the change and the hypothesis as falsifiable: "Changing X for [population] will move [primary metric] by [expected effect/direction] because [mechanism]." Ground the expected effect in prior data via knowledge_search (past experiments, baseline rates); if none exists, mark the effect size assumed and flag it.
2. Define one primary metric (the decision metric), supporting metrics, and guardrails (revenue, latency, error rate, churn signals) that must not regress. Specify the randomization unit (user/session/account) and the exposure point so assignment is unbiased.
3. Size the test: from the baseline rate, minimum detectable effect, power, and significance level, compute required sample and minimum runtime (cover full weekly cycles). State the analysis method and the decision rule up front to prevent peeking; pre-register the stopping criteria.
4. Document the design: hypothesis, metrics, guardrails, unit, sizing, duration, decision rule, and rollback plan. Report assumptions (baseline, MDE, traffic) and hand off for review; do not start the experiment — launch is a human decision.

# Notes

The design is invalid if success criteria are set after seeing data, the randomization unit differs from the analysis unit, or sample/runtime are too small to detect the MDE (underpowered = inconclusive). Guardrails are mandatory: a primary-metric win that regresses revenue or latency is a loss. This skill produces a draft spec only — a human approves launch and any ship/kill decision. Do not use for changes that cannot be safely or ethically randomized, or where traffic is too low to ever reach power.

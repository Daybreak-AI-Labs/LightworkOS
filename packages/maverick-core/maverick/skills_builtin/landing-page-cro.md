---
name: landing-page-cro
triggers:
  - landing page
  - cro
  - conversion optimization
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Audits a landing page and produces prioritized conversion-rate-optimization recommendations: each a specific change tied to a hypothesis and a testable success metric. Goal class is improving conversion on an existing page, not redesigning from scratch. Produces a ranked list of experiments ready for a human to prioritize and run.

# Steps

1. Gather context: use `knowledge_search` for the page's goal, target audience, current conversion rate/funnel data, and brand constraints; use `web_search` to review the live page content and check competitor/category conversion patterns. Cite each external reference.
2. Diagnose against the conversion funnel — clarity of value prop, headline/CTA alignment, friction in the form/flow, trust signals, page speed, and message-match with the traffic source. Ground each finding in observed page content or data, not assumption.
3. For each issue write a hypothesis ("Because X, changing Y should improve Z"), the proposed change, the metric to measure (e.g. CTR on primary CTA, form completion), and a rough effort/impact rank.
4. Output a prioritized table (recommendation, hypothesis, metric, effort, impact) and flag which changes warrant an A/B test versus a safe direct fix. Report assumptions and hand off for prioritization.

# Notes

Output is wrong if recommendations are generic best-practice with no tie to this page's data, if claimed lifts are stated as fact rather than hypotheses to test, or if current performance is guessed. Recommend and stage tests; a human ships changes and judges results against significance. Don't use it when there's no baseline traffic/data to test against, or for net-new pages with no existing page to audit.

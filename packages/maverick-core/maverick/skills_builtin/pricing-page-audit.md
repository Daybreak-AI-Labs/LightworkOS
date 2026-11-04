---
name: pricing-page-audit
triggers:
  - pricing page audit
  - pricing audit
  - packaging review
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Audits a live pricing/packaging page for clarity, comprehension, and conversion friction, then produces a prioritized list of concrete fixes. Output is a structured audit naming each issue, the page element it lives on, the evidence, and a recommended change ranked by impact and effort. Handles SaaS, services, and product pricing pages; it diagnoses, it does not redesign.

# Steps

1. Read the target pricing page (URL supplied by the requester) and capture the actual tiers, prices, feature rows, CTAs, billing toggles, and any fine print verbatim — do not paraphrase or fill gaps from memory.
2. Score each tier against clarity heuristics grounded in what the page shows: is the value metric obvious, is there a clear "most popular" anchor, are feature differences scannable, is the CTA action explicit, are annual/monthly and add-on costs unambiguous. Flag every place a buyer must guess.
3. Use web_search and knowledge_search to compare packaging norms for 2-3 named direct competitors (cite each source URL); note where this page deviates in tier count, naming, or what is gated, and whether the deviation helps or hurts.
4. Report a ranked fix list — each item: element, observed problem, evidence (page quote or competitor cite), recommended change, impact/effort. State assumptions (e.g. unknown buyer segment) and hand off as recommendations for the page owner to approve.

# Notes

Output is wrong if it invents prices/features the page does not show, or asserts conversion gains as fact — pricing changes must be A/B validated, so frame every recommendation as a hypothesis. Competitor claims must carry a fetched source and date; mark anything unverified. This is a draft audit: do not push edits to the live page or change prices — a human owner decides. Do not use it for legal/compliance review of pricing terms, or when no real page/URL is available (a hypothetical page yields fabricated findings).

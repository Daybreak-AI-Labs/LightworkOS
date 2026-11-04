---
name: seo-content-gap
triggers:
  - content gap
  - seo gap
  - competitor content
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Finds topics and queries where named competitors rank or publish and the target site does not, then prioritizes the gaps worth closing. Output is a content-gap analysis: each gap names the topic/query, which competitors cover it, what the target lacks, and a priority based on relevance and opportunity. Handles competitive organic-content planning; it identifies gaps, it does not produce the content.

# Steps

1. Establish the target site's existing coverage via knowledge_search (published pages, ranking topics) and confirm 2-4 real named competitors and the topic area in scope — do not guess competitors.
2. Use web_search to enumerate each competitor's covered topics and ranking queries in scope, capturing the source URL for every claim so the comparison is auditable.
3. Compute the gap: topics/queries covered by one or more competitors but absent or thin on the target site; for each, record who covers it, the evidence, and an estimated relevance to the target's audience and goals.
4. Prioritize gaps by relevance and apparent opportunity (intent value, competitive density) and report the ranked list, marking volume/difficulty as estimated vs sourced and stating assumptions for the content owner to act on.

# Notes

The analysis is wrong if "gaps" are based on unverified competitor coverage or on the target's coverage being misread — every gap needs a fetched source and a check against actual existing pages. Do not fabricate competitor rankings or volumes; mark estimates as unverified. This is a prioritized recommendation for a human to commission; it creates no pages and changes nothing live. Not for keyword-cluster building from scratch (use seo-keyword-strategy) or for on-page optimization of existing content.

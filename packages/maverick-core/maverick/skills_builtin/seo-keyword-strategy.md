---
name: seo-keyword-strategy
triggers:
  - keyword strategy
  - seo topics
  - search strategy
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Builds a keyword and topic strategy for a site or product area: a seed-expanded keyword set grouped into topic clusters and mapped to search intent and funnel stage. Output is a clustered keyword map where each cluster names a pillar topic, its member queries, the dominant intent, and a recommended page type. Handles organic-search planning; it does not write the pages.

# Steps

1. Establish seeds from real inputs: the site's products, existing ranking pages, and audience language gathered via knowledge_search; record the target domain and geo/language so intent reads correctly.
2. Expand seeds with web_search — pull related queries, "people also ask", and competitor-ranking terms; capture each query with its source so the list is verifiable, not invented.
3. Group queries into topic clusters (one pillar + supporting queries each) and label each query's intent (informational, commercial, transactional, navigational) and funnel stage from the SERP evidence you actually observed.
4. Map each cluster to a recommended page type (pillar, comparison, how-to, product) and report the keyword map with intent rationale, noting which volume/difficulty figures are estimated vs sourced and handing off to the SEO owner.

# Notes

Output is wrong if it lists keywords without intent evidence, fabricates search volume, or treats one model's guess as a metric — flag any volume/difficulty number as unverified unless pulled from a cited tool. Intent must come from observed SERPs, not assumption. This is a planning recommendation; it does not change site content or meta — a human prioritizes and implements. Not for technical SEO audits (crawl, indexation, Core Web Vitals) — use a separate skill.

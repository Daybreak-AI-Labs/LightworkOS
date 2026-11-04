---
name: competitive-teardown
triggers:
  - competitive teardown
  - competitor analysis
  - product comparison vs us
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Produces a structured teardown of a named competitor product: its capabilities, strengths, gaps, pricing/packaging, and the positioning implications for our own product. Output is a decision-grade brief, not a marketing hit-piece.

# Steps

1. Fix the scope: the competitor, the specific product/edition, and the comparison axes (capabilities, pricing, integrations, target segment, governance/security). Pull current facts via `web_search` (vendor docs, pricing pages, release notes, credible reviews) and our own context via `knowledge_search`. Date-stamp and cite every external claim.
2. Map capabilities against the agreed axes. Separate verified facts (sourced) from inference (marked `[inferred]`). Note product maturity signals: GA vs beta, last release date, public roadmap commitments.
3. Identify their genuine strengths and their real gaps relative to us. Be honest about where they win — an inflated teardown misleads strategy. Tie each gap to a concrete buyer pain it leaves unsolved.
4. Translate findings into positioning implications: where we differentiate, where we are at parity, where we are behind and must hedge. Report the teardown with a sourced fact table and state assumptions; flag any axis where evidence was thin.

# Notes

Output is wrong if it cites stale pricing/features, treats marketing copy as verified capability, or omits the competitor's real strengths to flatter us. Always cite sources with dates; mark inference as inference; never fabricate features or numbers. This is an input to strategy — recommendations (repositioning, pricing moves) are staged for a human owner, not executed. Don't use it for a vague "market overview" with no named competitor or axes.

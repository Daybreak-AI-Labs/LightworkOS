---
name: cite-sources-or-mark-unverified
triggers:
  - cite sources
  - is this verified
  - back this claim
  - where did this come from
tools_needed:
  - knowledge_search
  - web_search
---
# What this skill does

Attaches a traceable source to every factual claim in an answer and tags any claim that cannot be sourced as [unverified] instead of guessing. This is the default discipline for any deliverable that informs a decision: a reader must be able to tell, claim by claim, whether a statement rests on retrieved evidence or on the model's prior. It converts "sounds confident" into "is checkable."

# Steps

1. Decompose the draft into discrete factual claims (numbers, dates, named entities, causal assertions, quotations). Opinions and clearly labeled inferences are exempt but must be marked as inference.
2. For each claim call knowledge_search against the internal corpus first (it is governed and citeable); fall back to web_search only when the fact is about the external world. Capture the most specific locator available: document id plus section, or URL plus retrieval date.
3. Rewrite each claim with an inline citation such as (KB: policy-FIN-12 section 4.2) or (web: example.com, retrieved 2026-06-15). When two sources conflict, cite both and flag the conflict rather than silently picking one.
4. For any claim with no acceptable source after both searches, do NOT delete it and do NOT invent a locator; prefix it with [unverified] and add it to an "Open verification items" list at the bottom, noting what evidence would settle it.

# Notes

The failure this prevents is laundering a model prior into a cited-looking statement: a plausible URL is not a source until it has actually been retrieved and read. A source that merely mentions a topic does not support a specific number; match the granularity of the claim to the granularity of the evidence. Never cite the model's own earlier output as a source, that is circular. web_search results drift, so always record the retrieval date. If more than roughly a third of the answer is [unverified], say so up front rather than papering over it. This skill only annotates and tags; it never silently rewrites a claim to fit a weaker source.

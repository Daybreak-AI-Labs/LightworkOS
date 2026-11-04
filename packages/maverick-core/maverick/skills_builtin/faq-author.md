---
name: faq-author
triggers:
  - build an faq
  - frequently asked questions
  - turn these into help content
tools_needed:
  - knowledge_search
---
# What this skill does

Builds a customer- or employee-facing FAQ from the questions people actually ask, grounded in authoritative source material. Produces a grouped set of question/answer pairs with each answer traceable to a cited source, so support teams can publish it as help content without re-verifying every line.

# Steps

1. Collect the real input questions from the requester (support tickets, sales objections, onboarding threads). Do not invent questions — if the list is thin, ask for the source corpus before proceeding.
2. For each distinct question, run `knowledge_search` to find the authoritative answer; capture the source doc/section for citation. Mark any question with no source hit as UNVERIFIED rather than guessing.
3. Deduplicate and merge near-identical questions, then cluster them into logical groups (e.g. Getting Started, Billing, Security) so readers can scan.
4. Write each answer in plain language, one fact per sentence, with the citation inline or footnoted. Hand off the grouped FAQ, list any UNVERIFIED items needing a human/SME answer, and state which question groups had the thinnest source coverage.

# Notes

The output is wrong if an answer is asserted without a source — every claim must trace to `knowledge_search` or be flagged UNVERIFIED. Watch for stale source docs (pricing, limits, policy) and note the source date. This is a draft: a human owner approves before publishing, and any answer touching legal, pricing, or security commitments must be SME-reviewed. Do not use this to answer a single ad-hoc question — it's for assembling a reusable, grouped FAQ artifact.

---
name: ai-act-conformity-check
triggers:
  - check this system against the EU AI Act
  - is this a high-risk AI system
  - AI Act conformity obligations
tools_needed:
  - knowledge_search
---
# What this skill does

Performs a first-pass conformity check of an AI system against the EU AI Act. Produces a classification (prohibited, high-risk per Annex III/I, limited-risk/transparency, or minimal) and the resulting obligations — risk management, data governance, technical documentation, logging, human oversight, transparency, and conformity-assessment route. Output is a draft legal/compliance memo for review, not a CE-marking or legal sign-off.

# Steps

1. Capture the system's role, intended purpose, sector, deployment geography, and whether the provider places it on the EU market or its output is used in the EU, via knowledge_search against the system spec and the Act text/Annexes (cite article and recital numbers; mark anything unstated as an open question).
2. Screen for prohibited practices (Art. 5) first; if clear, classify as high-risk by checking Annex I (safety components) and Annex III (listed use cases) against the actual purpose, then transparency obligations (Art. 50) for limited-risk patterns like chatbots, deepfakes, or emotion recognition.
3. For the resulting class, enumerate the applicable obligations and the conformity-assessment route (self-assessment vs. notified body), plus GPAI/foundation-model duties if a general-purpose model is involved. Cite the governing article for each obligation; do not assert an obligation the text does not support.
4. Compile the memo with the classification, the deciding Annex/article, the obligation checklist, registration/CE-marking implications, and open legal questions. State assumptions, note applicability/transition dates, and hand off to legal/compliance counsel.

# Notes

Output is wrong if a classification is stated without citing the deciding article or Annex entry, if a prohibited-practice screen is skipped, or if "no obligation" is concluded from missing information rather than the text. The Act's classification turns on intended purpose and exact use case — small wording changes move a system between tiers, so flag ambiguity instead of guessing. This is a non-binding first-pass triage that drafts and recommends; the legal determination, conformity assessment, and any market-placement decision are irreversible actions reserved for qualified human counsel. Do not use for non-EU-market systems where the Act does not apply, and do not treat it as a completed conformity assessment.

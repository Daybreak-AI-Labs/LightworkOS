---
name: customer-journey-map
triggers:
  - map the customer journey
  - build a journey map of touchpoints
  - where are customers dropping off in their experience
tools_needed:
  - knowledge_search
---
# What this skill does

Constructs an end-to-end customer journey map for a defined persona and scenario: the stages a customer moves through, the touchpoints and channels at each, the customer's actions, thoughts, and emotional highs/lows, the pain points, and the resulting improvement opportunities. Produces a stage-by-stage map grounded in retrieved evidence (research, tickets, interviews), with unsupported stages flagged. It maps experience; it does not commit roadmap or process changes.

# Steps

1. Anchor the scope from the request: which persona/segment, which journey (onboarding, renewal, support resolution, purchase), and the start and end boundaries. If any is unstated, choose a default and label it an assumption rather than guessing silently.
2. Use `knowledge_search` to pull evidence per the scenario — support tickets, interview notes, NPS/CSAT verbatims, product analytics summaries, prior research. Tag each finding to a journey stage and cite its source; mark any stage with no supporting evidence as "unverified / hypothesis."
3. Lay out the stages in sequence; for each, capture touchpoints/channels, the customer's actions, their goals, their thoughts and emotional state (high/neutral/low), and the friction or pain observed. Note moments of truth and drop-off points where evidence shows them.
4. Derive opportunities from the documented pains (one or more per significant friction point) and deliver the map: stages × {touchpoints, actions, emotions, pains, opportunities}, plus the evidence citations and a list of unverified stages. Hand off as a research artifact; prioritization and any fix is a human/cross-functional decision.

# Notes

The map is wrong when emotions and pains are invented to fill a tidy curve — every claim must trace to a cited source or carry an explicit "hypothesis" tag; never fabricate verbatims. A journey with no boundaries sprawls; pin the start/end and persona or the map is unusable. Opportunities are recommendations, not commitments — do not present them as decided roadmap. Do not use this for a single transactional interaction (use a simpler touchpoint review) or when no customer evidence exists at all, since the result would be pure speculation dressed as research.

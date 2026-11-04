---
name: capability-maturity-model
triggers:
  - maturity model assessment
  - capability maturity
  - rate our maturity against a model
tools_needed:
  - knowledge_search
---
# What this skill does

Scores a capability against a defined maturity model (e.g., 5-level initial-to-optimized) and turns the gaps into a staged roadmap. It assigns a current level per dimension with evidence, identifies the target level, and sequences the moves between them. Output is a maturity assessment that justifies investment and ordering, not a vanity scorecard.

# Steps

1. Select or retrieve the maturity framework and its dimensions via knowledge_search (cite it); confirm the level definitions for each dimension so scoring is criteria-based, not gut feel. If no model is specified, propose a standard one and flag it as a choice for the user.
2. For each dimension, gather evidence of current practice (docs, prior assessments, stakeholder input) and assign a level strictly against the published criteria. Record the evidence per score and mark anything unverified.
3. Set a realistic target level per dimension (not always level 5 — target should fit business need), compute the gap, and sequence remediation into stages where each stage is a coherent step up and respects dependencies between dimensions.
4. Report the assessment with a per-dimension level table (current, target, gap, evidence), an overall maturity summary, and a staged roadmap. State assumptions, cite the model, and note that target levels and roadmap sequencing are recommendations for stakeholder sign-off.

# Notes

The output is wrong if levels are assigned by impression rather than against the model's criteria, or if every dimension is targeted at level 5 regardless of cost/benefit — over-maturing a low-value capability wastes investment. Always attach evidence to each score; a level without evidence is unverified and must be labeled so. Cite the framework used; do not invent level definitions. This is a recommendation; investment and target-state decisions belong to a human. Skip when there is no agreed model and no appetite to choose one — scoring against an invented scale is meaningless.

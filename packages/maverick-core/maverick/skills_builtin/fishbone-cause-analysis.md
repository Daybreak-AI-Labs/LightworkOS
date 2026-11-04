---
name: fishbone-cause-analysis
triggers:
  - fishbone
  - ishikawa
  - cause categories
tools_needed:
  - knowledge_search
---
# What this skill does

Structures the candidate causes of a defect or problem into an Ishikawa (fishbone) diagram organized by standard cause dimensions, then prioritizes the branches most likely to be root causes for follow-up investigation. It produces a categorized cause map and a ranked shortlist of candidate causes — a hypothesis-generation artifact, not a confirmed root cause.

# Steps

1. State the effect precisely (the defect, its measurable symptom, and where/when observed) from the supplied problem statement. A vague effect produces a useless diagram; confirm the effect before branching.
2. Select the category set appropriate to the domain via `knowledge_search` — 6M (Man, Machine, Method, Material, Measurement, Mother-nature/Environment) for manufacturing, or 4P/7Ps for service/process — and name which framework you chose.
3. Populate each branch with candidate causes drawn only from supplied evidence (observations, data, process knowledge). Tag each cause as evidenced or speculative; never present a guessed cause as fact.
4. Prioritize causes by plausibility and impact (optionally via team ranking or a quick "is it testable / how strong is the signal" pass). Mark the top candidates for verification with the data or test that would confirm or refute each.
5. Report the fishbone (effect plus categorized branches) and the prioritized candidate list with proposed verification steps, stating that these are hypotheses requiring data confirmation before any corrective action.

# Notes

Output is wrong if causes are presented as confirmed without verification, if branches are miscategorized (e.g. a measurement-system issue filed under Method), or if the effect is too broad to discriminate causes. Cite evidence per cause and clearly separate evidenced from speculative entries. This produces hypotheses only — it does not confirm root cause or authorize a fix; a human owns the verification and any corrective action. Not a substitute for designed experiments or 5-Whys when a single causal chain is already evident.

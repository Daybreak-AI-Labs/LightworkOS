---
name: candidate-evaluation-synthesis
triggers:
  - candidate evaluation
  - debrief synthesis
  - hiring decision
---
# What this skill does

Synthesizes an interview panel's feedback into a single evaluation for one candidate: a per-competency assessment backed by quoted evidence from interviewer notes, areas of agreement and disagreement, and a recommendation (e.g. hire / no-hire / more data) with rationale. Output supports a debrief; it does not make the decision.

# Steps

1. Gather every interviewer's written feedback and the competencies they were assigned. knowledge_search the role's competency model and scoring rubrics so each piece of feedback is scored against the same bar; note any interviewer who left no notes (a gap, not a neutral).
2. Map evidence to competencies: for each competency, collect the specific observations and quotes that support it, and tag whether the signal was positive, negative, or insufficient. Attribute every claim to its source interviewer — never merge into an unsourced summary.
3. Surface disagreement explicitly: where interviewers scored the same competency differently, present both with their evidence rather than averaging it away, and identify what additional signal would resolve it.
4. Hand off a synthesis with an evidence-backed recommendation and confidence level, stating assumptions (missing feedback, competencies assessed by only one interviewer) and noting clearly that the final hiring decision is a human one made at the debrief.

# Notes

The synthesis is wrong if it asserts conclusions without attributable evidence, launders interviewer disagreement into a false consensus, or weights an unscored competency as a pass. Quote and attribute all evidence; mark thin coverage as low-confidence. Watch for bias signals in source notes (comments on "culture fit," personality, or protected traits unrelated to competencies) and flag rather than amplify them. This is a recommendation only — extending or rejecting an offer is an irreversible human decision and must stay with the hiring manager. Not for building the rubric (use the question-bank skill).

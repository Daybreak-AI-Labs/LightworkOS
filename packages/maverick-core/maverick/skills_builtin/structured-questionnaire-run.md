---
name: structured-questionnaire-run
triggers:
  - run the assessment
  - work through this questionnaire
  - score this control
  - complete the questionnaire
tools_needed:
  - start_assessment
  - answer_question
  - finalize_assessment
---
# What this skill does

Drives an assessment/questionnaire flow end to end — start, answer each item with a cited basis, finalize — returning "unknown" honestly where evidence is absent rather than fabricating a passing answer. The goal class is "complete a structured assessment defensibly": every answer is backed by evidence or explicitly marked unknown, and the run is reproducible.

# Steps

1. Call start_assessment to open the flow and load the question set and any scoring rubric. Note required vs optional items and any conditional branches.
2. For each item, gather the supporting evidence first, then call answer_question with the answer AND the evidence reference. Match the answer to what the evidence actually supports, not to what would score best.
3. When evidence is missing or contradictory, answer unknown / not-determined and record what would be needed to resolve it; do not guess a compliant answer to avoid a gap.
4. Call finalize_assessment, then surface the completed result with its score, the list of unknowns, and any items routed for human confirmation.

# Notes

The temptation in any scored questionnaire is to answer toward the high score; resist it — an inflated assessment fails the moment it is audited and destroys the credibility of the whole exercise. Conditional branches matter: a wrong answer early can skip questions that should have been asked. "Unknown" is a legitimate, valuable answer; treating it as failure pressures fabrication. This skill records answers within the assessment tool; it does not submit the result to any external party or attest to it on a human's behalf.

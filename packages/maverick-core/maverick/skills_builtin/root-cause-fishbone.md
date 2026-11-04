---
name: root-cause-fishbone
triggers:
  - build a fishbone for this defect
  - ishikawa cause and effect analysis
  - what are the categories of root cause
tools_needed:
  - knowledge_search
---
# What this skill does

Decomposes a single confirmed defect or problem statement into candidate causes organized by standard Ishikawa categories (Man, Machine, Method, Material, Measurement, Environment), then ranks the branches by likelihood and evidence. Produces a fishbone diagram (as structured text/branches) with a prioritized shortlist of causes to investigate next, not a verdict.

# Steps

1. Pin the effect: restate the defect as one precise problem statement (what, where, when, magnitude). If the input is vague or bundles multiple problems, split it and ask which one to analyze rather than guessing.
2. For each of the six categories, use knowledge_search over incident history, SOPs, and prior corrective actions to surface concrete candidate causes; cite the source for each cause and mark causes with no supporting evidence as `unverified — hypothesis`.
3. Drill each plausible branch with "why" follow-ups until you reach an actionable cause (a thing a team could change), not a symptom.
4. Score each cause on likelihood (evidence strength) and impact, output the fishbone as category branches with sub-causes, and hand off a top-3 prioritized list of causes to verify, stating which are evidence-backed vs hypotheses.

# Notes

The output is wrong if hypotheses are presented as confirmed causes, or if symptoms are listed instead of root causes — always trace to something changeable. A sparse branch is fine; do not invent causes to fill a category. This is a diagnostic aid that recommends what to investigate; it does not confirm the cause or authorize a fix — a human owns that decision and any process change. Do not use it before the defect is reproduced or clearly defined, or for multi-defect tangles (analyze one effect per diagram).

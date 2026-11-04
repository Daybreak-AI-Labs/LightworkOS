---
name: pharmacovigilance-signal
triggers:
  - pharmacovigilance
  - adverse event
  - signal detection
tools_needed:
  - knowledge_search
---
# What this skill does

Assesses whether a suspected drug–adverse-event pair constitutes a safety signal: gathers the reported cases, computes/interprets disproportionality, and applies a structured causality framework to produce a defensible signal assessment. Outputs a draft signal evaluation with strength-of-evidence and a recommended action (monitor, prioritize for review, refer). It does not file regulatory reports or change labeling.

# Steps

1. Define the pair precisely: the suspect drug (active ingredient, not brand spread across synonyms) and the adverse event coded to a standard term (MedDRA PT/SOC). Ambiguity here corrupts every downstream count — resolve it first.
2. Use `knowledge_search` to retrieve the relevant case series and reference data: spontaneous-report counts, known label/SmPC events, biological plausibility, and any prior signals. Cite each source; mark counts you cannot source as `UNVERIFIED`.
3. Compute or interpret disproportionality (PRR, ROR, or IC/EBGM as available) with the standard caveats — note thresholds (e.g., PRR ≥ 2 with ≥3 cases and chi-square ≥ 4) and explicitly flag confounding, reporting bias, and indication bias. Do not treat disproportionality as proof of causation.
4. Apply a causality framework (e.g., Bradford Hill considerations or WHO-UMC categories): temporality, dechallenge/rechallenge, plausibility, and alternative explanations. Report a graded signal assessment (e.g., not a signal / weak / strong), the evidence, and a recommended next step. State assumptions and what a qualified safety physician must verify.

# Notes

The assessment is wrong if event terms aren't coded to a controlled vocabulary, if disproportionality is read as causality, or if reporting/notoriety bias is ignored (a media-driven spike mimics a signal). Spontaneous data cannot give true incidence — never imply a rate. This is a *draft* assessment: a qualified pharmacovigilance physician confirms signals, and any regulatory filing or labeling change is a human-owned, irreversible action that this skill only stages. Not for individual ICSR case processing or expedited reporting decisions.

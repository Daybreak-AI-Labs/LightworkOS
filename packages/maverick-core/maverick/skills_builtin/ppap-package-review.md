---
name: ppap-package-review
triggers:
  - review this PPAP package
  - part submission approval
  - is this production part submission complete
tools_needed:
  - knowledge_search
---
# What this skill does

Qualifies a Production Part Approval Process (PPAP) submission for a production part against the required element set for its submission level. Produces a structured review verdict (approve / interim / reject) backed by a per-element checklist, with each gap traced to the specific missing or non-conforming artifact. Handles incoming supplier submissions and internal re-validations after engineering changes.

# Steps

1. Read the submission package and confirm the controlling inputs: part number, revision, the PPAP submission level requested (1-5), and the reason for submission (initial, engineering change, tooling move, etc.). If level or reason is not stated, do not assume — flag it and proceed at Level 3 as the default working assumption.
2. Pull the governing element list for that level via knowledge_search against the AIAG PPAP manual / customer-specific requirements; cite the source and edition. Build the checklist of required elements (design records, DFMEA, PFMEA, control plan, MSA, dimensional results, material/performance test results, PSW, etc.) gated to the level.
3. Walk each required element against the package: mark present-and-conforming, present-but-deficient (state the specific defect, e.g. Cpk below 1.33, MSA %GRR over 10%, unsigned PSW), or missing. Cross-check internal consistency — part/rev/dates must agree across PSW, control plan, and dimensional results.
4. Report the verdict with the completed checklist, list every gap blocking approval, and state assumptions (level used, sources cited). Stage the decision as a recommendation: a human approver signs the PSW — never auto-approve or auto-reject a production part.

# Notes

The output is wrong if elements are checked for mere presence rather than conformance — a submitted-but-failing MSA is a reject, not a check. Submission level drives which elements are required; reviewing at the wrong level produces false gaps or false approvals, so the level must be confirmed, not guessed. Mark any requirement you could not source as unverified rather than inventing a threshold. Do not use this for prototype/pre-production parts outside the PPAP scope, and never issue the final approval — PPAP sign-off is an irreversible quality gate reserved for a human.

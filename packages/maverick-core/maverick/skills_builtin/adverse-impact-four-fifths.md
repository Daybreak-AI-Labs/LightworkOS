---
name: adverse-impact-four-fifths
triggers:
  - run adverse impact
  - four-fifths test
  - disparate impact rate
  - selection rate analysis
tools_needed:
  - spreadsheet
---
# What this skill does

This skill computes selection-rate ratios across protected-class categories for a hiring, promotion, or termination process and compares each ratio to the EEOC four-fifths (80%) rule of thumb to flag potential adverse impact. It works strictly on aggregated counts (applicants vs selected per group) and produces a group-level statistical screen — it is a diagnostic that points to where a closer legal/validation review is warranted, never an input to any individual's hire/fire decision. The deliverable is an aggregate-only impact-ratio table with flags and caveats, staged for HR/legal review.

# Steps

1. Use spreadsheet to load the aggregated counts: for each category (e.g. race/ethnicity, sex, age band) record the number considered and the number selected. Refuse to proceed on raw row-level records that identify individuals — the analysis must be on group totals only.
2. Compute the selection rate per group (selected / considered), identify the group with the highest selection rate as the reference, and compute each other group's impact ratio (group rate / highest rate).
3. Flag any group whose impact ratio falls below 0.80 (the four-fifths threshold) as a potential adverse-impact indicator. For any flagged or small-N group, note the absolute counts and that the 4/5ths rule is unstable at small sample sizes — recommend a significance test (e.g. Fisher's exact / Z-test of proportions) as a follow-up.
4. Assemble the output table (group, considered, selected, rate, impact ratio, flag) plus a caveats block, and stage it for HR/legal review. Mark clearly that this is a population-level screen and must not be used to adjust any individual decision.

# Notes

This is aggregate-only by design: never let a group-level ratio flow back into an individual selection decision — that itself can create disparate treatment. A passing 4/5ths result is not a clean bill of health (it is a rough screen, weak at small N), and a failing one is not proof of discrimination — it is a trigger for job-relatedness/business-necessity validation by counsel. Watch for small denominators where one person flips the ratio; surface the raw counts so a reviewer sees the fragility. Keep the data de-identified and do not retain protected-class data beyond the analysis. This skill computes and flags; it does not decide.

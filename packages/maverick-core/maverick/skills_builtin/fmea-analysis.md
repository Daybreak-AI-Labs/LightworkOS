---
name: fmea-analysis
triggers:
  - run an FMEA on this process
  - rank our failure modes by risk
  - what's the risk priority number for these failures
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a Failure Mode and Effects Analysis (FMEA) worksheet for a given process, product, or system. For each identified failure mode it captures effects, causes, and existing controls, scores Severity/Occurrence/Detection (1-10), computes the Risk Priority Number (RPN = S x O x D), and ranks the modes so the highest-risk items surface first with recommended mitigating actions and owners.

# Steps

1. Pull the real scope from the user: the process/system boundary, its functions, and any existing failure history (incident logs, returns, prior FMEAs). List the discrete functions or process steps — do not invent steps the user did not name.
2. For each function, enumerate potential failure modes (how it can fail to deliver the function), then for each mode record its effect(s), potential cause(s), and the current prevention/detection controls actually in place. Mark any item inferred rather than sourced as `[assumed]`.
3. In `spreadsheet`, score each row Severity (effect harm), Occurrence (cause likelihood), Detection (1 = controls catch it, 10 = escapes) on the 1-10 convention you state explicitly; compute RPN = S x O x D in a formula column. Sort descending by RPN, with Severity as the tiebreaker.
4. For rows above an agreed action threshold (or top N, or any S>=9), draft a recommended action, responsible owner, and target date; leave action/owner/date blank where the user must decide. Report the ranked worksheet, state your scoring scale and thresholds, and hand off — flag that owners and go/no-go on mitigations are human decisions.

# Notes

Output is wrong if scoring scales are inconsistent across rows, if RPN is read as an absolute risk (it is only a relative triage rank — a high-S/low-RPN mode can still be unacceptable, so always carry Severity separately), or if failure modes are confused with their causes/effects. RPN thresholds are organization-specific; never assert a universal cutoff. This skill drafts and prioritizes only — it does not authorize design changes, recalls, or process stops; those are staged for a qualified human owner. Do not use for a single isolated incident (use root-cause/FTA) or where quantitative reliability (failure rates, MTBF) is required rather than ordinal triage.

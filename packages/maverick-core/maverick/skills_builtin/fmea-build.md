---
name: fmea-build
triggers:
  - build an fmea for this process
  - failure modes and effects analysis
  - calculate rpn for these failure modes
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a Failure Mode and Effects Analysis for a process or product: enumerates each step's potential failure modes, their effects and causes, then scores Severity, Occurrence, and Detection (1-10 each) to compute Risk Priority Number (RPN = S x O x D). Produces a sorted FMEA table that ranks risks and flags the items needing recommended actions.

# Steps

1. Establish scope: get the ordered list of process steps or product functions to analyze. If no rating scale is provided, adopt a documented 1-10 scale and state it explicitly in the output so scores are reproducible.
2. For each step list potential failure modes, then for each: its effect (and worst-case severity), potential cause(s), and current controls (preventive and detection). Ground each entry in real process knowledge; mark assumed entries as `assumption`.
3. In the spreadsheet assign S, O, D per failure mode and compute `RPN = S*O*D`; also flag any item with Severity >= 9 regardless of RPN (safety/critical override). Sort descending by RPN.
4. Output the FMEA table and hand off the top RPN-ranked and high-severity rows as recommended-action candidates with proposed owners, stating that scores are estimates pending team review.

# Notes

The analysis is wrong if scores are guessed without a stated scale, if effects and causes are conflated, or if a high-severity item is buried by a low RPN — always honor the severity override. RPN is a triage signal, not an absolute risk; do not let it justify ignoring catastrophic-but-rare modes. This skill drafts and prioritizes; it does not approve or implement mitigations — a cross-functional team validates ratings and a human owns action sign-off. Do not use it on an undefined process or to certify a design as safe.

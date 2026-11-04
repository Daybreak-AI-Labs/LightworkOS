---
name: sast-finding-triage
triggers:
  - sast triage
  - static analysis findings
  - code scan findings
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Triages a batch of static-analysis (SAST) findings into true positives, false positives, and needs-context, by reading the flagged code in situ and validating each finding against actual data flow. Produces a per-finding verdict with rationale and a concrete fix for confirmed issues.

# Steps

1. Load the scanner output (rule ID, file, line, severity) and treat it as a claim to verify, not a fact. Group findings by rule so identical patterns are triaged consistently.
2. For each finding, read_file the flagged location plus enough surrounding context to trace whether tainted input reaches the sink — check for upstream validation, sanitization, or framework-level escaping that the scanner missed.
3. Use knowledge_search to confirm the rule's true semantics (e.g., CWE class, exploit precondition) so a verdict rests on the actual weakness, not the rule name. Mark a false positive only when the data flow is provably broken or the sink is inert.
4. Assign each finding true-positive / false-positive / needs-context, attach file:line evidence and a fix (or suppression justification) for confirmed ones, and report counts by severity. State which verdicts depend on assumptions about untraced callers.

# Notes

The output is wrong if a finding is dismissed as a false positive without tracing the data flow that proves the sink is unreachable — "looks fine" is not a verdict. Suppressions must carry a written justification; never silently drop a finding. This skill recommends verdicts and fixes; it does not edit code or modify the scanner baseline — a human merges fixes and approves suppressions. Do not use it to triage runtime/DAST or dependency findings (use the SCA skill for the latter).

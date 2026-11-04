---
name: tech-debt-assessment
triggers:
  - tech debt
  - technical debt
  - refactoring priorities
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Produces a prioritized technical-debt register for a codebase or component. Output is a table of debt items each scored by impact (risk, change-friction, toil) and effort, with a ranked remediation order and rationale. Handles the "what should we pay down first" goal class — it recommends priorities, it does not refactor.

# Steps

1. Inventory debt from real evidence: use `read_file` on the target modules, configs, and any TODO/FIXME/deprecation markers, and `knowledge_search` for incident history, prior refactor notes, and ownership. Record each item with a concrete code/file reference; never list debt you cannot point to.
2. For each item capture impact dimensions grounded in evidence: blast radius, change frequency (hot vs cold code), incident/bug linkage, and ongoing toil; mark any dimension you couldn't verify as UNVERIFIED rather than guessing.
3. Estimate remediation effort (S/M/L or rough days) and dependencies/sequencing constraints between items. Compute a priority signal (e.g. impact ÷ effort, or risk-weighted), and note quick wins vs large structural bets separately.
4. Produce the register sorted by priority with a one-line justification and the source reference per row. Report it and hand off, stating assumptions, confidence per estimate, and which items need owner input before scheduling.

# Notes

Wrong if items are vague ("clean up the auth code") with no file reference, if impact is asserted without evidence, or if effort estimates are presented as commitments rather than rough sizing. Prioritization is a recommendation for humans to schedule — do not begin refactors or delete code from this skill. Hot, incident-linked, low-effort items should outrank cosmetic ones; surface that explicitly. Do not use to justify a predetermined rewrite, and do not conflate style/lint nits with structural debt. Cite incident and frequency claims to a source; never fabricate metrics.

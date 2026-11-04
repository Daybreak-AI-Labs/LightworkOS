---
name: succession-bench-review
triggers:
  - succession
  - bench strength
  - key roles at risk
  - succession review
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Reviews succession bench strength for key roles: maps named successors to each critical role, scores readiness, and surfaces roles with thin or no coverage as risk. Handles the goal class "if we lost this leader, who steps in, and where are we exposed" — output is a bench review with readiness tiers and a ranked at-risk role list.

# Steps

1. In `spreadsheet`, load key roles and their candidate successors with the underlying signals: incumbent flight-risk/retirement horizon, role criticality, and each successor's readiness inputs (performance, potential, tenure-in-grade, prior reviews). Flag roles with zero identified successors immediately — that is the headline risk.
2. Assign a readiness tier per successor on a stated scale (e.g., Ready Now / Ready 1-2 yrs / Ready 3+ yrs / Emergency-only) using explicit, consistent criteria; record the criteria so the rating is auditable and not a black box.
3. Compute bench depth per role (count and tier mix of viable successors) and a coverage flag: critical role with no Ready-Now-or-soon successor = high risk. Use `knowledge_search` to pull the org's succession framework or prior bench reviews and cite which standard you applied.
4. Output the review: per-role bench table, a ranked at-risk roles list (high criticality x thin/no bench x high incumbent-risk), and recommended development or external-pipeline actions. End by reporting assumptions (readiness scale, criticality and flight-risk sources) and hand off to HR/leadership for talent-review calibration.

# Notes

Wrong if it treats a single named successor as adequate coverage (single point of failure), inflates readiness without criteria, or relies on a stale incumbent-risk guess — mark such inputs "unverified." Succession data is highly confidential and individually identifying; never expose it outside the talent-review audience and never use it to infer or communicate anyone's standing to them. This skill DRAFTS a review and RECOMMENDS development moves; promotions, role assignments, and external hiring are irreversible decisions reserved for human leadership in calibration. Do not use as a performance-rating or termination input.

---
name: draft-for-human-review
triggers:
  - prepare for approval
  - stage this
  - draft for sign-off
  - ready for review
tools_needed:
  - read_file
---
# What this skill does

Produces a review-ready artifact wrapped in a standard decision header so a human approver can act in seconds rather than reverse-engineering what they are being asked to bless. The goal class is "hand a deliverable to a person for sign-off": the work is staged, never executed, and the reviewer sees exactly what decision is required, who must make it, what changed, and what is still open.

# Steps

1. Read the underlying material with read_file (the draft, the prior version, the relevant policy) so the header reflects the real content, not a guess.
2. Prepend a four-field header: Decision-required (the single yes/no or pick-one being asked), Approver (the role or named owner who can authorize it), What-changed (a tight diff against the prior state or baseline), Open-questions (anything the reviewer must resolve before approving).
3. Keep the body self-contained: a reviewer should not need to open five tabs. Inline the key figures and quote the exact clause or number that drives the recommendation.
4. End with an explicit "This is a draft pending <Approver> sign-off — no action has been taken" line so the artifact cannot be mistaken for something already executed.

# Notes

The anti-pattern is burying the ask: a reviewer who has to read three pages to find the decision will rubber-stamp or stall. Decision-required must be answerable, not "please review." Do not collapse Open-questions into the body; an empty Open-questions list is a meaningful signal (nothing blocking), and hiding unknowns to look finished erodes trust. This skill stages only; it must never auto-send, auto-merge, or auto-file. Pair it with require-human-gate-checklist when the underlying action is on the hard-floor list.

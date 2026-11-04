---
name: feature-flag-rollout
triggers:
  - feature flag
  - progressive rollout
  - ring deployment
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a progressive feature-flag rollout plan for a single behavioral change gated behind a flag. Output is a staged ring plan (internal → small % → broad), an explicit kill switch, and the metrics that gate promotion between rings. Handles the "ship behind a flag and ramp safely" goal class, not the code change itself.

# Steps

1. Identify the flag from real inputs: flag name/key, the default (off) behavior, the new behavior, the blast radius (which users/tenants/surfaces), and whether the change is reversible at runtime. If any are missing, mark them UNVERIFIED and ask before assuming.
2. Run `knowledge_search` for the team's existing flag conventions, prior rollout postmortems, and SLO/alert definitions for the affected surface; cite what you find and note gaps.
3. Define rings with concrete entry/exit gates: e.g. ring 0 = internal/dogfood, ring 1 = 1-5%, ring 2 = 25-50%, ring 3 = 100%. For each ring state the audience selector, soak time, and the numeric promotion criteria (error rate, latency, conversion, support tickets) sourced from step 2.
4. Specify the kill switch: exact flag state to revert to, who can flip it, expected propagation time, and whether any data written under the new path needs cleanup. Report the plan and hand off, stating all assumptions and the rollback owner.

# Notes

Wrong if rings have no measurable exit gate (then it is a schedule, not a rollout) or if the kill switch leaves orphaned/incompatible data behind — flag flips must be truly reversible, otherwise treat the change as a migration instead. Do not use for changes that alter persisted schema or are not runtime-reversible; route those to a migration runbook. Promotion between rings is a recommendation; a human approves each promotion and any 100% rollout. Cite metric thresholds to a source; never invent SLO numbers.

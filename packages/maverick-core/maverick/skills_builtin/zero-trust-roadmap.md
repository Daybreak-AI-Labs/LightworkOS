---
name: zero-trust-roadmap
triggers:
  - zero trust
  - ztna roadmap
  - never trust always verify
tools_needed:
  - knowledge_search
---
# What this skill does

Assesses an organization's current security posture against a recognized zero-trust maturity model and produces a phased progression roadmap. Output is a maturity assessment scored across the standard pillars (identity, devices, network, applications/workloads, data) plus governance/automation, with each pillar placed on a maturity stage and a sequenced set of phases to advance. It produces a plan, not configuration changes.

# Steps

1. Establish the target framework via `knowledge_search` (e.g. CISA Zero Trust Maturity Model, NIST SP 800-207). Cite the specific model and version used; do not blend pillars from different models without saying so.
2. Gather the current state per pillar from supplied inputs (asset inventory, IAM/MFA coverage, segmentation, logging) — record each data point with its source. Mark any pillar with no evidence as "unverified", never assume a maturity level.
3. Score each pillar against the model's stages (e.g. Traditional / Initial / Advanced / Optimal) with a one-line justification per score citing the evidence.
4. Sequence phases by dependency and risk-reduction-per-effort (identity and device trust usually gate network/app controls). For each phase list entry criteria, the controls it adds, and exit criteria.
5. Report the assessment table, the phased roadmap, and an explicit assumptions/gaps list. Flag that prioritization is a recommendation — the security owner approves scope and timing before any control rollout.

# Notes

Output is wrong if maturity stages are inflated beyond the evidence, if pillars from incompatible frameworks are mixed silently, or if phases ignore dependencies (e.g. microsegmentation before device identity). Cite the framework and every current-state data point; mark gaps as unverified rather than guessing. This is an advisory deliverable — do not enable, disable, or reconfigure any control; staging and cutover are human-approved. Not for incident response or a single-control config question; use only for posture assessment and multi-phase planning.

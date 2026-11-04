---
name: prior-auth-workflow
triggers:
  - prior auth
  - preauthorization
  - authorization workflow
tools_needed:
  - knowledge_search
---
# What this skill does

Builds a structured prior-authorization (PA) workflow for a given service, drug, or procedure: the decision criteria, required clinical documentation, routing/escalation path, and turnaround-time targets. Produces a draft runbook a utilization-management team can apply to incoming requests, with each criterion traced to its source policy. Does not approve or deny any individual case.

# Steps

1. Pin the request scope: the specific CPT/HCPCS/NDC code(s), line of business (commercial, Medicare Advantage, Medicaid), and the payer/plan whose rules apply. If any of these are missing, stop and ask — PA criteria differ by plan and a wrong plan produces wrong rules.
2. Use `knowledge_search` to pull the governing medical/pharmacy policy and any regulatory turnaround standards (e.g., CMS expedited 72h / standard 14 calendar days for MA). Cite the policy ID and effective date for every criterion; mark anything you cannot source as `UNVERIFIED — confirm with UM policy`.
3. Translate the policy into an ordered decision tree: medical-necessity criteria, step-therapy/prior-trial requirements, required documentation (chart notes, labs, imaging), and explicit auto-approve vs. clinical-review-required branches.
4. Define routing and SLAs: who handles standard vs. expedited, the turnaround target per branch, and the escalation/peer-review path for likely denials. Report the draft workflow, list the sourced policies, and flag every gap a human reviewer must close before go-live.

# Notes

The output is wrong if criteria are pulled from the wrong plan/line of business, or if a turnaround target contradicts the regulatory floor — always verify the LOB first. Never emit a determination on a real member case; this skill drafts the *workflow*, and a licensed clinician makes coverage decisions. Denials in particular must always route to clinical/peer review, never auto-fire. Do not use when the user actually needs a single-case adjudication or an appeal letter — those are separate, human-owned actions.

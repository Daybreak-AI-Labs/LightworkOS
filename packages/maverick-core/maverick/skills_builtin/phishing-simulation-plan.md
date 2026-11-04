---
name: phishing-simulation-plan
triggers:
  - run a phishing test
  - plan a phishing simulation
  - set up security awareness training
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a runnable phishing simulation and follow-up training plan: target cohorts, lure templates mapped to real threat patterns, a send schedule, and the success/risk metrics that will judge it. Output is a staged plan a security lead reviews and authorizes before any email is sent.

# Steps

1. Pull the organization's threat profile and prior incidents from `knowledge_search` (industry, known lures, previous sim results, sanctioned-testing policy). If no policy authorizing simulated phishing exists, stop and flag — do not draft sends without it.
2. Define cohorts from real org data found in knowledge (department, role sensitivity, prior click history). Size each cohort and set a control group; never simulate against groups excluded by policy (e.g., legal hold, executives if disallowed).
3. Draft 2-3 lure templates per cohort grounded in the threat profile (credential harvest, attachment, MFA-fatigue). Mark each template with difficulty and the real pattern it imitates; cite the knowledge source.
4. Specify the send schedule (windowed, never all-at-once to avoid help-desk overload), the landing/training redirect, and metrics (click rate, report rate, time-to-report, repeat-clicker list). Report the full plan as a draft and hand off to the security lead for authorization, stating assumptions about cohort sizes and policy scope.

# Notes

Output is wrong if cohorts or lures are invented rather than grounded in `knowledge_search` results, or if the authorizing policy is unverified — mark anything unconfirmed as such. Sending the simulation is the irreversible action and is NOT part of this skill: the plan is staged for a human to approve and trigger. Do not use for real adversary emulation/red-team payloads, or when no sanctioned-testing policy exists. Always pair clicks with training, never punitive reporting alone.

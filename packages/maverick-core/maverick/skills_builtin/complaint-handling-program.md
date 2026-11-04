---
name: complaint-handling-program
triggers:
  - complaint handling
  - udaap
  - complaint program
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a regulated consumer-complaint-handling program for a financial-services entity, covering intake, triage, root-cause analysis (RCA), remediation, and regulatory reporting. Produces a documented program package mapped to applicable rules (CFPB UDAAP, Reg E/Z/B error-resolution timelines, prudential complaint-management expectations) that an examiner or compliance officer can adopt. Output is a draft program for human approval, not a filed policy.

# Steps

1. Establish scope from the entity's actual products and channels — pull the institution's product list, charter type, and primary/functional regulators from `knowledge_search`; do not assume which rules apply, cite the source for each (e.g. UDAAP applies to all; Reg E error-resolution only where applicable).
2. Define intake: enumerate every channel (call center, web, branch, mail, social, regulator/CFPB portal referrals), a single complaint-record schema (unique ID, date received, channel, product, allegation category, harm/monetary impact, status, owner, resolution date), and acknowledgment/response SLAs grounded in the timelines `knowledge_search` returns for each governing rule — mark any timeline you could not source as UNVERIFIED.
3. Build the triage + RCA workflow: severity tiering (regulatory/legal vs. service), routing rules, a structured RCA method (5-why or fishbone) tying each substantiated complaint to a root cause and a corrective action with an owner and due date, and a UDAAP escalation trigger for potential unfair/deceptive/abusive patterns.
4. Define reporting and governance: board/committee MI (volumes, trends by product/root-cause, aging, repeat issues, remediation status), regulator-facing reporting obligations, retention schedule, and a periodic program-effectiveness review. Hand off the assembled program draft to the compliance owner, stating which rule mappings are cited vs. UNVERIFIED and which timelines need legal confirmation.

# Notes

Wrong if it asserts a response timeline or rule applicability without a cited source — complaint timelines vary by regulation and product, so every number must trace to `knowledge_search` or be flagged UNVERIFIED for counsel. Do not let RCA collapse into per-complaint fixes; the regulatory value is in aggregated root-cause trends and systemic remediation. This skill drafts and recommends only — adopting the program, filing it, or committing to regulator reporting cadences is a human/legal decision. Do not use for adjudicating an individual complaint or for non-regulated general customer-service queues.

---
name: soc2-readiness-assessment
triggers:
  - SOC 2 readiness
  - are we ready for a SOC 2 audit
  - trust services criteria gap check
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Assesses an organization's readiness for a SOC 2 (Type I or Type II) examination by mapping current controls against the AICPA Trust Services Criteria in scope, identifying gaps in design and evidence, and producing a remediation plan. Produces a readiness report: per-criterion status (met / partial / gap), the evidence that exists vs. what an auditor will demand, and prioritized remediation with owners. Use it to decide whether to engage an auditor and where to spend remediation effort first.

# Steps

1. Confirm scope: which Trust Services Criteria categories apply (Security is mandatory; Availability, Confidentiality, Processing Integrity, Privacy are optional add-ons) and whether the target is Type I (design at a point in time) or Type II (operating effectiveness over a period). Pull the current control environment, policies, and any prior report via knowledge_search and read_file. Flag missing inputs rather than assuming a control exists.
2. Walk the in-scope criteria (the common criteria CC1-CC9 plus any added categories). For each, identify the control(s) intended to satisfy it, and check both design adequacy and whether real, dated evidence exists (tickets, logs, access reviews, change records). For Type II, confirm the evidence spans the full audit period — a control that started last week is not yet examinable.
3. Mark each criterion met / partial / gap. For partials and gaps, state precisely what an auditor will request and what is missing (policy not approved, no access-review cadence, logging not retained long enough, vendor list incomplete). Cite the source for every "met"; mark anything you could not corroborate as unverified.
4. Write the readiness report: criteria status table, the evidence gap per item, and a remediation plan ranked by audit-blocking severity with named owners and a realistic lead time (Type II needs an observation period after a control goes live). State that this is an internal readiness view, not an opinion — only a licensed CPA firm issues the SOC 2 report; remediation actions are recommendations for owners to execute.

# Notes

The output is wrong if a control is marked "met" on intent without dated evidence, if Type II readiness ignores that operating effectiveness needs a sustained observation window, or if optional categories are assessed when only Security is in scope (or vice versa). The most common false-positive is a written-but-unapproved policy or a control with no retained evidence — treat those as gaps. Never represent this as an audit opinion or attestation. This is a draft for the compliance owner and prospective auditor to act on; do not commit to an audit date or scope off it. Do not use to review a vendor's existing SOC 2 report — that is a questionnaire/report-review task.

---
name: data-subject-rights-runbook
triggers:
  - dsr runbook
  - data subject rights
  - access request process
---
# What this skill does

Operationalizes how an organization receives, verifies, and fulfills data subject / consumer rights requests (DSR/DSAR) — access, deletion, correction, portability, opt-out, and objection — across applicable regimes. Produces a runbook with intake channels, identity verification tiers, fulfillment workflow, and statutory SLAs. Output is an executable process spec for the privacy operations team.

# Steps

1. Determine which regimes and rights apply from the request (GDPR access/erasure/rectification/portability/restriction/objection; CCPA/CPRA know/delete/correct/opt-out/limit-SPI) and the data subject populations. Note the controlling SLA per regime — GDPR one month (extendable to three), CCPA 45 days (extendable to 90).
2. Use knowledge_search to retrieve the organization's data map / ROPA, system inventory, and existing intake forms so the runbook reflects where personal data actually lives. Define intake channels (form, email, toll-free where required) and a request-logging schema with timestamps for SLA tracking.
3. Specify identity verification tiers proportionate to request sensitivity (deletion of sensitive data demands stronger proof than a simple access copy), the fulfillment steps per right (locate -> collate/redact third-party data -> action -> respond), exemption/refusal handling with documented justification, and escalation for complex or high-volume requests.
4. Report the runbook as: intake -> verification -> triage -> fulfillment -> response/close, with a per-right SLA clock and audit-log requirements, and hand off for privacy/legal sign-off. State assumptions about systems and regimes in scope.

# Notes

Failure modes: starting the SLA clock at verification instead of receipt, deleting data subject to a legal-hold or statutory retention, releasing third parties' personal data in an access response (must redact), or honoring a request without adequate verification (identity-theft risk). Cite the governing SLA per regime; mark unconfirmed system coverage. Irreversible actions — especially erasure — are staged with a documented approval gate so a human authorizes before execution; this skill drafts and routes, it does not auto-delete. Not for the substantive lawful-basis or consent design decisions (use those skills first).

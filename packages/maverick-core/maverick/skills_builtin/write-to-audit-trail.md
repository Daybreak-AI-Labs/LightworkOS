---
name: write-to-audit-trail
triggers:
  - log this decision
  - record to audit
  - evidence this
  - make an audit entry
tools_needed:
  - redact
---
# What this skill does

Prepares a structured decision record for the operator's audit workflow. The base agent registry has no arbitrary audit-append tool. Platform tool-call auditing is separate and must not be presented as a signed append of this draft. Durable publication requires an explicitly provisioned audit integration or an operator handoff.

# Steps

1. Assemble the entry fields before writing: action (what was decided or produced), inputs (the data and parameters used), source_refs (citations backing any factual claims), confidence (a calibrated qualitative or numeric level), and actor (which agent/role and on whose behalf).
2. Serialize the structured draft as JSON. Call `redact` with `op="redact"` and that JSON as `text`, then `op="verify"` on the cleaned text. Preserve the field structure and flag any redaction that prevents reproducibility.
3. Include enough input detail to make the entry reproducible (versions, file ids, the exact question asked) but redact any secret or special-category value first — the audit log is durable and must not become a credential store.
4. Return the cleaned structured draft with `publication_status="awaiting_operator_or_audit_integration"`. If the operator has separately provisioned an audit integration, use only its documented contract and return its actual receipt. Without a successful receipt, explicitly say no durable audit entry was appended; do not invent a sequence id or signature.

# Notes

Audit entries are append-only: never attempt to edit or delete a prior entry to "fix" it — write a new correcting entry that references the original. Logging only the outcome and not the inputs/sources defeats the purpose; the point is reconstructability. Do not dump raw secrets, PANs, or special-category personal data into the trail (run redact-secrets-in-output / redact-pii-before-egress first). Confidence must be honest; an over-confident audit entry is worse than none because it misleads the reviewer who trusts it.

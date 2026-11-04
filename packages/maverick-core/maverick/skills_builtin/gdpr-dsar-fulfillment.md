---
name: gdpr-dsar-fulfillment
triggers:
  - fulfill a DSAR
  - data subject access request
  - right to access or erasure request
  - someone asked for a copy of their data
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Handles a GDPR/CCPA data-subject request (access, portability, or erasure) end to end as a draft plan. Produces a DSAR fulfillment package: a data map of every system holding the subject's personal data, the records to disclose or delete, required redactions of third-party data, and a documented list of lawful exemptions invoked. Output is a reviewable plan, not an executed erasure.

# Steps

1. Capture the request from real intake fields: subject identity, verification status, request type (access/portability/erasure/rectification), scope, and the legal regime (GDPR Art. 15/17, CCPA, etc.). Do not proceed past identity verification — flag if unverified.
2. Build the data map: use `knowledge_search` over the system inventory / RoPA to enumerate every store (CRM, ticketing, logs, backups, processors) that may hold the subject's data, keyed on real identifiers (email, account ID). Mark any source you could not confirm as "unverified — manual check required."
3. For each store, `read_file` the actual export/extract and classify fields: disclose, redact (third-party PII or another subject's data), or withhold-under-exemption (legal privilege, ongoing investigation, trade secret). Cite the exemption clause for every withhold.
4. Assemble the deliverable: data map table, per-source disposition, redaction list, exemption register with citations, and the response-deadline (e.g., 30 days GDPR). State assumptions, then hand off — erasure and the outbound disclosure are STAGED for a human DPO to approve and execute.

# Notes

Wrong if: identity is unverified, a data store is silently missed (backups and processor systems are the usual misses), or third-party PII leaks into an access response. Erasure is irreversible — never execute deletes; produce the delete list and require human sign-off, and confirm no legal hold or retention obligation blocks erasure first. Exemptions must cite a clause, never be asserted. Do not use this for non-personal-data requests or for bulk discovery — it is scoped to one identified data subject.

---
name: public-records-request-handling
triggers:
  - process a FOIA request
  - public records request
  - respond to a records request
tools_needed:
  - knowledge_search
---
# What this skill does

Processes an incoming public-records / FOIA request end to end: interprets scope, locates responsive records, screens for exemptions and required redactions, and drafts a compliant response with a defensible log. Produces a scoped record set, an exemption/redaction memo, and a draft reply letter. Handles statutory disclosure obligations under FOIA or state public-records law.

# Steps

1. Parse the request to fix the exact scope: requester, date range, custodians, record types, and any fee/format terms. If ambiguous or overbroad, draft a clarification/narrowing question rather than guessing.
2. Identify the governing statute and deadline via `knowledge_search` (the agency's records policy and the applicable FOIA/state law), and compute the response due date. Do not assume the federal FOIA timeline applies to a state body.
3. Locate responsive records by custodian/system and build a candidate set. Log search terms and locations so the search is reproducible and defensible.
4. Screen each record against exemptions (e.g., personal privacy, deliberative/attorney-client, security, statutory). Mark exact redactions, cite the exemption per withholding, and note any records to withhold in full.
5. Report: a draft response letter (released records, redactions with cited basis, any denials and appeal rights), plus the search log and exemption memo. State assumptions and flag every redaction/denial for legal/records-officer sign-off before release.

# Notes

Output is wrong if it cites the wrong statute, miscomputes the deadline, redacts without a named exemption, or over-withholds (default is disclosure). Cite the controlling law and policy; mark any uncertain exemption call as unverified for counsel. This is a draft — releasing records, applying redactions, denying a request, and asserting privilege are irreversible and require a human records officer or attorney to approve. Do not use for litigation discovery or internal subpoena response (different rules).

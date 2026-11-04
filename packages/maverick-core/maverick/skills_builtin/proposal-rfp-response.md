---
name: proposal-rfp-response
triggers:
  - rfp response
  - proposal
  - solicitation response
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Drafts a response to a formal RFP or solicitation that is mapped requirement-by-requirement to the issuer's asks. Produces the response narrative plus a compliance matrix — every shall/must/required item traced to where the proposal answers it — so reviewers and the evaluator can confirm full coverage and no item is silently dropped.

# Steps

1. Read the solicitation with `read_file` and extract every requirement: mandatory ("shall/must/required"), evaluation criteria, format/page/font constraints, and submission logistics (deadline, portal, required forms). Number each item; do not paraphrase away a mandatory term.
2. For each requirement, pull supporting content from internal sources via `knowledge_search` — past proposals, capability statements, certifications, past-performance write-ups. Cite the source for every factual or past-performance claim; mark any gap where no qualifying evidence exists.
3. Draft the response section by section in the issuer's required structure and order, answering each requirement in its own language. Build the compliance matrix: requirement ID, location in response, and compliant / partial / exception status.
4. Report the draft response plus the compliance matrix, a list of unmet or partially-met requirements, and any missing forms/signatures. State assumptions and flag every claim that needs SME or legal sign-off before submission.

# Notes

Output is wrong if a mandatory requirement is unaddressed, if format/page limits are violated (common disqualifier), or if a capability or past-performance claim is asserted without evidence — fabricated qualifications are disqualifying and unethical. This produces a draft for human review; submission, pricing, and binding commitments are decided and signed by an authorized person — never auto-submit. Do not use for informal quotes or when the solicitation is unavailable; the requirements list must come from the actual document, not memory.

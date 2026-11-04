---
name: nda-review-redline
triggers:
  - nda review
  - nda redline
  - review this confidentiality agreement
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Reviews a counterparty NDA clause-by-clause against the organization's NDA playbook and produces a redline: proposed edits, the negotiating position behind each, and residual risk notes. Handles mutual and one-way NDAs for the standard term set (definition of Confidential Information, exclusions, permitted use, term/survival, return/destruction, governing law, remedies). Output is a draft for a human reviewer, not a signed position.

# Steps

1. Read the source NDA with read_file; capture its actual clause headings, defined terms, and the party roles (discloser/recipient or mutual). Do not assume a structure the document does not have.
2. Pull the NDA playbook and any deviation precedents with knowledge_search (standard positions, must-haves, walk-away terms, approved fallbacks). Cite the playbook section per position.
3. For each clause, compare the document's text to the playbook standard. Flag: missing must-haves (e.g. no carve-out for independently developed material, no residuals clause, perpetual survival on all info), off-market terms (one-sided indemnity, injunctive relief without bond, unlimited term), and acceptable terms (mark as OK so the reviewer sees coverage).
4. Produce the redline: per clause, quote the original text, give the proposed edit, the one-line rationale tied to the playbook, and a risk note (high/med/low). End with a summary of must-fix vs. nice-to-have items and any open questions for counsel. State that unresolved or novel terms are flagged unverified for a human to decide.

# Notes

Output is wrong if it invents clauses not in the source, cites a playbook position that does not exist, or silently accepts an off-market term. Confidentiality term and survival often differ (term of agreement vs. survival of obligations) — read both; conflating them is a common error. This skill drafts and recommends only; accepting, signing, or sending the redline is a human/counsel decision. Do not use for substantive commercial agreements (MSA, license, employment) — those have far broader risk surfaces and need their own review.

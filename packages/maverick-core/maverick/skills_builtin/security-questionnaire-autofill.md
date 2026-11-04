---
name: security-questionnaire-autofill
triggers:
  - fill security questionnaire
  - answer sig
  - respond to caiq
  - trust center response
tools_needed:
  - knowledge_search
  - read_file
  - spreadsheet
---
# What this skill does

This skill maps inbound security questionnaire questions (SIG, CAIQ, VSA, or a custom buyer spreadsheet) to an organization's approved trust-center answer library and drafts cited responses for human review. Its single governing rule is that it never guesses a control status: every question without a vetted, sourced answer is flagged as unverified and routed to a human owner rather than filled with an optimistic default. The deliverable is a reviewable draft answer matrix, never a submitted or returned questionnaire.

# Steps

1. Use read_file to load the inbound questionnaire workbook and detect the standard from the sheet headers or question IDs (SIG Lite/Core, CAIQ v4, VSA, or bespoke). Capture the exact question text, control ID, and any required answer format (Yes/No/N-A, free text, evidence link).
2. For each question, call knowledge_search against the approved answer library (policies, prior completed questionnaires, the trust center, SOC 2 / ISO statements) and retrieve the closest vetted answer together with its source document and last-reviewed date.
3. Draft each response in the buyer's required format, attaching a citation to the source control or policy. Where the match is partial, ambiguous, or stale (past review date), do NOT answer: set the row status to UNVERIFIED -> human and record why.
4. Use spreadsheet to assemble the answer matrix with columns for question, control ID, drafted answer, citation, last-reviewed date, and confidence; produce a separate gap list of all UNVERIFIED rows, and stage both for the security owner's sign-off.

# Notes

Never assert a control is implemented, or change a Yes/No, without a cited source — a wrong control claim is a contractual misrepresentation. Do not submit, email, or upload the questionnaire; this skill stops at a staged draft. Treat any partial or fuzzy match as a gap, not an answer, and keep every evidence link intact so the reviewer can independently verify each claim. Re-running on an updated answer library is safe and additive; flag answers whose source has changed since the last fill.

---
name: sar-narrative-draft
triggers:
  - sar narrative
  - suspicious activity
  - bsa
tools_needed:
  - knowledge_search
---
# What this skill does

Drafts a Suspicious Activity Report (SAR) narrative from an investigated case file, structured to FinCEN's who/what/when/where/why/how convention. Produces a clear, fact-grounded narrative draft — staged for the BSA officer's review and filing decision — that links the documented activity to the indicators of suspicion without overstating the institution's conclusions. Output is never a filed SAR.

# Steps

1. Gather only the investigated, evidenced facts from the case file — subject(s) and roles, account numbers, the transaction activity (dates, amounts, counterparties, instruments, originating/beneficiary institutions), and the alerting typology — and confirm the activity is within the SAR lookback window. Cite each fact to its case-file source; if a key fact is unsupported, list it as a gap rather than inventing it.
2. Open the narrative with a one-sentence summary: what the institution is reporting, the suspected typology, total dollar amount, and the activity date range. Use `knowledge_search` to ground the typology language and any FinCEN advisory/key-term references in current guidance — mark anything you cannot source as UNVERIFIED.
3. Lay out the body chronologically — who did what, when, where, through which accounts/instruments, and why it is suspicious (deviation from expected activity, structuring, layering, etc.) — using neutral, factual language. State what is observed; do not assert intent or legal conclusions the investigation did not establish.
4. Close with what the institution did (account actions, prior SARs/continuing activity reference) and what it could not determine. Hand the draft to the BSA officer flagged DRAFT — NOT FILED, listing the fact-gaps and any UNVERIFIED references, and noting the filing-deadline clock so the human decides on filing.

# Notes

Wrong if it fabricates or embellishes any transaction detail, asserts criminal intent, or includes facts not in the case file — a SAR narrative must be defensible line-by-line against the investigation record. Tipping-off risk is real: this draft is internal and confidential, never shared with the subject. The skill drafts and recommends only — the decision to file a SAR, and the filing itself within the regulatory deadline, is the BSA officer's call. Do not use to decide whether activity is suspicious (that is the investigation); use it only to write up an already-substantiated case.

---
name: contract-obligation-extraction-deep
triggers:
  - obligation extraction
  - contract obligations
  - key dates
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Extracts the actionable obligations, deadlines, and conditional triggers from a contract into an obligation register for compliance and operational tracking. Produces a row per obligation capturing the obligated party (owner), the duty, the due date or recurrence, the triggering event/condition, the governing clause, and the consequence of breach. Output is a structured register grounded in quoted clause text — no invented dates.

# Steps

1. Load the document: read_file on the contract if a path is given, otherwise knowledge_search to retrieve the full text. Confirm you have the complete agreement including exhibits, SOWs, and amendments — obligations frequently live in schedules, and a later amendment can supersede a date.
2. Sweep for obligations clause by clause: capture every "shall," "must," "will," "agrees to," and notice/consent requirement. For each, record the owner (which party), the duty in plain terms, and the source section. Tag the type (payment, delivery, reporting, notice, renewal, audit, insurance, confidentiality-return).
3. Resolve dates and triggers: classify each obligation's timing as a fixed date, a recurrence (e.g., monthly invoice), a relative deadline (e.g., "within 30 days of receipt"), or event-triggered (e.g., "upon a data breach, notify within 72 hours"). Compute concrete dates only where the anchor date is present in the contract; otherwise record the relative rule verbatim and mark the date UNVERIFIED. Note notice periods that are absolute (auto-renewal opt-out windows are high-risk).
4. Capture consequences and report: for each obligation note the breach consequence (cure period, fee, termination right) where stated. Then hand off the obligation register sorted by next-due date, flagging any UNVERIFIED dates, conflicts between an amendment and the base contract, and the highest-risk near-term deadlines, stating assumptions for a human to validate.

# Notes

Output is wrong if it computes a date from an anchor not in the document, misses an obligation buried in an exhibit or amendment, or assigns the duty to the wrong party. Always tie each row to a quoted clause and section; never fabricate a deadline to fill a column. This is a draft/extract skill — the register is a tracking input that a human validates before any calendar/renewal action is taken; opting out of an auto-renewal or sending a contractual notice is an irreversible action a person must authorize. Do not use it to interpret ambiguous obligations as legal advice, or where the full executed document (with amendments) is unavailable.

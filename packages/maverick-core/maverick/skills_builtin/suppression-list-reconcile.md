---
name: suppression-list-reconcile
triggers:
  - reconcile suppression
  - clean the list
  - pre-send consent check
  - check opt-outs
tools_needed:
  - sql_query
  - read_file
  - spreadsheet
---
# What this skill does

This skill cross-references a target send list against every opt-out, do-not-contact, unsubscribe, hard-bounce, and consent-revocation source across systems, reports the drift between them, and certifies the list as clean — or HALTS — before any email or message is sent. It is a compliance gate that never itself triggers a send; its output is either a certified suppressed list or a stop with reasons.

# Steps

1. Use read_file to load the proposed target list and use sql_query to enumerate all authoritative suppression sources: global unsubscribe, per-brand/per-stream opt-outs, DNC/do-not-contact flags, hard bounces, spam complaints, and consent-withdrawn records (including GDPR/CAN-SPAM/CASL revocations).
2. Normalize identifiers (lowercase email, canonicalize, hash for matching) and left-join the target list against each suppression source, marking the specific reason any record is suppressed.
3. Use spreadsheet to report drift: records present in one suppression source but missing from another (system sync gaps), records on the list that should have been suppressed, and the net cleaned audience count with a per-reason breakdown.
4. Certify or HALT: if every required source was reachable and applied, emit the suppressed list plus a certification record (sources checked, timestamp, counts); if any source was missing, stale, or unreachable, HALT and report the gap instead of certifying.

# Notes

Sending to a suppressed contact is a legal and deliverability incident, so the default on any doubt is HALT, not "send anyway." Never treat an unreachable or stale suppression source as empty — a missing opt-out feed must block certification, not pass silently. Match on normalized identifiers; case and formatting differences cause missed suppressions. This skill does not send and must not be wired to auto-trigger a campaign; a human owns the go decision after reviewing the certification.

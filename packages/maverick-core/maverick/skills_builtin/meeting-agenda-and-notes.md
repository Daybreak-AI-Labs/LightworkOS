---
name: meeting-agenda-and-notes
triggers:
  - meeting agenda
  - meeting notes
  - action items
tools_needed:
  - knowledge_search
---
# What this skill does

Prepares a timeboxed agenda before a meeting and captures structured notes during or after it. Produces an agenda with owners and time allocations, plus a notes record that separates discussion from decisions and lists action items as owner + task + due date.

# Steps

1. Gather context with `knowledge_search`: the meeting's purpose, attendee list, prior meeting notes, and any open action items still outstanding. If purpose is unstated, derive the one or two decisions the meeting must reach and confirm them as the agenda's goal.
2. Build the agenda: ordered topics, each with an owner and a time box; front-load decisions over status updates. Include carried-over action items as a standing first item.
3. During/after the meeting, capture notes under three headings: Discussion (key points, briefly), Decisions (what was agreed, who decided), Action Items (owner, task, due date). Attribute decisions to a named person, not "the team".
4. Flag any action item with no owner or no due date as incomplete and request that the human assign it. Hand off the agenda and notes, noting which items are confirmed versus tentative.

# Notes

Notes are wrong if a decision is recorded without a deciding owner, or an action item lacks an owner or date — those are the fields people act on. Do not invent attendees, dates, or agreements you did not observe; mark anything reconstructed from memory as `[reconstructed]`. This skill drafts and records; commitments and irreversible decisions remain the attendees' to make. Not for transcription — capture decisions and actions, not a verbatim log.

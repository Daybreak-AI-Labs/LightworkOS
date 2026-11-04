---
name: meeting-to-action-items
triggers:
  - turn notes into actions
  - action items from this
  - follow-ups
  - summarize the meeting decisions
tools_needed:
  - read_file
---
# What this skill does

Converts a transcript or meeting notes into owner-dated action items, an explicit decisions list, and an open-questions list, so nothing agreed verbally is lost and every commitment has an accountable owner. The goal class is "make a meeting actionable": separate what was decided from what was merely discussed, and attach an owner and a due date to each follow-up.

# Steps

1. Read the transcript/notes with read_file and segment it into three buckets: decisions made, action items (commitments to do something), and open questions (unresolved threads).
2. For each action item, capture owner (the named person who took it), the concrete deliverable, and a due date. If an owner or date was not stated, mark it [owner TBD] / [date TBD] rather than guessing.
3. Record decisions as standalone statements with enough context to be understood later, and note who decided and any dissent, since "we agreed" often hides a non-consensus.
4. List open questions with the person best placed to resolve each, so the next step is obvious. Output the three lists in a compact, scannable format.

# Notes

Do not promote a discussion into a decision: "we talked about hiring" is not "we decided to hire." Conflating the two manufactures commitments nobody made. Unassigned action items die — always force an owner or explicitly flag the gap for follow-up. Verbatim transcripts are noisy; extract intent, but never invent a due date or owner that was not stated. This skill produces a draft summary for the participants to confirm; it does not assign tasks in any tracker or notify anyone.

---
name: product-roadmap-prioritization
triggers:
  - roadmap prioritization
  - feature prioritization
  - rice scoring the backlog
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Turns a flat list of candidate features into a defensible, ranked roadmap. It applies a transparent scoring model (default RICE: Reach x Impact x Confidence / Effort) to each item, then produces a prioritized table with per-item scores and written rationale so stakeholders can see why item N outranks item M.

# Steps

1. Pull the candidate list from the source the user names (backlog export, doc, or `knowledge_search` over product notes). Capture for each item: a one-line description, the customer/segment it serves, and any existing estimates. Do not invent items that aren't in the source.
2. Choose the scoring framework with the user; default to RICE. For each item, source the inputs: Reach from usage/segment data, Impact and Effort from team estimates, Confidence from how grounded those numbers are. Mark any number you estimated rather than sourced as `assumed`.
3. Build the scoring table in `spreadsheet`: one row per item, columns for each factor, a computed score column, and a rank. Keep the formula visible so the math is auditable.
4. Sort by score, write a one-to-two sentence rationale per top item (and per surprising rank), and report the ranked roadmap. State which inputs were assumed vs sourced and recommend the team confirm Effort estimates before committing.

# Notes

Garbage in, garbage out: RICE rank is only as good as Reach and Effort inputs — flag low-Confidence rows rather than presenting them as settled. The output is a recommendation, not a commitment; sequencing also depends on dependencies, team capacity, and strategy the score doesn't capture, so present it as a decision input for a human owner. Don't use this for a 2-3 item list (scoring overhead exceeds value) or when items aren't comparable units (a platform migration vs a button color don't share a Reach axis — split them first).

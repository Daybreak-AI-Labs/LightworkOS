---
name: decision-memo-author
triggers:
  - write a decision memo
  - draft a recommendation memo
  - put together a SASPE memo
tools_needed:
  - knowledge_search
---
# What this skill does

Authors a crisp one-to-two page decision memo that frames a single decision, lays out the viable options with tradeoffs, and lands a clear recommendation. Produces a structured memo (Situation, Assessment, Options, Recommendation, plus the ask) a decision-maker can act on in one read.

# Steps

1. Capture the exact decision to be made and the decision-maker/deadline from the requester. If the decision isn't a single answerable question, sharpen it before writing.
2. Run `knowledge_search` for relevant data, prior decisions, and constraints; cite each fact inline. Mark anything you assert without a source as `[unverified]`.
3. Draft the memo: Situation (context + why now), Assessment (key findings), Options (2-4, each with pros/cons/cost/risk), and a single Recommendation with rationale and the explicit ask.
4. State open questions and assumptions, then hand off the draft noting the recommendation is advisory and the named decision-maker owns the call.

# Notes

Output is wrong if it presents options without a recommendation, buries the ask, runs long, or states unsourced claims as fact. Keep it to one decision — split multi-decision requests into separate memos. The memo recommends; it does not execute — irreversible actions named in it stay staged for the decision-maker. Not for status updates or pure information sharing where no decision is pending.

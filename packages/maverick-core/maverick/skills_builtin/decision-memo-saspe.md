---
name: decision-memo-saspe
triggers:
  - decision memo
  - recommend an option
  - should we do x
  - options analysis
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Produces a decision memo in the Situation / Assumptions / Solutions / Pros-and-cons / Evaluation structure with an explicit recommendation, so a recommendation is transparent about its premises and trade-offs. The goal class is "recommend a course of action defensibly": make assumptions visible, compare real alternatives on consistent criteria, and commit to a recommendation.

# Steps

1. Read the relevant material with read_file and, where facts are needed, ground them with knowledge_search. Write the Situation: the decision to be made and why now.
2. List the Assumptions explicitly — the premises the recommendation depends on — so a reader can challenge a premise rather than the conclusion. Flag which assumptions are load-bearing.
3. Enumerate the Solutions (candidate options including status quo), then give Pros-and-cons for each against the SAME evaluation criteria (cost, risk, time, reversibility, strategic fit).
4. In Evaluation, score the options against the criteria and state the recommendation with its rationale and the conditions under which you would change your mind.

# Notes

Hidden assumptions are where decision memos go wrong; surfacing them lets a reviewer attack a premise instead of being trapped by the framing. Comparing options on shifting criteria is rigging the result — use one consistent yardstick. Always include the do-nothing / status-quo option; omitting it overstates the case for acting. A memo that refuses to recommend is incomplete; commit, while being honest about uncertainty. This skill drafts the memo for a decision-maker; it does not make or execute the decision.

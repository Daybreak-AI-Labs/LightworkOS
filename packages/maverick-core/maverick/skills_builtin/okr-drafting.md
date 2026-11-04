---
name: okr-drafting
triggers:
  - draft okrs
  - set objectives
  - key results for
  - quarterly goals
tools_needed:
  - read_file
---
# What this skill does

Turns a stated goal into a small set of qualitative Objectives, each with measurable, time-bound Key Results that include a baseline and a target, so progress is trackable and outcome-focused rather than activity-focused. The goal class is "make a goal measurable": ambitious objectives, plus key results that are numbers with a start point and an end point and a date.

# Steps

1. Read the goal and its context with read_file and draft a few (ideally three or fewer) Objectives: qualitative, inspirational, and clearly time-bounded statements of what success looks like.
2. For each Objective, write Key Results that are measurable outcomes (not tasks): each has a metric, a baseline (where we are now), a target (where we want to be), and a deadline.
3. Test each KR for outcome-vs-activity: "ship feature X" is activity; "increase activation rate from 40% to 55%" is outcome. Rewrite activity-shaped KRs into the result they are meant to produce.
4. Sanity-check ambition and count: KRs should be a stretch but not impossible, and there should be few enough to stay focused. Flag any KR lacking a baseline as not-yet-measurable.

# Notes

The dominant failure is activity-as-KR ("hold 10 meetings") which measures effort, not impact — always push to the outcome. A KR with no baseline cannot show progress; insist on the starting number even if it must be measured first. Too many objectives or KRs destroy focus; fewer and sharper wins. Sandbagging targets to guarantee a green score defeats the purpose; calibrate for a genuine stretch. This skill drafts OKRs for the owning team to commit to; it does not set or approve them unilaterally.

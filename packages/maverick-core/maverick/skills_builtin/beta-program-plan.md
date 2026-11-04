---
name: beta-program-plan
triggers:
  - plan a beta program
  - set up an early access program
  - design a pilot program for this feature
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a plan for a beta, early-access, or pilot program: who is in the cohort and why, how feedback and success signals are collected, and the explicit criteria for graduating to GA or pulling the program. Output is a beta plan a team can run end to end with clear go/no-go gates.

# Steps

1. Define the goal and scope from real inputs: what the beta must learn or de-risk (specific questions, not "get feedback"), the feature surface, and duration. Use knowledge_search over prior betas and customer records to ground cohort criteria and avoid repeating past mistakes.
2. Design the cohort: target size, segment/persona mix, inclusion and exclusion criteria, and recruitment/consent path. Size it to answer the learning goals and to surface edge cases; record selection rationale so results are interpretable, not anecdotal.
3. Specify the feedback and measurement loop: qualitative channels (interviews, in-product reports), quantitative signals (activation, retention, error/support volume), cadence, and owners. Set a baseline so you can tell whether the beta is working.
4. Define exit criteria up front — graduation thresholds for GA and the pull/extend triggers if signals fail — plus a comms and rollback plan. Report the plan with assumptions stated; launch and the final GA/kill call are human decisions, not auto-promoted.

# Notes

The plan fails when the cohort is whoever volunteered (selection bias), success criteria are decided after the beta, or there is no rollback for participants if it is pulled. Exit criteria must exist before launch or the program runs forever. This is a draft plan; recruiting real users, sending comms, and promoting to GA are irreversible, human-approved actions. Do not use for a hardened, fully validated feature that needs no learning loop — ship it via normal release instead.

---
name: product-discovery-plan
triggers:
  - product discovery
  - plan discovery research
  - opportunity solution tree
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a structured plan for de-risking a product bet before build. It names the desired outcome, surfaces the riskiest assumptions (desirability, viability, feasibility, usability), and pairs each with a concrete research method and success signal — so the team learns the cheapest, fastest way to confirm or kill an idea.

# Steps

1. State the target outcome and the bet under question from the user's input and `knowledge_search` over prior research, support tickets, and analytics. Frame the opportunity (user problem) separately from any proposed solution so discovery isn't anchored to one answer.
2. Enumerate the assumptions the bet depends on and tag each by risk type (desirability / viability / feasibility / usability) and by how much evidence already backs it. Rank by "most likely to be wrong AND most damaging if wrong" — those are what to test first.
3. For each top assumption, pick a fitting method (customer interviews, fake-door/landing test, prototype usability test, data analysis, tech spike) and define the signal that would confirm or refute it, plus rough effort. Match method to risk type; don't run interviews for a feasibility question.
4. Assemble the plan (outcome, prioritized assumptions, method + signal + effort per assumption, sequence) and hand off. Separate evidence-backed claims from untested assumptions explicitly, and recommend a human owner approve scope before fieldwork begins.

# Notes

Discovery fails when the team tests assumptions that are already safe while skipping the load-bearing risky one, or when "success" isn't defined up front so any result gets rationalized as validation — define the kill/confirm signal before collecting data. Mark every assumption unverified until evidence lands; never present a hypothesis as a finding. This plans research and stages recommendations; the build/no-build decision stays with a human. Don't use it once the bet is already validated and scoped (move to `feature-spec-author`).

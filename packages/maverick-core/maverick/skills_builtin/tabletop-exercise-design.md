---
name: tabletop-exercise-design
triggers:
  - tabletop
  - security exercise
  - incident simulation
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a security tabletop exercise: a realistic scenario, a timed sequence of injects that escalate the situation, the participants and roles, the decision points being tested, and the evaluation criteria used to score the team's response. Produces a facilitator-ready exercise package the security lead can run.

# Steps

1. Fix the objective and scope: what capability is under test (e.g. ransomware containment, breach-notification timing, exec escalation) and which team/roles participate. Pull the org's IR plan, severity runbook, and a relevant recent-threat profile via knowledge_search; cite them so the scenario is plausible for this org, not generic.
2. Write the scenario seed — a single realistic triggering event grounded in the org's actual stack and threat landscape (knowledge_search), not an invented adversary. State starting conditions and what participants know at T0.
3. Build a timed inject sequence (T+0, T+15, T+30...) where each inject forces a specific decision or surfaces a gap: new evidence, a complication, a stakeholder demand, a media or regulator query. Map every inject to an objective from step 1 and to the IR-plan step it exercises.
4. Define evaluation criteria per inject and overall: did the team follow the runbook, hit notification deadlines, escalate correctly, communicate clearly. Provide a facilitator guide with expected responses and probing questions, plus a hotwash/after-action template.
5. Report the package (scenario, roles, inject timeline, evaluation rubric, facilitator notes) as a draft, state assumptions and any inject whose realism depends on unverified org details, and hand off to the exercise owner to schedule and run.

# Notes

The exercise is wrong if injects don't map to a tested objective, if the scenario is generically plausible but contradicts the org's real architecture, or if evaluation criteria are subjective adjectives instead of observable actions. Do not fabricate threat intel or org details — mark any unconfirmed scenario element unverified. This is a simulation by design: it must never trigger real systems, real notifications, or real responders; keep all injects clearly labeled as exercise. Do not use it to script a response to a live incident or as a substitute for a real IR plan.

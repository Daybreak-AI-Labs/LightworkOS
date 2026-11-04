---
name: skills-gap-assessment
triggers:
  - skills gap
  - capability gap
  - build buy borrow
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Assesses a team or org's current capabilities against a target capability model and produces a skills-gap matrix. For each gap it sizes the shortfall and recommends build (train/develop), buy (hire), or borrow (contract/partner), with rationale grounded in current headcount data.

# Steps

1. Define the target: pull the capability/skills taxonomy and required proficiency levels for the target state. Use knowledge_search or the provided competency model; list any competency lacking a defined target as "to confirm."
2. Pull the current state: query the HRIS/skills inventory with sql_query for held skills and self/manager-rated proficiency by person and team. Where ratings are missing, mark cells "unknown" rather than assuming zero.
3. Build the gap matrix in a spreadsheet: target vs. current proficiency per skill, headcount at each level, and a gap magnitude (count and depth). Sort by business-criticality of the skill.
4. Recommend build/buy/borrow per gap using consistent criteria (time-to-proficiency, market scarcity, strategic vs. commodity, cost). Report the matrix with the decision rationale and flag every recommendation resting on unknown/unverified proficiency data.

# Notes

Output is wrong if it scores skills that have no defined target, treats missing data as zero, or recommends "buy" without considering internal development capacity. Self-rated proficiency is noisy — label it as such. Recommendations are advisory: hiring, training spend, and vendor engagements are decided by the function leader and finance. Do not use as an individual performance ranking; it measures aggregate capability, not people.

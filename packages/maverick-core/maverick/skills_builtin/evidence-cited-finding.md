---
name: evidence-cited-finding
triggers:
  - write a finding
  - rate this risk
  - audit finding
  - document an issue
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Emits an audit/assessment finding in the canonical structure (condition, criteria, cause, effect, evidence-ref, risk-rating) so it is defensible, actionable, and traceable. The goal class is "document a problem rigorously": separate what is (condition) from what should be (criteria), explain why the gap exists (cause) and what it leads to (effect), and anchor every part in evidence with a calibrated risk rating.

# Steps

1. Read the evidence with read_file and search the relevant standard/policy with knowledge_search to pin the exact criteria (the clause, control, or requirement the condition is measured against).
2. Write the condition as an observed, evidence-backed fact (what was found), distinct from the criteria (the authoritative expectation). Cite both.
3. Determine the cause (the underlying reason for the gap, ideally systemic not symptomatic) and the effect (the realistic risk or impact if unaddressed). Avoid conflating cause with a restatement of the condition.
4. Assign a risk-rating using a stated scale (e.g. likelihood x impact) and attach evidence-ref locators for every element. Output the six fields explicitly.

# Notes

A finding without criteria is just an opinion — always cite the authoritative "should be." The most common weakness is a cause that merely repeats the condition ("the control failed because it was not working"); push to the systemic root (use root-cause-5-whys if needed). Risk ratings must be consistent across findings, so apply the same scale every time. Do not inflate a rating for attention or deflate it to avoid friction. This skill drafts the finding for review; it does not publish it or open a remediation ticket.

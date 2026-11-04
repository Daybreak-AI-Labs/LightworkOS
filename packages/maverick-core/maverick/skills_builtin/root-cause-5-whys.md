---
name: root-cause-5-whys
triggers:
  - root cause
  - 5 whys
  - why did this happen
  - rca
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Runs a structured causal drill-down on an incident or defect, asking "why" iteratively until it reaches a systemic cause (a process or control gap, not a person to blame) and pairs it with a concrete corrective action. The goal class is "find the real cause, not the symptom": stop only when the answer is something the organization can fix at the root.

# Steps

1. Read the incident record / timeline with read_file and state the problem as a specific, observed effect (what happened, when, with what impact).
2. Ask why that effect occurred; answer with an evidence-backed cause, then ask why THAT occurred, iterating (typically about five times) — branching where there are multiple contributing causes rather than forcing a single line.
3. Stop when the cause is systemic (a missing control, an unclear process, a design gap) and within the organization's power to change — not at "human error," which is a symptom of a system that allowed the error.
4. For each root cause, propose a corrective action and a way to verify it worked, and search knowledge_search for whether similar root causes recurred, to spot a pattern.

# Notes

Stopping at "someone made a mistake" is the classic failure — blame is not a root cause, and it prevents the system fix that stops recurrence. Do not collapse a multi-cause incident into one tidy chain; real incidents usually have several contributing causes. Each "why" must be evidence-backed, not speculation — an unverified causal chain is just a story. This skill produces an analysis and proposed corrective actions for review; it does not implement fixes or assign blame in any record.

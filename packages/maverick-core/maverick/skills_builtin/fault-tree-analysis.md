---
name: fault-tree-analysis
triggers:
  - build a fault tree for this failure
  - run an FTA on the top event
  - what combinations of faults cause this outage
tools_needed:
  - knowledge_search
---
# What this skill does

Performs Fault Tree Analysis (FTA): deductive, top-down decomposition of a single undesired top event into the combinations of lower-level faults that can cause it. Produces a logic tree of intermediate events and basic events joined by AND/OR gates, then reduces it to its minimal cut sets — the smallest fault combinations sufficient to trigger the top event — so single points of failure and weakest combinations are explicit.

# Steps

1. Fix exactly one top event with the user (a specific, bounded failure/outage — not a vague category) and the system boundary. Use `knowledge_search` to pull the system's components, dependencies, and known failure mechanisms from design docs, incident records, or runbooks; cite each source and mark anything inferred as unverified.
2. Decompose deductively: ask "what immediately causes this?" at each node, connecting causes with AND gates (all must occur) or OR gates (any suffices). Continue until you reach basic events that are independent and resolvable (component faults, human errors, external conditions) — do not fabricate failure paths the sources do not support.
3. Derive the minimal cut sets via Boolean reduction of the gate logic. Identify any single-element cut set (a single point of failure) and note the smallest/most-likely combinations. If basic-event probabilities are sourced, compute top-event probability; otherwise present the structure qualitatively and say so.
4. Report the tree, the minimal cut sets, the single points of failure, and recommended barriers/redundancy for the weakest cut sets — citing sources and flagging unverified links. State assumptions (independence, completeness) and hand off: design or redundancy changes are staged for a human decision.

# Notes

The analysis is wrong if gate logic is inverted (AND vs OR is the crux — an OR where reality needs AND overstates risk and vice versa), if common-cause failures across "independent" basic events are missed, or if the tree is incomplete and presented as exhaustive. FTA is top-down and deductive — do not conflate it with bottom-up FMEA. Quantitative results are only as good as the input failure rates; never invent probabilities. This skill produces analysis and recommendations only; it does not implement redundancy or sign off on safety cases. Avoid for multi-event or purely sequential/timing problems better suited to event-tree or Markov methods.

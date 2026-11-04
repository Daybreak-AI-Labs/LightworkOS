---
name: stakeholder-raci-map
triggers:
  - raci
  - whos responsible
  - stakeholder map
  - accountability matrix
tools_needed:
  - read_file
---
# What this skill does

Builds a RACI (Responsible, Accountable, Consulted, Informed) matrix and stakeholder map so accountability is unambiguous before work starts — exactly one Accountable per activity, the right people Consulted, and no one important left off. The goal class is "make ownership clear up front": map activities to roles so nothing falls between two stools and nobody is surprised late.

# Steps

1. List the activities/decisions in scope and the stakeholders/roles involved by reading the project context with read_file.
2. For each activity assign exactly one Accountable (the single neck on the line), one or more Responsible (who does the work), Consulted (two-way input before the decision), and Informed (one-way notification after).
3. Check the matrix for anti-patterns: activities with zero or multiple Accountable, a stakeholder who is Consulted on everything (bottleneck), or a key stakeholder absent entirely.
4. Produce the matrix plus a short stakeholder map noting each party's interest and influence, and flag any contested ownership for the sponsor to resolve before work begins.

# Notes

Two Accountable parties for one activity means nobody is truly accountable — enforce exactly one. Confusing Responsible with Accountable is the usual mix-up: the doer is not necessarily the owner. An over-Consulted role becomes a bottleneck that stalls delivery; be sparing with C. Leaving a powerful stakeholder Informed when they expect to be Consulted breeds conflict; map influence honestly. This skill drafts the matrix for the sponsor to ratify; it does not assign people to roles by fiat.

---
name: incident-postmortem-5whys
triggers:
  - write postmortem
  - run a 5 whys
  - blameless retro
  - incident retrospective
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

This skill assembles a blameless post-incident review from an incident's timeline and artifacts: it reconstructs the sequence of events, computes impact and MTTR-style timing metrics (time to detect, mitigate, resolve), and drives a 5-whys analysis to surface contributing factors and the underlying systemic causes rather than a single root cause or a person to blame. It produces a structured postmortem with tracked, owned corrective actions. The output is a staged postmortem draft for review; it does not assign blame, file the corrective-action tickets, or change any system — humans own follow-through.

# Steps

1. Use read_file and knowledge_search to gather the incident record: the timeline (detection, escalation, mitigation, resolution timestamps), alerts that fired (and any that should have), chat/ops logs, the customer impact, and the change that triggered it if known.
2. Compute the impact and timing metrics: scope/severity, affected users or revenue, and the intervals — time to detect, time to mitigate, time to resolve — from the timeline. Note any detection or escalation gaps the timing exposes.
3. Run the 5-whys on the failure chain, asking "why" iteratively past the proximate cause into the systemic contributing factors (missing alert, fragile dependency, gap in runbook, unsafe deploy process). Frame every finding around systems and processes, not individuals — blameless language throughout. Capture multiple contributing factors; resist collapsing to one "root cause."
4. Assemble the postmortem (summary, timeline, impact, metrics, 5-whys/contributing factors, what went well, and a corrective-action table with owner and priority for each item) and stage it for the team's review. Mark that action items are tracked and owned by humans — this skill writes the document, it does not create tickets or remediate.

# Notes

Blameless is non-negotiable: write about the system that let the failure happen, never the person who pushed the button — naming an individual as the cause kills the honesty the process depends on, so rephrase any blame into a systemic factor. Resist single-root-cause tunnel vision; real incidents have several contributing factors, and 5-whys is a tool to reach them, not a script to stop at exactly five. Action items without an owner and a tracking link evaporate — give each one an owner and priority, but note that filing the tickets is a human step this skill does not perform. Distinguish what actually happened from speculation; mark unknowns as open questions rather than inventing a clean narrative. The metrics (detect/mitigate/resolve) are only as good as the timeline; cite the source timestamp for each.

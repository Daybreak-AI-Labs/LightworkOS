---
name: dora-ict-incident-classify
triggers:
  - classify ict incident for dora
  - dora major incident
  - ict incident severity
  - dora classification
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Applies the DORA regulatory technical standards classification criteria to an ICT-related incident — clients affected, data losses, duration and service downtime, geographical spread, economic impact, and reputational impact — to decide whether it is a major incident and to lay out the notification timeline. The goal class is "classify an ICT incident under DORA and surface the reporting clock" while keeping the actual regulator notification a human decision.

# Steps

1. Read the incident record with read_file and gather the classification inputs: number and type of clients/financial counterparts affected, whether data was lost (availability, authenticity, confidentiality, integrity), the duration and service downtime, the geographical spread across member states, and the economic and reputational impact.
2. Apply the DORA RTS thresholds to each criterion and determine whether the combination meets the major-incident bar; search knowledge_search for the current materiality thresholds and the criteria weighting.
3. If it is a major incident, lay out the reporting timeline: the initial notification, the intermediate report, and the final report, with their respective deadlines from the moment of classification/awareness.
4. Produce a classification memo: the criteria assessment, the major / non-major conclusion with rationale, and the notification schedule — explicitly marking the regulator notification itself as a human-gated step.

# Notes

DORA classification is multi-criteria with thresholds, not a single severity dial — an incident can be major on geographical spread or data loss even with modest downtime, so assess every criterion, not just the obvious one. The notification deadlines run from awareness/classification, so the clock starts early; surfacing it promptly matters. Critically, this skill DECIDES classification and PREPARES the timeline, but the actual notification to the competent authority is a regulator-facing action that stays human-gated — the agent never files it. Search for the current thresholds rather than relying on memory, since the RTS detail is specific.

---
name: postmortem-author
triggers:
  - write a postmortem
  - run an incident review
  - draft an RCA writeup
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a blameless incident postmortem for a resolved (or stabilized) operational incident. Output is a structured document: an impact summary, a fact-based timeline, the root cause and contributing factors, and a prioritized list of corrective actions with owners. The tone stays on systems and process, never on individuals.

# Steps

1. Gather the primary record via knowledge_search: the incident ticket, alert pages, chat/bridge transcript, deploy log, and any prior related postmortems. Note the canonical start time, detection time, mitigation time, and resolution time as timestamps with timezone; mark any gap you cannot source as `[unverified]`.
2. Build the timeline strictly from those artifacts — one row per event with timestamp, what happened, and the source. Distinguish trigger (what started it), detection (how we found out), and mitigation (what stopped the bleeding). Do not infer events that have no log entry.
3. Determine root cause and contributing factors. State the root cause as a chain ("X allowed Y because Z control was absent"), not a single blamed commit or person. List contributing factors (monitoring gaps, missing runbook, latent config) separately from the trigger.
4. Draft corrective actions: each is concrete, testable, has a proposed owner and a priority, and maps back to a contributing factor. Compute impact metrics (duration, users/requests affected, error budget burn) from sourced numbers. Hand off the draft for the incident owner to assign owners and ratify actions; flag any action that is irreversible or production-changing as requiring human sign-off.

# Notes

Wrong output looks like: a timeline with unsourced times, a root cause that names a person, or actions that are vague ("be more careful") or unowned. Every timestamp and metric must trace to an artifact — if you cannot source it, mark it `[unverified]` rather than guess. Do NOT use this for an active, unmitigated incident (that is incident response, not review) or where the sequence of events is still unknown. The skill drafts and recommends; assigning owners, committing to action dates, and any remediation that touches production are decided by the incident owner.

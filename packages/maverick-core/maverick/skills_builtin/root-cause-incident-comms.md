---
name: root-cause-incident-comms
triggers:
  - draft incident comms
  - write a status update for customers
  - customer notification for the outage
tools_needed:
  - knowledge_search
---
# What this skill does

Drafts a customer-facing incident communication during or after an outage or degradation. Produces a clear, calibrated update stating who is impacted, current status, what is being done, and an explicit time for the next update — written to inform without over-promising or speculating on root cause.

# Steps

1. Gather the confirmed facts from the requester or incident channel: services affected, start time, scope of impact, current mitigation status. Use only confirmed facts; do not infer root cause or ETA that hasn't been validated.
2. Run `knowledge_search` for the org's incident-comms templates, severity definitions, and status-page conventions so tone and structure match prior communications.
3. Draft the update with four sections: Impact (who/what, in customer terms), Current Status (investigating / identified / monitoring / resolved), What We're Doing (actions, no speculative root cause), and Next Update (a concrete timestamp).
4. Hand off the draft, explicitly listing any facts marked UNVERIFIED and any place you avoided stating a root cause or ETA. State the assumed severity and audience.

# Notes

The output is wrong if it speculates on root cause, promises an ETA that isn't confirmed, or assigns blame — these create liability and erode trust. Never publish before a human incident commander approves; external comms are an irreversible action staged for a human. Always include a next-update time so customers aren't left waiting. Do not use this for internal postmortems (that's a different, blameless artifact) or for legally reportable breaches without legal/security sign-off.

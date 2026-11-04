---
name: require-human-gate-checklist
triggers:
  - does this need approval
  - is this a hard floor
  - can i do this myself
  - is this reversible
tools_needed:
  - read_file
---
# What this skill does

Checks a proposed action against the hard-floor list of things an autonomous agent must never do unilaterally — moving money, submitting a legal/regulatory filing, notifying a regulator, granting or using privileged access, or anything with safety/physical consequence — and routes any match to require_human. The goal class is "decide whether I am allowed to do this alone": when in doubt, stop and escalate.

# Steps

1. Restate the proposed action in concrete terms (what changes, in which system, with what blast radius) by reading the relevant context with read_file.
2. Test it against each hard-floor category: (a) money movement or financial commitment, (b) legal or regulatory filing, (c) regulator/authority notification, (d) granting/elevating/using privileged access or secrets, (e) anything with safety or physical-world consequence, (f) irreversible deletion or destruction.
3. If ANY category matches, classify the action as human-gated: prepare a draft-for-human-review artifact and route to require_human with the specific reason and the category hit. Do not execute.
4. If none match, document why the action is reversible and within autonomous scope, and proceed — but record that determination so it is auditable.

# Notes

Reversibility is the deciding test: "can I cleanly undo this in seconds" — if not, treat it as gated. Agents drift toward action; the bias here is deliberately conservative because a false escalation costs a human a moment while a false self-authorization can be catastrophic. "Read-only preview" of a gated action is fine; performing it is not. This skill only classifies and routes; it never performs the gated action even after deciding it is gated. The hard-floor list is a floor, not a ceiling — local policy may gate more.

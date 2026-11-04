---
name: nhi-credential-rotation-runbook
triggers:
  - rotate service account
  - nhi rotation plan
  - stale machine identity
  - rotate machine credential
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Drafts (does not execute) a staged rotation runbook for a non-human identity (service account, API credential, machine certificate): maps the dependency blast radius, sequences the secret-store update, defines rollback, and inserts a human-gated cutover. The goal class is "plan a safe credential rotation": produce the procedure a human will run, so a stale or over-privileged machine identity can be rotated without an outage.

# Steps

1. Identify the NHI and where it is used by reading inventory, IAM, and config with read_file: which services authenticate with it, what scopes/permissions it holds, and where the credential is stored (secret manager, env, embedded).
2. Map the blast radius: every consumer that would break if the credential changed, and any hidden dependency (a cron job, a third-party integration). Search knowledge_search for the platform's recommended rotation pattern (dual-credential / overlap windows).
3. Sequence the rotation for zero downtime where possible: provision the new credential alongside the old (overlap), update consumers to the new secret in the store, verify, then revoke the old credential last; define an explicit rollback at each step.
4. Insert a human-gated cutover and pre-flight checklist: the runbook ENDS as a reviewed procedure with approval and rollback points — the agent drafts and stages it; a human authorizes and executes the actual rotation.

# Notes

Rotating before mapping the blast radius is how rotations cause outages — an unseen consumer (a nightly batch, a partner integration) still holding the old secret breaks at cutover, so dependency discovery is the whole game. Prefer an overlap/dual-credential window so old and new are both valid during transition; a hard swap with no overlap guarantees a gap. Always revoke the OLD credential last, after verifying the new one works, and keep rollback at every step. This skill DRAFTS and STAGES the runbook only — rotating or revoking a live credential is a privileged, human-gated action it must never perform itself.

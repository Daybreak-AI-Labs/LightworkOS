---
name: secrets-management-review
triggers:
  - secrets management
  - key rotation
  - credential hygiene
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Reviews how an organization or codebase stores, accesses, and rotates secrets (API keys, DB credentials, tokens, signing keys, certs) and produces a written review covering current exposure and a concrete rotation plan. Output is a prioritized findings list plus a per-secret rotation schedule a human can approve and execute.

# Steps

1. Gather the real inventory: run `knowledge_search` for the org's secrets policy, vault/KMS docs, and prior incidents, and `read_file` on supplied config, CI, IaC, and dotenv-style files. List every secret-bearing location actually found — never assume a vault exists if no evidence shows it.
2. Classify each secret by storage tier (hardcoded in source / plaintext config / env var / managed vault-KMS), blast radius, and whether it appears in version control or logs. Flag anything in-repo or in CI plaintext as high exposure.
3. For each secret, capture rotation reality: last-rotated date (or "unknown"), owner, rotation mechanism (manual vs automated), and whether rotation is non-disruptive (dual-key/overlap support). Mark unverifiable items as unverified, not compliant.
4. Produce the review: exposure findings ranked by severity, a rotation plan with cadence and method per secret, and quick wins (move to vault, revoke leaked, enable auto-rotation). End by reporting findings and stating assumptions; stage revocation/rotation actions as recommendations for a human to execute.

# Notes

Output is wrong if it claims a secret is "rotated" or "vaulted" without a source — cite the file or doc, else mark unverified. The hard safety boundary: do NOT revoke, rotate, or invalidate live credentials yourself — that can break production; draft the plan and let an owner execute in a maintenance window with rollback. Skip this skill for pure threat-modeling or network-perimeter questions; it is scoped to secret storage and rotation, not access control design broadly.

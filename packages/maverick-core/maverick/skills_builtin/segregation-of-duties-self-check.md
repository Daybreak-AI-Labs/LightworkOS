---
name: segregation-of-duties-self-check
triggers:
  - sod check
  - am i conflicted
  - make and approve
  - duty separation
tools_needed:
  - read_file
---
# What this skill does

Verifies that a single actor (including this agent) is not about to both initiate and approve the same transaction, or hold both custody and recording duties, and refuses the action if it would collapse maker/checker separation. The goal class is "do not be my own approver": enforce that the entity that creates a request is not the entity that authorizes, executes custody over, or independently records it.

# Steps

1. Identify the duties the proposed action touches: initiation/maker, authorization/checker, custody (access to the asset), and recording (booking the entry). Read the workflow context with read_file.
2. Map who performed the upstream step and who would perform this step. If the same actor (same agent identity, same human, same service account) would occupy two incompatible duties, that is an SoD conflict.
3. On a conflict, refuse to complete the second incompatible step and route it to a distinct approver/recorder via the human gate. Document which two duties collided.
4. Where full separation is impossible, propose a compensating control (independent after-the-fact review, dual sign-off, heightened logging) for a human to accept — do not just proceed because separation was inconvenient.

# Notes

The classic violation is one identity that drafts a payment AND approves it; an agent acting end-to-end is especially prone to this, so the check must run before the second step, not after. Compensating controls are a fallback for a human to bless, not an excuse the agent grants itself. Custody-plus-recording (the person who can move the asset also books it) is as dangerous as maker-plus-checker. This skill blocks and reroutes; it never grants itself an exception. When unsure whether two duties are incompatible, treat them as incompatible.

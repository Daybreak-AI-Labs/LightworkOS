---
name: idempotency-design
triggers:
  - idempotency
  - exactly once
  - retry safety
tools_needed:
  - knowledge_search
---
# What this skill does

Designs idempotent execution for an operation that may be retried, replayed, or delivered more than once (payments, webhooks, job consumers, API writes). Produces an idempotency design: the idempotency key, where dedup state lives, the conflict/concurrency rules, and the retention window — so a repeated request yields the same effect and the same response, exactly once.

# Steps

1. Pin the real operation from the inputs: name the trigger (HTTP write, queue message, cron), the side effects it causes (DB rows, external charges, emails), and what "the same operation twice" concretely means here. Do not invent endpoints — quote the ones given.
2. Define the idempotency key: prefer a client-supplied key (e.g. `Idempotency-Key` header) for at-least-once external callers, or a deterministic natural key (order_id + step) for internal flows. State exactly which request fields compose the key and how collisions across different callers are prevented.
3. Choose the dedup store and the atomic claim: a keyed table/row with a unique constraint, claimed in the same transaction as the side effect (or via outbox if the side effect is external). Use `knowledge_search` to confirm the platform's transactional and unique-constraint guarantees before relying on them; mark any guarantee you could not verify.
4. Specify behavior for each case — first call, concurrent duplicate (lock/insert-or-fail then return stored result), retry after success (replay stored response), retry after partial failure (resume or fail closed). Set a key retention TTL and the cleanup job.
5. Report the design with the key spec, store schema, concurrency rules, retention, and an explicit list of assumptions and any external side effect that cannot be made transactional and must be reconciled.

# Notes

The output is wrong if the key can collide across distinct intents, if the dedup claim is not atomic with the side effect (a crash between them double-charges), or if retention expires before the longest realistic retry window. Non-transactional external effects (charging a card, sending mail) need an outbox + reconciliation, not just a unique row — call this out rather than implying false safety. This is a design/recommendation: do not enable it on a live write path without a human reviewing the concurrency and failure cases. Not for read-only or naturally idempotent (PUT-by-full-state) operations where no dedup state is needed.

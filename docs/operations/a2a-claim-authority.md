# A2A durable claim authority

The existing governed-record backend selection also selects A2A task storage.
Local mode uses the private tenant SQLite ledger. PostgreSQL mode uses the
encrypted `a2a-task-authority-v1` namespace in `governed_records`, with forced
row-level security and the existing external fleet-key identity requirements.
There is no plaintext shared fallback or automatic local/shared cutover.

An incoming message is bound to its tenant, authenticated principal, message ID
and canonical request digest. The claim, task lookup, quota accounting and
terminal-eviction index commit together before any runner executes. Reusing an
ID with different content fails. Completed results replay without another run;
an in-progress claim left by a crash remains indeterminate. Evicting an old
result body preserves a tombstone and never makes the message ID reusable.

Each tenant admits at most 100,000 identities and 64 MiB of encrypted snapshot
bodies. Admission can examine up to 60 old terminal candidates to make room. If
that bounded transaction cannot make room it rolls back and reports capacity.
It does not discard identities, scan indefinitely or execute without a claim.

`a2a/tasks.authority.sealed` binds a local data root to the shared authority's
random identity. It is private and encrypted with the pinned fleet key. A local
downgrade, missing/replaced database generation, unavailable key or corrupted
binding refuses admission. The expected identity is checked inside each actual
claim/read/settlement transaction. A cached task does not bypass these checks.
Do not delete this receipt to work around an authority error.

## Offline migration

Stop the control plane and all direct callers writing the source A2A ledger.
Retain its original encryption keys and a verified backup. Configure the target
governed-record PostgreSQL backend and its pinned external encryption key using
the existing deployment configuration. Keep the replica count at 1 and ownership
enforcement enabled. Then run the explicit maintenance command:

```console
maverick a2a migrate-claims --tenant acme
```

The command takes exclusive local control-plane ownership and the same strict
admission lock as ordinary A2A I/O. It checks SQLite integrity, single-tenant
scope, claim identities, decrypted snapshot bindings and quota accounting under
`BEGIN IMMEDIATE`. Sources larger than 512 MiB or exceeding shared quotas refuse.
Plaintext sources refuse when current encryption policy requires ciphertext;
there is no implicit downgrade to read an unauthenticated source.

Import happens in 20-row atomic batches. An encrypted migration checkpoint binds
the source digest, target identity, cursor, imported count and retained bytes.
The shared namespace remains `migrating` until the full count and byte totals
match. Terminal, indeterminate and tombstone states are preserved exactly.
The local binding prevents a restart from opening a new empty local authority.

After the shared import commits, the original ledger is retained privately as
`tasks.migrated-<source-digest>.sqlite3`. Archive publication is exclusive and
streamed, with a committed file digest. The original pathname is removed only
after the retained copy verifies. No existing archive is overwritten. A retry
after publication verifies the same checkpoint and source/archive before
finishing; a retry after completion returns the verified completion receipt.
The JSON receipt contains digests and counts, without task payloads or DSNs.

If migration fails, preserve the source, local binding, archive if present and
shared checkpoint. Resolve the reported authority/storage problem and rerun for
the same tenant. Changed sources or target generations are refused. A generic
retry never re-executes a task, and there is no automatic rollback to an
empty local ledger. Do not manually clear the marker or pending shared state.

## Deployment boundary

This covers the claim authority, not the entire control plane's availability.
Flows, signing/append custody, learning and other local authorities still require
an explicit ownership/recovery contract. Runtime admission and deployment guards
retain the one-active-control-plane restriction. The local kernel lock is not a
distributed lease and cannot certify a network filesystem reporting false lock
success. Its counter is diagnostic; shared mutations use their own transactional
identity and revision checks. The [persistence inventory](persistence-authorities.md)
lists the remaining authority boundaries and qualification requirements.
